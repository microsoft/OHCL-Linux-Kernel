// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * Author:
 *   Saurabh Sengar <ssengar@microsoft.com>
 */

#include <asm/apic.h>
#include <asm/boot.h>
#include <asm/desc.h>
#include <asm/i8259.h>
#include <asm/mshyperv.h>
#include <asm/realmode.h>
#include <linux/memblock.h>
#include <../kernel/smpboot.h>

extern void hv_tdx_trampoline(void);
extern struct boot_params boot_params;
static struct real_mode_header hv_vtl_real_mode_header;
static u64 hv_tdx_trampoline_cr3;

static bool __init hv_vtl_msi_ext_dest_id(void)
{
	return true;
}

static void __init hv_tdx_reserve_real_mode(void)
{
	phys_addr_t mem;
	size_t size = real_mode_size_needed();
	u64 *pml4;
	u64 *pdpte;
	u64 i;

	/* Space for page table for lower 4GB. */
	size += PAGE_SIZE * 2;

	/* On TDX platforms, we only need the memory to be <4GB since
	 * the 64-bit trampoline only goes down to 32-bit mode. */
	mem = memblock_phys_alloc_range(size, PAGE_SIZE, 0, 1ul<<32);
	if (!mem)
		panic("No sub-4G memory is available for the trampoline\n");

	set_real_mode_mem(mem + PAGE_SIZE * 2);

	/* Initialize an identity mapped page table mapping the lower 4GB. */
	pml4 = __va(mem);
	pdpte = __va(mem + PAGE_SIZE);
	pml4[0] = __pa(pdpte) | _PAGE_PRESENT | _PAGE_RW;
	for (i = 0; i < 4; i++)
		pdpte[i] = (i << PUD_SHIFT) | _PAGE_PRESENT | _PAGE_RW | _PAGE_PSE | _PAGE_DIRTY | _PAGE_ACCESSED;

	hv_tdx_trampoline_cr3 = mem;
}

void __init hv_vtl_init_platform(void)
{
	pr_info("Linux runs in Hyper-V Virtual Trust Level\n");

	x86_init.resources.probe_roms = x86_init_noop;
	if (hv_isolation_type_tdx())
		x86_platform.realmode_reserve = hv_tdx_reserve_real_mode;
	else {
		x86_platform.realmode_reserve = x86_init_noop;
		x86_platform.realmode_init = x86_init_noop;
		real_mode_header = &hv_vtl_real_mode_header;
	}
	x86_init.irqs.pre_vector_init = x86_init_noop;
	x86_init.timers.timer_init = x86_init_noop;

	/* Avoid searching for BIOS MP tables */
	x86_init.mpparse.find_smp_config = x86_init_noop;
	x86_init.mpparse.get_smp_config = x86_init_uint_noop;

	x86_platform.get_wallclock = get_rtc_noop;
	x86_platform.set_wallclock = set_rtc_noop;
	x86_platform.get_nmi_reason = hv_get_nmi_reason;

	x86_platform.legacy.i8042 = X86_LEGACY_I8042_PLATFORM_ABSENT;
	x86_platform.legacy.rtc = 0;
	x86_platform.legacy.warm_reset = 0;
	x86_platform.legacy.reserve_bios_regions = 0;
	x86_platform.legacy.devices.pnpbios = 0;

	x86_init.hyper.msi_ext_dest_id = hv_vtl_msi_ext_dest_id;
}

static inline u64 hv_vtl_system_desc_base(struct ldttss_desc *desc)
{
	return ((u64)desc->base3 << 32) | ((u64)desc->base2 << 24) |
		(desc->base1 << 16) | desc->base0;
}

static inline u32 hv_vtl_system_desc_limit(struct ldttss_desc *desc)
{
	return ((u32)desc->limit1 << 16) | (u32)desc->limit0;
}

typedef void (*secondary_startup_64_fn)(void*, void*);
static void hv_vtl_ap_entry(void)
{
	((secondary_startup_64_fn)secondary_startup_64)(&boot_params, &boot_params);
}

static int hv_vtl_bringup_vcpu(u32 target_vp_index, int cpu, u64 eip_ignored)
{
	u64 status;
	int ret = 0;
	struct hv_enable_vp_vtl *input;
	unsigned long irq_flags;

	struct desc_ptr gdt_ptr;
	struct desc_ptr idt_ptr;

	struct ldttss_desc *tss;
	struct ldttss_desc *ldt;
	struct desc_struct *gdt;

	struct task_struct *idle = idle_thread_get(cpu);
	u64 rsp = (unsigned long)idle->thread.sp;

	u64 rip = (u64)&hv_vtl_ap_entry;

	native_store_gdt(&gdt_ptr);
	store_idt(&idt_ptr);

	gdt = (struct desc_struct *)((void *)(gdt_ptr.address));
	tss = (struct ldttss_desc *)(gdt + GDT_ENTRY_TSS);
	ldt = (struct ldttss_desc *)(gdt + GDT_ENTRY_LDT);

	local_irq_save(irq_flags);

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));

	input->partition_id = HV_PARTITION_ID_SELF;
	input->vp_index = target_vp_index;
	input->target_vtl.target_vtl = HV_VTL_MGMT;

	/*
	 * The x86_64 Linux kernel follows the 16-bit -> 32-bit -> 64-bit
	 * mode transition sequence after waking up an AP with SIPI whose
	 * vector points to the 16-bit AP startup trampoline code. Here in
	 * VTL2, we can't perform that sequence as the AP has to start in
	 * the 64-bit mode.
	 *
	 * To make this happen, we tell the hypervisor to load a valid 64-bit
	 * context (most of which is just magic numbers from the CPU manual)
	 * so that AP jumps right to the 64-bit entry of the kernel, and the
	 * control registers are loaded with values that let the AP fetch the
	 * code and data and carry on with work it gets assigned.
	 */

	input->vp_context.rip = rip;
	input->vp_context.rsp = rsp;
	input->vp_context.rflags = 0x0000000000000002;
	input->vp_context.efer = __rdmsr(MSR_EFER);
	input->vp_context.cr0 = native_read_cr0();
	input->vp_context.cr3 = __native_read_cr3();
	input->vp_context.cr4 = native_read_cr4();
	input->vp_context.msr_cr_pat = __rdmsr(MSR_IA32_CR_PAT);
	input->vp_context.idtr.limit = idt_ptr.size;
	input->vp_context.idtr.base = idt_ptr.address;
	input->vp_context.gdtr.limit = gdt_ptr.size;
	input->vp_context.gdtr.base = gdt_ptr.address;

	/* Non-system desc (64bit), long, code, present */
	input->vp_context.cs.selector = __KERNEL_CS;
	input->vp_context.cs.base = 0;
	input->vp_context.cs.limit = 0xffffffff;
	input->vp_context.cs.attributes = 0xa09b;
	/* Non-system desc (64bit), data, present, granularity, default */
	input->vp_context.ss.selector = __KERNEL_DS;
	input->vp_context.ss.base = 0;
	input->vp_context.ss.limit = 0xffffffff;
	input->vp_context.ss.attributes = 0xc093;

	/* System desc (128bit), present, LDT */
	input->vp_context.ldtr.selector = GDT_ENTRY_LDT * 8;
	input->vp_context.ldtr.base = hv_vtl_system_desc_base(ldt);
	input->vp_context.ldtr.limit = hv_vtl_system_desc_limit(ldt);
	input->vp_context.ldtr.attributes = 0x82;

	/* System desc (128bit), present, TSS, 0x8b - busy, 0x89 -- default */
	input->vp_context.tr.selector = GDT_ENTRY_TSS * 8;
	input->vp_context.tr.base = hv_vtl_system_desc_base(tss);
	input->vp_context.tr.limit = hv_vtl_system_desc_limit(tss);
	input->vp_context.tr.attributes = 0x8b;

	status = hv_do_hypercall(HVCALL_ENABLE_VP_VTL, input, NULL);

	if (!hv_result_success(status) &&
	    hv_result(status) != HV_STATUS_VTL_ALREADY_ENABLED) {
		pr_err("HVCALL_ENABLE_VP_VTL failed for VP : %d ! [Err: %#llx\n]",
		       target_vp_index, status);
		ret = -EINVAL;
		goto free_lock;
	}

	status = hv_do_hypercall(HVCALL_START_VP, input, NULL);

	if (!hv_result_success(status)) {
		pr_err("HVCALL_START_VP failed for VP : %d ! [Err: %#llx]\n",
		       target_vp_index, status);
		ret = -EINVAL;
	}

free_lock:
	local_irq_restore(irq_flags);

	return ret;
}

static int hv_vtl_bringup_tdx_vcpu(int vp_id, unsigned long start_eip)
{
	struct trampoline_context {
		u32 start_gate;

		u16 data_selector;
		u16 static_gdt_limit;
		u32 static_gdt_base;

		u16 task_selector;
		u16 idtr_limit;

		u64 idtr_base;

		u64 initial_rip;
		u16 code_selector;
		u16 padding_2[2];
		u16 gdtr_limit;
		u64 gdtr_base;

		u64 rsp;
		u64 rbp;
		u64 rsi;
		u64 r8;
		u64 r9;
		u64 r10;
		u64 r11;
		u64 cr0;
		u64 cr3;
		u64 cr4;
		u32 transition_cr3;
		u32 padding_3;

		u8 static_gdt[16];
	};

	u64 pa_context = 0xfffff000;
	struct trampoline_context *ctx;
	static DEFINE_MUTEX(reset_page_lock);
	u64 status;
	struct hv_enable_vp_vtl *input;
	unsigned long irq_flags;
	int ret;

	/* Map the trampoline page. */
	ctx = ioremap_encrypted(pa_context, sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;

	/*
	 * Ensure the hypervisor has started the processor, and that it
	 * is configured to run from VTL2.
	 */
	local_irq_save(irq_flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));
	input->partition_id = HV_PARTITION_ID_SELF;
	input->vp_index = vp_id;
	input->target_vtl.target_vtl = HV_VTL_MGMT;

	pr_info("enabling vtl2 for vp %d\n", vp_id);
	status = hv_do_hypercall(HVCALL_ENABLE_VP_VTL, input, NULL);
	if (!hv_result_success(status) &&
	    hv_result(status) != HV_STATUS_VTL_ALREADY_ENABLED) {
		pr_err("HVCALL_ENABLE_VP_VTL failed for VP : %d ! [Err: %#llx\n]",
		       vp_id, status);
		ret = -EINVAL;
		goto restore;
	}

	pr_info("starting vtl2 for vp %d\n", vp_id);
	status = hv_do_hypercall(HVCALL_START_VP, input, NULL);
	if (!hv_result_success(status)) {
		pr_err("HVCALL_START_VP failed for VP : %d ! [Err: %#llx]\n",
		       vp_id, status);
		ret = -EINVAL;
		goto restore;
	}

	ret = 0;

restore:
	local_irq_restore(irq_flags);
	if (ret) {
		iounmap(ctx);
		return ret;
	}

	/* Use the reset page to provide the initial context. */
	mutex_lock(&reset_page_lock);
	BUG_ON(ctx->start_gate != 0);
	ctx->gdtr_limit = 0;
	ctx->idtr_limit = 0;
	ctx->code_selector = 0;
	ctx->task_selector = 0;
	ctx->transition_cr3 = hv_tdx_trampoline_cr3;
	ctx->cr3 = hv_tdx_trampoline_cr3;
	ctx->cr0 = X86_CR0_PE | X86_CR0_PG | X86_CR0_NE;
	ctx->cr4 = X86_CR4_PAE | X86_CR4_MCE;
	ctx->r8 = pa_context;
	ctx->r9 = start_eip;
	ctx->initial_rip = __pa(hv_tdx_trampoline);
	smp_store_release(&ctx->start_gate, vp_id);

	/* Wait for the AP to read the context from the reset page. */
	while (smp_load_acquire(&ctx->start_gate) != 0)
		cpu_relax();
	mutex_unlock(&reset_page_lock);
	iounmap(ctx);
	return 0;
}

static int hv_vtl_wakeup_secondary_cpu(int apicid, unsigned long start_eip)
{
	int vp_id, cpu;

	/* Find the logical CPU for the APIC ID */
	for_each_present_cpu(cpu) {
		if (arch_match_cpu_phys_id(cpu, apicid))
			break;
	}
	if (cpu >= nr_cpu_ids)
		return -EINVAL;

	pr_debug("Bringing up CPU with APIC ID %d in VTL2...\n", apicid);
	/* TODO TDX: we cannot trust the hypervisor to perform this mapping...
		Instead, we need hypervisor support for TDX 1.5 ENUM_TOPOLOGY to query
		this directly from the tdx module. */
	vp_id = hv_apicid_to_vp_id(apicid);

	if (vp_id < 0) {
		pr_err("Couldn't find CPU with APIC ID %d\n", apicid);
		return -EINVAL;
	}
	if (vp_id > ms_hyperv.max_vp_index) {
		pr_err("Invalid CPU id %d for APIC ID %d\n", vp_id, apicid);
		return -EINVAL;
	}

	if (hv_isolation_type_tdx())
		return hv_vtl_bringup_tdx_vcpu(vp_id, start_eip);
	else
		return hv_vtl_bringup_vcpu(vp_id, cpu, start_eip);
}

int __init hv_vtl_early_init(void)
{
	/*
	 * `boot_cpu_has` returns the runtime feature support,
	 * and here is the earliest it can be used.
	 */
	if (cpu_feature_enabled(X86_FEATURE_XSAVE))
		panic("XSAVE has to be disabled as it is not supported by this module.\n"
			  "Please add 'noxsave' to the kernel command line.\n");

	/* For hardware-isolated VMs, use the common VP startup path.
	   Otherwise, use an enlightened path since SIPI is not
	   available for VTL2. */
	if (!hv_isolation_type_en_snp())
		apic_update_callback(wakeup_secondary_cpu_64, hv_vtl_wakeup_secondary_cpu);



	return 0;
}
