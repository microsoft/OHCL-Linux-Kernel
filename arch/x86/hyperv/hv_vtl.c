// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * Author:
 *   Saurabh Sengar <ssengar@microsoft.com>
 */

#include <linux/acpi.h>

#include <asm/acpi.h>
#include <asm/apic.h>
#include <asm/boot.h>
#include <asm/desc.h>
#include <asm/fpu/api.h>
#include <asm/fpu/types.h>
#include <asm/i8259.h>
#include <asm/mshyperv.h>
#include <asm/msr.h>
#include <asm/realmode.h>
#include <asm/reboot.h>
#include <asm/smap.h>
#include <asm/fpu/xcr.h>
#include <asm/realmode.h>
#include <asm/tdx.h>
#include <asm/smap.h>
#include <asm/sev.h>
#include <uapi/asm/mtrr.h>
#include <asm/debugreg.h>
#include <linux/export.h>
#include <../kernel/smpboot.h>
#include "../../kernel/fpu/legacy.h"
#include "../../drivers/hv/mshv_vtl.h"

extern struct boot_params boot_params;
static struct real_mode_header hv_vtl_real_mode_header;

static bool __init hv_vtl_msi_ext_dest_id(void)
{
	return true;
}

/*
 * The `native_machine_emergency_restart` function from `reboot.c` writes
 * to the physical address 0x472 to indicate the type of reboot for the
 * firmware. We cannot have that in VSM as the memory composition might
 * be more generic, and such write effectively corrupts the memory thus
 * making diagnostics harder at the very least.
 */
static void  __noreturn hv_vtl_emergency_restart(void)
{
	/*
	 * Cause a triple fault and the immediate reset. Here the code does not run
	 * on the top of any firmware, whereby cannot reach out to its services.
	 * The inifinite loop is for the improbable case that the triple fault does
	 * not work and have to preserve the state intact for debugging.
	 */
	for (;;) {
		idt_invalidate();
		__asm__ __volatile__("int3");
	}
}

static inline bool within_page(u64 addr, u64 start)
{
	return addr >= start && addr < (start + PAGE_SIZE);
}

static bool hv_vtl_is_private_mmio_tdx(u64 addr)
{
	u64 mb_addr = acpi_get_mp_wakeup_mailbox_paddr();

	return mb_addr && within_page(addr, mb_addr);
}

void __init hv_vtl_init_platform(void)
{
	/*
	 * This function is a no-op if the VTL mode is not enabled.
	 * If it is, this function runs if and only the kernel boots in
	 * VTL2 which the x86 hv initialization path makes sure of.
	 */
	pr_info("Linux runs in Hyper-V Virtual Trust Level %d\n", ms_hyperv.vtl);

	/*
	 * Disable TSC_ADJUST so that the periodic TSC sync check timer
	 * (start_sync_check_timer) and related TSC adjustment logic are
	 * skipped. The TSC exposed via Hyper-V will be consistent across
	 * processors.
	 */
	setup_clear_cpu_cap(X86_FEATURE_TSC_ADJUST);

	/* There is no paravisor present if we are here. */
	if (hv_isolation_type_tdx()) {
		x86_init.resources.realmode_limit = SZ_4G;
		x86_platform.hyper.is_private_mmio = hv_vtl_is_private_mmio_tdx;

	} else {
		x86_platform.realmode_reserve = x86_init_noop;
		x86_platform.realmode_init = x86_init_noop;
		real_mode_header = &hv_vtl_real_mode_header;
	}
	x86_init.irqs.pre_vector_init = x86_init_noop;
	x86_init.timers.timer_init = x86_init_noop;
	x86_init.resources.probe_roms = x86_init_noop;

	/* Avoid searching for BIOS MP tables */
	x86_init.mpparse.find_mptable = x86_init_noop;
	x86_init.mpparse.early_parse_smp_cfg = x86_init_noop;

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
	input->vp_context.efer = native_rdmsrq(MSR_EFER);
	input->vp_context.cr0 = native_read_cr0();
	input->vp_context.cr3 = __native_read_cr3();
	input->vp_context.cr4 = native_read_cr4();
	input->vp_context.msr_cr_pat = native_rdmsrq(MSR_IA32_CR_PAT);
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

static int hv_vtl_wakeup_secondary_cpu(u32 apicid, unsigned long start_eip, unsigned int cpu)
{
	int vp_index;

	pr_debug("Bringing up CPU with APIC ID %d in VTL2...\n", apicid);

	/*
	 * TODO TDX: we cannot trust the hypervisor to perform this mapping...
	 * Instead, we need hypervisor support for TDX 1.5 ENUM_TOPOLOGY to
	 * query this directly from the TDX module.
	 */
	vp_index = hv_apicid_to_vp_index(apicid);
	if (vp_index < 0) {
		pr_err("Couldn't find CPU with APIC ID %d\n", apicid);
		return -EINVAL;
	}
	if (vp_index > ms_hyperv.max_vp_index) {
		pr_err("Invalid CPU id %d for APIC ID %d\n", vp_index, apicid);
		return -EINVAL;
	}

	return hv_vtl_bringup_vcpu(vp_index, cpu, start_eip);
}

/*
 * The only way to restart in the VTL mode is to triple fault as the kernel runs
 * as firmware.
 */
static void  __noreturn hv_vtl_restart(char __maybe_unused *cmd)
{
       hv_vtl_emergency_restart();
}

int __init hv_vtl_early_init(void)
{
	machine_ops.emergency_restart = hv_vtl_emergency_restart;
	machine_ops.restart = hv_vtl_restart;

	/*
	 * `boot_cpu_has` returns the runtime feature support,
	 * and here is the earliest it can be used.
	 */
	if (cpu_feature_enabled(X86_FEATURE_XSAVE))
		panic("XSAVE has to be disabled as it is not supported by this module.\n"
			  "Please add 'noxsave' to the kernel command line.\n");

	/*
	 * For hardware-isolated VMs, use the common VP startup path.
	 * Otherwise, use an enlightened path since SIPI is not
	 * available for VTL2.
	 */
	if (!((hv_isolation_type_snp() || hv_isolation_type_tdx()) &&
	      !ms_hyperv.paravisor_present))
		apic_update_callback(wakeup_secondary_cpu_64, hv_vtl_wakeup_secondary_cpu);

	return 0;
}

DEFINE_STATIC_CALL_NULL(__mshv_vtl_return_hypercall, void (*)(void));

static u64 vtl_return_addr;

void mshv_tdx_request_cache_flush(bool wbnoinvd);
noinline void mshv_vtl_return_tdx(void);

void mshv_vtl_return_call_init(u64 vtl_return_offset)
{
	vtl_return_addr = (u64)((u8 *)hv_hypercall_pg + vtl_return_offset);
	static_call_update(__mshv_vtl_return_hypercall,
			   (void *)vtl_return_addr);
}
EXPORT_SYMBOL(mshv_vtl_return_call_init);

void mshv_vtl_return_call(struct mshv_vtl_cpu_context *vtl0)
{
	struct hv_vp_assist_page *hvp;
	u64 hypercall_addr;

	register u64 r8 asm("r8");
	register u64 r9 asm("r9");
	register u64 r10 asm("r10");
	register u64 r11 asm("r11");
	register u64 r12 asm("r12");
	register u64 r13 asm("r13");
	register u64 r14 asm("r14");
	register u64 r15 asm("r15");

	hvp = hv_vp_assist_page[smp_processor_id()];
	hvp->vtl_ret_x64rax = vtl0->rax;
	hvp->vtl_ret_x64rcx = vtl0->rcx;

	hypercall_addr = vtl_return_addr;

	kernel_fpu_begin_mask(0);
	fxrstor(&vtl0->fx_state);
	native_write_cr2(vtl0->cr2);
	r8 = vtl0->r8;
	r9 = vtl0->r9;
	r10 = vtl0->r10;
	r11 = vtl0->r11;
	r12 = vtl0->r12;
	r13 = vtl0->r13;
	r14 = vtl0->r14;
	r15 = vtl0->r15;

	asm __volatile__ (	\
	/* Save rbp pointer to the lower VTL, keep the stack 16-byte aligned */
		"pushq	%%rbp\n"
		"pushq	%%rcx\n"
	/* Restore the lower VTL's rbp */
		"movq	(%%rcx), %%rbp\n"
	/* Load return kind into rcx (HV_VTL_RETURN_INPUT_NORMAL_RETURN == 0) */
		"xorl	%%ecx, %%ecx\n"
	/* Transition to the lower VTL */
		CALL_NOSPEC
	/* Save VTL0's rax and rcx temporarily on 16-byte aligned stack */
		"pushq	%%rax\n"
		"pushq	%%rcx\n"
	/* Restore pointer to lower VTL rbp */
		"movq	16(%%rsp), %%rax\n"
	/* Save the lower VTL's rbp */
		"movq	%%rbp, (%%rax)\n"
	/* Restore saved registers */
		"movq	8(%%rsp), %%rax\n"
		"movq	24(%%rsp), %%rbp\n"
		"addq	$32, %%rsp\n"

		: "=a"(vtl0->rax), "=c"(vtl0->rcx),
		  "+d"(vtl0->rdx), "+b"(vtl0->rbx), "+S"(vtl0->rsi), "+D"(vtl0->rdi),
		  "+r"(r8), "+r"(r9), "+r"(r10), "+r"(r11),
		  "+r"(r12), "+r"(r13), "+r"(r14), "+r"(r15)
		: THUNK_TARGET(hypercall_addr), "c"(&vtl0->rbp)
		: "cc", "memory");

	vtl0->r8 = r8;
	vtl0->r9 = r9;
	vtl0->r10 = r10;
	vtl0->r11 = r11;
	vtl0->r12 = r12;
	vtl0->r13 = r13;
	vtl0->r14 = r14;
	vtl0->r15 = r15;
	vtl0->cr2 = native_read_cr2();

	fxsave(&vtl0->fx_state);
	kernel_fpu_end();
}
EXPORT_SYMBOL(mshv_vtl_return_call);

/* Static table mapping register names to their corresponding actions */
static const struct {
	enum hv_register_name reg_name;
	int debug_reg_num;  /* -1 if not a debug register */
	u32 msr_addr;       /* 0 if not an MSR */
} reg_table[] = {
	/* Debug registers */
	{HV_X64_REGISTER_DR0, 0, 0},
	{HV_X64_REGISTER_DR1, 1, 0},
	{HV_X64_REGISTER_DR2, 2, 0},
	{HV_X64_REGISTER_DR3, 3, 0},
	{HV_X64_REGISTER_DR6, 6, 0},
	/* MTRR MSRs */
	{HV_X64_REGISTER_MSR_MTRR_CAP, -1, MSR_MTRRcap},
	{HV_X64_REGISTER_MSR_MTRR_DEF_TYPE, -1, MSR_MTRRdefType},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_BASE0, -1, MTRRphysBase_MSR(0)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_BASE1, -1, MTRRphysBase_MSR(1)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_BASE2, -1, MTRRphysBase_MSR(2)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_BASE3, -1, MTRRphysBase_MSR(3)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_BASE4, -1, MTRRphysBase_MSR(4)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_BASE5, -1, MTRRphysBase_MSR(5)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_BASE6, -1, MTRRphysBase_MSR(6)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_BASE7, -1, MTRRphysBase_MSR(7)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_BASE8, -1, MTRRphysBase_MSR(8)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_BASE9, -1, MTRRphysBase_MSR(9)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_BASEA, -1, MTRRphysBase_MSR(0xa)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_BASEB, -1, MTRRphysBase_MSR(0xb)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_BASEC, -1, MTRRphysBase_MSR(0xc)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_BASED, -1, MTRRphysBase_MSR(0xd)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_BASEE, -1, MTRRphysBase_MSR(0xe)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_BASEF, -1, MTRRphysBase_MSR(0xf)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_MASK0, -1, MTRRphysMask_MSR(0)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_MASK1, -1, MTRRphysMask_MSR(1)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_MASK2, -1, MTRRphysMask_MSR(2)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_MASK3, -1, MTRRphysMask_MSR(3)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_MASK4, -1, MTRRphysMask_MSR(4)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_MASK5, -1, MTRRphysMask_MSR(5)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_MASK6, -1, MTRRphysMask_MSR(6)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_MASK7, -1, MTRRphysMask_MSR(7)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_MASK8, -1, MTRRphysMask_MSR(8)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_MASK9, -1, MTRRphysMask_MSR(9)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_MASKA, -1, MTRRphysMask_MSR(0xa)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_MASKB, -1, MTRRphysMask_MSR(0xb)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_MASKC, -1, MTRRphysMask_MSR(0xc)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_MASKD, -1, MTRRphysMask_MSR(0xd)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_MASKE, -1, MTRRphysMask_MSR(0xe)},
	{HV_X64_REGISTER_MSR_MTRR_PHYS_MASKF, -1, MTRRphysMask_MSR(0xf)},
	{HV_X64_REGISTER_MSR_MTRR_FIX64K00000, -1, MSR_MTRRfix64K_00000},
	{HV_X64_REGISTER_MSR_MTRR_FIX16K80000, -1, MSR_MTRRfix16K_80000},
	{HV_X64_REGISTER_MSR_MTRR_FIX16KA0000, -1, MSR_MTRRfix16K_A0000},
	{HV_X64_REGISTER_MSR_MTRR_FIX4KC0000, -1, MSR_MTRRfix4K_C0000},
	{HV_X64_REGISTER_MSR_MTRR_FIX4KC8000, -1, MSR_MTRRfix4K_C8000},
	{HV_X64_REGISTER_MSR_MTRR_FIX4KD0000, -1, MSR_MTRRfix4K_D0000},
	{HV_X64_REGISTER_MSR_MTRR_FIX4KD8000, -1, MSR_MTRRfix4K_D8000},
	{HV_X64_REGISTER_MSR_MTRR_FIX4KE0000, -1, MSR_MTRRfix4K_E0000},
	{HV_X64_REGISTER_MSR_MTRR_FIX4KE8000, -1, MSR_MTRRfix4K_E8000},
	{HV_X64_REGISTER_MSR_MTRR_FIX4KF0000, -1, MSR_MTRRfix4K_F0000},
	{HV_X64_REGISTER_MSR_MTRR_FIX4KF8000, -1, MSR_MTRRfix4K_F8000},
	/* Control Registers */
	{HV_X64_REGISTER_XFEM, -1, MSR_MTRRfix4K_F8000},
};

int mshv_vtl_get_set_reg(struct hv_register_assoc *regs, bool set, u64 shared)
{
	u64 *reg64;
	enum hv_register_name gpr_name;
	int i;

	gpr_name = regs->name;
	reg64 = &regs->value.reg64;

	/* Search for the register in the table */
	for (i = 0; i < ARRAY_SIZE(reg_table); i++) {
		if (reg_table[i].reg_name != gpr_name)
			continue;
		if (reg_table[i].debug_reg_num != -1) {
			/* Handle debug registers */
			if (gpr_name == HV_X64_REGISTER_DR6 && !shared)
				goto hypercall;
			if (set)
				native_set_debugreg(reg_table[i].debug_reg_num, *reg64);
			else
				*reg64 = native_get_debugreg(reg_table[i].debug_reg_num);
		} else {
			if (gpr_name == HV_X64_REGISTER_XFEM) {
				u64 cr4;

				if (!hv_isolation_type_tdx())
					return -EINVAL;

				cr4 = native_read_cr4();
				WARN_ON_ONCE(cr4 & X86_CR4_OSXSAVE);

				/* Briefly enable xsave in order to access xcr0. */
				native_write_cr4(cr4 | X86_CR4_OSXSAVE);

				/* The xsetbv may fault. Right now we trust user mode. */
				if (set)
					xsetbv(0, *reg64);
				else
					*reg64 = xgetbv(0);

				native_write_cr4(cr4);

				return 0;
			}

			/* Handle MSRs */
			if (set)
				wrmsrl(reg_table[i].msr_addr, *reg64);
			else
				rdmsrl(reg_table[i].msr_addr, *reg64);
		}
		return 0;
	}

hypercall:
	return 1;
}
EXPORT_SYMBOL_GPL(mshv_vtl_get_set_reg);
