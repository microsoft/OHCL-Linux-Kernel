// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * Author:
 *   Saurabh Sengar <ssengar@microsoft.com>
 */

#include <asm/apic.h>
#include <asm/boot.h>
#include <asm/debugreg.h>
#include <asm/desc.h>
#include <asm/i8259.h>
#include <asm/smap.h>
#include <asm/fpu/api.h>
#include <asm/fpu/types.h>
#include <asm/fpu/xcr.h>
#include <asm/realmode.h>
#include <asm/tdx.h>
#include <asm/reboot.h>
#include <asm/sev.h>
#include <uapi/asm/mtrr.h>

#include <../kernel/smpboot.h>
#include "../../kernel/fpu/legacy.h"
#include "../../drivers/hv/mshv_vtl.h"

#include <asm/mshyperv.h>
#include <uapi/hyperv/hvgdk.h>

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

/*
 * The only way to restart in the VTL mode is to triple fault as the kernel runs
 * as firmware.
 */
static void  __noreturn hv_vtl_restart(char __maybe_unused *cmd)
{
	hv_vtl_emergency_restart();
}

void __init hv_vtl_init_platform(void)
{
	pr_info("Linux runs in Hyper-V Virtual Trust Level\n");

	x86_init.resources.probe_roms = x86_init_noop;
	x86_platform.realmode_reserve = x86_init_noop;
	x86_platform.realmode_init = x86_init_noop;
	real_mode_header = &hv_vtl_real_mode_header;
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

static int hv_vtl_wakeup_secondary_cpu(u32 apicid, unsigned long start_eip, unsigned int cpu)
{
	int vp_index;

	pr_debug("Bringing up CPU with APIC ID %d in VTL2...\n", apicid);
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
	if (!(hv_isolation_type_snp() && !hyperv_paravisor_present))
		apic_update_callback(wakeup_secondary_cpu_64, hv_vtl_wakeup_secondary_cpu);

	return 0;
}

void mshv_tdx_request_cache_flush(bool wbnoinvd);
noinline void mshv_vtl_return_tdx(void);
struct mshv_vtl_run *mshv_vtl_this_run(void);

void hv_vtl_return(struct hv_vtl_cpu_context *vtl0, union hv_input_vtl target_vtl, u32 flags, u64 vtl_return_offset)
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

	if (hv_isolation_type_tdx()) {
#if defined(CONFIG_INTEL_TDX_GUEST)
		/* Read and clear tdx specific flags set by usermode. */
		u64 tdx_flags = READ_ONCE(mshv_vtl_this_run()->tdx_context.vp_state.flags);
		mshv_vtl_this_run()->tdx_context.vp_state.flags = 0;

		/*
		 * Clear RAX to an exit (PENDING_INTERRUPT) that the usermode
		 * VMM will do nothing, if we are halting.
		 */
		mshv_vtl_this_run()->tdx_context.exit_info.rax = 0x112000000000;

		/* Handle any flags set by usermode. */
		if (unlikely(tdx_flags)) {
			/* Handle any cache invalidation requests from usermode. */
			if (tdx_flags & MSHV_VTL_TDX_VP_STATE_FLAG_WBINVD)
				mshv_tdx_request_cache_flush(false);
			else if (tdx_flags & MSHV_VTL_TDX_VP_STATE_FLAG_WBNOINVD)
				mshv_tdx_request_cache_flush(true);
		}

		if (unlikely(flags & MSHV_VTL_RUN_FLAG_HALTED)) {
			tdx_halt();
		} else {
			/* Only supports VTL0 */
			mshv_vtl_return_tdx();
		}
		return;
#endif
	} else if (hv_isolation_type_snp()) {
#if defined(CONFIG_SEV_GUEST)
		if (unlikely(flags & MSHV_VTL_RUN_FLAG_HALTED))
			native_safe_halt();
		else
			snp_mshv_vtl_return(target_vtl.use_target_vtl ? target_vtl.target_vtl : 0);
		return;
#endif
	}

	hvp = hv_vp_assist_page[smp_processor_id()];

	hvp->vtl_ret_x64rax = vtl0->rax;
	hvp->vtl_ret_x64rcx = vtl0->rcx;

	hypercall_addr = (u64)((u8 *)hv_hypercall_pg + vtl_return_offset);

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
EXPORT_SYMBOL_GPL(hv_vtl_return);

/*
 * Set the register. If the function returns `1`, that must be done via
 * a hypercall. Returning `0` means success.
 */
int hv_vtl_set_reg(struct hv_register_assoc *regs, bool shared)
{
	u64 reg64;
	enum hv_register_name gpr_name;

	gpr_name = regs->name;
	reg64 = regs->value.reg64;

	switch (gpr_name) {
	case HV_X64_REGISTER_DR0:
		native_set_debugreg(0, reg64);
		break;
	case HV_X64_REGISTER_DR1:
		native_set_debugreg(1, reg64);
		break;
	case HV_X64_REGISTER_DR2:
		native_set_debugreg(2, reg64);
		break;
	case HV_X64_REGISTER_DR3:
		native_set_debugreg(3, reg64);
		break;
	case HV_X64_REGISTER_DR6:
		if (!shared)
			return 1;
		native_set_debugreg(6, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_CAP:
		wrmsrl(MSR_MTRRcap, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_DEF_TYPE:
		wrmsrl(MSR_MTRRdefType, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE0:
		wrmsrl(MTRRphysBase_MSR(0), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE1:
		wrmsrl(MTRRphysBase_MSR(1), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE2:
		wrmsrl(MTRRphysBase_MSR(2), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE3:
		wrmsrl(MTRRphysBase_MSR(3), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE4:
		wrmsrl(MTRRphysBase_MSR(4), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE5:
		wrmsrl(MTRRphysBase_MSR(5), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE6:
		wrmsrl(MTRRphysBase_MSR(6), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE7:
		wrmsrl(MTRRphysBase_MSR(7), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE8:
		wrmsrl(MTRRphysBase_MSR(8), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE9:
		wrmsrl(MTRRphysBase_MSR(9), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASEA:
		wrmsrl(MTRRphysBase_MSR(0xa), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASEB:
		wrmsrl(MTRRphysBase_MSR(0xb), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASEC:
		wrmsrl(MTRRphysBase_MSR(0xc), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASED:
		wrmsrl(MTRRphysBase_MSR(0xd), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASEE:
		wrmsrl(MTRRphysBase_MSR(0xe), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASEF:
		wrmsrl(MTRRphysBase_MSR(0xf), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK0:
		wrmsrl(MTRRphysMask_MSR(0), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK1:
		wrmsrl(MTRRphysMask_MSR(1), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK2:
		wrmsrl(MTRRphysMask_MSR(2), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK3:
		wrmsrl(MTRRphysMask_MSR(3), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK4:
		wrmsrl(MTRRphysMask_MSR(4), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK5:
		wrmsrl(MTRRphysMask_MSR(5), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK6:
		wrmsrl(MTRRphysMask_MSR(6), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK7:
		wrmsrl(MTRRphysMask_MSR(7), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK8:
		wrmsrl(MTRRphysMask_MSR(8), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK9:
		wrmsrl(MTRRphysMask_MSR(9), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKA:
		wrmsrl(MTRRphysMask_MSR(0xa), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKB:
		wrmsrl(MTRRphysMask_MSR(0xa), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKC:
		wrmsrl(MTRRphysMask_MSR(0xc), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKD:
		wrmsrl(MTRRphysMask_MSR(0xd), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKE:
		wrmsrl(MTRRphysMask_MSR(0xe), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKF:
		wrmsrl(MTRRphysMask_MSR(0xf), reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX64K00000:
		wrmsrl(MSR_MTRRfix64K_00000, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX16K80000:
		wrmsrl(MSR_MTRRfix16K_80000, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX16KA0000:
		wrmsrl(MSR_MTRRfix16K_A0000, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KC0000:
		wrmsrl(MSR_MTRRfix4K_C0000, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KC8000:
		wrmsrl(MSR_MTRRfix4K_C8000, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KD0000:
		wrmsrl(MSR_MTRRfix4K_D0000, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KD8000:
		wrmsrl(MSR_MTRRfix4K_D8000, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KE0000:
		wrmsrl(MSR_MTRRfix4K_E0000, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KE8000:
		wrmsrl(MSR_MTRRfix4K_E8000, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KF0000:
		wrmsrl(MSR_MTRRfix4K_F0000, reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KF8000:
		wrmsrl(MSR_MTRRfix4K_F8000, reg64);
		break;
	case HV_X64_REGISTER_XFEM:
		if (!hv_isolation_type_tdx())
			return -EINVAL;

		/* Briefly enable xsave in order to access xcr0. */
		u64 cr4 = native_read_cr4();

		WARN_ON_ONCE(cr4 & X86_CR4_OSXSAVE);
		native_write_cr4(cr4 | X86_CR4_OSXSAVE);
		/* This may fault. Right now we trust user mode. */
		xsetbv(0, reg64);
		native_write_cr4(cr4);

		break;

	default:
		return 1;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(hv_vtl_set_reg);

/*
 * Get the register. If the function returns `1`, that must be done via
 * a hypercall. Returning `0` means success.
 */
int hv_vtl_get_reg(struct hv_register_assoc *regs, bool shared)
{
	u64 *reg64;
	enum hv_register_name gpr_name;

	gpr_name = regs->name;
	reg64 = (u64 *)&regs->value.reg64;

	switch (gpr_name) {
	case HV_X64_REGISTER_DR0:
		*reg64 = native_get_debugreg(0);
		break;
	case HV_X64_REGISTER_DR1:
		*reg64 = native_get_debugreg(1);
		break;
	case HV_X64_REGISTER_DR2:
		*reg64 = native_get_debugreg(2);
		break;
	case HV_X64_REGISTER_DR3:
		*reg64 = native_get_debugreg(3);
		break;
	case HV_X64_REGISTER_DR6:
		if (!shared)
			return 1;
		*reg64 = native_get_debugreg(6);
		break;
	case HV_X64_REGISTER_MSR_MTRR_CAP:
		rdmsrl(MSR_MTRRcap, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_DEF_TYPE:
		rdmsrl(MSR_MTRRdefType, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE0:
		rdmsrl(MTRRphysBase_MSR(0), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE1:
		rdmsrl(MTRRphysBase_MSR(1), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE2:
		rdmsrl(MTRRphysBase_MSR(2), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE3:
		rdmsrl(MTRRphysBase_MSR(3), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE4:
		rdmsrl(MTRRphysBase_MSR(4), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE5:
		rdmsrl(MTRRphysBase_MSR(5), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE6:
		rdmsrl(MTRRphysBase_MSR(6), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE7:
		rdmsrl(MTRRphysBase_MSR(7), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE8:
		rdmsrl(MTRRphysBase_MSR(8), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASE9:
		rdmsrl(MTRRphysBase_MSR(9), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASEA:
		rdmsrl(MTRRphysBase_MSR(0xa), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASEB:
		rdmsrl(MTRRphysBase_MSR(0xb), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASEC:
		rdmsrl(MTRRphysBase_MSR(0xc), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASED:
		rdmsrl(MTRRphysBase_MSR(0xd), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASEE:
		rdmsrl(MTRRphysBase_MSR(0xe), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_BASEF:
		rdmsrl(MTRRphysBase_MSR(0xf), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK0:
		rdmsrl(MTRRphysMask_MSR(0), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK1:
		rdmsrl(MTRRphysMask_MSR(1), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK2:
		rdmsrl(MTRRphysMask_MSR(2), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK3:
		rdmsrl(MTRRphysMask_MSR(3), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK4:
		rdmsrl(MTRRphysMask_MSR(4), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK5:
		rdmsrl(MTRRphysMask_MSR(5), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK6:
		rdmsrl(MTRRphysMask_MSR(6), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK7:
		rdmsrl(MTRRphysMask_MSR(7), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK8:
		rdmsrl(MTRRphysMask_MSR(8), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASK9:
		rdmsrl(MTRRphysMask_MSR(9), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKA:
		rdmsrl(MTRRphysMask_MSR(0xa), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKB:
		rdmsrl(MTRRphysMask_MSR(0xb), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKC:
		rdmsrl(MTRRphysMask_MSR(0xc), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKD:
		rdmsrl(MTRRphysMask_MSR(0xd), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKE:
		rdmsrl(MTRRphysMask_MSR(0xe), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_PHYS_MASKF:
		rdmsrl(MTRRphysMask_MSR(0xf), *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX64K00000:
		rdmsrl(MSR_MTRRfix64K_00000, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX16K80000:
		rdmsrl(MSR_MTRRfix16K_80000, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX16KA0000:
		rdmsrl(MSR_MTRRfix16K_A0000, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KC0000:
		rdmsrl(MSR_MTRRfix4K_C0000, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KC8000:
		rdmsrl(MSR_MTRRfix4K_C8000, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KD0000:
		rdmsrl(MSR_MTRRfix4K_D0000, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KD8000:
		rdmsrl(MSR_MTRRfix4K_D8000, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KE0000:
		rdmsrl(MSR_MTRRfix4K_E0000, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KE8000:
		rdmsrl(MSR_MTRRfix4K_E8000, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KF0000:
		rdmsrl(MSR_MTRRfix4K_F0000, *reg64);
		break;
	case HV_X64_REGISTER_MSR_MTRR_FIX4KF8000:
		rdmsrl(MSR_MTRRfix4K_F8000, *reg64);
		break;
	case HV_X64_REGISTER_XFEM:
		if (!hv_isolation_type_tdx())
			return -EINVAL;

		/* Briefly enable xsave in order to access xcr0. */
		u64 cr4 = native_read_cr4();

		WARN_ON_ONCE(cr4 & X86_CR4_OSXSAVE);
		native_write_cr4(cr4 | X86_CR4_OSXSAVE);
		*reg64 = xgetbv(0);
		native_write_cr4(cr4);

		break;

	default:
		return 1;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(hv_vtl_get_reg);
