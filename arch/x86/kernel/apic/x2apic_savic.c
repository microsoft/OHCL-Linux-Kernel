// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Secure AVIC Support (SEV-SNP Guests)
 *
 * Copyright (C) 2024 Advanced Micro Devices, Inc.
 *
 * Author: Neeraj Upadhyay <Neeraj.Upadhyay@amd.com>
 */

#include <linux/cc_platform.h>
#include <linux/cpumask.h>
#include <linux/percpu-defs.h>
#include <linux/align.h>

#include <asm/apic.h>
#include <asm/sev.h>
#include <asm/mshyperv.h>

#include "local.h"

static struct apic_page __percpu *apic_page __ro_after_init;

static inline void savic_wr_control_msr(u64 val)
{
	native_wrmsr(MSR_AMD64_SECURE_AVIC_CONTROL, lower_32_bits(val), upper_32_bits(val));
}

static int savic_acpi_madt_oem_check(char *oem_id, char *oem_table_id)
{
	return x2apic_enabled() && cc_platform_has(CC_ATTR_SNP_SECURE_AVIC);
}

static inline void *get_reg_bitmap(unsigned int cpu, unsigned int offset)
{
	struct apic_page *ap = per_cpu_ptr(apic_page, cpu);

	return &ap->bytes[offset];
}

static inline void update_vector(unsigned int cpu, unsigned int offset,
				 unsigned int vector, bool set)
{
	void *bitmap = get_reg_bitmap(cpu, offset);

	if (set)
		apic_set_vector(vector, bitmap);
	else
		apic_clear_vector(vector, bitmap);
}

#define SAVIC_ALLOWED_IRR	0x204

static u32 savic_read(u32 reg)
{
	struct apic_page *ap = this_cpu_ptr(apic_page);

	/*
	 * When Secure AVIC is enabled, rdmsr/wrmsr of APIC registers
	 * result in VC exception (for non-accelerated register accesses)
	 * with VMEXIT_AVIC_NOACCEL error code. The VC exception handler
	 * can read/write the x2APIC register in the guest APIC backing page.
	 * Since doing this would increase the latency of accessing x2APIC
	 * registers, instead of doing rdmsr/wrmsr based accesses and
	 * handling apic register reads/writes in VC exception, the read()
	 * and write() callbacks directly read/write APIC register from/to
	 * the vCPU APIC backing page.
	 */
	switch (reg) {
	case APIC_LVTT:
	case APIC_TMICT:
	case APIC_TMCCT:
	case APIC_TDCR:
		return savic_ghcb_msr_read(reg);
	case APIC_ID:
	case APIC_LVR:
	case APIC_TASKPRI:
	case APIC_ARBPRI:
	case APIC_PROCPRI:
	case APIC_LDR:
	case APIC_SPIV:
	case APIC_ESR:
	case APIC_LVTTHMR:
	case APIC_LVTPC:
	case APIC_LVT0:
	case APIC_LVT1:
	case APIC_LVTERR:
	case APIC_EFEAT:
	case APIC_ECTRL:
	case APIC_SEOI:
	case APIC_IER:
	case APIC_EILVTn(0) ... APIC_EILVTn(3):
		return apic_get_reg(ap, reg);
	case APIC_ICR:
		return (u32) apic_get_reg64(ap, reg);
	case APIC_ISR ... APIC_ISR + 0x70:
	case APIC_TMR ... APIC_TMR + 0x70:
		if (WARN_ONCE(!IS_ALIGNED(reg, 16),
			      "APIC reg read offset 0x%x not aligned at 16 bytes", reg))
			return 0;
		return apic_get_reg(ap, reg);
	/* IRR and ALLOWED_IRR offset range */
	case APIC_IRR ... APIC_IRR + 0x74:
		/*
		 * Either aligned at 16 bytes for valid IRR reg offset or a
		 * valid Secure AVIC ALLOWED_IRR offset.
		 */
		if (WARN_ONCE(!(IS_ALIGNED(reg, 16) ||
				IS_ALIGNED(reg - SAVIC_ALLOWED_IRR, 16)),
			      "Misaligned IRR/ALLOWED_IRR APIC reg read offset 0x%x", reg))
			return 0;
		return apic_get_reg(ap, reg);
	default:
		pr_err("Permission denied: read of Secure AVIC reg offset 0x%x\n", reg);
		return 0;
	}
}

#define SAVIC_NMI_REQ		0x278

static inline void self_ipi_reg_write(unsigned int vector)
{
	/*
	 * Secure AVIC hardware accelerates guest's MSR write to SELF_IPI
	 * register. It updates the IRR in the APIC backing page, evaluates
	 * the new IRR for interrupt injection and continues with guest
	 * code execution.
	 */
	native_apic_msr_write(APIC_SELF_IPI, vector);
}

static void send_ipi_dest(unsigned int cpu, unsigned int vector, bool nmi)
{
	if (nmi) {
		struct apic_page *ap = per_cpu_ptr(apic_page, cpu);

		apic_set_reg(ap, SAVIC_NMI_REQ, 1);
		return;
	}

	update_vector(cpu, APIC_IRR, vector, true);
}

static void send_ipi_allbut(unsigned int vector, bool nmi)
{
	unsigned int cpu, src_cpu;

	guard(irqsave)();

	src_cpu = raw_smp_processor_id();

	for_each_cpu(cpu, cpu_online_mask) {
		if (cpu == src_cpu)
			continue;
		send_ipi_dest(cpu, vector, nmi);
	}
}

static inline void self_ipi(unsigned int vector, bool nmi)
{
	u32 icr_low = APIC_SELF_IPI | vector;

	if (nmi)
		icr_low |= APIC_DM_NMI;

	native_x2apic_icr_write(icr_low, 0);
}

static void savic_icr_write(u32 icr_low, u32 icr_high)
{
	struct apic_page *ap = this_cpu_ptr(apic_page);
	unsigned int dsh, vector;
	u64 icr_data;
	bool nmi;

	dsh = icr_low & APIC_DEST_ALLBUT;
	vector = icr_low & APIC_VECTOR_MASK;
	nmi = ((icr_low & APIC_DM_FIXED_MASK) == APIC_DM_NMI);

	switch (dsh) {
	case APIC_DEST_SELF:
		self_ipi(vector, nmi);
		break;
	case APIC_DEST_ALLINC:
		self_ipi(vector, nmi);
		fallthrough;
	case APIC_DEST_ALLBUT:
		send_ipi_allbut(vector, nmi);
		break;
	default:
		send_ipi_dest(icr_high, vector, nmi);
		break;
	}

	icr_data = ((u64)icr_high) << 32 | icr_low;
	if (dsh != APIC_DEST_SELF)
		savic_ghcb_msr_write(APIC_ICR, icr_data);
	apic_set_reg64(ap, APIC_ICR, icr_data);
}

static void savic_write(u32 reg, u32 data)
{
	struct apic_page *ap = this_cpu_ptr(apic_page);

	switch (reg) {
	case APIC_LVTT:
	case APIC_TMICT:
	case APIC_TDCR:
		savic_ghcb_msr_write(reg, data);
		break;
	case APIC_LVT0:
	case APIC_LVT1:
	case APIC_TASKPRI:
	case APIC_EOI:
	case APIC_SPIV:
	case SAVIC_NMI_REQ:
	case APIC_ESR:
	case APIC_LVTTHMR:
	case APIC_LVTPC:
	case APIC_LVTERR:
	case APIC_ECTRL:
	case APIC_SEOI:
	case APIC_IER:
	case APIC_EILVTn(0) ... APIC_EILVTn(3):
		apic_set_reg(ap, reg, data);
		break;
	case APIC_ICR:
		savic_icr_write(data, 0);
		break;
	case APIC_SELF_IPI:
		self_ipi_reg_write(data);
		break;
	/* ALLOWED_IRR offsets are writable */
	case SAVIC_ALLOWED_IRR ... SAVIC_ALLOWED_IRR + 0x70:
		if (IS_ALIGNED(reg - SAVIC_ALLOWED_IRR, 16)) {
			apic_set_reg(ap, reg, data);
			break;
		}
		fallthrough;
	default:
		pr_err("Permission denied: write to Secure AVIC reg offset 0x%x\n", reg);
	}
}

static void send_ipi(u32 dest, unsigned int vector, unsigned int dsh)
{
	unsigned int icr_low;

	icr_low = __prepare_ICR(dsh, vector, APIC_DEST_PHYSICAL);
	savic_icr_write(icr_low, dest);
}

static void savic_send_ipi(int cpu, int vector)
{
	u32 dest = per_cpu(x86_cpu_to_apicid, cpu);

	send_ipi(dest, vector, 0);
}

static void send_ipi_mask(const struct cpumask *mask, unsigned int vector, bool excl_self)
{
	unsigned int cpu, this_cpu;

	guard(irqsave)();

	this_cpu = raw_smp_processor_id();

	for_each_cpu(cpu, mask) {
		if (excl_self && cpu == this_cpu)
			continue;
		send_ipi(per_cpu(x86_cpu_to_apicid, cpu), vector, 0);
	}
}

static void savic_send_ipi_mask(const struct cpumask *mask, int vector)
{
	send_ipi_mask(mask, vector, false);
}

static void savic_send_ipi_mask_allbutself(const struct cpumask *mask, int vector)
{
	send_ipi_mask(mask, vector, true);
}

static void savic_send_ipi_allbutself(int vector)
{
	send_ipi(0, vector, APIC_DEST_ALLBUT);
}

static void savic_send_ipi_all(int vector)
{
	send_ipi(0, vector, APIC_DEST_ALLINC);
}

static void savic_send_ipi_self(int vector)
{
	self_ipi_reg_write(vector);
}

static void savic_update_vector(unsigned int cpu, unsigned int vector, bool set)
{
	update_vector(cpu, SAVIC_ALLOWED_IRR, vector, set);
}

static void savic_eoi(void)
{
	unsigned int cpu;
	void *bitmap;
	int vec;

	cpu = raw_smp_processor_id();
	bitmap = get_reg_bitmap(cpu, APIC_ISR);
	vec = apic_find_highest_vector(bitmap);
	if (WARN_ONCE(vec == -1, "EOI write while no active interrupt in APIC_ISR"))
		return;

	bitmap = get_reg_bitmap(cpu, APIC_TMR);

	/* Is level-triggered interrupt? */
	if (apic_test_vector(vec, bitmap)) {
		update_vector(cpu, APIC_ISR, vec, false);
		/*
		 * Propagate the EOI write to hv for level-triggered interrupts.
		 * Return to guest from GHCB protocol event takes care of
		 * re-evaluating interrupt state.
		 */
		savic_ghcb_msr_write(APIC_EOI, 0);
	} else {
		/*
		 * Hardware clears APIC_ISR and re-evaluates the interrupt state
		 * to determine if there is any pending interrupt which can be
		 * delivered to CPU.
		 */
		native_apic_msr_eoi();
	}
}

void x2apic_savic_init_backing_page(void *ap)
{
	u32 apic_id;

	/*
	 * Before Secure AVIC is enabled, APIC msr reads are intercepted.
	 * APIC_ID msr read returns the value from the Hypervisor.
	 */
	apic_id = native_apic_msr_read(APIC_ID);
	apic_set_reg(ap, APIC_ID, apic_id);
}

static void savic_teardown(void)
{
	/* Disable Secure AVIC */
	native_wrmsr(MSR_AMD64_SECURE_AVIC_CONTROL, 0, 0);
	savic_unregister_gpa(NULL);
}

static void savic_setup(void)
{
	void *backing_page;
	enum es_result res;
	unsigned long gpa;
	unsigned long gfn;
	int ret;

	if (!cc_platform_has(CC_ATTR_SNP_SECURE_AVIC))
		return;

	backing_page = this_cpu_ptr(apic_page);
	x2apic_savic_init_backing_page(backing_page);
	gpa = __pa(backing_page);

	gfn = gpa >> PAGE_SHIFT;

	/*
	 * The NPT entry for a vCPU's APIC backing page must always be
	 * present when the vCPU is running in order for Secure AVIC to
	 * function. A VMEXIT_BUSY is returned on VMRUN and the vCPU cannot
	 * be resumed if the NPT entry for the APIC backing page is not
	 * present. Notify GPA of the vCPU's APIC backing page to the
	 * hypervisor by calling savic_register_gpa(). Before executing
	 * VMRUN, the hypervisor makes use of this information to make sure
	 * the APIC backing page is mapped in NPT.
	 */
	if (hv_isolation_type_snp())
		ret = hv_set_savic_backing_page(gfn);
	else
		ret = savic_register_gpa(gpa);

	if (ret != ES_OK)
		snp_abort();
	savic_wr_control_msr(gpa | MSR_AMD64_SECURE_AVIC_EN | MSR_AMD64_SECURE_AVIC_ALLOWEDNMI);
}

static int savic_probe(void)
{
	if (!cc_platform_has(CC_ATTR_SNP_SECURE_AVIC))
		return 0;

	if (!x2apic_mode) {
		pr_err("Secure AVIC enabled in non x2APIC mode\n");
		snp_abort();
		/* unreachable */
	}

	apic_page = alloc_percpu(struct apic_page);
	if (!apic_page)
		snp_abort();

	return 1;
}

static struct apic apic_x2apic_savic __ro_after_init = {

	.name				= "secure avic x2apic",
	.probe				= savic_probe,
	.acpi_madt_oem_check		= savic_acpi_madt_oem_check,
	.setup				= savic_setup,
	.teardown			= savic_teardown,

	.dest_mode_logical		= false,

	.disable_esr			= 0,

	.cpu_present_to_apicid		= default_cpu_present_to_apicid,

	.max_apic_id			= UINT_MAX,
	.x2apic_set_max_apicid		= true,
	.get_apic_id			= x2apic_get_apic_id,

	.calc_dest_apicid		= apic_default_calc_apicid,

	.send_IPI			= savic_send_ipi,
	.send_IPI_mask			= savic_send_ipi_mask,
	.send_IPI_mask_allbutself	= savic_send_ipi_mask_allbutself,
	.send_IPI_allbutself		= savic_send_ipi_allbutself,
	.send_IPI_all			= savic_send_ipi_all,
	.send_IPI_self			= savic_send_ipi_self,

	.nmi_to_offline_cpu		= true,

	.read				= savic_read,
	.write				= savic_write,
	.eoi				= savic_eoi,
	.icr_read			= native_x2apic_icr_read,
	.icr_write			= savic_icr_write,

	.update_vector			= savic_update_vector,
};

apic_driver(apic_x2apic_savic);
