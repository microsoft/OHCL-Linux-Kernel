// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Secure AVIC Support (SEV-SNP Guests)
 *
 * Copyright (C) 2024 Advanced Micro Devices, Inc.
 *
 * Author: Neeraj Upadhyay <Neeraj.Upadhyay@amd.com>
 */

#include <linux/cc_platform.h>
#include <linux/percpu-defs.h>
#include <linux/align.h>

#include <asm/apic.h>
#include <asm/sev.h>

#include "local.h"

static struct apic_page __percpu *apic_page __ro_after_init;

static int savic_acpi_madt_oem_check(char *oem_id, char *oem_table_id)
{
	return x2apic_enabled() && cc_platform_has(CC_ATTR_SNP_SECURE_AVIC);
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

static void savic_write(u32 reg, u32 data)
{
	struct apic_page *ap = this_cpu_ptr(apic_page);

	switch (reg) {
	case APIC_LVTT:
	case APIC_LVT0:
	case APIC_LVT1:
	case APIC_TMICT:
	case APIC_TDCR:
	case APIC_SELF_IPI:
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
		apic_set_reg64(ap, reg, (u64) data);
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

static void init_apic_page(struct apic_page *ap)
{
	u32 apic_id;

	/*
	 * Before Secure AVIC is enabled, APIC msr reads are intercepted.
	 * APIC_ID msr read returns the value from the Hypervisor.
	 */
	apic_id = native_apic_msr_read(APIC_ID);
	apic_set_reg(ap, APIC_ID, apic_id);
}

static void savic_setup(void)
{
	void *backing_page;
	enum es_result res;
	unsigned long gpa;

	backing_page = this_cpu_ptr(apic_page);
	init_apic_page(backing_page);
	gpa = __pa(backing_page);

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
	res = savic_register_gpa(gpa);
	if (res != ES_OK)
		snp_abort();
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

	.dest_mode_logical		= false,

	.disable_esr			= 0,

	.cpu_present_to_apicid		= default_cpu_present_to_apicid,

	.max_apic_id			= UINT_MAX,
	.x2apic_set_max_apicid		= true,
	.get_apic_id			= x2apic_get_apic_id,

	.calc_dest_apicid		= apic_default_calc_apicid,

	.nmi_to_offline_cpu		= true,

	.read				= savic_read,
	.write				= savic_write,
	.eoi				= native_apic_msr_eoi,
	.icr_read			= native_x2apic_icr_read,
	.icr_write			= native_x2apic_icr_write,
};

apic_driver(apic_x2apic_savic);
