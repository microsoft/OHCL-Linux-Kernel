// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Secure AVIC Support (SEV-SNP Guests)
 *
 * Copyright (C) 2024 Advanced Micro Devices, Inc.
 *
 * Author: Kishon Vijay Abraham I <kvijayab@amd.com>
 */

#include <linux/cpumask.h>
#include <linux/cc_platform.h>
#include <linux/percpu-defs.h>

#include <asm/apic.h>
#include <asm/sev.h>

#include "local.h"

static DEFINE_PER_CPU(void *, apic_backing_page);
static DEFINE_PER_CPU(bool, savic_setup_done);

static int x2apic_savic_acpi_madt_oem_check(char *oem_id, char *oem_table_id)
{
	return x2apic_enabled() && cc_platform_has(CC_ATTR_SNP_SECURE_AVIC);
}

static void x2apic_savic_send_IPI(int cpu, int vector)
{
	u32 dest = per_cpu(x86_cpu_to_apicid, cpu);

	/* x2apic MSRs are special and need a special fence: */
	weak_wrmsr_fence();
	__x2apic_send_IPI_dest(dest, vector, APIC_DEST_PHYSICAL);
}

static void
__send_IPI_mask(const struct cpumask *mask, int vector, int apic_dest)
{
	unsigned long query_cpu;
	unsigned long this_cpu;
	unsigned long flags;

	/* x2apic MSRs are special and need a special fence: */
	weak_wrmsr_fence();

	local_irq_save(flags);

	this_cpu = smp_processor_id();
	for_each_cpu(query_cpu, mask) {
		if (apic_dest == APIC_DEST_ALLBUT && this_cpu == query_cpu)
			continue;
		__x2apic_send_IPI_dest(per_cpu(x86_cpu_to_apicid, query_cpu),
				       vector, APIC_DEST_PHYSICAL);
	}
	local_irq_restore(flags);
}

static void x2apic_savic_send_IPI_mask(const struct cpumask *mask, int vector)
{
	__send_IPI_mask(mask, vector, APIC_DEST_ALLINC);
}

static void x2apic_savic_send_IPI_mask_allbutself(const struct cpumask *mask, int vector)
{
	__send_IPI_mask(mask, vector, APIC_DEST_ALLBUT);
}

static void x2apic_savic_setup(void)
{
	void *backing_page;
	enum es_result ret;
	unsigned long gpa;

	if (this_cpu_read(savic_setup_done))
		return;

	backing_page = this_cpu_read(apic_backing_page);
	gpa = __pa(backing_page);
	ret = sev_notify_savic_gpa(gpa);
	if (ret != ES_OK)
		snp_abort();
	this_cpu_write(savic_setup_done, true);
}

static int x2apic_savic_probe(void)
{
	void *backing_pages;
	unsigned int cpu;
	size_t sz;
	int i;

	if (!cc_platform_has(CC_ATTR_SNP_SECURE_AVIC))
		return 0;

	if (!x2apic_mode) {
		pr_err("Secure AVIC enabled in non x2APIC mode\n");
		snp_abort();
	}

	sz = ALIGN(num_possible_cpus() * SZ_4K, SZ_2M);
	backing_pages = kzalloc(sz, GFP_ATOMIC);
	if (!backing_pages)
		snp_abort();

	i = 0;
	for_each_possible_cpu(cpu) {
		per_cpu(apic_backing_page, cpu) = backing_pages + i * SZ_4K;
		i++;
	}

	pr_info("Secure AVIC Enabled\n");

	return 1;
}

static struct apic apic_x2apic_savic __ro_after_init = {

	.name				= "secure avic x2apic",
	.probe				= x2apic_savic_probe,
	.acpi_madt_oem_check		= x2apic_savic_acpi_madt_oem_check,
	.setup				= x2apic_savic_setup,

	.dest_mode_logical		= false,

	.disable_esr			= 0,

	.cpu_present_to_apicid		= default_cpu_present_to_apicid,

	.max_apic_id			= UINT_MAX,
	.x2apic_set_max_apicid		= true,
	.get_apic_id			= x2apic_get_apic_id,

	.calc_dest_apicid		= apic_default_calc_apicid,

	.send_IPI			= x2apic_savic_send_IPI,
	.send_IPI_mask			= x2apic_savic_send_IPI_mask,
	.send_IPI_mask_allbutself	= x2apic_savic_send_IPI_mask_allbutself,
	.send_IPI_allbutself		= x2apic_send_IPI_allbutself,
	.send_IPI_all			= x2apic_send_IPI_all,
	.send_IPI_self			= x2apic_send_IPI_self,
	.nmi_to_offline_cpu		= true,

	.read				= native_apic_msr_read,
	.write				= native_apic_msr_write,
	.eoi				= native_apic_msr_eoi,
	.icr_read			= native_x2apic_icr_read,
	.icr_write			= native_x2apic_icr_write,
};

apic_driver(apic_x2apic_savic);
