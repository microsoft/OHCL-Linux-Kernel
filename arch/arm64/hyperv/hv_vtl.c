// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023, Microsoft, Inc.
 *
 * Author : Roman Kisel <romank@microsoft.com>
 */

#include <asm/boot.h>
#include <asm/mshyperv.h>
#include <asm/cpu_ops.h>


static int __init hv_vtl_cpu_init(unsigned int cpu)
{
	static struct hv_enable_vp_vtl enable_vp_vtl __aligned(HV_HYP_PAGE_SIZE);
	u64 status;
	int ret = 0;
	/*
	 * None of the kmalloc et. al. is available at this time and
	 * neither is hyperv_pcpu_input_arg initialized so far.
	 */
	struct hv_enable_vp_vtl *input = &enable_vp_vtl;
	unsigned long irq_flags;
	int i;

	/*
	 * nr_cpu_ids is not set at this time (or essentially, it is just
	 * NR_CPUS that is known at this time). Loop through and break when
	 * the hypervisor indicates the VP index is invalid.
	 */
	memset(input, 0, sizeof(*input));
	local_irq_save(irq_flags);
	for (i = 0; i < nr_cpu_ids; i++) {
		input->partition_id = HV_PARTITION_ID_SELF;
		input->vp_index = i;
		input->target_vtl.target_vtl = HV_VTL_MGMT;
		input->vp_context.pc = (u64)__pa_symbol(secondary_entry);

		/*
		 * This has to be done early on (before GIC code initializes)
		 * because the hypervisor doesn't setup the GICR overlay pages
		 * without this hypercall for VTL2. And without those GICR
		 * addresses correctly setup, the GIC code will not correctly
		 * initialize.
		 */
		status = hv_do_hypercall(HVCALL_ENABLE_VP_VTL, input, NULL);

		if (!hv_result_success(status) &&
		    hv_result(status) != HV_STATUS_VTL_ALREADY_ENABLED) {
			if (hv_result(status) != HV_STATUS_INVALID_VP_INDEX) {
				pr_err("HVCALL_ENABLE_VP_VTL failed for VP : %d ! [Err: %#llx\n]",
					cpu, status);
				ret = -EINVAL;
			}
			break;
		}
	}

	local_irq_restore(irq_flags);

	return ret;
}

static int __init hv_vtl_cpu_prepare(unsigned int cpu)
{
	return 0;
}

static int hv_vtl_cpu_boot(unsigned int cpu)
{
	u64 status;
	int ret = 0;
	struct hv_enable_vp_vtl *input;
	unsigned long irq_flags;

	local_irq_save(irq_flags);

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));
	input->partition_id = HV_PARTITION_ID_SELF;
	input->vp_index = cpu;
	input->target_vtl.target_vtl = HV_VTL_MGMT;

	/*
	 * This is essentially all that is passed with the PSCI cpu_on
	 * method, with x18 set to 0.
	 */
	input->vp_context.pc = (u64)__pa_symbol(secondary_entry);
	status = hv_do_hypercall(HVCALL_START_VP, input, NULL);
	if (!hv_result_success(status)) {
		pr_err("HVCALL_START_VP failed for VP : %d ! [Err: %#llx]\n",
		       cpu, status);
		ret = -EINVAL;
	}

	local_irq_restore(irq_flags);

	return ret;
}

const struct cpu_operations hv_vtl_cpu_ops = {
	.name		= "hv_vtl",
	.cpu_init	= hv_vtl_cpu_init,
	.cpu_prepare	= hv_vtl_cpu_prepare,
	.cpu_boot	= hv_vtl_cpu_boot,
};

void __init hv_vtl_init_platform(void)
{
	pr_info("Linux runs in Hyper-V Virtual Trust Level\n");
}

int __init hv_vtl_early_init(void)
{
	return 0;
}
early_initcall(hv_vtl_early_init);
