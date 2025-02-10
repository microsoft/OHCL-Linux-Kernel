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
	return 0;
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
	 * method, with x18 set to 0. The expectation is that the
	 * `HVCALL_ENABLE_VP_VTL` has already been called at this point.
	 */
	input->vp_context.pc = (u64)__pa_symbol(secondary_entry);
	status = hv_do_hypercall(HVCALL_START_VP, input, NULL);
	if (!hv_result_success(status)) {
		pr_err("HVCALL_START_VP failed for VP : %d ! [Err: %#llx]\n",
		       cpu, status);
		ret = hv_status_to_errno(status);
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
