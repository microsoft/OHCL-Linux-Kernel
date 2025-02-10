// SPDX-License-Identifier: GPL-2.0

/*
 * Core routines for interacting with Microsoft's Hyper-V hypervisor,
 * including hypervisor initialization.
 *
 * Copyright (C) 2021, Microsoft, Inc.
 *
 * Author : Michael Kelley <mikelley@microsoft.com>
 */

#include <linux/types.h>
#include <linux/acpi.h>
#include <linux/export.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/cpuhotplug.h>
#include <linux/libfdt.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <asm/mshyperv.h>

static bool hyperv_initialized;

int hv_get_hypervisor_version(union hv_hypervisor_version_info *info)
{
	hv_get_vpreg_128(HV_REGISTER_HYPERVISOR_VERSION,
			 (struct hv_get_vp_registers_output *)info);

	return 0;
}

static bool hyperv_detect_fdt(void)
{
#if IS_ENABLED(CONFIG_OF)
	const unsigned long hyp_node = of_get_flat_dt_subnode_by_name(
			of_get_flat_dt_root(), "hypervisor");

	return (hyp_node != -FDT_ERR_NOTFOUND) &&
			of_flat_dt_is_compatible(hyp_node, "microsoft,hyperv");
#else
	return false;
#endif
}

static bool hyperv_detect_acpi(void)
{
#if IS_ENABLED(CONFIG_ACPI)
	return !acpi_disabled &&
			!strncmp((char *)&acpi_gbl_FADT.hypervisor_id, "MsHyperV", 8);
#else
	return false;
#endif
}

static int __init hyperv_init(void)
{
	struct hv_get_vp_registers_output	result;
	u64	guest_id;
	int	ret;

	/*
	 * Allow for a kernel built with CONFIG_HYPERV to be running in
	 * a non-Hyper-V environment.
	 *
	 * In such cases, do nothing and return success.
	 */
	if (!hyperv_detect_fdt() && !hyperv_detect_acpi())
		return 0;

	/* Setup the guest ID */
	guest_id = hv_generate_guest_id(LINUX_VERSION_CODE);
	hv_set_vpreg(HV_REGISTER_GUEST_OS_ID, guest_id);

	/* Get the features and hints from Hyper-V */
	hv_get_vpreg_128(HV_REGISTER_FEATURES, &result);
	ms_hyperv.features = result.as32.a;
	ms_hyperv.priv_high = result.as32.b;
	ms_hyperv.misc_features = result.as32.c;

	hv_get_vpreg_128(HV_REGISTER_ENLIGHTENMENTS, &result);
	ms_hyperv.hints = result.as32.a;

	pr_info("Hyper-V: privilege flags low 0x%x, high 0x%x, hints 0x%x, misc 0x%x\n",
		ms_hyperv.features, ms_hyperv.priv_high, ms_hyperv.hints,
		ms_hyperv.misc_features);

	ret = hv_common_init();
	if (ret)
		return ret;

	ret = cpuhp_setup_state(CPUHP_AP_HYPERV_ONLINE, "arm64/hyperv_init:online",
				hv_common_cpu_init, hv_common_cpu_die);
	if (ret < 0) {
		hv_common_free();
		return ret;
	}

	ms_hyperv_late_init();

	/* Find the VTL */
	ms_hyperv.vtl = get_vtl();
	if (ms_hyperv.vtl > 0) /* non default VTL */
		hv_vtl_early_init();

	hv_vtl_init_platform();

	hyperv_initialized = true;
	return 0;
}

early_initcall(hyperv_init);

bool hv_is_hyperv_initialized(void)
{
	return hyperv_initialized;
}
EXPORT_SYMBOL_GPL(hv_is_hyperv_initialized);

static void (*vmbus_percpu_handler)(void);
void hv_setup_percpu_vmbus_handler(void (*handler)(void))
{
	vmbus_percpu_handler = handler;
}

irqreturn_t vmbus_percpu_isr(int irq, void *dev_id)
{
	if (vmbus_percpu_handler)
		vmbus_percpu_handler();
	return IRQ_HANDLED;
}
