/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Linux-specific definitions for managing interactions with Microsoft's
 * Hyper-V hypervisor. The definitions in this file are specific to
 * the ARM64 architecture.  See include/asm-generic/mshyperv.h for
 * definitions are that architecture independent.
 *
 * Definitions that are specified in the Hyper-V Top Level Functional
 * Spec (TLFS) should not go in this file, but should instead go in
 * hyperv-tlfs.h.
 *
 * Copyright (C) 2021, Microsoft, Inc.
 *
 * Author : Michael Kelley <mikelley@microsoft.com>
 */

#ifndef _ASM_MSHYPERV_H
#define _ASM_MSHYPERV_H

#include <linux/types.h>
#include <linux/arm-smccc.h>
#include <asm/idle.h>
#include <asm-generic/hyperv-defs.h>

/*
 * Declare calls to get and set Hyper-V VP register values on ARM64, which
 * requires a hypercall.
 */

struct hv_get_vp_registers_output;

void hv_set_vpreg(u32 reg, u64 value);
u64 hv_get_vpreg(u32 reg);
void hv_get_vpreg_128(u32 reg, struct hv_get_vp_registers_output *result);

static inline void hv_set_msr(unsigned int reg, u64 value)
{
	hv_set_vpreg(reg, value);
}

static inline u64 hv_get_msr(unsigned int reg)
{
	return hv_get_vpreg(reg);
}

extern u64 hv_current_partition_id;

/* SMCCC hypercall parameters */
#define HV_SMCCC_FUNC_NUMBER	1
#define HV_FUNC_ID	ARM_SMCCC_CALL_VAL(			\
				ARM_SMCCC_STD_CALL,		\
				ARM_SMCCC_SMC_64,		\
				ARM_SMCCC_OWNER_VENDOR_HYP,	\
				HV_SMCCC_FUNC_NUMBER)

#ifdef CONFIG_HYPERV_VTL_MODE

struct hv_vtl_cpu_context {
   /*
	* NOTE: x18 is managed by the hypervisor. It won't be reloaded from this array.
	* It is included here for convenience in the common case.
	*/
	__u64 x[31];
	__u64 rsvd;
	__uint128_t q[32];
};

void __init hv_vtl_init_platform(void);
int __init hv_vtl_early_init(void);
void hv_vtl_return(struct hv_vtl_cpu_context *vtl0, union hv_input_vtl target_vtl, u32 flags, u64 vtl_return_offset);

static inline void hv_vtl_idle(void)
{
	default_idle();
}

struct hv_register_assoc;

/*
 * Set the register. If the function returns `1`, that must be done via
 * a hypercall. Returning `0` means success.
 */
static inline int hv_vtl_set_reg(struct hv_register_assoc *regs, bool shared)
{
	return 1;
}

/*
 * Get the register. If the function returns `1`, that must be done via
 * a hypercall. Returning `0` means success.
 */
static inline int hv_vtl_get_reg(struct hv_register_assoc *regs, bool shared)
{
	return 1;
}

#else
static inline void __init hv_vtl_init_platform(void) {}
static inline int __init hv_vtl_early_init(void) { return 0; }
#endif

#include <asm-generic/mshyperv.h>

#endif
