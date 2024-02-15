/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file contains definitions from the Hyper-V Hypervisor Top-Level
 * Functional Specification (TLFS):
 * https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/tlfs
 *
 * Copyright (C) 2021, Microsoft, Inc.
 *
 * Author : Michael Kelley <mikelley@microsoft.com>
 */

#ifndef _ASM_HYPERV_TLFS_H
#define _ASM_HYPERV_TLFS_H

#include <linux/types.h>

/*
 * All data structures defined in the TLFS that are shared between Hyper-V
 * and a guest VM use Little Endian byte ordering.  This matches the default
 * byte ordering of Linux running on ARM64, so no special handling is required.
 */

/*
 * These Hyper-V registers provide information equivalent to the CPUID
 * instruction on x86/x64.
 */
#define HV_REGISTER_HYPERVISOR_VERSION		0x00000100 /*CPUID 0x40000002 */
#define HV_REGISTER_FEATURES			0x00000200 /*CPUID 0x40000003 */
#define HV_REGISTER_ENLIGHTENMENTS		0x00000201 /*CPUID 0x40000004 */

/*
 * Group C Features. See the asm-generic version of hyperv-tlfs.h
 * for a description of Feature Groups.
 */

/* Crash MSRs available */
#define HV_FEATURE_GUEST_CRASH_MSR_AVAILABLE	BIT(8)

/* STIMER direct mode is available */
#define HV_STIMER_DIRECT_MODE_AVAILABLE		BIT(13)

/*
 * Synthetic register definitions equivalent to MSRs on x86/x64
 */
#define HV_REGISTER_CRASH_P0		0x00000210
#define HV_REGISTER_CRASH_P1		0x00000211
#define HV_REGISTER_CRASH_P2		0x00000212
#define HV_REGISTER_CRASH_P3		0x00000213
#define HV_REGISTER_CRASH_P4		0x00000214
#define HV_REGISTER_CRASH_CTL		0x00000215

#define HV_REGISTER_GUEST_OSID		0x00090002
#define HV_REGISTER_VP_INDEX		0x00090003
#define HV_REGISTER_VP_ASSIST_PAGE  0x00090013
#define HV_REGISTER_TIME_REF_COUNT	0x00090004
#define HV_REGISTER_REFERENCE_TSC	0x00090017

#define HV_REGISTER_SINT0		0x000A0000
#define HV_REGISTER_SCONTROL		0x000A0010
#define HV_REGISTER_SIEFP		0x000A0012
#define HV_REGISTER_SIMP		0x000A0013
#define HV_REGISTER_EOM			0x000A0014

#define HV_REGISTER_STIMER0_CONFIG	0x000B0000
#define HV_REGISTER_STIMER0_COUNT	0x000B0001

/*
 * To support non-arch-specific code calling hv_set/get_register:
 * - On x86, HV_MSR_ indicates an MSR accessed via rdmsrl/wrmsrl
 * - On ARM, HV_MSR_ indicates a VP register accessed via hypercall
 */
#define HV_MSR_VP_INDEX		(HV_REGISTER_VP_INDEX)
#define HV_MSR_TIME_REF_COUNT	(HV_REGISTER_TIME_REF_COUNT)
#define HV_MSR_REFERENCE_TS	(HV_REGISTER_REFERENCE_TSC)
#define HV_SYN_REG_VP_ASSIST_PAGE		(HV_REGISTER_VP_ASSIST_PAGE)

#define HV_MSR_STIMER0_CONFIG	(HV_REGISTER_STIMER0_CONFIG)
#define HV_MSR_STIMER0_COUNT	(HV_REGISTER_STIMER0_COUNT)

#define HV_MSR_SCONTROL		(HV_REGISTER_SCONTROL)
#define HV_MSR_SIEFP		(HV_REGISTER_SIEFP)
#define HV_MSR_SIMP		(HV_REGISTER_SIMP)
#define HV_MSR_EOM		(HV_REGISTER_EOM)
#define HV_MSR_SINT0		(HV_REGISTER_SINT0)

#define HV_MSR_CRASH_P0		(HV_REGISTER_CRASH_P0)
#define HV_MSR_CRASH_P1		(HV_REGISTER_CRASH_P1)
#define HV_MSR_CRASH_P2		(HV_REGISTER_CRASH_P2)
#define HV_MSR_CRASH_P3		(HV_REGISTER_CRASH_P3)
#define HV_MSR_CRASH_P4		(HV_REGISTER_CRASH_P4)
#define HV_MSR_CRASH_CTL	(HV_REGISTER_CRASH_CTL)

union hv_msi_entry {
	u64 as_uint64[2];
	struct {
		u64 address;
		u32 data;
		u32 reserved;
	} __packed;
};

#define HV_ARM64_HVC_SMCCC_IMM16        0
#define HV_ARM64_HVC_IMM16              1
#define HV_ARM64_HVC_VTLENTRY_IMM16     2
#define HV_ARM64_HVC_VTLEXIT_IMM16      3
#define HV_ARM64_HVC_LAUNCH_IMM16       4

struct hv_init_vp_context {
	u64 pc;
	u64 sp_elh;
	u64 spctlr_el1;
	u64 mair_el1;
	u64 tcr_el1;
	u64 vbar_el1;
	u64 ttbr0_el1;
	u64 ttbr1_el1;
	u64 x18;
} __packed;

#include <asm-generic/hyperv-tlfs.h>

#endif
