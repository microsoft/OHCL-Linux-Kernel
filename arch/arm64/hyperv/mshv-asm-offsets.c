// SPDX-License-Identifier: GPL-2.0
/*
 * Generate definitions needed by assembly language modules.
 * This code generates raw asm output which is post-processed to extract
 * and format the required data.
 *
 * Copyright (c) 2025, Microsoft Corporation.
 *
 * Author:
 *   Naman Jain <namjain@microsoft.com>
 */
#define COMPILE_OFFSETS

#include <linux/kbuild.h>
#include <asm/mshyperv.h>

static void __used common(void)
{
	if (IS_ENABLED(CONFIG_HYPERV_VTL_MODE)) {
		/* General-purpose registers: x0-x17 (volatile), x19-x30 (callee-saved) */
		OFFSET(MSHV_VTL_CTX_X0,  mshv_vtl_cpu_context, x[0]);
		OFFSET(MSHV_VTL_CTX_X2,  mshv_vtl_cpu_context, x[2]);
		OFFSET(MSHV_VTL_CTX_X4,  mshv_vtl_cpu_context, x[4]);
		OFFSET(MSHV_VTL_CTX_X6,  mshv_vtl_cpu_context, x[6]);
		OFFSET(MSHV_VTL_CTX_X8,  mshv_vtl_cpu_context, x[8]);
		OFFSET(MSHV_VTL_CTX_X10, mshv_vtl_cpu_context, x[10]);
		OFFSET(MSHV_VTL_CTX_X12, mshv_vtl_cpu_context, x[12]);
		OFFSET(MSHV_VTL_CTX_X14, mshv_vtl_cpu_context, x[14]);
		OFFSET(MSHV_VTL_CTX_X16, mshv_vtl_cpu_context, x[16]);
		OFFSET(MSHV_VTL_CTX_X17, mshv_vtl_cpu_context, x[17]);
		/* x18 is hypervisor-managed per-VTL — not touched */
		OFFSET(MSHV_VTL_CTX_X19, mshv_vtl_cpu_context, x[19]);
		OFFSET(MSHV_VTL_CTX_X21, mshv_vtl_cpu_context, x[21]);
		OFFSET(MSHV_VTL_CTX_X23, mshv_vtl_cpu_context, x[23]);
		OFFSET(MSHV_VTL_CTX_X25, mshv_vtl_cpu_context, x[25]);
		OFFSET(MSHV_VTL_CTX_X27, mshv_vtl_cpu_context, x[27]);
		OFFSET(MSHV_VTL_CTX_X29, mshv_vtl_cpu_context, x[29]);

		BLANK();

		/* NEON/FP registers: q0-q31 (128-bit) */
		OFFSET(MSHV_VTL_CTX_Q0,  mshv_vtl_cpu_context, q[0]);
		OFFSET(MSHV_VTL_CTX_Q2,  mshv_vtl_cpu_context, q[2]);
		OFFSET(MSHV_VTL_CTX_Q4,  mshv_vtl_cpu_context, q[4]);
		OFFSET(MSHV_VTL_CTX_Q6,  mshv_vtl_cpu_context, q[6]);
		OFFSET(MSHV_VTL_CTX_Q8,  mshv_vtl_cpu_context, q[8]);
		OFFSET(MSHV_VTL_CTX_Q10, mshv_vtl_cpu_context, q[10]);
		OFFSET(MSHV_VTL_CTX_Q12, mshv_vtl_cpu_context, q[12]);
		OFFSET(MSHV_VTL_CTX_Q14, mshv_vtl_cpu_context, q[14]);
		OFFSET(MSHV_VTL_CTX_Q16, mshv_vtl_cpu_context, q[16]);
		OFFSET(MSHV_VTL_CTX_Q18, mshv_vtl_cpu_context, q[18]);
		OFFSET(MSHV_VTL_CTX_Q20, mshv_vtl_cpu_context, q[20]);
		OFFSET(MSHV_VTL_CTX_Q22, mshv_vtl_cpu_context, q[22]);
		OFFSET(MSHV_VTL_CTX_Q24, mshv_vtl_cpu_context, q[24]);
		OFFSET(MSHV_VTL_CTX_Q26, mshv_vtl_cpu_context, q[26]);
		OFFSET(MSHV_VTL_CTX_Q28, mshv_vtl_cpu_context, q[28]);
		OFFSET(MSHV_VTL_CTX_Q30, mshv_vtl_cpu_context, q[30]);
	}
}
