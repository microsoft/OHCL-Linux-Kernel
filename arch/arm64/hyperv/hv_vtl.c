// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026, Microsoft, Inc.
 *
 * Authors:
 *     Roman Kisel <romank@linux.microsoft.com>
 *     Naman Jain <namjain@linux.microsoft.com>
 */

#include <asm/boot.h>
#include <asm/mshyperv.h>
#include <asm/cpu_ops.h>
#include <asm/neon.h>
#include <linux/export.h>

void mshv_vtl_return_call(struct mshv_vtl_cpu_context *vtl0)
{
	struct user_fpsimd_state fpsimd_state;
	u64 base_ptr = (u64)vtl0->x;

	/*
	 * Obtain the CPU FPSIMD registers for VTL context switch.
	 * This saves the current task's FP/NEON state and allows us to
	 * safely load VTL0's FP/NEON context for the hypercall.
	 */
	kernel_neon_begin(&fpsimd_state);

	/*
	 * VTL switch for ARM64 platform - managing VTL0's CPU context.
	 * We explicitly use the stack to save the base pointer, and use x16
	 * as our working register for accessing the context structure.
	 *
	 * Register Handling:
	 * - X0-X17: Saved/restored (general-purpose, shared for VTL communication)
	 * - X18: NOT touched - hypervisor-managed per-VTL (platform register)
	 * - X19-X30: Saved/restored (part of VTL0's execution context)
	 * - Q0-Q31: Saved/restored (128-bit NEON/floating-point registers, shared)
	 * - SP: Not in structure, hypervisor-managed per-VTL
	 *
	 * X29 (FP) and X30 (LR) are in the structure and must be saved/restored
	 * as part of VTL0's complete execution state.
	 */
	asm __volatile__ (
		/* Save base pointer to stack explicitly, then load into x16 */
		"str %0, [sp, #-16]!\n\t"     /* Push base pointer onto stack */
		"mov x16, %0\n\t"             /* Load base pointer into x16 */
		/* Volatile registers (Windows ARM64 ABI: x0-x15) */
		"ldp x0, x1, [x16]\n\t"
		"ldp x2, x3, [x16, #(2*8)]\n\t"
		"ldp x4, x5, [x16, #(4*8)]\n\t"
		"ldp x6, x7, [x16, #(6*8)]\n\t"
		"ldp x8, x9, [x16, #(8*8)]\n\t"
		"ldp x10, x11, [x16, #(10*8)]\n\t"
		"ldp x12, x13, [x16, #(12*8)]\n\t"
		"ldp x14, x15, [x16, #(14*8)]\n\t"
		/* x16 will be loaded last, after saving base pointer */
		"ldr x17, [x16, #(17*8)]\n\t"
		/* x18 is hypervisor-managed per-VTL - DO NOT LOAD */

		/* General-purpose registers: x19-x30 */
		"ldp x19, x20, [x16, #(19*8)]\n\t"
		"ldp x21, x22, [x16, #(21*8)]\n\t"
		"ldp x23, x24, [x16, #(23*8)]\n\t"
		"ldp x25, x26, [x16, #(25*8)]\n\t"
		"ldp x27, x28, [x16, #(27*8)]\n\t"

		/* Frame pointer and link register */
		"ldp x29, x30, [x16, #(29*8)]\n\t"

		/* Shared NEON/FP registers: Q0-Q31 (128-bit) */
		"ldp q0, q1, [x16, #(32*8)]\n\t"
		"ldp q2, q3, [x16, #(32*8 + 2*16)]\n\t"
		"ldp q4, q5, [x16, #(32*8 + 4*16)]\n\t"
		"ldp q6, q7, [x16, #(32*8 + 6*16)]\n\t"
		"ldp q8, q9, [x16, #(32*8 + 8*16)]\n\t"
		"ldp q10, q11, [x16, #(32*8 + 10*16)]\n\t"
		"ldp q12, q13, [x16, #(32*8 + 12*16)]\n\t"
		"ldp q14, q15, [x16, #(32*8 + 14*16)]\n\t"
		"ldp q16, q17, [x16, #(32*8 + 16*16)]\n\t"
		"ldp q18, q19, [x16, #(32*8 + 18*16)]\n\t"
		"ldp q20, q21, [x16, #(32*8 + 20*16)]\n\t"
		"ldp q22, q23, [x16, #(32*8 + 22*16)]\n\t"
		"ldp q24, q25, [x16, #(32*8 + 24*16)]\n\t"
		"ldp q26, q27, [x16, #(32*8 + 26*16)]\n\t"
		"ldp q28, q29, [x16, #(32*8 + 28*16)]\n\t"
		"ldp q30, q31, [x16, #(32*8 + 30*16)]\n\t"

		/* Now load x16 itself */
		"ldr x16, [x16, #(16*8)]\n\t"

		/* Return to the lower VTL */
		"hvc #3\n\t"

		/* Save context after return - reload base pointer from stack */
		"stp x16, x17, [sp, #-16]!\n\t" /* Save x16, x17 temporarily */
		"ldr x16, [sp, #16]\n\t"        /* Reload base pointer (skip saved x16,x17) */

		/* Volatile registers */
		"stp x0, x1, [x16]\n\t"
		"stp x2, x3, [x16, #(2*8)]\n\t"
		"stp x4, x5, [x16, #(4*8)]\n\t"
		"stp x6, x7, [x16, #(6*8)]\n\t"
		"stp x8, x9, [x16, #(8*8)]\n\t"
		"stp x10, x11, [x16, #(10*8)]\n\t"
		"stp x12, x13, [x16, #(12*8)]\n\t"
		"stp x14, x15, [x16, #(14*8)]\n\t"
		"ldp x0, x1, [sp], #16\n\t"      /* Recover saved x16, x17 */
		"stp x0, x1, [x16, #(16*8)]\n\t"
		/* x18 is hypervisor-managed - DO NOT SAVE */

		/* General-purpose registers: x19-x30 */
		"stp x19, x20, [x16, #(19*8)]\n\t"
		"stp x21, x22, [x16, #(21*8)]\n\t"
		"stp x23, x24, [x16, #(23*8)]\n\t"
		"stp x25, x26, [x16, #(25*8)]\n\t"
		"stp x27, x28, [x16, #(27*8)]\n\t"
		"stp x29, x30, [x16, #(29*8)]\n\t"  /* Frame pointer and link register */

		/* Shared NEON/FP registers: Q0-Q31 (128-bit) */
		"stp q0, q1, [x16, #(32*8)]\n\t"
		"stp q2, q3, [x16, #(32*8 + 2*16)]\n\t"
		"stp q4, q5, [x16, #(32*8 + 4*16)]\n\t"
		"stp q6, q7, [x16, #(32*8 + 6*16)]\n\t"
		"stp q8, q9, [x16, #(32*8 + 8*16)]\n\t"
		"stp q10, q11, [x16, #(32*8 + 10*16)]\n\t"
		"stp q12, q13, [x16, #(32*8 + 12*16)]\n\t"
		"stp q14, q15, [x16, #(32*8 + 14*16)]\n\t"
		"stp q16, q17, [x16, #(32*8 + 16*16)]\n\t"
		"stp q18, q19, [x16, #(32*8 + 18*16)]\n\t"
		"stp q20, q21, [x16, #(32*8 + 20*16)]\n\t"
		"stp q22, q23, [x16, #(32*8 + 22*16)]\n\t"
		"stp q24, q25, [x16, #(32*8 + 24*16)]\n\t"
		"stp q26, q27, [x16, #(32*8 + 26*16)]\n\t"
		"stp q28, q29, [x16, #(32*8 + 28*16)]\n\t"
		"stp q30, q31, [x16, #(32*8 + 30*16)]\n\t"

		/* Clean up stack - pop base pointer */
		"add sp, sp, #16\n\t"

		: /* No outputs */
		: /* Input */ "r"(base_ptr)
		: /* Clobber list - x16 used as base, x18 is hypervisor-managed (not touched) */
		"memory", "cc",
		"x0", "x1", "x2", "x3", "x4", "x5",
		"x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
		"x14", "x15", "x16", "x17", "x19", "x20", "x21",
		"x22", "x23", "x24", "x25", "x26", "x27", "x28",
		"x29", "x30",
		"v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
		"v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
		"v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
		"v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31");

	/*
	 * Restore the task's FP/SIMD state and return CPU FPSIMD registers
	 * back to normal kernel use.
	 */
	kernel_neon_end(&fpsimd_state);
}
EXPORT_SYMBOL(mshv_vtl_return_call);

bool hv_vtl_configure_reg_page(struct mshv_vtl_per_cpu *per_cpu)
{
	pr_debug("Register page not supported on ARM64\n");
	return false;
}
EXPORT_SYMBOL_GPL(hv_vtl_configure_reg_page);
