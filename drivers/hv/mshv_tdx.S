/* SPDX-License-Identifier: GPL-2.0 */
#include <asm/asm-offsets.h>
#include <asm/asm.h>
#include <asm/tdx.h>

#include <linux/linkage.h>
#include <linux/errno.h>

#include "mshv_tdx_asm_offsets.h"

.section .noinstr.text, "ax"

#define tdcall          .byte 0x66,0x0f,0x01,0xcc
#define TDG_VP_ENTER	25

/*
 * __tdg_vp_enter()  - Make a VP.ENTER TDCALL
 *
 * @args (RDI)	- Entry RCX
 * @args (RSI)	- Entry RDX
 * @args (RDX)	- struct tdx_tdg_vp_enter_exit_info
 *
 * Return status of TDCALL via RAX.
 */
SYM_FUNC_START(__tdg_vp_enter)

	push %_ASM_BP
	_ASM_MOV %_ASM_SP, %_ASM_BP

	movq	$TDG_VP_ENTER, %rax
	movq	%rdi, %rcx
/* Swap 2nd and 3rd args so RDX will contain entry RDX value and RSI will point
 * to tdx_tdg_vp_enter_exit_info */
	xchg	%rsi, %rdx

        push	%rbx
        push	%r8
        push	%r9
        push	%r10
        push	%r11
        push	%r12
        push	%r13
        push	%r14
        push	%r15

	/* r8 - r15 needs to cleared before VP.ENTER */
        xor	%r8, %r8
        xor	%r9, %r9
        xor	%r10, %r10
        xor	%r11, %r11
        xor	%r12, %r12
        xor	%r13, %r13
        xor	%r14, %r14
        xor	%r15, %r15

/* Save the pointer to tdx_tdg_vp_enter_exit_info */
	push	%rsi

	tdcall

/* Store the exit RSI value before restoring RSI with pointer to
 * tdx_tdg_vp_enter_exit_info */
	push	%rax
	movq	8(%rsp), %rax
	movq	%rsi, TDX_TDG_EXIT_INFO_rsi(%rax)
	pop	%rax
	pop	%rsi

	movq	%rax, TDX_TDG_EXIT_INFO_rax(%rsi)
	movq	%rcx, TDX_TDG_EXIT_INFO_rcx(%rsi)
	movq	%rdx, TDX_TDG_EXIT_INFO_rdx(%rsi)
	movq	%rdi, TDX_TDG_EXIT_INFO_rdi(%rsi)
	movq	%r8, TDX_TDG_EXIT_INFO_r8(%rsi)
	movq	%r9, TDX_TDG_EXIT_INFO_r9(%rsi)
	movq	%r10, TDX_TDG_EXIT_INFO_r10(%rsi)
	movq	%r11, TDX_TDG_EXIT_INFO_r11(%rsi)
	movq	%r12, TDX_TDG_EXIT_INFO_r12(%rsi)
	movq	%r13, TDX_TDG_EXIT_INFO_r13(%rsi)

/* Following will scrub the registers */
        pop	%r15
        pop	%r14
        pop	%r13
        pop	%r12
        pop	%r11
        pop	%r10
        pop	%r9
        pop	%r8
        pop	%rbx

        pop %_ASM_BP
	RET

SYM_FUNC_END(__tdg_vp_enter)
