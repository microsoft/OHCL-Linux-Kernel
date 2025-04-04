// SPDX-License-Identifier: GPL-2.0
/*
 * Generate definitions needed by assembly language modules.
 * This code generates raw asm output which is post-processed to extract
 * and format the required data.
 */
#define COMPILE_OFFSETS

#include <linux/kbuild.h>
#include "mshv_vtl.h"

static void __used common(void)
{
	BLANK();
	OFFSET(TDX_TDG_EXIT_INFO_rax, tdx_tdg_vp_enter_exit_info, rax);
	OFFSET(TDX_TDG_EXIT_INFO_rcx, tdx_tdg_vp_enter_exit_info, rcx);
	OFFSET(TDX_TDG_EXIT_INFO_rdx, tdx_tdg_vp_enter_exit_info, rdx);
	OFFSET(TDX_TDG_EXIT_INFO_rsi, tdx_tdg_vp_enter_exit_info, rsi);
	OFFSET(TDX_TDG_EXIT_INFO_rdi, tdx_tdg_vp_enter_exit_info, rdi);
	OFFSET(TDX_TDG_EXIT_INFO_r8, tdx_tdg_vp_enter_exit_info, r8);
	OFFSET(TDX_TDG_EXIT_INFO_r9, tdx_tdg_vp_enter_exit_info, r9);
	OFFSET(TDX_TDG_EXIT_INFO_r10, tdx_tdg_vp_enter_exit_info, r10);
	OFFSET(TDX_TDG_EXIT_INFO_r11, tdx_tdg_vp_enter_exit_info, r11);
	OFFSET(TDX_TDG_EXIT_INFO_r12, tdx_tdg_vp_enter_exit_info, r12);
	OFFSET(TDX_TDG_EXIT_INFO_r13, tdx_tdg_vp_enter_exit_info, r13);
}
