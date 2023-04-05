/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _MSHV_VTL_H
#define _MSHV_VTL_H

#include <linux/mshv.h>
#include <linux/types.h>
#include <asm/fpu/types.h>

struct mshv_vtl_cpu_context {
	union {
		struct {
			u64 rax;
			u64 rcx;
			u64 rdx;
			u64 rbx;
			u64 cr2;
			u64 rbp;
			u64 rsi;
			u64 rdi;
			u64 r8;
			u64 r9;
			u64 r10;
			u64 r11;
			u64 r12;
			u64 r13;
			u64 r14;
			u64 r15;
		};
		u64 gp_regs[16];
	};

	struct fxregs_state fx_state;
};

struct mshv_vtl_run {
	u32 cancel;
	u32 vtl_ret_action_size;
	u32 pad[2];
	char exit_message[MAX_RUN_MSG_SIZE];
	union {
		struct mshv_vtl_cpu_context cpu_context;

		/*
		 * Reserving room for the cpu context to grow and be
		 * able to maintain compat with user mode.
		 */
		char reserved[1024];
	};
	char vtl_ret_actions[MAX_RUN_MSG_SIZE];
};

#endif /* _MSHV_VTL_H */
