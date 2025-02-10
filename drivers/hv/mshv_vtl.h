/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _MSHV_VTL_H
#define _MSHV_VTL_H

#include <linux/mshv.h>
#include <linux/types.h>
#include <asm/mshyperv.h>

struct mshv_vtl_run {
	u32 cancel;
	u32 vtl_ret_action_size;
	__u32 flags;
	__u8 scan_proxy_irr;
	__u8 pad[2];
	__u8 enter_mode;
	char exit_message[MAX_RUN_MSG_SIZE];
	union {
		struct hv_vtl_cpu_context cpu_context;

		/*
		 * Reserving room for the cpu context to grow and be
		 * able to maintain compat with user mode.
		 */
		char reserved[1024];
	};
	char vtl_ret_actions[MAX_RUN_MSG_SIZE];
};

#endif /* _MSHV_VTL_H */
