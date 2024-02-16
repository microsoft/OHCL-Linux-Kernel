/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _MSHV_VTL_H
#define _MSHV_VTL_H

#include <linux/mshv.h>
#include <linux/types.h>

#ifdef CONFIG_X86_64
#include <asm/fpu/types.h>
#endif

struct mshv_set_eventfd {
	int fd;
	u32 flag;
};

struct mshv_signal_event {
	u32 connection_id;
	u32 flag;
};

struct mshv_sint_post_msg {
	u64 message_type;
	u32 connection_id;
	u32 payload_size;
	u8 __user *payload;
};

struct mshv_ram_disposition {
	__u64 start_pfn;
	__u64 last_pfn;
} __packed;

struct mshv_set_poll_file {
	__u32 cpu;
	__u32 fd;
} __packed;

struct mshv_hvcall_setup {
	u64 bitmap_size;
	u64 *allow_bitmap;
} __packed;

struct mshv_hvcall {
	u64 control;
	u64 input_size;
	void *input_data;
	u64 status;
	u64 output_size;
	void *output_data;
} __packed;

struct mshv_vtl_cpu_context {
#ifdef CONFIG_X86_64
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

#elif defined CONFIG_ARM64
		/* 
		 * NOTE: x18 is managed by the hypervisor. It won't be reloaded from this array.
		 * It is included here for convenience in the common case.
		 */
		__u64 x[31];
		__u64 rsvd;
		__uint128_t q[32];
#else

	#error "Unsupported architecture"

#endif	
};

#define MSHV_VTL_RUN_FLAG_HALTED BIT(0)

struct mshv_vtl_run {
	u32 cancel;
	u32 vtl_ret_action_size;
	__u32 flags;
	__u8 scan_proxy_irr;
	__u8 pad[2];
	__u8 enter_mode;
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
	__u32 proxy_irr[8];
};

union mshv_vtl_ghcb {
    struct {
        u64 ghcb_data[511];
        u16 reserved;
        u16 version;
        u32 format;
    } __packed;
    struct {
        union hv_input_vtl target_vtl;
    };
};

#define SEV_GHCB_VERSION        1
#define SEV_GHCB_FORMAT_BASE        0
#define SEV_GHCB_FORMAT_VTL_RETURN  2

#endif /* _MSHV_VTL_H */
