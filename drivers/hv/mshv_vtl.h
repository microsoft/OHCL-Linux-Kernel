/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _MSHV_VTL_H
#define _MSHV_VTL_H

#include <linux/mshv.h>
#include <linux/types.h>
#include <asm/mshyperv.h>

#ifdef CONFIG_X86_64

/*
 * The register values returned from a TDG.VP.ENTER call.
 * These are readable via mmaping the mshv_vtl driver, and returned on a
 * run_vp ioctl exit.
 * See the TDX ABI specification for output operands for TDG.VP.ENTER.
 */
struct tdx_tdg_vp_enter_exit_info {
	u64 rax;
	u64 rcx;
	u64 rdx;
	u64 rsi;
	u64 rdi;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
};

/*
 * Register values that must be set by the kernel or flags that must be handled
 * before entering lower VTLs.
 */
struct tdx_vp_state {
	u64 msr_kernel_gs_base;
	u64 msr_star;
	u64 msr_lstar;
	u64 msr_sfmask;
	u64 msr_xss;
	u64 cr2;
	u64 msr_tsc_aux;
	u64 flags;
};

#define MSHV_VTL_TDX_VP_STATE_FLAG_WBINVD BIT(0)
#define MSHV_VTL_TDX_VP_STATE_FLAG_WBNOINVD BIT(1)

/*
 * The GPR list for TDG.VP.ENTER.
 * Made available via mmaping the mshv_vtl driver.
 * Specified in the TDX specification as L2_ENTER_GUEST_STATE.
 */
struct tdx_l2_enter_guest_state {
	u64 rax;
	u64 rcx;
	u64 rdx;
	u64 rbx;
	u64 rsp;
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
	u64 rflags;
	u64 rip;
	u64 ssp;
	u8 rvi;		/* GUEST_INTERRUPT_STATUS lower bits */
	u8 svi;		/* GUSET_INTERRUPT_STATUS upper bits */
	u8 reserved[6];
};

/*
 * This structure must be placed in a larger structure at offset 272 (0x110).
 * The GPR list for TDX and fx_state for xsave have alignment requirements on the
 * addresses they are at due to ISA requirements.
 */
struct tdx_vp_context {
	struct tdx_tdg_vp_enter_exit_info exit_info;
	__u8 pad1[48];
	struct tdx_vp_state vp_state;
	__u8 pad2[32];
	/* Contains the VM index and the TLB flush bit */
	__u64 entry_rcx;
	/* Must be on 256 byte boundary. */
	struct tdx_l2_enter_guest_state l2_enter_guest_state;
	/* Pad space until the next 256 byte boundary. */
	__u8 pad3[96];
	/* Must be 16 byte aligned. */
	struct fxregs_state fx_state;
	__u8 pad4[16];
};

static_assert(offsetof(struct tdx_vp_context, l2_enter_guest_state) + 272 == 512);
static_assert(sizeof(struct tdx_vp_context) == 1024);

#endif

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

#ifdef CONFIG_X86_64
		struct tdx_vp_context tdx_context;
#endif
		/*
		 * Reserving room for the cpu context to grow and be
		 * able to maintain compat with user mode.
		 */
		char reserved[1024];
	};
	char vtl_ret_actions[MAX_RUN_MSG_SIZE];
	__u32 proxy_irr[8];
	union hv_input_vtl target_vtl;
};

#ifdef CONFIG_X86_64
static_assert(offsetof(struct mshv_vtl_run, tdx_context) == 272);
#endif

#define SEV_GHCB_VERSION        1
#define SEV_GHCB_FORMAT_BASE        0
#define SEV_GHCB_FORMAT_VTL_RETURN  2

#endif /* _MSHV_VTL_H */
