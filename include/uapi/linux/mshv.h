/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_MSHV_H
#define _UAPI_LINUX_MSHV_H

/*
 * Userspace interface for /dev/mshv
 * Microsoft Hypervisor root partition APIs
 * NOTE: This API is not yet stable!
 */

#include <linux/types.h>
#include <hyperv/hvhdk.h>

#define MSHV_CAP_CORE_API_STABLE	0x0
#define MSHV_CAP_REGISTER_PAGE		0x1
#define MSHV_CAP_VTL_RETURN_ACTION	0x2
#define MSHV_CAP_DR6_SHARED		0x3

#define MSHV_VP_MMAP_REGISTERS_OFFSET (HV_VP_STATE_PAGE_REGISTERS * 0x1000)
#define MAX_RUN_MSG_SIZE		256

struct mshv_create_partition {
	__u64 flags;
	struct hv_partition_creation_properties partition_creation_properties;
	union hv_partition_synthetic_processor_features synthetic_processor_features;
	union hv_partition_isolation_properties isolation_properties;
};

/*
 * Mappings can't overlap in GPA space or userspace
 * To unmap, these fields must match an existing mapping
 */
struct mshv_user_mem_region {
	__u64 size;		/* bytes */
	__u64 guest_pfn;
	__u64 userspace_addr;	/* start of the userspace allocated memory */
	__u32 flags;		/* ignored on unmap */
	__u32 padding;
};

struct mshv_create_vp {
	__u32 vp_index;
};

#define MSHV_VP_MAX_REGISTERS	128

struct mshv_vp_registers {
	__u32 count;	/* at most MSHV_VP_MAX_REGISTERS */
	__u32 padding;
	__u64 regs_ptr;	/* pointer to struct hv_register_assoc */
};

struct mshv_install_intercept {
	__u32 access_type_mask;
	__u32 intercept_type; /* enum hv_intercept_type */
	union hv_intercept_parameters intercept_parameter;
};

struct mshv_assert_interrupt {
	union hv_interrupt_control control;
	__u64 dest_addr;
	__u32 vector;
	__u32 padding;
};

#ifdef HV_SUPPORTS_VP_STATE

struct mshv_vp_state {
	__u32 type;			     /* enum hv_get_set_vp_state_type */
	__u32 padding;
	struct hv_vp_state_data_xsave xsave; /* only for xsave request */
	__u64 buf_size;			     /* If xsave, must be page-aligned */
	/*
	 * If xsave, buf_ptr is a pointer to bytes, and must be page-aligned
	 * If lapic, buf_ptr is a pointer to struct hv_local_interrupt_controller_state
	 */
	__u64 buf_ptr;
};

#endif

struct mshv_partition_property {
	__u32 property_code; /* enum hv_partition_property_code */
	__u32 padding;
	__u64 property_value;
};

struct mshv_translate_gva {
	__u64 gva;
	__u64 flags;
	/* output */
	union hv_translate_gva_result result;
	__u64 gpa;
};

#define MSHV_IRQFD_FLAG_DEASSIGN (1 << 0)
#define MSHV_IRQFD_FLAG_RESAMPLE (1 << 1)

struct mshv_irqfd {
	__s32 fd;
	__s32 resamplefd;
	__u32 gsi;
	__u32 flags;
};

enum mshv_ioeventfd_flag {
	MSHV_IOEVENTFD_FLAG_NR_DATAMATCH,
	MSHV_IOEVENTFD_FLAG_NR_PIO,
	MSHV_IOEVENTFD_FLAG_NR_DEASSIGN,
	MSHV_IOEVENTFD_FLAG_NR_COUNT,
};

#define MSHV_IOEVENTFD_FLAG_DATAMATCH (1 << MSHV_IOEVENTFD_FLAG_NR_DATAMATCH)
#define MSHV_IOEVENTFD_FLAG_PIO       (1 << MSHV_IOEVENTFD_FLAG_NR_PIO)
#define MSHV_IOEVENTFD_FLAG_DEASSIGN  (1 << MSHV_IOEVENTFD_FLAG_NR_DEASSIGN)

#define MSHV_IOEVENTFD_VALID_FLAG_MASK  ((1 << MSHV_IOEVENTFD_FLAG_NR_COUNT) - 1)

struct mshv_ioeventfd {
	__u64 datamatch;
	__u64 addr;		/* legal pio/mmio address */
	__u32 len;		/* 1, 2, 4, or 8 bytes    */
	__s32 fd;
	__u32 flags;		/* bitwise OR of MSHV_IOEVENTFD_FLAG_'s */
	__u32 padding;
};

struct mshv_msi_routing_entry {
	__u32 gsi;
	__u32 address_lo;
	__u32 address_hi;
	__u32 data;
};

struct mshv_msi_routing {
	__u32 nr;
	__u32 padding;
	struct mshv_msi_routing_entry entries[];
};

#ifdef HV_SUPPORTS_REGISTER_INTERCEPT
struct mshv_register_intercept_result {
	__u32 intercept_type; /* enum hv_intercept_type */
	union hv_register_intercept_result_parameters parameters;
};
#endif

struct mshv_signal_event_direct {
	__u32 vp;
	__u8 vtl;
	__u8 sint;
	__u16 flag;
	/* output */
	__u8 newly_signaled;
	__u8 padding[3];
};

struct mshv_post_message_direct {
	__u32 vp;
	__u8 vtl;
	__u8 sint;
	__u16 length;
	__u8 message[HV_MESSAGE_SIZE];
};

struct mshv_register_deliverabilty_notifications {
	__u32 vp;
	__u32 padding;
	__u64 flag;
};

struct mshv_get_vp_cpuid_values {
	__u32 function;
	__u32 index;
	/* output */
	__u32 eax;
	__u32 ebx;
	__u32 ecx;
	__u32 edx;
};

struct mshv_vp_run_registers {
	__u64 message_ptr; /* pointer to struct hv_message */
	struct mshv_vp_registers registers;
};

struct mshv_get_gpa_pages_access_state {
	__u64 flags;
	__u64 hv_gpa_page_number;
	__u32 count;		/* in - requested. out - actual */
	__u32 padding;
	__u64 states_ptr;	/* pointer to union hv_gpa_page_access_state */
} __packed;

struct mshv_vtl_set_eventfd {
	__s32 fd;
	__u32 flag;
};

struct mshv_vtl_signal_event {
	__u32 connection_id;
	__u32 flag;
};

struct mshv_vtl_sint_post_msg {
	__u64 message_type;
	__u32 connection_id;
	__u32 payload_size;
	__u64 payload_ptr; /* pointer to message payload (bytes) */
};

struct mshv_vtl_ram_disposition {
	__u64 start_pfn;
	__u64 last_pfn;
};

struct mshv_vtl_set_poll_file {
	__u32 cpu;
	__u32 fd;
};

struct mshv_vtl_hvcall_setup {
	__u64 bitmap_size;
	__u64 allow_bitmap_ptr; /* pointer to __u64 */
};

struct mshv_vtl_hvcall {
	__u64 control;
	__u64 input_size;
	__u64 input_ptr; /* pointer to input struct */
	/* output */
	__u64 status;
	__u64 output_size;
	__u64 output_ptr; /* pointer to output struct */
};

struct mshv_sint_mask {
	__u8 mask;
	__u8 reserved[7];
};

struct mshv_tdcall {
	__u64 rax;	/* Call code and returned status */
	__u64 rcx;
	__u64 rdx;
	__u64 r8;
	__u64 r9;
	__u64 r10_out;	/* Only supported as output */
	__u64 r11_out;	/* Only supported as output */
} __packed;

struct mshv_pvalidate {
	__u64 start_pfn;
	__u64 page_count;
	__u8 validate;
	__u8 terminate_on_failure;
	__u8 ram;
	__u8 padding;
} __packed;

struct mshv_rmpadjust {
	__u64 start_pfn;
	__u64 page_count;
	__u64 value;
	__u8 terminate_on_failure;
	__u8 ram;
	__u8 padding[6];
} __packed;

struct mshv_rmpquery {
	__u64 start_pfn;
	__u64 page_count;
	__u8 terminate_on_failure;
	__u8 ram;
	__u8 padding[6];
	__u64 *flags;
	__u64 *page_size;
	__u64 *pages_processed;
} __packed;

struct mshv_invlpgb {
	__u64 rax;
	__u32 pad0;
	__u32 edx;
	__u32 pad1;
	__u32 ecx;
} __packed;

#define MSHV_IOCTL 0xB8

/* mshv device */
#define MSHV_CHECK_EXTENSION    _IOW(MSHV_IOCTL, 0x00, __u32)
#define MSHV_CREATE_PARTITION	_IOW(MSHV_IOCTL, 0x01, struct mshv_create_partition)

/* partition device */
#define MSHV_MAP_GUEST_MEMORY	_IOW(MSHV_IOCTL, 0x02, struct mshv_user_mem_region)
#define MSHV_UNMAP_GUEST_MEMORY	_IOW(MSHV_IOCTL, 0x03, struct mshv_user_mem_region)
#define MSHV_CREATE_VP		_IOW(MSHV_IOCTL, 0x04, struct mshv_create_vp)
#define MSHV_INSTALL_INTERCEPT	_IOW(MSHV_IOCTL, 0x08, struct mshv_install_intercept)
#define MSHV_ASSERT_INTERRUPT	_IOW(MSHV_IOCTL, 0x09, struct mshv_assert_interrupt)
#define MSHV_SET_PARTITION_PROPERTY \
				_IOW(MSHV_IOCTL, 0xC, struct mshv_partition_property)
#define MSHV_GET_PARTITION_PROPERTY \
				_IOWR(MSHV_IOCTL, 0xD, struct mshv_partition_property)
#define MSHV_IRQFD		_IOW(MSHV_IOCTL, 0xE, struct mshv_irqfd)
#define MSHV_IOEVENTFD		_IOW(MSHV_IOCTL, 0xF, struct mshv_ioeventfd)
#define MSHV_SET_MSI_ROUTING	_IOW(MSHV_IOCTL, 0x11, struct mshv_msi_routing)
#define MSHV_GET_GPA_ACCESS_STATES \
				_IOWR(MSHV_IOCTL, 0x12, struct mshv_get_gpa_pages_access_state)
/* vp device */
#define MSHV_GET_VP_REGISTERS   _IOWR(MSHV_IOCTL, 0x05, struct mshv_vp_registers)
#define MSHV_SET_VP_REGISTERS   _IOW(MSHV_IOCTL, 0x06, struct mshv_vp_registers)
#define MSHV_RUN_VP		_IOR(MSHV_IOCTL, 0x07, struct hv_message)
#define MSHV_RUN_VP_REGISTERS	_IOWR(MSHV_IOCTL, 0x1C, struct mshv_vp_run_registers)
#ifdef HV_SUPPORTS_VP_STATE
#define MSHV_GET_VP_STATE	_IOWR(MSHV_IOCTL, 0x0A, struct mshv_vp_state)
#define MSHV_SET_VP_STATE	_IOWR(MSHV_IOCTL, 0x0B, struct mshv_vp_state)
#endif
#define MSHV_TRANSLATE_GVA	_IOWR(MSHV_IOCTL, 0x0E, struct mshv_translate_gva)
#ifdef HV_SUPPORTS_REGISTER_INTERCEPT
#define MSHV_VP_REGISTER_INTERCEPT_RESULT \
				_IOW(MSHV_IOCTL, 0x17, struct mshv_register_intercept_result)
#endif
#define MSHV_SIGNAL_EVENT_DIRECT \
	_IOWR(MSHV_IOCTL, 0x18, struct mshv_signal_event_direct)
#define MSHV_POST_MESSAGE_DIRECT \
	_IOW(MSHV_IOCTL, 0x19, struct mshv_post_message_direct)
#define MSHV_REGISTER_DELIVERABILITY_NOTIFICATIONS \
	_IOW(MSHV_IOCTL, 0x1A, struct mshv_register_deliverabilty_notifications)
#define MSHV_GET_VP_CPUID_VALUES \
	_IOWR(MSHV_IOCTL, 0x1B, struct mshv_get_vp_cpuid_values)

/* vtl device */
#define MSHV_CREATE_VTL			_IOR(MSHV_IOCTL, 0x1D, char)
#define MSHV_VTL_ADD_VTL0_MEMORY	_IOW(MSHV_IOCTL, 0x21, struct mshv_vtl_ram_disposition)
#define MSHV_VTL_SET_POLL_FILE		_IOW(MSHV_IOCTL, 0x25, struct mshv_vtl_set_poll_file)
#define MSHV_VTL_RETURN_TO_LOWER_VTL	_IO(MSHV_IOCTL, 0x27)

/* For x86-64 SEV-SNP only */
#define MSHV_VTL_PVALIDATE	_IOW(MSHV_IOCTL, 0x28, struct mshv_pvalidate)
#define MSHV_VTL_RMPADJUST	_IOW(MSHV_IOCTL, 0x29, struct mshv_rmpadjust)

/* For x86-64 TDX only */
#define MSHV_VTL_TDCALL _IOWR(MSHV_IOCTL, 0x32, struct mshv_tdcall)
#define MSHV_VTL_READ_VMX_CR4_FIXED1 _IOR(MSHV_IOCTL, 0x33, __u64)

/* For x86-64 only */
#define MSHV_VTL_GUEST_VSM_VMSA_PFN	_IOWR(MSHV_IOCTL, 0x34, __u64)

/* For x86-64 SEV-SNP only */
#define MSHV_VTL_RMPQUERY	_IOW(MSHV_IOCTL, 0x35, struct mshv_rmpquery)
#define MSHV_VTL_INVLPGB	_IOW(MSHV_IOCTL, 0x36, struct mshv_invlpgb)
#define MSHV_VTL_TLBSYNC	_IO(MSHV_IOCTL, 0x37)

/* VMBus device IOCTLs */
#define MSHV_SINT_SIGNAL_EVENT    _IOW(MSHV_IOCTL, 0x22, struct mshv_vtl_signal_event)
#define MSHV_SINT_POST_MESSAGE    _IOW(MSHV_IOCTL, 0x23, struct mshv_vtl_sint_post_msg)
#define MSHV_SINT_SET_EVENTFD     _IOW(MSHV_IOCTL, 0x24, struct mshv_vtl_set_eventfd)
#define MSHV_SINT_PAUSE_MESSAGE_STREAM     _IOW(MSHV_IOCTL, 0x25, struct mshv_sint_mask)

/* hv_hvcall device */
#define MSHV_HVCALL_SETUP        _IOW(MSHV_IOCTL, 0x1E, struct mshv_vtl_hvcall_setup)
#define MSHV_HVCALL              _IOWR(MSHV_IOCTL, 0x1F, struct mshv_vtl_hvcall)

/* register page mapping example:
 * struct hv_vp_register_page *regs = mmap(NULL,
 *					   4096,
 *					   PROT_READ | PROT_WRITE,
 *					   MAP_SHARED,
 *					   vp_fd,
 *					   HV_VP_MMAP_REGISTERS_OFFSET);
 * munmap(regs, 4096);
 */

#endif
