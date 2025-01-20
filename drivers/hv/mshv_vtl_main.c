// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * Author:
 *   Saurabh Sengar <ssengar@microsoft.com>
 */

#include <linux/kernel.h>
#include <linux/hashtable.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/anon_inodes.h>
#include <linux/pfn_t.h>
#include <linux/cpuhotplug.h>
#include <linux/count_zeros.h>
#include <linux/context_tracking.h>
#include <linux/eventfd.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <asm/boot.h>
#include <asm/trace/hyperv.h>
#include <linux/tick.h>
#include <asm/pgalloc.h>
#include <trace/events/ipi.h>
#include <uapi/linux/mshv.h>
#include <asm/set_memory.h>

#ifdef CONFIG_X86_64

#include <asm/apic.h>
#include <uapi/asm/mtrr.h>
#include <asm/sev.h>
#include <asm/tdx.h>
#include <asm/fpu/xcr.h>
#include <asm/debugreg.h>
#include <asm/vmx.h>

#include "../../kernel/fpu/legacy.h"

#endif

#include "mshv.h"
#include "mshv_vtl.h"
#include "hyperv_vmbus.h"

MODULE_AUTHOR("Microsoft");
MODULE_LICENSE("GPL");

#define MSHV_ENTRY_REASON_LOWER_VTL_CALL     0x1
#define MSHV_ENTRY_REASON_INTERRUPT          0x2
#define MSHV_ENTRY_REASON_INTERCEPT          0x3

#define MAX_GUEST_MEM_SIZE	BIT_ULL(40)
#define MSHV_PG_OFF_CPU_MASK	0xFFFF
#define MSHV_REAL_OFF_SHIFT	16
#define MSHV_RUN_PAGE_OFFSET	0
#define MSHV_REG_PAGE_OFFSET	1
#define MSHV_VMSA_PAGE_OFFSET	2
#define MSHV_APIC_PAGE_OFFSET	3
#define MSHV_VMSA_GUEST_VSM_PAGE_OFFSET	4
#define VTL2_VMBUS_SINT_INDEX	7

#ifdef CONFIG_X86_64

static __always_inline unsigned long mshv_vtl_smap_save(void)
{
	unsigned long flags = 0;

	if (boot_cpu_has(X86_FEATURE_SMAP))
		asm volatile ("pushf; pop %0; stac\n\t" : "=rm" (flags) : : "memory", "cc");

	return flags;
}

static __always_inline void mshv_vtl_smap_restore(unsigned long flags)
{
	if (boot_cpu_has(X86_FEATURE_SMAP))
		asm volatile ("push %0; popf\n\t" : : "g" (flags) : "memory", "cc");
}

#endif

static struct device *mem_dev;

static struct tasklet_struct msg_dpc;
static wait_queue_head_t fd_wait_queue;
static bool has_message;
static struct eventfd_ctx *flag_eventfds[HV_EVENT_FLAGS_COUNT];
static DEFINE_MUTEX(flag_lock);
static bool __read_mostly mshv_has_reg_page;

struct mshv_vtl_hvcall_fd {
	u64 allow_bitmap[2 * PAGE_SIZE];
	bool allow_map_intialized;
	struct mutex init_mutex;
	struct miscdevice *dev;
};

struct mshv_vtl_poll_file {
	struct file *file;
	wait_queue_entry_t wait;
	wait_queue_head_t *wqh;
	poll_table pt;
	int cpu;
};

struct mshv_vtl {
	struct device *module_dev;
	u64 id;
	refcount_t ref_count;
};

union mshv_synic_overlay_page_msr {
	u64 as_u64;
	struct {
		u64 enabled: 1;
		u64 reserved: 11;
		u64 pfn: 52;
	};
};

union hv_register_vsm_capabilities {
	u64 as_uint64;
	struct {
		u64 dr6_shared: 1;
		u64 mbec_vtl_mask: 16;
		u64 deny_lower_vtl_startup: 1;
		u64 supervisor_shadow_stack: 1;
		u64 hardware_hvpt_available: 1;
		u64 software_hvpt_available: 1;
		u64 hardware_hvpt_range_bits: 6;
		u64 intercept_page_available: 1;
		u64 return_action_available: 1;
		u64 reserved: 35;
	} __packed;
};

union hv_register_vsm_page_offsets {
	struct {
		u64 vtl_call_offset : 12;
		u64 vtl_return_offset : 12;
		u64 reserved_mbz : 40;
	};
	u64 as_uint64;
} __packed;

struct mshv_vtl_per_cpu {
	struct mshv_vtl_run *run;
	struct page *reg_page;
	struct page *vmsa_page;
	struct page *vmsa_guest_vsm_page;
#if defined(CONFIG_X86_64) && defined(CONFIG_INTEL_TDX_GUEST)
	struct page *tdx_apic_page;
	u64 xss;
	u64 l1_msr_kernel_gs_base;
	u64 l1_msr_star;
	u64 l1_msr_lstar;
	u64 l1_msr_sfmask;
	u64 l1_msr_tsc_aux;
#endif
};

static struct mutex	mshv_vtl_poll_file_lock;
static union hv_register_vsm_page_offsets mshv_vsm_page_offsets;
static union hv_register_vsm_capabilities mshv_vsm_capabilities;

static DEFINE_PER_CPU(struct mshv_vtl_poll_file, mshv_vtl_poll_file);
static DEFINE_PER_CPU(unsigned long long, num_vtl0_transitions);
static DEFINE_PER_CPU(struct mshv_vtl_per_cpu, mshv_vtl_per_cpu);

struct mshv_vtl_run *mshv_vtl_this_run(void)
{
	return *this_cpu_ptr(&mshv_vtl_per_cpu.run);
}

static struct mshv_vtl_run *mshv_vtl_cpu_run(int cpu)
{
	return *per_cpu_ptr(&mshv_vtl_per_cpu.run, cpu);
}

static struct page *mshv_vtl_cpu_reg_page(int cpu)
{
	return *per_cpu_ptr(&mshv_vtl_per_cpu.reg_page, cpu);
}

#if defined(CONFIG_X86_64) && defined(CONFIG_INTEL_TDX_GUEST)

static struct page *tdx_apic_page(int cpu)
{
	return *per_cpu_ptr(&mshv_vtl_per_cpu.tdx_apic_page, cpu);
}

static struct page *tdx_this_apic_page(void)
{
	return *this_cpu_ptr(&mshv_vtl_per_cpu.tdx_apic_page);
}

/*
 * For ICR emulation on TDX, we need a fast way to map APICIDs to CPUIDs.
 * Instead of iterating through all CPUs for each target in the ICR destination field
 * precompute a mapping. APICIDs can be sparse so we have to use a hash table.
 * Note: CPU hotplug is not supported (both by this code and by the paravisor in general)
 */
static DEFINE_HASHTABLE(apicid_to_cpuid, bits_per(NR_CPUS));
struct apicid_to_cpuid_entry {
	int apicid;
	unsigned int cpuid;
	struct hlist_node node;
};

/*
 * Sets the cpu described by apicid in cpu_mask.
 * Returns 0 on success, -EINVAL if no cpu matches the apicid.
 */
static int mshv_tdx_set_cpumask_from_apicid(int apicid, struct cpumask *cpu_mask)
{
	struct apicid_to_cpuid_entry *found;

	hash_for_each_possible(apicid_to_cpuid, found, node, apicid) {
		if (found->apicid != apicid)
			continue;

		cpumask_set_cpu(found->cpuid, cpu_mask);
		return 0;
	}

	return -EINVAL;
}
#endif

static long __mshv_vtl_ioctl_check_extension(u32 arg)
{
	switch (arg) {
	case MSHV_CAP_REGISTER_PAGE:
		return mshv_has_reg_page;
	case MSHV_CAP_VTL_RETURN_ACTION:
		return mshv_vsm_capabilities.return_action_available;
	case MSHV_CAP_DR6_SHARED:
		return mshv_vsm_capabilities.dr6_shared;
	}

	return -EOPNOTSUPP;
}

static void mshv_vtl_configure_reg_page(struct mshv_vtl_per_cpu *per_cpu)
{
#ifdef CONFIG_X86_64
	struct hv_register_assoc reg_assoc = {};
	union mshv_synic_overlay_page_msr overlay = {};
	struct page *reg_page;
	union hv_input_vtl vtl = { .as_uint8 = 0 };
	int ret;

	reg_page = alloc_page(GFP_KERNEL | __GFP_ZERO | __GFP_RETRY_MAYFAIL);
	if (!reg_page) {
		WARN(1, "failed to allocate register page\n");
		return;
	}

	overlay.enabled = 1;
	overlay.pfn = page_to_phys(reg_page) >> HV_HYP_PAGE_SHIFT;
	reg_assoc.name = HV_X64_REGISTER_REG_PAGE;
	reg_assoc.value.reg64 = overlay.as_u64;

	ret = hv_call_set_vp_registers(HV_VP_INDEX_SELF, HV_PARTITION_ID_SELF,
				     1, vtl, &reg_assoc);
	if (ret) {
		__free_page(reg_page);

		if (ret == -EINVAL) {
			/*
			 * TODO: replace `ret == -EINVAL` with
			 *       `ret == HV_STATUS_INVALID_PARAMETER'.
			 *
			 * The older hypervisors might not support the register page.
			 * This feature is a performance optimization enabling the user
			 * mode not to use hypercalls for setting general purpose registers.
			 * The register page not being present or not being used isn't a bug.
			 *
			 * If the register page is not supported, the hypervisor returns
			 * `HV_STATUS_INVALID_PARAMETER`. That cannot be detected here as the
			 * `hv_call_set_vp_registers` above calls `hv_status_to_errno` whereby
			 * the original `HV_STATUS` is lost having been converted to `errno`.
			 *
			 * The best approximation is `ret == -EINVAL`. It is imprecise because of
			 * `HV_STATUS` to `errno` conversion, and due to that this is a necessary
			 * condition but not a sufficient one.
			 *
			 * The situation could be rectified by refactoring the code of
			 * `hv_call_set_vp_registers`by pulling out the hypercall-related part
			 * into some `hv_call_set_vp_registers_raw` function. Then here we could
			 * call `hv_call_set_vp_registers_raw` to be able to be precise when detecting
			 * whether the register page is available or not.
			 */
			pr_info("not using the register page");
		} else {
			pr_emerg("error when setting up the register page: %d\n", ret);
			BUG();
		}
	} else {
		per_cpu->reg_page = reg_page;
		mshv_has_reg_page = true;
	}
#else
	pr_debug("not using the register page");
#endif
}

#ifdef CONFIG_X86_64
static int mshv_configure_vmsa_page(u8 target_vtl, struct page** vmsa_page)
{
	struct page *page;
	struct hv_register_assoc reg_assoc = {};
	union hv_input_vtl vtl = {};
	int ret;

	/* Might be called from the page fault handling code hence GFP_ATOMIC */
	page = alloc_page(GFP_ATOMIC | __GFP_ZERO);
	if (!page)
		return -ENOMEM;

	if (target_vtl == 0) {
		reg_assoc.name = HV_X64_REGISTER_SEV_CONTROL;
		reg_assoc.value.reg64 = page_to_phys(page) | 1;

		vtl.use_target_vtl = 1;
		vtl.target_vtl = 0;
		ret = hv_call_set_vp_registers(HV_VP_INDEX_SELF, HV_PARTITION_ID_SELF,
						1, vtl, &reg_assoc);

		if (ret) {
			pr_err("failed to set VMSA page for VTL %d in hypervisor: %d\n",
			       target_vtl, ret);
			__free_page(page);
			return ret;
		}
	}

	/*
	 * Use VMPL1 as the target VMPL when setting a page bit, as
	 * required by AMD.
	 */
	ret = rmpadjust((unsigned long)page_address(page),
				RMP_PG_SIZE_4K, 1 | RMPADJUST_VMSA_PAGE_BIT);
	if (ret) {
		pr_emerg("failed to set VMSA page bit: %d\n", ret);
		return ret;
	}

	*vmsa_page = page;
	return 0;
}

#endif

static void mshv_vtl_synic_enable_regs(unsigned int cpu)
{
	union hv_synic_sint sint;

	sint.as_uint64 = 0;
	sint.vector = vmbus_interrupt;
	sint.masked = false;
	sint.auto_eoi = hv_recommend_using_aeoi();

	/*
	 * Enable intercepts, used when there is no intercept page, or
	 * for proxy interrupts for SNP.
	 */
	if (!mshv_vsm_capabilities.intercept_page_available
	    || hv_isolation_type_tdx()
	    || hv_isolation_type_snp())
		hv_set_register(HV_MSR_SINT0 + HV_SYNIC_INTERCEPTION_SINT_INDEX,
				sint.as_uint64);

	/* VTL2 Host VSP SINT is (un)masked when the user mode requests that */
}

static int mshv_vtl_get_vsm_regs(void)
{
	struct hv_register_assoc registers[2];
	union hv_input_vtl input_vtl;
	int ret, count = 0;

	/*
	 * BUGBUG-ISOLATION: these registers all untrusted on hardware iso platforms.
	 * Should we even query them? they seem meaningless on hardware iso.
	 */
	if (hv_isolation_type_tdx())
		pr_info("TODO: TDX detected, should skip vsm register query");

	input_vtl.as_uint8 = 0;
	registers[count++].name = HV_REGISTER_VSM_CAPABILITIES;

	/* Code page offset register is not supported on ARM */
#ifdef CONFIG_X86_64
	if (!hv_isolation_type_snp() && !hv_isolation_type_tdx())
		registers[count++].name = HV_REGISTER_VSM_CODE_PAGE_OFFSETS;
#endif

	ret = hv_call_get_vp_registers(HV_VP_INDEX_SELF, HV_PARTITION_ID_SELF,
				       count, input_vtl, registers);
	if (ret)
		return ret;

	mshv_vsm_capabilities.as_uint64 = registers[0].value.reg64;
#ifdef CONFIG_X86_64
	if (hv_isolation_type_snp())
		mshv_vsm_capabilities.dr6_shared = 0;
	else if (hv_isolation_type_tdx()) {
		mshv_vsm_capabilities.dr6_shared = 1;
	} else {
		mshv_vsm_page_offsets.as_uint64 = registers[1].value.reg64;
		pr_debug("%s: VSM code page offsets: %#016llx\n", __func__,
			 mshv_vsm_page_offsets.as_uint64);
	}
#endif

	return ret;
}

static int __maybe_unused mshv_vtl_configure_vsm_partition(struct device *dev)
{
	union hv_register_vsm_partition_config config;
	struct hv_register_assoc reg_assoc;
	union hv_input_vtl input_vtl;

	config.as_u64 = 0;
	config.default_vtl_protection_mask = HV_MAP_GPA_PERMISSIONS_MASK;
	config.enable_vtl_protection = 1;
	config.zero_memory_on_reset = 1;
	config.intercept_vp_startup = 1;
	config.intercept_cpuid_unimplemented = 1;

	if (mshv_vsm_capabilities.intercept_page_available) {
		dev_dbg(dev, "using intercept page\n");
		config.intercept_page = 1;
	}

	reg_assoc.name = HV_REGISTER_VSM_PARTITION_CONFIG;
	reg_assoc.value.reg64 = config.as_u64;
	input_vtl.as_uint8 = 0;

	return hv_call_set_vp_registers(HV_VP_INDEX_SELF, HV_PARTITION_ID_SELF,
				       1, input_vtl, &reg_assoc);
}

static void mshv_vtl_scan_proxy_interrupts(struct hv_per_cpu_context *per_cpu)
{
	struct hv_message *msg;
	u32 message_type;
	struct hv_x64_proxy_interrupt_message_payload *proxy;
	struct mshv_vtl_run *run;
	u32 vector;

	msg = (struct hv_message *)per_cpu->synic_message_page + HV_SYNIC_INTERCEPTION_SINT_INDEX;
	for (;;) {
		message_type = READ_ONCE(msg->header.message_type);
		if (message_type == HVMSG_NONE)
			break;

		if (message_type != HVMSG_X64_PROXY_INTERRUPT_INTERCEPT) {
			WARN_ONCE(1, "Unexpected message type: %d\n", message_type);
			vmbus_signal_eom(msg, message_type);
			continue;
		}

		proxy = (struct hv_x64_proxy_interrupt_message_payload *)msg->u.payload;
		run = mshv_vtl_this_run();

		if (proxy->assert_multiple) {
			for (int i = 0; i < 8; i++) {
				const u32 masked_irr = ~READ_ONCE(run->proxy_irr_blocked[i]) &
					READ_ONCE(proxy->u.asserted_irr[i]);

				/*
				 * nb atomic_t cast: See comment in
				 * mshv_tdx_handle_simple_icr_write
				 */
				atomic_or(masked_irr, (atomic_t *)&run->proxy_irr[i]);
			}
		} else {
			/* A malicious hypervisor might set a vector > 255. */
			vector = READ_ONCE(proxy->u.asserted_vector) & 0xff;
			const u32 bank = vector / 32;
			const u32 masked_irr = BIT(vector % 32) &
				~READ_ONCE(run->proxy_irr_blocked[bank]);

			/* nb atomic_t cast: See comment in mshv_tdx_handle_simple_icr_write */
			atomic_or(masked_irr, (atomic_t *)&run->proxy_irr[bank]);
		}

		WRITE_ONCE(run->scan_proxy_irr, 1);
		vmbus_signal_eom(msg, message_type);
	}
}

static void mshv_vtl_vmbus_isr(void)
{
	struct hv_per_cpu_context *per_cpu;
	struct hv_message *msg;
	u32 message_type;
	union hv_synic_event_flags *event_flags;
	unsigned long word;
	int i, j;
	struct eventfd_ctx *eventfd;

	per_cpu = this_cpu_ptr(hv_context.cpu_context);
	if (smp_processor_id() == 0) {
		msg = (struct hv_message *)per_cpu->synic_message_page + VTL2_VMBUS_SINT_INDEX;
		message_type = READ_ONCE(msg->header.message_type);
		if (message_type != HVMSG_NONE)
			tasklet_schedule(&msg_dpc);
	}

	/* Handle proxied interrupts from the host. */
	if (hv_isolation_type_tdx() || hv_isolation_type_snp())
		mshv_vtl_scan_proxy_interrupts(per_cpu);

	event_flags = (union hv_synic_event_flags *)per_cpu->synic_event_page +
			VTL2_VMBUS_SINT_INDEX;

	for (i = 0; i < HV_EVENT_FLAGS_LONG_COUNT; i++) {
		if (READ_ONCE(event_flags->flags[i])) {
			word = xchg(&event_flags->flags[i], 0);
			for_each_set_bit(j, &word, BITS_PER_LONG) {
				rcu_read_lock();
				eventfd = READ_ONCE(flag_eventfds[i * BITS_PER_LONG + j]);
				if (eventfd)
					eventfd_signal(eventfd, 1);
				rcu_read_unlock();
			}
		}
	}

	vmbus_isr();
}

#if defined(CONFIG_X86_64) && defined(CONFIG_INTEL_TDX_GUEST)

struct tdx_extended_field_code {
	union {
		u64 as_u64;
		struct {
			u64 field_code        : 24;
			u64 reserved_z0       : 8;
			u64 field_size        : 2;
			u64 last_element      : 4;
			u64 last_field        : 9;
			u64 reserved_z1       : 3;
			u64 increment_size    : 1;
			u64 write_mask_valid  : 1;
			u64 context_code      : 3;
			u64 reserved_z2       : 1;
			u64 class_code        : 6;
			u64 reserved_z3       : 1;
			u64 non_arch          : 1;
		};
	};
};

struct vmx_vmcs_field {
	union {
		u32 as_u32;

		struct {
			u32 access_high:1;
			u32 index:9;
			u32 type:2;		/* Use VMX_VMCS_FIELD_TYPE_* */
			u32 reserved_zero:1;
			u32 field_width:2;	/* Use VMX_VMCS_FIELD_WIDTH_* */
			u32 reserved:17;
		};
	};
};

static void mshv_write_tdx_apic_page(u64 apic_page_gpa)
{
	struct tdx_extended_field_code extended_field_code;
	struct vmx_vmcs_field vmcs_field;
	u64 status = 0;

	extended_field_code.as_u64 = 0;
	extended_field_code.field_code = 0x00002012; /* VMX_VMCS_VIRTUAL_APIC_PAGE */
	extended_field_code.context_code = 2;	     /* TDX_CONTEXT_CODE_VP_SCOPE  */
	extended_field_code.class_code = 36;	     /* L2_VM1 aka VTL0		   */

	vmcs_field.as_u32 = 0x00002012;
	extended_field_code.field_size = 3;	     /* TDX_FIELD_SIZE_64_BIT	   */

	/* Issue tdg_vp_wr to set the apic page. */
	status = __tdx_module_call(10, 0, extended_field_code.as_u64,
				   apic_page_gpa, 0xFFFFFFFFFFFFFFFF, NULL);
	pr_debug("set_apic_page gpa: %llx status: %llx\n", apic_page_gpa, status);

	if (status != 0)
		panic("write tdx apic page failed: %llx\n", status);
}

#endif

static int mshv_vtl_alloc_context(unsigned int cpu)
{
	struct mshv_vtl_per_cpu *per_cpu = this_cpu_ptr(&mshv_vtl_per_cpu);
	struct page *run_page;

	run_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!run_page)
		return -ENOMEM;

	per_cpu->run = page_address(run_page);
	if (hv_isolation_type_tdx()) {
#if defined(CONFIG_X86_64) && defined(CONFIG_INTEL_TDX_GUEST)
		struct page *tdx_apic_page;

		tdx_apic_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!tdx_apic_page)
			return -ENOMEM;

		per_cpu->tdx_apic_page = tdx_apic_page;

		/*
		 * Capture the initial syscall MSRs to be restored after VP.ENTER.
		 * TODO TDX: Needs review from kernel experts.
		 */
		rdmsrl(MSR_KERNEL_GS_BASE, per_cpu->l1_msr_kernel_gs_base);
		rdmsrl(MSR_STAR, per_cpu->l1_msr_star);
		rdmsrl(MSR_LSTAR, per_cpu->l1_msr_lstar);
		rdmsrl(MSR_SYSCALL_MASK, per_cpu->l1_msr_sfmask);

		/* Enable the apic page. */
		mshv_write_tdx_apic_page(page_to_phys(tdx_apic_page));
#endif
	} else if (hv_isolation_type_snp()) {
#ifdef CONFIG_X86_64
		int ret;

		ret = mshv_configure_vmsa_page(0, &per_cpu->vmsa_page);
		if (ret < 0)
			return ret;
#endif
	} else if (mshv_vsm_capabilities.intercept_page_available)
		mshv_vtl_configure_reg_page(per_cpu);

	mshv_vtl_synic_enable_regs(cpu);

	return 0;
}

static int hv_vtl_setup_synic(void)
{
	int ret;

	/* Use our isr to first filter out packets destined for userspace */
	hv_setup_vmbus_handler(mshv_vtl_vmbus_isr);
	hv_setup_percpu_vmbus_handler(mshv_vtl_vmbus_isr);

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "hyperv/vtl:online",
				mshv_vtl_alloc_context, NULL);
	if (ret < 0)
		return ret;

	return 0;
}

static int vtl_get_vp_registers(u16 count,
				struct hv_register_assoc *registers)
{
	union hv_input_vtl input_vtl;

	input_vtl.as_uint8 = 0;
	input_vtl.use_target_vtl = 1;
	return hv_call_get_vp_registers(HV_VP_INDEX_SELF, HV_PARTITION_ID_SELF,
					count, input_vtl, registers);
}

static int vtl_set_vp_registers(u16 count,
				struct hv_register_assoc *registers)
{
	union hv_input_vtl input_vtl;

	input_vtl.as_uint8 = 0;
	input_vtl.use_target_vtl = 1;
	return hv_call_set_vp_registers(HV_VP_INDEX_SELF, HV_PARTITION_ID_SELF,
					count, input_vtl, registers);
}

#define DECRYPTED_MASK	(1ul << 51)

static int mshv_vtl_ioctl_add_vtl0_mem(struct mshv_vtl *vtl, void __user *arg)
{
	struct mshv_vtl_ram_disposition vtl0_mem;
	struct dev_pagemap *pgmap;
	void *addr;
	bool decrypted;

	if (copy_from_user(&vtl0_mem, arg, sizeof(vtl0_mem)))
		return -EFAULT;

	decrypted = vtl0_mem.start_pfn & DECRYPTED_MASK;
	vtl0_mem.start_pfn &= ~DECRYPTED_MASK;
	vtl0_mem.last_pfn &= ~DECRYPTED_MASK;
	if (vtl0_mem.last_pfn <= vtl0_mem.start_pfn) {
		dev_err(vtl->module_dev, "range start pfn (%llx) > end pfn (%llx)\n",
			vtl0_mem.start_pfn, vtl0_mem.last_pfn);
		return -EFAULT;
	}

	pgmap = kzalloc(sizeof(*pgmap), GFP_KERNEL);
	if (!pgmap)
		return -ENOMEM;

	pgmap->ranges[0].start = PFN_PHYS(vtl0_mem.start_pfn);
	pgmap->ranges[0].end = PFN_PHYS(vtl0_mem.last_pfn) - 1;
	pgmap->nr_range = 1;
	pgmap->type = MEMORY_DEVICE_GENERIC;
	if (decrypted)
		pgmap->flags = PGMAP_DECRYPTED;

	/*
	 * Determine the highest page order that can be used for the range.
	 * This works best when the range is aligned; i.e. start and length.
	 */
	pgmap->vmemmap_shift = count_trailing_zeros(vtl0_mem.start_pfn | vtl0_mem.last_pfn);
	dev_dbg(vtl->module_dev,
		"Add VTL0 memory: start: 0x%llx, end_pfn: 0x%llx, page order: %lu\n",
		vtl0_mem.start_pfn, vtl0_mem.last_pfn, pgmap->vmemmap_shift);

	addr = devm_memremap_pages(mem_dev, pgmap);
	if (IS_ERR(addr)) {
		dev_err(vtl->module_dev, "devm_memremap_pages error: %ld\n", PTR_ERR(addr));
		kfree(pgmap);
		return -EFAULT;
	}

	/* Don't free pgmap, since it has to stick around until the memory
	 * is unmapped, which will never happen as there is no scenario
	 * where VTL0 can be released/shutdown without bringing down VTL2.
	 */
	return 0;
}

static void mshv_vtl_cancel(int cpu)
{
	int here = get_cpu();

	if (here != cpu) {
		if (!xchg_relaxed(&mshv_vtl_cpu_run(cpu)->cancel, 1))
			smp_send_reschedule(cpu);
	} else {
		WRITE_ONCE(mshv_vtl_this_run()->cancel, 1);
	}
	put_cpu();
}

static int mshv_vtl_poll_file_wake(wait_queue_entry_t *wait, unsigned int mode, int sync, void *key)
{
	struct mshv_vtl_poll_file *poll_file = container_of(wait, struct mshv_vtl_poll_file, wait);

	mshv_vtl_cancel(poll_file->cpu);
	return 0;
}

static void mshv_vtl_ptable_queue_proc(struct file *file, wait_queue_head_t *wqh, poll_table *pt)
{
	struct mshv_vtl_poll_file *poll_file = container_of(pt, struct mshv_vtl_poll_file, pt);

	WARN_ON(poll_file->wqh);
	poll_file->wqh = wqh;
	add_wait_queue(wqh, &poll_file->wait);
}

static int mshv_vtl_ioctl_set_poll_file(struct mshv_vtl_set_poll_file __user *user_input)
{
	struct file *file, *old_file;
	struct mshv_vtl_poll_file *poll_file;
	struct mshv_vtl_set_poll_file input;

	if (copy_from_user(&input, user_input, sizeof(input)))
		return -EFAULT;

	if (!cpu_online(input.cpu))
		return -EINVAL;

	file = NULL;
	if (input.fd >= 0) {
		file = fget(input.fd);
		if (!file)
			return -EBADFD;
	}

	poll_file = per_cpu_ptr(&mshv_vtl_poll_file, input.cpu);

	mutex_lock(&mshv_vtl_poll_file_lock);

	if (poll_file->wqh)
		remove_wait_queue(poll_file->wqh, &poll_file->wait);
	poll_file->wqh = NULL;

	old_file = poll_file->file;
	poll_file->file = file;
	poll_file->cpu = input.cpu;

	if (file) {
		init_waitqueue_func_entry(&poll_file->wait, mshv_vtl_poll_file_wake);
		init_poll_funcptr(&poll_file->pt, mshv_vtl_ptable_queue_proc);
		vfs_poll(file, &poll_file->pt);
	}

	mutex_unlock(&mshv_vtl_poll_file_lock);

	if (old_file)
		fput(old_file);

	return 0;
}


#if defined(CONFIG_X86_64) && defined(CONFIG_INTEL_TDX_GUEST)
/* Request a cache flush via TDG.VP.VMMCALL */
void mshv_tdx_request_cache_flush(bool wbnoinvd)
{
	struct tdx_hypercall_args args = {};

	args.r11 = 0x36; /* WBINVD call code */
	args.r12 = wbnoinvd ? 1 : 0; /* WBINVD/WBNOINVD indicator */
	__tdx_hypercall(&args);
}

#define TDCALL_ASM	".byte 0x66,0x0f,0x01,0xcc"

/* TODO TDX: Confirm noinline produces the right asm for saving register state */
noinline void mshv_vtl_return_tdx(void)
{
	struct tdx_tdg_vp_enter_exit_info *tdx_exit_info;
	struct tdx_vp_state *tdx_vp_state;
	struct mshv_vtl_run *vtl_run;
	struct mshv_vtl_per_cpu *per_cpu;

	register void *__sp asm("rsp");
	register u64 r8 asm("r8");
	register u64 r9 asm("r9");
	register u64 r10 asm("r10");
	register u64 r11 asm("r11");
	register u64 r12 asm("r12");
	register u64 r13 asm("r13");
	register u64 r14 asm("r14");
	register u64 r15 asm("r15");

	vtl_run = mshv_vtl_this_run();
	tdx_exit_info = &vtl_run->tdx_context.exit_info;
	tdx_vp_state = &vtl_run->tdx_context.vp_state;
	per_cpu = this_cpu_ptr(&mshv_vtl_per_cpu);

	/* TODO TDX: For now, hardcode VP.ENTER rax value. */
	u64 input_rax = 25;
	u64 input_rcx = vtl_run->tdx_context.entry_rcx;
	u64 input_rdx = virt_to_phys((void*) &vtl_run->tdx_context.l2_enter_guest_state);

	/*
	 * TODO TDX: KVM has some code and paths that seem like there is a way to
	 * defer TSC_AUX saving until usermode starts. For now, save/restore VTL2's
	 * view of TSC_AUX across every VP.ENTER call until we can do the same
	 * thing.
	*/
	rdmsrl(MSR_TSC_AUX, per_cpu->l1_msr_tsc_aux);

	kernel_fpu_begin_mask(0);
	fxrstor(&vtl_run->tdx_context.fx_state); // restore FP reg and XMM regs
	native_write_cr2(tdx_vp_state->cr2);

	/* Restore VTL0's syscall registers & MSRs */
	wrmsrl(MSR_KERNEL_GS_BASE, tdx_vp_state->msr_kernel_gs_base);
	wrmsrl(MSR_STAR, tdx_vp_state->msr_star);
	wrmsrl(MSR_LSTAR, tdx_vp_state->msr_lstar);
	wrmsrl(MSR_SYSCALL_MASK, tdx_vp_state->msr_sfmask);
	wrmsrl(MSR_TSC_AUX, tdx_vp_state->msr_tsc_aux);

	if (tdx_vp_state->msr_xss != per_cpu->xss)
		wrmsrl(MSR_IA32_XSS, tdx_vp_state->msr_xss);

	r8 = 0;
	r9 = 0;
	r10 = 0;
	r11 = 0;
	r12 = 0;
	r13 = 0;
	r14 = 0;
	r15 = 0;

	/*
	 * TODO TDX: pushq popq causes some build complaints unclear why when
	 * mshv uses it also. Alignment checks even though tdcall has no alignment reqs?
	 */
	asm __volatile__ (\
		/* Save RBP onto the stack since it'll be clobbered and inline asm won't save it. */
		"pushq	%%rbp\n"
		TDCALL_ASM "\n"
		/* restore rbp from the stack */
		"popq	%%rbp\n"
		: "=a"(tdx_exit_info->rax), "=c"(tdx_exit_info->rcx),
		  "=d"(tdx_exit_info->rdx), "=S"(tdx_exit_info->rsi), "=D"(tdx_exit_info->rdi),
		  "=r" (r8), "=r" (r9), "=r" (r10), "=r" (r11), "=r"(r12), "=r"(r13), "=r"(r14),
		  "=r"(r15), "+r" (__sp)
		: "a"(input_rax), "c"(input_rcx), "d"(input_rdx)
		: "rbx", "cc", "memory" /* TODO: is the "cc" necessary? */
	);

	tdx_exit_info->r8 = r8;
	tdx_exit_info->r9 = r9;
	tdx_exit_info->r10 = r10;
	tdx_exit_info->r11 = r11;
	tdx_exit_info->r12 = r12;
	tdx_exit_info->r13 = r13;
	tdx_vp_state->cr2 = native_read_cr2();
	rdmsrl(MSR_IA32_XSS, tdx_vp_state->msr_xss);
	per_cpu->xss = tdx_vp_state->msr_xss;

	rdmsrl(MSR_KERNEL_GS_BASE, tdx_vp_state->msr_kernel_gs_base);
	rdmsrl(MSR_STAR, tdx_vp_state->msr_star);
	rdmsrl(MSR_LSTAR, tdx_vp_state->msr_lstar);
	rdmsrl(MSR_SYSCALL_MASK, tdx_vp_state->msr_sfmask);
	rdmsrl(MSR_TSC_AUX, tdx_vp_state->msr_tsc_aux);

	/* Restore VTL2's syscall registers & MSRs */
	wrmsrl(MSR_KERNEL_GS_BASE, per_cpu->l1_msr_kernel_gs_base);
	wrmsrl(MSR_STAR, per_cpu->l1_msr_star);
	wrmsrl(MSR_LSTAR, per_cpu->l1_msr_lstar);
	wrmsrl(MSR_SYSCALL_MASK, per_cpu->l1_msr_sfmask);
	wrmsrl(MSR_TSC_AUX, per_cpu->l1_msr_tsc_aux);

	fxsave(&vtl_run->tdx_context.fx_state);
	kernel_fpu_end();
}
#else
void mshv_tdx_request_cache_flush(bool wbnoinvd) { }
noinline void mshv_vtl_return_tdx(void) { }
#endif

static bool mshv_vtl_process_intercept(void)
{
	struct hv_per_cpu_context *mshv_cpu;
	void *synic_message_page;
	struct hv_message *msg;
	u32 message_type;

	mshv_cpu = this_cpu_ptr(hv_context.cpu_context);
	synic_message_page = mshv_cpu->synic_message_page;
	if (unlikely(!synic_message_page))
		return true;

	msg = (struct hv_message *)synic_message_page + HV_SYNIC_INTERCEPTION_SINT_INDEX;
	message_type = READ_ONCE(msg->header.message_type);
	if (message_type == HVMSG_NONE)
		return true;

	memcpy(mshv_vtl_this_run()->exit_message, msg, sizeof(*msg));
	vmbus_signal_eom(msg, message_type);
	return false;
}

static bool in_idle_is_enabled;
DEFINE_PER_CPU(struct task_struct *, mshv_vtl_thread);

void mshv_vtl_switch_to_vtl0_irqoff(void)
{
	struct hv_vp_assist_page *hvp;
	struct mshv_vtl_run *this_run = mshv_vtl_this_run();
	struct hv_vtl_cpu_context *cpu_ctx = &this_run->cpu_context;
	u32 flags = READ_ONCE(this_run->flags);
	union hv_input_vtl target_vtl = READ_ONCE(this_run->target_vtl);

	trace_mshv_vtl_enter_vtl0_rcuidle(cpu_ctx);

	/* A VTL2 TDX kernel doesn't allocate hv_vp_assist_page at the moment */
	hvp = hv_vp_assist_page ? hv_vp_assist_page[smp_processor_id()] : NULL;

	/*
	 * Process signal event direct set in the run page, if any.
	 */
	if (hvp && mshv_vsm_capabilities.return_action_available) {
		u32 offset = READ_ONCE(mshv_vtl_this_run()->vtl_ret_action_size);

		WRITE_ONCE(mshv_vtl_this_run()->vtl_ret_action_size, 0);

		/*
		 * Hypervisor will take care of clearing out the actions
		 * set in the assist page.
		 */
		memcpy(hvp->vtl_ret_actions,
		       mshv_vtl_this_run()->vtl_ret_actions,
		       min_t(u32, offset, sizeof(hvp->vtl_ret_actions)));
	}

	hv_vtl_return(cpu_ctx, target_vtl, flags, mshv_vsm_page_offsets.vtl_return_offset);

	if (!hvp)
		return;

	trace_mshv_vtl_exit_vtl0_rcuidle(hvp->vtl_entry_reason, cpu_ctx);
}

static void mshv_vtl_idle(void)
{
	struct task_struct *p;

	p = this_cpu_read(mshv_vtl_thread);

	if (p) {
		/* Return early if we got cancelled. */
		if (READ_ONCE(mshv_vtl_this_run()->cancel)) {
			wake_up_process(p);
			raw_local_irq_enable();
			return;
		}

		mshv_vtl_switch_to_vtl0_irqoff();

		/* We are not the vtl thread, it means we need to wake it up */
		if (current != p) {
			this_cpu_write(mshv_vtl_thread, NULL);
			wake_up_process(p);
		}
		raw_local_irq_enable();
	} else {
		hv_vtl_idle();
	}
}

/* 0 is fast, 1 is play idle, 2 is idle2vtl0 */
#define MODE_MASK 0xf
#define REENTER_SHIFT 4

#define enter_mode(mode) ((mode) & MODE_MASK)
#define reenter_mode(mode) (((mode) >> REENTER_SHIFT) & MODE_MASK)

/*
 * Interrupt handling (particularly sending (via ICR writes) and receiving interrupts),
 * is a hot path on TDX. By performing some of the common functionality entirely in-kernel
 * we eliminate costly user<->kernel transitions.
 */
#ifndef CONFIG_INTEL_TDX_GUEST
static void mshv_tdx_free_apicid_to_cpuid_mapping(void) {}
static int mshv_tdx_create_apicid_to_cpuid_mapping(struct device *) { return 0; }
static bool mshv_tdx_try_handle_exit(struct mshv_vtl_run *) { return false; }
#else
static void mshv_tdx_free_apicid_to_cpuid_mapping(void)
{
	int bkt;
	struct apicid_to_cpuid_entry *entry;
	struct hlist_node *tmp;

	hash_for_each_safe(apicid_to_cpuid, bkt, tmp, entry, node) {
		hash_del(&entry->node);
		kfree(entry);
	}
}

/*
 * Creates and populates the apicid_to_cpuid hash table.
 * This mapping is used for fast ICR emulation on TDX.
 * Returns 0 on success.
 */
static int mshv_tdx_create_apicid_to_cpuid_mapping(struct device *dev)
{
	int cpu, ret = 0;

	for_each_online_cpu(cpu) {
		struct apicid_to_cpuid_entry *entry = kzalloc(sizeof(*entry), GFP_KERNEL);

		if (!entry) {
			ret = -ENOMEM;
			break;
		}

		entry->apicid = cpuid_to_apicid[cpu];
		entry->cpuid = cpu;

		if (entry->apicid == BAD_APICID) {
			dev_emerg(dev, "Bad APICID: %d !!\n", entry->apicid);
			ret = -ENODEV;
			break;
		}

		hash_add(apicid_to_cpuid, &entry->node, entry->apicid);
	}

	if (ret)
		mshv_tdx_free_apicid_to_cpuid_mapping();

	return ret;
}

static void mshv_tdx_advance_to_next_instruction(struct tdx_vp_context *context)
{
	const u32 instr_length = context->exit_info.r11 >> 32ULL;

	context->l2_enter_guest_state.rip += instr_length;
}

static void mshv_tdx_clear_exit_reason(struct tdx_vp_context *context)
{
	const u64 TDX_PENDING_INTERRUPT = 0x00001120ULL << 32ULL;

	context->exit_info.rax = TDX_PENDING_INTERRUPT;
}

static bool mshv_tdx_is_simple_icr_write(const struct tdx_vp_context *context)
{
	u64 msr_addr;
	u32 icr_lo;
	bool fixed;
	bool edge;

	if (((u32)context->exit_info.rax) != EXIT_REASON_MSR_WRITE)
		return false;

	msr_addr = context->l2_enter_guest_state.rcx;

	if (msr_addr != (APIC_BASE_MSR + (APIC_ICR >> 4)) && msr_addr != HV_X64_MSR_ICR)
		return false;

	icr_lo = context->l2_enter_guest_state.rax;
	fixed = !(icr_lo & (0b111 << 8));
	edge = !(icr_lo & BIT(15));

	return fixed && edge;
}

/*
 * Returns the cpumask described by dest, where dest is a logical destination.
 * cpu_mask should have no CPUs set.
 * Returns 0 on success
 */
static int mshv_tdx_get_logical_cpumask(u32 dest, struct cpumask *cpu_mask)
{
	int ret = 0;

	while ((u16)dest) {
		const u16 i = fls((u16)dest) - 1;
		const u32 physical_id = (dest >> 16 << 4) | i;

		ret = mshv_tdx_set_cpumask_from_apicid(physical_id, cpu_mask);
		dest &= ~BIT(i);
		if (ret)
			break;
	}

	return ret;
}

/*
 * Attempts to handle an ICR write. Returns 0 if successful, other values
 * indicate user-space should be invoked to gracefully handle the error.
 */
static int mshv_tdx_handle_simple_icr_write(struct tdx_vp_context *context)
{
	const u32 icr_lo = context->l2_enter_guest_state.rax;
	const u32 dest = context->l2_enter_guest_state.rdx;
	const u8 shorthand = (icr_lo >> 18) & 0b11;
	const u8 vector = icr_lo;
	const u64 bank = vector / 32;
	const u32 mask = BIT(vector % 32);
	const u32 self = smp_processor_id();

	bool send_ipi = false;
	struct cpumask local_mask = {};
	unsigned int cpu = 0;
	int ret = 0;

	if (shorthand == 0b10 || dest == (u32)-1) { /* shorthand all or destination id == all */
		cpumask_copy(&local_mask, cpu_online_mask);
	} else if (shorthand == 0b11) { /* shorthand all but self */
		cpumask_copy(&local_mask, cpu_online_mask);
		cpumask_clear_cpu(self, &local_mask);
	} else if (shorthand == 0b01) { /* shorthand self */
		cpumask_set_cpu(self, &local_mask);
	} else if (icr_lo & BIT(11)) { /* logical */
		ret = mshv_tdx_get_logical_cpumask(dest, &local_mask);
	} else { /* physical */
		ret = mshv_tdx_set_cpumask_from_apicid(dest, &local_mask);
	}

	if (ret)
		return ret;

	for_each_cpu(cpu, &local_mask) {
		/*
		 * The kernel doesn't provide an atomic_or which operates on u32,
		 * so cast to atomic_t, which should have the same layout
		 */
		static_assert(sizeof(atomic_t) == sizeof(u32));
		atomic_or(mask, (atomic_t *)
				(&(mshv_vtl_cpu_run(cpu)->proxy_irr[bank])));
		smp_store_release(&mshv_vtl_cpu_run(cpu)->scan_proxy_irr, 1);
		send_ipi |= cpu != self;
	}

	if (send_ipi) {
		cpumask_clear_cpu(self, &local_mask);
		__apic_send_IPI_mask(&local_mask, RESCHEDULE_VECTOR);
	}

	mshv_tdx_advance_to_next_instruction(context);
	mshv_tdx_clear_exit_reason(context);

	return 0;
}

static u32 *mshv_tdx_vapic_irr(void)
{
	return (u32 *)((char *)page_address(tdx_this_apic_page()) + APIC_IRR);
}

/*
 * Pull the interrupts in the `proxy_irr` field into the VAPIC page
 * Returns true if an exit to user-space is required (sync tmr state)
 */
static bool mshv_tdx_pull_proxy_irr(struct mshv_vtl_run *run)
{
	u32 *apic_page_irr = mshv_tdx_vapic_irr();

	if (!xchg(&run->scan_proxy_irr, 0))
		return false;

	for (int i = 0; i < 8; i++) {
		const u32 val = xchg(&run->proxy_irr[i], 0);

		if (!val)
			continue;

		if (run->proxy_irr_exit_mask[i] & val) {
			/*
			 * This vector was previously used for a level-triggered interrupt.
			 * An edge-triggered interrupt has now arrived, so we need to involve
			 * user-space to clear its copy of the tmr.
			 * Put the interrupt(s) back on the run page so it can do so.
			 * nb atomic_t cast: See comment in mshv_tdx_handle_simple_icr_write
			 */
			atomic_or(val, (atomic_t *)(&run->proxy_irr[i]));
			WRITE_ONCE(run->scan_proxy_irr, 1);
			return true;
		}

		/*
		 * IRR is non-contiguous.
		 * Each bank is 4 bytes with 12 bytes of padding between banks.
		 */
		apic_page_irr[i * 4] |= val;
	}

	return false;
}

/*
 * Checks if exit reason is due:
 * - An interrupt for the L1
 * - An exit from idle (same exit code as above)
 * - An interrupt pending for the L2 while trying to enter L1
 */
static bool mshv_tdx_is_intr(const struct tdx_vp_context *context)
{
	const u32 TDX_L2_EXIT_PENDING_INTERRUPT = 0x00001102;
	const u32 TDX_EXIT_PENDING_INTERRUPT = 0x00001120;
	const u32 tdx_exit = context->exit_info.rax >> 32ULL;

	return tdx_exit == TDX_L2_EXIT_PENDING_INTERRUPT ||
		tdx_exit == TDX_EXIT_PENDING_INTERRUPT;
}

static bool mshv_tdx_next_intr_exists(const struct tdx_vp_context *context)
{
	const u32 next_intr = (context->exit_info.r10 >> 32ULL);

	return next_intr & BIT(31);
}

static void mshv_tdx_update_rvi_halt(struct mshv_vtl_run *run)
{
	u32 *apic_page_irr = mshv_tdx_vapic_irr();
	struct tdx_l2_enter_guest_state *enter_state = &run->tdx_context.l2_enter_guest_state;

	enter_state->rvi = 0;
	for (int i = 7; i >= 0; i--) {
		if (apic_page_irr[i * 4]) {
			enter_state->rvi = i * 32 + fls(apic_page_irr[i * 4]) - 1;
			break;
		}
	}

	if (enter_state->rvi) {
		u8 *offload_flags = &run->offload_flags;
		(*offload_flags) &= ~MSHV_VTL_OFFLOAD_FLAG_HALT_HLT;
		(*offload_flags) &= ~MSHV_VTL_OFFLOAD_FLAG_HALT_IDLE;
		if (!(*offload_flags & MSHV_VTL_OFFLOAD_FLAG_HALT_OTHER))
			run->flags &= ~MSHV_VTL_RUN_FLAG_HALTED;
	}
}

static bool mshv_tdx_is_hlt(const struct tdx_vp_context *context)
{
	return ((u32)context->exit_info.rax) == EXIT_REASON_HLT;
}

static bool mshv_tdx_is_idle(const struct tdx_vp_context *context)
{
	return ((u32)context->exit_info.rax) == EXIT_REASON_MSR_READ &&
		(u32)context->l2_enter_guest_state.rcx == HV_X64_MSR_GUEST_IDLE;
}

static void mshv_tdx_handle_hlt_idle(struct tdx_vp_context *context)
{
	const u64 VP_WRITE = 10;
	struct tdx_extended_field_code ext_field_code = {};
	u64 status;

	ext_field_code.field_code    = GUEST_INTERRUPTIBILITY_INFO;
	ext_field_code.field_size    = 2;  /* TDX_FIELD_SIZE_32_BIT */
	ext_field_code.context_code  = 2;  /* TDX_CONTEXT_CODE_VP_SCOPE */
	ext_field_code.class_code    = 36; /* L2_VM1 (VTL0) */

	/* Clear interrupt shadow */
	status = __tdx_module_call(VP_WRITE, 0, ext_field_code.as_u64, 0, 1, NULL);

	if (status != 0)
		panic("tdcall vmcs write failed with code: %llx", status);

	mshv_tdx_advance_to_next_instruction(context);
	mshv_tdx_clear_exit_reason(context);
	mshv_vtl_this_run()->flags |= MSHV_VTL_RUN_FLAG_HALTED;
}

/*
 * Try to handle a TDX exit entirely in kernel, to avoid the overhead of a
 * user<->kernel transition. Currently handles ICR writes, HLT, idle, and interrupt injection.
 * Returns true if the exit was handled entirely in kernel, and the L2 should be re-entered.
 * Returns false if the exit must be handled by user-space.
 */
static bool mshv_tdx_try_handle_exit(struct mshv_vtl_run *run)
{
	struct tdx_vp_context *context = &run->tdx_context;
	const bool intr_inject = MSHV_VTL_OFFLOAD_FLAG_INTR_INJECT & run->offload_flags;
	const bool x2apic = MSHV_VTL_OFFLOAD_FLAG_X2APIC & run->offload_flags;
	bool ret_to_user = true;

	if (!intr_inject || mshv_tdx_next_intr_exists(context))
		return false;

	if (mshv_tdx_is_intr(context)) {
		ret_to_user = false;
	} else if (x2apic && mshv_tdx_is_simple_icr_write(context)) {
		ret_to_user = mshv_tdx_handle_simple_icr_write(context);
	} else if (mshv_tdx_is_hlt(context)) {
		ret_to_user = false;
		mshv_tdx_handle_hlt_idle(context);
		run->offload_flags |= MSHV_VTL_OFFLOAD_FLAG_HALT_HLT;
	} else if (mshv_tdx_is_idle(context)) {
		ret_to_user = false;
		mshv_tdx_handle_hlt_idle(context);
		run->offload_flags |= MSHV_VTL_OFFLOAD_FLAG_HALT_IDLE;
	}

	return !ret_to_user;
}
#endif /* CONFIG_INTEL_TDX_GUEST */

/*
 * Attempts to directly inject the interrupts in the proxy_irr field.
 * Returns true if an exit to user-space is required.
 */
static bool mshv_pull_proxy_irr(struct mshv_vtl_run *run)
{
	bool ret = READ_ONCE(run->scan_proxy_irr);

	if (!hv_isolation_type_tdx() ||
	    !(run->offload_flags & MSHV_VTL_OFFLOAD_FLAG_INTR_INJECT))
		return ret;

#ifdef CONFIG_INTEL_TDX_GUEST
	ret = mshv_tdx_pull_proxy_irr(run);
	mshv_tdx_update_rvi_halt(run);
#endif
	return ret;
}

static int mshv_vtl_ioctl_return_to_lower_vtl(void)
{
	u32 mode, enter, reenter;

	preempt_disable();
	mode = READ_ONCE(mshv_vtl_this_run()->enter_mode);
	enter = enter_mode(mode);
	reenter = reenter_mode(mode);

	for (;;) {
		const unsigned long VTL0_WORK = _TIF_SIGPENDING | _TIF_NEED_RESCHED |
						_TIF_NOTIFY_RESUME | _TIF_NOTIFY_SIGNAL;
		unsigned long ti_work;
		u32 cancel;
		unsigned long irq_flags;
		struct hv_vp_assist_page *hvp;
		int ret;

		local_irq_save(irq_flags);
		ti_work = READ_ONCE(current_thread_info()->flags);
		cancel = READ_ONCE(mshv_vtl_this_run()->cancel);
		cancel |= mshv_pull_proxy_irr(mshv_vtl_this_run());
		if (unlikely((ti_work & VTL0_WORK) || cancel)) {
			local_irq_restore(irq_flags);
			preempt_enable();
			if (cancel)
				ti_work |= _TIF_SIGPENDING;
			ret = mshv_xfer_to_guest_mode_handle_work(ti_work);
			if (ret)
				return ret;
			preempt_disable();
			continue;
		}

		if (tick_nohz_full_enabled() || nr_cpu_ids == 1 || !enter) {
			mshv_vtl_switch_to_vtl0_irqoff();
			local_irq_restore(irq_flags);
		} else if (enter == 2 && smp_load_acquire(&in_idle_is_enabled)) {
			set_current_state(TASK_INTERRUPTIBLE);
			this_cpu_write(mshv_vtl_thread, current);
			local_irq_restore(irq_flags);

			schedule_preempt_disabled();

			if (this_cpu_read(mshv_vtl_thread)) {
				this_cpu_write(mshv_vtl_thread, NULL);
				continue;
			}
		} else { /* play idle */
			current->flags |= PF_IDLE;
			/* Enter idle */
			tick_nohz_idle_enter();
			/* Stop ticks */
			tick_nohz_idle_stop_tick();

			ct_idle_enter();
			mshv_vtl_switch_to_vtl0_irqoff();
			ct_idle_exit();
			local_irq_restore(irq_flags);

			tick_nohz_idle_exit();

			current->flags &= ~PF_IDLE;
		}

		if (hv_isolation_type_tdx()) {
			if (mshv_tdx_try_handle_exit(mshv_vtl_this_run()))
				continue; /* Exit handled entirely in kernel */
			else
				goto done;
		}

		hvp = hv_vp_assist_page[smp_processor_id()];
		this_cpu_inc(num_vtl0_transitions);
		switch (hvp->vtl_entry_reason) {
		case MSHV_ENTRY_REASON_INTERRUPT:
			if (!mshv_vsm_capabilities.intercept_page_available &&
			    likely(!mshv_vtl_process_intercept()))
				goto done;

			/*
			 * Woken up with nothing to do, switch to the reenter
			 * mode
			 */
			enter = reenter;
			break;

		case MSHV_ENTRY_REASON_INTERCEPT:
			WARN_ON(!mshv_vsm_capabilities.intercept_page_available);
			memcpy(mshv_vtl_this_run()->exit_message, hvp->intercept_message,
			       sizeof(hvp->intercept_message));
			goto done;

		default:
			panic("unknown entry reason: %d", hvp->vtl_entry_reason);
		}
	}

done:
	preempt_enable();
	return 0;
}

static long
mshv_vtl_ioctl_get_set_regs(void __user *user_args, bool set)
{
	struct mshv_vp_registers args;
	struct hv_register_assoc *registers;
	long ret;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	if (args.count == 0 || args.count > MSHV_VP_MAX_REGISTERS)
		return -EINVAL;

	registers = kmalloc_array(args.count,
				  sizeof(*registers),
				  GFP_KERNEL);
	if (!registers)
		return -ENOMEM;

	if (copy_from_user(registers, (void __user *)args.regs_ptr,
			   sizeof(*registers) * args.count)) {
		ret = -EFAULT;
		goto free_return;
	}

	if (set) {
		ret = hv_vtl_set_reg(registers, mshv_vsm_capabilities.dr6_shared);
		if (ret <= 0)
			goto free_return; /* No need of hypercall */
		ret = vtl_set_vp_registers(args.count, registers);

	} else {
		ret = hv_vtl_get_reg(registers, mshv_vsm_capabilities.dr6_shared);
		if (ret <= 0)
			goto copy_args; /* No need of hypercall */
		ret = vtl_get_vp_registers(args.count, registers);
		if (ret)
			goto free_return;

copy_args:
		if (copy_to_user((void __user *)args.regs_ptr, registers,
				 sizeof(*registers) * args.count))
			ret = -EFAULT;
	}

free_return:
	kfree(registers);
	return ret;
}

static inline long
mshv_vtl_ioctl_set_regs(void __user *user_args)
{
	return mshv_vtl_ioctl_get_set_regs(user_args, true);
}

static inline long
mshv_vtl_ioctl_get_regs(void __user *user_args)
{
	return mshv_vtl_ioctl_get_set_regs(user_args, false);
}

#if defined(CONFIG_X86_64) && defined(CONFIG_INTEL_TDX_GUEST)

/*
 * Issue a TD module call from usermode. Note that currently only tdmodule
 * calls are supported, not TD.VMCALL.
 */
static long mshv_vtl_ioctl_tdcall(void __user *user_tdcall)
{
	struct mshv_tdcall tdcall = {};
	struct tdx_module_output output = {};
	u64 status = 0;

	if (!hv_isolation_type_tdx())
		return -EINVAL;

	if (copy_from_user(&tdcall, user_tdcall, sizeof(tdcall)))
		return -EFAULT;

	status = __tdx_module_call(tdcall.rax, tdcall.rcx, tdcall.rdx,
				   tdcall.r8, tdcall.r9, &output);
	tdcall.rax = status;
	tdcall.rcx = output.rcx;
	tdcall.rdx = output.rdx;
	tdcall.r8 = output.r8;
	tdcall.r9 = output.r9;
	tdcall.r10_out = output.r10;
	tdcall.r11_out = output.r11;

	return copy_to_user(user_tdcall, &tdcall, sizeof(tdcall)) ? -EFAULT : 0;
}

static long mshv_vtl_ioctl_read_vmx_cr4_fixed1(void __user *user_arg)
{
	u64 value;

	value = native_read_msr(MSR_IA32_VMX_CR4_FIXED1);

	return copy_to_user(user_arg, &value, sizeof(value)) ? -EFAULT : 0;
}
#endif

#if defined(CONFIG_X86_64) && defined(CONFIG_SEV_GUEST)

static void __noreturn mshv_sev_es_terminate(unsigned int set, unsigned int reason)
{
	native_wrmsrl(MSR_AMD64_SEV_ES_GHCB,
		      GHCB_SEV_TERM_REASON(set, reason) | GHCB_MSR_TERM_REQ);
	VMGEXIT();

	while (true)
		asm volatile("hlt\n" : : : "memory");
}

static long mshv_vtl_ioctl_pvalidate(void __user *pval_user)
{
	u64 pfn_end, pfn;
	long rc;
	struct mshv_pvalidate pval = {};

	if (!hv_isolation_type_snp())
		return -EINVAL;

	if (copy_from_user(&pval, pval_user, sizeof(pval)))
		return -EFAULT;

	if (!pval.page_count)
		return -ENODATA;

	pfn = pval.start_pfn;
	pfn_end = pfn + pval.page_count;

	while (pfn < pfn_end) {
		unsigned long pfns[1] = { pfn };
		void *vaddr;

		if (pval.ram)
			vaddr = kmap_local_page(pfn_to_page(pfn));
		else
			vaddr = vmap_pfn(pfns, ARRAY_SIZE(pfns), PAGE_KERNEL);

		if (!vaddr) {
			rc = -EINVAL;
			break;
		}

		rc = pvalidate((u64)vaddr, RMP_PG_SIZE_4K, pval.validate);
		if (pval.ram)
			kunmap_local(vaddr);
		else
			vunmap(vaddr);
		if (WARN(rc, "Failed to pvalidate pfn %#llx, ret %ld", pfn, rc)) {
			if (pval.terminate_on_failure)
				mshv_sev_es_terminate(SEV_TERM_SET_LINUX, GHCB_TERM_PVALIDATE);
			else
				break;
		}

		++pfn;
	}

	return rc;
}

static long mshv_vtl_ioctl_rmpadjust(void __user *rmpa_user)
{
	u64 pfn_end, pfn;
	long rc;
	struct mshv_rmpadjust rmpa = {};

	if (!hv_isolation_type_snp())
		return -EINVAL;

	if (copy_from_user(&rmpa, rmpa_user, sizeof(rmpa)))
		return -EFAULT;

	if (!rmpa.page_count)
		return -ENODATA;

	pfn = rmpa.start_pfn;
	pfn_end = pfn + rmpa.page_count;

	while (pfn < pfn_end) {
		unsigned long pfns[1] = { pfn };
		void *vaddr;

		if (rmpa.ram)
			vaddr = kmap_local_page(pfn_to_page(pfn));
		else
			vaddr = vmap_pfn(pfns, ARRAY_SIZE(pfns), PAGE_KERNEL);

		if (!vaddr) {
			rc = -EINVAL;
			break;
		}

		rc = rmpadjust((u64)vaddr, RMP_PG_SIZE_4K, rmpa.value);
		if (rmpa.ram)
			kunmap_local(vaddr);
		else
			vunmap(vaddr);
		if (WARN(rc, "Failed to rmpadjust pfn %#llx, ret %ld", pfn, rc)) {
			if (rmpa.terminate_on_failure)
				mshv_sev_es_terminate(SEV_TERM_SET_LINUX, GHCB_TERM_PSC);
			else
				break;
		}

		++pfn;
	}

	return rc;
}

static long mshv_vtl_ioctl_rmpquery(void __user *rmpq_user)
{
	u64 pfn_end, pfn;
	long rc;
	struct mshv_rmpquery rmpq = {};
	u64 pages_processed;
	u64 __user *user_flags_in_out;
	u64 __user *user_page_size_out;

	if (!hv_isolation_type_snp())
		return -EINVAL;

	if (copy_from_user(&rmpq, rmpq_user, sizeof(rmpq)))
		return -EFAULT;

	if (!rmpq.page_count)
		return -ENODATA;

	pfn = rmpq.start_pfn;
	pfn_end = pfn + rmpq.page_count;
	pages_processed = 0;
	user_flags_in_out = rmpq.flags;
	user_page_size_out = rmpq.page_size;
	rc = 0;

	while (pfn < pfn_end) {
		unsigned long pfns[1] = { pfn };
		void *vaddr = NULL;
		u64 page_size = -1;
		u64 flags = 0;

		if (copy_from_user(&flags, user_flags_in_out, sizeof(flags))) {
			pr_warn("Failed to copy flags in for pfn %#llx when querying RMP\n", pfn);
			rc = -EFAULT;
			break;
		}

		if (rmpq.ram)
			vaddr = kmap_local_page(pfn_to_page(pfn));
		else
			vaddr = vmap_pfn(pfns, ARRAY_SIZE(pfns), PAGE_KERNEL);

		if (!vaddr) {
			rc = -EINVAL;
			break;
		}

		rc = rmpquery((u64)vaddr, &page_size, &flags);
		if (rmpq.ram)
			kunmap_local(vaddr);
		else
			vunmap(vaddr);
		if (rc != 0 && rc != 2) {
			pr_warn("Bogus status %ld for pfn %#llx when querying RMP\n", rc, pfn);
			rc = -EINVAL;
			break;
		}
		if (rc == 2) {
			rc = -EPERM;
			pr_warn("Current ASID not 0 or the RMP entry is immutable\n");
		}

		if (rc) {
			pr_warn("Failed to rmpquery pfn %#llx, ret %ld\n", pfn, rc);
			if (rmpq.terminate_on_failure)
				mshv_sev_es_terminate(SEV_TERM_SET_LINUX, GHCB_TERM_PSC);
			else
				break;
		}

		if (copy_to_user(user_flags_in_out, &flags, sizeof(flags))) {
			pr_warn("Failed to copy flags out for pfn %#llx when querying RMP\n",
				pfn);
			rc = -EFAULT;
			break;
		}
		if (copy_to_user(user_page_size_out, &page_size, sizeof(page_size))) {
			pr_warn("Failed to copy page size out for pfn %#llx when querying RMP\n",
				pfn);
			rc = -EFAULT;
			break;
		}

		++pfn;
		++user_flags_in_out;
		++user_page_size_out;
		++pages_processed;
	}

	return copy_to_user(rmpq.pages_processed, &pages_processed, sizeof(pages_processed)) ?
		-EFAULT : rc;
}

static long mshv_vtl_ioctl_invlpgb(void __user *invlpgb_user)
{
	struct mshv_invlpgb invlpgb = {};

	if (copy_from_user(&invlpgb, invlpgb_user, sizeof(invlpgb)))
		return -EFAULT;

	/*
	 * `invlpgb` might not be supported by an older toolchain.
	 * Use the raw encoding instead of the mnemonic not to break
	 * the build on the older systems.
	*/
	asm volatile(".byte 0x0F,0x01,0xFE\n\t"
			:
			: "a"(invlpgb.rax), "c"(invlpgb.ecx), "d"(invlpgb.edx)
			: "memory");

	return 0;
}

static long mshv_vtl_ioctl_tlbsync(void)
{
	/*
	 * `tlbsync` might not be supported by an older toolchain.
	 * Use the raw encoding instead of the mnemonic not to break
	 * the build on the older systems.
	*/
	asm volatile(".byte 0x0F,0x01,0xFF\n\t"
			:
			:
			: "memory");

	return 0;
}

static void guest_vsm_vmsa_pfn_this_cpu(void *arg)
{
	int cpu;
	struct page *vmsa_guest_vsm_page;
	u64 *pfn = arg;

	cpu = get_cpu();
	vmsa_guest_vsm_page = *this_cpu_ptr(&mshv_vtl_per_cpu.vmsa_guest_vsm_page);
	if (!vmsa_guest_vsm_page) {
		if (mshv_configure_vmsa_page(1, per_cpu_ptr(&mshv_vtl_per_cpu.vmsa_guest_vsm_page, cpu)))
			*pfn = -ENOMEM;
		else
			vmsa_guest_vsm_page = *this_cpu_ptr(&mshv_vtl_per_cpu.vmsa_guest_vsm_page);
	}
	put_cpu();

	*pfn = vmsa_guest_vsm_page ? page_to_pfn(vmsa_guest_vsm_page) : -ENOMEM;
}

static long mshv_vtl_ioctl_guest_vsm_vmsa_pfn(void __user *user_arg)
{
	u64 pfn;
	u32 cpu_id;
	long ret;

	ret = copy_from_user(&cpu_id, user_arg, sizeof(cpu_id)) ? -EFAULT : 0;
	if (ret)
		return ret;

	ret = smp_call_function_single(cpu_id, guest_vsm_vmsa_pfn_this_cpu, &pfn, true);
	if (ret)
		return ret;
	ret = (long)pfn;
	if (ret < 0)
		return ret;

	ret = copy_to_user(user_arg, &pfn, sizeof(pfn)) ? -EFAULT : 0;

	return ret;
}
#endif

static long
mshv_vtl_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	long ret;
	struct mshv_vtl *vtl = filp->private_data;

	switch (ioctl) {
	case MSHV_VTL_SET_POLL_FILE:
		ret = mshv_vtl_ioctl_set_poll_file(
			(struct mshv_vtl_set_poll_file *)arg);
		break;
	case MSHV_GET_VP_REGISTERS:
		ret = mshv_vtl_ioctl_get_regs((void __user *)arg);
		break;
	case MSHV_SET_VP_REGISTERS:
		ret = mshv_vtl_ioctl_set_regs((void __user *)arg);
		break;
	case MSHV_VTL_RETURN_TO_LOWER_VTL:
		ret = mshv_vtl_ioctl_return_to_lower_vtl();
		break;
	case MSHV_VTL_ADD_VTL0_MEMORY:
		ret = mshv_vtl_ioctl_add_vtl0_mem(vtl, (void __user *)arg);
		break;
#if defined(CONFIG_X86_64) && defined(CONFIG_INTEL_TDX_GUEST)
	case MSHV_VTL_TDCALL:
		ret = mshv_vtl_ioctl_tdcall((void __user *)arg);
		break;
	case MSHV_VTL_READ_VMX_CR4_FIXED1:
		ret = mshv_vtl_ioctl_read_vmx_cr4_fixed1((void __user *)arg);
		break;
#endif

#if defined(CONFIG_X86_64) && defined(CONFIG_SEV_GUEST)
	case MSHV_VTL_PVALIDATE:
		ret = mshv_vtl_ioctl_pvalidate((void __user *)arg);
		break;
	case MSHV_VTL_RMPADJUST:
		ret = mshv_vtl_ioctl_rmpadjust((void __user *)arg);
		break;
	case MSHV_VTL_RMPQUERY:
		ret = mshv_vtl_ioctl_rmpquery((void __user *)arg);
		break;
	case MSHV_VTL_INVLPGB:
		ret = mshv_vtl_ioctl_invlpgb((void __user *)arg);
		break;
	case MSHV_VTL_TLBSYNC:
		ret = mshv_vtl_ioctl_tlbsync();
		break;
	case MSHV_VTL_GUEST_VSM_VMSA_PFN:
		ret = mshv_vtl_ioctl_guest_vsm_vmsa_pfn((void __user *)arg);
		break;
#endif

	default:
		dev_err(vtl->module_dev, "invalid vtl ioctl: %#x\n", ioctl);
		ret = -ENOTTY;
	}

	return ret;
}

static vm_fault_t mshv_vtl_fault(struct vm_fault *vmf)
{
	struct page *page;
	int cpu = vmf->pgoff & MSHV_PG_OFF_CPU_MASK;
	int real_off = vmf->pgoff >> MSHV_REAL_OFF_SHIFT;

	if (!cpu_online(cpu))
		return VM_FAULT_SIGBUS;

	if (real_off == MSHV_RUN_PAGE_OFFSET) {
		page = virt_to_page(mshv_vtl_cpu_run(cpu));
	} else if (real_off == MSHV_REG_PAGE_OFFSET) {
		if (!mshv_has_reg_page)
			return VM_FAULT_SIGBUS;
		page = mshv_vtl_cpu_reg_page(cpu);
#ifdef CONFIG_X86_64
	} else if (real_off == MSHV_VMSA_PAGE_OFFSET) {
		if (!hv_isolation_type_snp())
			return VM_FAULT_SIGBUS;
		page = *per_cpu_ptr(&mshv_vtl_per_cpu.vmsa_page, cpu);
	} else if (real_off == MSHV_VMSA_GUEST_VSM_PAGE_OFFSET) {
		struct page **page_ptr_ptr;
		if (!hv_isolation_type_snp())
			return VM_FAULT_SIGBUS;
		page_ptr_ptr = per_cpu_ptr(&mshv_vtl_per_cpu.vmsa_guest_vsm_page, cpu);
		if (!*page_ptr_ptr) {
			if (mshv_configure_vmsa_page(1, page_ptr_ptr) < 0)
				return VM_FAULT_SIGBUS;
		}
		page = *page_ptr_ptr;
	} else if (real_off == MSHV_VMSA_PAGE_OFFSET) {
		if (!hv_isolation_type_snp())
			return VM_FAULT_SIGBUS;
		page = *per_cpu_ptr(&mshv_vtl_per_cpu.vmsa_page, cpu);
#ifdef CONFIG_INTEL_TDX_GUEST
	} else if (real_off == MSHV_APIC_PAGE_OFFSET) {
		if (!hv_isolation_type_tdx())
			return VM_FAULT_SIGBUS;

		page = tdx_apic_page(cpu);
#endif
#endif
	} else {
		return VM_FAULT_NOPAGE;
	}

	get_page(page);
	vmf->page = page;

	return 0;
}

static const struct vm_operations_struct mshv_vtl_vm_ops = {
	.fault = mshv_vtl_fault,
};

static int mshv_vtl_mmap(struct file *filp, struct vm_area_struct *vma)
{
	vma->vm_ops = &mshv_vtl_vm_ops;
	return 0;
}

static int mshv_vtl_release(struct inode *inode, struct file *filp)
{
	struct mshv_vtl *vtl = filp->private_data;

	kfree(vtl);

	return 0;
}

static const struct file_operations mshv_vtl_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = mshv_vtl_ioctl,
	.release = mshv_vtl_release,
	.mmap = mshv_vtl_mmap,
};

static long __mshv_ioctl_create_vtl(void __user *user_arg, struct device *module_dev)
{
	struct mshv_vtl *vtl;
	struct file *file;
	int fd;

	vtl = kzalloc(sizeof(*vtl), GFP_KERNEL);
	if (!vtl)
		return -ENOMEM;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		return fd;
	file = anon_inode_getfile("mshv_vtl", &mshv_vtl_fops,
				  vtl, O_RDWR);
	if (IS_ERR(file))
		return PTR_ERR(file);
	refcount_set(&vtl->ref_count, 1);
	vtl->module_dev = module_dev;

	fd_install(fd, file);

	return fd;
}

static void mshv_vtl_synic_mask_vmbus_sint(const u8 *mask)
{
	union hv_synic_sint sint;

	sint.as_uint64 = 0;
	sint.vector = vmbus_interrupt;
	sint.masked = (*mask != 0);
	sint.auto_eoi = hv_recommend_using_aeoi();

	hv_set_register(HV_MSR_SINT0 + VTL2_VMBUS_SINT_INDEX,
		sint.as_uint64);

	if (!sint.masked)
		pr_debug("%s: Unmasking VTL2 VMBUS SINT\n", __func__);
	else
		pr_debug("%s: Masking VTL2 VMBUS SINT\n", __func__);
}

static void mshv_vtl_read_remote(void *buffer)
{
	struct hv_per_cpu_context *mshv_cpu = this_cpu_ptr(hv_context.cpu_context);
	struct hv_message *msg = (struct hv_message *)mshv_cpu->synic_message_page +
					VTL2_VMBUS_SINT_INDEX;
	u32 message_type = READ_ONCE(msg->header.message_type);

	WRITE_ONCE(has_message, false);
	if (message_type == HVMSG_NONE)
		return;

	memcpy(buffer, msg, sizeof(*msg));
	vmbus_signal_eom(msg, message_type);
}

static bool vtl_synic_mask_vmbus_sint_masked = true;

static ssize_t mshv_vtl_sint_read(struct file *filp, char __user *arg, size_t size, loff_t *offset)
{
	struct hv_message msg = {};
	int ret;

	if (size < sizeof(msg))
		return -EINVAL;

	for (;;) {
		smp_call_function_single(VMBUS_CONNECT_CPU, mshv_vtl_read_remote, &msg, true);
		if (msg.header.message_type != HVMSG_NONE)
			break;

		if (READ_ONCE(vtl_synic_mask_vmbus_sint_masked))
			return 0; /* EOF */

		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;

		ret = wait_event_interruptible(fd_wait_queue,
			READ_ONCE(has_message) || READ_ONCE(vtl_synic_mask_vmbus_sint_masked));
		if (ret)
			return ret;
	}

	if (copy_to_user(arg, &msg, sizeof(msg)))
		return -EFAULT;

	return sizeof(msg);
}

static __poll_t mshv_vtl_sint_poll(struct file *filp, poll_table *wait)
{
	__poll_t mask = 0;

	poll_wait(filp, &fd_wait_queue, wait);
	if (READ_ONCE(has_message) || READ_ONCE(vtl_synic_mask_vmbus_sint_masked))
		mask |= EPOLLIN | EPOLLRDNORM;

	return mask;
}

static void mshv_vtl_sint_on_msg_dpc(unsigned long data)
{
	WRITE_ONCE(has_message, true);
	wake_up_interruptible_poll(&fd_wait_queue, EPOLLIN);
}

static int mshv_vtl_sint_ioctl_post_message(struct mshv_vtl_sint_post_msg __user *arg)
{
	struct mshv_vtl_sint_post_msg message;
	u8 payload[HV_MESSAGE_PAYLOAD_BYTE_COUNT];

	if (copy_from_user(&message, arg, sizeof(message)))
		return -EFAULT;
	if (message.payload_size > HV_MESSAGE_PAYLOAD_BYTE_COUNT)
		return -EINVAL;
	if (copy_from_user(payload, (void __user *)message.payload_ptr,
			   message.payload_size))
		return -EFAULT;

	return hv_post_message((union hv_connection_id)message.connection_id,
			       message.message_type, (void *)payload,
			       message.payload_size);
}

static int mshv_vtl_sint_ioctl_signal_event(struct mshv_vtl_signal_event __user *arg)
{
	u64 input;
	struct mshv_vtl_signal_event signal_event;

	if (copy_from_user(&signal_event, arg, sizeof(signal_event)))
		return -EFAULT;

	input = signal_event.connection_id | ((u64)signal_event.flag << 32);
	return hv_do_fast_hypercall8(HVCALL_SIGNAL_EVENT, input) & HV_HYPERCALL_RESULT_MASK;
}

static int mshv_vtl_sint_ioctl_set_eventfd(struct mshv_vtl_set_eventfd __user *arg)
{
	struct mshv_vtl_set_eventfd set_eventfd;
	struct eventfd_ctx *eventfd, *old_eventfd;

	if (copy_from_user(&set_eventfd, arg, sizeof(set_eventfd)))
		return -EFAULT;
	if (set_eventfd.flag >= HV_EVENT_FLAGS_COUNT)
		return -EINVAL;

	eventfd = NULL;
	if (set_eventfd.fd >= 0) {
		eventfd = eventfd_ctx_fdget(set_eventfd.fd);
		if (IS_ERR(eventfd))
			return PTR_ERR(eventfd);
	}

	mutex_lock(&flag_lock);
	old_eventfd = flag_eventfds[set_eventfd.flag];
	WRITE_ONCE(flag_eventfds[set_eventfd.flag], eventfd);
	mutex_unlock(&flag_lock);

	if (old_eventfd) {
		synchronize_rcu();
		eventfd_ctx_put(old_eventfd);
	}

	return 0;
}

static int mshv_vtl_sint_ioctl_pause_message_stream(struct mshv_sint_mask __user *arg)
{
	static DEFINE_MUTEX(vtl2_vmbus_sint_mask_mutex);
	struct mshv_sint_mask mask;

	if (copy_from_user(&mask, arg, sizeof(mask)))
		return -EFAULT;
	mutex_lock(&vtl2_vmbus_sint_mask_mutex);
	on_each_cpu((smp_call_func_t)mshv_vtl_synic_mask_vmbus_sint, &mask.mask, 1);
	WRITE_ONCE(vtl_synic_mask_vmbus_sint_masked, mask.mask != 0);
	mutex_unlock(&vtl2_vmbus_sint_mask_mutex);
	if (mask.mask)
		wake_up_interruptible_poll(&fd_wait_queue, EPOLLIN);

	return 0;
}

static long mshv_vtl_sint_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case MSHV_SINT_POST_MESSAGE:
		return mshv_vtl_sint_ioctl_post_message((struct mshv_vtl_sint_post_msg *)arg);
	case MSHV_SINT_SIGNAL_EVENT:
		return mshv_vtl_sint_ioctl_signal_event((struct mshv_vtl_signal_event *)arg);
	case MSHV_SINT_SET_EVENTFD:
		return mshv_vtl_sint_ioctl_set_eventfd((struct mshv_vtl_set_eventfd *)arg);
	case MSHV_SINT_PAUSE_MESSAGE_STREAM:
		return mshv_vtl_sint_ioctl_pause_message_stream((struct mshv_sint_mask *)arg);
	default:
		return -ENOIOCTLCMD;
	}
}

static const struct file_operations mshv_vtl_sint_ops = {
	.owner = THIS_MODULE,
	.read = mshv_vtl_sint_read,
	.poll = mshv_vtl_sint_poll,
	.unlocked_ioctl = mshv_vtl_sint_ioctl,
};

static struct miscdevice mshv_vtl_sint_dev = {
	.name = "mshv_sint",
	.fops = &mshv_vtl_sint_ops,
	.mode = 0600,
	.minor = MISC_DYNAMIC_MINOR,
};

static int mshv_vtl_hvcall_open(struct inode *node, struct file *f)
{
	struct miscdevice *dev = f->private_data;
	struct mshv_vtl_hvcall_fd *fd;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	fd = vzalloc(sizeof(*fd));
	if (!fd)
		return -ENOMEM;
	fd->dev = dev;
	mutex_init(&fd->init_mutex);

	f->private_data = fd;

	return 0;
}

static int mshv_vtl_hvcall_release(struct inode *node, struct file *f)
{
	struct mshv_vtl_hvcall_fd *fd;

	fd = f->private_data;
	f->private_data = NULL;
	vfree(fd);

	return 0;
}

static int mshv_vtl_hvcall_setup(struct mshv_vtl_hvcall_fd *fd,
				 struct mshv_vtl_hvcall_setup __user *hvcall_setup_user)
{
	int ret = 0;
	struct mshv_vtl_hvcall_setup hvcall_setup;

	mutex_lock(&fd->init_mutex);

	if (fd->allow_map_intialized) {
		dev_err(fd->dev->this_device,
			"Hypercall allow map has already been set, pid %d\n",
			current->pid);
		ret = -EINVAL;
		goto exit;
	}

	if (copy_from_user(&hvcall_setup, hvcall_setup_user,
			   sizeof(struct mshv_vtl_hvcall_setup))) {
		ret = -EFAULT;
		goto exit;
	}
	if (hvcall_setup.bitmap_size > ARRAY_SIZE(fd->allow_bitmap)) {
		ret = -EINVAL;
		goto exit;
	}
	if (copy_from_user(&fd->allow_bitmap,
			   (void __user *)hvcall_setup.allow_bitmap_ptr,
			   hvcall_setup.bitmap_size)) {
		ret = -EFAULT;
		goto exit;
	}

	dev_info(fd->dev->this_device, "Hypercall allow map has been set, pid %d\n",
		 current->pid);
	fd->allow_map_intialized = true;

exit:

	mutex_unlock(&fd->init_mutex);

	return ret;
}

bool mshv_vtl_hvcall_is_allowed(struct mshv_vtl_hvcall_fd *fd, u16 call_code)
{
	u8 bits_per_item = 8 * sizeof(fd->allow_bitmap[0]);
	u16 item_index = call_code / bits_per_item;
	u64 mask = 1ULL << (call_code % bits_per_item);

	return fd->allow_bitmap[item_index] & mask;
}

static int mshv_vtl_hvcall_call(struct mshv_vtl_hvcall_fd *fd,
				struct mshv_vtl_hvcall __user *hvcall_user)
{
	struct mshv_vtl_hvcall hvcall;
	void *in, *out;
	int ret;

	if (copy_from_user(&hvcall, hvcall_user, sizeof(struct mshv_vtl_hvcall)))
		return -EFAULT;
	if (hvcall.input_size > HV_HYP_PAGE_SIZE)
		return -EINVAL;
	if (hvcall.output_size > HV_HYP_PAGE_SIZE)
		return -EINVAL;

	/*
	 * By default, all hypercalls are not allowed.
	 * The user mode code has to set up the allow bitmap once.
	 */

	if (!mshv_vtl_hvcall_is_allowed(fd, hvcall.control & 0xFFFF)) {
		dev_err(fd->dev->this_device,
			"Hypercall with control data %#llx isn't allowed\n",
			hvcall.control);
		return -EPERM;
	}

	in = (void *)__get_free_page(GFP_KERNEL);
	out = (void *)__get_free_page(GFP_KERNEL);

	if (copy_from_user(in, (void __user *)hvcall.input_ptr, hvcall.input_size)) {
		ret = -EFAULT;
		goto free_pages;
	}

	hvcall.status = hv_do_hypercall(hvcall.control, in, out);

	if (copy_to_user((void __user *)hvcall.output_ptr, out, hvcall.output_size)) {
		ret = -EFAULT;
		goto free_pages;
	}

	ret = put_user(hvcall.status, &hvcall_user->status);

free_pages:
	free_page((unsigned long)in);
	free_page((unsigned long)out);

	return ret;
}

static long mshv_vtl_hvcall_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct mshv_vtl_hvcall_fd *fd = f->private_data;

	switch (cmd) {
	case MSHV_HVCALL_SETUP:
		return mshv_vtl_hvcall_setup(fd, (struct mshv_vtl_hvcall_setup __user *)arg);
	case MSHV_HVCALL:
		return mshv_vtl_hvcall_call(fd, (struct mshv_vtl_hvcall __user *)arg);
	default:
		break;
	}

	return -ENOIOCTLCMD;
}

static const struct file_operations mshv_vtl_hvcall_file_ops = {
	.owner = THIS_MODULE,
	.open = mshv_vtl_hvcall_open,
	.release = mshv_vtl_hvcall_release,
	.unlocked_ioctl = mshv_vtl_hvcall_ioctl,
};

static struct miscdevice mshv_vtl_hvcall = {
	.name = "mshv_hvcall",
	.nodename = "mshv_hvcall",
	.fops = &mshv_vtl_hvcall_file_ops,
	.mode = 0600,
	.minor = MISC_DYNAMIC_MINOR,
};

static int mshv_vtl_low_open(struct inode *inodep, struct file *filp)
{
	pid_t pid = task_pid_vnr(current);
	uid_t uid = current_uid().val;
	int ret = 0;

	pr_debug("%s: Opening VTL low, task group %d, uid %d\n", __func__, pid, uid);

	if (capable(CAP_SYS_ADMIN)) {
		filp->private_data = inodep;
	} else {
		pr_err("%s: VTL low open failed: CAP_SYS_ADMIN required. task group %d, uid %d",
		       __func__, pid, uid);
		ret = -EPERM;
	}

	return ret;
}

static bool can_fault(struct vm_fault *vmf, pgoff_t pgoff, unsigned long size, pfn_t *pfn)
{
	unsigned long mask = size - 1;
	unsigned long start = vmf->address & ~mask;
	unsigned long end = start + size;
	bool valid;
	pgoff = vmf->pgoff & ~DECRYPTED_MASK;

	valid = (vmf->address & mask) == ((pgoff << PAGE_SHIFT) & mask) &&
		start >= vmf->vma->vm_start &&
		end <= vmf->vma->vm_end;

	if (valid)
		*pfn = __pfn_to_pfn_t(pgoff & ~(mask >> PAGE_SHIFT), PFN_DEV | PFN_MAP);

	return valid;
}

static vm_fault_t mshv_vtl_low_huge_fault(struct vm_fault *vmf, unsigned int order)
{
	pgoff_t pgoff;
	pfn_t pfn;
	int ret = VM_FAULT_FALLBACK;

	pgoff = vmf->pgoff & ~DECRYPTED_MASK;

	switch (order) {
	case 0:
		pfn = __pfn_to_pfn_t(pgoff, PFN_DEV | PFN_MAP);
		return vmf_insert_mixed(vmf->vma, vmf->address, pfn);

	case PMD_ORDER:
		if (can_fault(vmf, pgoff, PMD_SIZE, &pfn))
			ret = vmf_insert_pfn_pmd(vmf, pfn, vmf->flags & FAULT_FLAG_WRITE);
		return ret;

#if defined(CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD)
	case PUD_ORDER:
		if (can_fault(vmf, pgoff, PUD_SIZE, &pfn))
			ret = vmf_insert_pfn_pud(vmf, pfn, vmf->flags & FAULT_FLAG_WRITE);
		return ret;
#endif

	default:
		return VM_FAULT_SIGBUS;
	}
}

static vm_fault_t mshv_vtl_low_fault(struct vm_fault *vmf)
{
	return mshv_vtl_low_huge_fault(vmf, 0);
}

static const struct vm_operations_struct mshv_vtl_low_vm_ops = {
	.fault = mshv_vtl_low_fault,
	.huge_fault = mshv_vtl_low_huge_fault,
};

static int mshv_vtl_low_mmap(struct file *filp, struct vm_area_struct *vma)
{
	vma->vm_ops = &mshv_vtl_low_vm_ops;
	vm_flags_set(vma, VM_HUGEPAGE | VM_MIXEDMAP);
	if (vma->vm_pgoff & DECRYPTED_MASK)
		vma->vm_page_prot = pgprot_decrypted(vma->vm_page_prot);
	else
		vma->vm_page_prot = pgprot_encrypted(vma->vm_page_prot);

	return 0;
}

static ssize_t mshv_vtl_transitions_show(struct device *dev, struct device_attribute *attr, char *buff)
{
	int length = 0, cpu;

	length += sysfs_emit_at(buff, length, "cpu#x vtl-transitions\n");

	for_each_online_cpu(cpu)
		length += sysfs_emit_at(buff, length, "cpu%d %llu\n", cpu, per_cpu(num_vtl0_transitions, cpu));

	return length;
}

static DEVICE_ATTR_RO(mshv_vtl_transitions);

static struct attribute *mshv_hvcall_client_attrs[] = {
	&dev_attr_mshv_vtl_transitions.attr,
	NULL,
};
ATTRIBUTE_GROUPS(mshv_hvcall_client);

static const struct file_operations mshv_vtl_low_file_ops = {
	.owner		= THIS_MODULE,
	.open		= mshv_vtl_low_open,
	.mmap		= mshv_vtl_low_mmap,
};

static struct miscdevice mshv_vtl_low = {
	.groups = mshv_hvcall_client_groups,
	.name = "mshv_vtl_low",
	.nodename = "mshv_vtl_low",
	.fops = &mshv_vtl_low_file_ops,
	.mode = 0600,
	.minor = MISC_DYNAMIC_MINOR,
};

static void __init __maybe_unused mshv_vtl_init_dev_memory(u64 addr)
{
	pgd_t	*pgd;
	p4d_t	*p4d;

	pgd = pgd_offset_k(addr);
	if (pgd_none(*pgd)) {
		void *p = (void *)get_zeroed_page(GFP_KERNEL);

		BUG_ON(!p);
		pgd_populate(&init_mm, pgd, p);
	}

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d)) {
		void *p = (void *)get_zeroed_page(GFP_KERNEL);

		BUG_ON(!p);
		p4d_populate(&init_mm, p4d, p);
	}

}

static int __init mshv_vtl_init_memory(void)
{
#ifdef CONFIG_X86_64
	u64 addr;

	pr_debug("CONFIG_PHYSICAL_START: %#016x\n", CONFIG_PHYSICAL_START);
	pr_debug("LOAD_PHYSICAL_ADDR: %#016x\n", LOAD_PHYSICAL_ADDR);

	/*
	 * Add additional PML4 entries to vmmemmap to create struct page*'s
	 * for the sparse memory model and the memory added above 32TiB.
	 */
	BUILD_BUG_ON(IS_ENABLED(CONFIG_KASAN));
	for (addr = 0xffffea8000000000ULL; addr < 0xfffffc0000000000ULL; addr += 0x8000000000ULL)
		mshv_vtl_init_dev_memory(addr);

#endif
	return 0;
}

static int __init mshv_vtl_init(void)
{
	int ret;
	struct device *dev;

	ret = mshv_setup_vtl_func(__mshv_ioctl_create_vtl,
				  __mshv_vtl_ioctl_check_extension,
				  &dev);
	if (ret)
		return ret;

	tasklet_init(&msg_dpc, mshv_vtl_sint_on_msg_dpc, 0);
	init_waitqueue_head(&fd_wait_queue);

	if (mshv_vtl_get_vsm_regs()) {
		dev_emerg(dev, "Unable to get VSM capabilities !!\n");
		ret = -ENODEV;
		goto unset_func;
	}
#ifdef CONFIG_X86_64
	if (!hv_isolation_type_tdx() && !hv_isolation_type_snp()) {
		if (mshv_vtl_configure_vsm_partition(dev)) {
			dev_emerg(dev, "VSM configuration failed !!\n");
			ret = -ENODEV;
			goto unset_func;
		}
	}
#endif
	ret = mshv_tdx_create_apicid_to_cpuid_mapping(dev);
	if (ret)
		goto unset_func;

	ret = hv_vtl_setup_synic();
	if (ret)
		goto unset_func;

	ret = misc_register(&mshv_vtl_sint_dev);
	if (ret)
		goto unset_func;

	ret = misc_register(&mshv_vtl_hvcall);
	if (ret)
		goto free_sint;

	ret = misc_register(&mshv_vtl_low);
	if (ret)
		goto free_hvcall;

	mem_dev = kzalloc(sizeof(*mem_dev), GFP_KERNEL);
	if (!mem_dev) {
		ret = -ENOMEM;
		goto free_low;
	}

	mutex_init(&mshv_vtl_poll_file_lock);

	device_initialize(mem_dev);
	dev_set_name(mem_dev, "mshv vtl mem dev");
	ret = device_add(mem_dev);
	if (ret) {
		dev_err(dev, "mshv vtl mem dev add: %d\n", ret);
		goto free_mem;
	}

	mshv_vtl_init_memory();
	mshv_vtl_set_idle(mshv_vtl_idle);

	/*
	 * The idle routine has been set up, we can now mark in-idle mode as
	 * enabled if in_idle is set.
	*/
	smp_store_release(&in_idle_is_enabled, true);

	return 0;

free_mem:
	kfree(mem_dev);
free_low:
	misc_deregister(&mshv_vtl_low);
free_hvcall:
	misc_deregister(&mshv_vtl_hvcall);
free_sint:
	misc_deregister(&mshv_vtl_sint_dev);
unset_func:
	mshv_setup_vtl_func(NULL, NULL, NULL);
	return ret;
}

static void __exit mshv_vtl_exit(void)
{
	mshv_setup_vtl_func(NULL, NULL, NULL);
	mshv_tdx_free_apicid_to_cpuid_mapping();
	misc_deregister(&mshv_vtl_sint_dev);
	misc_deregister(&mshv_vtl_hvcall);
	misc_deregister(&mshv_vtl_low);
	device_del(mem_dev);
	kfree(mem_dev);
}

module_init(mshv_vtl_init);
module_exit(mshv_vtl_exit);
