// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * Author:
 *   Saurabh Sengar <ssengar@microsoft.com>
 */

#include <linux/kernel.h>
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
#include <linux/vmalloc.h>
#include <asm/boot.h>
#include <asm/trace/hyperv.h>
#include <linux/tick.h>
#include <asm/pgalloc.h>
#include <asm/mshyperv.h>
#include <trace/events/ipi.h>
#include <uapi/linux/mshv.h>

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
#define VTL2_VMBUS_SINT_INDEX	7

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
};

static struct mutex	mshv_vtl_poll_file_lock;
static union hv_register_vsm_page_offsets mshv_vsm_page_offsets;
static union hv_register_vsm_capabilities mshv_vsm_capabilities;

static DEFINE_PER_CPU(struct mshv_vtl_poll_file, mshv_vtl_poll_file);
static DEFINE_PER_CPU(unsigned long long, num_vtl0_transitions);
static DEFINE_PER_CPU(struct mshv_vtl_per_cpu, mshv_vtl_per_cpu);

static struct mshv_vtl_run *mshv_vtl_this_run(void)
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

static void mshv_vtl_synic_enable_regs(unsigned int cpu)
{
	union hv_synic_sint sint;

	sint.as_uint64 = 0;
	sint.vector = vmbus_interrupt;
	sint.masked = false;
	sint.auto_eoi = hv_recommend_using_aeoi();

	/* Enable intercepts */
	if (!mshv_vsm_capabilities.intercept_page_available)
		hv_set_msr(HV_MSR_SINT0 + HV_SYNIC_INTERCEPTION_SINT_INDEX,
			   sint.as_uint64);

	/* VTL2 Host VSP SINT is (un)masked when the user mode requests that */

}

static int mshv_vtl_get_vsm_regs(void)
{
	struct hv_register_assoc registers[2];
	union hv_input_vtl input_vtl;
	int ret, count = 0;

	input_vtl.as_uint8 = 0;
	registers[count++].name = HV_REGISTER_VSM_CAPABILITIES;

	/* Code page offset register is not supported on ARM */
#ifdef CONFIG_X86_64
	registers[count++].name = HV_REGISTER_VSM_CODE_PAGE_OFFSETS;
#endif

	ret = hv_call_get_vp_registers(HV_VP_INDEX_SELF, HV_PARTITION_ID_SELF,
				       count, input_vtl, registers);
	if (ret)
		return ret;

	mshv_vsm_capabilities.as_uint64 = registers[0].value.reg64;
#ifdef CONFIG_X86_64
	mshv_vsm_page_offsets.as_uint64 = registers[1].value.reg64;
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

	event_flags = (union hv_synic_event_flags *)per_cpu->synic_event_page +
			VTL2_VMBUS_SINT_INDEX;
	for (i = 0; i < HV_EVENT_FLAGS_LONG_COUNT; i++) {
		if (READ_ONCE(event_flags->flags[i])) {
			word = xchg(&event_flags->flags[i], 0);
			for_each_set_bit(j, &word, BITS_PER_LONG) {
				rcu_read_lock();
				eventfd = READ_ONCE(flag_eventfds[i * BITS_PER_LONG + j]);
				if (eventfd)
					eventfd_signal(eventfd);
				rcu_read_unlock();
			}
		}
	}

	vmbus_isr();
}

static int mshv_vtl_alloc_context(unsigned int cpu)
{
	struct mshv_vtl_per_cpu *per_cpu = this_cpu_ptr(&mshv_vtl_per_cpu);
	struct page *run_page;

	run_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!run_page)
		return -ENOMEM;

	per_cpu->run = page_address(run_page);
	if (mshv_vsm_capabilities.intercept_page_available)
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

static void mshv_vtl_switch_to_vtl0_irqoff(void)
{
	struct hv_vp_assist_page *hvp;
	struct mshv_vtl_run *this_run = mshv_vtl_this_run();
	struct hv_vtl_cpu_context *cpu_ctx = &this_run->cpu_context;
	u32 flags = READ_ONCE(this_run->flags);

	trace_mshv_vtl_enter_vtl0_rcuidle(cpu_ctx);

	/*
	 * Process signal event direct set in the run page, if any.
	 */
	if (mshv_vsm_capabilities.return_action_available) {
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

	hv_vtl_return(cpu_ctx, flags, mshv_vsm_page_offsets.vtl_return_offset);
	hvp = hv_vp_assist_page[smp_processor_id()];

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
		if (!ret)
			goto free_return; /* No need of hypercall */
		ret = vtl_set_vp_registers(args.count, registers);

	} else {
		ret = hv_vtl_get_reg(registers, mshv_vsm_capabilities.dr6_shared);
		if (!ret)
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

static long
mshv_vtl_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	long ret;
	struct mshv_vtl *vtl = filp->private_data;

	switch (ioctl) {
	case MSHV_VTL_SET_POLL_FILE:
		ret = mshv_vtl_ioctl_set_poll_file((struct mshv_vtl_set_poll_file *)arg);
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

	hv_set_msr(HV_MSR_SINT0 + VTL2_VMBUS_SINT_INDEX,
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

static bool mshv_vtl_hvcall_is_allowed(struct mshv_vtl_hvcall_fd *fd, u16 call_code)
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
	unsigned long flags;
	void *in, *out;

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

	local_irq_save(flags);
	in = *this_cpu_ptr(hyperv_pcpu_input_arg);
	out = *this_cpu_ptr(hyperv_pcpu_output_arg);

	if (copy_from_user(in, (void __user *)hvcall.input_ptr, hvcall.input_size)) {
		local_irq_restore(flags);
		return -EFAULT;
	}

	hvcall.status = hv_do_hypercall(hvcall.control, in, out);

	if (copy_to_user((void __user *)hvcall.output_ptr, out, hvcall.output_size)) {
		local_irq_restore(flags);
		return -EFAULT;
	}
	local_irq_restore(flags);

	return put_user(hvcall.status, &hvcall_user->status);
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

static bool can_fault(struct vm_fault *vmf, unsigned long size, pfn_t *pfn)
{
	unsigned long mask = size - 1;
	unsigned long start = vmf->address & ~mask;
	unsigned long end = start + size;
	bool valid;
	unsigned long pgoff = vmf->pgoff & ~DECRYPTED_MASK;

	valid = (vmf->address & mask) == ((pgoff << PAGE_SHIFT) & mask) &&
		start >= vmf->vma->vm_start &&
		end <= vmf->vma->vm_end;

	if (valid)
		*pfn = __pfn_to_pfn_t(pgoff & ~(mask >> PAGE_SHIFT), PFN_DEV | PFN_MAP);

	return valid;
}

static vm_fault_t mshv_vtl_low_huge_fault(struct vm_fault *vmf, unsigned int order)
{
	pfn_t pfn;
	int ret = VM_FAULT_FALLBACK;

	switch (order) {
	case 0:
		pfn = __pfn_to_pfn_t(vmf->pgoff & ~DECRYPTED_MASK, PFN_DEV | PFN_MAP);
		return vmf_insert_mixed(vmf->vma, vmf->address, pfn);

	case PMD_ORDER:
		if (can_fault(vmf, PMD_SIZE, &pfn))
			ret = vmf_insert_pfn_pmd(vmf, pfn, vmf->flags & FAULT_FLAG_WRITE);
		return ret;

#if defined(CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD)
	case PUD_ORDER:
		if (can_fault(vmf, PUD_SIZE, &pfn))
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
	if (mshv_vtl_configure_vsm_partition(dev)) {
		dev_emerg(dev, "VSM configuration failed !!\n");
		ret = -ENODEV;
		goto unset_func;
	}
#endif

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
	misc_deregister(&mshv_vtl_sint_dev);
	misc_deregister(&mshv_vtl_hvcall);
	misc_deregister(&mshv_vtl_low);
	device_del(mem_dev);
	kfree(mem_dev);
}

module_init(mshv_vtl_init);
module_exit(mshv_vtl_exit);
