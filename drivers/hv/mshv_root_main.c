// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * The main part of the mshv_root module, providing APIs to create
 * and manage guest partitions.
 *
 * Authors:
 *   Nuno Das Neves <nunodasneves@linux.microsoft.com>
 *   Lillian Grassin-Drake <ligrassi@microsoft.com>
 *   Wei Liu <wei.liu@kernel.org>
 *   Vineeth Remanan Pillai <viremana@linux.microsoft.com>
 *   Stanislav Kinsburskii <skinsburskii@linux.microsoft.com>
 *   Asher Kariv <askariv@microsoft.com>
 *   Muminul Islam <Muminul.Islam@microsoft.com>
 *   Anatol Belski <anbelski@linux.microsoft.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/cpuhotplug.h>
#include <linux/random.h>
#include <linux/nospec.h>
#include <linux/dev_printk.h>
#include <asm/mshyperv.h>

#include "mshv_eventfd.h"
#include "mshv.h"
#include "mshv_root.h"

struct mshv_root mshv_root = {};

enum hv_scheduler_type hv_scheduler_type;

static bool ignore_hv_version;
module_param(ignore_hv_version, bool, 0);

/* Once we implement the fast extended hypercall ABI they can go away. */
static void __percpu **root_scheduler_input;
static void __percpu **root_scheduler_output;

static int mshv_vp_release(struct inode *inode, struct file *filp);
static long mshv_vp_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg);
static struct mshv_partition *mshv_partition_get(struct mshv_partition *partition);
static void mshv_partition_put(struct mshv_partition *partition);
static int mshv_partition_release(struct inode *inode, struct file *filp);
static long mshv_partition_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg);
static int mshv_vp_mmap(struct file *file, struct vm_area_struct *vma);
static vm_fault_t mshv_vp_fault(struct vm_fault *vmf);

static const struct vm_operations_struct mshv_vp_vm_ops = {
	.fault = mshv_vp_fault,
};

static const struct file_operations mshv_vp_fops = {
	.owner = THIS_MODULE,
	.release = mshv_vp_release,
	.unlocked_ioctl = mshv_vp_ioctl,
	.llseek = noop_llseek,
	.mmap = mshv_vp_mmap,
};

static const struct file_operations mshv_partition_fops = {
	.owner = THIS_MODULE,
	.release = mshv_partition_release,
	.unlocked_ioctl = mshv_partition_ioctl,
	.llseek = noop_llseek,
};

static int mshv_get_vp_registers(u32 vp_index, u64 partition_id, u16 count,
				 struct hv_register_assoc *registers)
{
	union hv_input_vtl input_vtl;

	input_vtl.as_uint8 = 0;
	return hv_call_get_vp_registers(vp_index, partition_id,
					count, input_vtl, registers);
}

static int mshv_set_vp_registers(u32 vp_index, u64 partition_id, u16 count,
				 struct hv_register_assoc *registers)
{
	union hv_input_vtl input_vtl;

	input_vtl.as_uint8 = 0;
	return hv_call_set_vp_registers(vp_index, partition_id,
					count, input_vtl, registers);
}

static long
mshv_vp_ioctl_get_set_regs(struct mshv_vp *vp, void __user *user_args, bool set)
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
		u32 i;

		for (i = 0; i < args.count; i++) {
			/*
			 * Disallow setting suspend registers to ensure run vp state
			 * is consistent
			 */
			if (registers[i].name == HV_REGISTER_EXPLICIT_SUSPEND ||
			    registers[i].name == HV_REGISTER_INTERCEPT_SUSPEND) {
				vp_err(vp, "not allowed to set suspend registers\n");
				ret = -EINVAL;
				goto free_return;
			}
		}

		ret = mshv_set_vp_registers(vp->index, vp->partition->id,
					    args.count, registers);
	} else {
		ret = mshv_get_vp_registers(vp->index, vp->partition->id,
					    args.count, registers);
		if (ret)
			goto free_return;

		if (copy_to_user((void __user *)args.regs_ptr, registers,
				 sizeof(*registers) * args.count))
			ret = -EFAULT;
	}

free_return:
	kfree(registers);
	return ret;
}

static inline long
mshv_vp_ioctl_set_regs(struct mshv_vp *vp, void __user *user_args)
{
	return mshv_vp_ioctl_get_set_regs(vp, user_args, true);
}

static inline long
mshv_vp_ioctl_get_regs(struct mshv_vp *vp, void __user *user_args)
{
	return mshv_vp_ioctl_get_set_regs(vp, user_args, false);
}

/*
 * Explicit guest vCPU suspend is asynchronous by nature (as it is requested by
 * dom0 vCPU for guest vCPU) and thus it can race with "intercept" suspend,
 * done by the hypervisor.
 * "Intercept" suspend leads to asynchronous message delivery to dom0 which
 * should be awaited to keep the VP loop consistent (i.e. no message pending
 * upon VP resume).
 * VP intercept suspend can't be done when the VP is explicitly suspended
 * already, and thus can be only two possible race scenarios:
 *   1. implicit suspend bit set -> explicit suspend bit set -> message sent
 *   2. implicit suspend bit set -> message sent -> explicit suspend bit set
 * Checking for implicit suspend bit set after explicit suspend request has
 * succeeded in either case allows us to reliably identify, if there is a
 * message to receive and deliver to VMM.
 */
static long
mshv_suspend_vp(const struct mshv_vp *vp, bool *message_in_flight)
{
	struct hv_register_assoc explicit_suspend = {
		.name = HV_REGISTER_EXPLICIT_SUSPEND
	};
	struct hv_register_assoc intercept_suspend = {
		.name = HV_REGISTER_INTERCEPT_SUSPEND
	};
	union hv_explicit_suspend_register *es =
		&explicit_suspend.value.explicit_suspend;
	union hv_intercept_suspend_register *is =
		&intercept_suspend.value.intercept_suspend;
	int ret;

	es->suspended = 1;

	ret = mshv_set_vp_registers(vp->index, vp->partition->id,
				    1, &explicit_suspend);
	if (ret) {
		vp_err(vp, "failed to explicitly suspend vCPU\n");
		return ret;
	}

	ret = mshv_get_vp_registers(vp->index, vp->partition->id,
				    1, &intercept_suspend);
	if (ret) {
		vp_err(vp, "failed to get intercept suspend state\n");
		return ret;
	}

	*message_in_flight = is->suspended;

	return 0;
}

/*
 * This function is used when VPs are scheduled by the hypervisor's
 * scheduler.
 *
 * Caller has to make sure the registers contain cleared
 * HV_REGISTER_INTERCEPT_SUSPEND and HV_REGISTER_EXPLICIT_SUSPEND registers
 * exactly in this order (the hypervisor clears them sequentially) to avoid
 * potential invalid clearing a newly arrived HV_REGISTER_INTERCEPT_SUSPEND
 * after VP is released from HV_REGISTER_EXPLICIT_SUSPEND in case of the
 * opposite order.
 */
static long
mshv_run_vp_with_hv_scheduler(struct mshv_vp *vp, void __user *ret_message,
			      struct hv_register_assoc *registers, size_t count)

{
	struct hv_message *msg = vp->intercept_message_page;
	long ret;

	/* Resume VP execution */
	ret = mshv_set_vp_registers(vp->index, vp->partition->id,
				    count, registers);
	if (ret) {
		vp_err(vp, "failed to resume vCPU\n");
		return ret;
	}

	ret = wait_event_interruptible(vp->run.suspend_queue,
				       vp->run.kicked_by_hv == 1);
	if (ret) {
		bool message_in_flight;

		/*
		 * Otherwise the waiting was interrupted by a signal: suspend
		 * the vCPU explicitly and copy message in flight (if any).
		 */
		ret = mshv_suspend_vp(vp, &message_in_flight);
		if (ret)
			return ret;

		/* Return if no message in flight */
		if (!message_in_flight)
			return -EINTR;

		/* Wait for the message in flight. */
		wait_event(vp->run.suspend_queue, vp->run.kicked_by_hv == 1);
	}

	if (copy_to_user(ret_message, msg, sizeof(struct hv_message)))
		return -EFAULT;

	/*
	 * Reset the flag to make the wait_event call above work
	 * next time.
	 */
	vp->run.kicked_by_hv = 0;

	return 0;
}

static long
mshv_run_vp_with_root_scheduler(struct mshv_vp *vp, void __user *ret_message)
{
	struct hv_input_dispatch_vp *input;
	struct hv_output_dispatch_vp *output;
	long ret = 0;
	u64 status;
	bool complete = false;
	bool got_intercept_message = false;

	while (!complete) {
		if (vp->run.flags.blocked_by_explicit_suspend) {
			/*
			 * Need to clear explicit suspend before dispatching.
			 * Explicit suspend is either:
			 * - set before the first VP dispatch or
			 * - set explicitly via hypercall
			 * Since the latter case is not supported, we simply
			 * clear it here.
			 */
			struct hv_register_assoc explicit_suspend = {
				.name = HV_REGISTER_EXPLICIT_SUSPEND,
				.value.explicit_suspend.suspended = 0,
			};

			ret = mshv_set_vp_registers(vp->index, vp->partition->id,
						    1, &explicit_suspend);
			if (ret) {
				vp_err(vp, "%s: failed to unsuspend partition\n",
				       __func__);
				complete = true;
				break;
			}

			vp->run.flags.explicit_suspend = 0;

			/* Wait for the hypervisor to clear the blocked state */
			ret = wait_event_interruptible(vp->run.suspend_queue,
						       vp->run.kicked_by_hv == 1);
			if (ret) {
				ret = -EINTR;
				complete = true;
				break;
			}
			vp->run.kicked_by_hv = 0;
			vp->run.flags.blocked_by_explicit_suspend = 0;
		}

		if (vp->run.flags.blocked) {
			/*
			 * Dispatch state of this VP is blocked. Need to wait
			 * for the hypervisor to clear the blocked state before
			 * dispatching it.
			 */
			ret = wait_event_interruptible(vp->run.suspend_queue,
						       vp->run.kicked_by_hv == 1);
			if (ret) {
				ret = -EINTR;
				complete = true;
				break;
			}
			vp->run.kicked_by_hv = 0;
			vp->run.flags.blocked = 0;
		}

		preempt_disable();

		while (!vp->run.flags.blocked_by_explicit_suspend && !got_intercept_message) {
			u32 flags = 0;
			unsigned long irq_flags, ti_work;
			const unsigned long work_flags = _TIF_NEED_RESCHED |
							 _TIF_SIGPENDING |
							 _TIF_NOTIFY_SIGNAL |
							 _TIF_NOTIFY_RESUME;

			if (vp->run.flags.intercept_suspend)
				flags |= HV_DISPATCH_VP_FLAG_CLEAR_INTERCEPT_SUSPEND;

			local_irq_save(irq_flags);

			ti_work = READ_ONCE(current_thread_info()->flags);
			if (unlikely(ti_work & work_flags) || need_resched()) {
				local_irq_restore(irq_flags);
				preempt_enable();

				ret = mshv_xfer_to_guest_mode_handle_work(ti_work);

				preempt_disable();

				if (ret) {
					complete = true;
					break;
				}

				continue;
			}

			/*
			 * Note the lack of local_irq_restore after the dipatch
			 * call. We rely on the hypervisor to do that for us.
			 *
			 * Thread context should always have interrupt enabled,
			 * but we try to be defensive here by testing what it
			 * truly was before we disabled interrupt.
			 */
			if (!irqs_disabled_flags(irq_flags))
				flags |= HV_DISPATCH_VP_FLAG_ENABLE_CALLER_INTERRUPTS;

			/* Preemption is disabled at this point */
			input = *this_cpu_ptr(root_scheduler_input);
			output = *this_cpu_ptr(root_scheduler_output);

			memset(input, 0, sizeof(*input));
			memset(output, 0, sizeof(*output));

			input->partition_id = vp->partition->id;
			input->vp_index = vp->index;
			input->time_slice = 0; /* Run forever until something happens */
			input->spec_ctrl = 0; /* TODO: set sensible flags */
			input->flags = flags;

			status = hv_do_hypercall(HVCALL_DISPATCH_VP, input, output);

			if (!hv_result_success(status)) {
				vp_err(vp, "%s: status %s\n", __func__,
				       hv_status_to_string(status));
				ret = hv_status_to_errno(status);
				complete = true;
				break;
			}

			vp->run.flags.intercept_suspend = 0;

			if (output->dispatch_state == HV_VP_DISPATCH_STATE_BLOCKED) {
				if (output->dispatch_event == HV_VP_DISPATCH_EVENT_SUSPEND) {
					vp->run.flags.blocked_by_explicit_suspend = 1;
					/* TODO: remove warning once VP canceling is supported */
					WARN_ONCE(atomic64_read(&vp->run.signaled_count),
						  "%s: vp#%d: unexpected explicit suspend\n",
						   __func__, vp->index);
				} else {
					vp->run.flags.blocked = 1;
					ret = wait_event_interruptible(vp->run.suspend_queue,
								       vp->run.kicked_by_hv == 1);
					if (ret) {
						ret = -EINTR;
						complete = true;
						break;
					}
					vp->run.flags.blocked = 0;
					vp->run.kicked_by_hv = 0;
				}
			} else {
				/* HV_VP_DISPATCH_STATE_READY */
				if (output->dispatch_event == HV_VP_DISPATCH_EVENT_INTERCEPT)
					got_intercept_message = 1;
			}
		}

		preempt_enable();

		if (got_intercept_message) {
			vp->run.flags.intercept_suspend = 1;
			if (copy_to_user(ret_message, vp->intercept_message_page,
					 sizeof(struct hv_message)))
				ret =  -EFAULT;
			complete = true;
		}
	}

	return ret;
}

static long
mshv_vp_ioctl_run_vp(struct mshv_vp *vp, void __user *ret_message)
{
	if (hv_scheduler_type != HV_SCHEDULER_TYPE_ROOT) {
		struct hv_register_assoc suspend_registers[2] = {
			{ .name = HV_REGISTER_INTERCEPT_SUSPEND },
			{ .name = HV_REGISTER_EXPLICIT_SUSPEND }
		};

		return mshv_run_vp_with_hv_scheduler(vp, ret_message,
				suspend_registers, ARRAY_SIZE(suspend_registers));
	}

	return mshv_run_vp_with_root_scheduler(vp, ret_message);
}

static long
mshv_vp_ioctl_run_vp_regs(struct mshv_vp *vp,
			  struct mshv_vp_run_registers __user *user_args)
{
	struct hv_register_assoc suspend_registers[2] = {
		{ .name = HV_REGISTER_INTERCEPT_SUSPEND },
		{ .name = HV_REGISTER_EXPLICIT_SUSPEND }
	};
	struct mshv_vp_run_registers run_regs;
	struct hv_message __user *ret_message;
	int i, regs_count;

	if (hv_scheduler_type == HV_SCHEDULER_TYPE_ROOT)
		return -EOPNOTSUPP;

	if (copy_from_user(&run_regs, user_args, sizeof(run_regs)))
		return -EFAULT;

	ret_message = (struct hv_message __user *)run_regs.message_ptr;
	regs_count = run_regs.registers.count;

	if (regs_count + ARRAY_SIZE(suspend_registers) > MSHV_VP_MAX_REGISTERS)
		return -EINVAL;

	if (copy_from_user(vp->registers,
			   (void __user *)run_regs.registers.regs_ptr,
			   sizeof(*vp->registers) * regs_count))
		return -EFAULT;

	for (i = 0; i < regs_count; i++) {
		/*
		 * Disallow setting suspend registers to ensure run vp state
		 * is consistent
		 */
		if (vp->registers[i].name == HV_REGISTER_EXPLICIT_SUSPEND ||
		    vp->registers[i].name == HV_REGISTER_INTERCEPT_SUSPEND) {
			vp_err(vp, "not allowed to set suspend registers\n");
			return -EINVAL;
		}
	}

	/* Set the last registers to clear suspend */
	memcpy(vp->registers + regs_count,
	       suspend_registers, sizeof(suspend_registers));

	return mshv_run_vp_with_hv_scheduler(vp, ret_message, vp->registers,
			   regs_count + ARRAY_SIZE(suspend_registers));
}

#ifdef HV_SUPPORTS_VP_STATE

static long
mshv_vp_ioctl_get_set_state_pfn(struct mshv_vp *vp,
				struct mshv_vp_state *args,
				bool is_set)
{
	u64 page_count, remaining;
	int completed;
	struct page **pages;
	long ret;
	unsigned long u_buf;

	/* Buffer must be page aligned */
	if (!PAGE_ALIGNED(args->buf_size) ||
	    !PAGE_ALIGNED(args->buf_ptr))
		return -EINVAL;

	if (!access_ok((void __user *)args->buf_ptr, args->buf_size))
		return -EFAULT;

	/* Pin user pages so hypervisor can copy directly to them */
	page_count = args->buf_size >> HV_HYP_PAGE_SHIFT;
	pages = kcalloc(page_count, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	remaining = page_count;
	u_buf = (unsigned long)args->buf_ptr;
	while (remaining) {
		completed = pin_user_pages_fast(u_buf, remaining, FOLL_WRITE,
						&pages[page_count - remaining]);
		if (completed < 0) {
			vp_err(vp, "failed to pin user pages error %i\n", completed);
			ret = completed;
			goto unpin_pages;
		}
		remaining -= completed;
		u_buf += completed * HV_HYP_PAGE_SIZE;
	}

	if (is_set)
		ret = hv_call_set_vp_state(vp->index,
					   vp->partition->id,
					   args->type, args->xsave,
					   page_count, pages,
					   0, NULL);
	else
		ret = hv_call_get_vp_state(vp->index,
					   vp->partition->id,
					   args->type, args->xsave,
					   page_count, pages,
					   NULL);

unpin_pages:
	unpin_user_pages(pages, page_count - remaining);
	kfree(pages);
	return ret;
}

static long
mshv_vp_ioctl_get_set_state(struct mshv_vp *vp, void __user *user_args, bool is_set)
{
	struct mshv_vp_state args;
	long ret = 0;
	union hv_output_get_vp_state vp_state;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	/* For now just support these */
	if (args.type != HV_GET_SET_VP_STATE_LOCAL_INTERRUPT_CONTROLLER_STATE &&
	    args.type != HV_GET_SET_VP_STATE_XSAVE)
		return -EINVAL;

	/* If we need to pin pfns, delegate to helper */
	if (args.type & HV_GET_SET_VP_STATE_TYPE_PFN)
		return mshv_vp_ioctl_get_set_state_pfn(vp, &args, is_set);

	if (args.buf_size < sizeof(vp_state))
		return -EINVAL;

	if (is_set) {
		if (copy_from_user(&vp_state, (void __user *)args.buf_ptr,
				   sizeof(vp_state)))
			return -EFAULT;

		return hv_call_set_vp_state(vp->index,
					    vp->partition->id,
					    args.type, args.xsave,
					    0, NULL,
					    sizeof(vp_state),
					    (u8 *)&vp_state);
	}

	ret = hv_call_get_vp_state(vp->index,
				   vp->partition->id,
				   args.type, args.xsave,
				   0, NULL,
				   &vp_state);

	if (ret)
		return ret;

	if (copy_to_user((void __user *)args.buf_ptr,
			 &vp_state.interrupt_controller_state,
			 sizeof(vp_state.interrupt_controller_state)))
		return -EFAULT;

	return 0;
}

#endif

#ifdef HV_SUPPORTS_REGISTER_INTERCEPT

static long
mshv_vp_ioctl_register_intercept_result(struct mshv_vp *vp, void __user *user_args)
{
	struct mshv_register_intercept_result args;
	long ret;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	ret = hv_call_register_intercept_result(vp->index,
						vp->partition->id,
						args.intercept_type,
						&args.parameters);

	return ret;
}

#endif

static long
mshv_vp_ioctl_get_cpuid_values(struct mshv_vp *vp, void __user *user_args)
{
	struct mshv_get_vp_cpuid_values args;
	union hv_get_vp_cpuid_values_flags flags;
	struct hv_cpuid_leaf_info info;
	union hv_output_get_vp_cpuid_values result;
	long ret;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	flags.use_vp_xfem_xss = 1;
	flags.apply_registered_values = 1;
	flags.reserved = 0;

	memset(&info, 0, sizeof(info));
	info.eax = args.function;
	info.ecx = args.index;

	ret = hv_call_get_vp_cpuid_values(vp->index, vp->partition->id, flags,
					  &info, &result);

	if (ret)
		return ret;

	args.eax = result.eax;
	args.ebx = result.ebx;
	args.ecx = result.ecx;
	args.edx = result.edx;
	if (copy_to_user(user_args, &args, sizeof(args)))
		return -EFAULT;

	return 0;
}

static long
mshv_vp_ioctl_translate_gva(struct mshv_vp *vp, void __user *user_args)
{
	long ret;
	struct mshv_translate_gva args;
	u64 gpa;
	union hv_translate_gva_result result;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	ret = hv_call_translate_virtual_address(vp->index, vp->partition->id,
						args.flags, args.gva, &gpa,
						&result);

	if (ret)
		return ret;

	args.result = result;
	args.gpa = gpa;

	if (copy_to_user(user_args, &args, sizeof(args)))
		return -EFAULT;

	return 0;
}

static long
mshv_vp_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	struct mshv_vp *vp = filp->private_data;
	long r = -ENOTTY;

	if (mutex_lock_killable(&vp->mutex))
		return -EINTR;

	switch (ioctl) {
	case MSHV_RUN_VP:
		r = mshv_vp_ioctl_run_vp(vp, (void __user *)arg);
		break;
	case MSHV_RUN_VP_REGISTERS:
		r = mshv_vp_ioctl_run_vp_regs(vp, (void __user *)arg);
		break;
	case MSHV_GET_VP_REGISTERS:
		r = mshv_vp_ioctl_get_regs(vp, (void __user *)arg);
		break;
	case MSHV_SET_VP_REGISTERS:
		r = mshv_vp_ioctl_set_regs(vp, (void __user *)arg);
		break;
#ifdef HV_SUPPORTS_VP_STATE
	case MSHV_GET_VP_STATE:
		r = mshv_vp_ioctl_get_set_state(vp, (void __user *)arg, false);
		break;
	case MSHV_SET_VP_STATE:
		r = mshv_vp_ioctl_get_set_state(vp, (void __user *)arg, true);
		break;
#endif
	case MSHV_TRANSLATE_GVA:
		r = mshv_vp_ioctl_translate_gva(vp, (void __user *)arg);
		break;
#ifdef HV_SUPPORTS_REGISTER_INTERCEPT
	case MSHV_VP_REGISTER_INTERCEPT_RESULT:
		r = mshv_vp_ioctl_register_intercept_result(vp, (void __user *)arg);
		break;
#endif
	case MSHV_GET_VP_CPUID_VALUES:
		r = mshv_vp_ioctl_get_cpuid_values(vp, (void __user *)arg);
		break;
	default:
		vp_err(vp, "invalid ioctl: %#x\n", ioctl);
		break;
	}
	mutex_unlock(&vp->mutex);

	return r;
}

static vm_fault_t mshv_vp_fault(struct vm_fault *vmf)
{
	struct mshv_vp *vp = vmf->vma->vm_file->private_data;

	vmf->page = vp->register_page;
	get_page(vp->register_page);

	return 0;
}

static int mshv_vp_mmap(struct file *file, struct vm_area_struct *vma)
{
	int ret;
	struct mshv_vp *vp = file->private_data;

	if (vma->vm_pgoff != MSHV_VP_MMAP_REGISTERS_OFFSET)
		return -EINVAL;

	if (mutex_lock_killable(&vp->mutex))
		return -EINTR;

	if (!vp->register_page) {
		ret = hv_call_map_vp_state_page(vp->partition->id,
						vp->index,
						HV_VP_STATE_PAGE_REGISTERS,
						&vp->register_page);
		if (ret) {
			mutex_unlock(&vp->mutex);
			return ret;
		}
	}

	mutex_unlock(&vp->mutex);

	vma->vm_ops = &mshv_vp_vm_ops;
	return 0;
}

static int
mshv_vp_release(struct inode *inode, struct file *filp)
{
	struct mshv_vp *vp = filp->private_data;

	/* Rest of VP cleanup happens in destroy_partition() */
	mshv_partition_put(vp->partition);
	return 0;
}

static long
mshv_partition_ioctl_create_vp(struct mshv_partition *partition,
			       void __user *arg)
{
	struct mshv_create_vp args;
	struct mshv_vp *vp;
	struct file *file;
	int fd;
	long ret;
	struct page *intercept_message_page;

	if (copy_from_user(&args, arg, sizeof(args)))
		return -EFAULT;

	if (args.vp_index >= MSHV_MAX_VPS)
		return -EINVAL;

	if (partition->vps.array[args.vp_index])
		return -EEXIST;

	vp = kzalloc(sizeof(*vp), GFP_KERNEL);

	if (!vp)
		return -ENOMEM;

	mutex_init(&vp->mutex);
	init_waitqueue_head(&vp->run.suspend_queue);

	atomic64_set(&vp->run.signaled_count, 0);

	vp->registers = kmalloc_array(MSHV_VP_MAX_REGISTERS,
				      sizeof(*vp->registers), GFP_KERNEL);
	if (!vp->registers) {
		ret = -ENOMEM;
		goto free_vp;
	}

	vp->index = args.vp_index;
	vp->partition = mshv_partition_get(partition);
	if (!vp->partition) {
		ret = -EBADF;
		goto free_registers;
	}

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		ret = fd;
		goto put_partition;
	}

	file = anon_inode_getfile("mshv_vp", &mshv_vp_fops, vp, O_RDWR);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto put_fd;
	}

	/* vp index set to 0 - only valid for root partition VPs */
	ret = hv_call_create_vp(NUMA_NO_NODE, partition->id, args.vp_index, 0);
	if (ret)
		goto release_file;

	ret = hv_call_map_vp_state_page(partition->id, vp->index,
					HV_VP_STATE_PAGE_INTERCEPT_MESSAGE,
					&intercept_message_page);
	if (ret)
		goto release_file;

	vp->intercept_message_page = page_to_virt(intercept_message_page);

	/* already exclusive with the partition mutex for all ioctls */
	partition->vps.count++;
	partition->vps.array[args.vp_index] = vp;

	fd_install(fd, file);

	return fd;

release_file:
	file->f_op->release(file->f_inode, file);
put_fd:
	put_unused_fd(fd);
put_partition:
	mshv_partition_put(partition);
free_registers:
	kfree(vp->registers);
free_vp:
	kfree(vp);

	return ret;
}

static long
mshv_partition_ioctl_get_property(struct mshv_partition *partition,
				  void __user *user_args)
{
	struct mshv_partition_property args;
	long ret;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	ret = hv_call_get_partition_property(partition->id, args.property_code,
					     &args.property_value);

	if (ret)
		return ret;

	if (copy_to_user(user_args, &args, sizeof(args)))
		return -EFAULT;

	return 0;
}

static void
mshv_root_async_hypercall_handler(void *data, u64 *status)
{
	struct mshv_partition *partition = data;

	wait_for_completion(&partition->async_hypercall);
	reinit_completion(&partition->async_hypercall);

	partition_dbg(partition, "Async hypercall completed!\n");

	*status = HV_STATUS_SUCCESS;
}

static long
mshv_partition_ioctl_set_property(struct mshv_partition *partition,
				  void __user *user_args)
{
	struct mshv_partition_property args;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	return hv_call_set_partition_property(partition->id, args.property_code,
					      args.property_value,
					      mshv_root_async_hypercall_handler,
					      partition);
}

static long
mshv_partition_ioctl_map_memory(struct mshv_partition *partition,
				struct mshv_user_mem_region __user *user_mem)
{
	struct mshv_user_mem_region mem;
	struct mshv_mem_region *region;
	int completed;
	unsigned long remaining, batch_size, pin_addr;
	struct page **pages;
	u64 page_count, user_start, user_end, gpfn_start, gpfn_end;
	u64 region_page_count, region_user_start, region_user_end;
	u64 region_gpfn_start, region_gpfn_end;
	long ret = 0;

	if (copy_from_user(&mem, user_mem, sizeof(mem)))
		return -EFAULT;

	if (!mem.size ||
	    !PAGE_ALIGNED(mem.size) ||
	    !PAGE_ALIGNED(mem.userspace_addr) ||
	    !access_ok((const void *)mem.userspace_addr, mem.size))
		return -EINVAL;

	/* Reject overlapping regions */
	page_count = mem.size >> HV_HYP_PAGE_SHIFT;
	user_start = mem.userspace_addr;
	user_end = mem.userspace_addr + mem.size;
	gpfn_start = mem.guest_pfn;
	gpfn_end = mem.guest_pfn + page_count;

	hlist_for_each_entry(region, &partition->mem_regions, hnode) {
		region_page_count = region->size >> HV_HYP_PAGE_SHIFT;
		region_user_start = region->userspace_addr;
		region_user_end = region->userspace_addr + region->size;
		region_gpfn_start = region->guest_pfn;
		region_gpfn_end = region->guest_pfn + region_page_count;

		if (!(user_end <= region_user_start) &&
		    !(region_user_end <= user_start)) {
			return -EEXIST;
		}
		if (!(gpfn_end <= region_gpfn_start) &&
		    !(region_gpfn_end <= gpfn_start)) {
			return -EEXIST;
		}
	}

	region = vzalloc(sizeof(*region) + sizeof(*pages) * page_count);
	if (!region)
		return -ENOMEM;
	region->size = mem.size;
	region->guest_pfn = mem.guest_pfn;
	region->userspace_addr = mem.userspace_addr;
	pages = &region->pages[0];

	/* Pin the userspace pages */
	remaining = page_count;
	while (remaining) {
		/*
		 * We need to batch this, as pin_user_pages_fast with the
		 * FOLL_LONGTERM flag does a big temporary allocation
		 * of contiguous memory
		 */
		batch_size = min(remaining, PIN_PAGES_BATCH_SIZE);
		pin_addr = mem.userspace_addr + (page_count - remaining) * HV_HYP_PAGE_SIZE;
		completed = pin_user_pages_fast(pin_addr, batch_size,
						FOLL_WRITE | FOLL_LONGTERM,
						&pages[page_count - remaining]);
		if (completed < 0) {
			partition_err(partition, "failed to pin user pages error %i\n",
				      completed);
			ret = completed;
			goto err_unpin_pages;
		}
		remaining -= completed;
	}

	/* Map the pages to GPA pages */
	ret = hv_call_map_gpa_pages(partition->id, mem.guest_pfn,
				    page_count, mem.flags, pages);

	/* Install the new region */
	hlist_add_head(&region->hnode, &partition->mem_regions);

	return 0;

err_unpin_pages:
	unpin_user_pages(pages, page_count - remaining);
	vfree(region);

	return ret;
}

static long
mshv_partition_ioctl_unmap_memory(struct mshv_partition *partition,
				  struct mshv_user_mem_region __user *user_mem)
{
	struct mshv_user_mem_region mem;
	struct mshv_mem_region *region;
	u64 page_count;
	long ret;

	if (hlist_empty(&partition->mem_regions))
		return -EINVAL;

	if (copy_from_user(&mem, user_mem, sizeof(mem)))
		return -EFAULT;

	/* Find matching region */
	hlist_for_each_entry(region, &partition->mem_regions, hnode) {
		if (region->userspace_addr == mem.userspace_addr &&
		    region->size == mem.size &&
		    region->guest_pfn == mem.guest_pfn)
			break;
	}

	if (!region)
		return -EINVAL;

	hlist_del(&region->hnode);
	page_count = region->size >> HV_HYP_PAGE_SHIFT;
	ret = hv_call_unmap_gpa_pages(partition->id, region->guest_pfn,
				      page_count, 0);
	if (ret)
		return ret;

	unpin_user_pages(&region->pages[0], page_count);
	vfree(region);

	return 0;
}

static long
mshv_partition_ioctl_ioeventfd(struct mshv_partition *partition,
			       void __user *user_args)
{
	struct mshv_ioeventfd args;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	return mshv_ioeventfd(partition, &args);
}

static long
mshv_partition_ioctl_irqfd(struct mshv_partition *partition,
			   void __user *user_args)
{
	struct mshv_irqfd args;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	return mshv_irqfd(partition, &args);
}

static long
mshv_partition_ioctl_install_intercept(struct mshv_partition *partition,
				       void __user *user_args)
{
	struct mshv_install_intercept args;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	return hv_call_install_intercept(partition->id, args.access_type_mask,
					 args.intercept_type,
					 args.intercept_parameter);
}

static long
mshv_partition_ioctl_post_message_direct(struct mshv_partition *partition,
					 void __user *user_args)
{
	struct mshv_post_message_direct args;
	u8 message[HV_MESSAGE_SIZE];

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	if (args.length > HV_MESSAGE_SIZE)
		return -E2BIG;

	memset(&message[0], 0, sizeof(message));
	if (copy_from_user(&message[0], args.message, args.length))
		return -EFAULT;

	return hv_call_post_message_direct(args.vp,
					partition->id,
					args.vtl,
					args.sint,
					&message[0]);
}

static long
mshv_partition_ioctl_signal_event_direct(struct mshv_partition *partition,
					 void __user *user_args)
{
	struct mshv_signal_event_direct args;
	long ret;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	ret = hv_call_signal_event_direct(args.vp, partition->id, args.vtl,
					  args.sint, args.flag,
					  &args.newly_signaled);

	if (ret)
		return ret;

	if (copy_to_user(user_args, &args, sizeof(args)))
		return -EFAULT;

	return 0;
}

static long
mshv_partition_ioctl_assert_interrupt(struct mshv_partition *partition,
				      void __user *user_args)
{
	struct mshv_assert_interrupt args;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	return hv_call_assert_virtual_interrupt(partition->id, args.vector,
						args.dest_addr, args.control);
}

static long
mshv_partition_ioctl_get_gpa_access_state(struct mshv_partition *partition,
					  void __user *user_args)
{
	struct mshv_get_gpa_pages_access_state args;
	union hv_gpa_page_access_state *states;
	long ret;
	int written = 0;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	states = vzalloc(args.count * sizeof(*states));
	if (!states)
		return -ENOMEM;
	ret = hv_call_get_gpa_access_states(partition->id, args.count,
					    args.hv_gpa_page_number,
					    args.flags, &written, states);
	if (ret)
		goto free_return;

	args.count = written;
	if (copy_to_user(user_args, &args, sizeof(args))) {
		ret = -EFAULT;
		goto free_return;
	}

	if (copy_to_user((void __user *)args.states_ptr, states,
			 sizeof(*states) * args.count))
		ret = -EFAULT;

free_return:
	vfree(states);
	return ret;
}

static long
mshv_partition_ioctl_set_msi_routing(struct mshv_partition *partition,
				     void __user *user_args)
{
	struct mshv_msi_routing_entry *entries = NULL;
	struct mshv_msi_routing args;
	long ret;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	if (args.nr > MSHV_MAX_MSI_ROUTES)
		return -EINVAL;

	if (args.nr) {
		struct mshv_msi_routing __user *urouting = user_args;

		entries = vmemdup_user(urouting->entries,
				       array_size(sizeof(*entries),
						  args.nr));
		if (IS_ERR(entries))
			return PTR_ERR(entries);
	}
	ret = mshv_set_msi_routing(partition, entries, args.nr);
	kvfree(entries);

	return ret;
}

#ifdef HV_SUPPORTS_REGISTER_DELIVERABILITY_NOTIFICATIONS
static long
mshv_partition_ioctl_register_deliverabilty_notifications(struct mshv_partition *partition,
							  void __user *user_args)
{
	struct mshv_register_deliverabilty_notifications args;
	struct hv_register_assoc hv_reg;

	if (copy_from_user(&args, user_args, sizeof(args)))
		return -EFAULT;

	memset(&hv_reg, 0, sizeof(hv_reg));
	hv_reg.name = HV_X64_REGISTER_DELIVERABILITY_NOTIFICATIONS;
	hv_reg.value.reg64 = args.flag;

	return mshv_set_vp_registers(args.vp, partition->id, 1, &hv_reg);
}
#endif

static long
mshv_partition_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	struct mshv_partition *partition = filp->private_data;
	long ret;

	if (mutex_lock_killable(&partition->mutex))
		return -EINTR;

	switch (ioctl) {
	case MSHV_MAP_GUEST_MEMORY:
		ret = mshv_partition_ioctl_map_memory(partition,
						      (void __user *)arg);
		break;
	case MSHV_UNMAP_GUEST_MEMORY:
		ret = mshv_partition_ioctl_unmap_memory(partition,
							(void __user *)arg);
		break;
	case MSHV_CREATE_VP:
		ret = mshv_partition_ioctl_create_vp(partition,
						     (void __user *)arg);
		break;
	case MSHV_INSTALL_INTERCEPT:
		ret = mshv_partition_ioctl_install_intercept(partition,
							     (void __user *)arg);
		break;
	case MSHV_ASSERT_INTERRUPT:
		ret = mshv_partition_ioctl_assert_interrupt(partition,
							    (void __user *)arg);
		break;
	case MSHV_GET_PARTITION_PROPERTY:
		ret = mshv_partition_ioctl_get_property(partition,
							(void __user *)arg);
		break;
	case MSHV_SET_PARTITION_PROPERTY:
		ret = mshv_partition_ioctl_set_property(partition,
							(void __user *)arg);
		break;
	case MSHV_IRQFD:
		ret = mshv_partition_ioctl_irqfd(partition,
						 (void __user *)arg);
		break;
	case MSHV_IOEVENTFD:
		ret = mshv_partition_ioctl_ioeventfd(partition,
						     (void __user *)arg);
		break;
	case MSHV_SET_MSI_ROUTING:
		ret = mshv_partition_ioctl_set_msi_routing(partition,
							   (void __user *)arg);
		break;
	case MSHV_GET_GPA_ACCESS_STATES:
		ret = mshv_partition_ioctl_get_gpa_access_state(partition,
								(void __user *)arg);
		break;
	case MSHV_SIGNAL_EVENT_DIRECT:
		ret = mshv_partition_ioctl_signal_event_direct(partition,
							       (void __user *)arg);
		break;
	case MSHV_POST_MESSAGE_DIRECT:
		ret = mshv_partition_ioctl_post_message_direct(partition,
							       (void __user *)arg);
		break;
#ifdef HV_SUPPORTS_REGISTER_DELIVERABILITY_NOTIFICATIONS
	case MSHV_REGISTER_DELIVERABILITY_NOTIFICATIONS:
		ret = mshv_partition_ioctl_register_deliverabilty_notifications(partition,
										(void __user *)arg);
		break;
#endif
	default:
		ret = -ENOTTY;
	}

	mutex_unlock(&partition->mutex);
	return ret;
}

static int
disable_vp_dispatch(struct mshv_vp *vp)
{
	int ret;
	struct hv_register_assoc dispatch_suspend = {
		.name = HV_REGISTER_DISPATCH_SUSPEND,
		.value.dispatch_suspend.suspended = 1,
	};

	ret = mshv_set_vp_registers(vp->index, vp->partition->id,
				    1, &dispatch_suspend);
	if (ret)
		vp_err(vp, "failed to suspend partition\n");

	return ret;
}

static int
get_vp_signaled_count(struct mshv_vp *vp, u64 *count)
{
	int ret;
	struct hv_register_assoc root_signal_count = {
		.name = HV_REGISTER_VP_ROOT_SIGNAL_COUNT,
	};

	ret = mshv_get_vp_registers(vp->index, vp->partition->id,
				    1, &root_signal_count);

	if (ret) {
		vp_err(vp, "failed to get root signal count for partition\n");
		*count = 0;
		return ret;
	}

	*count = root_signal_count.value.reg64;

	return ret;
}

static void
drain_vp_signals(struct mshv_vp *vp)
{
	u64 hv_signal_count;
	u64 vp_signal_count;

	WARN_ON(get_vp_signaled_count(vp, &hv_signal_count));

	vp_signal_count = atomic64_read(&vp->run.signaled_count);

	/*
	 * There should be at most 1 outstanding notification, but be extra
	 * careful anyway.
	 */
	while (hv_signal_count != vp_signal_count) {
		WARN_ON(hv_signal_count - vp_signal_count != 1);

		if (wait_event_interruptible(vp->run.suspend_queue,
					     vp->run.kicked_by_hv == 1))
			break;
		vp->run.kicked_by_hv = 0;
		vp_signal_count = atomic64_read(&vp->run.signaled_count);
	}
}

static void drain_all_vps(const struct mshv_partition *partition)
{
	int i;
	struct mshv_vp *vp;

	/*
	 * VPs are reachable from ISR. It is safe to not take the partition
	 * lock because nobody else can enter this function and drop the
	 * partition from the list.
	 */
	for (i = 0; i < MSHV_MAX_VPS; i++) {
		vp = partition->vps.array[i];
		if (!vp)
			continue;
		/*
		 * Disable dispatching of the VP in the hypervisor. After this
		 * the hypervisor guarantees it won't generate any signals for
		 * the VP and the hypervisor's VP signal count won't change.
		 */
		disable_vp_dispatch(vp);
		drain_vp_signals(vp);
	}
}

static void
remove_partition(struct mshv_partition *partition)
{
	spin_lock(&mshv_root.partitions.lock);
	hlist_del_rcu(&partition->hnode);

	if (!--mshv_root.partitions.count)
		hv_setup_mshv_irq(NULL);

	spin_unlock(&mshv_root.partitions.lock);

	synchronize_rcu();
}

static void
destroy_partition(struct mshv_partition *partition)
{
	unsigned long page_count;
	struct mshv_vp *vp;
	struct mshv_mem_region *region;
	int i;
	struct hlist_node *n;

	/*
	 * This must be done before we drain all the vps and call
	 * remove_partition, otherwise we won't receive the interrupt
	 * for completion of this async hypercall.
	 */
	if (mshv_partition_isolation_type_snp(partition)) {
		WARN_ON(hv_call_set_partition_property(partition->id,
						       HV_PARTITION_PROPERTY_ISOLATION_STATE,
						       HV_PARTITION_ISOLATION_INSECURE_DIRTY,
						       mshv_root_async_hypercall_handler,
						       partition));
	}

	/*
	 * We only need to drain signals for root scheduler. This should be
	 * done before removing the partition from the partition list.
	 */
	if (hv_scheduler_type == HV_SCHEDULER_TYPE_ROOT)
		drain_all_vps(partition);

	/*
	 * Remove from list of partitions; after this point nothing else holds
	 * a reference to the partition
	 */
	remove_partition(partition);

	/* Remove vps */
	for (i = 0; i < MSHV_MAX_VPS; ++i) {
		vp = partition->vps.array[i];
		if (!vp)
			continue;

		kfree(vp->registers);
		if (vp->intercept_message_page) {
			(void)hv_call_unmap_vp_state_page(partition->id, vp->index,
					HV_VP_STATE_PAGE_INTERCEPT_MESSAGE);
			vp->intercept_message_page = NULL;
		}
		kfree(vp);
	}

	/* Deallocates and unmaps everything including vcpus, GPA mappings etc */
	hv_call_finalize_partition(partition->id);
	/* Withdraw and free all pages we deposited */
	hv_call_withdraw_memory(U64_MAX, NUMA_NO_NODE, partition->id);
	hv_call_delete_partition(partition->id);

	/* Remove regions and unpin the pages */
	hlist_for_each_entry_safe(region, n, &partition->mem_regions, hnode) {
		hlist_del(&region->hnode);
		page_count = region->size >> HV_HYP_PAGE_SHIFT;
		unpin_user_pages(&region->pages[0], page_count);
		vfree(region);
	}

	mshv_free_msi_routing(partition);
	kfree(partition);
}

static struct
mshv_partition *mshv_partition_get(struct mshv_partition *partition)
{
	if (refcount_inc_not_zero(&partition->ref_count))
		return partition;
	return NULL;
}

struct
mshv_partition *mshv_partition_find(u64 partition_id)
	__must_hold(RCU)
{
	struct mshv_partition *p;

	hash_for_each_possible_rcu(mshv_root.partitions.items, p, hnode, partition_id)
		if (p->id == partition_id)
			return p;

	return NULL;
}

static void
mshv_partition_put(struct mshv_partition *partition)
{
	if (refcount_dec_and_test(&partition->ref_count))
		destroy_partition(partition);
}

static int
mshv_partition_release(struct inode *inode, struct file *filp)
{
	struct mshv_partition *partition = filp->private_data;

	mshv_eventfd_release(partition);

	cleanup_srcu_struct(&partition->irq_srcu);

	mshv_partition_put(partition);

	return 0;
}

static int
add_partition(struct mshv_partition *partition)
{
	spin_lock(&mshv_root.partitions.lock);

	hash_add_rcu(mshv_root.partitions.items, &partition->hnode, partition->id);

	mshv_root.partitions.count++;
	if (mshv_root.partitions.count == 1)
		hv_setup_mshv_irq(mshv_isr);

	spin_unlock(&mshv_root.partitions.lock);

	return 0;
}

static long
__mshv_ioctl_create_partition(void __user *user_arg, struct device *module_dev)
{
	struct mshv_create_partition args;
	struct mshv_partition *partition;
	struct file *file;
	int fd;
	long ret;

	if (copy_from_user(&args, user_arg, sizeof(args)))
		return -EFAULT;

	/* Only support EXO partitions */
	args.flags |= HV_PARTITION_CREATION_FLAG_EXO_PARTITION;
	/* Enable intercept message page */
	args.flags |= HV_PARTITION_CREATION_FLAG_INTERCEPT_MESSAGE_PAGE_ENABLED;

	partition = kzalloc(sizeof(*partition), GFP_KERNEL);
	if (!partition)
		return -ENOMEM;

	partition->module_dev = module_dev;
	partition->isolation_type = args.isolation_properties.isolation_type;

	refcount_set(&partition->ref_count, 1);

	mutex_init(&partition->mutex);

	mutex_init(&partition->irq_lock);

	init_completion(&partition->async_hypercall);

	INIT_HLIST_HEAD(&partition->irq_ack_notifier_list);

	INIT_HLIST_HEAD(&partition->mem_regions);

	mshv_eventfd_init(partition);

	ret = init_srcu_struct(&partition->irq_srcu);
	if (ret)
		goto free_partition;

	ret = hv_call_create_partition(args.flags,
				       args.partition_creation_properties,
				       args.isolation_properties,
				       &partition->id);
	if (ret)
		goto cleanup_irq_srcu;

	ret = add_partition(partition);
	if (ret)
		goto delete_partition;

	ret = hv_call_set_partition_property(partition->id,
					     HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES,
					     args.synthetic_processor_features.as_uint64[0],
					     mshv_root_async_hypercall_handler,
					     partition);
	if (ret)
		goto remove_partition;

	ret = hv_call_initialize_partition(partition->id);
	if (ret)
		goto remove_partition;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		ret = fd;
		goto finalize_partition;
	}

	file = anon_inode_getfile("mshv_partition", &mshv_partition_fops,
				  partition, O_RDWR);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto put_fd;
	}

	fd_install(fd, file);

	return fd;

put_fd:
	put_unused_fd(fd);
finalize_partition:
	hv_call_finalize_partition(partition->id);
remove_partition:
	remove_partition(partition);
delete_partition:
	hv_call_withdraw_memory(U64_MAX, NUMA_NO_NODE, partition->id);
	hv_call_delete_partition(partition->id);
cleanup_irq_srcu:
	cleanup_srcu_struct(&partition->irq_srcu);
free_partition:
	kfree(partition);
	return ret;
}

static int mshv_cpuhp_online;
static int mshv_root_sched_online;

static const char *scheduler_type_to_string(enum hv_scheduler_type type)
{
	switch (type) {
	case HV_SCHEDULER_TYPE_LP:
		return "classic scheduler without SMT";
	case HV_SCHEDULER_TYPE_LP_SMT:
		return "classic scheduler with SMT";
	case HV_SCHEDULER_TYPE_CORE_SMT:
		return "core scheduler";
	case HV_SCHEDULER_TYPE_ROOT:
		return "root scheduler";
	default:
		return "unknown scheduler";
	};
}

/* Retrieve and stash the supported scheduler type */
static int __init mshv_retrieve_scheduler_type(struct device *dev)
{
	struct hv_input_get_system_property *input;
	struct hv_output_get_system_property *output;
	unsigned long flags;
	u64 status;

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	output = *this_cpu_ptr(hyperv_pcpu_output_arg);

	memset(input, 0, sizeof(*input));
	memset(output, 0, sizeof(*output));
	input->property_id = HV_SYSTEM_PROPERTY_SCHEDULER_TYPE;

	status = hv_do_hypercall(HVCALL_GET_SYSTEM_PROPERTY, input, output);
	if (!hv_result_success(status)) {
		local_irq_restore(flags);
		dev_err(dev, "%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	hv_scheduler_type = output->scheduler_type;
	local_irq_restore(flags);

	dev_info(dev, "hypervisor using %s\n",
		 scheduler_type_to_string(hv_scheduler_type));

	switch (hv_scheduler_type) {
	case HV_SCHEDULER_TYPE_CORE_SMT:
	case HV_SCHEDULER_TYPE_LP_SMT:
	case HV_SCHEDULER_TYPE_ROOT:
	case HV_SCHEDULER_TYPE_LP:
		/* Supported scheduler, nothing to do */
		break;
	default:
		dev_err(dev, "unsupported scheduler 0x%x, bailing.\n",
			hv_scheduler_type);
		return -EOPNOTSUPP;
	}

	return 0;
}

static int mshv_root_scheduler_init(unsigned int cpu)
{
	void **inputarg, **outputarg, *p;

	inputarg = (void **)this_cpu_ptr(root_scheduler_input);
	outputarg = (void **)this_cpu_ptr(root_scheduler_output);

	/* Allocate two consecutive pages. One for input, one for output. */
	p = kmalloc(2 * HV_HYP_PAGE_SIZE, GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	*inputarg = p;
	*outputarg = (char *)p + HV_HYP_PAGE_SIZE;

	return 0;
}

static int mshv_root_scheduler_cleanup(unsigned int cpu)
{
	void *p, **inputarg, **outputarg;

	inputarg = (void **)this_cpu_ptr(root_scheduler_input);
	outputarg = (void **)this_cpu_ptr(root_scheduler_output);

	p = *inputarg;

	*inputarg = NULL;
	*outputarg = NULL;

	kfree(p);

	return 0;
}

/* Must be called after retrieving the scheduler type */
static int
root_scheduler_init(struct device *dev)
{
	int ret;

	if (hv_scheduler_type != HV_SCHEDULER_TYPE_ROOT)
		return 0;

	root_scheduler_input = alloc_percpu(void *);
	root_scheduler_output = alloc_percpu(void *);

	if (!root_scheduler_input || !root_scheduler_output) {
		dev_err(dev, "failed to allocate root scheduler buffers\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mshv_root_sched",
				mshv_root_scheduler_init,
				mshv_root_scheduler_cleanup);

	if (ret < 0) {
		dev_err(dev, "failed to setup root scheduler state: %i\n", ret);
		goto out;
	}

	mshv_root_sched_online = ret;

	return 0;

out:
	free_percpu(root_scheduler_input);
	free_percpu(root_scheduler_output);
	return ret;
}

static void
root_scheduler_deinit(void)
{
	if (hv_scheduler_type != HV_SCHEDULER_TYPE_ROOT)
		return;

	cpuhp_remove_state(mshv_root_sched_online);
	free_percpu(root_scheduler_input);
	free_percpu(root_scheduler_output);
}

int __init mshv_root_init(void)
{
	int ret;
	struct device *dev;
	union hv_hypervisor_version_info version_info;

	if (!hv_root_partition)
		return -ENODEV;

	if (hv_get_hypervisor_version(&version_info))
		return -ENODEV;

	ret = mshv_set_create_partition_func(__mshv_ioctl_create_partition, &dev);
	if (ret)
		return ret;

	if (version_info.build_number < MSHV_HV_MIN_VERSION ||
	    version_info.build_number > MSHV_HV_MAX_VERSION) {
		dev_warn(dev, "Hypervisor version %u not supported!\n",
			 version_info.build_number);
		dev_notice(dev, "Min version: %u, max version: %u\n",
			   MSHV_HV_MIN_VERSION, MSHV_HV_MAX_VERSION);
		if (ignore_hv_version) {
			dev_notice(dev,
				   "Continuing because param mshv_root.ignore_hv_version is set\n");
		} else {
			dev_err(dev,
				"Failing because version is not supported. Use param mshv_root.ignore_hv_version=1 to proceed anyway\n");
			ret = -ENODEV;
			goto unset_func;
		}
	}

	if (mshv_retrieve_scheduler_type(dev)) {
		ret = -ENODEV;
		goto unset_func;
	}

	ret = root_scheduler_init(dev);
	if (ret)
		goto unset_func;

	mshv_root.synic_pages = alloc_percpu(struct hv_synic_pages);
	if (!mshv_root.synic_pages) {
		dev_err(dev, "failed to allocate percpu synic page\n");
		ret = -ENOMEM;
		goto root_sched_deinit;
	}

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mshv_synic",
				mshv_synic_init,
				mshv_synic_cleanup);
	if (ret < 0) {
		dev_err(dev, "failed to setup cpu hotplug state: %i\n", ret);
		goto free_synic_pages;
	}
	mshv_cpuhp_online = ret;

	ret = mshv_irqfd_wq_init();
	if (ret < 0) {
		dev_err(dev, "failed to setup mshv irqfd workqueue: %i\n", ret);
		goto remove_cpu_state;
	}

	spin_lock_init(&mshv_root.partitions.lock);
	hash_init(mshv_root.partitions.items);

	return 0;

remove_cpu_state:
	cpuhp_remove_state(mshv_cpuhp_online);
free_synic_pages:
	free_percpu(mshv_root.synic_pages);
root_sched_deinit:
	root_scheduler_deinit();
unset_func:
	mshv_set_create_partition_func(NULL, NULL);
	return ret;
}

void __exit mshv_root_exit(void)
{
	mshv_set_create_partition_func(NULL, NULL);

	mshv_irqfd_wq_cleanup();

	root_scheduler_deinit();

	cpuhp_remove_state(mshv_cpuhp_online);
	free_percpu(mshv_root.synic_pages);

	mshv_port_table_fini();
}

module_init(mshv_root_init);
module_exit(mshv_root_exit);
