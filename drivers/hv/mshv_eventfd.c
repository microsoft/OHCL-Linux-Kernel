// SPDX-License-Identifier: GPL-2.0-only
/*
 * eventfd support for mshv
 *
 * Heavily inspired from KVM implementation of irqfd/ioeventfd. The basic
 * framework code is taken from the kvm implementation.
 *
 * All credits to kvm developers.
 */

#include <linux/syscalls.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/workqueue.h>
#include <linux/eventfd.h>

#include "mshv_eventfd.h"
#include "mshv.h"
#include "mshv_root.h"

static struct workqueue_struct *irqfd_cleanup_wq;

void
mshv_register_irq_ack_notifier(struct mshv_partition *partition,
			       struct mshv_irq_ack_notifier *mian)
{
	mutex_lock(&partition->irq_lock);
	hlist_add_head_rcu(&mian->link, &partition->irq_ack_notifier_list);
	mutex_unlock(&partition->irq_lock);
}

void
mshv_unregister_irq_ack_notifier(struct mshv_partition *partition,
				 struct mshv_irq_ack_notifier *mian)
{
	mutex_lock(&partition->irq_lock);
	hlist_del_init_rcu(&mian->link);
	mutex_unlock(&partition->irq_lock);
	synchronize_rcu();
}

bool
mshv_notify_acked_gsi(struct mshv_partition *partition, int gsi)
{
	struct mshv_irq_ack_notifier *mian;
	bool acked = false;

	rcu_read_lock();
	hlist_for_each_entry_rcu(mian, &partition->irq_ack_notifier_list,
				 link) {
		if (mian->gsi == gsi) {
			mian->irq_acked(mian);
			acked = true;
		}
	}
	rcu_read_unlock();

	return acked;
}

static inline bool hv_should_clear_interrupt(enum hv_interrupt_type type)
{
	return type == HV_X64_INTERRUPT_TYPE_EXTINT;
}

static void
irqfd_resampler_ack(struct mshv_irq_ack_notifier *mian)
{
	struct mshv_kernel_irqfd_resampler *resampler;
	struct mshv_partition *partition;
	struct mshv_kernel_irqfd *irqfd;
	int idx;

	resampler = container_of(mian, struct mshv_kernel_irqfd_resampler,
				 notifier);
	partition = resampler->partition;

	idx = srcu_read_lock(&partition->irq_srcu);

	hlist_for_each_entry_rcu(irqfd, &resampler->irqfds_list, resampler_hnode) {
		if (hv_should_clear_interrupt(irqfd->lapic_irq.control.interrupt_type))
			hv_call_clear_virtual_interrupt(partition->id);

		eventfd_signal(irqfd->resamplefd, 1);
	}

	srcu_read_unlock(&partition->irq_srcu, idx);
}

static void
irqfd_assert(struct work_struct *work)
{
	struct mshv_kernel_irqfd *irqfd = container_of(work,
						       struct mshv_kernel_irqfd,
						       assert);
	struct mshv_lapic_irq *irq = &irqfd->lapic_irq;

	hv_call_assert_virtual_interrupt(irqfd->partition->id,
					 irq->vector, irq->apic_id,
					 irq->control);
}

static void
irqfd_inject(struct mshv_kernel_irqfd *irqfd)
{
	struct mshv_partition *partition = irqfd->partition;
	struct mshv_lapic_irq *irq = &irqfd->lapic_irq;
	unsigned int seq;
	int idx;

	WARN_ON(irqfd->resampler &&
		!irq->control.level_triggered);

	idx = srcu_read_lock(&partition->irq_srcu);
	if (irqfd->msi_entry.gsi) {
		if (!irqfd->msi_entry.entry_valid) {
			partition_warn(partition,
				       "Invalid routing info for gsi %u\n",
				       irqfd->msi_entry.gsi);
			srcu_read_unlock(&partition->irq_srcu, idx);
			return;
		}

		do {
			seq = read_seqcount_begin(&irqfd->msi_entry_sc);
		} while (read_seqcount_retry(&irqfd->msi_entry_sc, seq));
	}

	srcu_read_unlock(&partition->irq_srcu, idx);

	schedule_work(&irqfd->assert);
}

static void
irqfd_resampler_shutdown(struct mshv_kernel_irqfd *irqfd)
{
	struct mshv_kernel_irqfd_resampler *resampler = irqfd->resampler;
	struct mshv_partition *partition = resampler->partition;

	mutex_lock(&partition->irqfds.resampler_lock);

	hlist_del_rcu(&irqfd->resampler_hnode);
	synchronize_srcu(&partition->irq_srcu);

	if (hlist_empty(&resampler->irqfds_list)) {
		hlist_del(&resampler->hnode);
		mshv_unregister_irq_ack_notifier(partition, &resampler->notifier);
		kfree(resampler);
	}

	mutex_unlock(&partition->irqfds.resampler_lock);
}

/*
 * Race-free decouple logic (ordering is critical)
 */
static void
irqfd_shutdown(struct work_struct *work)
{
	struct mshv_kernel_irqfd *irqfd = container_of(work,
						       struct mshv_kernel_irqfd,
						       shutdown);

	/*
	 * Synchronize with the wait-queue and unhook ourselves to prevent
	 * further events.
	 */
	remove_wait_queue(irqfd->wqh, &irqfd->wait);

	if (irqfd->resampler) {
		irqfd_resampler_shutdown(irqfd);
		eventfd_ctx_put(irqfd->resamplefd);
	}

	/*
	 * We know no new events will be scheduled at this point, so block
	 * until all previously outstanding events have completed
	 */
	flush_work(&irqfd->assert);

	/*
	 * It is now safe to release the object's resources
	 */
	eventfd_ctx_put(irqfd->eventfd);
	kfree(irqfd);
}

/* assumes partition->irqfds.lock is held */
static bool
irqfd_is_active(struct mshv_kernel_irqfd *irqfd)
{
	return !hlist_unhashed(&irqfd->hnode);
}

/*
 * Mark the irqfd as inactive and schedule it for removal
 *
 * assumes partition->irqfds.lock is held
 */
static void
irqfd_deactivate(struct mshv_kernel_irqfd *irqfd)
{
	WARN_ON(!irqfd_is_active(irqfd));

	hlist_del(&irqfd->hnode);

	queue_work(irqfd_cleanup_wq, &irqfd->shutdown);
}

/*
 * Called with wqh->lock held and interrupts disabled
 */
static int
irqfd_wakeup(wait_queue_entry_t *wait, unsigned int mode,
	     int sync, void *key)
{
	struct mshv_kernel_irqfd *irqfd = container_of(wait,
						       struct mshv_kernel_irqfd,
						       wait);
	unsigned long flags = (unsigned long)key;
	int idx;
	unsigned int seq;
	struct mshv_partition *partition = irqfd->partition;
	int ret = 0;

	if (flags & POLLIN) {
		u64 cnt;

		eventfd_ctx_do_read(irqfd->eventfd, &cnt);
		idx = srcu_read_lock(&partition->irq_srcu);
		do {
			seq = read_seqcount_begin(&irqfd->msi_entry_sc);
		} while (read_seqcount_retry(&irqfd->msi_entry_sc, seq));

		/* An event has been signaled, inject an interrupt */
		irqfd_inject(irqfd);
		srcu_read_unlock(&partition->irq_srcu, idx);

		ret = 1;
	}

	if (flags & POLLHUP) {
		/* The eventfd is closing, detach from Partition */
		unsigned long flags;

		spin_lock_irqsave(&partition->irqfds.lock, flags);

		/*
		 * We must check if someone deactivated the irqfd before
		 * we could acquire the irqfds.lock since the item is
		 * deactivated from the mshv side before it is unhooked from
		 * the wait-queue.  If it is already deactivated, we can
		 * simply return knowing the other side will cleanup for us.
		 * We cannot race against the irqfd going away since the
		 * other side is required to acquire wqh->lock, which we hold
		 */
		if (irqfd_is_active(irqfd))
			irqfd_deactivate(irqfd);

		spin_unlock_irqrestore(&partition->irqfds.lock, flags);
	}

	return ret;
}

/* Must be called under irqfds.lock */
static void irqfd_update(struct mshv_partition *partition,
			 struct mshv_kernel_irqfd *irqfd)
{
	write_seqcount_begin(&irqfd->msi_entry_sc);
	irqfd->msi_entry = mshv_msi_map_gsi(partition, irqfd->gsi);
	mshv_set_msi_irq(&irqfd->msi_entry, &irqfd->lapic_irq);
	write_seqcount_end(&irqfd->msi_entry_sc);
}

void mshv_irqfd_routing_update(struct mshv_partition *partition)
{
	struct mshv_kernel_irqfd *irqfd;

	spin_lock_irq(&partition->irqfds.lock);
	hlist_for_each_entry(irqfd, &partition->irqfds.items, hnode)
		irqfd_update(partition, irqfd);
	spin_unlock_irq(&partition->irqfds.lock);
}

static void
irqfd_ptable_queue_proc(struct file *file, wait_queue_head_t *wqh,
			poll_table *pt)
{
	struct mshv_kernel_irqfd *irqfd = container_of(pt,
						       struct mshv_kernel_irqfd,
						       pt);

	irqfd->wqh = wqh;
	add_wait_queue_priority(wqh, &irqfd->wait);
}

static int
mshv_irqfd_assign(struct mshv_partition *partition,
		  struct mshv_irqfd *args)
{
	struct eventfd_ctx *eventfd = NULL, *resamplefd = NULL;
	struct mshv_kernel_irqfd *irqfd, *tmp;
	unsigned int events;
	struct fd f;
	int ret;
	int idx;

	irqfd = kzalloc(sizeof(*irqfd), GFP_KERNEL);
	if (!irqfd)
		return -ENOMEM;

	irqfd->partition = partition;
	irqfd->gsi = args->gsi;
	INIT_WORK(&irqfd->shutdown, irqfd_shutdown);
	INIT_WORK(&irqfd->assert, irqfd_assert);
	seqcount_spinlock_init(&irqfd->msi_entry_sc,
			       &partition->irqfds.lock);

	f = fdget(args->fd);
	if (!f.file) {
		ret = -EBADF;
		goto out;
	}

	eventfd = eventfd_ctx_fileget(f.file);
	if (IS_ERR(eventfd)) {
		ret = PTR_ERR(eventfd);
		goto fail;
	}

	irqfd->eventfd = eventfd;

	if (args->flags & MSHV_IRQFD_FLAG_RESAMPLE) {
		struct mshv_kernel_irqfd_resampler *resampler;

		resamplefd = eventfd_ctx_fdget(args->resamplefd);
		if (IS_ERR(resamplefd)) {
			ret = PTR_ERR(resamplefd);
			goto fail;
		}

		irqfd->resamplefd = resamplefd;

		mutex_lock(&partition->irqfds.resampler_lock);

		hlist_for_each_entry(resampler,
				     &partition->irqfds.resampler_list, hnode) {
			if (resampler->notifier.gsi == irqfd->gsi) {
				irqfd->resampler = resampler;
				break;
			}
		}

		if (!irqfd->resampler) {
			resampler = kzalloc(sizeof(*resampler),
					    GFP_KERNEL_ACCOUNT);
			if (!resampler) {
				ret = -ENOMEM;
				mutex_unlock(&partition->irqfds.resampler_lock);
				goto fail;
			}

			resampler->partition = partition;
			INIT_HLIST_HEAD(&resampler->irqfds_list);
			resampler->notifier.gsi = irqfd->gsi;
			resampler->notifier.irq_acked = irqfd_resampler_ack;

			hlist_add_head(&resampler->hnode, &partition->irqfds.resampler_list);
			mshv_register_irq_ack_notifier(partition,
						       &resampler->notifier);
			irqfd->resampler = resampler;
		}

		hlist_add_head_rcu(&irqfd->resampler_hnode, &irqfd->resampler->irqfds_list);

		mutex_unlock(&partition->irqfds.resampler_lock);
	}

	/*
	 * Install our own custom wake-up handling so we are notified via
	 * a callback whenever someone signals the underlying eventfd
	 */
	init_waitqueue_func_entry(&irqfd->wait, irqfd_wakeup);
	init_poll_funcptr(&irqfd->pt, irqfd_ptable_queue_proc);

	spin_lock_irq(&partition->irqfds.lock);
	if (args->flags & MSHV_IRQFD_FLAG_RESAMPLE &&
	    !irqfd->lapic_irq.control.level_triggered) {
		/*
		 * Resample Fd must be for level triggered interrupt
		 * Otherwise return with failure
		 */
		spin_unlock_irq(&partition->irqfds.lock);
		ret = -EINVAL;
		goto fail;
	}
	ret = 0;
	hlist_for_each_entry(tmp, &partition->irqfds.items, hnode) {
		if (irqfd->eventfd != tmp->eventfd)
			continue;
		/* This fd is used for another irq already. */
		ret = -EBUSY;
		spin_unlock_irq(&partition->irqfds.lock);
		goto fail;
	}

	idx = srcu_read_lock(&partition->irq_srcu);
	irqfd_update(partition, irqfd);
	hlist_add_head(&irqfd->hnode, &partition->irqfds.items);
	spin_unlock_irq(&partition->irqfds.lock);

	/*
	 * Check if there was an event already pending on the eventfd
	 * before we registered, and trigger it as if we didn't miss it.
	 */
	events = vfs_poll(f.file, &irqfd->pt);

	if (events & POLLIN)
		irqfd_inject(irqfd);

	srcu_read_unlock(&partition->irq_srcu, idx);
	/*
	 * do not drop the file until the irqfd is fully initialized, otherwise
	 * we might race against the POLLHUP
	 */
	fdput(f);

	return 0;

fail:
	if (irqfd->resampler)
		irqfd_resampler_shutdown(irqfd);

	if (resamplefd && !IS_ERR(resamplefd))
		eventfd_ctx_put(resamplefd);

	if (eventfd && !IS_ERR(eventfd))
		eventfd_ctx_put(eventfd);

	fdput(f);

out:
	kfree(irqfd);
	return ret;
}

/*
 * shutdown any irqfd's that match fd+gsi
 */
static int
mshv_irqfd_deassign(struct mshv_partition *partition,
		    struct mshv_irqfd *args)
{
	struct mshv_kernel_irqfd *irqfd;
	struct hlist_node *n;
	struct eventfd_ctx *eventfd;

	eventfd = eventfd_ctx_fdget(args->fd);
	if (IS_ERR(eventfd))
		return PTR_ERR(eventfd);

	hlist_for_each_entry_safe(irqfd, n, &partition->irqfds.items, hnode) {
		if (irqfd->eventfd == eventfd && irqfd->gsi == args->gsi)
			irqfd_deactivate(irqfd);
	}

	eventfd_ctx_put(eventfd);

	/*
	 * Block until we know all outstanding shutdown jobs have completed
	 * so that we guarantee there will not be any more interrupts on this
	 * gsi once this deassign function returns.
	 */
	flush_workqueue(irqfd_cleanup_wq);

	return 0;
}

int
mshv_irqfd(struct mshv_partition *partition, struct mshv_irqfd *args)
{
	if (args->flags & MSHV_IRQFD_FLAG_DEASSIGN)
		return mshv_irqfd_deassign(partition, args);

	return mshv_irqfd_assign(partition, args);
}

/*
 * This function is called as the mshv VM fd is being released.
 * Shutdown all irqfds that still remain open
 */
static void
mshv_irqfd_release(struct mshv_partition *partition)
{
	struct mshv_kernel_irqfd *irqfd;
	struct hlist_node *n;

	spin_lock_irq(&partition->irqfds.lock);

	hlist_for_each_entry_safe(irqfd, n, &partition->irqfds.items, hnode)
		irqfd_deactivate(irqfd);

	spin_unlock_irq(&partition->irqfds.lock);

	/*
	 * Block until we know all outstanding shutdown jobs have completed
	 * since we do not take a mshv_partition* reference.
	 */
	flush_workqueue(irqfd_cleanup_wq);
}

int mshv_irqfd_wq_init(void)
{
	irqfd_cleanup_wq = alloc_workqueue("mshv-irqfd-cleanup", 0, 0);
	if (!irqfd_cleanup_wq)
		return -ENOMEM;

	return 0;
}

void mshv_irqfd_wq_cleanup(void)
{
	destroy_workqueue(irqfd_cleanup_wq);
}

/*
 * --------------------------------------------------------------------
 * ioeventfd: translate a MMIO memory write to an eventfd signal.
 *
 * userspace can register a MMIO address with an eventfd for receiving
 * notification when the memory has been touched.
 *
 * TODO: Implement eventfd for PIO as well.
 * --------------------------------------------------------------------
 */

static void
ioeventfd_release(struct kernel_mshv_ioeventfd *p, struct mshv_partition *partition)
{
	if (p->doorbell_id > 0)
		mshv_unregister_doorbell(partition, p->doorbell_id);
	eventfd_ctx_put(p->eventfd);
	kfree(p);
}

/* MMIO writes trigger an event if the addr/val match */
static void
ioeventfd_mmio_write(int doorbell_id, void *data)
{
	struct mshv_partition *partition = (struct mshv_partition *)data;
	struct kernel_mshv_ioeventfd *p;

	rcu_read_lock();
	hlist_for_each_entry_rcu(p, &partition->ioeventfds.items, hnode) {
		if (p->doorbell_id == doorbell_id) {
			eventfd_signal(p->eventfd, 1);
			break;
		}
	}
	rcu_read_unlock();
}

static bool
ioeventfd_check_collision(struct mshv_partition *partition,
			  struct kernel_mshv_ioeventfd *p)
	__must_hold(&partition->mutex)
{
	struct kernel_mshv_ioeventfd *_p;

	hlist_for_each_entry(_p, &partition->ioeventfds.items, hnode)
		if (_p->addr == p->addr && _p->length == p->length &&
		    (_p->wildcard || p->wildcard ||
		     _p->datamatch == p->datamatch))
			return true;

	return false;
}

static int
mshv_assign_ioeventfd(struct mshv_partition *partition,
		      struct mshv_ioeventfd *args)
	__must_hold(&partition->mutex)
{
	struct kernel_mshv_ioeventfd *p;
	struct eventfd_ctx *eventfd;
	u64 doorbell_flags = 0;
	int ret;

	/* This mutex is currently protecting ioeventfd.items list */
	WARN_ON_ONCE(!mutex_is_locked(&partition->mutex));

	if (args->flags & MSHV_IOEVENTFD_FLAG_PIO)
		return -EOPNOTSUPP;

	/* must be natural-word sized */
	switch (args->len) {
	case 0:
		doorbell_flags = HV_DOORBELL_FLAG_TRIGGER_SIZE_ANY;
		break;
	case 1:
		doorbell_flags = HV_DOORBELL_FLAG_TRIGGER_SIZE_BYTE;
		break;
	case 2:
		doorbell_flags = HV_DOORBELL_FLAG_TRIGGER_SIZE_WORD;
		break;
	case 4:
		doorbell_flags = HV_DOORBELL_FLAG_TRIGGER_SIZE_DWORD;
		break;
	case 8:
		doorbell_flags = HV_DOORBELL_FLAG_TRIGGER_SIZE_QWORD;
		break;
	default:
		partition_err(partition, "ioeventfd: invalid length specified\n");
		return -EINVAL;
	}

	/* check for range overflow */
	if (args->addr + args->len < args->addr)
		return -EINVAL;

	/* check for extra flags that we don't understand */
	if (args->flags & ~MSHV_IOEVENTFD_VALID_FLAG_MASK)
		return -EINVAL;

	eventfd = eventfd_ctx_fdget(args->fd);
	if (IS_ERR(eventfd))
		return PTR_ERR(eventfd);

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p) {
		ret = -ENOMEM;
		goto fail;
	}

	p->addr    = args->addr;
	p->length  = args->len;
	p->eventfd = eventfd;

	/* The datamatch feature is optional, otherwise this is a wildcard */
	if (args->flags & MSHV_IOEVENTFD_FLAG_DATAMATCH) {
		p->datamatch = args->datamatch;
	} else {
		p->wildcard = true;
		doorbell_flags |= HV_DOORBELL_FLAG_TRIGGER_ANY_VALUE;
	}

	if (ioeventfd_check_collision(partition, p)) {
		ret = -EEXIST;
		goto unlock_fail;
	}

	ret = mshv_register_doorbell(partition, ioeventfd_mmio_write, p->addr,
				     p->datamatch, doorbell_flags);
	if (ret < 0) {
		partition_err(partition, "Failed to register ioeventfd doorbell!\n");
		goto unlock_fail;
	}

	p->doorbell_id = ret;

	hlist_add_head_rcu(&p->hnode, &partition->ioeventfds.items);

	return 0;

unlock_fail:
	kfree(p);

fail:
	eventfd_ctx_put(eventfd);

	return ret;
}

static int
mshv_deassign_ioeventfd(struct mshv_partition *partition,
			struct mshv_ioeventfd *args)
	__must_hold(&partition->mutex)
{
	struct kernel_mshv_ioeventfd *p;
	struct eventfd_ctx *eventfd;
	struct hlist_node *n;
	int ret = -ENOENT;

	/* This mutex is currently protecting ioeventfd.items list */
	WARN_ON_ONCE(!mutex_is_locked(&partition->mutex));

	eventfd = eventfd_ctx_fdget(args->fd);
	if (IS_ERR(eventfd))
		return PTR_ERR(eventfd);

	hlist_for_each_entry_safe(p, n, &partition->ioeventfds.items, hnode) {
		bool wildcard = !(args->flags & MSHV_IOEVENTFD_FLAG_DATAMATCH);

		if (p->eventfd != eventfd  ||
		    p->addr != args->addr  ||
		    p->length != args->len ||
		    p->wildcard != wildcard)
			continue;

		if (!p->wildcard && p->datamatch != args->datamatch)
			continue;

		hlist_del_rcu(&p->hnode);
		synchronize_rcu();
		ioeventfd_release(p, partition);
		ret = 0;
		break;
	}

	eventfd_ctx_put(eventfd);

	return ret;
}

int
mshv_ioeventfd(struct mshv_partition *partition,
	       struct mshv_ioeventfd *args)
	__must_hold(&partition->mutex)
{
	/* PIO not yet implemented */
	if (args->flags & MSHV_IOEVENTFD_FLAG_PIO)
		return -EOPNOTSUPP;

	if (args->flags & MSHV_IOEVENTFD_FLAG_DEASSIGN)
		return mshv_deassign_ioeventfd(partition, args);

	return mshv_assign_ioeventfd(partition, args);
}

void
mshv_eventfd_init(struct mshv_partition *partition)
{
	spin_lock_init(&partition->irqfds.lock);
	INIT_HLIST_HEAD(&partition->irqfds.items);

	INIT_HLIST_HEAD(&partition->irqfds.resampler_list);
	mutex_init(&partition->irqfds.resampler_lock);

	INIT_HLIST_HEAD(&partition->ioeventfds.items);
}

void
mshv_eventfd_release(struct mshv_partition *partition)
{
	struct hlist_head items;
	struct hlist_node *n;
	struct kernel_mshv_ioeventfd *p;

	hlist_move_list(&partition->ioeventfds.items, &items);
	synchronize_rcu();

	hlist_for_each_entry_safe(p, n, &items, hnode) {
		hlist_del(&p->hnode);
		ioeventfd_release(p, partition);
	}

	mshv_irqfd_release(partition);
}
