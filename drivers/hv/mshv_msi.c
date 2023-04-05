// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * Authors:
 *   Vineeth Remanan Pillai <viremana@linux.microsoft.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/mshyperv.h>

#include "mshv_eventfd.h"
#include "mshv.h"
#include "mshv_root.h"

MODULE_AUTHOR("Microsoft");
MODULE_LICENSE("GPL");

int mshv_set_msi_routing(struct mshv_partition *partition,
			 const struct mshv_msi_routing_entry *ue,
			 unsigned int nr)
{
	struct mshv_msi_routing_table *new = NULL, *old;
	u32 i, nr_rt_entries = 0;
	int r = 0;

	if (nr == 0)
		goto swap_routes;

	for (i = 0; i < nr; i++) {
		if (ue[i].gsi >= MSHV_MAX_MSI_ROUTES)
			return -EINVAL;

		if (ue[i].address_hi)
			return -EINVAL;

		nr_rt_entries = max(nr_rt_entries, ue[i].gsi);
	}
	nr_rt_entries += 1;

	new = kzalloc(struct_size(new, entries, nr_rt_entries),
		      GFP_KERNEL_ACCOUNT);
	if (!new)
		return -ENOMEM;

	new->nr_rt_entries = nr_rt_entries;
	for (i = 0; i < nr; i++) {
		struct mshv_kernel_msi_routing_entry *e;

		e = &new->entries[ue[i].gsi];

		/*
		 * Allow only one to one mapping between GSI and MSI routing.
		 */
		if (e->gsi != 0) {
			r = -EINVAL;
			goto out;
		}

		e->gsi = ue[i].gsi;
		e->address_lo = ue[i].address_lo;
		e->address_hi = ue[i].address_hi;
		e->data = ue[i].data;
		e->entry_valid = true;
	}

swap_routes:
	mutex_lock(&partition->irq_lock);
	old = rcu_dereference_protected(partition->msi_routing, 1);
	rcu_assign_pointer(partition->msi_routing, new);
	mshv_irqfd_routing_update(partition);
	mutex_unlock(&partition->irq_lock);

	synchronize_srcu_expedited(&partition->irq_srcu);
	new = old;

out:
	kfree(new);

	return r;
}

void mshv_free_msi_routing(struct mshv_partition *partition)
{
	/*
	 * Called only during vm destruction.
	 * Nobody can use the pointer at this stage
	 */
	struct mshv_msi_routing_table *rt = rcu_access_pointer(partition->msi_routing);

	kfree(rt);
}

struct mshv_kernel_msi_routing_entry
mshv_msi_map_gsi(struct mshv_partition *partition, u32 gsi)
{
	struct mshv_kernel_msi_routing_entry entry = { 0 };
	struct mshv_msi_routing_table *msi_rt;

	msi_rt = srcu_dereference_check(partition->msi_routing,
					&partition->irq_srcu,
					lockdep_is_held(&partition->irq_lock));
	if (!msi_rt) {
		/*
		 * Premature register_irqfd, setting valid_entry = 0
		 * would ignore this entry anyway
		 */
		entry.gsi = gsi;
		return entry;
	}

	return msi_rt->entries[gsi];
}

void mshv_set_msi_irq(struct mshv_kernel_msi_routing_entry *e,
		      struct mshv_lapic_irq *irq)
{
	memset(irq, 0, sizeof(*irq));
	if (!e || !e->entry_valid)
		return;

	irq->vector = e->data & 0xFF;
	irq->apic_id = (e->address_lo >> 12) & 0xFF;
	irq->control.interrupt_type = (e->data & 0x700) >> 8;
	irq->control.level_triggered = (e->data >> 15) & 0x1;
	irq->control.logical_dest_mode = (e->address_lo >> 2) & 0x1;
}
