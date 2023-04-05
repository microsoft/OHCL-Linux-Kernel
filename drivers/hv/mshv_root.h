/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023, Microsoft Corporation.
 */

#ifndef _MSHV_ROOT_H_
#define _MSHV_ROOT_H_

#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/semaphore.h>
#include <linux/sched.h>
#include <linux/srcu.h>
#include <linux/wait.h>
#include <linux/hashtable.h>
#include <uapi/linux/mshv.h>

/*
 * Hypervisor must be between these version numbers (inclusive)
 * to guarantee compatibility
 */
#define MSHV_HV_MIN_VERSION		(25212)
#define MSHV_HV_MAX_VERSION		(25330)

#define MSHV_PARTITIONS_HASH_BITS	9
#define MSHV_MAX_VPS			256

#define PIN_PAGES_BATCH_SIZE	(0x10000000 / HV_HYP_PAGE_SIZE)

struct mshv_vp {
	u32 index;
	struct mshv_partition *partition;
	struct mutex mutex;
	struct page *register_page;
	struct hv_message *intercept_message_page;
	struct hv_register_assoc *registers;
	struct {
		atomic64_t signaled_count;
		struct {
			u64 explicit_suspend: 1;
			u64 blocked_by_explicit_suspend: 1; /* root scheduler only */
			u64 intercept_suspend: 1;
			u64 blocked: 1; /* root scheduler only */
			u64 reserved: 60;
		} flags;
		unsigned int kicked_by_hv;
		wait_queue_head_t suspend_queue;
	} run;
};

#define vp_fmt(fmt) "p%lluv%u: " fmt
#define vp_dev(v) ((v)->partition->module_dev)
#define vp_emerg(v, fmt, ...) \
	dev_emerg(vp_dev(v), vp_fmt(fmt), (v)->partition->id, (v)->index, ##__VA_ARGS__)
#define vp_crit(v, fmt, ...) \
	dev_crit(vp_dev(v), vp_fmt(fmt), (v)->partition->id, (v)->index, ##__VA_ARGS__)
#define vp_alert(v, fmt, ...) \
	dev_alert(vp_dev(v), vp_fmt(fmt), (v)->partition->id, (v)->index, ##__VA_ARGS__)
#define vp_err(v, fmt, ...) \
	dev_err(vp_dev(v), vp_fmt(fmt), (v)->partition->id, (v)->index, ##__VA_ARGS__)
#define vp_warn(v, fmt, ...) \
	dev_warn(vp_dev(v), vp_fmt(fmt), (v)->partition->id, (v)->index, ##__VA_ARGS__)
#define vp_notice(v, fmt, ...) \
	dev_notice(vp_dev(v), vp_fmt(fmt), (v)->partition->id, (v)->index, ##__VA_ARGS__)
#define vp_info(v, fmt, ...) \
	dev_info(vp_dev(v), vp_fmt(fmt), (v)->partition->id, (v)->index, ##__VA_ARGS__)
#define vp_dbg(v, fmt, ...) \
	dev_dbg(vp_dev(v), vp_fmt(fmt), (v)->partition->id, (v)->index, ##__VA_ARGS__)

struct mshv_mem_region {
	struct hlist_node hnode;
	u64 size; /* bytes */
	u64 guest_pfn;
	u64 userspace_addr; /* start of the userspace allocated memory */
	struct page *pages[];
};

struct mshv_irq_ack_notifier {
	struct hlist_node link;
	unsigned int gsi;
	void (*irq_acked)(struct mshv_irq_ack_notifier *mian);
};

struct mshv_partition {
	struct device *module_dev;
	struct hlist_node hnode;
	u64 id;
	refcount_t ref_count;
	struct mutex mutex;
	struct hlist_head mem_regions; // not ordered
	struct {
		u32 count;
		struct mshv_vp *array[MSHV_MAX_VPS];
	} vps;

	struct mutex irq_lock;
	struct srcu_struct irq_srcu;
	struct hlist_head irq_ack_notifier_list;

	struct completion async_hypercall;

	struct {
		spinlock_t        lock;
		struct hlist_head items;
		struct mutex resampler_lock;
		struct hlist_head resampler_list;
	} irqfds;
	struct {
		struct hlist_head items;
	} ioeventfds;
	struct mshv_msi_routing_table __rcu *msi_routing;
	u64 isolation_type;
};

#define partition_fmt(fmt) "p%llu: " fmt
#define partition_dev(p) ((p)->module_dev)
#define partition_emerg(p, fmt, ...) \
	dev_emerg(partition_dev(p), partition_fmt(fmt), (p)->id, ##__VA_ARGS__)
#define partition_crit(p, fmt, ...) \
	dev_crit(partition_dev(p), partition_fmt(fmt), (p)->id, ##__VA_ARGS__)
#define partition_alert(p, fmt, ...) \
	dev_alert(partition_dev(p), partition_fmt(fmt), (p)->id, ##__VA_ARGS__)
#define partition_err(p, fmt, ...) \
	dev_err(partition_dev(p), partition_fmt(fmt), (p)->id, ##__VA_ARGS__)
#define partition_warn(p, fmt, ...) \
	dev_warn(partition_dev(p), partition_fmt(fmt), (p)->id, ##__VA_ARGS__)
#define partition_notice(p, fmt, ...) \
	dev_notice(partition_dev(p), partition_fmt(fmt), (p)->id, ##__VA_ARGS__)
#define partition_info(p, fmt, ...) \
	dev_info(partition_dev(p), partition_fmt(fmt), (p)->id, ##__VA_ARGS__)
#define partition_dbg(p, fmt, ...) \
	dev_dbg(partition_dev(p), partition_fmt(fmt), (p)->id, ##__VA_ARGS__)

struct mshv_lapic_irq {
	u32 vector;
	u64 apic_id;
	union hv_interrupt_control control;
};

#define MSHV_MAX_MSI_ROUTES		4096

struct mshv_kernel_msi_routing_entry {
	u32 entry_valid;
	u32 gsi;
	u32 address_lo;
	u32 address_hi;
	u32 data;
};

struct mshv_msi_routing_table {
	u32 nr_rt_entries;
	struct mshv_kernel_msi_routing_entry entries[];
};

struct hv_synic_pages {
	struct hv_message_page *synic_message_page;
	struct hv_synic_event_flags_page *synic_event_flags_page;
	struct hv_synic_event_ring_page *synic_event_ring_page;
};

struct mshv_root {
	struct hv_synic_pages __percpu *synic_pages;
	struct {
		spinlock_t lock;
		u64 count;
		DECLARE_HASHTABLE(items, MSHV_PARTITIONS_HASH_BITS);
	} partitions;
};

/*
 * Callback for doorbell events.
 * NOTE: This is called in interrupt context. Callback
 * should defer slow and sleeping logic to later.
 */
typedef void (*doorbell_cb_t) (int doorbell_id, void *);

/*
 * port table information
 */
struct port_table_info {
	struct rcu_head rcu;
	enum hv_port_type port_type;
	union {
		struct {
			u64 reserved[2];
		} port_message;
		struct {
			u64 reserved[2];
		} port_event;
		struct {
			u64 reserved[2];
		} port_monitor;
		struct {
			doorbell_cb_t doorbell_cb;
			void *data;
		} port_doorbell;
	};
};

int mshv_set_msi_routing(struct mshv_partition *partition,
			 const struct mshv_msi_routing_entry *entries,
			 unsigned int nr);
void mshv_free_msi_routing(struct mshv_partition *partition);

struct mshv_kernel_msi_routing_entry mshv_msi_map_gsi(struct mshv_partition *partition, u32 gsi);

void mshv_set_msi_irq(struct mshv_kernel_msi_routing_entry *e,
		      struct mshv_lapic_irq *irq);

void mshv_irqfd_routing_update(struct mshv_partition *partition);

void mshv_port_table_fini(void);
int mshv_portid_alloc(struct port_table_info *info);
int mshv_portid_lookup(int port_id, struct port_table_info *info);
void mshv_portid_free(int port_id);

int mshv_register_doorbell(struct mshv_partition *partition, doorbell_cb_t doorbell_cb,
			   u64 gpa, u64 val, u64 flags);
int mshv_unregister_doorbell(struct mshv_partition *partition, int doorbell_portid);

void mshv_isr(void);
int mshv_synic_init(unsigned int cpu);
int mshv_synic_cleanup(unsigned int cpu);

static inline bool mshv_partition_isolation_type_snp(struct mshv_partition *partition)
{
	return partition->isolation_type == HV_PARTITION_ISOLATION_TYPE_SNP;
}

extern struct mshv_root mshv_root;

#endif /* _MSHV_ROOT_H_ */
