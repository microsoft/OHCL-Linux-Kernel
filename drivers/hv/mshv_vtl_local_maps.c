// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024, Microsoft Corporation.
 *
 * Author:
 *   Roman Kisel <romank@linux.microsoft.com>
 */

/*
 * Problem
 * =======
 * Give each processor a VA range it can briefly use for mapping a PFN range
 * that might or might not be RAM providing a uniform easy access whether
 * the PFN range needs to be mapped to a large or a normal page. The existing
 * kernel API (`kmap_local_page` and `vmap_pfn`) make that easy for the 4KiB
 * pages only, and for the large pages in the page fault handling or mmap
 * handling.
 *
 * Proposed solution
 * =================
 * Choose an unused VA range from the upper half, and dispense VA space
 * to each processor as a function of its ID. This approach eliminates contention,
 * allows running processing on several CPUs, and does not require remote TLB
 * flushes.
 * [The documentation](https://www.kernel.org/doc/html/v6.6/arch/x86/x86_64/mm.html)
 * mentions that this VA range ffff800000000000..ffff87ffffffffff of 8TiB size
 * might be used by the hypervisor. As VTL2 plays the role of the hypervisor
 * for the lower VTLs, it appears rather justified to choose that VA region.
 *
 * Here and below, the 4-level paging is assumed. The generalization to
 * the 5-level one is straightforward. Maximum number of processors supported is
 * 2048.
 *
 * Let `start` = `ffff800000000000` (PML4 index 256).
 *
 * 2MiB maps
 * =========
 * To give each processor an ability to map its local 2MiB VA range, one needs
 * 2048/0x200 = 4 PMD tables. All they way up to PML4, that requires 1 table for
 * each level. The VA for the local 2MiB maps takes 4GiB for all processors, and
 * for the processor `N` the 2MiB VA range begins at `start` + `N`*2MiB.
 *
 * 4KiB maps
 * =========
 * To give each processor an ability to map its local 4KiB VA range, one needs
 * 2048/0x200 = 4 PTE tables. All the way up to PML4, that requires 1 table for
 * each paging level. In total, the required VA space is 8MiB of size, and the
 * 4KiB local VA range for the processor `N` begins at `start` + 4GiB + `N`*4KiB.
 *
 * Safety
 * ======
 * This kibd of code might be very dangerous to run, and there are many checks
 * put in place to make sure some random memory won't be mapped and potentially
 * scribbled over.
 *
 * Usage
 * =====
 * The process that wishes to pass PFNs to the kernel for processing with `pvalidate`
 * and similar (where mapping to some/any VA is needed for the operation), should open
 * and keep opened `/dev/mshv_local_maps` while these operations are in progress.
 * Opening is idempotent hence opening several times doesn't change anything for the
 * process. The processing happens per-CPU with preemption disabled (the watchdogs
 * receive pets to avoid soft lockup warnings).
 *
 * Other approaches
 * ================
 * Instead of giving each CPUs its own VMA range that it can brifely map and unmap,
 * one could consider creating a static linear VM map of all addresses that can be mapped.
 * That leads to a significant memory consumption by the paging tables. E.g., for
 * a 512GiB VM, there will be (512<<40)/(1<<21) 2MiB pages and given that the page table
 * entry occupied 8 bytes that comes down to 2 GiB ((512<<40)/(1<<21)*8/1024/1024/1024)
 * required by the page tables only. In the context of "pvalidate" and "padjust", one
 * cannot use the 1GiB pages unfortunately.
 * In stark contrast to this, the implemented approach requires 14-15 page tables (4KiB each)
 * for any memory size. The static approach could save on the time required to write a page
 * table entry (8 bytes) and the local TLB flush. The tests show that there are no
 * noticable slowdown due to that though.
 */


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pgtable.h>
#include <linux/miscdevice.h>
#include <linux/sched.h>
#include <linux/nmi.h>
#include <linux/clocksource.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/pgtable_types.h>
#include <asm/mshyperv.h>
#include <asm/pgtable_64_types.h>

#include "mshv_vtl_local_maps.h"

MODULE_AUTHOR("Microsoft");
MODULE_LICENSE("GPL");

struct mshv_local_maps {
	struct list_head node;
	void *table;
	enum mshv_page_type page_type;
};

static DEFINE_MUTEX(mshv_local_maps_mutex);

#define MAX_HYPERV_CPUS 			(u64)(HV_MAXIMUM_PROCESSORS)
#define LARGE_PAGE_SIZE 			(u64)(PMD_SIZE)
#define NORMAL_PAGE_SIZE 			(u64)(PAGE_SIZE)
#define ENTRIES_PER_PGTABLE			(u64)(0x200)

#define LOCAL_LARGE_VA_START 		(pgtable_l5_enabled() ?	\
					 0xff00000000000000ULL : 0xffff800000000000ULL)

#define LOCAL_LARGE_VA_END 			(u64)(LOCAL_LARGE_VA_START + MAX_HYPERV_CPUS*LARGE_PAGE_SIZE)
#define LOCAL_NORMAL_VA_START 		(u64)(LOCAL_LARGE_VA_END)
#define LOCAL_NORMAL_VA_END 		(u64)(LOCAL_NORMAL_VA_START + MAX_HYPERV_CPUS*NORMAL_PAGE_SIZE)
#define LOCAL_VA_START 				(u64)(LOCAL_LARGE_VA_START)
#define LOCAL_VA_END 				(u64)(LOCAL_NORMAL_VA_END)

static struct mshv_local_maps *mshv_vtl_local_map_list_add_entry(
	void* table, enum mshv_page_type page_type, struct mshv_local_maps *maps)
{
	struct mshv_local_maps *maps_entry;

	maps_entry = kzalloc(sizeof(*maps_entry), GFP_KERNEL);
	if (maps_entry) {
		maps_entry->table = table;
		maps_entry->page_type = page_type;
		list_add(&maps_entry->node, &maps->node);
	}
	return maps_entry;
}

static void mshv_vtl_teardown_local_maps_no_lock(struct mshv_local_maps *maps);

struct mshv_local_maps *mshv_vtl_setup_local_maps(void)
{
	struct mshv_local_maps *maps;
	u64 page_tables_allocated = 0;
	u64 vaddr = LOCAL_VA_START;

	maps = kzalloc(sizeof(*maps), GFP_KERNEL);
	if (!maps)
		return NULL;
	INIT_LIST_HEAD(&maps->node);

	mutex_lock(&mshv_local_maps_mutex);

	/* Don't leak that to the log. Uncomment if stuck. */
	/* pr_debug("%s: PGD %#llx\n", __func__, (u64)(current->active_mm->pgd)); */

	/*
	 * 8 iterations for 2048 processors, allocating 14 4KiB pages
	 * (for the 4-level page tables, one more for the 5-level case). That doesn't
	 * look as a noticable cost of speeding up when using large pages, don't bother
	 * setting the number of CPUs dynamically.
	 */
	while (vaddr < LOCAL_VA_END) {
		pgd_t *pgdp = pgd_offset(current->active_mm, vaddr);
		p4d_t *p4dp;
		pud_t *pudp;
		pmd_t *pmdp;
		pte_t *ptep;

		/*
		 * The indexes in the topmost tables aren't changing for the VA ranges
		 * we're interested in. Keeping code for them inside the loop for consistency.
		 */
		if (pgd_none(*pgdp)) {
			p4dp = (p4d_t *)get_zeroed_page(GFP_KERNEL);
			if (!p4dp)
				goto error;
			page_tables_allocated++;

			pgd_populate(current->active_mm, pgdp, p4dp);
			if (!mshv_vtl_local_map_list_add_entry(pgdp, PGD_PAGE, maps))
				goto error;
		}

		p4dp = p4d_offset(pgdp, vaddr);
		if (p4d_none(*p4dp)) {
			pudp = (pud_t *)get_zeroed_page(GFP_KERNEL);
			if (!pudp)
				goto error;
			page_tables_allocated++;

			p4d_populate(current->active_mm, p4dp, pudp);
			if (!mshv_vtl_local_map_list_add_entry(p4dp, P4D_PAGE, maps))
				goto error;
		}

		pudp = pud_offset(p4dp, vaddr);
		if (pud_none(*pudp)) {
			pmdp = (pmd_t *)get_zeroed_page(GFP_KERNEL);
			if (!pmdp)
				goto error;
			page_tables_allocated++;

			pud_populate(current->active_mm, pudp, pmdp);
			if (!mshv_vtl_local_map_list_add_entry(pudp, PUD_PAGE, maps))
				goto error;
		}

		if (vaddr >= LOCAL_NORMAL_VA_START) {
			pmdp = pmd_offset(pudp, vaddr);
			if (!pmd_present(*pmdp)) {
				ptep = (pte_t *)get_zeroed_page(GFP_KERNEL);
				if (!ptep)
					goto error;
				page_tables_allocated++;

				pmd_populate_kernel(current->active_mm, pmdp, ptep);
				if (!mshv_vtl_local_map_list_add_entry(pmdp, PMD_PAGE, maps))
					goto error;
			}

			pte_t *pte = pte_offset_kernel(pmdp, vaddr);
			if (!pte_present(*pte)) {
				pte_t *pte = (pte_t *)get_zeroed_page(GFP_KERNEL);
				if (!pte)
					goto error;
				page_tables_allocated++;

				if (!mshv_vtl_local_map_list_add_entry(pte, PTE_PAGE, maps))
					goto error;
			}
		}

		if (vaddr >= LOCAL_NORMAL_VA_START)
			vaddr += ENTRIES_PER_PGTABLE*NORMAL_PAGE_SIZE;
		else
			vaddr += ENTRIES_PER_PGTABLE*LARGE_PAGE_SIZE;
	}

	pr_debug("%s: page tables allocated %llu\n", __func__, page_tables_allocated);
	pr_debug("%s: LOCAL_LARGE_VA_START = %#llx\n", __func__, LOCAL_LARGE_VA_START);
	pr_debug("%s: LOCAL_LARGE_VA_END = %#llx\n", __func__, LOCAL_LARGE_VA_END);
	pr_debug("%s: LOCAL_NORMAL_VA_START = %#llx\n", __func__, LOCAL_NORMAL_VA_START);
	pr_debug("%s: LOCAL_NORMAL_VA_END = %#llx\n", __func__, LOCAL_NORMAL_VA_END);
	pr_debug("%s: LOCAL_VA_START = %#llx\n", __func__, LOCAL_VA_START);
	pr_debug("%s: LOCAL_VA_END = %#llx\n", __func__, LOCAL_VA_END);

	mutex_unlock(&mshv_local_maps_mutex);
	return maps;

error:
	mshv_vtl_teardown_local_maps_no_lock(maps);

	mutex_unlock(&mshv_local_maps_mutex);
	return NULL;
}

static void mshv_vtl_teardown_local_maps_no_lock(struct mshv_local_maps *maps)
{
	struct mshv_local_maps *maps_entry, *tmp;
	u64 page_tables_freed = 0;

	/* Clean the top-level entries. */

	u64 vaddr = LOCAL_VA_START;
	while (vaddr < LOCAL_VA_END) {
		pgd_t *pgdp = pgd_offset(current->active_mm, vaddr);

		if (!pgd_none(*pgdp))
			pgd_populate(current->active_mm, pgdp, 0);

		/*
		 * Likley could iterate over the VA space covered by one top-level entry.
		 * Or just do this once as the range won't take more than one the top level
		 * entry.
		 */
		if (vaddr >= LOCAL_NORMAL_VA_START)
			vaddr += ENTRIES_PER_PGTABLE*NORMAL_PAGE_SIZE;
		else
			vaddr += ENTRIES_PER_PGTABLE*LARGE_PAGE_SIZE;
	}

	/* Now remove the memory taken by the page tables. */
	list_for_each_entry_safe(maps_entry, tmp, &maps->node, node) {
		free_page((unsigned long)maps_entry->table);

		list_del(&maps_entry->node);
		kfree(maps_entry);

		page_tables_freed++;
	}

	pr_debug("teardown complete, %llu pages freed.\n", page_tables_freed);
}

void mshv_vtl_teardown_local_maps(struct mshv_local_maps *maps)
{
	mutex_lock(&mshv_local_maps_mutex);
	mshv_vtl_teardown_local_maps_no_lock(maps);
	mutex_unlock(&mshv_local_maps_mutex);
}

/* Used for debugging only. */
void __maybe_unused mshv_vtl_dump_local_maps(struct mshv_local_maps *maps)
{
	struct mshv_local_maps *maps_entry;

	mutex_lock(&mshv_local_maps_mutex);

	pr_info("dumping mshv_local_maps...\n");
	list_for_each_entry(maps_entry, &maps->node, node) {
		switch (maps_entry->page_type) {
			case PGD_PAGE:
				pr_info("PGD page allocated at %#llx\n", (u64)(maps_entry->table));
				break;
			case P4D_PAGE:
				pr_info("P4D page allocated at %#llx\n", (u64)(maps_entry->table));
				break;
			case PUD_PAGE:
				pr_info("PUD page allocated at %#llx\n", (u64)(maps_entry->table));
				break;
			case PMD_PAGE:
				pr_info("PMD page allocated at %#llx\n", (u64)(maps_entry->table));
				break;
			case PTE_PAGE:
				pr_info("PTE page allocated at %#llx\n", (u64)(maps_entry->table));
				break;
			default:
				pr_warn("Unknown page type at %#llx\n", (u64)(maps_entry->table));
				break;
		}
	}

	mutex_unlock(&mshv_local_maps_mutex);
}

static void pet_watchdogs(void)
{
	touch_softlockup_watchdog_sync();
	clocksource_touch_watchdog();
	rcu_cpu_stall_reset();
	reset_hung_task_detector();
	touch_nmi_watchdog();
}

ssize_t mshv_use_local_page(u64 pfn, bool large, u64 pfn_count, u64 *failed_pfn,
		mshv_use_local_page_func f, void *param)
{
	u32 cpu;
	u64 vaddr;
	u64 last_pfn;
	pgd_t *pgdp;
	p4d_t *p4dp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t* leafp;
	pteval_t page_flags;
	ssize_t res = 0;

	*failed_pfn = -1;

	if (large && !IS_ALIGNED(pfn, ENTRIES_PER_PGTABLE))
		return -EINVAL;
	if (large && (pfn_count < ENTRIES_PER_PGTABLE))
		return -EINVAL;

	last_pfn = pfn + pfn_count;
	if (large && !IS_ALIGNED(last_pfn, ENTRIES_PER_PGTABLE))
		return -EINVAL;

	cpu = get_cpu();
	if (large)
		vaddr = LOCAL_LARGE_VA_START + LARGE_PAGE_SIZE*cpu;
	else
		vaddr = LOCAL_NORMAL_VA_START + NORMAL_PAGE_SIZE*cpu;

	pr_debug("%s: requested to process %lld pages starting at %#llx, cpu %d, vaddr %#llx\n",
			__func__, pfn_count, pfn, cpu, vaddr);

	while (pfn < last_pfn) {
		/*
		 * Map vaddr: read-only, non-execute, and non-global.
		 *
		 * The two former flags ensures no data corruption and safety (if
		 * we take pvalidate as an example, it just reads one byte from
		 * the mapped page).
		 *
		 * The latter one makes flushing TLB cheaper, with just `invlpg`.
		 *
		 * `_PAGE_ENC` automatically changes to `0` when no confidential
		 * pages are supported.
		 */
		page_flags = _PAGE_PRESENT | _PAGE_ACCESSED | _PAGE_DIRTY | _PAGE_NX | _PAGE_ENC;
		pgdp = pgd_offset(current->active_mm, vaddr);
		if (!pgdp || !pte_present(*(pte_t*)pgdp)) {
			res = -EFAULT;
			break;
		}
		p4dp = p4d_offset(pgdp, vaddr);
		if (!p4dp || !pte_present(*(pte_t*)p4dp)) {
			res = -EFAULT;
			break;
		}
		pudp = pud_offset(p4dp, vaddr);
		if (!pudp || !pte_present(*(pte_t*)pudp)) {
			res = -EFAULT;
			break;
		}
		pmdp = pmd_offset(pudp, vaddr);
		if (!pmdp || (!large && !pte_present(*(pte_t*)pmdp))) {
			res = -EFAULT;
			break;
		}

		if (large) {
			page_flags |= _PAGE_PSE;
			leafp = (pte_t *)pmdp;
		} else {
			leafp = pte_offset_kernel(pmdp, vaddr);
			if (!leafp) {
				res = -EFAULT;
				break;
			}
		}

		/*
		 * When cleaning the entry, it is purposefully set to `0`,
		 * hence using a stronger than `pte_present()` condition
		 * to catch possible errors.
		 */
		if (leafp->pte) {
			pr_warn("%s: the leaf entry is not zero: %#llx, large %d, pfn %#llx, vaddr %#llx\n",
					__func__, (u64)(leafp->pte), large, pfn, vaddr);
			res = -EBUSY;
			break;
		}

		set_pte(leafp, __pte((pfn << PAGE_SHIFT) | page_flags));
		asm volatile("": : :"memory"); /* Compiler fence to prevent compiler reordering. */

		/* Use vaddr */
		res = f((void*)vaddr, param);

		/*
		 * Unmap vaddr and flush TLB. Other processor couldn't use this VA so omit
		 * remote TLB flushes. Instead of flipping individual bits (e.g. _PAGE_PRESENT),
		 * set the entry to `0` as that is an invalid entry on x86_64. That also checks
		 * with validation.
		 */

		set_pte(leafp, __pte(0));
		asm volatile("invlpg (%0)" ::"r" (vaddr) : "memory");

		if (res) {
			*failed_pfn = pfn;
			break;
		}

		/*
		 * The code runs with preemption disabled, pet the watchdogs every 0x200th
		 * iteration.
		 */
		if (large) {
			if (IS_ALIGNED(pfn, ENTRIES_PER_PGTABLE*ENTRIES_PER_PGTABLE))
				pet_watchdogs();
		} else {
			if (IS_ALIGNED(pfn, ENTRIES_PER_PGTABLE))
				pet_watchdogs();
		}

		if (large)
			pfn += ENTRIES_PER_PGTABLE;
		else
			pfn += 1;
	}

	put_cpu();
	pr_debug("%s: result %ld, requested to process %lld pages, not processed %lld pages\n", __func__, res, pfn_count, last_pfn - pfn);
	return res;
}
