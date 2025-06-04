#ifndef __MSHV_VTL_LOCAL_MAPS_H__
#define __MSHV_VTL_LOCAL_MAPS_H__
// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kernel.h>
#include <linux/types.h>

struct mshv_local_maps;

#ifdef CONFIG_SEV_GUEST
#include <asm/pgtable_64_types.h>

enum mshv_page_type {
	PGD_PAGE,
	P4D_PAGE,
	PUD_PAGE,
	PMD_PAGE,
	PTE_PAGE
};

#define PAGES_PER_PMD 	((u64)(PMD_SIZE / PAGE_SIZE))

struct mshv_local_maps *mshv_vtl_setup_local_maps(void);
void mshv_vtl_teardown_local_maps(struct mshv_local_maps *maps);
void mshv_vtl_dump_local_maps(struct mshv_local_maps *maps);

typedef ssize_t (*mshv_use_local_page_func)(void*, void*);
ssize_t mshv_use_local_page(u64 pfn, bool large, u64 pfn_count, u64 *failed_pfn, mshv_use_local_page_func f, void *param);

#else

inline static struct mshv_local_maps *mshv_vtl_setup_local_maps(void)
{
	return NULL;
}

inline static void mshv_vtl_teardown_local_maps(struct mshv_local_maps *maps)
{
}

#endif /* CONFIG_SEV_GUEST */

#endif /* __MSHV_VTL_LOCAL_MAPS_H__ */
