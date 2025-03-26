// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/acpi.h>
#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/kexec.h>
#include <linux/memblock.h>
#include <linux/pgtable.h>
#include <linux/sched/hotplug.h>
#include <asm/barrier.h>
#include <asm/init.h>
#include <asm/intel_pt.h>
#include <asm/nmi.h>
#include <asm/processor.h>
#include <asm/reboot.h>

static u64 acpi_mp_pgd __ro_after_init;
static u64 acpi_mp_reset_vector_paddr __ro_after_init;

static void acpi_mp_stop_this_cpu(void)
{
	asm_acpi_mp_play_dead(acpi_mp_reset_vector_paddr, acpi_mp_pgd);
}

static void acpi_mp_play_dead(void)
{
	play_dead_common();
	asm_acpi_mp_play_dead(acpi_mp_reset_vector_paddr, acpi_mp_pgd);
}

static void acpi_mp_cpu_die(unsigned int cpu)
{
	struct acpi_madt_multiproc_wakeup_mailbox *mailbox = acpi_get_mp_wakeup_mailbox();
	u32 apicid = per_cpu(x86_cpu_to_apicid, cpu);
	unsigned long timeout;

	/*
	 * Use TEST mailbox command to prove that BIOS got control over
	 * the CPU before declaring it dead.
	 *
	 * BIOS has to clear 'command' field of the mailbox.
	 */
	mailbox->apic_id = apicid;
	smp_store_release(&mailbox->command,
			  ACPI_MP_WAKE_COMMAND_TEST);

	/* Don't wait longer than a second. */
	timeout = USEC_PER_SEC;
	while (READ_ONCE(mailbox->command) && --timeout)
		udelay(1);

	if (!timeout)
		pr_err("Failed to hand over CPU %d to BIOS\n", cpu);
}

/* The argument is required to match type of x86_mapping_info::alloc_pgt_page */
static void __init *alloc_pgt_page(void *dummy)
{
	return memblock_alloc(PAGE_SIZE, PAGE_SIZE);
}

static void __init free_pgt_page(void *pgt, void *dummy)
{
	return memblock_free(pgt, PAGE_SIZE);
}

/*
 * Make sure asm_acpi_mp_play_dead() is present in the identity mapping at
 * the same place as in the kernel page tables. asm_acpi_mp_play_dead() switches
 * to the identity mapping and the function has be present at the same spot in
 * the virtual address space before and after switching page tables.
 */
static int __init init_transition_pgtable(pgd_t *pgd)
{
	pgprot_t prot = PAGE_KERNEL_EXEC_NOENC;
	unsigned long vaddr, paddr;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	vaddr = (unsigned long)asm_acpi_mp_play_dead;
	pgd += pgd_index(vaddr);
	if (!pgd_present(*pgd)) {
		p4d = (p4d_t *)alloc_pgt_page(NULL);
		if (!p4d)
			return -ENOMEM;
		set_pgd(pgd, __pgd(__pa(p4d) | _KERNPG_TABLE));
	}
	p4d = p4d_offset(pgd, vaddr);
	if (!p4d_present(*p4d)) {
		pud = (pud_t *)alloc_pgt_page(NULL);
		if (!pud)
			return -ENOMEM;
		set_p4d(p4d, __p4d(__pa(pud) | _KERNPG_TABLE));
	}
	pud = pud_offset(p4d, vaddr);
	if (!pud_present(*pud)) {
		pmd = (pmd_t *)alloc_pgt_page(NULL);
		if (!pmd)
			return -ENOMEM;
		set_pud(pud, __pud(__pa(pmd) | _KERNPG_TABLE));
	}
	pmd = pmd_offset(pud, vaddr);
	if (!pmd_present(*pmd)) {
		pte = (pte_t *)alloc_pgt_page(NULL);
		if (!pte)
			return -ENOMEM;
		set_pmd(pmd, __pmd(__pa(pte) | _KERNPG_TABLE));
	}
	pte = pte_offset_kernel(pmd, vaddr);

	paddr = __pa(vaddr);
	set_pte(pte, pfn_pte(paddr >> PAGE_SHIFT, prot));

	return 0;
}

static int __init acpi_mp_setup_reset(u64 reset_vector)
{
	struct x86_mapping_info info = {
		.alloc_pgt_page = alloc_pgt_page,
		.free_pgt_page	= free_pgt_page,
		.page_flag      = __PAGE_KERNEL_LARGE_EXEC,
		.kernpg_flag    = _KERNPG_TABLE_NOENC,
	};
	pgd_t *pgd;

	pgd = alloc_pgt_page(NULL);
	if (!pgd)
		return -ENOMEM;

	for (int i = 0; i < nr_pfn_mapped; i++) {
		unsigned long mstart, mend;

		mstart = pfn_mapped[i].start << PAGE_SHIFT;
		mend   = pfn_mapped[i].end << PAGE_SHIFT;
		if (kernel_ident_mapping_init(&info, pgd, mstart, mend)) {
			kernel_ident_mapping_free(&info, pgd);
			return -ENOMEM;
		}
	}

	if (kernel_ident_mapping_init(&info, pgd,
				      PAGE_ALIGN_DOWN(reset_vector),
				      PAGE_ALIGN(reset_vector + 1))) {
		kernel_ident_mapping_free(&info, pgd);
		return -ENOMEM;
	}

	if (init_transition_pgtable(pgd)) {
		kernel_ident_mapping_free(&info, pgd);
		return -ENOMEM;
	}

	smp_ops.play_dead = acpi_mp_play_dead;
	smp_ops.stop_this_cpu = acpi_mp_stop_this_cpu;
	smp_ops.cpu_die = acpi_mp_cpu_die;

	acpi_mp_reset_vector_paddr = reset_vector;
	acpi_mp_pgd = __pa(pgd);

	return 0;
}

static void acpi_mp_disable_offlining(struct acpi_madt_multiproc_wakeup *mp_wake)
{
	cpu_hotplug_disable_offlining();

	/*
	 * ACPI MADT doesn't allow to offline a CPU after it was onlined. This
	 * limits kexec: the second kernel won't be able to use more than one CPU.
	 *
	 * To prevent a kexec kernel from onlining secondary CPUs invalidate the
	 * mailbox address in the ACPI MADT wakeup structure which prevents a
	 * kexec kernel to use it.
	 *
	 * This is safe as the booting kernel has the mailbox address cached
	 * already and acpi_wakeup_cpu() uses the cached value to bring up the
	 * secondary CPUs.
	 *
	 * Note: This is a Linux specific convention and not covered by the
	 *       ACPI specification.
	 */
	mp_wake->mailbox_address = 0;
}

int __init acpi_parse_mp_wake(union acpi_subtable_headers *header,
			      const unsigned long end)
{
	struct acpi_madt_multiproc_wakeup *mp_wake;

	mp_wake = (struct acpi_madt_multiproc_wakeup *)header;

	/*
	 * Cannot use the standard BAD_MADT_ENTRY() to sanity check the @mp_wake
	 * entry.  'sizeof (struct acpi_madt_multiproc_wakeup)' can be larger
	 * than the actual size of the MP wakeup entry in ACPI table because the
	 * 'reset_vector' is only available in the V1 MP wakeup structure.
	 */
	if (!mp_wake)
		return -EINVAL;
	if (end - (unsigned long)mp_wake < ACPI_MADT_MP_WAKEUP_SIZE_V0)
		return -EINVAL;
	if (mp_wake->header.length < ACPI_MADT_MP_WAKEUP_SIZE_V0)
		return -EINVAL;

	acpi_table_print_madt_entry(&header->common);

	acpi_setup_mp_wakeup_mailbox(mp_wake->mailbox_address);

	if (mp_wake->version >= ACPI_MADT_MP_WAKEUP_VERSION_V1 &&
	    mp_wake->header.length >= ACPI_MADT_MP_WAKEUP_SIZE_V1) {
		if (acpi_mp_setup_reset(mp_wake->reset_vector)) {
			pr_warn("Failed to setup MADT reset vector\n");
			acpi_mp_disable_offlining(mp_wake);
		}
	} else {
		/*
		 * CPU offlining requires version 1 of the ACPI MADT wakeup
		 * structure.
		 */
		acpi_mp_disable_offlining(mp_wake);
	}

	return 0;
}
