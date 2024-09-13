// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Secure AVIC Support (SEV-SNP Guests)
 *
 * Copyright (C) 2024 Advanced Micro Devices, Inc.
 *
 * Author: Kishon Vijay Abraham I <kvijayab@amd.com>
 */

#include <linux/cpumask.h>
#include <linux/cc_platform.h>
#include <linux/percpu-defs.h>
#include <linux/align.h>
#include <linux/sizes.h>

#include <asm/apic.h>
#include <asm/cpuid.h>
#include <asm/sev.h>

#include "local.h"

#define VEC_POS(v)	((v) & (32 - 1))
#define REG_POS(v)	(((v) >> 5) << 4)

static DEFINE_PER_CPU(void *, apic_backing_page);
static DEFINE_PER_CPU(bool, savic_setup_done);

enum lapic_lvt_entry {
	LVT_TIMER,
	LVT_THERMAL_MONITOR,
	LVT_PERFORMANCE_COUNTER,
	LVT_LINT0,
	LVT_LINT1,
	LVT_ERROR,

	APIC_MAX_NR_LVT_ENTRIES,
};

#define APIC_LVTx(x) (APIC_LVTT + 0x10 * (x))

static inline void savic_wr_control_msr(u64 val)
{
	native_wrmsr(MSR_AMD64_SECURE_AVIC_CONTROL, lower_32_bits(val), upper_32_bits(val));
}

static int x2apic_savic_acpi_madt_oem_check(char *oem_id, char *oem_table_id)
{
	return x2apic_enabled() && cc_platform_has(CC_ATTR_SNP_SECURE_AVIC);
}

static inline u32 get_reg(char *page, int reg_off)
{
	return READ_ONCE(*((u32 *)(page + reg_off)));
}

static inline void set_reg(char *page, int reg_off, u32 val)
{
	WRITE_ONCE(*((u32 *)(page + reg_off)), val);
}

static u32 read_msr_from_hv(u32 reg)
{
	u64 data, msr;
	int ret;

	msr = APIC_BASE_MSR + (reg >> 4);
	ret = sev_ghcb_msr_read(msr, &data);
	if (ret != ES_OK) {
		pr_err("Secure AVIC msr (%#llx) read returned error (%d)\n", msr, ret);
		/* MSR read failures are treated as fatal errors */
		snp_abort();
	}

	return lower_32_bits(data);
}

static void write_msr_to_hv(u32 reg, u64 data)
{
	u64 msr;
	int ret;

	msr = APIC_BASE_MSR + (reg >> 4);
	ret = sev_ghcb_msr_write(msr, data);
	if (ret != ES_OK) {
		pr_err("Secure AVIC msr (%#llx) write returned error (%d)\n", msr, ret);
		/* MSR writes should never fail. Any failure is fatal error for SNP guest */
		snp_abort();
	}
}

#define SAVIC_ALLOWED_IRR_OFFSET	0x204

static u32 x2apic_savic_read(u32 reg)
{
	void *backing_page = this_cpu_read(apic_backing_page);

	switch (reg) {
	case APIC_LVTT:
	case APIC_TMICT:
	case APIC_TMCCT:
	case APIC_TDCR:
		return read_msr_from_hv(reg);
	case APIC_ID:
	case APIC_LVR:
	case APIC_TASKPRI:
	case APIC_ARBPRI:
	case APIC_PROCPRI:
	case APIC_LDR:
	case APIC_SPIV:
	case APIC_ESR:
	case APIC_ICR:
	case APIC_LVTTHMR:
	case APIC_LVTPC:
	case APIC_LVT0:
	case APIC_LVT1:
	case APIC_LVTERR:
	case APIC_EFEAT:
	case APIC_ECTRL:
	case APIC_SEOI:
	case APIC_IER:
	case APIC_EILVTn(0) ... APIC_EILVTn(3):
		return get_reg(backing_page, reg);
	case APIC_ISR ... APIC_ISR + 0x70:
	case APIC_TMR ... APIC_TMR + 0x70:
		WARN_ONCE(!IS_ALIGNED(reg, 16), "Reg offset %#x not aligned at 16 bytes", reg);
		return get_reg(backing_page, reg);
	/* IRR and ALLOWED_IRR offset range */
	case APIC_IRR ... APIC_IRR + 0x74:
		/*
		 * Either aligned at 16 bytes for valid IRR reg offset or a
		 * valid Secure AVIC ALLOWED_IRR offset.
		 */
		WARN_ONCE(!(IS_ALIGNED(reg, 16) || IS_ALIGNED(reg - SAVIC_ALLOWED_IRR_OFFSET, 16)),
			  "Misaligned IRR/ALLOWED_IRR reg offset %#x", reg);
		return get_reg(backing_page, reg);
	default:
		pr_err("Permission denied: read of Secure AVIC reg offset %#x\n", reg);
		return 0;
	}
}

#define SAVIC_NMI_REQ_OFFSET		0x278

static void x2apic_savic_write(u32 reg, u32 data)
{
	void *backing_page = this_cpu_read(apic_backing_page);
	unsigned int cfg;

	switch (reg) {
	case APIC_LVTT:
	case APIC_LVT0:
	case APIC_LVT1:
	case APIC_TMICT:
	case APIC_TDCR:
		write_msr_to_hv(reg, data);
		break;
	/* APIC_ID is writable and configured by guest for Secure AVIC */
	case APIC_ID:
	case APIC_TASKPRI:
	case APIC_EOI:
	case APIC_SPIV:
	case SAVIC_NMI_REQ_OFFSET:
	case APIC_ESR:
	case APIC_ICR:
	case APIC_LVTTHMR:
	case APIC_LVTPC:
	case APIC_LVTERR:
	case APIC_ECTRL:
	case APIC_SEOI:
	case APIC_IER:
	case APIC_EILVTn(0) ... APIC_EILVTn(3):
		set_reg(backing_page, reg, data);
		break;
	/* Self IPIs are accelerated by hardware, use wrmsr */
	case APIC_SELF_IPI:
		cfg = __prepare_ICR(APIC_DEST_SELF, data, 0);
		native_x2apic_icr_write(cfg, 0);
		break;
	/* ALLOWED_IRR offsets are writable */
	case SAVIC_ALLOWED_IRR_OFFSET ... SAVIC_ALLOWED_IRR_OFFSET + 0x70:
		if (IS_ALIGNED(reg - SAVIC_ALLOWED_IRR_OFFSET, 16)) {
			set_reg(backing_page, reg, data);
			break;
		}
		fallthrough;
	default:
		pr_err("Permission denied: write to Secure AVIC reg offset %#x\n", reg);
	}
}

static void send_ipi(int cpu, int vector, bool nmi)
{
	void *backing_page;
	int reg_off;

	backing_page = per_cpu(apic_backing_page, cpu);
	reg_off = APIC_IRR + REG_POS(vector);
	/*
	 * Use test_and_set_bit() to ensure that IRR updates are atomic w.r.t. other
	 * IRR updates such as during VMRUN and during CPU interrupt handling flow.
	 */
	test_and_set_bit(VEC_POS(vector), (unsigned long *)((char *)backing_page + reg_off));
	if (nmi)
		set_reg(backing_page, SAVIC_NMI_REQ_OFFSET, nmi);
}

static void send_ipi_dest(u64 icr_data)
{
	int vector, cpu;
	bool nmi;

	vector = icr_data & APIC_VECTOR_MASK;
	cpu = icr_data >> 32;
	nmi = ((icr_data & APIC_DM_FIXED_MASK) == APIC_DM_NMI);

	send_ipi(cpu, vector, nmi);
}

static void send_ipi_target(u64 icr_data)
{
	if (icr_data & APIC_DEST_LOGICAL) {
		pr_err("IPI target should be of PHYSICAL type\n");
		return;
	}

	send_ipi_dest(icr_data);
}

static void send_ipi_allbut(u64 icr_data)
{
	const struct cpumask *self_cpu_mask = get_cpu_mask(smp_processor_id());
	unsigned long flags;
	int vector, cpu;
	bool nmi;

	vector = icr_data & APIC_VECTOR_MASK;
	nmi = ((icr_data & APIC_DM_FIXED_MASK) == APIC_DM_NMI);
	local_irq_save(flags);
	for_each_cpu_andnot(cpu, cpu_present_mask, self_cpu_mask)
		send_ipi(cpu, vector, nmi);
	write_msr_to_hv(APIC_ICR, icr_data);
	local_irq_restore(flags);
}

static void send_ipi_allinc(u64 icr_data)
{
	int vector;

	send_ipi_allbut(icr_data);
	vector = icr_data & APIC_VECTOR_MASK;
	native_x2apic_icr_write(APIC_DEST_SELF | vector, 0);
}

static void x2apic_savic_icr_write(u32 icr_low, u32 icr_high)
{
	int dsh, vector;
	u64 icr_data;

	icr_data = ((u64)icr_high) << 32 | icr_low;
	dsh = icr_low & APIC_DEST_ALLBUT;

	switch (dsh) {
	case APIC_DEST_SELF:
		vector = icr_data & APIC_VECTOR_MASK;
		x2apic_savic_write(APIC_SELF_IPI, vector);
		break;
	case APIC_DEST_ALLINC:
		send_ipi_allinc(icr_data);
		break;
	case APIC_DEST_ALLBUT:
		send_ipi_allbut(icr_data);
		break;
	default:
		send_ipi_target(icr_data);
		write_msr_to_hv(APIC_ICR, icr_data);
	}
}

static void __send_IPI_dest(unsigned int apicid, int vector, unsigned int dest)
{
	unsigned int cfg = __prepare_ICR(0, vector, dest);

	x2apic_savic_icr_write(cfg, apicid);
}

static void x2apic_savic_send_IPI(int cpu, int vector)
{
	u32 dest = per_cpu(x86_cpu_to_apicid, cpu);

	__send_IPI_dest(dest, vector, APIC_DEST_PHYSICAL);
}

static void
__send_IPI_mask(const struct cpumask *mask, int vector, int apic_dest)
{
	unsigned long query_cpu;
	unsigned long this_cpu;
	unsigned long flags;

	local_irq_save(flags);

	this_cpu = smp_processor_id();
	for_each_cpu(query_cpu, mask) {
		if (apic_dest == APIC_DEST_ALLBUT && this_cpu == query_cpu)
			continue;
		__send_IPI_dest(per_cpu(x86_cpu_to_apicid, query_cpu), vector,
				      APIC_DEST_PHYSICAL);
	}

	local_irq_restore(flags);
}

static void x2apic_savic_send_IPI_mask(const struct cpumask *mask, int vector)
{
	__send_IPI_mask(mask, vector, APIC_DEST_ALLINC);
}

static void x2apic_savic_send_IPI_mask_allbutself(const struct cpumask *mask, int vector)
{
	__send_IPI_mask(mask, vector, APIC_DEST_ALLBUT);
}

static void __send_IPI_shorthand(int vector, u32 which)
{
	unsigned int cfg = __prepare_ICR(which, vector, 0);

	x2apic_savic_icr_write(cfg, 0);
}

static void x2apic_savic_send_IPI_allbutself(int vector)
{
	__send_IPI_shorthand(vector, APIC_DEST_ALLBUT);
}

static void x2apic_savic_send_IPI_all(int vector)
{
	__send_IPI_shorthand(vector, APIC_DEST_ALLINC);
}

static void x2apic_savic_send_IPI_self(int vector)
{
	__send_IPI_shorthand(vector, APIC_DEST_SELF);
}

static void x2apic_savic_update_vector(unsigned int cpu, unsigned int vector, bool set)
{
	void *backing_page;
	unsigned long *reg;
	int reg_off;

	backing_page = per_cpu(apic_backing_page, cpu);
	reg_off = SAVIC_ALLOWED_IRR_OFFSET + REG_POS(vector);
	reg = (unsigned long *)((char *)backing_page + reg_off);

	if (set)
		test_and_set_bit(VEC_POS(vector), reg);
	else
		test_and_clear_bit(VEC_POS(vector), reg);
}

static void init_backing_page(void *backing_page)
{
	u32 hv_apic_id;
	u32 apic_id;
	u32 val;
	int i;

	val = read_msr_from_hv(APIC_LVR);
	set_reg(backing_page, APIC_LVR, val);

	/*
	 * Hypervisor is used for all timer related functions,
	 * so don't copy those values.
	 */
	for (i = LVT_THERMAL_MONITOR; i < APIC_MAX_NR_LVT_ENTRIES; i++) {
		val = read_msr_from_hv(APIC_LVTx(i));
		set_reg(backing_page, APIC_LVTx(i), val);
	}

	val = read_msr_from_hv(APIC_LVT0);
	set_reg(backing_page, APIC_LVT0, val);

	val = read_msr_from_hv(APIC_LDR);
	set_reg(backing_page, APIC_LDR, val);

	/* Read APIC ID from Extended Topology Enumeration CPUID */
	apic_id = cpuid_edx(0x0000000b);
	hv_apic_id = read_msr_from_hv(APIC_ID);
	WARN_ONCE(hv_apic_id != apic_id, "Inconsistent APIC_ID values: %d (cpuid), %d (msr)",
			apic_id, hv_apic_id);
	set_reg(backing_page, APIC_ID, apic_id);
}

static void x2apic_savic_setup(void)
{
	void *backing_page;
	enum es_result ret;
	unsigned long gpa;

	if (this_cpu_read(savic_setup_done))
		return;

	backing_page = this_cpu_read(apic_backing_page);
	init_backing_page(backing_page);
	gpa = __pa(backing_page);
	ret = sev_notify_savic_gpa(gpa);
	if (ret != ES_OK)
		snp_abort();
	savic_wr_control_msr(gpa | MSR_AMD64_SECURE_AVIC_EN | MSR_AMD64_SECURE_AVIC_ALLOWEDNMI);
	this_cpu_write(savic_setup_done, true);
}

static int x2apic_savic_probe(void)
{
	void *backing_pages;
	unsigned int cpu;
	size_t sz;
	int i;

	if (!cc_platform_has(CC_ATTR_SNP_SECURE_AVIC))
		return 0;

	if (!x2apic_mode) {
		pr_err("Secure AVIC enabled in non x2APIC mode\n");
		snp_abort();
	}

	sz = ALIGN(num_possible_cpus() * SZ_4K, SZ_2M);
	backing_pages = kzalloc(sz, GFP_ATOMIC);
	if (!backing_pages)
		snp_abort();

	i = 0;
	for_each_possible_cpu(cpu) {
		per_cpu(apic_backing_page, cpu) = backing_pages + i * SZ_4K;
		i++;
	}

	pr_info("Secure AVIC Enabled\n");

	return 1;
}

static struct apic apic_x2apic_savic __ro_after_init = {

	.name				= "secure avic x2apic",
	.probe				= x2apic_savic_probe,
	.acpi_madt_oem_check		= x2apic_savic_acpi_madt_oem_check,
	.setup				= x2apic_savic_setup,

	.dest_mode_logical		= false,

	.disable_esr			= 0,

	.cpu_present_to_apicid		= default_cpu_present_to_apicid,

	.max_apic_id			= UINT_MAX,
	.x2apic_set_max_apicid		= true,
	.get_apic_id			= x2apic_get_apic_id,

	.calc_dest_apicid		= apic_default_calc_apicid,

	.send_IPI			= x2apic_savic_send_IPI,
	.send_IPI_mask			= x2apic_savic_send_IPI_mask,
	.send_IPI_mask_allbutself	= x2apic_savic_send_IPI_mask_allbutself,
	.send_IPI_allbutself		= x2apic_savic_send_IPI_allbutself,
	.send_IPI_all			= x2apic_savic_send_IPI_all,
	.send_IPI_self			= x2apic_savic_send_IPI_self,
	.nmi_to_offline_cpu		= true,

	.read				= x2apic_savic_read,
	.write				= x2apic_savic_write,
	.eoi				= native_apic_msr_eoi,
	.icr_read			= native_x2apic_icr_read,
	.icr_write			= x2apic_savic_icr_write,

	.update_vector			= x2apic_savic_update_vector,
};

apic_driver(apic_x2apic_savic);
