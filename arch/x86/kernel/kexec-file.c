// SPDX-License-Identifier: GPL-2.0-only

#include <linux/efi.h>
#include <linux/kexec.h>
#include <linux/libfdt.h>
#include <linux/of_fdt.h>
#include <linux/random.h>
#include <linux/string.h>

#include <asm/bootparam.h>
#include <asm/crash.h>
#include <asm/e820/api.h>
#include <asm/efi.h>
#include <asm/kexec-file.h>
#include <asm/setup.h>

int x86_kexec_setup_initrd(struct boot_params *params,
			   unsigned long initrd_load_addr,
			   unsigned long initrd_len)
{
	params->hdr.ramdisk_image = initrd_load_addr & 0xffffffffUL;
	params->hdr.ramdisk_size = initrd_len & 0xffffffffUL;

	params->ext_ramdisk_image = initrd_load_addr >> 32;
	params->ext_ramdisk_size = initrd_len >> 32;

	return 0;
}

int x86_kexec_setup_cmdline(struct kimage *image, struct boot_params *params,
			    unsigned long bootparams_load_addr,
			    unsigned long cmdline_offset, char *cmdline,
			    unsigned long cmdline_len)
{
	char *cmdline_ptr = ((char *)params) + cmdline_offset;
	unsigned long cmdline_ptr_phys, len = 0;
	u32 cmdline_low_32, cmdline_ext_32;

	if (image->type == KEXEC_TYPE_CRASH) {
		len = sprintf(cmdline_ptr, "elfcorehdr=0x%lx ",
			      image->elf_load_addr);

		if (image->dm_crypt_keys_addr != 0)
			len += sprintf(cmdline_ptr + len,
				       "dmcryptkeys=0x%lx ",
				       image->dm_crypt_keys_addr);
	}
	memcpy(cmdline_ptr + len, cmdline, cmdline_len);
	cmdline_len += len;

	cmdline_ptr[cmdline_len - 1] = '\0';

	kexec_dprintk("Final command line is: %s\n", cmdline_ptr);
	cmdline_ptr_phys = bootparams_load_addr + cmdline_offset;
	cmdline_low_32 = cmdline_ptr_phys & 0xffffffffUL;
	cmdline_ext_32 = cmdline_ptr_phys >> 32;

	params->hdr.cmd_line_ptr = cmdline_low_32;
	if (cmdline_ext_32)
		params->ext_cmd_line_ptr = cmdline_ext_32;

	return 0;
}

static int setup_e820_entries(struct boot_params *params)
{
	unsigned int nr_e820_entries;

	nr_e820_entries = e820_table_kexec->nr_entries;

	/* TODO: Pass entries more than E820_MAX_ENTRIES_ZEROPAGE in bootparams setup data */
	if (nr_e820_entries > E820_MAX_ENTRIES_ZEROPAGE)
		nr_e820_entries = E820_MAX_ENTRIES_ZEROPAGE;

	params->e820_entries = nr_e820_entries;
	memcpy(&params->e820_table, &e820_table_kexec->entries,
	       nr_e820_entries * sizeof(struct e820_entry));

	return 0;
}

static void
setup_rng_seed(struct boot_params *params, unsigned long params_load_addr,
	       unsigned int rng_seed_setup_data_offset)
{
	struct setup_data *sd = (void *)params + rng_seed_setup_data_offset;
	unsigned long setup_data_phys;

	if (!rng_is_initialized())
		return;

	sd->type = SETUP_RNG_SEED;
	sd->len = X86_KEXEC_RNG_SEED_LENGTH;
	get_random_bytes(sd->data, X86_KEXEC_RNG_SEED_LENGTH);
	setup_data_phys = params_load_addr + rng_seed_setup_data_offset;
	sd->next = params->hdr.setup_data;
	params->hdr.setup_data = setup_data_phys;
}

#ifdef CONFIG_EFI
static int setup_efi_info_memmap(struct boot_params *params,
				 unsigned long params_load_addr,
				 unsigned int efi_map_offset,
				 unsigned int efi_map_sz)
{
	void *efi_map = (void *)params + efi_map_offset;
	unsigned long efi_map_phys_addr = params_load_addr + efi_map_offset;
	struct efi_info *ei = &params->efi_info;

	if (!efi_map_sz)
		return 0;

	efi_runtime_map_copy(efi_map, efi_map_sz);

	ei->efi_memmap = efi_map_phys_addr & 0xffffffff;
	ei->efi_memmap_hi = efi_map_phys_addr >> 32;
	ei->efi_memmap_size = efi_map_sz;

	return 0;
}

static int
prepare_add_efi_setup_data(struct boot_params *params,
			   unsigned long params_load_addr,
			   unsigned int efi_setup_data_offset)
{
	unsigned long setup_data_phys;
	struct setup_data *sd = (void *)params + efi_setup_data_offset;
	struct efi_setup_data *esd = (void *)sd + sizeof(struct setup_data);

	esd->fw_vendor = efi_fw_vendor;
	esd->tables = efi_config_table;
	esd->smbios = efi.smbios;

	sd->type = SETUP_EFI;
	sd->len = sizeof(struct efi_setup_data);

	setup_data_phys = params_load_addr + efi_setup_data_offset;
	sd->next = params->hdr.setup_data;
	params->hdr.setup_data = setup_data_phys;

	return 0;
}

static int
setup_efi_state(struct boot_params *params, unsigned long params_load_addr,
		unsigned int efi_map_offset, unsigned int efi_map_sz,
		unsigned int efi_setup_data_offset)
{
	struct efi_info *current_ei = &boot_params.efi_info;
	struct efi_info *ei = &params->efi_info;

	if (!params->acpi_rsdp_addr) {
		if (efi.acpi20 != EFI_INVALID_TABLE_ADDR)
			params->acpi_rsdp_addr = efi.acpi20;
		else if (efi.acpi != EFI_INVALID_TABLE_ADDR)
			params->acpi_rsdp_addr = efi.acpi;
	}

	if (!efi_enabled(EFI_RUNTIME_SERVICES))
		return 0;

	if (!current_ei->efi_memmap_size)
		return 0;

	params->secure_boot = boot_params.secure_boot;
	ei->efi_loader_signature = current_ei->efi_loader_signature;
	ei->efi_systab = current_ei->efi_systab;
	ei->efi_systab_hi = current_ei->efi_systab_hi;

	ei->efi_memdesc_version = current_ei->efi_memdesc_version;
	ei->efi_memdesc_size = efi_get_runtime_map_desc_size();

	setup_efi_info_memmap(params, params_load_addr, efi_map_offset,
			      efi_map_sz);
	prepare_add_efi_setup_data(params, params_load_addr,
				   efi_setup_data_offset);
	return 0;
}
#endif /* CONFIG_EFI */

#ifdef CONFIG_OF_FLATTREE
static void setup_dtb(struct boot_params *params,
		      unsigned long params_load_addr,
		      unsigned int dtb_setup_data_offset)
{
	struct setup_data *sd = (void *)params + dtb_setup_data_offset;
	unsigned long setup_data_phys, dtb_len;

	dtb_len = fdt_totalsize(initial_boot_params);
	sd->type = SETUP_DTB;
	sd->len = dtb_len;

	memcpy(sd->data, initial_boot_params, dtb_len);

	setup_data_phys = params_load_addr + dtb_setup_data_offset;
	sd->next = params->hdr.setup_data;
	params->hdr.setup_data = setup_data_phys;
}
#endif /* CONFIG_OF_FLATTREE */

static void
setup_ima_state(const struct kimage *image, struct boot_params *params,
		unsigned long params_load_addr,
		unsigned int ima_setup_data_offset)
{
#ifdef CONFIG_IMA_KEXEC
	struct setup_data *sd = (void *)params + ima_setup_data_offset;
	unsigned long setup_data_phys;
	struct ima_setup_data *ima;

	if (!image->ima_buffer_size)
		return;

	sd->type = SETUP_IMA;
	sd->len = sizeof(*ima);

	ima = (void *)sd + sizeof(struct setup_data);
	ima->addr = image->ima_buffer_addr;
	ima->size = image->ima_buffer_size;

	setup_data_phys = params_load_addr + ima_setup_data_offset;
	sd->next = params->hdr.setup_data;
	params->hdr.setup_data = setup_data_phys;
#endif /* CONFIG_IMA_KEXEC */
}

static void setup_kho(const struct kimage *image, struct boot_params *params,
		      unsigned long params_load_addr,
		      unsigned int setup_data_offset)
{
	struct setup_data *sd = (void *)params + setup_data_offset;
	struct kho_data *kho = (void *)sd + sizeof(*sd);

	if (!IS_ENABLED(CONFIG_KEXEC_HANDOVER))
		return;

	sd->type = SETUP_KEXEC_KHO;
	sd->len = sizeof(struct kho_data);

	if (!image->kho.fdt || !image->kho.scratch)
		return;

	kho->fdt_addr = image->kho.fdt;
	kho->fdt_size = PAGE_SIZE;
	kho->scratch_addr = image->kho.scratch->mem;
	kho->scratch_size = image->kho.scratch->bufsz;
	sd->next = params->hdr.setup_data;
	params->hdr.setup_data = params_load_addr + setup_data_offset;
}

int x86_kexec_setup_boot_parameters(struct kimage *image,
				    struct boot_params *params,
				    unsigned long params_load_addr,
				    unsigned int efi_map_offset,
				    unsigned int efi_map_sz,
				    unsigned int setup_data_offset)
{
	unsigned int nr_e820_entries;
	unsigned long long mem_k, start, end;
	int i, ret = 0;

	params->hdr.hardware_subarch = boot_params.hdr.hardware_subarch;
	memcpy(&params->screen_info, &screen_info, sizeof(struct screen_info));

	params->screen_info.ext_mem_k = 0;
	params->alt_mem_k = 0;
	params->acpi_rsdp_addr = boot_params.acpi_rsdp_addr;
	memset(&params->apm_bios_info, 0, sizeof(params->apm_bios_info));
	memset(&params->hd0_info, 0, sizeof(params->hd0_info));
	memset(&params->hd1_info, 0, sizeof(params->hd1_info));

#ifdef CONFIG_CRASH_DUMP
	if (image->type == KEXEC_TYPE_CRASH) {
		ret = crash_setup_memmap_entries(image, params);
		if (ret)
			return ret;
	} else {
		setup_e820_entries(params);
	}
#else
	setup_e820_entries(params);
#endif

	nr_e820_entries = params->e820_entries;

	kexec_dprintk("E820 memmap:\n");
	for (i = 0; i < nr_e820_entries; i++) {
		kexec_dprintk("%016llx-%016llx (%d)\n",
			      params->e820_table[i].addr,
			      params->e820_table[i].addr +
			      params->e820_table[i].size - 1,
			      params->e820_table[i].type);
		if (params->e820_table[i].type != E820_TYPE_RAM)
			continue;
		start = params->e820_table[i].addr;
		end = params->e820_table[i].addr +
		      params->e820_table[i].size - 1;

		if (start <= 0x100000 && end > 0x100000) {
			mem_k = (end >> 10) - (0x100000 >> 10);
			params->screen_info.ext_mem_k = mem_k;
			params->alt_mem_k = mem_k;
			if (mem_k > 0xfc00)
				params->screen_info.ext_mem_k = 0xfc00;
			if (mem_k > 0xffffffff)
				params->alt_mem_k = 0xffffffff;
		}
	}

#ifdef CONFIG_EFI
	setup_efi_state(params, params_load_addr, efi_map_offset, efi_map_sz,
			setup_data_offset);
	setup_data_offset += sizeof(struct setup_data) +
			     sizeof(struct efi_setup_data);
#endif

#ifdef CONFIG_OF_FLATTREE
	if (image->force_dtb && initial_boot_params) {
		setup_dtb(params, params_load_addr, setup_data_offset);
		setup_data_offset += sizeof(struct setup_data) +
				     fdt_totalsize(initial_boot_params);
	} else {
		pr_debug("Not carrying over DTB, force_dtb = %d\n",
			 image->force_dtb);
	}
#endif

	if (IS_ENABLED(CONFIG_IMA_KEXEC)) {
		setup_ima_state(image, params, params_load_addr,
				setup_data_offset);
		setup_data_offset += sizeof(struct setup_data) +
				     sizeof(struct ima_setup_data);
	}

	if (IS_ENABLED(CONFIG_KEXEC_HANDOVER)) {
		setup_kho(image, params, params_load_addr, setup_data_offset);
		setup_data_offset += sizeof(struct setup_data) +
				     sizeof(struct kho_data);
	}

	setup_rng_seed(params, params_load_addr, setup_data_offset);

	memcpy(params->eddbuf, boot_params.eddbuf,
	       EDDMAXNR * sizeof(struct edd_info));
	params->eddbuf_entries = boot_params.eddbuf_entries;

	memcpy(params->edd_mbr_sig_buffer, boot_params.edd_mbr_sig_buffer,
	       EDD_MBR_SIG_MAX * sizeof(unsigned int));

	return ret;
}
