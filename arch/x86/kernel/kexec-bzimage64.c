// SPDX-License-Identifier: GPL-2.0-only
/*
 * Kexec bzImage loader
 *
 * Copyright (C) 2014 Red Hat Inc.
 * Authors:
 *      Vivek Goyal <vgoyal@redhat.com>
 */

#define pr_fmt(fmt)	"kexec-bzImage64: " fmt

#include <linux/string.h>
#include <linux/printk.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/kexec.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/libfdt.h>
#include <linux/of_fdt.h>
#include <linux/efi.h>
#include <linux/random.h>

#include <asm/bootparam.h>
#include <asm/setup.h>
#include <asm/crash.h>
#include <asm/efi.h>
#include <asm/e820/api.h>
#include <asm/kexec-bzimage64.h>
#include <asm/kexec-file.h>

/*
 * Defines lowest physical address for various segments. Not sure where
 * exactly these limits came from. Current bzimage64 loader in kexec-tools
 * uses these so I am retaining it. It can be changed over time as we gain
 * more insight.
 */
#define MIN_PURGATORY_ADDR	0x3000
#define MIN_BOOTPARAM_ADDR	0x3000
#define MIN_KERNEL_LOAD_ADDR	0x100000
#define MIN_INITRD_LOAD_ADDR	0x1000000

/*
 * This is a place holder for all boot loader specific data structure which
 * gets allocated in one call but gets freed much later during cleanup
 * time. Right now there is only one field but it can grow as need be.
 */
struct bzimage64_data {
	/*
	 * Temporary buffer to hold bootparams buffer. This should be
	 * freed once the bootparam segment has been loaded.
	 */
	void *bootparams_buf;
};

static int bzImage64_probe(const char *buf, unsigned long len)
{
	int ret = -ENOEXEC;
	struct setup_header *header;

	/* kernel should be at least two sectors long */
	if (len < 2 * 512) {
		pr_err("File is too short to be a bzImage\n");
		return ret;
	}

	header = (struct setup_header *)(buf + offsetof(struct boot_params, hdr));
	if (memcmp((char *)&header->header, "HdrS", 4) != 0) {
		pr_err("Not a bzImage\n");
		return ret;
	}

	if (header->boot_flag != 0xAA55) {
		pr_err("No x86 boot sector present\n");
		return ret;
	}

	if (header->version < 0x020C) {
		pr_err("Must be at least protocol version 2.12\n");
		return ret;
	}

	if (!(header->loadflags & LOADED_HIGH)) {
		pr_err("zImage not a bzImage\n");
		return ret;
	}

	if (!(header->xloadflags & XLF_KERNEL_64)) {
		pr_err("Not a bzImage64. XLF_KERNEL_64 is not set.\n");
		return ret;
	}

	if (!(header->xloadflags & XLF_CAN_BE_LOADED_ABOVE_4G)) {
		pr_err("XLF_CAN_BE_LOADED_ABOVE_4G is not set.\n");
		return ret;
	}

	/*
	 * Can't handle 32bit EFI as it does not allow loading kernel
	 * above 4G. This should be handled by 32bit bzImage loader
	 */
	if (efi_enabled(EFI_RUNTIME_SERVICES) && !efi_enabled(EFI_64BIT)) {
		pr_debug("EFI is 32 bit. Can't load kernel above 4G.\n");
		return ret;
	}

	if (!(header->xloadflags & XLF_5LEVEL) && pgtable_l5_enabled()) {
		pr_err("bzImage cannot handle 5-level paging mode.\n");
		return ret;
	}

	/* I've got a bzImage */
	pr_debug("It's a relocatable bzImage64\n");
	ret = 0;

	return ret;
}

static void *bzImage64_load(struct kimage *image, char *kernel,
			    unsigned long kernel_len, char *initrd,
			    unsigned long initrd_len, char *cmdline,
			    unsigned long cmdline_len)
{

	struct setup_header *header;
	int setup_sects, kern16_size, ret = 0;
	unsigned long setup_header_size, params_cmdline_sz;
	struct boot_params *params;
	unsigned long bootparam_load_addr, kernel_load_addr, initrd_load_addr;
	struct bzimage64_data *ldata;
	struct kexec_entry64_regs regs64;
	void *stack;
	unsigned int setup_hdr_offset = offsetof(struct boot_params, hdr);
	unsigned int efi_map_offset, efi_map_sz, efi_setup_data_offset;
	struct kexec_buf kbuf = { .image = image, .buf_max = ULONG_MAX,
				  .top_down = true };
	struct kexec_buf pbuf = { .image = image, .buf_min = MIN_PURGATORY_ADDR,
				  .buf_max = ULONG_MAX, .top_down = true };

	header = (struct setup_header *)(kernel + setup_hdr_offset);
	setup_sects = header->setup_sects;
	if (setup_sects == 0)
		setup_sects = 4;

	kern16_size = (setup_sects + 1) * 512;
	if (kernel_len < kern16_size) {
		pr_err("bzImage truncated\n");
		return ERR_PTR(-ENOEXEC);
	}

	if (cmdline_len > header->cmdline_size) {
		pr_err("Kernel command line too long\n");
		return ERR_PTR(-EINVAL);
	}

	/*
	 * In case of crash dump, we will append elfcorehdr=<addr> to
	 * command line. Make sure it does not overflow
	 */
	if (cmdline_len + X86_KEXEC_ELFCOREHDR_STR_LEN > header->cmdline_size) {
		pr_err("Appending elfcorehdr=<addr> to command line exceeds maximum allowed length\n");
		return ERR_PTR(-EINVAL);
	}

#ifdef CONFIG_CRASH_DUMP
	/* Allocate and load backup region */
	if (image->type == KEXEC_TYPE_CRASH) {
		ret = crash_load_segments(image);
		if (ret)
			return ERR_PTR(ret);
		ret = crash_load_dm_crypt_keys(image);
		if (ret == -ENOENT) {
			kexec_dprintk("No dm crypt key to load\n");
		} else if (ret) {
			pr_err("Failed to load dm crypt keys\n");
			return ERR_PTR(ret);
		}
		if (image->dm_crypt_keys_addr &&
		    cmdline_len + X86_KEXEC_ELFCOREHDR_STR_LEN +
		    X86_KEXEC_DMCRYPTKEYS_STR_LEN >
			    header->cmdline_size) {
			pr_err("Appending dmcryptkeys=<addr> to command line exceeds maximum allowed length\n");
			return ERR_PTR(-EINVAL);
		}
	}
#endif

	/*
	 * Load purgatory. For 64bit entry point, purgatory  code can be
	 * anywhere.
	 */
	ret = kexec_load_purgatory(image, &pbuf);
	if (ret) {
		pr_err("Loading purgatory failed\n");
		return ERR_PTR(ret);
	}

	kexec_dprintk("Loaded purgatory at 0x%lx\n", pbuf.mem);


	/*
	 * Load Bootparams and cmdline and space for efi stuff.
	 *
	 * Allocate memory together for multiple data structures so
	 * that they all can go in single area/segment and we don't
	 * have to create separate segment for each. Keeps things
	 * little bit simple
	 */
	efi_map_sz = efi_get_runtime_map_size();
	params_cmdline_sz = sizeof(struct boot_params) + cmdline_len +
				X86_KEXEC_ELFCOREHDR_STR_LEN;
	if (image->dm_crypt_keys_addr)
		params_cmdline_sz += X86_KEXEC_DMCRYPTKEYS_STR_LEN;
	params_cmdline_sz = ALIGN(params_cmdline_sz, 16);
	kbuf.bufsz = params_cmdline_sz + ALIGN(efi_map_sz, 16) +
				sizeof(struct setup_data) +
				sizeof(struct efi_setup_data) +
				sizeof(struct setup_data) +
				X86_KEXEC_RNG_SEED_LENGTH;

#ifdef CONFIG_OF_FLATTREE
	if (image->force_dtb && initial_boot_params)
		kbuf.bufsz += sizeof(struct setup_data) +
			      fdt_totalsize(initial_boot_params);
#endif

	if (IS_ENABLED(CONFIG_IMA_KEXEC))
		kbuf.bufsz += sizeof(struct setup_data) +
			      sizeof(struct ima_setup_data);

	if (IS_ENABLED(CONFIG_KEXEC_HANDOVER))
		kbuf.bufsz += sizeof(struct setup_data) +
			      sizeof(struct kho_data);

	params = kvzalloc(kbuf.bufsz, GFP_KERNEL);
	if (!params)
		return ERR_PTR(-ENOMEM);
	efi_map_offset = params_cmdline_sz;
	efi_setup_data_offset = efi_map_offset + ALIGN(efi_map_sz, 16);

	/* Copy setup header onto bootparams. Documentation/arch/x86/boot.rst */
	setup_header_size = 0x0202 + kernel[0x0201] - setup_hdr_offset;

	/* Is there a limit on setup header size? */
	memcpy(&params->hdr, (kernel + setup_hdr_offset), setup_header_size);

	kbuf.buffer = params;
	kbuf.memsz = kbuf.bufsz;
	kbuf.buf_align = 16;
	kbuf.buf_min = MIN_BOOTPARAM_ADDR;
	ret = kexec_add_buffer(&kbuf);
	if (ret)
		goto out_free_params;
	bootparam_load_addr = kbuf.mem;
	kexec_dprintk("Loaded boot_param, command line and misc at 0x%lx bufsz=0x%lx memsz=0x%lx\n",
		      bootparam_load_addr, kbuf.bufsz, kbuf.memsz);

	/* Load kernel */
	kbuf.buffer = kernel + kern16_size;
	kbuf.bufsz =  kernel_len - kern16_size;
	kbuf.memsz = PAGE_ALIGN(header->init_size);
	kbuf.buf_align = header->kernel_alignment;
	if (header->pref_address < MIN_KERNEL_LOAD_ADDR)
		kbuf.buf_min = MIN_KERNEL_LOAD_ADDR;
	else
		kbuf.buf_min = header->pref_address;
	kbuf.mem = KEXEC_BUF_MEM_UNKNOWN;
	ret = kexec_add_buffer(&kbuf);
	if (ret)
		goto out_free_params;
	kernel_load_addr = kbuf.mem;

	kexec_dprintk("Loaded 64bit kernel at 0x%lx bufsz=0x%lx memsz=0x%lx\n",
		      kernel_load_addr, kbuf.bufsz, kbuf.memsz);

	/* Load initrd high */
	if (initrd) {
		kbuf.buffer = initrd;
		kbuf.bufsz = kbuf.memsz = initrd_len;
		kbuf.buf_align = PAGE_SIZE;
		kbuf.buf_min = MIN_INITRD_LOAD_ADDR;
		kbuf.mem = KEXEC_BUF_MEM_UNKNOWN;
		ret = kexec_add_buffer(&kbuf);
		if (ret)
			goto out_free_params;
		initrd_load_addr = kbuf.mem;

		kexec_dprintk("Loaded initrd at 0x%lx bufsz=0x%lx memsz=0x%lx\n",
			      initrd_load_addr, initrd_len, initrd_len);

		x86_kexec_setup_initrd(params, initrd_load_addr,
				       initrd_len);
	}

	x86_kexec_setup_cmdline(image, params, bootparam_load_addr,
				sizeof(struct boot_params), cmdline, cmdline_len);

	/* bootloader info. Do we need a separate ID for kexec kernel loader? */
	params->hdr.type_of_loader = 0x0D << 4;
	params->hdr.loadflags = 0;

	/* Setup purgatory regs for entry */
	ret = kexec_purgatory_get_set_symbol(image, "entry64_regs", &regs64,
					     sizeof(regs64), 1);
	if (ret)
		goto out_free_params;

	regs64.rbx = 0; /* Bootstrap Processor */
	regs64.rsi = bootparam_load_addr;
	regs64.rip = kernel_load_addr + 0x200;
	stack = kexec_purgatory_get_symbol_addr(image, "stack_end");
	if (IS_ERR(stack)) {
		pr_err("Could not find address of symbol stack_end\n");
		ret = -EINVAL;
		goto out_free_params;
	}

	regs64.rsp = (unsigned long)stack;
	ret = kexec_purgatory_get_set_symbol(image, "entry64_regs", &regs64,
					     sizeof(regs64), 0);
	if (ret)
		goto out_free_params;

	ret = x86_kexec_setup_boot_parameters(image, params,
					      bootparam_load_addr,
					      efi_map_offset, efi_map_sz,
					      efi_setup_data_offset);
	if (ret)
		goto out_free_params;

	/* Allocate loader specific data */
	ldata = kzalloc(sizeof(struct bzimage64_data), GFP_KERNEL);
	if (!ldata) {
		ret = -ENOMEM;
		goto out_free_params;
	}

	/*
	 * Store pointer to params so that it could be freed after loading
	 * params segment has been loaded and contents have been copied
	 * somewhere else.
	 */
	ldata->bootparams_buf = params;
	return ldata;

out_free_params:
	kvfree(params);
	return ERR_PTR(ret);
}

/* This cleanup function is called after various segments have been loaded */
static int bzImage64_cleanup(void *loader_data)
{
	struct bzimage64_data *ldata = loader_data;

	if (!ldata)
		return 0;

	kvfree(ldata->bootparams_buf);
	ldata->bootparams_buf = NULL;

	return 0;
}

const struct kexec_file_ops kexec_bzImage64_ops = {
	.probe = bzImage64_probe,
	.load = bzImage64_load,
	.cleanup = bzImage64_cleanup,
#ifdef CONFIG_KEXEC_BZIMAGE_VERIFY_SIG
	.verify_sig = kexec_kernel_verify_pe_sig,
#endif
};
