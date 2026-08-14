// SPDX-License-Identifier: GPL-2.0-only
/*
 * x86-64 ELF vmlinux loader for kexec_file_load.
 */

#define pr_fmt(fmt) "kexec-elf64: " fmt

#include <linux/efi.h>
#include <linux/elf.h>
#include <linux/kexec.h>
#include <linux/libfdt.h>
#include <linux/mm.h>
#include <linux/of_fdt.h>
#include <linux/slab.h>

#include <asm/bootparam.h>
#include <asm/crash.h>
#include <asm/efi.h>
#include <asm/kexec-bzimage64.h>
#include <asm/kexec-file.h>
#include <asm/setup.h>

#define MIN_PURGATORY_ADDR	0x3000
#define MIN_BOOTPARAM_ADDR	0x3000
#define MIN_INITRD_LOAD_ADDR	0x1000000
struct elf64_data {
	void *bootparams_buf;
	void *kernel_buf;
};

static int elf64_validate_header(const struct elfhdr *ehdr)
{
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
	    ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
	    ehdr->e_type != ET_EXEC || !elf_check_arch(ehdr)) {
		pr_debug("Not a supported x86-64 vmlinux image\n");
		return -ENOEXEC;
	}

	return 0;
}

static int elf64_probe(const char *kernel, unsigned long kernel_len)
{
	struct kexec_elf_info elf_info = {};
	struct elfhdr ehdr;
	int ret;

#ifdef CONFIG_MODULE_SIG_FORMAT
	ret = kexec_elf_payload_len(kernel, kernel_len, &kernel_len);
	if (ret)
		return ret;
#endif

	ret = kexec_build_elf_info(kernel, kernel_len, &ehdr, &elf_info);
	if (ret)
		return ret;

	ret = elf64_validate_header(&ehdr);
	kexec_free_elf_info(&elf_info);
	return ret;
}

static int elf64_entry_address(const struct elfhdr *ehdr,
			       const struct kexec_elf_info *elf_info,
			       unsigned long *entry)
{
	int i;

	for (i = 0; i < ehdr->e_phnum; i++) {
		const struct elf_phdr *phdr = &elf_info->proghdrs[i];
		unsigned long offset;

		if (phdr->p_type != PT_LOAD)
			continue;

		if (ehdr->e_entry >= phdr->p_vaddr &&
		    ehdr->e_entry - phdr->p_vaddr < phdr->p_memsz) {
			offset = ehdr->e_entry - phdr->p_vaddr;
			*entry = phdr->p_paddr + offset;
			return 0;
		}

		if (ehdr->e_entry >= phdr->p_paddr &&
		    ehdr->e_entry - phdr->p_paddr < phdr->p_memsz) {
			*entry = ehdr->e_entry;
			return 0;
		}
	}

	pr_err("ELF entry point is not covered by a PT_LOAD segment\n");
	return -ENOEXEC;
}

static int elf64_image_layout(const struct elfhdr *ehdr,
			      const struct kexec_elf_info *elf_info,
			      unsigned long *lowest_addr,
			      unsigned long *image_size,
			      unsigned long *image_align)
{
	unsigned long lowest = ULONG_MAX, highest = 0, align = PAGE_SIZE;
	bool loaded = false;
	int i, j;

	for (i = 0; i < ehdr->e_phnum; i++) {
		const struct elf_phdr *phdr = &elf_info->proghdrs[i];

		if (phdr->p_type != PT_LOAD)
			continue;

		if (!phdr->p_memsz || phdr->p_filesz > phdr->p_memsz) {
			pr_err("PT_LOAD has invalid file or memory size\n");
			return -ENOEXEC;
		}
		if (!IS_ALIGNED(phdr->p_paddr, PAGE_SIZE)) {
			pr_err("PT_LOAD physical address is not page aligned\n");
			return -ENOEXEC;
		}
		if (phdr->p_align > 1 &&
		    (!is_power_of_2(phdr->p_align) ||
		     !IS_ALIGNED(phdr->p_paddr, phdr->p_align))) {
			pr_err("PT_LOAD has invalid alignment\n");
			return -ENOEXEC;
		}
		for (j = 0; j < i; j++) {
			const struct elf_phdr *other = &elf_info->proghdrs[j];

			if (other->p_type != PT_LOAD)
				continue;
			if (phdr->p_paddr < other->p_paddr + other->p_memsz &&
			    other->p_paddr < phdr->p_paddr + phdr->p_memsz) {
				pr_err("PT_LOAD physical ranges overlap\n");
				return -ENOEXEC;
			}
		}

		lowest = min_t(unsigned long, lowest, phdr->p_paddr);
		highest = max_t(unsigned long, highest,
				phdr->p_paddr + phdr->p_memsz);
		align = max_t(unsigned long, align, phdr->p_align);
		loaded = true;
	}

	if (!loaded)
		return -ENOEXEC;
	if (highest - lowest > ULONG_MAX - (PAGE_SIZE - 1))
		return -EOVERFLOW;
	if (!IS_ALIGNED(lowest, align)) {
		pr_err("PT_LOAD layout cannot preserve segment alignment\n");
		return -ENOEXEC;
	}

	*lowest_addr = lowest;
	*image_size = PAGE_ALIGN(highest - lowest);
	if (*image_size >> PAGE_SHIFT > totalram_pages() / 2) {
		pr_err("PT_LOAD span consumes more than half of system memory\n");
		return -E2BIG;
	}
	*image_align = align;
	return 0;
}

static int elf64_load_kernel(struct kimage *image,
			     const struct elfhdr *ehdr,
			     const struct kexec_elf_info *elf_info,
			     unsigned long *lowest_addr,
			     unsigned long *load_addr,
			     unsigned long *load_size,
			     void **kernel_buf)
{
	struct kexec_buf kbuf = {
		.image = image,
		.buf_min = SZ_1M,
		.buf_max = ULONG_MAX,
		.top_down = true,
	};
	unsigned long image_size, image_align;
	void *buf;
	int i, ret;

	ret = elf64_image_layout(ehdr, elf_info, lowest_addr, &image_size,
				 &image_align);
	if (ret)
		return ret;

	buf = kvzalloc(image_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	for (i = 0; i < ehdr->e_phnum; i++) {
		const struct elf_phdr *phdr = &elf_info->proghdrs[i];
		unsigned long offset;

		if (phdr->p_type != PT_LOAD)
			continue;

		offset = phdr->p_paddr - *lowest_addr;
		if (offset > image_size ||
		    phdr->p_filesz > image_size - offset) {
			ret = -EOVERFLOW;
			goto out_free_buf;
		}
		memcpy((char *)buf + offset,
		       elf_info->buffer + phdr->p_offset,
		       phdr->p_filesz);

		kexec_dprintk("Loaded PT_LOAD at 0x%llx bufsz=0x%llx memsz=0x%llx\n",
			      phdr->p_paddr, phdr->p_filesz, phdr->p_memsz);
	}

	kbuf.buffer = buf;
	kbuf.bufsz = image_size;
	kbuf.memsz = image_size;
	kbuf.buf_align = image_align;
	kbuf.mem = KEXEC_BUF_MEM_UNKNOWN;
	ret = kexec_add_buffer(&kbuf);
	if (ret)
		goto out_free_buf;

	*load_addr = kbuf.mem;
	*load_size = image_size;
	*kernel_buf = buf;
	return 0;

out_free_buf:
	kvfree(buf);
	return ret;
}

static int elf64_setup_purgatory(struct kimage *image,
				 unsigned long entry,
				 unsigned long bootparam_load_addr)
{
	struct kexec_entry64_regs regs64;
	void *stack;
	int ret;

	ret = kexec_purgatory_get_set_symbol(image, "entry64_regs", &regs64,
					     sizeof(regs64), 1);
	if (ret)
		return ret;

	regs64.rbx = 0;
	regs64.rsi = bootparam_load_addr;
	regs64.rip = entry;

	stack = kexec_purgatory_get_symbol_addr(image, "stack_end");
	if (IS_ERR(stack)) {
		pr_err("Could not find address of symbol stack_end\n");
		return -EINVAL;
	}

	regs64.rsp = (unsigned long)stack;
	return kexec_purgatory_get_set_symbol(image, "entry64_regs", &regs64,
					      sizeof(regs64), 0);
}

static void *elf64_load(struct kimage *image, char *kernel,
			unsigned long kernel_len, char *initrd,
			unsigned long initrd_len, char *cmdline,
			unsigned long cmdline_len)
{
	struct kexec_buf kbuf = {
		.image = image,
		.buf_max = ULONG_MAX,
		.top_down = true,
	};
	struct kexec_buf pbuf = {
		.image = image,
		.buf_min = MIN_PURGATORY_ADDR,
		.buf_max = ULONG_MAX,
		.top_down = true,
	};
	unsigned long bootparam_load_addr, initrd_load_addr, entry;
	unsigned long kernel_load_addr, kernel_size, lowest_addr;
	unsigned long entry_offset;
	unsigned long params_cmdline_sz;
	unsigned int efi_map_offset, efi_map_sz, setup_data_offset;
	struct kexec_elf_info elf_info = {};
	struct elf64_data *ldata;
	struct boot_params *params;
	struct elfhdr ehdr;
	int ret;

	if (!cmdline_len || cmdline_len > COMMAND_LINE_SIZE)
		return ERR_PTR(-EINVAL);

#ifdef CONFIG_MODULE_SIG_FORMAT
	ret = kexec_elf_payload_len(kernel, kernel_len, &kernel_len);
	if (ret)
		return ERR_PTR(ret);
#endif

	ret = kexec_build_elf_info(kernel, kernel_len, &ehdr, &elf_info);
	if (ret)
		return ERR_PTR(ret);

	ret = elf64_validate_header(&ehdr);
	if (ret)
		goto out_free_elf;
	if (!IS_ENABLED(CONFIG_RELOCATABLE)) {
		ret = -EOPNOTSUPP;
		goto out_free_elf;
	}

	ret = elf64_entry_address(&ehdr, &elf_info, &entry);
	if (ret)
		goto out_free_elf;

#ifdef CONFIG_CRASH_DUMP
	if (image->type == KEXEC_TYPE_CRASH) {
		ret = crash_load_segments(image);
		if (ret)
			goto out_free_elf;

		ret = crash_load_dm_crypt_keys(image);
		if (ret == -ENOENT) {
			kexec_dprintk("No dm crypt key to load\n");
		} else if (ret) {
			pr_err("Failed to load dm crypt keys\n");
			goto out_free_elf;
		}
	}
#endif

	ldata = kzalloc(sizeof(*ldata), GFP_KERNEL);
	if (!ldata) {
		ret = -ENOMEM;
		goto out_free_elf;
	}

	ret = elf64_load_kernel(image, &ehdr, &elf_info, &lowest_addr,
				&kernel_load_addr, &kernel_size,
				&ldata->kernel_buf);
	if (ret)
		goto out_free_ldata;

	if (entry < lowest_addr) {
		ret = -ENOEXEC;
		goto out_free_ldata;
	}
	entry_offset = entry - lowest_addr;
	if (entry_offset >= kernel_size ||
	    kernel_load_addr > ULONG_MAX - entry_offset) {
		ret = -ENOEXEC;
		goto out_free_ldata;
	}
	entry = kernel_load_addr + entry_offset;

	ret = kexec_load_purgatory(image, &pbuf);
	if (ret) {
		pr_err("Loading purgatory failed\n");
		goto out_free_ldata;
	}

	efi_map_sz = efi_get_runtime_map_size();
	params_cmdline_sz = sizeof(*params) + cmdline_len +
			    X86_KEXEC_ELFCOREHDR_STR_LEN;
	if (image->dm_crypt_keys_addr)
		params_cmdline_sz += X86_KEXEC_DMCRYPTKEYS_STR_LEN;
	if (params_cmdline_sz - sizeof(*params) > COMMAND_LINE_SIZE) {
		ret = -EINVAL;
		goto out_free_ldata;
	}
	params_cmdline_sz = ALIGN(params_cmdline_sz, 16);
	kbuf.bufsz = params_cmdline_sz + ALIGN(efi_map_sz, 16) +
		      sizeof(struct setup_data) + sizeof(struct efi_setup_data) +
		      sizeof(struct setup_data) + X86_KEXEC_RNG_SEED_LENGTH;

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
	if (!params) {
		ret = -ENOMEM;
		goto out_free_ldata;
	}

	efi_map_offset = params_cmdline_sz;
	setup_data_offset = efi_map_offset + ALIGN(efi_map_sz, 16);

	kbuf.buffer = params;
	kbuf.memsz = kbuf.bufsz;
	kbuf.buf_align = 16;
	kbuf.buf_min = MIN_BOOTPARAM_ADDR;
	kbuf.mem = KEXEC_BUF_MEM_UNKNOWN;
	ret = kexec_add_buffer(&kbuf);
	if (ret)
		goto out_free_params;
	bootparam_load_addr = kbuf.mem;

	if (initrd) {
		kbuf.buffer = initrd;
		kbuf.bufsz = initrd_len;
		kbuf.memsz = initrd_len;
		kbuf.buf_align = PAGE_SIZE;
		kbuf.buf_min = MIN_INITRD_LOAD_ADDR;
		kbuf.mem = KEXEC_BUF_MEM_UNKNOWN;
		ret = kexec_add_buffer(&kbuf);
		if (ret)
			goto out_free_params;
		initrd_load_addr = kbuf.mem;
		x86_kexec_setup_initrd(params, initrd_load_addr, initrd_len);
	}

	x86_kexec_setup_cmdline(image, params, bootparam_load_addr,
				sizeof(*params), cmdline, cmdline_len);
	params->hdr.type_of_loader = 0x0d << 4;
	params->hdr.loadflags = 0;

	ret = elf64_setup_purgatory(image, entry, bootparam_load_addr);
	if (ret)
		goto out_free_params;

	ret = x86_kexec_setup_boot_parameters(image, params,
					      bootparam_load_addr,
					      efi_map_offset, efi_map_sz,
					      setup_data_offset);
	if (ret)
		goto out_free_params;

	ldata->bootparams_buf = params;
	kexec_free_elf_info(&elf_info);
	return ldata;

out_free_params:
	kvfree(params);
out_free_ldata:
	kvfree(ldata->kernel_buf);
	kfree(ldata);
out_free_elf:
	kexec_free_elf_info(&elf_info);
	return ERR_PTR(ret);
}

static int elf64_cleanup(void *loader_data)
{
	struct elf64_data *ldata = loader_data;

	if (!ldata)
		return 0;

	kvfree(ldata->bootparams_buf);
	kvfree(ldata->kernel_buf);
	return 0;
}

const struct kexec_file_ops kexec_elf64_ops = {
	.probe = elf64_probe,
	.load = elf64_load,
	.cleanup = elf64_cleanup,
#ifdef CONFIG_KEXEC_ELF_VERIFY_SIG
	.verify_sig = kexec_kernel_verify_elf_sig,
#endif
};
