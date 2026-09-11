/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_KEXEC_FILE_H
#define _ASM_X86_KEXEC_FILE_H

struct boot_params;
struct kimage;

#define X86_KEXEC_ELFCOREHDR_STR_LEN 30
#define X86_KEXEC_DMCRYPTKEYS_STR_LEN 31
#define X86_KEXEC_RNG_SEED_LENGTH 32

int x86_kexec_setup_initrd(struct boot_params *params,
			   unsigned long initrd_load_addr,
			   unsigned long initrd_len);
int x86_kexec_setup_cmdline(struct kimage *image, struct boot_params *params,
			    unsigned long bootparams_load_addr,
			    unsigned long cmdline_offset, char *cmdline,
			    unsigned long cmdline_len);
int x86_kexec_setup_boot_parameters(struct kimage *image,
				    struct boot_params *params,
				    unsigned long params_load_addr,
				    unsigned int efi_map_offset,
				    unsigned int efi_map_sz,
				    unsigned int setup_data_offset);

#endif /* _ASM_X86_KEXEC_FILE_H */
