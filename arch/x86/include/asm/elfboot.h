/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_ELFBOOT_H
#define _ASM_X86_ELFBOOT_H

#include <linux/types.h>

#define X86_ELFBOOT_NOTE_NAME "Linux.x86.elfboot.rfc"
#define X86_ELFBOOT_NOTE_TYPE 1
#define X86_ELFBOOT_VERSION 1

#define X86_ELFBOOT_PHYS_RELOCATE 0x00000001U
#define X86_ELFBOOT_CMDLINE_OVERRIDE 0x00000002U
#define X86_ELFBOOT_FLAGS (X86_ELFBOOT_PHYS_RELOCATE | \
			 X86_ELFBOOT_CMDLINE_OVERRIDE)

struct x86_elfboot {
	__u32 version;
	__u32 flags;
	__u32 cmdline_size;
	__u32 alignment;
	__u32 phys_bits_4;
	__u32 phys_bits_5;
	__u64 entry;
};

#endif
