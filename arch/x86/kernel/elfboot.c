// SPDX-License-Identifier: GPL-2.0-only

#include <linux/elfnote.h>
#include <linux/sizes.h>

#include <asm/elfboot.h>
#include <asm/setup.h>
#include <asm/sparsemem.h>

extern const unsigned char startup_64[];

#ifdef CONFIG_CMDLINE_BOOL
#define ELFBOOT_CMDLINE CONFIG_CMDLINE
#else
#define ELFBOOT_CMDLINE ""
#endif

struct x86_elfboot_note {
	struct x86_elfboot boot;
	char cmdline[sizeof(ELFBOOT_CMDLINE)];
} __packed;

static_assert(sizeof(struct x86_elfboot) == 32);
static_assert(sizeof(ELFBOOT_CMDLINE) <= COMMAND_LINE_SIZE);

#ifndef CONFIG_CMDLINE_FROM_BOOTCONFIG
ELFNOTE64(X86_ELFBOOT_NOTE_NAME, X86_ELFBOOT_NOTE_TYPE,
	  ((struct x86_elfboot_note) {
		.boot = {
			.version = X86_ELFBOOT_VERSION,
			.flags = X86_ELFBOOT_PHYS_RELOCATE |
				(IS_ENABLED(CONFIG_CMDLINE_OVERRIDE) ?
				 X86_ELFBOOT_CMDLINE_OVERRIDE : 0),
			.cmdline_size = COMMAND_LINE_SIZE - 1,
			.alignment = SZ_2M,
			.phys_bits_4 = MAX_PHYSMEM_BITS_L4,
			.phys_bits_5 = MAX_PHYSMEM_BITS_L5,
			.entry = (unsigned long)startup_64,
		},
		.cmdline = ELFBOOT_CMDLINE,
	  }));
#endif
