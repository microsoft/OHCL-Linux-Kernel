/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2023, Microsoft Corporation.
 */

#include <linux/linkage.h>

/*
 * Put this in .rodata since it has an unprotected indirect jump. It
 * is only used while the page tables are configured to allow execute
 * of any page.
 */
	.section ".rodata", "a", @progbits
SYM_CODE_START(hv_tdx_trampoline)
        /* Clear the start_gate value. */
        movl    $0, (%r8)
        jmp     *%r9
SYM_CODE_END(hv_tdx_trampoline)
