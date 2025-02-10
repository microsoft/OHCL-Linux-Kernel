/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_IDLE_H
#define _ASM_ARM64_IDLE_H

void noinstr default_idle(void);
void noinstr arch_cpu_idle(void);
void noinstr mshv_vtl_set_idle(void (*idle)(void));

#endif
