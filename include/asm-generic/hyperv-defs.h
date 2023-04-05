/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_HYPERV_DEFS_H
#define _ASM_GENERIC_HYPERV_DEFS_H

/*
 * There are cases where Microsoft Hypervisor ABIs are needed which may not be
 * stable or present in the Hyper-V TLFS document. E.g. the mshv_root driver.
 *
 * As these interfaces are unstable and may differ from hyperv-tlfs.h, they
 * must be kept separate and independent.
 *
 * However, code from files that depend on hyperv-tlfs.h (such as mshyperv.h)
 * is still needed, so work around the issue by conditionally including the
 * correct definitions.
 *
 * Note: Since they are independent of each other, there are many definitions
 * duplicated in both hyperv-tlfs.h and uapi/hyperv/hv*.h files.
 */
#ifdef HV_HYPERV_DEFS
#include <uapi/hyperv/hvhdk.h>
#else
#include <asm/hyperv-tlfs.h>
#endif

#endif /* _ASM_GENERIC_HYPERV_DEFS_H */

