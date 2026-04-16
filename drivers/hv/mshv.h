/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023, Microsoft Corporation.
 */

#ifndef _MSHV_H_
#define _MSHV_H_

#include <linux/stddef.h>
#include <linux/string.h>
#include <hyperv/hvhdk.h>

#define mshv_field_nonzero(STRUCT, MEMBER) \
	memchr_inv(&((STRUCT).MEMBER), \
		   0, sizeof_field(typeof(STRUCT), MEMBER))

int hv_call_get_partition_property(u64 partition_id, u64 property_code,
				   u64 *property_value);

#endif /* _MSHV_H */
