#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

if [ "$(uname -m)" != "x86_64" ]; then
	echo "x86-64 only [SKIP]"
	exit 4
fi

if [ -z "${KEXEC_VMLINUX:-}" ]; then
	echo "set KEXEC_VMLINUX to an x86-64 vmlinux image [SKIP]"
	exit 4
fi

if [ ! -r "$KEXEC_VMLINUX" ]; then
	echo "$KEXEC_VMLINUX is not readable [SKIP]"
	exit 4
fi

KERNEL_IMAGE="$KEXEC_VMLINUX"
export KERNEL_IMAGE
exec ./test_kexec_file_load.sh
