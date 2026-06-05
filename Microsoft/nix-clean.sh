#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Clean build artifacts

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "Cleaning build artifacts..."

# Remove build directories.
# build-hcl-kernel.sh writes to ${KERNEL_ROOT}/../build by default.
rm -rf "${KERNEL_ROOT}/../build"
rm -rf "${KERNEL_ROOT}/build"

# Clean in-tree builds
cd "${KERNEL_ROOT}"
make mrproper 2>/dev/null || true

echo "Clean completed!"
