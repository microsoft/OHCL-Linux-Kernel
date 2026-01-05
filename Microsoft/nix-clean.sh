#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Clean build artifacts

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "Cleaning build artifacts..."

# Remove build directories
rm -rf "${KERNEL_ROOT}/build"
rm -rf "${KERNEL_ROOT}/build-repro-1"
rm -rf "${KERNEL_ROOT}/build-repro-2"
rm -rf "${KERNEL_ROOT}/reproducibility-report"

# Clean in-tree builds
cd "${KERNEL_ROOT}"
make mrproper 2>/dev/null || true

echo "Clean completed!"
