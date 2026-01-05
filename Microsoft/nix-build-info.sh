#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Extract and display build information from a kernel build

set -euo pipefail

BUILD_DIR="${1:-build}"

if [ ! -d "${BUILD_DIR}" ]; then
    echo "Error: Build directory not found: ${BUILD_DIR}"
    echo "Usage: $0 [build-directory]"
    exit 1
fi

if [ -f "${BUILD_DIR}/build-info.txt" ]; then
    cat "${BUILD_DIR}/build-info.txt"
else
    echo "No build-info.txt found in ${BUILD_DIR}"
    echo ""
    echo "Available files:"
    ls -lh "${BUILD_DIR}" | head -20
fi

echo ""
echo "Checksums:"
if [ -f "${BUILD_DIR}/kernel-image.sha256" ]; then
    cat "${BUILD_DIR}/kernel-image.sha256"
fi

# Find and display kernel image info
for img in "${BUILD_DIR}"/arch/*/boot/Image \
           "${BUILD_DIR}"/arch/*/boot/bzImage \
           "${BUILD_DIR}"/arch/*/boot/zImage \
           "${BUILD_DIR}"/vmlinux; do
    if [ -f "$img" ]; then
        echo ""
        echo "Kernel image: $img"
        ls -lh "$img"
        file "$img" 2>/dev/null || true
    fi
done
