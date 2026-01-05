#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Configure kernel with menuconfig in reproducible environment

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_OUTPUT="${BUILD_OUTPUT:-${KERNEL_ROOT}/build}"

# Reproducible build environment
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1609459200}"
export LANG="C.UTF-8"
export LC_ALL="C.UTF-8"
export TZ="UTC"
export KBUILD_BUILD_USER="${KBUILD_BUILD_USER:-builder}"
export KBUILD_BUILD_HOST="${KBUILD_BUILD_HOST:-nixos}"

echo "Opening kernel configuration menu..."
echo "Build output: ${BUILD_OUTPUT}"

mkdir -p "${BUILD_OUTPUT}"

cd "${KERNEL_ROOT}"

# Load existing config if available
if [ -f "${BUILD_OUTPUT}/.config" ]; then
    echo "Loading existing config from ${BUILD_OUTPUT}/.config"
else
    echo "No existing config found, starting with defconfig"
    make O="${BUILD_OUTPUT}" defconfig
fi

# Open menuconfig
make O="${BUILD_OUTPUT}" menuconfig

echo ""
echo "Configuration saved to: ${BUILD_OUTPUT}/.config"
echo "To build with this config, run: ./scripts/nix-build.sh"
