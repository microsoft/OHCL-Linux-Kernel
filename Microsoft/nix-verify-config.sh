#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Verify kernel configuration has reproducible build settings enabled

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIG_FILE="${1:-${KERNEL_ROOT}/build/.config}"

if [ ! -f "${CONFIG_FILE}" ]; then
    echo "Error: Config file not found: ${CONFIG_FILE}"
    echo "Usage: $0 [config-file]"
    exit 1
fi

echo "Checking kernel config for reproducibility settings..."
echo "Config file: ${CONFIG_FILE}"
echo ""

check_config() {
    local option="$1"
    local expected="$2"
    local description="$3"

    if grep -q "^${option}=${expected}$" "${CONFIG_FILE}"; then
        echo "✓ ${option}=${expected} - ${description}"
        return 0
    elif grep -q "^# ${option} is not set$" "${CONFIG_FILE}"; then
        echo "✗ ${option} is not set - ${description}"
        return 1
    else
        echo "? ${option} - not found or has different value"
        grep "^${option}=" "${CONFIG_FILE}" || echo "  (not set)"
        return 1
    fi
}

echo "=== Debug Info Settings ==="
# For reproducibility, debug info should be minimal or normalized
check_config "CONFIG_DEBUG_INFO_NONE" "y" "No debug info (most reproducible)" || \
check_config "CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT" "y" "Default debug info" || \
echo "  Note: Debug info settings can affect reproducibility"

echo ""
echo "=== Module Settings ==="
check_config "CONFIG_MODULE_SIG" "n" "Module signing disabled (for testing)" || \
echo "  Note: Module signing can be enabled for production"

echo ""
echo "=== Timestamp Settings ==="
# Check if kernel is built without embedded timestamps
if grep -q "CONFIG_BUILD_SALT" "${CONFIG_FILE}"; then
    echo "  CONFIG_BUILD_SALT is set (can affect reproducibility)"
fi

echo ""
echo "=== Recommendations for Reproducible Builds ==="
echo "  - Use SOURCE_DATE_EPOCH environment variable"
echo "  - Set KBUILD_BUILD_USER and KBUILD_BUILD_HOST consistently"
echo "  - Disable random options like CONFIG_GCC_PLUGIN_RANDSTRUCT"
echo "  - Use consistent toolchain versions (handled by Nix)"
echo "  - Avoid build-time hostname/username embedding"

echo ""
echo "Note: The build scripts automatically set reproducible build flags."
echo "See scripts/nix-build.sh for the complete reproducible build environment."
