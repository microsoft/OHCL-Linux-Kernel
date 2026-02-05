#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Reproducible kernel build script for NixOS
# This script ensures consistent build environment for reproducible builds

set -euo pipefail

# Auto-detect and enter Nix environment if not already in one
if [ -z "${IN_NIX_SHELL:-}" ]; then
    # Check if nix is available
    if ! command -v nix &> /dev/null; then
        # Try to source nix profile
        if [ -f ~/.nix-profile/etc/profile.d/nix.sh ]; then
            . ~/.nix-profile/etc/profile.d/nix.sh
        else
            echo "Error: Nix is not installed or not in PATH"
            echo "Please run: ./Microsoft/nix-setup.sh"
            exit 1
        fi
    fi

    # Re-execute this script inside nix develop with experimental features enabled
    # Use --ignore-environment (-i) to create a pure shell that excludes system packages
    # Keep essential variables: HOME (for temp files), USER (for build metadata), TERM (for output)
    # Keep SOURCE_DATE_EPOCH for reproducible builds
    exec nix --extra-experimental-features "nix-command flakes" develop \
        -i \
        -k HOME \
        -k USER \
        -k TERM \
        -k SOURCE_DATE_EPOCH \
        --command "$0" "$@"
fi

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_ROOT_ORIGINAL="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Fixed build path for reproducibility - ensures identical paths across machines
FIXED_BUILD_PATH="${FIXED_BUILD_PATH:-/tmp/ohcl-kernel-build}"
KERNEL_ROOT="${FIXED_BUILD_PATH}/src"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Parse architecture and build type from command line
ARCH_TYPE="${1:-x64}"  # Default to x64
BUILD_TYPE="${2:-}"     # Optional: cvm

# Validate architecture
case "${ARCH_TYPE}" in
    x64|x86_64|amd64)
        ARCH_TYPE="x64"
        KERNEL_ARCH="x86_64"
        ;;
    arm64|aarch64)
        ARCH_TYPE="arm64"
        KERNEL_ARCH="arm64"
        CROSS_COMPILE="aarch64-linux-gnu-"
        ;;
    build|clean|help|--help|-h)
        # These are commands, not architectures - will be handled later
        ;;
    *)
        log_error "Unknown architecture: ${ARCH_TYPE}"
        log_error "Supported: x64, arm64"
        exit 1
        ;;
esac

# Build configuration
BUILD_OUTPUT="${BUILD_OUTPUT:-${KERNEL_ROOT}/build}"

# Reproducible build environment
# Always use timestamp of the top commit for SOURCE_DATE_EPOCH
# Override any value set by Nix itself
export SOURCE_DATE_EPOCH="$(git -C "${KERNEL_ROOT_ORIGINAL}" log -1 --pretty=%ct)"
export LANG="C.UTF-8"
export LC_ALL="C.UTF-8"
export TZ="UTC"

# Flag to indicate reproducible build mode (used by build-hcl-kernel.sh)
export REPRODUCIBLE_BUILD=1

# Kernel-specific reproducible flags
export KBUILD_BUILD_TIMESTAMP="@${SOURCE_DATE_EPOCH}"
export KBUILD_BUILD_USER="${KBUILD_BUILD_USER:-builder}"
export KBUILD_BUILD_HOST="${KBUILD_BUILD_HOST:-nixos}"
export KBUILD_BUILD_VERSION="1"

# Cleanup function to remove temporary build directory
cleanup_build_path() {
    if [ -n "${FIXED_BUILD_PATH}" ] && [ -d "${FIXED_BUILD_PATH}" ]; then
        log_info "Cleaning up temporary build directory: ${FIXED_BUILD_PATH}"
        rm -rf "${FIXED_BUILD_PATH}"
    fi
}

# Set trap to cleanup on exit (success or failure)
trap cleanup_build_path EXIT

main() {
    log_info "Starting reproducible kernel build..."
    log_info "Original source: ${KERNEL_ROOT_ORIGINAL}"
    log_info "Fixed build path: ${KERNEL_ROOT}"
    log_info "Reproducible environment:"
    log_info "  SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"
    log_info "  KBUILD_BUILD_USER=${KBUILD_BUILD_USER}"
    log_info "  KBUILD_BUILD_HOST=${KBUILD_BUILD_HOST}"

    # Copy source to fixed path for reproducibility
    # This ensures the same paths are embedded in binaries regardless of where source is located
    log_info "Copying source to fixed build path..."
    rm -rf "${FIXED_BUILD_PATH}"
    mkdir -p "${FIXED_BUILD_PATH}"
    # Use anchored excludes (/) to avoid matching subdirectories like tools/build
    rsync -a --exclude='/.git' --exclude='/build' --exclude='/out' \
        "${KERNEL_ROOT_ORIGINAL}/" "${KERNEL_ROOT}/"
    log_info "Source copied to ${KERNEL_ROOT}"

    # Set environment for reproducibility
    export KBUILD_BUILD_TIMESTAMP="${KBUILD_BUILD_TIMESTAMP}"
    export KBUILD_BUILD_USER="${KBUILD_BUILD_USER}"
    export KBUILD_BUILD_HOST="${KBUILD_BUILD_HOST}"
    export KBUILD_BUILD_VERSION="${KBUILD_BUILD_VERSION}"

    # Unset Nix-specific compiler flags that might interfere with kernel build
    unset NIX_CFLAGS_COMPILE
    unset NIX_CFLAGS_COMPILE_FOR_TARGET
    unset NIX_LDFLAGS
    unset NIX_LDFLAGS_FOR_TARGET

    cd "${KERNEL_ROOT}"

    # Handle CVM build if requested
    if [ "${BUILD_TYPE}" = "cvm" ]; then
        log_info "Building with CVM config..."
        "${KERNEL_ROOT}/Microsoft/merge-cvm-config.sh"
    fi

    # Invoke the existing build-hcl-kernel.sh script
    log_info "Invoking build-hcl-kernel.sh..."
    "${KERNEL_ROOT}/Microsoft/build-hcl-kernel.sh" "${ARCH_TYPE}"

    # Copy build artifacts back to original location
    log_info "Copying build artifacts back to original location..."
    mkdir -p "${KERNEL_ROOT_ORIGINAL}/out"
    rsync -a "${KERNEL_ROOT}/out/" "${KERNEL_ROOT_ORIGINAL}/out/"

    # Copy build directory back to original location
    log_info "Copying build directory back to original location..."
    mkdir -p "${KERNEL_ROOT_ORIGINAL}/../build"
    rsync -a "${FIXED_BUILD_PATH}/build/" "${KERNEL_ROOT_ORIGINAL}/../build/"

    log_info "Build completed successfully!"
    log_info "Build artifacts are in: ${KERNEL_ROOT_ORIGINAL}/out"

    # Print sha256sum of vmlinux for reproducibility verification
    # Check the STRIPPED vmlinux (final post-processed output)
    # build-hcl-kernel.sh creates stripped vmlinux at $BUILD_DIR/vmlinux
    local VMLINUX_PATH="${KERNEL_ROOT_ORIGINAL}/../build/vmlinux"
    if [ -f "${VMLINUX_PATH}" ]; then
        echo ""
        log_info "Reproducibility verification:"
        echo "  vmlinux sha256sum: $(sha256sum "${VMLINUX_PATH}" | cut -d' ' -f1)"
    fi
}

# Handle command line arguments
# Determine command (3rd arg for arch builds, or 1st arg if no arch specified)
COMMAND="${3:-build}"
if [ "${ARCH_TYPE}" = "build" ] || [ "${ARCH_TYPE}" = "clean" ] || [ "${ARCH_TYPE}" = "help" ] || [ "${ARCH_TYPE}" = "--help" ] || [ "${ARCH_TYPE}" = "-h" ]; then
    COMMAND="${ARCH_TYPE}"
    ARCH_TYPE="x64"  # Reset to default
fi
if [ "${BUILD_TYPE}" = "build" ] || [ "${BUILD_TYPE}" = "clean" ] || [ "${BUILD_TYPE}" = "help" ]; then
    COMMAND="${BUILD_TYPE}"
    BUILD_TYPE=""
fi

case "${COMMAND}" in
    build)
        main
        ;;
    clean)
        log_info "Cleaning build directory: ${BUILD_OUTPUT}"
        rm -rf "${BUILD_OUTPUT}"
        log_info "Clean completed"
        ;;
    help|--help|-h)
        echo "Usage: $0 [ARCH] [BUILD_TYPE] [COMMAND]"
        echo ""
        echo "Arguments:"
        echo "  ARCH        - Architecture: x64, arm64 (default: x64)"
        echo "  BUILD_TYPE  - Build type: cvm (optional)"
        echo "  COMMAND     - Command: build, clean, help (default: build)"
        echo ""
        echo "Examples:"
        echo "  $0 x64           - Build for x64"
        echo "  $0 arm64         - Build for arm64"
        echo "  $0 x64 cvm       - Build for x64 with CVM config"
        echo "  $0 arm64 cvm     - Build for arm64 with CVM config"
        echo ""
        echo "Commands:"
        echo "  build  - Build the kernel (default)"
        echo "  clean  - Clean build artifacts"
        echo "  help   - Show this help message"
        echo ""
        echo "Environment variables:"
        echo "  BUILD_OUTPUT        - Build output directory (default: ./build)"
        echo "  CONFIG_FILE_OVERRIDE - Override config file (default: auto-detect Microsoft config)"
        echo "  SOURCE_DATE_EPOCH   - Timestamp for reproducible builds"
        echo "  KBUILD_BUILD_USER   - Username for kernel build"
        echo "  KBUILD_BUILD_HOST   - Hostname for kernel build"
        ;;
    *)
        log_error "Unknown command: $1"
        log_info "Run '$0 help' for usage information"
        exit 1
        ;;
esac
