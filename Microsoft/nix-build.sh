#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Reproducible kernel build script for NixOS
# This script ensures consistent build environment for reproducible builds
# Automatically sets up Nix on first run using bundled nix-user-chroot

set -euo pipefail

# Script directory (need this early for local nix detection)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Local nix paths
NIX_LOCAL_DIR="${SCRIPT_DIR}/.nix-local"
NIX_STORE_DIR="${NIX_LOCAL_DIR}/nix"
NIX_BIN_DIR="${SCRIPT_DIR}/nix-bin"
NIX_VERSION="2.24.10"

# Function to set up Nix automatically on first run
setup_nix_if_needed() {
    # Check if Nix store already exists
    if [ -d "${NIX_STORE_DIR}/store" ]; then
        return 0
    fi

    echo ">>> Setting up Nix environment (first run)..."

    # Detect architecture
    ARCH="$(uname -m)"
    case "${ARCH}" in
        x86_64|amd64)
            ARCH="x86_64"
            NIX_ARCH="x86_64-linux"
            ;;
        aarch64|arm64)
            ARCH="aarch64"
            NIX_ARCH="aarch64-linux"
            ;;
        *)
            echo "Error: Unsupported architecture: ${ARCH}"
            exit 1
            ;;
    esac

    # Check for bundled nix-user-chroot
    local NIX_USER_CHROOT_SRC="${NIX_BIN_DIR}/nix-user-chroot-${ARCH}"
    if [ ! -x "${NIX_USER_CHROOT_SRC}" ]; then
        echo "Error: nix-user-chroot not found at ${NIX_USER_CHROOT_SRC}"
        echo "Please ensure Microsoft/nix-bin/ contains the required binaries."
        exit 1
    fi

    # Create local directories
    mkdir -p "${NIX_LOCAL_DIR}"
    mkdir -p "${NIX_STORE_DIR}"

    # Copy nix-user-chroot to local dir
    cp "${NIX_USER_CHROOT_SRC}" "${NIX_LOCAL_DIR}/nix-user-chroot"
    chmod +x "${NIX_LOCAL_DIR}/nix-user-chroot"

    # Check for bundled Nix tarball or download it
    local NIX_TARBALL="${NIX_BIN_DIR}/nix-${NIX_VERSION}-${NIX_ARCH}.tar.xz"
    local NIX_TARBALL_LOCAL="${NIX_LOCAL_DIR}/nix.tar.xz"

    if [ -f "${NIX_TARBALL}" ]; then
        echo "Using bundled Nix tarball..."
        cp "${NIX_TARBALL}" "${NIX_TARBALL_LOCAL}"
    else
        echo "Downloading Nix ${NIX_VERSION}..."
        local NIX_URL="https://releases.nixos.org/nix/nix-${NIX_VERSION}/nix-${NIX_VERSION}-${NIX_ARCH}.tar.xz"
        if ! curl -fsSL "${NIX_URL}" -o "${NIX_TARBALL_LOCAL}"; then
            echo "Error: Failed to download Nix"
            exit 1
        fi
    fi

    # Extract Nix
    echo "Extracting Nix..."
    tar -xf "${NIX_TARBALL_LOCAL}" -C "${NIX_LOCAL_DIR}"
    local NIX_EXTRACTED=$(ls -d "${NIX_LOCAL_DIR}"/nix-*-linux 2>/dev/null | head -1)

    # Install Nix into local store using nix-user-chroot
    echo "Installing Nix to local store..."
    "${NIX_LOCAL_DIR}/nix-user-chroot" "${NIX_STORE_DIR}" "${NIX_EXTRACTED}/install" --no-daemon

    # Clean up
    rm -f "${NIX_TARBALL_LOCAL}"
    rm -rf "${NIX_EXTRACTED}"

    # Enable flakes
    mkdir -p ~/.config/nix
    if ! grep -q "experimental-features.*flakes" ~/.config/nix/nix.conf 2>/dev/null; then
        echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf
    fi

    echo ">>> Nix setup complete!"
}

# Auto-detect and enter Nix environment if not already in one
if [ -z "${IN_NIX_SHELL:-}" ]; then
    # Set up Nix if needed (first run)
    setup_nix_if_needed

    NIX_USER_CHROOT="${NIX_LOCAL_DIR}/nix-user-chroot"

    # Verify nix-user-chroot is available
    if [ ! -x "${NIX_USER_CHROOT}" ]; then
        echo "Error: nix-user-chroot not found at ${NIX_USER_CHROOT}"
        echo "Run the setup again or check Microsoft/nix-bin/ directory"
        exit 1
    fi

    if [ ! -d "${NIX_STORE_DIR}/store" ]; then
        echo "Error: Nix store not found at ${NIX_STORE_DIR}"
        echo "Setup may have failed. Try removing ${NIX_LOCAL_DIR} and running again."
        exit 1
    fi

    # Use nix-user-chroot to run nix develop (this maps NIX_STORE_DIR to /nix)
    cd "${KERNEL_ROOT}"
    exec "${NIX_USER_CHROOT}" "${NIX_STORE_DIR}" bash -c '
        # Source nix profile from the mapped /nix directory
        if [ -f ~/.nix-profile/etc/profile.d/nix.sh ]; then
            . ~/.nix-profile/etc/profile.d/nix.sh
        elif [ -f /nix/var/nix/profiles/default/etc/profile.d/nix.sh ]; then
            . /nix/var/nix/profiles/default/etc/profile.d/nix.sh
        fi
        exec nix --extra-experimental-features "nix-command flakes" develop --command "$@"
    ' -- "$0" "$@"
fi

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
MAKE_JOBS="${MAKE_JOBS:-$(nproc)}"

# Reproducible build environment
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1609459200}"
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

main() {
    log_info "Starting reproducible kernel build..."
    log_info "Kernel source: ${KERNEL_ROOT}"
    log_info "Build output: ${BUILD_OUTPUT}"
    log_info "Reproducible environment:"
    log_info "  SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"
    log_info "  KBUILD_BUILD_USER=${KBUILD_BUILD_USER}"
    log_info "  KBUILD_BUILD_HOST=${KBUILD_BUILD_HOST}"

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

    log_info "Build completed successfully!"
    log_info "Build artifacts are in: ${BUILD_OUTPUT}"

    # Print sha256sum of vmlinux for reproducibility verification
    if [ -f "${BUILD_OUTPUT}/vmlinux" ]; then
        log_info "vmlinux sha256sum:"
        sha256sum "${BUILD_OUTPUT}/vmlinux"
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
        echo "  MAKE_JOBS           - Number of parallel jobs (default: nproc)"
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
