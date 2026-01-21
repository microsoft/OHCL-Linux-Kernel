#!/bin/bash
#
# Build script for HCL kernel in Azure DevOps pipeline
# This script mirrors the structure of Microsoft/build-hcl-kernel.sh
# but implements the same functionality as the pipeline's inline build steps.
#
# This script is called ONLY for HCL product builds. Other products (WSL, mariner,
# lcow, lvbs) continue to use the inline pipeline logic.
#

set -eo pipefail

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Build HCL kernel for pipeline with specified configuration.

OPTIONS:
    -s, --source-dir DIR      Path to kernel source directory (required)
    -b, --build-dir DIR       Path to build output directory (required)
    -c, --config FILE         Path to kernel config file relative to source dir (required)
    -a, --arch ARCH           Target architecture: amd64 or arm64 (required)
    -k, --kernel-type TYPE    Kernel type: none or cvm (default: none)
    --compiler CC             Compiler to use (default: gcc)
    --scripts-dir DIR         Path to msft-lkt scripts directory (required for cvm)
    -h, --help                Show this help message

EXAMPLE:
    $0 -s /path/to/kernel-source -b /path/to/build -c Microsoft/hcl-x64.config -a amd64
    $0 -s /path/to/kernel-source -b /path/to/build -c Microsoft/hcl-arm64.config -a arm64 -k cvm

EOF
    exit 1
}

# Default values
KERNEL_TYPE="none"
COMPILER="gcc"
SCRIPTS_DIR=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--source-dir)
            SOURCE_DIR="$2"
            shift 2
            ;;
        -b|--build-dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        -c|--config)
            CONFIG="$2"
            shift 2
            ;;
        -a|--arch)
            ARCH="$2"
            shift 2
            ;;
        -k|--kernel-type)
            KERNEL_TYPE="$2"
            shift 2
            ;;
        --compiler)
            COMPILER="$2"
            shift 2
            ;;
        --scripts-dir)
            SCRIPTS_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            ;;
    esac
done

# Validate required arguments
if [[ -z "$SOURCE_DIR" ]] || [[ -z "$BUILD_DIR" ]] || [[ -z "$CONFIG" ]] || [[ -z "$ARCH" ]]; then
    echo "Error: Missing required arguments" >&2
    usage
fi

# Validate scripts-dir is provided for CVM builds
if [[ "$KERNEL_TYPE" == "cvm" ]] && [[ -z "$SCRIPTS_DIR" ]]; then
    echo "Error: --scripts-dir is required for CVM kernel builds" >&2
    usage
fi

# Validate architecture
if [[ "$ARCH" != "amd64" ]] && [[ "$ARCH" != "arm64" ]]; then
    echo "Error: Invalid architecture '$ARCH'. Must be 'amd64' or 'arm64'" >&2
    exit 1
fi

# Set architecture-specific variables
if [[ "$ARCH" == "amd64" ]]; then
    MAKE_ARCH="x86"
else
    MAKE_ARCH="arm64"
fi

# Resolve paths
SOURCE_DIR=$(realpath "$SOURCE_DIR")
BUILD_DIR=$(realpath "$BUILD_DIR")

# Define output directories (matching pipeline structure)
LINUX_HEADERS_DIR="$BUILD_DIR/linux-headers"
DEBUG_SYMBOL_DIR="$BUILD_DIR/debug_symbols"
LINUX_DIR="$BUILD_DIR/linux_dir"
LINUX_BOOT_DIR="$LINUX_DIR/boot"

echo "=============================================="
echo "HCL Kernel Pipeline Build Script"
echo "=============================================="
echo "Source directory:  $SOURCE_DIR"
echo "Build directory:   $BUILD_DIR"
echo "Config file:       $CONFIG"
echo "Architecture:      $ARCH (make arch: $MAKE_ARCH)"
echo "Kernel type:       $KERNEL_TYPE"
echo "Compiler:          $COMPILER"
echo "=============================================="

# Create output directories
mkdir -p "$BUILD_DIR"
mkdir -p "$LINUX_HEADERS_DIR"
mkdir -p "$DEBUG_SYMBOL_DIR"
mkdir -p "$LINUX_DIR"
mkdir -p "$LINUX_BOOT_DIR"

cd "$SOURCE_DIR"

#
# Step 0: CVM Config Merge (only for cvm kernel type)
#
merge_cvm_config() {
    echo ""
    echo ">>> Merging CVM config for HCL..."

    # Map architecture to config file naming
    if [[ "$ARCH" == "amd64" ]]; then
        CONFIG_ARCH="x64"
        BASE_CONFIG="hcl-x64.config"
        FRAGMENT_CONFIG="x64-cvm.config"
    else
        CONFIG_ARCH="arm64"
        BASE_CONFIG="hcl-arm64.config"
        FRAGMENT_CONFIG="arm64-cvm.config"
    fi

    cd "$SOURCE_DIR/Microsoft"

    # Verify config files exist
    if [[ ! -f "$BASE_CONFIG" ]]; then
        echo "Error: Base config file $BASE_CONFIG not found!" >&2
        exit 1
    fi
    if [[ ! -f "$FRAGMENT_CONFIG" ]]; then
        echo "Error: Fragment config file $FRAGMENT_CONFIG not found!" >&2
        exit 1
    fi

    # Copy base config to .config in source directory
    cp "$BASE_CONFIG" "$SOURCE_DIR/.config"

    # Merge the fragment configuration
    cd "$SOURCE_DIR"
    chmod +x "$SCRIPTS_DIR/merge_config_hcl.sh"
    "$SCRIPTS_DIR/merge_config_hcl.sh" -m .config "Microsoft/$FRAGMENT_CONFIG"

    # Ensure merged config is valid
    make olddefconfig

    # Move merged config back to Microsoft directory (overwrites original)
    mv .config "Microsoft/hcl-$CONFIG_ARCH.config"
    echo ">>> CVM config merged: Microsoft/hcl-$CONFIG_ARCH.config"

    cd "$SOURCE_DIR"
}

#
# Step 1: Build kernel
#
build_kernel() {
    echo ""
    echo ">>> Building kernel..."

    # For CVM kernel type, run mrproper first
    if [[ "$KERNEL_TYPE" == "cvm" ]]; then
        echo "Running make mrproper for CVM build..."
        make mrproper
    fi

    # Copy config to build directory
    cp "$CONFIG" "$BUILD_DIR/.config"

    # Run olddefconfig
    echo "Running olddefconfig..."
    make CC="$COMPILER" O="$BUILD_DIR" olddefconfig

    # Build kernel with all targets
    echo "Building kernel (make all)..."
    make LOCALVERSION="" CC="$COMPILER" O="$BUILD_DIR" -j "$(nproc)" all

    echo ">>> Kernel build complete"
}

#
# Step 2: Install headers
#
build_headers() {
    echo ""
    echo ">>> Installing kernel headers..."

    make CC="$COMPILER" O="$BUILD_DIR" ARCH="$MAKE_ARCH" \
        headers_install INSTALL_HDR_PATH="$LINUX_HEADERS_DIR"

    echo ">>> Headers installed to $LINUX_HEADERS_DIR"
}

#
# Step 3: Install modules
#
build_modules() {
    echo ""
    echo ">>> Installing kernel modules..."

    make CC="$COMPILER" O="$BUILD_DIR" ARCH="$MAKE_ARCH" \
        modules_install INSTALL_MOD_PATH="$LINUX_DIR"

    echo ">>> Modules installed to $LINUX_DIR"
}

#
# Step 4: Generate debug symbols
#
build_debug_symbols() {
    echo ""
    echo ">>> Generating debug symbols..."

    cd "$BUILD_DIR"

    # Copy vmlinux to debug symbol directory
    cp -a "$BUILD_DIR/vmlinux" "$DEBUG_SYMBOL_DIR/"

    # Generate kernel debug symbols
    echo "Extracting vmlinux debug symbols..."
    objcopy --only-keep-debug "$DEBUG_SYMBOL_DIR/vmlinux" \
        "$DEBUG_SYMBOL_DIR/vmlinux.debug"

    # Generate module debug symbols and strip modules
    echo "Processing module debug symbols..."
    for module_path in $(find "$BUILD_DIR" -name '*.ko'); do
        module=$(basename "$module_path")

        # Copy module to debug symbol directory
        cp -a "$module_path" "$DEBUG_SYMBOL_DIR/"

        # Extract debug symbols
        objcopy --only-keep-debug "$DEBUG_SYMBOL_DIR/$module" \
            "$DEBUG_SYMBOL_DIR/$module.debug"

        # Strip debug symbols from original module
        objcopy --strip-unneeded "$module_path"
    done

    echo ">>> Debug symbols generated in $DEBUG_SYMBOL_DIR"
}

#
# Step 5: Package kernel files to boot directory
#
package_kernel() {
    echo ""
    echo ">>> Packaging kernel files..."

    cd "$SOURCE_DIR"

    # Get kernel version
    KERNEL_VERSION=$(cat "$BUILD_DIR/include/config/kernel.release")
    echo "Kernel version: $KERNEL_VERSION"

    # Copy architecture-specific kernel image
    if [[ "$MAKE_ARCH" == "arm64" ]]; then
        cp -a "$BUILD_DIR/arch/arm64/boot/Image" \
            "$LINUX_BOOT_DIR/Image-$KERNEL_VERSION"
        echo "Copied Image to $LINUX_BOOT_DIR/Image-$KERNEL_VERSION"
    else
        cp -a "$BUILD_DIR/arch/x86/boot/bzImage" \
            "$LINUX_BOOT_DIR/vmlinuz-$KERNEL_VERSION"
        echo "Copied bzImage to $LINUX_BOOT_DIR/vmlinuz-$KERNEL_VERSION"
    fi

    # Strip and copy vmlinux
    echo "Stripping vmlinux..."
    objcopy --strip-all "$BUILD_DIR/vmlinux"
    cp -a "$BUILD_DIR/vmlinux" "$LINUX_BOOT_DIR/vmlinux-$KERNEL_VERSION"

    # Copy config and System.map
    cp -a "$BUILD_DIR/.config" "$LINUX_BOOT_DIR/config-$KERNEL_VERSION"
    cp -a "$BUILD_DIR/System.map" "$LINUX_BOOT_DIR/System.map-$KERNEL_VERSION"

    echo ">>> Kernel files packaged in $LINUX_BOOT_DIR"
}

#
# Main build sequence
#
main() {
    # Merge CVM config if building CVM kernel
    if [[ "$KERNEL_TYPE" == "cvm" ]]; then
        merge_cvm_config
    fi

    build_kernel
    build_headers
    build_modules
    build_debug_symbols
    package_kernel

    echo ""
    echo "=============================================="
    echo "Build completed successfully!"
    echo "=============================================="
    echo "Output locations:"
    echo "  Build output:    $BUILD_DIR"
    echo "  Boot files:      $LINUX_BOOT_DIR"
    echo "  Modules:         $LINUX_DIR/lib/modules/"
    echo "  Headers:         $LINUX_HEADERS_DIR"
    echo "  Debug symbols:   $DEBUG_SYMBOL_DIR"
    echo "=============================================="
}

# Run main
main
