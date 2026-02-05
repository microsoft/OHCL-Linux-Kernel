#!/bin/bash
#
# Build script for HCL kernel in Azure DevOps pipeline
# This script mirrors the structure of Microsoft/build-hcl-kernel.sh
# but implements the same functionality as the pipeline's inline build steps.
#
# This script is called ONLY for OHCL product builds.
#

set -eo pipefail

usage() {
    local exit_code="${1:-1}"
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
    --reproducible            Enable reproducible build mode (uses Nix environment)
    -h, --help                Show this help message

EXAMPLE:
    $0 -s /path/to/kernel-source -b /path/to/build -c Microsoft/hcl-x64.config -a amd64
    $0 -s /path/to/kernel-source -b /path/to/build -c Microsoft/hcl-arm64.config -a arm64 -k cvm
    $0 -s /path/to/kernel-source -b /path/to/build -c Microsoft/hcl-x64.config -a amd64 --reproducible

EOF
    exit "$exit_code"
}

# Default values
KERNEL_TYPE="none"
COMPILER="gcc"
SCRIPTS_DIR=""
REPRODUCIBLE_BUILD=""

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
        --reproducible)
            REPRODUCIBLE_BUILD="1"
            shift
            ;;
        -h|--help)
            usage 0
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

#
# Reproducible build setup - enter Nix environment if requested
#
setup_reproducible_build() {
    if [[ -n "$REPRODUCIBLE_BUILD" ]] && [[ -z "${IN_NIX_SHELL:-}" ]]; then
        echo ">>> Setting up reproducible build environment..."

        # Run nix-setup.sh to ensure Nix is installed and configured
        NIX_SETUP_SCRIPT="$SOURCE_DIR/Microsoft/nix-setup.sh"
        if [[ -f "$NIX_SETUP_SCRIPT" ]]; then
            chmod +x "$NIX_SETUP_SCRIPT"
            "$NIX_SETUP_SCRIPT"
        fi

        # Source nix profile if not already available
        if ! command -v nix &> /dev/null; then
            if [[ -f ~/.nix-profile/etc/profile.d/nix.sh ]]; then
                . ~/.nix-profile/etc/profile.d/nix.sh
                export PATH="$HOME/.nix-profile/bin:$PATH"

            else
                echo "Error: Nix is not installed or not in PATH" >&2
                echo "Please run: ./Microsoft/nix-setup.sh" >&2
                exit 1
            fi
        fi

        # Re-execute this script inside nix develop shell
        # Use --ignore-environment (-i) to create a pure shell that excludes system packages
        # Keep essential variables: HOME (for temp files), USER (for build metadata), TERM (for output)
        echo "Entering Nix development shell (pure mode)..."
        cd "$SOURCE_DIR"
        exec nix --extra-experimental-features "nix-command flakes" develop \
              -i \
              -k HOME \
              -k USER \
              -k TERM \
            --command \
            "$0" \
            --source-dir "$SOURCE_DIR" \
            --build-dir "$BUILD_DIR" \
            --config "$CONFIG" \
            --arch "$ARCH" \
            --kernel-type "$KERNEL_TYPE" \
            --compiler "$COMPILER" \
            ${SCRIPTS_DIR:+--scripts-dir "$SCRIPTS_DIR"} \
            --reproducible
    fi
}

# Resolve paths first (needed by setup_reproducible_build)
SOURCE_DIR=$(realpath "$SOURCE_DIR")
BUILD_DIR=$(realpath "$BUILD_DIR")

# Call reproducible build setup before anything else
setup_reproducible_build

# For reproducible builds, copy source to a fixed path
# This ensures identical paths in binaries regardless of where source is located
ORIGINAL_SOURCE_DIR="$SOURCE_DIR"
ORIGINAL_BUILD_DIR="$BUILD_DIR"

setup_fixed_build_path() {
    if [[ -n "$REPRODUCIBLE_BUILD" ]]; then
        FIXED_BUILD_PATH="${FIXED_BUILD_PATH:-/tmp/ohcl-kernel-build}"
        FIXED_SOURCE_DIR="${FIXED_BUILD_PATH}/src"
        FIXED_BUILD_DIR="${FIXED_BUILD_PATH}/build"

        echo ">>> Setting up fixed build path for reproducibility..."
        echo "    Original source: $ORIGINAL_SOURCE_DIR"
        echo "    Fixed source: $FIXED_SOURCE_DIR"

        # Clean and create fixed build path
        rm -rf "${FIXED_BUILD_PATH}"
        mkdir -p "${FIXED_BUILD_PATH}"

        # Copy source to fixed path (use anchored excludes to avoid matching subdirs like tools/build)
        rsync -a --exclude='/.git' --exclude='/build' --exclude='/out' --exclude='/compare' \
            "${ORIGINAL_SOURCE_DIR}/" "${FIXED_SOURCE_DIR}/"

        # Update paths to use fixed locations
        SOURCE_DIR="${FIXED_SOURCE_DIR}"
        BUILD_DIR="${FIXED_BUILD_DIR}"

        echo "    Source copied to fixed path"
    fi
}

# Cleanup function to remove temporary build directory
cleanup_fixed_build_path() {
    if [[ -n "$REPRODUCIBLE_BUILD" ]] && [[ -n "${FIXED_BUILD_PATH:-}" ]] && [[ -d "${FIXED_BUILD_PATH:-}" ]]; then
        echo ">>> Cleaning up temporary build directory: ${FIXED_BUILD_PATH}"
        rm -rf "${FIXED_BUILD_PATH}"
    fi
}

# Copy build artifacts back to original location
copy_artifacts_back() {
    if [[ -n "$REPRODUCIBLE_BUILD" ]]; then
        echo ">>> Copying build artifacts back to original location..."
        mkdir -p "${ORIGINAL_BUILD_DIR}"
        rsync -a "${FIXED_BUILD_DIR}/" "${ORIGINAL_BUILD_DIR}/"
        echo "    Artifacts copied to ${ORIGINAL_BUILD_DIR}"
    fi
}

# Set trap to cleanup on exit (success or failure)
if [[ -n "$REPRODUCIBLE_BUILD" ]]; then
    trap cleanup_fixed_build_path EXIT
fi

# Setup fixed build path for reproducible builds
setup_fixed_build_path

# Detect host architecture
HOST_ARCH="$(uname -m)"

# Set architecture-specific variables
if [[ "$ARCH" == "amd64" ]]; then
    MAKE_ARCH="x86"
    KERNEL_ARCH="x86_64"
    # Check if we're cross-compiling from arm64 to x86_64
    if [[ "$HOST_ARCH" == "aarch64" ]]; then
        # Cross-compiling from arm64 with Nix toolchain
        if [[ -n "$REPRODUCIBLE_BUILD" ]]; then
            CROSS_COMPILE_PREFIX="x86_64-unknown-linux-gnu-"
            COMPILER="${CROSS_COMPILE_PREFIX}gcc"
        else
            # Cross-compiling with system toolchain
            CROSS_COMPILE_PREFIX="x86_64-linux-gnu-"
        fi
    else
        # Native x86_64 build
        CROSS_COMPILE_PREFIX=""
        # For reproducible builds, ensure we use Nix's gcc
        if [[ -n "$REPRODUCIBLE_BUILD" ]]; then
            COMPILER="gcc"
        fi
    fi
else
    MAKE_ARCH="arm64"
    KERNEL_ARCH="arm64"
    # Only use cross-compiler when cross-compiling (host != target)
    # On native arm64 machines, use native compiler (no prefix)
    if [[ "$HOST_ARCH" == "aarch64" ]]; then
        # Native arm64 build - no cross-compile prefix needed
        CROSS_COMPILE_PREFIX=""
        # For reproducible builds, ensure we use Nix's gcc
        if [[ -n "$REPRODUCIBLE_BUILD" ]]; then
            COMPILER="gcc"
        fi
    elif [[ -n "$REPRODUCIBLE_BUILD" ]]; then
        # Cross-compiling from x86_64 with Nix toolchain
        CROSS_COMPILE_PREFIX="aarch64-unknown-linux-gnu-"
        COMPILER="${CROSS_COMPILE_PREFIX}gcc"
    else
        # Cross-compiling from x86_64 with system toolchain
        CROSS_COMPILE_PREFIX="aarch64-linux-gnu-"
    fi
fi

# Define output directories (matching pipeline structure)
LINUX_HEADERS_DIR="$BUILD_DIR/linux-headers"
DEBUG_SYMBOL_DIR="$BUILD_DIR/debug_symbols"
LINUX_DIR="$BUILD_DIR/linux_dir"
LINUX_BOOT_DIR="$LINUX_DIR/boot"

# Setup reproducible build environment variables
if [[ -n "$REPRODUCIBLE_BUILD" ]]; then
    # Always use timestamp of the top commit for SOURCE_DATE_EPOCH
    # Override any pre-set value to ensure consistency
    export SOURCE_DATE_EPOCH="$(git -C "$ORIGINAL_SOURCE_DIR" log -1 --pretty=%ct)"
    export LANG="C.UTF-8"
    export LC_ALL="C.UTF-8"
    export TZ="UTC"
    export KBUILD_BUILD_TIMESTAMP="@${SOURCE_DATE_EPOCH}"
    export KBUILD_BUILD_USER="${KBUILD_BUILD_USER:-builder}"
    export KBUILD_BUILD_HOST="${KBUILD_BUILD_HOST:-nixos}"
    export KBUILD_BUILD_VERSION="1"

    # Unset Nix-specific compiler flags that might interfere with kernel build
    unset NIX_CFLAGS_COMPILE
    unset NIX_CFLAGS_COMPILE_FOR_TARGET
    unset NIX_LDFLAGS
    unset NIX_LDFLAGS_FOR_TARGET
fi

echo "=============================================="
echo "HCL Kernel Pipeline Build Script"
echo "=============================================="
echo "Source directory:  $SOURCE_DIR"
echo "Build directory:   $BUILD_DIR"
echo "Config file:       $CONFIG"
echo "Architecture:      $ARCH (make arch: $MAKE_ARCH)"
echo "Kernel type:       $KERNEL_TYPE"
echo "Compiler:          $COMPILER"
if [[ -n "$REPRODUCIBLE_BUILD" ]]; then
    echo "Reproducible:      YES"
    echo "  SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH"
    echo "  KBUILD_BUILD_USER: $KBUILD_BUILD_USER"
    echo "  KBUILD_BUILD_HOST: $KBUILD_BUILD_HOST"
fi
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

    # Ensure merged config is validated for the requested target architecture.
    make ARCH="$KERNEL_ARCH" olddefconfig

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

    # Print current directory for debugging
    echo ">>> Current directory: $(pwd)"

    # For reproducible builds, always clean the build directory to ensure no stale state
    if [[ -n "$REPRODUCIBLE_BUILD" ]]; then
        echo "Cleaning build directory for reproducible build..."
        rm -rf "$BUILD_DIR"
        mkdir -p "$BUILD_DIR"
    fi

    # Clean source tree for CVM builds (merge_cvm_config leaves artifacts)
    if [[ "$KERNEL_TYPE" == "cvm" ]]; then
        echo "Running make mrproper for CVM build..."
        make mrproper
    fi

    # Set KBUILD_OUTPUT to match build-hcl-kernel.sh behavior
    # This ensures consistent build artifact locations
    # Note: build-hcl-kernel.sh uses $BUILD_DIR/linux subdirectory
    export KBUILD_OUTPUT="$BUILD_DIR/linux"

    # Export KCONFIG_CONFIG with absolute path (matches build-hcl-kernel.sh)
    export KCONFIG_CONFIG="$SOURCE_DIR/$CONFIG"

    # Create output directories
    mkdir -p "$KBUILD_OUTPUT"
    mkdir -p "$LINUX_HEADERS_DIR"
    mkdir -p "$DEBUG_SYMBOL_DIR"
    mkdir -p "$LINUX_BOOT_DIR"

    # Copy config to build directory
    cp "$SOURCE_DIR/$CONFIG" "$KBUILD_OUTPUT/.config"

    # Build make arguments
    local make_args=()
    make_args+=("ARCH=$KERNEL_ARCH")
    make_args+=("LOCALVERSION=")
    make_args+=("CC=$COMPILER")
    make_args+=("O=$KBUILD_OUTPUT")

    # Add cross-compile prefix for arm64
    if [[ -n "$CROSS_COMPILE_PREFIX" ]]; then
        make_args+=("CROSS_COMPILE=$CROSS_COMPILE_PREFIX")
    fi

    # Add reproducible build flags
    if [[ -n "$REPRODUCIBLE_BUILD" ]]; then
        make_args+=("KCFLAGS=-fdebug-prefix-map=$SOURCE_DIR=.")
    fi

    # Run olddefconfig
    echo "Running olddefconfig..."
    make "${make_args[@]}" olddefconfig

    # Build kernel with all targets
    echo "Building kernel (make all)..."
    make "${make_args[@]}" -j "$(nproc)" all
    echo ">>> Kernel build complete"
}

#
# Step 2: Install headers
#
build_headers() {
    echo ""
    echo ">>> Installing kernel headers..."

    local make_args=("CC=$COMPILER" "O=$KBUILD_OUTPUT" "ARCH=$KERNEL_ARCH")
    if [[ -n "$CROSS_COMPILE_PREFIX" ]]; then
        make_args+=("CROSS_COMPILE=$CROSS_COMPILE_PREFIX")
    fi

    make "${make_args[@]}" headers_install INSTALL_HDR_PATH="$LINUX_HEADERS_DIR"

    echo ">>> Headers installed to $LINUX_HEADERS_DIR"
}

#
# Step 3: Install modules
#
build_modules() {
    echo ""
    echo ">>> Installing kernel modules..."

    local make_args=("CC=$COMPILER" "O=$KBUILD_OUTPUT" "ARCH=$KERNEL_ARCH")
    if [[ -n "$CROSS_COMPILE_PREFIX" ]]; then
        make_args+=("CROSS_COMPILE=$CROSS_COMPILE_PREFIX")
    fi

    make "${make_args[@]}" modules_install INSTALL_MOD_PATH="$LINUX_DIR"

    echo ">>> Modules installed to $LINUX_DIR"
}

#
# Step 4: Generate debug symbols
#
build_debug_symbols() {
    echo ""
    echo ">>> Generating debug symbols..."

    cd "$BUILD_DIR"

    # Use cross-compile objcopy for arm64
    local OBJCOPY="${CROSS_COMPILE_PREFIX}objcopy"

    # Copy vmlinux to debug symbol directory and extract debug info
    cp -a "$KBUILD_OUTPUT/vmlinux" "$DEBUG_SYMBOL_DIR/"

    # Generate kernel debug symbols with compression
    echo "Extracting vmlinux debug symbols..."
    $OBJCOPY --only-keep-debug --compress-debug-sections "$DEBUG_SYMBOL_DIR/vmlinux" \
        "$DEBUG_SYMBOL_DIR/vmlinux.debug"

    # Create stripped vmlinux at BUILD_DIR root (matches build-hcl-kernel.sh behavior)
    echo "Creating stripped vmlinux at $BUILD_DIR/vmlinux..."
    if [[ -n "$REPRODUCIBLE_BUILD" ]]; then
        $OBJCOPY --strip-all "$KBUILD_OUTPUT/vmlinux" "$BUILD_DIR/vmlinux"
    else
        $OBJCOPY --strip-all --add-gnu-debuglink="$DEBUG_SYMBOL_DIR/vmlinux.debug" "$KBUILD_OUTPUT/vmlinux" "$BUILD_DIR/vmlinux"
    fi

    # Also save debug info with .dbg extension (matches build-hcl-kernel.sh)
    cp -a "$DEBUG_SYMBOL_DIR/vmlinux.debug" "$BUILD_DIR/vmlinux.dbg"

    # Generate module debug symbols and strip modules
    echo "Processing module debug symbols..."
    while IFS= read -r -d '' module_path; do
        rel_module_path="${module_path#"$KBUILD_OUTPUT"/}"
        dbg_module_path="$DEBUG_SYMBOL_DIR/$rel_module_path"
        dbg_path="${dbg_module_path}.debug"

        # Preserve module subdirectory layout under debug_symbols.
        mkdir -p "$(dirname "$dbg_module_path")"
        cp -a "$module_path" "$dbg_module_path"

        # Extract debug symbols with compression
        $OBJCOPY --only-keep-debug --compress-debug-sections "$dbg_module_path" "$dbg_path"

        # Strip debug symbols from original module
        # For reproducible builds, skip --add-gnu-debuglink as it embeds a CRC
        if [[ -n "$REPRODUCIBLE_BUILD" ]]; then
            $OBJCOPY --strip-unneeded "$module_path"
        else
            $OBJCOPY --strip-unneeded --add-gnu-debuglink="$dbg_path" "$module_path"
        fi
    done < <(find "$KBUILD_OUTPUT" -name '*.ko' -print0)

    echo ">>> Debug symbols generated in $DEBUG_SYMBOL_DIR"
}

#
# Step 5: Package kernel files to boot directory
#
package_kernel() {
    echo ""
    echo ">>> Packaging kernel files..."

    cd "$SOURCE_DIR"

    # Use cross-compile objcopy for arm64
    local OBJCOPY="${CROSS_COMPILE_PREFIX}objcopy"

    # Get kernel version
    KERNEL_VERSION=$(cat "$KBUILD_OUTPUT/include/config/kernel.release")
    echo "Kernel version: $KERNEL_VERSION"

    # Copy architecture-specific kernel image
    if [[ "$MAKE_ARCH" == "arm64" ]]; then
        if [[ -f "$KBUILD_OUTPUT/arch/arm64/boot/Image" ]]; then
            cp -a "$KBUILD_OUTPUT/arch/arm64/boot/Image" \
                "$LINUX_BOOT_DIR/Image-$KERNEL_VERSION"
            echo "Copied Image to $LINUX_BOOT_DIR/Image-$KERNEL_VERSION"
        else
            echo "Warning: Image not found at $KBUILD_OUTPUT/arch/arm64/boot/Image"
        fi
    else
        if [[ -f "$KBUILD_OUTPUT/arch/x86/boot/bzImage" ]]; then
            cp -a "$KBUILD_OUTPUT/arch/x86/boot/bzImage" \
                "$LINUX_BOOT_DIR/vmlinuz-$KERNEL_VERSION"
            echo "Copied bzImage to $LINUX_BOOT_DIR/vmlinuz-$KERNEL_VERSION"
        else
            echo "Warning: bzImage not found at $KBUILD_OUTPUT/arch/x86/boot/bzImage"
        fi
    fi

    # Strip and copy vmlinux
    echo "Stripping vmlinux..."
    $OBJCOPY --strip-all "$KBUILD_OUTPUT/vmlinux"
    cp -a "$KBUILD_OUTPUT/vmlinux" "$LINUX_BOOT_DIR/vmlinux-$KERNEL_VERSION"

    # Copy config and System.map
    cp -a "$KBUILD_OUTPUT/.config" "$LINUX_BOOT_DIR/config-$KERNEL_VERSION"
    cp -a "$KBUILD_OUTPUT/System.map" "$LINUX_BOOT_DIR/System.map-$KERNEL_VERSION"

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

    echo ">>> [1/5] Building kernel..."
    build_kernel
    echo ">>> [2/5] Installing headers..."
    build_headers
    echo ">>> [3/5] Installing modules..."
    build_modules
    echo ">>> [4/5] Generating debug symbols..."
    build_debug_symbols
    echo ">>> [5/5] Packaging kernel files..."
    package_kernel

    # Move build artifacts from /linux subdirectory to BUILD_DIR root for pipeline compatibility
    echo ""
    echo ">>> Moving build artifacts from $KBUILD_OUTPUT to $BUILD_DIR for pipeline..."
    rsync -a --remove-source-files "$KBUILD_OUTPUT/" "$BUILD_DIR/"
    find "$KBUILD_OUTPUT" -type d -empty -delete
    echo ">>> Artifacts moved to $BUILD_DIR"

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
    if [[ -n "$REPRODUCIBLE_BUILD" ]]; then
        echo ""
        echo "Reproducible build completed with:"
        echo "  SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH"
        echo "  KBUILD_BUILD_USER: $KBUILD_BUILD_USER"
        echo "  KBUILD_BUILD_HOST: $KBUILD_BUILD_HOST"
    fi
    echo "=============================================="

    # Copy artifacts back to original location for reproducible builds
    copy_artifacts_back

    # Print sha256sum of vmlinux for reproducibility verification
    # Check the STRIPPED vmlinux after it's been copied back to original location
    if [[ -n "$REPRODUCIBLE_BUILD" ]] && [[ -f "$ORIGINAL_BUILD_DIR/vmlinux" ]]; then
        echo ""
        echo "Reproducibility verification:"
        echo "  vmlinux sha256sum: $(sha256sum "$ORIGINAL_BUILD_DIR/vmlinux" | cut -d' ' -f1)"
        echo "  (stripped vmlinux from $ORIGINAL_BUILD_DIR/vmlinux)"
    fi
}

# Run main
main
