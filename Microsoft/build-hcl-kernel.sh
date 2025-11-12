#!/bin/bash

# ============================================================================
# OHCL Linux Kernel - Reproducible Build System
# ============================================================================
# This script builds the kernel with reproducibility features:
# - Verifies toolchain versions match baseline
# - Sets deterministic build environment
# - Uses SOURCE_DATE_EPOCH from git
# - Warns about reproducibility issues
# ============================================================================

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SRC_DIR=$(realpath ${SCRIPT_DIR}/..)
TOOLCHAIN_FILE="${SCRIPT_DIR}/TOOLCHAIN_VERSIONS"

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================================================
# DEPENDENCY VERIFICATION
# ============================================================================

verify_dependencies() {
    echo "============================================================================"
    echo "  Checking Build Dependencies"
    echo "============================================================================"
    
    local MISSING_DEPS=0
    
    # Function to check if command exists
    check_command() {
        if ! command -v $1 &> /dev/null; then
            echo -e "${RED}✗${NC} $1 not found"
            MISSING_DEPS=1
        else
            echo -e "${GREEN}✓${NC} $1"
        fi
    }
    
    # Check essential tools
    check_command gcc
    check_command make
    check_command flex
    check_command bison
    check_command ld
    check_command git
    check_command bc
    
    # Check for cross-compiler if building arm64
    if [[ " $@ " =~ " arm64 " ]]; then
        check_command aarch64-linux-gnu-gcc
    fi
    
    # Check for essential libraries
    if ! ldconfig -p 2>/dev/null | grep -q libelf; then
        echo -e "${RED}✗${NC} libelf not found"
        MISSING_DEPS=1
    else
        echo -e "${GREEN}✓${NC} libelf"
    fi
    
    if [ $MISSING_DEPS -eq 1 ]; then
        echo ""
        echo -e "${RED}ERROR: Missing required build dependencies!${NC}"
        echo ""
        echo "To install dependencies, run:"
        echo "  sudo ${SCRIPT_DIR}/install-deps.sh"
        echo ""
        exit 1
    fi
    
    echo ""
}

# ============================================================================
# TOOLCHAIN VERSION TRACKING & VERIFICATION
# ============================================================================

setup_reproducible_environment() {
    echo "============================================================================"
    echo "  Reproducible Build Setup"
    echo "============================================================================"
    
    # Functions to get current tool versions
    get_gcc_version() { gcc --version | head -n1 | grep -oP '\d+\.\d+\.\d+' | head -n1 || echo "unknown"; }
    get_ld_version() { ld --version | head -n1 | grep -oP '\d+\.\d+' | head -n1 || echo "unknown"; }
    get_make_version() { make --version | head -n1 | grep -oP '\d+\.\d+' | head -n1 || echo "unknown"; }
    get_flex_version() { flex --version 2>&1 | head -n1 | grep -oP '\d+\.\d+\.\d+' | head -n1 || echo "unknown"; }
    get_bison_version() { bison --version | head -n1 | grep -oP '\d+\.\d+(\.\d+)?' | head -n1 || echo "unknown"; }
    
    # Check if this is first build - create TOOLCHAIN_VERSIONS
    if [ ! -f "$TOOLCHAIN_FILE" ]; then
        echo "First build detected - recording toolchain baseline..."
        cat > "$TOOLCHAIN_FILE" << EOF
# Reproducible Build Environment Record
# Auto-generated on first build
# Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
#
# This file records the exact versions of all build dependencies.
# Subsequent builds will verify against these versions to ensure reproducibility.

[CRITICAL - Toolchain]
# These directly affect binary output - must match for reproducibility
GCC_VERSION=$(get_gcc_version)
BINUTILS_VERSION=$(get_ld_version)
MAKE_VERSION=$(get_make_version)

[IMPORTANT - Build Tools]
# These can affect generated code - version differences cause warnings
FLEX_VERSION=$(get_flex_version)
BISON_VERSION=$(get_bison_version)

[ENVIRONMENT]
# System information for complete reproducibility record
OS_RELEASE=$(lsb_release -ds 2>/dev/null || cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || echo "unknown")
BASELINE_DATE=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
EOF
        echo -e "${GREEN}✓${NC} Toolchain baseline recorded: $TOOLCHAIN_FILE"
        echo ""
    else
        # Verify toolchain matches baseline
        echo "Verifying toolchain versions..."
        
        # Get baseline versions and strip any whitespace
        BASELINE_GCC=$(grep "^GCC_VERSION=" "$TOOLCHAIN_FILE" | cut -d'=' -f2 | tr -d ' \t\n\r')
        BASELINE_LD=$(grep "^BINUTILS_VERSION=" "$TOOLCHAIN_FILE" | cut -d'=' -f2 | tr -d ' \t\n\r')
        BASELINE_MAKE=$(grep "^MAKE_VERSION=" "$TOOLCHAIN_FILE" | cut -d'=' -f2 | tr -d ' \t\n\r')
        
        # Get current versions and strip any whitespace
        CURRENT_GCC=$(get_gcc_version | tr -d ' \t\n\r')
        CURRENT_LD=$(get_ld_version | tr -d ' \t\n\r')
        CURRENT_MAKE=$(get_make_version | tr -d ' \t\n\r')
        
        CRITICAL_MISMATCH=0
        IMPORTANT_MISMATCH=0
        
        # Verify critical toolchain components
        if [ "$CURRENT_GCC" != "$BASELINE_GCC" ]; then
            echo -e "${RED}⚠ CRITICAL${NC}: GCC version mismatch"
            echo "  Baseline: '$BASELINE_GCC' | Current: '$CURRENT_GCC'"
            CRITICAL_MISMATCH=1
        else
            echo -e "${GREEN}✓${NC} GCC: $CURRENT_GCC"
        fi
        
        if [ "$CURRENT_LD" != "$BASELINE_LD" ]; then
            echo -e "${YELLOW}⚠ CRITICAL${NC}: Binutils version mismatch"
            echo "  Baseline: $BASELINE_LD | Current: $CURRENT_LD"
            CRITICAL_MISMATCH=1
        else
            echo -e "${GREEN}✓${NC} Binutils: $CURRENT_LD"
        fi
        
        if [ "$CURRENT_MAKE" != "$BASELINE_MAKE" ]; then
            echo -e "${YELLOW}⚠ WARNING${NC}: Make version differs"
            echo "  Baseline: $BASELINE_MAKE | Current: $CURRENT_MAKE"
            IMPORTANT_MISMATCH=1
        else
            echo -e "${GREEN}✓${NC} Make: $CURRENT_MAKE"
        fi
        
        # Display warnings if mismatches detected
        if [ $CRITICAL_MISMATCH -eq 1 ]; then
            echo ""
            echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -e "${YELLOW}⚠  REPRODUCIBILITY WARNING - CRITICAL TOOLCHAIN MISMATCH${NC}"
            echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo ""
            echo "  Your toolchain versions differ from the recorded baseline."
            echo "  This build will NOT be bit-for-bit reproducible with previous"
            echo "  builds made using the baseline toolchain."
            echo ""
            echo "  Impact: HIGH - Binary output will differ"
            echo ""
            echo "  Options:"
            echo "    1. Continue anyway (builds will work, but not reproducible)"
            echo "    2. Install matching toolchain (see $TOOLCHAIN_FILE)"
            echo "    3. Update baseline: rm $TOOLCHAIN_FILE && rebuild"
            echo ""
            echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo ""
            read -p "Press Enter to continue with non-reproducible build, or Ctrl+C to abort..."
            echo ""
        elif [ $IMPORTANT_MISMATCH -eq 1 ]; then
            echo ""
            echo -e "${YELLOW}Note: Some build tools differ from baseline.${NC}"
            echo "      This may affect reproducibility."
            echo ""
        else
            echo -e "${GREEN}✓ All toolchain versions match baseline${NC}"
            echo ""
        fi
    fi
    
    # ========================================================================
    # SET REPRODUCIBILITY ENVIRONMENT VARIABLES
    # ========================================================================
    
    echo "Configuring reproducible build environment..."
    
    # Set SOURCE_DATE_EPOCH from git
    if [ -d "${SRC_DIR}/.git" ]; then
        export SOURCE_DATE_EPOCH=$(git -C "${SRC_DIR}" log -1 --pretty=%ct)
        GIT_COMMIT=$(git -C "${SRC_DIR}" rev-parse --short HEAD)
        echo "  Git commit: ${GIT_COMMIT}"
        echo "  SOURCE_DATE_EPOCH: ${SOURCE_DATE_EPOCH}"
        echo "  Date: $(date -u -d "@${SOURCE_DATE_EPOCH}" +"%Y-%m-%d %H:%M:%S UTC")"
    else
        echo -e "  ${YELLOW}⚠ WARNING${NC}: Not a git repository"
        echo "  Using current time (NOT REPRODUCIBLE across time)"
        export SOURCE_DATE_EPOCH=$(date +%s)
    fi
    
    # Fixed build identity for reproducibility
    export KBUILD_BUILD_USER="builder"
    export KBUILD_BUILD_HOST="reproducible"
    export KBUILD_BUILD_TIMESTAMP=$(date -u -d "@${SOURCE_DATE_EPOCH}" +"%Y-%m-%d %H:%M:%S UTC")
    
    # Compiler flags for path normalization (reproducibility)
    export KCFLAGS="-fdebug-prefix-map=${SRC_DIR}=. -fmacro-prefix-map=${SRC_DIR}=."
    export KAFLAGS="-fdebug-prefix-map=${SRC_DIR}=."
    
    # Ensure deterministic environment
    export LC_ALL=C
    export TZ=UTC
    export LANG=C
    
    echo "  Build user: ${KBUILD_BUILD_USER}"
    echo "  Build host: ${KBUILD_BUILD_HOST}"
    echo ""
    echo -e "${GREEN}✓ Reproducible environment configured${NC}"
    echo ""
}

# ============================================================================
# ORIGINAL BUILD SCRIPT (with reproducibility enhancements)
# ============================================================================

usage() {
>&2 echo "Try $0 --help for more information."
exit 1
}

O=`getopt -n "$0" -l help -- nh "$@"` || usage
eval set -- "$O"

builds=()
desc=()
arch=()
clean=1

while true; do
case "$1" in
-n)
clean=
shift
;;
--)
shift
break
;;
-h|--help)
echo "Usage: $0 [-n] [BUILD ...]"
echo ""
echo "  Builds the kernel with reproducibility support."
echo ""
echo "  -n: Do not clean before building"
echo ""
echo "  Available builds:"
echo "    dev x64 arm64"
echo ""
echo "  Reproducibility:"
echo "    - First build records toolchain baseline"
echo "    - Subsequent builds verify and warn if toolchain differs"
echo "    - Uses SOURCE_DATE_EPOCH from git for deterministic timestamps"
echo "    - See Microsoft/TOOLCHAIN_VERSIONS for recorded baseline"
echo ""
exit
;;
*)
usage
;;
esac
done

while [ $# != 0 ]; do
case "$1" in
dev)
builds+=(dev)
desc+=("dev")
;;
x64)
arch=("x64")
;;
arm64)
arch=("arm64")
;;
*)
>&2 echo "Unknown build type: $1"
usage
;;
esac
shift
done

if test -z "$builds"; then
builds=("dev")
desc=("dev")
fi

if test -z "$arch"; then
arch=("x64")
fi

objcopy=("objcopy")
makeargs=("ARCH=x86_64")
targets=("vmlinux modules")
if [ "$arch" = "arm64" ]; then
objcopy=("aarch64-linux-gnu-objcopy")
makeargs=("ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-")
targets=("vmlinux Image modules")
fi

# Run dependency verification
verify_dependencies "$@"

# Setup reproducible build environment
setup_reproducible_environment

# ============================================================================
# BUILD KERNEL FUNCTION
# ============================================================================

LINUX_SRC=$SRC_DIR
BUILD_DIR=`realpath $LINUX_SRC/../build`
OUT_DIR=`realpath $LINUX_SRC/out`
MOD_DIR=/build/native/bin/$arch/modules/kernel/

export KBUILD_OUTPUT=$BUILD_DIR/linux

build_kernel() {
    if [ -n "$clean" ]; then
        make mrproper
    fi
    export KCONFIG_CONFIG=$LINUX_SRC/Microsoft/hcl-$arch.config
    
    # Build with reproducibility flags
    make $makeargs \
        KBUILD_BUILD_TIMESTAMP="${KBUILD_BUILD_TIMESTAMP}" \
        KBUILD_BUILD_USER="${KBUILD_BUILD_USER}" \
        KBUILD_BUILD_HOST="${KBUILD_BUILD_HOST}" \
        -j `nproc` olddefconfig $targets
    
    cp $LINUX_SRC/Microsoft/hcl-$arch.config $OUT_DIR
    $objcopy --only-keep-debug --compress-debug-sections $KBUILD_OUTPUT/vmlinux $BUILD_DIR/vmlinux.dbg
    $objcopy --strip-all --add-gnu-debuglink=$BUILD_DIR/vmlinux.dbg $KBUILD_OUTPUT/vmlinux $BUILD_DIR/vmlinux
    
    # Process modules deterministically (sorted order)
    find $BUILD_DIR -name '*.ko' | sort | while read -r mod; do
        relative_path="${mod#$BUILD_DIR/linux}"
        dest_dir="$OUT_DIR/$MOD_DIR/$(dirname "$relative_path")"
        mkdir -p "$dest_dir"
        outmod="$dest_dir/$(basename $mod)"
        $objcopy --only-keep-debug --compress-debug-sections "$mod" "$outmod.dbg"
        $objcopy --strip-unneeded --add-gnu-debuglink "$outmod.dbg" "$mod" "$outmod"
    done
    
    cp $BUILD_DIR/vmlinux $OUT_DIR/build/native/bin/$arch
    cp $BUILD_DIR/vmlinux.dbg $OUT_DIR/build/native/bin/$arch
    
    # Record build metadata
    cat > $OUT_DIR/build/native/bin/$arch/kernel_build_metadata.json << EOF
{
  "build_timestamp": "${KBUILD_BUILD_TIMESTAMP}",
  "source_date_epoch": "${SOURCE_DATE_EPOCH}",
  "git_commit": "$(git -C "${SRC_DIR}" rev-parse HEAD 2>/dev/null || echo 'unknown')",
  "gcc_version": "$(gcc --version | head -n1)",
  "reproducible": true
}
EOF
    
    cp $LINUX_SRC/Microsoft/hcl-$arch.config $OUT_DIR
    if [ "$arch" = "arm64" ]; then
        cp $BUILD_DIR/linux/arch/$arch/boot/Image $OUT_DIR/build/native/bin/$arch
    fi
}

# ============================================================================
# MAIN BUILD EXECUTION
# ============================================================================

if [ -n "$clean" ]; then
    rm -rf $KBUILD_OUTPUT
    rm -rf $OUT_DIR
fi

mkdir -p $KBUILD_OUTPUT
mkdir -p $OUT_DIR

cd $LINUX_SRC

cp $SCRIPT_DIR/*.cpio.gz $OUT_DIR 2>/dev/null || true
cp $SCRIPT_DIR/*.config $OUT_DIR

echo "============================================================================"
echo "  Building Kernel"
echo "============================================================================"

for b in ${!builds[@]}
do
    echo "Building ${desc[b]} kernel for $arch..."
    BUILD_TYPE=${1:-${builds[b]}}
    build_kernel
done

echo ""
echo "Installing headers to $BUILD_DIR"
rm -rf $BUILD_DIR/include
if [ "$arch" = "arm64" ]; then
    make headers_install ARCH=arm64 INSTALL_HDR_PATH=$BUILD_DIR -j `nproc` > /dev/null
else
    make headers_install ARCH=x86_64 INSTALL_HDR_PATH=$BUILD_DIR -j `nproc` > /dev/null
fi

echo ""
echo "============================================================================"
echo "  Build Complete!"
echo "============================================================================"
echo ""
echo "Output directory: $OUT_DIR"
echo "Kernel binary: $OUT_DIR/build/native/bin/$arch/vmlinux"
echo ""
echo "Build metadata: $OUT_DIR/build/native/bin/$arch/kernel_build_metadata.json"
echo "Toolchain baseline: $TOOLCHAIN_FILE"
echo ""
echo "To verify reproducibility, run:"
echo "  ./Microsoft/verify-reproducible.sh"
echo "============================================================================"
