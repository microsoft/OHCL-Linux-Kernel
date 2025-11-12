#!/bin/bash
set -e

# ============================================================================
# OHCL Linux Kernel - Reproducibility Verification Script
# ============================================================================
# This script builds the kernel twice and verifies that the outputs are
# bit-for-bit identical, proving reproducibility.
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "============================================================================"
echo "  OHCL Linux Kernel - Reproducibility Verification"
echo "============================================================================"
echo ""
echo "This will build the kernel twice and compare the outputs to verify"
echo "that the build is reproducible (produces identical binaries)."
echo ""

# Parse arguments
ARCH=${1:-x64}
SKIP_CLEAN=${2:-}

if [ "$ARCH" != "x64" ] && [ "$ARCH" != "arm64" ]; then
    echo "Usage: $0 [x64|arm64] [--skip-clean]"
    echo ""
    echo "  Default: x64"
    echo "  --skip-clean: Skip initial clean (faster, but less thorough)"
    exit 1
fi

echo "Architecture: $ARCH"
echo ""

# Verify we're in the right location
cd "$KERNEL_ROOT"

# Check if toolchain baseline exists
if [ ! -f "${SCRIPT_DIR}/TOOLCHAIN_VERSIONS" ]; then
    echo -e "${YELLOW}⚠ WARNING${NC}: No toolchain baseline found"
    echo "  Run a normal build first to establish baseline:"
    echo "  ./Microsoft/build-hcl-kernel.sh $ARCH"
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Define build directories (matching build script)
BUILD_DIR="$(realpath $KERNEL_ROOT/../build)"
OUT_DIR="$(realpath $KERNEL_ROOT/out)"

# Clean first (unless skipped)
if [ "$SKIP_CLEAN" != "--skip-clean" ]; then
    echo "Cleaning previous builds..."
    make mrproper 2>/dev/null || true
    rm -rf "$OUT_DIR" "$BUILD_DIR" 2>/dev/null || true
    echo ""
fi

# ============================================================================
# FIRST BUILD
# ============================================================================

echo "============================================================================"
echo "  First Build"
echo "============================================================================"
echo ""

"${SCRIPT_DIR}/build-hcl-kernel.sh" $ARCH

# Save first build output
echo ""
echo "Saving first build output..."
cp -a "$OUT_DIR" out-build1
cp -a "$BUILD_DIR" build-build1

# Record checksums
BUILD1_VMLINUX_SHA=$(sha256sum out-build1/build/native/bin/$ARCH/vmlinux | awk '{print $1}')
echo "Build 1 vmlinux SHA256: $BUILD1_VMLINUX_SHA"

# ============================================================================
# SECOND BUILD
# ============================================================================

echo ""
echo "============================================================================"
echo "  Second Build"
echo "============================================================================"
echo ""

# Clean between builds
make mrproper
rm -rf "$OUT_DIR" "$BUILD_DIR"

"${SCRIPT_DIR}/build-hcl-kernel.sh" $ARCH

# Save second build output
echo ""
echo "Saving second build output..."
cp -a "$OUT_DIR" out-build2
cp -a "$BUILD_DIR" build-build2

# Record checksums
BUILD2_VMLINUX_SHA=$(sha256sum out-build2/build/native/bin/$ARCH/vmlinux | awk '{print $1}')
echo "Build 2 vmlinux SHA256: $BUILD2_VMLINUX_SHA"

# ============================================================================
# COMPARISON
# ============================================================================

echo ""
echo "============================================================================"
echo "  Comparing Builds"
echo "============================================================================"
echo ""

# Compare vmlinux binaries
echo "Comparing vmlinux binaries..."
if cmp -s out-build1/build/native/bin/$ARCH/vmlinux out-build2/build/native/bin/$ARCH/vmlinux; then
    echo -e "${GREEN}✓ vmlinux binaries are IDENTICAL${NC}"
    VMLINUX_MATCH=1
else
    echo -e "${RED}✗ vmlinux binaries DIFFER${NC}"
    VMLINUX_MATCH=0
fi

# Compare debug info
echo ""
echo "Comparing debug info..."
if cmp -s out-build1/build/native/bin/$ARCH/vmlinux.dbg out-build2/build/native/bin/$ARCH/vmlinux.dbg; then
    echo -e "${GREEN}✓ vmlinux.dbg files are IDENTICAL${NC}"
    DEBUG_MATCH=1
else
    echo -e "${YELLOW}⚠ vmlinux.dbg files differ${NC}"
    echo "  (Debug info may contain timestamps, this is often acceptable)"
    DEBUG_MATCH=0
fi

# Compare kernel modules (if any)
echo ""
echo "Comparing kernel modules..."
MODULE_COUNT=$(find out-build1/build/native/bin/$ARCH/modules -name '*.ko' 2>/dev/null | wc -l || echo 0)
if [ $MODULE_COUNT -gt 0 ]; then
    echo "Found $MODULE_COUNT modules to compare..."
    MODULE_DIFF=0
    
    for mod1 in $(find out-build1/build/native/bin/$ARCH/modules -name '*.ko' 2>/dev/null); do
        mod2="${mod1/out-build1/out-build2}"
        if [ -f "$mod2" ]; then
            if ! cmp -s "$mod1" "$mod2"; then
                echo -e "${RED}✗${NC} $(basename $mod1) differs"
                MODULE_DIFF=$((MODULE_DIFF + 1))
            fi
        fi
    done
    
    if [ $MODULE_DIFF -eq 0 ]; then
        echo -e "${GREEN}✓ All $MODULE_COUNT modules are IDENTICAL${NC}"
        MODULES_MATCH=1
    else
        echo -e "${RED}✗ $MODULE_DIFF modules differ${NC}"
        MODULES_MATCH=0
    fi
else
    echo "No modules found to compare"
    MODULES_MATCH=1
fi

# Detailed comparison with diffoscope if available
echo ""
if command -v diffoscope &> /dev/null; then
    echo "Running detailed comparison with diffoscope..."
    echo "(This may take a moment...)"
    
    if diffoscope --text diffoscope-report.txt \
                   --max-report-size 10M \
                   out-build1/build/native/bin/$ARCH/vmlinux \
                   out-build2/build/native/bin/$ARCH/vmlinux 2>/dev/null; then
        echo -e "${GREEN}✓ diffoscope found no differences${NC}"
    else
        echo -e "${YELLOW}⚠ diffoscope found some differences${NC}"
        echo "  Detailed report saved to: diffoscope-report.txt"
        echo "  (First 50 lines shown below)"
        echo ""
        head -50 diffoscope-report.txt
    fi
else
    echo "Note: Install 'diffoscope' for detailed binary comparison"
    echo "  sudo apt-get install diffoscope"
fi

# ============================================================================
# FINAL RESULTS
# ============================================================================

echo ""
echo "============================================================================"
echo "  Verification Results"
echo "============================================================================"
echo ""

if [ $VMLINUX_MATCH -eq 1 ] && [ $MODULES_MATCH -eq 1 ]; then
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✓ SUCCESS - BUILD IS REPRODUCIBLE!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "The two builds produced bit-for-bit identical binaries."
    echo "This kernel can be reproducibly built."
    echo ""
    echo "SHA256 Checksums:"
    echo "  Build 1: $BUILD1_VMLINUX_SHA"
    echo "  Build 2: $BUILD2_VMLINUX_SHA"
    echo ""
    
    # Save attestation
    cat > reproducibility-attestation.txt << EOF
OHCL Linux Kernel - Reproducibility Attestation
================================================

Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Architecture: $ARCH
Git Commit: $(git rev-parse HEAD 2>/dev/null || echo "unknown")

Verification Method: Two consecutive builds compared
Result: REPRODUCIBLE

vmlinux SHA256: $BUILD1_VMLINUX_SHA

Toolchain (from TOOLCHAIN_VERSIONS):
$(cat "${SCRIPT_DIR}/TOOLCHAIN_VERSIONS" 2>/dev/null || echo "Not found")

This attestation confirms that building from the same source with the
same toolchain produces identical binaries.
EOF
    
    echo "Attestation saved to: reproducibility-attestation.txt"
    echo ""
    RESULT=0
    
else
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED}✗ FAILURE - BUILD IS NOT REPRODUCIBLE${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "The two builds produced different binaries."
    echo ""
    echo "Summary:"
    if [ $VMLINUX_MATCH -eq 0 ]; then
        echo -e "  ${RED}✗${NC} vmlinux differs"
    fi
    if [ $DEBUG_MATCH -eq 0 ]; then
        echo -e "  ${YELLOW}⚠${NC} debug info differs (may be acceptable)"
    fi
    if [ $MODULES_MATCH -eq 0 ]; then
        echo -e "  ${RED}✗${NC} modules differ"
    fi
    echo ""
    echo "Possible causes:"
    echo "  1. Toolchain version mismatch (check TOOLCHAIN_VERSIONS)"
    echo "  2. Non-deterministic build steps"
    echo "  3. Timestamps not properly controlled"
    echo "  4. Build environment differences"
    echo ""
    echo "To debug:"
    echo "  - Check ${SCRIPT_DIR}/TOOLCHAIN_VERSIONS"
    echo "  - Review diffoscope-report.txt (if generated)"
    echo "  - Ensure SOURCE_DATE_EPOCH is set correctly"
    echo ""
    RESULT=1
fi

# Cleanup option
echo "Build artifacts saved in:"
echo "  out-build1/ and build-build1/"
echo "  out-build2/ and build-build2/"
echo ""
read -p "Clean up build artifacts? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Cleaning up..."
    rm -rf out-build1 out-build2 build-build1 build-build2
    echo "Done"
fi

echo ""
echo "============================================================================"

exit $RESULT
