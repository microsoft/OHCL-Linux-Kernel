#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Reproducibility verification script
# Builds the kernel twice and compares outputs to verify reproducibility

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Parse architecture from command line (first non-option argument)
ARCH_TYPE=""
for arg in "$@"; do
    case "$arg" in
        --*|-*)
            # Skip options
            ;;
        *)
            if [ -z "$ARCH_TYPE" ]; then
                ARCH_TYPE="$arg"
            fi
            ;;
    esac
done

# Default to x64 if not specified
ARCH_TYPE="${ARCH_TYPE:-x64}"

# Build directories - use same name for both builds to ensure reproducibility
BUILD_DIR="${KERNEL_ROOT}/build"
BUILD_DIR1="${KERNEL_ROOT}/build-repro-1"
BUILD_DIR2="${KERNEL_ROOT}/build-repro-2"
DIFF_OUTPUT="${KERNEL_ROOT}/reproducibility-report"

# Use diffoscope if available
USE_DIFFOSCOPE="${USE_DIFFOSCOPE:-true}"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $*"
}

cleanup_builds() {
    if [ "${1:-}" = "keep" ]; then
        log_info "Keeping build directories for inspection"
        return
    fi

    log_info "Cleaning up build directories..."
    rm -rf "${BUILD_DIR1}" "${BUILD_DIR2}"
}

build_kernel_twice() {
    log_step "Building kernel - First build"
    rm -rf "${BUILD_DIR}"
    BUILD_OUTPUT="${BUILD_DIR}" "${SCRIPT_DIR}/nix-build.sh" "${ARCH_TYPE}" build
    # Copy to preserve first build
    cp -r "${BUILD_DIR}" "${BUILD_DIR1}"

    log_step "Building kernel - Second build"
    rm -rf "${BUILD_DIR}"
    BUILD_OUTPUT="${BUILD_DIR}" "${SCRIPT_DIR}/nix-build.sh" "${ARCH_TYPE}" build
    # Copy to preserve second build
    cp -r "${BUILD_DIR}" "${BUILD_DIR2}"

    log_info "Both builds completed"
}

find_kernel_artifacts() {
    local build_dir="$1"

    # Find kernel image
    for img in arch/*/boot/Image arch/*/boot/bzImage arch/*/boot/zImage vmlinux; do
        if [ -f "${build_dir}/${img}" ]; then
            echo "${img}"
            return 0
        fi
    done

    return 1
}

compare_files() {
    local file1="$1"
    local file2="$2"
    local label="$3"

    if ! [ -f "${file1}" ] || ! [ -f "${file2}" ]; then
        log_warn "File not found for comparison: ${label}"
        return 1
    fi

    if cmp -s "${file1}" "${file2}"; then
        log_info "✓ ${label}: IDENTICAL"
        return 0
    else
        log_error "✗ ${label}: DIFFERENT"
        return 1
    fi
}

compare_checksums() {
    log_step "Comparing checksums..."

    local success=true

    # Compare kernel images
    KERNEL_IMAGE=$(find_kernel_artifacts "${BUILD_DIR1}")
    if [ -n "${KERNEL_IMAGE}" ]; then
        compare_files "${BUILD_DIR1}/${KERNEL_IMAGE}" "${BUILD_DIR2}/${KERNEL_IMAGE}" "Kernel image" || success=false

        # Show checksums
        log_info "Build 1 checksum: $(sha256sum "${BUILD_DIR1}/${KERNEL_IMAGE}" | cut -d' ' -f1)"
        log_info "Build 2 checksum: $(sha256sum "${BUILD_DIR2}/${KERNEL_IMAGE}" | cut -d' ' -f1)"
    fi

    # Compare System.map
    compare_files "${BUILD_DIR1}/System.map" "${BUILD_DIR2}/System.map" "System.map" || success=false

    # Compare vmlinux (if exists separately)
    if [ -f "${BUILD_DIR1}/vmlinux" ]; then
        compare_files "${BUILD_DIR1}/vmlinux" "${BUILD_DIR2}/vmlinux" "vmlinux" || success=false
    fi

    # Compare .config
    compare_files "${BUILD_DIR1}/.config" "${BUILD_DIR2}/.config" "Kernel config" || success=false

    if [ "${success}" = "true" ]; then
        return 0
    else
        return 1
    fi
}

find_differences() {
    log_step "Finding differences between builds..."

    mkdir -p "${DIFF_OUTPUT}"

    KERNEL_IMAGE=$(find_kernel_artifacts "${BUILD_DIR1}")
    if [ -z "${KERNEL_IMAGE}" ]; then
        log_error "Could not find kernel image"
        return 1
    fi

    local file1="${BUILD_DIR1}/${KERNEL_IMAGE}"
    local file2="${BUILD_DIR2}/${KERNEL_IMAGE}"

    # Basic diff
    log_info "Creating binary diff report..."
    cmp -l "${file1}" "${file2}" > "${DIFF_OUTPUT}/binary-diff.txt" 2>&1 || true

    if [ -s "${DIFF_OUTPUT}/binary-diff.txt" ]; then
        local diff_count=$(wc -l < "${DIFF_OUTPUT}/binary-diff.txt")
        log_warn "Found ${diff_count} byte differences"
    fi

    # Use diffoscope for detailed analysis if available
    if command -v diffoscope >/dev/null 2>&1 && [ "${USE_DIFFOSCOPE}" = "true" ]; then
        log_info "Running diffoscope for detailed analysis..."
        diffoscope --text "${DIFF_OUTPUT}/diffoscope-report.txt" \
                   --html "${DIFF_OUTPUT}/diffoscope-report.html" \
                   "${file1}" "${file2}" 2>&1 | head -n 100 || true

        if [ -f "${DIFF_OUTPUT}/diffoscope-report.html" ]; then
            log_info "Detailed report saved to: ${DIFF_OUTPUT}/diffoscope-report.html"
        fi
    else
        log_info "Diffoscope not available, skipping detailed analysis"
        log_info "Install diffoscope for detailed reproducibility reports: nix-shell -p diffoscope"
    fi

    # Create summary report
    cat > "${DIFF_OUTPUT}/summary.txt" << EOF
Reproducibility Check Summary
============================
Date: $(date -u)
Kernel Source: ${KERNEL_ROOT}

Build 1: ${BUILD_DIR1}
Build 2: ${BUILD_DIR2}

Kernel Image: ${KERNEL_IMAGE}
  Build 1 SHA256: $(sha256sum "${file1}" | cut -d' ' -f1)
  Build 2 SHA256: $(sha256sum "${file2}" | cut -d' ' -f1)
  Size Build 1: $(stat -c%s "${file1}") bytes
  Size Build 2: $(stat -c%s "${file2}") bytes

Files Compared:
EOF

    # Add comparison results for each file
    for artifact in "${KERNEL_IMAGE}" "System.map" ".config" "vmlinux"; do
        if [ -f "${BUILD_DIR1}/${artifact}" ] && [ -f "${BUILD_DIR2}/${artifact}" ]; then
            if cmp -s "${BUILD_DIR1}/${artifact}" "${BUILD_DIR2}/${artifact}"; then
                echo "  ✓ ${artifact}: IDENTICAL" >> "${DIFF_OUTPUT}/summary.txt"
            else
                echo "  ✗ ${artifact}: DIFFERENT" >> "${DIFF_OUTPUT}/summary.txt"
            fi
        fi
    done

    log_info "Summary report saved to: ${DIFF_OUTPUT}/summary.txt"
}

generate_report() {
    log_step "Generating reproducibility report..."

    if [ ! -d "${DIFF_OUTPUT}" ]; then
        mkdir -p "${DIFF_OUTPUT}"
    fi

    # Copy build info from both builds
    cp "${BUILD_DIR1}/build-info.txt" "${DIFF_OUTPUT}/build1-info.txt" 2>/dev/null || true
    cp "${BUILD_DIR2}/build-info.txt" "${DIFF_OUTPUT}/build2-info.txt" 2>/dev/null || true

    # Create overall report
    {
        echo "========================================"
        echo "Reproducibility Check Report"
        echo "========================================"
        echo ""
        echo "Timestamp: $(date -u)"
        echo "Kernel Source: ${KERNEL_ROOT}"
        echo ""

        if [ -f "${DIFF_OUTPUT}/summary.txt" ]; then
            cat "${DIFF_OUTPUT}/summary.txt"
        fi

        echo ""
        echo "For detailed analysis, see:"
        echo "  - ${DIFF_OUTPUT}/summary.txt"
        echo "  - ${DIFF_OUTPUT}/binary-diff.txt"
        if [ -f "${DIFF_OUTPUT}/diffoscope-report.html" ]; then
            echo "  - ${DIFF_OUTPUT}/diffoscope-report.html"
        fi
    } > "${DIFF_OUTPUT}/README.txt"

    cat "${DIFF_OUTPUT}/README.txt"
}

main() {
    log_info "Starting reproducibility check..."
    log_info "This will build the kernel twice and compare the outputs"
    echo ""

    # Trap to cleanup on exit
    trap 'cleanup_builds' EXIT

    # Clean previous builds
    cleanup_builds

    # Build twice
    build_kernel_twice

    echo ""
    log_step "Comparing build outputs..."

    # Compare the builds
    if compare_checksums; then
        echo ""
        log_info "================================"
        log_info "✓ BUILD IS REPRODUCIBLE! ✓"
        log_info "================================"
        echo ""
        log_info "Both builds produced identical artifacts"
        RESULT=0
    else
        echo ""
        log_error "================================"
        log_error "✗ BUILD IS NOT REPRODUCIBLE ✗"
        log_error "================================"
        echo ""
        log_error "The builds produced different artifacts"

        # Find and report differences
        find_differences
        RESULT=1
    fi

    # Generate report
    generate_report

    # Keep builds for inspection if not reproducible
    if [ ${RESULT} -ne 0 ]; then
        trap 'cleanup_builds keep' EXIT
        log_info "Build directories preserved for inspection:"
        log_info "  ${BUILD_DIR1}"
        log_info "  ${BUILD_DIR2}"
    fi

    return ${RESULT}
}

# Parse command line arguments
KEEP_BUILDS=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --keep-builds)
            KEEP_BUILDS=true
            trap 'cleanup_builds keep' EXIT
            shift
            ;;
        --no-diffoscope)
            USE_DIFFOSCOPE=false
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [ARCH] [OPTIONS]"
            echo ""
            echo "Arguments:"
            echo "  ARCH               Architecture: x64, arm64 (default: x64)"
            echo ""
            echo "Options:"
            echo "  --keep-builds      Keep build directories after comparison"
            echo "  --no-diffoscope    Don't use diffoscope for detailed analysis"
            echo "  --help, -h         Show this help message"
            echo ""
            echo "This script builds the kernel twice with identical settings"
            echo "and compares the outputs to verify reproducibility."
            echo ""
            echo "Examples:"
            echo "  $0 x64                    - Check reproducibility for x64"
            echo "  $0 arm64 --keep-builds    - Check arm64 and keep build dirs"
            exit 0
            ;;
        *)
            # Non-option argument (architecture), already handled in parsing above
            shift
            ;;
    esac
done

log_info "Checking reproducibility for architecture: ${ARCH_TYPE}"

main
