#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Update script for Nix binaries used in reproducible builds
# This script downloads the latest versions of:
#   - nix-user-chroot (for rootless Nix)
#   - Nix tarballs (optional, for offline builds)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NIX_BIN_DIR="${SCRIPT_DIR}/nix-bin"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
    echo -e "${BLUE}>>>${NC} $*"
}

# Get latest release version from GitHub API
get_latest_github_release() {
    local repo="$1"
    curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" | \
        grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

# Get latest Nix version from nixos.org
get_latest_nix_version() {
    # Fetch the latest stable Nix version
    curl -fsSL "https://releases.nixos.org/nix/latest/install" 2>/dev/null | \
        grep -o 'nix-[0-9.]*' | head -1 | sed 's/nix-//' || \
    curl -fsSL "https://api.github.com/repos/NixOS/nix/releases/latest" | \
        grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

# Update nix-user-chroot binaries
update_nix_user_chroot() {
    log_step "Updating nix-user-chroot..."

    local latest_version
    latest_version=$(get_latest_github_release "nix-community/nix-user-chroot")

    if [ -z "${latest_version}" ]; then
        log_error "Failed to get latest nix-user-chroot version"
        return 1
    fi

    log_info "Latest nix-user-chroot version: ${latest_version}"

    mkdir -p "${NIX_BIN_DIR}"

    # Download x86_64 binary
    log_info "Downloading nix-user-chroot for x86_64..."
    local x86_url="https://github.com/nix-community/nix-user-chroot/releases/download/${latest_version}/nix-user-chroot-bin-${latest_version}-x86_64-unknown-linux-musl"
    if curl -fsSL "${x86_url}" -o "${NIX_BIN_DIR}/nix-user-chroot-x86_64"; then
        chmod +x "${NIX_BIN_DIR}/nix-user-chroot-x86_64"
        log_info "Downloaded nix-user-chroot-x86_64"
    else
        log_error "Failed to download nix-user-chroot for x86_64"
    fi

    # Download aarch64 binary
    log_info "Downloading nix-user-chroot for aarch64..."
    local arm_url="https://github.com/nix-community/nix-user-chroot/releases/download/${latest_version}/nix-user-chroot-bin-${latest_version}-aarch64-unknown-linux-musl"
    if curl -fsSL "${arm_url}" -o "${NIX_BIN_DIR}/nix-user-chroot-aarch64"; then
        chmod +x "${NIX_BIN_DIR}/nix-user-chroot-aarch64"
        log_info "Downloaded nix-user-chroot-aarch64"
    else
        log_error "Failed to download nix-user-chroot for aarch64"
    fi

    # Update version in nix-build.sh comment for reference
    log_info "nix-user-chroot updated to ${latest_version}"
}

# Update the NIX_VERSION in nix-build.sh
update_nix_version_in_script() {
    local new_version="$1"

    log_step "Updating NIX_VERSION in nix-build.sh to ${new_version}..."

    local nix_build_sh="${SCRIPT_DIR}/nix-build.sh"
    local pipeline_sh="${SCRIPT_DIR}/build-hcl-kernel-pipeline.sh"

    if [ -f "${nix_build_sh}" ]; then
        sed -i "s/^NIX_VERSION=\"[^\"]*\"/NIX_VERSION=\"${new_version}\"/" "${nix_build_sh}"
        log_info "Updated nix-build.sh"
    fi

    if [ -f "${pipeline_sh}" ]; then
        sed -i "s/^NIX_VERSION=\"[^\"]*\"/NIX_VERSION=\"${new_version}\"/" "${pipeline_sh}"
        log_info "Updated build-hcl-kernel-pipeline.sh"
    fi
}

# Optionally download Nix tarballs for offline builds
download_nix_tarballs() {
    local version="$1"

    log_step "Downloading Nix ${version} tarballs for offline builds..."

    mkdir -p "${NIX_BIN_DIR}"

    # Download x86_64 tarball
    log_info "Downloading Nix for x86_64-linux..."
    local x86_url="https://releases.nixos.org/nix/nix-${version}/nix-${version}-x86_64-linux.tar.xz"
    if curl -fsSL "${x86_url}" -o "${NIX_BIN_DIR}/nix-${version}-x86_64-linux.tar.xz"; then
        log_info "Downloaded nix-${version}-x86_64-linux.tar.xz"
    else
        log_warn "Failed to download Nix tarball for x86_64"
    fi

    # Download aarch64 tarball
    log_info "Downloading Nix for aarch64-linux..."
    local arm_url="https://releases.nixos.org/nix/nix-${version}/nix-${version}-aarch64-linux.tar.xz"
    if curl -fsSL "${arm_url}" -o "${NIX_BIN_DIR}/nix-${version}-aarch64-linux.tar.xz"; then
        log_info "Downloaded nix-${version}-aarch64-linux.tar.xz"
    else
        log_warn "Failed to download Nix tarball for aarch64"
    fi
}

# Show current versions
show_current_versions() {
    log_step "Current versions:"

    # nix-user-chroot
    if [ -f "${NIX_BIN_DIR}/nix-user-chroot-x86_64" ]; then
        local size_x86=$(ls -lh "${NIX_BIN_DIR}/nix-user-chroot-x86_64" | awk '{print $5}')
        log_info "nix-user-chroot-x86_64: present (${size_x86})"
    else
        log_warn "nix-user-chroot-x86_64: not found"
    fi

    if [ -f "${NIX_BIN_DIR}/nix-user-chroot-aarch64" ]; then
        local size_arm=$(ls -lh "${NIX_BIN_DIR}/nix-user-chroot-aarch64" | awk '{print $5}')
        log_info "nix-user-chroot-aarch64: present (${size_arm})"
    else
        log_warn "nix-user-chroot-aarch64: not found"
    fi

    # NIX_VERSION from scripts
    if [ -f "${SCRIPT_DIR}/nix-build.sh" ]; then
        local nix_version=$(grep '^NIX_VERSION=' "${SCRIPT_DIR}/nix-build.sh" | cut -d'"' -f2)
        log_info "NIX_VERSION in nix-build.sh: ${nix_version}"
    fi

    # Nix tarballs
    local tarballs=$(ls "${NIX_BIN_DIR}"/nix-*.tar.xz 2>/dev/null || true)
    if [ -n "${tarballs}" ]; then
        log_info "Bundled Nix tarballs:"
        for tarball in ${tarballs}; do
            local size=$(ls -lh "${tarball}" | awk '{print $5}')
            log_info "  $(basename "${tarball}") (${size})"
        done
    fi
}

# Clean old Nix tarballs
clean_old_tarballs() {
    log_step "Cleaning old Nix tarballs..."
    rm -f "${NIX_BIN_DIR}"/nix-*.tar.xz
    log_info "Cleaned old tarballs"
}

# Print usage
usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Update Nix binaries for reproducible builds."
    echo ""
    echo "Commands:"
    echo "  all              - Update everything (nix-user-chroot + NIX_VERSION)"
    echo "  nix-user-chroot  - Update only nix-user-chroot binaries"
    echo "  nix-version      - Update NIX_VERSION in scripts to latest"
    echo "  download-nix     - Download Nix tarballs for offline builds"
    echo "  status           - Show current versions"
    echo "  clean            - Remove old Nix tarballs"
    echo "  help             - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 all                    - Update everything to latest"
    echo "  $0 nix-user-chroot        - Update nix-user-chroot only"
    echo "  $0 download-nix           - Download Nix tarballs for offline use"
    echo "  $0 status                 - Show what's currently installed"
    echo ""
}

# Main
main() {
    local command="${1:-help}"

    case "${command}" in
        all)
            update_nix_user_chroot
            echo ""
            local latest_nix
            latest_nix=$(get_latest_nix_version)
            if [ -n "${latest_nix}" ]; then
                update_nix_version_in_script "${latest_nix}"
            else
                log_warn "Could not determine latest Nix version"
            fi
            echo ""
            show_current_versions
            echo ""
            log_info "Update complete! Run 'git diff' to see changes."
            ;;
        nix-user-chroot)
            update_nix_user_chroot
            echo ""
            show_current_versions
            ;;
        nix-version)
            local latest_nix
            latest_nix=$(get_latest_nix_version)
            if [ -n "${latest_nix}" ]; then
                update_nix_version_in_script "${latest_nix}"
            else
                log_error "Could not determine latest Nix version"
                exit 1
            fi
            ;;
        download-nix)
            local nix_version
            if [ -f "${SCRIPT_DIR}/nix-build.sh" ]; then
                nix_version=$(grep '^NIX_VERSION=' "${SCRIPT_DIR}/nix-build.sh" | cut -d'"' -f2)
            fi
            if [ -z "${nix_version:-}" ]; then
                nix_version=$(get_latest_nix_version)
            fi
            if [ -n "${nix_version}" ]; then
                download_nix_tarballs "${nix_version}"
            else
                log_error "Could not determine Nix version"
                exit 1
            fi
            ;;
        status)
            show_current_versions
            ;;
        clean)
            clean_old_tarballs
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            log_error "Unknown command: ${command}"
            usage
            exit 1
            ;;
    esac
}

main "$@"
