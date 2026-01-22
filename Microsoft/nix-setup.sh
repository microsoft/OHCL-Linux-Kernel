#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Quick setup script for reproducible builds with NixOS
# Uses official Nix binaries with nix-user-chroot for rootless installation

set -euo pipefail

# Script directory - all nix files will be stored here
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Local paths (everything stays in the project folder)
NIX_LOCAL_DIR="${SCRIPT_DIR}/.nix-local"
NIX_STORE_DIR="${NIX_LOCAL_DIR}/nix"
NIX_USER_CHROOT="${NIX_LOCAL_DIR}/nix-user-chroot"
NIX_WRAPPER="${SCRIPT_DIR}/nix-local"

echo "==============================================="
echo "OHCL Kernel - Reproducible Build Setup"
echo "==============================================="
echo ""

# Check if already set up
if [ -x "${NIX_WRAPPER}" ] && [ -d "${NIX_STORE_DIR}/store" ]; then
    echo "✓ Local Nix is already installed"
    echo "  Location: ${NIX_LOCAL_DIR}/"
    echo ""
else
    # Check if system nix is available
    if command -v nix &> /dev/null; then
        echo "✓ System Nix is available"
        echo "  Skipping local installation."
        echo ""
    else
        echo "Installing Nix locally (no root required)..."
        echo "Everything will be stored in: ${NIX_LOCAL_DIR}/"
        echo ""

        # Create directories
        mkdir -p "${NIX_LOCAL_DIR}"
        mkdir -p "${NIX_STORE_DIR}"

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
                echo "❌ Unsupported architecture: ${ARCH}"
                exit 1
                ;;
        esac

        # Download nix-user-chroot
        echo "Downloading nix-user-chroot..."
        NIX_USER_CHROOT_URL="https://github.com/nix-community/nix-user-chroot/releases/download/1.2.2/nix-user-chroot-bin-1.2.2-${ARCH}-unknown-linux-musl"
        if ! curl -fsSL "${NIX_USER_CHROOT_URL}" -o "${NIX_USER_CHROOT}"; then
            echo "❌ Failed to download nix-user-chroot"
            exit 1
        fi
        chmod +x "${NIX_USER_CHROOT}"
        echo "✓ Downloaded nix-user-chroot"

        # Download official Nix tarball
        echo "Downloading official Nix..."
        NIX_VERSION="2.24.10"
        NIX_URL="https://releases.nixos.org/nix/nix-${NIX_VERSION}/nix-${NIX_VERSION}-${NIX_ARCH}.tar.xz"
        NIX_TARBALL="${NIX_LOCAL_DIR}/nix.tar.xz"

        if ! curl -fsSL "${NIX_URL}" -o "${NIX_TARBALL}"; then
            echo "❌ Failed to download Nix"
            exit 1
        fi
        echo "✓ Downloaded Nix ${NIX_VERSION}"

        # Extract Nix
        echo "Extracting Nix..."
        tar -xf "${NIX_TARBALL}" -C "${NIX_LOCAL_DIR}"
        NIX_EXTRACTED=$(ls -d "${NIX_LOCAL_DIR}"/nix-*-linux 2>/dev/null | head -1)

        # Install Nix into local store using nix-user-chroot
        echo "Installing Nix to local store..."
        "${NIX_USER_CHROOT}" "${NIX_STORE_DIR}" "${NIX_EXTRACTED}/install" --no-daemon

        # Clean up
        rm -f "${NIX_TARBALL}"
        rm -rf "${NIX_EXTRACTED}"
        echo "✓ Nix installed to ${NIX_STORE_DIR}"

        # Create wrapper script
        cat > "${NIX_WRAPPER}" << 'WRAPPER_EOF'
#!/usr/bin/env bash
# Wrapper to run commands with local Nix store
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NIX_LOCAL_DIR="${SCRIPT_DIR}/.nix-local"
NIX_STORE_DIR="${NIX_LOCAL_DIR}/nix"
NIX_USER_CHROOT="${NIX_LOCAL_DIR}/nix-user-chroot"

if [ ! -x "${NIX_USER_CHROOT}" ]; then
    echo "Error: nix-user-chroot not found. Run ./Microsoft/nix-setup.sh first."
    exit 1
fi

# Source nix profile inside the chroot and run the command
exec "${NIX_USER_CHROOT}" "${NIX_STORE_DIR}" bash -c '
    if [ -f ~/.nix-profile/etc/profile.d/nix.sh ]; then
        . ~/.nix-profile/etc/profile.d/nix.sh
    fi
    exec "$@"
' -- "$@"
WRAPPER_EOF
        chmod +x "${NIX_WRAPPER}"
        echo "✓ Created wrapper script: ${NIX_WRAPPER}"
    fi
fi

# Enable flakes
echo "Configuring flakes..."
mkdir -p ~/.config/nix
if ! grep -q "experimental-features.*flakes" ~/.config/nix/nix.conf 2>/dev/null; then
    echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf
    echo "✓ Flakes enabled in ~/.config/nix/nix.conf"
else
    echo "✓ Flakes already enabled"
fi

# Verify installation
echo ""
echo "Verifying Nix installation..."
if [ -x "${NIX_WRAPPER}" ]; then
    if "${NIX_WRAPPER}" nix --version 2>/dev/null; then
        echo "✓ Local Nix is working"
    else
        echo "⚠️  Local Nix may need initialization on first run"
    fi
elif command -v nix &> /dev/null; then
    nix --version
    echo "✓ System Nix is working"
fi

echo ""
echo "==============================================="
echo "Setup Complete!"
echo "==============================================="
echo ""
if [ -x "${NIX_WRAPPER}" ]; then
    echo "Nix is installed locally in:"
    echo "  Wrapper: ${NIX_WRAPPER}"
    echo "  Store:   ${NIX_STORE_DIR}/"
    echo ""
    echo "To clean up Nix completely, delete:"
    echo "  rm -rf ${NIX_LOCAL_DIR} ${NIX_WRAPPER}"
fi
echo ""
echo "You can now build the kernel with:"
echo ""
echo "  ./Microsoft/nix-build.sh x64"
echo "  ./Microsoft/nix-build.sh arm64"
echo ""
echo "For more information, run:"
echo "  ./Microsoft/nix-build.sh --help"
echo ""
