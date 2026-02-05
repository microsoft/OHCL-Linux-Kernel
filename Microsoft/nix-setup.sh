#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Quick setup script for reproducible builds with NixOS

set -euo pipefail

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "==============================================="
echo "OHCL Kernel - Reproducible Build Setup"
echo "==============================================="
echo ""

# Helper function to source nix and update PATH
source_nix_profile() {
    if [ -f ~/.nix-profile/etc/profile.d/nix.sh ]; then
        . ~/.nix-profile/etc/profile.d/nix.sh
        export PATH="$HOME/.nix-profile/bin:$PATH"
        return 0
    elif [ -f /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ]; then
        . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
        export PATH="/nix/var/nix/profiles/default/bin:$PATH"
        return 0
    fi
    return 1
}

# Check if nix is installed
if ! command -v nix &> /dev/null; then
    # Try to source nix profile first in case it's installed but not in PATH
    if source_nix_profile; then
        echo ">>> Nix profile sourced from existing installation"
    fi
fi

# Check again after sourcing
if ! command -v nix &> /dev/null; then
    # Check if /nix directory exists (Nix is installed but profile not sourced)
    if [ -d /nix ]; then
        echo "⚠️  Nix is installed but not in PATH"
        echo ""
        echo "Please restart your shell or run:"
        echo "  . ~/.nix-profile/etc/profile.d/nix.sh"
        echo ""
        echo "Then run this script again: $0"
        exit 0
    fi

    echo "⚠️  Nix is not installed!"
    echo ""
    echo "Installing Nix (single-user installation)..."
    echo "This will download and install Nix package manager."
    echo ""

    # Create nixbld group and users for sandboxed builds (required for Nix sandbox)
    if ! getent group nixbld > /dev/null 2>&1; then
        echo "Creating nixbld group and users for sandbox..."
        groupadd -r nixbld || sudo groupadd -r nixbld

        # Create 10 build users (Nix uses these for parallel isolated builds)
        for i in $(seq 1 10); do
            useradd -r -g nixbld -G nixbld \
                -d /var/empty -s /sbin/nologin \
                -c "Nix build user $i" \
                "nixbld$i" 2>/dev/null || \
            sudo useradd -r -g nixbld -G nixbld \
                -d /var/empty -s /sbin/nologin \
                -c "Nix build user $i" \
                "nixbld$i" 2>/dev/null || true
        done
        echo "✓ Created nixbld group and 10 build users"
    fi

    # Install Nix
    echo "install nix"
    if curl -L https://nixos.org/nix/install | sh -s -- --no-daemon; then
        echo ""
        echo "✓ Nix installed successfully!"
        echo ""
        # Source nix profile immediately for current session
        if source_nix_profile; then
            echo "✓ Nix environment loaded"
        else
            echo "⚠️  Could not source Nix profile"
        fi
        # Continue with setup instead of exiting
    else
        echo ""
        echo "❌ Nix installation failed!"
        echo ""
        echo "You can try manually installing with:"
        echo "  curl -L https://nixos.org/nix/install | sh"
        echo ""
        echo "Or for multi-user installation:"
        echo "  curl -L https://nixos.org/nix/install | sh -s -- --daemon"
        echo ""
        exit 1
    fi
fi

echo "✓ Nix is installed"

# Check if flakes are enabled
echo "Enabling flakes..."
mkdir -p ~/.config/nix
if ! grep -q "experimental-features.*flakes" ~/.config/nix/nix.conf 2>/dev/null; then
    echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf
    echo "✓ Flakes enabled in ~/.config/nix/nix.conf"
else
    echo "✓ Flakes already enabled in ~/.config/nix/nix.conf"
fi

# Verify flakes work (only when this repo contains a flake)
if [ -f "${KERNEL_ROOT}/flake.nix" ]; then
    if nix --extra-experimental-features "nix-command flakes" flake metadata "${KERNEL_ROOT}" --no-write-lock-file >/dev/null 2>&1; then
        echo "✓ Nix flakes are working"
    else
        echo "⚠ Could not verify flakes, but config is set"
    fi
else
    echo "✓ No flake.nix found; skipping flakes verification"
fi

# Initialize flake.lock if it doesn't exist (must be in kernel root where flake.nix is)
if [ -f "${KERNEL_ROOT}/flake.nix" ]; then
    if [ ! -f "${KERNEL_ROOT}/flake.lock" ]; then
        echo ""
        echo "Initializing flake.lock..."
        cd "${KERNEL_ROOT}"
        nix --extra-experimental-features "nix-command flakes" flake lock
        echo "✓ flake.lock created"
    else
        echo "✓ flake.lock already exists"
    fi
else
    echo "⚠ No flake.nix found in ${KERNEL_ROOT}, skipping flake.lock initialization"
fi

# Source nix profile for current session (ensure it's available)
source_nix_profile && echo "✓ Nix environment ready"

echo ""
echo "==============================================="
echo "Setup Complete!"
echo "==============================================="
echo ""
echo "You can now build the kernel with:"
echo ""
echo "  ./Microsoft/nix-build.sh x64"
echo "  ./Microsoft/nix-build.sh arm64"
echo ""
echo "The script will automatically enter the Nix environment."
echo ""
echo "For more information, run:"
echo "  ./Microsoft/nix-build.sh --help"
echo ""
