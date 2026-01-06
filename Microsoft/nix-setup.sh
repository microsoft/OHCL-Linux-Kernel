#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Quick setup script for reproducible builds with NixOS

set -euo pipefail

echo "==============================================="
echo "OHCL Kernel - Reproducible Build Setup"
echo "==============================================="
echo ""

# Check if nix is installed
if ! command -v nix &> /dev/null; then
    echo "⚠️  Nix is not installed!"
    echo ""
    echo "Installing Nix (single-user installation)..."
    echo "This will download and install Nix package manager."
    echo ""

    # Install Nix
    if curl -L https://nixos.org/nix/install | sh -s -- --no-daemon; then
        echo ""
        echo "✓ Nix installed successfully!"
        echo ""
        echo "⚠️  Please restart your shell or run:"
        echo "  . ~/.nix-profile/etc/profile.d/nix.sh"
        echo ""
        echo "Then run this script again: $0"
        exit 0
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

# Verify flakes work
if nix --extra-experimental-features "nix-command flakes" flake --version &> /dev/null 2>&1; then
    echo "✓ Nix flakes are working"
else
    echo "⚠ Could not verify flakes, but config is set"
fi

# Initialize flake.lock if it doesn't exist
if [ ! -f flake.lock ]; then
    echo ""
    echo "Initializing flake.lock..."
    nix --extra-experimental-features "nix-command flakes" flake lock
    echo "✓ flake.lock created"
fi

# Source nix profile for current session
if [ -f ~/.nix-profile/etc/profile.d/nix.sh ]; then
    echo ""
    echo "Sourcing Nix profile for current session..."
    . ~/.nix-profile/etc/profile.d/nix.sh
    echo "✓ Nix environment loaded"
fi

echo ""
echo "==============================================="
echo "Setup Complete!"
echo "==============================================="
echo ""
echo "You can now build the kernel directly with:"
echo ""
echo "  ./Microsoft/nix-build.sh x64"
echo ""
echo "Or verify reproducibility with:"
echo ""
echo "  ./Microsoft/nix-check-repro.sh x64"
echo ""
echo "The scripts will automatically enter the Nix environment."
echo ""
echo "Available architectures: x64, arm64"
echo ""
echo "For more information, see:"
echo "  - REPRODUCIBLE-BUILDS.md"
echo "  - ./Microsoft/nix-build.sh --help"
echo ""
