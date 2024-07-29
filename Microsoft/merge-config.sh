#!/bin/bash

set -x

# Define paths to configurations
KERNEL_SRC_PATH="../"
BASE_CONFIG_X64="hcl-x64.config"
FRAGMENT_CONFIG_X64="x64-cvm.config"
BASE_CONFIG_ARM64="hcl-arm64.config"
FRAGMENT_CONFIG_ARM64="arm64-cvm.config"

# Function to detect the architecture type
arch() {
    uname -m
}

# Determine the architecture
ARCH=$(arch)

# Adjust the architecture name for x86_64 to x64
if [ "$ARCH" == "x86_64" ]; then
    ARCH="x64"
elif [ "$ARCH" != "aarch64" ]; then
    ARCH="arm64"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

# Determine the base and fragment configuration files based on the architecture
if [ "$ARCH" == "x64" ]; then
    BASE_CONFIG="$BASE_CONFIG_X64"
    FRAGMENT_CONFIG="$FRAGMENT_CONFIG_X64"
elif [ "$ARCH" == "arm64" ]; then
    BASE_CONFIG="$BASE_CONFIG_ARM64"
    FRAGMENT_CONFIG="$FRAGMENT_CONFIG_ARM64"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

# Ensure the provided config files exist
if [ ! -f "$BASE_CONFIG" ]; then
    echo "Base config file $BASE_CONFIG not found!"
    exit 1
fi

if [ ! -f "$FRAGMENT_CONFIG" ]; then
    echo "Fragment config file $FRAGMENT_CONFIG not found!"
    exit 1
fi

# Copy the base configuration to the .config file
cp "$BASE_CONFIG" "$KERNEL_SRC_PATH.config"

# Merge the fragment configuration into the .config file
cd "$KERNEL_SRC_PATH"
./scripts/kconfig/merge_config.sh -m .config "Microsoft/$FRAGMENT_CONFIG"

# Ensure the merged configuration is valid
make olddefconfig

mv .config Microsoft/hcl-$ARCH.config
echo "Merged configuration created at Microsoft/hcl-$ARCH-config"
