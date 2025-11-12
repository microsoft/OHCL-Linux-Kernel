#!/bin/bash -e

set -o pipefail
# set -x

# ============================================================================
# OHCL Linux Kernel - CVM Config Merger with Reproducibility Support
# ============================================================================

#Get the script's directory (M folder)
SCRIPT_DIR=$(dirname "$(realpath "$0")")
TOOLCHAIN_FILE="${SCRIPT_DIR}/TOOLCHAIN_VERSIONS"

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# Quick toolchain check for reproducibility
if [ -f "$TOOLCHAIN_FILE" ]; then
    echo "Checking toolchain for reproducibility..."
    
    get_gcc_version() { gcc --version | head -n1 | grep -oP '\d+\.\d+\.\d+' || echo "unknown"; }
    BASELINE_GCC=$(grep "^GCC_VERSION=" "$TOOLCHAIN_FILE" | cut -d'=' -f2)
    CURRENT_GCC=$(get_gcc_version)
    
    if [ "$CURRENT_GCC" != "$BASELINE_GCC" ]; then
        echo -e "${YELLOW}⚠ WARNING${NC}: GCC version differs from baseline"
        echo "  This may affect reproducibility of the merged config"
    else
        echo -e "${GREEN}✓${NC} Toolchain matches baseline"
    fi
    echo ""
fi

# Kernel root is assumed to be the parent directory of the M folder
KERNEL_ROOT_DIR=$(dirname "$SCRIPT_DIR")

# Ensure the script is being run from the kernel root directory
if [[ "$(pwd)" != "$KERNEL_ROOT_DIR" ]]; then
	echo "Error: Please run this script from the top-level ${KERNEL_ROOT_DIR} folder."
    exit 1
fi

# Define paths to configurations
BASE_CONFIG_X64="${SCRIPT_DIR}/hcl-x64.config"
FRAGMENT_CONFIG_X64="${SCRIPT_DIR}/x64-cvm.config"
BASE_CONFIG_ARM64="${SCRIPT_DIR}/hcl-arm64.config"
FRAGMENT_CONFIG_ARM64="${SCRIPT_DIR}/arm64-cvm.config"

# Determine the architecture
ARCH=$(uname -m)

# Adjust the architecture name for x86_64 to x64
if [ "$ARCH" == "x86_64" ]; then
    ARCH="x64"
elif [ "$ARCH" == "aarch64" ]; then
    ARCH="arm64"
else
    echo "Unsupported architecture: $ARCH" 1>&2
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
    echo "Unsupported architecture: $ARCH" 1>&2
    exit 1
fi

# Ensure the provided config files exist
if [ ! -f "$BASE_CONFIG" ]; then
    echo "Base config file $BASE_CONFIG not found!" 1>&2
    exit 1
fi

if [ ! -f "$FRAGMENT_CONFIG" ]; then
    echo "Fragment config file $FRAGMENT_CONFIG not found!" 1>&2
    exit 1
fi

# Copy the base configuration to the .config file
cp "$BASE_CONFIG" "$KERNEL_SRC_PATH.config"

# Merge the fragment configuration into the .config file
./scripts/kconfig/merge_config.sh -m .config "$FRAGMENT_CONFIG"

# Ensure the merged configuration is valid and preserve BUILD_SALT for reproducibility
make olddefconfig

# Ensure BUILD_SALT remains empty for reproducibility
if grep -q "^CONFIG_BUILD_SALT=" .config; then
    sed -i 's/^CONFIG_BUILD_SALT=.*/CONFIG_BUILD_SALT=""/' .config
    echo -e "${GREEN}✓${NC} BUILD_SALT cleared for reproducibility"
fi

mv .config Microsoft/hcl-$ARCH.config
echo "Merged configuration created at Microsoft/hcl-$ARCH.config"
echo -e "${GREEN}✓${NC} Configuration is reproducible-build ready"

make mrproper
