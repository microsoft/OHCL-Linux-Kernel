# Quick Start - Reproducible Builds

## First Time Setup (5 minutes)

```bash
# 1. Install dependencies (creates toolchain baseline)
cd OHCL-Linux-Kernel
sudo ./Microsoft/install-deps.sh

# 2. Build the kernel
./Microsoft/build-hcl-kernel.sh x64

# 3. (Optional) Verify reproducibility
./Microsoft/verify-reproducible.sh x64
```

## Regular Build

```bash
cd OHCL-Linux-Kernel
./Microsoft/build-hcl-kernel.sh x64
```

**Output**: `out/build/native/bin/x64/vmlinux`

## What Happens Automatically

✅ Checks all dependencies are installed  
✅ Verifies toolchain matches baseline  
✅ Warns if reproducibility at risk  
✅ Uses git timestamp for deterministic builds  
✅ Records build metadata  

## Files Created

- **`TOOLCHAIN_VERSIONS`** - Your toolchain baseline (auto-generated first build)
- **`out/`** - Build output directory
- **`build/`** - Intermediate build files

## Common Commands

```bash
# Build for ARM64
./Microsoft/build-hcl-kernel.sh arm64

# Merge CVM config (then build normally)
cd OHCL-Linux-Kernel
./Microsoft/merge-cvm-config.sh
./Microsoft/build-hcl-kernel.sh x64

# Verify reproducibility
./Microsoft/verify-reproducible.sh x64

# Update toolchain baseline
rm Microsoft/TOOLCHAIN_VERSIONS
./Microsoft/build-hcl-kernel.sh x64
```

## Warnings Explained

### ⚠ Toolchain Mismatch
Your GCC/binutils/make version differs from baseline.  
**Action**: Press Enter to continue, or install matching versions.

### ⚠ Not a git repository
Using current time instead of git commit timestamp.  
**Action**: Ensure you're in a git repository for reproducibility.

## Need Help?

📖 **Full Documentation**: `Microsoft/README-REPRODUCIBLE-BUILDS.md`  
🔧 **Dependencies**: `sudo ./Microsoft/install-deps.sh`  
✅ **Verification**: `./Microsoft/verify-reproducible.sh x64`

## Distribution

When distributing builds, include:
- `vmlinux` binary
- `TOOLCHAIN_VERSIONS` file
- `kernel_build_metadata.json`
- Git commit hash
- SHA256 checksum

## That's It!

The build system handles reproducibility automatically. Just build normally and it works.
