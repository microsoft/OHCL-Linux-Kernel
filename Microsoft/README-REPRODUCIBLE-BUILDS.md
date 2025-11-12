# OHCL Linux Kernel - Reproducible Builds Guide

## Overview

This kernel repository is configured for **reproducible builds** - the ability to rebuild the kernel from source and get bit-for-bit identical binaries. This is crucial for:

- **Security**: Verify that distributed binaries match the source code
- **Trust**: Anyone can verify the build independently
- **Compliance**: Meet standards for software supply chain security
- **Debugging**: Ensure consistent binaries across environments

## Quick Start

### First-Time Setup

1. **Install dependencies** (records toolchain baseline):
```bash
cd OHCL-Linux-Kernel
sudo ./Microsoft/install-deps.sh
```

2. **Build the kernel** (automatically configured for reproducibility):
```bash
./Microsoft/build-hcl-kernel.sh x64
```

3. **Verify reproducibility** (optional but recommended):
```bash
./Microsoft/verify-reproducible.sh x64
```

That's it! The build system automatically handles all reproducibility requirements.

## How It Works

### Automatic Features

The build system automatically:

1. **Records Toolchain Baseline**: First build creates `TOOLCHAIN_VERSIONS` with exact tool versions
2. **Verifies On Each Build**: Subsequent builds check if toolchain matches baseline
3. **Warns About Mismatches**: Clear warnings if reproducibility is at risk
4. **Sets Deterministic Environment**: 
   - Uses `SOURCE_DATE_EPOCH` from git commit timestamp
   - Fixed build user/host identifiers
   - Normalized file paths in debug info
   - Deterministic locale and timezone

### Key Files

- **`TOOLCHAIN_VERSIONS`**: Auto-generated baseline of tool versions
- **`build-hcl-kernel.sh`**: Enhanced build script with reproducibility
- **`install-deps.sh`**: Installs pinned dependencies
- **`verify-reproducible.sh`**: Verifies two builds produce identical output
- **`merge-cvm-config.sh`**: Config merger preserving BUILD_SALT

## Usage

### Normal Build

```bash
cd OHCL-Linux-Kernel
./Microsoft/build-hcl-kernel.sh x64      # or arm64
```

**Output**: `out/build/native/bin/x64/vmlinux`

The build automatically:
- Checks dependencies exist
- Verifies toolchain matches baseline (warns if not)
- Sets reproducible environment
- Records build metadata

### Building with CVM Config

```bash
cd OHCL-Linux-Kernel
./Microsoft/merge-cvm-config.sh          # Merges CVM config
./Microsoft/build-hcl-kernel.sh x64      # Then build normally
```

The merge script preserves `CONFIG_BUILD_SALT=""` for reproducibility.

### Verifying Reproducibility

```bash
cd OHCL-Linux-Kernel
./Microsoft/verify-reproducible.sh x64
```

This:
1. Builds the kernel twice from scratch
2. Compares outputs bit-for-bit
3. Reports if builds are identical
4. Generates attestation if successful

**Expected output**: `✓ SUCCESS - BUILD IS REPRODUCIBLE!`

## Understanding Warnings

### Toolchain Mismatch Warning

```
⚠ REPRODUCIBILITY WARNING - CRITICAL TOOLCHAIN MISMATCH

Your toolchain versions differ from the recorded baseline.
This build will NOT be bit-for-bit reproducible with previous builds.
```

**What it means**: Your GCC, binutils, or make version differs from the baseline recorded in `TOOLCHAIN_VERSIONS`.

**Impact**: The build will succeed and produce a working kernel, but the binary output will differ from previous builds made with the baseline toolchain.

**Options**:
1. **Continue anyway**: Press Enter. Build works but isn't reproducible with baseline.
2. **Install matching toolchain**: Install the versions listed in `TOOLCHAIN_VERSIONS`
3. **Update baseline**: Delete `TOOLCHAIN_VERSIONS` and rebuild to create new baseline

### Not a Git Repository Warning

```
⚠ WARNING: Not a git repository
Using current time (NOT REPRODUCIBLE across time)
```

**What it means**: The source directory isn't a git repository, so `SOURCE_DATE_EPOCH` uses current time instead of commit timestamp.

**Impact**: Each build will have different timestamps, making it non-reproducible across different build times.

**Solution**: Ensure you're building from a git repository clone.

## Advanced Topics

### Updating Toolchain Baseline

To update the baseline with current tool versions:

```bash
rm OHCL-Linux-Kernel/Microsoft/TOOLCHAIN_VERSIONS
./Microsoft/build-hcl-kernel.sh x64  # Creates new baseline
```

**When to update**:
- After OS upgrade
- After intentional toolchain update
- When starting fresh on new build system

### Cross-Architecture Builds

For ARM64:
```bash
./Microsoft/build-hcl-kernel.sh arm64
./Microsoft/verify-reproducible.sh arm64
```

Requires `aarch64-linux-gnu-gcc` (installed by `install-deps.sh`).

### Build Metadata

Each build records metadata in:
```
out/build/native/bin/<arch>/kernel_build_metadata.json
```

Contains:
- Build timestamp (SOURCE_DATE_EPOCH)
- Git commit hash
- GCC version
- Reproducibility status

### Distributing Builds

When distributing kernel binaries, also provide:

1. **Source Information**:
   - Git repository URL
   - Commit hash (from metadata JSON)

2. **Build Environment**:
   - `TOOLCHAIN_VERSIONS` file
   - OS version (Ubuntu 22.04 LTS recommended)

3. **Verification**:
   - SHA256 checksum of `vmlinux`
   - Reproducibility attestation (if generated)

**Example distribution package**:
```
ohcl-kernel-6.12.52/
├── vmlinux
├── vmlinux.dbg
├── TOOLCHAIN_VERSIONS
├── kernel_build_metadata.json
├── CHECKSUMS.txt
└── reproducibility-attestation.txt
```

## Troubleshooting

### Build Fails with Missing Dependencies

```bash
sudo ./Microsoft/install-deps.sh
```

### Verification Shows Differences

1. **Check toolchain**: Ensure `TOOLCHAIN_VERSIONS` matches current tools
2. **Check git status**: Ensure clean working directory
3. **Review differences**: Check `diffoscope-report.txt` if generated
4. **Common causes**:
   - Toolchain version mismatch
   - Building from dirty git tree
   - System time not set correctly

### Reproducibility on Different Machines

For reproducibility across different machines:

1. **Same OS**: Use same OS version (Ubuntu 22.04 LTS recommended)
2. **Same Toolchain**: Match versions in `TOOLCHAIN_VERSIONS`
3. **Same Source**: Build from same git commit
4. **Clean Build**: Always use `make mrproper` or rebuild from scratch

## Technical Details

### SOURCE_DATE_EPOCH

The build uses `SOURCE_DATE_EPOCH` (Unix timestamp) from the git commit timestamp. This:
- Makes all timestamps deterministic
- Allows reproducibility across time
- Follows [reproducible-builds.org](https://reproducible-builds.org) standards

### Compiler Flags

These flags normalize paths in debug info:
```bash
-fdebug-prefix-map=${SRC_DIR}=.
-fmacro-prefix-map=${SRC_DIR}=.
```

### Build Environment

Fixed for determinism:
```bash
LC_ALL=C
TZ=UTC
LANG=C
KBUILD_BUILD_USER=builder
KBUILD_BUILD_HOST=reproducible
```

### Configuration

Key config options:
- `CONFIG_BUILD_SALT=""` - No random salt in build
- `CONFIG_MODULE_SIG=n` - No module signing (contains timestamps)
- `CONFIG_LOCALVERSION="-microsoft-hcl"` - Consistent version string

## References

- [Reproducible Builds](https://reproducible-builds.org/) - Standards and best practices
- [SOURCE_DATE_EPOCH](https://reproducible-builds.org/docs/source-date-epoch/) - Timestamp specification
- [Debian Reproducible Builds](https://wiki.debian.org/ReproducibleBuilds) - Debian's implementation
- [Linux Kernel Documentation](https://www.kernel.org/doc/html/latest/kbuild/reproducible-builds.html) - Kernel-specific guidance

## Support

For issues or questions:
1. Check this documentation
2. Review warning messages (they explain the issue)
3. Verify dependencies with `install-deps.sh`
4. Test reproducibility with `verify-reproducible.sh`

## Version History

- **Initial Release**: Full reproducible builds implementation with:
  - Automatic toolchain verification
  - SOURCE_DATE_EPOCH from git
  - Comprehensive dependency tracking
  - Verification tooling
  - Complete documentation
