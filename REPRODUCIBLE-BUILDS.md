# Reproducible Builds with NixOS for OHCL Linux Kernel

This repository includes a complete reproducible build system using NixOS, based on the principles from [reproducible.nixos.org](https://reproducible.nixos.org/).

## Overview

Reproducible builds ensure that building the kernel from the same source code produces bit-for-bit identical binaries, which:
- Verifies build infrastructure integrity
- Prevents supply chain attacks
- Enables independent verification
- Ensures build consistency across environments

## Prerequisites

### Installing Nix

If you don't have Nix installed:

```bash
# Install Nix (single-user installation)
sh <(curl -L https://nixos.org/nix/install) --no-daemon

# Or multi-user installation (recommended for Linux)
sh <(curl -L https://nixos.org/nix/install) --daemon

# Enable flakes (required)
mkdir -p ~/.config/nix
echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf
```

### For ARM64 Cross-Compilation

The build system automatically handles cross-compilation for ARM64 using the tools specified in the flake.

## Quick Start

### 1. Enter the Development Environment

```bash
# Enter the reproducible build environment
nix develop

# This will:
# - Install all required build dependencies
# - Set up reproducible environment variables
# - Configure the shell for kernel building
```

### 2. Build the Kernel

```bash
# Build using the reproducible build script
./Microsoft/nix-build.sh

# Or specify a custom build output directory
BUILD_OUTPUT=./my-build ./Microsoft/nix-build.sh

# Build for ARM64 (handled by existing Microsoft scripts integration)
# First, use menuconfig to select arm64 config:
./Microsoft/nix-menuconfig.sh
# Then build:
./Microsoft/nix-build.sh
```

### 3. Verify Reproducibility

```bash
# Build twice and compare outputs
./Microsoft/nix-check-repro.sh

# This will:
# - Build the kernel twice with identical settings
# - Compare all output artifacts
# - Generate a detailed reproducibility report
```

## Available Scripts

### Core Build Scripts

#### `./Microsoft/nix-build.sh`
Main build script with reproducible environment settings.

```bash
# Basic build
./Microsoft/nix-build.sh

# Clean build artifacts
./Microsoft/nix-build.sh clean

# Show help
./Microsoft/nix-build.sh help

# Environment variables:
BUILD_OUTPUT=./build       # Output directory
MAKE_JOBS=8               # Parallel jobs (default: nproc)
CONFIG_FILE=./.config     # Kernel config file
SOURCE_DATE_EPOCH=...     # Fixed timestamp for reproducibility
```

#### `./Microsoft/nix-check-repro.sh`
Verify build reproducibility by building twice and comparing.

```bash
# Check reproducibility
./Microsoft/nix-check-repro.sh

# Keep build directories for inspection
./Microsoft/nix-check-repro.sh --keep-builds

# Skip diffoscope analysis
./Microsoft/nix-check-repro.sh --no-diffoscope
```

### Helper Scripts

#### `./Microsoft/nix-menuconfig.sh`
Configure kernel with ncurses menu interface.

```bash
./Microsoft/nix-menuconfig.sh
```

#### `./Microsoft/nix-clean.sh`
Remove all build artifacts and temporary files.

```bash
./Microsoft/nix-clean.sh
```

#### `./Microsoft/nix-build-info.sh`
Display build information and checksums.

```bash
# Show info for default build
./Microsoft/nix-build-info.sh

# Show info for specific build
./Microsoft/nix-build-info.sh ./build-repro-1
```

#### `./Microsoft/nix-verify-config.sh`
Verify kernel configuration has reproducible build settings.

```bash
./Microsoft/nix-verify-config.sh [config-file]
```

## Integration with Existing Build Scripts

The reproducible build system integrates with the existing Microsoft build scripts:

### Building with Microsoft Scripts in Reproducible Environment

```bash
# Enter nix development environment
nix develop

# Use existing build scripts
./Microsoft/build-hcl-kernel.sh arm64

# Or for x64
./Microsoft/build-hcl-kernel.sh x64
```

The Nix environment provides:
- Consistent toolchain versions
- Reproducible timestamps via `SOURCE_DATE_EPOCH`
- Normalized build environment variables
- All required dependencies

## Reproducible Build Configuration

The build system uses these settings for reproducibility:

### Environment Variables

```bash
SOURCE_DATE_EPOCH=1609459200           # Fixed timestamp (2021-01-01)
LANG=C.UTF-8                          # Consistent locale
LC_ALL=C.UTF-8                        # Consistent locale
TZ=UTC                                # UTC timezone
KBUILD_BUILD_TIMESTAMP=@1609459200    # Kernel build timestamp
KBUILD_BUILD_USER=builder             # Consistent username
KBUILD_BUILD_HOST=nixos               # Consistent hostname
KBUILD_BUILD_VERSION=1                # Fixed version number
```

### Compiler Flags

```bash
KCFLAGS=-fdebug-prefix-map=${PWD}=/build/source
KAFLAGS=-fdebug-prefix-map=${PWD}=/build/source
```

These flags normalize filesystem paths in debug information.

## Advanced Usage

### Using Nix Flake Directly

```bash
# Build kernel as a Nix package
nix build

# Run build app
nix run .#build

# Run reproducibility check app
nix run .#check-repro

# Enter development shell
nix develop

# Update flake inputs (dependencies)
nix flake update
```

### Custom SOURCE_DATE_EPOCH

To use a different timestamp (e.g., based on git commit):

```bash
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
./scripts/nix-build.sh
```

### Building Different Configurations

```bash
# Build with arm64 configuration
export KCONFIG_CONFIG=Microsoft/hcl-arm64.config
./scripts/nix-build.sh

# Build with x64 configuration
export KCONFIG_CONFIG=Microsoft/hcl-x64.config
./scripts/nix-build.sh
```

## Verifying Reproducibility

### Understanding the Report

After running `./scripts/nix-check-repro.sh`, you'll get:

- **reproducibility-report/summary.txt**: Overall comparison results
- **reproducibility-report/binary-diff.txt**: Byte-level differences (if any)
- **reproducibility-report/diffoscope-report.html**: Detailed analysis (if diffoscope available)
- **reproducibility-report/README.txt**: Human-readable summary

### Expected Results

**Reproducible Build:**
```
✓ BUILD IS REPRODUCIBLE! ✓
Both builds produced identical artifacts
```

**Non-Reproducible Build:**
```
✗ BUILD IS NOT REPRODUCIBLE ✗
The builds produced different artifacts
See reproducibility-report/ for details
```

### Common Reproducibility Issues

1. **Timestamps**: Fixed by `SOURCE_DATE_EPOCH` and kernel build flags
2. **Usernames/Hostnames**: Fixed by `KBUILD_BUILD_USER` and `KBUILD_BUILD_HOST`
3. **Filesystem paths**: Fixed by `-fdebug-prefix-map` flags
4. **Random data**: Should use seeded RNG (kernel config dependent)
5. **Parallel build ordering**: Usually not an issue with modern make

## Troubleshooting

### Build Fails in Nix Environment

```bash
# Make sure flakes are enabled
nix flake show

# Update flake inputs
nix flake update

# Clear nix cache if needed
nix-collect-garbage -d
```

### Reproducibility Check Fails

```bash
# Run with --keep-builds to inspect
./Microsoft/nix-check-repro.sh --keep-builds

# Compare specific files
diff build-repro-1/vmlinux build-repro-2/vmlinux

# Use diffoscope for detailed analysis
diffoscope build-repro-1/vmlinux build-repro-2/vmlinux
```

### Missing Dependencies

```bash
# The Nix environment should provide everything, but if needed:
nix develop --impure  # Allow impure dependencies

# Or add to flake.nix buildInputs
```

## Architecture Support

The build system supports:

- **x86_64**: Native and cross-compilation
- **arm64/aarch64**: Cross-compilation with `aarch64-linux-gnu-*` tools
- Other architectures can be added by updating `flake.nix`

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Reproducible Build Check

on: [push, pull_request]

jobs:
  reproducible-build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Nix
        uses: cachix/install-nix-action@v22
        with:
          extra_nix_config: |
            experimental-features = nix-command flakes

      - name: Check Reproducibility
        run: |
          nix develop --command ./scripts/nix-check-repro.sh

      - name: Upload Report
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: reproducibility-report
          path: reproducibility-report/
```

## Development Workflow

### Typical Development Cycle

1. **Enter Nix environment**: `nix develop`
2. **Configure kernel**: `./Microsoft/nix-menuconfig.sh`
3. **Build**: `./Microsoft/nix-build.sh`
4. **Test changes**: Deploy and test kernel
5. **Verify reproducibility**: `./Microsoft/nix-check-repro.sh`
6. **Commit changes**: Include config and build scripts

### Making Changes to Build System

The build system consists of:

- `flake.nix`: Nix flake defining dependencies and build environment
- `Microsoft/nix-*.sh`: Build and verification scripts
- `Microsoft/*.config`: Kernel configurations

Changes to any of these should be tested with reproducibility checks.

## Resources

- [Reproducible Builds Project](https://reproducible-builds.org/)
- [NixOS Reproducible Builds](https://reproducible.nixos.org/)
- [Nix Manual](https://nixos.org/manual/nix/stable/)
- [Nix Flakes](https://nixos.wiki/wiki/Flakes)
- [Linux Kernel Build System](https://www.kernel.org/doc/html/latest/kbuild/)

## Contributing

When contributing to the build system:

1. Test reproducibility: `./Microsoft/nix-check-repro.sh`
2. Verify existing builds still work
3. Document any new environment variables or scripts
4. Update this README with new features

## License

The reproducible build scripts are provided under GPL-2.0, consistent with the Linux kernel license.

## Support

For issues with:
- **Reproducible builds**: Check [reproducibility-report/](./reproducibility-report/) output
- **Nix environment**: Verify Nix installation and flake.lock
- **Kernel building**: See kernel build logs in build output directory
- **Scripts**: Run with `bash -x` for debug output

## Acknowledgments

This reproducible build system is based on:
- [NixOS](https://nixos.org/) for declarative, reproducible environments
- [Reproducible Builds Project](https://reproducible-builds.org/) for guidelines and tools
- Linux kernel build system documentation and best practices
