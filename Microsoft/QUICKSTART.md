# Quick Reference - Reproducible Builds

## One-Time Setup

```bash
# 1. Run setup script
./Microsoft/nix-setup.sh

# 2. Enter development environment
nix develop
```

## Common Commands

```bash
# Build kernel
./Microsoft/nix-build.sh

# Check reproducibility
./Microsoft/nix-check-repro.sh

# Configure kernel
./Microsoft/nix-menuconfig.sh

# Clean builds
./Microsoft/nix-clean.sh

# View build info
./Microsoft/nix-build-info.sh
```

## Using with Existing Build Scripts

```bash
# Enter nix environment first
nix develop

# Then use Microsoft scripts
./Microsoft/build-hcl-kernel.sh arm64
./Microsoft/build-hcl-kernel.sh x64
```

## Key Environment Variables

```bash
BUILD_OUTPUT=./build           # Where to build
MAKE_JOBS=8                    # Parallel jobs
CONFIG_FILE=./path/to/.config  # Kernel config
SOURCE_DATE_EPOCH=1609459200   # Fixed timestamp
```

## Troubleshooting

```bash
# Build fails?
nix flake update           # Update dependencies
nix develop --command bash # Debug in nix shell

# Reproducibility fails?
./Microsoft/nix-check-repro.sh --keep-builds
diffoscope build-repro-1/vmlinux build-repro-2/vmlinux

# Clean everything
./Microsoft/nix-clean.sh
rm -rf build-repro-* reproducibility-report/
```

## File Structure

```
flake.nix                        # Nix flake configuration
REPRODUCIBLE-BUILDS.md           # Full documentation
Microsoft/
  nix-setup.sh                   # Initial setup
  nix-build.sh                   # Build kernel
  nix-check-repro.sh             # Verify reproducibility
  nix-menuconfig.sh              # Configure kernel
  nix-clean.sh                   # Clean artifacts
  nix-build-info.sh              # Show build info
  nix-verify-config.sh           # Check config
```

## For More Details

See `REPRODUCIBLE-BUILDS.md` for comprehensive documentation.
