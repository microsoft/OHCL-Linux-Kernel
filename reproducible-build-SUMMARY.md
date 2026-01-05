# Reproducible Builds - Implementation Summary

## Status: ✅ SUCCESSFUL

The OHCL Linux kernel now supports fully reproducible builds using NixOS.

## Results

Both builds produce **identical binaries**:
- **Kernel Image SHA256**: `9f3ca28eba716f59d18ee06b8739383738f8b8eee091b23e8f094e33a6e4eb1b`
- **vmlinux**: IDENTICAL ✓
- **System.map**: IDENTICAL ✓
- **Kernel config**: IDENTICAL ✓

## Implementation Details

### NixOS Build System
- **flake.nix**: Defines reproducible build environment with pinned dependencies
- **flake.lock**: Locks nixpkgs to specific commit for deterministic package versions
- All build scripts in `Microsoft/` directory

### Key Scripts
1. **nix-build.sh**: Main build script with reproducible environment variables
2. **nix-check-repro.sh**: Verifies reproducibility by building twice and comparing
3. **nix-clean.sh**: Cleans build artifacts
4. **nix-shell.sh**: Enters reproducible development environment

### Reproducibility Techniques

1. **Deterministic Timestamps**:
   - `SOURCE_DATE_EPOCH=1609459200` (2021-01-01 00:00:00 UTC)
   - All file timestamps normalized to this epoch

2. **Normalized Build Environment**:
   - `KBUILD_BUILD_USER=builder`
   - `KBUILD_BUILD_HOST=nixos`
   - `KBUILD_BUILD_VERSION=1`
   - `LANG=C.UTF-8`, `TZ=UTC`

3. **Debug Prefix Mapping**:
   - `KCFLAGS/KAFLAGS=-fdebug-prefix-map=${KERNEL_ROOT}=/build/source`
   - Maps absolute paths to normalized paths in debug info

4. **Consistent Directory Names** (Critical Fix):
   - Both builds use same directory name: `BUILD_OUTPUT=build`
   - Previous issue: Different directory names (build-repro-1 vs build-repro-2) were embedded in binary
   - Solution: Use same name, clean between builds, copy results for comparison

5. **Kernel Configuration**:
   - `CONFIG_BUILD_SALT=""` (empty string for reproducible build IDs)
   - `CONFIG_GCC_PLUGIN_RANDSTRUCT_NONE=y` (no random struct layout)

## Testing

### Verified Working
- ✅ x64 architecture with default config
- ✅ Multiple consecutive builds produce identical binaries

### To Test
- ⏳ arm64 architecture
- ⏳ CVM (Confidential VM) builds
- ⏳ Custom configurations

## Usage

### Quick Start
```bash
# Enter reproducible environment
./Microsoft/nix-shell.sh

# Build kernel
./Microsoft/nix-build.sh x64

# Verify reproducibility
./Microsoft/nix-check-repro.sh x64
```

### Architecture Support
- x64: `./Microsoft/nix-build.sh x64`
- arm64: `./Microsoft/nix-build.sh arm64`

### CVM Builds
```bash
./Microsoft/nix-build.sh x64 cvm
./Microsoft/nix-check-repro.sh x64 cvm
```

## Technical Deep Dive

### The Path Embedding Problem

**Initial Issue**: Builds differed by 42 bytes despite identical source and environment.

**Root Cause Analysis**:
```bash
# Hex dump showed embedded paths
hexdump -C build-repro-1/arch/x86/boot/bzImage | grep -A2 -B2 "ld-repro"
# Result: "build-repro-1" vs "build-repro-2" embedded at offset 0x051a7b40

# Strings confirmed paths in binary
strings build-repro-1/vmlinux | grep build-repro
# Result: /build/source/build-repro-1 appeared multiple times
```

**Why -fdebug-prefix-map Wasn't Enough**:
- `-fdebug-prefix-map` only affects debug information (DWARF sections)
- Build directory paths were embedded as **data strings** in the binary
- These data strings come from kernel's build system (__FILE__ macros, etc.)
- Cannot be remapped by compiler flags alone

**Solution**:
- Use **identical directory name** for both builds: `build/`
- Clean directory between builds: `rm -rf build`
- Copy results to separate dirs for comparison: `build-repro-1/`, `build-repro-2/`
- This ensures embedded paths are identical: `/build/source/build`

### Attempted Solutions (Historical)

1. ❌ **Map BUILD_OUTPUT path**: Added `-fdebug-prefix-map=${BUILD_OUTPUT}=/build/output`
   - Failed: Paths still embedded (not just in debug info)

2. ❌ **Map intermediate paths**: Added mappings for `/build/source/build-repro-X`
   - Failed: Too late in compilation, paths already embedded

3. ❌ **Complex multi-level mapping**: Tried mapping relative paths
   - Failed: Overly complex, didn't address root cause

4. ✅ **Same directory name**: Use `build/` for both builds
   - **SUCCESS**: Eliminates path differences at the source

## Branch Information

- **Branch**: `repro-build-nix`
- **Based On**: `origin/product/hcl-main/6.12` (Linux 6.12.52)
- **Commits Ahead**: 7 commits

## Commit History

1. `9af973333c13`: Add NixOS reproducible build system for OHCL kernel
2. `735a9e29d006`: Add flake.lock with pinned Nix dependencies
3. `521e4144e68b`: Fix reproducibility: Map build output directory to fixed path
4. `6082ee0b52bb`: Fix reproducibility: Map intermediate path transformations
5. `8b810de007a4`: Add debug output for path mapping in reproducible builds
6. `036dc569974b`: Simplify reproducible build: Remove complex BUILD_OUTPUT path mapping
7. `1b0908c24cde`: Fix reproducibility: Use same build directory name for both builds ✅

## NixOS Setup Requirements

### Installing Nix
```bash
# Single-user installation (recommended)
sh <(curl -L https://nixos.org/nix/install) --no-daemon

# Enable flakes
mkdir -p ~/.config/nix
echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf
```

### Environment
- Nix version: 2.33.0 or later
- Flakes enabled
- nixpkgs: Pinned to commit `b134951a4c9fd` in flake.lock

## References

- NixOS Reproducible Builds: https://reproducible.nixos.org/
- Reproducible Builds Project: https://reproducible-builds.org/
- Kernel Build System: https://www.kernel.org/doc/html/latest/kbuild/
- Debug Prefix Map: https://gcc.gnu.org/onlinedocs/gcc/Debugging-Options.html

## Future Work

1. Test arm64 architecture reproducibility
2. Test CVM configuration reproducibility
3. Consider upstreaming to main branch
4. Document in official OHCL build documentation
5. Set up CI/CD reproducibility checks

## Credits

Implemented using NixOS reproducible build techniques and Linux kernel build system knowledge.
Issue resolution followed systematic debugging with hex dumps, strings analysis, and iterative testing.

---

**Date**: January 2026
**Kernel Version**: 6.12.52-microsoft-hcl+
**Build System**: NixOS with Flakes
