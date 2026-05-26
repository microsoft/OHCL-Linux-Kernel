#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Repackage the output of build-hcl-kernel-pipeline.sh into the layout
# expected by the GitHub Actions release pipeline (release_artifacts/<arch>/).
#
# Usage:
#   package-ci-artifacts.sh <build-dir> <ci-arch> <source-dir> <out-dir> \
#       <git-branch> <git-sha> <build-id>
#
#   ci-arch: x64 | cvm-x64 | arm64
#
# Layout produced under <out-dir>/<ci-arch>/:
#   vmlinux                  (stripped, reproducible)
#   vmlinux.dbg              (full debug info)
#   Image                    (arm64 only)
#   kernel_config            (matching .config used for the build)
#   kernel_build_metadata.json
#   modules/                 (kernel modules, stripped)
#   modules/debug-files/     (matching .dbg files)

set -euo pipefail

if [[ $# -lt 7 ]]; then
    echo "Usage: $0 <build-dir> <ci-arch> <source-dir> <out-dir> <git-branch> <git-sha> <build-id>" >&2
    exit 1
fi

BD="$(realpath "$1")"
CI_ARCH="$2"
SRC="$(realpath "$3")"
OUT_BASE="$(realpath -m "$4")"
GIT_BRANCH="$5"
GIT_SHA="$6"
BUILD_ID="$7"

case "$CI_ARCH" in
    x64|cvm-x64)
        OBJCOPY="objcopy"
        CONFIG_SRC="$SRC/Microsoft/hcl-x64.config"
        ;;
    arm64)
        # The Nix shell provides an aarch64 cross objcopy with this prefix
        OBJCOPY="aarch64-unknown-linux-gnu-objcopy"
        CONFIG_SRC="$SRC/Microsoft/hcl-arm64.config"
        ;;
    *)
        echo "Unsupported arch: $CI_ARCH" >&2
        exit 1
        ;;
esac

if ! command -v "$OBJCOPY" >/dev/null 2>&1; then
    # Fall back to host objcopy if the cross binary is unavailable; for arm64
    # this requires aarch64 binutils to be installed.
    if [[ "$CI_ARCH" == "arm64" ]] && command -v aarch64-linux-gnu-objcopy >/dev/null 2>&1; then
        OBJCOPY="aarch64-linux-gnu-objcopy"
    else
        echo "Error: $OBJCOPY not found in PATH" >&2
        exit 1
    fi
fi

ARTIFACTS="$OUT_BASE/$CI_ARCH"
rm -rf "$ARTIFACTS"
mkdir -p "$ARTIFACTS"

echo ">>> Packaging artifacts for $CI_ARCH"
echo "    build dir: $BD"
echo "    output:    $ARTIFACTS"

# Keep vmlinux and vmlinux.dbg in the same layout as the original workflow.
cp -a "$BD/vmlinux"     "$ARTIFACTS/vmlinux"
cp -a "$BD/vmlinux.dbg" "$ARTIFACTS/vmlinux.dbg"
"$OBJCOPY" --strip-all --add-gnu-debuglink="$ARTIFACTS/vmlinux.dbg" "$ARTIFACTS/vmlinux"

# Determine kernel version for locating the kernel image
KVER=""
for candidate in "$BD/include/config/kernel.release" "$BD/linux/include/config/kernel.release"; do
    if [[ -f "$candidate" ]]; then
        KVER="$(cat "$candidate")"
        break
    fi
done

if [[ "$CI_ARCH" == "arm64" ]]; then
    IMG=""
    for candidate in \
        "$BD/linux_dir/boot/Image-$KVER" \
        "$BD/arch/arm64/boot/Image" \
        "$BD/linux/arch/arm64/boot/Image"; do
        if [[ -f "$candidate" ]]; then
            IMG="$candidate"
            break
        fi
    done
    if [[ -z "$IMG" ]]; then
        echo "Error: arm64 Image not found under $BD" >&2
        exit 1
    fi
    cp -a "$IMG" "$ARTIFACTS/Image"
fi

cp -a "$CONFIG_SRC" "$ARTIFACTS/kernel_config"

# Build metadata. Always derive the date from the HEAD commit so the metadata
# is deterministic across re-runs of the same commit (the Nix dev shell hook
# pins SOURCE_DATE_EPOCH to 1980-01-01, which we deliberately override here).
SDE="$(cd "$SRC" && git log -1 --pretty=%ct 2>/dev/null || echo "${SOURCE_DATE_EPOCH:-0}")"
BUILD_NAME="$(date -u -d "@$SDE" +%Y%m%d)"
cat > "$ARTIFACTS/kernel_build_metadata.json" <<EOF
{
  "git_branch": "$GIT_BRANCH",
  "git_revision": "$GIT_SHA",
  "build_id": "$BUILD_ID",
  "build_name": "$BUILD_NAME"
}
EOF

# Modules: copy the modules_install tree, drop the build/source symlinks, then
# strip each module and emit a matching .dbg under modules/debug-files/.
MOD_SRC_BASE=""
for candidate in "$BD/linux_dir/lib/modules" "$BD/linux/lib/modules"; do
    if [[ -d "$candidate" ]]; then
        MOD_SRC_BASE="$candidate"
        break
    fi
done

if [[ -z "$MOD_SRC_BASE" ]]; then
    echo "Error: modules_install tree not found under $BD" >&2
    exit 1
fi

# Select modules for the built kernel release when available.
if [[ -n "$KVER" && -d "$MOD_SRC_BASE/$KVER" ]]; then
    MOD_SRC="$MOD_SRC_BASE/$KVER"
else
    mapfile -t mod_dirs < <(find "$MOD_SRC_BASE" -mindepth 1 -maxdepth 1 -type d | sort)
    if [[ ${#mod_dirs[@]} -eq 1 ]]; then
        MOD_SRC="${mod_dirs[0]}"
    else
        echo "Error: expected one modules directory under $MOD_SRC_BASE, found ${#mod_dirs[@]}" >&2
        printf '  %s\n' "${mod_dirs[@]}" >&2
        exit 1
    fi
fi

mkdir -p "$ARTIFACTS/modules"
rsync -a "$MOD_SRC/" "$ARTIFACTS/modules/"
rm -f "$ARTIFACTS/modules/build" "$ARTIFACTS/modules/source"
mkdir -p "$ARTIFACTS/modules/debug-files"

while IFS= read -r -d '' mod; do
    rel_mod="${mod#"$ARTIFACTS/modules"/}"
    dbg="$ARTIFACTS/modules/debug-files/${rel_mod}.dbg"
    mkdir -p "$(dirname "$dbg")"
    "$OBJCOPY" --only-keep-debug --compress-debug-sections "$mod" "$dbg"
    "$OBJCOPY" --strip-unneeded --add-gnu-debuglink="$dbg" "$mod"
done < <(find "$ARTIFACTS/modules" -name '*.ko' -print0)

echo ">>> Packaging done."
echo "    vmlinux sha256: $(sha256sum "$ARTIFACTS/vmlinux" | cut -d' ' -f1)"
