#!/bin/bash

usage() {
	>&2 echo "Try $0 --help for more information."
	exit 1
}

O=`getopt -n "$0" -l help -- nh "$@"` || usage
eval set -- "$O"

builds=()
desc=()
arch=()
clean=1

while true; do
	case "$1" in
		-n)
			clean=
			shift
			;;
		--)
			shift
			break
			;;
		-h|--help)
			echo "Usage: $0 [-n] [BUILD ...]"
			echo ""
			echo "  Builds everything by default."
			echo ""
			echo "  -n: Do not clean before building"
			echo ""
			echo "  Available builds:"
			echo "    dev x64 arm64"
			echo ""
			exit
			;;
		*)
			usage
			;;
	esac
done

while [ $# != 0 ]; do
	case "$1" in
		dev)
			builds+=(dev)
			desc+=("dev")
			;;
		x64)
			arch=("x64")
			;;
		arm64)
			arch=("arm64")
			;;
		*)
			>&2 echo "Unknown build type: $1"
			usage
			;;
	esac
	shift
done

if test -z "$builds"; then
	builds=("dev")
	desc=("dev")
fi

if test -z "$arch"; then
	arch=("x64")
fi

# Detect host architecture
HOST_ARCH="$(uname -m)"

objcopy=("objcopy")
if [ -n "$REPRODUCIBLE_BUILD" ]; then
	# For reproducible builds, explicitly set CC to use Nix's gcc
	makeargs=("ARCH=x86_64" "CC=gcc")
else
	makeargs=("ARCH=x86_64")
fi
targets=("vmlinux modules")
if [ "$arch" = "arm64" ]; then
	# Only use cross-compiler when cross-compiling (host != target)
	if [ "$HOST_ARCH" = "aarch64" ]; then
		# Native arm64 build - no cross-compile prefix needed
		cross_prefix=""
	elif [ -n "$REPRODUCIBLE_BUILD" ]; then
		# Cross-compiling from x86_64 with Nix toolchain
		cross_prefix="aarch64-unknown-linux-gnu-"
	else
		# Cross-compiling from x86_64 with system toolchain
		cross_prefix="aarch64-linux-gnu-"
	fi

	if [ -n "$cross_prefix" ]; then
		objcopy=("${cross_prefix}objcopy")
		# For reproducible builds, explicitly set CC to use the Nix cross-compiler
		if [ -n "$REPRODUCIBLE_BUILD" ]; then
			makeargs=("ARCH=arm64" "CROSS_COMPILE=${cross_prefix}" "CC=${cross_prefix}gcc")
		else
			makeargs=("ARCH=arm64" "CROSS_COMPILE=${cross_prefix}")
		fi
	else
		# For native builds, explicitly set CC to ensure we use Nix's gcc in reproducible mode
		if [ -n "$REPRODUCIBLE_BUILD" ]; then
			makeargs=("ARCH=arm64" "CC=gcc")
		else
			makeargs=("ARCH=arm64")
		fi
	fi
	targets=("vmlinux Image modules")
fi

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SRC_DIR=`realpath ${SCRIPT_DIR}/..`

# For reproducible builds, add flags to disable Build ID and normalize debug paths
if [ -n "$REPRODUCIBLE_BUILD" ]; then
	makeargs+=("KBUILD_BUILD_ID=none")
	makeargs+=("KCFLAGS=-fdebug-prefix-map=$SRC_DIR= -fmacro-prefix-map=$SRC_DIR=")
	# Prevent + suffix from being added to version string
	makeargs+=("LOCALVERSION=")
fi

# Post-process binary to normalize for reproducibility:
# 1. Zero out any remaining absolute build paths
# 2. Zero out ALL Build IDs (which are non-deterministic across machines)
normalize_binary_for_reproducibility() {
	local binary="$1"
	local src_path="$2"

	if [ ! -f "$binary" ]; then
		return 0
	fi

	# Zero out any remaining build paths (replace with null bytes of same length)
	if [ -n "$src_path" ]; then
		local path_len=${#src_path}
		local null_padding=$(printf '%*s' "$path_len" '' | tr ' ' '\0')
		LC_ALL=C sed -i "s|$src_path|$null_padding|g" "$binary" 2>/dev/null || true
	fi

	# Zero out ALL Build IDs in the binary
	# Build ID note format: 04 00 00 00 14 00 00 00 03 00 00 00 "GNU\0" <20 bytes>
	# We search for the exact byte pattern and zero the 20 bytes after "GNU\0"
	# Pattern in hex: 04000000 14000000 03000000 474e5500 (little-endian)
	local pattern=$(printf '\x04\x00\x00\x00\x14\x00\x00\x00\x03\x00\x00\x00GNU\x00')
	local pattern_len=16
	local build_id_len=20

	# Use od to find all occurrences of the pattern
	LC_ALL=C grep -oba "GNU" "$binary" 2>/dev/null | while IFS=: read -r offset _; do
		if [ "$offset" -ge 12 ]; then
			local header_offset=$((offset - 12))
			# Read 16 bytes and check if it matches the Build ID note header
			local header=$(dd if="$binary" bs=1 skip="$header_offset" count=16 2>/dev/null | od -An -tx1 | tr -d ' \n')
			# Check for Build ID note header: 04000000 14000000 03000000 474e5500
			if [[ "$header" == "04000000140000000300000047"* ]]; then
				local build_id_offset=$((offset + 4))
				# Zero out the 20-byte Build ID
				printf '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' | \
					dd of="$binary" bs=1 seek="$build_id_offset" conv=notrunc 2>/dev/null
			fi
		fi
	done
}

build_kernel() {
	if [ -n "$clean" ]; then
		make mrproper
	fi
	export KCONFIG_CONFIG=$LINUX_SRC/Microsoft/hcl-$arch.config
	make "${makeargs[@]}" -j `nproc` olddefconfig $targets
	cp $LINUX_SRC/Microsoft/hcl-$arch.config $OUT_DIR
	$objcopy --only-keep-debug --compress-debug-sections $KBUILD_OUTPUT/vmlinux $BUILD_DIR/vmlinux.dbg
	# For reproducible builds, skip --add-gnu-debuglink as it embeds a CRC of the debug file
	# which can vary between builds. The debuglink is only used for debugging and is not
	# essential for the kernel to function.
	if [ -n "$REPRODUCIBLE_BUILD" ]; then
		$objcopy --strip-all $KBUILD_OUTPUT/vmlinux $BUILD_DIR/vmlinux
		# Post-process to zero out build paths and Build ID for reproducibility
		normalize_binary_for_reproducibility "$BUILD_DIR/vmlinux" "$SRC_DIR"
	else
		$objcopy --strip-all --add-gnu-debuglink=$BUILD_DIR/vmlinux.dbg $KBUILD_OUTPUT/vmlinux $BUILD_DIR/vmlinux
	fi

	find $BUILD_DIR -name '*.ko' | while read -r mod; do
		relative_path="${mod#$BUILD_DIR/linux}"
		dest_dir="$OUT_DIR/$MOD_DIR/$(dirname "$relative_path")"
		mkdir -p "$dest_dir"
		outmod="$dest_dir/$(basename $mod)"
		$objcopy --only-keep-debug --compress-debug-sections "$mod" "$outmod.dbg"
		if [ -n "$REPRODUCIBLE_BUILD" ]; then
			$objcopy --strip-unneeded "$mod" "$outmod"
			# Post-process to zero out build paths and Build ID for reproducibility
			normalize_binary_for_reproducibility "$outmod" "$SRC_DIR"
		else
			$objcopy --strip-unneeded --add-gnu-debuglink "$outmod.dbg" "$mod" "$outmod"
		fi
	done

	cp $BUILD_DIR/vmlinux $OUT_DIR/build/native/bin/$arch
	cp $BUILD_DIR/vmlinux.dbg $OUT_DIR/build/native/bin/$arch
	echo "{}" > $OUT_DIR/build/native/bin/$arch/kernel_build_metadata.json
	cp $LINUX_SRC/Microsoft/hcl-$arch.config $OUT_DIR
	if [ "$arch" = "arm64" ]; then
		cp $BUILD_DIR/linux/arch/$arch/boot/Image $OUT_DIR/build/native/bin/$arch
	fi
}

LINUX_SRC=$SRC_DIR
BUILD_DIR=`realpath $LINUX_SRC/../build`
OUT_DIR=`realpath $LINUX_SRC/out`
MOD_DIR=/build/native/bin/$arch/modules/kernel/

export KBUILD_OUTPUT=$BUILD_DIR/linux

if [ -n "$clean" ]; then
	rm -rf $KBUILD_OUTPUT
	rm -rf $OUT_DIR
fi

mkdir -p $KBUILD_OUTPUT
mkdir -p $OUT_DIR

cd $LINUX_SRC

cp $SCRIPT_DIR/*.cpio.gz $OUT_DIR
cp $SCRIPT_DIR/*.config $OUT_DIR

for b in ${!builds[@]}
do
	echo "Building ${desc[b]} kernel..."
	BUILD_TYPE=${1:-${builds[b]}}
	build_kernel
done

echo "Installing headers to $BUILD_DIR"
rm -rf $BUILD_DIR/include
if [ "$arch" = "arm64" ]; then
	make headers_install ARCH=arm64 INSTALL_HDR_PATH=$BUILD_DIR -j `nproc` > /dev/null
else
	make headers_install ARCH=x86_64 INSTALL_HDR_PATH=$BUILD_DIR -j `nproc` > /dev/null
fi
