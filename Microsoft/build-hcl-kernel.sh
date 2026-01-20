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

objcopy=("objcopy")
makeargs=("ARCH=x86_64")
targets=("vmlinux modules")
if [ "$arch" = "arm64" ]; then
	# Use Nix cross-compiler prefix for reproducible builds, system prefix otherwise
	if [ -n "$REPRODUCIBLE_BUILD" ]; then
		cross_prefix="aarch64-unknown-linux-gnu-"
	else
		cross_prefix="aarch64-linux-gnu-"
	fi
	objcopy=("${cross_prefix}objcopy")
	makeargs=("ARCH=arm64" "CROSS_COMPILE=${cross_prefix}")
	targets=("vmlinux Image modules")
fi

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SRC_DIR=`realpath ${SCRIPT_DIR}/..`

# For reproducible builds, add flags to disable Build ID and normalize debug paths
if [ -n "$REPRODUCIBLE_BUILD" ]; then
	makeargs+=("KBUILD_BUILD_ID=none")
	makeargs+=("KCFLAGS=-fdebug-prefix-map=$SRC_DIR=.")
fi

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
