#!/bin/bash

usage() {
	>&2 echo "Try $0 --help for more information."
	exit 1
}

O=`getopt -n "$0" -l help -- nh "$@"` || usage
eval set -- "$O"

builds=()
desc=()
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
			echo "    dev"
			echo ""
			exit
			;;
		*)
			usage
			;;
	esac
done

if [ $# == 0 ]; then
	builds=(dev)
	desc=("dev")
else
	while [ $# != 0 ]; do
		case "$1" in
			dev)
				builds+=(dev)
				desc+=("dev")
				;;
			*)
				>&2 echo "Unknown build type: $1"
				usage
				;;
		esac
		shift
	done
fi

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SRC_DIR=`realpath ${SCRIPT_DIR}/..`

build_kernel() {
	if [ -n "$clean" ]; then
		make mrproper
	fi
	export KCONFIG_CONFIG=$LINUX_SRC/Microsoft/hcl.config
	# For the verbose build
	#make SHELL='sh -x' ARCH=x86_64 -j `nproc` 2> ${BUILD_DIR}/hcl-build-verbose.log
	make ARCH=x86_64 -j `nproc` olddefconfig vmlinux modules
	cp $LINUX_SRC/Microsoft/hcl.config $OUT_DIR
	objcopy --only-keep-debug --compress-debug-sections $KBUILD_OUTPUT/vmlinux $BUILD_DIR/vmlinux.dbg
	objcopy --strip-all --add-gnu-debuglink=$BUILD_DIR/vmlinux.dbg $KBUILD_OUTPUT/vmlinux $BUILD_DIR/vmlinux
	find $BUILD_DIR -name '*.ko' | while read -r mod; do
		outmod="$OUT_DIR/$(basename $mod)"
		objcopy --only-keep-debug --compress-debug-sections "$mod" "$outmod.dbg"
		objcopy --strip-unneeded --add-gnu-debuglink "$outmod.dbg" "$mod" "$outmod"
	done
	cp $BUILD_DIR/vmlinux $OUT_DIR
	cp $BUILD_DIR/vmlinux.dbg $OUT_DIR
	cp $LINUX_SRC/Microsoft/hcl.config $OUT_DIR
}

LINUX_SRC=$SRC_DIR
BUILD_DIR=`realpath $LINUX_SRC/../build`
OUT_DIR=`realpath $LINUX_SRC/out`

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

echo "Installing headers to ${BUILD_DIR}"
rm -rf $BUILD_DIR/include
make headers_install ARCH=x86_64 INSTALL_HDR_PATH=${BUILD_DIR} -j `nproc` > /dev/null
