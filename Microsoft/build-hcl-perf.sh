#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SRC_DIR=`realpath ${SCRIPT_DIR}/..`

TOOLS_SRC=$SRC_DIR/tools
BUILD_DIR=`realpath $TOOLS_SRC/../../buildperf`

rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR

echo "Build perf..."

cd $TOOLS_SRC
make ARCH=x86_64 LDFLAGS=-static O=${BUILD_DIR} perf
strip $BUILD_DIR/tools/perf/perf

cd $SCRIPT_DIR
rm ./perf.cpio.gz
./gen_init_ramfs.py ./hcl-rootfs-perf.config ./perf.cpio.gz
