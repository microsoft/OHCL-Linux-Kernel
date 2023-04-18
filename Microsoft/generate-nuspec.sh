#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

xmlstarlet ed -s '/package/metadata' -t elem -n version -v "${BUILD_BUILDNUMBER}-$(date +%Y%m%d)-dev" ${SCRIPT_DIR}/hcl.nuspec |\
xmlstarlet ed -s '/package/metadata' -t elem -n releaseNotes -v "${BUILD_SOURCEVERSION}: ${BUILD_SOURCEVERSIONMESSAGE}" |\
xmlstarlet ed -s '/package/files/file' -t attr -n src -v "${OB_OUTPUTDIRECTORY}/**" > ${BUILD_SOURCESDIRECTORY}/hcl.nuspec
cat ${BUILD_SOURCESDIRECTORY}/hcl.nuspec
