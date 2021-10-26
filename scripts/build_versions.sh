#!/bin/bash

set -e

BUILD_DIR=./build_versions

# Test that we have golang code generator script requirements installed
python -c "
try:
    import yaml
except ImportError:
    exit(1)
" 
if [ $? -ne 0 ]; then
    echo "*** ERROR *** Python requirements not found. Try: python -m pip install -r ./scripts/python/requirements.txt"
    exit 1
fi

function version_lt() { 
  test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" == "$1"; 
} 


mkdir -p ${BUILD_DIR}

# Pretty good effort at finding versions of go
declare -a GO_VERSIONS=($(which go) ${HOME}/sdk/go1**/bin/go)
GO_VERSIONS=($(echo "${GO_VERSIONS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))

semver_regex="^.*/sdk/[^0-9]*([0-9]+\.[0-9]+[^/]+).*$"
for GO_VERSION in "${GO_VERSIONS[@]}"
do
    if [[ ${GO_VERSION} =~ $semver_regex ]]; then
        if version_lt ${BASH_REMATCH[1]} "1.15"; then
          continue
        fi
        echo Building version: ${BASH_REMATCH[1]}
        ${GO_VERSION} build -o ./build_versions/hiddenbridge_${BASH_REMATCH[1]} ./cmd/hiddenbridge
        echo hiddenbridge
        ${GO_VERSION} build -o ./build_versions/signcert_${BASH_REMATCH[1]} ./cmd/signcert
        echo signcert
    fi
done

# ls ${BUILD_DIR}
