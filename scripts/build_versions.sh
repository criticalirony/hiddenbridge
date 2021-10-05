#!/usr/bin/env bash

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

mkdir -p ${BUILD_DIR}

# Pretty good effort at finding versions of go
declare -a GO_VERSIONS=($(which go) ${HOME}/sdk/go1**/bin/go)
GO_VERSIONS=($(echo "${GO_VERSIONS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))

semver_regex="^[^0-9]*([0-9]+\.[0-9]+[^/]+).*$"
for GO_VERSION in "${GO_VERSIONS[@]}"
do
    if [[ ${GO_VERSION} =~ $semver_regex ]]; then
        echo "Buliding: with go${BASH_REMATCH[1]}"
        ${GO_VERSION} build -o ./build_versions/hiddenbridge_${BASH_REMATCH[1]} ./cmd/hiddenbridge
        ${GO_VERSION} build -o ./build_versions/signcert_${BASH_REMATCH[1]} ./cmd/signcert
    fi
done

ls ${BUILD_DIR}
