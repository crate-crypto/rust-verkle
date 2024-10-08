#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="$PROJECT_ROOT/bindings/java/java_code/src/main/resources"
LIB_TYPE="dynamic"
LIB_NAME="java_eth_kzg"

# Check if a target is provided
if [ $# -eq 0 ]; then
    echo "Please provide a target architecture."
    echo "Supported targets: x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu, aarch64-apple-darwin, x86_64-apple-darwin, x86_64-pc-windows-gnu"
    exit 1
fi

TARGET=$1

case $TARGET in
    "x86_64-unknown-linux-gnu")
        $PROJECT_ROOT/scripts/compile_to_native.sh Linux x86_64 $LIB_NAME $LIB_TYPE $OUT_DIR zigbuild
        ;;
    "aarch64-unknown-linux-gnu")
        $PROJECT_ROOT/scripts/compile_to_native.sh Linux arm64 $LIB_NAME $LIB_TYPE $OUT_DIR zigbuild
        ;;
    "aarch64-apple-darwin")
        $PROJECT_ROOT/scripts/compile_to_native.sh Darwin arm64 $LIB_NAME $LIB_TYPE $OUT_DIR zigbuild
        ;;
    "x86_64-apple-darwin")
        $PROJECT_ROOT/scripts/compile_to_native.sh Darwin x86_64 $LIB_NAME $LIB_TYPE $OUT_DIR zigbuild
        ;;
    "x86_64-pc-windows-gnu")
        $PROJECT_ROOT/scripts/compile_to_native.sh Windows x86_64 $LIB_NAME $LIB_TYPE $OUT_DIR
        ;;
    *)
        echo "Unsupported target: $TARGET"
        echo "Supported targets: x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu, aarch64-apple-darwin, x86_64-apple-darwin, x86_64-pc-windows-gnu"
        exit 1
        ;;
esac