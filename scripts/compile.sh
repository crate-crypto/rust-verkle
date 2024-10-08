#!/bin/bash
# When developing locally, one should call this script to
# build the necessary binaries needed for the other languages
# to interact with the rust library.
# Note: This is specifically for libraries that need to have a compiled
# dynamic or static library.

# Determine the script's directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OS=$(uname)
ARCH=$(uname -m)

# For windows, we install x86_64-pc-windows-gnu, instead of relying on the msvc version
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "mingw"* ]]; then
    echo "Installing x86_64-pc-windows-gnu target for Rust..."
    rustup target add x86_64-pc-windows-gnu
fi

# Function to compile for Java
compile_java() {
    echo "Compiling for Java..."
    OUT_DIR="$PROJECT_ROOT/bindings/java/java_code/src/main/resources"
    LIB_TYPE="dynamic"
    LIB_NAME="java_verkle_cryptography"
    $PROJECT_ROOT/scripts/compile_to_native.sh $OS $ARCH $LIB_NAME $LIB_TYPE $OUT_DIR
}

# Function to compile for all languages
compile_all() {
    compile_java
}

# If no argument is provided, compile for all languages
if [ $# -eq 0 ]; then
    compile_all
    exit 0
fi

# Compile based on the argument
case $1 in
    java)
        compile_java
        ;;
    *)
        echo "Invalid argument. Use java or run without arguments to compile for all languages."
        exit 1
        ;;
esac