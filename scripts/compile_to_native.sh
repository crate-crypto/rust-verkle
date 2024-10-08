#!/bin/bash

# Function to display usage information
usage() {
    echo "Usage: $0 [OS] [ARCH] [LIB_NAME] [LIB_TYPE] [OUT_DIR] [BUILD_TOOL]"
    echo "Compile the project for the specified OS, architecture, library name, library type, output directory, and build tool."
    echo "If no OS and ARCH are provided, it defaults to the current system's OS and architecture."
    echo "If no LIB_NAME is provided, it defaults to 'c_eth_kzg'."
    echo "If no LIB_TYPE is provided, it defaults to 'both'."
    echo "If no OUT_DIR is provided, it defaults to './bindings/c/build'."
    echo "If no BUILD_TOOL is provided, it defaults to 'cargo'."
    echo
    echo "Arguments:"
    echo "  OS          Operating system (e.g., Linux, Darwin, MINGW64_NT)"
    echo "  ARCH        Architecture (e.g., x86_64, arm64, universal)"
    echo "  LIB_NAME    Library name (e.g., c_eth_kzg)"
    echo "  LIB_TYPE    Library type to copy (static, dynamic, or both)"
    echo "  OUT_DIR     Output directory for the compiled libraries"
    echo "  BUILD_TOOL  Build tool to use (cargo or zigbuild)"
    echo
    echo "Examples:"
    echo "  $0                                              # Uses the system's OS and architecture, copies both libraries to the default directory with the default library name, using cargo"
    echo "  $0 Linux x86_64 my_lib static . cargo           # Compiles for Linux on x86_64 and copies only static libraries to the current directory with the library name 'my_lib', using cargo"
    echo "  $0 Darwin arm64 my_lib dynamic ./out/dir zigbuild  # Compiles for macOS on ARM (Apple Silicon) and copies only dynamic libraries to './out/dir' with the library name 'my_lib', using zigbuild"
    exit 1
}

# Check for help flag
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    usage
fi

# Determine the script's directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Determine the operating system, architecture, library name, library type, output directory, and build tool if not provided
OS="${1:-$(uname)}"
ARCH="${2:-$(uname -m)}"
LIB_NAME="${3:-c_eth_kzg}"
LIB_TYPE="${4:-both}"
OUT_DIR="${5:-$PROJECT_ROOT/bindings/c/build}"
BUILD_TOOL="${6:-cargo}"
echo "Detected/Provided OS: $OS"
echo "Detected/Provided architecture: $ARCH"
echo "Library name: $LIB_NAME"
echo "Library type to copy: $LIB_TYPE"
echo "Output directory: $OUT_DIR"
echo "Build tool: $BUILD_TOOL"

STATIC_LIB_NAME=""
DYNAMIC_LIB_NAME=""
TARGET_NAME=""

# Function to check if a Rust target is installed
check_rust_target_installed() {
    local target=$1
    echo "Compiling for target: $target"
    $SCRIPT_DIR/check_if_rustup_target_installed.sh $target

    # Check the exit code 
    if [ $? -eq 0 ]; then
        echo "The default Rust target is installed for $target."
    else
        echo "The default Rust target is not installed for $target."
        exit 1
    fi
}

# Check for Windows OS and ensure ARCH is x86_64
if [[ "$OS" == "MINGW64_NT" || "$OS" == "CYGWIN_NT" ]]; then
    if [[ "$ARCH" != "x86_64" ]]; then
        echo "Error: On Windows, the architecture must be x86_64."
        exit 1
    fi
fi

case "$OS" in
    "Darwin")
        case "$ARCH" in
            "arm64")
                # Copy static and shared libraries for macOS ARM
                TARGET_NAME="aarch64-apple-darwin"
                STATIC_LIB_NAME="lib${LIB_NAME}.a"
                DYNAMIC_LIB_NAME="lib${LIB_NAME}.dylib"
                ;;
            "x86_64")
                # Copy static and shared libraries for macOS Intel
                TARGET_NAME="x86_64-apple-darwin"
                STATIC_LIB_NAME="lib${LIB_NAME}.a"
                DYNAMIC_LIB_NAME="lib${LIB_NAME}.dylib"
                ;;
            "universal")
                # Build universal binary for macOS
                TARGET_NAME="universal-apple-darwin"
                STATIC_LIB_NAME="lib${LIB_NAME}.a"
                DYNAMIC_LIB_NAME="lib${LIB_NAME}.dylib"
                ;;
            *)
                echo "Unsupported macOS architecture: $ARCH"
                exit 1
                ;;
        esac
        ;;
    "Linux")
        case "$ARCH" in
            "arm64")
                # Copy static and shared libraries for Linux ARM
                TARGET_NAME="aarch64-unknown-linux-gnu"
                STATIC_LIB_NAME="lib${LIB_NAME}.a"
                DYNAMIC_LIB_NAME="lib${LIB_NAME}.so"
                ;;
            "x86_64")
                # Copy static and shared libraries for Linux Intel
                TARGET_NAME="x86_64-unknown-linux-gnu"
                STATIC_LIB_NAME="lib${LIB_NAME}.a"
                DYNAMIC_LIB_NAME="lib${LIB_NAME}.so"
                ;;
            *)
                echo "Unsupported Linux architecture: $ARCH"
                exit 1
                ;;
        esac
        ;;
        # Github runners will return MINGW64_NT-10.0-20348
        # so we add a wildcard to match the prefix
    MINGW64_NT-*|CYGWIN_NT-*|"Windows")
        TARGET_NAME="x86_64-pc-windows-gnu"
        STATIC_LIB_NAME="lib${LIB_NAME}.a"
        DYNAMIC_LIB_NAME="${LIB_NAME}.dll"
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

# Function to perform the build
do_build() {
    local target=$1
    if [ "$BUILD_TOOL" == "zigbuild" ]; then
        cargo zigbuild --release --target=$target
    else
        cargo build --release --target=$target
    fi
}

# Build for universal mac target if selected
if [[ "$ARCH" == "universal" ]]; then
    check_rust_target_installed "x86_64-apple-darwin"
    check_rust_target_installed "aarch64-apple-darwin"

    do_build "x86_64-apple-darwin"
    do_build "aarch64-apple-darwin"

    # Create the universal binary
    mkdir -p "$OUT_DIR/$TARGET_NAME"
    lipo -create -output "$OUT_DIR/$TARGET_NAME/$STATIC_LIB_NAME" \
        "$PROJECT_ROOT/target/x86_64-apple-darwin/release/$STATIC_LIB_NAME" \
        "$PROJECT_ROOT/target/aarch64-apple-darwin/release/$STATIC_LIB_NAME"

    lipo -create -output "$OUT_DIR/$TARGET_NAME/$DYNAMIC_LIB_NAME" \
        "$PROJECT_ROOT/target/x86_64-apple-darwin/release/$DYNAMIC_LIB_NAME" \
        "$PROJECT_ROOT/target/aarch64-apple-darwin/release/$DYNAMIC_LIB_NAME"
else
    check_rust_target_installed "$TARGET_NAME"
    do_build "$TARGET_NAME"

    # Create the output directory if it doesn't exist
    mkdir -p "$OUT_DIR/$TARGET_NAME"

    # Copy the libraries to the specified output directory
    if [ "$LIB_TYPE" == "static" ] || [ "$LIB_TYPE" == "both" ]; then
        cp -R "$PROJECT_ROOT/target/$TARGET_NAME/release/$STATIC_LIB_NAME" "$OUT_DIR/$TARGET_NAME/"
    fi

    if [ "$LIB_TYPE" == "dynamic" ] || [ "$LIB_TYPE" == "both" ]; then
        cp -R "$PROJECT_ROOT/target/$TARGET_NAME/release/$DYNAMIC_LIB_NAME" "$OUT_DIR/$TARGET_NAME/"
    fi
fi

echo "Build completed for target: $TARGET_NAME"