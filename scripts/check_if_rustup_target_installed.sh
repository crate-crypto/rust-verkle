#!/bin/bash

# Check if a target name is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <target-name>"
  exit 1
fi

# Get the Rust target from the first argument
TARGET_NAME="$1"

# Check if the target is installed
if rustup target list --installed | grep -q "$TARGET_NAME"; then
  echo "The Rust target '$TARGET_NAME' is installed."
  exit 0
else
  echo "The Rust target '$TARGET_NAME' is not installed."
  echo "You can install the target with 'rustup target add $TARGET_NAME'"
  exit 1
fi
