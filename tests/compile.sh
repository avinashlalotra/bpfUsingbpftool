#!/bin/bash

echo "===================================="
echo "      Compiling Write Tests         "
echo "===================================="
echo

CC=gcc
CFLAGS="-Wall -O2"

SRC_DIR="src"
BIN_DIR="bin"
TMP_DIR="tmp"

fail_count=0

# Ensure directories exist
mkdir -p "$BIN_DIR"
mkdir -p "$TMP_DIR"

# Clean old binaries
echo "Cleaning old binaries..."
rm -f "$BIN_DIR"/*

# Clean old test files
echo "Cleaning tmp directory..."
rm -f "$TMP_DIR"/*

echo

for file in "$SRC_DIR"/*.c; do
    [[ -e "$file" ]] || continue

    filename=$(basename "$file")
    binary="${filename%.c}"

    echo "Compiling $filename → $BIN_DIR/$binary"

    $CC $CFLAGS "$file" -o "$BIN_DIR/$binary"

    if [[ $? -ne 0 ]]; then
        echo "❌ Failed to compile $filename"
        fail_count=$((fail_count + 1))
    else
        echo "✅ Compiled $binary"
    fi

    echo
done

echo "===================================="

if [[ $fail_count -ne 0 ]]; then
    echo "⚠️  $fail_count compilation errors occurred."
    exit 1
else
    echo "🔥 All tests compiled successfully."
fi