#!/bin/bash

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <path>"
    exit 1
fi

if [ ! -e "$1" ]; then
    echo "Error: '$1' does not exist"
    exit 1
fi

# Get major and minor numbers in hex
major_hex=$(stat -c "%t" "$1") || exit 1
minor_hex=$(stat -c "%T" "$1") || exit 1

# Convert hex to decimal
major_dec=$((16#$major_hex))
minor_dec=$((16#$minor_hex))

# Linux encoding: (major << 20) | minor
raw_dev=$(( ((major_dec << 20)) | minor_dec ))

echo "$raw_dev"