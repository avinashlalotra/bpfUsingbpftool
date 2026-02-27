#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <path>"
    exit 1
fi

if [ ! -e "$1" ]; then
    echo "Error: '$1' does not exist"
    exit 1
fi

# Get major/minor in hex from stat
major_hex=$(stat -c "%t" "$1") || exit 1
minor_hex=$(stat -c "%T" "$1") || exit 1

# Convert to decimal
major=$((16#$major_hex))
minor=$((16#$minor_hex))

# Kernel dev_t encoding (new_encode_dev)
MINORBITS=20
MINORMASK=$(( (1 << MINORBITS) - 1 ))

low_minor=$(( minor & MINORMASK ))
high_minor=$(( minor & ~MINORMASK ))

raw_dev=$(( low_minor | (major << MINORBITS) | (high_minor << 12) ))

echo "$raw_dev"