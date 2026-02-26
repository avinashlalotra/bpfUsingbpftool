#!/bin/bash

BIN_DIR="bin"
TMP_DIR="tmp"

tests=(
    write
    writeev
    pwrite
    sendfile
    splice
    copy_file_range
    mmap
    mmap_msync
    o_direct
    ftruncate
    fallocate
    punchhole
    collapse_range
)

pass_count=0
fail_count=0
total_count=0

# Array to store failed tests
failed_tests=()

echo "===================================="
echo "   eBPF Write Path Coverage Test    "
echo "===================================="
echo

for test in "${tests[@]}"; do
    binary="$BIN_DIR/$test"

    if [[ ! -x "$binary" ]]; then
        echo "❌ Binary $binary not found. Skipping."
        echo
        continue
    fi

    echo "------------------------------------"
    echo "Next test: $test"
    echo "------------------------------------"


    "$binary"

    echo
    read -p "Did your FIM log this write? (y/n): " result

    total_count=$((total_count + 1))

    if [[ "$result" == "y" || "$result" == "Y" ]]; then
        pass_count=$((pass_count + 1))
        echo "✅ Marked as PASS"
    else
        fail_count=$((fail_count + 1))
        failed_tests+=("$test")
        echo "❌ Marked as FAIL"
    fi

    echo
done

echo "===================================="
echo "             SUMMARY                "
echo "===================================="
echo "Total tests run : $total_count"
echo "Passed          : $pass_count"
echo "Failed          : $fail_count"

if [[ $fail_count -eq 0 ]]; then
    echo "🔥 Full coverage achieved."
else
    echo
    echo "⚠️  Failed Tests:"
    echo "------------------------------------"
    printf "%-5s | %-20s\n" "No." "Test Name"
    echo "------------------------------------"

    index=1
    for test in "${failed_tests[@]}"; do
        printf "%-5s | %-20s\n" "$index" "$test"
        index=$((index + 1))
    done

    echo "------------------------------------"
fi

echo "===================================="