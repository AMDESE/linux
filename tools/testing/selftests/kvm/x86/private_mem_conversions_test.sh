#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Wrapper script which runs different test setups of
# private_mem_conversions_test.
#
# Copyright (C) 2025, Google LLC.

NUM_VCPUS_TO_TEST=4
NUM_MEMSLOTS_TO_TEST=$NUM_VCPUS_TO_TEST

# Required pages are based on the test setup in the C code.
REQUIRED_NUM_2M_HUGEPAGES=$((1024 * NUM_VCPUS_TO_TEST))
REQUIRED_NUM_1G_HUGEPAGES=$((2 * NUM_VCPUS_TO_TEST))

get_hugepage_count() {
    local page_size_kb=$1
    local path="/sys/kernel/mm/hugepages/hugepages-${page_size_kb}kB/nr_hugepages"
    if [ -f "$path" ]; then
        cat "$path"
    else
        echo 0
    fi
}

get_default_hugepage_size_in_kb() {
    local size=$(grep "Hugepagesize:" /proc/meminfo | awk '{print $2}')
    echo "$size"
}

run_tests() {
    local executable_path=$1
    local src_type=$2
    local num_memslots=$3
    local num_vcpus=$4

    echo "$executable_path -s $src_type -m $num_memslots -n $num_vcpus"
    "$executable_path" -s "$src_type" -m "$num_memslots" -n "$num_vcpus"
}

script_dir=$(dirname "$(realpath "$0")")
test_executable="${script_dir}/private_mem_conversions_test"
kvm_has_gmem_attributes_tool="${script_dir}/../kvm_has_gmem_attributes"

if [ ! -f "$test_executable" ]; then
    echo "Error: Test executable not found at '$test_executable'" >&2
    exit 1
fi

if [ ! -f "$kvm_has_gmem_attributes_tool" ]; then
    echo "Error: kvm_has_gmem_attributes utility not found at '$kvm_has_gmem_attributes_tool'" >&2
    exit 1
fi

kvm_has_gmem_attributes=$("$kvm_has_gmem_attributes_tool" | tail -n1)

if [ "$kvm_has_gmem_attributes" -eq 1 ]; then
    backing_src_types=("shmem")
else
    hugepage_2mb_count=$(get_hugepage_count 2048)
    hugepage_2mb_enabled=$((hugepage_2mb_count >= REQUIRED_NUM_2M_HUGEPAGES))
    hugepage_1gb_count=$(get_hugepage_count 1048576)
    hugepage_1gb_enabled=$((hugepage_1gb_count >= REQUIRED_NUM_1G_HUGEPAGES))

    default_hugepage_size_kb=$(get_default_hugepage_size_in_kb)
    hugepage_default_enabled=0
    if [ "$default_hugepage_size_kb" -eq 2048 ]; then
        hugepage_default_enabled=$hugepage_2mb_enabled
    elif [ "$default_hugepage_size_kb" -eq 1048576 ]; then
        hugepage_default_enabled=$hugepage_1gb_enabled
    fi

    backing_src_types=("anonymous" "anonymous_thp")

    if [ "$hugepage_default_enabled" -eq 1 ]; then
        backing_src_types+=("anonymous_hugetlb")
    else
        echo "skipping anonymous_hugetlb backing source type"
    fi

    if [ "$hugepage_2mb_enabled" -eq 1 ]; then
        backing_src_types+=("anonymous_hugetlb_2mb")
    else
        echo "skipping anonymous_hugetlb_2mb backing source type"
    fi

    if [ "$hugepage_1gb_enabled" -eq 1 ]; then
        backing_src_types+=("anonymous_hugetlb_1gb")
    else
        echo "skipping anonymous_hugetlb_1gb backing source type"
    fi

    backing_src_types+=("shmem")

    if [ "$hugepage_default_enabled" -eq 1 ]; then
        backing_src_types+=("shared_hugetlb")
    else
        echo "skipping shared_hugetlb backing source type"
    fi
fi

return_code=0
for i in "${!backing_src_types[@]}"; do
    src_type=${backing_src_types[$i]}
    if [ "$i" -gt 0 ]; then
        echo
    fi

    if ! run_tests "$test_executable" "$src_type" 1 1; then
        return_code=$?
        echo "Test failed for source type '$src_type'. Arguments: -s $src_type -m 1 -n 1" >&2
        break
    fi

    if ! run_tests "$test_executable" "$src_type" 1 "$NUM_VCPUS_TO_TEST"; then
        return_code=$?
        echo "Test failed for source type '$src_type'. Arguments: -s $src_type -m 1 -n $NUM_VCPUS_TO_TEST" >&2
        break
    fi

    if ! run_tests "$test_executable" "$src_type" "$NUM_MEMSLOTS_TO_TEST" "$NUM_VCPUS_TO_TEST"; then
        return_code=$?
        echo "Test failed for source type '$src_type'. Arguments: -s $src_type -m $NUM_MEMSLOTS_TO_TEST -n $NUM_VCPUS_TO_TEST" >&2
        break
    fi
done

exit "$return_code"
