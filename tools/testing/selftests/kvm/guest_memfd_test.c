// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright Intel Corporation, 2023
 *
 * Author: Chao Peng <chao.p.peng@linux.intel.com>
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <numa.h>
#include <numaif.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>

#include <linux/bitmap.h>
#include <linux/falloc.h>
#include <linux/sizes.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "kvm_util.h"
#include "test_util.h"
#include "ucall_common.h"

static size_t page_size;

static void test_file_read_write(int fd, size_t total_size)
{
	char buf[64];

	TEST_ASSERT(read(fd, buf, sizeof(buf)) < 0,
		    "read on a guest_mem fd should fail");
	TEST_ASSERT(write(fd, buf, sizeof(buf)) < 0,
		    "write on a guest_mem fd should fail");
	TEST_ASSERT(pread(fd, buf, sizeof(buf), 0) < 0,
		    "pread on a guest_mem fd should fail");
	TEST_ASSERT(pwrite(fd, buf, sizeof(buf), 0) < 0,
		    "pwrite on a guest_mem fd should fail");
}

static void test_mmap_cow(int fd, size_t size)
{
	void *mem;

	mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	TEST_ASSERT(mem == MAP_FAILED, "Copy-on-write not allowed by guest_memfd.");
}

static void test_mmap_supported(int fd, size_t total_size)
{
	const char val = 0xaa;
	char *mem;
	size_t i;
	int ret;

	mem = kvm_mmap(total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd);

	memset(mem, val, total_size);
	for (i = 0; i < total_size; i++)
		TEST_ASSERT_EQ(READ_ONCE(mem[i]), val);

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE, 0,
			page_size);
	TEST_ASSERT(!ret, "fallocate the first page should succeed.");

	for (i = 0; i < page_size; i++)
		TEST_ASSERT_EQ(READ_ONCE(mem[i]), 0x00);
	for (; i < total_size; i++)
		TEST_ASSERT_EQ(READ_ONCE(mem[i]), val);

	memset(mem, val, page_size);
	for (i = 0; i < total_size; i++)
		TEST_ASSERT_EQ(READ_ONCE(mem[i]), val);

	kvm_munmap(mem, total_size);
}

#define TEST_REQUIRE_NUMA_MULTIPLE_NODES()	\
	TEST_REQUIRE(numa_available() != -1 && numa_max_node() >= 1)

static void test_mbind(int fd, size_t total_size)
{
	unsigned long nodemask = 1; /* nid: 0 */
	unsigned long maxnode = 8;
	unsigned long get_nodemask;
	int get_policy;
	char *mem;
	int ret;

	TEST_REQUIRE_NUMA_MULTIPLE_NODES();

	mem = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	TEST_ASSERT(mem != MAP_FAILED, "mmap for mbind test should succeed");

	/* Test MPOL_INTERLEAVE policy */
	ret = syscall(__NR_mbind, mem, page_size * 2, MPOL_INTERLEAVE,
		      &nodemask, maxnode, 0);
	TEST_ASSERT(!ret, "mbind with INTERLEAVE to node 0 should succeed");
	ret = syscall(__NR_get_mempolicy, &get_policy, &get_nodemask,
		      maxnode, mem, MPOL_F_ADDR);
	TEST_ASSERT(!ret && get_policy == MPOL_INTERLEAVE && get_nodemask == nodemask,
		    "Policy should be MPOL_INTERLEAVE and nodes match");

	/* Test basic MPOL_BIND policy */
	ret = syscall(__NR_mbind, mem + page_size * 2, page_size * 2, MPOL_BIND,
		      &nodemask, maxnode, 0);
	TEST_ASSERT(!ret, "mbind with MPOL_BIND to node 0 should succeed");
	ret = syscall(__NR_get_mempolicy, &get_policy, &get_nodemask,
		      maxnode, mem + page_size * 2, MPOL_F_ADDR);
	TEST_ASSERT(!ret && get_policy == MPOL_BIND && get_nodemask == nodemask,
		    "Policy should be MPOL_BIND and nodes match");

	/* Test MPOL_DEFAULT policy */
	ret = syscall(__NR_mbind, mem, total_size, MPOL_DEFAULT, NULL, 0, 0);
	TEST_ASSERT(!ret, "mbind with MPOL_DEFAULT should succeed");
	ret = syscall(__NR_get_mempolicy, &get_policy, &get_nodemask,
		      maxnode, mem, MPOL_F_ADDR);
	TEST_ASSERT(!ret && get_policy == MPOL_DEFAULT && get_nodemask == 0,
		    "Policy should be MPOL_DEFAULT and nodes zero");

	/* Test with invalid policy */
	ret = syscall(__NR_mbind, mem, page_size, 999, &nodemask, maxnode, 0);
	TEST_ASSERT(ret == -1 && errno == EINVAL,
		    "mbind with invalid policy should fail with EINVAL");

	TEST_ASSERT(munmap(mem, total_size) == 0, "munmap should succeed");
}

static void test_numa_allocation(int fd, size_t total_size)
{
	unsigned long node0_mask = 1;  /* Node 0 */
	unsigned long node1_mask = 2;  /* Node 1 */
	unsigned long maxnode = 8;
	void *pages[4];
	int status[4];
	char *mem;
	int ret, i;

	TEST_REQUIRE_NUMA_MULTIPLE_NODES();

	/* Clean slate: deallocate all file space, if any */
	ret = fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, total_size);
	TEST_ASSERT(!ret, "fallocate(PUNCH_HOLE) should succeed");

	mem = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	TEST_ASSERT(mem != MAP_FAILED, "mmap should succeed");

	for (i = 0; i < 4; i++)
		pages[i] = (char *)mem + page_size * i;

	/* Set NUMA policy after allocation */
	memset(mem, 0xaa, page_size);
	ret = syscall(__NR_mbind, pages[0], page_size, MPOL_BIND, &node0_mask, maxnode, 0);
	TEST_ASSERT(!ret, "mbind after allocation page 0 to node 0 should succeed");
	ret = fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, page_size);
	TEST_ASSERT(!ret, "fallocate(PUNCH_HOLE) should succeed");

	/* Set NUMA policy before allocation */
	ret = syscall(__NR_mbind, pages[0], page_size * 2, MPOL_BIND, &node1_mask, maxnode, 0);
	TEST_ASSERT(!ret, "mbind page 0, 1 to node 1 should succeed");
	ret = syscall(__NR_mbind, pages[2], page_size * 2, MPOL_BIND, &node0_mask, maxnode, 0);
	TEST_ASSERT(!ret, "mbind page 2, 3 to node 0 should succeed");
	memset(mem, 0xaa, total_size);

	/* Validate if pages are allocated on specified NUMA nodes */
	ret = syscall(__NR_move_pages, 0, 4, pages, NULL, status, 0);
	TEST_ASSERT(ret >= 0, "move_pages should succeed for status check");
	TEST_ASSERT(status[0] == 1, "Page 0 should be allocated on node 1");
	TEST_ASSERT(status[1] == 1, "Page 1 should be allocated on node 1");
	TEST_ASSERT(status[2] == 0, "Page 2 should be allocated on node 0");
	TEST_ASSERT(status[3] == 0, "Page 3 should be allocated on node 0");

	/* Punch hole for all pages */
	ret = fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, total_size);
	TEST_ASSERT(!ret, "fallocate(PUNCH_HOLE) should succeed");

	/* Change NUMA policy nodes and reallocate */
	ret = syscall(__NR_mbind, pages[0], page_size * 2, MPOL_BIND, &node0_mask, maxnode, 0);
	TEST_ASSERT(!ret, "mbind page 0, 1 to node 0 should succeed");
	ret = syscall(__NR_mbind, pages[2], page_size * 2, MPOL_BIND, &node1_mask, maxnode, 0);
	TEST_ASSERT(!ret, "mbind page 2, 3 to node 1 should succeed");
	memset(mem, 0xaa, total_size);

	ret = syscall(__NR_move_pages, 0, 4, pages, NULL, status, 0);
	TEST_ASSERT(ret >= 0, "move_pages should succeed after reallocation");
	TEST_ASSERT(status[0] == 0, "Page 0 should be allocated on node 0");
	TEST_ASSERT(status[1] == 0, "Page 1 should be allocated on node 0");
	TEST_ASSERT(status[2] == 1, "Page 2 should be allocated on node 1");
	TEST_ASSERT(status[3] == 1, "Page 3 should be allocated on node 1");

	TEST_ASSERT(munmap(mem, total_size) == 0, "munmap should succeed");
}

static void test_fault_sigbus(int fd, size_t accessible_size, size_t map_size)
{
	const char val = 0xaa;
	char *mem;
	size_t i;

	mem = kvm_mmap(map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd);

	TEST_EXPECT_SIGBUS(memset(mem, val, map_size));
	TEST_EXPECT_SIGBUS((void)READ_ONCE(mem[accessible_size]));

	for (i = 0; i < accessible_size; i++)
		TEST_ASSERT_EQ(READ_ONCE(mem[i]), val);

	kvm_munmap(mem, map_size);
}

static void test_fault_overflow(int fd, size_t total_size)
{
	test_fault_sigbus(fd, total_size, total_size * 4);
}

static void test_fault_private(int fd, size_t total_size)
{
	test_fault_sigbus(fd, 0, total_size);
}

static void test_mmap_not_supported(int fd, size_t total_size)
{
	char *mem;

	mem = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	TEST_ASSERT_EQ(mem, MAP_FAILED);

	mem = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	TEST_ASSERT_EQ(mem, MAP_FAILED);
}

static void test_file_size(int fd, size_t total_size)
{
	struct stat sb;
	int ret;

	ret = fstat(fd, &sb);
	TEST_ASSERT(!ret, "fstat should succeed");
	TEST_ASSERT_EQ(sb.st_size, total_size);
	TEST_ASSERT_EQ(sb.st_blksize, page_size);
}

static void test_fallocate(int fd, size_t total_size)
{
	int ret;

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, total_size);
	TEST_ASSERT(!ret, "fallocate with aligned offset and size should succeed");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			page_size - 1, page_size);
	TEST_ASSERT(ret, "fallocate with unaligned offset should fail");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE, total_size, page_size);
	TEST_ASSERT(ret, "fallocate beginning at total_size should fail");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE, total_size + page_size, page_size);
	TEST_ASSERT(ret, "fallocate beginning after total_size should fail");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			total_size, page_size);
	TEST_ASSERT(!ret, "fallocate(PUNCH_HOLE) at total_size should succeed");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			total_size + page_size, page_size);
	TEST_ASSERT(!ret, "fallocate(PUNCH_HOLE) after total_size should succeed");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			page_size, page_size - 1);
	TEST_ASSERT(ret, "fallocate with unaligned size should fail");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			page_size, page_size);
	TEST_ASSERT(!ret, "fallocate(PUNCH_HOLE) with aligned offset and size should succeed");

	ret = fallocate(fd, FALLOC_FL_KEEP_SIZE, page_size, page_size);
	TEST_ASSERT(!ret, "fallocate to restore punched hole should succeed");
}

static void test_invalid_punch_hole(int fd, size_t total_size)
{
	struct {
		off_t offset;
		off_t len;
	} testcases[] = {
		{0, 1},
		{0, page_size - 1},
		{0, page_size + 1},

		{1, 1},
		{1, page_size - 1},
		{1, page_size},
		{1, page_size + 1},

		{page_size, 1},
		{page_size, page_size - 1},
		{page_size, page_size + 1},
	};
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(testcases); i++) {
		ret = fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
				testcases[i].offset, testcases[i].len);
		TEST_ASSERT(ret == -1 && errno == EINVAL,
			    "PUNCH_HOLE with !PAGE_SIZE offset (%lx) and/or length (%lx) should fail",
			    testcases[i].offset, testcases[i].len);
	}
}

static void test_create_guest_memfd_invalid_sizes(struct kvm_vm *vm,
						  uint64_t guest_memfd_flags)
{
	size_t size;
	int fd;

	for (size = 1; size < page_size; size++) {
		fd = __vm_create_guest_memfd(vm, size, guest_memfd_flags);
		TEST_ASSERT(fd < 0 && errno == EINVAL,
			    "guest_memfd() with non-page-aligned page size '0x%lx' should fail with EINVAL",
			    size);
	}
}

static void test_create_guest_memfd_multiple(struct kvm_vm *vm)
{
	int fd1, fd2, ret;
	struct stat st1, st2;

	fd1 = __vm_create_guest_memfd(vm, page_size, 0);
	TEST_ASSERT(fd1 != -1, "memfd creation should succeed");

	ret = fstat(fd1, &st1);
	TEST_ASSERT(ret != -1, "memfd fstat should succeed");
	TEST_ASSERT(st1.st_size == page_size, "memfd st_size should match requested size");

	fd2 = __vm_create_guest_memfd(vm, page_size * 2, 0);
	TEST_ASSERT(fd2 != -1, "memfd creation should succeed");

	ret = fstat(fd2, &st2);
	TEST_ASSERT(ret != -1, "memfd fstat should succeed");
	TEST_ASSERT(st2.st_size == page_size * 2, "second memfd st_size should match requested size");

	ret = fstat(fd1, &st1);
	TEST_ASSERT(ret != -1, "memfd fstat should succeed");
	TEST_ASSERT(st1.st_size == page_size, "first memfd st_size should still match requested size");
	TEST_ASSERT(st1.st_ino != st2.st_ino, "different memfd should have different inode numbers");

	close(fd2);
	close(fd1);
}

static void test_vm_with_gmem_flag(struct kvm_vm *vm, uint64_t flag,
				   bool expect_valid)
{
	size_t page_size = getpagesize();
	int fd;

	fd = __vm_create_guest_memfd(vm, page_size, flag);

	if (expect_valid) {
		TEST_ASSERT(fd >= 0,
			    "guest_memfd() with flag '0x%lx' should succeed",
			    flag);
		close(fd);
	} else {
		TEST_ASSERT(fd < 0 && errno == EINVAL,
			    "guest_memfd() with flag '0x%lx' should fail with EINVAL",
			    flag);
	}
}

static void test_guest_memfd_flags(struct kvm_vm *vm, uint64_t valid_flags)
{
	uint64_t flag;

	for (flag = BIT(0); flag; flag <<= 1) {
		test_vm_with_gmem_flag(vm, flag, flag & valid_flags);

		if (flag == GUEST_MEMFD_FLAG_MMAP) {
			test_vm_with_gmem_flag(
				vm, flag | GUEST_MEMFD_FLAG_INIT_SHARED, true);
		}
	}
}

#define gmem_test(__test, __vm, __flags)				\
do {									\
	int fd = vm_create_guest_memfd(__vm, page_size * 4, __flags);	\
									\
	test_##__test(fd, page_size * 4);				\
	close(fd);							\
} while (0)

static void __test_guest_memfd(struct kvm_vm *vm, uint64_t flags)
{
	test_create_guest_memfd_multiple(vm);
	test_create_guest_memfd_invalid_sizes(vm, flags);

	gmem_test(file_read_write, vm, flags);

	if (flags & GUEST_MEMFD_FLAG_MMAP) {
		if (flags & GUEST_MEMFD_FLAG_INIT_SHARED) {
			gmem_test(mmap_supported, vm, flags);
			gmem_test(fault_overflow, vm, flags);
			gmem_test(mbind, vm, flags);
			gmem_test(numa_allocation, vm, flags);
		} else {
			gmem_test(fault_private, vm, flags);
		}

		gmem_test(mmap_cow, vm, flags);
	} else {
		gmem_test(mmap_not_supported, vm, flags);
	}

	gmem_test(file_size, vm, flags);
	gmem_test(fallocate, vm, flags);
	gmem_test(invalid_punch_hole, vm, flags);
}

static void test_guest_memfd(unsigned long vm_type)
{
	struct kvm_vm *vm = vm_create_barebones_type(vm_type);
	uint64_t flags;

	flags = vm_check_cap(vm, KVM_CAP_GUEST_MEMFD_FLAGS);
	test_guest_memfd_flags(vm, flags);

	__test_guest_memfd(vm, 0);
	if (flags & GUEST_MEMFD_FLAG_MMAP)
		__test_guest_memfd(vm, GUEST_MEMFD_FLAG_MMAP);

	/* MMAP should always be supported if INIT_SHARED is supported. */
	if (flags & GUEST_MEMFD_FLAG_INIT_SHARED)
		__test_guest_memfd(vm, GUEST_MEMFD_FLAG_MMAP |
				       GUEST_MEMFD_FLAG_INIT_SHARED);

	kvm_vm_free(vm);
}

static void guest_code(uint8_t *mem, uint64_t size)
{
	size_t i;

	for (i = 0; i < size; i++)
		__GUEST_ASSERT(mem[i] == 0xaa,
			       "Guest expected 0xaa at offset %lu, got 0x%x", i, mem[i]);

	memset(mem, 0xff, size);
	GUEST_DONE();
}

static void test_guest_memfd_guest(void)
{
	/*
	 * Skip the first 4gb and slot0.  slot0 maps <1gb and is used to back
	 * the guest's code, stack, and page tables, and low memory contains
	 * the PCI hole and other MMIO regions that need to be avoided.
	 */
	const uint64_t gpa = SZ_4G;
	const int slot = 1;

	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	uint8_t *mem;
	size_t size;
	int fd, i;

	if (!kvm_check_cap(KVM_CAP_GUEST_MEMFD_FLAGS))
		return;

	vm = __vm_create_shape_with_one_vcpu(VM_SHAPE_DEFAULT, &vcpu, 1, guest_code);

	TEST_ASSERT(vm_check_cap(vm, KVM_CAP_GUEST_MEMFD_FLAGS) & GUEST_MEMFD_FLAG_MMAP,
		    "Default VM type should support MMAP, supported flags = 0x%x",
		    vm_check_cap(vm, KVM_CAP_GUEST_MEMFD_FLAGS));
	TEST_ASSERT(vm_check_cap(vm, KVM_CAP_GUEST_MEMFD_FLAGS) & GUEST_MEMFD_FLAG_INIT_SHARED,
		    "Default VM type should support INIT_SHARED, supported flags = 0x%x",
		    vm_check_cap(vm, KVM_CAP_GUEST_MEMFD_FLAGS));

	size = vm->page_size;
	fd = vm_create_guest_memfd(vm, size, GUEST_MEMFD_FLAG_MMAP |
					     GUEST_MEMFD_FLAG_INIT_SHARED);
	vm_set_user_memory_region2(vm, slot, KVM_MEM_GUEST_MEMFD, gpa, size, NULL, fd, 0);

	mem = kvm_mmap(size, PROT_READ | PROT_WRITE, MAP_SHARED, fd);
	memset(mem, 0xaa, size);
	kvm_munmap(mem, size);

	virt_pg_map(vm, gpa, gpa);
	vcpu_args_set(vcpu, 2, gpa, size);
	vcpu_run(vcpu);

	TEST_ASSERT_EQ(get_ucall(vcpu, NULL), UCALL_DONE);

	mem = kvm_mmap(size, PROT_READ | PROT_WRITE, MAP_SHARED, fd);
	for (i = 0; i < size; i++)
		TEST_ASSERT_EQ(mem[i], 0xff);

	close(fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	unsigned long vm_types, vm_type;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_GUEST_MEMFD));

	page_size = getpagesize();

	/*
	 * Not all architectures support KVM_CAP_VM_TYPES. However, those that
	 * support guest_memfd have that support for the default VM type.
	 */
	vm_types = kvm_check_cap(KVM_CAP_VM_TYPES);
	if (!vm_types)
		vm_types = BIT(VM_TYPE_DEFAULT);

	for_each_set_bit(vm_type, &vm_types, BITS_PER_TYPE(vm_types))
		test_guest_memfd(vm_type);

	test_guest_memfd_guest();
}
