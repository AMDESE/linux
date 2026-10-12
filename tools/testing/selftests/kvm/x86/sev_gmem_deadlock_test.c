// SPDX-License-Identifier: GPL-2.0-only
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/psp-sev.h>

#include "kvm_util.h"
#include "processor.h"
#include "sev.h"
#include "svm_util.h"
#include "test_util.h"

static bool stop_threads;
static void *gmem_hva;
static int sev_fd;
static struct kvm_vm *vm;
static u64 test_gpa;
static u64 test_size;

/*
 * Whether the guest_memfd instance supports in-place conversion (i.e. the
 * backing is mmap()'d and shared/private conversion happens within the same
 * pages).  Drives how the populate thread issues SNP_LAUNCH_UPDATE: in-place
 * gmem accepts a NULL source, while non-in-place gmem must be handed a source
 * HVA to copy the contents from.
 */
static bool in_place;

/*
 * Every command exposed via SEV_ISSUE_CMD.  The deadlock reproducer wants the
 * PSP driver to touch the guest_memfd-backed buffer at gmem_hva, but the buffer
 * the driver actually accesses differs per command: for some the cmd.data
 * pointer itself is the buffer the kernel reads/writes, for others cmd.data is a
 * small control struct that embeds the address(es) of the buffer(s) the kernel
 * dereferences.  setup_sev_cmd() arranges, for each command, that gmem_hva ends
 * up as the buffer the driver touches.
 */
static const __u32 sev_cmds[] = {
	SEV_PLATFORM_STATUS,
	SEV_PEK_GEN,
	SEV_PEK_CSR,
	SEV_PDH_GEN,
	SEV_PDH_CERT_EXPORT,
	SEV_PEK_CERT_IMPORT,
	SEV_GET_ID,
	SEV_GET_ID2,
	SNP_PLATFORM_STATUS,
	SNP_COMMIT,
	SNP_SET_CONFIG,
	SNP_VLEK_LOAD,
};

/* Backing storage for the per-command control structs passed via cmd.data. */
union sev_cmd_buf {
	struct sev_user_data_pek_csr		pek_csr;
	struct sev_user_data_pek_cert_import	pek_import;
	struct sev_user_data_pdh_cert_export	pdh_export;
	struct sev_user_data_get_id2		get_id2;
	struct sev_user_data_snp_vlek_load	vlek_load;
};

static void setup_sev_cmd(struct sev_issue_cmd *cmd, union sev_cmd_buf *buf,
			  __u32 which)
{
	memset(cmd, 0, sizeof(*cmd));
	memset(buf, 0, sizeof(*buf));
	cmd->cmd = which;

	switch (which) {
	/*
	 * cmd.data itself is the buffer the kernel reads from / writes to, so
	 * point it straight at gmem_hva.
	 */
	case SEV_PLATFORM_STATUS:
	case SEV_GET_ID:
	case SNP_PLATFORM_STATUS:
	case SNP_SET_CONFIG:
		cmd->data = (uint64_t)gmem_hva;
		break;

	/*
	 * These commands ignore the data pointer entirely (no user buffer), but
	 * still exercise the ioctl path.
	 */
	case SEV_PEK_GEN:
	case SEV_PDH_GEN:
	case SNP_COMMIT:
		cmd->data = 0;
		break;

	/*
	 * cmd.data is a control struct; the kernel dereferences the address
	 * field(s) within it.  Point those at gmem_hva.
	 */
	case SEV_PEK_CSR:
		buf->pek_csr.address = (uint64_t)gmem_hva;
		buf->pek_csr.length = test_size;
		cmd->data = (uint64_t)&buf->pek_csr;
		break;
	case SEV_PEK_CERT_IMPORT:
		buf->pek_import.pek_cert_address = (uint64_t)gmem_hva;
		buf->pek_import.pek_cert_len = test_size;
		buf->pek_import.oca_cert_address = (uint64_t)gmem_hva;
		buf->pek_import.oca_cert_len = test_size;
		cmd->data = (uint64_t)&buf->pek_import;
		break;
	case SEV_PDH_CERT_EXPORT:
		buf->pdh_export.pdh_cert_address = (uint64_t)gmem_hva;
		buf->pdh_export.pdh_cert_len = test_size;
		buf->pdh_export.cert_chain_address = (uint64_t)gmem_hva;
		buf->pdh_export.cert_chain_len = test_size;
		cmd->data = (uint64_t)&buf->pdh_export;
		break;
	case SEV_GET_ID2:
		buf->get_id2.address = (uint64_t)gmem_hva;
		buf->get_id2.length = test_size;
		cmd->data = (uint64_t)&buf->get_id2;
		break;
	case SNP_VLEK_LOAD:
		buf->vlek_load.len = sizeof(buf->vlek_load);
		buf->vlek_load.vlek_wrapped_version = 0;
		buf->vlek_load.vlek_wrapped_address = (uint64_t)gmem_hva;
		cmd->data = (uint64_t)&buf->vlek_load;
		break;
	}
}

static void *sev_ioctl_fn(void *arg)
{
	struct sev_issue_cmd cmd;
	union sev_cmd_buf buf;
	int i;

	while (!READ_ONCE(stop_threads)) {
		for (i = 0; i < ARRAY_SIZE(sev_cmds); i++) {
			madvise(gmem_hva, test_size, MADV_DONTNEED);

			printf("%s: issuing cmd %d\n", __func__, cmd.cmd);
			setup_sev_cmd(&cmd, &buf, sev_cmds[i]);

			ioctl(sev_fd, SEV_ISSUE_CMD, &cmd);
		}
	}
	return NULL;
}

static void *snp_populate_fn(void *arg)
{
	while (!READ_ONCE(stop_threads)) {
		int ret, fd;
		/*
		 * In-place gmem is updated without a source buffer; non-in-place
		 * gmem must be populated from a source HVA, so copy from the
		 * shared backing at gmem_hva.
		 */
		u64 src = in_place ? 0 : (u64)gmem_hva;

		snp_launch_update_data(vm, test_gpa, src, test_size,
				       KVM_SEV_SNP_PAGE_TYPE_NORMAL);
		fd = addr_gpa2gmemfd(vm, test_gpa);
		ret = fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, test_gpa, 4096);
		TEST_ASSERT(!ret, "fallocate failed!");
	}
	return NULL;
}

static void guest_code(void)
{
}

static void run_deadlock_test(bool in_place_mode)
{
	struct kvm_vcpu *vcpu;
	pthread_t t1, t2;
	gva_t gva;

	in_place = in_place_mode;
	WRITE_ONCE(stop_threads, false);

	vm = vm_create_shape_with_one_vcpu(VM_SHAPE_SNP, &vcpu, guest_code);

	test_size = getpagesize();
	gva = vm_alloc_shared(vm, test_size, KVM_UTIL_MIN_VADDR,
			      MEM_REGION_TEST_DATA);
	test_gpa = addr_gva2gpa(vm, gva);
	gmem_hva = addr_gva2hva(vm, gva);

	snp_vm_launch_start(vm, snp_default_policy());

	vm_mem_set_private(vm, test_gpa, test_size);

	pthread_create(&t1, NULL, sev_ioctl_fn, NULL);
	pthread_create(&t2, NULL, snp_populate_fn, NULL);

	sleep(5);
	WRITE_ONCE(stop_threads, true);

	pthread_join(t1, NULL);
	pthread_join(t2, NULL);

	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	bool in_place_mode;

	TEST_REQUIRE(kvm_cpu_has(X86_FEATURE_SEV));
	TEST_REQUIRE(kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(KVM_X86_SNP_VM));

	sev_fd = open_sev_dev_path_or_exit();

	/*
	 * Use in-place conversion when the kernel advertises guest_memfd
	 * memory attributes; otherwise exercise the non-in-place path.
	 */
	in_place_mode = kvm_has_cap(KVM_CAP_GUEST_MEMFD_MEMORY_ATTRIBUTES);
	pr_info("Running SNP gmem deadlock test %s in-place conversion\n",
		in_place_mode ? "with" : "without");
	run_deadlock_test(in_place_mode);

	close(sev_fd);

	return 0;
}
