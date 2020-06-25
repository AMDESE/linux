// SPDX-License-Identifier: GPL-2.0-only
/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * AMD SVM-SEV support
 *
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 */

#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include <linux/kernel.h>
#include <linux/highmem.h>
#include <linux/psp-sev.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/trace_events.h>
#include <linux/mem_encrypt.h>
#include <linux/set_memory.h>

#include <asm/trap_defs.h>
#include <asm/fpu/internal.h>

#include "x86.h"
#include "svm.h"
#include "trace.h"

static u8 sev_enc_bit;
static int sev_flush_asids(void);
static DECLARE_RWSEM(sev_deactivate_lock);
static DEFINE_MUTEX(sev_bitmap_lock);
unsigned int max_sev_asid;
static unsigned int min_sev_asid;
static unsigned long *sev_asid_bitmap;
static unsigned long *sev_reclaim_asid_bitmap;
static void *rmp_table_vaddr;

static void snp_print_rmpentry(u64 spa);
static void snp_free_context_page(struct page *page);
static int snp_decommission_context(struct kvm *kvm);

struct enc_region {
	struct list_head list;
	unsigned long npages;
	struct page **pages;
	unsigned long uaddr;
	unsigned long size;
};

static int sev_flush_asids(void)
{
	int ret, error = 0;

	/*
	 * DEACTIVATE will clear the WBINVD indicator causing DF_FLUSH to fail,
	 * so it must be guarded.
	 */
	down_write(&sev_deactivate_lock);

	wbinvd_on_all_cpus();
	ret = sev_guest_df_flush(&error);

	up_write(&sev_deactivate_lock);

	if (ret)
		pr_err("SEV: DF_FLUSH failed, ret=%d, error=%#x\n", ret, error);

	return ret;
}

/* Must be called with the sev_bitmap_lock held */
static bool __sev_recycle_asids(int min_asid, int max_asid)
{
	int pos;

	/* Check if there are any ASIDs to reclaim before performing a flush */
	pos = find_next_bit(sev_reclaim_asid_bitmap, max_sev_asid, min_asid);
	if (pos >= max_asid)
		return false;

	if (sev_flush_asids())
		return false;

	/* The flush process will flush all reclaimable SEV and SEV-ES ASIDs */
	bitmap_xor(sev_asid_bitmap, sev_asid_bitmap, sev_reclaim_asid_bitmap,
		   max_sev_asid);
	bitmap_zero(sev_reclaim_asid_bitmap, max_sev_asid);

	return true;
}

static int sev_asid_new(struct kvm_sev_info *sev)
{
	int pos, min_asid, max_asid;
	bool retry = true;

	mutex_lock(&sev_bitmap_lock);

	/*
	 * SEV-enabled guests must use asid from min_sev_asid to max_sev_asid.
	 * SEV-ES-enabled guest can use from 1 to min_sev_asid - 1.
	 */
	min_asid = sev->es_active ? 0 : min_sev_asid - 1;
	max_asid = sev->es_active ? min_sev_asid - 1 : max_sev_asid;
again:
	pos = find_next_zero_bit(sev_asid_bitmap, max_sev_asid, min_asid);
	if (pos >= max_asid) {
		if (retry && __sev_recycle_asids(min_asid, max_asid)) {
			retry = false;
			goto again;
		}
		mutex_unlock(&sev_bitmap_lock);
		return -EBUSY;
	}

	__set_bit(pos, sev_asid_bitmap);

	mutex_unlock(&sev_bitmap_lock);

	return pos + 1;
}

static int sev_get_asid(struct kvm *kvm)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	return sev->asid;
}

static void sev_asid_free(int asid)
{
	struct svm_cpu_data *sd;
	int cpu, pos;

	mutex_lock(&sev_bitmap_lock);

	pos = asid - 1;
	__set_bit(pos, sev_reclaim_asid_bitmap);

	for_each_possible_cpu(cpu) {
		sd = per_cpu(svm_data, cpu);
		sd->sev_vmcbs[pos] = NULL;
	}

	mutex_unlock(&sev_bitmap_lock);
}

static void sev_unbind_asid(struct kvm *kvm, unsigned int handle)
{
	struct sev_data_decommission *decommission;
	struct sev_data_deactivate *data;

	if (!handle)
		return;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return;

	/* deactivate handle */
	data->handle = handle;

	/* Guard DEACTIVATE against WBINVD/DF_FLUSH used in ASID recycling */
	down_read(&sev_deactivate_lock);
	sev_guest_deactivate(data, NULL);
	up_read(&sev_deactivate_lock);

	kfree(data);

	decommission = kzalloc(sizeof(*decommission), GFP_KERNEL);
	if (!decommission)
		return;

	/* decommission handle */
	decommission->handle = handle;
	sev_guest_decommission(decommission, NULL);

	kfree(decommission);
}

static int sev_guest_init(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	int asid, ret;

	ret = -EBUSY;
	if (unlikely(sev->active))
		return ret;

	asid = sev_asid_new(sev);
	if (asid < 0)
		return ret;

	if (sev->snp_active)
		ret = sev_snp_init(&argp->error);
	else
		ret = sev_platform_init(&argp->error);

	if (ret)
		goto e_free;

	sev->active = true;
	sev->asid = asid;
	INIT_LIST_HEAD(&sev->regions_list);

	return 0;

e_free:
	sev_asid_free(asid);
	return ret;
}

static int sev_es_guest_init(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	if (!sev_es)
		return -ENOTTY;

	to_kvm_svm(kvm)->sev_info.es_active = true;

	return sev_guest_init(kvm, argp);
}

static int sev_snp_guest_init(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	int rc;

	if (!sev_snp)
		return -ENOTTY;

	sev->es_active = true;
	sev->snp_active = true;

	rc = sev_guest_init(kvm, argp);
	if (rc)
		goto e_done;

	return 0;

e_done:
	sev->es_active = false;
	sev->snp_active = false;
	return rc;
}

static int sev_bind_asid(struct kvm *kvm, unsigned int handle, int *error)
{
	struct sev_data_activate *data;
	int asid = sev_get_asid(kvm);
	int ret;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	/* activate ASID on the given handle */
	data->handle = handle;
	data->asid   = asid;
	ret = sev_guest_activate(data, error);
	kfree(data);

	return ret;
}

static int __sev_issue_cmd(int fd, int id, void *data, int *error)
{
	struct fd f;
	int ret;

	f = fdget(fd);
	if (!f.file)
		return -EBADF;

	ret = sev_issue_cmd_external_user(f.file, id, data, error);

	fdput(f);
	return ret;
}

static int sev_issue_cmd(struct kvm *kvm, int id, void *data, int *error)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	return __sev_issue_cmd(sev->fd, id, data, error);
}

static int sev_launch_start(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_launch_start *start;
	struct kvm_sev_launch_start params;
	void *dh_blob, *session_blob;
	int *error = &argp->error;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	start = kzalloc(sizeof(*start), GFP_KERNEL_ACCOUNT);
	if (!start)
		return -ENOMEM;

	dh_blob = NULL;
	if (params.dh_uaddr) {
		dh_blob = psp_copy_user_blob(params.dh_uaddr, params.dh_len);
		if (IS_ERR(dh_blob)) {
			ret = PTR_ERR(dh_blob);
			goto e_free;
		}

		start->dh_cert_address = __sme_set(__pa(dh_blob));
		start->dh_cert_len = params.dh_len;
	}

	session_blob = NULL;
	if (params.session_uaddr) {
		session_blob = psp_copy_user_blob(params.session_uaddr, params.session_len);
		if (IS_ERR(session_blob)) {
			ret = PTR_ERR(session_blob);
			goto e_free_dh;
		}

		start->session_address = __sme_set(__pa(session_blob));
		start->session_len = params.session_len;
	}

	start->handle = params.handle;
	start->policy = params.policy;

	/* create memory encryption context */
	ret = __sev_issue_cmd(argp->sev_fd, SEV_CMD_LAUNCH_START, start, error);
	if (ret)
		goto e_free_session;

	/* Bind ASID to this guest */
	ret = sev_bind_asid(kvm, start->handle, error);
	if (ret)
		goto e_free_session;

	/* return handle to userspace */
	params.handle = start->handle;
	if (copy_to_user((void __user *)(uintptr_t)argp->data, &params, sizeof(params))) {
		sev_unbind_asid(kvm, start->handle);
		ret = -EFAULT;
		goto e_free_session;
	}

	sev->handle = start->handle;
	sev->fd = argp->sev_fd;

e_free_session:
	kfree(session_blob);
e_free_dh:
	kfree(dh_blob);
e_free:
	kfree(start);
	return ret;
}

static struct page **sev_pin_memory(struct kvm *kvm, unsigned long uaddr,
				    unsigned long ulen, unsigned long *n,
				    int write)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	unsigned long npages, npinned, size;
	unsigned long locked, lock_limit;
	struct page **pages;
	unsigned long first, last;

	if (ulen == 0 || uaddr + ulen < uaddr)
		return NULL;

	/* Calculate number of pages. */
	first = (uaddr & PAGE_MASK) >> PAGE_SHIFT;
	last = ((uaddr + ulen - 1) & PAGE_MASK) >> PAGE_SHIFT;
	npages = (last - first + 1);

	locked = sev->pages_locked + npages;
	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	if (locked > lock_limit && !capable(CAP_IPC_LOCK)) {
		pr_err("SEV: %lu locked pages exceed the lock limit of %lu.\n", locked, lock_limit);
		return NULL;
	}

	/* Avoid using vmalloc for smaller buffers. */
	size = npages * sizeof(struct page *);
	if (size > PAGE_SIZE)
		pages = __vmalloc(size, GFP_KERNEL_ACCOUNT | __GFP_ZERO,
				  PAGE_KERNEL);
	else
		pages = kmalloc(size, GFP_KERNEL_ACCOUNT);

	if (!pages)
		return NULL;

	/* Pin the user virtual address. */
	npinned = get_user_pages_fast(uaddr, npages, write ? FOLL_WRITE : 0, pages);
	if (npinned != npages) {
		pr_err("SEV: Failure locking %lu pages.\n", npages);
		goto err;
	}

	*n = npages;
	sev->pages_locked = locked;

	return pages;

err:
	if (npinned > 0)
		release_pages(pages, npinned);

	kvfree(pages);
	return NULL;
}

static void sev_unpin_memory(struct kvm *kvm, struct page **pages,
			     unsigned long npages)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	release_pages(pages, npages);
	kvfree(pages);
	sev->pages_locked -= npages;
}

static void sev_clflush_pages(struct page *pages[], unsigned long npages)
{
	uint8_t *page_virtual;
	unsigned long i;

	if (npages == 0 || pages == NULL)
		return;

	for (i = 0; i < npages; i++) {
		page_virtual = kmap_atomic(pages[i]);
		clflush_cache_range(page_virtual, PAGE_SIZE);
		kunmap_atomic(page_virtual);
	}
}

static unsigned long get_num_contig_pages(unsigned long idx,
				struct page **inpages, unsigned long npages)
{
	unsigned long paddr, next_paddr;
	unsigned long i = idx + 1, pages = 1;

	/* find the number of contiguous pages starting from idx */
	paddr = __sme_page_pa(inpages[idx]);
	while (i < npages) {
		next_paddr = __sme_page_pa(inpages[i++]);
		if ((paddr + PAGE_SIZE) == next_paddr) {
			pages++;
			paddr = next_paddr;
			continue;
		}
		break;
	}

	return pages;
}

static int sev_launch_update_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	unsigned long vaddr, vaddr_end, next_vaddr, npages, pages, size, i;
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_sev_launch_update_data params;
	struct sev_data_launch_update_data *data;
	struct page **inpages;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	vaddr = params.uaddr;
	size = params.len;
	vaddr_end = vaddr + size;

	/* Lock the user memory. */
	inpages = sev_pin_memory(kvm, vaddr, size, &npages, 1);
	if (!inpages) {
		ret = -ENOMEM;
		goto e_free;
	}

	/*
	 * The LAUNCH_UPDATE command will perform in-place encryption of the
	 * memory content (i.e it will write the same memory region with C=1).
	 * It's possible that the cache may contain the data with C=0, i.e.,
	 * unencrypted so invalidate it first.
	 */
	sev_clflush_pages(inpages, npages);

	for (i = 0; vaddr < vaddr_end; vaddr = next_vaddr, i += pages) {
		int offset, len;

		/*
		 * If the user buffer is not page-aligned, calculate the offset
		 * within the page.
		 */
		offset = vaddr & (PAGE_SIZE - 1);

		/* Calculate the number of pages that can be encrypted in one go. */
		pages = get_num_contig_pages(i, inpages, npages);

		len = min_t(size_t, ((pages * PAGE_SIZE) - offset), size);

		data->handle = sev->handle;
		data->len = len;
		data->address = __sme_page_pa(inpages[i]) + offset;
		ret = sev_issue_cmd(kvm, SEV_CMD_LAUNCH_UPDATE_DATA, data, &argp->error);
		if (ret)
			goto e_unpin;

		size -= len;
		next_vaddr = vaddr + len;
	}

e_unpin:
	/* content of memory is updated, mark pages dirty */
	for (i = 0; i < npages; i++) {
		set_page_dirty_lock(inpages[i]);
		mark_page_accessed(inpages[i]);
	}
	/* unlock the user pages */
	sev_unpin_memory(kvm, inpages, npages);
e_free:
	kfree(data);
	return ret;
}

static int sev_launch_update_vmsa(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_launch_update_vmsa *vmsa;
	int i, ret;

	if (!sev_es_guest(kvm))
		return -ENOTTY;

	vmsa = kzalloc(sizeof(*vmsa), GFP_KERNEL);
	if (!vmsa)
		return -ENOMEM;

	for (i = 0; i < kvm->created_vcpus; i++) {
		struct vcpu_svm *svm = to_svm(kvm->vcpus[i]);
		struct vmcb_save_area *save = get_vmsa(svm);

		/* Set XCR0 before encrypting */
		save->xcr0 = svm->vcpu.arch.xcr0;

		/*
		 * The LAUNCH_UPDATE_VMSA command will perform in-place
		 * encryption of the VMSA memory content (i.e it will write
		 * the same memory region with the guest's key), so invalidate
		 * it first.
		 */
		clflush_cache_range(svm->vmsa, PAGE_SIZE);

		vmsa->handle = sev->handle;
		vmsa->address = __sme_pa(svm->vmsa);
		vmsa->len = PAGE_SIZE;
		ret = sev_issue_cmd(kvm, SEV_CMD_LAUNCH_UPDATE_VMSA, vmsa,
				    &argp->error);
		if (ret)
			goto e_free;

		svm->vcpu.arch.vmsa_encrypted = true;
	}

e_free:
	kfree(vmsa);
	return ret;
}

static int sev_launch_measure(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	void __user *measure = (void __user *)(uintptr_t)argp->data;
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_launch_measure *data;
	struct kvm_sev_launch_measure params;
	void __user *p = NULL;
	void *blob = NULL;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, measure, sizeof(params)))
		return -EFAULT;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	/* User wants to query the blob length */
	if (!params.len)
		goto cmd;

	p = (void __user *)(uintptr_t)params.uaddr;
	if (p) {
		if (params.len > SEV_FW_BLOB_MAX_SIZE) {
			ret = -EINVAL;
			goto e_free;
		}

		ret = -ENOMEM;
		blob = kmalloc(params.len, GFP_KERNEL);
		if (!blob)
			goto e_free;

		data->address = __psp_pa(blob);
		data->len = params.len;
	}

cmd:
	data->handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_LAUNCH_MEASURE, data, &argp->error);

	/*
	 * If we query the session length, FW responded with expected data.
	 */
	if (!params.len)
		goto done;

	if (ret)
		goto e_free_blob;

	if (blob) {
		if (copy_to_user(p, blob, params.len))
			ret = -EFAULT;
	}

done:
	params.len = data->len;
	if (copy_to_user(measure, &params, sizeof(params)))
		ret = -EFAULT;
e_free_blob:
	kfree(blob);
e_free:
	kfree(data);
	return ret;
}

static int sev_launch_finish(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_launch_finish *data;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	data->handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_LAUNCH_FINISH, data, &argp->error);

	kfree(data);
	return ret;
}

static int sev_guest_status(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_sev_guest_status params;
	struct sev_data_guest_status *data;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	data->handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_GUEST_STATUS, data, &argp->error);
	if (ret)
		goto e_free;

	params.policy = data->policy;
	params.state = data->state;
	params.handle = data->handle;

	if (copy_to_user((void __user *)(uintptr_t)argp->data, &params, sizeof(params)))
		ret = -EFAULT;
e_free:
	kfree(data);
	return ret;
}

static int __sev_issue_dbg_cmd(struct kvm *kvm, unsigned long src,
			       unsigned long dst, int size,
			       int *error, bool enc)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_dbg *data;
	int ret;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	data->handle = sev->handle;
	data->dst_addr = dst;
	data->src_addr = src;
	data->len = size;

	ret = sev_issue_cmd(kvm,
			    enc ? SEV_CMD_DBG_ENCRYPT : SEV_CMD_DBG_DECRYPT,
			    data, error);
	kfree(data);
	return ret;
}

static int __sev_dbg_decrypt(struct kvm *kvm, unsigned long src_paddr,
			     unsigned long dst_paddr, int sz, int *err)
{
	int offset;

	/*
	 * Its safe to read more than we are asked, caller should ensure that
	 * destination has enough space.
	 */
	src_paddr = round_down(src_paddr, 16);
	offset = src_paddr & 15;
	sz = round_up(sz + offset, 16);

	return __sev_issue_dbg_cmd(kvm, src_paddr, dst_paddr, sz, err, false);
}

static int __sev_dbg_decrypt_user(struct kvm *kvm, unsigned long paddr,
				  unsigned long __user dst_uaddr,
				  unsigned long dst_paddr,
				  int size, int *err)
{
	struct page *tpage = NULL;
	int ret, offset;

	/* if inputs are not 16-byte then use intermediate buffer */
	if (!IS_ALIGNED(dst_paddr, 16) ||
	    !IS_ALIGNED(paddr,     16) ||
	    !IS_ALIGNED(size,      16)) {
		tpage = (void *)alloc_page(GFP_KERNEL);
		if (!tpage)
			return -ENOMEM;

		dst_paddr = __sme_page_pa(tpage);
	}

	ret = __sev_dbg_decrypt(kvm, paddr, dst_paddr, size, err);
	if (ret)
		goto e_free;

	if (tpage) {
		offset = paddr & 15;
		if (copy_to_user((void __user *)(uintptr_t)dst_uaddr,
				 page_address(tpage) + offset, size))
			ret = -EFAULT;
	}

e_free:
	if (tpage)
		__free_page(tpage);

	return ret;
}

static int __sev_dbg_encrypt_user(struct kvm *kvm, unsigned long paddr,
				  unsigned long __user vaddr,
				  unsigned long dst_paddr,
				  unsigned long __user dst_vaddr,
				  int size, int *error)
{
	struct page *src_tpage = NULL;
	struct page *dst_tpage = NULL;
	int ret, len = size;

	/* If source buffer is not aligned then use an intermediate buffer */
	if (!IS_ALIGNED(vaddr, 16)) {
		src_tpage = alloc_page(GFP_KERNEL);
		if (!src_tpage)
			return -ENOMEM;

		if (copy_from_user(page_address(src_tpage),
				(void __user *)(uintptr_t)vaddr, size)) {
			__free_page(src_tpage);
			return -EFAULT;
		}

		paddr = __sme_page_pa(src_tpage);
	}

	/*
	 *  If destination buffer or length is not aligned then do read-modify-write:
	 *   - decrypt destination in an intermediate buffer
	 *   - copy the source buffer in an intermediate buffer
	 *   - use the intermediate buffer as source buffer
	 */
	if (!IS_ALIGNED(dst_vaddr, 16) || !IS_ALIGNED(size, 16)) {
		int dst_offset;

		dst_tpage = alloc_page(GFP_KERNEL);
		if (!dst_tpage) {
			ret = -ENOMEM;
			goto e_free;
		}

		ret = __sev_dbg_decrypt(kvm, dst_paddr,
					__sme_page_pa(dst_tpage), size, error);
		if (ret)
			goto e_free;

		/*
		 *  If source is kernel buffer then use memcpy() otherwise
		 *  copy_from_user().
		 */
		dst_offset = dst_paddr & 15;

		if (src_tpage)
			memcpy(page_address(dst_tpage) + dst_offset,
			       page_address(src_tpage), size);
		else {
			if (copy_from_user(page_address(dst_tpage) + dst_offset,
					   (void __user *)(uintptr_t)vaddr, size)) {
				ret = -EFAULT;
				goto e_free;
			}
		}

		paddr = __sme_page_pa(dst_tpage);
		dst_paddr = round_down(dst_paddr, 16);
		len = round_up(size, 16);
	}

	ret = __sev_issue_dbg_cmd(kvm, paddr, dst_paddr, len, error, true);

e_free:
	if (src_tpage)
		__free_page(src_tpage);
	if (dst_tpage)
		__free_page(dst_tpage);
	return ret;
}

static int sev_dbg_crypt(struct kvm *kvm, struct kvm_sev_cmd *argp, bool dec)
{
	unsigned long vaddr, vaddr_end, next_vaddr;
	unsigned long dst_vaddr;
	struct page **src_p, **dst_p;
	struct kvm_sev_dbg debug;
	unsigned long n;
	unsigned int size;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&debug, (void __user *)(uintptr_t)argp->data, sizeof(debug)))
		return -EFAULT;

	if (!debug.len || debug.src_uaddr + debug.len < debug.src_uaddr)
		return -EINVAL;
	if (!debug.dst_uaddr)
		return -EINVAL;

	vaddr = debug.src_uaddr;
	size = debug.len;
	vaddr_end = vaddr + size;
	dst_vaddr = debug.dst_uaddr;

	for (; vaddr < vaddr_end; vaddr = next_vaddr) {
		int len, s_off, d_off;

		/* lock userspace source and destination page */
		src_p = sev_pin_memory(kvm, vaddr & PAGE_MASK, PAGE_SIZE, &n, 0);
		if (!src_p)
			return -EFAULT;

		dst_p = sev_pin_memory(kvm, dst_vaddr & PAGE_MASK, PAGE_SIZE, &n, 1);
		if (!dst_p) {
			sev_unpin_memory(kvm, src_p, n);
			return -EFAULT;
		}

		/*
		 * The DBG_{DE,EN}CRYPT commands will perform {dec,en}cryption of the
		 * memory content (i.e it will write the same memory region with C=1).
		 * It's possible that the cache may contain the data with C=0, i.e.,
		 * unencrypted so invalidate it first.
		 */
		sev_clflush_pages(src_p, 1);
		sev_clflush_pages(dst_p, 1);

		/*
		 * Since user buffer may not be page aligned, calculate the
		 * offset within the page.
		 */
		s_off = vaddr & ~PAGE_MASK;
		d_off = dst_vaddr & ~PAGE_MASK;
		len = min_t(size_t, (PAGE_SIZE - s_off), size);

		if (dec)
			ret = __sev_dbg_decrypt_user(kvm,
						     __sme_page_pa(src_p[0]) + s_off,
						     dst_vaddr,
						     __sme_page_pa(dst_p[0]) + d_off,
						     len, &argp->error);
		else
			ret = __sev_dbg_encrypt_user(kvm,
						     __sme_page_pa(src_p[0]) + s_off,
						     vaddr,
						     __sme_page_pa(dst_p[0]) + d_off,
						     dst_vaddr,
						     len, &argp->error);

		sev_unpin_memory(kvm, src_p, n);
		sev_unpin_memory(kvm, dst_p, n);

		if (ret)
			goto err;

		next_vaddr = vaddr + len;
		dst_vaddr = dst_vaddr + len;
		size -= len;
	}
err:
	return ret;
}

static int sev_launch_secret(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_launch_secret *data;
	struct kvm_sev_launch_secret params;
	struct page **pages;
	void *blob, *hdr;
	unsigned long n;
	int ret, offset;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	pages = sev_pin_memory(kvm, params.guest_uaddr, params.guest_len, &n, 1);
	if (!pages)
		return -ENOMEM;

	/*
	 * The secret must be copied into contiguous memory region, lets verify
	 * that userspace memory pages are contiguous before we issue command.
	 */
	if (get_num_contig_pages(0, pages, n) != n) {
		ret = -EINVAL;
		goto e_unpin_memory;
	}

	ret = -ENOMEM;
	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		goto e_unpin_memory;

	offset = params.guest_uaddr & (PAGE_SIZE - 1);
	data->guest_address = __sme_page_pa(pages[0]) + offset;
	data->guest_len = params.guest_len;

	blob = psp_copy_user_blob(params.trans_uaddr, params.trans_len);
	if (IS_ERR(blob)) {
		ret = PTR_ERR(blob);
		goto e_free;
	}

	data->trans_address = __psp_pa(blob);
	data->trans_len = params.trans_len;

	hdr = psp_copy_user_blob(params.hdr_uaddr, params.hdr_len);
	if (IS_ERR(hdr)) {
		ret = PTR_ERR(hdr);
		goto e_free_blob;
	}
	data->hdr_address = __psp_pa(hdr);
	data->hdr_len = params.hdr_len;

	data->handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_LAUNCH_UPDATE_SECRET, data, &argp->error);

	kfree(hdr);

e_free_blob:
	kfree(blob);
e_free:
	kfree(data);
e_unpin_memory:
	sev_unpin_memory(kvm, pages, n);
	return ret;
}

static void snp_print_rmpentry(u64 spa)
{
	unsigned long start = (unsigned long)rmp_table_vaddr + (4 * PAGE_SIZE);
	uint8_t *ptr;
	int i;

	start += sizeof(struct rmp_entry) * (spa >> PAGE_SHIFT);
	ptr = (uint8_t *)start;

	pr_cont("(rmpentry) spa: 0x%llx entry:", spa);
	for (i = 15; i >= 0; i--)
		pr_cont("%02hhx", ptr[i]);
	pr_cont("\n");
}

static int snp_page_reclaim(unsigned long spa)
{
	struct sev_data_snp_page_reclaim *data;
	struct rmpupdate_entry e = {};
	int rc, error;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	data->paddr = spa;
	rc = sev_snp_reclaim(data, &error);
	if (rc) {
		pr_err("SNP: failed to reclaim spa 0x%lx error=%#x\n", spa, error);
		snp_print_rmpentry(spa);
		goto e_free;
	}

	snp_rmpupdate_set(spa, &e);

e_free:
	kfree(data);
	return rc;
}

static void snp_free_context_page(struct page *page)
{
	unsigned long spa = page_to_pfn(page) << PAGE_SHIFT;

	/* reclaim the page before changing the attribute */
	if (snp_page_reclaim(spa))
		return;

	__free_page(page);
}

static struct page *snp_alloc_context_page(void)
{
	struct rmpupdate_entry entry = {};
	struct page *page = NULL;

	page = alloc_page(GFP_KERNEL);
	if (!page)
		return NULL;

	/*
	 * set the page attribute to be RO, this page should never be touched by the
	 * x86.
	 */
	if (set_memory_4k((unsigned long)page_address(page), 1)) {
		__free_page(page);
		return NULL;
	}

	/* make the page immutable */
	entry.immutable = 1;
	entry.assigned = 1;
	if (snp_rmpupdate_set(page_to_pfn(page) << PAGE_SHIFT, &entry))
		goto e_free;

	return page;

e_free:
	snp_free_context_page(page);
	return NULL;
}

static struct page *snp_context_create(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct sev_data_snp_gctx_create *data;
	struct page *context = NULL;
	int rc;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return NULL;

	/* allocate memory for context page */
	context = snp_alloc_context_page();
	if (!context)
		goto e_free;

	data->gctx_paddr = __sme_page_pa(context);
	rc = __sev_issue_cmd(argp->sev_fd, SEV_CMD_SNP_GCTX_CREATE, data, &argp->error);
	if (rc) {
		snp_free_context_page(context);
		context = NULL;
	}

e_free:
	kfree(data);
	return context;
}

static int snp_bind_asid(struct kvm *kvm, int *error)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_snp_activate *data;
	int asid = sev_get_asid(kvm);
	int ret, retry_count = 0;

	data = kmalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	/* activate ASID on the given context */
	data->gctx_paddr = __sme_page_pa(sev->snp_context);
	data->asid   = asid;
again:
	ret = sev_issue_cmd(kvm, SEV_CMD_SNP_ACTIVATE, data, error);

	/* Check if the DF_FLUSH is required, and try again */
	if ((!retry_count) && (ret) && (*error == SEV_RET_DFFLUSH_REQUIRED)) {
		wbinvd_on_all_cpus();

		ret = sev_guest_snp_df_flush(error);
		if (ret)
			goto e_free;

		/* only one retry */
		retry_count = 1;

		goto again;
	}

e_free:
	kfree(data);
	return ret;
}

static int snp_launch_start(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_snp_launch_start *start;
	struct kvm_sev_snp_launch_start params;
	int rc;

	if (!sev_snp_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	/* initialize the guest context */
	sev->snp_context = snp_context_create(kvm, argp);
	if (!sev->snp_context)
		return -ENOTTY;

	rc = -ENOMEM;
	start = kzalloc(sizeof(*start), GFP_KERNEL_ACCOUNT);
	if (!start)
		goto e_free_context;

	/* issue the LAUNCH_START command */
	start->gctx_paddr = __sme_page_pa(sev->snp_context);
	start->policy = params.policy;
	rc = __sev_issue_cmd(argp->sev_fd, SEV_CMD_SNP_LAUNCH_START, start, &argp->error);
	if (rc)
		goto e_free_context;

	/* Bind ASID to this guest */
	sev->fd = argp->sev_fd;
	rc = snp_bind_asid(kvm, &argp->error);
	if (rc)
		goto e_free_context;

	goto e_free_start;

e_free_context:
	snp_decommission_context(kvm);
e_free_start:
	kfree(start);
	return rc;
}

static struct kvm_memory_slot *hva_to_memslot(struct kvm *kvm, unsigned long hva)
{
	struct kvm_memslots *slots = kvm_memslots(kvm);
	struct kvm_memory_slot *memslot;

	kvm_for_each_memslot(memslot, slots) {
		if (hva >= memslot->userspace_addr &&
		    hva < memslot->userspace_addr + (memslot->npages << PAGE_SHIFT))
			return memslot;
	}

	return NULL;
}

static bool hva_to_gpa(struct kvm *kvm, unsigned long hva, gpa_t *gpa)
{
	struct kvm_memory_slot *memslot;
	gpa_t gpa_offset;

	memslot = hva_to_memslot(kvm, hva);
	if (!memslot)
		return false;

	gpa_offset = hva - memslot->userspace_addr;
	*gpa = ((memslot->base_gfn << PAGE_SHIFT) + gpa_offset);

	return true;
}

static int snp_launch_update(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	unsigned long npages, vaddr, vaddr_end, i, next_vaddr;
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_snp_launch_update *data;
	struct kvm_sev_snp_launch_update params;
	int *error = &argp->error;
	struct page **inpages;
	int ret;

	if (!sev_snp_guest(kvm))
		return -ENOTTY;

	if (!sev->snp_context)
		return -EINVAL;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	/* Lock the user memory. */
	inpages = sev_pin_memory(kvm, params.uaddr, params.len, &npages, 1);
	if (!inpages) {
		ret = -ENOMEM;
		goto e_free;
	}

	vaddr = params.uaddr;
	vaddr_end = vaddr + params.len;

	for (i = 0; vaddr < vaddr_end; vaddr = next_vaddr, i++) {
		unsigned long psize, pmask, spa;
		struct rmpupdate_entry e = {};
		int level;
		gpa_t gpa;

		if (!hva_to_gpa(kvm, vaddr, &gpa)) {
			pr_err("SNP: failed to find gpa for hva 0x%lx\n", vaddr);
			ret = -EINVAL;
			goto e_unpin;
		}

		/*
		 * We force all the data encrypted through the LAUNCH_UPDATE to
		 * mapped as a 4K entry in the RMP table.
		 */
		spa = page_to_pfn(inpages[i]) << PAGE_SHIFT;
		level = PG_LEVEL_4K;

		psize = page_level_size(level);
		pmask = page_level_mask(level);
		gpa = gpa & pmask;

		/* make the page as pre-guest */
		e.assigned = 1;
		e.gpa = gpa;
		e.asid = sev_get_asid(kvm);
		e.immutable = true;
		e.pagesize = 0; /* always encrypt as 4K page */
		if (set_memory_4k((unsigned long)__va(spa), 1)) {
			ret = -EFAULT;
			pr_err("SNP: failed to split the page\n");
			goto e_unpin;
		}

		ret = snp_rmpupdate_set(spa, &e);
		if (ret) {
			pr_err("SNP: failed to transition vaddr 0x%lx spa 0x%lx "
				" gpa 0x%llx pagesize %d asid %d to pre-guest ret=%d\n",
				vaddr, spa, e.gpa, e.pagesize, e.asid, ret);
			snp_print_rmpentry(spa);
			ret = -EFAULT;
			goto e_unpin;
		}

		data->gctx_paddr = __sme_page_pa(sev->snp_context);
		data->vmpl1_perms = 0xf;
		data->vmpl2_perms = 0xf;
		data->vmpl3_perms = 0xf;
		data->address = spa;
		data->page_size = e.pagesize;
		data->page_type = params.page_type;

		ret = __sev_issue_cmd(argp->sev_fd, SEV_CMD_SNP_LAUNCH_UPDATE,
					data, error);
		if (ret) {
			snp_page_reclaim(spa);
			goto e_unpin;
		}

		next_vaddr = (vaddr & pmask) + psize;
	}

e_unpin:
	/* content of memory is updated, mark pages dirty */
	for (i = 0; i < npages; i++) {
		set_page_dirty_lock(inpages[i]);
		mark_page_accessed(inpages[i]);
	}
	/* unlock the user pages */
	sev_unpin_memory(kvm, inpages, npages);
e_free:
	kfree(data);
	return ret;
}

static int snp_launch_update_vmsa(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_snp_launch_update *data;
	int i, ret;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	for (i = 0; i < kvm->created_vcpus; i++) {
		struct vcpu_svm *svm = to_svm(kvm->vcpus[i]);
		struct vmcb_save_area *save = get_vmsa(svm);
		struct rmpupdate_entry e = {};

		/* Set XCR0 before encrypting */
		save->xcr0 = svm->vcpu.arch.xcr0;

		data->gctx_paddr = __sme_page_pa(sev->snp_context);
		data->address = __sme_pa(svm->vmsa);
		data->page_type = SNP_PAGE_TYPE_VMSA;

		/* add to the RMP table */
		e.assigned = 1;
		e.immutable = 1;
		e.asid = sev->asid;
		e.gpa = -1;
		ret = snp_rmpupdate_set(__pa(svm->vmsa), &e);
		if (ret) {
			pr_err("SNP: failed to add VMSA %d to RMP table error=%d\n", i, ret);
			goto e_free;
		}

		/* issue the SNP command to encrypt the VMSA */
		ret = __sev_issue_cmd(argp->sev_fd, SEV_CMD_SNP_LAUNCH_UPDATE,
				data, &argp->error);
		if (ret) {
			snp_page_reclaim(__pa(svm->vmsa));
			goto e_free;
		}

		svm->vcpu.arch.vmsa_encrypted = true;
	}

e_free:
	kfree(data);
	return ret;
}

static int snp_launch_finish(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_snp_launch_finish *data;
	void *id_block = NULL, *id_auth = NULL;
	struct kvm_sev_snp_launch_finish params;
	int ret;

	if (!sev_snp_guest(kvm))
		return -ENOTTY;

	if (!sev->snp_context)
		return -EINVAL;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	if ((ret = snp_launch_update_vmsa(kvm, argp)))
		return ret;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	if (params.id_block_en) {
		id_block = psp_copy_user_blob(params.id_block_uaddr, KVM_SEV_SNP_ID_BLOCK_SIZE);
		if (IS_ERR(id_block)) {
			ret = PTR_ERR(id_block);
			goto e_free;
		}

		data->id_block_en = 1;
		data->id_block_paddr = __sme_pa(id_block);
	}

	if (params.auth_key_en) {
		id_auth = psp_copy_user_blob(params.id_auth_uaddr, KVM_SEV_SNP_ID_AUTH_SIZE);
		if (IS_ERR(id_auth)) {
			ret = PTR_ERR(id_auth);
			goto e_free_1;
		}

		data->auth_key_en = 1;
		data->id_auth_paddr = __sme_pa(id_auth);
	}

	data->gctx_paddr = __sme_page_pa(sev->snp_context);
	ret = sev_issue_cmd(kvm, SEV_CMD_SNP_LAUNCH_FINISH, data, &argp->error);

	kfree(id_auth);

e_free_1:
	kfree(id_block);
e_free:
	kfree(data);
	return ret;
}

int svm_mem_enc_op(struct kvm *kvm, void __user *argp)
{
	struct kvm_sev_cmd sev_cmd;
	int r;

	if (!svm_sev_enabled() || !sev)
		return -ENOTTY;

	if (!argp)
		return 0;

	if (copy_from_user(&sev_cmd, argp, sizeof(struct kvm_sev_cmd)))
		return -EFAULT;

	mutex_lock(&kvm->lock);

	switch (sev_cmd.id) {
	case KVM_SEV_INIT:
		r = sev_guest_init(kvm, &sev_cmd);
		break;
	case KVM_SEV_ES_INIT:
		r = sev_es_guest_init(kvm, &sev_cmd);
		break;
	case KVM_SEV_SNP_INIT:
		r = sev_snp_guest_init(kvm, &sev_cmd);
		break;
	case KVM_SEV_LAUNCH_START:
		r = sev_launch_start(kvm, &sev_cmd);
		break;
	case KVM_SEV_LAUNCH_UPDATE_DATA:
		r = sev_launch_update_data(kvm, &sev_cmd);
		break;
	case KVM_SEV_LAUNCH_UPDATE_VMSA:
		r = sev_launch_update_vmsa(kvm, &sev_cmd);
		break;
	case KVM_SEV_LAUNCH_MEASURE:
		r = sev_launch_measure(kvm, &sev_cmd);
		break;
	case KVM_SEV_LAUNCH_FINISH:
		r = sev_launch_finish(kvm, &sev_cmd);
		break;
	case KVM_SEV_GUEST_STATUS:
		r = sev_guest_status(kvm, &sev_cmd);
		break;
	case KVM_SEV_DBG_DECRYPT:
		r = sev_dbg_crypt(kvm, &sev_cmd, true);
		break;
	case KVM_SEV_DBG_ENCRYPT:
		r = sev_dbg_crypt(kvm, &sev_cmd, false);
		break;
	case KVM_SEV_LAUNCH_SECRET:
		r = sev_launch_secret(kvm, &sev_cmd);
		break;
	case KVM_SEV_SNP_LAUNCH_START:
		r = snp_launch_start(kvm, &sev_cmd);
		break;
	case KVM_SEV_SNP_LAUNCH_UPDATE:
		r = snp_launch_update(kvm, &sev_cmd);
		break;
	case KVM_SEV_SNP_LAUNCH_FINISH:
		r = snp_launch_finish(kvm, &sev_cmd);
		break;
	default:
		r = -EINVAL;
		goto out;
	}

	if (copy_to_user(argp, &sev_cmd, sizeof(struct kvm_sev_cmd)))
		r = -EFAULT;

out:
	mutex_unlock(&kvm->lock);
	return r;
}

int svm_register_enc_region(struct kvm *kvm,
			    struct kvm_enc_region *range)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct enc_region *region;
	int ret = 0;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (range->addr > ULONG_MAX || range->size > ULONG_MAX)
		return -EINVAL;

	region = kzalloc(sizeof(*region), GFP_KERNEL_ACCOUNT);
	if (!region)
		return -ENOMEM;

	region->pages = sev_pin_memory(kvm, range->addr, range->size, &region->npages, 1);
	if (!region->pages) {
		ret = -ENOMEM;
		goto e_free;
	}

	/*
	 * The guest may change the memory encryption attribute from C=0 -> C=1
	 * or vice versa for this memory range. Lets make sure caches are
	 * flushed to ensure that guest data gets written into memory with
	 * correct C-bit.
	 */
	sev_clflush_pages(region->pages, region->npages);

	region->uaddr = range->addr;
	region->size = range->size;

	mutex_lock(&kvm->lock);
	list_add_tail(&region->list, &sev->regions_list);
	mutex_unlock(&kvm->lock);

	return ret;

e_free:
	kfree(region);
	return ret;
}

static struct enc_region *
find_enc_region(struct kvm *kvm, struct kvm_enc_region *range)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct list_head *head = &sev->regions_list;
	struct enc_region *i;

	list_for_each_entry(i, head, list) {
		if (i->uaddr == range->addr &&
		    i->size == range->size)
			return i;
	}

	return NULL;
}

static void __unregister_enc_region_locked(struct kvm *kvm,
					   struct enc_region *region)
{
	unsigned long i, spa;
	struct rmpupdate_entry e = {};

	/* On SNP, make the region as a hypervisor page */
	if (sev_snp_guest(kvm)) {
		for (i = 0; i < region->npages; i++) {;
			spa = page_to_pfn(region->pages[i]) << PAGE_SHIFT;
			snp_rmpupdate_set(spa, &e);
		}
	}

	sev_unpin_memory(kvm, region->pages, region->npages);
	list_del(&region->list);
	kfree(region);
}

int svm_unregister_enc_region(struct kvm *kvm,
			      struct kvm_enc_region *range)
{
	struct enc_region *region;
	int ret;

	mutex_lock(&kvm->lock);

	if (!sev_guest(kvm)) {
		ret = -ENOTTY;
		goto failed;
	}

	region = find_enc_region(kvm, range);
	if (!region) {
		ret = -EINVAL;
		goto failed;
	}

	/*
	 * Ensure that all guest tagged cache entries are flushed before
	 * releasing the pages back to the system for use. CLFLUSH will
	 * not do this, so issue a WBINVD.
	 */
	wbinvd_on_all_cpus();

	__unregister_enc_region_locked(kvm, region);

	mutex_unlock(&kvm->lock);
	return 0;

failed:
	mutex_unlock(&kvm->lock);
	return ret;
}

static int snp_decommission_context(struct kvm *kvm)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_snp_decommission *data;

	/* if context is not created then do nothing */
	if (!sev->snp_context)
		return 0;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	data->gctx_paddr = __sme_page_pa(sev->snp_context);
	sev_guest_snp_decommission(data, NULL);

	/* free the context page now */
	snp_free_context_page(sev->snp_context);
	sev->snp_context = NULL;

	kfree(data);

	return 0;
}

void sev_vm_destroy(struct kvm *kvm)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct list_head *head = &sev->regions_list;
	struct list_head *pos, *q;

	if (!sev_guest(kvm))
		return;

	mutex_lock(&kvm->lock);

	/*
	 * Ensure that all guest tagged cache entries are flushed before
	 * releasing the pages back to the system for use. CLFLUSH will
	 * not do this, so issue a WBINVD.
	 */
	wbinvd_on_all_cpus();

	/*
	 * if userspace was terminated before unregistering the memory regions
	 * then lets unpin all the registered memory.
	 */
	if (!list_empty(head)) {
		list_for_each_safe(pos, q, head) {
			__unregister_enc_region_locked(kvm,
				list_entry(pos, struct enc_region, list));
		}
	}

	mutex_unlock(&kvm->lock);

	if (sev_snp_guest(kvm)) {
		if (snp_decommission_context(kvm)) {
			pr_err("SEV-SNP: failed to free guest context, leaking asid!\n");
			return;
		}
	} else {
		sev_unbind_asid(kvm, sev->handle);
	}

	sev_asid_free(sev->asid);
}

static __init int init_rmp_table(void)
{
	u64 rmp_base, rmp_end;
	unsigned long sz;

	rdmsrl_safe(MSR_AMD64_RMP_BASE, &rmp_base);
	rdmsrl_safe(MSR_AMD64_RMP_END, &rmp_end);

	if (!rmp_base || !rmp_end)
		return 1;

	sz = rmp_end - rmp_base;

	rmp_table_vaddr = memremap(rmp_base, sz, MEMREMAP_WB);
	if (!rmp_table_vaddr) {
		pr_err("SNP: failed to remap 0x%llx-0x%llx\n", rmp_base, rmp_end);
		return 1;
	}

	return 0;
}

static __exit void rmp_unsetup(void)
{
	if (rmp_table_vaddr)
		memunmap(rmp_table_vaddr);
}

void __init sev_hardware_setup(void)
{
	unsigned int eax, ebx, ecx, edx;
	bool sev_snp_supported = false;
	bool sev_es_supported = false;
	bool sev_supported = false;

	/* Does the CPU support SEV? */
	if (!boot_cpu_has(X86_FEATURE_SEV))
		goto out;

	/* Retrieve SEV CPUID information */
	cpuid(0x8000001f, &eax, &ebx, &ecx, &edx);

	/* Set encryption bit location for SEV-ES guests */
	sev_enc_bit = ebx & 0x3f;

	/* Maximum number of encrypted guests supported simultaneously */
	max_sev_asid = ecx;

	/* SNP requires the SEV-ES to be enabled */
	if (sev_snp)
		sev_es = 1;

	if (!svm_sev_enabled())
		goto out;

	/* Minimum ASID value that should be used for SEV guest */
	min_sev_asid = edx;

	/* Initialize SEV ASID bitmaps */
	sev_asid_bitmap = bitmap_zalloc(max_sev_asid, GFP_KERNEL);
	if (!sev_asid_bitmap)
		goto out;

	sev_reclaim_asid_bitmap = bitmap_zalloc(max_sev_asid, GFP_KERNEL);
	if (!sev_reclaim_asid_bitmap)
		goto out;

	pr_info("SEV supported: %u ASIDs\n", max_sev_asid - min_sev_asid + 1);
	sev_supported = true;

	/* SEV-ES support requested? */
	if (!sev_es)
		goto out;

	/* Does the CPU support SEV-ES? */
	if (!boot_cpu_has(X86_FEATURE_SEV_ES))
		goto out;

	/* Has the system been allocated ASIDs for SEV-ES? */
	if (min_sev_asid == 1)
		goto out;

	pr_info("SEV-ES supported: %u ASIDs\n", min_sev_asid - 1);
	sev_es_supported = true;

	/* SEV-SNP support requested? */
	if (!sev_snp)
		goto out;

	/* Does the CPU support SEV-SNP? */
	if (!boot_cpu_has(X86_FEATURE_SEV_SNP))
		goto out;

	if (init_rmp_table())
		goto out;

	pr_info("SEV-SNP supported: %u ASIDs\n", min_sev_asid - 1);
	sev_snp_supported = true;
out:
	sev = sev_supported;
	sev_es = sev_es_supported;
	sev_snp = sev_snp_supported;
}

void sev_hardware_teardown(void)
{
	if (!svm_sev_enabled())
		return;

	rmp_unsetup();
	bitmap_free(sev_asid_bitmap);
	bitmap_free(sev_reclaim_asid_bitmap);

	sev_flush_asids();
}

static void pre_sev_es_run(struct vcpu_svm *svm)
{
	if (!svm->ghcb)
		return;

	if (svm->ghcb_sa_free) {
		/*
		 * The scratch area lives outside the GHCB, so there is a
		 * buffer that, depending on the operation performed, may
		 * need to be synced, then freed.
		 */
		if (svm->ghcb_sa_sync) {
			kvm_write_guest(svm->vcpu.kvm,
					ghcb_get_sw_scratch(svm->ghcb),
					svm->ghcb_sa, svm->ghcb_sa_len);
			svm->ghcb_sa_sync = false;
		}

		kfree(svm->ghcb_sa);
		svm->ghcb_sa = NULL;
		svm->ghcb_sa_free = false;
	}

	trace_kvm_vmgexit_exit(svm->vcpu.vcpu_id, svm->ghcb);

	kvm_vcpu_unmap(&svm->vcpu, &svm->ghcb_map, true);
	svm->ghcb = NULL;
}

void pre_sev_run(struct vcpu_svm *svm, int cpu)
{
	struct svm_cpu_data *sd = per_cpu(svm_data, cpu);
	int asid = sev_get_asid(svm->vcpu.kvm);

	/* Perform any SEV-ES pre-run actions */
	pre_sev_es_run(svm);

	/* Assign the asid allocated with this SEV guest */
	svm->vmcb->control.asid = asid;

	/*
	 * Flush guest TLB:
	 *
	 * 1) when different VMCB for the same ASID is to be run on the same host CPU.
	 * 2) or this VMCB was executed on different host CPU in previous VMRUNs.
	 */
	if (sd->sev_vmcbs[asid] == svm->vmcb &&
	    svm->last_cpu == cpu)
		return;

	svm->last_cpu = cpu;
	sd->sev_vmcbs[asid] = svm->vmcb;
	svm->vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ASID;
	mark_dirty(svm->vmcb, VMCB_ASID);
}

#define GHCB_SCRATCH_AREA_LIMIT		(16ULL * PAGE_SIZE)
static bool setup_vmgexit_scratch(struct vcpu_svm *svm, bool sync, u64 len)
{
	struct vmcb_control_area *control = &svm->vmcb->control;
	struct ghcb *ghcb = svm->ghcb;
	u64 ghcb_scratch_beg, ghcb_scratch_end;
	u64 scratch_gpa_beg, scratch_gpa_end;
	void *scratch_va;

	scratch_gpa_beg = ghcb_get_sw_scratch(ghcb);
	if (!scratch_gpa_beg) {
		pr_err("vmgexit: scratch gpa not provided\n");
		return false;
	}

	scratch_gpa_end = scratch_gpa_beg + len;
	if (scratch_gpa_end < scratch_gpa_beg) {
		pr_err("vmgexit: scratch length (%#llx) not valid for scratch address (%#llx)\n",
		       len, scratch_gpa_beg);
		return false;
	}

	if ((scratch_gpa_beg & PAGE_MASK) == control->ghcb_gpa) {
		/* Scratch area begins within GHCB */
		ghcb_scratch_beg = control->ghcb_gpa +
				   offsetof(struct ghcb, shared_buffer);
		ghcb_scratch_end = control->ghcb_gpa +
				   offsetof(struct ghcb, reserved_1);

		/*
		 * If the scratch area begins within the GHCB, it must be
		 * completely contained in the GHCB shared buffer area.
		 */
		if ((scratch_gpa_beg < ghcb_scratch_beg) ||
		    (scratch_gpa_end > ghcb_scratch_end)) {
			pr_err("vmgexit: scratch area is outside of GHCB shared buffer area (%#llx - %#llx)\n",
			       scratch_gpa_beg, scratch_gpa_end);
			return false;
		}

		scratch_va = (void *)svm->ghcb;
		scratch_va += (scratch_gpa_beg - control->ghcb_gpa);
	} else {
		/*
		 * The guest memory must be read into a kernel buffer, so
		 * limit the size
		 */
		if (len > GHCB_SCRATCH_AREA_LIMIT) {
			pr_err("vmgexit: scratch area exceeds KVM limits (%#llx requested, %#llx limit)\n",
			       len, GHCB_SCRATCH_AREA_LIMIT);
			return false;
		}
		scratch_va = kzalloc(len, GFP_KERNEL);
		if (!scratch_va)
			return false;

		if (kvm_read_guest(svm->vcpu.kvm, scratch_gpa_beg, scratch_va, len)) {
			/* Unable to copy scratch area from guest */
			pr_err("vmgexit: kvm_read_guest for scratch area failed\n");

			kfree(scratch_va);
			return false;
		}

		/*
		 * The scratch area is outside the GHCB. The operation will
		 * dictate whether the buffer needs to be synced before running
		 * the vCPU next time (i.e. a read was requested so the data
		 * must be written back to the guest memory).
		 */
		svm->ghcb_sa_sync = sync;
		svm->ghcb_sa_free = true;
	}

	svm->ghcb_sa = scratch_va;
	svm->ghcb_sa_len = len;

	return true;
}

static void set_ghcb_msr_bits(struct vcpu_svm *svm, u64 value, u64 mask,
			      unsigned int pos)
{
	svm->vmcb->control.ghcb_gpa &= ~(mask << pos);
	svm->vmcb->control.ghcb_gpa |= (value & mask) << pos;
}

static u64 get_ghcb_msr_bits(struct vcpu_svm *svm, u64 mask, unsigned int pos)
{
	return (svm->vmcb->control.ghcb_gpa >> pos) & mask;
}

static void set_ghcb_msr(struct vcpu_svm *svm, u64 value)
{
	svm->vmcb->control.ghcb_gpa = value;
}

static int sev_handle_vmgexit_msr_protocol(struct vcpu_svm *svm)
{
	struct vmcb_control_area *control = &svm->vmcb->control;
	u64 ghcb_info;
	int ret = 1;

	ghcb_info = control->ghcb_gpa & GHCB_MSR_INFO_MASK;

	trace_kvm_vmgexit_msr_protocol_enter(svm->vcpu.vcpu_id,
					     control->ghcb_gpa);

	switch (ghcb_info) {
	case GHCB_MSR_SEV_INFO_REQ:
		set_ghcb_msr(svm, GHCB_MSR_SEV_INFO(GHCB_VERSION_MAX,
						    GHCB_VERSION_MIN,
						    sev_enc_bit));
		break;
	case GHCB_MSR_CPUID_REQ: {
		u64 cpuid_fn, cpuid_reg, cpuid_value;

		cpuid_fn = get_ghcb_msr_bits(svm,
					     GHCB_MSR_CPUID_FUNC_MASK,
					     GHCB_MSR_CPUID_FUNC_POS);

		/* Initialize the registers needed by the CPUID intercept */
		svm_rax_write(svm, cpuid_fn);
		svm_rcx_write(svm, 0);

		ret = svm_invoke_exit_handler(svm, SVM_EXIT_CPUID);
		if (!ret) {
			ret = -EINVAL;
			break;
		}

		cpuid_reg = get_ghcb_msr_bits(svm,
					      GHCB_MSR_CPUID_REG_MASK,
					      GHCB_MSR_CPUID_REG_POS);
		if (cpuid_reg == 0)
			cpuid_value = svm_rax_read(svm);
		else if (cpuid_reg == 1)
			cpuid_value = svm_rbx_read(svm);
		else if (cpuid_reg == 2)
			cpuid_value = svm_rcx_read(svm);
		else
			cpuid_value = svm_rdx_read(svm);

		set_ghcb_msr_bits(svm, cpuid_value,
				  GHCB_MSR_CPUID_VALUE_MASK,
				  GHCB_MSR_CPUID_VALUE_POS);

		set_ghcb_msr_bits(svm, GHCB_MSR_CPUID_RESP,
				  GHCB_MSR_INFO_MASK,
				  GHCB_MSR_INFO_POS);
		break;
	}
	case GHCB_MSR_TERM_REQ: {
		u64 reason_set, reason_code;

		reason_set = get_ghcb_msr_bits(svm,
					       GHCB_MSR_TERM_REASON_SET_MASK,
					       GHCB_MSR_TERM_REASON_SET_POS);
		reason_code = get_ghcb_msr_bits(svm,
						GHCB_MSR_TERM_REASON_MASK,
						GHCB_MSR_TERM_REASON_POS);
		pr_info("SEV-ES guest requested termination: %#llx:%#llx\n",
			reason_set, reason_code);
	}
		/* Fallthrough */
	default:
		ret = -EINVAL;
	}

	trace_kvm_vmgexit_msr_protocol_exit(svm->vcpu.vcpu_id,
					    control->ghcb_gpa, ret);

	return ret;
}

int sev_handle_vmgexit(struct vcpu_svm *svm)
{
	struct vmcb_control_area *control = &svm->vmcb->control;
	struct ghcb *ghcb;
	u64 ghcb_gpa;
	int ret;

	/* Validate the GHCB */
	ghcb_gpa = control->ghcb_gpa;
	if (ghcb_gpa & GHCB_MSR_INFO_MASK)
		return sev_handle_vmgexit_msr_protocol(svm);

	if (!ghcb_gpa) {
		pr_err("vmgexit: GHCB gpa is not set\n");
		return -EINVAL;
	}

	if (kvm_vcpu_map(&svm->vcpu, ghcb_gpa >> PAGE_SHIFT, &svm->ghcb_map)) {
		/* Unable to map GHCB from guest */
		pr_err("vmgexit: error mapping GHCB from guest\n");
		return -EINVAL;
	}

	svm->ghcb = svm->ghcb_map.hva;
	ghcb = svm->ghcb_map.hva;

	trace_kvm_vmgexit_enter(svm->vcpu.vcpu_id, ghcb);

	control->exit_code = lower_32_bits(ghcb_get_sw_exit_code(ghcb));
	control->exit_code_hi = upper_32_bits(ghcb_get_sw_exit_code(ghcb));
	control->exit_info_1 = ghcb_get_sw_exit_info_1(ghcb);
	control->exit_info_2 = ghcb_get_sw_exit_info_2(ghcb);

	ghcb_set_sw_exit_info_1(ghcb, 0);
	ghcb_set_sw_exit_info_2(ghcb, 0);

	ret = -EINVAL;
	switch (ghcb_get_sw_exit_code(ghcb)) {
	case SVM_VMGEXIT_MMIO_READ:
		if (!setup_vmgexit_scratch(svm, true, control->exit_info_2))
			break;

		ret = kvm_sev_es_mmio_read(&svm->vcpu,
					   control->exit_info_1,
					   control->exit_info_2,
					   svm->ghcb_sa);
		break;
	case SVM_VMGEXIT_MMIO_WRITE:
		if (!setup_vmgexit_scratch(svm, false, control->exit_info_2))
			break;

		ret = kvm_sev_es_mmio_write(&svm->vcpu,
					    control->exit_info_1,
					    control->exit_info_2,
					    svm->ghcb_sa);
		break;
	case SVM_VMGEXIT_NMI_COMPLETE:
		ret = svm_invoke_exit_handler(svm, SVM_EXIT_IRET);
		break;
	case SVM_VMGEXIT_AP_HLT_LOOP:
		svm->ap_hlt_loop = true;
		ret = kvm_emulate_halt(&svm->vcpu);
		break;
	case SVM_VMGEXIT_AP_JUMP_TABLE: {
		struct kvm_sev_info *sev = &to_kvm_svm(svm->vcpu.kvm)->sev_info;

		switch (control->exit_info_1) {
		case 0:
			/* Set AP jump table address */
			sev->ap_jump_table = control->exit_info_2;
			break;
		case 1:
			/* Get AP jump table address */
			ghcb_set_sw_exit_info_2(ghcb, sev->ap_jump_table);
			break;
		default:
			pr_err("svm: vmgexit: unsupported AP jump table request - exit_info_1=%#llx\n",
			       control->exit_info_1);
			ghcb_set_sw_exit_info_1(ghcb, 1);
			ghcb_set_sw_exit_info_2(ghcb,
						X86_TRAP_UD |
						SVM_EVTINJ_TYPE_EXEPT |
						SVM_EVTINJ_VALID);
		}

		ret = 1;
		break;
	}
	case SVM_VMGEXIT_UNSUPPORTED_EVENT:
		pr_err("vmgexit: unsupported event - exit_info_1=%#llx, exit_info_2=%#llx\n",
		       control->exit_info_1,
		       control->exit_info_2);
		break;
	default:
		ret = svm_invoke_exit_handler(svm, ghcb_get_sw_exit_code(ghcb));
	}

	return ret;
}

int sev_es_string_io(struct vcpu_svm *svm, int size, unsigned int port, int in)
{
	if (!setup_vmgexit_scratch(svm, in, svm->vmcb->control.exit_info_2))
		return -EINVAL;

	return kvm_sev_es_string_io(&svm->vcpu, size, port,
				    svm->ghcb_sa, svm->ghcb_sa_len, in);
}

void sev_vcpu_deliver_sipi_vector(struct kvm_vcpu *vcpu, u8 vector)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	/* First SIPI: Use the the values as initially set by the VMM */
	if (!svm->ap_hlt_loop)
		return;

	/*
	 * Subsequent SIPI: Return from an AP Reset Hold VMGEXIT, where
	 * the guest will set the CS and RIP. Set SW_EXIT_INFO_2 to a
	 * non-zero value.
	 */
	ghcb_set_sw_exit_info_2(svm->ghcb, 1);
	svm->ap_hlt_loop = false;
}

void sev_es_init_vmcb(struct vcpu_svm *svm)
{
	svm->vmcb->control.nested_ctl |= SVM_NESTED_CTL_SEV_ES_ENABLE;
	svm->vmcb->control.virt_ext |= LBR_CTL_ENABLE_MASK;

	/*
	 * An SEV-ES guest requires a VMSA area that is a separate from the
	 * VMCB page. Do not include the encryption mask on the VMSA physical
	 * address since hardware will access it using the guest key.
	 */
	svm->vmcb->control.vmsa_pa = __pa(svm->vmsa);

	/* Can't intercept CR register access, HV can't modify CR registers */
	clr_cr_intercept(svm, INTERCEPT_CR0_READ);
	clr_cr_intercept(svm, INTERCEPT_CR4_READ);
	clr_cr_intercept(svm, INTERCEPT_CR8_READ);
	clr_cr_intercept(svm, INTERCEPT_CR0_WRITE);
	clr_cr_intercept(svm, INTERCEPT_CR4_WRITE);
	clr_cr_intercept(svm, INTERCEPT_CR8_WRITE);

	clr_intercept(svm, INTERCEPT_SELECTIVE_CR0);

	/* Track CR register changes */
	set_intercept(svm, TRAP_CR0_WRITE);
	set_intercept(svm, TRAP_CR4_WRITE);
	set_intercept(svm, TRAP_CR8_WRITE);

	/* No support for enable_vmware_backdoor */
	clr_exception_intercept(svm, GP_VECTOR);

	/* Can't intercept XSETBV, HV can't modify XCR0 directly */
	clr_intercept(svm, INTERCEPT_XSETBV);

	/* Clear intercepts on selected MSRs */
	set_msr_interception(svm->msrpm, MSR_EFER, 1, 1);
	set_msr_interception(svm->msrpm, MSR_IA32_CR_PAT, 1, 1);
	set_msr_interception(svm->msrpm, MSR_IA32_LASTBRANCHFROMIP, 1, 1);
	set_msr_interception(svm->msrpm, MSR_IA32_LASTBRANCHTOIP, 1, 1);
	set_msr_interception(svm->msrpm, MSR_IA32_LASTINTFROMIP, 1, 1);
	set_msr_interception(svm->msrpm, MSR_IA32_LASTINTTOIP, 1, 1);
}

void sev_es_create_vcpu(struct vcpu_svm *svm)
{
	/*
	 * Set the GHCB MSR value as per the GHCB specification when creating
	 * a vCPU for an SEV-ES guest.
	 */
	set_ghcb_msr(svm, GHCB_MSR_SEV_INFO(GHCB_VERSION_MAX,
					    GHCB_VERSION_MIN,
					    sev_enc_bit));
}

void sev_es_vcpu_load(struct vcpu_svm *svm, int cpu)
{
	struct svm_cpu_data *sd = per_cpu(svm_data, cpu);
	struct vmcb_save_area *hostsa;
	unsigned int i;

	/*
	 * As an SEV-ES guest, hardware will restore the host state on VMEXIT,
	 * of which one step is to perform a VMLOAD. Since hardware does not
	 * perform a VMSAVE on VMRUN, the host savearea must be updated.
	 */
	asm volatile("vmsave"
		:
		: "a" (__sme_page_pa(sd->save_area))
		: "memory");

	/*
	 * Certain MSRs are restored on VMEXIT, only save ones that aren't
	 * saved via the vmsave above.
	 */
	for (i = 0; i < NR_HOST_SAVE_USER_MSRS; i++) {
		if (host_save_user_msrs[i].sev_es_restored)
			continue;

		rdmsrl(host_save_user_msrs[i].index, svm->host_user_msrs[i]);
	}

	/* XCR0 is restored on VMEXIT, save the current host value */
	hostsa = (struct vmcb_save_area *)(page_address(sd->save_area) + 0x400);
	hostsa->xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);
}

void sev_es_vcpu_put(struct vcpu_svm *svm)
{
	unsigned int i;

	/*
	 * Certain MSRs are restored on VMEXIT and were saved with vmsave in
	 * sev_es_vcpu_load() above. Only restore ones that weren't.
	 */
	for (i = 0; i < NR_HOST_SAVE_USER_MSRS; i++) {
		if (host_save_user_msrs[i].sev_es_restored)
			continue;

		wrmsrl(host_save_user_msrs[i].index, svm->host_user_msrs[i]);
	}
}
