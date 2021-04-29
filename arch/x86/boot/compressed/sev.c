// SPDX-License-Identifier: GPL-2.0
/*
 * AMD Encrypted Register State Support
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

/*
 * misc.h needs to be first because it knows how to include the other kernel
 * headers in the pre-decompression code in a way that does not break
 * compilation.
 */
#include "misc.h"

#include <asm/pgtable_types.h>
#include <asm/sev.h>
#include <asm/trapnr.h>
#include <asm/trap_pf.h>
#include <asm/msr-index.h>
#include <asm/fpu/xcr.h>
#include <asm/ptrace.h>
#include <asm/svm.h>

#include "error.h"
#include "sev.h"

struct ghcb boot_ghcb_page __aligned(PAGE_SIZE);
struct ghcb *boot_ghcb;
static u64 sev_status_val;
static bool sev_status_checked;

/*
 * Copy a version of this function here - insn-eval.c can't be used in
 * pre-decompression code.
 */
static bool insn_has_rep_prefix(struct insn *insn)
{
	insn_byte_t p;
	int i;

	insn_get_prefixes(insn);

	for_each_insn_prefix(insn, i, p) {
		if (p == 0xf2 || p == 0xf3)
			return true;
	}

	return false;
}

/*
 * Only a dummy for insn_get_seg_base() - Early boot-code is 64bit only and
 * doesn't use segments.
 */
static unsigned long insn_get_seg_base(struct pt_regs *regs, int seg_reg_idx)
{
	return 0UL;
}

static inline u64 sev_es_rd_ghcb_msr(void)
{
	unsigned long low, high;

	asm volatile("rdmsr" : "=a" (low), "=d" (high) :
			"c" (MSR_AMD64_SEV_ES_GHCB));

	return ((high << 32) | low);
}

static inline void sev_es_wr_ghcb_msr(u64 val)
{
	u32 low, high;

	low  = val & 0xffffffffUL;
	high = val >> 32;

	asm volatile("wrmsr" : : "c" (MSR_AMD64_SEV_ES_GHCB),
			"a"(low), "d" (high) : "memory");
}

static enum es_result vc_decode_insn(struct es_em_ctxt *ctxt)
{
	char buffer[MAX_INSN_SIZE];
	enum es_result ret;

	memcpy(buffer, (unsigned char *)ctxt->regs->ip, MAX_INSN_SIZE);

	insn_init(&ctxt->insn, buffer, MAX_INSN_SIZE, 1);
	insn_get_length(&ctxt->insn);

	ret = ctxt->insn.immediate.got ? ES_OK : ES_DECODE_FAILED;

	return ret;
}

static enum es_result vc_write_mem(struct es_em_ctxt *ctxt,
				   void *dst, char *buf, size_t size)
{
	memcpy(dst, buf, size);

	return ES_OK;
}

static enum es_result vc_read_mem(struct es_em_ctxt *ctxt,
				  void *src, char *buf, size_t size)
{
	memcpy(buf, src, size);

	return ES_OK;
}

#undef __init
#undef __pa
#define __init
#define __pa(x)	((unsigned long)(x))

#define __BOOT_COMPRESSED

/* Basic instruction decoding support needed */
#include "../../lib/inat.c"
#include "../../lib/insn.c"

/* Include code for early handlers */
#include "../../kernel/sev-shared.c"

static inline bool sev_snp_enabled(void)
{
	unsigned long low, high;

	if (!sev_status_checked) {
		asm volatile("rdmsr\n"
			     : "=a" (low), "=d" (high)
			     : "c" (MSR_AMD64_SEV));
		sev_status_val = (high << 32) | low;
		sev_status_checked = true;
	}

	return sev_status_val & MSR_AMD64_SEV_SNP_ENABLED ? true : false;
}

static void snp_page_state_change(unsigned long paddr, int op)
{
	u64 val;

	if (!sev_snp_enabled())
		return;

	/*
	 * If the page is getting changed from private to shard then invalidate the page
	 * before requesting the state change in the RMP table.
	 */
	if ((op == SNP_PAGE_STATE_SHARED) && pvalidate(paddr, RMP_PG_SIZE_4K, 0))
		goto e_pvalidate;

	/* Issue VMGEXIT to change the page state in RMP table. */
	sev_es_wr_ghcb_msr(GHCB_MSR_PSC_REQ_GFN(paddr >> PAGE_SHIFT, op));
	VMGEXIT();

	/* Read the response of the VMGEXIT. */
	val = sev_es_rd_ghcb_msr();
	if ((GHCB_RESP_CODE(val) != GHCB_MSR_PSC_RESP) || GHCB_MSR_PSC_RESP_VAL(val))
		goto e_psc;

	/*
	 * Now that page is added in the RMP table, validate it so that it is consistent
	 * with the RMP entry.
	 */
	if ((op == SNP_PAGE_STATE_PRIVATE) && pvalidate(paddr, RMP_PG_SIZE_4K, 1))
		goto e_pvalidate;

	return;

e_psc:
	sev_es_terminate(1, GHCB_TERM_PSC);

e_pvalidate:
	sev_es_terminate(1, GHCB_TERM_PVALIDATE);
}

void snp_set_page_private(unsigned long paddr)
{
	snp_page_state_change(paddr, SNP_PAGE_STATE_PRIVATE);
}

void snp_set_page_shared(unsigned long paddr)
{
	snp_page_state_change(paddr, SNP_PAGE_STATE_SHARED);
}

static bool early_setup_sev_es(void)
{
	if (!sev_es_negotiate_protocol())
		sev_es_terminate(0, GHCB_SEV_ES_REASON_PROTOCOL_UNSUPPORTED);

	/* If SEV-SNP is enabled then check if the hypervisor supports the SEV-SNP features. */
	if (sev_snp_enabled() && !sev_snp_check_hypervisor_features())
		sev_es_terminate(0, GHCB_SEV_ES_REASON_SNP_UNSUPPORTED);

	if (set_page_decrypted((unsigned long)&boot_ghcb_page))
		return false;

	/* Page is now mapped decrypted, clear it */
	memset(&boot_ghcb_page, 0, sizeof(boot_ghcb_page));

	boot_ghcb = &boot_ghcb_page;

	/* Initialize lookup tables for the instruction decoder */
	inat_init_tables();

	return true;
}

void sev_es_shutdown_ghcb(void)
{
	if (!boot_ghcb)
		return;

	if (!sev_es_check_cpu_features())
		error("SEV-ES CPU Features missing.");

	/*
	 * GHCB Page must be flushed from the cache and mapped encrypted again.
	 * Otherwise the running kernel will see strange cache effects when
	 * trying to use that page.
	 */
	if (set_page_encrypted((unsigned long)&boot_ghcb_page))
		error("Can't map GHCB page encrypted");

	/*
	 * GHCB page is mapped encrypted again and flushed from the cache.
	 * Mark it non-present now to catch bugs when #VC exceptions trigger
	 * after this point.
	 */
	if (set_page_non_present((unsigned long)&boot_ghcb_page))
		error("Can't unmap GHCB page");
}

bool sev_es_check_ghcb_fault(unsigned long address)
{
	/* Check whether the fault was on the GHCB page */
	return ((address & PAGE_MASK) == (unsigned long)&boot_ghcb_page);
}

void do_boot_stage2_vc(struct pt_regs *regs, unsigned long exit_code)
{
	struct es_em_ctxt ctxt;
	enum es_result result;

	if (!boot_ghcb && !early_setup_sev_es())
		sev_es_terminate(0, GHCB_SEV_ES_REASON_GENERAL_REQUEST);

	vc_ghcb_invalidate(boot_ghcb);
	result = vc_init_em_ctxt(&ctxt, regs, exit_code);
	if (result != ES_OK)
		goto finish;

	switch (exit_code) {
	case SVM_EXIT_RDTSC:
	case SVM_EXIT_RDTSCP:
		result = vc_handle_rdtsc(boot_ghcb, &ctxt, exit_code);
		break;
	case SVM_EXIT_IOIO:
		result = vc_handle_ioio(boot_ghcb, &ctxt);
		break;
	case SVM_EXIT_CPUID:
		result = vc_handle_cpuid(boot_ghcb, &ctxt);
		break;
	default:
		result = ES_UNSUPPORTED;
		break;
	}

finish:
	if (result == ES_OK)
		vc_finish_insn(&ctxt);
	else if (result != ES_RETRY)
		sev_es_terminate(0, GHCB_SEV_ES_REASON_GENERAL_REQUEST);
}
