// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2019 SUSE
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#include <linux/sched/debug.h>	/* For show_regs() */
#include <linux/percpu-defs.h>
#include <linux/mem_encrypt.h>
#include <linux/printk.h>
#include <linux/set_memory.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/xarray.h>

#include <asm/trap_defs.h>
#include <asm/realmode.h>
#include <asm/sev-es.h>
#include <asm/fpu/internal.h>
#include <asm/processor.h>
#include <asm/traps.h>
#include <asm/svm.h>
#include <asm/smp.h>
#include <asm/cpu.h>

#define DR7_RESET_VALUE        0x400

struct sev_es_cpuid_cache_entry {
	unsigned long eax;
	unsigned long ebx;
	unsigned long ecx;
	unsigned long edx;
};

static struct xarray sev_es_cpuid_cache;
static bool __ro_after_init sev_es_cpuid_cache_initialized;

/* For early boot hypervisor communication in SEV-ES enabled guests */
struct ghcb boot_ghcb_page __bss_decrypted __aligned(PAGE_SIZE);

/*
 * Needs to be in the .data section because we need it NULL before bss is
 * cleared
 */
struct ghcb __initdata *boot_ghcb;
static DEFINE_PER_CPU(unsigned long, cached_dr7) = DR7_RESET_VALUE;
DEFINE_PER_CPU(bool, sev_es_in_nmi) = false;
/* Needed before per-cpu access is set up */
static unsigned long early_dr7 = DR7_RESET_VALUE;

struct ghcb_state {
	struct ghcb *ghcb;
};

/* Runtime GHCB pointers */
static struct ghcb __percpu *ghcb_page;

/*
 * Mark the per-cpu GHCB as in-use to detect nested #VC exceptions.
 * There is no need for it to be atomic, because nothing is written to the GHCB
 * between the read and the write of ghcb_active. So it is safe to use it when a
 * nested #VC exception happens before the write.
 */
static DEFINE_PER_CPU(bool, ghcb_active);

static struct ghcb* sev_es_get_ghcb(struct ghcb_state *state)
{
	struct ghcb *ghcb = (struct ghcb *)this_cpu_ptr(ghcb_page);
	bool *active = this_cpu_ptr(&ghcb_active);

	if (unlikely(*active)) {
		/* GHCB is already in use - save its contents */

		state->ghcb = kzalloc(sizeof(struct ghcb), GFP_ATOMIC);
		if (!state->ghcb)
			return NULL;

		*state->ghcb = *ghcb;
	} else {
		state->ghcb = NULL;
		*active = true;
	}

	return ghcb;
}

static void sev_es_put_ghcb(struct ghcb_state *state)
{
	bool *active = this_cpu_ptr(&ghcb_active);
	struct ghcb *ghcb = (struct ghcb *)this_cpu_ptr(ghcb_page);

	if (state->ghcb) {
		/* Restore saved state and free backup memory */
		*ghcb = *state->ghcb;
		kfree(state->ghcb);
		state->ghcb = NULL;
	} else {
		*active = false;
	}
}

/* Needed in vc_early_vc_forward_exception */
extern void early_exception(struct pt_regs *regs, int trapnr);

static inline u64 sev_es_rd_ghcb_msr(void);

static inline u64 sev_es_rd_ghcb_msr(void)
{
	return native_read_msr(MSR_AMD64_SEV_ES_GHCB);
}

static inline void sev_es_wr_ghcb_msr(u64 val)
{
	u32 low, high;

	low  = (u32)(val);
	high = (u32)(val >> 32);

	native_write_msr(MSR_AMD64_SEV_ES_GHCB, low, high);
}

static bool vc_check_kernel(struct pt_regs *regs)
{
	return regs->cs == __KERNEL_CS;
}

static enum es_result vc_fetch_insn_byte(struct es_em_ctxt *ctxt,
					 unsigned int offset,
					 char *buffer)
{
	if (user_mode(ctxt->regs)) {
		unsigned long addr = ctxt->regs->ip + offset;
		char __user *rip = (char __user *)addr;

		if (unlikely(addr >= TASK_SIZE_MAX))
			return ES_UNSUPPORTED;

		if (copy_from_user(buffer + offset, rip, 1)) {
			ctxt->fi.vector     = X86_TRAP_PF;
			ctxt->fi.cr2        = addr;
			ctxt->fi.error_code = X86_PF_INSTR | X86_PF_USER;
			return ES_EXCEPTION;
		}
	} else {
		char *rip = (char *)ctxt->regs->ip + offset;

		if (probe_kernel_read(buffer + offset, rip, 1) != 0) {
			ctxt->fi.vector     = X86_TRAP_PF;
			ctxt->fi.cr2        = (unsigned long)rip;
			ctxt->fi.error_code = X86_PF_INSTR;
			return ES_EXCEPTION;
		}
	}

	return ES_OK;
}

static enum es_result vc_write_mem(struct es_em_ctxt *ctxt,
				   void *dst, char *buf, size_t size)
{
	/* More checks are needed when we boot to user-space */
	if (!vc_check_kernel(ctxt->regs))
		return ES_UNSUPPORTED;

	memcpy(dst, buf, size);

	return ES_OK;
}

static enum es_result vc_read_mem(struct es_em_ctxt *ctxt,
				  void *src, char *buf, size_t size)
{
	/* More checks are needed when we boot to user-space */
	if (!vc_check_kernel(ctxt->regs))
		return ES_UNSUPPORTED;

	memcpy(buf, src, size);

	return ES_OK;
}

static phys_addr_t vc_slow_virt_to_phys(struct ghcb *ghcb, long vaddr)
{
	unsigned long va = (unsigned long)vaddr;
	unsigned int level;
	phys_addr_t pa;
	pgd_t *pgd;
	pte_t *pte;

	pgd = pgd_offset(current->active_mm, va);
	pte = lookup_address_in_pgd(pgd, va, &level);
	if (!pte)
		return 0;

	pa = (phys_addr_t)pte_pfn(*pte) << PAGE_SHIFT;
	pa |= va & ~page_level_mask(level);

	return pa;
}

/* Include code shared with pre-decompression boot stage */
#include "sev-es-shared.c"

void sev_es_nmi_enter(void)
{
	this_cpu_write(sev_es_in_nmi, true);
}

void sev_es_nmi_complete(void)
{
	struct ghcb_state state;
	struct ghcb *ghcb;

	ghcb = sev_es_get_ghcb(&state);

	vc_ghcb_invalidate(ghcb);
	ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_NMI_COMPLETE);
	ghcb_set_sw_exit_info_1(ghcb, 0);
	ghcb_set_sw_exit_info_2(ghcb, 0);

	sev_es_wr_ghcb_msr(__pa(ghcb));
	VMGEXIT();

	sev_es_put_ghcb(&state);

	this_cpu_write(sev_es_in_nmi, false);
}

static u64 sev_es_get_jump_table_addr(void)
{
	struct ghcb_state state;
	unsigned long flags;
	struct ghcb *ghcb;
	u64 ret;

	local_irq_save(flags);

	ghcb = sev_es_get_ghcb(&state);

	vc_ghcb_invalidate(ghcb);
	ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_AP_JUMP_TABLE);
	ghcb_set_sw_exit_info_1(ghcb, SVM_VMGEXIT_GET_AP_JUMP_TABLE);
	ghcb_set_sw_exit_info_2(ghcb, 0);

	sev_es_wr_ghcb_msr(__pa(ghcb));
	VMGEXIT();

	if (!ghcb_is_valid_sw_exit_info_1(ghcb) ||
	    !ghcb_is_valid_sw_exit_info_2(ghcb))
		ret = 0;

	ret = ghcb->save.sw_exit_info_2;

	sev_es_put_ghcb(&state);

	local_irq_restore(flags);

	return ret;
}

int sev_es_setup_ap_jump_table(struct real_mode_header *rmh)
{
	u16 startup_cs, startup_ip;
	phys_addr_t jump_table_pa;
	u64 jump_table_addr;
	u16 *jump_table;

	jump_table_addr = sev_es_get_jump_table_addr();

	/* Check if AP Jump Table is non-zero and page-aligned */
	if (!jump_table_addr || jump_table_addr & ~PAGE_MASK)
		return 0;

	jump_table_pa = jump_table_addr & PAGE_MASK;

	startup_cs = (u16)(rmh->trampoline_start >> 4);
	startup_ip = (u16)(rmh->sev_es_trampoline_start -
			   rmh->trampoline_start);

	jump_table = ioremap_encrypted(jump_table_pa, PAGE_SIZE);
	if (!jump_table)
		return -EIO;

	jump_table[0] = startup_ip;
	jump_table[1] = startup_cs;

	iounmap(jump_table);

	return 0;
}

static enum es_result vc_handle_msr(struct ghcb *ghcb, struct es_em_ctxt *ctxt)
{
	struct pt_regs *regs = ctxt->regs;
	enum es_result ret;
	bool write;
	u64 exit_info_1;

	write = (ctxt->insn.opcode.bytes[1] == 0x30);

	ghcb_set_rcx(ghcb, regs->cx);
	if (write) {
		ghcb_set_rax(ghcb, regs->ax);
		ghcb_set_rdx(ghcb, regs->dx);
		exit_info_1 = 1;
	} else {
		exit_info_1 = 0;
	}

	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_MSR, exit_info_1, 0);
	if (ret != ES_OK)
		return ret;
	else if (!write) {
		regs->ax = ghcb->save.rax;
		regs->dx = ghcb->save.rdx;
	}

	return ret;
}

/*
 * This function runs on the first #VC exception after the kernel
 * switched to virtual addresses.
 */
static bool __init sev_es_setup_ghcb(void)
{
	/* First make sure the hypervisor talks a supported protocol. */
	if (!sev_es_negotiate_protocol())
		return false;
	/*
	 * Clear the boot_ghcb. The first exception comes in before the bss
	 * section is cleared.
	 */
	memset(&boot_ghcb_page, 0, PAGE_SIZE);

	/* Alright - Make the boot-ghcb public */
	boot_ghcb = &boot_ghcb_page;

	return true;
}

#ifdef CONFIG_HOTPLUG_CPU
static void sev_es_ap_hlt_loop(void)
{
	struct ghcb_state state;
	struct ghcb *ghcb;

	ghcb = sev_es_get_ghcb(&state);

	while (true) {
		vc_ghcb_invalidate(ghcb);
		ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_AP_HLT_LOOP);
		ghcb_set_sw_exit_info_1(ghcb, 0);
		ghcb_set_sw_exit_info_2(ghcb, 0);

		sev_es_wr_ghcb_msr(__pa(ghcb));
		VMGEXIT();

		/* Wakup Signal? */
		if (ghcb_is_valid_sw_exit_info_2(ghcb) &&
		    ghcb->save.sw_exit_info_2 != 0)
			break;
	}

	sev_es_put_ghcb(&state);
}

void sev_es_play_dead(void)
{
	play_dead_common();

	/* IRQs now disabled */

	sev_es_ap_hlt_loop();

	/*
	 * If we get here, the VCPU was woken up again. Jump to CPU
	 * startup code to get it back online.
	 */

	start_cpu();
}
#else  /* CONFIG_HOTPLUG_CPU */
#define sev_es_play_dead	native_play_dead
#endif /* CONFIG_HOTPLUG_CPU */

#ifdef CONFIG_SMP
static void sev_es_setup_play_dead(void)
{
	smp_ops.play_dead = sev_es_play_dead;
}
#else
static inline void sev_es_setup_play_dead(void) { }
#endif

void sev_es_init_ghcbs(void)
{
	int cpu;

	if (!sev_es_active())
		return;

	/* Allocate GHCB pages */
	ghcb_page = __alloc_percpu(sizeof(struct ghcb), PAGE_SIZE);

	/* Initialize per-cpu GHCB pages */
	for_each_possible_cpu(cpu) {
		struct ghcb *ghcb = (struct ghcb *)per_cpu_ptr(ghcb_page, cpu);

		set_memory_decrypted((unsigned long)ghcb,
				     sizeof(*ghcb) >> PAGE_SHIFT);
		memset(ghcb, 0, sizeof(*ghcb));
	}

	sev_es_setup_play_dead();

	xa_init_flags(&sev_es_cpuid_cache, XA_FLAGS_LOCK_IRQ);
	sev_es_cpuid_cache_initialized = true;
}

static void __init vc_early_vc_forward_exception(struct es_em_ctxt *ctxt)
{
	int trapnr = ctxt->fi.vector;

	if (trapnr == X86_TRAP_PF)
		native_write_cr2(ctxt->fi.cr2);

	ctxt->regs->orig_ax = ctxt->fi.error_code;
	early_exception(ctxt->regs, trapnr);
}

static void sev_es_set_cpuid_cache_index(struct es_em_ctxt *ctxt)
{
	unsigned long hi, lo;

	ctxt->cpuid_cache_index = ULONG_MAX;

	/* Don't attempt to cache until the xarray is initialized */
	if (!sev_es_cpuid_cache_initialized)
		return;

	lo = ctxt->regs->ax & 0xffffffff;

	/*
	 * CPUID 0x0000000d requires both RCX and XCR0, so it can't be
	 * cached.
	 */
	if (lo == 0x0000000d)
		return;

	/*
	 * Some callers of CPUID don't always set RCX to zero for CPUID
	 * functions that don't require RCX, which can result in excessive
	 * cached values, so RCX needs to be manually zeroed for use as part
	 * of the cache index. Future CPUID values may need RCX, but since
	 * they can't be known, they must not be cached.
	 */
	if (lo > 0x80000020)
		return;

	switch (lo) {
	case 0x00000007:
	case 0x0000000b:
	case 0x0000000f:
	case 0x00000010:
	case 0x8000001d:
	case 0x80000020:
		hi = ctxt->regs->cx << 32;
		break;
	default:
		hi = 0;
	}

	ctxt->cpuid_cache_index = hi | lo;
}

static bool sev_es_check_cpuid_cache(struct es_em_ctxt *ctxt)
{
	struct sev_es_cpuid_cache_entry *cache_entry;

	if (ctxt->cpuid_cache_index == ULONG_MAX)
		return false;

	cache_entry = xa_load(&sev_es_cpuid_cache, ctxt->cpuid_cache_index);
	if (!cache_entry)
		return false;

	ctxt->regs->ax = cache_entry->eax;
	ctxt->regs->bx = cache_entry->ebx;
	ctxt->regs->cx = cache_entry->ecx;
	ctxt->regs->dx = cache_entry->edx;

	return true;
}

static void sev_es_add_cpuid_cache(struct es_em_ctxt *ctxt)
{
	struct sev_es_cpuid_cache_entry *cache_entry;
	int ret;

	if (ctxt->cpuid_cache_index == ULONG_MAX)
		return;

	cache_entry = kzalloc(sizeof(*cache_entry), GFP_ATOMIC);
	if (cache_entry) {
		cache_entry->eax = ctxt->regs->ax;
		cache_entry->ebx = ctxt->regs->bx;
		cache_entry->ecx = ctxt->regs->cx;
		cache_entry->edx = ctxt->regs->dx;

		/* Ignore insertion errors */
		ret = xa_insert(&sev_es_cpuid_cache, ctxt->cpuid_cache_index,
				cache_entry, GFP_ATOMIC);
	}
}

static enum es_result vc_handle_dr7_write(struct ghcb *ghcb,
					  struct es_em_ctxt *ctxt,
					  bool early)
{
	u8 rm = X86_MODRM_RM(ctxt->insn.modrm.value);
	unsigned long *reg;
	enum es_result ret;

	if (ctxt->insn.rex_prefix.nbytes &&
	    X86_REX_B(ctxt->insn.rex_prefix.value))
		rm |= 0x8;

	reg = vc_register_from_idx(ctxt->regs, rm);

	/* Using a value of 0 for ExitInfo1 means RAX holds the value */
	ghcb_set_rax(ghcb, *reg);
	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_WRITE_DR7, 0, 0);
	if (ret != ES_OK)
		return ret;

	if (early)
		early_dr7 = *reg;
	else
		this_cpu_write(cached_dr7, *reg);

	return ES_OK;
}

static enum es_result vc_handle_dr7_read(struct ghcb *ghcb,
					 struct es_em_ctxt *ctxt,
					 bool early)
{
	u8 rm = X86_MODRM_RM(ctxt->insn.modrm.value);
	unsigned long *reg;

	if (ctxt->insn.rex_prefix.nbytes &&
	    X86_REX_B(ctxt->insn.rex_prefix.value))
		rm |= 0x8;

	reg = vc_register_from_idx(ctxt->regs, rm);

	if (early)
		*reg = early_dr7;
	else
		*reg = this_cpu_read(cached_dr7);

	return ES_OK;
}

static enum es_result vc_handle_wbinvd(struct ghcb *ghcb,
				       struct es_em_ctxt *ctxt)
{
	return sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_WBINVD, 0, 0);
}

static enum es_result vc_handle_rdtsc(struct ghcb *ghcb,
				      struct es_em_ctxt *ctxt,
				      unsigned long exit_code)
{
	bool rdtscp = (exit_code == SVM_EXIT_RDTSCP);
	enum es_result ret;

	ret = sev_es_ghcb_hv_call(ghcb, ctxt, exit_code, 0, 0);
	if (ret != ES_OK)
		return ret;

	if (!(ghcb_is_valid_rax(ghcb) && ghcb_is_valid_rdx(ghcb) &&
	     (!rdtscp || ghcb_is_valid_rcx(ghcb))))
		return ES_VMM_ERROR;

	ctxt->regs->ax = ghcb->save.rax;
	ctxt->regs->dx = ghcb->save.rdx;
	if (rdtscp)
		ctxt->regs->cx = ghcb->save.rcx;

	return ES_OK;
}

static enum es_result vc_handle_rdpmc(struct ghcb *ghcb, struct es_em_ctxt *ctxt)
{
	enum es_result ret;

	ghcb_set_rcx(ghcb, ctxt->regs->cx);

	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_RDPMC, 0, 0);
	if (ret != ES_OK)
		return ret;

	if (!(ghcb_is_valid_rax(ghcb) && ghcb_is_valid_rdx(ghcb)))
		return ES_VMM_ERROR;

	ctxt->regs->ax = ghcb->save.rax;
	ctxt->regs->dx = ghcb->save.rdx;

	return ES_OK;
}

static enum es_result vc_handle_monitor(struct ghcb *ghcb,
					struct es_em_ctxt *ctxt)
{
	phys_addr_t monitor_pa;
	pgd_t *pgd;

	pgd = __va(read_cr3_pa());
	monitor_pa = vc_slow_virt_to_phys(ghcb, ctxt->regs->ax);

	ghcb_set_rax(ghcb, monitor_pa);
	ghcb_set_rcx(ghcb, ctxt->regs->cx);
	ghcb_set_rdx(ghcb, ctxt->regs->dx);

	return sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_MONITOR, 0, 0);
}

static enum es_result vc_handle_mwait(struct ghcb *ghcb,
				      struct es_em_ctxt *ctxt)
{
	ghcb_set_rax(ghcb, ctxt->regs->ax);
	ghcb_set_rcx(ghcb, ctxt->regs->cx);

	return sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_MWAIT, 0, 0);
}

static enum es_result vc_handle_vmmcall(struct ghcb *ghcb,
					struct es_em_ctxt *ctxt)
{
	enum es_result ret;

	ghcb_set_rax(ghcb, ctxt->regs->ax);
	ghcb_set_cpl(ghcb, user_mode(ctxt->regs) ? 3 : 0);

	if (x86_platform.hyper.sev_es_hcall_prepare)
		x86_platform.hyper.sev_es_hcall_prepare(ghcb, ctxt->regs);

	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_VMMCALL, 0, 0);
	if (ret != ES_OK)
		return ret;

	if (!ghcb_is_valid_rax(ghcb))
		return ES_VMM_ERROR;

	ctxt->regs->ax = ghcb->save.rax;

	/*
	 * Call sev_es_hcall_finish() after regs->ax is already set.
	 * This allows the hypervisor handler to overwrite it again if
	 * necessary.
	 */
	if (x86_platform.hyper.sev_es_hcall_finish &&
	    !x86_platform.hyper.sev_es_hcall_finish(ghcb, ctxt->regs))
		return ES_VMM_ERROR;

	return ES_OK;
}

static enum es_result vc_handle_db_exception(struct ghcb *ghcb,
					     struct es_em_ctxt *ctxt)
{
	if (this_cpu_read(sev_es_in_nmi))
		sev_es_nmi_complete();
	else
		do_debug(ctxt->regs, 0);

	/* Exception event, do not advance RIP */
	return ES_RETRY;
}

static enum es_result vc_handle_exitcode(struct es_em_ctxt *ctxt,
					 struct ghcb *ghcb,
					 unsigned long exit_code,
					 bool early)
{
	enum es_result result;

	switch (exit_code) {
	case SVM_EXIT_READ_DR7:
		result = vc_handle_dr7_read(ghcb, ctxt, early);
		break;
	case SVM_EXIT_WRITE_DR7:
		result = vc_handle_dr7_write(ghcb, ctxt, early);
		break;
	case SVM_EXIT_EXCP_BASE + X86_TRAP_DB:
		result = vc_handle_db_exception(ghcb, ctxt);
		break;
	case SVM_EXIT_EXCP_BASE + X86_TRAP_AC:
		do_alignment_check(ctxt->regs, 0);
		result = ES_RETRY;
		break;
	case SVM_EXIT_RDTSC:
	case SVM_EXIT_RDTSCP:
		result = vc_handle_rdtsc(ghcb, ctxt, exit_code);
		break;
	case SVM_EXIT_RDPMC:
		result = vc_handle_rdpmc(ghcb, ctxt);
		break;
	case SVM_EXIT_INVD:
		pr_err_ratelimited("#VC exception for INVD??? Seriously???\n");
		result = ES_UNSUPPORTED;
		break;
	case SVM_EXIT_CPUID:
		sev_es_set_cpuid_cache_index(ctxt);
		if (sev_es_check_cpuid_cache(ctxt)) {
			result = ES_OK;
		} else {
			result = vc_handle_cpuid(ghcb, ctxt);
			if (result == ES_OK)
				sev_es_add_cpuid_cache(ctxt);
		}
		break;
	case SVM_EXIT_IOIO:
		result = vc_handle_ioio(ghcb, ctxt);
		break;
	case SVM_EXIT_MSR:
		result = vc_handle_msr(ghcb, ctxt);
		break;
	case SVM_EXIT_VMMCALL:
		result = vc_handle_vmmcall(ghcb, ctxt);
		break;
	case SVM_EXIT_WBINVD:
		result = vc_handle_wbinvd(ghcb, ctxt);
		break;
	case SVM_EXIT_MONITOR:
		result = vc_handle_monitor(ghcb, ctxt);
		break;
	case SVM_EXIT_MWAIT:
		result = vc_handle_mwait(ghcb, ctxt);
		break;
	case SVM_EXIT_NPF:
		result = vc_handle_mmio(ghcb, ctxt);
		break;
	default:
		/*
		 * Unexpected #VC exception
		 */
		result = ES_UNSUPPORTED;
	}

	return result;
}

static enum es_result vc_context_filter(struct pt_regs *regs, long exit_code)
{
	enum es_result r = ES_OK;

	if (user_mode(regs)) {
		switch (exit_code) {
		/* List of #VC exit-codes we support in user-space */
		case SVM_EXIT_EXCP_BASE ... SVM_EXIT_LAST_EXCP:
		case SVM_EXIT_CPUID:
			r = ES_OK;
			break;
		default:
			r = ES_UNSUPPORTED;
			break;
		}
	}

	return r;
}

static void vc_forward_exception(struct es_em_ctxt *ctxt)
{
	long error_code = ctxt->fi.error_code;
	int trapnr = ctxt->fi.vector;

	ctxt->regs->orig_ax = ctxt->fi.error_code;

	switch (trapnr) {
	case X86_TRAP_GP:
		do_general_protection(ctxt->regs, error_code);
		break;
	case X86_TRAP_UD:
		do_invalid_op(ctxt->regs, 0);
		break;
	default:
		BUG();
	}
}

dotraplinkage void do_vmm_communication(struct pt_regs *regs, unsigned long exit_code)
{
	struct ghcb_state state;
	struct es_em_ctxt ctxt;
	enum es_result result;
	struct ghcb *ghcb;

	/*
	 * This is invoked through an interrupt gate, so IRQs are disabled. The
	 * code below might walk page-tables for user or kernel addresses, so
	 * keep the IRQs disabled to protect us against concurrent TLB flushes.
	 */

	ghcb = sev_es_get_ghcb(&state);
	if (!ghcb) {
		/* This can only fail on an allocation error, so just retry */
		result = ES_RETRY;
	} else {
		vc_ghcb_invalidate(ghcb);
		result = vc_init_em_ctxt(&ctxt, regs, exit_code);
	}

	/* Check if the exception is supported in the context we came from. */
	if (result == ES_OK)
		result = vc_context_filter(regs, exit_code);

	if (result == ES_OK)
		result = vc_handle_exitcode(&ctxt, ghcb, exit_code, false);

	sev_es_put_ghcb(&state);

	/* Done - now check the result */
	switch (result) {
	case ES_OK:
		vc_finish_insn(&ctxt);
		break;
	case ES_UNSUPPORTED:
		pr_err_ratelimited("Unsupported exit-code 0x%02lx in early #VC exception (IP: 0x%lx)\n",
				   exit_code, regs->ip);
		goto fail;
	case ES_VMM_ERROR:
		pr_err_ratelimited("Failure in communication with VMM (exit-code 0x%02lx IP: 0x%lx)\n",
				   exit_code, regs->ip);
		goto fail;
	case ES_DECODE_FAILED:
		pr_err_ratelimited("PANIC: Failed to decode instruction (exit-code 0x%02lx IP: 0x%lx)\n",
				   exit_code, regs->ip);
		goto fail;
	case ES_EXCEPTION:
		vc_forward_exception(&ctxt);
		break;
	case ES_RETRY:
		/* Nothing to do */
		break;
	default:
		BUG();
	}

	return;

fail:
	if (user_mode(regs)) {
		/*
		 * Do not kill the machine if user-space triggered the
		 * exception. Send SIGBUS instead and let user-space deal with
		 * it.
		 */
		force_sig_fault(SIGBUS, BUS_OBJERR, (void __user *)0);
	} else {
		/* Show some debug info */
		show_regs(regs);

		/* Ask hypervisor to sev_es_terminate */
		sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);

		/* If that fails and we get here - just halt the machine */
		while (true)
			halt();
	}
}

bool __init boot_vc_exception(struct pt_regs *regs)
{
	unsigned long exit_code = regs->orig_ax;
	struct es_em_ctxt ctxt;
	enum es_result result;

	/* Do initial setup or terminate the guest */
	if (unlikely(boot_ghcb == NULL && !sev_es_setup_ghcb()))
		sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);

	vc_ghcb_invalidate(boot_ghcb);
	result = vc_init_em_ctxt(&ctxt, regs, exit_code);

	if (result == ES_OK)
		result = vc_handle_exitcode(&ctxt, boot_ghcb, exit_code, true);

	/* Done - now check the result */
	switch (result) {
	case ES_OK:
		vc_finish_insn(&ctxt);
		break;
	case ES_UNSUPPORTED:
		early_printk("PANIC: Unsupported exit-code 0x%02lx in early #VC exception (IP: 0x%lx)\n",
				exit_code, regs->ip);
		goto fail;
	case ES_VMM_ERROR:
		early_printk("PANIC: Failure in communication with VMM (exit-code 0x%02lx IP: 0x%lx)\n",
				exit_code, regs->ip);
		goto fail;
	case ES_DECODE_FAILED:
		early_printk("PANIC: Failed to decode instruction (exit-code 0x%02lx IP: 0x%lx)\n",
				exit_code, regs->ip);
		goto fail;
	case ES_EXCEPTION:
		vc_early_vc_forward_exception(&ctxt);
		break;
	case ES_RETRY:
		/* Nothing to do */
		break;
	default:
		BUG();
	}

	return true;

fail:
	show_regs(regs);

	while (true)
		halt();
}
