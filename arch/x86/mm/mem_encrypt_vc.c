// SPDX-License-Identifier: GPL-2.0
/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2019 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */

#define DISABLE_BRANCH_PROFILING

#include <stdarg.h>

#include <linux/mem_encrypt.h>
#include <linux/percpu-defs.h>
#include <linux/printk.h>
#include <linux/context_tracking.h>

#include <asm/mem_encrypt_vc.h>
#include <asm/set_memory.h>
#include <asm/svm.h>
#include <asm/msr-index.h>
#include <asm/traps.h>
#include <asm/insn.h>

typedef u64 (*vmg_nae_exit_t)(struct ghcb *ghcb, unsigned long ghcb_pa,
			      struct pt_regs *regs, struct insn *insn);

static DEFINE_PER_CPU_DECRYPTED(struct ghcb, ghcb_page) __aligned(PAGE_SIZE);

static struct ghcb *early_ghcb_va;

static u64 vmg_unsupported_event(void)
{
	u64 event;

	event = X86_TRAP_GP | SVM_EVTINJ_TYPE_EXEPT | SVM_EVTINJ_VALID;

	return event;
}

static u64 vmg_exception(u64 excp)
{
	if ((excp & SVM_EVTINJ_TYPE_MASK) != SVM_EVTINJ_TYPE_EXEPT)
		return vmg_unsupported_event();

	if (!(excp & SVM_EVTINJ_VALID))
		return vmg_unsupported_event();

	switch (excp & SVM_EVTINJ_VEC_MASK) {
	case X86_TRAP_GP:
	case X86_TRAP_UD:
		return excp;
	default:
		return vmg_unsupported_event();
	}
}

static u64 vmg_error_check(struct ghcb *ghcb)
{
	unsigned int action;

	action = lower_32_bits(ghcb->save.sw_exit_info_1);
	switch (action) {
	case 0:
		return 0;
	case 1:
		return vmg_exception(ghcb->save.sw_exit_info_2);
	default:
		return vmg_unsupported_event();
	}
}

static u64 vmg_exit(struct ghcb *ghcb, u64 exit_code,
		    u64 exit_info_1, u64 exit_info_2)
{
	ghcb->save.sw_exit_code = exit_code;
	ghcb->save.sw_exit_info_1 = exit_info_1;
	ghcb->save.sw_exit_info_2 = exit_info_2;

	/* VMGEXIT instruction */
	asm volatile ("rep; vmmcall" ::: "memory");

	return vmg_error_check(ghcb);
}

static unsigned long vc_start(struct ghcb *ghcb)
{
	unsigned long flags;

	local_irq_save(flags);
	preempt_disable();

	memset(&ghcb->save, 0, sizeof(ghcb->save));

	ghcb->protocol_version = GHCB_VERSION_MAX;
	ghcb->ghcb_usage = GHCB_USAGE_STANDARD;

	return flags;
}

static void vc_finish(struct ghcb *ghcb, unsigned long flags)
{
	local_irq_restore(flags);
	preempt_enable();
}

static long *vmg_reg_idx_to_pt_reg(struct pt_regs *regs, u8 reg)
{
	switch (reg) {
	case 0:		return &regs->ax;
	case 1:		return &regs->cx;
	case 2:		return &regs->dx;
	case 3:		return &regs->bx;
	case 4:		return &regs->sp;
	case 5:		return &regs->bp;
	case 6:		return &regs->si;
	case 7:		return &regs->di;
	case 8:		return &regs->r8;
	case 9:		return &regs->r9;
	case 10:	return &regs->r10;
	case 11:	return &regs->r11;
	case 12:	return &regs->r12;
	case 13:	return &regs->r13;
	case 14:	return &regs->r14;
	case 15:	return &regs->r15;
	}

	/* reg is a u8, so can never get here, but just in case */
	WARN_ONCE(1, "register index is not valid: %#hhx\n", reg);

	return NULL;
}

static phys_addr_t vmg_slow_virt_to_phys(struct ghcb *ghcb, long vaddr)
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

static long vmg_insn_rmdata(struct insn *insn, struct pt_regs *regs)
{
	long effective_addr;
	u8 mod, rm;

	if (!insn->modrm.nbytes)
		return 0;

	if (insn_rip_relative(insn))
		return regs->ip + insn->displacement.value;

	mod = X86_MODRM_MOD(insn->modrm.value);
	rm = X86_MODRM_RM(insn->modrm.value);

	if (insn->rex_prefix.nbytes && X86_REX_B(insn->rex_prefix.value))
		rm |= 0x8;

	if (mod == 3)
		return *vmg_reg_idx_to_pt_reg(regs, rm);

	switch (mod) {
	case 1:
	case 2:
		effective_addr = insn->displacement.value;
		break;
	default:
		effective_addr = 0;
	}

	if (insn->sib.nbytes) {
		u8 scale, index, base;

		scale = X86_SIB_SCALE(insn->sib.value);
		index = X86_SIB_INDEX(insn->sib.value);
		base = X86_SIB_BASE(insn->sib.value);
		if (insn->rex_prefix.nbytes &&
		    X86_REX_X(insn->rex_prefix.value))
			index |= 0x8;
		if (insn->rex_prefix.nbytes &&
		    X86_REX_B(insn->rex_prefix.value))
			base |= 0x8;

		if (index != 4)
			effective_addr += (*vmg_reg_idx_to_pt_reg(regs, index) << scale);

		if ((base != 5) || mod)
			effective_addr += *vmg_reg_idx_to_pt_reg(regs, base);
		else
			effective_addr += insn->displacement.value;
	} else {
		effective_addr += *vmg_reg_idx_to_pt_reg(regs, rm);
	}

	return effective_addr;
}

static long *vmg_insn_regdata(struct insn *insn, struct pt_regs *regs)
{
	u8 reg;

	if (!insn->modrm.nbytes)
		return 0;

	reg = X86_MODRM_REG(insn->modrm.value);
	if (insn->rex_prefix.nbytes && X86_REX_R(insn->rex_prefix.value))
		reg |= 0x8;

	return vmg_reg_idx_to_pt_reg(regs, reg);
}

static void vmg_insn_init(struct insn *insn, char *insn_buffer,
			  unsigned long ip)
{
	int insn_len, bytes_rem;

	if (ip > TASK_SIZE) {
		insn_buffer = (void *)ip;
		insn_len = MAX_INSN_SIZE;
	} else {
		bytes_rem = copy_from_user(insn_buffer, (const void __user *)ip,
					   MAX_INSN_SIZE);
		insn_len = MAX_INSN_SIZE - bytes_rem;
	}

	insn_init(insn, insn_buffer, insn_len, true);

	/* Parse the full instruction */
	insn_get_length(insn);

	/*
	 * TODO: Error checking
	 *   If insn->immediate.got is not set after insn_get_length() then
	 *   the parsing failed at some point.
	 */
}

static u64 vmg_issue_unsupported(struct ghcb *ghcb, u64 error1, u64 error2)
{
	u64 ret;

	ret = vmg_exit(ghcb, SVM_VMGEXIT_UNSUPPORTED_EVENT, error1, error2);

	/*
	 * An unsupported event was issued so be sure to raise a further
	 * exception if not instructed by the hypervisor.
	 */
	if (!ret)
		ret = vmg_unsupported_event();

	return ret;
}

static u64 vmg_mmio_exec(struct ghcb *ghcb, unsigned long ghcb_pa,
			 struct pt_regs *regs, struct insn *insn,
			 unsigned int bytes, bool read)
{
	u64 exit_code, exit_info_1, exit_info_2;

	/* Register-direct addressing mode not supported with MMIO */
	if (X86_MODRM_MOD(insn->modrm.value) == 3)
		return vmg_issue_unsupported(ghcb, SVM_EXIT_NPF, 0);

	exit_code = read ? SVM_VMGEXIT_MMIO_READ : SVM_VMGEXIT_MMIO_WRITE;

	exit_info_1 = vmg_insn_rmdata(insn, regs);
	exit_info_1 = vmg_slow_virt_to_phys(ghcb, exit_info_1);
	exit_info_2 = bytes;	// Can never be greater than 8

	ghcb->save.sw_scratch = ghcb_pa + offsetof(struct ghcb, shared_buffer);

	return vmg_exit(ghcb, exit_code, exit_info_1, exit_info_2);
}

static u64 vmg_mmio(struct ghcb *ghcb, unsigned long ghcb_pa,
		    struct pt_regs *regs, struct insn *insn)
{
	unsigned int bytes = 0;
	long *reg_data;
	int sign_byte;
	u8 opcode;
	u64 ret;

	if (insn->opcode.bytes[0] != 0x0f)
		opcode = insn->opcode.bytes[0];
	else
		opcode = insn->opcode.bytes[1];

	switch (opcode) {
	/* MMIO Write */
	case 0x88:
		bytes = 1;
		/* Fallthrough */
	case 0x89:
		if (!bytes)
			bytes = insn->opnd_bytes;

		reg_data = vmg_insn_regdata(insn, regs);
		memcpy(ghcb->shared_buffer, reg_data, bytes);

		ret = vmg_mmio_exec(ghcb, ghcb_pa, regs, insn, bytes, false);
		break;

	case 0xc6:
		bytes = 1;
		/* Fallthrough */
	case 0xc7:
		if (!bytes)
			bytes = insn->opnd_bytes;

		memcpy(ghcb->shared_buffer, insn->immediate1.bytes, bytes);

		ret = vmg_mmio_exec(ghcb, ghcb_pa, regs, insn, bytes, false);
		break;

	/* MMIO Read */
	case 0x8a:
		bytes = 1;
		/* Fallthrough */
	case 0x8b:
		if (!bytes)
			bytes = insn->opnd_bytes;

		ret = vmg_mmio_exec(ghcb, ghcb_pa, regs, insn, bytes, true);
		if (ret)
			break;

		reg_data = vmg_insn_regdata(insn, regs);
		if (bytes == 4)
			*reg_data = 0;	/* Zero-extend for 32-bit operation */

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;

	/* MMIO Read w/ zero-extension */
	case 0xb6:
		bytes = 1;
		/* Fallthrough */
	case 0xb7:
		if (!bytes)
			bytes = 2;

		ret = vmg_mmio_exec(ghcb, ghcb_pa, regs, insn, bytes, true);
		if (ret)
			break;

		/* Zero extend based on operand size */
		reg_data = vmg_insn_regdata(insn, regs);
		memset(reg_data, 0, insn->opnd_bytes);

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;

	/* MMIO Read w/ sign-extension */
	case 0xbe:
		bytes = 1;
		/* Fallthrough */
	case 0xbf:
		if (!bytes)
			bytes = 2;

		ret = vmg_mmio_exec(ghcb, ghcb_pa, regs, insn, bytes, true);
		if (ret)
			break;

		/* Sign extend based on operand size */
		reg_data = vmg_insn_regdata(insn, regs);
		if (bytes == 1) {
			u8 *val = (u8 *)ghcb->shared_buffer;

			sign_byte = (*val & 0x80) ? 0x00 : 0xff;
		} else {
			u16 *val = (u16 *)ghcb->shared_buffer;

			sign_byte = (*val & 0x8000) ? 0x00 : 0xff;
		}
		memset(reg_data, sign_byte, insn->opnd_bytes);

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;

	default:
		ret = vmg_issue_unsupported(ghcb, SVM_EXIT_NPF, 0);
	}

	return ret;
}

static u64 sev_es_vc_exception(struct pt_regs *regs, long error_code)
{
	char insn_buffer[MAX_INSN_SIZE];
	vmg_nae_exit_t nae_exit = NULL;
	enum ctx_state prev_state;
	unsigned long ghcb_pa;
	unsigned long flags;
	struct ghcb *ghcb;
	struct insn insn;
	u64 ret;

	prev_state = exception_enter();

	ghcb_pa = native_read_msr(MSR_AMD64_SEV_GHCB);
	if (!ghcb_pa ||
	    ((ghcb_pa & GHCB_MSR_INFO_MASK) == GHCB_MSR_SEV_INFO_RESP)) {
		/* GHCB not yet established, so set it up */
		ghcb_pa = __pa(this_cpu_ptr(&ghcb_page));
		native_wrmsrl(MSR_AMD64_SEV_GHCB, ghcb_pa);
	}

	/* Get the proper GHCB virtual address to use */
	if (ghcb_pa == __pa(early_ghcb)) {
		ghcb = early_ghcb_va;
	} else {
		WARN_ONCE(ghcb_pa != __pa(this_cpu_ptr(&ghcb_page)),
			  "GHCB MSR value was not what was expected\n");

		ghcb = this_cpu_ptr(&ghcb_page);
	}

	flags = vc_start(ghcb);

	switch (error_code) {
	case SVM_EXIT_NPF:
		nae_exit = vmg_mmio;
		break;
	default:
		ret = vmg_issue_unsupported(ghcb, error_code, 0);
	}

	if (nae_exit) {
		vmg_insn_init(&insn, insn_buffer, regs->ip);
		ret = nae_exit(ghcb, ghcb_pa, regs, &insn);
		if (!ret)
			regs->ip += insn.length;
	}

	vc_finish(ghcb, flags);

	exception_exit(prev_state);

	return ret;
}

dotraplinkage void do_vmm_communication(struct pt_regs *regs, long error_code)
{
	u64 ret;

	ret = sev_es_vc_exception(regs, error_code);
	if (!ret)
		return;

	error_code = (ret & SVM_EVTINJ_VALID_ERR) ? upper_32_bits(ret) : 0;

	switch (ret & SVM_EVTINJ_VEC_MASK) {
	case X86_TRAP_GP:
		do_general_protection(regs, error_code);
		break;
	case X86_TRAP_UD:
		do_invalid_op(regs, error_code);
		break;
	}
}

void __init early_ghcb_init(void)
{
	unsigned long early_ghcb_pa;

	if (!sev_es_active())
		return;

	early_ghcb_pa = __pa(early_ghcb);
	early_ghcb_va = early_memremap_decrypted(early_ghcb_pa, PAGE_SIZE);
	BUG_ON(!early_ghcb_va);

	memset(early_ghcb_va, 0, PAGE_SIZE);

	native_wrmsrl(MSR_AMD64_SEV_GHCB, early_ghcb_pa);
}

void __init ghcb_init(void)
{
	int cpu;

	if (!sev_es_active())
		return;

	for_each_possible_cpu(cpu) {
		struct ghcb *ghcb = &per_cpu(ghcb_page, cpu);

		set_memory_decrypted((unsigned long)ghcb,
				     sizeof(ghcb_page) >> PAGE_SHIFT);
		memset(ghcb, 0, sizeof(*ghcb));
	}

	/*
	 * Switch the BSP over from the early GHCB page to the per-CPU GHCB
	 * page and un-map the early mapping.
	 */
	native_wrmsrl(MSR_AMD64_SEV_GHCB, __pa(this_cpu_ptr(&ghcb_page)));

	early_memunmap(early_ghcb_va, PAGE_SIZE);
}
