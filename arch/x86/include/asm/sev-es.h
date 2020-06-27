/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AMD Encrypted Register State Support
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#ifndef __ASM_ENCRYPTED_STATE_H
#define __ASM_ENCRYPTED_STATE_H

#include <linux/types.h>

#include <asm/stacktrace.h>
#include <asm/insn.h>

#define GHCB_SEV_INFO		0x001UL
#define GHCB_SEV_INFO_REQ	0x002UL
#define		GHCB_INFO(v)		((v) & 0xfffUL)
#define		GHCB_PROTO_MAX(v)	(((v) >> 48) & 0xffffUL)
#define		GHCB_PROTO_MIN(v)	(((v) >> 32) & 0xffffUL)
#define		GHCB_PROTO_OUR		0x0001UL
#define GHCB_SEV_CPUID_REQ	0x004UL
#define		GHCB_CPUID_REQ_EAX	0
#define		GHCB_CPUID_REQ_EBX	1
#define		GHCB_CPUID_REQ_ECX	2
#define		GHCB_CPUID_REQ_EDX	3
#define		GHCB_CPUID_REQ(fn, reg) (GHCB_SEV_CPUID_REQ | \
					(((unsigned long)reg & 3) << 30) | \
					(((unsigned long)fn) << 32))

#define	GHCB_PROTOCOL_MAX	0x0001UL
#define GHCB_DEFAULT_USAGE	0x0000UL

#define GHCB_SEV_CPUID_RESP	0x005UL
#define GHCB_SEV_TERMINATE	0x100UL
#define		GHCB_SEV_TERMINATE_REASON(reason_set, reason_val)	\
			(((((u64)reason_set) &  0x7) << 12) |		\
			 ((((u64)reason_val) & 0xff) << 16))
#define		GHCB_SEV_ES_REASON_GENERAL_REQUEST	0
#define		GHCB_SEV_ES_REASON_PROTOCOL_UNSUPPORTED	1

#define	GHCB_SEV_GHCB_RESP_CODE(v)	((v) & 0xfff)
#define	VMGEXIT()			{ asm volatile("rep; vmmcall\n\r"); }

enum es_result {
	ES_OK,			/* All good */
	ES_UNSUPPORTED,		/* Requested operation not supported */
	ES_VMM_ERROR,		/* Unexpected state from the VMM */
	ES_DECODE_FAILED,	/* Instruction decoding failed */
	ES_EXCEPTION,		/* Instruction caused exception */
	ES_RETRY,		/* Retry instruction emulation */
};

struct es_fault_info {
	unsigned long vector;
	unsigned long error_code;
	unsigned long cr2;
};

struct vmgexit_mem_op_hdr {
	uint64_t count	: 32;
	uint64_t rsvd	: 32;
};

struct vmgexit_mem_op {
	uint64_t npages		: 12;
	uint64_t gfn		: 40;

#define MEM_OP_SNP_SHARED		0x1
#define MEM_OP_SNP_PRIVATE		0x2

	uint64_t cmd		: 3;
	uint64_t rsvd		: 8;
	uint64_t rmp_pagesize	: 1;
};

struct pt_regs;

/* ES instruction emulation context */
struct es_em_ctxt {
	struct pt_regs *regs;
	struct insn insn;
	struct es_fault_info fi;
};

void __init do_vc_no_ghcb(struct pt_regs *regs, unsigned long exit_code);

static inline u64 lower_bits(u64 val, unsigned int bits)
{
	u64 mask = (1ULL << bits) - 1;

	return (val & mask);
}

extern void vc_no_ghcb(void);
extern bool vc_boot_ghcb(struct pt_regs *regs);

struct real_mode_header;
enum stack_type;

#ifdef CONFIG_AMD_MEM_ENCRYPT
const char *vc_stack_name(enum stack_type type);
void sev_es_nmi_enter(void);
void sev_es_nmi_exit(void);
int sev_es_setup_ap_jump_table(struct real_mode_header *rmh);
void sev_es_nmi_complete(void);
int __init sev_es_efi_map_ghcbs(pgd_t *pgd);
#else /* CONFIG_AMD_MEM_ENCRYPT */
static inline const char *vc_stack_name(enum stack_type type)
{
	return NULL;
}
static inline int sev_es_setup_ap_jump_table(struct real_mode_header *rmh)
{
	return 0;
}
static inline void sev_es_nmi_complete(void) { }
static inline int sev_es_efi_map_ghcbs(pgd_t *pgd)
{
	return 0;
}
#endif /* CONFIG_AMD_MEM_ENCRYPT*/

#endif
