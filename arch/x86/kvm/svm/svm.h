// SPDX-License-Identifier: GPL-2.0-only
/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * AMD SVM support
 *
 * Copyright (C) 2006 Qumranet, Inc.
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 *
 * Authors:
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *   Avi Kivity   <avi@qumranet.com>
 */

#ifndef __SVM_SVM_H
#define __SVM_SVM_H

#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include <linux/bits.h>

#include <asm/svm.h>

#define __sme_page_pa(x) __sme_set(page_to_pfn(x) << PAGE_SHIFT)

static const struct svm_host_save_msrs {
	u32 index;		/* Index of the MSR */
	bool sev_es_restored;	/* True if MSR is restored on SEV-ES VMEXIT */
} host_save_user_msrs[] = {
#ifdef CONFIG_X86_64
	{ .index = MSR_STAR,			.sev_es_restored = true },
	{ .index = MSR_LSTAR,			.sev_es_restored = true },
	{ .index = MSR_CSTAR,			.sev_es_restored = true },
	{ .index = MSR_SYSCALL_MASK,		.sev_es_restored = true },
	{ .index = MSR_KERNEL_GS_BASE,		.sev_es_restored = true },
	{ .index = MSR_FS_BASE,			.sev_es_restored = true },
#endif
	{ .index = MSR_IA32_SYSENTER_CS,	.sev_es_restored = true },
	{ .index = MSR_IA32_SYSENTER_ESP,	.sev_es_restored = true },
	{ .index = MSR_IA32_SYSENTER_EIP,	.sev_es_restored = true },
	{ .index = MSR_TSC_AUX,			.sev_es_restored = false },
};
#define NR_HOST_SAVE_USER_MSRS ARRAY_SIZE(host_save_user_msrs)

#define MSRPM_OFFSETS	16
extern u32 msrpm_offsets[MSRPM_OFFSETS] __read_mostly;
extern bool npt_enabled;

enum {
	VMCB_INTERCEPTS, /* Intercept vectors, TSC offset,
			    pause filter count */
	VMCB_PERM_MAP,   /* IOPM Base and MSRPM Base */
	VMCB_ASID,	 /* ASID */
	VMCB_INTR,	 /* int_ctl, int_vector */
	VMCB_NPT,        /* npt_en, nCR3, gPAT */
	VMCB_CR,	 /* CR0, CR3, CR4, EFER */
	VMCB_DR,         /* DR6, DR7 */
	VMCB_DT,         /* GDT, IDT */
	VMCB_SEG,        /* CS, DS, SS, ES, CPL */
	VMCB_CR2,        /* CR2 only */
	VMCB_LBR,        /* DBGCTL, BR_FROM, BR_TO, LAST_EX_FROM, LAST_EX_TO */
	VMCB_AVIC,       /* AVIC APIC_BAR, AVIC APIC_BACKING_PAGE,
			  * AVIC PHYSICAL_TABLE pointer,
			  * AVIC LOGICAL_TABLE pointer
			  */
	VMCB_DIRTY_MAX,
};

/* TPR and CR2 are always written before VMRUN */
#define VMCB_ALWAYS_DIRTY_MASK	((1U << VMCB_INTR) | (1U << VMCB_CR2))

struct kvm_sev_info {
	bool active;		/* SEV enabled guest */
	bool es_active;		/* SEV-ES enabled guest */
	unsigned int asid;	/* ASID used for this guest */
	unsigned int handle;	/* SEV firmware handle */
	int fd;			/* SEV device fd */
	unsigned long pages_locked; /* Number of pages locked */
	struct list_head regions_list;  /* List of registered regions */
	u64 ap_jump_table;	/* SEV-ES AP Jump Table address */
};

struct kvm_svm {
	struct kvm kvm;

	/* Struct members for AVIC */
	u32 avic_vm_id;
	struct page *avic_logical_id_table_page;
	struct page *avic_physical_id_table_page;
	struct hlist_node hnode;

	struct kvm_sev_info sev_info;
};

struct kvm_vcpu;

struct nested_state {
	struct vmcb *hsave;
	u64 hsave_msr;
	u64 vm_cr_msr;
	u64 vmcb;

	/* These are the merged vectors */
	u32 *msrpm;

	/* gpa pointers to the real vectors */
	u64 vmcb_msrpm;
	u64 vmcb_iopm;

	/* A VMEXIT is required but not yet emulated */
	bool exit_required;

	/* cache for intercepts of the guest */
	u32 intercept_cr;
	u32 intercept_dr;
	u32 intercept_exceptions;
	u64 intercept;

	/* Nested Paging related state */
	u64 nested_cr3;
};

struct vcpu_svm {
	struct kvm_vcpu vcpu;
	struct vmcb *vmcb;
	unsigned long vmcb_pa;
	struct svm_cpu_data *svm_data;
	uint64_t asid_generation;
	uint64_t sysenter_esp;
	uint64_t sysenter_eip;
	uint64_t tsc_aux;

	u64 msr_decfg;

	u64 next_rip;

	u64 host_user_msrs[NR_HOST_SAVE_USER_MSRS];
	struct {
		u16 fs;
		u16 gs;
		u16 ldt;
		u64 gs_base;
	} host;

	u64 spec_ctrl;
	/*
	 * Contains guest-controlled bits of VIRT_SPEC_CTRL, which will be
	 * translated into the appropriate L2_CFG bits on the host to
	 * perform speculative control.
	 */
	u64 virt_spec_ctrl;

	u32 *msrpm;

	ulong nmi_iret_rip;

	struct nested_state nested;

	bool nmi_singlestep;
	u64 nmi_singlestep_guest_rflags;

	unsigned int3_injected;
	unsigned long int3_rip;

	/* cached guest cpuid flags for faster access */
	bool nrips_enabled	: 1;

	u32 ldr_reg;
	u32 dfr_reg;
	struct page *avic_backing_page;
	u64 *avic_physical_id_cache;
	bool avic_is_running;

	/*
	 * Per-vcpu list of struct amd_svm_iommu_ir:
	 * This is used mainly to store interrupt remapping information used
	 * when update the vcpu affinity. This avoids the need to scan for
	 * IRTE and try to match ga_tag in the IOMMU driver.
	 */
	struct list_head ir_list;
	spinlock_t ir_list_lock;

	/* which host CPU was used for running this vcpu */
	unsigned int last_cpu;

	/* SEV-ES support */
	struct vmcb_save_area *vmsa;
	struct ghcb *ghcb;
	struct kvm_host_map ghcb_map;
	bool ap_hlt_loop;

	/* SEV-ES scratch area support */
	void *ghcb_sa;
	u64 ghcb_sa_len;
	bool ghcb_sa_sync;
	bool ghcb_sa_free;
};

struct svm_cpu_data {
	int cpu;

	u64 asid_generation;
	u32 max_asid;
	u32 next_asid;
	u32 min_asid;
	struct kvm_ldttss_desc *tss_desc;

	struct page *save_area;
	struct vmcb *current_vmcb;

	/* index = sev_asid, value = vmcb pointer */
	struct vmcb **sev_vmcbs;
};

DECLARE_PER_CPU(struct svm_cpu_data *, svm_data);

void recalc_intercepts(struct vcpu_svm *svm);

static inline struct kvm_svm *to_kvm_svm(struct kvm *kvm)
{
	return container_of(kvm, struct kvm_svm, kvm);
}

static inline bool sev_guest(struct kvm *kvm)
{
#ifdef CONFIG_KVM_AMD_SEV
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	return sev->active;
#else
	return false;
#endif
}

static inline bool sev_es_guest(struct kvm *kvm)
{
#ifdef CONFIG_KVM_AMD_SEV
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	return sev_guest(kvm) && sev->es_active;
#else
	return false;
#endif
}

static inline void mark_all_dirty(struct vmcb *vmcb)
{
	vmcb->control.clean = 0;
}

static inline void mark_all_clean(struct vmcb *vmcb)
{
	vmcb->control.clean = ((1 << VMCB_DIRTY_MAX) - 1)
			       & ~VMCB_ALWAYS_DIRTY_MASK;
}

static inline void mark_dirty(struct vmcb *vmcb, int bit)
{
	vmcb->control.clean &= ~(1 << bit);
}

static inline struct vcpu_svm *to_svm(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct vcpu_svm, vcpu);
}

static inline struct vmcb *get_host_vmcb(struct vcpu_svm *svm)
{
	if (is_guest_mode(&svm->vcpu))
		return svm->nested.hsave;
	else
		return svm->vmcb;
}

static inline void set_cr_intercept(struct vcpu_svm *svm, int bit)
{
	struct vmcb *vmcb = get_host_vmcb(svm);

	vmcb->control.intercept_cr |= (1U << bit);

	recalc_intercepts(svm);
}

static inline void clr_cr_intercept(struct vcpu_svm *svm, int bit)
{
	struct vmcb *vmcb = get_host_vmcb(svm);

	vmcb->control.intercept_cr &= ~(1U << bit);

	recalc_intercepts(svm);
}

static inline bool is_cr_intercept(struct vcpu_svm *svm, int bit)
{
	struct vmcb *vmcb = get_host_vmcb(svm);

	return vmcb->control.intercept_cr & (1U << bit);
}

#define SVM_DR_INTERCEPTS		\
	((1 << INTERCEPT_DR0_READ)	\
	| (1 << INTERCEPT_DR1_READ)	\
	| (1 << INTERCEPT_DR2_READ)	\
	| (1 << INTERCEPT_DR3_READ)	\
	| (1 << INTERCEPT_DR4_READ)	\
	| (1 << INTERCEPT_DR5_READ)	\
	| (1 << INTERCEPT_DR6_READ)	\
	| (1 << INTERCEPT_DR7_READ)	\
	| (1 << INTERCEPT_DR0_WRITE)	\
	| (1 << INTERCEPT_DR1_WRITE)	\
	| (1 << INTERCEPT_DR2_WRITE)	\
	| (1 << INTERCEPT_DR3_WRITE)	\
	| (1 << INTERCEPT_DR4_WRITE)	\
	| (1 << INTERCEPT_DR5_WRITE)	\
	| (1 << INTERCEPT_DR6_WRITE)	\
	| (1 << INTERCEPT_DR7_WRITE))

#define SVM_SEV_ES_DR_INTERCEPTS	\
	((1 << INTERCEPT_DR7_READ)	\
	| (1 << INTERCEPT_DR7_WRITE))

static inline void set_dr_intercepts(struct vcpu_svm *svm)
{
	struct vmcb *vmcb = get_host_vmcb(svm);

	vmcb->control.intercept_dr =
		(sev_es_guest(svm->vcpu.kvm)) ? SVM_SEV_ES_DR_INTERCEPTS
					      : SVM_DR_INTERCEPTS;

	recalc_intercepts(svm);
}

static inline void clr_dr_intercepts(struct vcpu_svm *svm)
{
	struct vmcb *vmcb = get_host_vmcb(svm);

	vmcb->control.intercept_dr =
		(sev_es_guest(svm->vcpu.kvm)) ? SVM_SEV_ES_DR_INTERCEPTS
					      : 0;

	recalc_intercepts(svm);
}

static inline void set_exception_intercept(struct vcpu_svm *svm, int bit)
{
	struct vmcb *vmcb = get_host_vmcb(svm);

	vmcb->control.intercept_exceptions |= (1U << bit);

	recalc_intercepts(svm);
}

static inline void clr_exception_intercept(struct vcpu_svm *svm, int bit)
{
	struct vmcb *vmcb = get_host_vmcb(svm);

	vmcb->control.intercept_exceptions &= ~(1U << bit);

	recalc_intercepts(svm);
}

static inline void set_intercept(struct vcpu_svm *svm, int bit)
{
	struct vmcb *vmcb = get_host_vmcb(svm);

	vmcb->control.intercept |= (1ULL << bit);

	recalc_intercepts(svm);
}

static inline void clr_intercept(struct vcpu_svm *svm, int bit)
{
	struct vmcb *vmcb = get_host_vmcb(svm);

	vmcb->control.intercept &= ~(1ULL << bit);

	recalc_intercepts(svm);
}

static inline bool is_intercept(struct vcpu_svm *svm, int bit)
{
	return (svm->vmcb->control.intercept & (1ULL << bit)) != 0;
}

static inline bool vgif_enabled(struct vcpu_svm *svm)
{
	return !!(svm->vmcb->control.int_ctl & V_GIF_ENABLE_MASK);
}

static inline void enable_gif(struct vcpu_svm *svm)
{
	if (vgif_enabled(svm))
		svm->vmcb->control.int_ctl |= V_GIF_MASK;
	else
		svm->vcpu.arch.hflags |= HF_GIF_MASK;
}

static inline void disable_gif(struct vcpu_svm *svm)
{
	if (vgif_enabled(svm))
		svm->vmcb->control.int_ctl &= ~V_GIF_MASK;
	else
		svm->vcpu.arch.hflags &= ~HF_GIF_MASK;
}

static inline bool gif_set(struct vcpu_svm *svm)
{
	if (vgif_enabled(svm))
		return !!(svm->vmcb->control.int_ctl & V_GIF_MASK);
	else
		return !!(svm->vcpu.arch.hflags & HF_GIF_MASK);
}

/* svm.c */
#define MSR_INVALID			0xffffffffU

extern int sev;
extern int sev_es;
extern int sev_snp;

u32 svm_msrpm_offset(u32 msr);
void svm_set_efer(struct kvm_vcpu *vcpu, u64 efer);
void svm_set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0);
int svm_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4);
void svm_flush_tlb(struct kvm_vcpu *vcpu, bool invalidate_gpa);
void disable_nmi_singlestep(struct vcpu_svm *svm);
int svm_invoke_exit_handler(struct vcpu_svm *svm, u64 exit_code);
void set_msr_interception(u32 *msrpm, unsigned msr, int read, int write);

/* nested.c */

#define NESTED_EXIT_HOST	0	/* Exit handled on host level */
#define NESTED_EXIT_DONE	1	/* Exit caused nested vmexit  */
#define NESTED_EXIT_CONTINUE	2	/* Further checks needed      */

/* This function returns true if it is save to enable the nmi window */
static inline bool nested_svm_nmi(struct vcpu_svm *svm)
{
	if (!is_guest_mode(&svm->vcpu))
		return true;

	if (!(svm->nested.intercept & (1ULL << INTERCEPT_NMI)))
		return true;

	svm->vmcb->control.exit_code = SVM_EXIT_NMI;
	svm->nested.exit_required = true;

	return false;
}

static inline bool svm_nested_virtualize_tpr(struct kvm_vcpu *vcpu)
{
	return is_guest_mode(vcpu) && (vcpu->arch.hflags & HF_VINTR_MASK);
}

void enter_svm_guest_mode(struct vcpu_svm *svm, u64 vmcb_gpa,
			  struct vmcb *nested_vmcb, struct kvm_host_map *map);
int nested_svm_vmrun(struct vcpu_svm *svm);
void nested_svm_vmloadsave(struct vmcb_save_area *from_vmsa,
			   struct vmcb_save_area *to_vmsa);
int nested_svm_vmexit(struct vcpu_svm *svm);
int nested_svm_exit_handled(struct vcpu_svm *svm);
int nested_svm_check_permissions(struct vcpu_svm *svm);
int nested_svm_check_exception(struct vcpu_svm *svm, unsigned nr,
			       bool has_error_code, u32 error_code);
int svm_check_nested_events(struct kvm_vcpu *vcpu);
int nested_svm_exit_special(struct vcpu_svm *svm);

/* avic.c */

#define AVIC_LOGICAL_ID_ENTRY_GUEST_PHYSICAL_ID_MASK	(0xFF)
#define AVIC_LOGICAL_ID_ENTRY_VALID_BIT			31
#define AVIC_LOGICAL_ID_ENTRY_VALID_MASK		(1 << 31)

#define AVIC_PHYSICAL_ID_ENTRY_HOST_PHYSICAL_ID_MASK	(0xFFULL)
#define AVIC_PHYSICAL_ID_ENTRY_BACKING_PAGE_MASK	(0xFFFFFFFFFFULL << 12)
#define AVIC_PHYSICAL_ID_ENTRY_IS_RUNNING_MASK		(1ULL << 62)
#define AVIC_PHYSICAL_ID_ENTRY_VALID_MASK		(1ULL << 63)

#define VMCB_AVIC_APIC_BAR_MASK		0xFFFFFFFFFF000ULL

extern int avic;

static inline void avic_update_vapic_bar(struct vcpu_svm *svm, u64 data)
{
	svm->vmcb->control.avic_vapic_bar = data & VMCB_AVIC_APIC_BAR_MASK;
	mark_dirty(svm->vmcb, VMCB_AVIC);
}

static inline bool avic_vcpu_is_running(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	u64 *entry = svm->avic_physical_id_cache;

	if (!entry)
		return false;

	return (READ_ONCE(*entry) & AVIC_PHYSICAL_ID_ENTRY_IS_RUNNING_MASK);
}

int avic_ga_log_notifier(u32 ga_tag);
void avic_vm_destroy(struct kvm *kvm);
int avic_vm_init(struct kvm *kvm);
void avic_init_vmcb(struct vcpu_svm *svm);
void svm_toggle_avic_for_irq_window(struct kvm_vcpu *vcpu, bool activate);
int avic_incomplete_ipi_interception(struct vcpu_svm *svm);
int avic_unaccelerated_access_interception(struct vcpu_svm *svm);
int avic_init_vcpu(struct vcpu_svm *svm);
void avic_vcpu_load(struct kvm_vcpu *vcpu, int cpu);
void avic_vcpu_put(struct kvm_vcpu *vcpu);
void avic_post_state_restore(struct kvm_vcpu *vcpu);
void svm_set_virtual_apic_mode(struct kvm_vcpu *vcpu);
void svm_refresh_apicv_exec_ctrl(struct kvm_vcpu *vcpu);
bool svm_check_apicv_inhibit_reasons(ulong bit);
void svm_pre_update_apicv_exec_ctrl(struct kvm *kvm, bool activate);
void svm_load_eoi_exitmap(struct kvm_vcpu *vcpu, u64 *eoi_exit_bitmap);
void svm_hwapic_irr_update(struct kvm_vcpu *vcpu, int max_irr);
void svm_hwapic_isr_update(struct kvm_vcpu *vcpu, int max_isr);
int svm_deliver_avic_intr(struct kvm_vcpu *vcpu, int vec);
bool svm_dy_apicv_has_pending_interrupt(struct kvm_vcpu *vcpu);
int svm_update_pi_irte(struct kvm *kvm, unsigned int host_irq,
		       uint32_t guest_irq, bool set);
void svm_vcpu_blocking(struct kvm_vcpu *vcpu);
void svm_vcpu_unblocking(struct kvm_vcpu *vcpu);

/* sev.c */

#define GHCB_VERSION_MAX		1ULL
#define GHCB_VERSION_MIN		1ULL

#define GHCB_MSR_INFO_POS		0
#define GHCB_MSR_INFO_MASK		(BIT_ULL(12) - 1)

#define GHCB_MSR_SEV_INFO_RESP		0x001
#define GHCB_MSR_SEV_INFO_REQ		0x002
#define GHCB_MSR_VER_MAX_POS		48
#define GHCB_MSR_VER_MAX_MASK		0xffff
#define GHCB_MSR_VER_MIN_POS		32
#define GHCB_MSR_VER_MIN_MASK		0xffff
#define GHCB_MSR_CBIT_POS		24
#define GHCB_MSR_CBIT_MASK		0xff
#define GHCB_MSR_SEV_INFO(_max, _min, _cbit)				\
	((((_max) & GHCB_MSR_VER_MAX_MASK) << GHCB_MSR_VER_MAX_POS) |	\
	 (((_min) & GHCB_MSR_VER_MIN_MASK) << GHCB_MSR_VER_MIN_POS) |	\
	 (((_cbit) & GHCB_MSR_CBIT_MASK) << GHCB_MSR_CBIT_POS) |	\
	 GHCB_MSR_SEV_INFO_RESP)

#define GHCB_MSR_CPUID_REQ		0x004
#define GHCB_MSR_CPUID_RESP		0x005
#define GHCB_MSR_CPUID_FUNC_POS		32
#define GHCB_MSR_CPUID_FUNC_MASK	0xffffffff
#define GHCB_MSR_CPUID_VALUE_POS	32
#define GHCB_MSR_CPUID_VALUE_MASK	0xffffffff
#define GHCB_MSR_CPUID_REG_POS		30
#define GHCB_MSR_CPUID_REG_MASK		0x3

#define GHCB_MSR_TERM_REQ		0x100
#define GHCB_MSR_TERM_REASON_SET_POS	12
#define GHCB_MSR_TERM_REASON_SET_MASK	0xf
#define GHCB_MSR_TERM_REASON_POS	16
#define GHCB_MSR_TERM_REASON_MASK	0xff

extern unsigned int max_sev_asid;

static inline bool svm_sev_enabled(void)
{
	return IS_ENABLED(CONFIG_KVM_AMD_SEV) ? max_sev_asid : 0;
}

void sev_vm_destroy(struct kvm *kvm);
int svm_mem_enc_op(struct kvm *kvm, void __user *argp);
int svm_register_enc_region(struct kvm *kvm,
			    struct kvm_enc_region *range);
int svm_unregister_enc_region(struct kvm *kvm,
			      struct kvm_enc_region *range);
void pre_sev_run(struct vcpu_svm *svm, int cpu);
void __init sev_hardware_setup(void);
void sev_hardware_teardown(void);
int sev_handle_vmgexit(struct vcpu_svm *svm);
int sev_es_string_io(struct vcpu_svm *svm, int size, unsigned int port, int in);
void sev_vcpu_deliver_sipi_vector(struct kvm_vcpu *vcpu, u8 vector);
void sev_es_init_vmcb(struct vcpu_svm *svm);
void sev_es_create_vcpu(struct vcpu_svm *svm);
void sev_es_vcpu_load(struct vcpu_svm *svm, int cpu);
void sev_es_vcpu_put(struct vcpu_svm *svm);

/* vmenter.S */

void __svm_sev_es_vcpu_run(unsigned long vmcb_pa);
void __svm_vcpu_run(unsigned long vmcb_pa, unsigned long *regs);

/* VMSA Accessor functions */

static inline struct vmcb_save_area *get_vmsa(struct vcpu_svm *svm)
{
	struct vmcb_save_area *vmsa;

	if (sev_es_guest(svm->vcpu.kvm)) {
		/*
		 * Before LAUNCH_UPDATE_VMSA, use the actual SEV-ES save area
		 * to construct the initial state.  Afterwards, use the mapped
		 * GHCB in a VMGEXIT or the traditional save area as a scratch
		 * area when outside of a VMGEXIT.
		 */
		if (svm->vcpu.arch.vmsa_encrypted) {
			if (svm->ghcb)
				vmsa = &svm->ghcb->save;
			else
				vmsa = &svm->vmcb->save;
		} else {
			vmsa = svm->vmsa;
		}
	} else {
		vmsa = &svm->vmcb->save;
	}

	return vmsa;
}

#define DEFINE_VMSA_SEGMENT_ENTRY(_field, _entry, _size)		\
	static inline _size						\
	svm_##_field##_read_##_entry(struct vcpu_svm *svm)		\
	{								\
		struct vmcb_save_area *vmsa = get_vmsa(svm);		\
									\
		return vmsa->_field._entry;				\
	}								\
									\
	static inline void						\
	svm_##_field##_write_##_entry(struct vcpu_svm *svm,		\
				      _size value)			\
	{								\
		struct vmcb_save_area *vmsa = get_vmsa(svm);		\
									\
		vmsa->_field._entry = value;				\
		if (svm->vcpu.arch.vmsa_encrypted) {			\
			SEV_ES_SET_VALID(vmsa, _field)			\
		}							\
	}								\

#define DEFINE_VMSA_SEGMENT_ACCESSOR(_field)				\
	DEFINE_VMSA_SEGMENT_ENTRY(_field, selector, u16)		\
	DEFINE_VMSA_SEGMENT_ENTRY(_field, attrib, u16)			\
	DEFINE_VMSA_SEGMENT_ENTRY(_field, limit, u32)			\
	DEFINE_VMSA_SEGMENT_ENTRY(_field, base, u64)			\
									\
	static inline struct vmcb_seg *					\
	svm_##_field##_read(struct vcpu_svm *svm)			\
	{								\
		struct vmcb_save_area *vmsa = get_vmsa(svm);		\
									\
		return &vmsa->_field;					\
	}								\
									\
	static inline void						\
	svm_##_field##_write(struct vcpu_svm *svm,			\
			    struct vmcb_seg *seg)			\
	{								\
		struct vmcb_save_area *vmsa = get_vmsa(svm);		\
									\
		vmsa->_field = *seg;					\
		if (svm->vcpu.arch.vmsa_encrypted) {			\
			SEV_ES_SET_VALID(vmsa, _field)			\
		}							\
	}

DEFINE_VMSA_SEGMENT_ACCESSOR(cs)
DEFINE_VMSA_SEGMENT_ACCESSOR(ds)
DEFINE_VMSA_SEGMENT_ACCESSOR(es)
DEFINE_VMSA_SEGMENT_ACCESSOR(fs)
DEFINE_VMSA_SEGMENT_ACCESSOR(gs)
DEFINE_VMSA_SEGMENT_ACCESSOR(ss)
DEFINE_VMSA_SEGMENT_ACCESSOR(gdtr)
DEFINE_VMSA_SEGMENT_ACCESSOR(idtr)
DEFINE_VMSA_SEGMENT_ACCESSOR(ldtr)
DEFINE_VMSA_SEGMENT_ACCESSOR(tr)

#define DEFINE_VMSA_SIZE_ACCESSOR(_field, _size)			\
	static inline _size						\
	svm_##_field##_read(struct vcpu_svm *svm)			\
	{								\
		struct vmcb_save_area *vmsa = get_vmsa(svm);		\
									\
		return vmsa->_field;					\
	}								\
									\
	static inline void						\
	svm_##_field##_write(struct vcpu_svm *svm, _size value)		\
	{								\
		struct vmcb_save_area *vmsa = get_vmsa(svm);		\
									\
		vmsa->_field = value;					\
		if (svm->vcpu.arch.vmsa_encrypted) {			\
			SEV_ES_SET_VALID(vmsa, _field)			\
		}							\
	}								\
									\
	static inline void						\
	svm_##_field##_and(struct vcpu_svm *svm, _size value)		\
	{								\
		struct vmcb_save_area *vmsa = get_vmsa(svm);		\
									\
		vmsa->_field &= value;					\
		if (svm->vcpu.arch.vmsa_encrypted) {			\
			SEV_ES_SET_VALID(vmsa, _field)			\
		}							\
	}								\
									\
	static inline void						\
	svm_##_field##_or(struct vcpu_svm *svm, _size value)		\
	{								\
		struct vmcb_save_area *vmsa = get_vmsa(svm);		\
									\
		vmsa->_field |= value;					\
		if (svm->vcpu.arch.vmsa_encrypted) {			\
			SEV_ES_SET_VALID(vmsa, _field)			\
		}							\
	}

#define DEFINE_VMSA_ACCESSOR(_field)					\
	DEFINE_VMSA_SIZE_ACCESSOR(_field, u64)

#define DEFINE_VMSA_U8_ACCESSOR(_field)					\
	DEFINE_VMSA_SIZE_ACCESSOR(_field, u8)

DEFINE_VMSA_ACCESSOR(efer)
DEFINE_VMSA_ACCESSOR(cr0)
DEFINE_VMSA_ACCESSOR(cr2)
DEFINE_VMSA_ACCESSOR(cr3)
DEFINE_VMSA_ACCESSOR(cr4)
DEFINE_VMSA_ACCESSOR(dr6)
DEFINE_VMSA_ACCESSOR(dr7)
DEFINE_VMSA_ACCESSOR(rflags)
DEFINE_VMSA_ACCESSOR(star)
DEFINE_VMSA_ACCESSOR(lstar)
DEFINE_VMSA_ACCESSOR(cstar)
DEFINE_VMSA_ACCESSOR(sfmask)
DEFINE_VMSA_ACCESSOR(kernel_gs_base)
DEFINE_VMSA_ACCESSOR(sysenter_cs)
DEFINE_VMSA_ACCESSOR(sysenter_esp)
DEFINE_VMSA_ACCESSOR(sysenter_eip)
DEFINE_VMSA_ACCESSOR(g_pat)
DEFINE_VMSA_ACCESSOR(dbgctl)
DEFINE_VMSA_ACCESSOR(br_from)
DEFINE_VMSA_ACCESSOR(br_to)
DEFINE_VMSA_ACCESSOR(last_excp_from)
DEFINE_VMSA_ACCESSOR(last_excp_to)

DEFINE_VMSA_U8_ACCESSOR(cpl)
DEFINE_VMSA_ACCESSOR(rip)
DEFINE_VMSA_ACCESSOR(rax)
DEFINE_VMSA_ACCESSOR(rbx)
DEFINE_VMSA_ACCESSOR(rcx)
DEFINE_VMSA_ACCESSOR(rdx)
DEFINE_VMSA_ACCESSOR(rsp)
DEFINE_VMSA_ACCESSOR(rbp)
DEFINE_VMSA_ACCESSOR(rsi)
DEFINE_VMSA_ACCESSOR(rdi)
DEFINE_VMSA_ACCESSOR(r8)
DEFINE_VMSA_ACCESSOR(r9)
DEFINE_VMSA_ACCESSOR(r10)
DEFINE_VMSA_ACCESSOR(r11)
DEFINE_VMSA_ACCESSOR(r12)
DEFINE_VMSA_ACCESSOR(r13)
DEFINE_VMSA_ACCESSOR(r14)
DEFINE_VMSA_ACCESSOR(r15)
DEFINE_VMSA_ACCESSOR(sw_exit_code)
DEFINE_VMSA_ACCESSOR(sw_exit_info_1)
DEFINE_VMSA_ACCESSOR(sw_exit_info_2)
DEFINE_VMSA_ACCESSOR(sw_scratch)
DEFINE_VMSA_ACCESSOR(xcr0)

#endif
