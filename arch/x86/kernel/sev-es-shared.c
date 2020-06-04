// SPDX-License-Identifier: GPL-2.0
/*
 * AMD Encrypted Register State Support
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 *
 * This file is not compiled stand-alone. It contains code shared
 * between the pre-decompression boot code and the running Linux kernel
 * and is included directly into both code-bases.
 */

static void sev_es_terminate(unsigned int reason)
{
	/* Request Guest Termination from Hypvervisor */
	sev_es_wr_ghcb_msr(GHCB_SEV_TERMINATE);
	VMGEXIT();

	while (true)
		asm volatile("hlt\n" : : : "memory");
}

static bool sev_es_negotiate_protocol(void)
{
	u64 val;

	/* Do the GHCB protocol version negotiation */
	sev_es_wr_ghcb_msr(GHCB_SEV_INFO_REQ);
	VMGEXIT();
	val = sev_es_rd_ghcb_msr();

	if (GHCB_INFO(val) != GHCB_SEV_INFO)
		return false;

	if (GHCB_PROTO_MAX(val) < GHCB_PROTO_OUR ||
	    GHCB_PROTO_MIN(val) > GHCB_PROTO_OUR)
		return false;

	return true;
}

static void vc_ghcb_invalidate(struct ghcb *ghcb)
{
	memset(ghcb->save.valid_bitmap, 0, sizeof(ghcb->save.valid_bitmap));
}

static bool vc_valid_cs(struct pt_regs *regs)
{
	return (regs->cs == __KERNEL_CS) || (regs->cs == __USER_CS) ||
	       (regs->cs == __USER32_CS);
}

static enum es_result vc_decode_insn(struct es_em_ctxt *ctxt)
{
	char buffer[MAX_INSN_SIZE];
	enum es_result ret;
	unsigned int i;

	if (!vc_valid_cs(ctxt->regs))
		return ES_UNSUPPORTED;

	/* Fetch instruction */
	for (i = 0; i < MAX_INSN_SIZE; i++) {
		ret = vc_fetch_insn_byte(ctxt, i, buffer);
		if (ret != ES_OK)
			break;
	}

	insn_init(&ctxt->insn, buffer, i - 1, 1);
	insn_get_length(&ctxt->insn);

	if (ret != ES_EXCEPTION)
		ret = ctxt->insn.immediate.got ? ES_OK : ES_DECODE_FAILED;

	return ret;
}

static bool vc_decoding_needed(unsigned long exit_code)
{
	/* Exceptions don't require to decode the instruction */
	return !(exit_code >= SVM_EXIT_EXCP_BASE &&
		 exit_code <= SVM_EXIT_LAST_EXCP);
}

static enum es_result vc_init_em_ctxt(struct es_em_ctxt *ctxt,
				      struct pt_regs *regs,
				      unsigned long exit_code)
{
	enum es_result ret = ES_OK;

	memset(ctxt, 0, sizeof(*ctxt));
	ctxt->regs = regs;

	if (vc_decoding_needed(exit_code))
		ret = vc_decode_insn(ctxt);

	return ret;
}

static void vc_finish_insn(struct es_em_ctxt *ctxt)
{
	ctxt->regs->ip += ctxt->insn.length;
}

static enum es_result sev_es_ghcb_hv_call(struct ghcb *ghcb,
					  struct es_em_ctxt *ctxt,
					  u64 exit_code, u64 exit_info_1,
					  u64 exit_info_2)
{
	enum es_result ret;

	ghcb_set_sw_exit_code(ghcb, exit_code);
	ghcb_set_sw_exit_info_1(ghcb, exit_info_1);
	ghcb_set_sw_exit_info_2(ghcb, exit_info_2);

	sev_es_wr_ghcb_msr(__pa(ghcb));
	VMGEXIT();

	if ((ghcb->save.sw_exit_info_1 & 0xffffffff) == 1) {
		u64 info = ghcb->save.sw_exit_info_2;
		unsigned long v;

		info = ghcb->save.sw_exit_info_2;
		v = info & SVM_EVTINJ_VEC_MASK;

		/* Check if exception information from hypervisor is sane. */
		if ((info & SVM_EVTINJ_VALID) &&
		    ((v == X86_TRAP_GP) || (v == X86_TRAP_UD)) &&
		    ((info & SVM_EVTINJ_TYPE_MASK) == SVM_EVTINJ_TYPE_EXEPT)) {
			ctxt->fi.vector = v;
			if (info & SVM_EVTINJ_VALID_ERR)
				ctxt->fi.error_code = info >> 32;
			ret = ES_EXCEPTION;
		} else {
			ret = ES_VMM_ERROR;
		}
	} else {
		ret = ES_OK;
	}

	return ret;
}

/*
 * Boot VC Handler - This is the first VC handler during boot, there is no GHCB
 * page yet, so it only supports the MSR based communication with the
 * hypervisor and only the CPUID exit-code.
 */
void __init vc_no_ghcb_handler(struct pt_regs *regs, unsigned long exit_code)
{
	unsigned int fn = lower_bits(regs->ax, 32);
	unsigned long val;

	/* Only CPUID is supported via MSR protocol */
	if (exit_code != SVM_EXIT_CPUID)
		goto fail;

	sev_es_wr_ghcb_msr(GHCB_CPUID_REQ(fn, GHCB_CPUID_REQ_EAX));
	VMGEXIT();
	val = sev_es_rd_ghcb_msr();
	if (GHCB_SEV_GHCB_RESP_CODE(val) != GHCB_SEV_CPUID_RESP)
		goto fail;
	regs->ax = copy_lower_bits(regs->ax, val >> 32, 32);

	sev_es_wr_ghcb_msr(GHCB_CPUID_REQ(fn, GHCB_CPUID_REQ_EBX));
	VMGEXIT();
	val = sev_es_rd_ghcb_msr();
	if (GHCB_SEV_GHCB_RESP_CODE(val) != GHCB_SEV_CPUID_RESP)
		goto fail;
	regs->bx = copy_lower_bits(regs->bx, val >> 32, 32);

	sev_es_wr_ghcb_msr(GHCB_CPUID_REQ(fn, GHCB_CPUID_REQ_ECX));
	VMGEXIT();
	val = sev_es_rd_ghcb_msr();
	if (GHCB_SEV_GHCB_RESP_CODE(val) != GHCB_SEV_CPUID_RESP)
		goto fail;
	regs->cx = copy_lower_bits(regs->cx, val >> 32, 32);

	sev_es_wr_ghcb_msr(GHCB_CPUID_REQ(fn, GHCB_CPUID_REQ_EDX));
	VMGEXIT();
	val = sev_es_rd_ghcb_msr();
	if (GHCB_SEV_GHCB_RESP_CODE(val) != GHCB_SEV_CPUID_RESP)
		goto fail;
	regs->dx = copy_lower_bits(regs->dx, val >> 32, 32);

	regs->ip += 2;

	return;

fail:
	sev_es_wr_ghcb_msr(GHCB_SEV_TERMINATE);
	VMGEXIT();

	/* Shouldn't get here - if we do halt the machine */
	while (true)
		asm volatile("hlt\n");
}

static enum es_result vc_insn_string_read(struct es_em_ctxt *ctxt,
					  void *src, char *buf,
					  unsigned int data_size,
					  unsigned int count,
					  bool backwards)
{
	int i, b = backwards ? -1 : 1;
	enum es_result ret = ES_OK;

	for (i = 0; i < count; i++) {
		void *s = src + (i * data_size * b);
		char *d = buf + (i * data_size);

		ret = vc_read_mem(ctxt, s, d, data_size);
		if (ret != ES_OK)
			break;
	}

	return ret;
}

static enum es_result vc_insn_string_write(struct es_em_ctxt *ctxt,
					   void *dst, char *buf,
					   unsigned int data_size,
					   unsigned int count,
					   bool backwards)
{
	int i, s = backwards ? -1 : 1;
	enum es_result ret = ES_OK;

	for (i = 0; i < count; i++) {
		void *d = dst + (i * data_size * s);
		char *b = buf + (i * data_size);

		ret = vc_write_mem(ctxt, d, b, data_size);
		if (ret != ES_OK)
			break;
	}

	return ret;
}

#define IOIO_TYPE_STR  BIT(2)
#define IOIO_TYPE_IN   1
#define IOIO_TYPE_INS  (IOIO_TYPE_IN | IOIO_TYPE_STR)
#define IOIO_TYPE_OUT  0
#define IOIO_TYPE_OUTS (IOIO_TYPE_OUT | IOIO_TYPE_STR)

#define IOIO_REP       BIT(3)

#define IOIO_ADDR_64   BIT(9)
#define IOIO_ADDR_32   BIT(8)
#define IOIO_ADDR_16   BIT(7)

#define IOIO_DATA_32   BIT(6)
#define IOIO_DATA_16   BIT(5)
#define IOIO_DATA_8    BIT(4)

#define IOIO_SEG_ES    (0 << 10)
#define IOIO_SEG_DS    (3 << 10)

static bool vc_insn_repmode(struct insn *insn)
{
	unsigned int i;

	for (i = 0; i < insn->prefixes.nbytes; i++) {
		switch (insn->prefixes.bytes[i]) {
		case 0xf2:
		case 0xf3:
			return true;
		}
	}

	return false;
}


static enum es_result vc_ioio_exitinfo(struct es_em_ctxt *ctxt, u64 *exitinfo)
{
	struct insn *insn = &ctxt->insn;
	*exitinfo = 0;

	switch (insn->opcode.bytes[0]) {
	/* INS opcodes */
	case 0x6c:
	case 0x6d:
		*exitinfo |= IOIO_TYPE_INS;
		*exitinfo |= IOIO_SEG_ES;
		*exitinfo |= (ctxt->regs->dx & 0xffff) << 16;
		break;

	/* OUTS opcodes */
	case 0x6e:
	case 0x6f:
		*exitinfo |= IOIO_TYPE_OUTS;
		*exitinfo |= IOIO_SEG_DS;
		*exitinfo |= (ctxt->regs->dx & 0xffff) << 16;
		break;

	/* IN immediate opcodes */
	case 0xe4:
	case 0xe5:
		*exitinfo |= IOIO_TYPE_IN;
		*exitinfo |= insn->immediate.value << 16;
		break;

	/* OUT immediate opcodes */
	case 0xe6:
	case 0xe7:
		*exitinfo |= IOIO_TYPE_OUT;
		*exitinfo |= insn->immediate.value << 16;
		break;

	/* IN register opcodes */
	case 0xec:
	case 0xed:
		*exitinfo |= IOIO_TYPE_IN;
		*exitinfo |= (ctxt->regs->dx & 0xffff) << 16;
		break;

	/* OUT register opcodes */
	case 0xee:
	case 0xef:
		*exitinfo |= IOIO_TYPE_OUT;
		*exitinfo |= (ctxt->regs->dx & 0xffff) << 16;
		break;

	default:
		return ES_DECODE_FAILED;
	}

	switch (insn->opcode.bytes[0]) {
	case 0x6c:
	case 0x6e:
	case 0xe4:
	case 0xe6:
	case 0xec:
	case 0xee:
		/* Single byte opcodes */
		*exitinfo |= IOIO_DATA_8;
		break;
	default:
		/* Length determined by instruction parsing */
		*exitinfo |= (insn->opnd_bytes == 2) ? IOIO_DATA_16
						     : IOIO_DATA_32;
	}
	switch (insn->addr_bytes) {
	case 2:
		*exitinfo |= IOIO_ADDR_16;
		break;
	case 4:
		*exitinfo |= IOIO_ADDR_32;
		break;
	case 8:
		*exitinfo |= IOIO_ADDR_64;
		break;
	}

	if (vc_insn_repmode(insn))
		*exitinfo |= IOIO_REP;

	return ES_OK;
}

static enum es_result vc_handle_ioio(struct ghcb *ghcb, struct es_em_ctxt *ctxt)
{
	struct pt_regs *regs = ctxt->regs;
	u64 exit_info_1, exit_info_2;
	enum es_result ret;

	ret = vc_ioio_exitinfo(ctxt, &exit_info_1);
	if (ret != ES_OK)
		return ret;

	if (exit_info_1 & IOIO_TYPE_STR) {
		int df = (regs->flags & X86_EFLAGS_DF) ? -1 : 1;
		unsigned int io_bytes, exit_bytes;
		unsigned int ghcb_count, op_count;
		u64 sw_scratch;

		/*
		 * For the string variants with rep prefix the amount of in/out
		 * operations per #VC exception is limited so that the kernel
		 * has a chance to take interrupts an re-schedule while the
		 * instruction is emulated.
		 */
		io_bytes   = (exit_info_1 >> 4) & 0x7;
		ghcb_count = sizeof(ghcb->shared_buffer) / io_bytes;

		op_count    = (exit_info_1 & IOIO_REP) ? regs->cx : 1;
		exit_info_2 = min(op_count, ghcb_count);
		exit_bytes  = exit_info_2 * io_bytes;

		if (!(exit_info_1 & IOIO_TYPE_IN)) {
			ret = vc_insn_string_read(ctxt, (void *)regs->si,
					       ghcb->shared_buffer, io_bytes,
					       exit_info_2, df);
			if (ret)
				return ret;
		}

		sw_scratch = __pa(ghcb) + offsetof(struct ghcb, shared_buffer);
		ghcb_set_sw_scratch(ghcb, sw_scratch);
		ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_IOIO,
				   exit_info_1, exit_info_2);
		if (ret != ES_OK)
			return ret;

		/* Everything went well, write back results */
		if (exit_info_1 & IOIO_TYPE_IN) {
			ret = vc_insn_string_write(ctxt, (void *)regs->di,
						ghcb->shared_buffer, io_bytes,
						exit_info_2, df);
			if (ret)
				return ret;

			if (df)
				regs->di -= exit_bytes;
			else
				regs->di += exit_bytes;
		} else {
			if (df)
				regs->si -= exit_bytes;
			else
				regs->si += exit_bytes;
		}

		if (exit_info_1 & IOIO_REP)
			regs->cx -= exit_info_2;

		ret = regs->cx ? ES_RETRY : ES_OK;

	} else {
		int bits = (exit_info_1 & 0x70) >> 1;
		u64 rax = 0;

		if (!(exit_info_1 & IOIO_TYPE_IN))
			rax = lower_bits(regs->ax, bits);

		ghcb_set_rax(ghcb, rax);

		ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_IOIO, exit_info_1, 0);
		if (ret != ES_OK)
			return ret;

		if (exit_info_1 & IOIO_TYPE_IN) {
			if (!ghcb_is_valid_rax(ghcb))
				return ES_VMM_ERROR;
			regs->ax = copy_lower_bits(regs->ax, ghcb->save.rax,
						   bits);
		}
	}

	return ret;
}

static enum es_result vc_handle_cpuid(struct ghcb *ghcb,
				      struct es_em_ctxt *ctxt)
{
	struct pt_regs *regs = ctxt->regs;
	u32 cr4 = native_read_cr4();
	enum es_result ret;
	const u32 eax = regs->ax & 0xffffffffU;
	const u32 ecx = regs->cx & 0xffffffffU;
	const bool request_feature_bits = (eax == 0x1U);

	ghcb_set_rax(ghcb, eax);
	ghcb_set_rcx(ghcb, ecx);

	if (cr4 & X86_CR4_OSXSAVE)
		/* Safe to read xcr0 */
		ghcb_set_xcr0(ghcb, xgetbv(XCR_XFEATURE_ENABLED_MASK));
	else
		/* xgetbv will cause #GP - use reset value for xcr0 */
		ghcb_set_xcr0(ghcb, 1);

	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_CPUID, 0, 0);
	if (ret != ES_OK)
		return ret;

	if (!(ghcb_is_valid_rax(ghcb) &&
	      ghcb_is_valid_rbx(ghcb) &&
	      ghcb_is_valid_rcx(ghcb) &&
	      ghcb_is_valid_rdx(ghcb)))
		return ES_VMM_ERROR;

	/*
	 * Without RDRAND, KASLR relies on the TSC value for randomnization
	 * which is controlled by the HV either through interception or modifying
	 * the TSC_RATIO_MSR.
	 * As a hardening, RDRAND is made a minimal required feature and VM
	 * returns error if the HV states that RDRAND is not supported.
	*/
	if (request_feature_bits && !(ghcb->save.rcx & (1U << 30)))
		return ES_VMM_ERROR;

	regs->ax = ghcb->save.rax & 0xffffffff;
	regs->bx = ghcb->save.rbx & 0xffffffff;
	regs->cx = ghcb->save.rcx & 0xffffffff;
	regs->dx = ghcb->save.rdx & 0xffffffff;

	return ES_OK;
}

/* Map from x86 register index to pt_regs offset */
static unsigned long *vc_register_from_idx(struct pt_regs *regs, u8 reg)
{
	static int reg2pt_regs[] = {
		10, 11, 12, 5, 19, 4, 13, 14, 9, 8, 7, 6, 3, 2, 1, 0
	};
	unsigned long *regs_array = (unsigned long *)regs;

	if (WARN_ONCE(reg > 15, "register index is not valid: %#hhx\n", reg))
		return NULL;

	return &regs_array[reg2pt_regs[reg]];
}

static u64 vc_insn_get_eff_addr(struct es_em_ctxt *ctxt)
{
	u64 effective_addr;
	u8 mod, rm;

	if (!ctxt->insn.modrm.nbytes)
		return 0;

	if (insn_rip_relative(&ctxt->insn))
		return ctxt->regs->ip + ctxt->insn.displacement.value;

	mod = X86_MODRM_MOD(ctxt->insn.modrm.value);
	rm = X86_MODRM_RM(ctxt->insn.modrm.value);

	if (ctxt->insn.rex_prefix.nbytes &&
	    X86_REX_B(ctxt->insn.rex_prefix.value))
		rm |= 0x8;

	if (mod == 3)
		return *vc_register_from_idx(ctxt->regs, rm);

	switch (mod) {
	case 1:
	case 2:
		effective_addr = ctxt->insn.displacement.value;
		break;
	default:
		effective_addr = 0;
	}

	if (ctxt->insn.sib.nbytes) {
		u8 scale, index, base;

		scale = X86_SIB_SCALE(ctxt->insn.sib.value);
		index = X86_SIB_INDEX(ctxt->insn.sib.value);
		base = X86_SIB_BASE(ctxt->insn.sib.value);
		if (ctxt->insn.rex_prefix.nbytes &&
		    X86_REX_X(ctxt->insn.rex_prefix.value))
			index |= 0x8;
		if (ctxt->insn.rex_prefix.nbytes &&
		    X86_REX_B(ctxt->insn.rex_prefix.value))
			base |= 0x8;

		if (index != 4)
			effective_addr += (*vc_register_from_idx(ctxt->regs, index)
					   << scale);

		if ((base != 5) || mod)
			effective_addr += *vc_register_from_idx(ctxt->regs, base);
		else
			effective_addr += ctxt->insn.displacement.value;
	} else {
		effective_addr += *vc_register_from_idx(ctxt->regs, rm);
	}

	return effective_addr;
}

static unsigned long *vc_insn_get_reg(struct es_em_ctxt *ctxt)
{
	u8 reg;

	if (!ctxt->insn.modrm.nbytes)
		return NULL;

	reg = X86_MODRM_REG(ctxt->insn.modrm.value);
	if (ctxt->insn.rex_prefix.nbytes &&
	    X86_REX_R(ctxt->insn.rex_prefix.value))
		reg |= 0x8;

	return vc_register_from_idx(ctxt->regs, reg);
}

static enum es_result vc_do_mmio(struct ghcb *ghcb, struct es_em_ctxt *ctxt,
				 unsigned int bytes, bool read)
{
	u64 exit_code, exit_info_1, exit_info_2;
	unsigned long ghcb_pa = __pa(ghcb);

	/* Register-direct addressing mode not supported with MMIO */
	if (X86_MODRM_MOD(ctxt->insn.modrm.value) == 3)
		return ES_UNSUPPORTED;

	exit_code = read ? SVM_VMGEXIT_MMIO_READ : SVM_VMGEXIT_MMIO_WRITE;

	exit_info_1 = vc_insn_get_eff_addr(ctxt);
	exit_info_1 = vc_slow_virt_to_phys(ghcb, exit_info_1);
	exit_info_2 = bytes;    /* Can never be greater than 8 */

	ghcb->save.sw_scratch = ghcb_pa + offsetof(struct ghcb, shared_buffer);

	return sev_es_ghcb_hv_call(ghcb, ctxt, exit_code, exit_info_1, exit_info_2);
}

static enum es_result vc_handle_mmio_twobyte_ops(struct ghcb *ghcb,
						 struct es_em_ctxt *ctxt)
{
	struct insn *insn = &ctxt->insn;
	unsigned int bytes = 0;
	enum es_result ret;
	int sign_byte;
	long *reg_data;

	switch (insn->opcode.bytes[1]) {
		/* MMIO Read w/ zero-extension */
	case 0xb6:
		bytes = 1;
		/* Fallthrough */
	case 0xb7:
		if (!bytes)
			bytes = 2;

		ret = vc_do_mmio(ghcb, ctxt, bytes, true);
		if (ret)
			break;

		/* Zero extend based on operand size */
		reg_data = vc_insn_get_reg(ctxt);
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

		ret = vc_do_mmio(ghcb, ctxt, bytes, true);
		if (ret)
			break;

		/* Sign extend based on operand size */
		reg_data = vc_insn_get_reg(ctxt);
		if (bytes == 1) {
			u8 *val = (u8 *)ghcb->shared_buffer;

			sign_byte = (*val & 0x80) ? 0xff : 0x00;
		} else {
			u16 *val = (u16 *)ghcb->shared_buffer;

			sign_byte = (*val & 0x8000) ? 0xff : 0x00;
		}
		memset(reg_data, sign_byte, insn->opnd_bytes);

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;

	default:
		ret = ES_UNSUPPORTED;
	}

	return ret;
}

static enum es_result vc_handle_mmio(struct ghcb *ghcb,
				     struct es_em_ctxt *ctxt)
{
	struct insn *insn = &ctxt->insn;
	unsigned int bytes = 0;
	enum es_result ret;
	long *reg_data;

	switch (insn->opcode.bytes[0]) {
	/* MMIO Write */
	case 0x88:
		bytes = 1;
		/* Fallthrough */
	case 0x89:
		if (!bytes)
			bytes = insn->opnd_bytes;

		reg_data = vc_insn_get_reg(ctxt);
		memcpy(ghcb->shared_buffer, reg_data, bytes);

		ret = vc_do_mmio(ghcb, ctxt, bytes, false);
		break;

	case 0xc6:
		bytes = 1;
		/* Fallthrough */
	case 0xc7:
		if (!bytes)
			bytes = insn->opnd_bytes;

		memcpy(ghcb->shared_buffer, insn->immediate1.bytes, bytes);

		ret = vc_do_mmio(ghcb, ctxt, bytes, false);
		break;

		/* MMIO Read */
	case 0x8a:
		bytes = 1;
		/* Fallthrough */
	case 0x8b:
		if (!bytes)
			bytes = insn->opnd_bytes;

		ret = vc_do_mmio(ghcb, ctxt, bytes, true);
		if (ret)
			break;

		reg_data = vc_insn_get_reg(ctxt);
		if (bytes == 4)
			*reg_data = 0;  /* Zero-extend for 32-bit operation */

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;

		/* Two-Byte Opcodes */
	case 0x0f:
		ret = vc_handle_mmio_twobyte_ops(ghcb, ctxt);
		break;
	default:
		ret = ES_UNSUPPORTED;
	}

	return ret;
}
