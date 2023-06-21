// SPDX-License-Identifier: GPL-2.0
/*
 * AMD SEV-ES #VC exception handling.
 * Adapted from Linux@6d7d0603ca:
 * - arch/x86/kernel/sev.c
 * - arch/x86/kernel/sev-shared.c
 */

#include "amd_sev.h"
#include "svm.h"
#include "x86/xsave.h"

extern phys_addr_t ghcb_addr;

static void vc_ghcb_invalidate(struct ghcb *ghcb)
{
	ghcb->save.sw_exit_code = 0;
	memset(ghcb->save.valid_bitmap, 0, sizeof(ghcb->save.valid_bitmap));
}

static bool vc_decoding_needed(unsigned long exit_code)
{
	/* Exceptions don't require to decode the instruction */
	return !(exit_code >= SVM_EXIT_EXCP_BASE &&
		 exit_code <= SVM_EXIT_LAST_EXCP);
}

static enum es_result vc_decode_insn(struct es_em_ctxt *ctxt)
{
	unsigned char buffer[MAX_INSN_SIZE];
	int ret;

	memcpy(buffer, (unsigned char *)ctxt->regs->rip, MAX_INSN_SIZE);

	ret = insn_decode(&ctxt->insn, buffer, MAX_INSN_SIZE, INSN_MODE_64);
	if (ret < 0)
		return ES_DECODE_FAILED;
	else
		return ES_OK;
}

static enum es_result vc_init_em_ctxt(struct es_em_ctxt *ctxt,
				      struct ex_regs *regs,
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
	ctxt->regs->rip += ctxt->insn.length;
}

static inline void sev_es_wr_ghcb_msr(u64 val)
{
	wrmsr(MSR_AMD64_SEV_ES_GHCB, val);
}

static enum es_result sev_es_ghcb_hv_call(struct ghcb *ghcb,
					  struct es_em_ctxt *ctxt,
					  u64 exit_code, u64 exit_info_1,
					  u64 exit_info_2)
{
	enum es_result ret;

	/* Fill in protocol and format specifiers */
	ghcb->protocol_version = GHCB_PROTOCOL_MAX;
	ghcb->ghcb_usage       = GHCB_DEFAULT_USAGE;

	ghcb_set_sw_exit_code(ghcb, exit_code);
	ghcb_set_sw_exit_info_1(ghcb, exit_info_1);
	ghcb_set_sw_exit_info_2(ghcb, exit_info_2);

	sev_es_wr_ghcb_msr(__pa(ghcb));
	VMGEXIT();

	if ((ghcb->save.sw_exit_info_1 & 0xffffffff) == 1) {
		u64 info = ghcb->save.sw_exit_info_2;
		unsigned long v;

		v = info & SVM_EVTINJ_VEC_MASK;

		/* Check if exception information from hypervisor is sane. */
		if ((info & SVM_EVTINJ_VALID) &&
		    ((v == GP_VECTOR) || (v == UD_VECTOR)) &&
		    ((info & SVM_EVTINJ_TYPE_MASK) == SVM_EVTINJ_TYPE_EXEPT)) {
			ctxt->fi.vector = v;
			if (info & SVM_EVTINJ_VALID_ERR)
				ctxt->fi.error_code = info >> 32;
			ret = ES_EXCEPTION;
		} else {
			ret = ES_VMM_ERROR;
		}
	} else if (ghcb->save.sw_exit_info_1 & 0xffffffff) {
		ret = ES_VMM_ERROR;
	} else {
		ret = ES_OK;
	}

	return ret;
}

static enum es_result vc_handle_cpuid(struct ghcb *ghcb,
				      struct es_em_ctxt *ctxt)
{
	struct ex_regs *regs = ctxt->regs;
	u32 cr4 = read_cr4();
	enum es_result ret;

	ghcb_set_rax(ghcb, regs->rax);
	ghcb_set_rcx(ghcb, regs->rcx);

	if (cr4 & X86_CR4_OSXSAVE) {
		/* Safe to read xcr0 */
		u64 xcr0;
		xgetbv_checking(XCR_XFEATURE_ENABLED_MASK, &xcr0);
		ghcb_set_xcr0(ghcb, xcr0);
	} else {
		/* xgetbv will cause #GP - use reset value for xcr0 */
		ghcb_set_xcr0(ghcb, 1);
	}

	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_CPUID, 0, 0);
	if (ret != ES_OK)
		return ret;

	if (!(ghcb_rax_is_valid(ghcb) &&
	      ghcb_rbx_is_valid(ghcb) &&
	      ghcb_rcx_is_valid(ghcb) &&
	      ghcb_rdx_is_valid(ghcb)))
		return ES_VMM_ERROR;

	regs->rax = ghcb->save.rax;
	regs->rbx = ghcb->save.rbx;
	regs->rcx = ghcb->save.rcx;
	regs->rdx = ghcb->save.rdx;

	return ES_OK;
}

static enum es_result vc_handle_msr(struct ghcb *ghcb, struct es_em_ctxt *ctxt)
{
	struct ex_regs *regs = ctxt->regs;
	enum es_result ret;
	u64 exit_info_1;

	/* Is it a WRMSR? */
	exit_info_1 = (ctxt->insn.opcode.bytes[1] == 0x30) ? 1 : 0;

	ghcb_set_rcx(ghcb, regs->rcx);
	if (exit_info_1) {
		ghcb_set_rax(ghcb, regs->rax);
		ghcb_set_rdx(ghcb, regs->rdx);
	}

	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_MSR, exit_info_1, 0);

	if ((ret == ES_OK) && (!exit_info_1)) {
		regs->rax = ghcb->save.rax;
		regs->rdx = ghcb->save.rdx;
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

/**
 * insn_has_rep_prefix() - Determine if instruction has a REP prefix
 * @insn:       Instruction containing the prefix to inspect
 *
 * Returns:
 *
 * 1 if the instruction has a REP prefix, 0 if not.
 */
static int insn_has_rep_prefix(struct insn *insn)
{
	insn_byte_t p;
	int i;

	insn_get_prefixes(insn);

	for_each_insn_prefix(insn, i, p) {
		if (p == 0xf2 || p == 0xf3)
			return 1;
	}

	return 0;
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
		*exitinfo |= (ctxt->regs->rdx & 0xffff) << 16;
		break;

	/* OUTS opcodes */
	case 0x6e:
	case 0x6f:
		*exitinfo |= IOIO_TYPE_OUTS;
		*exitinfo |= IOIO_SEG_DS;
		*exitinfo |= (ctxt->regs->rdx & 0xffff) << 16;
		break;

	/* IN immediate opcodes */
	case 0xe4:
	case 0xe5:
		*exitinfo |= IOIO_TYPE_IN;
		*exitinfo |= (u8)insn->immediate.value << 16;
		break;

	/* OUT immediate opcodes */
	case 0xe6:
	case 0xe7:
		*exitinfo |= IOIO_TYPE_OUT;
		*exitinfo |= (u8)insn->immediate.value << 16;
		break;

	/* IN register opcodes */
	case 0xec:
	case 0xed:
		*exitinfo |= IOIO_TYPE_IN;
		*exitinfo |= (ctxt->regs->rdx & 0xffff) << 16;
		break;

	/* OUT register opcodes */
	case 0xee:
	case 0xef:
		*exitinfo |= IOIO_TYPE_OUT;
		*exitinfo |= (ctxt->regs->rdx & 0xffff) << 16;
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

	if (insn_has_rep_prefix(insn))
		*exitinfo |= IOIO_REP;

	return ES_OK;
}

static enum es_result vc_handle_ioio(struct ghcb *ghcb, struct es_em_ctxt *ctxt)
{
	struct ex_regs *regs = ctxt->regs;
	u64 exit_info_1;
	enum es_result ret;

	ret = vc_ioio_exitinfo(ctxt, &exit_info_1);
	if (ret != ES_OK)
		return ret;

	if (exit_info_1 & IOIO_TYPE_STR) {
		ret = ES_VMM_ERROR;
	} else {
		/* IN/OUT into/from rAX */

		int bits = (exit_info_1 & 0x70) >> 1;
		u64 rax = 0;

		if (!(exit_info_1 & IOIO_TYPE_IN))
			rax = lower_bits(regs->rax, bits);

		ghcb_set_rax(ghcb, rax);

		ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_IOIO, exit_info_1, 0);
		if (ret != ES_OK)
			return ret;

		if (exit_info_1 & IOIO_TYPE_IN) {
			if (!ghcb_rax_is_valid(ghcb))
				return ES_VMM_ERROR;
			regs->rax = lower_bits(ghcb->save.rax, bits);
		}
	}

	return ret;
}

static enum es_result vc_handle_exitcode(struct es_em_ctxt *ctxt,
					 struct ghcb *ghcb,
					 unsigned long exit_code)
{
	enum es_result result;

	switch (exit_code) {
	case SVM_EXIT_CPUID:
		result = vc_handle_cpuid(ghcb, ctxt);
		break;
	case SVM_EXIT_MSR:
		result = vc_handle_msr(ghcb, ctxt);
		break;
	case SVM_EXIT_IOIO:
		result = vc_handle_ioio(ghcb, ctxt);
		break;
	default:
		/*
		 * Unexpected #VC exception
		 */
		result = ES_UNSUPPORTED;
	}

	return result;
}

void handle_sev_es_vc(struct ex_regs *regs)
{
	struct ghcb *ghcb = (struct ghcb *) ghcb_addr;
	unsigned long exit_code = regs->error_code;
	struct es_em_ctxt ctxt;
	enum es_result result;

	if (!ghcb) {
		/* TODO: kill guest */
		return;
	}

	vc_ghcb_invalidate(ghcb);
	result = vc_init_em_ctxt(&ctxt, regs, exit_code);
	if (result == ES_OK)
		result = vc_handle_exitcode(&ctxt, ghcb, exit_code);
	if (result == ES_OK) {
		vc_finish_insn(&ctxt);
	} else {
		printf("Unable to handle #VC exitcode, exit_code=%lx result=%x\n",
		       exit_code, result);
	}

	return;
}
