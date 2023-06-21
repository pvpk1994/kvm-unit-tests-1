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

static enum es_result vc_handle_exitcode(struct es_em_ctxt *ctxt,
					 struct ghcb *ghcb,
					 unsigned long exit_code)
{
	enum es_result result;

	switch (exit_code) {
	case SVM_EXIT_CPUID:
		result = vc_handle_cpuid(ghcb, ctxt);
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
