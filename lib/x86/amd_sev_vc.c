// SPDX-License-Identifier: GPL-2.0
/*
 * AMD SEV-ES #VC exception handling.
 * Adapted from Linux@6d7d0603ca:
 * - arch/x86/kernel/sev.c
 * - arch/x86/kernel/sev-shared.c
 */

#include "amd_sev.h"
#include "svm.h"

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

static enum es_result vc_handle_exitcode(struct es_em_ctxt *ctxt,
					 struct ghcb *ghcb,
					 unsigned long exit_code)
{
	enum es_result result;

	switch (exit_code) {
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
