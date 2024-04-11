// SPDX-License-Identifier: GPL-2.0

#include "amd_sev.h"

extern phys_addr_t ghcb_addr;

void handle_sev_es_vc(struct ex_regs *regs)
{
	struct ghcb *ghcb = (struct ghcb *) ghcb_addr;

	if (!ghcb) {
		/* TODO: kill guest */
		return;
	}
}
