/*
 * AMD SEV test cases
 *
 * Copyright (c) 2021, Google Inc
 *
 * Authors:
 *   Hyunwook (Wooky) Baek <baekhw@google.com>
 *   Zixuan Wang <zixuanwang@google.com>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "libcflat.h"
#include "x86/processor.h"
#include "x86/amd_sev.h"
#include "msr.h"
#include "alloc_page.h"
#include "x86/vm.h"

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define TESTDEV_IO_PORT 0xe0

static char st1[] = "abcdefghijklmnop";

static int test_sev_activation(void)
{
	struct cpuid cpuid_out;
	u64 msr_out;

	printf("SEV activation test is loaded.\n");

	/* Tests if CPUID function to check SEV is implemented */
	cpuid_out = cpuid(CPUID_FN_LARGEST_EXT_FUNC_NUM);
	printf("CPUID Fn8000_0000[EAX]: 0x%08x\n", cpuid_out.a);
	if (cpuid_out.a < CPUID_FN_ENCRYPT_MEM_CAPAB) {
		printf("CPUID does not support FN%08x\n",
		       CPUID_FN_ENCRYPT_MEM_CAPAB);
		return EXIT_FAILURE;
	}

	/* Tests if SEV is supported */
	cpuid_out = cpuid(CPUID_FN_ENCRYPT_MEM_CAPAB);
	printf("CPUID Fn8000_001F[EAX]: 0x%08x\n", cpuid_out.a);
	printf("CPUID Fn8000_001F[EBX]: 0x%08x\n", cpuid_out.b);
	if (!(cpuid_out.a & SEV_SUPPORT_MASK)) {
		printf("SEV is not supported.\n");
		return EXIT_FAILURE;
	}
	printf("SEV is supported\n");

	/* Tests if SEV is enabled */
	msr_out = rdmsr(MSR_SEV_STATUS);
	printf("MSR C001_0131[EAX]: 0x%08lx\n", msr_out & 0xffffffff);
	if (!(msr_out & SEV_ENABLED_MASK)) {
		printf("SEV is not enabled.\n");
		return EXIT_FAILURE;
	}
	printf("SEV is enabled\n");

	return EXIT_SUCCESS;
}

static void test_sev_es_activation(void)
{
	if (rdmsr(MSR_SEV_STATUS) & SEV_ES_ENABLED_MASK) {
		printf("SEV-ES is enabled.\n");
	} else {
		printf("SEV-ES is not enabled.\n");
	}
}

static void test_stringio(void)
{
	int st1_len = sizeof(st1) - 1;
	u16 got;

	asm volatile("cld \n\t"
		     "movw %0, %%dx \n\t"
		     "rep outsw \n\t"
		     : : "i"((short)TESTDEV_IO_PORT),
		         "S"(st1), "c"(st1_len / 2));

	asm volatile("inw %1, %0\n\t" : "=a"(got) : "i"((short)TESTDEV_IO_PORT));

	report((got & 0xff) == st1[sizeof(st1) - 3], "outsb nearly up");
	report((got & 0xff00) >> 8 == st1[sizeof(st1) - 2], "outsb up");
}

enum es_result hv_snp_ap_feature_check(struct ghcb *ghcb_page)
{
	u64 result = get_hv_features(ghcb_page);

	/* Check for hypervisor SEV-SNP feature support */
	if (!(result & GHCB_HV_FT_SNP)) {
		printf("Hypervisor SEV-SNP feature not supported.\n");
		return ES_VMM_ERROR;
	}

	/* Now check for hypervisor SEV-SNP AP creation feature support */
	if (!(result & GHCB_HV_FT_SNP_AP_CREATION)) {
		printf("Hypervisor SEV-SNP AP creation feature not supported.\n");
		return ES_UNSUPPORTED;
	}

	return ES_OK;
}

int main(void)
{
	int rtn;
	unsigned long *vaddr;

	struct ghcb *ghcb_page = (struct ghcb *)(rdmsr(SEV_ES_GHCB_MSR_INDEX));

	rtn = test_sev_activation();
	report(rtn == EXIT_SUCCESS, "SEV activation test.");
	test_sev_es_activation();
	test_stringio();

	if (!amd_sev_snp_enabled()) {
		printf("SEV-SNP not enabled.\n");
		return 0;
	}

	printf("SEV-SNP is enabled.\n");

	/* Perform AP support feature check */
	if (!hv_snp_ap_feature_check(ghcb_page))
		printf("SEV-SNP AP Creation feature supported by hypervisor.\n");

	setup_vm();
	vaddr = alloc_page();
	force_4k_page(vaddr);
	rtn = set_page_decrypted_ghcb_msr((unsigned long)vaddr);

	if (!rtn)
		printf("Page state change successful.\n");

	return report_summary();
}
