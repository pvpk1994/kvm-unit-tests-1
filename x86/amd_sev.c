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
#include "vmalloc.h"
#include "x86/vm.h"
#include "alloc_page.h"

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

/* Check to find if SEV-SNP's Confidential Computing Blob is present */
static efi_status_t find_cc_blob_efi(void)
{
	struct cc_blob_sev_info *snp_cc_blob;
	efi_status_t status;

	status = efi_get_system_config_table(EFI_CC_BLOB_GUID,
					     (void **)&snp_cc_blob);

	if (status != EFI_SUCCESS)
		return status;

	if (!snp_cc_blob) {
		printf("SEV-SNP CC blob not found\n");
		return EFI_NOT_FOUND;
	}

	if (snp_cc_blob->magic != CC_BLOB_SEV_HDR_MAGIC) {
		printf("SEV-SNP CC blob header/signature mismatch");
		return EFI_UNSUPPORTED;
	}

	return EFI_SUCCESS;
}

static void test_sev_snp_activation(void)
{
	report_info("TEST: SEV-SNP Activation test");

	efi_status_t status;

	if (!(rdmsr(MSR_SEV_STATUS) & SEV_SNP_ENABLED_MASK)) {
		report_skip("SEV-SNP is not enabled");
		return;
	}

	report_info("SEV-SNP is enabled");

	status = find_cc_blob_efi();
	report(status == EFI_SUCCESS, "SEV-SNP CC-blob presence");
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

static efi_status_t sev_set_pages_state_msr_proto(unsigned long vaddr, int npages,
						  int operation)
{
	efi_status_t status;

	vaddr &= PAGE_MASK;

	if (operation == SNP_PAGE_STATE_SHARED) {
		status = __sev_set_pages_state_msr_proto(vaddr, npages, operation);

		if (status != ES_OK) {
			printf("Page state change (private->shared) failure");
			return status;
		}

		set_pte_decrypted(vaddr, npages);
	} else {
		set_pte_encrypted(vaddr, npages);

		status = __sev_set_pages_state_msr_proto(vaddr, npages, operation);

		if (status != ES_OK) {
			printf("Page state change (shared->private) failure.\n");
			return status;
		}
	}

	return ES_OK;
}

static void test_sev_psc_ghcb_msr(void)
{
	report_info("TEST: GHCB MSR based Page state change test");

	void *vaddr;
	efi_status_t status;

	vaddr = alloc_pages(SEV_ALLOC_ORDER);
	force_4k_page(vaddr);

	report(is_validated_private_page((unsigned long)vaddr, RMP_PG_SIZE_4K, true),
	       "Expected page state: Private");

	status = sev_set_pages_state_msr_proto((unsigned long)vaddr, NUM_SEV_PAGES,
					       SNP_PAGE_STATE_SHARED);

	report(status == ES_OK, "Private->Shared Page state change for %d pages",
	       NUM_SEV_PAGES);

	/* Convert the pages back to private after PSC */
	status = sev_set_pages_state_msr_proto((unsigned long)vaddr,
					       NUM_SEV_PAGES,
					       SNP_PAGE_STATE_PRIVATE);

	/* Free up all the pages */
	free_pages_by_order(vaddr, SEV_ALLOC_ORDER);
}

int main(void)
{
	int rtn;
	rtn = test_sev_activation();
	report(rtn == EXIT_SUCCESS, "SEV activation test.");
	test_sev_es_activation();
	test_sev_snp_activation();
	test_stringio();
	setup_vm();
	if (amd_sev_snp_enabled())
		test_sev_psc_ghcb_msr();

	return report_summary();
}
