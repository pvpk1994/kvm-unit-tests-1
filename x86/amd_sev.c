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
bool large_entry, allow_noupdate;

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

static void sev_set_pages_state(unsigned long vaddr, int npages, int op,
				struct ghcb *ghcb)
{
	struct snp_psc_desc desc;
	unsigned long vaddr_end;

	vaddr &= PAGE_MASK;
	vaddr_end = vaddr + (npages << PAGE_SHIFT);

	if (IS_ALIGNED(vaddr, LARGE_PAGE_SIZE))
		large_entry = true;

	while (vaddr < vaddr_end)
		vaddr = __sev_set_pages_state(&desc, vaddr, vaddr_end,
					      op, ghcb);
}

static void snp_free_pages(int order, int npages, unsigned long vaddr,
			   struct ghcb *ghcb)
{
	set_pte_encrypted(vaddr, NUM_SEV_PAGES);

	/* Convert pages back to default guest-owned state */
	sev_set_pages_state(vaddr, npages, SNP_PAGE_STATE_PRIVATE,
			    ghcb);

	/* Free all the associated physical pages */
	free_pages_by_order((void *)va_to_pa(vaddr), order);

	/* unset large_entry (if set) */
	large_entry = false;

	/* unset allow_noupdate */
	allow_noupdate = false;
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

static int test_write(unsigned long vaddr, int npages)
{
	unsigned long vaddr_end = vaddr + (npages << PAGE_SHIFT);

	while (vaddr < vaddr_end) {
		memcpy((void *)vaddr, st1, strnlen(st1, PAGE_SIZE));
		vaddr += PAGE_SIZE;
	}

	return 0;
}

static void test_sev_psc_ghcb_nae(void)
{
	report_info("TEST: GHCB Protocol based Page state change test");

	unsigned long vaddr;
	struct ghcb *ghcb = (struct ghcb *)(rdmsr(SEV_ES_GHCB_MSR_INDEX));

	vaddr = snp_alloc_pages(NUM_SEV_PAGES, SEV_ALLOC_ORDER,
				RMP_PG_SIZE_2M);

	report(is_validated_private_page(vaddr, RMP_PG_SIZE_2M, true),
	       "Expected page state: Private");

	sev_set_pages_state(vaddr, NUM_SEV_PAGES, SNP_PAGE_STATE_SHARED, ghcb);

	set_pte_decrypted(vaddr, NUM_SEV_PAGES);

	report(!test_write((unsigned long)vaddr, NUM_SEV_PAGES),
	       "Write to %d unencrypted pages after private->shared conversion",
	       NUM_SEV_PAGES);

	/* Convert pages from shared->private */
	set_pte_encrypted(vaddr, NUM_SEV_PAGES);

	sev_set_pages_state(vaddr, NUM_SEV_PAGES, SNP_PAGE_STATE_PRIVATE, ghcb);

	report(is_validated_private_page(vaddr, RMP_PG_SIZE_2M, true),
	       "Expected page state: Private");

	allow_noupdate = true;

	snp_free_pages(SEV_ALLOC_ORDER, NUM_SEV_PAGES, vaddr, ghcb);
}

static void __test_sev_psc_private(unsigned long vaddr, struct ghcb *ghcb,
				   int npages)
{
	allow_noupdate = true;

	set_pte_encrypted(vaddr, npages);

	/* Convert the whole 2M range back to private */
	sev_set_pages_state(vaddr, NUM_SEV_PAGES, SNP_PAGE_STATE_PRIVATE, ghcb);

	report(is_validated_private_page(vaddr, RMP_PG_SIZE_2M, true),
	       "Expected page state: Private");
}

static void __test_sev_psc_shared(unsigned long vaddr, struct ghcb *ghcb,
				  int npages)
{
	allow_noupdate = true;

	/* Convert the whole 2M range to shared */
	sev_set_pages_state(vaddr, npages, SNP_PAGE_STATE_SHARED, ghcb);

	set_pte_decrypted(vaddr, npages);

	/* Conduct a write test to ensure pages are in expected state */
	report(!test_write(vaddr, npages),
	       "Write to %d unencrypted pages after private->shared conversion",
	       npages);
}

static void test_sev_psc_intermix(bool is_private)
{
	unsigned long vaddr;
	struct ghcb *ghcb = (struct ghcb *)(rdmsr(SEV_ES_GHCB_MSR_INDEX));

	vaddr = snp_alloc_pages(NUM_SEV_PAGES, SEV_ALLOC_ORDER,
				RMP_PG_SIZE_2M);

	/* Ensure pages are in private state by checking 1st page is private */
	report(is_validated_private_page(vaddr, RMP_PG_SIZE_2M, true),
	       "Expected page state: Private");

	sev_set_pages_state(vaddr, NUM_SEV_PAGES, SNP_PAGE_STATE_SHARED, ghcb);

	set_pte_decrypted(vaddr, NUM_SEV_PAGES);

	/* Convert a bunch of sub-pages to private and leave the rest in shared */
	set_pte_encrypted(vaddr, NUM_SEV_PAGES);
	sev_set_pages_state(vaddr, 256, SNP_PAGE_STATE_PRIVATE, ghcb);

	report(is_validated_private_page(vaddr, RMP_PG_SIZE_4K, true),
	       "Expected page state: Private");

	/* Now convert all the pages back to private */
	if (is_private)
		__test_sev_psc_private(vaddr, ghcb, NUM_SEV_PAGES);
	else
		__test_sev_psc_shared(vaddr, ghcb, NUM_SEV_PAGES);

	/* Free up all the used pages */
	snp_free_pages(SEV_ALLOC_ORDER, NUM_SEV_PAGES, vaddr, ghcb);
}

static void test_sev_psc_mix_to_pvt(void)
{
	report_info("TEST: 2M Intermixed to Private PSC test");
	test_sev_psc_intermix(true);
}

static void test_sev_psc_mix_to_shared(void)
{
	report_info("TEST: 2M Intermixed to Shared PSC test");
	test_sev_psc_intermix(false);
}

static void test_sev_snp_smash(void)
{
	report_info("TEST: PSMASH and UNSMASH operations on 2M range");

	int ret;
	unsigned long vaddr, vaddr_arr[3];
	struct snp_psc_desc desc = {0};
	struct ghcb *ghcb = (struct ghcb *)(rdmsr(SEV_ES_GHCB_MSR_INDEX));

	/*
	 * Allocate 2 2M-aligned large pages. Do not use
	 * SEV_ALLOC_ORDER/NUM_SEV_PAGES as any changes to these
	 * variables might end up blowing this test that deals with
	 * individual add_psc_entry()'s.
	 */
	vaddr = snp_alloc_pages(1 << 10, 10, RMP_PG_SIZE_2M);

	/*
	 * Create a PSC request where:
	 * - First entry requests HV to UNSMASH 1st 2M range.
	 * - Second entry requests HV to SMASH 2nd 2M range.
	 * - Second entry again requests HV to UNSMASH 2nd 2M range.
	 */
	vaddr_arr[0] = vaddr;
	add_psc_entry(&desc, 0, SNP_PAGE_STATE_UNSMASH, vaddr_arr[0],
		      true, 0);
	vaddr_arr[1] = vaddr + LARGE_PAGE_SIZE;
	add_psc_entry(&desc, 1, SNP_PAGE_STATE_PSMASH, vaddr_arr[1],
		      true, 0);
	vaddr_arr[2] = vaddr_arr[1];
	add_psc_entry(&desc, 2, SNP_PAGE_STATE_UNSMASH, vaddr_arr[2],
		      true, 0);

	ret = vmgexit_psc(&desc, ghcb);

	assert_msg(!ret, "VMGEXIT failed with ret value: %d", ret);

	/*
	 * Ensure the page states are still private after
	 * requesting PSMASH/UNSMASH operation.
	 */
	report(is_validated_private_page(vaddr, RMP_PG_SIZE_2M, true),
	       "Expected page state: Private");

	allow_noupdate = true;
	pvalidate_pages(&desc, vaddr_arr);

	/* Free up all the used pages */
	snp_free_pages(10, 1 << 10, vaddr, ghcb);
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
	if (amd_sev_snp_enabled()) {
		test_sev_psc_ghcb_msr();
		test_sev_psc_ghcb_nae();
		test_sev_psc_mix_to_pvt();
		test_sev_psc_mix_to_shared();
		test_sev_snp_smash();
	}

	return report_summary();
}
