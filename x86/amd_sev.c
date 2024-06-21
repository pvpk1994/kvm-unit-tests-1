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
	efi_status_t status;

	report_info("TEST: SEV-SNP Activation test");

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

static enum es_result sev_set_pages_state_msr_proto(unsigned long vaddr,
						    int npages, int operation)
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

static int test_write(unsigned long vaddr, int npages)
{
	unsigned long vaddr_end = vaddr + (npages << PAGE_SHIFT);

	while (vaddr < vaddr_end) {
		memcpy((void *)vaddr, st1, strnlen(st1, PAGE_SIZE));
		vaddr += PAGE_SIZE;
	}

	return 0;
}

static void sev_set_pages_state(unsigned long vaddr, int npages, int op,
				struct ghcb *ghcb, bool allow_noupdate)
{
	struct snp_psc_desc desc;
	unsigned long vaddr_end;
	bool large_entry;

	vaddr &= PAGE_MASK;
	vaddr_end = vaddr + (npages << PAGE_SHIFT);

	if (IS_ALIGNED(vaddr, LARGE_PAGE_SIZE))
		large_entry = true;

	while (vaddr < vaddr_end) {
		vaddr = __sev_set_pages_state(&desc, vaddr, vaddr_end,
					      op, ghcb, large_entry,
					      allow_noupdate);
	}
}

static void snp_free_pages(int order, int npages, unsigned long vaddr,
			   struct ghcb *ghcb, bool allow_noupdate)
{
	set_pte_encrypted(vaddr, SEV_ALLOC_PAGE_COUNT);

	/* Convert pages back to default guest-owned state */
	sev_set_pages_state(vaddr, npages, SNP_PAGE_STATE_PRIVATE, ghcb,
			    allow_noupdate);

	/* Free all the associated physical pages */
	free_pages_by_order((void *)pgtable_va_to_pa(vaddr), order);
}

static void test_sev_psc_ghcb_msr(void)
{
	void *vaddr;
	efi_status_t status;

	report_info("TEST: GHCB MSR based Page state change test");

	vaddr = alloc_pages(SEV_ALLOC_ORDER);
	force_4k_page(vaddr);

	report(is_validated_private_page((unsigned long)vaddr, RMP_PG_SIZE_4K),
	       "Expected page state: Private");

	status = sev_set_pages_state_msr_proto((unsigned long)vaddr,
					       SEV_ALLOC_PAGE_COUNT,
					       SNP_PAGE_STATE_SHARED);

	report(status == ES_OK, "Private->Shared Page state change for %d pages",
	       SEV_ALLOC_PAGE_COUNT);

	/*
	 * Access the now-shared page(s) with C-bit cleared and ensure
	 * writes to these pages are successful
	 */
	report(!test_write((unsigned long)vaddr, SEV_ALLOC_PAGE_COUNT),
	       "Write to %d unencrypted 4K pages after private->shared conversion",
	       (SEV_ALLOC_PAGE_COUNT) / (1 << ORDER_4K));

	/* convert the pages back to private after PSC */
	status = sev_set_pages_state_msr_proto((unsigned long)vaddr,
					       SEV_ALLOC_PAGE_COUNT,
					       SNP_PAGE_STATE_PRIVATE);

	/* Free up all the pages */
	free_pages_by_order(vaddr, SEV_ALLOC_ORDER);
}

static void init_vpages(void)
{
	/*
	 * alloc_vpages_aligned() allocates contiguous virtual
	 * pages that grow downward from vfree_top, 0, and this is
	 * problematic for SNP related PSC tests because
	 * vaddr < vaddr_end using unsigned values causes an issue
	 * (vaddr_end is 0x0). To avoid this, allocate a dummy virtual
	 * page.
	 */
	alloc_vpages_aligned(1, 0);
}

static void test_sev_psc_ghcb_nae(void)
{
	unsigned long vaddr;
	struct ghcb *ghcb = (struct ghcb *)rdmsr(SEV_ES_GHCB_MSR_INDEX);

	report_info("TEST: GHCB Protocol based page state change test");

	vaddr = (unsigned long)vmalloc_pages(SEV_ALLOC_PAGE_COUNT,
					     SEV_ALLOC_ORDER, RMP_PG_SIZE_2M);

	report(is_validated_private_page(vaddr, RMP_PG_SIZE_2M),
	       "Expected page state: Private");

	sev_set_pages_state(vaddr, SEV_ALLOC_PAGE_COUNT, SNP_PAGE_STATE_SHARED,
			    ghcb, false);

	set_pte_decrypted(vaddr, SEV_ALLOC_PAGE_COUNT);

	report(!test_write((unsigned long)vaddr, SEV_ALLOC_PAGE_COUNT),
	       "Write to %d unencrypted 2M pages after private->shared conversion",
	       (SEV_ALLOC_PAGE_COUNT) / (1 << ORDER_2M));

	/* Convert pages from shared->private */
	set_pte_encrypted(vaddr, SEV_ALLOC_PAGE_COUNT);

	sev_set_pages_state(vaddr, SEV_ALLOC_PAGE_COUNT, SNP_PAGE_STATE_PRIVATE,
			    ghcb, false);

	report(is_validated_private_page(vaddr, RMP_PG_SIZE_2M),
	       "Expected page state: Private");

	snp_free_pages(SEV_ALLOC_ORDER, SEV_ALLOC_PAGE_COUNT, vaddr, ghcb, true);
}

static void __test_sev_psc_private(unsigned long vaddr, struct ghcb *ghcb,
				   int npages, bool allow_noupdate)
{
	set_pte_encrypted(vaddr, npages);

	/* Convert the whole 2M range back to private */
	sev_set_pages_state(vaddr, npages, SNP_PAGE_STATE_PRIVATE, ghcb,
			    allow_noupdate);

	report(is_validated_private_page(vaddr, RMP_PG_SIZE_2M),
	       "Expected page state: Private");
}

static void __test_sev_psc_shared(unsigned long vaddr, struct ghcb *ghcb,
				  int npages, bool allow_noupdate)
{
	/* Convert the whole 2M range to shared */
	sev_set_pages_state(vaddr, npages, SNP_PAGE_STATE_SHARED, ghcb,
			    allow_noupdate);

	set_pte_decrypted(vaddr, npages);

	/* Conduct a write test to ensure pages are in expected state */
	report(!test_write(vaddr, npages),
	       "Write to %d unencrypted 2M pages after private->shared conversion",
	       npages / (1 << ORDER_2M));
}

static void test_sev_psc_intermix(bool to_private)
{
	unsigned long vaddr;
	struct ghcb *ghcb = (struct ghcb *)(rdmsr(SEV_ES_GHCB_MSR_INDEX));

	/* Allocate a 2M private page */
	vaddr = (unsigned long)vmalloc_pages((SEV_ALLOC_PAGE_COUNT) / 2,
					     SEV_ALLOC_ORDER - 1, RMP_PG_SIZE_2M);

	/* Ensure pages are in private state by checking the page is private */
	report(is_validated_private_page(vaddr, RMP_PG_SIZE_2M),
	       "Expected page state: Private");

	sev_set_pages_state(vaddr, (SEV_ALLOC_PAGE_COUNT) / 2,
			    SNP_PAGE_STATE_SHARED, ghcb, false);

	set_pte_decrypted(vaddr, (SEV_ALLOC_PAGE_COUNT) / 2);

	set_pte_encrypted(vaddr, (SEV_ALLOC_PAGE_COUNT) / 2);
	/* Convert a bunch of sub-pages (256) to private and leave the rest shared */
	sev_set_pages_state(vaddr, 256, SNP_PAGE_STATE_PRIVATE, ghcb, false);

	report(is_validated_private_page(vaddr, RMP_PG_SIZE_4K),
	       "Expected page state: Private");

	/* Now convert all the pages back to private */
	if (to_private)
		__test_sev_psc_private(vaddr, ghcb, (SEV_ALLOC_PAGE_COUNT) / 2, true);
	else
		__test_sev_psc_shared(vaddr, ghcb, (SEV_ALLOC_PAGE_COUNT) / 2, true);

	/* Free up all the used pages */
	snp_free_pages(SEV_ALLOC_ORDER - 1, (SEV_ALLOC_PAGE_COUNT) / 2,
		       vaddr, ghcb, true);
}

static void test_sev_psc_intermix_to_private(void)
{
	report_info("TEST: 2M Intermixed to Private PSC test");
	test_sev_psc_intermix(true);
}

static void test_sev_psc_intermix_to_shared(void)
{
	report_info("TEST: 2M Intermixed to Shared PSC test");
	test_sev_psc_intermix(false);
}

static void test_sev_snp_psmash(void)
{
	int ret;
	unsigned long vaddr, vaddr_arr[3];
	struct snp_psc_desc desc = {0};
	struct ghcb *ghcb = (struct ghcb *)(rdmsr(SEV_ES_GHCB_MSR_INDEX));

	report_info("TEST: PSMASH and UNSMASH operations on 2M range");

	vaddr = (unsigned long)vmalloc_pages(SEV_ALLOC_PAGE_COUNT,
					     SEV_ALLOC_ORDER, RMP_PG_SIZE_2M);

	/*
	 * Create a PSC request for first PSC entry where:
	 * - guest issues an UNSMASH on a 2M private range.
	 * Hypervisor treats an UNSMASH hint from guest as a nop.
	 * So it is expected that the state of pages after conversion to
	 * be in the same state as before.
	 */
	vaddr_arr[0] = vaddr;
	add_psc_entry(&desc, 0, SNP_PAGE_STATE_UNSMASH, vaddr_arr[0],
		      true, 0);

	/*
	 * Create a PSC request for second PSC entry where:
	 * - guest issues a PSMASH on the next 2M private range.
	 * Hypervisor should also treat PSMASH hint from guest as a nop.
	 */
	vaddr_arr[1] = vaddr + LARGE_PAGE_SIZE;
	add_psc_entry(&desc, 1, SNP_PAGE_STATE_PSMASH, vaddr_arr[1],
		      true, 0);

	/*
	 * For 3rd PSC entry:
	 * Perform an UNSMASH on the PSMASH'd entry where:
	 * - guest now issues an UNSMASH on a 2M private PSMASH'd entry,
	 * but since a PSMASH/UNSMASH are noops, states of these pages
	 * should be in their original (private) states.
	 */
	vaddr_arr[2] = vaddr_arr[1];
	add_psc_entry(&desc, 2, SNP_PAGE_STATE_UNSMASH, vaddr_arr[2],
		      true, 0);

	ret = vmgexit_psc(&desc, ghcb);

	assert_msg(!ret, "VMGEXIT failed with ret value: %d", ret);

	/*
	 * Ensure the page states are still in the original (private)
	 * state after hypervisor handled PSMASH/UNSMASH operations.
	 */
	report(is_validated_private_page(vaddr, RMP_PG_SIZE_2M),
	       "Expected page state: Private");

	report(is_validated_private_page(vaddr + LARGE_PAGE_SIZE,
					 RMP_PG_SIZE_2M),
	       "Expected page state: Private");

	pvalidate_pages(&desc, vaddr_arr, true);

	/* Free up all the used pages */
	snp_free_pages(SEV_ALLOC_ORDER, SEV_ALLOC_PAGE_COUNT, vaddr,
		       ghcb, true);
}

static void __test_sev_snp_page_offset(int cur_page_offset)
{
	struct ghcb *ghcb = (struct ghcb *)(rdmsr(SEV_ES_GHCB_MSR_INDEX));
	struct snp_psc_desc desc = {0};
	unsigned long vaddr, vaddr_start;
	int ret, iter;

	/* Allocate a 2M large page */
	vaddr = (unsigned long)vmalloc_pages((SEV_ALLOC_PAGE_COUNT) / 2,
					     SEV_ALLOC_ORDER - 1,
					     RMP_PG_SIZE_2M);
	/*
	 * Create a PSC private->shared request where a non-zero
	 * cur_page offset is set to examine how hypervisor handles such
	 * requests.
	 */
	add_psc_entry(&desc, 0, SNP_PAGE_STATE_SHARED, vaddr, true,
		      cur_page_offset);

	ret = vmgexit_psc(&desc, ghcb);
	assert_msg(!ret, "VMGEXIT failed with ret value: %d", ret);

	/*
	 * Conduct a re-validation test to examine if the pages within 1
	 * to cur_page offset are still in their expected private state.
	 */
	vaddr_start = vaddr;
	for (iter = 0; iter < cur_page_offset; iter++) {
		ret = is_validated_private_page(vaddr_start, RMP_PG_SIZE_4K);
		assert_msg(ret, "Page not in expected private state");
		vaddr_start += PAGE_SIZE;
	}

	pvalidate_pages(&desc, &vaddr, true);

	/* Free up the used pages */
	snp_free_pages(SEV_ALLOC_ORDER - 1, (SEV_ALLOC_PAGE_COUNT) / 2,
		       vaddr, ghcb, true);
}

static void test_sev_snp_page_offset(void)
{
	int iter;
	/*
	 * Set a pool of current page offsets such that all
	 * possible edge-cases are covered in order to examine
	 * how hypervisor handles PSC requests with non-zero cur_page
	 * offsets.
	 */
	int cur_page_offsets[] = {0, 1, 256, 511, 512};

	report_info("TEST: Injecting non-zero current page offsets");

	for (iter = 0; iter < ARRAY_SIZE(cur_page_offsets); iter++)
		__test_sev_snp_page_offset(cur_page_offsets[iter]);
}

int main(void)
{
	int rtn;
	rtn = test_sev_activation();
	report(rtn == EXIT_SUCCESS, "SEV activation test.");
	test_sev_es_activation();
	test_sev_snp_activation();
	test_stringio();

	/* Setup a new page table via setup_vm() */
	setup_vm();
	if (amd_sev_snp_enabled()) {
		/*
		 * call init_vpages() before running any of SEV-SNP
		 * related PSC tests.
		 */
		init_vpages();
		test_sev_psc_ghcb_msr();
		test_sev_psc_ghcb_nae();
		test_sev_psc_intermix_to_private();
		test_sev_psc_intermix_to_shared();
		test_sev_snp_psmash();
		test_sev_snp_page_offset();
	}

	return report_summary();
}
