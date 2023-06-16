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

struct cc_blob_sev_info *snp_cc_blob;

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
	efi_status_t status;

	status = efi_get_system_config_table(EFI_CC_BLOB_GUID,
					     (void **)&snp_cc_blob);

	if (status != EFI_SUCCESS)
		return status;

	if (!snp_cc_blob)
		return EFI_NOT_FOUND;

	if (snp_cc_blob->magic != CC_BLOB_SEV_HDR_MAGIC)
		return EFI_UNSUPPORTED;

	return EFI_SUCCESS;
}

static inline int pvalidate(u64 vaddr, bool rmp_size,
			    bool validate)
{
	bool rmp_unchanged;
	int result;

	asm volatile(".byte 0xF2, 0x0F, 0x01, 0xFF\n\t"
		     CC_SET(c)
		     : CC_OUT(c) (rmp_unchanged), "=a" (result)
		     : "a" (vaddr), "c" (rmp_size), "d" (validate)
		     : "memory", "cc");

	if (rmp_unchanged)
		return PVALIDATE_FAIL_NOUPDATE;

	return result;
}

static efi_status_t __sev_set_pages_state_msr_proto(unsigned long vaddr,
						    unsigned long vaddr_end,
						    int operation)
{
	int ret;
	u64 val;
	unsigned long paddr;

	while (vaddr < vaddr_end) {
		/*
		 * Although identity mapped, compute GPA to use guest
		 * physical frame number (GFN) while requesting an
		 * explicit page state change.
		 */
		paddr = __pa(vaddr);

		if (operation == SNP_PAGE_STATE_SHARED) {
			/* Page invalidation happens before changing to shared */
			ret = pvalidate(vaddr, RMP_PG_SIZE_4K, false);
			if (ret) {
				printf("Failed to invalidate vaddr: 0x%lx, ret: %d\n",
				       vaddr, ret);
				return ES_UNSUPPORTED;
			}
		}

		wrmsr(SEV_ES_GHCB_MSR_INDEX,
		      GHCB_MSR_PSC_REQ_GFN(paddr >> PAGE_SHIFT, operation));

		VMGEXIT();

		val = rdmsr(SEV_ES_GHCB_MSR_INDEX);

		if (GHCB_RESP_CODE(val) != GHCB_MSR_PSC_RESP) {
			printf("Wrong PSC response code: 0x%x\n",
			       (unsigned int)GHCB_RESP_CODE(val));
			return ES_VMM_ERROR;
		}

		if (GHCB_MSR_PSC_RESP_VAL(val)) {
			printf("Failed to change page state to %s paddr: 0x%lx error: 0x%llx\n",
			       operation == SNP_PAGE_STATE_PRIVATE ? "private"
								   : "shared",
			       paddr, GHCB_MSR_PSC_RESP_VAL(val));
			return ES_VMM_ERROR;
		}

		if (operation == SNP_PAGE_STATE_PRIVATE) {
			ret = pvalidate(vaddr, RMP_PG_SIZE_4K, true);
			if (ret) {
				printf("Failed to validate vaddr: 0x%lx, ret: %d\n",
				       vaddr, ret);
				return ES_UNSUPPORTED;
			}
		}

		vaddr += PAGE_SIZE;
	}

	return ES_OK;
}

static inline void set_pte_decrypted(unsigned long vaddr, int npages)
{
	pteval_t *pte;
	unsigned long vaddr_end = vaddr + (npages * PAGE_SIZE);

	while (vaddr < vaddr_end) {
		pte = get_pte((pgd_t *)read_cr3(), (void *)vaddr);

		if (!pte)
			assert_msg(pte, "No pte found for vaddr 0x%lx", vaddr);

		/* unset c-bit */
		*pte &= ~(get_amd_sev_c_bit_mask());

		vaddr += PAGE_SIZE;
	}
}

static inline void sev_set_pages_state_msr_proto(unsigned long vaddr,
						 int npages, int operation)
{
	efi_status_t status;

	vaddr = vaddr & PAGE_MASK;
	unsigned long vaddr_end = vaddr + (npages * PAGE_SIZE);

	/*
	 * If the encryption bit is to be cleared, change the page state
	 * in the RMP table.
	 */
	if (operation == SNP_PAGE_STATE_SHARED) {
		status = __sev_set_pages_state_msr_proto(vaddr, vaddr_end,
							 operation);
		if (status != ES_OK) {
			printf("Page state change (Private->Shared) failure.\n");
			return;
		}

		set_pte_decrypted(vaddr, npages);
		flush_tlb();
	}
}

static void test_sev_snp_activation(void)
{
	efi_status_t status;

	if (rdmsr(MSR_SEV_STATUS) & SEV_SNP_ENABLED_MASK) {
		report_info("SEV-SNP is enabled");
	} else {
		report_skip("SEV-SNP is not enabled");
		return;
	}

	status = find_cc_blob_efi();
	report(status == EFI_SUCCESS, "SEV-SNP CC-blob presence");
}

static int test_read_write(unsigned long vaddr, int npages)
{
	unsigned long vaddr_end = vaddr + (npages << PAGE_SHIFT);

	while (vaddr < vaddr_end) {
		strcpy((char *)vaddr, st1);
		if (strcmp((char *)vaddr, st1))
			return 1;
		vaddr += PAGE_SIZE;
	}

	return 0;
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

static void test_sev_psc_ghcb_msr(int order)
{
	pteval_t *pte;
	unsigned long *vaddr;

	if (!amd_sev_snp_enabled())
		return;

	vaddr = alloc_pages(order);
	if (!vaddr) {
		printf("Page allocation failure.\n");
		return;
	}

	/*
	 * Page state changes using GHCB MSR protocol can only happen on
	 * 4K pages.
	 */
	force_4k_page(vaddr);
	pte = get_pte_level((pgd_t *)read_cr3(), (void *)vaddr, 1);
	if (!pte) {
		assert_msg(pte, "No pte found for vaddr %p", vaddr);
		return;
	}

	if (*pte & get_amd_sev_c_bit_mask()) {
		report_info("Private->Shared conversion test using GHCB MSR");

		/* Perform Private->Shared page state change */
		sev_set_pages_state_msr_proto((unsigned long)vaddr, 1 << order,
					      SNP_PAGE_STATE_SHARED);

		/*
		 * Access the now-shared page(s) with C-bit cleared and
		 * ensure read/writes return expected data.
		 */
		report(!test_read_write((unsigned long)vaddr, 1 << order),
		       "Write to %d unencrypted pages after private->shared conversion",
		       1 << order);
	}
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
		test_sev_psc_ghcb_msr(10);
	return report_summary();
}
