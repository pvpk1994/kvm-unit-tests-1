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

extern phys_addr_t ghcb_addr;

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

	return rmp_unchanged ? 1 : result;
}

static inline efi_status_t __page_state_change(unsigned long paddr,
					       enum psc_op op)
{
	u64 val;

	/* Save the old GHCB MSR */
	phys_addr_t ghcb_old_msr = rdmsr(SEV_ES_GHCB_MSR_INDEX);

	/*
	 * If action requested is to convert the page from private to
	 * shared, then invalidate the page before we send it to
	 * hypervisor to change the state of page in RMP table.
	 */
	if (op == SNP_PAGE_STATE_SHARED &&
	    pvalidate(paddr, RMP_PG_SIZE_4K, 0))
		return ES_UNSUPPORTED;

	/*
	 * Now issue VMGEXIT to change the state of the page in RMP
	 * table
	 */
	wrmsr(SEV_ES_GHCB_MSR_INDEX,
	      GHCB_MSR_PSC_REQ_GFN(paddr >> PAGE_SHIFT, op));

	VMGEXIT();

	val = rdmsr(SEV_ES_GHCB_MSR_INDEX);

	/* Restore the old GHCB MSR */
	wrmsr(SEV_ES_GHCB_MSR_INDEX, ghcb_old_msr);

	if (GHCB_RESP_CODE(val) != GHCB_MSR_PSC_RESP ||
	    GHCB_MSR_PSC_RESP_VAL(val)) {
		return ES_VMM_ERROR;
	}

	/*
	 * PSC is successful in the RMP table, validate the page in the
	 * guest so that it is consistent with the RMP entry.
	 */
	if (op == SNP_PAGE_STATE_PRIVATE &&
	    pvalidate(paddr, RMP_PG_SIZE_4K, 1)) {
		return ES_UNSUPPORTED;
	}

	return ES_OK;
}

static inline efi_status_t snp_set_page_shared_ghcb_msr(unsigned long paddr)
{
	return __page_state_change(paddr, SNP_PAGE_STATE_SHARED);
}

static inline void unset_c_bit_pte(unsigned long vaddr)
{
	pteval_t *pte;

	pte = get_pte((pgd_t *)read_cr3(), (void *)vaddr);

	if (!pte) {
		printf("WARNING: pte is null.\n");
		assert(pte);
	}

	/* unset c-bit */
	*pte &= ~(get_amd_sev_c_bit_mask());
}

static inline void set_page_decrypted(unsigned long vaddr)
{
	efi_status_t status;

	/*
	 * If the encryption bit is to be cleared, change the page state
	 * in the RMP table.
	 */
	status = snp_set_page_shared_ghcb_msr(__pa(vaddr & PAGE_MASK));
	if (status != ES_OK) {
		printf("Page state change (Private->Shared) failure.\n");
		return;
	}

	flush_tlb();
	unset_c_bit_pte(vaddr);
	flush_tlb();
}

static void test_sev_snp_activation(void)
{
	efi_status_t status;

	if (!amd_sev_snp_enabled()) {
		printf("SEV-SNP is not enabled.\n");
		return;
	}

	printf("SEV-SNP is enabled.\n");

	status = find_cc_blob_efi();
	if (status != EFI_SUCCESS) {
		printf("WARNING: SEV-SNP CC blob is NOT present.\n");
		return;
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

static void test_page_state_change(void)
{
	pteval_t *pte;
	unsigned long *vaddr;

	if (!amd_sev_snp_enabled())
		return;

	vaddr = alloc_page();
	if (!vaddr) {
		printf("Page allocation failure.\n");
		return;
	}

	/*
	 * Page state change using GHCB MSR protocol can only happen on
	 * 4K page.
	 */
	force_4k_page(vaddr);
	pte = get_pte_level((pgd_t *)read_cr3(), (void *)vaddr, 1);
	if (pte == NULL) {
		printf("No pte found.\n");
		return;
	}

	if (*pte & get_amd_sev_c_bit_mask()) {
		printf("Private->Shared conversion test.\n");
		/* Perform Private->Shared page state change */
		strcpy((char *)vaddr, st1);
		report(!strcmp((char *)vaddr, st1), "Write to encrypted page before private->shared conversion");

		set_page_decrypted((unsigned long)vaddr);

		strcpy((char *)vaddr, st1);
		report(!strcmp((char *)vaddr, st1), "Write to unencrypted page after private->shared conversion");
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
	test_page_state_change();
	return report_summary();
}
