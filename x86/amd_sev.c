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

static void pvalidate_pages(struct snp_psc_desc *desc)
{
	struct psc_entry *entry;
	unsigned long vaddr;
	unsigned int size, i;
	int pvalidate_result;
	bool validate;

	for (i = 0; i <= desc->hdr.end_entry; i++) {
		entry = &desc->entries[i];

		vaddr = (unsigned long)__pa(entry->gfn << PAGE_SHIFT);
		size = entry->pagesize ? RMP_PG_SIZE_2M : RMP_PG_SIZE_4K;
		validate = entry->operation == SNP_PAGE_STATE_PRIVATE;

		pvalidate_result = pvalidate(vaddr, size, validate);
		if (pvalidate_result == PVALIDATE_FAIL_SIZE_MISMATCH &&
		    size == RMP_PG_SIZE_2M) {
			unsigned long vaddr_end = vaddr + LARGE_PAGE_SIZE;

			for (; vaddr < vaddr_end; vaddr += PAGE_SIZE) {
				pvalidate_result = pvalidate(vaddr, RMP_PG_SIZE_4K,
							     validate);
				if (pvalidate_result &&
				    pvalidate_result != PVALIDATE_FAIL_NOUPDATE)
					break;
			}
		}

		if (pvalidate_result &&
		    pvalidate_result != PVALIDATE_FAIL_NOUPDATE) {
			printf("Failed to validate address: 0x%lx ret: %d\n",
			       vaddr, pvalidate_result);
			return;
		}
	}
}

static int verify_exception(struct ghcb *ghcb)
{
	return ghcb->save.sw_exit_info_1 & GENMASK_ULL(31, 0);
}

static inline int sev_ghcb_hv_call(struct ghcb *ghcb, u64 exit_code,
				   u64 exit_info_1, u64 exit_info_2)
{
	ghcb->protocol_version = GHCB_PROTOCOL_MAX;
	ghcb->ghcb_usage = GHCB_DEFAULT_USAGE;

	ghcb_set_sw_exit_code(ghcb, exit_code);
	ghcb_set_sw_exit_info_1(ghcb, exit_info_1);
	ghcb_set_sw_exit_info_2(ghcb, exit_info_2);

	VMGEXIT();

	return verify_exception(ghcb);
}

static int vmgexit_psc(struct snp_psc_desc *desc, struct ghcb *ghcb)
{
	int cur_entry, end_entry, ret = 0;
	struct snp_psc_desc *data;

	vc_ghcb_invalidate(ghcb);

	/* Copy the input desc into GHCB shared buffer */
	data = (struct snp_psc_desc *)ghcb->shared_buffer;
	memcpy(ghcb->shared_buffer, desc, MIN(GHCB_SHARED_BUF_SIZE,
					      sizeof(*desc)));
	cur_entry = data->hdr.cur_entry;
	end_entry = data->hdr.end_entry;

	while (data->hdr.cur_entry <= data->hdr.end_entry) {
		ghcb_set_sw_scratch(ghcb, (u64)__pa(data));

		/* Advance shared buffer data points to.. */
		ret = sev_ghcb_hv_call(ghcb, SVM_VMGEXIT_PSC, 0, 0);

		/*
		 * Page state change VMGEXIT passes error code to
		 * exit_info_2.
		 */
		if (ret || ghcb->save.sw_exit_info_2) {
			printf("SNP: PSC failed ret=%d exit_info_2=%lx\n",
			       ret, ghcb->save.sw_exit_info_2);
			ret = 1;
			break;
		}

		if (data->hdr.end_entry > end_entry ||
		    cur_entry > data->hdr.cur_entry) {
			printf("SNP: PSC processing going backward, end_entry %d (got %d) cur_entry %d (got %d)\n",
			       end_entry, data->hdr.end_entry,
			       cur_entry, data->hdr.cur_entry);
			ret = 1;
			break;
		}

		if (data->hdr.reserved) {
			printf("Reserved bit is set in the PSC header\n");
			ret = 1;
			break;
		}
	}

	return ret;
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

static inline void set_pte_encrypted(unsigned long vaddr, int npages)
{
	pteval_t *pte;
	unsigned long vaddr_end = vaddr + (npages * PAGE_SIZE);

	while (vaddr < vaddr_end) {
		pte = get_pte((pgd_t *)read_cr3(), (void *)vaddr);

		if (!pte)
			assert_msg(pte, "No pte found for vaddr 0x%lx", vaddr);

		/* Set C-bit */
		*pte |= get_amd_sev_c_bit_mask();

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
	} else {
		set_pte_encrypted(vaddr, npages);
		flush_tlb();

		status = __sev_set_pages_state_msr_proto(vaddr, vaddr_end,
							 operation);
		if (status != ES_OK) {
			printf("Page state change (Shared->Private failure.\n");
			return;
		}
	}
}

static unsigned long __sev_set_pages_state(struct snp_psc_desc *desc,
					   unsigned long vaddr, unsigned long vaddr_end,
					   int op, struct ghcb *ghcb, bool large_entry)
{
	struct psc_hdr *hdr;
	struct psc_entry *entry;
	unsigned long pfn;
	int iter, ret;

	hdr = &desc->hdr;
	entry = desc->entries;

	memset(desc, 0, sizeof(*desc));
	iter = 0;

	while (vaddr < vaddr_end && iter < ARRAY_SIZE(desc->entries)) {
		hdr->end_entry = iter;
		pfn = __pa(vaddr) >> PAGE_SHIFT;
		entry->gfn = pfn;
		entry->operation = op;

		if (large_entry && IS_ALIGNED(vaddr, LARGE_PAGE_SIZE) &&
		    (vaddr_end - vaddr) >= LARGE_PAGE_SIZE) {
			entry->pagesize = RMP_PG_SIZE_2M;
			vaddr += LARGE_PAGE_SIZE;
		} else {
			entry->pagesize = RMP_PG_SIZE_4K;
			vaddr += PAGE_SIZE;
		}

		entry++;
		iter++;
	}

	if (op == SNP_PAGE_STATE_SHARED)
		pvalidate_pages(desc);

	ret = vmgexit_psc(desc, ghcb);
	if (ret) {
		printf("VMGEXIT failed with ret: %d\n", ret);
		return 0;
	}

	if (op == SNP_PAGE_STATE_PRIVATE)
		pvalidate_pages(desc);

	return vaddr;
}

static void sev_set_pages_state(unsigned long vaddr, unsigned long npages,
				int op, struct ghcb *ghcb, bool large_entry)
{
	struct snp_psc_desc desc;
	unsigned long vaddr_end;

	vaddr = vaddr & PAGE_MASK;
	vaddr_end = vaddr + (npages << PAGE_SHIFT);

	while (vaddr < vaddr_end)
		vaddr = __sev_set_pages_state(&desc, vaddr, vaddr_end, op,
					      ghcb, large_entry);
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

	report_info("Shared->Private conversion test using GHCB MSR");
	sev_set_pages_state_msr_proto((unsigned long)vaddr, 1 << order,
				      SNP_PAGE_STATE_PRIVATE);

	/*
	 * Access the now-private page(s) with C-bit set and ensure
	 * read/writes return expected data.
	 */
	report(!test_read_write((unsigned long)vaddr, 1 << order),
	       "Write to %d encrypted pages after shared->private conversion",
	       1 << order);

}

static int validate_page_state(u64 vaddr, bool rmp_size, bool state)
{
	int i;
	int npages = rmp_size ? 512 : 1;

	for (i = 0; i < npages; i++) {
		int ret = pvalidate(vaddr, rmp_size, state);

		if (ret != PVALIDATE_FAIL_NOUPDATE)
			return ret;
	}

	return 0;
}

static void test_sev_psc_ghcb_nae(int order)
{
	pteval_t *pte;
	bool large_page = false;
	unsigned long *vm_pages;
	struct ghcb *ghcb = (struct ghcb *)(rdmsr(SEV_ES_GHCB_MSR_INDEX));

	/* Allocates 1 << order pages */
	vm_pages = alloc_pages(order);
	if (!vm_pages) {
		printf("Page allocation failure.\n");
		return;
	}

	pte = get_pte_level((pgd_t *)read_cr3(), (void *)vm_pages, 1);
	if (!pte && IS_ALIGNED((unsigned long)vm_pages,
			       LARGE_PAGE_SIZE)) {
		report_info("Installing a large 2M page");
		/* Install 2M large page */
		install_large_page((pgd_t *)read_cr3(),
				   (phys_addr_t)vm_pages, (void *)(ulong)vm_pages);
		large_page = true;
	}

	report_info("Private->Shared conversion test using GHCB NAE");

	/* Private->Shared operations */
	sev_set_pages_state((unsigned long)vm_pages, 1 << order,
			    SNP_PAGE_STATE_SHARED, ghcb, large_page);

	set_pte_decrypted((unsigned long)vm_pages, 1 << order);
	flush_tlb();

	report(!test_read_write((unsigned long)vm_pages, 1 << order),
	       "Write to %d un-encrypted pages after private->shared conversion",
	       1 << order);

	/* Shared->Private operations */
	report_info("Shared->Private conversion test using GHCB NAE");

	set_pte_encrypted((unsigned long)vm_pages, 1 << order);
	flush_tlb();

	sev_set_pages_state((unsigned long)vm_pages, 1 << order,
			    SNP_PAGE_STATE_PRIVATE, ghcb, large_page);
	report(!test_read_write((unsigned long)vm_pages, 1 << order),
	       "Write to %d encrypted pages after shared->private conversion",
	       1 << order);
}

static void __test_sev_psc_private(unsigned long vaddr, struct ghcb *ghcb,
				   bool large_page, pteval_t *pte)
{
	/* Set c-bit on 2M PMD */
	*pte |= get_amd_sev_c_bit_mask();
	flush_tlb();

	/* Step-3: Convert whole 2M range back to private */
	sev_set_pages_state(vaddr, 512, SNP_PAGE_STATE_PRIVATE, ghcb,
			    large_page);

	report(!test_read_write(vaddr, 512), "Write to 2M encrypted range");
}

static void __test_sev_psc_shared(unsigned long vaddr, struct ghcb *ghcb,
				  bool large_page, pteval_t *pte)
{
	int ret;
	/*
	 * Conversion to 2M private->shared will generate a #PF exception,
	 * since the c-bit is currently unset on the PMD.
	 * Reset it.
	 */
	*pte |= get_amd_sev_c_bit_mask();
	flush_tlb();

	sev_set_pages_state(vaddr, 512, SNP_PAGE_STATE_PRIVATE, ghcb,
			    large_page);

	ret = validate_page_state(vaddr, large_page, SNP_PAGE_STATE_PRIVATE);

	if (ret == PVALIDATE_FAIL_SIZE_MISMATCH)
		report_info("Page size mismatch between guest(2M) and RMP entry(4K)");

	/* Step-3: Convert the whole range from private to shared */
	sev_set_pages_state(vaddr, 512, SNP_PAGE_STATE_SHARED, ghcb,
			    large_page);

	/* Unset the c-bit before writing into these shared pages */
	*pte &= ~(get_amd_sev_c_bit_mask());
	flush_tlb();

	report(!test_read_write(vaddr, 512), "Write to 2M un-encrypted range");
}

static void test_sev_psc_intermix(bool is_private)
{
	unsigned long *vm_page;
	bool large_page = false;
	pteval_t *pte;
	struct ghcb *ghcb = (struct ghcb *)(rdmsr(SEV_ES_GHCB_MSR_INDEX));

	/* Allocate 2^9 = 1 2M page */
	vm_page = alloc_pages(9);
	if (!vm_page) {
		printf("Page allocation failure.\n");
		return;
	}

	pte = get_pte_level((pgd_t *)read_cr3(), (void *)vm_page, 1);
	if (pte) {
		report_skip("This test needs large page allocation only");
		return;
	}

	if (!pte && IS_ALIGNED((unsigned long)vm_page, LARGE_PAGE_SIZE)) {
		install_large_page((pgd_t *)read_cr3(), (phys_addr_t)vm_page,
				   (void *)(ulong)vm_page);
		large_page = true;
	}

	/* Step-1: Convert the 2M range into shared */
	sev_set_pages_state((unsigned long)vm_page, 512,
			    SNP_PAGE_STATE_SHARED, ghcb,
			    large_page);

	pte = get_pte_level((pgd_t *)read_cr3(), (void *)vm_page, 2);
	if (!pte) {
		assert_msg(pte, "Invalid PTE");
		return;
	}

	/* Unset c-bit on 2M PMD after step-1 */
	*pte &= ~(get_amd_sev_c_bit_mask());
	flush_tlb();

	report(!test_read_write((unsigned long)vm_page, 512),
	       "Write to a 2M un-encrypted range");

	*pte |= get_amd_sev_c_bit_mask();
	flush_tlb();

	/*
	 * Step-2: Convert half sub-pages into private and leave other
	 * half in shared states.
	 */
	sev_set_pages_state((unsigned long)vm_page, 256,
			    SNP_PAGE_STATE_PRIVATE, ghcb, false);

	report(!validate_page_state((unsigned long)vm_page, false,
				    SNP_PAGE_STATE_PRIVATE),
	       "Page state expected: Private");

	report(!test_read_write((unsigned long)vm_page, 256),
	       "Write to 256 4K private pages within 2M un-encrpyted page");

	/*
	 * Unset C-bit on PMD and now try writing to the sub-pages that
	 * are currently in shared state.
	 */
	*pte &= ~(get_amd_sev_c_bit_mask());
	flush_tlb();

	report(!test_read_write((unsigned long)vm_page + 256 * PAGE_SIZE, 256),
	       "Write to 256 4K shared pages within 2M un-encrypted page");

	is_private ?
	__test_sev_psc_private((unsigned long)vm_page, ghcb, large_page, pte) :
	__test_sev_psc_shared((unsigned long)vm_page, ghcb, large_page, pte);
}

int main(void)
{
	int rtn;
	bool is_private = false;

	rtn = test_sev_activation();
	report(rtn == EXIT_SUCCESS, "SEV activation test.");
	test_sev_es_activation();
	test_sev_snp_activation();
	test_stringio();
	setup_vm();

	if (amd_sev_snp_enabled()) {
		test_sev_psc_ghcb_msr(10);
		test_sev_psc_ghcb_nae(15);
		test_sev_psc_intermix(is_private);
	}
	return report_summary();
}
