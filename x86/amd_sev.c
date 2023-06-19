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
#include "alloc.h"
#include "alloc_page.h"
#include "x86/vm.h"

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define TESTDEV_IO_PORT 0xe0

#define CPUID_EXTENDED_STATE	0xd

#define _PAGE_ENC	(_AT(pteval_t, get_amd_sev_c_bit_mask()))

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

static void copy_cpuid_leaf(struct cpuid_leaf *leaf, struct cpuid g_cpuid,
			    u32 eax_input, u32 ecx_input)
{
	leaf->eax_in = eax_input;
	leaf->ecx_in = ecx_input;
	leaf->eax = g_cpuid.a;
	leaf->ebx = g_cpuid.b;
	leaf->ecx = g_cpuid.c;
	leaf->edx = g_cpuid.d;
}

inline bool compare_cpuid(struct cpuid_leaf cpuid0, struct cpuid_leaf cpuid1)
{
	return cpuid0.eax == cpuid1.eax && cpuid0.ebx == cpuid1.ebx &&
	       cpuid0.ecx == cpuid1.ecx && cpuid0.edx == cpuid1.edx;
}

/* Fetch CPUID leaf from Hypervisor, via VMGEXIT using GHCB page */
static uint64_t fetch_cpuid_hyp(struct ghcb *ghcb, struct cpuid_leaf *leaf)
{
	uint64_t status = 0;

	ghcb_set_rax(ghcb, leaf->eax_in);
	ghcb_set_rcx(ghcb, leaf->ecx_in);

	if (leaf->eax_in == CPUID_EXTENDED_STATE)
		ghcb_set_xcr0(ghcb, (X86_CR4_OSXSAVE & asm_read_cr4()) ?
				    asm_xgetbv(0) : 1);

	status = vmgexit(ghcb, SVM_EXIT_CPUID, 0, 0);
	if (status != 0)
		return status;

	/* Check if valid bits are set for each register by hypervisor */
	if (!ghcb_rax_is_valid(ghcb) || !ghcb_rbx_is_valid(ghcb) ||
	    !ghcb_rcx_is_valid(ghcb) || !ghcb_rdx_is_valid(ghcb)) {
		status = 1;
		return status;
	}

	/* Copy ghcb register info to cpuid leaf */
	leaf->eax = (u32)ghcb->save.rax;
	leaf->ebx = (u32)ghcb->save.rbx;
	leaf->ecx = (u32)ghcb->save.rcx;
	leaf->edx = (u32)ghcb->save.rdx;

	return status;
}

static inline void result_mismatch(u32 iter, struct cpuid_leaf *guest,
				   struct cpuid_leaf *hyp)
{
	printf("WARNING: CPUID leaf %d mismatch.\n", iter);

	/* Guest reported CPUID leaf mismatch */
	printf("SNP CPUID leaf-0x%08x:\n sub-leaf-0x%08x:\n"
	       " EAX:0x%x\n EBX:0x%x\n ECX:0x%x\n EDX:0x%x\n",
	       guest->eax_in, guest->ecx_in, guest->eax, guest->ebx,
	       guest->ecx, guest->edx);

	/* Hypervisor reported CPUID leaf mismatch */
	printf("Hypervisor CPUID leaf-0x%08x:\n sub-leaf-0x%08x:\n"
	       " EAX:0x%x\n EBX:0x%x\n ECX:0x%x\n EDX:0x%x\n",
	       hyp->eax_in, hyp->ecx_in, hyp->eax, hyp->ebx,
	       hyp->ecx, hyp->edx);
}

static efi_status_t test_standard_cpuid_range(struct cpuid result,
					      struct ghcb *ghcb)
{
	efi_status_t status = EFI_SUCCESS;
	u32 std_range_max = result.a, iter;

	printf("standard max range: %d\n", std_range_max);
	for (iter = 0; iter <= std_range_max; iter++) {
		struct cpuid guest_cpuid = cpuid_indexed(iter, 0);
		struct cpuid_leaf guest_cpuid_leaf, hyp_cpuid;

		copy_cpuid_leaf(&guest_cpuid_leaf, guest_cpuid, iter, 0);

		hyp_cpuid.eax_in = iter;
		hyp_cpuid.ecx_in = 0;

		if (fetch_cpuid_hyp(ghcb, &hyp_cpuid))
			return EFI_UNSUPPORTED;

		if (!compare_cpuid(guest_cpuid_leaf, hyp_cpuid)) {
			result_mismatch(iter, &guest_cpuid_leaf,
					&hyp_cpuid);
			status = EFI_NOT_FOUND;
		}

		/*
		 * Special handling for CPUID leaf 0xb having non-zero
		 * sub-leaves.
		 */
		if (guest_cpuid_leaf.eax_in == 0x0000000b) {
			do {
				guest_cpuid_leaf.ecx_in++;

				guest_cpuid = cpuid_indexed(guest_cpuid_leaf.eax_in,
							    guest_cpuid_leaf.ecx_in);

				copy_cpuid_leaf(&guest_cpuid_leaf,
						guest_cpuid, iter,
						guest_cpuid_leaf.ecx_in);

				hyp_cpuid.eax_in = guest_cpuid_leaf.eax_in;
				hyp_cpuid.ecx_in = guest_cpuid_leaf.ecx_in;

				fetch_cpuid_hyp(ghcb, &hyp_cpuid);

				if (!compare_cpuid(guest_cpuid_leaf,
						   hyp_cpuid)) {
					result_mismatch(iter, &guest_cpuid_leaf,
							&hyp_cpuid);
					status = EFI_NOT_FOUND;
				}

			} while (guest_cpuid.a);
		}

		/*
		 * Special handling for CPUID leaf 0xD having non-zero
		 * sub-leaves
		 */
		else if (guest_cpuid_leaf.eax_in == 0x0000000d) {
			u32 subleaf = 1;
			u32 xsave_support_ft_mask = guest_cpuid.a;

			guest_cpuid = cpuid_indexed(iter, 1);

			copy_cpuid_leaf(&guest_cpuid_leaf, guest_cpuid,
					iter, 1);

			hyp_cpuid.eax_in = iter;
			hyp_cpuid.ecx_in = 1;

			fetch_cpuid_hyp(ghcb, &hyp_cpuid);

			if (!compare_cpuid(guest_cpuid_leaf, hyp_cpuid)) {
				result_mismatch(iter, &guest_cpuid_leaf,
						&hyp_cpuid);
				status = EFI_NOT_FOUND;
			}

			for (subleaf = 1; subleaf < 32; subleaf++) {
				if (!(xsave_support_ft_mask & (1 << subleaf))) {
					subleaf++;
					continue;
				}
				guest_cpuid = cpuid_indexed(iter, subleaf);

				copy_cpuid_leaf(&guest_cpuid_leaf,
						guest_cpuid, iter, subleaf);

				hyp_cpuid.eax_in = iter;
				hyp_cpuid.ecx_in = subleaf;

				fetch_cpuid_hyp(ghcb, &hyp_cpuid);

				if (!compare_cpuid(guest_cpuid_leaf, hyp_cpuid)) {
					result_mismatch(iter, &guest_cpuid_leaf,
							&hyp_cpuid);
					status = EFI_NOT_FOUND;
				}
			}
		}
	}
	return status;
}

static efi_status_t test_extended_cpuid_range(struct cpuid result,
					      struct ghcb *ghcb)
{
	efi_status_t status = EFI_SUCCESS;
	u32 ext_range_max = result.a & 0xff, iter;

	printf("extended max range: %d\n", ext_range_max);
	for (iter = 0x80000000; iter <= result.a; iter++) {
		struct cpuid guest_cpuid = cpuid_indexed(iter, 0);
		struct cpuid_leaf guest_cpuid_leaf, hyp_cpuid;

		copy_cpuid_leaf(&guest_cpuid_leaf, guest_cpuid, iter, 0);

		hyp_cpuid.eax_in = iter;
		hyp_cpuid.ecx_in = 0;

		if (fetch_cpuid_hyp(ghcb, &hyp_cpuid))
			return EFI_UNSUPPORTED;

		if (!compare_cpuid(guest_cpuid_leaf, hyp_cpuid)) {
			result_mismatch(iter, &guest_cpuid_leaf,
					&hyp_cpuid);
			status = EFI_NOT_FOUND;
		}

		if (guest_cpuid_leaf.eax_in == 0x8000001d) {
			u32 subfn = 1;

			do {
				guest_cpuid = cpuid_indexed(iter, subfn);

				copy_cpuid_leaf(&guest_cpuid_leaf,
						guest_cpuid, iter, subfn);

				hyp_cpuid.eax_in = iter;
				hyp_cpuid.ecx_in = subfn;

				fetch_cpuid_hyp(ghcb, &hyp_cpuid);

				if (!compare_cpuid(guest_cpuid_leaf,
						   hyp_cpuid)) {
					result_mismatch(iter, &guest_cpuid_leaf,
							&hyp_cpuid);
					status = EFI_NOT_FOUND;
				}

				subfn++;
			} while (guest_cpuid.a);
		}
	}
	return status;
}

static efi_status_t test_sev_snp_cpuid(struct ghcb *ghcb)
{
	struct cpuid res_std, res_ext;

	res_std = cpuid_indexed(0x0, 0);
	res_ext = cpuid_indexed(0x80000000, 0);

	if (test_standard_cpuid_range(res_std, ghcb) == EFI_SUCCESS &&
	    test_extended_cpuid_range(res_ext, ghcb) == EFI_SUCCESS) {
		return EFI_SUCCESS;
	}

	return EFI_NOT_FOUND;
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

static inline void __page_state_change(unsigned long paddr, enum psc_op op)
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
		return;

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
		return;
	}

	/*
	 * If here: PSC is successful in RMP table, validate the page
	 * in the guest so that it is consistent with the RMP entry
	 */
	if (op == SNP_PAGE_STATE_PRIVATE &&
	    pvalidate(paddr, RMP_PG_SIZE_4K, 1)) {
		return;
	}
}

static void snp_set_page_private(unsigned long paddr)
{
	__page_state_change(paddr, SNP_PAGE_STATE_PRIVATE);
}

static inline void snp_set_page_shared(unsigned long paddr)
{
	__page_state_change(paddr, SNP_PAGE_STATE_SHARED);
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

static inline void set_c_bit_pte(unsigned long vaddr)
{
	pteval_t *pte;

	pte = get_pte((pgd_t *)read_cr3(), (void *)vaddr);

	if (!pte) {
		printf("WARNING: pte is null.\n");
		assert(pte);
	}

	/* Set c-bit */
	*pte |= get_amd_sev_c_bit_mask();
}

static inline void set_clr_page_flags(pteval_t set, pteval_t clr,
				      unsigned long vaddr)
{
	if (clr & _PAGE_ENC) {
		/*
		 * If the encryption bit is to be cleared, change the
		 * page state in the RMP table.
		 */
		snp_set_page_shared(__pa(vaddr & PAGE_MASK));
		flush_tlb();
		unset_c_bit_pte(vaddr);
		flush_tlb();
	}

	else if (set & _PAGE_ENC) {
		flush_tlb();
		set_c_bit_pte(vaddr);
		flush_tlb();
		snp_set_page_private(__pa(vaddr & PAGE_MASK));
	}

	flush_tlb();
}

static inline void set_page_decrypted_ghcb_msr(unsigned long vaddr)
{
	set_clr_page_flags(0, _PAGE_ENC, vaddr);
}

static inline void set_page_encrypted_ghcb_msr(unsigned long vaddr)
{
	set_clr_page_flags(_PAGE_ENC, 0, vaddr);
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

	data = (struct snp_psc_desc *)ghcb->shared_buffer;
	memcpy(ghcb->shared_buffer, desc, sizeof(*desc));

	cur_entry = data->hdr.cur_entry;
	end_entry = data->hdr.end_entry;

	while (data->hdr.cur_entry <= data->hdr.end_entry) {
		ghcb_set_sw_scratch(ghcb, (uint64_t)__pa(data));

		ret = sev_ghcb_hv_call(ghcb, SVM_VMGEXIT_PSC, 0, 0);

		if (ret || ghcb->save.sw_exit_info_2) {
			printf("SNP: PSC failed ret=%d exit_info_2=%lx\n",
			       ret, ghcb->save.sw_exit_info_2);
			ret = 1;
			break;
		}

		if (data->hdr.reserved) {
			printf("Reserved bit is set in the PSC header\n");
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

		printf("cur_entry: %d end_entry: %d\n",
		       data->hdr.cur_entry, data->hdr.end_entry);
	}

	return ret;
}

static void __set_pages_state(struct snp_psc_desc *data, unsigned long vaddr,
			      unsigned long vaddr_end, int op, struct ghcb *ghcb)
{
	struct psc_hdr *hdr;
	struct psc_entry *entries;
	unsigned long pfn;
	int iter = 0;
	unsigned long vaddr_start = vaddr;

	hdr = &data->hdr;
	entries = data->entries;

	memset(data, 0, sizeof(*data));

	while (vaddr_start < vaddr_end) {
		pfn = __pa(vaddr_start) >> PAGE_SHIFT;
		entries->gfn = pfn;
		entries->operation = op;
		hdr->end_entry = iter;
		entries->pagesize = RMP_PG_SIZE_4K;

		vaddr_start += PAGE_SIZE;
		entries++;
		iter++;
	}

	if (vmgexit_psc(data, ghcb))
		return;
}

static void set_pages_state(unsigned long vaddr, unsigned int npages,
			    int op, struct ghcb *ghcb)
{
	unsigned long vaddr_next, vaddr_end;
	unsigned long vaddr_start = __pa(vaddr & PAGE_MASK);
	struct snp_psc_desc *desc;

	desc = malloc(sizeof(*desc));
	if (!desc) {
		printf("WARNING: Failed to allocate memory for PSC descriptor.\n");
		return;
	}

	vaddr_end = vaddr_start + (npages * PAGE_SIZE);

	/*
	 * Calculate the last vaddr that can fit in PSC_MAX_ENTRY's
	 * struct snp_psc_desc.
	 */
	while (vaddr_start < vaddr_end) {
		vaddr_next = MIN(vaddr_end,
				 (VMGEXIT_PSC_MAX_ENTRY * PAGE_SIZE) + vaddr_start);

		__set_pages_state(desc, vaddr_start, vaddr_next, op,
				  ghcb);

		vaddr_start = vaddr_next;
	}

	free(desc);
}

static void pvalidate_pages(unsigned long vaddr, unsigned int npages,
			    bool validate)
{
	unsigned long vaddr_start, vaddr_end;
	int pvalidate_result;

	/* Compute the last address */
	vaddr_start = vaddr;
	vaddr_start = __pa(vaddr_start & PAGE_MASK);
	vaddr_end = vaddr_start + (npages * PAGE_SIZE);

	/* Issue pvaldiate on every single page */
	while (vaddr_start < vaddr_end) {
		pvalidate_result = pvalidate(vaddr_start, RMP_PG_SIZE_4K,
					     validate);

		if (pvalidate_result)
			return;

		vaddr_start += PAGE_SIZE;
	}
}

static inline void snp_set_memory_shared_ghcb_nae(unsigned long vaddr,
						  unsigned int npages, struct ghcb *ghcb)
{
	/* Invalidate all the pages before turning them to shared */
	pvalidate_pages(vaddr, npages, false);

	set_pages_state(vaddr, npages, SNP_PAGE_STATE_SHARED, ghcb);
}

static inline void snp_set_memory_private_ghcb_nae(unsigned long vaddr,
						   unsigned int npages,
						   struct ghcb *ghcb)
{
	/* pvalidate all the pages after turning them to private */
	set_pages_state(vaddr, npages, SNP_PAGE_STATE_PRIVATE, ghcb);

	pvalidate_pages(vaddr, npages, true);
}

static void test_sev_snp_activation(void)
{
	efi_status_t status;

	if (rdmsr(MSR_SEV_STATUS) & SEV_SNP_ENABLED_MASK) {
		printf("SEV-SNP is enabled.\n");
	} else {
		printf("SEV-SNP is not enabled.\n");
	}

	if (amd_sev_snp_enabled()) {
		status = find_cc_blob_efi();

		if (status != EFI_SUCCESS)
			printf("%sSEV-SNP CC blob is %spresent.\n",
			       "WARNING: ", "NOT ");

		struct ghcb *ghcb = (struct ghcb *)
				    (rdmsr(SEV_ES_GHCB_MSR_INDEX));

		status = test_sev_snp_cpuid(ghcb);
		if (status != EFI_SUCCESS)
			printf("SEV-SNP CPUID NOT matching all leaves\n");
	} else {
		printf("WARNING: SEV-SNP is not enabled.\n");
	}
}

static void test_read_write(unsigned long paddr, int num_pages, int op)
{
	int iter;
	unsigned long addr_start = paddr;

	for (iter = 0; iter < num_pages; iter++) {
		strcpy((char *)&addr_start, st1);
		if (op == SNP_PAGE_STATE_SHARED)
			printf("Shared page %d's content: %s\n", iter + 1,
			       (char *)&addr_start);
		else
			printf("Private page %d's content: %s\n", iter + 1,
			       (char *)&addr_start);

		addr_start += PAGE_SIZE;
	}
}

static inline void test_sev_snp_psc(void)
{
	unsigned long *vaddr, *vm_pages;

	if (!amd_sev_snp_enabled())
		return;

	vaddr = alloc_page();

	if (!vaddr) {
		printf("WARNING: Page not allocated!\n");
		assert(vaddr);
	}

	force_4k_page(vaddr);
	/* Perform Private <=> Shared page state change */
	strcpy((char *)vaddr, st1);
	printf("Address content: %s\n", (char *)vaddr);

	set_page_decrypted_ghcb_msr((unsigned long)vaddr);

	strcpy((char *)vaddr, st1);
	printf("Address content: %s\n", (char *)vaddr);

	/* Convert same page back from Shared => Private here */
	set_page_encrypted_ghcb_msr((unsigned long)vaddr);

	strcpy((char *)vaddr, st1);
	printf("Address content: %s\n", (char *)vaddr);

	/* Allocate 4 (1<<2) pages for testing */
	vm_pages = alloc_pages(2);

	force_4k_page(vm_pages);
	struct ghcb *ghcb = (struct ghcb *)(rdmsr(SEV_ES_GHCB_MSR_INDEX));

	/* Page State Changes - Private to Shared */
	snp_set_memory_shared_ghcb_nae((unsigned long)vm_pages, 4, ghcb);
	test_read_write((unsigned long)vm_pages, 4, SNP_PAGE_STATE_SHARED);

	/* Page state changes - Shared to Private */
	snp_set_memory_private_ghcb_nae((unsigned long)vm_pages, 4, ghcb);
	test_read_write((unsigned long)vm_pages, 4,
			SNP_PAGE_STATE_PRIVATE);
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

int main(void)
{
	int rtn;
	rtn = test_sev_activation();
	report(rtn == EXIT_SUCCESS, "SEV activation test.");
	test_sev_es_activation();
	setup_vm();
	test_sev_snp_activation();
	test_sev_snp_psc();
	test_stringio();
	return report_summary();
}
