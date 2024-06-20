/*
 * AMD SEV support in kvm-unit-tests
 *
 * Copyright (c) 2021, Google Inc
 *
 * Authors:
 *   Zixuan Wang <zixuanwang@google.com>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "amd_sev.h"
#include "x86/processor.h"
#include "x86/vm.h"
#include "vmalloc.h"
#include "alloc_page.h"

static unsigned short amd_sev_c_bit_pos;
phys_addr_t ghcb_addr;

bool amd_sev_enabled(void)
{
	struct cpuid cpuid_out;
	static bool sev_enabled;
	static bool initialized = false;

	/* Check CPUID and MSR for SEV status and store it for future function calls. */
	if (!initialized) {
		sev_enabled = false;
		initialized = true;

		/* Test if we can query SEV features */
		cpuid_out = cpuid(CPUID_FN_LARGEST_EXT_FUNC_NUM);
		if (cpuid_out.a < CPUID_FN_ENCRYPT_MEM_CAPAB) {
			return sev_enabled;
		}

		/* Test if SEV is supported */
		cpuid_out = cpuid(CPUID_FN_ENCRYPT_MEM_CAPAB);
		if (!(cpuid_out.a & SEV_SUPPORT_MASK)) {
			return sev_enabled;
		}

		/* Test if SEV is enabled */
		if (rdmsr(MSR_SEV_STATUS) & SEV_ENABLED_MASK) {
			sev_enabled = true;
		}
	}

	return sev_enabled;
}

efi_status_t setup_amd_sev(void)
{
	struct cpuid cpuid_out;

	if (!amd_sev_enabled()) {
		return EFI_UNSUPPORTED;
	}

	/*
	 * Extract C-Bit position from ebx[5:0]
	 * AMD64 Architecture Programmer's Manual Volume 3
	 *   - Section " Function 8000_001Fh - Encrypted Memory Capabilities"
	 */
	cpuid_out = cpuid(CPUID_FN_ENCRYPT_MEM_CAPAB);
	amd_sev_c_bit_pos = (unsigned short)(cpuid_out.b & 0x3f);

	return EFI_SUCCESS;
}

bool amd_sev_es_enabled(void)
{
	static bool sev_es_enabled;
	static bool initialized = false;

	if (!initialized) {
		sev_es_enabled = false;
		initialized = true;

		if (!amd_sev_enabled()) {
			return sev_es_enabled;
		}

		/* Test if SEV-ES is enabled */
		if (rdmsr(MSR_SEV_STATUS) & SEV_ES_ENABLED_MASK) {
			sev_es_enabled = true;
		}
	}

	return sev_es_enabled;
}

bool amd_sev_snp_enabled(void)
{
	static bool sev_snp_enabled;
	static bool initialized;

	if (!initialized) {
		if (amd_sev_es_enabled())
			sev_snp_enabled = rdmsr(MSR_SEV_STATUS) &
					  SEV_SNP_ENABLED_MASK;
		initialized = true;
	}

	return sev_snp_enabled;
}

efi_status_t setup_vc_handler(void)
{
	struct descriptor_table_ptr idtr;
	idt_entry_t *idt;
	idt_entry_t vc_handler_idt;

	/*
	 * If AMD SEV-SNP is enabled, then SEV-ES is also enabled, so
	 * checking for SEV-ES covers both.
	 */
	if (!amd_sev_es_enabled()) {
		return EFI_UNSUPPORTED;
	}

	/*
	 * Copy UEFI's #VC IDT entry, so KVM-Unit-Tests can reuse it and does
	 * not have to re-implement a #VC handler for #VC exceptions before
	 * GHCB is mapped. Also update the #VC IDT code segment to use
	 * KVM-Unit-Tests segments, KERNEL_CS, so that we do not
	 * have to copy the UEFI GDT entries into KVM-Unit-Tests GDT.
	 */
	sidt(&idtr);
	idt = (idt_entry_t *)idtr.base;
	vc_handler_idt = idt[SEV_ES_VC_HANDLER_VECTOR];
	vc_handler_idt.selector = KERNEL_CS;
	boot_idt[SEV_ES_VC_HANDLER_VECTOR] = vc_handler_idt;

	return EFI_SUCCESS;
}

void setup_ghcb_pte(pgd_t *page_table)
{
	/*
	 * SEV-ES guest uses GHCB page to communicate with the host. This page
	 * must be unencrypted, i.e. its c-bit should be unset. To do so, this
	 * function searches GHCB's L1 pte, creates corresponding L1 ptes if not
	 * found, and unsets the c-bit of GHCB's L1 pte.
	 */
	phys_addr_t ghcb_base_addr;
	pteval_t *pte;

	/* Read the current GHCB page addr */
	ghcb_addr = rdmsr(SEV_ES_GHCB_MSR_INDEX);

	/* Search Level 1 page table entry for GHCB page */
	pte = get_pte_level(page_table, (void *)ghcb_addr, 1);

	/* Create Level 1 pte for GHCB page if not found */
	if (pte == NULL) {
		/* Find Level 2 page base address */
		ghcb_base_addr = ghcb_addr & ~(LARGE_PAGE_SIZE - 1);
		/* Install Level 1 ptes */
		install_pages(page_table, ghcb_base_addr, LARGE_PAGE_SIZE, (void *)ghcb_base_addr);
		/* Find Level 2 pte, set as 4KB pages */
		pte = get_pte_level(page_table, (void *)ghcb_addr, 2);
		assert(pte);
		*pte &= ~(PT_PAGE_SIZE_MASK);
		/* Find Level 1 GHCB pte */
		pte = get_pte_level(page_table, (void *)ghcb_addr, 1);
		assert(pte);
	}

	/* Unset c-bit in Level 1 GHCB pte */
	*pte &= ~(get_amd_sev_c_bit_mask());
}

unsigned long long get_amd_sev_c_bit_mask(void)
{
	if (amd_sev_enabled()) {
		return 1ull << amd_sev_c_bit_pos;
	} else {
		return 0;
	}
}

unsigned long long get_amd_sev_addr_upperbound(void)
{
	if (amd_sev_enabled()) {
		return amd_sev_c_bit_pos - 1;
	} else {
		/* Default memory upper bound */
		return PT_ADDR_UPPER_BOUND_DEFAULT;
	}
}

void set_pte_decrypted(unsigned long vaddr, int npages)
{
	pteval_t *pte;
	unsigned long vaddr_end = vaddr + (npages * PAGE_SIZE);

	while (vaddr < vaddr_end) {
		pte = get_pte((pgd_t *)read_cr3(), (void *)vaddr);

		if (!pte)
			assert_msg(pte, "No pte found for vaddr 0x%lx", vaddr);

		/* unset C-bit */
		*pte &= ~get_amd_sev_c_bit_mask();

		vaddr += PAGE_SIZE;
	}

	flush_tlb();
}

void set_pte_encrypted(unsigned long vaddr, int npages)
{
	pteval_t *pte;
	unsigned long vaddr_end = vaddr + (npages * PAGE_SIZE);

	while (vaddr < vaddr_end) {
		pte = get_pte((pgd_t *)read_cr3(), (void *)vaddr);

		if (!pte)
			assert_msg(pte, "No pte found for vaddr 0x%lx", vaddr);

		/* set C-bit */
		*pte |= get_amd_sev_c_bit_mask();

		vaddr += PAGE_SIZE;
	}

	flush_tlb();
}

int pvalidate(unsigned long vaddr, bool rmp_size, bool validate)
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

bool is_validated_private_page(unsigned long vaddr, bool rmp_size)
{
	int ret;

	/* Attempt a PVALIDATE here for the provided page size */
	ret = pvalidate(vaddr, rmp_size, true);
	if (ret == PVALIDATE_FAIL_NOUPDATE)
		return true;

	/*
	 * If PVALIDATE_FAIL_SIZEMISMATCH, entry in the RMP is 4K and
	 * what guest is providing is a 2M entry. Therefore, fallback
	 * to pvalidating 4K entries within 2M range.
	 */
	if (rmp_size && ret == PVALIDATE_FAIL_SIZEMISMATCH) {
		unsigned long vaddr_end = vaddr + LARGE_PAGE_SIZE;

		for (; vaddr < vaddr_end; vaddr += PAGE_SIZE) {
			ret = pvalidate(vaddr, RMP_PG_SIZE_4K, true);
			if (ret != PVALIDATE_FAIL_NOUPDATE)
				return false;
		}

		return true;
	}

	return false;
}

enum es_result __sev_set_pages_state_msr_proto(unsigned long vaddr, int npages,
					       int operation)
{
	unsigned long vaddr_end = vaddr + (npages * PAGE_SIZE);
	unsigned long paddr;
	int ret;
	unsigned long val;

	/*
	 * GHCB maybe established at this point, so save and restore the
	 * current value which will be overwritten by the MSR protocol
	 * request.
	 */
	phys_addr_t ghcb_old_msr = rdmsr(SEV_ES_GHCB_MSR_INDEX);

	while (vaddr < vaddr_end) {
		paddr = __pa(vaddr);

		if (operation == SNP_PAGE_STATE_SHARED) {
			ret = pvalidate(vaddr, RMP_PG_SIZE_4K, false);
			if (ret) {
				printf("Failed to invalidate vaddr: 0x%lx, ret: %d\n",
				       vaddr, ret);
				wrmsr(SEV_ES_GHCB_MSR_INDEX, ghcb_old_msr);
				return ES_UNSUPPORTED;
			}
		}

		wrmsr(SEV_ES_GHCB_MSR_INDEX,
		      GHCB_MSR_PSC_REQ_GFN(paddr >> PAGE_SHIFT, operation));

		VMGEXIT();

		val = rdmsr(SEV_ES_GHCB_MSR_INDEX);

		if (GHCB_RESP_CODE(val) != GHCB_MSR_PSC_RESP) {
			printf("Incorrect PSC response code: 0x%x\n",
			       (unsigned int)GHCB_RESP_CODE(val));
			wrmsr(SEV_ES_GHCB_MSR_INDEX, ghcb_old_msr);
			return ES_VMM_ERROR;
		}

		if (GHCB_MSR_PSC_RESP_VAL(val)) {
			printf("Failed to change page state to %s paddr: 0x%lx error: 0x%llx\n",
			       operation == SNP_PAGE_STATE_PRIVATE ? "private" :
								     "shared",
			       paddr, GHCB_MSR_PSC_RESP_VAL(val));
			wrmsr(SEV_ES_GHCB_MSR_INDEX, ghcb_old_msr);
			return ES_VMM_ERROR;
		}

		if (operation == SNP_PAGE_STATE_PRIVATE) {
			ret = pvalidate(vaddr, RMP_PG_SIZE_4K, true);
			if (ret) {
				printf("Failed to validate vaddr: 0x%lx, ret: %d\n",
				       vaddr, ret);
				wrmsr(SEV_ES_GHCB_MSR_INDEX, ghcb_old_msr);
				return ES_UNSUPPORTED;
			}
		}

		vaddr += PAGE_SIZE;
	}

	/* Restore old GHCB msr - setup by OVMF */
	wrmsr(SEV_ES_GHCB_MSR_INDEX, ghcb_old_msr);

	return ES_OK;
}

static bool pvalidate_failed(int result, bool allow_noupdate)
{
	if (result && (!allow_noupdate || result != PVALIDATE_FAIL_NOUPDATE))
		return true;

	return false;
}

void pvalidate_pages(struct snp_psc_desc *desc, unsigned long *vaddr_arr,
		     bool allow_noupdate)
{
	struct psc_entry *entry;
	int ret, i;
	unsigned long vaddr;
	bool validate;

	for (i = 0; i <= desc->hdr.end_entry; i++) {
		vaddr = vaddr_arr[i];
		entry = &desc->entries[i];
		validate = entry->operation == SNP_PAGE_STATE_PRIVATE ? true : false;

		ret = pvalidate(vaddr, entry->pagesize, validate);
		if (ret == PVALIDATE_FAIL_SIZEMISMATCH) {
			assert(entry->pagesize == RMP_PG_SIZE_2M);
			unsigned long vaddr_end = vaddr + LARGE_PAGE_SIZE;

			for (; vaddr < vaddr_end; vaddr += PAGE_SIZE) {
				ret = pvalidate(vaddr, RMP_PG_SIZE_4K, validate);
				if (pvalidate_failed(ret, allow_noupdate))
					break;
			}
		}
		assert(!pvalidate_failed(ret, allow_noupdate));
	}
}

static int verify_exception(struct ghcb *ghcb)
{
	return ghcb->save.sw_exit_info_1 & GENMASK_ULL(31, 0);
}

static int sev_ghcb_hv_call(struct ghcb *ghcb, u64 exit_code,
			    u64 exit_info_1, u64 exit_info_2)
{
	ghcb->version = GHCB_PROTOCOL_MAX;
	ghcb->ghcb_usage = GHCB_DEFAULT_USAGE;

	ghcb_set_sw_exit_code(ghcb, exit_code);
	ghcb_set_sw_exit_info_1(ghcb, exit_info_1);
	ghcb_set_sw_exit_info_2(ghcb, exit_info_2);

	VMGEXIT();

	return verify_exception(ghcb);
}

int vmgexit_psc(struct snp_psc_desc *desc, struct ghcb *ghcb)
{
	int cur_entry, end_entry, ret = 0;
	struct snp_psc_desc *data;

	/* Ensure end_entry is within bounds */
	assert(desc->hdr.end_entry < VMGEXIT_PSC_MAX_ENTRY);

	vc_ghcb_invalidate(ghcb);

	data = (struct snp_psc_desc *)ghcb->shared_buffer;
	memcpy(ghcb->shared_buffer, desc, GHCB_SHARED_BUF_SIZE);

	cur_entry = data->hdr.cur_entry;
	end_entry = data->hdr.end_entry;

	while (data->hdr.cur_entry <= data->hdr.end_entry) {
		ghcb_set_sw_scratch(ghcb, (u64)__pa(data));

		ret = sev_ghcb_hv_call(ghcb, SVM_VMGEXIT_PSC, 0, 0);

		if (ret) {
			report_info("SNP: PSC failed with ret: %d\n", ret);
			ret = 1;
			break;
		}

		if (cur_entry > data->hdr.cur_entry) {
			report_info("SNP: PSC processing going backward, cur_entry %d (got %d)\n",
				    cur_entry, data->hdr.cur_entry);
			ret = 1;
			break;
		}

		if (data->hdr.end_entry != end_entry) {
			report_info("End entry mismatch: end_entry %d (got %d)\n",
				    end_entry, data->hdr.end_entry);
			ret = 1;
			break;
		}

		if (data->hdr.reserved) {
			report_info("Reserved bit is set in the PSC header\n");
			ret = 1;
			break;
		}
	}

	/* Copy the output in shared buffer back to desc */
	memcpy(desc, ghcb->shared_buffer, GHCB_SHARED_BUF_SIZE);

	return ret;
}

void add_psc_entry(struct snp_psc_desc *desc, u8 idx, u8 op, unsigned long vaddr,
		   bool large_entry, u16 cur_page_offset)
{
	struct psc_hdr *hdr = &desc->hdr;
	struct psc_entry *entry = &desc->entries[idx];

	assert_msg(!large_entry || IS_ALIGNED(vaddr, LARGE_PAGE_SIZE),
		   "Must use 2M-aligned addresses for large PSC entries");

	entry->gfn = pgtable_va_to_pa(vaddr) >> PAGE_SHIFT;
	entry->operation = op;
	entry->pagesize = large_entry;
	entry->cur_page = cur_page_offset;
	hdr->end_entry = idx;
}

unsigned long __sev_set_pages_state(struct snp_psc_desc *desc, unsigned long vaddr,
				    unsigned long vaddr_end, int op,
				    struct ghcb *ghcb, bool large_entry,
				    bool allow_noupdate)
{
	unsigned long vaddr_arr[VMGEXIT_PSC_MAX_ENTRY];
	int ret, iter = 0, iter2 = 0;
	u8 page_size;

	memset(desc, 0, sizeof(*desc));

	report_info("%s: address start %lx end %lx op %d large %d",
		    __func__, vaddr, vaddr_end, op, large_entry);

	while (vaddr < vaddr_end && iter < ARRAY_SIZE(desc->entries)) {
		vaddr_arr[iter] = vaddr;

		if (large_entry && IS_ALIGNED(vaddr, LARGE_PAGE_SIZE) &&
		    (vaddr_end - vaddr) >= LARGE_PAGE_SIZE) {
			add_psc_entry(desc, iter, op, vaddr, true, 0);
			vaddr += LARGE_PAGE_SIZE;
		} else {
			add_psc_entry(desc, iter, op, vaddr, false, 0);
			vaddr += PAGE_SIZE;
		}

		iter++;
	}

	if (op == SNP_PAGE_STATE_SHARED)
		pvalidate_pages(desc, vaddr_arr, allow_noupdate);

	ret = vmgexit_psc(desc, ghcb);
	assert_msg(!ret, "VMGEXIT failed with ret value: %d", ret);

	if (op == SNP_PAGE_STATE_PRIVATE)
		pvalidate_pages(desc, vaddr_arr, allow_noupdate);

	for (iter2 = 0; iter2 < iter; iter2++) {
		page_size = desc->entries[iter2].pagesize;

		if (page_size == RMP_PG_SIZE_2M)
			assert_msg(desc->entries[iter2].cur_page == 512,
				   "Failed to process sub-entries within 2M range");
		else if (page_size == RMP_PG_SIZE_4K)
			assert_msg(desc->entries[iter2].cur_page == 1,
				   "Failed to process 4K entry");
	}

	return vaddr;
}
