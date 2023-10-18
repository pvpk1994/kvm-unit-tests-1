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

static u16 ghcb_version;
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

efi_status_t setup_amd_sev_es(void)
{
	struct descriptor_table_ptr idtr;
	idt_entry_t *idt;
	idt_entry_t vc_handler_idt;

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

bool amd_sev_snp_enabled(void)
{
	static bool sev_snp_enabled;
	static bool initialized = false;

	if (!initialized) {
		sev_snp_enabled = false;
		initialized = true;

		if (!amd_sev_es_enabled())
			return sev_snp_enabled;

		/* Test if SEV-SNP is enabled */
		sev_snp_enabled = rdmsr(MSR_SEV_STATUS) &
				  SEV_SNP_ENABLED_MASK;
	}

	return sev_snp_enabled;
}

static inline u64 get_hv_features(struct ghcb *ghcb_page)
{
	ghcb_page->protocol_version = ghcb_version;
	if (ghcb_page->protocol_version < 2) {
		printf("GHCB protocol version has to be 2!\n");
		return 0;
	}

	ghcb_page->ghcb_usage = GHCB_DEFAULT_USAGE;

	ghcb_set_sw_exit_code(ghcb_page, SVM_VMGEXIT_HV_FEATURES);
	ghcb_set_sw_exit_info_1(ghcb_page, 0);
	ghcb_set_sw_exit_info_2(ghcb_page, 0);

	VMGEXIT();

	if (!ghcb_page->save.sw_exit_info_2) {
		printf("Unable to retreive features bitmap.\n");
		return 0;
	}

	return ghcb_page->save.sw_exit_info_2;
}

enum es_result hv_snp_ap_feature_check(struct ghcb *ghcb_page)
{
	u64 result = get_hv_features(ghcb_page);

	/* Check for hypervisor SEV-SNP feature support */
	if (!(result & GHCB_HV_FT_SNP)) {
		printf("Hypervisor SEV-SNP feature NOT supported.\n");
		return ES_VMM_ERROR;
	}

	/* Check for hypervisor SEV-SNP AP creation support */
	if (!(result & GHCB_HV_FT_SNP_AP_CREATION)) {
		printf("Hyeprvisor SEV-SNP AP creation feature NOT supported.\n");
		return ES_UNSUPPORTED;
	}

	return ES_OK;
}

void get_ghcb_version(void)
{
	u64 val;
	phys_addr_t ghcb_old_msr;

	ghcb_old_msr = rdmsr(SEV_ES_GHCB_MSR_INDEX);

	/* GHCB protocol version negotiation */
	wrmsr(SEV_ES_GHCB_MSR_INDEX, GHCB_MSR_SEV_INFO_REQ);
	VMGEXIT();

	val = rdmsr(SEV_ES_GHCB_MSR_INDEX);

	if (GHCB_MSR_INFO(val) != GHCB_MSR_SEV_INFO_RESP)
		return;

	if (GHCB_MSR_PROTO_MAX(val) < GHCB_PROTOCOL_MIN ||
	    GHCB_MSR_PROTO_MIN(val) > GHCB_PROTOCOL_MAX)
		return;

	ghcb_version = MIN(GHCB_MSR_PROTO_MAX(val), GHCB_PROTOCOL_MAX);

	/* Restore old GHCB MSR */
	wrmsr(SEV_ES_GHCB_MSR_INDEX, ghcb_old_msr);
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

static inline enum es_result __page_state_change(unsigned long paddr,
						 enum psc_op op)
{
	u64 val;

	if (!amd_sev_snp_enabled())
		return ES_UNSUPPORTED;

	/* save the old GHCB MSR */
	phys_addr_t ghcb_old_msr = rdmsr(SEV_ES_GHCB_MSR_INDEX);

	/*
	 * If action requested is to convert page from private to shared,
	 * then invalidate the page before we send it to hypervisor to
	 * change state of page in RMP table.
	 */
	if (op == SNP_PAGE_STATE_SHARED &&
	    pvalidate(paddr, RMP_PG_SIZE_4K, 0)) {
		return ES_UNSUPPORTED;
	}

	/*
	 * Issue VMGEXIT now to change state of page in RMP table
	 */
	sev_es_wr_ghcb_msr(GHCB_MSR_PSC_REQ_GFN(paddr >> PAGE_SHIFT, op));
	VMGEXIT();

	val = rdmsr(SEV_ES_GHCB_MSR_INDEX);

	/* Restore old GHCB MSR value */
	sev_es_wr_ghcb_msr(ghcb_old_msr);

	if (GHCB_RESP_CODE(val) != GHCB_MSR_PSC_RESP ||
	    GHCB_MSR_PSC_RESP_VAL(val)) {
		printf("PSC response code from hypervisor does not match expected response.\n");
		return ES_UNSUPPORTED;
	}

	return ES_OK;
}

static inline enum es_result snp_set_page_shared(unsigned long paddr)
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

static inline enum es_result clr_page_flags(pteval_t set, pteval_t clr,
					    unsigned long vaddr)
{
	if (clr & _PAGE_ENC) {
		/*
		 * If the encryption bit is to be cleared, change the
		 * state in the RMP table.
		 */
		snp_set_page_shared(__pa(vaddr & PAGE_MASK));
		unset_c_bit_pte(vaddr);
	}

	flush_tlb();

	return ES_OK;
}

enum es_result set_page_decrypted_ghcb_msr(unsigned long vaddr)
{
	return clr_page_flags(0, _PAGE_ENC, vaddr);
}
