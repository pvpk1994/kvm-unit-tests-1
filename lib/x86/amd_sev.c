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

static unsigned short amd_sev_c_bit_pos;
phys_addr_t ghcb_addr;

u64 asm_read_cr4(void)
{
	u64 data;

	__asm__ __volatile__("mov %%cr4, %0" : "=a" (data));

	return data;
}

u64 asm_xgetbv(u32 index)
{
	u32 eax, edx;

	__asm__ __volatile__("xgetbv" : "=a" (eax), "=d" (edx) : "c"
			     (index));

	return eax + ((u64)edx << 32);
}

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

/*
 * Mark a field at specified offset as valid in GHCB.
 * Hypervisor will fail the GHCB requests in cases where fields are set
 * without updating the bitmap.
 */
void vmg_set_offset_valid(ghcb_page *ghcb, GHCB_REGISTER offset)
{
	u32 offset_index;
	u32 offset_bit;

	offset_index = offset / 8;
	offset_bit   = offset % 8;

	ghcb->save_area.valid_bitmap[offset_index] |= (1 << offset_bit);
}

void mem_fence(void)
{
	__asm__ __volatile__("":::"memory");
}

/* Hypervisor features are available from GHCB version 2 */
u64 get_hv_features(ghcb_page *ghcb)
{
	u64 val;

	if (ghcb->protocol_version < 2) {
		printf("GHCB protocol version has to be 2!\n");
		return 0;
	}

	/* Save old GHCB MSR */
	phys_addr_t ghcb_old_msr = rdmsr(SEV_ES_GHCB_MSR_INDEX);

	wrmsr(SEV_ES_GHCB_MSR_INDEX, GHCB_MSR_HV_FT_REQ);
	VMGEXIT();

	val = rdmsr(SEV_ES_GHCB_MSR_INDEX);
	/* Restore old GHCB MSR */
	wrmsr(SEV_ES_GHCB_MSR_INDEX, ghcb_old_msr);

	if (GHCB_RESP_CODE(val) != GHCB_MSR_HV_FT_RESP) {
		printf("SNP AP creation response code from hypervisor does not match expected response.\n");
		return 0;
	}

	return GHCB_MSR_HV_FT_RESP_VAL(val);
}

void vmgexit(ghcb_page *ghcb, u64 exit_code,
	     u64 exit_info1, u64 exit_info2)
{
	ghcb->save_area.sw_exit_code = exit_code;
	ghcb->save_area.sw_exit_info1 = exit_info1;
	ghcb->save_area.sw_exit_info2 = exit_info2;

	vmg_set_offset_valid(ghcb, ghcb_sw_exit_code);
	vmg_set_offset_valid(ghcb, ghcb_sw_exit_info1);
	vmg_set_offset_valid(ghcb, ghcb_sw_exit_info2);

	/*
	 * Memory fencing ensures writes are not ordered after the
	 * VMGEXIT(), and reads are not ordered before it.
	 */
	mem_fence();
	VMGEXIT();
	mem_fence();
}
