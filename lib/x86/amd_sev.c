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
#include "alloc_page.h"
#include "vmalloc.h"
#include "apic.h"
#include "smp.h"
#include "fwcfg.h"


//static struct percpu_data __percpu_data[MAX_TEST_CPUS];

/*
 * AP INIT values as documented in APM2
 * under section "Processor Initialization state"
 */
#define AP_INIT_CS_LIMIT	0xffff
#define AP_INIT_DS_LIMIT	0xffff
#define AP_INIT_LDTR_LIMIT	0xffff
#define AP_INIT_GDTR_LIMIT	0xffff
#define AP_INIT_IDTR_LIMIT	0xffff
#define AP_INIT_TR_LIMIT	0xffff
#define AP_INIT_RFLAGS_DEFAULT	0x2
#define AP_INIT_DR6_DEFAULT	0xffff0ff0
#define AP_INIT_CR0_DEFAULT	0x60000010
#define AP_DR7_RESET		0x400
#define AP_INIT_GPAT_DEFAULT	0x0007040600070406ULL
#define AP_INIT_XCR0_DEFAULT	0x1
#define AP_INIT_MXCSR_DEFAULT	0x1f80
#define AP_INIT_X87_FTW_DEFAULT	0x5555
#define AP_INIT_X87_FCW_DEFAULT	0x40

#define SVM_SELECTOR_S_SHIFT	4
#define SVM_SELECTOR_P_SHIFT	7
#define SVM_SELECTOR_S_MASK	(1 << SVM_SELECTOR_S_SHIFT)
#define SVM_SELECTOR_P_MASK	(1 << SVM_SELECTOR_P_SHIFT)
#define SVM_SELECTOR_S_MASK	(1 << SVM_SELECTOR_S_SHIFT)

#define SVM_SELECTOR_WRITE_MASK	(1 << 1)
#define SVM_SELECTOR_READ_MASK	SVM_SELECTOR_WRITE_MASK
#define SVM_SELECTOR_CODE_MASK	(1 << 3)

#define __ATTR_BASE		(SVM_SELECTOR_P_MASK | SVM_SELECTOR_S_MASK)
#define INIT_CS_ATTRIBS		(__ATTR_BASE | SVM_SELECTOR_READ_MASK | SVM_SELECTOR_CODE_MASK)
#define INIT_DS_ATTRIBS		(__ATTR_BASE | SVM_SELECTOR_WRITE_MASK)

#define INIT_LDTR_ATTRIBS	(SVM_SELECTOR_P_MASK | 2)
#define INIT_TR_ATTRIBS		(SVM_SELECTOR_P_MASK | 3)

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

static inline bool vmg_set_offset_is_valid(ghcb_page *ghcb,
					   GHCB_REGISTER offset)
{
	return test_bit(offset, (unsigned long *)&ghcb->save_area.valid_bitmap);
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
		printf("GHCB version:%d\n", ghcb->protocol_version);
		printf("Illegal GHCB version.\n");
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
		printf("GHCB response code does not match, val:%ld\n",
		       val);
		return 0;
	}

	return GHCB_MSR_HV_FT_RESP_VAL(val);
}

static int snp_set_vmsa(void *va, bool vmsa)
{
	u64 attrs;

	/*
	 * Running at VMPL level 0 allows kernel to change VMSA bit for
	 * a page using RMPADJUST instruction. However, for instruction
	 * to succeed, we must target the permissions of a lesser
	 * previliged VMPL level, therefore use VMPL @ level 1 (APM Volume 3).
	 */
	attrs = 1;
	if (vmsa)
		attrs |= RMPADJUST_VMSA_PAGE_BIT;

	return rmpadjust((unsigned long)va, RMP_PG_SIZE_4K, attrs);
}

void vc_invalidate_ghcb(ghcb_page *ghcb)
{
	ghcb->save_area.sw_exit_code = 0;
	memset(ghcb->save_area.valid_bitmap, 0,
	       sizeof(ghcb->save_area.valid_bitmap));
}

void bringup_snp_aps()
{
	int ret;
	u64 cr4;
	struct sev_es_save_area *vmsa;
	unsigned long *vaddr;

	ghcb_page *ghcb = (ghcb_page *)rdmsr(SEV_ES_GHCB_MSR_INDEX);

	ghcb->protocol_version = 2;

	if (!(get_hv_features(ghcb) & GHCB_HV_FT_SNP_AP_CREATION)) {
		printf("SNP AP creation feature NOT supported by hypervisor.\n");
		return;
	}

	/* To enable alloc_page() for EFI builds */
	setup_vm();

	/*
	 * TODO: Account for VMSA related SNP erratum
	 * This erratum e.xists for large pages (2M/1G)
	 * Issuing a force_4k_page() should resolve the issue?
	 */
	vaddr = alloc_page();
	printf("vaddr page: 0x%lx, 0x%lx\n", (unsigned long)vaddr, 
		__pa(vaddr));
	vmsa = (struct sev_es_save_area *)(vaddr);
	force_4k_page(vmsa);

	if (!IS_ALIGNED((phys_addr_t)vmsa, PAGE_SIZE)) {
		printf("VMSA page is NOT 4k boundary aligned.\n");
		return;
	}
	//PAGE_ALIGN(vmsa);

	if (!vmsa) {
		printf("VMSA page not allocated!\n");
		return;
	}

	/* CR4 must maintain MCE value */
	cr4 = read_cr4() & X86_CR4_MCE;

	/*
	 * RM_TRAMPOLINE_ADDR is defined at addr 0x0.
	 * sipi_vector becomes 0 and therefore cs.base, rip, and
	 * cs.selector all are 0.
	 */
	vmsa->cs.base 		= 0;
	vmsa->cs.limit 		= AP_INIT_CS_LIMIT;
	vmsa->cs.attrib 	= INIT_CS_ATTRIBS;
	vmsa->cs.selector 	= 0;

	vmsa->rip 		= 0;

	vmsa->ds.limit 		= AP_INIT_DS_LIMIT;
	vmsa->ds.attrib 	= INIT_DS_ATTRIBS;

	vmsa->es		= vmsa->ds;
	vmsa->fs		= vmsa->ds;
	vmsa->gs		= vmsa->ds;
	vmsa->ss		= vmsa->ds;

	vmsa->gdtr.limit	= AP_INIT_GDTR_LIMIT;
	vmsa->ldtr.limit	= AP_INIT_LDTR_LIMIT;
	vmsa->ldtr.attrib	= INIT_LDTR_ATTRIBS;
	vmsa->tr.limit		= AP_INIT_TR_LIMIT;
	vmsa->tr.attrib		= INIT_TR_ATTRIBS;

	vmsa->cr4		= cr4;
//	vmsa->cr0		= AP_INIT_CR0_DEFAULT;
	vmsa->cr0		= 0x10;
	vmsa->dr7		= AP_DR7_RESET;
	vmsa->dr6		= AP_INIT_DR6_DEFAULT;
	vmsa->rflags		= AP_INIT_RFLAGS_DEFAULT;
	vmsa->g_pat		= AP_INIT_GPAT_DEFAULT;
	vmsa->xcr0		= AP_INIT_XCR0_DEFAULT;
	vmsa->mxcsr		= AP_INIT_MXCSR_DEFAULT;
	vmsa->x87_ftw		= AP_INIT_X87_FTW_DEFAULT;
	vmsa->x87_fcw		= AP_INIT_X87_FCW_DEFAULT;

	vmsa->efer		= EFER_SVME;

	/*
	 * Set SNP specific fields for VMSA:
	 * 1. VMPL Level
	 * 2. SEV_FEATURES: sev_status MSR right shifted 2 bits
	 */
	vmsa->vmpl		= 0;
//	printf("MSR_SEV_STATUS: 0x%lx\n", rdmsr(MSR_SEV_STATUS));
	vmsa->sev_features	= rdmsr(MSR_SEV_STATUS) >> 2;

	/* Switch over the page to a VMSA page now */
	ret = snp_set_vmsa(vmsa, true);

	if (ret) {
		printf("WARNING: VMSA page conversion failure.\n");
		printf("ret code: %d\n",ret);
		return;
	}

//	wrmsr(MSR_GS_BASE, (u64)&__percpu_data[0x1]);
//	irq_disable();

	phys_addr_t ghcb_old_msr = rdmsr(SEV_ES_GHCB_MSR_INDEX);

	irq_disable();
//	vc_invalidate_ghcb(ghcb);
	vmg_set_offset_valid(ghcb, ghcb_rax);
	ghcb->save_area.rax = vmsa->sev_features;

	vmg_set_offset_valid(ghcb, ghcb_sw_exit_code);
	ghcb->save_area.sw_exit_code = SVM_VMGEXIT_AP_CREATION;

//	if (apic_id() !=0) {
	vmg_set_offset_valid(ghcb, ghcb_sw_exit_info1);
	ghcb->save_area.sw_exit_info1 = ((u64)0x1 << 32 |
					SVM_VMGEXIT_AP_CREATE);
//	}
	vmg_set_offset_valid(ghcb, ghcb_sw_exit_info2);
	ghcb->save_area.sw_exit_info2 = __pa(vmsa);

	wrmsr(SEV_ES_GHCB_MSR_INDEX, __pa(ghcb));
	VMGEXIT();

	if (!vmg_set_offset_is_valid(ghcb, ghcb_sw_exit_info1) ||
	    (u32)(ghcb->save_area.sw_exit_info1 &  0xffffffff)) {
		printf("SNP AP Creation Error.\n");
		return;
	}

	irq_enable();

	/* Store the current VMSA page in per-cpu of AP */
	this_cpu_write_smp_id(0x1);
	this_cpu_write_vmsa(vmsa);
	printf("CPUid: %d, vmsa->sev_features: 0x%lx\n",
		this_cpu_read_smp_id(),
		vmsa->sev_features);
	//__percpu_data[0x1].vmsa = vmsa;

	this_cpu_write_smp_id(pre_boot_apic_id());
	printf("SMP ID in %s: %d\n",__func__,smp_id());
	printf("Number of cpus: %d\n", fwcfg_get_nb_cpus());
	/* Restore old GHCB MSR */
	wrmsr(SEV_ES_GHCB_MSR_INDEX, ghcb_old_msr);
//	irq_enable();
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
