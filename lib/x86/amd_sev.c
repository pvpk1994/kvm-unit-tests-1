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
#include "smp.h"
#include "fwcfg.h"
#include "apic.h"
#include "vmalloc.h"
#include "asm/setup.h"

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

u64 get_hv_features(struct ghcb *ghcb_page)
{
	u64 val;

	if (ghcb_page->protocol_version < 2) {
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

static inline int snp_set_vmsa(void *va, bool vmsa)
{
	u64 attrs;

	/* Running at VMPL 0 allows kernel to change VMSA bit for a page
	 * using RMPADJUST instr. However, for instr to succeed, we must
	 * target permissions of a lesser privileged VMPL level.
	 * Therefore, use VMPL level 1 (APM Vol 3 - RMPADJUST instr)
	 */
	attrs = 1;

	if (vmsa)
		attrs |= RMPADJUST_VMSA_PAGE_BIT;

	return rmpadjust((unsigned long)va, RMP_PG_SIZE_4K, attrs);
}

void bringup_snp_aps(int apicid)
{
	int ret;
	u64 cr4;
	struct sev_es_save_area *vmsa;

	struct ghcb *ghcb = (struct ghcb *)rdmsr(SEV_ES_GHCB_MSR_INDEX);

	if (hv_snp_ap_feature_check(ghcb)) {
		printf("SEV-SNP AP hypervisor feature NOT supported.\n");
		return;
	}

	/* To enable alloc_page() for EFI builds */
	setup_vm();

	/*
	 * TODO: Account for VMSA related SNP erratum
	 * This erratum e.xists for large pages (2M/1G)
	 * Issuing a force_4k_page() should resolve the issue?
	 */
	vmsa = (struct sev_es_save_area *)alloc_page();
	force_4k_page(vmsa);

	if (!IS_ALIGNED((phys_addr_t)vmsa, PAGE_SIZE)) {
		printf("VMSA page is NOT 4k boundary aligned.\n");
		return;
	}

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
	vmsa->cs.base		= 0;
	vmsa->cs.limit		= AP_INIT_CS_LIMIT;
	vmsa->cs.attrib		= INIT_CS_ATTRIBS;
	vmsa->cs.selector	= 0;

	vmsa->rip		= 0;

	vmsa->ds.limit		= AP_INIT_DS_LIMIT;
	vmsa->ds.attrib		= INIT_DS_ATTRIBS;

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
	vmsa->sev_features	= rdmsr(MSR_SEV_STATUS) >> 2;

	/* Switch over the page to a VMSA page now */
	ret = snp_set_vmsa(vmsa, true);

	if (ret) {
		printf("WARNING: VMSA page conversion failure.\n");
		printf("return code: %d\n", ret);
		return;
	}

	phys_addr_t ghcb_old_msr = rdmsr(SEV_ES_GHCB_MSR_INDEX);

	irq_disable();

	vc_ghcb_invalidate(ghcb);
	ghcb_set_rax(ghcb, vmsa->sev_features);
	ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_AP_CREATION);
	ghcb_set_sw_exit_info_1(ghcb, ((u64)apicid << 32) | SVM_VMGEXIT_AP_CREATE);
	ghcb_set_sw_exit_info_2(ghcb, __pa(vmsa));

	wrmsr(SEV_ES_GHCB_MSR_INDEX, __pa(ghcb));
	VMGEXIT();

	if (!ghcb_sw_exit_info_1_is_valid(ghcb) ||
	    (u32)(ghcb->save.sw_exit_info_1 &  0xffffffff)) {
		printf("SEV-SNP AP Creation Error.\n");
		return;
	}

	irq_enable();

	printf("id_map[1]: %d\n", id_map[1]);

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

static inline void alloc_runtime_data(void)
{
	struct sev_es_runtime_data *data;

	/* Enable alloc_page() for EFI builds */
	setup_vm();

	data = (struct sev_es_runtime_data *)alloc_page();
	force_4k_page(data);

	if (!data)
		return;

	/* Since BSP has entered cpu_relax() by now, this_cpu_* will
	 * only read/write data to AP.
	 */
	this_cpu_write_runtime_data(data);
}

static inline void init_ghcb(void)
{
	struct sev_es_runtime_data *data;

	data = this_cpu_read_runtime_data();

	if (!data)
		return;

	/* This GHCB page needs to be decrypted, use GHCB MSR protocol */
	if (set_page_decrypted_ghcb_msr((unsigned long)&data->ghcb_page))
		return;

	memset(&data->ghcb_page, 0, sizeof(data->ghcb_page));
	data->ghcb_active = false;
}

void sev_snp_init_ap_ghcb(void)
{
	if (!amd_sev_snp_enabled())
		return;

	/* Allocate and initialize per-CPU GHCB page */
	alloc_runtime_data();
	init_ghcb();
}

struct ghcb *get_ghcb(struct ghcb_state *state)
{
	struct sev_es_runtime_data *data;
	struct ghcb *ghcb;

	data = this_cpu_read_runtime_data();
	ghcb = &data->ghcb_page;

	state->ghcb = NULL;
	data->ghcb_active = true;

	return ghcb;
}

void put_ghcb(struct ghcb_state *state)
{
	struct sev_es_runtime_data *data;
	struct ghcb *ghcb;

	data = this_cpu_read_runtime_data();
	ghcb = &data->ghcb_page;

	/* no backup ghcb support at the moment */
	if (!state->ghcb) {
		vc_ghcb_invalidate(ghcb);
		data->ghcb_active = false;
	}
}

static inline void snp_register_ghcb(unsigned long pa)
{
	unsigned long pfn = pa >> PAGE_SHIFT;
	u64 val;

	sev_es_wr_ghcb_msr(GHCB_MSR_REG_GPA_REQ_VAL(pfn));
	VMGEXIT();
	val = rdmsr(MSR_AMD64_SEV_ES_GHCB);

	if ((GHCB_RESP_CODE(val) != GHCB_MSR_REG_GPA_RESP) ||
	    (GHCB_MSR_REG_GPA_RESP_VAL(val) != pfn)) {
		printf("GHCB GPA registration failure.\n");
		return;
	}
}

void snp_register_per_cpu_ghcb(void)
{
	struct sev_es_runtime_data *data;
	struct ghcb *ghcb;

	data = this_cpu_read_runtime_data();
	ghcb = &data->ghcb_page;

	/* Identity mapping: va = pa */
	snp_register_ghcb((unsigned long)ghcb);
}

static inline efi_status_t check_wrmsr_ghcb(u32 fn, int reg_idx,
					    u32 *reg)
{
	/* Save old GHCB MSR value */
	phys_addr_t ghcb_old_msr = rdmsr(SEV_ES_GHCB_MSR_INDEX);

	wrmsr(SEV_ES_GHCB_MSR_INDEX, GHCB_CPUID_REQ(fn, reg_idx));
	VMGEXIT();

	phys_addr_t ghcb_new_msr = rdmsr(SEV_ES_GHCB_MSR_INDEX);

	if (GHCB_RESP_CODE(ghcb_new_msr) != GHCB_MSR_CPUID_RESP)
		return EFI_UNSUPPORTED;

	*reg = (ghcb_new_msr >> 32);

	/* Restore old GHCB MSR value */
	sev_es_wr_ghcb_msr(ghcb_old_msr);

	return EFI_SUCCESS;
}

u8 snp_cpuid(struct cpuid_leaf leaf, u32 i)
{
	efi_status_t ret;
	u8 local_apicid;

	leaf.fn = i;

	ret = check_wrmsr_ghcb(leaf.fn, GHCB_CPUID_REQ_EAX,
			       &leaf.eax);

	ret = ret ? : check_wrmsr_ghcb(leaf.fn, GHCB_CPUID_REQ_EBX,
				       &leaf.ebx);

	ret = ret ? : check_wrmsr_ghcb(leaf.fn, GHCB_CPUID_REQ_ECX,
				       &leaf.ecx);

	ret = ret ? : check_wrmsr_ghcb(leaf.fn, GHCB_CPUID_REQ_EDX,
				       &leaf.edx);

	local_apicid = (u8)((leaf.ebx & GENMASK_ULL(31, 24)) >> 24);

	return local_apicid;
}
