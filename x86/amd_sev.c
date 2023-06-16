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
#include "x86/xsave.h"
#include "alloc_page.h"
#include "x86/vm.h"

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define TESTDEV_IO_PORT 0xe0

#define CPUID_EXTENDED_STATE	0xd

extern phys_addr_t ghcb_addr;
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
	u64 result;

	ghcb_set_rax(ghcb, leaf->eax_in);
	ghcb_set_rcx(ghcb, leaf->ecx_in);

	xgetbv_checking(XCR_XFEATURE_ENABLED_MASK, &result);

	if (leaf->eax_in == CPUID_EXTENDED_STATE)
		ghcb_set_xcr0(ghcb, (X86_CR4_OSXSAVE & read_cr4()) ?
				    result : 1);

	ghcb->ghcb_usage = GHCB_DEFAULT_USAGE;
	ghcb->protocol_version = GHCB_PROTOCOL_MAX;
	ghcb_set_sw_exit_code(ghcb, SVM_EXIT_CPUID);
	ghcb_set_sw_exit_info_1(ghcb, 0);
	ghcb_set_sw_exit_info_2(ghcb, 0);

	VMGEXIT();

	if (!ghcb_sw_exit_info_1_is_valid(ghcb) ||
	    ghcb->save.sw_exit_info_1 & 0xffffffff)
		return 1;

	/* Check if valid bits are set for each register by hypervisor */
	if (!ghcb_rax_is_valid(ghcb) || !ghcb_rbx_is_valid(ghcb) ||
	    !ghcb_rcx_is_valid(ghcb) || !ghcb_rdx_is_valid(ghcb))
		return 2;

	/* Copy ghcb register info to cpuid leaf */
	leaf->eax = (u32)ghcb->save.rax;
	leaf->ebx = (u32)ghcb->save.rbx;
	leaf->ecx = (u32)ghcb->save.rcx;
	leaf->edx = (u32)ghcb->save.rdx;

	return 0;
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

static inline efi_status_t fetch_and_compare(u32 iter, u32 ecx_in,
					     struct ghcb *ghcb,
					     struct cpuid *guest_cpuid)
{
	struct cpuid_leaf guest_cpuid_leaf, hyp_cpuid;
	*guest_cpuid = cpuid_indexed(iter, ecx_in);

	copy_cpuid_leaf(&guest_cpuid_leaf, *guest_cpuid, iter, ecx_in);

	hyp_cpuid.eax_in = iter;
	hyp_cpuid.ecx_in = ecx_in;

	if (fetch_cpuid_hyp(ghcb, &hyp_cpuid))
		return EFI_UNSUPPORTED;

	if (!compare_cpuid(guest_cpuid_leaf, hyp_cpuid)) {
		result_mismatch(iter, &guest_cpuid_leaf, &hyp_cpuid);
		return EFI_NOT_FOUND;
	}

	return EFI_SUCCESS;
}

static inline efi_status_t iter_over_leafs(u32 start, struct ghcb *ghcb,
					   bool is_extended, struct cpuid result)
{
	efi_status_t status = EFI_SUCCESS;
	u32 range_max = result.a, iter;

	if (is_extended)
		range_max &= 0xff;

	for (iter = start; iter <= range_max; iter++) {
		struct cpuid guest_cpuid;

		status = fetch_and_compare(iter, 0, ghcb, &guest_cpuid);
		if (status == EFI_UNSUPPORTED)
			return status;

		/* Sub-leaf handling for standard and extended leafs */
		if (iter == 0x0000000b || iter == 0x8000001d) {
			u32 subleaf = 0;

			do {
				subleaf++;
				status = fetch_and_compare(iter, subleaf,
							   ghcb, &guest_cpuid);

				if (status == EFI_UNSUPPORTED)
					return status;
			} while (guest_cpuid.a);
		}

		/* sub-leaf handling for CPUID leaf 0xD with non-zero sub leafs */
		else if (iter == 0x0000000d) {
			u32 xsave_support_ft_mask = guest_cpuid.a;
			u32 subleaf;

			status = fetch_and_compare(iter, 1, ghcb, &guest_cpuid);

			if (status == EFI_UNSUPPORTED)
				return status;

			for (subleaf = 1; subleaf < 32; subleaf++) {
				if (!(xsave_support_ft_mask & (1 << subleaf))) {
					subleaf++;
					continue;
				}

				status = fetch_and_compare(iter, subleaf,
							   ghcb, &guest_cpuid);

				if (status == EFI_UNSUPPORTED)
					return status;
			}
		}
	}

	return status;
}

static inline efi_status_t test_sev_snp_cpuid(struct ghcb *ghcb)
{
	struct cpuid res_std, res_ext;

	res_std = cpuid_indexed(0x0, 0);
	res_ext = cpuid_indexed(0x80000000, 0);

	if (iter_over_leafs(0x0, ghcb, false, res_std) == EFI_SUCCESS &&
	    iter_over_leafs(0x80000000, ghcb, true, res_ext) == EFI_SUCCESS)
		return EFI_SUCCESS;

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
	 * If here: PSC is successful in RMP table, validate the page
	 * in the guest so that it is consistent with the RMP entry
	 */
	if (op == SNP_PAGE_STATE_PRIVATE &&
	    pvalidate(paddr, RMP_PG_SIZE_4K, 1)) {
		return ES_UNSUPPORTED;
	}

	return ES_OK;
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

static void test_sev_snp_activation(void)
{
	efi_status_t status;

	if (!amd_sev_snp_enabled()) {
		printf("SEV-SNP is NOT enabled.\n");
		return;
	}

	printf("SEV-SNP is enabled.\n");

	status = find_cc_blob_efi();
	if (status != EFI_SUCCESS) {
		printf("WARNING: SEV-SNP CC blob is NOT present.\n");
		return;
	}

	struct ghcb *ghcb = (struct ghcb *)ghcb_addr;

	status = test_sev_snp_cpuid(ghcb);
	if (status != EFI_SUCCESS) {
		printf("WARNING: SEV-SNP CPUID NOT matching all leaves\n");
		return;
	}
}

static inline void test_sev_snp_psc(void)
{
	unsigned long *vaddr;

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
