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

#define CPUID_EXTENDED_STATE	0x0D

#define _PAGE_ENC	(_AT(pteval_t, get_amd_sev_c_bit_mask()))

struct cc_blob_sev_info *snp_cc_blob;

static char st1[] = "abcdefghijklmnop";

static unsigned long addr;
static unsigned long *vm_pages;

static void snp_set_page_shared(unsigned long paddr);
static void snp_set_page_private(unsigned long paddr);
static void set_page_encrypted(void);
static void set_page_decrypted(void);
static void unset_c_bit_pte(void);
static void test_sev_snp_psc(void);
static void set_c_bit_pte(void);
static void snp_set_memory_shared(unsigned long vaddr, unsigned int npages,
				  ghcb_page *ghcb);
static void snp_set_memory_private(unsigned long vaddr, unsigned int npages,
				   ghcb_page *ghcb);

/* #VC handler for runtime per-CPU data */
struct sev_es_runtime_data {
	ghcb_page ghcb;

	/*
	 * Reserve one page per CPU as a backup storage for unencrypted
	 * GHCB. This is needed when an NMI happens while the #VC
	 * handler is using the primary GHCB, and the NMI handler itself
	 * is causing another #VC exception. In such a case, the GHCB
	 * content of the first handler needs to be backed up and
	 * restored.
	 */
	ghcb_page backup_ghcb;

	/*
	 * Mark the per-CPU GHCBs as in-use to detect nested #VC exceptions.
	 * This is necessary for example: #VC -> NMI -> #VC when NMI
	 * happens while first #VC handler uses GHCB. When an NMI
	 * handler raises a second #VC handler, it might overwrite the
	 * contents of the first GHCB written by the first handler. To
	 * avoid this potential overwrite condition, content of first
	 * GHCB is saved and restored when GHCB is detected to be in use
	 * already.
	 */
	bool ghcb_active;
	bool backup_ghcb_active;
};

struct ghcb_state {
	ghcb_page *ghcb;
};

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
		printf("WARNING: SEV-SNP CC header magic does not match.\n");

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

	printf("SNP CPUID leaf-0x%08x:\n sub-leaf-0x%08x:\n"
		" EAX:0x%x\n EBX:0x%x\n ECX:0x%x\n EDX:0x%x\n",
		leaf->eax_in, leaf->ecx_in, leaf->eax, leaf->ebx,
		leaf->ecx, leaf->edx);
}

inline bool compare_cpuid(struct cpuid_leaf cpuid0, struct cpuid_leaf
				cpuid1)
{
	return cpuid0.eax == cpuid1.eax && cpuid0.ebx == cpuid1.ebx &&
		cpuid0.ecx == cpuid1.ecx && cpuid0.edx == cpuid1.edx;
}

/* Fetch CPUID leaf from Hypervisor, via VMGEXIT using GHCB page */
static void fetch_cpuid_hyp(ghcb_page *ghcb, struct cpuid_leaf *leaf)
{
	ghcb->save_area.rax = leaf->eax_in;
	vmg_set_offset_valid(ghcb, ghcb_rax);
	ghcb->save_area.rcx = leaf->ecx_in;
	vmg_set_offset_valid(ghcb, ghcb_rcx);

	if (leaf->eax_in == CPUID_EXTENDED_STATE) {
		ia32_cr4 cr;

		cr.uint64 = asm_read_cr4();
		ghcb->save_area.xcr0 = (cr.bits.osxsave == 1) ?
				       asm_xgetbv(0) : 1;
		vmg_set_offset_valid(ghcb, ghcb_xcr0);
	}

	vmgexit(ghcb, SVM_EXIT_CPUID, 0, 0);

	leaf->eax = (u32)ghcb->save_area.rax;
	leaf->ebx = (u32)ghcb->save_area.rbx;
	leaf->ecx = (u32)ghcb->save_area.rcx;
	leaf->edx = (u32)ghcb->save_area.rdx;

	printf("Hypervisor CPUID leaf-0x%08x:\n sub-leaf-0x%08x:\n"
	       " EAX:0x%x\n EBX:0x%x\n ECX:0x%x\n EDX:0x%x\n",
	       leaf->eax_in, leaf->ecx_in, leaf->eax, leaf->ebx,
	       leaf->ecx, leaf->edx);
}

static efi_status_t test_standard_cpuid_range(struct cpuid result,
					      ghcb_page *ghcb)
{
	u32 std_range_max = result.a, iter;

	printf("standard max range: %d\n", std_range_max);
	for (iter = 1; iter <= std_range_max; iter++) {
		struct cpuid guest_cpuid = cpuid_indexed(iter, 0);
		struct cpuid_leaf guest_cpuid_leaf, hyp_cpuid;

		copy_cpuid_leaf(&guest_cpuid_leaf, guest_cpuid, iter, 0);

		hyp_cpuid.eax_in = iter;
		hyp_cpuid.ecx_in = 0;

		fetch_cpuid_hyp(ghcb, &hyp_cpuid);

		if (!compare_cpuid(guest_cpuid_leaf, hyp_cpuid)) {
			printf("WARNING: CPUID leaf %d mismatch.\n", iter);
			return EFI_NOT_FOUND;
		}

		/*
		 * Special handling for CPUID leaf 0xb having non-zero
		 * sub-leaves.
		 */
		if (guest_cpuid_leaf.eax_in == 0x0000000b) {
			u32 subfn = 1;

			guest_cpuid_leaf.ecx_in = subfn;

			do {
				guest_cpuid =
					cpuid_indexed(guest_cpuid_leaf.eax_in,
						      subfn);

				copy_cpuid_leaf(&guest_cpuid_leaf,
						guest_cpuid, iter, subfn);

				hyp_cpuid.eax_in = iter;
				hyp_cpuid.ecx_in = subfn;

				fetch_cpuid_hyp(ghcb, &hyp_cpuid);

				if (!compare_cpuid(guest_cpuid_leaf,
						   hyp_cpuid)) {
					printf("WARNING: CPUID leaf %d sub-leaf %d mismatch.\n",
					       iter, guest_cpuid_leaf.ecx_in);
					return EFI_NOT_FOUND;
				}
				subfn++;
			} while (guest_cpuid.a);
		}

		/*
		 * Special handling for CPUID leaf 0xD having non-zero
		 * sub-leaves
		 */
		else if (guest_cpuid_leaf.eax_in == 0x0000000d) {
			u32 subleaf = 1;
			u32 xsave_support_ft_mask = guest_cpuid.a;

			/* subleaf 1 is always present */
			guest_cpuid = cpuid_indexed(iter, 1);

			copy_cpuid_leaf(&guest_cpuid_leaf, guest_cpuid,
					iter, 1);

			hyp_cpuid.eax_in = iter;
			hyp_cpuid.ecx_in = 1;

			fetch_cpuid_hyp(ghcb, &hyp_cpuid);

			if (!compare_cpuid(guest_cpuid_leaf, hyp_cpuid)) {
				printf("WARNING: CPUID leaf %d sub-leaf %d mismatch.\n",
				       iter, subleaf);
				return EFI_NOT_FOUND;
			}

			while (subleaf < 32) {
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
					printf("WARNING: CPUID leaf %d sub-leaf %d mismatch.\n",
					       iter, subleaf);
					return EFI_NOT_FOUND;
				}
				subleaf++;
			}
		}
	}
	return EFI_SUCCESS;
}

static efi_status_t test_extended_cpuid_range(struct cpuid result,
					      ghcb_page *ghcb)
{
	u32 ext_range_max = result.a & 0xff, iter;

	printf("extended max range: %d\n", ext_range_max);
	for (iter = 0x80000001; iter <= result.a; iter++) {
		struct cpuid guest_cpuid = cpuid_indexed(iter, 0);
		struct cpuid_leaf guest_cpuid_leaf, hyp_cpuid;

		copy_cpuid_leaf(&guest_cpuid_leaf, guest_cpuid, iter, 0);

		hyp_cpuid.eax_in = iter;
		hyp_cpuid.ecx_in = 0;

		fetch_cpuid_hyp(ghcb, &hyp_cpuid);

		if (!compare_cpuid(guest_cpuid_leaf, hyp_cpuid)) {
			printf("WARNING: CPUID leaf %d mismatch.\n", iter);
			return EFI_NOT_FOUND;
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
					printf("WARNING: CPUID leaf %d sub-leaf %d mismatch.\n",
					       iter, subfn);
					return EFI_NOT_FOUND;
				}
				subfn++;
			} while (guest_cpuid.a);
		}
	}

	return EFI_SUCCESS;
}

static efi_status_t test_sev_snp_cpuid(ghcb_page *ghcb)
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

	if (rmp_unchanged)
		return 1;

	return result;
}

static void __page_state_change(unsigned long paddr, enum psc_op op)
{
	u64 val;

	if (!(rdmsr(MSR_SEV_STATUS) & SEV_SNP_ENABLED_MASK))
		return;

	/* Save the old GHCB MSR */
	phys_addr_t ghcb_old_msr = rdmsr(SEV_ES_GHCB_MSR_INDEX);

	/*
	 * If action requested is to convert the page from private to
	 * shared, then invalidate the page before we send it to
	 * hypervisor to change the state of page in RMP table.
	 */
	if (op == SNP_PAGE_STATE_SHARED &&
	    pvalidate(paddr, RMP_PG_SIZE_4K, 0)) {
		/* Restore old GHCB MSR */
		wrmsr(SEV_ES_GHCB_MSR_INDEX, ghcb_old_msr);
		printf("WARNING: pvalidate failed during private -> shared conversion.\n");
		return;
	}

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
		wrmsr(SEV_ES_GHCB_MSR_INDEX, ghcb_old_msr);
		printf("WARNING: Failed to read Hypervisor response.\n");
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

static void snp_set_page_shared(unsigned long paddr)
{
	__page_state_change(paddr, SNP_PAGE_STATE_SHARED);
}

static void unset_c_bit_pte(void)
{
	pteval_t *pte;

	pte = get_pte((pgd_t *)read_cr3(), (void *)addr);

	if (!pte) {
		printf("WARNING: pte is null.\n");
		assert(pte);
	}

	/* unset c-bit */
	*pte &= ~(get_amd_sev_c_bit_mask());
}

void set_c_bit_pte(void)
{
	pteval_t *pte;

	pte = get_pte((pgd_t *)read_cr3(), (void *)addr);

	if (!pte) {
		printf("WARNING: pte is null.\n");
		assert(pte);
	}

	/* Set c-bit */
	*pte |= get_amd_sev_c_bit_mask();
}

static void set_clr_page_flags(pteval_t set, pteval_t clr)
{
	if (clr & _PAGE_ENC) {
		/*
		 * If the encryption bit is cleared, make the page state
		 * entry to SHARED in RMP table.
		 */
		snp_set_page_shared(__pa(addr & PAGE_MASK));
		unset_c_bit_pte();
	}

	else if (set & _PAGE_ENC) {
		set_c_bit_pte();
		snp_set_page_private(__pa(addr & PAGE_MASK));
	}

	flush_tlb();
}

void set_page_decrypted(void)
{
	set_clr_page_flags(0, _PAGE_ENC);
}

void set_page_encrypted(void)
{
	set_clr_page_flags(_PAGE_ENC, 0);
}

static enum es_result verify_exception(ghcb_page *ghcb)
{
	int ret;

	ret = ghcb->save_area.sw_exit_info1 & GENMASK_ULL(31, 0);

	if (!ret)
		return ES_OK;

	return ret;
}

static enum es_result sev_ghcb_hv_call(ghcb_page *ghcb, u64 exit_code,
				       u64 exit_info_1, u64 exit_info_2)
{
	ghcb->protocol_version = 2;
	ghcb->ghcb_usage = GHCB_DEFAULT_USAGE;

	ghcb_set_sw_exit_code(ghcb, exit_code);
	ghcb_set_sw_exit_info1(ghcb, exit_info_1);
	ghcb_set_sw_exit_info2(ghcb, exit_info_2);

	VMGEXIT();

	return verify_exception(ghcb);
}

static int vmgexit_psc(struct snp_psc_desc *desc, ghcb_page *ghcb)
{
	int cur_entry, end_entry, ret = 0;
	struct snp_psc_desc *data;

	/* Save the old GHCB MSR */
	phys_addr_t ghcb_old_msr = rdmsr(SEV_ES_GHCB_MSR_INDEX);

	data = (struct snp_psc_desc *)ghcb->shared_buffer;
	memcpy(ghcb->shared_buffer, desc, sizeof(*desc));

	cur_entry = data->hdr.cur_entry;
	end_entry = data->hdr.end_entry;

	while (data->hdr.cur_entry <= data->hdr.end_entry) {
		ghcb_set_sw_scratch(ghcb, (uint64_t)__pa(data));

		ret = sev_ghcb_hv_call(ghcb, SVM_VMGEXIT_PSC, 0, 0);

		if (ret || ghcb->save_area.sw_exit_info2) {
			wrmsr(SEV_ES_GHCB_MSR_INDEX, ghcb_old_msr);
			printf("SNP: PSC failed ret=%d exit_info_2=%lx\n",
			       ret, ghcb->save_area.sw_exit_info2);
			ret = 1;
			goto out;
		}

		if (data->hdr.reserved) {
			wrmsr(SEV_ES_GHCB_MSR_INDEX, ghcb_old_msr);
			printf("Reserved bit is set in the PSC header\n");
			ret = 1;
			goto out;
		}

		if (data->hdr.end_entry > end_entry ||
		    cur_entry > data->hdr.cur_entry) {
			wrmsr(SEV_ES_GHCB_MSR_INDEX, ghcb_old_msr);
			printf("SNP: PSC processing going backward, end_entry %d (got %d) cur_entry %d (got %d)\n",
			       end_entry, data->hdr.end_entry,
			       cur_entry, data->hdr.cur_entry);
			ret = 1;
			goto out;
		}

		wrmsr(SEV_ES_GHCB_MSR_INDEX, ghcb_old_msr);
		printf("cur_entry: %d end_entry: %d\n",
		       data->hdr.cur_entry, data->hdr.end_entry);
	}

	wrmsr(SEV_ES_GHCB_MSR_INDEX, ghcb_old_msr);
	return ret;

out:
	return ret;
}

static void __set_pages_state(struct snp_psc_desc *data, unsigned long vaddr,
			      unsigned long vaddr_end, int op, ghcb_page *ghcb)
{
	/* Save the old GHCB MSR */
	phys_addr_t ghcb_old_msr = rdmsr(SEV_ES_GHCB_MSR_INDEX);
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

	if (vmgexit_psc(data, ghcb)) {
		wrmsr(SEV_ES_GHCB_MSR_INDEX, ghcb_old_msr);
		printf("WARNING: VMGEXIT unsuccessful.\n");
		return;
	}

	wrmsr(SEV_ES_GHCB_MSR_INDEX, ghcb_old_msr);
}

static void set_pages_state(unsigned long vaddr, unsigned int npages,
			    int op, ghcb_page *ghcb)
{
	unsigned long vaddr_start = __pa(vaddr & PAGE_MASK), vaddr_end;
	struct snp_psc_desc *desc;

	desc = malloc(sizeof(*desc));
	if (!desc) {
		printf("WARNING: Failed to allocate memory for PSC descriptor.\n");
		return;
	}

	vaddr_end = vaddr_start + (npages << PAGE_SHIFT);

	/*
	 * Calculate the last vaddr that can fit in PSC_MAX_ENTRY's
	 * struct snp_psc_desc.
	 */

	__set_pages_state(desc, vaddr_start, vaddr_end, op, ghcb);

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

	/* Save the old GHCB MSR */
	phys_addr_t ghcb_old_msr = rdmsr(SEV_ES_GHCB_MSR_INDEX);

	/* Issue pvaldiate on every single page */
	while (vaddr_start < vaddr_end) {
		pvalidate_result = pvalidate(vaddr_start, RMP_PG_SIZE_4K,
					     validate);
		wrmsr(SEV_ES_GHCB_MSR_INDEX, ghcb_old_msr);

		printf("%s, vaddr: 0x%lx vaddr_end: 0x%lx\n", __func__,
		       vaddr_start, vaddr_end);

		if (pvalidate_result) {
			wrmsr(SEV_ES_GHCB_MSR_INDEX, ghcb_old_msr);
			printf("WARNING: pvalidate unsuccessful\n");
			return;
		}
		vaddr_start = vaddr_start + PAGE_SIZE;
	}
}

void snp_set_memory_shared(unsigned long vaddr, unsigned int npages,
			   ghcb_page *ghcb)
{
	/* Invalidate all the pages before turning them to shared */
	pvalidate_pages(vaddr, npages, false);

	set_pages_state(vaddr, npages, SNP_PAGE_STATE_SHARED, ghcb);
}

void snp_set_memory_private(unsigned long vaddr, unsigned int npages,
			    ghcb_page *ghcb)
{
	/* pvalidate all the pages after turning them to private */
	set_pages_state(vaddr, npages, SNP_PAGE_STATE_PRIVATE, ghcb);

	pvalidate_pages(vaddr, npages, true);
}

static void test_sev_snp_activation(void)
{
	unsigned long vmpl_bits;
	efi_status_t status;
	struct cpuid cpuid_out;

	cpuid_out = cpuid(CPUID_FN_ENCRYPT_MEM_CAPAB);

	if (!(cpuid_out.a & SEV_SNP_SUPPORT_MASK)) {
		printf("SEV-SNP is not advertised by CPUID.\n");
		return;
	}
	printf("SEV-SNP is advertised by CPUID.\n");

	if (cpuid_out.a & VMPL_SUPPORT_MASK) {
		printf("VMPL support is advertised by CPUID.\n");

		vmpl_bits = (cpuid_out.b & VMPL_COUNT_MASK) >>
				VMPL_COUNT_SHIFT;
		printf("Number of VMPLs: %lu\n", vmpl_bits);
	} else {
		printf("VMPL support is NOT advertised by CPUID.\n");
	}

	if (rdmsr(MSR_SEV_STATUS) & SEV_SNP_ENABLED_MASK) {
		printf("SEV-SNP is enabled.\n");

		status = find_cc_blob_efi();

		ghcb_page *ghcb = (ghcb_page *)
			(rdmsr(SEV_ES_GHCB_MSR_INDEX));

		status = test_sev_snp_cpuid(ghcb);

		printf("SEV-SNP CPUID %s matching all leaves\n",
		       status == EFI_SUCCESS ? "" : "NOT");

		printf("%s SEV-SNP CC blob is %s present.\n",
		       status == EFI_SUCCESS ? "" : "WARNING:",
		       status == EFI_SUCCESS ? "" : "NOT");
	} else
		printf("WARNING: SEV-SNP is not enabled.\n");
}

static void test_read_write(unsigned long paddr, int num_pages, int op)
{
	int iter;

	for (iter = 0; iter < num_pages; iter++) {
		strcpy((char *)&paddr, st1);
		if (op == SNP_PAGE_STATE_SHARED)
			printf("Shared page %d's content: %s\n", iter + 1,
			       (char *)&paddr);
		else
			printf("Private page %d's content: %s\n", iter + 1,
			       (char *)&paddr);

		paddr += PAGE_SIZE;
	}
}

static void test_sev_snp_psc(void)
{
	unsigned long addr_shared, vaddr, addr_private;

	addr = (unsigned long)alloc_page();

	if (!addr) {
		printf("WARNING: Page not allocated!\n");
		assert(addr);
	}

	install_4k_pte((pgd_t *)read_cr3(), addr);
	/* Perform Private <=> Shared page state change */
	set_page_decrypted();
	vaddr = addr;
	strcpy((char *)addr, st1);
	printf("Address content: %s\n", (char *)addr);

	/* Convert same page back from Shared => Private here */
	addr = vaddr;
	set_page_encrypted();
	strcpy((char *)addr, st1);
	printf("Address content: %s\n", (char *)addr);

	/* Allocate 4 (1<<2) pages for testing */
	vm_pages = (unsigned long *)alloc_pages(2);

	install_4k_pte((pgd_t *)read_cr3(), (unsigned long)vm_pages);

	ghcb_page *ghcb = (ghcb_page *)(rdmsr(SEV_ES_GHCB_MSR_INDEX));

	addr_shared = __pa((unsigned long)vm_pages);
	/* Page State Changes - Private to Shared */
	snp_set_memory_shared(addr_shared, 4, ghcb);
	test_read_write(addr_shared, 4, SNP_PAGE_STATE_SHARED);

	/* Page state changes - Shared to Private */
	addr_private = __pa((unsigned long)vm_pages);
	snp_set_memory_private(addr_private, 4, ghcb);
	test_read_write(addr_private, 4, SNP_PAGE_STATE_PRIVATE);
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
	test_sev_snp_activation();
	test_sev_snp_psc();
	test_stringio();
	return report_summary();
}
