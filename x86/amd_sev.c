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

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define TESTDEV_IO_PORT 0xe0

#define CPUID_EXTENDED_STATE	0x0D

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
		printf("WARNING: SEV-SNP CC header magic does not match.\n");

	return EFI_SUCCESS;
}

static void copy_cpuid_leaf(struct cpuid_leaf *leaf, struct cpuid
			g_cpuid, uint32_t eax_input, uint32_t ecx_input)
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

	leaf->eax = (uint32_t) ghcb->save_area.rax;
	leaf->ebx = (uint32_t) ghcb->save_area.rbx;
	leaf->ecx = (uint32_t) ghcb->save_area.rcx;
	leaf->edx = (uint32_t) ghcb->save_area.rdx;

	printf("Hypervisor CPUID leaf-0x%08x:\n sub-leaf-0x%08x:\n"
		" EAX:0x%x\n EBX:0x%x\n ECX:0x%x\n EDX:0x%x\n",
		leaf->eax_in, leaf->ecx_in, leaf->eax, leaf->ebx,
		leaf->ecx, leaf->edx);

}

static efi_status_t test_standard_cpuid_range(struct cpuid result,
				ghcb_page *ghcb)
{
	uint32_t std_range_max = result.a, iter;

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
			uint32_t subfn = 1;

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
			uint32_t subleaf = 1;
			uint32_t xsave_support_ft_mask = guest_cpuid.a;

			/* subleaf 1 is always present */
			guest_cpuid = cpuid_indexed(iter, 1);

			copy_cpuid_leaf(&guest_cpuid_leaf, guest_cpuid,
					iter, 1);

			hyp_cpuid.eax_in = iter;
			hyp_cpuid.ecx_in = 1;

			fetch_cpuid_hyp(ghcb, &hyp_cpuid);

			if (!compare_cpuid(guest_cpuid_leaf, hyp_cpuid)) {
				printf("WARNING: CPUID leaf %d sub-leaf %d mismatch.\n"
					, iter, subleaf);
				return EFI_NOT_FOUND;
			}

			while (subleaf < 32) {
				if (!(xsave_support_ft_mask & (1 <<
					subleaf))) {
					subleaf++;
					continue;
				}

				guest_cpuid = cpuid_indexed(iter,
						subleaf);

				copy_cpuid_leaf(&guest_cpuid_leaf,
					guest_cpuid, iter, subleaf);

				hyp_cpuid.eax_in = iter;
				hyp_cpuid.ecx_in = subleaf;

				fetch_cpuid_hyp(ghcb, &hyp_cpuid);

				if (!compare_cpuid(guest_cpuid_leaf,
					hyp_cpuid)) {
					printf("WARNING: CPUID leaf %d sub-leaf %d mismatch.\n"
						, iter, subleaf);
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
	uint32_t ext_range_max = result.a & 0xff, iter;

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
			uint32_t subfn = 1;

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
	printf("SEV-SNP IS advertised by CPUID.\n");

	if (cpuid_out.a & VMPL_SUPPORT_MASK) {
		printf("VMPL support is advertised by CPUID.\n");

		vmpl_bits = (cpuid_out.b & VMPL_COUNT_MASK) >>
				VMPL_COUNT_SHIFT;
		printf("Number of VMPLs: %lu\n", vmpl_bits);
	} else {
		printf("VMPL support is NOTTTT yet advertised by CPUID.\n");
	}

	if (rdmsr(MSR_SEV_STATUS) & SEV_SNP_ENABLED_MASK) {
		printf("SEV-SNP is enabled.\n");

		status = find_cc_blob_efi();

		ghcb_page *ghcb = (ghcb_page *)
			(rdmsr(SEV_ES_GHCB_MSR_INDEX));

		status = test_sev_snp_cpuid(ghcb);

		printf("SEV-SNP CPUID %s matching all leaves\n", status
				== EFI_SUCCESS ? "":"NOT");

		printf("%s SEV-SNP CC blob is %s present.\n",
			status == EFI_SUCCESS ? "" : "WARNING:",
			status == EFI_SUCCESS ? "" : "NOT");
	} else
		printf("WARNING: SEV-SNP is not enabled.\n");
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
	test_stringio();
	return report_summary();
}
