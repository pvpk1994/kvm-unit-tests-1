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

#ifndef _X86_AMD_SEV_H_
#define _X86_AMD_SEV_H_

#ifdef CONFIG_EFI

#include "libcflat.h"
#include "desc.h"
#include "asm/page.h"
#include "efi.h"

/*
 * AMD SEV Confidential computing blob structure. The structure is
 * defined in OVMF UEFI firmware header:
 *
 * https://github.com/tianocore/edk2/blob/master/OvmfPkg/Include/Guid/ConfidentialComputingSevSnpBlob.h
 */
#define CC_BLOB_SEV_HDR_MAGIC	0x45444d41
struct cc_blob_sev_info {
	u32 magic;
	u16 version;
	u16 reserved;
	u64 secrets_phys;
	u32 secrets_len;
	u32 rsvd1;
	u64 cpuid_phys;
	u32 cpuid_len;
	u32 rsvd2;
} __packed;

/*
 * AMD Programmer's Manual Volume 3
 *   - Section "Function 8000_0000h - Maximum Extended Function Number and Vendor String"
 *   - Section "Function 8000_001Fh - Encrypted Memory Capabilities"
 */
#define CPUID_FN_LARGEST_EXT_FUNC_NUM 0x80000000
#define CPUID_FN_ENCRYPT_MEM_CAPAB    0x8000001f
#define SEV_SUPPORT_MASK              0b10
#define SEV_SNP_SUPPORT_MASK		0b10000
#define VMPL_SUPPORT_MASK		0b100000
#define VMPL_COUNT_MASK			0xF000
#define VMPL_COUNT_SHIFT		12

/*
 * AMD Programmer's Manual Volume 2
 *   - Section "SEV_STATUS MSR"
 */
#define MSR_SEV_STATUS      0xc0010131
#define SEV_ENABLED_MASK    0b1
#define SEV_ES_ENABLED_MASK 0b10
#define SEV_SNP_ENABLED_MASK		0b100

bool amd_sev_enabled(void);
efi_status_t setup_amd_sev(void);

/*
 * AMD Programmer's Manual Volume 2
 *   - Section "#VC Exception"
 */
#define SEV_ES_VC_HANDLER_VECTOR 29

/*
 * AMD Programmer's Manual Volume 2
 *   - Section "GHCB"
 */
#define SEV_ES_GHCB_MSR_INDEX 0xc0010130

bool amd_sev_es_enabled(void);
void setup_ghcb_pte(pgd_t *page_table);

bool amd_sev_snp_enabled(void);
efi_status_t setup_vc_handler(void);

unsigned long long get_amd_sev_c_bit_mask(void);
unsigned long long get_amd_sev_addr_upperbound(void);

#endif /* CONFIG_EFI */

#endif /* _X86_AMD_SEV_H_ */
