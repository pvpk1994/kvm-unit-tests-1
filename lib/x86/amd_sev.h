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

#ifdef TARGET_EFI

#include "libcflat.h"
#include "desc.h"
#include "asm/page.h"
#include "efi.h"

/*
 * AMD SEV Confidential computing blob structure. The structure is
 * defined in OVMF UEFI firmware header:
 * This is it.
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

struct cpuid_leaf {
	uint32_t eax_in;
	uint32_t ecx_in;
	uint32_t eax;
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
};

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
#define SVM_EXIT_CPUID  0x72ULL

/*
 * AMD Programmer's Manual Volume 2
 *   - Section "GHCB"
 */
#define SEV_ES_GHCB_MSR_INDEX 0xc0010130
#define VMGEXIT()		{ asm volatile("rep; vmmcall\n\r"); }

typedef struct {
	uint8_t  reserved1[203];
	uint8_t  cpl;
	uint8_t  reserved8[300];
	uint64_t rax;
	uint8_t  reserved4[264];
	uint64_t rcx;
	uint64_t rdx;
	uint64_t rbx;
	uint8_t  reserved5[112];
	uint64_t sw_exit_code;
	uint64_t sw_exit_info1;
	uint64_t sw_exit_info2;
	uint64_t sw_scratch;
	uint8_t  reserved6[56];
	uint64_t xcr0;
	uint8_t  valid_bitmap[16];
	uint64_t x87_state_gpa;
	uint8_t  reserved7[1016];
} ghcb_save_area;

typedef struct {
	ghcb_save_area	save_area;
	uint8_t		shared_buffer[2032];
	uint8_t		reserved1[10];
	uint16_t	protocol_version;
	uint32_t	ghcb_usage;
} ghcb_page;

#define OFFSET_OF(TYPE, Field)  ((uint64_t)&(((TYPE *)0)->Field))

#define GHCB_SAVE_AREA_QWORD_OFFSET(reg_field) \
	(OFFSET_OF(ghcb_page, save_area.reg_field) / sizeof(uint64_t))

typedef enum {
	ghcb_cpl	= GHCB_SAVE_AREA_QWORD_OFFSET(cpl),
	ghcb_rax	= GHCB_SAVE_AREA_QWORD_OFFSET(rax),
	ghcb_rbx	= GHCB_SAVE_AREA_QWORD_OFFSET(rbx),
	ghcb_rcx	= GHCB_SAVE_AREA_QWORD_OFFSET(rcx),
	ghcb_rdx	= GHCB_SAVE_AREA_QWORD_OFFSET(rdx),
	ghcb_xcr0	= GHCB_SAVE_AREA_QWORD_OFFSET(xcr0),
	ghcb_sw_exit_code = GHCB_SAVE_AREA_QWORD_OFFSET(sw_exit_code),
	ghcb_sw_exit_info1 = GHCB_SAVE_AREA_QWORD_OFFSET(sw_exit_info1),
	ghcb_sw_exit_info2 = GHCB_SAVE_AREA_QWORD_OFFSET(sw_exit_info2),
	ghcb_sw_scratch	= GHCB_SAVE_AREA_QWORD_OFFSET(sw_scratch),
} GHCB_REGISTER;

/* MSR information for SEV_ES_GHCB_MSR_INDEX */
typedef union {
	struct {
		uint32_t function:  12;
		uint32_t reserved1: 20;
		uint32_t reserved2: 32;
	} ghcb_info;

	struct {
		uint8_t reserved[3];
		uint8_t sev_enc_bit_pos;
		uint8_t sev_protocol_min;
		uint8_t sev_protocol_max;
	} ghcb_protocol;

	struct {
		uint32_t function       : 12;
		uint32_t reason_code_set: 4;
		uint32_t reason_code    : 8;
		uint32_t reserved1      : 8;
		uint32_t reserved2      : 32;
	} ghcb_terminate;

	struct {
		uint64_t function  : 12;
		uint64_t features  : 52;
	} ghcb_hyp_features;

	struct {
		uint64_t function	: 12;
		uint64_t guest_frame_no : 52;
	} ghcb_gpa_reg;

	struct {
		uint64_t  function	: 12;
		uint64_t  gfn		: 40;
		uint64_t  operation	: 4;
		uint64_t  reserved	: 8;
	} snp_psc_req;

	struct {
		uint32_t    function : 12;
		uint32_t    reserved : 20;
		uint32_t    error_code;
	} snp_psc_resp;


	uint64_t ghcb_phys_addr;
	void *ghcb;

} msr_sev_ghcb_reg;

bool amd_sev_es_enabled(void);
void setup_ghcb_pte(pgd_t *page_table);

bool amd_sev_snp_enabled(void);
efi_status_t setup_vc_handler(void);

unsigned long long get_amd_sev_c_bit_mask(void);
unsigned long long get_amd_sev_addr_upperbound(void);
void vmg_set_offset_valid(ghcb_page *ghcb, GHCB_REGISTER offset);
void mem_fence(void);
void vmgexit(ghcb_page *ghcb, uint64_t exit_code, uint64_t exit_info1,
		uint64_t exit_info2);
uint64_t asm_read_cr4(void);
uint64_t asm_xgetbv(uint32_t index);

#endif /* TARGET_EFI */

#endif /* _X86_AMD_SEV_H_ */
