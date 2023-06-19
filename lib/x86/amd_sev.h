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
#include "processor.h"

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

struct cpuid_leaf {
	u32 eax_in;
	u32 ecx_in;
	u32 eax;
	u32 ebx;
	u32 ecx;
	u32 edx;
};

/*
 * AMD Programmer's Manual Volume 3
 *   - Section "Function 8000_0000h - Maximum Extended Function Number and Vendor String"
 *   - Section "Function 8000_001Fh - Encrypted Memory Capabilities"
 */
#define CPUID_FN_LARGEST_EXT_FUNC_NUM 0x80000000
#define CPUID_FN_ENCRYPT_MEM_CAPAB    0x8000001f
#define SEV_SUPPORT_MASK              0b10
#define SEV_SNP_SUPPORT_MASK          0b10000
#define VMPL_SUPPORT_MASK             0b100000
#define VMPL_COUNT_MASK               0xF000
#define VMPL_COUNT_SHIFT              12

/*
 * AMD Programmer's Manual Volume 2
 *   - Section "SEV_STATUS MSR"
 */
#define MSR_SEV_STATUS      0xc0010131
#define SEV_ENABLED_MASK    0b1
#define SEV_ES_ENABLED_MASK 0b10
#define SEV_SNP_ENABLED_MASK 0b100

bool amd_sev_enabled(void);
efi_status_t setup_amd_sev(void);

/*
 * AMD Programmer's Manual Volume 2
 *   - Section "#VC Exception"
 */
#define SEV_ES_VC_HANDLER_VECTOR 29
#define SVM_EXIT_CPUID  0x72ULL
#define SVM_VMGEXIT_PSC	0x80000010

/*
 * AMD Programmer's Manual Volume 2
 *   - Section "GHCB"
 */
#define SEV_ES_GHCB_MSR_INDEX 0xc0010130
#define VMGEXIT()		{ asm volatile("rep; vmmcall\n\r"); }
#define VMGEXIT_PSC_MAX_ENTRY	253

#define GHCB_DATA_LOW		12
#define GHCB_MSR_INFO_MASK	(BIT_ULL(GHCB_DATA_LOW) - 1)
#define GHCB_RESP_CODE(v)	((v) & GHCB_MSR_INFO_MASK)
#define GHCB_DEFAULT_USAGE	0ULL

/*
 * SNP Page State Change Operation
 *
 * GHCBData[55:52] - Page operation:
 *	0x0001	Page assignment, Private
 *	0x0002	Page assignment, Shared
 *	0x0003	PSMASH hint
 *	0x0004	UNSMASH hint
 */
enum psc_op {
	SNP_PAGE_STATE_PRIVATE = 1,
	SNP_PAGE_STATE_SHARED =  2,
};

#define RMP_PG_SIZE_4K		0
#define PAGE_SHIFT		12
#define GHCB_MSR_PSC_REQ	0x14
#define GHCB_MSR_PSC_REQ_GFN(gfn, op)				\
	/* GHCBData[55:52] */					\
	(((u64)((op) & 0xf) << 52)		|		\
	/* GHCBData[51:12] */					\
	((u64)((gfn) & GENMASK_ULL(39, 0)) << 12) |		\
	/* GHCBData[11:0] */					\
	GHCB_MSR_PSC_REQ)

#define GHCB_MSR_PSC_RESP	0x15
#define GHCB_MSR_PSC_RESP_VAL(val)		\
	/* GHCBData[63:32] */			\
	(((u64)(val) & GENMASK_ULL(63, 32)) >> 32)

typedef struct {
	u8  reserved1[203];
	u8  cpl;
	u8  reserved8[300];
	u64 rax;
	u8  reserved4[264];
	u64 rcx;
	u64 rdx;
	u64 rbx;
	u8  reserved5[112];
	u64 sw_exit_code;
	u64 sw_exit_info1;
	u64 sw_exit_info2;
	u64 sw_scratch;
	u8  reserved6[56];
	u64 xcr0;
	u8  valid_bitmap[16];
	u64 x87_state_gpa;
	u8  reserved7[1016];
} ghcb_save_area;

typedef struct {
	ghcb_save_area	save_area;
	u8		shared_buffer[2032];
	u8		reserved1[10];
	u16		protocol_version;
	u32		ghcb_usage;
} ghcb_page;

#define OFFSET_OF(TYPE, field)  ((u64)&(((TYPE *)0)->field))

#define GHCB_SAVE_AREA_QWORD_OFFSET(reg_field) \
	(OFFSET_OF(ghcb_page, save_area.reg_field) / sizeof(u64))

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

struct psc_hdr {
	u16 cur_entry;
	u16 end_entry;
	u32 reserved;
};

struct psc_entry {
	u64 cur_page	: 12;
	u64 gfn		: 40;
	u64 operation	: 4;
	u64 pagesize	: 1;
	u64 reserved	: 7;
};

struct snp_psc_desc {
	struct psc_hdr hdr;
	struct psc_entry entries[VMGEXIT_PSC_MAX_ENTRY];
};

bool amd_sev_es_enabled(void);
efi_status_t setup_vc_handler(void);
bool amd_sev_snp_enabled(void);
void setup_ghcb_pte(pgd_t *page_table);

unsigned long long get_amd_sev_c_bit_mask(void);
unsigned long long get_amd_sev_addr_upperbound(void);
void vmg_set_offset_valid(ghcb_page *ghcb, GHCB_REGISTER offset);
void mem_fence(void);
void vmgexit(ghcb_page *ghcb, u64 exit_code, u64 exit_info1,
	     u64 exit_info2);
uint64_t asm_read_cr4(void);
uint64_t asm_xgetbv(uint32_t index);
/*
 * Macros to generate condition code outputs from inline assembly,
 * The output operand must be type "bool".
 */
#ifdef __GCC_ASM_FLAG_OUTPUTS__
# define CC_SET(c) "\n\t/* output condition code " #c "*/\n"
# define CC_OUT(c) "=@cc" #c
#else
# define CC_SET(c) "\n\tset" #c " %[_cc_" #c "]\n"
# define CC_OUT(c)[_cc_ ## c] "=qm"
#endif

#endif /* CONFIG_EFI */

#endif /* _X86_AMD_SEV_H_ */
