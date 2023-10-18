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
#include "insn/insn.h"
#include "svm.h"
#include "alloc_page.h"

#define GHCB_SHARED_BUF_SIZE    2032

/*
 * SNP Page state change operation
 *
 * GHCBData[55:52] - Page operation:
 *	0x01 - page assignment, private
 *	0x02 - page assignment, shared
 *	0x03 - psmash (yet to be implemented)
 *	0x04 - unsmash ( yet to be implemented)
 */
enum psc_op {
	SNP_PAGE_STATE_PRIVATE = 1,
	SNP_PAGE_STATE_SHARED = 2,
};

struct ghcb {
	struct vmcb_save_area save;
	u8 reserved_save[2048 - sizeof(struct vmcb_save_area)];

	u8 shared_buffer[GHCB_SHARED_BUF_SIZE];

	u8 reserved_0xff0[10];
	u16 protocol_version;	/* negotiated SEV-ES/GHCB protocol version */
	u32 ghcb_usage;
} __packed;

/* SEV Informataion Request/Response */
#define GHCB_MSR_SEV_INFO_RESP	0x001
#define GHCB_MSR_SEV_INFO_REQ	0x002

#define GHCB_MSR_SEV_INFO(_max, _min, _cbit)		\
	/* GHCBData[63:48] */				\
	(((_max) & 0xffff) << 48) |			\
	/* GHCBData[47:32] */				\
	(((_min) & 0xffff) << 32) |			\
	/* GHCBData[31:24] */				\
	(((_cbit) & 0xff) << 24) |			\
	GHCB_MSR_SEV_INFO_RESP)

#define GHCB_MSR_INFO(v)	((v) & 0xfffUL)
#define GHCB_MSR_PROTO_MAX(v)	(((v) >> 48) & 0xffff)
#define GHCB_MSR_PROTO_MIN(v)	(((v) >> 32) & 0xffff)

#define _PAGE_ENC		(_AT(pteval_t, get_amd_sev_c_bit_mask()))

#define GHCB_PROTO_OUR		0x0001UL
#define GHCB_PROTOCOL_MIN	1ULL
#define GHCB_PROTOCOL_MAX	2ULL
#define GHCB_DEFAULT_USAGE	0ULL

#define	VMGEXIT()			{ asm volatile("rep; vmmcall\n\r"); }

enum es_result {
	ES_OK,			/* All good */
	ES_UNSUPPORTED,		/* Requested operation not supported */
	ES_VMM_ERROR,		/* Unexpected state from the VMM */
	ES_DECODE_FAILED,	/* Instruction decoding failed */
	ES_EXCEPTION,		/* Instruction caused exception */
	ES_RETRY,		/* Retry instruction emulation */
};

struct es_fault_info {
	unsigned long vector;
	unsigned long error_code;
	unsigned long cr2;
};

/* ES instruction emulation context */
struct es_em_ctxt {
	struct ex_regs *regs;
	struct insn insn;
	struct es_fault_info fi;
};

/*
 * AMD Programmer's Manual Volume 3
 *   - Section "Function 8000_0000h - Maximum Extended Function Number and Vendor String"
 *   - Section "Function 8000_001Fh - Encrypted Memory Capabilities"
 */
#define CPUID_FN_LARGEST_EXT_FUNC_NUM 0x80000000
#define CPUID_FN_ENCRYPT_MEM_CAPAB    0x8000001f
#define SEV_SUPPORT_MASK              0b10

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

/*
 * AMD Programmer's Manual Volume 2
 *   - Section "GHCB"
 */
#define SEV_ES_GHCB_MSR_INDEX 0xc0010130

bool amd_sev_es_enabled(void);
bool amd_sev_snp_enabled(void);
efi_status_t setup_amd_sev_es(void);
void setup_ghcb_pte(pgd_t *page_table);
void handle_sev_es_vc(struct ex_regs *regs);
void sev_es_wr_ghcb_msr(u64 val);

unsigned long long get_amd_sev_c_bit_mask(void);
unsigned long long get_amd_sev_addr_upperbound(void);
enum es_result set_page_decrypted_ghcb_msr(unsigned long paddr);

/* GHCB Accessor functions from Linux's include/asm/svm.h */

#define GHCB_BITMAP_IDX(field)							\
	(offsetof(struct vmcb_save_area, field) / sizeof(u64))

#define DEFINE_GHCB_ACCESSORS(field)						\
	static inline bool ghcb_##field##_is_valid(const struct ghcb *ghcb)	\
	{									\
		return test_bit(GHCB_BITMAP_IDX(field),				\
				(unsigned long *)&ghcb->save.valid_bitmap);	\
	}									\
										\
	static inline u64 ghcb_get_##field(struct ghcb *ghcb)			\
	{									\
		return ghcb->save.field;					\
	}									\
										\
	static inline u64 ghcb_get_##field##_if_valid(struct ghcb *ghcb)	\
	{									\
		return ghcb_##field##_is_valid(ghcb) ? ghcb->save.field : 0;	\
	}									\
										\
	static inline void ghcb_set_##field(struct ghcb *ghcb, u64 value)	\
	{									\
		set_bit(GHCB_BITMAP_IDX(field),				\
			  (u8 *)&ghcb->save.valid_bitmap);		\
		ghcb->save.field = value;					\
	}

DEFINE_GHCB_ACCESSORS(cpl)
DEFINE_GHCB_ACCESSORS(rip)
DEFINE_GHCB_ACCESSORS(rsp)
DEFINE_GHCB_ACCESSORS(rax)
DEFINE_GHCB_ACCESSORS(rcx)
DEFINE_GHCB_ACCESSORS(rdx)
DEFINE_GHCB_ACCESSORS(rbx)
DEFINE_GHCB_ACCESSORS(rbp)
DEFINE_GHCB_ACCESSORS(rsi)
DEFINE_GHCB_ACCESSORS(rdi)
DEFINE_GHCB_ACCESSORS(r8)
DEFINE_GHCB_ACCESSORS(r9)
DEFINE_GHCB_ACCESSORS(r10)
DEFINE_GHCB_ACCESSORS(r11)
DEFINE_GHCB_ACCESSORS(r12)
DEFINE_GHCB_ACCESSORS(r13)
DEFINE_GHCB_ACCESSORS(r14)
DEFINE_GHCB_ACCESSORS(r15)
DEFINE_GHCB_ACCESSORS(sw_exit_code)
DEFINE_GHCB_ACCESSORS(sw_exit_info_1)
DEFINE_GHCB_ACCESSORS(sw_exit_info_2)
DEFINE_GHCB_ACCESSORS(sw_scratch)
DEFINE_GHCB_ACCESSORS(xcr0)

#define GHCB_HV_FT_SNP				BIT_ULL(0)
#define GHCB_HV_FT_SNP_AP_CREATION		BIT_ULL(1)

#define GHCB_DATA_LOW				12
#define GHCB_MSR_INFO_MASK			(BIT_ULL(GHCB_DATA_LOW) - 1)
#define GHCB_RESP_CODE(v)			((v) & GHCB_MSR_INFO_MASK)

#define GHCB_MSR_PSC_REQ			0x14
#define GHCB_MSR_PSC_RESP			0x15
#define RMPADJUST_VMSA_PAGE_BIT			BIT(16)
#define RMP_PG_SIZE_4K				0

#define GHCB_MSR_PSC_REQ_GFN(gfn, op)				\
	/* GHCBData[55:52] */					\
	(((u64)((op) & 0xf) << 52)		|		\
	/* GHCBData[51:12] */					\
	((u64)((gfn) & GENMASK_ULL(39, 0)) << 12) |		\
	/* GHCBData[11:0] */					\
	GHCB_MSR_PSC_REQ)

#define GHCB_MSR_PSC_RESP_VAL(val)		\
	/* GHCBData[63:32] */			\
	(((u64)(val) & GENMASK_ULL(63, 32)) >> 32)

u64 get_hv_features(struct ghcb *ghcb_page);
enum es_result hv_snp_ap_feature_check(struct ghcb *ghcb_page);
void get_ghcb_version(void);

static inline int rmpadjust(unsigned long vaddr, bool rmp_size,
			    unsigned long attrs)
{
	int ret;

	/* rmpadjust menominc support in binutils 2.36 and newer */
	__asm__ __volatile__(".byte 0xF3, 0x0F, 0x01, 0xFE\n\t"
			     : "=a"(ret)
			     : "a"(vaddr), "c"(rmp_size), "d"(attrs)
			     : "memory", "cc");

	return ret;
}

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
