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

#define GHCB_SHARED_BUF_SIZE    2032

struct ghcb_save_area {
	u8 reserved_0x0[203];
	u8 cpl;
	u8 reserved_0xcc[116];
	u64 xss;
	u8 reserved_0x148[24];
	u64 dr7;
	u8 reserved_0x168[16];
	u64 rip;
	u8 reserved_0x180[88];
	u64 rsp;
	u8 reserved_0x1e0[24];
	u64 rax;
	u8 reserved_0x200[264];
	u64 rcx;
	u64 rdx;
	u64 rbx;
	u8 reserved_0x320[8];
	u64 rbp;
	u64 rsi;
	u64 rdi;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u8 reserved_0x380[16];
	u64 sw_exit_code;
	u64 sw_exit_info_1;
	u64 sw_exit_info_2;
	u64 sw_scratch;
	u8 reserved_0x3b0[56];
	u64 xcr0;
	u8 valid_bitmap[16];
	u64 x87_state_gpa;
} __packed;

struct ghcb {
	struct ghcb_save_area save;
	u8 reserved_save[2048 - sizeof(struct ghcb_save_area)];

	u8 shared_buffer[GHCB_SHARED_BUF_SIZE];

	u8 reserved_0xff0[10];
	u16 protocol_version;	/* negotiated SEV-ES/GHCB protocol version */
	u32 ghcb_usage;
} __packed;

#define GHCB_PROTO_OUR		0x0001UL
#define GHCB_PROTOCOL_MAX	1ULL
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
efi_status_t setup_amd_sev_es(void);
void setup_ghcb_pte(pgd_t *page_table);
void handle_sev_es_vc(struct ex_regs *regs);

unsigned long long get_amd_sev_c_bit_mask(void);
unsigned long long get_amd_sev_addr_upperbound(void);

/* GHCB Accessor functions from Linux's include/asm/svm.h */
#define GHCB_BITMAP_IDX(field)							\
	(offsetof(struct ghcb_save_area, field) / sizeof(u64))

#define DEFINE_GHCB_ACCESSORS(field)						\
	static __always_inline bool ghcb_##field##_is_valid(const struct ghcb *ghcb) \
	{									\
		return test_bit(GHCB_BITMAP_IDX(field),				\
				(unsigned long *)&ghcb->save.valid_bitmap);	\
	}									\
										\
	static __always_inline u64 ghcb_get_##field(struct ghcb *ghcb)		\
	{									\
		return ghcb->save.field;					\
	}									\
										\
	static __always_inline u64 ghcb_get_##field##_if_valid(struct ghcb *ghcb) \
	{									\
		return ghcb_##field##_is_valid(ghcb) ? ghcb->save.field : 0;	\
	}									\
										\
	static __always_inline void ghcb_set_##field(struct ghcb *ghcb, u64 value) \
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

#endif /* CONFIG_EFI */

#endif /* _X86_AMD_SEV_H_ */
