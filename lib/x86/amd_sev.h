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

/* GHCB Hypervisor Feature request/response */
#define GHCB_MSR_HV_FT_REQ	0x080
#define GHCB_MSR_HV_FT_RESP	0x081
#define GHCB_MSR_HV_FT_RESP_VAL(v)		\
	/* GHCBData[63:32] */			\
	(((u64)(v) & GENMASK_ULL(63, 12)) >> 12)

#define GHCB_HV_FT_SNP			BIT_ULL(0)
#define GHCB_HV_FT_SNP_AP_CREATION	BIT_ULL(1)

/* VMSA page bit */
#define RMPADJUST_VMSA_PAGE_BIT		BIT(16)

/* VMGEXIT related events for AP */
#define SVM_VMGEXIT_AP_CREATION		0x80000013
#define SVM_VMGEXIT_AP_INIT		0
#define SVM_VMGEXIT_AP_CREATE		1
#define SVM_VMGEXIT_AP_DESTROY		2

/* VMCB segment */
struct vmcb_seg {
	u16 selector;
	u16 attrib;
	u32 limit;
	u64 base;
} __packed;

/* Save area definition for SEV-ES and SEV-SNP guests */
/*
struct sev_es_save_area {
	struct vmcb_seg es;
	struct vmcb_seg cs;
	struct vmcb_seg ss;
	struct vmcb_seg ds;
	struct vmcb_seg fs;
	struct vmcb_seg gs;
	struct vmcb_seg gdtr;
	struct vmcb_seg ldtr;
	struct vmcb_seg idtr;
	struct vmcb_seg tr;
//	u8 reserved_0xc8[2];
	u8 vmpl;
//	u8 reserved_0xcc[4];
	u64 efer;
//	u8 reserved_0xd8[104];
	u64 cr4;
	u64 cr0;
	u64 dr7;
	u64 dr6;
	u64 rflags;
	u64 rip;
//	u8 reserved_0x1c0[24];
//	u8 reserved_0x248[32];
	u64 g_pat;
//	u8 reserved_0x298[80];
//	u8 reserved_0x2f0[24];
//	u64 reserved_0x320;	// rsp already available at 0x01d8
//	u8 reserved_0x380[16];
	u64 sev_features;
//	u8 reserved_0x3f0[16];

	// Floating point area
	u64 x87_dp;
	u64 xcr0;
	u32 mxcsr;
	u16 x87_ftw;
	u16 x87_fcw;
}__packed;
*/

/* Save area definition for SEV-ES and SEV-SNP guests */
struct sev_es_save_area {
	struct vmcb_seg es;
	struct vmcb_seg cs;
	struct vmcb_seg ss;
	struct vmcb_seg ds;
	struct vmcb_seg fs;
	struct vmcb_seg gs;
	struct vmcb_seg gdtr;
	struct vmcb_seg ldtr;
	struct vmcb_seg idtr;
	struct vmcb_seg tr;
	u64 vmpl0_ssp;
	u64 vmpl1_ssp;
	u64 vmpl2_ssp;
	u64 vmpl3_ssp;
	u64 u_cet;
	u8 reserved_0xc8[2];
	u8 vmpl;
	u8 cpl;
	u8 reserved_0xcc[4];
	u64 efer;
	u8 reserved_0xd8[104];
	u64 xss;
	u64 cr4;
	u64 cr3;
	u64 cr0;
	u64 dr7;
	u64 dr6;
	u64 rflags;
	u64 rip;
	u64 dr0;
	u64 dr1;
	u64 dr2;
	u64 dr3;
	u64 dr0_addr_mask;
	u64 dr1_addr_mask;
	u64 dr2_addr_mask;
	u64 dr3_addr_mask;
	u8 reserved_0x1c0[24];
	u64 rsp;
	u64 s_cet;
	u64 ssp;
	u64 isst_addr;
	u64 rax;
	u64 star;
	u64 lstar;
	u64 cstar;
	u64 sfmask;
	u64 kernel_gs_base;
	u64 sysenter_cs;
	u64 sysenter_esp;
	u64 sysenter_eip;
	u64 cr2;
	u8 reserved_0x248[32];
	u64 g_pat;
	u64 dbgctl;
	u64 br_from;
	u64 br_to;
	u64 last_excp_from;
	u64 last_excp_to;
	u8 reserved_0x298[80];
	u32 pkru;
	u32 tsc_aux;
	u8 reserved_0x2f0[24];
	u64 rcx;
	u64 rdx;
	u64 rbx;
	u64 reserved_0x320;	/* rsp already available at 0x01d8 */
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
	u64 guest_exit_info_1;
	u64 guest_exit_info_2;
	u64 guest_exit_int_info;
	u64 guest_nrip;
	u64 sev_features;
	u64 vintr_ctrl;
	u64 guest_exit_code;
	u64 virtual_tom;
	u64 tlb_id;
	u64 pcpu_id;
	u64 event_inj;
	u64 xcr0;
	u8 reserved_0x3f0[16];

	/* Floating point area */
	u64 x87_dp;
	u32 mxcsr;
	u16 x87_ftw;
	u16 x87_fsw;
	u16 x87_fcw;
	u16 x87_fop;
	u16 x87_ds;
	u16 x87_cs;
	u64 x87_rip;
	u8 fpreg_x87[80];
	u8 fpreg_xmm[256];
	u8 fpreg_ymm[256];
} __packed;

typedef struct {
	u8  reserved1[203];
	u8  cpl;
	u8  reserved8[300];
	// u64 xss;
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
	// ghcb_xss	= GHCB_SAVE_AREA_QWORD_OFFSET(xss),
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
u64 get_hv_features(ghcb_page *ghcb);
void bringup_snp_aps(void);

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

static inline int rmpadjust(unsigned long vaddr, bool rmp_pg_size,
			    unsigned long attrs)
{
	int ret;

	__asm__ __volatile__(".byte 0xF3, 0x0F, 0x01, 0xFE\n\t"
			      : "=a"(ret)
			      : "a"(vaddr), "c"(rmp_pg_size),  "d"(attrs)
			      : "memory", "cc");

	return ret;
}

static inline bool constant_test_bit(int nr, const void *addr)
{
	const u32 *p = addr;
	return ((1UL << (nr & 31)) & (p[nr >> 5])) != 0;
}
static inline bool variable_test_bit(int nr, const void *addr)
{
	bool v;
	const u32 *p = addr;

	asm("btl %2,%1" CC_SET(c) : CC_OUT(c) (v) : "m" (*p), "Ir" (nr));
	return v;
}

#define test_bit(nr,addr) (__builtin_constant_p(nr) ? \
 			   constant_test_bit((nr),(addr)) : \
 			   variable_test_bit((nr),(addr)))

void vc_invalidate_ghcb(ghcb_page *ghcb);

#endif /* CONFIG_EFI */

#endif /* _X86_AMD_SEV_H_ */
