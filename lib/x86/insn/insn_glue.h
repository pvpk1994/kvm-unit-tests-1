/*
 * Necessary definitions from Linux to adapt the insn decoder for
 * kvm-unit-tests.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

/**
 * BUILD_BUG - no-op.
 */
#define BUILD_BUG()

/*
 * Virt escape sequences to trigger instruction emulation;
 * ideally these would decode to 'whole' instruction and not destroy
 * the instruction stream; sadly this is not true for the 'kvm' one :/
 */
#define __XEN_EMULATE_PREFIX  0x0f,0x0b,0x78,0x65,0x6e  /* ud2 ; .ascii "xen" */
#define __KVM_EMULATE_PREFIX  0x0f,0x0b,0x6b,0x76,0x6d	/* ud2 ; .ascii "kvm" */

# define __packed		__attribute__((__packed__))
#define __get_unaligned_t(type, ptr) ({						\
	const struct { type x; } __packed *__pptr = (typeof(__pptr))(ptr);	\
	__pptr->x;								\
})
#define get_unaligned(ptr)	__get_unaligned_t(typeof(*(ptr)), (ptr))

#define	EINVAL		22	/* Invalid argument */
#define	ENODATA		61	/* No data available */

#define CONFIG_X86_64		1
#define IS_ENABLED(option)	1
