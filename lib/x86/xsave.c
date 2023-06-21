// SPDX-License-Identifier: GPL-2.0

#include "libcflat.h"
#include "xsave.h"
#include "processor.h"

int xgetbv_checking(u32 index, u64 *result)
{
	u32 eax, edx;

	asm volatile(ASM_TRY("1f")
		".byte 0x0f,0x01,0xd0\n\t" /* xgetbv */
		"1:"
		: "=a" (eax), "=d" (edx)
		: "c" (index));
	*result = eax + ((u64)edx << 32);
	return exception_vector();
}

int xsetbv_safe(u32 index, u64 value)
{
	u32 eax = value;
	u32 edx = value >> 32;

	asm volatile(ASM_TRY("1f")
		".byte 0x0f,0x01,0xd1\n\t" /* xsetbv */
		"1:"
		: : "a" (eax), "d" (edx), "c" (index));
	return exception_vector();
}

uint64_t get_supported_xcr0(void)
{
	struct cpuid r;

	r = cpuid_indexed(0xd, 0);
	printf("eax %x, ebx %x, ecx %x, edx %x\n",
		r.a, r.b, r.c, r.d);
	return r.a + ((u64)r.d << 32);
}
