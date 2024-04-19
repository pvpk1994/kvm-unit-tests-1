// SPDX-License-Identifier: GPL-2.0

#include "libcflat.h"
#include "xsave.h"
#include "processor.h"

int xgetbv_safe(u32 index, u64 *result)
{
	return rdreg64_safe(".byte 0x0f,0x01,0xd0", index, result);
}

int xsetbv_safe(u32 index, u64 value)
{
	return wrreg64_safe(".byte 0x0f,0x01,0xd1", index, value);
}

uint64_t get_supported_xcr0(void)
{
    struct cpuid r;
    r = cpuid_indexed(0xd, 0);
    printf("eax %x, ebx %x, ecx %x, edx %x\n",
            r.a, r.b, r.c, r.d);
    return r.a + ((u64)r.d << 32);
}


