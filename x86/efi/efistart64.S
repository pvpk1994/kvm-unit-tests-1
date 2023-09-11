/* Startup code and pre-defined data structures */

#include "apic-defs.h"
#include "asm-generic/page.h"
#include "crt0-efi-x86_64.S"


/* Reserve stack in .data */
.data
.align PAGE_SIZE
	. = . + PAGE_SIZE * MAX_TEST_CPUS
.globl stacktop
stacktop:

.globl smp_stacktop
smp_stacktop:	.long 0

.align PAGE_SIZE
.globl ptl2
ptl2:
	. = . + 4 * PAGE_SIZE
.align PAGE_SIZE

.globl ptl3
ptl3:
	. = . + PAGE_SIZE
.align PAGE_SIZE

.globl ptl4
ptl4:
	. = . + PAGE_SIZE
.align PAGE_SIZE

.section .init
.code64
.text

.code16
REALMODE_GDT_LOWMEM = PAGE_SIZE - 2
/*
.globl sev_snp_trampoline_start
	cli
	mov %cs, %ax
	mov %ax, %ds
	mov %ax, %es
	mov %ax, %ss
5
	lidtl tr_idt
	lgdtl tr_gdt
	call bringup_snp_aps
*/

.globl rm_trampoline
rm_trampoline:

.globl sipi_entry
sipi_entry:
/*
	mov %cr0, %eax
	or $1, %eax
	mov %eax, %cr0
*/
//	wbinvd

	mov %cr0, %eax
	or $0x1, %eax
	mov %eax, %cr0


	/* Retrieve relocated ap_rm_gdt_descr address at REALMODE_GDT_LOWMEM. */
	movw (REALMODE_GDT_LOWMEM), %ebx

	/* Load reloacted GDT at the address stored in ebx */
	lgdtl (%ebx)

//       	mov $0x1111, %esi
//1:jmp 1b

	lcall $0x18, $0x0
//	mov $0x1111, %esi
//1:jmp 1b

.globl ap_rm_gdt
ap_rm_gdt:
	.quad 0
	.quad 0x00cf9b000000ffff // flat 32-bit code segment
	.quad 0x00cf93000000ffff // flat 32-bit data segment
	.quad 0                  // call gate to 32-bit AP entrypoint
.globl ap_rm_gdt_end
ap_rm_gdt_end:

.globl ap_rm_gdt_descr
ap_rm_gdt_descr:
	.word 0
	.long 0

.globl sipi_end
sipi_end:

.globl rm_trampoline_end
rm_trampoline_end:

#include "../trampolines.S"
