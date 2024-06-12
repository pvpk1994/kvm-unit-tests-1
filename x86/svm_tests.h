#ifndef X86_SVM_TESTS_H
#define X86_SVM_TESTS_H

#include "x86/svm.h"

struct svm_test {
	const char *name;
	bool (*supported)(void);
	void (*prepare)(struct svm_test *test);
	void (*prepare_gif_clear)(struct svm_test *test);
	void (*guest_func)(struct svm_test *test);
	bool (*finished)(struct svm_test *test);
	bool (*succeeded)(struct svm_test *test);
	int exits;
	ulong scratch;
	/* Alternative test interface. */
	void (*v2)(void);
	int on_vcpu;
	bool on_vcpu_done;
};

typedef void (*test_guest_func)(struct svm_test *);

int run_svm_tests(int ac, char **av, struct svm_test *svm_tests);
u64 *npt_get_pte(u64 address);
u64 *npt_get_pde(u64 address);
u64 *npt_get_pdpe(u64 address);
u64 *npt_get_pml4e(void);
bool smp_supported(void);
bool default_supported(void);
bool vgif_supported(void);
bool lbrv_supported(void);
bool tsc_scale_supported(void);
bool pause_filter_supported(void);
bool pause_threshold_supported(void);
void default_prepare(struct svm_test *test);
void default_prepare_gif_clear(struct svm_test *test);
bool default_finished(struct svm_test *test);
bool npt_supported(void);
bool vnmi_supported(void);
int get_test_stage(struct svm_test *test);
void set_test_stage(struct svm_test *test, int s);
void inc_test_stage(struct svm_test *test);
void vmcb_ident(struct vmcb *vmcb);
struct regs get_regs(void);
void vmmcall(void);
void svm_setup_vmrun(u64 rip);
int __svm_vmrun(u64 rip);
int svm_vmrun(void);
void test_set_guest(test_guest_func func);

extern struct vmcb *vmcb;

static inline void stgi(void)
{
    asm volatile ("stgi");
}

static inline void clgi(void)
{
    asm volatile ("clgi");
}

#define SAVE_GPR_C                              \
        "xchg %%rbx, regs+0x8\n\t"              \
        "xchg %%rcx, regs+0x10\n\t"             \
        "xchg %%rdx, regs+0x18\n\t"             \
        "xchg %%rbp, regs+0x28\n\t"             \
        "xchg %%rsi, regs+0x30\n\t"             \
        "xchg %%rdi, regs+0x38\n\t"             \
        "xchg %%r8, regs+0x40\n\t"              \
        "xchg %%r9, regs+0x48\n\t"              \
        "xchg %%r10, regs+0x50\n\t"             \
        "xchg %%r11, regs+0x58\n\t"             \
        "xchg %%r12, regs+0x60\n\t"             \
        "xchg %%r13, regs+0x68\n\t"             \
        "xchg %%r14, regs+0x70\n\t"             \
        "xchg %%r15, regs+0x78\n\t"

#define LOAD_GPR_C      SAVE_GPR_C

#define ASM_PRE_VMRUN_CMD                       \
                "vmload %%rax\n\t"              \
                "mov regs+0x80, %%r15\n\t"      \
                "mov %%r15, 0x170(%%rax)\n\t"   \
                "mov regs, %%r15\n\t"           \
                "mov %%r15, 0x1f8(%%rax)\n\t"   \
                LOAD_GPR_C                      \

#define ASM_POST_VMRUN_CMD                      \
                SAVE_GPR_C                      \
                "mov 0x170(%%rax), %%r15\n\t"   \
                "mov %%r15, regs+0x80\n\t"      \
                "mov 0x1f8(%%rax), %%r15\n\t"   \
                "mov %%r15, regs\n\t"           \
                "vmsave %%rax\n\t"              \

#define SVM_BARE_VMRUN \
	asm volatile ( \
		ASM_PRE_VMRUN_CMD \
                "vmrun %%rax\n\t"               \
		ASM_POST_VMRUN_CMD \
		: \
		: "a" (virt_to_phys(vmcb)) \
		: "memory", "r15") \

#endif
