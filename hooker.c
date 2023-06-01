#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nadav");
MODULE_DESCRIPTION("A simple read syscall hooker");
MODULE_VERSION("0.01");

typedef unsigned long ulong;

asmlinkage ssize_t (*origin_syscall)(int, void *, size_t);
ulong *syscall_table;
extern unsigned long __force_order;

static inline void modcr0(ulong val)
{
    asm volatile("mov %0,%%cr0"
                 : "+r"(val), "+m"(__force_order));
}

static inline void protect_readonly_mem(void)
{
    modcr0(read_cr0() | X86_CR0_WP);
}

static inline void unprotect_readonly_mem(void)
{
    modcr0(read_cr0() & ~X86_CR0_WP);
}

static void *hook_sys_call(void *hooked_addr, ulong *sys_call_table, ulong offset)
{
    void *real_sys_call = (void *)sys_call_table[offset];
    unprotect_readonly_mem();
    sys_call_table[offset] = (ulong)hooked_addr;
    protect_readonly_mem();

    return real_sys_call;
}

static void unhook_syscall(ulong *sys_call_table, void *origin_sys_call, ulong offset)
{
    unprotect_readonly_mem();
    sys_call_table[offset] = (ulong)origin_sys_call;
    protect_readonly_mem();
}

asmlinkage ssize_t modified_read(int fd, void *buffer, size_t count)
{
    ssize_t ret = origin_syscall(fd, buffer, count);
    pr_info("Hooked version of read syscall just got called !");
    return ret;
}

static int _hooker_init(void)
{
    unsigned char EX_CODE = 0;

    syscall_table = (ulong *)kallsyms_lookup_name("sys_call_table");
    if (syscall_table == NULL)
    {
        EX_CODE = 1;
        goto cleanup;
    }
    origin_syscall = hook_sys_call(syscall_table, syscall_table, __NR_read);
    goto cleanup;

cleanup:
    if (EX_CODE > 0)
    {
        pr_info("syscall hooker failed to load..");
    }
    else
    {
        pr_info("Successfully hooked the read syscall!");
    }
    return EX_CODE;
}

static void __hooker_unload(void)
{
    unhook_syscall(syscall_table, (void *)origin_syscall, __NR_read);
}

module_init(_hooker_init);
module_exit(__hooker_unload);
