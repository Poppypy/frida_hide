#include "kallsyms.h"
#include "linux/printk.h"
#include "kpmodule.h"
#include "hook.h"
#include "stdbool.h"
#include "stdint.h"
#include "syscall.h"
#include "compiler.h"
#include "kputils.h"
#include "linux/kernel.h"
#include "linux/string.h"
#include <asm/current.h>


struct seq_file{
    char *buf;
	size_t size;
	size_t from;
	size_t count;
};
struct sockaddr_in {
    short sin_family;
    unsigned short sin_port;     
    unsigned int sin_addr;     
    char sin_zero[8];
};

void *show_map_vma = 0;
char *(*__get_task_comm)(char *buf, size_t buf_size, struct task_struct *tsk) = 0;  // 为了后续能够调用，定义成函数指针变量
unsigned long (*__arch_copy_from_user)(void *to, const void __user *from, unsigned long n) = 0;

int __get_task_comm_hook_status = 0;
int connect_hook_status = 0;

// 内核环境下的 memmem 实现
static void *memmem_local(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen)
{
    if (!haystack || !needle || haystacklen < needlelen || needlelen == 0)
        return NULL;
    for (size_t i = 0; i <= haystacklen - needlelen; ++i) {
        if (memcmp((const char *)haystack + i, needle, needlelen) == 0)
            return (void *)((const char *)haystack + i);
    }
    return NULL;
}

// 检查 seq_file 缓冲区中是否包含敏感关键词
static int is_hiden_module(struct seq_file *m)
{
    if (!m || !m->buf || m->count == 0) return false;
    // 需要隐藏的关键词列表
    static const char *keywords[] = {
        "frida-agent",
        "frida",
        "gum-js-loop",
        "GumJS",
        "gmain",
        NULL
    };

    for (int i = 0; keywords[i] != NULL; ++i) {
        if (memmem_local(m->buf, m->count, keywords[i], strlen(keywords[i])))
            return 1;
    }
    return 0;
}

int is_hiden_comm(const char *comm)
{
    // 需要隐藏的线程名关键词列表
    static const char *keywords[] = {
        "gmain",
        "gum-js-loop",
        "gdbus",
        "pool-frida",
        "linjector",
    };

    for (int i = 0; i < sizeof(keywords) / sizeof(keywords[0]); i++) {
        if (strstr(comm, keywords[i])) {
            return 1;
        }
    }
    return 0;
}

void before_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    args->local.data0 = 0;
    if (m && m->buf) {
        // 记录 seq_file 中的count，在 after hook 中设置 count 为记录值
        args->local.data0 = m->count;
    } 
}

void after_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    if (m && m->buf) {
        if (args->local.data0 && is_hiden_module(m)) {  // is_hiden_module 查找 frida-agent 等字符串
            pr_info("inject-hide: maps hide -> frida-agent \n");
            m->count = args->local.data0;  // 恢复原来的 count 值
        }
    }
}

void __attribute__((optimize("O0"))) after_get_task_comm(hook_fargs3_t *args, void *udata)
{
    char *comm = (char *)args->arg0;
    size_t comm_buf_len = (size_t)args->arg1;
    if (comm && comm_buf_len) {
        if (is_hiden_comm(comm)){
            pr_info("inject-hide: get_task_comm hide -> %s\n", comm);
            size_t hide_len = strlen(comm);
            for(size_t i = 0; i < hide_len; i++) {
                comm[i] = ' ';
            }
        }
    }
}

// 网络协议中的端口号（大端）转换为主机字节序（小端）
u16 ntohs(u16 port) {
    return port >> 8 | port << 8;
}
void before_connect(hook_fargs3_t *args, void *udata) {
    struct sockaddr_in addr_kernel;
    const char __user *addr = (typeof(addr))syscall_argn(args, 1);
    if (!addr) return;

    __arch_copy_from_user(&addr_kernel, addr, sizeof(struct sockaddr_in));

    u16 port = ntohs(addr_kernel.sin_port);
    if (port == 27042) {
        char comm[16];
        __get_task_comm(comm, sizeof(comm), current);

        pr_warn("inject-hide: connect to frida-agent, comm: %s, port: %d\n", comm, port);
        if (!strstr(comm, "adbd")) {  // 只允许 adbd 连接 frida
            pr_warn("inject-hide: connect to frida-agent blocked, comm: %s, port: %d\n", comm, port);
            args->skip_origin = 1;  // 跳过原始的 connect 函数
            args->ret = -1;  // 返回 -1 表示拒绝连接
        }
    }
}

void frida_hide_install(void)
{
    show_map_vma = (void *) kallsyms_lookup_name("show_map_vma");
    if (show_map_vma) {
        hook_err_t err = hook_wrap2(show_map_vma, before_show_map_vma, after_show_map_vma, NULL);
    }

    __get_task_comm = (void *) kallsyms_lookup_name("__get_task_comm");
    if (__get_task_comm) {
        hook_err_t err = hook_wrap3(__get_task_comm, 0, after_get_task_comm, 0);
        __get_task_comm_hook_status = err ? 0 : 1;
    }

    __arch_copy_from_user = (void *)kallsyms_lookup_name("__arch_copy_from_user");
    if(__arch_copy_from_user && __get_task_comm) {
        hook_err_t err = fp_hook_syscalln(__NR_connect, 3, before_connect, 0, NULL);
        connect_hook_status = err ? 0 : 1;
    }
}

void frida_hide_uninstall(void)
{
    if (show_map_vma) {
        unhook(show_map_vma);
        show_map_vma = 0;
    }

    if (__get_task_comm) {
        unhook(__get_task_comm);
        __get_task_comm = 0;
        __get_task_comm_hook_status = 0;
    }

    if(connect_hook_status) {
        fp_unhook_syscalln(__NR_connect, before_connect, 0);
        connect_hook_status = 0;
    }
}