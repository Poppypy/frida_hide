#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <taskext.h>
#include <hook.h>
#include <linux/string.h>

KPM_NAME("frida_hide");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Security Researcher");
KPM_DESCRIPTION("Hide Frida injection from detection");

// ==================== 常量定义 ====================
#define FRIDA_PORT 27042

#ifndef ECONNREFUSED
#define ECONNREFUSED 111
#endif

// ==================== 结构体定义 ====================

struct seq_file {
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

// ==================== 内核函数定义 ====================

// 使用 kfunc_def 定义需要调用的内核函数
kfunc_def(__get_task_comm, char *, char *buf, size_t buf_size, struct task_struct *tsk);
kfunc_def(__arch_copy_from_user, unsigned long, void *to, const void __user *from, unsigned long n);

// ==================== 全局变量 ====================

static uint64_t show_map_vma_addr = 0;
static uint64_t connect_syscall_addr = 0;

// ==================== 辅助函数 ====================

static void *memmem_local(const void *haystack, size_t haystacklen, 
                          const void *needle, size_t needlelen)
{
    if (!haystack || !needle || haystacklen < needlelen || needlelen == 0)
        return 0;
    
    const char *h = (const char *)haystack;
    const char *n = (const char *)needle;
    
    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        int match = 1;
        for (size_t j = 0; j < needlelen; j++) {
            if (h[i + j] != n[j]) {
                match = 0;
                break;
            }
        }
        if (match) return (void *)(h + i);
    }
    return 0;
}

static int contains_frida_string(struct seq_file *m)
{
    if (!m || !m->buf || m->count == 0) 
        return 0;
    
    static const char *keywords[] = {
        "frida-agent",
        "frida",
        "gum-js-loop",
        "GumJS",
        "gmain",
    };
    
    int num = sizeof(keywords) / sizeof(keywords[0]);
    for (int i = 0; i < num; i++) {
        size_t len = 0;
        const char *p = keywords[i];
        while (*p++) len++;
        
        if (memmem_local(m->buf, m->count, keywords[i], len))
            return 1;
    }
    return 0;
}

static int is_frida_thread(const char *comm)
{
    if (!comm)
        return 0;
    
    static const char *keywords[] = {
        "gmain",
        "gum-js-loop",
        "gdbus",
        "pool-frida",
        "linjector",
    };
    
    int num = sizeof(keywords) / sizeof(keywords[0]);
    for (int i = 0; i < num; i++) {
        // 简单的 strstr 实现
        const char *h = comm;
        const char *n = keywords[i];
        while (*h) {
            const char *a = h;
            const char *b = n;
            while (*a && *b && *a == *b) { a++; b++; }
            if (!*b) return 1;
            h++;
        }
    }
    return 0;
}

static inline uint16_t swap16(uint16_t val) 
{
    return (val >> 8) | (val << 8);
}

// ==================== Hook 函数 ====================

// show_map_vma hook - 隐藏 /proc/pid/maps 中的 frida
static void before_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    args->local.data0 = 0;
    
    if (m && m->buf) {
        args->local.data0 = (uint64_t)m->count;
    }
}

static void after_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    
    if (m && m->buf && args->local.data0) {
        if (contains_frida_string(m)) {
            m->count = (size_t)args->local.data0;
            pr_info("kpm: hide frida from maps\n");
        }
    }
}

// __get_task_comm hook - 隐藏线程名
static void after_get_task_comm(hook_fargs3_t *args, void *udata)
{
    char *comm = (char *)args->arg0;
    
    if (comm && is_frida_thread(comm)) {
        pr_info("kpm: hide thread %s\n", comm);
        // 用空格覆盖
        char *p = comm;
        while (*p) { *p = ' '; p++; }
    }
}

// connect hook - 阻止连接 frida 端口
static void before_connect_syscall(hook_fargs3_t *args, void *udata)
{
    struct sockaddr_in addr_buf;
    
    // 获取 sockaddr 参数（第二个参数，索引 1）
    void __user *addr_user = (void __user *)syscall_argn(args, 1);
    
    if (!addr_user || !kfunc(__arch_copy_from_user))
        return;
    
    unsigned long ret = kfunc(__arch_copy_from_user)(&addr_buf, addr_user, sizeof(addr_buf));
    if (ret != 0)
        return;
    
    uint16_t port = swap16(addr_buf.sin_port);
    
    if (port == FRIDA_PORT) {
        char comm[16] = {0};
        struct task_struct *task = current;
        
        if (kfunc(__get_task_comm) && task) {
            kfunc(__get_task_comm)(comm, sizeof(comm), task);
        }
        
        // 允许 adbd 连接
        const char *adbd = "adbd";
        const char *h = comm;
        int is_adbd = 0;
        while (*h) {
            const char *a = h;
            const char *b = adbd;
            while (*a && *b && *a == *b) { a++; b++; }
            if (!*b) { is_adbd = 1; break; }
            h++;
        }
        
        if (!is_adbd) {
            pr_warn("kpm: block connect to frida port, comm=%s\n", comm);
            args->ret = (uint64_t)(-ECONNREFUSED);
            args->skip_origin = 1;
        }
    }
}

// ==================== 模块入口 ====================

static long frida_hide_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("kpm: frida_hide loading...\n");
    
    // 查找内核函数
    kfunc_lookup_name(__get_task_comm);
    kfunc_lookup_name(__arch_copy_from_user);
    
    // 1. Hook show_map_vma
    show_map_vma_addr = kallsyms_lookup_name("show_map_vma");
    if (show_map_vma_addr) {
        hook_err_t err = hook_wrap2((void *)show_map_vma_addr, 
                                    before_show_map_vma, 
                                    after_show_map_vma, 
                                    NULL);
        if (err == HOOK_NO_ERR) {
            pr_info("kpm: show_map_vma hooked at %llx\n", show_map_vma_addr);
        } else {
            pr_err("kpm: hook show_map_vma failed: %d\n", err);
            show_map_vma_addr = 0;
        }
    } else {
        pr_warn("kpm: show_map_vma not found\n");
    }
    
    // 2. Hook __get_task_comm
    if (kfunc(__get_task_comm)) {
        hook_err_t err = hook_wrap3((void *)kfunc(__get_task_comm), 
                                    NULL, 
                                    after_get_task_comm, 
                                    NULL);
        if (err == HOOK_NO_ERR) {
            pr_info("kpm: __get_task_comm hooked\n");
        } else {
            pr_err("kpm: hook __get_task_comm failed: %d\n", err);
        }
    }
    
    // 3. Hook connect 系统调用
    if (kfunc(__arch_copy_from_user)) {
        hook_err_t err = fp_hook_syscalln(__NR_connect, 3, before_connect_syscall, NULL, NULL);
        if (err == HOOK_NO_ERR) {
            connect_syscall_addr = 1;  // 标记已 hook
            pr_info("kpm: connect syscall hooked\n");
        } else {
            pr_err("kpm: hook connect failed: %d\n", err);
        }
    }
    
    pr_info("kpm: frida_hide loaded\n");
    return 0;
}

static long frida_hide_control0(const char *args, char *__user out_msg, int outlen)
{
    pr_info("kpm: control0 args=%s\n", args ? args : "null");
    
    char msg[] = "frida_hide running";
    if (out_msg && outlen > 0) {
        int len = sizeof(msg);
        if (len > outlen) len = outlen;
        compat_copy_to_user(out_msg, msg, len);
    }
    
    return 0;
}

static long frida_hide_exit(void *__user reserved)
{
    pr_info("kpm: frida_hide unloading...\n");
    
    if (show_map_vma_addr) {
        unhook((void *)show_map_vma_addr);
        show_map_vma_addr = 0;
    }
    
    if (kfunc(__get_task_comm)) {
        unhook((void *)kfunc(__get_task_comm));
    }
    
    if (connect_syscall_addr) {
        fp_unhook_syscalln(__NR_connect, before_connect_syscall, NULL);
        connect_syscall_addr = 0;
    }
    
    pr_info("kpm: frida_hide unloaded\n");
    return 0;
}

KPM_INIT(frida_hide_init);
KPM_CTL0(frida_hide_control0);
KPM_EXIT(frida_hide_exit);
