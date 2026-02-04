#include <linux/kernel.h>

#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/string.h>
// KPM 元数据声明
#include <linux/module.h>
#include <linux/version.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/net.h>
#include <linux/in.h>

KPM_NAME("frida_hide");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Security Researcher");
KPM_DESCRIPTION("Hide Frida injection from detection");
// ==================== 结构体定义 ====================
// 手动定义 seq_file 结构体（避免依赖内核头文件）
struct seq_file_compat {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
    // 其他字段省略，我们只需要这些
};

struct sockaddr_in_compat {
    short sin_family;
    unsigned short sin_port;
    unsigned int sin_addr;
    char sin_zero[8];
};

// 全局变量
static void *show_map_vma = NULL;
static char *(*__get_task_comm)(char *buf, size_t buf_size, struct task_struct *tsk) = NULL;
static unsigned long (*__arch_copy_from_user)(void *to, const void __user *from, unsigned long n) = NULL;
static int show_map_vma_hooked = 0;
static int get_task_comm_hooked = 0;
static int connect_hooked = 0;

// ==================== 辅助函数 ====================

// 内核环境下的 memmem 实现
static void *memmem_local(const void *haystack, size_t haystacklen, 
                          const void *needle, size_t needlelen)
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
    if (!m || !m->buf || m->count == 0) 
        return 0;
    
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

// 检查线程名是否需要隐藏
static int is_hiden_comm(const char *comm)
{
    if (!comm)
        return 0;
    
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

// 网络协议中的端口号（大端）转换为主机字节序（小端）
static u16 ntohs_local(u16 port) 
{
    return (port >> 8) | (port << 8);
}

// ==================== Hook 回调函数 ====================

// show_map_vma before hook
static void before_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    args->local.data0 = 0;
    
    if (m && m->buf) {
        // 记录 seq_file 中的 count，在 after hook 中可能需要恢复
        args->local.data0 = m->count;
    }
}

// show_map_vma after hook
static void after_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    
    if (m && m->buf && args->local.data0) {
        if (is_hiden_module(m)) {
            pr_info("frida_hide: hiding frida-agent from /proc/pid/maps\n");
            m->count = args->local.data0;  // 恢复原来的 count 值，隐藏新增内容
        }
    }
}

// __get_task_comm after hook
static void __attribute__((optimize("O0"))) after_get_task_comm(hook_fargs3_t *args, void *udata)
{
    char *comm = (char *)args->arg0;
    size_t comm_buf_len = (size_t)args->arg1;
    
    if (comm && comm_buf_len > 0) {
        if (is_hiden_comm(comm)) {
            pr_info("frida_hide: hiding thread name -> %s\n", comm);
            size_t hide_len = strlen(comm);
            // 用空格覆盖线程名
            for (size_t i = 0; i < hide_len && i < comm_buf_len; i++) {
                comm[i] = ' ';
            }
        }
    }
}

// connect 系统调用 before hook
static void before_connect(hook_fargs3_t *args, void *udata) 
{
    struct sockaddr_in_compat addr_kernel;
    const char __user *addr = (typeof(addr))syscall_argn(args, 1);
    
    if (!addr || !__arch_copy_from_user) 
        return;
    
    // 从用户空间复制地址结构
    if (__arch_copy_from_user(&addr_kernel, addr, sizeof(struct sockaddr_in_compat)) != 0)
        return;
    
    u16 port = ntohs_local(addr_kernel.sin_port);
    
    // Frida 默认端口 27042
    if (port == 27042) {
        char comm[16] = {0};
        if (__get_task_comm) {
            __get_task_comm(comm, sizeof(comm), current);
        }
        
        pr_warn("frida_hide: detected connect to frida-agent, comm: %s, port: %d\n", comm, port);
        
        // 只允许 adbd 连接 frida
        if (!strstr(comm, "adbd")) {
            pr_warn("frida_hide: blocking connection to frida-agent, comm: %s\n", comm);
            args->skip_origin = 1;  // 跳过原始的 connect 函数
            args->ret = -ECONNREFUSED;  // 返回连接被拒绝错误
        }
    }
}

// ==================== KPM 生命周期函数 ====================

static long frida_hide_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("frida_hide: module initializing...\n");
    hook_err_t err;
    
    // 1. Hook show_map_vma (隐藏 /proc/pid/maps)
    show_map_vma = (void *)kallsyms_lookup_name("show_map_vma");
    if (show_map_vma) {
        err = hook_wrap2(show_map_vma, before_show_map_vma, after_show_map_vma, NULL);
        if (err == HOOK_NO_ERR) {
            show_map_vma_hooked = 1;
            pr_info("frida_hide: show_map_vma hooked successfully\n");
        } else {
            pr_err("frida_hide: failed to hook show_map_vma, err: %d\n", err);
        }
    } else {
        pr_warn("frida_hide: show_map_vma not found\n");
    }
    
    // 2. Hook __get_task_comm (隐藏线程名)
    __get_task_comm = (void *)kallsyms_lookup_name("__get_task_comm");
    if (__get_task_comm) {
        err = hook_wrap3(__get_task_comm, NULL, after_get_task_comm, NULL);
        if (err == HOOK_NO_ERR) {
            get_task_comm_hooked = 1;
            pr_info("frida_hide: __get_task_comm hooked successfully\n");
        } else {
            pr_err("frida_hide: failed to hook __get_task_comm, err: %d\n", err);
        }
    } else {
        pr_warn("frida_hide: __get_task_comm not found\n");
    }
    
    // 3. Hook connect 系统调用 (阻止连接)
    __arch_copy_from_user = (void *)kallsyms_lookup_name("__arch_copy_from_user");
    if (__arch_copy_from_user && __get_task_comm) {
        err = fp_hook_syscalln(__NR_connect, 3, before_connect, NULL, NULL);
        if (err == HOOK_NO_ERR) {
            connect_hooked = 1;
            pr_info("frida_hide: connect syscall hooked successfully\n");
        } else {
            pr_err("frida_hide: failed to hook connect, err: %d\n", err);
        }
    } else {
        pr_warn("frida_hide: __arch_copy_from_user or __get_task_comm not found, skipping connect hook\n");
    }
    
    pr_info("frida_hide: module initialized (hooks: maps=%d, comm=%d, connect=%d)\n",
            show_map_vma_hooked, get_task_comm_hooked, connect_hooked);
    
    return 0;
}

static long frida_hide_control0(const char *args, char *__user out_msg, int outlen)
{
    pr_info("frida_hide: control called with args: %s\n", args ? args : "(null)");
    
    char msg[128];
    snprintf(msg, sizeof(msg), "Frida Hide Status: maps=%d comm=%d connect=%d",
             show_map_vma_hooked, get_task_comm_hooked, connect_hooked);
    
    if (out_msg && outlen > 0) {
        compat_copy_to_user(out_msg, msg, min((int)sizeof(msg), outlen));
    }
    
    return 0;
}

static long frida_hide_exit(void *__user reserved)
{
    pr_info("frida_hide: module exiting...\n");
    
    // 1. Unhook show_map_vma
    if (show_map_vma_hooked && show_map_vma) {
        unhook(show_map_vma);
        show_map_vma = NULL;
        show_map_vma_hooked = 0;
        pr_info("frida_hide: show_map_vma unhooked\n");
    }
    
    // 2. Unhook __get_task_comm
    if (get_task_comm_hooked && __get_task_comm) {
        unhook(__get_task_comm);
        __get_task_comm = NULL;
        get_task_comm_hooked = 0;
        pr_info("frida_hide: __get_task_comm unhooked\n");
    }
    
    // 3. Unhook connect
    if (connect_hooked) {
        fp_unhook_syscalln(__NR_connect, before_connect, NULL);
        connect_hooked = 0;
        pr_info("frida_hide: connect syscall unhooked\n");
    }
    
    __arch_copy_from_user = NULL;
    
    pr_info("frida_hide: module exited\n");
    return 0;
}

// 注册 KPM 回调
KPM_INIT(frida_hide_init);
KPM_CTL0(frida_hide_control0);
KPM_EXIT(frida_hide_exit);
