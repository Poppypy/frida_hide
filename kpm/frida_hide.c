#include <kallsyms.h>
#include <linux/printk.h>
#include <log.h>
#include <kpmodule.h>
#include <hook.h>
#include <stdbool.h>
#include <stdint.h>
#include <syscall.h>
#include <compiler.h>
#include <kputils.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/asm-generic/unistd.h>
#include <asm/current.h>

#ifndef MYKPM_VERSION
// VSCode IntelliSense 没有走 Makefile 的 -DMYKPM_VERSION 时会报红；编译时仍以 Makefile 传入为准。
#define MYKPM_VERSION "dev"
#endif

#ifndef __NR_connect
// IntelliSense 兜底：正常编译会从 <uapi/asm-generic/unistd.h> 获得该宏。
#define __NR_connect 203
#endif

KPM_NAME("FridaHide");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("popy");
KPM_DESCRIPTION("Hide Frida traces in maps/threads/connect");


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

static void *show_map_vma = NULL;
static char *(*__get_task_comm)(char *buf, size_t buf_size, struct task_struct *tsk) = NULL;  // 为了后续能够调用，定义成函数指针变量
static unsigned long (*__arch_copy_from_user)(void *to, const void __user *from, unsigned long n) = NULL;

static int show_map_vma_hook_status = 0;
static int get_task_comm_hook_status = 0;
static int connect_hook_status = 0;
static int frida_hide_enabled = 1;
static int frida_hide_log_enabled = 1;
static int frida_hide_log_verbose = 0;

#define FH_LOGI(fmt, ...)                       \
    do {                                        \
        if (frida_hide_log_enabled)             \
            logki(fmt, ##__VA_ARGS__);          \
    } while (0)
#define FH_LOGW(fmt, ...)                       \
    do {                                        \
        if (frida_hide_log_enabled)             \
            logkw(fmt, ##__VA_ARGS__);          \
    } while (0)
#define FH_LOGD(fmt, ...)                               \
    do {                                                \
        if (frida_hide_log_enabled && frida_hide_log_verbose) \
            logkd(fmt, ##__VA_ARGS__);                  \
    } while (0)
#define FH_BOOT(fmt, ...)                      \
    do {                                       \
        if (frida_hide_log_enabled)            \
            log_boot(fmt, ##__VA_ARGS__);      \
    } while (0)

#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#endif

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
static const char *get_hiden_module_keyword(struct seq_file *m)
{
    if (!m || !m->buf || m->count == 0) return NULL;
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
            return keywords[i];
    }
    return NULL;
}

static const char *get_hiden_comm_keyword(const char *comm)
{
    // 需要隐藏的线程名关键词列表
    static const char *keywords[] = {
        "gmain",
        "gum-js-loop",
        "gdbus",
        "pool-frida",
        "linjector",
        NULL
    };

    for (int i = 0; keywords[i] != NULL; i++) {
        if (strstr(comm, keywords[i])) {
            return keywords[i];
        }
    }
    return NULL;
}

static void before_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    args->local.data0 = 0;
    if (m && m->buf) {
        // 记录 seq_file 中的count，在 after hook 中设置 count 为记录值
        args->local.data0 = m->count;
    } 
}

static void after_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    if (m && m->buf) {
        const char *keyword = NULL;
        if (args->local.data0 && (keyword = get_hiden_module_keyword(m))) {  // get_hiden_module_keyword 查找 frida-agent 等字符串
            FH_LOGI("inject-hide: maps hide -> %s\n", keyword);
            m->count = args->local.data0;  // 恢复原来的 count 值
        }
    }
}

static void __attribute__((optimize("O0"))) after_get_task_comm(hook_fargs3_t *args, void *udata)
{
    char *comm = (char *)args->arg0;
    size_t comm_buf_len = (size_t)args->arg1;
    if (comm && comm_buf_len) {
        const char *keyword = get_hiden_comm_keyword(comm);
        if (keyword){
            FH_LOGI("inject-hide: get_task_comm hide -> %s (matched: %s)\n", comm, keyword);
            size_t hide_len = strlen(comm);
            for(size_t i = 0; i < hide_len; i++) {
                comm[i] = ' ';
            }
        }
    }
}

// 网络协议中的端口号（大端）转换为主机字节序（小端）
static inline uint16_t ntohs_u16(uint16_t port)
{
    return (uint16_t)((port >> 8) | (port << 8));
}
static void before_connect(hook_fargs3_t *args, void *udata)
{
    struct sockaddr_in addr_kernel;
    const char __user *addr = (const char __user *)(uintptr_t)syscall_argn(args, 1);
    if (!addr) return;

    if (!__arch_copy_from_user) return;
    if (__arch_copy_from_user(&addr_kernel, addr, sizeof(struct sockaddr_in)) != 0) return;

    uint16_t port = ntohs_u16(addr_kernel.sin_port);
    if (port == 27042) {
        char comm[16];
        if (!__get_task_comm) return;
        __get_task_comm(comm, sizeof(comm), current);

        FH_LOGW("inject-hide: connect to frida-agent, comm: %s, port: %d\n", comm, port);
        if (!strstr(comm, "adbd")) {  // 只允许 adbd 连接 frida
            FH_LOGW("inject-hide: connect to frida-agent blocked, comm: %s, port: %d\n", comm, port);
            args->skip_origin = 1;  // 跳过原始的 connect 函数
            args->ret = -EPERM;  // 返回 -EPERM 表示拒绝连接
        }
    }
}

void frida_hide_install(void)
{
    FH_LOGI("inject-hide: install\n");
    FH_BOOT("inject-hide: install\n");
    show_map_vma = (void *) kallsyms_lookup_name("show_map_vma");
    FH_LOGD("inject-hide: show_map_vma addr=0x%lx\n", (unsigned long)(uintptr_t)show_map_vma);
    if (show_map_vma) {
        hook_err_t err = hook_wrap2(show_map_vma, before_show_map_vma, after_show_map_vma, NULL);
        if (err == HOOK_NO_ERR) {
            show_map_vma_hook_status = 1;
            FH_LOGI("inject-hide: hook show_map_vma ok\n");
            FH_BOOT("inject-hide: hook show_map_vma ok\n");
        } else {
            FH_LOGW("inject-hide: hook show_map_vma failed: %d\n", err);
            FH_BOOT("inject-hide: hook show_map_vma failed: %d\n", err);
        }
    } else {
        FH_LOGW("inject-hide: kallsyms show_map_vma not found\n");
        FH_BOOT("inject-hide: kallsyms show_map_vma not found\n");
    }

    __get_task_comm = (void *) kallsyms_lookup_name("__get_task_comm");
    if (!__get_task_comm) {
        __get_task_comm = (void *)kallsyms_lookup_name("get_task_comm");
    }
    FH_LOGD("inject-hide: get_task_comm addr=0x%lx\n", (unsigned long)(uintptr_t)__get_task_comm);
    if (__get_task_comm) {
        hook_err_t err = hook_wrap3(__get_task_comm, 0, after_get_task_comm, 0);
        if (err == HOOK_NO_ERR) {
            get_task_comm_hook_status = 1;
            FH_LOGI("inject-hide: hook get_task_comm ok\n");
            FH_BOOT("inject-hide: hook get_task_comm ok\n");
        } else {
            FH_LOGW("inject-hide: hook get_task_comm failed: %d\n", err);
            FH_BOOT("inject-hide: hook get_task_comm failed: %d\n", err);
        }
    } else {
        FH_LOGW("inject-hide: kallsyms get_task_comm not found\n");
        FH_BOOT("inject-hide: kallsyms get_task_comm not found\n");
    }

    __arch_copy_from_user = (void *)kallsyms_lookup_name("__arch_copy_from_user");
    if (!__arch_copy_from_user) {
        __arch_copy_from_user = (void *)kallsyms_lookup_name("copy_from_user");
    }
    FH_LOGD("inject-hide: copy_from_user addr=0x%lx\n", (unsigned long)(uintptr_t)__arch_copy_from_user);
    if(__arch_copy_from_user && __get_task_comm) {
        hook_err_t err = fp_hook_syscalln(__NR_connect, 3, before_connect, 0, NULL);
        if (err == HOOK_NO_ERR) {
            connect_hook_status = 1;
            FH_LOGI("inject-hide: hook connect syscall ok\n");
            FH_BOOT("inject-hide: hook connect syscall ok\n");
        } else {
            FH_LOGW("inject-hide: hook connect syscall failed: %d\n", err);
            FH_BOOT("inject-hide: hook connect syscall failed: %d\n", err);
        }
    } else {
        FH_LOGW("inject-hide: kallsyms copy_from_user not found\n");
        FH_BOOT("inject-hide: kallsyms copy_from_user not found\n");
    }
}

void frida_hide_uninstall(void)
{
    FH_LOGI("inject-hide: uninstall\n");
    FH_BOOT("inject-hide: uninstall\n");
    if (show_map_vma && show_map_vma_hook_status) {
        unhook(show_map_vma);
        show_map_vma = 0;
        show_map_vma_hook_status = 0;
    }

    if (__get_task_comm && get_task_comm_hook_status) {
        unhook(__get_task_comm);
        __get_task_comm = 0;
        get_task_comm_hook_status = 0;
    }

    if(connect_hook_status) {
        fp_unhook_syscalln(__NR_connect, before_connect, 0);
        connect_hook_status = 0;
    }
}

static long frida_hide_init(const char *args, const char *event, void *reserved)
{
    FH_LOGI("inject-hide: module init\n");
    FH_BOOT("inject-hide: module init\n");
    if (frida_hide_enabled) {
        frida_hide_install();
    } else {
        FH_LOGI("inject-hide: start disabled\n");
        FH_BOOT("inject-hide: start disabled\n");
    }
    return 0;
}

static long frida_hide_exit(void *reserved)
{
    FH_LOGI("inject-hide: module exit\n");
    FH_BOOT("inject-hide: module exit\n");
    frida_hide_uninstall();
    return 0;
}

static long frida_hide_ctl0(const char *args, char __user *out_msg, int outlen)
{
    char reply_msg[256];
    int reply_len = 0;

    if (!args || !strncmp(args, "STATUS", 6)) {
        reply_len = snprintf(reply_msg, sizeof(reply_msg),
                             "enabled: %s\nlog: %s\nverbose: %s\nshow_map_vma: %d\nget_task_comm: %d\nconnect: %d\n",
                             frida_hide_enabled ? "enabled" : "disabled",
                             frida_hide_log_enabled ? "on" : "off",
                             frida_hide_log_verbose ? "on" : "off",
                             show_map_vma_hook_status, get_task_comm_hook_status, connect_hook_status);
    } else if (!strcmp(args, "EN")) {
        if (!frida_hide_enabled) {
            frida_hide_enabled = 1;
            frida_hide_install();
        }
        reply_len = snprintf(reply_msg, sizeof(reply_msg), "enabled");
    } else if (!strcmp(args, "DIS")) {
        if (frida_hide_enabled) {
            frida_hide_enabled = 0;
            frida_hide_uninstall();
        }
        reply_len = snprintf(reply_msg, sizeof(reply_msg), "disabled");
    } else if (!strncmp(args, "LOG ", 4)) {
        frida_hide_log_enabled = (args[4] != '0');
        reply_len = snprintf(reply_msg, sizeof(reply_msg), "log: %s", frida_hide_log_enabled ? "on" : "off");
    } else if (!strncmp(args, "LOGV ", 5)) {
        frida_hide_log_verbose = (args[5] != '0');
        reply_len = snprintf(reply_msg, sizeof(reply_msg), "verbose: %s", frida_hide_log_verbose ? "on" : "off");
    } else {
        reply_len = snprintf(reply_msg, sizeof(reply_msg),
                             "Unknown command\nAvailable: STATUS | EN | DIS | LOG 0/1 | LOGV 0/1\n");
    }

    if (out_msg && outlen > 0 && reply_len > 0) {
        int copy_len = min(reply_len + 1, outlen);
        if (compat_copy_to_user(out_msg, reply_msg, copy_len) <= 0) {
            FH_LOGW("inject-hide: failed to copy reply to user\n");
            return -1;
        }
    }

    return 0;
}

KPM_INIT(frida_hide_init);
KPM_CTL0(frida_hide_ctl0);
KPM_EXIT(frida_hide_exit);
