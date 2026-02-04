#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/string.h>

// KPM 元数据
KPM_NAME("frida_hide");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Security Researcher");
KPM_DESCRIPTION("Hide Frida injection from detection");

// ==================== 常量定义 ====================
#ifndef ECONNREFUSED
#define ECONNREFUSED 111
#endif

#define FRIDA_PORT 27042

// ==================== 结构体定义 ====================

// seq_file 结构体（用于 /proc 文件系统）
struct seq_file {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
};

// sockaddr_in 结构体
struct sockaddr_in {
    short sin_family;
    unsigned short sin_port;
    unsigned int sin_addr;
    char sin_zero[8];
};

// ==================== 全局变量 ====================

static void *show_map_vma = NULL;
static char *(*__get_task_comm)(char *buf, size_t buf_size, struct task_struct *tsk) = NULL;
static unsigned long (*__arch_copy_from_user)(void *to, const void __user *from, unsigned long n) = NULL;

static int show_map_vma_hooked = 0;
static int get_task_comm_hooked = 0;
static int connect_hooked = 0;

// ==================== 辅助函数 ====================

// 内存搜索函数
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

// 检查是否包含 Frida 相关字符串
static int is_hiden_module(struct seq_file *m)
{
    if (!m || !m->buf || m->count == 0) 
        return 0;
    
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

// 大端转小端
static inline u16 ntohs_local(u16 port) 
{
    return (port >> 8) | (port << 8);
}

// ==================== Hook 回调函数 ====================

// show_map_vma before hook - 记录原始 count
static void before_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    args->local.data0 = 0;
    
    if (m && m->buf) {
        args->local.data0 = m->count;
    }
}

// show_map_vma after hook - 隐藏 Frida 相关条目
static void after_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    
    if (m && m->buf && args->local.data0) {
        if (is_hiden_module(m)) {
            logki("hiding frida-agent from /proc/pid/maps\n");
            m->count = args->local.data0;
        }
    }
}

// __get_task_comm after hook - 隐藏线程名
static void __attribute__((optimize("O0"))) after_get_task_comm(hook_fargs3_t *args, void *udata)
{
    char *comm = (char *)args->arg0;
    size_t comm_buf_len = (size_t)args->arg1;
    
    if (comm && comm_buf_len > 0) {
        if (is_hiden_comm(comm)) {
            logki("hiding thread name: %s\n", comm);
            size_t hide_len = strlen(comm);
            for (size_t i = 0; i < hide_len && i < comm_buf_len; i++) {
                comm[i] = ' ';
            }
        }
    }
}

// connect 系统调用 before hook - 阻止连接 Frida
static void before_connect(hook_fargs3_t *args, void *udata) 
{
    struct sockaddr_in addr_kernel;
    const char __user *addr = (typeof(addr))syscall_argn(args, 1);
    
    if (!addr || !__arch_copy_from_user) 
        return;
    
    if (__arch_copy_from_user(&addr_kernel, addr, sizeof(struct sockaddr_in)) != 0)
        return;
    
    u16 port = ntohs_local(addr_kernel.sin_port);
    
    if (port == FRIDA_PORT) {
        char comm[16] = {0};
        if (__get_task_comm) {
            __get_task_comm(comm, sizeof(comm), current);
        }
        
        logkw("detected connect to frida-agent, comm: %s, port: %d\n", comm, port);
        
        // 只允许 adbd 连接
        if (!strstr(comm, "adbd")) {
            logkw("blocking connection, comm: %s\n", comm);
            args->skip_origin = 1;
            args->ret = -ECONNREFUSED;
        }
    }
}

// ==================== KPM 生命周期函数 ====================

static long frida_hide_init(const char *args, const char *event, void *__user reserved)
{
    logki("module initializing...\n");
    hook_err_t err;
    
    // 1. Hook show_map_vma
    show_map_vma = (void *)kallsyms_lookup_name("show_map_vma");
    if (show_map_vma) {
        err = hook_wrap2(show_map_vma, before_show_map_vma, after_show_map_vma, NULL);
        if (err == HOOK_NO_ERR) {
            show_map_vma_hooked = 1;
            logki("show_map_vma hooked\n");
        } else {
            logke("failed to hook show_map_vma: %d\n", err);
        }
    } else {
        logkw("show_map_vma not found\n");
    }
    
    // 2. Hook __get_task_comm
    __get_task_comm = (void *)kallsyms_lookup_name("__get_task_comm");
    if (__get_task_comm) {
        err = hook_wrap3(__get_task_comm, NULL, after_get_task_comm, NULL);
        if (err == HOOK_NO_ERR) {
            get_task_comm_hooked = 1;
            logki("__get_task_comm hooked\n");
        } else {
            logke("failed to hook __get_task_comm: %d\n", err);
        }
    } else {
        logkw("__get_task_comm not found\n");
    }
    
    // 3. Hook connect 系统调用
    __arch_copy_from_user = (void *)kallsyms_lookup_name("__arch_copy_from_user");
    if (__arch_copy_from_user && __get_task_comm) {
        err = fp_hook_syscalln(__NR_connect, 3, before_connect, NULL, NULL);
        if (err == HOOK_NO_ERR) {
            connect_hooked = 1;
            logki("connect syscall hooked\n");
        } else {
            logke("failed to hook connect: %d\n", err);
        }
    } else {
        logkw("skipping connect hook (missing dependencies)\n");
    }
    
    logki("initialized (maps=%d, comm=%d, connect=%d)\n",
          show_map_vma_hooked, get_task_comm_hooked, connect_hooked);
    
    return 0;
}

static long frida_hide_control0(const char *args, char *__user out_msg, int outlen)
{
    logki("control called: %s\n", args ? args : "(null)");
    
    char msg[128];
    snprintf(msg, sizeof(msg), "Status: maps=%d comm=%d connect=%d",
             show_map_vma_hooked, get_task_comm_hooked, connect_hooked);
    
    if (out_msg && outlen > 0) {
        compat_copy_to_user(out_msg, msg, outlen < sizeof(msg) ? outlen : sizeof(msg));
    }
    
    return 0;
}

static long frida_hide_exit(void *__user reserved)
{
    logki("module exiting...\n");
    
    if (show_map_vma_hooked && show_map_vma) {
        unhook(show_map_vma);
        show_map_vma = NULL;
        show_map_vma_hooked = 0;
    }
    
    if (get_task_comm_hooked && __get_task_comm) {
        unhook(__get_task_comm);
        __get_task_comm = NULL;
        get_task_comm_hooked = 0;
    }
    
    if (connect_hooked) {
        fp_unhook_syscalln(__NR_connect, before_connect, NULL);
        connect_hooked = 0;
    }
    
    __arch_copy_from_user = NULL;
    logki("module exited\n");
    return 0;
}

KPM_INIT(frida_hide_init);
KPM_CTL0(frida_hide_control0);
KPM_EXIT(frida_hide_exit);
