#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/err.h>
#include <uapi/asm-generic/errno.h>
#include <hook.h>
#include <ksyms.h>

KPM_NAME("frida_hide");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Security Researcher");
KPM_DESCRIPTION("Hide Frida injection from detection");

// ==================== 常量定义 ====================
#define FRIDA_PORT_START 27042
#define FRIDA_PORT_END 27049
#define LOGV(fmt, ...) pr_info("frida_hide: " fmt, ##__VA_ARGS__)

#define AF_INET 2
#define ECONNREFUSED 111

// ==================== 结构体定义 ====================

struct seq_file {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
};

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int sin_addr;
    char sin_zero[8];
};

// socket 结构简化
struct socket {
    void *state;
    void *flags;
    void *file;
    void *sk;
    void *ops;
    // ...
};

// ==================== 全局变量 ====================

static uint64_t show_map_vma_addr = 0;
static uint64_t tcp_v4_connect_addr = 0;
static uint64_t proc_pid_comm_read_addr = 0;
static uint64_t comm_write_addr = 0;

// ==================== 辅助函数 ====================

static size_t my_strlen(const char *s)
{
    size_t len = 0;
    if (s) {
        while (*s++) len++;
    }
    return len;
}

static char *my_strstr(const char *haystack, const char *needle)
{
    if (!haystack || !needle) return 0;
    if (!*needle) return (char *)haystack;
    
    while (*haystack) {
        const char *h = haystack;
        const char *n = needle;
        while (*h && *n && *h == *n) {
            h++;
            n++;
        }
        if (!*n) return (char *)haystack;
        haystack++;
    }
    return 0;
}

static void *my_memmem(const void *haystack, size_t haystacklen, 
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

static inline uint16_t bswap16(uint16_t val) 
{
    return (val >> 8) | (val << 8);
}

// 检查是否是 frida 相关线程名
static int is_frida_thread_name(const char *name)
{
    if (!name || !*name) return 0;
    
    static const char *keywords[] = {
        "gmain",
        "gdbus", 
        "gum-js-loop",
        "pool-frida",
        "linjector",
    };
    
    int num = sizeof(keywords) / sizeof(keywords[0]);
    for (int i = 0; i < num; i++) {
        if (my_strstr(name, keywords[i])) {
            return 1;
        }
    }
    return 0;
}

// 检查 maps 内容是否包含 frida 特征
static int contains_frida_string(const char *buf, size_t len)
{
    if (!buf || len == 0) return 0;
    
    static const char *keywords[] = {
        "frida",
        "gadget",
        "gum-js",
    };
    
    int num = sizeof(keywords) / sizeof(keywords[0]);
    for (int i = 0; i < num; i++) {
        if (my_memmem(buf, len, keywords[i], my_strlen(keywords[i])))
            return 1;
    }
    return 0;
}

// 检查端口是否是 frida 端口
static int is_frida_port(uint16_t port)
{
    return (port >= FRIDA_PORT_START && port <= FRIDA_PORT_END);
}

// ==================== Hook 函数 ====================

// 1. show_map_vma hook - 隐藏 /proc/pid/maps 中的 frida 映射
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
    
    if (!m || !m->buf)
        return;
    
    size_t old_count = (size_t)args->local.data0;
    if (old_count == 0)
        return;
    
    // 检查新增的内容是否包含 frida 相关字符串
    if (m->count > old_count) {
        const char *new_data = m->buf + old_count;
        size_t new_len = m->count - old_count;
        
        if (contains_frida_string(new_data, new_len)) {
            // 回滚，隐藏这一行
            m->count = old_count;
        }
    }
}

// 2. tcp_v4_connect hook - 阻止连接 frida 端口
// int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
static void before_tcp_v4_connect(hook_fargs3_t *args, void *udata)
{
    struct sockaddr_in *addr = (struct sockaddr_in *)args->arg1;
    
    if (!addr)
        return;
    
    // 检查是否是 AF_INET
    if (addr->sin_family != AF_INET)
        return;
    
    uint16_t port = bswap16(addr->sin_port);
    
    // 检查是否是 frida 端口
    if (is_frida_port(port)) {
        LOGV("blocked connect to frida port %d\n", port);
        // 返回连接被拒绝
        args->ret = (uint64_t)(-(long)ECONNREFUSED);
        args->skip_origin = 1;
    }
}

// 3. comm_read hook - 隐藏 /proc/pid/task/tid/comm 中的 frida 线程名
// ssize_t comm_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
// 或者 hook seq_show for comm

// 方案A: hook proc_pid_comm_read (如果存在)
static void after_comm_read(hook_fargs4_t *args, void *udata)
{
    // 这个比较复杂，因为数据已经复制到用户空间
    // 需要用 copy_to_user 覆盖
}

// 方案B: hook __get_task_comm 或 get_task_comm
// char *__get_task_comm(char *buf, size_t buf_size, struct task_struct *tsk)
static void after_get_task_comm(hook_fargs3_t *args, void *udata)
{
    char *buf = (char *)args->arg0;
    
    if (!buf)
        return;
    
    if (is_frida_thread_name(buf)) {
        // 替换为普通线程名
        const char *fake = "kworker";
        char *p = buf;
        const char *f = fake;
        while (*f) {
            *p++ = *f++;
        }
        *p = '\0';
    }
}

// 方案C: hook comm_show (seq_file 方式读取 comm)
// int comm_show(struct seq_file *m, void *v)
static void before_comm_show(hook_fargs2_t *args, void *udata)
{
    args->local.data0 = 0;
    struct seq_file *m = (struct seq_file *)args->arg0;
    if (m && m->buf) {
        args->local.data0 = (uint64_t)m->count;
    }
}

static void after_comm_show(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    
    if (!m || !m->buf)
        return;
    
    size_t old_count = (size_t)args->local.data0;
    
    if (m->count > old_count) {
        char *new_data = m->buf + old_count;
        size_t new_len = m->count - old_count;
        
        // 检查是否包含 frida 线程名
        if (is_frida_thread_name(new_data)) {
            // 替换为假名
            const char *fake = "kworker\n";
            size_t fake_len = my_strlen(fake);
            
            // 覆盖内容
            char *p = new_data;
            const char *f = fake;
            while (*f && (size_t)(p - new_data) < new_len) {
                *p++ = *f++;
            }
            m->count = old_count + fake_len;
        }
    }
}

// ==================== 模块入口 ====================

static long frida_hide_init(const char *args, const char *event, void *__user reserved)
{
    LOGV("loading, version: %s\n", MYKPM_VERSION);
    
    int hooks_installed = 0;
    
    // 1. Hook show_map_vma - 隐藏 maps
    show_map_vma_addr = kallsyms_lookup_name("show_map_vma");
    if (show_map_vma_addr) {
        hook_err_t err = hook_wrap2((void *)show_map_vma_addr, 
                                    before_show_map_vma, 
                                    after_show_map_vma, 
                                    (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("show_map_vma hooked at 0x%llx\n", show_map_vma_addr);
            hooks_installed++;
        } else {
            LOGV("hook show_map_vma failed: %d\n", err);
            show_map_vma_addr = 0;
        }
    } else {
        LOGV("show_map_vma not found\n");
    }
    
    // 2. Hook tcp_v4_connect - 阻止连接 frida 端口
    tcp_v4_connect_addr = kallsyms_lookup_name("tcp_v4_connect");
    if (tcp_v4_connect_addr) {
        hook_err_t err = hook_wrap3((void *)tcp_v4_connect_addr, 
                                    before_tcp_v4_connect, 
                                    (void *)0, 
                                    (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("tcp_v4_connect hooked at 0x%llx\n", tcp_v4_connect_addr);
            hooks_installed++;
        } else {
            LOGV("hook tcp_v4_connect failed: %d\n", err);
            tcp_v4_connect_addr = 0;
        }
    } else {
        LOGV("tcp_v4_connect not found\n");
    }
    
    // 3. Hook comm_show - 隐藏线程名 (方案C)
    uint64_t comm_show_addr = kallsyms_lookup_name("comm_show");
    if (comm_show_addr) {
        hook_err_t err = hook_wrap2((void *)comm_show_addr, 
                                    before_comm_show, 
                                    after_comm_show, 
                                    (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("comm_show hooked at 0x%llx\n", comm_show_addr);
            comm_write_addr = comm_show_addr;  // 保存用于 unhook
            hooks_installed++;
        } else {
            LOGV("hook comm_show failed: %d\n", err);
        }
    } else {
        LOGV("comm_show not found, trying __get_task_comm\n");
        
        // 备选方案: hook __get_task_comm
        uint64_t get_task_comm_addr = kallsyms_lookup_name("__get_task_comm");
        if (!get_task_comm_addr) {
            get_task_comm_addr = kallsyms_lookup_name("get_task_comm");
        }
        
        if (get_task_comm_addr) {
            hook_err_t err = hook_wrap3((void *)get_task_comm_addr, 
                                        (void *)0, 
                                        after_get_task_comm, 
                                        (void *)0);
            if (err == HOOK_NO_ERR) {
                LOGV("get_task_comm hooked at 0x%llx\n", get_task_comm_addr);
                comm_write_addr = get_task_comm_addr;
                hooks_installed++;
            } else {
                LOGV("hook get_task_comm failed: %d\n", err);
            }
        } else {
            LOGV("get_task_comm not found\n");
        }
    }
    
    // 4. 尝试 hook proc_pid_cmdline_read (可选，用于隐藏 cmdline)
    uint64_t cmdline_addr = kallsyms_lookup_name("proc_pid_cmdline_read");
    if (cmdline_addr) {
        LOGV("proc_pid_cmdline_read found at 0x%llx (not hooked yet)\n", cmdline_addr);
    }
    
    LOGV("loaded, %d hooks installed\n", hooks_installed);
    return 0;
}

static long frida_hide_control0(const char *args, char *__user out_msg, int outlen)
{
    LOGV("control0 called, args=%s\n", args ? args : "null");
    
    char msg[64];
    int len = 0;
    
    // 简单的状态报告
    msg[len++] = 'O';
    msg[len++] = 'K';
    msg[len++] = ':';
    msg[len++] = ' ';
    msg[len++] = 'm';
    msg[len++] = 'a';
    msg[len++] = 'p';
    msg[len++] = 's';
    msg[len++] = '=';
    msg[len++] = show_map_vma_addr ? '1' : '0';
    msg[len++] = ',';
    msg[len++] = 't';
    msg[len++] = 'c';
    msg[len++] = 'p';
    msg[len++] = '=';
    msg[len++] = tcp_v4_connect_addr ? '1' : '0';
    msg[len++] = ',';
    msg[len++] = 'c';
    msg[len++] = 'o';
    msg[len++] = 'm';
    msg[len++] = 'm';
    msg[len++] = '=';
    msg[len++] = comm_write_addr ? '1' : '0';
    msg[len++] = '\0';
    
    if (out_msg && outlen > 0) {
        if (len > outlen) len = outlen;
        compat_copy_to_user(out_msg, msg, len);
    }
    
    return 0;
}

static long frida_hide_exit(void *__user reserved)
{
    LOGV("unloading...\n");
    
    if (show_map_vma_addr) {
        unhook((void *)show_map_vma_addr);
        show_map_vma_addr = 0;
    }
    
    if (tcp_v4_connect_addr) {
        unhook((void *)tcp_v4_connect_addr);
        tcp_v4_connect_addr = 0;
    }
    
    if (comm_write_addr) {
        unhook((void *)comm_write_addr);
        comm_write_addr = 0;
    }
    
    LOGV("unloaded\n");
    return 0;
}

KPM_INIT(frida_hide_init);
KPM_CTL0(frida_hide_control0);
KPM_EXIT(frida_hide_exit);
