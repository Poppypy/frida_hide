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
#define UID_APP_START 10000

// ==================== 结构体定义 ====================

struct seq_file {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
    size_t pad_until;
    loff_t index;
    loff_t read_pos;
};

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int sin_addr;
    char sin_zero[8];
};

// ==================== 全局变量 ====================

static uint64_t show_map_vma_addr = 0;
static uint64_t show_smap_addr = 0;
static uint64_t tcp_v4_connect_addr = 0;
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

static int is_app_process(void)
{
    uid_t uid = current_uid();
    return (uid >= UID_APP_START);
}

static int is_frida_thread_name(const char *name)
{
    if (!name || !*name) return 0;
    
    static const char *keywords[] = {
        "gmain",
        "gdbus", 
        "gum-js-loop",
        "pool-frida",
        "linjector",
        "frida",
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
    
    // 关键词列表
    static const char *keywords[] = {
        "frida",
        "Frida", 
        "FRIDA",
        "gadget",
        "Gadget",
        "gum-js",
        "frida-agent",
        "frida_agent",
        "linjector",
        "memfd:",
    };
    
    int num = sizeof(keywords) / sizeof(keywords[0]);
    for (int i = 0; i < num; i++) {
        if (my_memmem(buf, len, keywords[i], my_strlen(keywords[i]))) {
            // 对于 memfd: 需要进一步检查
            if (i == 9) { // memfd:
                // 检查 memfd 后面是否有 frida/agent 相关
                char *pos = (char *)my_memmem(buf, len, "memfd:", 6);
                if (pos) {
                    size_t remaining = len - (pos - buf);
                    if (my_memmem(pos, remaining, "frida", 5) ||
                        my_memmem(pos, remaining, "agent", 5) ||
                        my_memmem(pos, remaining, "gum", 3)) {
                        return 1;
                    }
                }
                continue;
            }
            return 1;
        }
    }
    return 0;
}

static int is_frida_port(uint16_t port)
{
    return (port >= FRIDA_PORT_START && port <= FRIDA_PORT_END);
}

// ==================== Hook 函数 ====================

// show_map_vma hook - 隐藏 /proc/pid/maps 中的 frida 映射
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
    
    if (m->count > old_count) {
        const char *new_data = m->buf + old_count;
        size_t new_len = m->count - old_count;
        
        if (contains_frida_string(new_data, new_len)) {
            m->count = old_count;
            LOGV("hidden frida mapping\n");
        }
    }
}

// tcp_v4_connect hook
static void before_tcp_v4_connect(hook_fargs3_t *args, void *udata)
{
    struct sockaddr_in *addr = (struct sockaddr_in *)args->arg1;
    
    if (!addr)
        return;
    
    if (addr->sin_family != AF_INET)
        return;
    
    uint16_t port = bswap16(addr->sin_port);
    
    if (!is_frida_port(port))
        return;
    
    if (!is_app_process())
        return;
    
    LOGV("blocked connect to port %d\n", port);
    args->ret = (uint64_t)(-(long)ECONNREFUSED);
    args->skip_origin = 1;
}

// comm_show hook
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
        
        char saved = 0;
        if (new_len > 0 && new_len < 256) {
            saved = new_data[new_len];
            new_data[new_len] = '\0';
        }
        
        if (is_frida_thread_name(new_data)) {
            const char *fake = "kworker\n";
            size_t fake_len = 8;
            int j = 0;
            while (j < (int)fake_len) {
                new_data[j] = fake[j];
                j++;
            }
            m->count = old_count + fake_len;
        } else if (saved) {
            new_data[new_len] = saved;
        }
    }
}

// __get_task_comm hook
static void after_get_task_comm(hook_fargs3_t *args, void *udata)
{
    char *buf = (char *)args->arg0;
    
    if (!buf)
        return;
    
    if (is_frida_thread_name(buf)) {
        buf[0] = 'k';
        buf[1] = 'w';
        buf[2] = 'o';
        buf[3] = 'r';
        buf[4] = 'k';
        buf[5] = 'e';
        buf[6] = 'r';
        buf[7] = '\0';
    }
}

// ==================== 模块入口 ====================

static long frida_hide_init(const char *args, const char *event, void *__user reserved)
{
    LOGV("loading, version: %s\n", MYKPM_VERSION);
    
    int hooks_installed = 0;
    
    // 1. Hook show_map_vma
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
    
    // 2. Hook show_smap
    show_smap_addr = kallsyms_lookup_name("show_smap");
    if (show_smap_addr) {
        hook_err_t err = hook_wrap2((void *)show_smap_addr, 
                                    before_show_map_vma, 
                                    after_show_map_vma, 
                                    (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("show_smap hooked at 0x%llx\n", show_smap_addr);
            hooks_installed++;
        } else {
            LOGV("hook show_smap failed: %d\n", err);
            show_smap_addr = 0;
        }
    } else {
        LOGV("show_smap not found\n");
    }
    
    // 3. Hook tcp_v4_connect
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
    
    // 4. Hook comm_show
    uint64_t comm_show_addr = kallsyms_lookup_name("comm_show");
    if (comm_show_addr) {
        hook_err_t err = hook_wrap2((void *)comm_show_addr, 
                                    before_comm_show, 
                                    after_comm_show, 
                                    (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("comm_show hooked at 0x%llx\n", comm_show_addr);
            comm_write_addr = comm_show_addr;
            hooks_installed++;
        } else {
            LOGV("hook comm_show failed: %d\n", err);
        }
    } else {
        LOGV("comm_show not found, trying __get_task_comm\n");
        
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
        }
    }
    
    LOGV("loaded, %d hooks installed\n", hooks_installed);
    return 0;
}

static long frida_hide_control0(const char *args, char *__user out_msg, int outlen)
{
    char msg[] = "frida_hide: OK";
    if (out_msg && outlen > 0) {
        int len = sizeof(msg);
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
    
    if (show_smap_addr) {
        unhook((void *)show_smap_addr);
        show_smap_addr = 0;
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
