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
KPM_DESCRIPTION("Hide Frida injection from detection - Full Version");

// ==================== 常量定义 ====================
#define FRIDA_PORT_START 27042
#define FRIDA_PORT_END 27049
#define LOGV(fmt, ...) pr_info("frida_hide: " fmt, ##__VA_ARGS__)

#define AF_INET 2
#define ECONNREFUSED 111
#define ENOENT 2
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

// vm_area_struct 简化定义
struct vm_area_struct_partial {
    unsigned long vm_start;
    unsigned long vm_end;
    unsigned long vm_flags;
    // ... 其他字段
};

// ==================== 全局变量 ====================

static uint64_t show_map_vma_addr = 0;
static uint64_t show_smap_addr = 0;
static uint64_t tcp_v4_connect_addr = 0;
static uint64_t comm_write_addr = 0;
static uint64_t proc_pid_readlink_addr = 0;
static uint64_t do_readlinkat_addr = 0;
static uint64_t seq_read_addr = 0;
static uint64_t vfs_read_addr = 0;

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

static void my_memcpy(void *dst, const void *src, size_t n)
{
    char *d = dst;
    const char *s = src;
    while (n--) *d++ = *s++;
}

static int my_memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *p1 = s1, *p2 = s2;
    while (n--) {
        if (*p1 != *p2) return *p1 - *p2;
        p1++;
        p2++;
    }
    return 0;
}

static char my_tolower(char c)
{
    if (c >= 'A' && c <= 'Z') return c + 32;
    return c;
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

// 不区分大小写的子串搜索
static char *my_strcasestr(const char *haystack, const char *needle)
{
    if (!haystack || !needle) return 0;
    if (!*needle) return (char *)haystack;
    
    size_t needle_len = my_strlen(needle);
    
    while (*haystack) {
        int match = 1;
        for (size_t i = 0; i < needle_len; i++) {
            if (!haystack[i]) {
                match = 0;
                break;
            }
            if (my_tolower(haystack[i]) != my_tolower(needle[i])) {
                match = 0;
                break;
            }
        }
        if (match) return (char *)haystack;
        haystack++;
    }
    return 0;
}

static int is_frida_thread_name(const char *name)
{
    if (!name || !*name) return 0;
    
    static const char *keywords[] = {
        "gmain", "gdbus", "gum-js-loop", "pool-frida",
        "linjector", "frida", "agent-main", "v8:",
        "gum-js", "pool-spawner",
    };
    
    int num = sizeof(keywords) / sizeof(keywords[0]);
    for (int i = 0; i < num; i++) {
        if (my_strcasestr(name, keywords[i])) return 1;
    }
    return 0;
}

// 检查是否是 frida 相关的映射内容
static int is_frida_mapping_content(const char *buf, size_t len)
{
    if (!buf || len == 0) return 0;
    
    static const char *keywords[] = {
        "frida-agent", "frida-gadget", "re.frida.server",
        "gum-js-loop", "gum-js", "pool-frida", "linjector",
        "memfd:frida", "memfd:gum", "frida_agent",
        "/data/local/tmp/re.frida", "gadget",
    };
    
    int num = sizeof(keywords) / sizeof(keywords[0]);
    for (int i = 0; i < num; i++) {
        // 使用不区分大小写的搜索
        size_t klen = my_strlen(keywords[i]);
        for (size_t j = 0; j + klen <= len; j++) {
            int match = 1;
            for (size_t k = 0; k < klen; k++) {
                if (my_tolower(buf[j + k]) != my_tolower(keywords[i][k])) {
                    match = 0;
                    break;
                }
            }
            if (match) return 1;
        }
    }
    return 0;
}

// 检查并修复 RWX 权限行
// maps 格式: 7c00000000-7c00001000 rwxp 00000000 fe:00 12345  /path/to/lib.so
static int fix_rwx_in_line(char *line, size_t len)
{
    if (!line || len < 25) return 0;
    
    // 找到权限字段位置 (在第一个空格之后)
    char *space = 0;
    for (size_t i = 0; i < len; i++) {
        if (line[i] == ' ') {
            space = &line[i];
            break;
        }
    }
    
    if (!space || (size_t)(space - line + 5) > len) return 0;
    
    char *perms = space + 1;
    
    // 检查是否是 rwxp 或 rwxs
    if (perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x') {
        // 检查是否是 libc.so 相关
        if (my_strcasestr(line, "libc.so")) {
            // 将 rwx 改为 r-x
            perms[1] = '-';
            LOGV("fixed libc rwx -> r-x\n");
            return 1;
        }
    }
    return 0;
}

// 检查是否应该隐藏整行
static int should_hide_map_line(const char *line, size_t len)
{
    if (!line || len == 0) return 0;
    
    // 1. 检查 frida 特征关键字
    if (is_frida_mapping_content(line, len)) {
        return 1;
    }
    
    // 2. 检查 memfd 匿名映射
    if (my_memmem(line, len, "memfd:", 6)) {
        // memfd:frida, memfd:gum 等
        if (my_strcasestr(line, "frida") || 
            my_strcasestr(line, "gum") ||
            my_strcasestr(line, "jit-cache")) {
            return 1;
        }
    }
    
    // 3. 检查 /data/local/tmp 下的可疑文件
    if (my_memmem(line, len, "/data/local/tmp/", 16)) {
        if (my_strcasestr(line, "frida") ||
            my_strcasestr(line, "gadget") ||
            my_strcasestr(line, "agent")) {
            return 1;
        }
    }
    
    return 0;
}

static int is_frida_port(uint16_t port)
{
    return (port >= FRIDA_PORT_START && port <= FRIDA_PORT_END);
}

// 检查 fd 链接目标是否是 frida 相关
static int is_frida_fd_target(const char *target, size_t len)
{
    if (!target || len == 0) return 0;
    
    static const char *keywords[] = {
        "frida-agent", "frida-gadget", "re.frida.server",
        "gum-js-loop", "gum-js", "pool-frida", "linjector",
        "memfd:frida", "memfd:gum",
    };
    
    int num = sizeof(keywords) / sizeof(keywords[0]);
    for (int i = 0; i < num; i++) {
        if (my_strcasestr(target, keywords[i])) return 1;
    }
    return 0;
}

// ==================== Hook 函数 ====================

// show_map_vma hook - 隐藏 frida 映射并修复 RWX 权限
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
    
    if (!m || !m->buf) return;
    
    size_t old_count = (size_t)args->local.data0;
    
    if (m->count <= old_count) return;
    
    char *new_data = m->buf + old_count;
    size_t new_len = m->count - old_count;
    
    // 1. 检查是否应该隐藏整行
    if (should_hide_map_line(new_data, new_len)) {
        m->count = old_count;
        LOGV("hidden frida mapping line\n");
        return;
    }
    
    // 2. 修复 RWX 权限
    fix_rwx_in_line(new_data, new_len);
}

// tcp_v4_connect hook - 阻断 Frida 端口连接
static void before_tcp_v4_connect(hook_fargs3_t *args, void *udata)
{
    struct sockaddr_in *addr = (struct sockaddr_in *)args->arg1;
    
    if (!addr) return;
    if (addr->sin_family != AF_INET) return;
    
    uint16_t port = bswap16(addr->sin_port);
    
    if (!is_frida_port(port)) return;
    if (!is_app_process()) return;
    
    LOGV("blocked connect to frida port %d\n", port);
    args->ret = (uint64_t)(-(long)ECONNREFUSED);
    args->skip_origin = 1;
}

// comm_show hook - 隐藏 Frida 线程名
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
    
    if (!m || !m->buf) return;
    
    size_t old_count = (size_t)args->local.data0;
    
    if (m->count <= old_count) return;
    
    char *new_data = m->buf + old_count;
    size_t new_len = m->count - old_count;
    
    // 检查线程名
    char temp[64];
    size_t copy_len = new_len < 63 ? new_len : 63;
    my_memcpy(temp, new_data, copy_len);
    temp[copy_len] = '\0';
    
    // 去掉换行符
    for (int i = 0; i < (int)copy_len; i++) {
        if (temp[i] == '\n' || temp[i] == '\r') {
            temp[i] = '\0';
            break;
        }
    }
    
    if (is_frida_thread_name(temp)) {
        // 替换为普通线程名
        const char *fake = "binder:0\n";
        size_t fake_len = 9;
        my_memcpy(new_data, fake, fake_len);
        m->count = old_count + fake_len;
        LOGV("hidden frida thread: %s\n", temp);
    }
}

// __get_task_comm hook
static void after_get_task_comm(hook_fargs3_t *args, void *udata)
{
    char *buf = (char *)args->arg0;
    
    if (!buf) return;
    
    if (is_frida_thread_name(buf)) {
        const char *fake = "binder:0";
        my_memcpy(buf, fake, 9);
        LOGV("hidden frida thread comm\n");
    }
}

// do_readlinkat hook - 隐藏 /proc/pid/fd 中的 frida 链接
static void before_do_readlinkat(hook_fargs4_t *args, void *udata)
{
    args->local.data0 = 0;
}

static void after_do_readlinkat(hook_fargs4_t *args, void *udata)
{
    long ret = (long)args->ret;
    if (ret <= 0) return;
    
    // 这里需要检查返回的路径内容
    // 由于是用户空间缓冲区，处理较复杂
    // 暂时跳过详细实现
}

// ==================== 模块入口 ====================

static long frida_hide_init(const char *args, const char *event, void *__user reserved)
{
    LOGV("loading version: %s\n", MYKPM_VERSION);
    
    int hooks_installed = 0;
    
    // 1. Hook show_map_vma - 隐藏 maps 中的 frida 映射和修复 RWX
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
    
    // 2. Hook show_smap - 同样处理 smaps
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
            show_smap_addr = 0;
        }
    }
    
    // 3. Hook tcp_v4_connect - 阻断 Frida 端口
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
            tcp_v4_connect_addr = 0;
        }
    }
    
    // 4. Hook comm_show - 隐藏线程名
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
        }
    } else {
        // 尝试 hook __get_task_comm
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
            }
        }
    }
    
    // 5. 尝试 hook proc_pid_readlink 处理 fd 链接
    proc_pid_readlink_addr = kallsyms_lookup_name("proc_pid_readlink");
    if (proc_pid_readlink_addr) {
        // 这个 hook 比较复杂，暂时跳过
        LOGV("proc_pid_readlink found at 0x%llx (not hooked)\n", proc_pid_readlink_addr);
    }
    
    LOGV("loaded successfully, %d hooks installed\n", hooks_installed);
    return 0;
}

static long frida_hide_control0(const char *args, char *__user out_msg, int outlen)
{
    char msg[64] = "frida_hide: OK, hooks active";
    if (out_msg && outlen > 0) {
        int len = my_strlen(msg) + 1;
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
    
    LOGV("unloaded successfully\n");
    return 0;
}

KPM_INIT(frida_hide_init);
KPM_CTL0(frida_hide_control0);
KPM_EXIT(frida_hide_exit);
