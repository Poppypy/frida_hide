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
KPM_DESCRIPTION("Hide Frida/Root/Xposed detection - Ultimate Edition");

// ==================== 常量定义 ====================
#define FRIDA_PORT_START 27042
#define FRIDA_PORT_END 27052
#define LOGV(fmt, ...) pr_info("frida_hide: " fmt, ##__VA_ARGS__)

#define AF_INET 2
#define AF_INET6 10
#define ECONNREFUSED 111
#define ENOENT 2
#define UID_APP_START 10000
#define MAX_PATH_LEN 256

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

struct sockaddr_in6 {
    unsigned short sin6_family;
    unsigned short sin6_port;
    unsigned int sin6_flowinfo;
    unsigned char sin6_addr[16];
    unsigned int sin6_scope_id;
};

// ==================== 全局变量 ====================

static uint64_t show_map_vma_addr = 0;
static uint64_t show_smap_addr = 0;
static uint64_t tcp_v4_connect_addr = 0;
static uint64_t tcp_v6_connect_addr = 0;
static uint64_t do_faccessat_addr = 0;
static uint64_t sys_faccessat2_addr = 0;
static uint64_t vfs_fstatat_addr = 0;
static uint64_t vfs_statx_addr = 0;
static uint64_t do_statx_addr = 0;
static uint64_t do_filp_open_addr = 0;
static uint64_t proc_pid_status_addr = 0;
static uint64_t comm_write_addr = 0;

// filename 结构体（简化版，用于 do_filp_open）
struct filename {
    const char *name;
    // 其他字段省略
};

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
        // Frida 线程
        "gmain", "gdbus", "gum-js-loop", "pool-frida",
        "linjector", "frida", "agent-main", "v8:",
        "frida-server", "frida-helper",
        // Xposed/LSPosed 线程
        "xposed", "lspd", "edxp",
    };

    int num = sizeof(keywords) / sizeof(keywords[0]);
    for (int i = 0; i < num; i++) {
        if (my_strstr(name, keywords[i])) return 1;
    }
    return 0;
}

// 检查是否是 frida/xposed/root 相关的映射
static int is_frida_mapping(const char *buf, size_t len)
{
    if (!buf || len == 0) return 0;

    static const char *keywords[] = {
        // ===== Frida 特征 =====
        "frida", "Frida", "FRIDA",
        "frida-agent", "frida_agent", "frida-gadget",
        "frida-agent-32.so", "frida-agent-64.so",
        "frida-agent.so", "frida-agent-raw.so",
        "gadget", "Gadget", "gum-js", "libgum",
        "linjector", "re.frida.server", "re.frida",
        "/data/local/tmp/",

        // ===== Xposed 特征 =====
        "xposed", "Xposed", "XposedBridge",
        "libxposed_art.so",
        "app_process32_xposed", "app_process64_xposed",
        "app_process32_zposed", "app_process64_zposed",
        "de/robv/android/xposed",

        // ===== Riru 特征 =====
        "libriruloader.so", "libriru_", "libriru_edxp.so",

        // ===== LSPosed/EdXposed 特征 =====
        "liblspd.so", "lspd", "edxposed", "EdXposed",
        "/data/misc/edxp_",

        // ===== Magisk 特征 =====
        "MAGISK_INJ_", "/.magisk/", "magisk",

        // ===== Substrate 特征 =====
        "com.saurik.substrate", "slSubstrate",

        // ===== 脱壳工具特征 =====
        "libFupk3.so", "/data/fart", "cn/mik/Fartext",
        "myfartInvoke", "blackdex", "FunDex",

        // ===== 其他 Hook 框架 =====
        "libsotweak.so", "whale", "SandHook", "epic",
    };

    int num = sizeof(keywords) / sizeof(keywords[0]);
    for (int i = 0; i < num; i++) {
        if (my_memmem(buf, len, keywords[i], my_strlen(keywords[i]))) {
            return 1;
        }
    }

    // 检查 memfd: 特殊情况
    char *pos = (char *)my_memmem(buf, len, "memfd:", 6);
    if (pos) {
        size_t remaining = len - (pos - buf);
        if (remaining > 6) {
            // memfd:frida 或 memfd:jit-cache 等
            if (my_memmem(pos + 6, remaining - 6, "frida", 5) ||
                my_memmem(pos + 6, remaining - 6, "jit", 3) ||
                my_memmem(pos + 6, remaining - 6, "agent", 5) ||
                my_memmem(pos + 6, remaining - 6, "gum", 3)) {
                return 1;
            }
        }
    }
    return 0;
}

// 检查并修复 RWX 权限 - 将 rwxp 改为 r-xp
static void fix_rwx_permission(char *line, size_t len)
{
    if (!line || len < 20) return;

    // maps 格式: addr-addr rwxp offset ...
    // 权限字段通常在第一个空格后
    char *perm = 0;
    for (size_t i = 0; i < len - 4; i++) {
        if (line[i] == ' ') {
            perm = &line[i + 1];
            break;
        }
    }

    if (!perm) return;

    // 检查是否是 rwxp 或 rwxs
    if (perm[0] == 'r' && perm[1] == 'w' && perm[2] == 'x') {
        // 检查是否是 libc.so 或 libdl.so 相关
        if (my_memmem(line, len, "libc.so", 7) ||
            my_memmem(line, len, "libdl.so", 8) ||
            my_memmem(line, len, "linker", 6)) {
            // 将 rwx 改为 r-x
            perm[1] = '-';  // rwx -> r-x
            LOGV("fixed rwx permission in maps\n");
        }
    }
}

// 检查是否是可疑的匿名映射（可能是 Frida 注入的代码）
static int is_suspicious_anon_mapping(const char *line, size_t len)
{
    if (!line || len < 10) return 0;

    // 检查是否有 rwx 权限
    const char *perm = 0;
    for (size_t i = 0; i < len - 4; i++) {
        if (line[i] == ' ') {
            perm = &line[i + 1];
            break;
        }
    }

    if (!perm) return 0;

    // rwxp 匿名映射可能是 Frida JIT 代码
    if (perm[0] == 'r' && perm[1] == 'w' && perm[2] == 'x' && perm[3] == 'p') {
        // 检查是否是匿名映射（行尾没有文件路径或只有 [anon:...]）
        if (my_memmem(line, len, "[anon:", 6)) {
            // 检查是否是可疑的匿名映射名称
            if (my_memmem(line, len, "jit", 3) ||
                my_memmem(line, len, "frida", 5) ||
                my_memmem(line, len, "gum", 3)) {
                return 1;
            }
        }
    }
    return 0;
}

static int is_frida_port(uint16_t port)
{
    return (port >= FRIDA_PORT_START && port <= FRIDA_PORT_END);
}

// 字符串比较函数
static int my_strcmp(const char *s1, const char *s2)
{
    while (*s1 && *s2 && *s1 == *s2) {
        s1++;
        s2++;
    }
    return (unsigned char)*s1 - (unsigned char)*s2;
}

// 检查字符串是否以指定前缀开头
static int my_startswith(const char *str, const char *prefix)
{
    if (!str || !prefix) return 0;
    while (*prefix) {
        if (*str != *prefix) return 0;
        str++;
        prefix++;
    }
    return 1;
}

// 检查是否是敏感路径（Root/Magisk/Xposed 等）
// 使用精确匹配或前缀匹配，避免误拦截
static int is_sensitive_path(const char *path)
{
    if (!path) return 0;

    // ===== 精确匹配的路径 =====
    static const char *exact_paths[] = {
        // Su 二进制
        "/system/bin/su",
        "/system/xbin/su",
        "/system/sbin/su",
        "/sbin/su",
        "/vendor/bin/su",
        "/vendor/xbin/su",
        "/odm/bin/su",
        "/product/bin/su",
        "/system_ext/bin/su",
        "/su/bin/su",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/data/local/tmp/su",
        "/cache/su",
        "/data/su",
        "/dev/su",
        "/apex/com.android.runtime/bin/su",
        "/apex/com.android.art/bin/su",
        // Magisk
        "/system/bin/magisk",
        "/sbin/magisk",
        // BusyBox
        "/system/bin/busybox",
        "/system/xbin/busybox",
    };

    int num_exact = sizeof(exact_paths) / sizeof(exact_paths[0]);
    for (int i = 0; i < num_exact; i++) {
        if (my_strcmp(path, exact_paths[i]) == 0) {
            return 1;
        }
    }

    // ===== 前缀匹配的路径（目录）=====
    static const char *prefix_paths[] = {
        // Magisk
        "/sbin/.magisk",
        "/.magisk",
        "/data/adb/magisk",
        "/data/adb/modules",
        // KernelSU
        "/data/adb/ksu",
        "/data/adb/ksud",
        // APatch
        "/data/adb/ap",
        "/data/adb/apd",
        // Xposed/EdXposed
        "/data/misc/edxp_",
        // Frida
        "/data/local/tmp/re.frida.server",
        "/data/local/tmp/frida-server",
        "/data/local/tmp/frida",
        // 脱壳工具
        "/data/fart",
        "/data/local/tmp/fart",
    };

    int num_prefix = sizeof(prefix_paths) / sizeof(prefix_paths[0]);
    for (int i = 0; i < num_prefix; i++) {
        if (my_startswith(path, prefix_paths[i])) {
            return 1;
        }
    }

    // ===== 特殊处理 /data/adb 目录 =====
    // 精确匹配 /data/adb 或 /data/adb/
    if (my_strcmp(path, "/data/adb") == 0 ||
        my_strcmp(path, "/data/adb/") == 0) {
        return 1;
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

    // 1. 检查是否包含 frida 特征，如果是则隐藏整行
    if (is_frida_mapping(new_data, new_len)) {
        m->count = old_count;
        LOGV("hidden frida mapping\n");
        return;
    }

    // 2. 检查是否是可疑的匿名映射
    if (is_suspicious_anon_mapping(new_data, new_len)) {
        m->count = old_count;
        LOGV("hidden suspicious anon mapping\n");
        return;
    }

    // 3. 修复 RWX 权限（针对 libc 等系统库）
    fix_rwx_permission(new_data, new_len);
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

    LOGV("blocked tcp4 connect to port %d\n", port);
    args->ret = (uint64_t)(-(long)ECONNREFUSED);
    args->skip_origin = 1;
}

// tcp_v6_connect hook - 阻断 IPv6 Frida 端口连接
static void before_tcp_v6_connect(hook_fargs3_t *args, void *udata)
{
    struct sockaddr_in6 *addr = (struct sockaddr_in6 *)args->arg1;

    if (!addr) return;
    if (addr->sin6_family != AF_INET6) return;

    uint16_t port = bswap16(addr->sin6_port);

    if (!is_frida_port(port)) return;
    if (!is_app_process()) return;

    LOGV("blocked tcp6 connect to port %d\n", port);
    args->ret = (uint64_t)(-(long)ECONNREFUSED);
    args->skip_origin = 1;
}

// do_faccessat hook - 隐藏敏感文件 (access 系统调用)
static void before_do_faccessat(hook_fargs4_t *args, void *udata)
{
    // do_faccessat(int dfd, const char __user *filename, int mode, int flags)
    const char __user *filename = (const char __user *)args->arg1;

    if (!filename) return;
    if (!is_app_process()) return;

    char buf[MAX_PATH_LEN];
    long len = compat_strncpy_from_user(buf, filename, sizeof(buf) - 1);

    if (len <= 0 || len >= (long)(sizeof(buf) - 1)) return;
    buf[len] = '\0';

    if (is_sensitive_path(buf)) {
        LOGV("blocked faccessat: %s\n", buf);
        args->ret = (uint64_t)(-(long)ENOENT);
        args->skip_origin = 1;
    }
}

// vfs_fstatat hook - 隐藏敏感文件 (stat/fstatat 系统调用)
// int vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat, int flags)
static void before_vfs_fstatat(hook_fargs4_t *args, void *udata)
{
    const char __user *filename = (const char __user *)args->arg1;

    if (!filename) return;
    if (!is_app_process()) return;

    char buf[MAX_PATH_LEN];
    long len = compat_strncpy_from_user(buf, filename, sizeof(buf) - 1);

    if (len <= 0 || len >= (long)(sizeof(buf) - 1)) return;
    buf[len] = '\0';

    if (is_sensitive_path(buf)) {
        LOGV("blocked fstatat: %s\n", buf);
        args->ret = (uint64_t)(-(long)ENOENT);
        args->skip_origin = 1;
    }
}

// vfs_statx hook - 隐藏敏感文件 (statx 系统调用)
// int vfs_statx(int dfd, const char __user *filename, int flags, unsigned int mask, struct statx __user *buffer)
static void before_vfs_statx(hook_fargs5_t *args, void *udata)
{
    const char __user *filename = (const char __user *)args->arg1;

    if (!filename) return;
    if (!is_app_process()) return;

    char buf[MAX_PATH_LEN];
    long len = compat_strncpy_from_user(buf, filename, sizeof(buf) - 1);

    if (len <= 0 || len >= (long)(sizeof(buf) - 1)) return;
    buf[len] = '\0';

    if (is_sensitive_path(buf)) {
        LOGV("blocked vfs_statx: %s\n", buf);
        args->ret = (uint64_t)(-(long)ENOENT);
        args->skip_origin = 1;
    }
}

// do_statx hook - 隐藏敏感文件 (statx 系统调用入口)
// int do_statx(int dfd, const char __user *filename, unsigned flags, unsigned int mask, struct statx __user *buffer)
static void before_do_statx(hook_fargs5_t *args, void *udata)
{
    const char __user *filename = (const char __user *)args->arg1;

    if (!filename) return;
    if (!is_app_process()) return;

    char buf[MAX_PATH_LEN];
    long len = compat_strncpy_from_user(buf, filename, sizeof(buf) - 1);

    if (len <= 0 || len >= (long)(sizeof(buf) - 1)) return;
    buf[len] = '\0';

    if (is_sensitive_path(buf)) {
        LOGV("blocked do_statx: %s\n", buf);
        args->ret = (uint64_t)(-(long)ENOENT);
        args->skip_origin = 1;
    }
}

// do_filp_open hook - 阻止打开敏感文件 (open/openat 系统调用)
// struct file *do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op)
static void before_do_filp_open(hook_fargs3_t *args, void *udata)
{
    struct filename *pathname = (struct filename *)args->arg1;

    if (!pathname) return;
    if (!pathname->name) return;
    if (!is_app_process()) return;

    const char *path = pathname->name;

    if (is_sensitive_path(path)) {
        LOGV("blocked filp_open: %s\n", path);
        // 返回 ERR_PTR(-ENOENT)
        args->ret = (uint64_t)(-(long)ENOENT);
        args->skip_origin = 1;
    }
}

// proc_pid_status hook - 隐藏 TracerPid
static void before_proc_pid_status(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    args->local.data0 = 0;

    if (m && m->buf) {
        args->local.data0 = (uint64_t)m->count;
    }
}

static void after_proc_pid_status(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;

    if (!m || !m->buf) return;

    size_t old_count = (size_t)args->local.data0;
    if (m->count <= old_count) return;

    char *buf = m->buf;
    size_t count = m->count;

    // 查找 "TracerPid:\t" 并将其值改为 0
    char *pos = (char *)my_memmem(buf, count, "TracerPid:\t", 11);
    if (pos && (size_t)(pos - buf) + 11 < count) {
        char *val_start = pos + 11;
        // 找到数字结束位置
        char *val_end = val_start;
        while (val_end < buf + count && *val_end >= '0' && *val_end <= '9') {
            val_end++;
        }
        // 如果 TracerPid 不为 0，则改为 0
        if (val_end > val_start && !(val_end - val_start == 1 && *val_start == '0')) {
            *val_start = '0';
            // 移动后面的内容
            size_t remaining = (buf + count) - val_end;
            if (remaining > 0) {
                char *dst = val_start + 1;
                char *src = val_end;
                while (remaining--) {
                    *dst++ = *src++;
                }
            }
            m->count -= (val_end - val_start - 1);
            LOGV("hidden TracerPid\n");
        }
    }
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

    // 临时添加 null 终止符以便字符串操作
    char saved = 0;
    if (new_len > 0 && new_len < 256) {
        saved = new_data[new_len];
        new_data[new_len] = '\0';
    }

    if (is_frida_thread_name(new_data)) {
        const char *fake = "kworker\n";
        size_t fake_len = 8;
        for (int j = 0; j < (int)fake_len; j++) {
            new_data[j] = fake[j];
        }
        m->count = old_count + fake_len;
        LOGV("hidden frida thread name\n");
    } else if (saved) {
        new_data[new_len] = saved;
    }
}

// __get_task_comm hook
static void after_get_task_comm(hook_fargs3_t *args, void *udata)
{
    char *buf = (char *)args->arg0;

    if (!buf) return;

    if (is_frida_thread_name(buf)) {
        buf[0] = 'k'; buf[1] = 'w'; buf[2] = 'o'; buf[3] = 'r';
        buf[4] = 'k'; buf[5] = 'e'; buf[6] = 'r'; buf[7] = '\0';
        LOGV("hidden frida thread comm\n");
    }
}

// ==================== 模块入口 ====================

static long frida_hide_init(const char *args, const char *event, void *__user reserved)
{
    LOGV("loading ultimate version: %s\n", MYKPM_VERSION);

    int hooks_installed = 0;

    // 1. Hook show_map_vma - 隐藏 maps 中的敏感映射
    show_map_vma_addr = kallsyms_lookup_name("show_map_vma");
    if (show_map_vma_addr) {
        hook_err_t err = hook_wrap2((void *)show_map_vma_addr,
                                    before_show_map_vma,
                                    after_show_map_vma,
                                    (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("[+] show_map_vma hooked at 0x%llx\n", show_map_vma_addr);
            hooks_installed++;
        } else {
            LOGV("[-] hook show_map_vma failed: %d\n", err);
            show_map_vma_addr = 0;
        }
    }

    // 2. Hook show_smap - 同样处理 smaps
    show_smap_addr = kallsyms_lookup_name("show_smap");
    if (show_smap_addr) {
        hook_err_t err = hook_wrap2((void *)show_smap_addr,
                                    before_show_map_vma,
                                    after_show_map_vma,
                                    (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("[+] show_smap hooked at 0x%llx\n", show_smap_addr);
            hooks_installed++;
        } else {
            show_smap_addr = 0;
        }
    }

    // 3. Hook tcp_v4_connect - 阻断 Frida IPv4 端口
    tcp_v4_connect_addr = kallsyms_lookup_name("tcp_v4_connect");
    if (tcp_v4_connect_addr) {
        hook_err_t err = hook_wrap3((void *)tcp_v4_connect_addr,
                                    before_tcp_v4_connect,
                                    (void *)0,
                                    (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("[+] tcp_v4_connect hooked at 0x%llx\n", tcp_v4_connect_addr);
            hooks_installed++;
        } else {
            tcp_v4_connect_addr = 0;
        }
    }

    // 4. Hook tcp_v6_connect - 阻断 Frida IPv6 端口
    tcp_v6_connect_addr = kallsyms_lookup_name("tcp_v6_connect");
    if (tcp_v6_connect_addr) {
        hook_err_t err = hook_wrap3((void *)tcp_v6_connect_addr,
                                    before_tcp_v6_connect,
                                    (void *)0,
                                    (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("[+] tcp_v6_connect hooked at 0x%llx\n", tcp_v6_connect_addr);
            hooks_installed++;
        } else {
            tcp_v6_connect_addr = 0;
        }
    }

    // 5. Hook do_faccessat - 隐藏敏感文件 (access/faccessat 系统调用)
    do_faccessat_addr = kallsyms_lookup_name("do_faccessat");
    if (do_faccessat_addr) {
        hook_err_t err = hook_wrap4((void *)do_faccessat_addr,
                                    before_do_faccessat,
                                    (void *)0,
                                    (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("[+] do_faccessat hooked at 0x%llx\n", do_faccessat_addr);
            hooks_installed++;
        } else {
            do_faccessat_addr = 0;
        }
    }

    // 5.1 Hook __arm64_sys_faccessat2 - faccessat2 系统调用入口
    sys_faccessat2_addr = kallsyms_lookup_name("__arm64_sys_faccessat2");
    if (!sys_faccessat2_addr) {
        sys_faccessat2_addr = kallsyms_lookup_name("__se_sys_faccessat2");
    }
    if (!sys_faccessat2_addr) {
        sys_faccessat2_addr = kallsyms_lookup_name("do_faccessat2");
    }
    if (sys_faccessat2_addr) {
        hook_err_t err = hook_wrap4((void *)sys_faccessat2_addr,
                                    before_do_faccessat,
                                    (void *)0,
                                    (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("[+] sys_faccessat2 hooked at 0x%llx\n", sys_faccessat2_addr);
            hooks_installed++;
        } else {
            sys_faccessat2_addr = 0;
        }
    }

    // 6. Hook vfs_fstatat - 隐藏敏感文件 (stat/lstat/fstatat 系统调用)
    vfs_fstatat_addr = kallsyms_lookup_name("vfs_fstatat");
    if (vfs_fstatat_addr) {
        hook_err_t err = hook_wrap4((void *)vfs_fstatat_addr,
                                    before_vfs_fstatat,
                                    (void *)0,
                                    (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("[+] vfs_fstatat hooked at 0x%llx\n", vfs_fstatat_addr);
            hooks_installed++;
        } else {
            vfs_fstatat_addr = 0;
        }
    }

    // 7. Hook vfs_statx - 隐藏敏感文件 (statx 系统调用)
    vfs_statx_addr = kallsyms_lookup_name("vfs_statx");
    if (vfs_statx_addr) {
        hook_err_t err = hook_wrap5((void *)vfs_statx_addr,
                                    before_vfs_statx,
                                    (void *)0,
                                    (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("[+] vfs_statx hooked at 0x%llx\n", vfs_statx_addr);
            hooks_installed++;
        } else {
            vfs_statx_addr = 0;
        }
    }

    // 8. Hook do_statx - 隐藏敏感文件 (statx 系统调用入口)
    do_statx_addr = kallsyms_lookup_name("do_statx");
    if (do_statx_addr) {
        hook_err_t err = hook_wrap5((void *)do_statx_addr,
                                    before_do_statx,
                                    (void *)0,
                                    (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("[+] do_statx hooked at 0x%llx\n", do_statx_addr);
            hooks_installed++;
        } else {
            do_statx_addr = 0;
        }
    }

    // 9. Hook do_filp_open - 阻止打开敏感文件 (open/openat 系统调用)
    do_filp_open_addr = kallsyms_lookup_name("do_filp_open");
    if (do_filp_open_addr) {
        hook_err_t err = hook_wrap3((void *)do_filp_open_addr,
                                    before_do_filp_open,
                                    (void *)0,
                                    (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("[+] do_filp_open hooked at 0x%llx\n", do_filp_open_addr);
            hooks_installed++;
        } else {
            do_filp_open_addr = 0;
        }
    }

    // 10. Hook proc_pid_status - 隐藏 TracerPid
    proc_pid_status_addr = kallsyms_lookup_name("proc_pid_status");
    if (proc_pid_status_addr) {
        hook_err_t err = hook_wrap2((void *)proc_pid_status_addr,
                                    before_proc_pid_status,
                                    after_proc_pid_status,
                                    (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("[+] proc_pid_status hooked at 0x%llx\n", proc_pid_status_addr);
            hooks_installed++;
        } else {
            proc_pid_status_addr = 0;
        }
    }

    // 11. Hook comm_show 或 __get_task_comm - 隐藏线程名
    uint64_t comm_show_addr_local = kallsyms_lookup_name("comm_show");
    if (comm_show_addr_local) {
        hook_err_t err = hook_wrap2((void *)comm_show_addr_local,
                                    before_comm_show,
                                    after_comm_show,
                                    (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("[+] comm_show hooked at 0x%llx\n", comm_show_addr_local);
            comm_write_addr = comm_show_addr_local;
            hooks_installed++;
        }
    } else {
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
                LOGV("[+] get_task_comm hooked at 0x%llx\n", get_task_comm_addr);
                comm_write_addr = get_task_comm_addr;
                hooks_installed++;
            }
        }
    }

    LOGV("=== loaded successfully, %d hooks installed ===\n", hooks_installed);
    return 0;
}

static long frida_hide_control0(const char *args, char *__user out_msg, int outlen)
{
    char msg[] = "frida_hide: ultimate edition OK";
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

    if (comm_write_addr) {
        unhook((void *)comm_write_addr);
        comm_write_addr = 0;
    }
    if (proc_pid_status_addr) {
        unhook((void *)proc_pid_status_addr);
        proc_pid_status_addr = 0;
    }
    if (do_filp_open_addr) {
        unhook((void *)do_filp_open_addr);
        do_filp_open_addr = 0;
    }
    if (do_statx_addr) {
        unhook((void *)do_statx_addr);
        do_statx_addr = 0;
    }
    if (vfs_statx_addr) {
        unhook((void *)vfs_statx_addr);
        vfs_statx_addr = 0;
    }
    if (vfs_fstatat_addr) {
        unhook((void *)vfs_fstatat_addr);
        vfs_fstatat_addr = 0;
    }
    if (sys_faccessat2_addr) {
        unhook((void *)sys_faccessat2_addr);
        sys_faccessat2_addr = 0;
    }
    if (do_faccessat_addr) {
        unhook((void *)do_faccessat_addr);
        do_faccessat_addr = 0;
    }
    if (tcp_v6_connect_addr) {
        unhook((void *)tcp_v6_connect_addr);
        tcp_v6_connect_addr = 0;
    }
    if (tcp_v4_connect_addr) {
        unhook((void *)tcp_v4_connect_addr);
        tcp_v4_connect_addr = 0;
    }
    if (show_smap_addr) {
        unhook((void *)show_smap_addr);
        show_smap_addr = 0;
    }
    if (show_map_vma_addr) {
        unhook((void *)show_map_vma_addr);
        show_map_vma_addr = 0;
    }

    LOGV("unloaded\n");
    return 0;
}

KPM_INIT(frida_hide_init);
KPM_CTL0(frida_hide_control0);
KPM_EXIT(frida_hide_exit);
