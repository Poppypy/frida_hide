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
KPM_DESCRIPTION("Advanced Frida/Root/Xposed Detection Bypass - Fixed Version");

// ==================== 常量定义 ====================
#define FRIDA_PORT_START 27042
#define FRIDA_PORT_END 27052
#define LOGV(fmt, ...) pr_info("frida_hide: " fmt, ##__VA_ARGS__)

#define AF_INET 2
#define AF_INET6 10
#define ECONNREFUSED 111
#define ENOENT 2
#define UID_APP_START 10000
#define MAX_THREAD_NAME 16
#define MAX_PATH_LEN 256
#define MAX_LINE_LEN 512

// ==================== 类型定义 ====================
// 注意：uid_t, gid_t, kuid_t 等类型已在 ktypes.h 中定义，无需重复定义

// ==================== 结构体定义 ====================
// 注意：这里不直接定义 seq_file，而是使用偏移量访问
// 不同内核版本的 seq_file 结构可能不同

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

// ==================== 内核函数指针 ====================
static kuid_t (*kfunc_current_uid)(void) = NULL;
static uid_t (*kfunc___kuid_val)(kuid_t uid) = NULL;
static char* (*kfunc_seq_buf_ptr)(void *m) = NULL;
static size_t (*kfunc_seq_buf_used)(void *m) = NULL;

// ==================== 全局变量 ====================
static uint64_t show_map_vma_addr = 0;
static uint64_t show_smap_addr = 0;
static uint64_t tcp_v4_connect_addr = 0;
static uint64_t tcp_v6_connect_addr = 0;
static uint64_t comm_show_addr = 0;
static uint64_t get_task_comm_addr = 0;
static uint64_t do_faccessat_addr = 0;

// seq_file 结构体偏移量（需要根据内核版本调整）
static int seq_file_buf_offset = 0;      // buf 字段偏移
static int seq_file_count_offset = 24;   // count 字段偏移
static int seq_file_size_offset = 8;     // size 字段偏移

static unsigned long hidden_maps_count = 0;
static unsigned long blocked_connections = 0;
static unsigned long hidden_threads = 0;
static unsigned long blocked_access = 0;

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
    if (!haystack || !needle) return NULL;
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
    return NULL;
}

static void *my_memmem(const void *haystack, size_t haystacklen, 
                       const void *needle, size_t needlelen)
{
    if (!haystack || !needle || haystacklen < needlelen || needlelen == 0)
        return NULL;
    
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
    return NULL;
}

static void *my_memcpy(void *dest, const void *src, size_t n)
{
    char *d = (char *)dest;
    const char *s = (const char *)src;
    while (n--) {
        *d++ = *s++;
    }
    return dest;
}

static void *my_memset(void *s, int c, size_t n)
{
    unsigned char *p = (unsigned char *)s;
    while (n--) {
        *p++ = (unsigned char)c;
    }
    return s;
}

static inline uint16_t bswap16(uint16_t val) 
{
    return (val >> 8) | (val << 8);
}

// 安全的 seq_file 访问函数
static inline char *seq_file_get_buf(void *m)
{
    if (!m) return NULL;
    return *(char **)((char *)m + seq_file_buf_offset);
}

static inline size_t seq_file_get_count(void *m)
{
    if (!m) return 0;
    return *(size_t *)((char *)m + seq_file_count_offset);
}

static inline void seq_file_set_count(void *m, size_t count)
{
    if (!m) return;
    *(size_t *)((char *)m + seq_file_count_offset) = count;
}

static inline size_t seq_file_get_size(void *m)
{
    if (!m) return 0;
    return *(size_t *)((char *)m + seq_file_size_offset);
}

// 获取当前进程 UID
static uid_t get_current_uid(void)
{
    if (kfunc_current_uid && kfunc___kuid_val) {
        kuid_t kuid = kfunc_current_uid();
        return kfunc___kuid_val(kuid);
    }
    
    // 备用方案：直接从 current->cred 读取
    // 这里简化处理，返回 0 表示 root
    return 0;
}

static int is_app_process(void)
{
    uid_t uid = get_current_uid();
    return (uid >= UID_APP_START);
}

// ==================== 检测特征库 ====================

// Frida 线程名特征
static const char *frida_thread_keywords[] = {
    "gmain", "gdbus", "gum-js-loop", "pool-frida",
    "linjector", "frida", "agent-main", "v8:",
    "glib-", "gio-", "gadget", "Gadget",
    "frida-server", "re.frida", "JSC", "jsc-",
    NULL
};

// Frida 映射特征
static const char *frida_map_keywords[] = {
    "frida", "Frida", "FRIDA",
    "frida-agent", "frida_agent", "frida-gadget",
    "frida-agent-32.so", "frida-agent-64.so",
    "frida-agent.so", "frida-agent-raw.so",
    "re.frida.server", "frida-server",
    "gadget", "Gadget", "gum-js", "gum-", "libgum",
    "linjector", "/data/local/tmp/re.frida",
    "/data/local/tmp/frida", "agent-",
    NULL
};

// memfd 可疑名称
static const char *memfd_keywords[] = {
    "frida", "jit", "agent", "gum", "gadget",
    "linjector", "v8", "JSC", "QuickJS",
    NULL
};

// Root/Magisk/KernelSU/APatch 路径
static const char *root_paths[] = {
    "/system/bin/su", "/system/xbin/su",
    "/sbin/su", "/su/bin/su",
    "/vendor/bin/su", "/system/sbin/su",
    "/data/local/tmp/su", "/data/local/su",
    "/magisk", "/.magisk",
    "/sbin/.magisk", "/data/adb/magisk",
    "/system/bin/magisk", "/data/adb/ksu",
    "/data/adb/ap", "/data/adb/modules",
    NULL
};

// Xposed/LSPosed/EdXposed 特征
static const char *xposed_keywords[] = {
    "xposed", "Xposed", "XposedBridge",
    "de/robv/android/xposed", "de.robv.android.xposed",
    "edxposed", "EdXposed", "lsposed", "LSPosed",
    "liblspd.so", "riru", "Riru", "libriruloader.so",
    "libriru_", "app_process32_xposed", "app_process64_xposed",
    "libxposed_art.so", "/data/misc/edxp_",
    NULL
};

// 系统库白名单（不应修改其权限）
static const char *system_libs[] = {
    "/system/lib", "/system/lib64",
    "/vendor/lib", "/vendor/lib64",
    "/apex/", "linker", "libc.so",
    "libdl.so", "libm.so", "liblog.so",
    NULL
};

// ==================== 检测函数 ====================

static int match_keywords(const char *str, const char **keywords)
{
    if (!str) return 0;
    for (int i = 0; keywords[i] != NULL; i++) {
        if (my_strstr(str, keywords[i])) return 1;
    }
    return 0;
}

static int match_keywords_mem(const char *buf, size_t len, const char **keywords)
{
    if (!buf || len == 0) return 0;
    for (int i = 0; keywords[i] != NULL; i++) {
        size_t klen = my_strlen(keywords[i]);
        if (klen > 0 && my_memmem(buf, len, keywords[i], klen)) {
            return 1;
        }
    }
    return 0;
}

static int is_frida_thread_name(const char *name)
{
    if (!name) return 0;
    return match_keywords(name, frida_thread_keywords);
}

static int is_frida_mapping(const char *buf, size_t len)
{
    if (!buf || len == 0) return 0;
    
    // 检查主要关键字
    if (match_keywords_mem(buf, len, frida_map_keywords)) return 1;
    
    // 检查 memfd: 特征
    char *pos = (char *)my_memmem(buf, len, "memfd:", 6);
    if (pos) {
        size_t offset = pos - buf;
        if (offset + 6 < len) {
            size_t remaining = len - offset - 6;
            if (match_keywords_mem(pos + 6, remaining, memfd_keywords)) {
                return 1;
            }
        }
    }
    
    // 检查 [anon:...] 特征
    pos = (char *)my_memmem(buf, len, "[anon:", 6);
    if (pos) {
        size_t offset = pos - buf;
        if (offset + 6 < len) {
            size_t remaining = len - offset - 6;
            if (match_keywords_mem(pos + 6, remaining, memfd_keywords)) {
                return 1;
            }
        }
    }
    
    return 0;
}

static int is_system_library(const char *line, size_t len)
{
    if (!line || len == 0) return 0;
    return match_keywords_mem(line, len, system_libs);
}

static int is_suspicious_rwx_mapping(const char *line, size_t len)
{
    if (!line || len < 20) return 0;
    
    // 查找权限字段（格式：地址 权限 偏移 设备 inode 路径）
    const char *perm = NULL;
    size_t space_count = 0;
    
    for (size_t i = 0; i < len && i < 50; i++) {
        if (line[i] == ' ') {
            if (space_count == 0 && i + 4 < len) {
                perm = &line[i + 1];
                break;
            }
            space_count++;
        }
    }
    
    if (!perm || (size_t)(perm - line) + 4 > len) return 0;
    
    // 检查 rwxp 权限（可读、可写、可执行、私有）
    if (perm[0] == 'r' && perm[1] == 'w' && perm[2] == 'x' && perm[3] == 'p') {
        // 排除系统库
        if (is_system_library(line, len)) return 0;
        
        // 匿名 rwx 映射可能是 Frida JIT
        if (my_memmem(line, len, "[anon:", 6) ||
            my_memmem(line, len, "memfd:", 6)) {
            if (match_keywords_mem(line, len, memfd_keywords)) {
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

static int is_sensitive_path(const char *path)
{
    if (!path) return 0;
    return match_keywords(path, root_paths);
}

// ==================== Hook 函数 ====================

// show_map_vma / show_smap hook
static void before_show_map_vma(hook_fargs2_t *args, void *udata)
{
    void *m = (void *)args->arg0;
    args->local.data0 = 0;
    args->local.data1 = 0;
    
    if (!m) return;
    
    char *buf = seq_file_get_buf(m);
    size_t count = seq_file_get_count(m);
    
    if (buf && count < 0x100000) {  // 合理性检查
        args->local.data0 = (uint64_t)count;
        args->local.data1 = 1;  // 标记有效
    }
}

static void after_show_map_vma(hook_fargs2_t *args, void *udata)
{
    if (!args->local.data1) return;  // 无效则跳过
    
    void *m = (void *)args->arg0;
    if (!m) return;
    
    char *buf = seq_file_get_buf(m);
    size_t size = seq_file_get_size(m);
    size_t count = seq_file_get_count(m);
    size_t old_count = (size_t)args->local.data0;
    
    if (!buf || count <= old_count || count > size) return;
    
    char *new_data = buf + old_count;
    size_t new_len = count - old_count;
    
    // 边界检查
    if (old_count >= size || new_len > size - old_count) return;
    
    // 检查是否是 Frida 相关映射
    if (is_frida_mapping(new_data, new_len)) {
        seq_file_set_count(m, old_count);
        hidden_maps_count++;
        LOGV("hidden frida mapping\n");
        return;
    }
    
    // 检查可疑的 rwx 映射
    if (is_suspicious_rwx_mapping(new_data, new_len)) {
        seq_file_set_count(m, old_count);
        hidden_maps_count++;
        LOGV("hidden suspicious rwx mapping\n");
        return;
    }
}

// tcp_v4_connect hook
static void before_tcp_v4_connect(hook_fargs3_t *args, void *udata)
{
    struct sockaddr_in *addr = (struct sockaddr_in *)args->arg1;
    
    if (!addr) return;
    if (addr->sin_family != AF_INET) return;
    
    uint16_t port = bswap16(addr->sin_port);
    
    if (!is_frida_port(port)) return;
    if (!is_app_process()) return;
    
    blocked_connections++;
    LOGV("blocked tcp4 connection to port %d\n", port);
    
    args->ret = (uint64_t)(-(long)ECONNREFUSED);
    args->skip_origin = 1;
}

// tcp_v6_connect hook
static void before_tcp_v6_connect(hook_fargs3_t *args, void *udata)
{
    struct sockaddr_in6 *addr = (struct sockaddr_in6 *)args->arg1;
    
    if (!addr) return;
    if (addr->sin6_family != AF_INET6) return;
    
    uint16_t port = bswap16(addr->sin6_port);
    
    if (!is_frida_port(port)) return;
    if (!is_app_process()) return;
    
    blocked_connections++;
    LOGV("blocked tcp6 connection to port %d\n", port);
    
    args->ret = (uint64_t)(-(long)ECONNREFUSED);
    args->skip_origin = 1;
}

// comm_show hook
static void before_comm_show(hook_fargs2_t *args, void *udata)
{
    void *m = (void *)args->arg0;
    args->local.data0 = 0;
    args->local.data1 = 0;
    
    if (!m) return;
    
    char *buf = seq_file_get_buf(m);
    size_t count = seq_file_get_count(m);
    
    if (buf && count < 0x100000) {
        args->local.data0 = (uint64_t)count;
        args->local.data1 = 1;
    }
}

static void after_comm_show(hook_fargs2_t *args, void *udata)
{
    if (!args->local.data1) return;
    
    void *m = (void *)args->arg0;
    if (!m) return;
    
    char *buf = seq_file_get_buf(m);
    size_t size = seq_file_get_size(m);
    size_t count = seq_file_get_count(m);
    size_t old_count = (size_t)args->local.data0;
    
    if (!buf || count <= old_count || count > size) return;
    
    char *new_data = buf + old_count;
    size_t new_len = count - old_count;
    
    // 边界检查
    if (old_count >= size || new_len > size - old_count) return;
    if (new_len == 0 || new_len > MAX_THREAD_NAME + 2) return;
    
    // 创建临时缓冲区进行检查
    char temp[MAX_THREAD_NAME + 2];
    size_t copy_len = (new_len < sizeof(temp) - 1) ? new_len : sizeof(temp) - 1;
    my_memcpy(temp, new_data, copy_len);
    temp[copy_len] = '\0';
    
    // 移除末尾换行符进行检查
    if (copy_len > 0 && temp[copy_len - 1] == '\n') {
        temp[copy_len - 1] = '\0';
    }
    
    if (is_frida_thread_name(temp)) {
        // 替换为假名称
        const char *fake = "kworker/u:0\n";
        size_t fake_len = my_strlen(fake);
        
        if (fake_len <= size - old_count) {
            my_memcpy(new_data, fake, fake_len);
            seq_file_set_count(m, old_count + fake_len);
            hidden_threads++;
            LOGV("hidden thread name: %s\n", temp);
        }
    }
}

// get_task_comm hook
static void after_get_task_comm(hook_fargs3_t *args, void *udata)
{
    char *buf = (char *)args->arg0;
    size_t buf_size = (size_t)args->arg1;
    
    if (!buf || buf_size == 0) return;
    if (buf_size > MAX_THREAD_NAME) buf_size = MAX_THREAD_NAME;
    
    // 确保字符串以 null 结尾
    buf[buf_size - 1] = '\0';
    
    if (is_frida_thread_name(buf)) {
        const char *fake = "kworker/u:0";
        size_t fake_len = my_strlen(fake);
        
        if (fake_len < buf_size) {
            my_memcpy(buf, fake, fake_len);
            buf[fake_len] = '\0';
            hidden_threads++;
            LOGV("hidden task comm\n");
        }
    }
}

// do_faccessat hook - 隐藏敏感文件
static void before_do_faccessat(hook_fargs3_t *args, void *udata)
{
    // do_faccessat(int dfd, const char __user *filename, int mode)
    const char __user *filename = (const char __user *)args->arg1;
    
    if (!filename) return;
    if (!is_app_process()) return;
    
    char buf[MAX_PATH_LEN];
    long len = compat_strncpy_from_user(buf, filename, sizeof(buf) - 1);
    
    if (len <= 0 || len >= (long)(sizeof(buf) - 1)) return;
    buf[len] = '\0';
    
    // 检查是否是敏感路径
    if (is_sensitive_path(buf) || 
        match_keywords(buf, frida_map_keywords) ||
        match_keywords(buf, xposed_keywords)) {
        
        blocked_access++;
        LOGV("blocked access to: %s\n", buf);
        
        args->ret = (uint64_t)(-(long)ENOENT);
        args->skip_origin = 1;
    }
}

// ==================== 初始化辅助函数 ====================

static int init_kernel_funcs(void)
{
    // 获取 current_uid 函数
    kfunc_current_uid = (void *)kallsyms_lookup_name("current_uid");
    if (!kfunc_current_uid) {
        LOGV("[-] current_uid not found\n");
    }
    
    // 获取 __kuid_val 函数（可能是内联的，尝试多个名称）
    kfunc___kuid_val = (void *)kallsyms_lookup_name("__kuid_val");
    if (!kfunc___kuid_val) {
        kfunc___kuid_val = (void *)kallsyms_lookup_name("from_kuid");
    }
    
    // 如果找不到这些函数，使用备用方案
    if (!kfunc_current_uid || !kfunc___kuid_val) {
        LOGV("[!] UID functions not found, using fallback\n");
    }
    
    return 0;
}

static int detect_seq_file_offsets(void)
{
    // 尝试检测 seq_file 结构体偏移
    // 这里使用常见的偏移值，实际可能需要根据内核版本调整
    
    // Linux 4.x - 5.x 常见偏移
    seq_file_buf_offset = 0;      // char *buf
    seq_file_size_offset = 8;     // size_t size
    seq_file_count_offset = 24;   // size_t count (跳过 from)
    
    LOGV("seq_file offsets: buf=%d, size=%d, count=%d\n",
         seq_file_buf_offset, seq_file_size_offset, seq_file_count_offset);
    
    return 0;
}

// ==================== 模块入口 ====================

static long frida_hide_init(const char *args, const char *event, void *__user reserved)
{
    LOGV("loading version: %s\n", MYKPM_VERSION);
    
    int hooks_ok = 0;
    int hooks_failed = 0;
    
    // 初始化内核函数指针
    init_kernel_funcs();
    
    // 检测 seq_file 偏移
    detect_seq_file_offsets();
    
    // Hook show_map_vma
    show_map_vma_addr = kallsyms_lookup_name("show_map_vma");
    if (show_map_vma_addr) {
        if (hook_wrap2((void *)show_map_vma_addr, before_show_map_vma, 
                       after_show_map_vma, NULL) == HOOK_NO_ERR) {
            LOGV("[+] show_map_vma hooked at %llx\n", show_map_vma_addr);
            hooks_ok++;
        } else {
            LOGV("[-] show_map_vma hook failed\n");
            show_map_vma_addr = 0;
            hooks_failed++;
        }
    } else {
        LOGV("[-] show_map_vma not found\n");
    }
    
    // Hook show_smap
    show_smap_addr = kallsyms_lookup_name("show_smap");
    if (show_smap_addr) {
        if (hook_wrap2((void *)show_smap_addr, before_show_map_vma,
                       after_show_map_vma, NULL) == HOOK_NO_ERR) {
            LOGV("[+] show_smap hooked at %llx\n", show_smap_addr);
            hooks_ok++;
        } else {
            LOGV("[-] show_smap hook failed\n");
            show_smap_addr = 0;
            hooks_failed++;
        }
    } else {
        LOGV("[-] show_smap not found\n");
    }
    
    // Hook tcp_v4_connect
    tcp_v4_connect_addr = kallsyms_lookup_name("tcp_v4_connect");
    if (tcp_v4_connect_addr) {
        if (hook_wrap3((void *)tcp_v4_connect_addr, before_tcp_v4_connect,
                       NULL, NULL) == HOOK_NO_ERR) {
            LOGV("[+] tcp_v4_connect hooked at %llx\n", tcp_v4_connect_addr);
            hooks_ok++;
        } else {
            LOGV("[-] tcp_v4_connect hook failed\n");
            tcp_v4_connect_addr = 0;
            hooks_failed++;
        }
    } else {
        LOGV("[-] tcp_v4_connect not found\n");
    }
    
    // Hook tcp_v6_connect
    tcp_v6_connect_addr = kallsyms_lookup_name("tcp_v6_connect");
    if (tcp_v6_connect_addr) {
        if (hook_wrap3((void *)tcp_v6_connect_addr, before_tcp_v6_connect,
                       NULL, NULL) == HOOK_NO_ERR) {
            LOGV("[+] tcp_v6_connect hooked at %llx\n", tcp_v6_connect_addr);
            hooks_ok++;
        } else {
            LOGV("[-] tcp_v6_connect hook failed\n");
            tcp_v6_connect_addr = 0;
            hooks_failed++;
        }
    } else {
        LOGV("[-] tcp_v6_connect not found\n");
    }
    
    // Hook comm_show 或 get_task_comm
    comm_show_addr = kallsyms_lookup_name("comm_show");
    if (comm_show_addr) {
        if (hook_wrap2((void *)comm_show_addr, before_comm_show,
                       after_comm_show, NULL) == HOOK_NO_ERR) {
            LOGV("[+] comm_show hooked at %llx\n", comm_show_addr);
            hooks_ok++;
        } else {
            LOGV("[-] comm_show hook failed\n");
            comm_show_addr = 0;
            hooks_failed++;
        }
    }
    
    // 如果 comm_show 不可用，尝试 get_task_comm
    if (!comm_show_addr) {
        get_task_comm_addr = kallsyms_lookup_name("__get_task_comm");
        if (!get_task_comm_addr) {
            get_task_comm_addr = kallsyms_lookup_name("get_task_comm");
        }
        if (get_task_comm_addr) {
            if (hook_wrap3((void *)get_task_comm_addr, NULL,
                           after_get_task_comm, NULL) == HOOK_NO_ERR) {
                LOGV("[+] get_task_comm hooked at %llx\n", get_task_comm_addr);
                hooks_ok++;
            } else {
                LOGV("[-] get_task_comm hook failed\n");
                get_task_comm_addr = 0;
                hooks_failed++;
            }
        } else {
            LOGV("[-] get_task_comm not found\n");
        }
    }
    
    // Hook do_faccessat
    do_faccessat_addr = kallsyms_lookup_name("do_faccessat");
    if (do_faccessat_addr) {
        if (hook_wrap3((void *)do_faccessat_addr, before_do_faccessat,
                       NULL, NULL) == HOOK_NO_ERR) {
            LOGV("[+] do_faccessat hooked at %llx\n", do_faccessat_addr);
            hooks_ok++;
        } else {
            LOGV("[-] do_faccessat hook failed\n");
            do_faccessat_addr = 0;
            hooks_failed++;
        }
    } else {
        LOGV("[-] do_faccessat not found\n");
    }
    
    LOGV("initialization complete: %d hooks installed, %d failed\n", hooks_ok, hooks_failed);
    
    if (hooks_ok == 0) {
        LOGV("[!] WARNING: No hooks installed, module may not function\n");
        return -1;
    }
    
    return 0;
}

static long frida_hide_control0(const char *args, char *__user out_msg, int outlen)
{
    char msg[256];
    int len;
    
    // 手动格式化字符串（避免依赖 snprintf）
    char *p = msg;
    const char *prefix = "frida_hide stats: ";
    while (*prefix) *p++ = *prefix++;
    
    // maps count
    const char *maps_label = "maps=";
    while (*maps_label) *p++ = *maps_label++;
    
    // 简单的数字转字符串
    unsigned long val = hidden_maps_count;
    char num_buf[20];
    int num_len = 0;
    do {
        num_buf[num_len++] = '0' + (val % 10);
        val /= 10;
    } while (val > 0);
    while (num_len > 0) *p++ = num_buf[--num_len];
    
    *p++ = ' ';
    
    // conn count
    const char *conn_label = "conn=";
    while (*conn_label) *p++ = *conn_label++;
    val = blocked_connections;
    num_len = 0;
    do {
        num_buf[num_len++] = '0' + (val % 10);
        val /= 10;
    } while (val > 0);
    while (num_len > 0) *p++ = num_buf[--num_len];
    
    *p++ = ' ';
    
    // thread count
    const char *thread_label = "thread=";
    while (*thread_label) *p++ = *thread_label++;
    val = hidden_threads;
    num_len = 0;
    do {
        num_buf[num_len++] = '0' + (val % 10);
        val /= 10;
    } while (val > 0);
    while (num_len > 0) *p++ = num_buf[--num_len];
    
    *p++ = ' ';
    
    // access count
    const char *access_label = "access=";
    while (*access_label) *p++ = *access_label++;
    val = blocked_access;
    num_len = 0;
    do {
        num_buf[num_len++] = '0' + (val % 10);
        val /= 10;
    } while (val > 0);
    while (num_len > 0) *p++ = num_buf[--num_len];
    
    *p = '\0';
    len = p - msg;
    
    if (out_msg && outlen > 0) {
        if (len >= outlen) len = outlen - 1;
        compat_copy_to_user(out_msg, msg, len + 1);
    }
    
    LOGV("control0 called: %s\n", msg);
    return 0;
}

static long frida_hide_exit(void *__user reserved)
{
    LOGV("unloading module...\n");
    
    // 按照安装的相反顺序卸载 hooks
    if (do_faccessat_addr) {
        unhook((void *)do_faccessat_addr);
        LOGV("[+] do_faccessat unhooked\n");
    }
    
    if (get_task_comm_addr) {
        unhook((void *)get_task_comm_addr);
        LOGV("[+] get_task_comm unhooked\n");
    }
    
    if (comm_show_addr) {
        unhook((void *)comm_show_addr);
        LOGV("[+] comm_show unhooked\n");
    }
    
    if (tcp_v6_connect_addr) {
        unhook((void *)tcp_v6_connect_addr);
        LOGV("[+] tcp_v6_connect unhooked\n");
    }
    
    if (tcp_v4_connect_addr) {
        unhook((void *)tcp_v4_connect_addr);
        LOGV("[+] tcp_v4_connect unhooked\n");
    }
    
    if (show_smap_addr) {
        unhook((void *)show_smap_addr);
        LOGV("[+] show_smap unhooked\n");
    }
    
    if (show_map_vma_addr) {
        unhook((void *)show_map_vma_addr);
        LOGV("[+] show_map_vma unhooked\n");
    }
    
    LOGV("module unloaded, final stats: maps=%lu conn=%lu thread=%lu access=%lu\n",
         hidden_maps_count, blocked_connections, hidden_threads, blocked_access);
    
    return 0;
}

KPM_INIT(frida_hide_init);
KPM_CTL0(frida_hide_control0);
KPM_EXIT(frida_hide_exit);
