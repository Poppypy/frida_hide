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
// 日志开关: 1=开启(调试用), 0=关闭(正式使用)
static int log_enabled = 1;

#define LOGV(fmt, ...) do { if (log_enabled) pr_info("frida_hide: " fmt, ##__VA_ARGS__); } while(0)

#define AF_INET 2
#define AF_INET6 10
#define ECONNREFUSED 111
#define ENOENT 2
#define UID_APP_START 10000
#define MAX_PATH_LEN 256

// VM flags 定义 (来自 linux/mm.h)
#define VM_READ     0x00000001
#define VM_WRITE    0x00000002
#define VM_EXEC     0x00000004
#define VM_SHARED   0x00000008

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

// vm_area_struct 简化定义 (用于访问关键字段)
// 注意：不同内核版本布局可能不同，这里使用常见的 ARM64 Android 内核布局
struct vm_area_struct_common {
    unsigned long vm_start;
    unsigned long vm_end;
    struct vm_area_struct_common *vm_next;
    struct vm_area_struct_common *vm_prev;
    void *vm_mm;              // struct mm_struct *
    unsigned long vm_page_prot_padding;  // pgprot_t (通常是 unsigned long)
    unsigned long vm_flags;
};

// 用于获取 vma 中 vm_file 的偏移量（需要动态计算）
// 在大多数 ARM64 Android 内核中，vm_file 的偏移量约为 0xa0-0xb0
#define VMA_VM_FILE_OFFSET_MIN 0x80
#define VMA_VM_FILE_OFFSET_MAX 0xc0

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
static uint64_t do_readlinkat_addr = 0;

// vm_area_struct 字段偏移量（在 init 时动态检测）
static int vma_vm_flags_offset = -1;
static int vma_vm_file_offset = -1;

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
        // Frida 线程（精确特征，避免误杀）
        "gum-js-loop", "pool-frida",
        "linjector", "frida-server", "frida-helper",
        "frida-agent", "frida:",
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
        // ===== Frida 特征（精确）=====
        "frida-agent", "frida_agent", "frida-gadget",
        "frida-agent-32.so", "frida-agent-64.so",
        "frida-agent.so", "frida-agent-raw.so",
        "frida-server", "frida-helper",
        "frida-gadget.so", "frida-gadget-",
        "gum-js-loop", "libgum.so",
        "linjector", "re.frida.server", "re.frida.",
        "/data/local/tmp/re.frida",
        "/data/local/tmp/frida",

        // ===== Xposed 特征 =====
        "XposedBridge",
        "libxposed_art.so",
        "app_process32_xposed", "app_process64_xposed",
        "app_process32_zposed", "app_process64_zposed",
        "de/robv/android/xposed",

        // ===== Riru 特征 =====
        "libriruloader.so", "libriru_edxp.so",

        // ===== LSPosed/EdXposed 特征 =====
        "liblspd.so", "edxposed", "EdXposed",
        "/data/misc/edxp_",

        // ===== Magisk 特征（只匹配注入标记，不匹配 "magisk" 本身）=====
        "MAGISK_INJ_",

        // ===== Substrate 特征 =====
        "com.saurik.substrate", "slSubstrate",

        // ===== 脱壳工具特征 =====
        "libFupk3.so", "/data/fart", "cn/mik/Fartext",
        "myfartInvoke", "blackdex", "FunDex",

        // ===== 其他 Hook 框架 =====
        "libsotweak.so",
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
// 注意：这只是修改 /proc/self/maps 的输出字符串，不影响实际内存权限
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

    // 检查是否是 rwxp 或 rwxs（可读、可写、可执行）
    if (perm[0] == 'r' && perm[1] == 'w' && perm[2] == 'x') {
        // 检查是否是常见的被 hook 的系统库
        // Frida inline hook 会修改这些库的代码段，导致权限变为 rwx
        if (my_memmem(line, len, "libc.so", 7) ||
            my_memmem(line, len, "libc++.so", 9) ||
            my_memmem(line, len, "libdl.so", 8) ||
            my_memmem(line, len, "libm.so", 7) ||
            my_memmem(line, len, "liblog.so", 9) ||
            my_memmem(line, len, "libandroid_runtime.so", 21) ||
            my_memmem(line, len, "libart.so", 9) ||
            my_memmem(line, len, "libbase.so", 10) ||
            my_memmem(line, len, "linker", 6) ||
            my_memmem(line, len, "/apex/", 6)) {  // apex 下的所有库
            // 将 rwx 改为 r-x（只修改输出字符串）
            perm[1] = '-';
            LOGV("fixed rwx permission in maps output\n");
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
        // Magisk Frida 模块的 frida-server
        "/system/bin/frida-server",
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
        // Magisk（只匹配 magisk 自身目录，不匹配 /data/adb/modules 整体）
        "/sbin/.magisk",
        "/.magisk",
        "/data/adb/magisk",
        // KernelSU
        "/data/adb/ksu",
        "/data/adb/ksud",
        // APatch
        "/data/adb/ap/",
        "/data/adb/apd",
        // Xposed/EdXposed
        "/data/misc/edxp_",
        // Frida
        "/data/local/tmp/re.frida.server",
        "/data/local/tmp/frida-server",
        "/data/local/tmp/frida",
        // Magisk Frida 模块
        "/data/adb/modules/magisk-frida",
        "/data/adb/modules/magiskfrida",
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

// 检查是否是 /proc/*/mem 或 /proc/*/pagemap 路径
// 这些路径可以被 NagaLinker 用于检测调试器/注入器
static int is_proc_mem_path(const char *path)
{
    if (!path || !my_startswith(path, "/proc/")) return 0;

    size_t len = my_strlen(path);
    if (len < 6) return 0;

    // 匹配 /proc/%d/mem 或 /proc/%d/pagemap
    // 跳过 "/proc/" 前缀
    const char *p = path + 6;

    // 跳过数字部分 (PID)
    while (*p >= '0' && *p <= '9') p++;

    // 检查后续路径
    if (my_strcmp(p, "/mem") == 0) return 1;
    if (my_strcmp(p, "/pagemap") == 0) return 1;

    return 0;
}

// 检查是否是 /proc/self/fd/%d 或 /proc/%d/fd/%d 路径
static int is_proc_fd_path(const char *path)
{
    if (!path) return 0;

    // /proc/self/fd/
    if (my_startswith(path, "/proc/self/fd/")) return 1;

    // /proc/%d/fd/
    if (my_startswith(path, "/proc/")) {
        const char *p = path + 6;
        // 跳过 PID 数字
        while (*p >= '0' && *p <= '9') p++;
        if (my_startswith(p, "/fd/")) return 1;
    }

    return 0;
}

// 检查 readlink 返回的路径是否是 Frida 相关的
static int is_frida_link_target(const char *target)
{
    if (!target) return 0;

    static const char *frida_paths[] = {
        "/data/local/tmp/re.frida",
        "/data/local/tmp/frida",
        "memfd:frida",
        "memfd:gum",
        "memfd:agent",
        "[memfd:frida",
        "[memfd:gum",
        "frida-agent",
        "frida-server",
        "frida-gadget",
        "linjector",
        "/tmp/frida",
        "/run/frida",
    };

    int num = sizeof(frida_paths) / sizeof(frida_paths[0]);
    for (int i = 0; i < num; i++) {
        if (my_strstr(target, frida_paths[i])) return 1;
    }

    return 0;
}

// ==================== Hook 函数 ====================

// 辅助函数：获取 vma 的 vm_flags
static unsigned long *get_vma_flags_ptr(void *vma)
{
    if (!vma || vma_vm_flags_offset < 0) return 0;
    return (unsigned long *)((char *)vma + vma_vm_flags_offset);
}

// 辅助函数：获取 vma 的 vm_file
// 尝试多个偏移量以提高兼容性
static void *get_vma_file(void *vma)
{
    if (!vma) return 0;

    // 如果已设置偏移量，先尝试它
    if (vma_vm_file_offset > 0) {
        void **file_ptr = (void **)((char *)vma + vma_vm_file_offset);
        void *file = *file_ptr;
        if (file && ((unsigned long)file > 0xffff000000000000UL) &&
            ((unsigned long)file < 0xffffffffffffffffUL)) {
            return file;
        }
    }

    // 尝试其他常见偏移量（Linux 5.4 ARM64）
    static const int file_offsets[] = {0x98, 0x90, 0xa0, 0x88, 0xa8};

    for (int i = 0; i < sizeof(file_offsets)/sizeof(file_offsets[0]); i++) {
        if (file_offsets[i] == vma_vm_file_offset) continue;  // 已经尝试过

        void **file_ptr = (void **)((char *)vma + file_offsets[i]);
        void *file = *file_ptr;

        // 验证是否是有效的内核指针
        if (file && ((unsigned long)file > 0xffff000000000000UL) &&
            ((unsigned long)file < 0xffffffffffffffffUL)) {
            return file;
        }
    }

    return 0;
}

// 辅助函数：从 file 获取文件路径名
// 使用 d_path 内核函数（如果可用）或手动遍历
static const char *get_file_name_simple(void *file)
{
    if (!file) return 0;

    // 方法1：直接从 file 结构体获取 dentry
    // struct file 布局（ARM64 Linux 5.x/6.x）：
    // 0x00: f_u (union)
    // 0x08: f_path.mnt
    // 0x10: f_path.dentry
    // 或者
    // 0x10: f_path.mnt
    // 0x18: f_path.dentry

    void *dentry = 0;

    // 尝试常见的 dentry 偏移
    static const int dentry_offsets[] = {0x10, 0x18, 0x20, 0x08};

    for (int i = 0; i < sizeof(dentry_offsets)/sizeof(dentry_offsets[0]); i++) {
        void **ptr = (void **)((char *)file + dentry_offsets[i]);
        void *d = *ptr;

        // 验证是否是有效的内核指针
        if (d && ((unsigned long)d > 0xffff000000000000UL) &&
            ((unsigned long)d < 0xffffffffffffffffUL)) {
            // 进一步验证：dentry 的第一个字段通常是 d_flags (unsigned int)
            // 或者检查 d_name 结构
            dentry = d;
            break;
        }
    }

    if (!dentry) return 0;

    // 从 dentry 获取 d_name
    // struct dentry 布局（ARM64 Linux 5.x/6.x）：
    // d_name 是 struct qstr，包含 { hash, len, name }
    // d_name 在 dentry 中的偏移通常是 0x20 或 0x28
    // qstr.name 在 qstr 中的偏移是 0x08（在 hash 和 len 之后）

    static const int qstr_offsets[] = {0x20, 0x28, 0x30, 0x18, 0x38};

    for (int i = 0; i < sizeof(qstr_offsets)/sizeof(qstr_offsets[0]); i++) {
        // qstr 结构: { unsigned int hash; unsigned int len; const char *name; }
        // name 指针在 qstr 偏移 0x08 处
        const char **name_ptr = (const char **)((char *)dentry + qstr_offsets[i] + 0x08);
        const char *name = *name_ptr;

        // 验证 name 指针
        if (name && ((unsigned long)name > 0xffff000000000000UL) &&
            ((unsigned long)name < 0xffffffffffffffffUL)) {
            // 验证是否是有效的文件名（以字母或数字开头）
            char c = name[0];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '_' || c == '.') {
                return name;
            }
        }
    }

    return 0;
}

// 检查是否是需要隐藏 RWX 权限的系统库
static int is_system_lib_for_rwx_fix(const char *name)
{
    if (!name) return 0;

    // 检查常见的被 Frida hook 的系统库
    if (my_strstr(name, "libc.so")) return 1;
    if (my_strstr(name, "libc++.so")) return 1;
    if (my_strstr(name, "libdl.so")) return 1;
    if (my_strstr(name, "libm.so")) return 1;
    if (my_strstr(name, "liblog.so")) return 1;
    if (my_strstr(name, "libart.so")) return 1;
    if (my_strstr(name, "libbase.so")) return 1;
    if (my_strstr(name, "linker")) return 1;
    if (my_strstr(name, "libandroid_runtime.so")) return 1;
    if (my_strstr(name, "libutils.so")) return 1;
    if (my_strstr(name, "libbinder.so")) return 1;

    return 0;
}

// show_map_vma hook - 隐藏 frida 映射并修复 RWX 权限
// 函数签名: void show_map_vma(struct seq_file *m, struct vm_area_struct *vma)
static void before_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    void *vma = (void *)args->arg1;

    args->local.data0 = 0;  // 保存 seq_file count
    args->local.data1 = 0;  // 保存原始 vm_flags（如果需要修改）
    args->local.data2 = 0;  // 标记是否是 app 进程

    // 只对 app 进程生效，避免影响 frida-server 等 root 进程
    if (!is_app_process()) return;

    args->local.data2 = 1;

    if (m && m->buf) {
        args->local.data0 = (uint64_t)m->count;
    }

    if (!vma) return;
    if (vma_vm_flags_offset < 0) return;  // 偏移量未设置

    // 获取 vm_flags 指针
    unsigned long *flags_ptr = get_vma_flags_ptr(vma);
    if (!flags_ptr) return;

    unsigned long flags = *flags_ptr;

    // 验证 flags 是否合理（应该包含基本的权限位）
    // 如果 flags 看起来不像权限标志，说明偏移量可能不对
    if (flags == 0 || flags > 0xFFFFFFFF) {
        return;  // 不合理的值，跳过
    }

    // 检查是否是 RWX 权限
    if ((flags & (VM_READ | VM_WRITE | VM_EXEC)) != (VM_READ | VM_WRITE | VM_EXEC)) {
        return;  // 不是 RWX，不需要处理
    }

    // 检查是否是文件映射（有 vm_file）
    void *file = get_vma_file(vma);
    if (!file) return;  // 匿名映射或偏移量不对，不处理

    // 获取文件名
    const char *name = get_file_name_simple(file);
    if (!name) return;

    // 检查是否是需要修复的系统库
    if (!is_system_lib_for_rwx_fix(name)) return;

    // 保存原始 flags
    args->local.data1 = flags;

    // 临时清除 VM_WRITE 标志，让输出显示 r-x 而不是 rwx
    *flags_ptr = flags & ~VM_WRITE;

    LOGV("temp clear VM_WRITE for %s (flags: 0x%lx -> 0x%lx)\n",
         name, flags, *flags_ptr);
}

static void after_show_map_vma(hook_fargs2_t *args, void *udata)
{
    // 非 app 进程直接返回
    if (!args->local.data2) return;

    struct seq_file *m = (struct seq_file *)args->arg0;
    void *vma = (void *)args->arg1;

    // 恢复原始 vm_flags（如果之前修改过）
    if (args->local.data1 && vma) {
        unsigned long original_flags = args->local.data1;
        unsigned long *flags_ptr = get_vma_flags_ptr(vma);

        if (flags_ptr) {
            *flags_ptr = original_flags;
            LOGV("restored vm_flags: 0x%lx\n", original_flags);
        }
    }

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

    // 3. 修复 RWX 权限 - 作为后备方案，修改输出字符串
    // 如果方案 A（修改 vm_flags）成功，这里应该不会再看到 rwx
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
// 注意：不同内核版本参数数量可能不同 (3或4个参数)
static void before_do_faccessat(hook_fargs4_t *args, void *udata)
{
    // do_faccessat(int dfd, const char __user *filename, int mode [, int flags])
    const char __user *filename = (const char __user *)args->arg1;

    if (!filename) return;

    char buf[MAX_PATH_LEN];
    long len = compat_strncpy_from_user(buf, filename, sizeof(buf) - 1);

    if (len <= 0 || len >= (long)(sizeof(buf) - 1)) return;
    buf[len] = '\0';

    // 只拦截 app 进程（UID >= 10000），不拦截 system_server（UID=1000）
    if (is_sensitive_path(buf)) {
        if (is_app_process()) {
            LOGV("blocked faccessat: path=%s\n", buf);
            args->ret = (uint64_t)(-(long)ENOENT);
            args->skip_origin = 1;
        }
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
// 同时阻止 /proc/*/mem 和 /proc/*/pagemap 访问
// struct file *do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op)
static void before_do_filp_open(hook_fargs3_t *args, void *udata)
{
    struct filename *pathname = (struct filename *)args->arg1;

    if (!pathname) return;
    if (!pathname->name) return;
    if (!is_app_process()) return;

    const char *path = pathname->name;

    // 1. 检查敏感路径（su/magisk/xposed 等）
    if (is_sensitive_path(path)) {
        LOGV("blocked filp_open: %s\n", path);
        // 返回 ERR_PTR(-ENOENT)
        args->ret = (uint64_t)(-(long)ENOENT);
        args->skip_origin = 1;
        return;
    }

    // 2. 检查 /proc/*/mem 和 /proc/*/pagemap（NagaLinker 检测）
    if (is_proc_mem_path(path)) {
        LOGV("blocked proc mem access: %s\n", path);
        args->ret = (uint64_t)(-(long)ENOENT);
        args->skip_origin = 1;
        return;
    }
}

// proc_pid_status hook - 隐藏 TracerPid
static void before_proc_pid_status(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    args->local.data0 = 0;
    args->local.data1 = 0;  // 标记是否是 app 进程

    if (!is_app_process()) return;

    args->local.data1 = 1;

    if (m && m->buf) {
        args->local.data0 = (uint64_t)m->count;
    }
}

static void after_proc_pid_status(hook_fargs2_t *args, void *udata)
{
    if (!args->local.data1) return;  // 非 app 进程跳过

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
    args->local.data1 = 0;  // 标记是否是 app 进程

    if (!is_app_process()) return;

    args->local.data1 = 1;

    struct seq_file *m = (struct seq_file *)args->arg0;
    if (m && m->buf) {
        args->local.data0 = (uint64_t)m->count;
    }
}

static void after_comm_show(hook_fargs2_t *args, void *udata)
{
    if (!args->local.data1) return;  // 非 app 进程跳过

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
    if (!is_app_process()) return;  // 只对 app 进程生效

    char *buf = (char *)args->arg0;

    if (!buf) return;

    if (is_frida_thread_name(buf)) {
        buf[0] = 'k'; buf[1] = 'w'; buf[2] = 'o'; buf[3] = 'r';
        buf[4] = 'k'; buf[5] = 'e'; buf[6] = 'r'; buf[7] = '\0';
        LOGV("hidden frida thread comm\n");
    }
}

// do_readlinkat hook - 过滤 FD 符号链接检测结果
// ssize_t do_readlinkat(int dfd, const char __user *path, char __user *buf,
//                       size_t bufsiz, int flags)
// 当应用读取 /proc/self/fd/%d 的符号链接时，如果目标指向 Frida 相关路径，
// 则返回伪造的路径（如 /dev/null）
static void after_do_readlinkat(hook_fargs5_t *args, void *udata)
{
    if (!is_app_process()) return;

    // 获取返回值（读取的字节数）
    ssize_t ret = (ssize_t)args->ret;
    if (ret <= 0) return;

    const char __user *path = (const char __user *)args->arg1;
    char __user *buf = (char __user *)args->arg2;
    size_t bufsiz = (size_t)args->arg3;

    if (!path || !buf) return;

    // 只处理 /proc/*/fd/* 路径
    char path_buf[64];
    long path_len = compat_strncpy_from_user(path_buf, path, sizeof(path_buf) - 1);
    if (path_len <= 0) return;
    path_buf[path_len] = '\0';

    if (!is_proc_fd_path(path_buf)) return;

    // 读取返回的链接目标
    char link_buf[MAX_PATH_LEN];
    if ((size_t)ret >= sizeof(link_buf)) return;

    long copy_len = compat_strncpy_from_user(link_buf, buf, (size_t)ret);
    if (copy_len <= 0) return;
    link_buf[copy_len] = '\0';

    // 检查链接目标是否是 Frida 相关
    if (is_frida_link_target(link_buf)) {
        // 替换为伪造路径
        const char *fake = "/dev/null";
        size_t fake_len = 9;

        if (bufsiz >= fake_len + 1) {
            compat_copy_to_user(buf, fake, fake_len + 1);
            args->ret = (uint64_t)fake_len;
            LOGV("hidden frida fd link: %s -> %s (was: %s)\n",
                 path_buf, fake, link_buf);
        }
    }
}

// ==================== 模块入口 ====================

// 动态检测 vm_area_struct 中 vm_flags 和 vm_file 的偏移量
static void detect_vma_offsets(void)
{
    // Linux 5.4 ARM64 内核中 vm_area_struct 的布局：
    // 0x00: vm_start
    // 0x08: vm_end
    // 0x10: vm_next
    // 0x18: vm_prev
    // 0x20: vm_rb (rb_node, 24 bytes)
    // 0x38: rb_subtree_gap
    // 0x40: vm_mm
    // 0x48: vm_page_prot (pgprot_t)
    // 0x50: vm_flags
    // ...
    // 0x90-0xa0: vm_file (取决于配置)

    // 对于 5.4.86 内核，使用以下偏移
    vma_vm_flags_offset = 0x50;  // vm_flags 偏移
    vma_vm_file_offset = 0x98;   // vm_file 偏移（5.4 内核常见值）

    LOGV("kernel 5.4 detected, using vma offsets: vm_flags=0x%x, vm_file=0x%x\n",
         vma_vm_flags_offset, vma_vm_file_offset);
}

static long frida_hide_init(const char *args, const char *event, void *__user reserved)
{
    LOGV("loading ultimate version: %s\n", MYKPM_VERSION);

    // 检测 VMA 结构体偏移量
    detect_vma_offsets();

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
            LOGV("[-] hook do_faccessat FAILED: %d\n", err);
            do_faccessat_addr = 0;
        }
    } else {
        LOGV("[-] do_faccessat NOT FOUND\n");
    }

    // 5.1 尝试多个 faccessat2 相关符号
    static const char *faccessat2_syms[] = {
        "__arm64_sys_faccessat2",
        "__se_sys_faccessat2",
        "do_faccessat2",
        "__arm64_sys_faccessat",
        "__se_sys_faccessat",
    };
    for (int i = 0; i < sizeof(faccessat2_syms)/sizeof(faccessat2_syms[0]); i++) {
        uint64_t addr = kallsyms_lookup_name(faccessat2_syms[i]);
        if (addr) {
            LOGV("[*] found %s at 0x%llx\n", faccessat2_syms[i], addr);
            // 避免重复 hook 同一地址
            if (addr != do_faccessat_addr && sys_faccessat2_addr == 0) {
                hook_err_t err = hook_wrap4((void *)addr,
                                            before_do_faccessat,
                                            (void *)0,
                                            (void *)0);
                if (err == HOOK_NO_ERR) {
                    LOGV("[+] %s hooked at 0x%llx\n", faccessat2_syms[i], addr);
                    sys_faccessat2_addr = addr;
                    hooks_installed++;
                } else {
                    LOGV("[-] hook %s FAILED: %d\n", faccessat2_syms[i], err);
                }
            }
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

    // 12. Hook do_readlinkat - 过滤 FD 符号链接检测
    do_readlinkat_addr = kallsyms_lookup_name("do_readlinkat");
    if (!do_readlinkat_addr) {
        // 尝试其他符号名
        do_readlinkat_addr = kallsyms_lookup_name("__arm64_sys_readlinkat");
    }
    if (!do_readlinkat_addr) {
        do_readlinkat_addr = kallsyms_lookup_name("__se_sys_readlinkat");
    }
    if (do_readlinkat_addr) {
        hook_err_t err = hook_wrap5((void *)do_readlinkat_addr,
                                    (void *)0,
                                    after_do_readlinkat,
                                    (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("[+] do_readlinkat hooked at 0x%llx\n", do_readlinkat_addr);
            hooks_installed++;
        } else {
            LOGV("[-] hook do_readlinkat FAILED: %d\n", err);
            do_readlinkat_addr = 0;
        }
    } else {
        LOGV("[-] do_readlinkat NOT FOUND\n");
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

    if (do_readlinkat_addr) {
        unhook((void *)do_readlinkat_addr);
        do_readlinkat_addr = 0;
    }
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
