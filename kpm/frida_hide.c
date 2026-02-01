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
#include <linux/fs.h>
#include <linux/slab.h>      // 添加：用于 kmalloc/kfree
#include <asm/atomic.h>  // 替代 linux/atomic.h
#include <uapi/asm-generic/unistd.h>
#include <asm/current.h>
#include <linux/gfp.h>       // 添加：用于 GFP_KERNEL
#include <linux/kstrtox.h>   // 添加：用于 kstrtoint
#include <linux/slab.h>      // 已有：用于 kmalloc/kfree
#ifndef MYKPM_VERSION
#define MYKPM_VERSION "2.0"
#endif

// 系统调用号定义
#ifndef __NR_connect
#define __NR_connect 203
#endif
#ifndef __NR_readlinkat
#define __NR_readlinkat 78
#endif
#ifndef __NR_readlink
#define __NR_readlink 58
#endif
#ifndef __NR_openat
#define __NR_openat 56
#endif
#ifndef __NR_statfs
#define __NR_statfs 43
#endif
#ifndef __NR_getdents64
#define __NR_getdents64 61
#endif



KPM_NAME("FridaHide");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("frida_hide_v2");
KPM_DESCRIPTION("Advanced Frida detection bypass for Android");

// ==========================================
// 结构体定义
// ==========================================

struct seq_file {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
    loff_t index;
    loff_t read_pos;
    u64 version;
    void *private;
};

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int sin_addr;
    unsigned char __pad[8];
};

// 已手动定义，无需 #include <linux/dirent.h>
struct linux_dirent64 {
    u64 d_ino;
    s64 d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

#define AF_INET 2
#define DT_LNK 10
// ==========================================
// 配置与全局变量
// ==========================================

// 配置
static int TARGET_PORT = 27042;
static char TARGET_PACKAGE[256] = "com.example.app"; // 目标包名，留空则全局生效

// 函数指针
static void *show_map_vma = NULL;
static char *(*__get_task_comm)(char *buf, size_t buf_size, struct task_struct *tsk) = NULL;
static unsigned long (*__arch_copy_from_user)(void *to, const void __user *from, unsigned long n) = NULL;
static unsigned long (*__arch_copy_to_user)(void __user *to, const void *from, unsigned long n) = NULL;

// Hook 状态
static int show_map_vma_hook_status = 0;
static int get_task_comm_hook_status = 0;
static int connect_hook_status = 0;
static int readlinkat_hook_status = 0;
static int readlink_hook_status = 0;
static int openat_hook_status = 0;
static int getdents64_hook_status = 0;

// 运行时配置
static int frida_hide_enabled = 1;
static int frida_hide_log_enabled = 1;
static int frida_hide_log_verbose = 0;

// 统计计数器（减少日志噪音）
static atomic_t stat_maps_hidden = ATOMIC_INIT(0);
static atomic_t stat_readlink_hidden = ATOMIC_INIT(0);
static atomic_t stat_comm_hidden = ATOMIC_INIT(0);
static atomic_t stat_connect_blocked = ATOMIC_INIT(0);
static atomic_t stat_openat_blocked = ATOMIC_INIT(0);
static atomic_t stat_fd_hidden = ATOMIC_INIT(0);

// 日志宏
#define FH_LOGI(fmt, ...) do { if (frida_hide_log_enabled) logki("[FH] " fmt, ##__VA_ARGS__); } while (0)
#define FH_LOGW(fmt, ...) do { if (frida_hide_log_enabled) logkw("[FH] " fmt, ##__VA_ARGS__); } while (0)
#define FH_LOGD(fmt, ...) do { if (frida_hide_log_verbose) logkd("[FH] " fmt, ##__VA_ARGS__); } while (0)

#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#endif

// ==========================================
// 辅助函数
// ==========================================

static inline uint16_t local_ntohs(uint16_t val) {
    return (val << 8) | (val >> 8);
}

// 优化的内存搜索（大小写不敏感）
static void *memmem_case_insensitive(const void *haystack, size_t haystacklen, 
                                      const void *needle, size_t needlelen)
{
    if (!haystack || !needle || haystacklen < needlelen || needlelen == 0)
        return NULL;
    
    const unsigned char *h = haystack;
    const unsigned char *n = needle;
    
    for (size_t i = 0; i <= haystacklen - needlelen; ++i) {
        size_t j;
        for (j = 0; j < needlelen; ++j) {
            unsigned char hc = h[i + j];
            unsigned char nc = n[j];
            // 转小写比较
            if (hc >= 'A' && hc <= 'Z') hc += 32;
            if (nc >= 'A' && nc <= 'Z') nc += 32;
            if (hc != nc) break;
        }
        if (j == needlelen) return (void *)(h + i);
    }
    return NULL;
}

// 检查是否为目标进程（如果配置了包名）
static int is_target_process(void)
{
    if (TARGET_PACKAGE[0] == '\0') return 1; // 未配置则全局生效
    
    char comm[TASK_COMM_LEN];
    if (__get_task_comm) {
        __get_task_comm(comm, sizeof(comm), current);
        return (strstr(comm, TARGET_PACKAGE) != NULL);
    }
    return 0;
}

// 增强的敏感内容检测
static int is_sensitive_content(const char *buffer, size_t len)
{
    static const char *keywords[] = {
        "frida", "FRIDA",
        "gum-js-loop", "GumJS",
        "gmain", "gdbus",
        "linjector",
        "re.frida.server",
        "/data/local/tmp/re.frida.server",
        "frida-agent", "frida-helper",
        "frida-gadget",
        "/memfd:frida",
        NULL
    };

    for (int i = 0; keywords[i] != NULL; ++i) {
        if (memmem_case_insensitive(buffer, len, keywords[i], strlen(keywords[i])))
            return 1;
    }
    return 0;
}

// 检查线程名
static int is_sensitive_comm(const char *comm)
{
    static const char *keywords[] = {
        "gmain", "gum-js-loop", "gdbus",
        "pool-frida", "linjector", "frida"
    };
    
    for (int i = 0; i < sizeof(keywords) / sizeof(keywords[0]); i++) {
        if (strstr(comm, keywords[i])) return 1;
    }
    return 0;
}

// 检查路径是否敏感
static int is_sensitive_path(const char *path)
{
    static const char *patterns[] = {
        "/proc/", "/sys/", "/dev/",
        "frida", "gum", "linjector",
        "/data/local/tmp/re.frida",
        "/data/adb/modules/magisk-frida",
        NULL
    };
    
    for (int i = 0; patterns[i] != NULL; ++i) {
        if (strstr(path, patterns[i])) return 1;
    }
    return 0;
}

// ==========================================
// Hook 实现
// ==========================================

// [1] Hook: show_map_vma - 逐行过滤 maps
static void before_show_map_vma(hook_fargs2_t *args, void *udata)
{
    if (!is_target_process()) return;
    
    struct seq_file *m = (struct seq_file *)args->arg0;
    if (!m) return;
    
    args->local.data0 = m->count; // 保存当前位置
}

static void after_show_map_vma(hook_fargs2_t *args, void *udata)
{
    if (!is_target_process()) return;
    
    struct seq_file *m = (struct seq_file *)args->arg0;
    if (!m || !m->buf) return;
    
    size_t old_count = args->local.data0;
    size_t new_count = m->count;
    
    // 检查新增的内容
    if (new_count > old_count) {
        char *new_content = m->buf + old_count;
        size_t new_len = new_count - old_count;
        
        if (is_sensitive_content(new_content, new_len)) {
            m->count = old_count; // 回滚，丢弃这一行
            atomic_inc(&stat_maps_hidden);
            FH_LOGD("maps: hidden line (total: %d)\n", atomic_read(&stat_maps_hidden));
        }
    }
}

// [2] Hook: get_task_comm - 伪装线程名
static void after_get_task_comm(hook_fargs3_t *args, void *udata)
{
    if (!is_target_process()) return;
    
    char *comm = (char *)args->arg0;
    if (!comm) return;
    
    if (is_sensitive_comm(comm)) {
        // 伪装成常见的系统线程名
        const char *fake_names[] = {
            "Binder", "RenderThread", "HeapTaskDaemon",
            "FinalizerDaemon", "AsyncTask"
        };
        int idx = (int)(args->arg1) % (sizeof(fake_names) / sizeof(fake_names[0]));
        strncpy(comm, fake_names[idx], TASK_COMM_LEN - 1);
        comm[TASK_COMM_LEN - 1] = '\0';
        
        atomic_inc(&stat_comm_hidden);
        FH_LOGD("comm: %s -> %s (total: %d)\n", 
                (char*)args->arg0, comm, atomic_read(&stat_comm_hidden));
    }
}

// [3] Hook: connect - 端口保护
static void before_connect(hook_fargs3_t *args, void *udata)
{
    struct sockaddr_in addr_kernel;
    const void __user *addr_user = (const void __user *)(uintptr_t)syscall_argn(args, 1);

    if (!addr_user || !__arch_copy_from_user) return;
    if (__arch_copy_from_user(&addr_kernel, addr_user, sizeof(addr_kernel)) != 0) return;

    if (addr_kernel.sin_family != AF_INET) return;
    uint16_t port = local_ntohs(addr_kernel.sin_port);

    if (port == TARGET_PORT || port == 27042 || port == 27043) {
        char comm[TASK_COMM_LEN];
        if (__get_task_comm) {
            __get_task_comm(comm, sizeof(comm), current);
            // 白名单：允许 adbd/shell
            if (!strstr(comm, "adbd") && !strstr(comm, "sh")) {
                atomic_inc(&stat_connect_blocked);
                FH_LOGW("connect: BLOCKED port %d from %s (total: %d)\n", 
                        port, comm, atomic_read(&stat_connect_blocked));
                args->skip_origin = 1;
                args->ret = -ECONNREFUSED; // 伪装成连接被拒绝
            }
        }
    }
}

// [4] Hook: readlink 通用处理
static void after_readlink_common(void *user_buf_ptr, uint64_t *ret_ptr)
{
    if (!is_target_process()) return;
    
    long ret = *ret_ptr;
    if (ret <= 0 || !user_buf_ptr || !__arch_copy_from_user || !__arch_copy_to_user) 
        return;

    char kbuf[512];
    long read_len = min(ret, (long)(sizeof(kbuf) - 1));
    
    if (__arch_copy_from_user(kbuf, user_buf_ptr, read_len) != 0) return;
    kbuf[read_len] = '\0';

    if (is_sensitive_content(kbuf, read_len)) {
        // 根据原路径类型选择伪造目标
        const char *fake_path;
        if (strstr(kbuf, "/memfd:")) {
            fake_path = "/dev/ashmem/dalvik-main space"; // 伪装成正常的 memfd
        } else if (strstr(kbuf, ".so")) {
            fake_path = "/system/lib64/libc.so"; // 伪装成系统库
        } else {
            fake_path = "/dev/null";
        }
        
        size_t fake_len = strlen(fake_path);
        if (__arch_copy_to_user(user_buf_ptr, fake_path, fake_len) == 0) {
            *ret_ptr = fake_len;
            atomic_inc(&stat_readlink_hidden);
            FH_LOGD("readlink: %s -> %s (total: %d)\n", 
                    kbuf, fake_path, atomic_read(&stat_readlink_hidden));
        }
    }
}

static void after_readlinkat(hook_fargs4_t *args, void *udata)
{
    void *user_buf = (void *)syscall_argn(args, 2);
    after_readlink_common(user_buf, &args->ret);
}

static void after_readlink(hook_fargs3_t *args, void *udata)
{
    void *user_buf = (void *)syscall_argn(args, 1);
    after_readlink_common(user_buf, &args->ret);
}

// [5] Hook: openat - 阻止打开敏感文件
static void before_openat(hook_fargs4_t *args, void *udata)
{
    if (!is_target_process()) return;
    
    const char __user *pathname_user = (const char __user *)(uintptr_t)syscall_argn(args, 1);
    if (!pathname_user || !__arch_copy_from_user) return;
    
    char pathname[256];
    if (__arch_copy_from_user(pathname, pathname_user, sizeof(pathname) - 1) != 0) return;
    pathname[sizeof(pathname) - 1] = '\0';
    
    // 检查是否尝试打开敏感路径
    if (is_sensitive_path(pathname)) {
        atomic_inc(&stat_openat_blocked);
        FH_LOGD("openat: BLOCKED %s (total: %d)\n", 
                pathname, atomic_read(&stat_openat_blocked));
        args->skip_origin = 1;
        args->ret = -ENOENT; // 文件不存在
    }
}

// [6] Hook: getdents64 - 隐藏 /proc/self/fd 中的敏感项
static void after_getdents64(hook_fargs3_t *args, void *udata)
{
    if (!is_target_process()) return;
    
    long ret = args->ret;
    if (ret <= 0) return;
    
    void __user *dirent_user = (void __user *)(uintptr_t)syscall_argn(args, 1);
    if (!dirent_user || !__arch_copy_from_user || !__arch_copy_to_user) return;
    
    // 分配内核缓冲区
    char *kbuf = kmalloc(ret, GFP_KERNEL);
    if (!kbuf) return;
    
    if (__arch_copy_from_user(kbuf, dirent_user, ret) != 0) {
        kfree(kbuf);
        return;
    }
    
    // 遍历目录项，过滤敏感项
    long pos = 0;
    long new_pos = 0;
    int hidden_count = 0;
    
    while (pos < ret) {
        struct linux_dirent64 *d = (struct linux_dirent64 *)(kbuf + pos);
        int should_hide = 0;
        
        // 检查文件名是否敏感
        if (is_sensitive_content(d->d_name, strlen(d->d_name))) {
            should_hide = 1;
            hidden_count++;
        }
        
        if (!should_hide) {
            if (new_pos != pos) {
                memmove(kbuf + new_pos, kbuf + pos, d->d_reclen);
            }
            new_pos += d->d_reclen;
        }
        
        pos += d->d_reclen;
    }
    
    if (hidden_count > 0) {
        __arch_copy_to_user(dirent_user, kbuf, new_pos);
        args->ret = new_pos;
        atomic_add(hidden_count, &stat_fd_hidden);
        FH_LOGD("getdents64: hidden %d entries (total: %d)\n", 
                hidden_count, atomic_read(&stat_fd_hidden));
    }
    
    kfree(kbuf);
}

// ==========================================
// 模块生命周期
// ==========================================

void frida_hide_install(void)
{
    FH_LOGI("Installing hooks (v%s)...\n", MYKPM_VERSION);
    
    // 初始化函数指针
    __arch_copy_from_user = (void *)kallsyms_lookup_name("__arch_copy_from_user");
    if (!__arch_copy_from_user) 
        __arch_copy_from_user = (void *)kallsyms_lookup_name("_copy_from_user");
    
    __arch_copy_to_user = (void *)kallsyms_lookup_name("__arch_copy_to_user");
    if (!__arch_copy_to_user) 
        __arch_copy_to_user = (void *)kallsyms_lookup_name("_copy_to_user");
    
    __get_task_comm = (void *)kallsyms_lookup_name("__get_task_comm");
    if (!__get_task_comm) 
        __get_task_comm = (void *)kallsyms_lookup_name("get_task_comm");

    // 1. Hook show_map_vma
    show_map_vma = (void *)kallsyms_lookup_name("show_map_vma");
    if (show_map_vma) {
        if (hook_wrap2(show_map_vma, before_show_map_vma, after_show_map_vma, NULL) == HOOK_NO_ERR) {
            show_map_vma_hook_status = 1;
            FH_LOGI("✓ show_map_vma hooked\n");
        }
    }

    // 2. Hook get_task_comm
    if (__get_task_comm) {
        if (hook_wrap3(__get_task_comm, NULL, after_get_task_comm, NULL) == HOOK_NO_ERR) {
            get_task_comm_hook_status = 1;
            FH_LOGI("✓ get_task_comm hooked\n");
        }
    }

    // 3. Hook connect
    if (__arch_copy_from_user && __get_task_comm) {
        if (fp_hook_syscalln(__NR_connect, 3, before_connect, NULL, NULL) == HOOK_NO_ERR) {
            connect_hook_status = 1;
            FH_LOGI("✓ connect hooked (port: %d)\n", TARGET_PORT);
        }
    }

    // 4. Hook readlinkat & readlink
    if (__arch_copy_from_user && __arch_copy_to_user) {
        if (fp_hook_syscalln(__NR_readlinkat, 4, NULL, after_readlinkat, NULL) == HOOK_NO_ERR) {
            readlinkat_hook_status = 1;
            FH_LOGI("✓ readlinkat hooked\n");
        }
        if (fp_hook_syscalln(__NR_readlink, 3, NULL, after_readlink, NULL) == HOOK_NO_ERR) {
            readlink_hook_status = 1;
            FH_LOGI("✓ readlink hooked\n");
        }
    }

    // 5. Hook openat (新增)
    if (__arch_copy_from_user) {
        if (fp_hook_syscalln(__NR_openat, 4, before_openat, NULL, NULL) == HOOK_NO_ERR) {
            openat_hook_status = 1;
            FH_LOGI("✓ openat hooked\n");
        }
    }

    // 6. Hook getdents64 (新增 - 隐藏 fd 目录项)
    if (__arch_copy_from_user && __arch_copy_to_user) {
        if (fp_hook_syscalln(__NR_getdents64, 3, NULL, after_getdents64, NULL) == HOOK_NO_ERR) {
            getdents64_hook_status = 1;
            FH_LOGI("✓ getdents64 hooked\n");
        }
    }

    FH_LOGI("Installation complete. Active hooks: %d\n",
            show_map_vma_hook_status + get_task_comm_hook_status + 
            connect_hook_status + readlinkat_hook_status + 
            readlink_hook_status + openat_hook_status + getdents64_hook_status);
}

void frida_hide_uninstall(void)
{
    FH_LOGI("Uninstalling hooks...\n");
    
    if (show_map_vma_hook_status) {
        unhook(show_map_vma);
        show_map_vma_hook_status = 0;
    }
    
    if (get_task_comm_hook_status) {
        unhook(__get_task_comm);
        get_task_comm_hook_status = 0;
    }
    
    if (connect_hook_status) {
        fp_unhook_syscalln(__NR_connect, before_connect, NULL);
        connect_hook_status = 0;
    }
    
    if (readlinkat_hook_status) {
        fp_unhook_syscalln(__NR_readlinkat, NULL, after_readlinkat);
        readlinkat_hook_status = 0;
    }
    
    if (readlink_hook_status) {
        fp_unhook_syscalln(__NR_readlink, NULL, after_readlink);
        readlink_hook_status = 0;
    }
    
    if (openat_hook_status) {
        fp_unhook_syscalln(__NR_openat, before_openat, NULL);
        openat_hook_status = 0;
    }
    
    if (getdents64_hook_status) {
        fp_unhook_syscalln(__NR_getdents64, NULL, after_getdents64);
        getdents64_hook_status = 0;
    }
    
    FH_LOGI("Uninstall complete\n");
}

static long frida_hide_init(const char *args, const char *event, void *reserved)
{
    FH_LOGI("FridaHide v%s initializing...\n", MYKPM_VERSION);
    
    // 解析参数 (格式: "port=27042,package=com.example.app")
    if (args && strlen(args) > 0) {
        char *args_copy = kstrdup(args, GFP_KERNEL);
    if (args_copy) {
        char *token, *cur = args_copy;
        while ((token = strsep(&cur, ","))) {
            if (strncmp(token, "port=", 5) == 0) {
                kstrtoint(token + 5, 10, &TARGET_PORT);
                FH_LOGI("Config: port=%d\n", TARGET_PORT);
            } else if (strncmp(token, "package=", 8) == 0) {
                strncpy(TARGET_PACKAGE, token + 8, sizeof(TARGET_PACKAGE) - 1);
                TARGET_PACKAGE[sizeof(TARGET_PACKAGE) - 1] = '\0';
                FH_LOGI("Config: package=%s\n", TARGET_PACKAGE);
            } else if (strcmp(token, "verbose") == 0) {
                frida_hide_log_verbose = 1;
                FH_LOGI("Config: verbose logging enabled\n");
            }
        }
        kfree(args_copy);
    }
    }
    
    if (frida_hide_enabled) {
        frida_hide_install();
    }
    
    return 0;
}

static long frida_hide_exit(void *reserved)
{
    FH_LOGI("FridaHide exiting...\n");
    frida_hide_uninstall();
    
    // 打印统计信息
    FH_LOGI("Statistics:\n");
    FH_LOGI("  Maps hidden: %d\n", atomic_read(&stat_maps_hidden));
    FH_LOGI("  Readlinks hidden: %d\n", atomic_read(&stat_readlink_hidden));
    FH_LOGI("  Comms hidden: %d\n", atomic_read(&stat_comm_hidden));
    FH_LOGI("  Connects blocked: %d\n", atomic_read(&stat_connect_blocked));
    FH_LOGI("  Openats blocked: %d\n", atomic_read(&stat_openat_blocked));
    FH_LOGI("  FDs hidden: %d\n", atomic_read(&stat_fd_hidden));
    
    return 0;
}

static long frida_hide_ctl0(const char *args, char __user *out_msg, int outlen)
{
    char reply_msg[512];
    int reply_len = 0;

    if (!args || !strncmp(args, "STATUS", 6)) {
        // 状态查询
        reply_len = snprintf(reply_msg, sizeof(reply_msg),
            "FridaHide v%s Status:\n"
            "Enabled: %s\n"
            "Target Package: %s\n"
            "Target Port: %d\n"
            "\nActive Hooks:\n"
            "  show_map_vma: %s\n"
            "  get_task_comm: %s\n"
            "  connect: %s\n"
            "  readlinkat: %s\n"
            "  readlink: %s\n"
            "  openat: %s\n"
            "  getdents64: %s\n"
            "\nStatistics:\n"
            "  Maps hidden: %d\n"
            "  Readlinks: %d\n"
            "  Comms: %d\n"
            "  Connects blocked: %d\n"
            "  Openats blocked: %d\n"
            "  FDs hidden: %d\n",
            MYKPM_VERSION,
            frida_hide_enabled ? "YES" : "NO",
            TARGET_PACKAGE[0] ? TARGET_PACKAGE : "(all processes)",
            TARGET_PORT,
            show_map_vma_hook_status ? "✓" : "✗",
            get_task_comm_hook_status ? "✓" : "✗",
            connect_hook_status ? "✓" : "✗",
            readlinkat_hook_status ? "✓" : "✗",
            readlink_hook_status ? "✓" : "✗",
            openat_hook_status ? "✓" : "✗",
            getdents64_hook_status ? "✓" : "✗",
            atomic_read(&stat_maps_hidden),
            atomic_read(&stat_readlink_hidden),
            atomic_read(&stat_comm_hidden),
            atomic_read(&stat_connect_blocked),
            atomic_read(&stat_openat_blocked),
            atomic_read(&stat_fd_hidden)
        );
    } 
    else if (!strcmp(args, "ENABLE") || !strcmp(args, "EN")) {
        if (!frida_hide_enabled) {
            frida_hide_enabled = 1;
            frida_hide_install();
        }
        reply_len = snprintf(reply_msg, sizeof(reply_msg), "FridaHide enabled");
    } 
    else if (!strcmp(args, "DISABLE") || !strcmp(args, "DIS")) {
        if (frida_hide_enabled) {
            frida_hide_enabled = 0;
            frida_hide_uninstall();
        }
        reply_len = snprintf(reply_msg, sizeof(reply_msg), "FridaHide disabled");
    }
    else if (!strncmp(args, "PORT=", 5)) {
        int new_port;
        if (kstrtoint(args + 5, 10, &new_port) == 0) {
            TARGET_PORT = new_port;
            reply_len = snprintf(reply_msg, sizeof(reply_msg), 
                                "Port updated to %d", TARGET_PORT);
        } else {
            reply_len = snprintf(reply_msg, sizeof(reply_msg), "Invalid port");
        }
    }
    else if (!strncmp(args, "PACKAGE=", 8)) {
        strncpy(TARGET_PACKAGE, args + 8, sizeof(TARGET_PACKAGE) - 1);
        TARGET_PACKAGE[sizeof(TARGET_PACKAGE) - 1] = '\0';
        reply_len = snprintf(reply_msg, sizeof(reply_msg), 
                            "Package filter: %s", TARGET_PACKAGE);
    }
    else if (!strcmp(args, "VERBOSE")) {
        frida_hide_log_verbose = !frida_hide_log_verbose;
        reply_len = snprintf(reply_msg, sizeof(reply_msg), 
                            "Verbose logging: %s", 
                            frida_hide_log_verbose ? "ON" : "OFF");
    }
    else if (!strcmp(args, "RESET_STATS")) {
        atomic_set(&stat_maps_hidden, 0);
        atomic_set(&stat_readlink_hidden, 0);
        atomic_set(&stat_comm_hidden, 0);
        atomic_set(&stat_connect_blocked, 0);
        atomic_set(&stat_openat_blocked, 0);
        atomic_set(&stat_fd_hidden, 0);
        reply_len = snprintf(reply_msg, sizeof(reply_msg), "Statistics reset");
    }
    else {
        reply_len = snprintf(reply_msg, sizeof(reply_msg),
            "Unknown command. Available:\n"
            "  STATUS - Show status\n"
            "  ENABLE/DISABLE - Toggle module\n"
            "  PORT=<num> - Set target port\n"
            "  PACKAGE=<name> - Set target package\n"
            "  VERBOSE - Toggle verbose logging\n"
            "  RESET_STATS - Reset counters\n");
    }

    if (out_msg && outlen > 0 && reply_len > 0) {
        if (__arch_copy_to_user) {
            __arch_copy_to_user(out_msg, reply_msg, min(reply_len + 1, outlen));
        }
    }
    
    return 0;
}

KPM_INIT(frida_hide_init);
KPM_CTL0(frida_hide_ctl0);
KPM_EXIT(frida_hide_exit);
