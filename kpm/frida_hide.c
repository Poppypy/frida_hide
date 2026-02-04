#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/err.h>
#include <uapi/asm-generic/errno.h>
#include <hook.h>
#include <ksyms.h>

KPM_NAME("maps_filter");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Developer");
KPM_DESCRIPTION("Filter /proc/pid/maps to hide sensitive mappings");

// ==================== 日志宏 ====================
#define LOGV(fmt, ...) pr_info("maps_filter: " fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) pr_err("maps_filter: " fmt, ##__VA_ARGS__)

// ==================== 常量定义 ====================
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

struct vm_area_struct;

// ==================== 全局变量 ====================

static uint64_t show_map_vma_addr = 0;
static uint64_t show_smap_addr = 0;
static uint64_t show_smaps_rollup_addr = 0;

// 是否启用包名过滤
static int enable_package_filter = 0;

// ==================== 辅助函数（必须在使用前定义）====================

static size_t local_strlen(const char *s)
{
    size_t len = 0;
    if (s) {
        while (*s++) len++;
    }
    return len;
}

static void *local_memmem(const void *haystack, size_t haystacklen,
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

static int local_strcmp(const char *s1, const char *s2)
{
    while (*s1 && *s1 == *s2) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

// ==================== 隐藏规则 ====================

static const char *hidden_keywords[] = {
    "/data/adb/",
    "/data/adb/apatch/",
    "/data/adb/kpatch/",
    "apatch",
    "kpatch",
    "magisk",
    "/sbin/.magisk/",
    "/dev/.magisk/",
    "/system/xbin/su",
    "/system/bin/su",
    "supersu",
    "superuser",
    "xposed",
    "lsposed",
    "edxposed",
    "riru",
    "zygisk",
    "frida",
    "gadget",
    "gum-js",
    "linjector",
    "memfd:jit-cache",
    NULL
};

// 检查 maps 行是否需要隐藏
static int should_hide_mapping(const char *buf, size_t len)
{
    int i;
    if (!buf || len == 0) return 0;
    
    for (i = 0; hidden_keywords[i] != NULL; i++) {
        const char *keyword = hidden_keywords[i];
        size_t klen = local_strlen(keyword);
        
        if (local_memmem(buf, len, keyword, klen)) {
            return 1;
        }
    }
    
    return 0;
}

// 检查是否需要修改 rwx 权限显示
static int should_fix_rwx_permission(const char *buf, size_t len)
{
    const char *space = NULL;
    const char *perms;
    size_t i;
    
    if (!buf || len < 30) return 0;
    
    for (i = 0; i < len; i++) {
        if (buf[i] == ' ') {
            space = &buf[i];
            break;
        }
    }
    
    if (!space || (size_t)(space - buf + 5) >= len)
        return 0;
    
    perms = space + 1;
    
    if (perms[0] == 'r' && perms[1] == 'w' && 
        perms[2] == 'x' && perms[3] == 'p') {
        
        if (local_memmem(buf, len, "libc.so", 7) ||
            local_memmem(buf, len, "/libc-", 6) ||
            local_memmem(buf, len, "/apex/com.android.runtime/lib", 29)) {
            return 1;
        }
    }
    
    return 0;
}

// ==================== Hook 回调函数 ====================

static void before_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    
    args->local.data0 = 0;
    args->local.data1 = 0;
    
    if (!m || !m->buf)
        return;
    
    args->local.data0 = (uint64_t)m->count;
    args->local.data1 = 1;
}

static void after_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m;
    size_t old_count;
    char *new_data;
    size_t new_len;
    
    if (!args->local.data1)
        return;
    
    m = (struct seq_file *)args->arg0;
    
    if (!m || !m->buf)
        return;
    
    old_count = (size_t)args->local.data0;
    
    if (m->count <= old_count)
        return;
    
    new_data = m->buf + old_count;
    new_len = m->count - old_count;
    
    if (should_hide_mapping(new_data, new_len)) {
        m->count = old_count;
        LOGV("hidden mapping line\n");
        return;
    }
    
    if (should_fix_rwx_permission(new_data, new_len)) {
        char *space = NULL;
        size_t i;
        
        for (i = 0; i < new_len; i++) {
            if (new_data[i] == ' ') {
                space = &new_data[i];
                break;
            }
        }
        
        if (space && (size_t)(space - new_data + 5) < new_len) {
            char *perms = space + 1;
            if (perms[0] == 'r' && perms[1] == 'w' && 
                perms[2] == 'x' && perms[3] == 'p') {
                perms[1] = '-';
                LOGV("fixed rwx -> r-x permission\n");
            }
        }
    }
}

static void before_show_smap(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    
    args->local.data0 = 0;
    args->local.data1 = 0;
    
    if (!m || !m->buf)
        return;
    
    args->local.data0 = (uint64_t)m->count;
    args->local.data1 = 1;
}

static void after_show_smap(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m;
    size_t old_count;
    char *new_data;
    size_t new_len;
    
    if (!args->local.data1)
        return;
    
    m = (struct seq_file *)args->arg0;
    
    if (!m || !m->buf)
        return;
    
    old_count = (size_t)args->local.data0;
    
    if (m->count <= old_count)
        return;
    
    new_data = m->buf + old_count;
    new_len = m->count - old_count;
    
    if (should_hide_mapping(new_data, new_len)) {
        m->count = old_count;
        LOGV("hidden smap entry\n");
        return;
    }
    
    if (should_fix_rwx_permission(new_data, new_len)) {
        char *space = NULL;
        size_t i;
        
        for (i = 0; i < new_len; i++) {
            if (new_data[i] == ' ') {
                space = &new_data[i];
                break;
            }
        }
        
        if (space && (size_t)(space - new_data + 5) < new_len) {
            char *perms = space + 1;
            if (perms[0] == 'r' && perms[1] == 'w' && 
                perms[2] == 'x' && perms[3] == 'p') {
                perms[1] = '-';
                LOGV("fixed smap rwx permission\n");
            }
        }
    }
}

// ==================== 模块入口 ====================

static long maps_filter_init(const char *args, const char *event, void *__user reserved)
{
    int hooks_installed = 0;
    int hooks_failed = 0;
    hook_err_t err;
    
    LOGV("loading, version: %s\n", MYKPM_VERSION);
    
    // 1. Hook show_map_vma
    show_map_vma_addr = kallsyms_lookup_name("show_map_vma");
    if (show_map_vma_addr) {
        err = hook_wrap2((void *)show_map_vma_addr,
                         before_show_map_vma,
                         after_show_map_vma,
                         (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("show_map_vma hooked at 0x%lx\n", (unsigned long)show_map_vma_addr);
            hooks_installed++;
        } else {
            LOGE("hook show_map_vma failed: %d\n", err);
            show_map_vma_addr = 0;
            hooks_failed++;
        }
    } else {
        LOGV("show_map_vma not found, trying show_vma\n");
        
        show_map_vma_addr = kallsyms_lookup_name("show_vma");
        if (show_map_vma_addr) {
            err = hook_wrap2((void *)show_map_vma_addr,
                             before_show_map_vma,
                             after_show_map_vma,
                             (void *)0);
            if (err == HOOK_NO_ERR) {
                LOGV("show_vma hooked at 0x%lx\n", (unsigned long)show_map_vma_addr);
                hooks_installed++;
            } else {
                show_map_vma_addr = 0;
                hooks_failed++;
            }
        }
    }
    
    // 2. Hook show_smap
    show_smap_addr = kallsyms_lookup_name("show_smap");
    if (show_smap_addr) {
        err = hook_wrap2((void *)show_smap_addr,
                         before_show_smap,
                         after_show_smap,
                         (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("show_smap hooked at 0x%lx\n", (unsigned long)show_smap_addr);
            hooks_installed++;
        } else {
            LOGE("hook show_smap failed: %d\n", err);
            show_smap_addr = 0;
            hooks_failed++;
        }
    } else {
        LOGV("show_smap not found\n");
    }
    
    // 3. Hook show_smaps_rollup
    show_smaps_rollup_addr = kallsyms_lookup_name("show_smaps_rollup");
    if (show_smaps_rollup_addr) {
        err = hook_wrap2((void *)show_smaps_rollup_addr,
                         before_show_smap,
                         after_show_smap,
                         (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("show_smaps_rollup hooked at 0x%lx\n", (unsigned long)show_smaps_rollup_addr);
            hooks_installed++;
        } else {
            LOGV("hook show_smaps_rollup failed: %d\n", err);
            show_smaps_rollup_addr = 0;
        }
    }
    
    LOGV("init complete: %d hooks installed, %d failed\n", hooks_installed, hooks_failed);
    
    if (hooks_installed == 0) {
        LOGE("no hooks installed, module may not work\n");
        return -1;
    }
    
    return 0;
}

// ==================== 控制接口 ====================

static long maps_filter_control0(const char *args, char *__user out_msg, int outlen)
{
    char msg[64] = "maps_filter: OK";
    int len;
    
    LOGV("control0 called, args: %s\n", args ? args : "null");
    
    if (args && local_strcmp(args, "status") == 0) {
        msg[0] = 's';
        msg[1] = 't';
        msg[2] = 'a';
        msg[3] = 't';
        msg[4] = 'u';
        msg[5] = 's';
        msg[6] = ':';
        msg[7] = ' ';
        msg[8] = 'O';
        msg[9] = 'K';
        msg[10] = '\0';
    }
    
    len = local_strlen(msg);
    if (out_msg && outlen > 0) {
        if (len >= outlen) len = outlen - 1;
        compat_copy_to_user(out_msg, msg, len + 1);
    }
    
    return 0;
}

// ==================== 模块退出 ====================

static long maps_filter_exit(void *__user reserved)
{
    LOGV("unloading...\n");
    
    if (show_map_vma_addr) {
        unhook((void *)show_map_vma_addr);
        LOGV("show_map_vma unhooked\n");
        show_map_vma_addr = 0;
    }
    
    if (show_smap_addr) {
        unhook((void *)show_smap_addr);
        LOGV("show_smap unhooked\n");
        show_smap_addr = 0;
    }
    
    if (show_smaps_rollup_addr) {
        unhook((void *)show_smaps_rollup_addr);
        LOGV("show_smaps_rollup unhooked\n");
        show_smaps_rollup_addr = 0;
    }
    
    LOGV("unloaded\n");
    return 0;
}

// ==================== KPM 宏注册 ====================

KPM_INIT(maps_filter_init);
KPM_CTL0(maps_filter_control0);
KPM_EXIT(maps_filter_exit);
