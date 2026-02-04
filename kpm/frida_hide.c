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
KPM_VERSION("1.0.0");
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
    // 其他字段省略
};

struct vm_area_struct;

// ==================== 全局变量 ====================

static uint64_t show_map_vma_addr = 0;
static uint64_t show_smap_addr = 0;
static uint64_t show_smaps_rollup_addr = 0;
// ==================== 隐藏规则 ====================

// 需要隐藏的路径关键词
static const char *hidden_keywords[] = {
    // APatch 相关
    "/data/adb/",
    "/data/adb/apatch/",
    "/data/adb/kpatch/",
    "apatch",
    "kpatch",
    
    // Magisk 相关
    "magisk",
    "/sbin/.magisk/",
    "/dev/.magisk/",
    
    // Root 相关
    "/system/xbin/su",
    "/system/bin/su",
    "supersu",
    "superuser",
    
    // Xposed/LSPosed 相关
    "xposed",
    "lsposed",
    "edxposed",
    "riru",
    "zygisk",
    
    // Frida 相关
    "frida",
    "gadget",
    "gum-js",
    "linjector",
    
    // 其他检测目标
    "memfd:jit-cache",
    
    NULL  // 结束标记
};

// 检查 maps 行是否需要隐藏
static int should_hide_mapping(const char *buf, size_t len)
{
    if (!buf || len == 0) return 0;
    
    for (int i = 0; hidden_keywords[i] != NULL; i++) {
        const char *keyword = hidden_keywords[i];
        size_t klen = my_strlen(keyword);
        
        if (my_memmem(buf, len, keyword, klen)) {
            return 1;
        }
    }
    
    return 0;
}

// 检查是否需要修改 rwx 权限显示
// maps 格式: 7f8a4c000000-7f8a4c021000 rwxp 00000000 00:00 0 /path
static int should_fix_rwx_permission(const char *buf, size_t len)
{
    if (!buf || len < 30) return 0;
    
    // 查找权限字段位置（第一个空格后）
    const char *space = NULL;
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == ' ') {
            space = &buf[i];
            break;
        }
    }
    
    if (!space || (size_t)(space - buf + 5) >= len)
        return 0;
    
    const char *perms = space + 1;
    
    // 检查是否是 rwxp（可读可写可执行私有）
    if (perms[0] == 'r' && perms[1] == 'w' && 
        perms[2] == 'x' && perms[3] == 'p') {
        
        // 检查是否是 libc.so（正常不应该有 rwx）
        if (my_memmem(buf, len, "libc.so", 7) ||
            my_memmem(buf, len, "/libc-", 6) ||
            my_memmem(buf, len, "/apex/com.android.runtime/lib", 29)) {
            return 1;
        }
    }
    
    return 0;
}
// ==================== Hook 回调函数 ====================

/*
 * show_map_vma 函数原型:
 * static void show_map_vma(struct seq_file *m, struct vm_area_struct *vma)
 * 
 * 这个函数负责输出 /proc/pid/maps 的每一行
 * 我们在 before 中记录当前 count，在 after 中检查新增内容
 */

// show_map_vma 前置 Hook
static void before_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    
    // 保存当前 count 到 local.data0
    args->local.data0 = 0;
    args->local.data1 = 0;  // 标记是否需要处理
    
    if (!m || !m->buf)
        return;
    
    // 只处理 App 进程（可选）
    // if (!is_app_process())
    //     return;
    
    args->local.data0 = (uint64_t)m->count;
    args->local.data1 = 1;  // 标记需要处理
}

// show_map_vma 后置 Hook
static void after_show_map_vma(hook_fargs2_t *args, void *udata)
{
    // 检查是否需要处理
    if (!args->local.data1)
        return;
    
    struct seq_file *m = (struct seq_file *)args->arg0;
    
    if (!m || !m->buf)
        return;
    
    size_t old_count = (size_t)args->local.data0;
    
    // 检查是否有新内容写入
    if (m->count <= old_count)
        return;
    
    char *new_data = m->buf + old_count;
    size_t new_len = m->count - old_count;
    
    // 检查是否需要隐藏这一行
    if (should_hide_mapping(new_data, new_len)) {
        // 回滚 count，相当于删除这一行
        m->count = old_count;
        LOGV("hidden mapping line\n");
        return;
    }
    
    // 检查是否需要修复 rwx 权限
    if (should_fix_rwx_permission(new_data, new_len)) {
        // 查找权限字段并修改
        char *space = NULL;
        for (size_t i = 0; i < new_len; i++) {
            if (new_data[i] == ' ') {
                space = &new_data[i];
                break;
            }
        }
        
        if (space && (size_t)(space - new_data + 5) < new_len) {
            char *perms = space + 1;
            // 将 rwxp 改为 r-xp
            if (perms[0] == 'r' && perms[1] == 'w' && 
                perms[2] == 'x' && perms[3] == 'p') {
                perms[1] = '-';  // w -> -
                LOGV("fixed rwx -> r-x permission\n");
            }
        }
    }
}

/*
 * show_smap 函数原型:
 * static int show_smap(struct seq_file *m, void *v)
 * 
 * 用于 /proc/pid/smaps，格式更详细
 * 使用相同的处理逻辑
 */

// show_smap 前置 Hook（复用 show_map_vma 的逻辑）
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

// show_smap 后置 Hook
static void after_show_smap(hook_fargs2_t *args, void *udata)
{
    if (!args->local.data1)
        return;
    
    struct seq_file *m = (struct seq_file *)args->arg0;
    
    if (!m || !m->buf)
        return;
    
    size_t old_count = (size_t)args->local.data0;
    
    if (m->count <= old_count)
        return;
    
    char *new_data = m->buf + old_count;
    size_t new_len = m->count - old_count;
    
    // smaps 输出多行，检查第一行（包含路径）
    if (should_hide_mapping(new_data, new_len)) {
        m->count = old_count;
        LOGV("hidden smap entry\n");
        return;
    }
    
    // 修复权限
    if (should_fix_rwx_permission(new_data, new_len)) {
        char *space = NULL;
        for (size_t i = 0; i < new_len; i++) {
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
// ==================== 进程过滤（可选功能）====================

/*
 * 如果只想对特定包名的进程生效，可以启用进程过滤
 * 通过检查 /proc/pid/cmdline 来判断包名
 */

// 目标包名（可配置）
static const char *target_packages[] = {
    "com.target.app",
    "com.example.game",
    NULL  // 结束标记
};

// 是否启用包名过滤（0=对所有进程生效，1=只对目标包名生效）
static int enable_package_filter = 0;

// 获取当前进程的 cmdline
static int get_current_cmdline(char *buf, size_t buflen)
{
    if (!buf || buflen == 0)
        return -1;
    
    struct task_struct *task = current;
    struct mm_struct *mm;
    
    if (!task)
        return -1;
    
    mm = task->mm;
    if (!mm)
        return -1;
    
    // 读取 arg_start 到 arg_end 的内容
    unsigned long arg_start = mm->arg_start;
    unsigned long arg_end = mm->arg_end;
    
    if (arg_start >= arg_end)
        return -1;
    
    size_t len = arg_end - arg_start;
    if (len > buflen - 1)
        len = buflen - 1;
    
    // 从用户空间复制
    if (compat_copy_from_user(buf, (void __user *)arg_start, len))
        return -1;
    
    buf[len] = '\0';
    return 0;
}

// 检查当前进程是否是目标包名
static int is_target_package(void)
{
    if (!enable_package_filter)
        return 1;  // 未启用过滤，对所有进程生效
    
    char cmdline[256];
    if (get_current_cmdline(cmdline, sizeof(cmdline)) < 0)
        return 0;
    
    for (int i = 0; target_packages[i] != NULL; i++) {
        if (my_memmem(cmdline, my_strlen(cmdline), 
                      target_packages[i], my_strlen(target_packages[i]))) {
            return 1;
        }
    }
    
    return 0;
}

// 带进程过滤的 show_map_vma 前置 Hook
static void before_show_map_vma_filtered(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    
    args->local.data0 = 0;
    args->local.data1 = 0;
    
    if (!m || !m->buf)
        return;
    
    // 检查是否是目标进程
    if (!is_target_package())
        return;
    
    args->local.data0 = (uint64_t)m->count;
    args->local.data1 = 1;
}
// ==================== 控制接口 ====================

/*
 * control0 用于处理用户空间的控制命令
 * 可以通过 APatch Manager 或命令行工具调用
 */
static long maps_filter_control0(const char *args, char *__user out_msg, int outlen)
{
    char msg[128];
    int len;
    
    LOGV("control0 called, args: %s\n", args ? args : "null");
    
    // 解析命令
    if (!args || !*args) {
        // 无参数，返回状态
        len = snprintf(msg, sizeof(msg), 
                       "maps_filter: running, hooks=%d,%d",
                       show_map_vma_addr ? 1 : 0,
                       show_smap_addr ? 1 : 0,
                       show_smaps_rollup_addr ? 1 : 0);
    }
    else if (my_memmem(args, my_strlen(args), "status", 6)) {
        // 返回详细状态
        len = snprintf(msg, sizeof(msg),
                       "show_map_vma: 0x%llx\n"
                       "show_smap: 0x%llx\n"
                       "show_smaps_rollup: 0x%llx",
                       show_map_vma_addr,
                       show_smap_addr,
                       show_smaps_rollup_addr);
    }
    else if (my_memmem(args, my_strlen(args), "enable_filter", 13)) {
        // 启用包名过滤
        enable_package_filter = 1;
        len = snprintf(msg, sizeof(msg), "package filter enabled");
        LOGV("package filter enabled\n");
    }
    else if (my_memmem(args, my_strlen(args), "disable_filter", 14)) {
        // 禁用包名过滤
        enable_package_filter = 0;
        len = snprintf(msg, sizeof(msg), "package filter disabled");
        LOGV("package filter disabled\n");
    }
    else {
        len = snprintf(msg, sizeof(msg), "unknown command: %s", args);
    }
    
    // 复制结果到用户空间
    if (out_msg && outlen > 0) {
        if (len >= outlen) len = outlen - 1;
        compat_copy_to_user(out_msg, msg, len + 1);
    }
    
    return 0;
}

/*
 * control1 可用于添加/删除隐藏规则（高级功能）
 */
static long maps_filter_control1(void *a1, void *a2, void *a3)
{
    // 预留接口，可扩展
    return 0;
}

// ==================== 模块退出 ====================

static long maps_filter_exit(void *__user reserved)
{
    LOGV("unloading...\n");
    
    // 按顺序卸载所有 Hook
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
    
    LOGV("unloaded successfully\n");
    return 0;
}

// ==================== KPM 宏注册 ====================

KPM_INIT(maps_filter_init);
KPM_CTL0(maps_filter_control0);
KPM_CTL1(maps_filter_control1);
KPM_EXIT(maps_filter_exit);
