#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <uapi/asm-generic/errno.h>
#include <hook.h>
#include <ksyms.h>

KPM_NAME("frida_hide");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Security Researcher");
KPM_DESCRIPTION("Hide Frida injection from detection");

// ==================== 常量定义 ====================
#define FRIDA_PORT 27042
#define LOGV(fmt, ...) pr_info("frida_hide: " fmt, ##__VA_ARGS__)

// ==================== 结构体定义 ====================

struct seq_file {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
};

struct sockaddr_in {
    short sin_family;
    unsigned short sin_port;
    unsigned int sin_addr;
    char sin_zero[8];
};

// ==================== 全局变量 ====================

static uint64_t show_map_vma_addr = 0;

// ==================== 辅助函数 ====================

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

static size_t my_strlen(const char *s)
{
    size_t len = 0;
    if (s) {
        while (*s++) len++;
    }
    return len;
}

static int contains_frida_string(const char *buf, size_t len)
{
    if (!buf || len == 0) 
        return 0;
    
    static const char *keywords[] = {
        "frida-agent",
        "frida",
        "gum-js-loop",
        "gmain",
    };
    
    int num = sizeof(keywords) / sizeof(keywords[0]);
    for (int i = 0; i < num; i++) {
        if (my_memmem(buf, len, keywords[i], my_strlen(keywords[i])))
            return 1;
    }
    return 0;
}

// ==================== Hook 函数 ====================

// show_map_vma hook - 隐藏 /proc/pid/maps 中的 frida
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
            LOGV("hidden frida from maps\n");
        }
    }
}

// ==================== 模块入口 ====================

static long frida_hide_init(const char *args, const char *event, void *__user reserved)
{
    LOGV("loading, version: %s\n", MYKPM_VERSION);
    
    // Hook show_map_vma
    show_map_vma_addr = kallsyms_lookup_name("show_map_vma");
    if (show_map_vma_addr) {
        hook_err_t err = hook_wrap2((void *)show_map_vma_addr, 
                                    before_show_map_vma, 
                                    after_show_map_vma, 
                                    (void *)0);
        if (err == HOOK_NO_ERR) {
            LOGV("show_map_vma hooked at 0x%llx\n", show_map_vma_addr);
        } else {
            LOGV("hook show_map_vma failed: %d\n", err);
            show_map_vma_addr = 0;
        }
    } else {
        LOGV("show_map_vma not found\n");
    }
    
    LOGV("loaded\n");
    return 0;
}

static long frida_hide_control0(const char *args, char *__user out_msg, int outlen)
{
    LOGV("control0 called\n");
    
    char msg[] = "frida_hide running";
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
    
    LOGV("unloaded\n");
    return 0;
}

KPM_INIT(frida_hide_init);
KPM_CTL0(frida_hide_control0);
KPM_EXIT(frida_hide_exit);
