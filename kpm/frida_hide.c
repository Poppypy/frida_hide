#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/err.h>
#include <asm/current.h>
#include <syscall.h>

KPM_NAME("kpm-frida-hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("popy");
KPM_DESCRIPTION("Hide Frida artifacts from detection");

// ============ 结构体定义 ============
struct seq_file {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
    size_t pad;
    loff_t index;
    loff_t read_pos;
    u64 version;
    void *lock[4];
    const void *op;
    int poll_event;
    const void *file;
    void *private;
};

struct sockaddr_in {
    short sin_family;
    unsigned short sin_port;
    unsigned int sin_addr;
    char sin_zero[8];
};

// ============ 函数指针类型定义 ============
typedef char *(*find_get_task_comm)(char *buf, size_t buf_size, struct task_struct *tsk);
typedef unsigned long (*find_arch_copy_from_user)(void *to, const void __user *from, unsigned long n);
typedef void *(*find_memdup_user)(const void __user *src, size_t len);
typedef void (*find_kfree)(const void *ptr);

// ============ 全局变量 ============
static void *show_map_vma = NULL;
static find_get_task_comm got_get_task_comm = NULL;
static find_arch_copy_from_user got_arch_copy_from_user = NULL;
static find_memdup_user got_memdup_user = NULL;
static find_kfree got_kfree = NULL;

static bool show_map_vma_hooked = false;
static bool get_task_comm_hooked = false;
static bool connect_hooked = false;

// ============ 工具函数 ============
static void *memmem_local(const void *haystack, size_t haystacklen, 
                          const void *needle, size_t needlelen)
{
    if (!haystack || !needle || haystacklen < needlelen || needlelen == 0)
        return NULL;
    
    for (size_t i = 0; i <= haystacklen - needlelen; ++i) {
        if (memcmp((const char *)haystack + i, needle, needlelen) == 0)
            return (void *)((const char *)haystack + i);
    }
    return NULL;
}

static bool is_hiden_module(struct seq_file *m)
{
    if (!m || !m->buf || m->count == 0) 
        return false;
    
    static const char *keywords[] = {
        "frida-agent",
        "frida",
        "gum-js-loop",
        "GumJS",
        "gmain",
        NULL
    };

    for (int i = 0; keywords[i] != NULL; ++i) {
        if (memmem_local(m->buf, m->count, keywords[i], strlen(keywords[i])))
            return true;
    }
    return false;
}

static bool is_hiden_comm(const char *comm)
{
    static const char *keywords[] = {
        "gmain",
        "gum-js-loop",
        "gdbus",
        "pool-frida",
        "linjector",
    };

    for (int i = 0; i < sizeof(keywords) / sizeof(keywords[0]); i++) {
        if (strstr(comm, keywords[i])) {
            return true;
        }
    }
    return false;
}

static inline u16 ntohs_local(u16 port) 
{
    return (port >> 8) | (port << 8);
}

// ============ Hook 回调函数 ============
static void before_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    args->local.data0 = 0;
    
    if (m && m->buf) {
        args->local.data0 = m->count;
    }
}

static void after_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    
    if (m && m->buf && args->local.data0) {
        if (is_hiden_module(m)) {
            pr_info("kpm-frida-hide: maps hide -> frida-agent\n");
            m->count = args->local.data0;
        }
    }
}

static void __attribute__((optimize("O0"))) after_get_task_comm(hook_fargs3_t *args, void *udata)
{
    char *comm = (char *)args->arg0;
    size_t comm_buf_len = (size_t)args->arg1;
    
    if (!comm || !comm_buf_len)
        return;
    
    if (is_hiden_comm(comm)) {
        pr_info("kpm-frida-hide: get_task_comm hide -> %s\n", comm);
        size_t hide_len = strlen(comm);
        for (size_t i = 0; i < hide_len; i++) {
            comm[i] = ' ';
        }
    }
}

static void before_connect(hook_fargs3_t *args, void *udata)
{
    struct sockaddr_in addr_kernel;
    const void __user *addr = (const void __user *)syscall_argn(args, 1);
    
    if (!addr || !got_memdup_user || !got_kfree || !got_get_task_comm)
        return;

    // 安全读取用户空间数据
    void *data = got_memdup_user(addr, sizeof(struct sockaddr_in));
    if (IS_ERR(data)) {
        return;
    }
    
    memcpy(&addr_kernel, data, sizeof(struct sockaddr_in));
    got_kfree(data);

    u16 port = ntohs_local(addr_kernel.sin_port);
    if (port == 27042) {
        char comm[16];
        got_get_task_comm(comm, sizeof(comm), current);

        pr_warn("kpm-frida-hide: connect to frida-agent, comm: %s, port: %d\n", 
                comm, port);
        
        if (!strstr(comm, "adbd")) {
            pr_warn("kpm-frida-hide: connect blocked, comm: %s, port: %d\n", 
                    comm, port);
            args->skip_origin = 1;
            args->ret = -ECONNREFUSED;
        }
    }
}

// ============ 初始化和清理 ============
static long install(const char *args, const char *event, void *__user reserved)
{
    hook_err_t err;
    
    pr_info("kpm-frida-hide: installing...\n");

    // 查找符号
    show_map_vma = (void *)kallsyms_lookup_name("show_map_vma");
    got_get_task_comm = (find_get_task_comm)kallsyms_lookup_name("__get_task_comm");
    got_arch_copy_from_user = (find_arch_copy_from_user)kallsyms_lookup_name("__arch_copy_from_user");
    got_memdup_user = (find_memdup_user)kallsyms_lookup_name("memdup_user");
    got_kfree = (find_kfree)kallsyms_lookup_name("kfree");

    // Hook show_map_vma
    if (show_map_vma) {
        err = hook_wrap2(show_map_vma, before_show_map_vma, after_show_map_vma, NULL);
        if (err == HOOK_NO_ERR) {
            show_map_vma_hooked = true;
            pr_info("kpm-frida-hide: show_map_vma hooked\n");
        } else {
            pr_err("kpm-frida-hide: show_map_vma hook failed: %d\n", err);
        }
    } else {
        pr_warn("kpm-frida-hide: show_map_vma not found\n");
    }

    // Hook __get_task_comm
    if (got_get_task_comm) {
        err = hook_wrap3(got_get_task_comm, NULL, after_get_task_comm, NULL);
        if (err == HOOK_NO_ERR) {
            get_task_comm_hooked = true;
            pr_info("kpm-frida-hide: __get_task_comm hooked\n");
        } else {
            pr_err("kpm-frida-hide: __get_task_comm hook failed: %d\n", err);
        }
    } else {
        pr_warn("kpm-frida-hide: __get_task_comm not found\n");
    }

    // Hook connect syscall
    if (got_memdup_user && got_kfree && got_get_task_comm) {
        err = fp_hook_syscalln(__NR_connect, 3, before_connect, NULL, NULL);
        if (err == HOOK_NO_ERR) {
            connect_hooked = true;
            pr_info("kpm-frida-hide: connect syscall hooked\n");
        } else {
            pr_err("kpm-frida-hide: connect syscall hook failed: %d\n", err);
        }
    } else {
        pr_warn("kpm-frida-hide: missing symbols for connect hook\n");
    }

    pr_info("kpm-frida-hide: installation complete\n");
    return 0;
}

static long uninstall(void *__user reserved)
{
    pr_info("kpm-frida-hide: uninstalling...\n");

    if (show_map_vma_hooked && show_map_vma) {
        unhook(show_map_vma);
        show_map_vma_hooked = false;
        pr_info("kpm-frida-hide: show_map_vma unhooked\n");
    }

    if (get_task_comm_hooked && got_get_task_comm) {
        unhook(got_get_task_comm);
        get_task_comm_hooked = false;
        pr_info("kpm-frida-hide: __get_task_comm unhooked\n");
    }

    if (connect_hooked) {
        fp_unhook_syscalln(__NR_connect, before_connect, NULL);
        connect_hooked = false;
        pr_info("kpm-frida-hide: connect syscall unhooked\n");
    }

    // 清理指针
    show_map_vma = NULL;
    got_get_task_comm = NULL;
    got_arch_copy_from_user = NULL;
    got_memdup_user = NULL;
    got_kfree = NULL;

    pr_info("kpm-frida-hide: uninstall complete\n");
    return 0;
}

KPM_INIT(install);
KPM_EXIT(uninstall);
