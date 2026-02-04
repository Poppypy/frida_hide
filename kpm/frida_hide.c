#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/errno.h>
#include <syscall.h>
#include <asm/current.h>
#include <uapi/asm-generic/unistd.h>

KPM_NAME("kpm-frida-hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("popy");
KPM_DESCRIPTION("Hide Frida artifacts from detection");

extern char *strstr(const char *, const char *);
extern char *strchr(const char *, int);
extern int strcmp(const char *, const char *);
extern int strncmp(const char *, const char *, size_t);
extern size_t strlen(const char *);
extern char *strcpy(char *, const char *);
extern char *strncpy(char *, const char *, size_t);
extern void *memset(void *, int, size_t);
extern void *memcpy(void *, const void *, size_t);
extern void *memmove(void *, const void *, size_t);

#define GFP_KERNEL 0xCC0
#define AF_INET 2
#define FRIDA_PORT_START 27042
#define FRIDA_PORT_END   27049
#define MAX_PATH 256
#define MAX_BUF  4096

struct in_addr {
    unsigned int s_addr;
};

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    struct in_addr sin_addr;
    unsigned char  __pad[8];
};

typedef void *(*kmalloc_t)(size_t size, unsigned int flags);
typedef void (*kfree_t)(const void *objp);
typedef long (*copy_from_user_t)(void *to, const void __user *from, long n);
typedef long (*strncpy_from_user_t)(char *dst, const char __user *src, long count);

static kmalloc_t kfunc_kmalloc = NULL;
static kfree_t kfunc_kfree = NULL;
static copy_from_user_t kfunc_copy_from_user = NULL;
static strncpy_from_user_t kfunc_strncpy_from_user = NULL;

static const char *HIDE_KEYWORDS[] = {
    "frida", "gum-js", "gdbus", "gmain", "linjector",
    "re.frida.server", "gadget", "frida-agent", "pool-frida"
};
#define HIDE_KEYWORDS_COUNT (sizeof(HIDE_KEYWORDS) / sizeof(HIDE_KEYWORDS[0]))

static int hook_enabled = 1;

static inline unsigned short my_ntohs(unsigned short netshort) {
    return (netshort >> 8) | (netshort << 8);
}

static inline void *my_kzalloc(size_t size, unsigned int flags) {
    if (!kfunc_kmalloc) return NULL;
    void *ptr = kfunc_kmalloc(size, flags);
    if (ptr) memset(ptr, 0, size);
    return ptr;
}

static bool contains_frida_keyword(const char *str) {
    if (!str) return false;
    for (int i = 0; i < HIDE_KEYWORDS_COUNT; i++) {
        if (strstr(str, HIDE_KEYWORDS[i])) return true;
    }
    return false;
}

static bool is_proc_maps_path(const char *path) {
    if (!path) return false;
    if (strstr(path, "/proc/") && strstr(path, "/maps")) return true;
    return false;
}

static bool is_proc_comm_path(const char *path) {
    if (!path) return false;
    if (strstr(path, "/proc/") && strstr(path, "/comm")) return true;
    return false;
}

static bool is_proc_task_path(const char *path) {
    if (!path) return false;
    if (strstr(path, "/proc/") && strstr(path, "/task")) return true;
    return false;
}

// 存储每个fd对应的路径信息
#define MAX_FD_TRACK 256
static struct {
    int fd;
    int type; // 0=none, 1=maps, 2=comm
} fd_track[MAX_FD_TRACK];

static void track_fd(int fd, int type) {
    for (int i = 0; i < MAX_FD_TRACK; i++) {
        if (fd_track[i].fd == 0 || fd_track[i].fd == fd) {
            fd_track[i].fd = fd;
            fd_track[i].type = type;
            return;
        }
    }
}

static int get_fd_type(int fd) {
    for (int i = 0; i < MAX_FD_TRACK; i++) {
        if (fd_track[i].fd == fd) {
            return fd_track[i].type;
        }
    }
    return 0;
}

static void untrack_fd(int fd) {
    for (int i = 0; i < MAX_FD_TRACK; i++) {
        if (fd_track[i].fd == fd) {
            fd_track[i].fd = 0;
            fd_track[i].type = 0;
            return;
        }
    }
}

// Hook openat - 跟踪打开的文件
static void before_openat(hook_fargs4_t *args, void *udata) {
    args->local.data0 = 0;
}

static void after_openat(hook_fargs4_t *args, void *udata) {
    if (!hook_enabled) return;
    
    long fd = (long)args->ret;
    if (fd < 0) return;
    
    const char __user *filename = (const char __user *)syscall_argn(args, 1);
    if (!filename || !kfunc_strncpy_from_user) return;
    
    char path[MAX_PATH];
    memset(path, 0, sizeof(path));
    
    long len = kfunc_strncpy_from_user(path, filename, MAX_PATH - 1);
    if (len <= 0) return;
    
    if (is_proc_maps_path(path)) {
        track_fd(fd, 1);
    } else if (is_proc_comm_path(path)) {
        track_fd(fd, 2);
    }
}

// Hook read - 过滤读取内容
static void before_read(hook_fargs3_t *args, void *udata) {
    args->local.data0 = 0;
    args->local.data1 = 0;
}

static void after_read(hook_fargs3_t *args, void *udata) {
    if (!hook_enabled) return;
    
    long ret = (long)args->ret;
    if (ret <= 0) return;
    
    int fd = (int)syscall_argn(args, 0);
    int fd_type = get_fd_type(fd);
    if (fd_type == 0) return;
    
    char __user *ubuf = (char __user *)syscall_argn(args, 1);
    if (!ubuf || !kfunc_kmalloc || !kfunc_kfree || !kfunc_copy_from_user) return;
    
    char *kbuf = my_kzalloc(ret + 1, GFP_KERNEL);
    if (!kbuf) return;
    
    if (kfunc_copy_from_user(kbuf, ubuf, ret)) {
        kfunc_kfree(kbuf);
        return;
    }
    kbuf[ret] = '\0';
    
    if (fd_type == 2) {
        // /proc/xxx/comm - 检查线程名
        if (contains_frida_keyword(kbuf)) {
            pr_info("frida-hide: hiding comm: %s\n", kbuf);
            memset(kbuf, 0, ret);
            strcpy(kbuf, "main\n");
            int new_len = strlen(kbuf);
            compat_copy_to_user(ubuf, kbuf, new_len);
            args->ret = new_len;
        }
    } else if (fd_type == 1) {
        // /proc/xxx/maps - 过滤frida相关行
        char *new_buf = my_kzalloc(ret + 1, GFP_KERNEL);
        if (!new_buf) {
            kfunc_kfree(kbuf);
            return;
        }
        
        char *src = kbuf;
        char *dst = new_buf;
        long new_len = 0;
        
        while (*src) {
            char *line_end = strchr(src, '\n');
            int line_len;
            
            if (line_end) {
                line_len = line_end - src + 1;
            } else {
                line_len = strlen(src);
            }
            
            // 临时保存这一行
            char line[512];
            if (line_len < 512) {
                memcpy(line, src, line_len);
                line[line_len] = '\0';
                
                // 检查是否包含frida关键词
                if (!contains_frida_keyword(line)) {
                    memcpy(dst, src, line_len);
                    dst += line_len;
                    new_len += line_len;
                } else {
                    pr_info("frida-hide: filtering maps line\n");
                }
            }
            
            src += line_len;
            if (!line_end) break;
        }
        
        if (new_len > 0 && new_len != ret) {
            compat_copy_to_user(ubuf, new_buf, new_len);
            args->ret = new_len;
        }
        
        kfunc_kfree(new_buf);
    }
    
    kfunc_kfree(kbuf);
}

// Hook close - 清理跟踪
static void before_close(hook_fargs1_t *args, void *udata) {
    int fd = (int)syscall_argn(args, 0);
    untrack_fd(fd);
}

static void after_close(hook_fargs1_t *args, void *udata) {
}

// Hook connect - 阻止连接frida端口
static void before_connect(hook_fargs3_t *args, void *udata) {
    if (!hook_enabled || !kfunc_copy_from_user) return;
    
    int addrlen = (int)syscall_argn(args, 2);
    if (addrlen < (int)sizeof(struct sockaddr_in)) return;
    
    void __user *uservaddr = (void __user *)syscall_argn(args, 1);
    if (!uservaddr) return;
    
    struct sockaddr_in kaddr;
    if (kfunc_copy_from_user(&kaddr, uservaddr, sizeof(kaddr))) return;
    
    if (kaddr.sin_family == AF_INET) {
        unsigned int port = my_ntohs(kaddr.sin_port);
        if (port >= FRIDA_PORT_START && port <= FRIDA_PORT_END) {
            pr_info("frida-hide: blocking port %d\n", port);
            args->ret = (uint64_t)(-ECONNREFUSED);
            args->skip_origin = true;
        }
    }
}

static void after_connect(hook_fargs3_t *args, void *udata) {
}

static long frida_hide_init(const char *args, const char *event, void *__user reserved) {
    pr_info("frida-hide: initializing...\n");
    
    memset(fd_track, 0, sizeof(fd_track));
    
    kfunc_kmalloc = (kmalloc_t)kallsyms_lookup_name("__kmalloc");
    if (!kfunc_kmalloc) kfunc_kmalloc = (kmalloc_t)kallsyms_lookup_name("kmalloc");
    kfunc_kfree = (kfree_t)kallsyms_lookup_name("kfree");
    kfunc_copy_from_user = (copy_from_user_t)kallsyms_lookup_name("_copy_from_user");
    if (!kfunc_copy_from_user) kfunc_copy_from_user = (copy_from_user_t)kallsyms_lookup_name("copy_from_user");
    kfunc_strncpy_from_user = (strncpy_from_user_t)kallsyms_lookup_name("strncpy_from_user");
    
    if (!kfunc_kmalloc || !kfunc_kfree || !kfunc_copy_from_user || !kfunc_strncpy_from_user) {
        pr_err("frida-hide: failed to find kernel functions\n");
        return -1;
    }
    
    pr_info("frida-hide: kernel functions resolved\n");
    
    hook_err_t err;
    
    err = inline_hook_syscalln(__NR_openat, 4, before_openat, after_openat, NULL);
    if (err) pr_err("frida-hide: hook openat failed: %d\n", err);
    else pr_info("frida-hide: hook openat ok\n");
    
    err = inline_hook_syscalln(__NR_read, 3, before_read, after_read, NULL);
    if (err) pr_err("frida-hide: hook read failed: %d\n", err);
    else pr_info("frida-hide: hook read ok\n");
    
    err = inline_hook_syscalln(__NR_close, 1, before_close, after_close, NULL);
    if (err) pr_err("frida-hide: hook close failed: %d\n", err);
    else pr_info("frida-hide: hook close ok\n");
    
    err = inline_hook_syscalln(__NR_connect, 3, before_connect, after_connect, NULL);
    if (err) pr_err("frida-hide: hook connect failed: %d\n", err);
    else pr_info("frida-hide: hook connect ok\n");
    
    pr_info("frida-hide: initialized successfully\n");
    return 0;
}

static long frida_hide_control(const char *args, char *__user out_msg, int outlen) {
    if (!args) return -1;
    
    if (strcmp(args, "stop") == 0) {
        hook_enabled = 0;
        pr_info("frida-hide: disabled\n");
    } else if (strcmp(args, "start") == 0) {
        hook_enabled = 1;
        pr_info("frida-hide: enabled\n");
    }
    
    char msg[32] = "ok";
    compat_copy_to_user(out_msg, msg, sizeof(msg));
    return 0;
}

static long frida_hide_exit(void *__user reserved) {
    pr_info("frida-hide: unloading...\n");
    
    inline_unhook_syscalln(__NR_openat, before_openat, after_openat);
    inline_unhook_syscalln(__NR_read, before_read, after_read);
    inline_unhook_syscalln(__NR_close, before_close, after_close);
    inline_unhook_syscalln(__NR_connect, before_connect, after_connect);
    
    pr_info("frida-hide: unloaded\n");
    return 0;
}

KPM_INIT(frida_hide_init);
KPM_CTL0(frida_hide_control);
KPM_EXIT(frida_hide_exit);
