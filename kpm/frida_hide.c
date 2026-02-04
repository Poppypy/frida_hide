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
extern int strcmp(const char *, const char *);
extern size_t strlen(const char *);
extern void *memset(void *, int, size_t);
extern void *memmove(void *, const void *, size_t);

#define GFP_KERNEL 0xCC0
#define AF_INET 2
#define FRIDA_PORT_START 27042
#define FRIDA_PORT_END   27049

struct linux_dirent64 {
    u64            d_ino;
    s64            d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

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

static kmalloc_t kfunc_kmalloc = NULL;
static kfree_t kfunc_kfree = NULL;

static const char *HIDE_KEYWORDS[] = {
    "frida", "gum-js", "gdbus", "gmain", "linjector",
    "re.frida.server", "gadget", "frida-agent", "frida-server"
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

static bool should_hide(const char *name) {
    if (!name) return false;
    for (int i = 0; i < HIDE_KEYWORDS_COUNT; i++) {
        if (strstr(name, HIDE_KEYWORDS[i])) return true;
    }
    return false;
}

static void before_getdents64(hook_fargs3_t *args, void *udata) {
    args->local.data0 = 0;
}

static void after_getdents64(hook_fargs3_t *args, void *udata) {
    if (!hook_enabled) return;
    long ret = (long)args->ret;
    if (ret <= 0) return;
    
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)syscall_argn(args, 1);
    if (!dirent || !kfunc_kmalloc || !kfunc_kfree) return;
    
    struct linux_dirent64 *kdirent = my_kzalloc(ret, GFP_KERNEL);
    if (!kdirent) return;
    
    if (compat_copy_from_user(kdirent, dirent, ret)) {
        kfunc_kfree(kdirent);
        return;
    }
    
    struct linux_dirent64 *cur = kdirent;
    long pos = 0;
    long new_ret = ret;
    
    while (pos < new_ret) {
        unsigned short reclen = cur->d_reclen;
        if (reclen == 0) break;
        
        if (should_hide(cur->d_name)) {
            pr_info("frida-hide: hiding: %s\n", cur->d_name);
            long remaining = new_ret - pos - reclen;
            if (remaining > 0) memmove(cur, (char *)cur + reclen, remaining);
            new_ret -= reclen;
            continue;
        }
        pos += reclen;
        cur = (struct linux_dirent64 *)((char *)kdirent + pos);
    }
    
    if (new_ret > 0 && new_ret != ret) {
        compat_copy_to_user(dirent, kdirent, new_ret);
        args->ret = (uint64_t)new_ret;
    }
    kfunc_kfree(kdirent);
}

static void before_readlinkat(hook_fargs4_t *args, void *udata) {
    args->local.data0 = 0;
}

static void after_readlinkat(hook_fargs4_t *args, void *udata) {
    if (!hook_enabled) return;
    long ret = (long)args->ret;
    if (ret <= 0 || !kfunc_kmalloc || !kfunc_kfree) return;
    
    char __user *buf = (char __user *)syscall_argn(args, 2);
    int bufsiz = (int)syscall_argn(args, 3);
    if (!buf) return;
    
    char *kbuf = my_kzalloc(ret + 1, GFP_KERNEL);
    if (!kbuf) return;
    
    if (compat_copy_from_user(kbuf, buf, ret)) {
        kfunc_kfree(kbuf);
        return;
    }
    kbuf[ret] = '\0';
    
    if (should_hide(kbuf)) {
        pr_info("frida-hide: hiding link: %s\n", kbuf);
        args->ret = (uint64_t)(-ENOENT);
    }
    kfunc_kfree(kbuf);
}

static void before_connect(hook_fargs3_t *args, void *udata) {
    if (!hook_enabled) return;
    
    int addrlen = (int)syscall_argn(args, 2);
    if (addrlen < sizeof(struct sockaddr_in)) return;
    
    void __user *uservaddr = (void __user *)syscall_argn(args, 1);
    if (!uservaddr) return;
    
    struct sockaddr_in kaddr;
    if (compat_copy_from_user(&kaddr, uservaddr, sizeof(kaddr))) return;
    
    if (kaddr.sin_family == AF_INET) {
        unsigned int port = my_ntohs(kaddr.sin_port);
        if (port >= FRIDA_PORT_START && port <= FRIDA_PORT_END) {
            pr_info("frida-hide: blocking port %d\n", port);
            args->ret = (uint64_t)(-ECONNREFUSED);
            args->skip_origin = true;
        }
    }
}

static void after_connect(hook_fargs3_t *args, void *udata) {}

static long frida_hide_init(const char *args, const char *event, void *__user reserved) {
    pr_info("frida-hide: initializing...\n");
    
    kfunc_kmalloc = (kmalloc_t)kallsyms_lookup_name("__kmalloc");
    if (!kfunc_kmalloc) kfunc_kmalloc = (kmalloc_t)kallsyms_lookup_name("kmalloc");
    kfunc_kfree = (kfree_t)kallsyms_lookup_name("kfree");
    
    if (!kfunc_kmalloc || !kfunc_kfree) {
        pr_err("frida-hide: failed to find kmalloc/kfree\n");
        return -1;
    }
    
    hook_err_t err;
    
    err = inline_hook_syscalln(__NR_getdents64, 3, before_getdents64, after_getdents64, NULL);
    if (err) pr_err("frida-hide: hook getdents64 failed: %d\n", err);
    else pr_info("frida-hide: hook getdents64 ok\n");
    
    err = inline_hook_syscalln(__NR_readlinkat, 4, before_readlinkat, after_readlinkat, NULL);
    if (err) pr_err("frida-hide: hook readlinkat failed: %d\n", err);
    else pr_info("frida-hide: hook readlinkat ok\n");
    
    err = inline_hook_syscalln(__NR_connect, 3, before_connect, after_connect, NULL);
    if (err) pr_err("frida-hide: hook connect failed: %d\n", err);
    else pr_info("frida-hide: hook connect ok\n");
    
    pr_info("frida-hide: initialized\n");
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
    
    inline_unhook_syscall(__NR_getdents64, before_getdents64, after_getdents64);
    inline_unhook_syscall(__NR_readlinkat, before_readlinkat, after_readlinkat);
    inline_unhook_syscall(__NR_connect, before_connect, after_connect);
    
    pr_info("frida-hide: unloaded\n");
    return 0;
}

KPM_INIT(frida_hide_init);
KPM_CTL0(frida_hide_control);
KPM_EXIT(frida_hide_exit);
