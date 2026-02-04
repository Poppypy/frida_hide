#include <log.h>
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/errno.h>
#include <syscall.h>
#include <asm/current.h>

// --- 必须手动声明内核字符串函数，避免隐式声明错误 ---
// 这些函数在内核中是导出的，直接声明即可链接
extern char *strstr(const char *, const char *);
extern int strcmp(const char *, const char *);
extern __kernel_size_t strlen(const char *);

KPM_NAME("kpm-frida-hide");
KPM_VERSION("r24");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("popy");
KPM_DESCRIPTION("Hide Frida artifacts from detection");

// --- 基础类型定义 ---
#define GFP_KERNEL 0x400
#define GFP_ATOMIC 0x20

typedef void *(*t_kmalloc)(size_t size, unsigned int flags);
typedef void (*t_kfree)(const void *objp);
typedef void *(*t_memset)(void *s, int c, size_t n);
typedef void *(*t_memmove)(void *dest, const void *src, size_t n);

static t_kmalloc got_kmalloc = NULL;
static t_kfree got_kfree = NULL;
static t_memset got_memset = NULL;
static t_memmove got_memmove = NULL;

// 自实现 kzalloc
static inline void *my_kzalloc(size_t size, unsigned int flags) {
    if (!got_kmalloc || !got_memset) return NULL;
    void *ptr = got_kmalloc(size, flags);
    if (ptr) {
        got_memset(ptr, 0, size);
    }
    return ptr;
}

// --- 结构体定义 (移到最上方，解决可见性问题) ---

// 1. dirent64
struct linux_dirent64 {
    u64            d_ino;
    s64            d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

// 2. sockaddr 相关 (解决 incomplete type / scope warning)
#define AF_INET 2

struct in_addr {
    unsigned int s_addr;
};

// 必须先完整定义，再在 typedef 中引用
struct sockaddr {
    unsigned short sa_family;
    char           sa_data[14];
};

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    struct in_addr sin_addr;
    unsigned char  __pad[8];
};

static inline unsigned short my_ntohs(unsigned short netshort) {
    return (netshort >> 8) | (netshort << 8);
}

// --- 系统调用与辅助函数 ---

typedef unsigned long (*find_copy_from_user)(void *to, const void *from, unsigned long n);
typedef unsigned long (*find_copy_to_user)(void *to, const void *from, unsigned long n);

// 现在 struct sockaddr 已经定义，这里引用是安全的
typedef long (*t_syscall_getdents64)(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
typedef long (*t_syscall_readlinkat)(int dfd, const char __user *path, char __user *buf, int bufsiz);
typedef long (*t_syscall_connect)(int fd, struct sockaddr __user *uservaddr, int addrlen);

static find_copy_from_user got_copy_from_user = NULL;
static find_copy_to_user got_copy_to_user = NULL;

static const char* HIDE_KEYWORDS[] = {
    "frida",
    "gum-js",
    "gdbus",
    "gmain",
    "linjector",
    "re.frida.server",
    "gadget"
};
#define HIDE_KEYWORDS_COUNT (sizeof(HIDE_KEYWORDS) / sizeof(HIDE_KEYWORDS[0]))

#define FRIDA_PORT_START 27042
#define FRIDA_PORT_END   27049

static bool install_successful = false;
static char* control_status = "start";

static bool should_hide(const char* name) {
    if (!name) return false;
    for (int i = 0; i < HIDE_KEYWORDS_COUNT; i++) {
        if (strstr(name, HIDE_KEYWORDS[i])) {
            return true;
        }
    }
    return false;
}

// --- Hooks ---

static t_syscall_getdents64 orig_getdents64 = NULL;
static t_syscall_readlinkat orig_readlinkat = NULL;
static t_syscall_connect orig_connect = NULL;

// 1. Hook getdents64
static asmlinkage long hook_sys_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count) {
    long ret = orig_getdents64(fd, dirent, count);

    if (ret <= 0 || strcmp(control_status, "start") != 0) return ret;
    if (!got_kmalloc || !got_kfree) return ret;

    struct linux_dirent64 *kdirent = (struct linux_dirent64 *)my_kzalloc(ret, GFP_KERNEL);
    if (!kdirent) return ret;

    if (got_copy_from_user(kdirent, dirent, ret)) {
        got_kfree(kdirent);
        return ret;
    }

    struct linux_dirent64 *cur = kdirent;
    long pos = 0;
    long new_ret = ret;
    
    while (pos < ret) {
        long reclen = cur->d_reclen;
        if (should_hide(cur->d_name)) {
            long next_offset = pos + reclen;
            long bytes_to_move = ret - next_offset;
            
            if (bytes_to_move > 0 && got_memmove) {
                got_memmove(cur, (char *)cur + reclen, bytes_to_move);
            }
            
            new_ret -= reclen;
            ret -= reclen;
            continue; 
        }
        pos += reclen;
        cur = (struct linux_dirent64 *)((char *)cur + reclen);
    }

    if (new_ret > 0) {
        got_copy_to_user(dirent, kdirent, new_ret);
    }
    
    got_kfree(kdirent);
    return new_ret;
}

// 2. Hook readlinkat
static asmlinkage long hook_sys_readlinkat(int dfd, const char __user *path, char __user *buf, int bufsiz) {
    long ret = orig_readlinkat(dfd, path, buf, bufsiz);
    
    if (ret <= 0 || strcmp(control_status, "start") != 0) return ret;
    if (!got_kmalloc || !got_kfree) return ret;

    char *kbuf = (char *)my_kzalloc(ret + 1, GFP_KERNEL);
    if (!kbuf) return ret;

    if (got_copy_from_user(kbuf, buf, ret)) {
        got_kfree(kbuf);
        return ret;
    }
    kbuf[ret] = '\0';

    if (should_hide(kbuf)) {
        char *fake = "/dev/null";
        int fake_len = strlen(fake);
        if (bufsiz >= fake_len) {
            got_memset(kbuf, 0, ret);
            got_copy_to_user(buf, fake, fake_len);
            got_kfree(kbuf);
            return fake_len;
        }
    }

    got_kfree(kbuf);
    return ret;
}

// 3. Hook connect
static asmlinkage long hook_sys_connect(int fd, struct sockaddr __user *uservaddr, int addrlen) {
    if (strcmp(control_status, "start") != 0) {
        return orig_connect(fd, uservaddr, addrlen);
    }

    struct sockaddr_in kaddr;
    if (addrlen >= sizeof(struct sockaddr_in)) {
        if (got_copy_from_user(&kaddr, uservaddr, sizeof(struct sockaddr_in)) == 0) {
            if (kaddr.sin_family == AF_INET) {
                unsigned int port = my_ntohs(kaddr.sin_port);
                if (port >= FRIDA_PORT_START && port <= FRIDA_PORT_END) {
                    return -ECONNREFUSED;
                }
            }
        }
    }
    return orig_connect(fd, uservaddr, addrlen);
}


// --- Init & Resolve Symbols ---

bool init_funcs() {
    got_copy_from_user = (find_copy_from_user)kallsyms_lookup_name("copy_from_user");
    got_copy_to_user = (find_copy_to_user)kallsyms_lookup_name("copy_to_user");
    
    got_kmalloc = (t_kmalloc)kallsyms_lookup_name("__kmalloc"); 
    if (!got_kmalloc) got_kmalloc = (t_kmalloc)kallsyms_lookup_name("kmalloc");
    
    got_kfree = (t_kfree)kallsyms_lookup_name("kfree");
    got_memset = (t_memset)kallsyms_lookup_name("memset");
    got_memmove = (t_memmove)kallsyms_lookup_name("memmove");

    if (!got_copy_from_user || !got_copy_to_user || !got_kmalloc || !got_kfree || !got_memset) {
        logke("Failed to resolve essential kernel symbols");
        return false;
    }
    
    void *sym_getdents64 = (void *)kallsyms_lookup_name("__arm64_sys_getdents64");
    if (!sym_getdents64) sym_getdents64 = (void *)kallsyms_lookup_name("sys_getdents64");
    
    void *sym_readlinkat = (void *)kallsyms_lookup_name("__arm64_sys_readlinkat");
    if (!sym_readlinkat) sym_readlinkat = (void *)kallsyms_lookup_name("sys_readlinkat");
    
    void *sym_connect = (void *)kallsyms_lookup_name("__arm64_sys_connect");
    if (!sym_connect) sym_connect = (void *)kallsyms_lookup_name("sys_connect");

    if (!sym_getdents64 || !sym_readlinkat || !sym_connect) {
        logke("Failed to find syscall symbols");
        return false;
    }

    hook(sym_getdents64, hook_sys_getdents64, (void **)&orig_getdents64);
    hook(sym_readlinkat, hook_sys_readlinkat, (void **)&orig_readlinkat);
    hook(sym_connect, hook_sys_connect, (void **)&orig_connect);

    return true;
}

static long install(const char *args, const char *event, void *__user reserved)
{
    install_successful = init_funcs();
    if (!install_successful) {
        logke("Frida Hider module install fail.");
    } else {
        logke("Frida Hider module install successful.");
    }
    return 0;
}

static long control(const char *args, char *__user out_msg, int outlen)
{
    if (strcmp(args, "stop") == 0) {
        control_status = "stop";
    } else if (strcmp(args, "start") == 0) {
        control_status = "start";
    }
    return 0;
}

static long uninstall(void *__user reserved)
{
    if (install_successful) {
        void *sym_getdents64 = (void *)kallsyms_lookup_name("__arm64_sys_getdents64");
        if (!sym_getdents64) sym_getdents64 = (void *)kallsyms_lookup_name("sys_getdents64");
        void *sym_readlinkat = (void *)kallsyms_lookup_name("__arm64_sys_readlinkat");
        if (!sym_readlinkat) sym_readlinkat = (void *)kallsyms_lookup_name("sys_readlinkat");
        void *sym_connect = (void *)kallsyms_lookup_name("__arm64_sys_connect");
        if (!sym_connect) sym_connect = (void *)kallsyms_lookup_name("sys_connect");

        if (sym_getdents64) unhook(sym_getdents64);
        if (sym_readlinkat) unhook(sym_readlinkat);
        if (sym_connect) unhook(sym_connect);
    }
    logke("Frida Hider uninstall successful\n");
    return 0;
}

KPM_INIT(install);
KPM_CTL0(control);
KPM_EXIT(uninstall);