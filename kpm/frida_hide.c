#include <log.h>
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <asm/current.h>
#include <linux/types.h>
#include "linux/include/linux/string.h"
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/list.h>

// --- 移除导致报错的头文件，改为下方手动定义 ---
// #include <linux/dirent.h> 
// #include <linux/socket.h>
// #include <linux/in.h>
// #include <linux/net.h>

KPM_NAME("kpm-frida-hide");
KPM_VERSION("r22");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("popy");
KPM_DESCRIPTION("Hide Frida artifacts from detection");

// --- 手动定义缺失的结构体和宏 (Self-contained) ---

// 1. dirent64 结构体 (用于 sys_getdents64)
struct linux_dirent64 {
    u64            d_ino;
    s64            d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

// 2. 网络相关定义 (用于 sys_connect)
#define AF_INET     2

// 从内核源码中提取的 sockaddr 定义
struct sockaddr {
    unsigned short sa_family;   /* address family, AF_xxx   */
    char           sa_data[14]; /* 14 bytes of protocol address */
};

// 从内核源码中提取的 sockaddr_in 定义
struct in_addr {
    unsigned int s_addr;
};

struct sockaddr_in {
    unsigned short sin_family;  /* Address family       */
    unsigned short sin_port;    /* Port number          */
    struct in_addr sin_addr;    /* Internet address     */
    unsigned char  __pad[8];    /* Pad to size of `struct sockaddr' */
};

// 简单的字节序转换 (ARM64通常是小端，网络是大端)
static inline unsigned short my_ntohs(unsigned short netshort) {
    return (netshort >> 8) | (netshort << 8);
}

// --- 类型定义 ---

typedef unsigned long (*find_copy_from_user)(void *to, const void *from, unsigned long n);
typedef unsigned long (*find_copy_to_user)(void *to, const void *from, unsigned long n);

// 原始系统调用函数指针类型
typedef long (*t_syscall_getdents64)(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
typedef long (*t_syscall_readlinkat)(int dfd, const char __user *path, char __user *buf, int bufsiz);
typedef long (*t_syscall_connect)(int fd, struct sockaddr __user *uservaddr, int addrlen);

static find_copy_from_user got_copy_from_user = NULL;
static find_copy_to_user got_copy_to_user = NULL;

// --- 隐藏配置 ---

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

// Frida 默认端口范围
#define FRIDA_PORT_START 27042
#define FRIDA_PORT_END   27049

static bool install_successful = false;
static char* control_status = "start";

// --- 辅助函数 ---

static bool should_hide(const char* name) {
    if (!name) return false;
    for (int i = 0; i < HIDE_KEYWORDS_COUNT; i++) {
        if (strstr(name, HIDE_KEYWORDS[i])) {
            return true;
        }
    }
    return false;
}

// --- Hook 实现 ---

static t_syscall_getdents64 orig_getdents64 = NULL;
static t_syscall_readlinkat orig_readlinkat = NULL;
static t_syscall_connect orig_connect = NULL;

// 1. Hook getdents64
static asmlinkage long hook_sys_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count) {
    long ret = orig_getdents64(fd, dirent, count);

    if (ret <= 0 || strcmp(control_status, "start") != 0) return ret;

    struct linux_dirent64 *kdirent = (struct linux_dirent64 *)kzalloc(ret, GFP_KERNEL);
    if (!kdirent) return ret;

    if (got_copy_from_user(kdirent, dirent, ret)) {
        kfree(kdirent);
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
            
            if (bytes_to_move > 0) {
                memmove(cur, (char *)cur + reclen, bytes_to_move);
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
    
    kfree(kdirent);
    return new_ret;
}

// 2. Hook readlinkat
static asmlinkage long hook_sys_readlinkat(int dfd, const char __user *path, char __user *buf, int bufsiz) {
    long ret = orig_readlinkat(dfd, path, buf, bufsiz);
    
    if (ret <= 0 || strcmp(control_status, "start") != 0) return ret;

    char *kbuf = kzalloc(ret + 1, GFP_KERNEL);
    if (!kbuf) return ret;

    if (got_copy_from_user(kbuf, buf, ret)) {
        kfree(kbuf);
        return ret;
    }
    kbuf[ret] = '\0';

    if (should_hide(kbuf)) {
        char *fake = "/dev/null";
        int fake_len = strlen(fake);
        if (bufsiz >= fake_len) {
            memset(kbuf, 0, ret);
            got_copy_to_user(buf, fake, fake_len);
            kfree(kbuf);
            return fake_len;
        }
    }

    kfree(kbuf);
    return ret;
}

// 3. Hook connect
static asmlinkage long hook_sys_connect(int fd, struct sockaddr __user *uservaddr, int addrlen) {
    if (strcmp(control_status, "start") != 0) {
        return orig_connect(fd, uservaddr, addrlen);
    }

    // 手动分配栈空间读取 sockaddr_in
    struct sockaddr_in kaddr;
    if (addrlen >= sizeof(struct sockaddr_in)) {
        if (got_copy_from_user(&kaddr, uservaddr, sizeof(struct sockaddr_in)) == 0) {
            if (kaddr.sin_family == AF_INET) {
                // 使用我们手写的 my_ntohs 避免依赖网络头文件
                unsigned int port = my_ntohs(kaddr.sin_port);
                
                if (port >= FRIDA_PORT_START && port <= FRIDA_PORT_END) {
                    // logke("Blocking connection to Frida port: %d", port);
                    return -ECONNREFUSED;
                }
            }
        }
    }

    return orig_connect(fd, uservaddr, addrlen);
}


// --- 模块初始化 ---

bool init_funcs() {
    got_copy_from_user = (find_copy_from_user)kallsyms_lookup_name("copy_from_user");
    got_copy_to_user = (find_copy_to_user)kallsyms_lookup_name("copy_to_user");
    
    if (!got_copy_from_user || !got_copy_to_user) {
        logke("Failed to find copy_from/to_user");
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