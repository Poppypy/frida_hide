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
#include <linux/dirent.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/net.h>
#include "linux/include/linux/string.h"
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/list.h>

KPM_NAME("kpm-frida-hider");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("popy");
KPM_DESCRIPTION("Hide Frida artifacts from detection");

// --- 类型定义 ---

struct linux_dirent64 {
    u64            d_ino;
    s64            d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

typedef unsigned long (*find_copy_from_user)(void *to, const void *from, unsigned long n);
typedef unsigned long (*find_copy_to_user)(void *to, const void *from, unsigned long n);
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

// 1. Hook getdents64: 隐藏文件和进程
// 对应检测: scanPsForFrida, scanCommonPathsForFridaBinaries
static long new_getdents64(const struct pt_regs *regs) {
    // 原始调用
    // getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count)
    // regs->regs[0] = fd, [1] = dirent, [2] = count
    
    // 我们不能直接调用原始 syscall 函数指针，因为 KPM 框架的 fp_hook_syscalln 会处理。
    // 这里我们作为 pre-hook 其实不太方便修改返回值，
    // 但 KPM 的 hook 机制通常允许我们在 post-hook 或者通过 replace 方式处理。
    // 由于 KPM 示例主要展示了 before_exit 这种 pre-hook，
    // 若要修改 buffer，我们需要在 syscall 返回后执行。
    // 如果 KPM 库不支持 post-hook，我们需要用更底层的 hook (如 inline hook 原始 syscall 入口)。
    
    // 假设这是标准的 inline hook 或者 KPM 提供了替换机制。
    // 这里演示标准的 "Call Original -> Filter -> Return" 逻辑。
    
    // 注意：在实际 KPM 环境中，如果只提供 pre-hook，你可能需要 hook 那个特定的内核函数 (sys_getdents64)。
    // 下面代码假设我们是替换了 sys_getdents64 的逻辑。
    
    return 0; // 占位，实际逻辑在下面单独的 hook 函数中
}

// 由于 KPM 的 hook_syscalln 是 pre-callback，无法直接处理 buffer 返回数据。
// 我们需要 hook sys_getdents64 这个符号本身。

static t_syscall_getdents64 orig_getdents64 = NULL;
static t_syscall_readlinkat orig_readlinkat = NULL;
static t_syscall_connect orig_connect = NULL;

static asmlinkage long hook_sys_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count) {
    long ret = orig_getdents64(fd, dirent, count);

    if (ret <= 0 || strcmp(control_status, "start") != 0) return ret;

    // 分配内核缓冲区
    // 注意：大 buffer 分配可能失败，这里简化处理
    struct linux_dirent64 *kdirent = (struct linux_dirent64 *)kzalloc(ret, GFP_KERNEL);
    if (!kdirent) return ret;

    if (got_copy_from_user(kdirent, dirent, ret)) {
        kfree(kdirent);
        return ret;
    }

    struct linux_dirent64 *cur = kdirent;
    long pos = 0;
    long new_ret = ret;
    
    // 遍历并过滤
    while (pos < ret) {
        long reclen = cur->d_reclen;
        if (should_hide(cur->d_name)) {
            // 需要隐藏：将后面的数据前移，覆盖当前项
            long next_offset = pos + reclen;
            long bytes_to_move = ret - next_offset;
            
            if (bytes_to_move > 0) {
                memmove(cur, (char *)cur + reclen, bytes_to_move);
            }
            
            new_ret -= reclen;
            ret -= reclen; // 总长度减少，不移动 pos，重新检查当前位置（已经是下一项了）
            continue; 
        }
        pos += reclen;
        cur = (struct linux_dirent64 *)((char *)cur + reclen);
    }

    // 写回用户空间
    if (new_ret > 0) {
        got_copy_to_user(dirent, kdirent, new_ret);
    }
    
    kfree(kdirent);
    return new_ret;
}

// 2. Hook readlinkat: 隐藏 /proc/self/fd 下的特征链接
// 对应检测: scanProcSelfFd
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
        // 发现敏感路径 (如 /data/local/tmp/frida-agent.so)
        // 伪造返回为 /dev/null 或者一个无害路径
        char *fake = "/dev/null";
        int fake_len = strlen(fake);
        if (bufsiz >= fake_len) {
            memset(kbuf, 0, ret); // 清空
            got_copy_to_user(buf, fake, fake_len);
            kfree(kbuf);
            return fake_len;
        }
    }

    kfree(kbuf);
    return ret;
}

// 3. Hook connect: 阻断 Frida 端口连接
// 对应检测: scanDefaultFridaPorts
static asmlinkage long hook_sys_connect(int fd, struct sockaddr __user *uservaddr, int addrlen) {
    if (strcmp(control_status, "start") != 0) {
        return orig_connect(fd, uservaddr, addrlen);
    }

    struct sockaddr_in kaddr;
    if (addrlen >= sizeof(struct sockaddr_in)) {
        if (got_copy_from_user(&kaddr, uservaddr, sizeof(struct sockaddr_in)) == 0) {
            if (kaddr.sin_family == AF_INET) {
                unsigned int port = ntohs(kaddr.sin_port);
                // 检查是否是 Frida 端口
                if (port >= FRIDA_PORT_START && port <= FRIDA_PORT_END) {
                    // 检查是否是本地回环 (127.0.0.1)
                    // 127.0.0.1 = 0x7F000001 (Network byte order depends on impl, safer to check raw)
                    // htonl(INADDR_LOOPBACK)
                    
                    // 简单粗暴：任何尝试连接这些端口的行为都阻断
                    logke("Blocking connection to Frida port: %d", port);
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
    
    // 查找原始系统调用地址
    // 注意：sys_call_table 查找方式在不同内核版本不同，KPM 可能提供了 wrapper。
    // 这里使用 kallsyms_lookup_name 查找导出的 sys_ 符号。
    // 如果内核未导出 sys_getdents64，可能需要通过 sys_call_table 查找。
    
    // 尝试直接 hook 符号
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

    // 执行 Hook
    // 注意：kpm-backtrace 使用 hook() 函数，传入 原始地址, hook地址, 和备份地址指针
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
        // Unhook logic
        // KPM 的 unhook 需要原始函数地址
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