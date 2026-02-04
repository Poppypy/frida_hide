#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>

KPM_NAME("kpm-frida-hide");
KPM_VERSION("r25");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("popy");
KPM_DESCRIPTION("Hide Frida artifacts from detection");

// ==================== 类型定义 ====================

struct linux_dirent64 {
    u64            d_ino;
    s64            d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    struct {
        unsigned int s_addr;
    } sin_addr;
    unsigned char __pad[8];
};

// ==================== 全局变量 ====================

static const char* HIDE_KEYWORDS[] = {
    "frida",
    "gum-js",
    "gdbus",
    "gmain",
    "linjector",
    "re.frida.server",
    "gadget"
};
#define HIDE_KEYWORDS_COUNT 7

#define FRIDA_PORT_START 27042
#define FRIDA_PORT_END   27049

static bool module_enabled = true;  // ✅ 使用 bool 而不是字符串指针
static bool install_successful = false;

// ==================== 函数指针 ====================

typedef long (*syscall_fn_t)(const struct pt_regs *);

static syscall_fn_t orig_getdents64 = NULL;
static syscall_fn_t orig_readlinkat = NULL;
static syscall_fn_t orig_connect = NULL;

// ==================== 辅助函数 ====================

static inline unsigned short ntohs(unsigned short netshort) {
    return (netshort >> 8) | (netshort << 8);
}

static bool should_hide(const char* name) {
    if (!name) return false;
    
    for (int i = 0; i < HIDE_KEYWORDS_COUNT; i++) {
        if (strstr(name, HIDE_KEYWORDS[i])) {
            return true;
        }
    }
    return false;
}

// ==================== Hook 函数 ====================

// 1. Hook getdents64 - 修复版本
static long hook_sys_getdents64(const struct pt_regs *regs) {
    unsigned int fd = regs->regs[0];
    struct linux_dirent64 __user *dirent = (void *)regs->regs[1];
    unsigned int count = regs->regs[2];
    
    long ret = orig_getdents64(regs);
    
    if (ret <= 0 || !module_enabled) {
        return ret;
    }

    // ✅ 使用 GFP_ATOMIC 避免睡眠
    struct linux_dirent64 *kdirent = kzalloc(ret, GFP_ATOMIC);
    if (!kdirent) {
        pr_warn("[Frida-Hide] kzalloc failed in getdents64\n");
        return ret;
    }

    if (copy_from_user(kdirent, dirent, ret)) {
        kfree(kdirent);
        return ret;
    }

    struct linux_dirent64 *cur = kdirent;
    long pos = 0;
    long new_ret = ret;
    
    // ✅ 修复逻辑：正确处理内存移动
    while (pos < new_ret) {
        long reclen = cur->d_reclen;
        
        if (reclen <= 0 || reclen > new_ret - pos) {
            pr_warn("[Frida-Hide] Invalid reclen: %ld at pos %ld\n", reclen, pos);
            break;
        }
        
        if (should_hide(cur->d_name)) {
            long bytes_to_move = new_ret - pos - reclen;
            
            if (bytes_to_move > 0) {
                memmove(cur, (char *)cur + reclen, bytes_to_move);
            }
            
            new_ret -= reclen;
            // ✅ 不移动 pos 和 cur，因为新条目已经在当前位置
            continue;
        }
        
        pos += reclen;
        cur = (struct linux_dirent64 *)((char *)cur + reclen);
    }

    if (new_ret > 0 && new_ret != ret) {
        copy_to_user(dirent, kdirent, new_ret);
    }
    
    kfree(kdirent);
    return new_ret;
}

// 2. Hook readlinkat - 修复版本
static long hook_sys_readlinkat(const struct pt_regs *regs) {
    int dfd = regs->regs[0];
    const char __user *path = (void *)regs->regs[1];
    char __user *buf = (void *)regs->regs[2];
    int bufsiz = regs->regs[3];
    
    long ret = orig_readlinkat(regs);
    
    if (ret <= 0 || !module_enabled) {
        return ret;
    }

    char *kbuf = kzalloc(ret + 1, GFP_ATOMIC);
    if (!kbuf) {
        return ret;
    }

    if (copy_from_user(kbuf, buf, ret)) {
        kfree(kbuf);
        return ret;
    }
    kbuf[ret] = '\0';

    if (should_hide(kbuf)) {
        const char *fake = "/dev/null";
        int fake_len = strlen(fake);
        
        if (bufsiz >= fake_len) {
            copy_to_user(buf, fake, fake_len);
            kfree(kbuf);
            return fake_len;
        }
    }

    kfree(kbuf);
    return ret;
}

// 3. Hook connect - 修复版本
static long hook_sys_connect(const struct pt_regs *regs) {
    int fd = regs->regs[0];
    struct sockaddr __user *uservaddr = (void *)regs->regs[1];
    int addrlen = regs->regs[2];
    
    if (!module_enabled) {
        return orig_connect(regs);
    }

    if (addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in kaddr;
        
        if (copy_from_user(&kaddr, uservaddr, sizeof(struct sockaddr_in)) == 0) {
            if (kaddr.sin_family == AF_INET) {
                unsigned int port = ntohs(kaddr.sin_port);
                
                if (port >= FRIDA_PORT_START && port <= FRIDA_PORT_END) {
                    pr_info("[Frida-Hide] Blocked connection to Frida port %u\n", port);
                    return -ECONNREFUSED;
                }
            }
        }
    }
    
    return orig_connect(regs);
}

// ==================== 初始化与卸载 ====================

static long install(const char *args, const char *event, void *__user reserved)
{
    pr_info("=== [Frida-Hide] Module initializing ===\n");
    pr_info("[Frida-Hide] Args: %s, Event: %s\n", args ? args : "none", event ? event : "none");
    
    // ✅ 查找系统调用符号（ARM64 优先）
    void *sym_getdents64 = (void *)kallsyms_lookup_name("__arm64_sys_getdents64");
    if (!sym_getdents64) {
        sym_getdents64 = (void *)kallsyms_lookup_name("sys_getdents64");
    }
    
    void *sym_readlinkat = (void *)kallsyms_lookup_name("__arm64_sys_readlinkat");
    if (!sym_readlinkat) {
        sym_readlinkat = (void *)kallsyms_lookup_name("sys_readlinkat");
    }
    
    void *sym_connect = (void *)kallsyms_lookup_name("__arm64_sys_connect");
    if (!sym_connect) {
        sym_connect = (void *)kallsyms_lookup_name("sys_connect");
    }

    pr_info("[Frida-Hide] Symbol addresses:\n");
    pr_info("  getdents64: %px\n", sym_getdents64);
    pr_info("  readlinkat: %px\n", sym_readlinkat);
    pr_info("  connect:    %px\n", sym_connect);

    if (!sym_getdents64 || !sym_readlinkat || !sym_connect) {
        pr_err("[Frida-Hide] FATAL: Failed to find syscall symbols!\n");
        return -ENOENT;
    }

    // ✅ 安装 hooks
    int ret1 = hook(sym_getdents64, hook_sys_getdents64, (void **)&orig_getdents64);
    int ret2 = hook(sym_readlinkat, hook_sys_readlinkat, (void **)&orig_readlinkat);
    int ret3 = hook(sym_connect, hook_sys_connect, (void **)&orig_connect);

    pr_info("[Frida-Hide] Hook results: getdents64=%d, readlinkat=%d, connect=%d\n", 
            ret1, ret2, ret3);

    if (ret1 != 0 || ret2 != 0 || ret3 != 0) {
        pr_err("[Frida-Hide] Hook installation failed!\n");
        
        // 清理已安装的 hooks
        if (ret1 == 0) unhook(sym_getdents64);
        if (ret2 == 0) unhook(sym_readlinkat);
        if (ret3 == 0) unhook(sym_connect);
        
        return -EFAULT;
    }

    install_successful = true;
    pr_info("=== [Frida-Hide] Module installed successfully ===\n");
    return 0;
}

static long control(const char *args, char *__user out_msg, int outlen)
{
    if (!args) {
        return -EINVAL;
    }

    pr_info("[Frida-Hide] Control command: %s\n", args);

    if (strcmp(args, "stop") == 0) {
        module_enabled = false;
        pr_info("[Frida-Hide] Module disabled\n");
    } else if (strcmp(args, "start") == 0) {
        module_enabled = true;
        pr_info("[Frida-Hide] Module enabled\n");
    } else if (strcmp(args, "status") == 0) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Frida-Hide: %s", module_enabled ? "enabled" : "disabled");
        
        if (out_msg && outlen > 0) {
            copy_to_user(out_msg, msg, min((int)sizeof(msg), outlen));
        }
    } else {
        pr_warn("[Frida-Hide] Unknown command: %s\n", args);
        return -EINVAL;
    }

    return 0;
}

static long uninstall(void *__user reserved)
{
    pr_info("=== [Frida-Hide] Module uninstalling ===\n");

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
        
        pr_info("[Frida-Hide] All hooks removed\n");
    }

    pr_info("=== [Frida-Hide] Module uninstalled ===\n");
    return 0;
}

KPM_INIT(install);
KPM_CTL0(control);
KPM_EXIT(uninstall);
