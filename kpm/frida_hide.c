#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/err.h>
#include <uapi/asm-generic/errno.h>
#include <hook.h>
#include <ksyms.h>

KPM_NAME("frida_hide");
KPM_VERSION("3.0.0-venus");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Security Researcher");
KPM_DESCRIPTION("Hide Frida/Root/Xposed - NagaLinker v8.91 bypass");

#define LOG_ENABLED 0
#define LOGV(fmt,...) do{if(LOG_ENABLED)pr_info("frida_hide: "fmt,##__VA_ARGS__);}while(0)

#define FRIDA_PORT_START 27042
#define FRIDA_PORT_END   27052
#define AF_INET  2
#define AF_INET6 10
#define ECONNREFUSED 111
#define ENOENT 2
#define UID_APP_START 10000
#define MAX_PATH_LEN 256
#define VM_READ  0x00000001
#define VM_WRITE 0x00000002
#define VM_EXEC  0x00000004

struct seq_file{char*buf;size_t size,from,count,pad_until;loff_t index,read_pos;};
struct sockaddr_in{unsigned short sin_family,sin_port;unsigned int sin_addr;char sin_zero[8];};
struct sockaddr_in6{unsigned short sin6_family,sin6_port;unsigned int sin6_flowinfo,scope_id;unsigned char sin6_addr[16];};
struct filename{const char*name;};
struct linux_dirent64{unsigned long d_ino;long d_off;unsigned short d_reclen;unsigned char d_type;char d_name[];};

static uint64_t show_map_vma_addr=0,show_smap_addr=0,tcp_v4_connect_addr=0;
static uint64_t tcp_v6_connect_addr=0,do_faccessat_addr=0,sys_faccessat2_addr=0;
static uint64_t vfs_fstatat_addr=0,vfs_statx_addr=0,do_statx_addr=0,do_filp_open_addr=0;
static uint64_t proc_pid_status_addr=0,comm_write_addr=0,getdents64_addr=0;
static uint64_t do_readlinkat_addr=0;
static int vma_vm_flags_offset=0x50,vma_vm_file_offset=0x98;

// Hook macros
#define HOOK_WRAP2(sym,bf,af,av,c) do{av=kallsyms_lookup_name(#sym);if(av&&hook_wrap2((void*)av,bf,af,0)==HOOK_NO_ERR){LOGV("[+]"#sym"\n");c++;}else av=0;}while(0)
#define HOOK_WRAP3(sym,bf,af,av,c) do{av=kallsyms_lookup_name(#sym);if(av&&hook_wrap3((void*)av,bf,af,0)==HOOK_NO_ERR){LOGV("[+]"#sym"\n");c++;}else av=0;}while(0)
#define HOOK_WRAP4(sym,bf,af,av,c) do{av=kallsyms_lookup_name(#sym);if(av&&hook_wrap4((void*)av,bf,af,0)==HOOK_NO_ERR){LOGV("[+]"#sym"\n");c++;}else av=0;}while(0)
#define HOOK_WRAP5(sym,bf,af,av,c) do{av=kallsyms_lookup_name(#sym);if(av&&hook_wrap5((void*)av,bf,af,0)==HOOK_NO_ERR){LOGV("[+]"#sym"\n");c++;}else av=0;}while(0)
#define UNHOOK(av) do{if(av){unhook((void*)av);av=0;}}while(0)

// String helpers
static inline size_t my_strlen(const char*s){if(!s)return 0;const char*p=s;while(*p)p++;return p-s;}
static inline int my_strcmp(const char*s1,const char*s2){while(*s1&&*s1==*s2){s1++;s2++;}return*(unsigned char*)s1-*(unsigned char*)s2;}
static inline int my_startswith(const char*s,const char*p){if(!s||!p)return 0;while(*p)if(*s++!=*p++)return 0;return 1;}
static inline char*my_strstr(const char*h,const char*n){if(!h||!n||!*n)return(char*)h;size_t nlen=my_strlen(n);while(*h){const char*p=h,*q=n;while(*p&&*q&&*p==*q){p++;q++;}if(!*q)return(char*)h;h++;}return 0;}
static inline void*my_memmem(const void*h,size_t hl,const void*n,size_t nl){if(!h||!n||hl<nl||!nl)return 0;const char*hp=h,*np=n;for(size_t i=0;i<=hl-nl;i++){int m=1;for(size_t j=0;j<nl&&m;j++)if(hp[i+j]!=np[j])m=0;if(m)return(void*)(hp+i);}return 0;}
static inline uint16_t bswap16(uint16_t v){return(v>>8)|(v<<8);}
static inline int is_app(void){return current_uid()>=UID_APP_START;}
static inline int is_kptr(const void*p){return p&&((unsigned long)p>0xffff000000000000UL);}

// Detection helpers - Frida mapping keywords (for maps filtering)
static inline int is_frida_mapping(const char*buf,size_t len){
    if(!buf||len<5)return 0;
    // Priority 1: Core Frida
    if(my_memmem(buf,len,"frida",5))return 1;
    if(my_memmem(buf,len,"gum-js",6))return 1;
    if(len>10&&my_memmem(buf,len,"linjector",9))return 1;
    // Priority 2: Xposed/EdXposed
    if(my_memmem(buf,len,"xposed",6))return 1;
    if(my_memmem(buf,len,"edxposed",8))return 1;
    if(my_memmem(buf,len,"liblspd",7))return 1;
    if(my_memmem(buf,len,"libriru",7))return 1;
    // Priority 3: Substrate/Other
    if(my_memmem(buf,len,"substrate",9))return 1;
    if(my_memmem(buf,len,"libFupk",7))return 1;
    if(my_memmem(buf,len,"/data/fart",10))return 1;
    if(my_memmem(buf,len,"blackdex",8))return 1;
    // Priority 4: memfd check (Frida uses memfd for JIT)
    char*pos=(char*)my_memmem(buf,len,"memfd:",6);
    if(pos){size_t off=pos-buf+6;if(off<len){const char*rest=buf+off;size_t rl=len-off;
        if(my_memmem(rest,rl,"frida",5)||my_memmem(rest,rl,"jit",3)||my_memmem(rest,rl,"agent",5)||my_memmem(rest,rl,"gum",3))return 1;}}
    // Priority 5: NagaLinker encrypted keyword bypass
    if(my_memmem(buf,len,"MAGISK_INJ",10))return 1;
    return 0;
}

// Sensitive paths - su binaries, Magisk, Frida server, etc.
static inline int is_sensitive_path(const char*path){
    if(!path||!*path)return 0;
    // Exact match su paths
    static const char*su_paths[]={"/system/bin/su","/system/xbin/su","/sbin/su","/vendor/bin/su","/su/bin/su","/data/local/su","/data/local/bin/su","/data/local/tmp/su"};
    for(int i=0;i<8;i++)if(my_strcmp(path,su_paths[i])==0)return 1;
    // Prefix match Magisk/KernelSU/APatch
    if(my_startswith(path,"/sbin/.magisk")||my_startswith(path,"/.magisk")||my_startswith(path,"/data/adb/magisk")||
       my_startswith(path,"/data/adb/ksu")||my_startswith(path,"/data/adb/ap/")||my_startswith(path,"/data/adb/apd"))return 1;
    if(my_strcmp(path,"/data/adb")==0||my_strcmp(path,"/data/adb/")==0)return 1;
    // Frida server paths
    if(my_startswith(path,"/data/local/tmp/frida")||my_startswith(path,"/data/local/tmp/re.frida"))return 1;
    // Xposed/EdXposed
    if(my_startswith(path,"/data/misc/edxpu_"))return 1;
    // NagaLinker specific: /proc/self/fd access for detection (sub_85AE0)
    if(my_startswith(path,"/proc/self/fd/")&&my_strstr(path,"frida"))return 1;
    return 0;
}

// NagaLinker detection paths - /proc/*/mem, /proc/*/pagemap (sub_79E64)
static inline int is_proc_mem_path(const char*path){
    if(!path)return 0;
    // /proc/%d/mem or /proc/%d/pagemap pattern
    if(!my_startswith(path,"/proc/"))return 0;
    // Check for /mem or /pagemap at end
    size_t len=my_strlen(path);
    if(len>4&&my_strcmp(path+len-4,"/mem")==0)return 1;
    if(len>8&&my_strcmp(path+len-8,"/pagemap")==0)return 1;
    return 0;
}

// System lib RWX check
static inline int is_system_lib_for_rwx(const char*name){
    if(!name)return 0;
    if(*name!='l'&&*name!='a')return 0;
    if(my_strstr(name,"libc.so"))return 1;
    if(my_strstr(name,"libc++.so"))return 1;
    if(my_strstr(name,"libart.so"))return 1;
    if(my_strstr(name,"libdl.so"))return 1;
    if(my_strstr(name,"libm.so"))return 1;
    if(my_strstr(name,"liblog.so"))return 1;
    if(my_strstr(name,"libbase.so"))return 1;
    if(my_strstr(name,"libutils.so"))return 1;
    if(my_strstr(name,"libbinder.so"))return 1;
    if(my_strstr(name,"libandroid_runtime.so"))return 1;
    if(my_strstr(name,"linker"))return 1;
    return 0;
}

// Frida port check
static inline int is_frida_port(uint16_t port){return port>=FRIDA_PORT_START&&port<=FRIDA_PORT_END;}

// Frida thread name check (sub_60728, sub_79E64)
static inline int is_frida_thread(const char*name){
    if(!name||!*name)return 0;
    char c=name[0];
    if(c=='g'&&my_startswith(name,"gum-js"))return 1;
    if(c=='p'&&my_startswith(name,"pool-frida"))return 1;
    if(c=='l'&&my_startswith(name,"linjector"))return 1;
    if(c=='f'&&(my_startswith(name,"frida")||my_startswith(name,"frida:")))return 1;
    if(c=='x'&&my_startswith(name,"xposed"))return 1;
    if(c=='l'&&my_startswith(name,"lspd"))return 1;
    return 0;
}

// VMA helpers
static inline unsigned long*get_vma_flags_ptr(void*vma){return vma?(unsigned long*)((char*)vma+vma_vm_flags_offset):0;}
static void*get_vma_file(void*vma){
    if(!vma)return 0;
    void**fp=(void**)((char*)vma+vma_vm_file_offset);
    void*f=*fp;
    if(f&&is_kptr(f))return f;
    static const int offs[]={0x90,0xa0,0x88,0xa8};
    for(int i=0;i<4;i++){
        if(offs[i]==vma_vm_file_offset)continue;
        fp=(void**)((char*)vma+offs[i]);f=*fp;
        if(f&&is_kptr(f)){vma_vm_file_offset=offs[i];return f;}
    }
    return 0;
}
static const char*get_file_name(void*file){
    if(!file)return 0;
    static const int dentry_off[]={0x10,0x18,0x20},qstr_off[]={0x20,0x28,0x30};
    for(int i=0;i<3;i++){
        void*de=*(void**)((char*)file+dentry_off[i]);
        if(!de||!is_kptr(de))continue;
        for(int j=0;j<3;j++){
            const char*name=*(const char**)((char*)de+qstr_off[j]+0x08);
            if(name&&is_kptr(name)){char c=name[0];
                if((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='.'||c=='/')return name;}
        }
    }
    return 0;
}

// ==================== Hook implementations ====================

// show_map_vma / show_smap - filter maps output
static void before_show_map_vma(hook_fargs2_t*args,void*udata){
    args->local.data0=0;args->local.data1=0;args->local.data2=0;
    if(!is_app())return;
    args->local.data2=1;
    struct seq_file*m=(struct seq_file*)args->arg0;
    void*vma=(void*)args->arg1;
    if(m&&m->buf)args->local.data0=(uint64_t)m->count;
    if(!vma)return;
    unsigned long*fp=get_vma_flags_ptr(vma);
    if(!fp)return;
    unsigned long flags=*fp;
    if(flags==0||flags>0xFFFFFFFF)return;
    // RWX check
    if((flags&(VM_READ|VM_WRITE|VM_EXEC))==(VM_READ|VM_WRITE|VM_EXEC)){
        void*file=get_vma_file(vma);
        if(file){const char*name=get_file_name(file);
            if(name&&is_system_lib_for_rwx(name)){args->local.data1=flags;*fp=flags&~VM_WRITE;}}
    }
}
static void after_show_map_vma(hook_fargs2_t*args,void*udata){
    if(!args->local.data2)return;
    if(args->local.data1){unsigned long*fp=get_vma_flags_ptr((void*)args->arg1);if(fp)*fp=args->local.data1;}
    struct seq_file*m=(struct seq_file*)args->arg0;
    if(!m||!m->buf)return;
    size_t old=(size_t)args->local.data0;
    if(m->count<=old)return;
    char*nd=m->buf+old;size_t nl=m->count-old;
    // Hide Frida mappings
    if(is_frida_mapping(nd,nl)){m->count=old;return;}
    // Fix RWX permissions for system libs
    for(size_t i=0;i<nl-4;i++){
        if(nd[i]==' '&&nd[i+1]=='r'&&nd[i+2]=='w'&&nd[i+3]=='x'){
            if(is_system_lib_for_rwx(nd)){nd[i+2]='-';break;}
        }
    }
}

// tcp_v4_connect - block Frida ports
static void before_tcp_v4_connect(hook_fargs3_t*args,void*udata){
    struct sockaddr_in*addr=(struct sockaddr_in*)args->arg1;
    if(!addr||addr->sin_family!=AF_INET)return;
    if(!is_app())return;
    uint16_t port=bswap16(addr->sin_port);
    if(is_frida_port(port)){args->ret=(uint64_t)(-(long)ECONNREFUSED);args->skip_origin=1;}
}

// tcp_v6_connect - block Frida ports
static void before_tcp_v6_connect(hook_fargs3_t*args,void*udata){
    struct sockaddr_in6*addr=(struct sockaddr_in6*)args->arg1;
    if(!addr||addr->sin6_family!=AF_INET6)return;
    if(!is_app())return;
    uint16_t port=bswap16(addr->sin6_port);
    if(is_frida_port(port)){args->ret=(uint64_t)(-(long)ECONNREFUSED);args->skip_origin=1;}
}

// do_faccessat - block file access
static void before_faccessat(hook_fargs4_t*args,void*udata){
    const char __user*fn=(const char __user*)args->arg1;
    if(!fn||!is_app())return;
    char buf[MAX_PATH_LEN];
    long len=compat_strncpy_from_user(buf,fn,sizeof(buf)-1);
    if(len<=0||len>=MAX_PATH_LEN)return;
    buf[len]='\0';
    if(is_sensitive_path(buf)){args->ret=(uint64_t)(-(long)ENOENT);args->skip_origin=1;}
}

// vfs_fstatat - block stat
static void before_vfs_fstatat(hook_fargs4_t*args,void*udata){
    const char __user*fn=(const char __user*)args->arg1;
    if(!fn||!is_app())return;
    char buf[MAX_PATH_LEN];
    long len=compat_strncpy_from_user(buf,fn,sizeof(buf)-1);
    if(len<=0||len>=MAX_PATH_LEN)return;
    buf[len]='\0';
    if(is_sensitive_path(buf)){args->ret=(uint64_t)(-(long)ENOENT);args->skip_origin=1;}
}

// vfs_statx / do_statx - block statx
static void before_statx(hook_fargs5_t*args,void*udata){
    const char __user*fn=(const char __user*)args->arg1;
    if(!fn||!is_app())return;
    char buf[MAX_PATH_LEN];
    long len=compat_strncpy_from_user(buf,fn,sizeof(buf)-1);
    if(len<=0||len>=MAX_PATH_LEN)return;
    buf[len]='\0';
    if(is_sensitive_path(buf)){args->ret=(uint64_t)(-(long)ENOENT);args->skip_origin=1;}
}

// do_filp_open - block file open (enhanced for NagaLinker sub_79E64)
static void before_do_filp_open(hook_fargs3_t*args,void*udata){
    struct filename*pn=(struct filename*)args->arg1;
    if(!pn||!pn->name||!is_app())return;
    const char*path=pn->name;
    // Standard sensitive path check
    if(is_sensitive_path(path)){args->ret=(uint64_t)(-(long)ENOENT);args->skip_origin=1;return;}
    // NagaLinker specific: block /proc/*/mem and /proc/*/pagemap (sub_79E64 detection)
    if(is_proc_mem_path(path)){args->ret=(uint64_t)(-(long)ENOENT);args->skip_origin=1;}
}

// proc_pid_status - hide TracerPid
static void before_proc_pid_status(hook_fargs2_t*args,void*udata){
    args->local.data0=0;args->local.data1=0;
    if(!is_app())return;
    args->local.data1=1;
    struct seq_file*m=(struct seq_file*)args->arg0;
    if(m&&m->buf)args->local.data0=(uint64_t)m->count;
}
static void after_proc_pid_status(hook_fargs2_t*args,void*udata){
    if(!args->local.data1)return;
    struct seq_file*m=(struct seq_file*)args->arg0;
    if(!m||!m->buf)return;
    size_t old=(size_t)args->local.data0;
    if(m->count<=old)return;
    char*buf=m->buf;size_t count=m->count;
    // Find and modify TracerPid
    char*pos=(char*)my_memmem(buf,count,"TracerPid:\t",11);
    if(pos&&(size_t)(pos-buf)+11<count){
        char*val=pos+11;
        while(val<buf+count&&*val>='0'&&*val<='9')val++;
        if(val>pos+11){*(pos+11)='0';
            size_t skip=val-(pos+12);
            if(skip>0){char*dst=pos+12,*src=val;while(src<buf+count)*dst++=*src++;m->count-=skip;}}
    }
}

// comm_show - hide Frida thread names (sub_60728 thread scanning)
static void before_comm_show(hook_fargs2_t*args,void*udata){
    args->local.data0=0;args->local.data1=0;
    if(!is_app())return;
    args->local.data1=1;
    struct seq_file*m=(struct seq_file*)args->arg0;
    if(m&&m->buf)args->local.data0=(uint64_t)m->count;
}
static void after_comm_show(hook_fargs2_t*args,void*udata){
    if(!args->local.data1)return;
    struct seq_file*m=(struct seq_file*)args->arg0;
    if(!m||!m->buf)return;
    size_t old=(size_t)args->local.data0;
    if(m->count<=old)return;
    char*nd=m->buf+old;size_t nl=m->count-old;
    if(nl>0&&nl<64&&is_frida_thread(nd)){
        const char*fake="kworker\n";
        for(int i=0;i<8;i++)nd[i]=fake[i];
        m->count=old+8;
    }
}

// __get_task_comm - hide Frida thread names
static void after_get_task_comm(hook_fargs3_t*args,void*udata){
    if(!is_app())return;
    char*buf=(char*)args->arg0;
    if(buf&&is_frida_thread(buf)){buf[0]='k';buf[1]='w';buf[2]='o';buf[3]='r';buf[4]='k';buf[5]='e';buf[6]='r';buf[7]='\0';}
}

// do_readlinkat - hide Frida FD links (NagaLinker sub_85AE0 FD detection)
static void after_do_readlinkat(hook_fargs4_t*args,void*udata){
    if(!is_app())return;
    const char __user*pathname=(const char __user*)args->arg1;
    char __user*buf=(char __user*)args->arg2;
    long ret=(long)args->ret;
    if(ret<=0||!buf||!pathname)return;
    // Check if reading /proc/self/fd/*
    char pathbuf[64];
    long plen=compat_strncpy_from_user(pathbuf,pathname,sizeof(pathbuf)-1);
    if(plen<=0)return;
    pathbuf[plen]='\0';
    if(!my_startswith(pathbuf,"/proc/self/fd/"))return;
    // Read the link target
    char linkbuf[256];
    if(compat_strncpy_from_user(linkbuf,buf,ret>255?255:ret)<=0)return;
    linkbuf[ret>255?255:ret]='\0';
    // Check if target contains Frida keywords
    if(is_frida_mapping(linkbuf,my_strlen(linkbuf))){
        // Replace with fake path
        const char*fake="/dev/null";
        compat_copy_to_user(buf,fake,10);
        args->ret=9;
    }
}

// ==================== Init/Exit ====================

static long frida_hide_init(const char*args,const char*event,void*__user reserved){
    LOGV("init v3.0.0-venus\n");
    int count=0;

    // Maps/Smaps filtering
    HOOK_WRAP2(show_map_vma,before_show_map_vma,after_show_map_vma,show_map_vma_addr,count);
    HOOK_WRAP2(show_smap,before_show_map_vma,after_show_map_vma,show_smap_addr,count);

    // TCP port blocking
    HOOK_WRAP3(tcp_v4_connect,before_tcp_v4_connect,0,tcp_v4_connect_addr,count);
    HOOK_WRAP3(tcp_v6_connect,before_tcp_v6_connect,0,tcp_v6_connect_addr,count);

    // File access blocking
    HOOK_WRAP4(do_faccessat,before_faccessat,0,do_faccessat_addr,count);

    // faccessat2 syscall variant
    uint64_t addr=kallsyms_lookup_name("__arm64_sys_faccessat2");
    if(!addr)addr=kallsyms_lookup_name("__se_sys_faccessat2");
    if(addr&&addr!=do_faccessat_addr){
        if(hook_wrap4((void*)addr,before_faccessat,0,0)==HOOK_NO_ERR){sys_faccessat2_addr=addr;count++;}
    }

    HOOK_WRAP4(vfs_fstatat,before_vfs_fstatat,0,vfs_fstatat_addr,count);
    HOOK_WRAP5(vfs_statx,before_statx,0,vfs_statx_addr,count);
    HOOK_WRAP5(do_statx,before_statx,0,do_statx_addr,count);
    HOOK_WRAP3(do_filp_open,before_do_filp_open,0,do_filp_open_addr,count);

    // TracerPid hiding
    HOOK_WRAP2(proc_pid_status,before_proc_pid_status,after_proc_pid_status,proc_pid_status_addr,count);

    // Thread name hiding
    uint64_t comm_addr=kallsyms_lookup_name("comm_show");
    if(comm_addr){
        if(hook_wrap2((void*)comm_addr,before_comm_show,after_comm_show,0)==HOOK_NO_ERR){comm_write_addr=comm_addr;count++;}
    }else{
        comm_addr=kallsyms_lookup_name("__get_task_comm");
        if(!comm_addr)comm_addr=kallsyms_lookup_name("get_task_comm");
        if(comm_addr){
            if(hook_wrap3((void*)comm_addr,0,after_get_task_comm,0)==HOOK_NO_ERR){comm_write_addr=comm_addr;count++;}
        }
    }

    // readlinkat - hide Frida FD links (NagaLinker sub_85AE0 bypass)
    HOOK_WRAP4(do_readlinkat,0,after_do_readlinkat,do_readlinkat_addr,count);

    LOGV("loaded, %d hooks\n",count);
    return 0;
}

static long frida_hide_control0(const char*args,char*__user out_msg,int outlen){
    const char msg[]="frida_hide v3.0.0-venus OK";
    if(out_msg&&outlen>0)compat_copy_to_user(out_msg,msg,sizeof(msg)<outlen?sizeof(msg):outlen);
    return 0;
}

static long frida_hide_exit(void*__user reserved){
    LOGV("exit\n");
    UNHOOK(do_readlinkat_addr);
    UNHOOK(comm_write_addr);
    UNHOOK(proc_pid_status_addr);
    UNHOOK(do_filp_open_addr);
    UNHOOK(do_statx_addr);
    UNHOOK(vfs_statx_addr);
    UNHOOK(vfs_fstatat_addr);
    UNHOOK(sys_faccessat2_addr);
    UNHOOK(do_faccessat_addr);
    UNHOOK(tcp_v6_connect_addr);
    UNHOOK(tcp_v4_connect_addr);
    UNHOOK(show_smap_addr);
    UNHOOK(show_map_vma_addr);
    return 0;
}

KPM_INIT(frida_hide_init);
KPM_CTL0(frida_hide_control0);
KPM_EXIT(frida_hide_exit);
