#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

__attribute__((constructor)) static void bounded_process(void) {alarm(5);}
static int active(const char *mode)
{
    const char *armed=getenv("AIVPN_STATE_ARMED"),*selected=getenv("AIVPN_STATE_FAULT");
    return armed && !strcmp(armed,"1") && selected && !strcmp(selected,mode);
}
static int fd_path(int fd,char path[4096])
{
    char source[64];snprintf(source,sizeof(source),"/proc/self/fd/%d",fd);
    ssize_t count=readlink(source,path,4095);if(count<0)return 0;
    path[count]=0;return 1;
}
static int named(int fd,const char *name)
{
    char path[4096];if(!fd_path(fd,path))return 0;
    const char *base=strrchr(path,'/');return base && !strcmp(base+1,name);
}
static int denied(void) {errno=EIO;return -1;}
int openat(int parent,const char *name,int flags,...)
{
    static int (*real)(int,const char *,int,...);
    if(!real)real=dlsym(RTLD_NEXT,"openat");
    mode_t mode=0;
    if(flags&O_CREAT) {va_list args;va_start(args,flags);mode=(mode_t)va_arg(args,int);va_end(args);}
    if(active("open") || (active("temporary-open") && !strcmp(name,".new-state.json")))return denied();
    int fd=real(parent,name,flags,mode);
    if(active("descriptor-zero") && fd>0) {
        if(dup3(fd,0,O_CLOEXEC)<0) {close(fd);return -1;}
        close(fd);return 0;
    }
    return fd;
}
int fchmod(int fd,mode_t mode)
{
    static int (*real)(int,mode_t);if(!real)real=dlsym(RTLD_NEXT,"fchmod");
    if(active("chmod") || (active("chmod-temporary") && named(fd,".new-state.json")))return denied();
    return real(fd,mode);
}
int flock(int fd,int operation)
{
    static int (*real)(int,int);if(!real)real=dlsym(RTLD_NEXT,"flock");
    if(active("lock"))return denied();
    return real(fd,operation);
}
int fsync(int fd)
{
    static int (*real)(int);if(!real)real=dlsym(RTLD_NEXT,"fsync");
    struct stat metadata;if(fstat(fd,&metadata))return -1;
    if((S_ISREG(metadata.st_mode) && active("sync-file")) || (S_ISDIR(metadata.st_mode) && (active("sync-directory") || active("sync-open"))))return denied();
    return real(fd);
}
int renameat(int from,const char *old,int to,const char *next)
{
    static int (*real)(int,const char *,int,const char *);if(!real)real=dlsym(RTLD_NEXT,"renameat");
    if(active("rename"))return denied();
    return real(from,old,to,next);
}
int unlinkat(int parent,const char *name,int flags)
{
    static int (*real)(int,const char *,int);if(!real)real=dlsym(RTLD_NEXT,"unlinkat");
    if(active("unlink"))return denied();
    return real(parent,name,flags);
}
ssize_t write(int fd,const void *data,size_t count)
{
    static ssize_t (*real)(int,const void *,size_t);if(!real)real=dlsym(RTLD_NEXT,"write");
    if(named(fd,".new-state.json")) {
        if(active("write-error"))return denied();
        if(active("write-zero"))return 0;
        if(active("write-short") && count>1)count=1;
    }
    return real(fd,data,count);
}
ssize_t read(int fd,void *data,size_t count)
{
    static ssize_t (*real)(int,void *,size_t);if(!real)real=dlsym(RTLD_NEXT,"read");
    if(named(fd,"state.json")) {
        if(active("read-error"))return denied();
        if(active("read-early-eof"))return 0;
        if(active("read-rewrite")) {
            ssize_t result=real(fd,data,count);char path[4096];
            if(!fd_path(fd,path))return -1;
            int output=open(path,O_WRONLY|O_CLOEXEC);if(output<0)return -1;
            struct timespec times[2]={{.tv_nsec=UTIME_OMIT},{.tv_sec=42,.tv_nsec=0}};
            int changed=futimens(output,times);close(output);return changed?-1:result;
        }
        if(active("read-short") && count>1)count=1;
        static int grown;
        if(active("read-grow") && !grown) {
            grown=1;
            char path[4096];if(!fd_path(fd,path))return -1;
            int output=open(path,O_WRONLY|O_APPEND|O_CLOEXEC);if(output<0)return -1;
            ssize_t written=write(output,"x",1);close(output);if(written!=1)return -1;
        }
    }
    return real(fd,data,count);
}
pid_t getpid(void)
{
    static pid_t (*real)(void);if(!real)real=dlsym(RTLD_NEXT,"getpid");
    pid_t value=real();return active("foreign-process")?value+1:value;
}
