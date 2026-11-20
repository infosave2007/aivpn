#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int matches(const char *key, const char *value) {
    const char *wanted = getenv(key);
    return wanted && !strcmp(wanted, value);
}
static void stop(void) { kill(getpid(), SIGKILL); }
static int directory_is(int fd, const char *kind) {
    char path[64], target[512];
    snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
    ssize_t n=readlink(path,target,sizeof(target)-1);
    if(n<0)return 0;
    target[n]=0;
    const char *last=strrchr(target,'/');
    return last && !strcmp(last+1,kind);
}
int renameat(int fromfd, const char *from, int tofd, const char *to) {
    int (*real)(int,const char *,int,const char *)=dlsym(RTLD_NEXT,"renameat");
    int result=real(fromfd,from,tofd,to);
    const char *dir=getenv("VERIFIED_RENAME_DIR");
    static unsigned calls;
    if(!result && dir && directory_is(tofd,dir) && !strcmp(to,"state.json")) {
        calls++;
        const char *nth=getenv("VERIFIED_RENAME_NTH");
        if(nth && calls==strtoul(nth,NULL,10)) {
            if(matches("VERIFIED_MODE","ambiguous")){errno=EIO;return -1;}
            stop();
        }
    }
    return result;
}
int bpf_obj_pin(int fd,const char *path) {
    int (*real)(int,const char *)=dlsym(RTLD_NEXT,"bpf_obj_pin");
    int result=real(fd,path);
    const char *cut=getenv("VERIFIED_PIN_CUT");
    if(!result && cut && strstr(path,cut))stop();
    return result;
}
int mkdirat(int parent,const char *name,mode_t mode) {
    int (*real)(int,const char *,mode_t)=dlsym(RTLD_NEXT,"mkdirat");
    int result=real(parent,name,mode);
    if(!result && matches("VERIFIED_MODE","pending") && !strncmp(name,"pending_",8))stop();
    return result;
}
int renameat2(int fromfd,const char *from,int tofd,const char *to,unsigned flags) {
    int (*real)(int,const char *,int,const char *,unsigned)=dlsym(RTLD_NEXT,"renameat2");
    int result=real(fromfd,from,tofd,to,flags);
    if(!result && matches("VERIFIED_MODE","completed") && !strncmp(to,"link_",5))stop();
    if(!result && matches("VERIFIED_MODE","releasing") && !strncmp(to,"releasing_",10))stop();
    return result;
}
int unlinkat(int parent,const char *name,int flags) {
    int (*real)(int,const char *,int)=dlsym(RTLD_NEXT,"unlinkat");
    int result=real(parent,name,flags);
    if(!result && flags==AT_REMOVEDIR && matches("VERIFIED_MODE","rmdir") && !strncmp(name,"releasing_",10))stop();
    if(!result && matches("VERIFIED_UNLINK_CUT",name))stop();
    return result;
}
int bpf_map_update_elem(int fd,const void *key,const void *value,__u64 flags) {
    int (*real)(int,const void *,const void *,__u64)=dlsym(RTLD_NEXT,"bpf_map_update_elem");
    struct bpf_map_info info={0};unsigned size=sizeof(info);
    if(!matches("VERIFIED_MODE","exec-race") || flags!=BPF_NOEXIST || bpf_obj_get_info_by_fd(fd,&info,&size) || info.type!=BPF_MAP_TYPE_INODE_STORAGE) return real(fd,key,value,flags);
    pid_t child=fork();
    if(!child){execl("/usr/bin/retention-target","retention-target",NULL);_exit(120);}
    int status=0;if(child<0 || waitpid(child,&status,0)!=child || status)abort();
    int result=real(fd,key,value,flags);
    unsigned long long winner=0;
    if(bpf_map_lookup_elem(fd,key,&winner))abort();
    FILE *output=fopen("/lab/verified-race-result","w");if(!output)abort();
    fprintf(output,"%d %llu %llu\n",result,*(const unsigned long long *)value,winner);fclose(output);
    return result;
}
