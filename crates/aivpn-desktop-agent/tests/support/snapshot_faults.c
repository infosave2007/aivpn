#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static int candidate=-1;
static int failure(const char *point) {
    const char *selected=getenv("AIVPN_SNAPSHOT_FAULT");
    return selected && strcmp(selected,point)==0;
}
int bpf_map_create(enum bpf_map_type type,const char *name,__u32 key,__u32 value,__u32 count,const struct bpf_map_create_opts *options) {
    int (*next)(enum bpf_map_type,const char *,__u32,__u32,__u32,const struct bpf_map_create_opts *)=dlsym(RTLD_NEXT,"bpf_map_create");
    int snapshot=name && strcmp(name,"binding_bundle")==0;
    if(snapshot && failure("allocation"))return -ENOMEM;
    int fd=next(type,name,key,value,count,options);
    if(snapshot)candidate=fd;
    return fd;
}
int bpf_map_update_elem(int fd,const void *key,const void *value,__u64 flags) {
    if(fd==candidate && failure("fill"))return -EIO;
    int (*next)(int,const void *,const void *,__u64)=dlsym(RTLD_NEXT,"bpf_map_update_elem");
    return next(fd,key,value,flags);
}
int bpf_map_get_next_key(int fd,const void *key,void *next_key) {
    if(fd==candidate && failure("readback"))return -EIO;
    int (*next)(int,const void *,void *)=dlsym(RTLD_NEXT,"bpf_map_get_next_key");
    return next(fd,key,next_key);
}
int bpf_map_freeze(int fd) {
    if(fd==candidate && failure("freeze"))return -EIO;
    int (*next)(int)=dlsym(RTLD_NEXT,"bpf_map_freeze");
    return next(fd);
}
