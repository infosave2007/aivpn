#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int mode(const char *name) {
    const char *value = getenv("RETENTION_FAULT");
    return value && !strcmp(value, name);
}
static void stop(void) { kill(getpid(), SIGKILL); }

int bpf_obj_pin(int fd, const char *path) {
    int (*real)(int, const char *) = dlsym(RTLD_NEXT, "bpf_obj_pin");
    if (mode("pin-error") && strstr(path, "/link")) return -EIO;
    int result = real(fd, path);
    const char *cut = getenv("RETENTION_PIN_CUT");
    if (!result && cut && strstr(path, cut)) stop();
    return result;
}
int mkdirat(int parent, const char *name, mode_t permissions) {
    int (*real)(int,const char *,mode_t) = dlsym(RTLD_NEXT,"mkdirat");
    int result = real(parent,name,permissions);
    if (!result && mode("reserve") && !strncmp(name,"pending_",8)) stop();
    return result;
}
int unlinkat(int parent, const char *name, int flags) {
    int (*real)(int,const char *,int) = dlsym(RTLD_NEXT,"unlinkat");
    int result = real(parent,name,flags);
    const char *cut = getenv("RETENTION_UNLINK_CUT");
    if (!result && cut && !strcmp(cut,name)) stop();
    return result;
}
int renameat2(int oldfd, const char *old, int newfd, const char *new, unsigned flags) {
    int (*real)(int,const char *,int,const char *,unsigned) = dlsym(RTLD_NEXT, "renameat2");
    int result = real(oldfd,old,newfd,new,flags);
    if (!result && mode("commit") && !strncmp(new,"link_",5)) stop();
    if (!result && mode("release") && !strncmp(new,"releasing_",10)) stop();
    return result;
}
int bpf_link_create(int program, int target, enum bpf_attach_type type, const struct bpf_link_create_opts *opts) {
    int (*real)(int,int,enum bpf_attach_type,const struct bpf_link_create_opts *) = dlsym(RTLD_NEXT,"bpf_link_create");
    if (type != BPF_TRACE_UPROBE_MULTI) return real(program,target,type,opts);
    struct bpf_link_create_opts changed = *opts;
    unsigned long offsets[2] = {0,1};
    if (mode("pid0")) changed.uprobe_multi.pid = 0;
    if (mode("pid_other")) changed.uprobe_multi.pid = (unsigned)getppid();
    if (mode("offset")) { offsets[0]=1;changed.uprobe_multi.offsets=offsets; }
    if (mode("count")) { changed.uprobe_multi.cnt=2;changed.uprobe_multi.offsets=offsets; }
    if (mode("flags")) changed.uprobe_multi.flags = BPF_F_UPROBE_MULTI_RETURN;
    int result = real(program,target,type,&changed);
    if (result >= 0 && mode("replace")) {
        if (rename(getenv("RETENTION_REPLACEMENT"),getenv("RETENTION_TARGET"))) abort();
    }
    return result;
}

int ar_retention_test_forge(int program, int file, int fault) {
    char path[64];
    snprintf(path,sizeof(path),"/proc/self/fd/%d",file);
    unsigned long offsets[2]={0,1};
    struct bpf_link_create_opts opts={.sz=sizeof(opts)};
    opts.uprobe_multi.path=path;opts.uprobe_multi.offsets=offsets;
    opts.uprobe_multi.cnt=1;opts.uprobe_multi.pid=(unsigned)getpid();
    if(fault==1) opts.uprobe_multi.pid=0;
    if(fault==2) offsets[0]=1;
    if(fault==3) opts.uprobe_multi.cnt=2;
    if(fault==4) opts.uprobe_multi.flags=BPF_F_UPROBE_MULTI_RETURN;
    return bpf_link_create(program,0,BPF_TRACE_UPROBE_MULTI,&opts);
}
int ar_retention_test_id(int fd) {
    struct bpf_link_info info={0};uint32_t size=sizeof(info);
    int result=bpf_obj_get_info_by_fd(fd,&info,&size);
    return result ? result : (int)info.id;
}

/* Пространства ID независимы. Программа KPROBE имеет тот же номер enum2,
 * что ARRAY map, поэтому одного чтения первого поля info недостаточно. */
static int collision_program(void) {
    const struct bpf_insn code[] = {
        {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0},
        {.code = BPF_JMP | BPF_EXIT},
    };
    return bpf_prog_load(BPF_PROG_TYPE_KPROBE, "retention_test", "GPL",
                         code, sizeof(code) / sizeof(code[0]), NULL);
}
static int program_identity(int fd, uint32_t *identity) {
    struct bpf_prog_info info = {0};
    uint32_t length = sizeof(info);
    int result = bpf_obj_get_info_by_fd(fd, &info, &length);
    if (!result) { identity[0] = info.type; identity[1] = info.id; }
    return result;
}
int ar_retention_test_reserve_map_ids(void) {
    int program = collision_program();
    if (program < 0) return program;
    uint32_t identity[2];
    int result = program_identity(program, identity);
    close(program);
    if (result) return result;
    for (unsigned index = 0; index < 4096; index++) {
        int fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "collision_gap", 4, 16, 1, NULL);
        if (fd < 0) return fd;
        struct bpf_map_info info = {0};
        uint32_t length = sizeof(info);
        result = bpf_obj_get_info_by_fd(fd, &info, &length);
        close(fd);
        if (result) return result;
        if (info.id >= identity[1] + 128) return 0;
    }
    return -E2BIG;
}
int ar_retention_test_same_id_program(int map, uint32_t *identity) {
    struct bpf_map_info info = {0};
    uint32_t length = sizeof(info);
    int result = bpf_obj_get_info_by_fd(map, &info, &length);
    if (result) return result;
    if (info.type != BPF_MAP_TYPE_ARRAY || info.key_size != 4 ||
        info.value_size != 16 || info.max_entries != 1) return -EINVAL;
    for (unsigned index = 0; index < 4096; index++) {
        int fd = collision_program();
        if (fd < 0) return fd;
        result = program_identity(fd, identity);
        if (!result && identity[1] == info.id) return fd;
        close(fd);
        if (result) return result;
        if (identity[1] > info.id) return -ERANGE;
    }
    return -E2BIG;
}
