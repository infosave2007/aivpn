#pragma once
#include <stdbool.h>

extern bool bpf_session_is_return(void *context) __ksym;
extern __u64 *bpf_session_cookie(void *context) __ksym;

#if defined(__TARGET_ARCH_x86)
struct pt_regs___lookup {
    unsigned long di, ax;
} __attribute__((preserve_access_index));
static __always_inline __u64 lookup_fd_argument(void *context) {
    return BPF_CORE_READ((struct pt_regs___lookup *)context, di);
}
static __always_inline __u64 lookup_fd_return(void *context) {
    return BPF_CORE_READ((struct pt_regs___lookup *)context, ax);
}
#elif defined(__TARGET_ARCH_arm64)
struct user_pt_regs___lookup {
    unsigned long regs[31];
} __attribute__((preserve_access_index));
static __always_inline __u64 lookup_fd_argument(void *context) {
    return BPF_CORE_READ((struct user_pt_regs___lookup *)context, regs[0]);
}
static __always_inline __u64 lookup_fd_return(void *context) {
    return BPF_CORE_READ((struct user_pt_regs___lookup *)context, regs[0]);
}
#else
#error Unsupported FD return ABI
#endif

/* Cookie принадлежит одному вызову, включая вложенные обращения к fdget_raw. */
SEC("kprobe.session/fdget_raw")
int lookup_fdget(struct pt_regs *context) {
    struct lookup_capture *capture = lookup_current(0);
    struct lookup_operation *operation = lookup_top(capture);
    int returning = bpf_session_is_return(context);
    if (!operation || !operation->walk)
        return returning ? 0 : 1;
    __u64 *session = bpf_session_cookie(context);
    if (!session)
        return returning ? 0 : 1;
    if (!returning) {
        if (operation->fd_state != 1 ||
            (__u32)lookup_fd_argument(context) != (__u32)operation->expected_fd)
            return 1;
        *session = operation->token;
        operation->fd_state = 2;
        return 0;
    }
    if (!*session || *session != operation->token || operation->fd_state != 2)
        return 0;
    __u64 address = lookup_fd_return(context) & ~3ULL;
    __u64 *source = address ? bpf_map_lookup_elem(&lookup_files, &address) : 0;
    __u64 id = source ? lookup_acquire(*source) : 0;
    const struct ap_lookup_proof *proof = lookup_find(id);
    __u64 inode = address ? (unsigned long)BPF_CORE_READ((struct file *)(unsigned long)address, f_inode) : 0;
    if (id && (!proof || !inode || proof->facts.inode_address != inode)) {
        lookup_release(id);
        id = 0;
    }
    __u64 previous = __sync_lock_test_and_set(&operation->base_lookup, id);
    lookup_release(previous);
    operation->fd_state = id ? 3 : 4;
    return 0;
}
