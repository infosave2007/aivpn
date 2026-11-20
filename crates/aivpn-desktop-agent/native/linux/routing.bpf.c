#include "../dns_ports.h"
#include <linux/bpf.h>
#include <linux/in6.h>
#include <stddef.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
/* libbpf до 1.4 не объявляет аннотации аргументов глобальных подпрограмм. */
#ifndef __arg_ctx
#define __arg_ctx __attribute__((btf_decl_tag("arg:ctx")))
#endif
#ifndef __arg_nonnull
#define __arg_nonnull __attribute__((btf_decl_tag("arg:nonnull")))
#endif
#define AIVPN_BPF
#define AP_FOR(index, limit)                                                                       \
    for (int index = 0, _once = 1; _once; _once = 0)                                               \
    bpf_for(index, 0, limit)
#include "routing.h"
#ifdef AP_BINDING_SNAPSHOT
#include "binding-snapshot.h"
#endif
#include "kernel-policy/evaluate.h"
#include "transport-state.h"

struct sk_buff___ct {
    unsigned long _nfct;
    struct sock *sk;
} __attribute__((preserve_access_index));
struct nf_conntrack_zone {
    __u16 id;
} __attribute__((preserve_access_index));
struct nf_conn___zone {
    struct nf_conntrack_zone zone;
} __attribute__((preserve_access_index));
extern void *bpf_cast_to_kern_ctx(void *) __ksym;
static __always_inline __u32 connection_zone(__u64 tagged) {
    struct nf_conn___zone *connection = (void *)(unsigned long)(tagged & ~7ULL);
    return connection ? BPF_CORE_READ(connection, zone.id) : 0;
}
static __always_inline __u32 packet_zone(struct __sk_buff *packet) {
    struct sk_buff___ct *internal = bpf_cast_to_kern_ctx(packet);
    return connection_zone(BPF_CORE_READ(internal, _nfct));
}
struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
} __attribute__((preserve_access_index));
struct inode {
    unsigned long i_ino;
} __attribute__((preserve_access_index));
struct file {
    struct path f_path;
    struct inode *f_inode;
    unsigned int f_flags;
} __attribute__((preserve_access_index));
struct linux_binprm {
    struct file *file;
    unsigned int is_check : 1;
} __attribute__((preserve_access_index));
struct kuid_t {
    __u32 val;
} __attribute__((preserve_access_index));
struct cred {
    struct kuid_t uid;
} __attribute__((preserve_access_index));
struct ns_common {
    unsigned int inum;
} __attribute__((preserve_access_index));
struct mnt_namespace {
    struct ns_common ns;
} __attribute__((preserve_access_index));
struct nsproxy {
    struct mnt_namespace *mnt_ns;
} __attribute__((preserve_access_index));
struct task_struct {
    struct task_struct *real_parent;
    const struct cred *real_cred;
    int tgid;
    struct nsproxy *nsproxy;
    struct fs_struct *fs;
    struct nameidata *nameidata;
    unsigned int in_execve : 1;
} __attribute__((preserve_access_index));
struct path_buffer {
    char bytes[4096];
};
struct working_buffer {
    char reverse_path[4096];
    struct path_buffer path;
    struct ap_context context;
#ifdef AP_BINDING_SNAPSHOT
    struct bs_key lookup_key;
    __u64 source_markers[4];
    struct ap_lookup_candidate prefix_physical, prefix_logical;
    struct lookup_fs_work base_guard;
    char lookup_suffix[4096];
    volatile __u32 lookup_output, lookup_component;
#endif
    __u32 busy, reserved;
};
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct task_capture);
} processes SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct process_companion);
} process_companions SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, __u64);
} task_identities SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, struct working_buffer);
} scratch SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ph_hash);
} path_key SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct application_key);
    __type(value, __u32);
} applications SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_INODE_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, __u64);
} inode_tokens SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} file_counter SEC(".maps"), file_result SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u32);
} file_bindings SEC(".maps");
SEC("uprobe.multi") int retain_application_inode(void *context) {
    (void)context;
    return 0;
}
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, struct ap_policy);
} policies SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct profile);
} profiles SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct interface_key);
    __type(value, __u32);
} interface_profiles SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, struct mark_key);
    __type(value, __u32);
} mark_profiles SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} profile_zones SEC(".maps");
#include "dns-state.h"
/* Нулевой mask сохраняет прежний ABI fixtures; новый путь резервирует старшие 16 bits. */
static __always_inline int profile_mark_matches(const struct profile *profile, __u32 mark) {
    __u32 mask = profile->mark_mask ? profile->mark_mask : ~0U;
    return (mark & mask) == profile->mark;
}
static __always_inline __u32 *owned_mark_profile(struct mark_key *key) {
    __u32 *slot = bpf_map_lookup_elem(&mark_profiles, key);
    if (slot) return slot;
    struct mark_key masked = {.network_namespace = key->network_namespace, .mark = key->mark & 0xffff0000U};
    slot = bpf_map_lookup_elem(&mark_profiles, &masked);
    const struct profile *profile = slot ? bpf_map_lookup_elem(&profiles, slot) : 0;
    return profile && profile->mark_mask == 0xffff0000U ? slot : 0;
}

extern int bpf_path_d_path(struct path *, char *, size_t) __ksym;
extern struct task_struct *bpf_task_acquire(struct task_struct *) __ksym;
extern void bpf_task_release(struct task_struct *) __ksym;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

static __always_inline struct working_buffer *scratch_acquire(void) {
#pragma clang loop unroll(disable)
    for (__u32 slot = 0; slot < 4; slot++) {
        __u32 key = slot;
        struct working_buffer *work = bpf_map_lookup_elem(&scratch, &key);
        if (work && !__sync_val_compare_and_swap(&work->busy, 0, 1))
            return work;
    }
    return 0;
}
static __always_inline void scratch_release(struct working_buffer *work) {
    __sync_lock_test_and_set(&work->busy, 0);
}
static __noinline __u64 next_file_cookie(void) {
    __u32 zero = 0;
    __u64 *counter = bpf_map_lookup_elem(&file_counter, &zero);
    if (!counter)
        return 0;
    for (unsigned retry = 0; retry < 16; retry++) {
        __u64 previous = __sync_fetch_and_add(counter, 0);
        if (previous == ~0ULL)
            return 0;
        if (__sync_val_compare_and_swap(counter, previous, previous + 1) == previous)
            return previous + 1;
    }
    return 0;
}
static __noinline __u64 task_identity(struct task_struct *task, int create) {
    __u64 *identity = bpf_task_storage_get(&task_identities, task, 0,
                                           create ? BPF_LOCAL_STORAGE_GET_F_CREATE : 0);
    if (!identity)
        return 0;
    if (!*identity && create) {
        /* Файлы и процессы используют общий неповторяющийся счетчик. */
        __u64 candidate = next_file_cookie();
        if (candidate)
            __sync_val_compare_and_swap(identity, 0, candidate);
    }
    return *identity;
}
SEC("socket") int allocate_file_cookie(struct __sk_buff *packet) {
    (void)packet;
    __u32 zero = 0;
    __u64 *result = bpf_map_lookup_elem(&file_result, &zero);
    if (!result)
        return 0;
    *result = next_file_cookie();
    return *result != 0;
}
static __noinline __u64 inode_cookie(struct file *file) {
    bpf_rcu_read_lock();
    struct inode *inode = file->f_inode;
    __u64 *found = bpf_inode_storage_get(&inode_tokens, inode, 0, 0);
    if (!found) {
        __u64 candidate = next_file_cookie();
        if (candidate)
            found = bpf_inode_storage_get(&inode_tokens, inode, &candidate,
                                          BPF_LOCAL_STORAGE_GET_F_CREATE);
    }
    __u64 cookie = found ? *found : 0;
    bpf_rcu_read_unlock();
    return cookie;
}
__noinline void hash_resolved_path(struct path_buffer *path, __u32 length,
                                   const struct ph_hash *key, struct ph_hash *output) {
    if (!path || !key || !output || length < 1 || length >= sizeof(path->bytes))
        return;
    *output = ph_path((const __u8 *)path->bytes, length, key->low, key->high);
}
#include "file-identity.h"

static __noinline void classify(struct origin_hash *origin, struct file *file) {
    origin->path_flags = 0;
    origin->file_cookie = 0;
    origin->filesystem_device = 0;
    origin->path = (struct ph_hash){0};
    origin->logical_path = (struct ph_hash){0};
    if (!file)
        return;
    origin->file_cookie = inode_cookie(file);
    if (!origin->file_cookie || !origin->task_identity || !origin->exec_identity || !origin->owner_epoch)
        return;
    __u32 zero = 0;
    struct ph_hash *key = bpf_map_lookup_elem(&path_key, &zero);
    if (!key)
        return;
    struct working_buffer *work = scratch_acquire();
    if (!work)
        return;
    __u32 before = 0, after = 0;
    if (physical_rename_sequence(&before) || (before & 1)) {
        scratch_release(work);
        return;
    }
    physical_read_barrier(work);
    int length = physical_file_path(file, work, &origin->filesystem_device);
    if (length > 0 && length < 4096) {
        hash_resolved_path(&work->path, (__u32)length, key, &origin->path);
        origin->path_flags |= AP_PATH_PHYSICAL;
    }
    length = bpf_path_d_path(&file->f_path, work->path.bytes, sizeof(work->path.bytes));
    if (length > 1 && length <= 4096) {
        hash_resolved_path(&work->path, (__u32)length - 1, key, &origin->logical_path);
        origin->path_flags |= AP_PATH_LOGICAL;
    }
    physical_read_barrier(work);
    if (physical_rename_sequence(&after) || before != after)
        origin->path_flags = 0;
    scratch_release(work);
}
#include "exec-history.h"

static __always_inline struct process_companion *task_companion(struct task_struct *task, int create) {
    return bpf_task_storage_get(&process_companions, task, 0,
        create ? BPF_LOCAL_STORAGE_GET_F_CREATE : 0);
}
static __always_inline void publish_capture(struct task_capture *capture,
                                            struct process_companion *companion) {
    __u64 token = next_file_cookie();
    if (companion)
        companion->snapshot_identity = token;
    capture->committed.snapshot_identity = token;
}
/* Без source, захваченного до binfmt, текущий ELF не доказывает прежний запуск. */
static __noinline struct task_capture *capture_current(int create) {
    struct task_struct *task = bpf_get_current_task_btf();
    struct task_capture *capture = bpf_task_storage_get(&processes, task, 0,
        create ? BPF_LOCAL_STORAGE_GET_F_CREATE : 0);
    if (capture && !capture->committed.self.source.task_identity) {
        __u64 identity = task_identity(task, create);
        __u64 epoch = next_file_cookie();
        frame_owner(&capture->committed.self, (__u32)bpf_get_current_uid_gid(), epoch, identity);
        capture->committed.self.source.exec_identity = next_file_cookie();
        capture->committed.self.image.exec_identity = capture->committed.self.source.exec_identity;
        publish_capture(capture, task_companion(task, create));
    }
    return capture;
}

static __noinline int owner_needs_capture(__u32 uid) {
    struct ap_policy_view view = {0};
#ifdef AP_BINDING_SNAPSHOT
    /* Пока root не опубликован, exec не получает нового ограничения. */
    __u32 zero = 0;
    if (!bpf_map_lookup_elem(&binding_root, &zero))
        return 0;
    int found = bs_begin(&view, uid);
    if (found <= 0)
        return 0;
    struct working_buffer *work = scratch_acquire();
    if (!work)
        return 0;
    view.lookup = &work->lookup_key;
#else
    __u64 owner = 3ULL << 32;
    view.policy = bpf_map_lookup_elem(&policies, &owner);
    if (!view.policy) {
        owner = (1ULL << 32) | uid;
        view.policy = bpf_map_lookup_elem(&policies, &owner);
    }
    if (!view.policy)
        return 0;
#endif
    int needs_capture = 0;
    AP_FOR(index, AP_RULE_LIMIT) {
        if ((unsigned)index >= view.policy->count)
            break;
        const struct ap_rule *rule = AP_VIEW_RULE(&view, index);
        if (!rule) {
            needs_capture = 0;
            break;
        }
        needs_capture |= rule->selector != 0;
    }
#ifdef AP_BINDING_SNAPSHOT
    scratch_release(work);
#endif
    return needs_capture;
}

static __noinline struct process_state *ensure_identity(void) {
    struct task_capture *capture = capture_current(1);
    if (!capture)
        return 0;
    /* Captured partial не повышается по имени, прочитанному после exec. */
    return &capture->committed;
}

SEC("fexit/commit_creds")
int BPF_PROG(observe_owner, struct cred *credentials, int ret) {
    (void)ctx;
    (void)credentials;
    if (ret)
        return 0;
    struct task_struct *task = bpf_get_current_task_btf();
    struct task_capture *capture = bpf_task_storage_get(&processes, task, 0, 0);
    if (!capture)
        return 0;
    __u32 owner = BPF_CORE_READ(task, real_cred, uid.val);
    int in_exec = BPF_CORE_READ_BITFIELD_PROBED(task, in_execve);
    __u32 previous = capture->pending.active && in_exec ? capture->pending.source.uid :
                                                        capture->committed.self.source.uid;
    if (owner != previous) {
        struct process_companion *companion = task_companion(task, 0);
        if (!process_pair_valid(&capture->committed, companion))
            history_unknown_pair(&capture->committed, companion);
        history_owner(capture, companion, owner, next_file_cookie(),
                      in_exec);
        publish_capture(capture, companion);
    }
    return 0;
}

SEC("lsm/socket_create")
int BPF_PROG(prepare_socket, int family, int type, int protocol, int kern, int ret) {
    (void)ctx;
    (void)type;
    (void)protocol;
    if (ret || kern || (family != 2 && family != 10))
        return ret;
    ensure_identity();
    return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(inherit_process, struct task_struct *child, unsigned long flags, int ret) {
    (void)ctx;
    if (ret)
        return ret;
    struct process_state *parent = ensure_identity();
    struct task_capture *capture =
        bpf_task_storage_get(&processes, child, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!parent || !capture)
        return owner_needs_capture((__u32)bpf_get_current_uid_gid()) ? -12 : 0;
    struct process_companion *companion = task_companion(child, 1);
    const struct process_companion *parent_companion = task_companion(bpf_get_current_task_btf(), 0);
    if (!companion && owner_needs_capture((__u32)bpf_get_current_uid_gid()))
        return -12;
    if (companion) {
        copy_process_companion(companion, parent_companion);
        if (!parent_companion || parent_companion->snapshot_identity != parent->snapshot_identity)
            companion->available = 0;
    }
    history_fork(capture, parent, companion, task_identity(child, 1), next_file_cookie(),
                 (flags & 0x10000UL) != 0);
    if (!process_pair_valid(parent, parent_companion)) {
        history_unknown_pair(&capture->committed, companion);
        capture->witness.armed = 0;
    }
    publish_capture(capture, companion);
    return 0;
}

#ifdef AP_BINDING_SNAPSHOT
#include "lookup-capture.h"
#endif

SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(capture_exec_begin, struct linux_binprm *bprm, int ret) {
    (void)ctx;
    struct task_capture *capture = capture_current(1);
    if (capture) {
        capture->pending.active = 0;
        lookup_pending_clear(&capture->pending);
    }
    if (ret || BPF_CORE_READ_BITFIELD_PROBED(bprm, is_check)) {
#ifdef AP_BINDING_SNAPSHOT
        struct lookup_capture *lookup = lookup_current(0);
        if (lookup)
            lookup_clear_ready(lookup);
#endif
        return ret;
    }
    struct process_companion *companion = task_companion(bpf_get_current_task_btf(), 1);
    if ((!capture || !companion) && owner_needs_capture((__u32)bpf_get_current_uid_gid()))
        return -12;
    if (!capture)
        return 0;
    capture->pending.source = (struct origin_hash){0};
    capture->pending.attempt = next_file_cookie();
    capture->pending.previous_owner = 0;
    capture->pending.source.uid = (__u32)bpf_get_current_uid_gid();
    capture->pending.source.task_identity = capture->committed.self.source.task_identity;
    capture->pending.source.owner_epoch = capture->committed.self.source.owner_epoch;
    capture->pending.source.exec_identity = capture->pending.attempt;
    classify(&capture->pending.source, bprm->file);
#ifdef AP_BINDING_SNAPSHOT
    lookup_take_source(&capture->pending, bprm->file);
#endif
    capture->pending.active = 1;
    return 0;
}

SEC("lsm/bprm_committed_creds")
int BPF_PROG(classify_exec, struct linux_binprm *bprm) {
    (void)ctx;
    struct task_capture *capture = capture_current(1);
    if (!capture)
        return 0;
    struct process_companion *companion = task_companion(bpf_get_current_task_btf(), 0);
    if (!process_pair_valid(&capture->committed, companion)) {
        history_unknown_pair(&capture->committed, companion);
        capture->witness.armed = 0;
    }
    history_commit_exec(capture, companion);
    struct exec_frame *frame = &capture->committed.self;
    frame->source = capture->pending.active ? capture->pending.source : (struct origin_hash){0};
    frame->image = (struct origin_hash){0};
    __u64 exec = capture->pending.active ? capture->pending.attempt : next_file_cookie();
    __u64 epoch = capture->pending.active ? frame->source.owner_epoch : next_file_cookie();
    frame_owner(frame, (__u32)bpf_get_current_uid_gid(), epoch,
                task_identity(bpf_get_current_task_btf(), 1));
    frame->source.exec_identity = frame->image.exec_identity = exec;
    classify(&frame->image, bprm->file);
    lookup_pending_commit(frame, &capture->pending);
    capture->pending.active = 0;
    publish_capture(capture, companion);
    return 0;
}
struct atomic64_t {
    long long counter;
} __attribute__((preserve_access_index));
struct sock_common {
    struct atomic64_t skc_cookie;
    unsigned char skc_state;
    unsigned short skc_family, skc_dport;
    __u32 skc_daddr, skc_rcv_saddr;
    unsigned short skc_num;
    struct sock *skc_listener;
    struct in6_addr skc_v6_daddr, skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));
struct sock {
    struct sock_common __sk_common;
    unsigned short sk_type, sk_protocol;
    __u8 sk_kern_sock : 1;
} __attribute__((preserve_access_index));
struct socket {
    struct sock *sk;
} __attribute__((preserve_access_index));
struct sockaddr;
struct msghdr;
SEC("lsm/socket_connect")
int BPF_PROG(prepare_connect, struct socket *sock, struct sockaddr *address, int length, int ret) {
    (void)ctx;
    (void)sock;
    (void)address;
    (void)length;
    if (!ret)
        ensure_identity();
    return ret;
}
#ifndef AP_BINDING_SNAPSHOT
__noinline void fill_origin(struct ap_origin *origin __arg_nonnull,
                            const struct origin_hash *source __arg_nonnull,
                            const struct ap_policy *policy __arg_nonnull,
                            const struct ap_context *context __arg_nonnull, unsigned depth) {
    origin->owner_kind = 1;
    origin->owner = source->uid;
    origin->package = 0;
    origin->resolved = source->path_flags == AP_PATH_COMPLETE;
    __u32 *file_application =
        source->file_cookie ? bpf_map_lookup_elem(&file_bindings, &source->file_cookie) : 0;
    __u32 confirmed_application = file_application ? *file_application : 0;
    struct application_key key = {source->path, source->filesystem_device};
    __u32 *application =
        (source->path_flags & AP_PATH_PHYSICAL) ? bpf_map_lookup_elem(&applications, &key) : 0;
    /* Доверие inode не отменяет подмену другого выбранного имени.
       Тот же подтвержденный inode сохраняет доверие через hardlink. */
    if (application && *application != confirmed_application) {
        origin->application = *application;
        if (ap_origin_matches(policy, context, origin, depth)) {
            origin->resolved = 0;
            origin->application = 0;
            return;
        }
    }
    if (source->path_flags & AP_PATH_LOGICAL) {
        key.path = source->logical_path;
        key.filesystem_device = AP_LOGICAL_SCOPE;
        application = bpf_map_lookup_elem(&applications, &key);
        if (application && *application != confirmed_application) {
            origin->application = *application;
            if (ap_origin_matches(policy, context, origin, depth)) {
                origin->resolved = 0;
                origin->application = 0;
                return;
            }
        }
    }
    origin->application = confirmed_application;
    /* Известный inode не восполняет отсутствующие physical/logical facts. */
}

#else
#include "binding-evaluate.h"
#endif

#ifdef AP_BINDING_SNAPSHOT
static __always_inline void copy_process_state(struct process_state *target,
                                                const struct process_state *source) {
#else
__noinline void copy_process_state(struct process_state *target __arg_nonnull,
                                    const struct process_state *source __arg_nonnull) {
#endif
    if (target == source)
        return;
    target->snapshot_identity = 0;
    __asm__ __volatile__("" ::: "memory");
    copy_exec_frame(&target->self, &source->self);
    target->parent_count = source->parent_count;
    target->ancestry_flags = source->ancestry_flags;
    AP_FOR(index, AP_PARENT_LIMIT) {
        copy_history_slot(&target->parents[index], &source->parents[index]);
    }
    __asm__ __volatile__("" ::: "memory");
    target->snapshot_identity = source->snapshot_identity;
}

#include "policy-choice.h"
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} udp_option_active SEC(".maps");
static __always_inline void udp_flags_created(void) {
    __u32 zero = 0;
    __u64 *active = bpf_map_lookup_elem(&udp_option_active, &zero);
    if (active)
        __sync_fetch_and_add(active, 1);
}
static __always_inline void udp_flags_released(__u64 flags) {
    if (!flags)
        return;
    __u32 zero = 0;
    __u64 *active = bpf_map_lookup_elem(&udp_option_active, &zero);
    if (active)
        __sync_fetch_and_sub(active, 1);
}
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct lifetime_events);
} lifetime_events SEC(".maps");
static __always_inline void lifetime_published(void) {
    __u32 zero = 0;
    struct lifetime_events *events = bpf_map_lookup_elem(&lifetime_events, &zero);
    if (events) {
        __sync_fetch_and_add(&events->active, 1);
        __sync_fetch_and_add(&events->created, 1);
    }
}
static __always_inline void lifetime_retired(__u64 flags) {
    udp_flags_released(flags);
    __u32 zero = 0;
    struct lifetime_events *events = bpf_map_lookup_elem(&lifetime_events, &zero);
    if (events) {
        __sync_fetch_and_sub(&events->active, 1);
        __sync_fetch_and_add(&events->retired, 1);
    }
}
#define SS_TOKEN_PUBLISHED() lifetime_published()
#define SS_RELEASE_UDP_OPTIONS(flags) lifetime_retired(flags)
#ifndef AR_CACHE_LIMIT
#define AR_CACHE_LIMIT 65536
#endif
/* Один неизменяемый источник на активный защищенный UDP socket, а не на каждый поток. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, AR_CACHE_LIMIT);
    __type(key, __u64);
    __type(value, struct process_state);
} routing_subjects SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, AR_CACHE_LIMIT);
    __type(key, __u64);
    __type(value, struct process_companion);
} routing_companions SEC(".maps");
#include "socket-routing-state.h"
#include "connection-types.h"
#include "socket-hooks.h"

SEC("lsm/socket_setsockopt")
int BPF_PROG(record_udp_reuse, struct socket *socket, int level, int option, int ret) {
    (void)ctx;
    if (ret || level != 1 || (option != 2 && option != 15))
        return ret;
    struct sock *sock = socket->sk;
    if (!sock || BPF_CORE_READ(sock, sk_type) != 2 || BPF_CORE_READ(sock, sk_protocol) != 17)
        return ret;
    unsigned family = BPF_CORE_READ(sock, __sk_common.skc_family);
    if (family != 2 && family != 10)
        return ret;
    struct ss_state *state = ss_adopt_clone(sock);
    if (!state)
        return -12;
    struct ss_lifetime *token = ss_lifetime_acquire(state, state->cookie, 0);
    if (!token)
        return -12;
    int result = -16;
    for (unsigned attempt = 0; attempt < 8; attempt++) {
        __u64 previous = token->udp_options;
        if (previous & 1) {
            result = -1;
            break;
        }
        if (__sync_val_compare_and_swap(&token->udp_options, previous, previous | 2) == previous) {
            if (!previous)
                udp_flags_created();
            result = 0;
            break;
        }
    }
    bpf_obj_drop_impl(token, 0);
    return result;
}
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 65536);
    __type(key, struct tcp_tuple);
    __type(value, struct tcp_tuple_route);
} tcp_routes SEC(".maps");
static __noinline int packet_key(struct __sk_buff *packet, struct flow_key *key, int reverse,
                                 struct tcp_tuple *tuple) {
    __u8 first, head[40];
    if (bpf_skb_load_bytes_relative(packet, 0, &first, 1, BPF_HDR_START_NET))
        return -1;
    unsigned offset = 0, protocol = 0;
    if ((first >> 4) == 4) {
        if (bpf_skb_load_bytes_relative(packet, 0, head, 20, BPF_HDR_START_NET))
            return -1;
        offset = (head[0] & 15) * 4;
        if (offset < 20)
            return -1;
        if ((head[6] & 31) || head[7])
            return -1;
        key->family = 4;
        __builtin_memcpy(key->destination, head + (reverse ? 12 : 16), 4);
        protocol = head[9];
        if (tuple)
            __builtin_memcpy(tuple->source, head + 12, 4);
    } else if ((first >> 4) == 6) {
        if (bpf_skb_load_bytes_relative(packet, 0, head, 40, BPF_HDR_START_NET))
            return -1;
        key->family = 6;
        __builtin_memcpy(key->destination, head + (reverse ? 8 : 24), 16);
        protocol = head[6];
        offset = 40;
        if (tuple)
            __builtin_memcpy(tuple->source, head + 8, 16);
        for (unsigned index = 0; index < 8; index++) {
            if (protocol != 0 && protocol != 43 && protocol != 60 && protocol != 44 &&
                protocol != 51)
                break;
            __u8 extension[8];
            if (bpf_skb_load_bytes_relative(packet, offset, extension, 8, BPF_HDR_START_NET))
                return -1;
            if (protocol == 44 && ((extension[2] & 0xff) || (extension[3] & 0xf8)))
                return -1;
            unsigned length = protocol == 44   ? 8
                              : protocol == 51 ? ((unsigned)extension[1] + 2) * 4
                                               : ((unsigned)extension[1] + 1) * 8;
            offset += length;
            protocol = extension[0];
        }
        if (protocol == 0 || protocol == 43 || protocol == 60 || protocol == 44 || protocol == 51)
            return -1;
    } else
        return -1;
    key->protocol = protocol;
    if (protocol == 6 || protocol == 17) {
        __u8 ports[4];
        if (bpf_skb_load_bytes_relative(packet, offset, ports, 4, BPF_HDR_START_NET))
            return -1;
        key->port = reverse ? ((__u32)ports[0] << 8) | ports[1] : ((__u32)ports[2] << 8) | ports[3];
        if (tuple)
            tuple->source_port = ((__u32)ports[0] << 8) | ports[1];
    }
    if (tuple) {
        if (protocol == 6)
            tuple->zone = packet_zone(packet);
        tuple->netns = bpf_get_netns_cookie(packet);
        tuple->family = key->family;
        tuple->destination_port = key->port;
        tuple->protocol = protocol;
        __builtin_memcpy(tuple->destination, key->destination, 16);
    }
    key->cookie = bpf_get_socket_cookie(packet);
    return 0;
}
static __always_inline __u64 cached_result(struct cached_route *cached, unsigned family) {
    struct ap_decision *decision = &cached->decision;
    if (decision->action != 2)
        return decision->action == 0 ? 0 : 1;
    if (!decision->profile)
        return 1;
    __u64 result = (__u64)decision->profile + 2;
    struct profile *profile = bpf_map_lookup_elem(&profiles, &decision->profile);
    if (!profile || !profile->generation || (family == 4 ? !profile->ready4 : !profile->ready6))
        return 1;
    __u64 previous =
        __sync_val_compare_and_swap(&cached->network_generation, 0, profile->generation);
    return !previous || previous == profile->generation ? result : 1;
}
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tcp_reap_request);
} tcp_reap_requests SEC(".maps");
SEC("socket") int reap_tcp_routes(struct __sk_buff *packet) {
    (void)packet;
    __u32 zero = 0;
    struct tcp_reap_request *request = bpf_map_lookup_elem(&tcp_reap_requests, &zero);
    if (!request)
        return 0;
    struct tcp_tuple_route *old = bpf_map_lookup_elem(&tcp_routes, &request->tuple);
    if (!old)
        return 0;
    __u64 now = bpf_ktime_get_ns();
    int result = 0;
    if (__sync_val_compare_and_swap(&old->lock, 0, 1))
        return 5;
    struct ss_lifetime *token = old->lifetime;
    if (old->cookie == request->cookie && old->epoch == request->epoch &&
        old->expires == request->expires) {
        if (token && token->alive)
            result = 3;
        else if (old->expires > now)
            result = 4;
        else {
            route_version_retire(&old->sequence);
            old->retired = 1;
            result = 1;
        }
    }
    __sync_lock_test_and_set(&old->lock, 0);
    if (result != 1)
        return result;
    return bpf_map_delete_elem(&tcp_routes, &request->tuple) ? 2 : 1;
}
struct tcp_route_snapshot {
    struct cached_route route;
    __u64 cookie, epoch, expires, sequence, id;
    __u32 alive, reserved;
};
/* Живые читатели не конкурируют с ACK за CAS записи исходящего пакета. */
static __noinline int tcp_route_read(struct tcp_tuple_route *entry, __u64 now,
                                     struct tcp_route_snapshot *out) {
    for (unsigned attempt = 0; attempt < 2; attempt++) {
        __u64 before = route_version_read(&entry->sequence);
        if (before & 1)
            continue;
        ss_copy_route(&out->route, &entry->route);
        out->cookie = entry->cookie;
        out->epoch = entry->epoch;
        out->id = entry->id;
        out->expires = entry->expires;
        bpf_rcu_read_lock();
        struct ss_lifetime *token = entry->lifetime;
        int valid =
            !entry->retired && token && token->cookie == out->cookie && token->epoch == out->epoch;
        out->alive = valid ? token->alive : 0;
        bpf_rcu_read_unlock();
        __u64 after = route_version_read(&entry->sequence);
        if (before == after && !entry->retired) {
            out->sequence = after;
            return valid && (out->alive || out->expires > now);
        }
    }
    return 0;
}
static __noinline int tcp_route_unchanged(struct tcp_tuple_route *entry, struct ss_state *state,
                                          const struct ar_record *record, __u64 now) {
    struct tcp_route_snapshot saved = {};
    return tcp_route_read(entry, now, &saved) && saved.alive && saved.cookie == state->cookie &&
           saved.epoch == record->epoch && saved.id == record->flow.id &&
           route_choice_equal(&saved.route, &record->flow.route) &&
           saved.route.network_generation == record->flow.route.network_generation &&
           saved.route.system_device == record->flow.route.system_device &&
           saved.expires > now + TCP_TUPLE_LIFETIME_NS - 1000000000ULL;
}
/* Запись удерживает только ссылку на время жизни, а не личность или граф сокета. */
static __noinline int remember_tcp_tuple(const struct tcp_tuple *tuple, struct ss_state *state,
                                         const struct ar_record *record) {
#ifdef AP_BINDING_SNAPSHOT
    if (!record->flow.admitted)
        return -1;
#endif
    const struct cached_route *cached = &record->flow.route;
    __u64 cookie = state->cookie, epoch = record->epoch, now = bpf_ktime_get_ns();
    struct tcp_tuple_route *old = bpf_map_lookup_elem(&tcp_routes, tuple);
    if (!old) {
        if (cached->decision.action == 0)
            return 0;
        struct tcp_tuple_route empty = {};
        if (bpf_map_update_elem(&tcp_routes, tuple, &empty, BPF_NOEXIST)) {
            old = bpf_map_lookup_elem(&tcp_routes, tuple);
            if (!old)
                return -1;
        } else
            old = bpf_map_lookup_elem(&tcp_routes, tuple);
        if (!old)
            return -1;
    }
    if (tcp_route_unchanged(old, state, record, now))
        return 0;
    if (__sync_val_compare_and_swap(&old->lock, 0, 1))
        return -1;
    if (old->retired)
        goto reject;
    struct ss_lifetime *token = ss_lifetime_acquire(state, cookie, epoch);
    if (!token)
        goto reject;
    if (route_version_begin(&old->sequence)) {
        bpf_obj_drop_impl(token, 0);
        goto reject;
    }
    if (!old->lifetime || old->cookie != cookie || old->epoch != epoch || old->id != record->flow.id ||
        !route_choice_equal(&old->route, cached) ||
        old->route.network_generation != cached->network_generation ||
        old->route.system_device != cached->system_device ||
        old->expires <= now + TCP_TUPLE_LIFETIME_NS - 1000000000ULL) {
        ss_copy_route(&old->route, cached);
        old->cookie = cookie;
        old->epoch = epoch;
        old->id = record->flow.id;
        old->expires = now + TCP_TUPLE_LIFETIME_NS;
        struct ss_lifetime *previous = bpf_kptr_xchg(&old->lifetime, token);
        if (previous)
            bpf_obj_drop_impl(previous, 0);
    } else
        bpf_obj_drop_impl(token, 0);
    route_version_end(&old->sequence);
    __sync_lock_test_and_set(&old->lock, 0);
    return 0;
reject:
    __sync_lock_test_and_set(&old->lock, 0);
    return -1;
}
#define TCP_ORIGINAL_TUPLE (1U << 31)
/* Фазы до NAT и на выходе различаются даже при совпадении адресов и zone. */
static __always_inline struct tcp_tuple_route *control_tuple_route(struct tcp_tuple *tuple,
                                                                   struct bpf_sock *socket) {
    __u32 zone = tuple->zone;
    tuple->zone = 0;
    tuple->reserved = TCP_ORIGINAL_TUPLE | (socket ? socket->bound_dev_if : 0);
    struct tcp_tuple_route *route = bpf_map_lookup_elem(&tcp_routes, tuple);
    if (route)
        return route;
    tuple->zone = zone;
    tuple->reserved = 0;
    return bpf_map_lookup_elem(&tcp_routes, tuple);
}
/* Ключ берется у настоящего TCP-сокета, до NAT, без догадок об исходном адресе. */
static __noinline int remember_socket_tuple(struct __sk_buff *packet, struct ss_state *state,
                                            const struct ar_record *record) {
    struct bpf_sock *context = packet->sk;
    if (!context || context->state == 6 || context->state == 12 || context->state == 10)
        return 0;
    struct sk_buff___ct *internal = bpf_cast_to_kern_ctx(packet);
    struct sock *sock = BPF_CORE_READ(internal, sk);
    if (!sock)
        return 0;
    if (BPF_CORE_READ_BITFIELD_PROBED(sock, sk_kern_sock)) {
        if (!state->derived_stream)
            return 0;
    }
    struct tcp_tuple tuple = {.netns = bpf_get_netns_cookie(packet),
                              .protocol = 6,
                              .reserved = TCP_ORIGINAL_TUPLE | context->bound_dev_if};
    unsigned family = BPF_CORE_READ(sock, __sk_common.skc_family);
    tuple.family = family == 2 ? 4 : 6;
    tuple.source_port = BPF_CORE_READ(sock, __sk_common.skc_num);
    tuple.destination_port = __builtin_bswap16(BPF_CORE_READ(sock, __sk_common.skc_dport));
    if (family == 2) {
        __u32 source = BPF_CORE_READ(sock, __sk_common.skc_rcv_saddr),
              destination = BPF_CORE_READ(sock, __sk_common.skc_daddr);
        __builtin_memcpy(tuple.source, &source, 4);
        __builtin_memcpy(tuple.destination, &destination, 4);
    } else if (family == 10) {
        BPF_CORE_READ_INTO(&tuple.source, sock, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&tuple.destination, sock, __sk_common.skc_v6_daddr);
        __u32 *words = (void *)tuple.destination;
        if (!words[0] && !words[1] && !tuple.destination[8] && !tuple.destination[9] &&
            tuple.destination[10] == 255 && tuple.destination[11] == 255) {
            __u32 source, destination = words[3];
            __builtin_memcpy(&source, tuple.source + 12, 4);
            __builtin_memset(tuple.source, 0, 16);
            __builtin_memset(tuple.destination, 0, 16);
            __builtin_memcpy(tuple.source, &source, 4);
            __builtin_memcpy(tuple.destination, &destination, 4);
            tuple.family = 4;
        }
    } else
        return -1;
    if (!tuple.source_port || !tuple.destination_port)
        return 0;
    if (remember_tcp_tuple(&tuple, state, record))
        return -1;
    return 0;
}
static __noinline __u64 finish_timewait(struct tcp_tuple_route *route, unsigned family) {
    __u64 now = bpf_ktime_get_ns();
    struct tcp_route_snapshot saved = {};
    if (!tcp_route_read(route, now, &saved))
        return 1;
    if (saved.expires <= now + TCP_TUPLE_LIFETIME_NS - 1000000000ULL &&
        !__sync_val_compare_and_swap(&route->lock, 0, 1)) {
        if (!route->retired && route_version_read(&route->sequence) == saved.sequence &&
            !route_version_begin(&route->sequence)) {
            route->expires = now + TCP_TUPLE_LIFETIME_NS;
            route_version_end(&route->sequence);
        }
        __sync_lock_test_and_set(&route->lock, 0);
    }
    return cached_result(&saved.route, family);
}
struct admission_work {
    __u32 busy, reserved;
    struct flow_key key;
    __u64 tag, epoch;
#ifdef AP_BINDING_SNAPSHOT
    struct ar_record record;
    struct tcp_tuple tuple;
#endif
};
#include "packet-output-state.h"

struct net {
    __u64 net_cookie;
} __attribute__((preserve_access_index));
struct kernfs_node {
    __u64 id;
} __attribute__((preserve_access_index));
struct kobject {
    struct kernfs_node *sd;
} __attribute__((preserve_access_index));
struct device {
    struct kobject kobj;
} __attribute__((preserve_access_index));
struct possible_net_t {
    struct net *net;
} __attribute__((preserve_access_index));
struct net_device {
    int ifindex;
    struct device dev;
    struct possible_net_t nd_net;
} __attribute__((preserve_access_index));
static __always_inline __u64 device_identity(const struct net_device *device) {
    return BPF_CORE_READ(device, dev.kobj.sd, id);
}
struct nf_hook_state {
    __u8 hook, pf;
    struct sock *sk;
    struct net *net;
    const struct net_device *out;
    const struct net_device *in;
} __attribute__((preserve_access_index));
struct sk_buff {
    __u8 *head;
    __u32 tail;
    __u16 network_header;
    __u32 mark;
    int skb_iif;
    struct net_device *dev;
    unsigned long _nfct;
} __attribute__((preserve_access_index));

static __always_inline const struct net_device *packet_device(struct __sk_buff *packet) {
    struct sk_buff *internal = bpf_cast_to_kern_ctx(packet);
    return BPF_CORE_READ(internal, dev);
}
static __always_inline __u32 owned_interface_profile(__u64 network_namespace,
                                                     const struct net_device *device) {
    struct interface_key key = {.network_namespace = network_namespace,
                                .interface_index = (__u32)BPF_CORE_READ(device, ifindex)};
    __u32 *slot = bpf_map_lookup_elem(&interface_profiles, &key);
    struct profile *profile = slot ? bpf_map_lookup_elem(&profiles, slot) : 0;
    return profile && profile->device_identity &&
                   profile->device_identity == device_identity(device)
               ? *slot
               : 0;
}
#ifdef AP_BINDING_SNAPSHOT
struct sock_common___request {
    struct possible_net_t skc_net;
} __attribute__((preserve_access_index));
struct sock___request {
    struct sock_common___request __sk_common;
} __attribute__((preserve_access_index));
static __noinline int request_interface_allowed(struct sk_buff *packet, struct sock *socket) {
    /* TCP очищает skb->dev перед inet_conn_request; входной индекс остается в skb_iif. */
    struct interface_key key = {
        .network_namespace = BPF_CORE_READ((struct sock___request *)socket, __sk_common.skc_net.net, net_cookie),
        .interface_index = (__u32)BPF_CORE_READ(packet, skb_iif),
    };
    return key.interface_index && !bpf_map_lookup_elem(&interface_profiles, &key);
}
#endif
SEC("socket") int match_owned_input(struct __sk_buff *packet) {
    const struct net_device *device = packet_device(packet);
    return owned_interface_profile(BPF_CORE_READ(device, nd_net.net, net_cookie), device) != 0;
}
#include "connection-state.h"
#include "packet-input-state.h"
static __noinline int validate_output(struct __sk_buff *packet, __u64 action,
                                      const struct admission_work *admission) {
    if (action == 0) {
        struct mark_key key = {.network_namespace = bpf_get_netns_cookie(packet),
                               .mark = packet->mark};
        if (owned_mark_profile(&key))
            return 0;
#ifdef AP_BINDING_SNAPSHOT
        (void)admission;
        return 1;
#else
        return observe_connection(packet, action, admission);
#endif
    }
    if (action < 2)
        return 0;
    __u32 slot = (__u32)(action - 2);
    struct profile *profile = bpf_map_lookup_elem(&profiles, &slot);
    if (!profile || bpf_get_netns_cookie(packet) != profile->network_namespace ||
        packet->ifindex != profile->interface_index || !profile_mark_matches(profile, packet->mark))
        return 0;
    __u8 first, source[16];
    if (bpf_skb_load_bytes_relative(packet, 0, &first, 1, BPF_HDR_START_NET))
        return 0;
    if ((first >> 4) == 4) {
        if (bpf_skb_load_bytes_relative(packet, 12, source, 4, BPF_HDR_START_NET))
            return 0;
        for (unsigned index = 0; index < 4; index++)
            if (source[index] != profile->ipv4[index])
                return 0;
    } else if ((first >> 4) == 6) {
        if (bpf_skb_load_bytes_relative(packet, 8, source, 16, BPF_HDR_START_NET))
            return 0;
        for (unsigned index = 0; index < 16; index++)
            if (source[index] != profile->ipv6[index])
                return 0;
    } else
        return 0;
#ifdef AP_BINDING_SNAPSHOT
    return 1;
#else
    return observe_connection(packet, action, admission);
#endif
}

static __noinline int transport_packet(struct __sk_buff *packet) {
    struct flow_key key = {};
    if (packet_key(packet, &key, 0, 0)) return -1;
    return transport_choice(key.cookie, bpf_get_netns_cookie(packet), key.family,
                            key.protocol, key.port, key.destination, 0);
}
#ifndef AP_BINDING_SNAPSHOT
static __noinline int finish_output_admission(const struct admission_work *work, __u64 action,
                                              int allowed) {
    if (action == 0)
        return allowed;
    if (!work->tag || (work->tag & 3) == 3)
        return 0;
    struct cc_entry *entry = bpf_map_lookup_elem(&routing_overrides, &work->key);
    if (!entry || entry->cookie != work->key.cookie || entry->epoch != work->epoch)
        return 0;
    if (allowed && ar_result(&entry->route, work->key.family) != action)
        return 0;
    return cc_packet_admission(entry, work->tag, allowed);
}
#else
static __noinline int finish_output_admission(struct __sk_buff *packet,
                                               struct admission_work *work, int allowed) {
    if (!work->key.protocol) return allowed;
    if (!allowed) return 0;
    struct bpf_sock *socket = packet->sk;
    struct ss_state *state = socket ? bpf_sk_storage_get(&socket_states, socket, 0, 0) : 0;
    if (!state) return 0;
    struct ar_work *scratch = route_slot(0);
    if (!scratch) scratch = route_slot(1);
    if (!scratch) scratch = route_slot(2);
    if (!scratch) scratch = route_slot(3);
    if (!scratch) return 0;
    int result = 0;
    struct cc_snapshot *current = &scratch->cached;
    if (ar_read(&work->key, current) != 1 || current->admission != 1 ||
        current->epoch != work->record.epoch || current->id != work->record.flow.id ||
        !route_choice_equal(&current->route, &work->record.flow.route)) goto done;
    work->record.flow.admitted = 1;
    if (work->key.protocol == 6) {
        if (remember_tcp_tuple(&work->tuple, state, &work->record) ||
            remember_socket_tuple(packet, state, &work->record)) goto done;
    }
    result = 1;
done:
    __sync_lock_test_and_set(&scratch->busy, 0);
    return result;
}
#endif
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, struct admission_work);
} admission_scratch SEC(".maps");
static __always_inline struct admission_work *admission_slot(__u32 slot) {
    struct admission_work *work = bpf_map_lookup_elem(&admission_scratch, &slot);
    return work && !__sync_val_compare_and_swap(&work->busy, 0, 1) ? work : 0;
}
static __always_inline struct admission_work *admission_begin(void) {
    struct admission_work *work = admission_slot(0);
    if (!work)
        work = admission_slot(1);
    if (!work)
        work = admission_slot(2);
    if (!work)
        work = admission_slot(3);
    return work;
}
static __noinline void capture_output_admission(struct __sk_buff *packet,
                                                struct admission_work *work) {
    __builtin_memset(&work->key, 0, sizeof(work->key));
    work->tag = 0;
    work->epoch = 0;
#ifdef AP_BINDING_SNAPSHOT
    (void)packet;

#else
    if (packet_key(packet, &work->key, 0, 0) || work->key.protocol != 17) {
        work->key.protocol = 0;
        return;
    }
    struct cc_entry *entry = bpf_map_lookup_elem(&routing_overrides, &work->key);
    if (!entry)
        return;
    __u64 tag = __sync_fetch_and_add(&entry->admission, 0);
    if (!tag || (tag & 3) == 3)
        return;
    work->epoch = entry->epoch;
    __u64 after = __sync_fetch_and_add(&entry->admission, 0);
    if ((after >> 2) == (tag >> 2) && (after & 3) != 3 && entry->cookie == work->key.cookie &&
        entry->id == (tag >> 2))
        work->tag = tag;
#endif
}
#ifndef AP_BINDING_SNAPSHOT
static __noinline int reject_output_without_work(struct __sk_buff *packet) {
    struct flow_key key = {};
    if (packet_key(packet, &key, 0, 0) || key.protocol != 17)
        return 0;
    struct cc_entry *entry = bpf_map_lookup_elem(&routing_overrides, &key);
    if (entry)
        cc_packet_admission(entry, __sync_fetch_and_add(&entry->admission, 0), 0);
    return 0;
}
#endif
SEC("cgroup_skb/egress")
int guard_output(struct __sk_buff *packet) {
    int transport = transport_packet(packet);
    if (transport >= 0) return transport == 1;
    struct admission_work *work = admission_begin();
    if (!work) {
#ifdef AP_BINDING_SNAPSHOT
        return 0;
#else
        __u64 action = packet_route(packet, 0);
        return action == 0 ? validate_output(packet, action, 0)
                           : reject_output_without_work(packet);
#endif
    }
    capture_output_admission(packet, work);
    __u64 action = packet_route(packet, work);
    int allowed = validate_output(packet, action, work);
#ifdef AP_BINDING_SNAPSHOT
    allowed = finish_output_admission(packet, work, allowed);
    if (allowed)
        allowed = observe_connection(packet, action, work);
#else
    if (work->key.protocol == 17)
        allowed = finish_output_admission(work, action, allowed);
#endif
    __sync_lock_test_and_set(&work->busy, 0);
#ifdef AP_BINDING_SNAPSHOT
    /* Global helper не переносит доказанный диапазон результата в вызывающий hook. */
    asm volatile("" : "+r"(allowed));
    return allowed == 1;
#else
    return allowed;
#endif
}
struct early_work {
    struct flow_key key;
    struct tcp_tuple tuple;
    struct cc_snapshot snapshot;
    struct cached_route desired;
    __u32 busy;
};
#ifdef AP_BINDING_SNAPSHOT
/* Только временные скаляры текущего hook. Указатель inner сюда не попадает. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct early_work);
} early_scratch SEC(".maps");
#endif
static __always_inline __u64 early_packet_decision(struct __sk_buff *packet, struct early_work *work) {
    if (packet_key(packet, &work->key, 0, &work->tuple))
        return 0;
    int transport = transport_choice(work->key.cookie, bpf_get_netns_cookie(packet), work->key.family,
                                     work->key.protocol, work->key.port, work->key.destination, 0);
    if (transport >= 0) return transport ? 0 : 1;
    struct bpf_sock *socket = packet->sk;
    struct sk_buff___ct *internal = bpf_cast_to_kern_ctx(packet);
    struct sock *kernel_socket = BPF_CORE_READ(internal, sk);
    int control = 0;
    if (kernel_socket && socket && socket->state != 6 && socket->state != 12)
        control = BPF_CORE_READ_BITFIELD_PROBED(kernel_socket, sk_kern_sock);
    if (work->key.protocol == 6 && (!socket || socket->state == 6 || control)) {
        struct tcp_tuple_route *route = control_tuple_route(&work->tuple, socket);
        if (route)
            return finish_timewait(route, work->key.family);
    }
    int found = ar_read(&work->key, &work->snapshot);
    if (found < 0)
        return 1;
    if (found && work->snapshot.admission == 0 && work->key.protocol == 17
#ifdef AP_BINDING_SNAPSHOT
        && 0
#endif
    ) {
        const struct process_state *subject = bpf_map_lookup_elem(&routing_subjects, &work->key.cookie);
        if (!subject)
            return 1;
        const struct process_companion *companion =
            bpf_map_lookup_elem(&routing_companions, &work->key.cookie);
        if (!companion || ar_choose(subject, companion, &work->key, &work->desired))
            return 1;
        work->desired.network_generation = ar_generation(&work->desired, work->key.family);
        return ar_result(&work->desired, work->key.family);
    }
    return found ? ar_result(&work->snapshot.route, work->key.family) : 0;
}
static __noinline __u64 early_packet_route(struct __sk_buff *packet) {
#ifdef AP_BINDING_SNAPSHOT
    __u32 zero = 0;
    struct early_work *work = bpf_map_lookup_elem(&early_scratch, &zero);
    if (!work || __sync_val_compare_and_swap(&work->busy, 0, 1)) return 1;
    __builtin_memset(work, 0, offsetof(struct early_work, busy));
    __u64 result = early_packet_decision(packet, work);
    __sync_lock_test_and_set(&work->busy, 0);
    return result;
#else
    struct early_work work = {};
    return early_packet_decision(packet, &work);
#endif
}
SEC("socket") int match_block(struct __sk_buff *packet) { return early_packet_route(packet) == 1; }
SEC("socket") int match_vpn(struct __sk_buff *packet) { return early_packet_route(packet) >= 2; }
const volatile __u32 selected_profile SEC(".rodata.profile") = 0;
SEC("socket") int match_profile(struct __sk_buff *packet) {
    return early_packet_route(packet) == (__u64)selected_profile + 2;
}
union nf_inet_addr {
    __u32 all[4];
} __attribute__((preserve_access_index));
union nf_conntrack_man_proto {
    __u16 all;
} __attribute__((preserve_access_index));
struct nf_conntrack_man {
    union nf_inet_addr u3;
    union nf_conntrack_man_proto u;
    __u16 l3num;
} __attribute__((preserve_access_index));
struct nf_conntrack_tuple {
    struct nf_conntrack_man src;
    struct {
        union nf_inet_addr u3;
        union {
            __u16 all;
        } u;
        __u8 protonum, dir;
    } dst;
} __attribute__((preserve_access_index));
struct nf_conntrack_tuple_hash {
    struct nf_conntrack_tuple tuple;
} __attribute__((preserve_access_index));
struct nf_conn {
    struct nf_conntrack_tuple_hash tuplehash[2];
} __attribute__((preserve_access_index));
struct bpf_ct_opts {
    __s32 netns_id, error;
    __u8 l4proto, dir;
    __u16 ct_zone_id;
    __u8 ct_zone_dir, reserved[3];
};
extern struct nf_conn *bpf_skb_ct_lookup(struct __sk_buff *, struct bpf_sock_tuple *, __u32,
                                         struct bpf_ct_opts *, __u32) __ksym;
extern void bpf_ct_release(struct nf_conn *) __ksym;
extern void *bpf_rdonly_cast(const void *, __u32) __ksym;
struct icmp_observation {
    __u64 cookie;
    __u32 socket_found, flow_found, action, profile, ct_found, ct_error, local_address, local_port;
};
#ifdef AIVPN_ROUTE_DIAGNOSTICS
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct icmp_observation);
} icmp_debug SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} icmp_stages SEC(".maps");
static __always_inline void icmp_stage(__u32 stage) {
    __u64 *count = bpf_map_lookup_elem(&icmp_stages, &stage);
    if (count)
        __sync_fetch_and_add(count, 1);
}
#else
static __always_inline void icmp_stage(__u32 stage) { (void)stage; }
#endif
SEC("tcx/ingress") int route_related_icmp(struct __sk_buff *packet) {
    __u8 head[20], icmp[8], quote[20], ports[4];
    if (bpf_skb_load_bytes_relative(packet, 0, head, 20, BPF_HDR_START_NET) ||
        (head[0] >> 4) != 4 || head[9] != 1)
        return -1;
    icmp_stage(0);
    if ((head[6] & 63) || head[7]) {
        icmp_stage(1);
        return -1;
    }
    __u32 offset = (head[0] & 15) * 4;
    if (offset < 20 || bpf_skb_load_bytes_relative(packet, offset, icmp, 8, BPF_HDR_START_NET) ||
        (icmp[0] != 3 && icmp[0] != 11 && icmp[0] != 12)) {
        icmp_stage(5);
        return -1;
    }
    if (bpf_skb_load_bytes_relative(packet, offset + 8, quote, 20, BPF_HDR_START_NET) ||
        (quote[0] >> 4) != 4 || (quote[9] != 17 && quote[9] != 6)) {
        icmp_stage(2);
        return 2;
    }
    __u32 header = (quote[0] & 15) * 4;
    if (header < 20 ||
        bpf_skb_load_bytes_relative(packet, offset + 8 + header, ports, 4, BPF_HDR_START_NET))
        return -1;
    struct bpf_sock_tuple tuple = {0};
    __builtin_memcpy(&tuple.ipv4.saddr, quote + 16, 4);
    __builtin_memcpy(&tuple.ipv4.daddr, quote + 12, 4);
    __builtin_memcpy(&tuple.ipv4.sport, ports + 2, 2);
    __builtin_memcpy(&tuple.ipv4.dport, ports, 2);
    const struct net_device *device = packet_device(packet);
    __u32 slot = owned_interface_profile(BPF_CORE_READ(device, nd_net.net, net_cookie), device);
    if (!slot)
        return -1;
    int allowed = 0;
    struct icmp_observation result = {0};
    struct bpf_ct_opts options = {.netns_id = -1, .l4proto = quote[9]};
    __u32 *zone = bpf_map_lookup_elem(&profile_zones, &slot);
    if (zone)
        options.ct_zone_id = (__u16)*zone;
    struct nf_conn *connection =
        bpf_skb_ct_lookup(packet, &tuple, sizeof(tuple.ipv4), &options, sizeof(options));
    if (connection) {
        result.ct_found = 1;
        tuple.ipv4.saddr = BPF_CORE_READ(connection, tuplehash[0].tuple.dst.u3.all[0]);
        tuple.ipv4.daddr = BPF_CORE_READ(connection, tuplehash[0].tuple.src.u3.all[0]);
        tuple.ipv4.sport = BPF_CORE_READ(connection, tuplehash[0].tuple.dst.u.all);
        tuple.ipv4.dport = BPF_CORE_READ(connection, tuplehash[0].tuple.src.u.all);
        bpf_ct_release(connection);
    } else
        result.ct_error = (__u32)options.error;
    result.local_address = tuple.ipv4.daddr;
    result.local_port = tuple.ipv4.dport;
    struct bpf_sock *socket =
        quote[9] == 6
            ? bpf_sk_lookup_tcp(packet, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0)
            : bpf_sk_lookup_udp(packet, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
    if (socket) {
        result.socket_found = 1;
        const struct sock *internal = bpf_rdonly_cast(socket, bpf_core_type_id_kernel(struct sock));
        result.cookie = BPF_CORE_READ(internal, __sk_common.skc_cookie.counter);
        struct flow_key key = {.cookie = result.cookie,
                               .family = 4,
                               .port = __builtin_bswap16(tuple.ipv4.sport),
                               .protocol = quote[9]};
        __builtin_memcpy(key.destination, &tuple.ipv4.saddr, 4);
        struct cc_snapshot flow = {};
        int found = ar_read(&key, &flow);
        if (found == 1 && flow.alive) {
            result.flow_found = 1;
            result.action = flow.route.decision.action;
            result.profile = flow.route.decision.profile;
            __u64 action = ar_result(&flow.route, 4);
            struct ss_state *state = bpf_sk_storage_get(&socket_states, socket, 0, 0);
            struct ss_lifetime *token =
                state ? ss_lifetime_acquire(state, key.cookie, flow.epoch) : 0;
            if (token) {
                if (action == 0)
                    allowed = flow.route.system_device &&
                              flow.route.system_device == device_identity(packet_device(packet));
                else
                    allowed = action >= 2 && action - 2 == slot &&
                              (key.protocol != 17 || token->udp_options == 1);
                bpf_obj_drop_impl(token, 0);
            }
        }
        bpf_sk_release(socket);
    }
#ifdef AIVPN_ROUTE_DIAGNOSTICS
    __u32 zero = 0;
    bpf_map_update_elem(&icmp_debug, &zero, &result, BPF_ANY);
#endif
    struct profile *profile = bpf_map_lookup_elem(&profiles, &slot);
    if (allowed && profile) {
        icmp_stage(3);
        packet->mark = profile->mark;
        return -1;
    }
    icmp_stage(4);
    return 2;
}
struct bpf_nf_ctx {
    const struct nf_hook_state *state;
    struct sk_buff *skb;
};
extern int bpf_dynptr_from_skb(struct __sk_buff *, __u64, struct bpf_dynptr *) __ksym;
static __noinline int netfilter_tcp_tuple(struct bpf_nf_ctx *context, struct tcp_tuple *tuple) {
    struct bpf_dynptr packet;
    __u8 head[40] = {0};
    unsigned offset, protocol;
    if (bpf_dynptr_from_skb((struct __sk_buff *)context->skb, 0, &packet) ||
        bpf_dynptr_read(head, 20, &packet, 0, 0))
        return -1;
    if ((head[0] >> 4) == 4) {
        tuple->family = 4;
        offset = (head[0] & 15) * 4;
        protocol = head[9];
        if (offset < 20 || (head[6] & 31) || head[7])
            return -1;
        __builtin_memcpy(tuple->source, head + 12, 4);
        __builtin_memcpy(tuple->destination, head + 16, 4);
    } else if ((head[0] >> 4) == 6) {
        if (bpf_dynptr_read(head, 40, &packet, 0, 0))
            return -1;
        tuple->family = 6;
        offset = 40;
        protocol = head[6];
        __builtin_memcpy(tuple->source, head + 8, 16);
        __builtin_memcpy(tuple->destination, head + 24, 16);
        for (unsigned index = 0; index < 8; index++) {
            if (protocol != 0 && protocol != 43 && protocol != 60 && protocol != 44 &&
                protocol != 51)
                break;
            __u8 extension[8];
            if (bpf_dynptr_read(extension, 8, &packet, offset, 0))
                return -1;
            if (protocol == 44 && (extension[2] || (extension[3] & 0xf8)))
                return -1;
            unsigned length = protocol == 44   ? 8
                              : protocol == 51 ? ((unsigned)extension[1] + 2) * 4
                                               : ((unsigned)extension[1] + 1) * 8;
            offset += length;
            protocol = extension[0];
        }
    } else
        return -1;
    if (protocol == 0 || protocol == 43 || protocol == 60 || protocol == 44 || protocol == 51)
        return -1;
    tuple->protocol = protocol;
    if (protocol != 6 && protocol != 17)
        return 1;
    __u8 ports[4];
    if (bpf_dynptr_read(ports, 4, &packet, offset, 0))
        return -1;
    tuple->source_port = ((__u32)ports[0] << 8) | ports[1];
    tuple->destination_port = ((__u32)ports[2] << 8) | ports[3];
    tuple->netns = BPF_CORE_READ(context->state, net, net_cookie);
    tuple->zone = connection_zone(BPF_CORE_READ(context->skb, _nfct));
    return protocol == 6 ? 0 : 1;
}
static __noinline int approved_connection_input(struct bpf_nf_ctx *context, __u32 slot,
                                                unsigned family, int is_error) {
    icmp_stage(6);
    __u64 tagged = BPF_CORE_READ(context->skb, _nfct);
    unsigned info = tagged & 7;
    if (is_error && info != 1 && info != 4)
        return 0;
    __u64 connection = tagged & ~7ULL;
    struct ct_entry *entry = bpf_map_lookup_elem(&connection_routes, &connection);
    if (!entry)
        return 0;
    struct ar_work *work = route_begin(0, 0);
    if (!work)
        return 0;
    int allowed = 0;
    if (!connection_read(entry, &work->connection) || !connection_current(work, family, is_error))
        goto done;
    struct ct_record *saved = &work->connection.data;
    if (saved->network_namespace != BPF_CORE_READ(context->state, net, net_cookie) ||
        saved->device != device_identity(context->state->in))
        goto done;
    __u64 action = ar_result(&saved->route, family);
    if (action == 0)
        allowed = saved->route.system_device && saved->route.system_device == saved->device;
    else
        allowed = action >= 2 && action - 2 == slot;
    if (allowed)
        icmp_stage(7);
done:
    __sync_lock_test_and_set(&work->busy, 0);
    return allowed;
}
static __noinline int approved_icmp(struct bpf_nf_ctx *context, __u32 slot, unsigned family) {
    struct bpf_dynptr packet;
    __u8 head[40], kind;
    if (bpf_dynptr_from_skb((struct __sk_buff *)context->skb, 0, &packet) ||
        bpf_dynptr_read(head, 20, &packet, 0, 0))
        return 0;
    unsigned offset = (head[0] & 15) * 4;
    if (family == 6) {
        if (bpf_dynptr_read(head, 40, &packet, 0, 0))
            return 0;
        unsigned protocol = head[6];
        offset = 40;
        for (unsigned index = 0; index < 8; index++) {
            if (protocol != 0 && protocol != 43 && protocol != 60 && protocol != 44 &&
                protocol != 51)
                break;
            __u8 extension[8];
            if (bpf_dynptr_read(extension, 8, &packet, offset, 0))
                return 0;
            offset += protocol == 44   ? 8
                      : protocol == 51 ? ((unsigned)extension[1] + 2) * 4
                                       : ((unsigned)extension[1] + 1) * 8;
            protocol = extension[0];
        }
        if (protocol != 58)
            return 0;
    }
    if (offset < 20 || bpf_dynptr_read(&kind, 1, &packet, offset, 0))
        return 0;
    if (family == 4) {
        if (kind != 3 && kind != 11 && kind != 12)
            return kind == 0 || kind == 14 || kind == 16 || kind == 18;
    } else {
        if (kind >= 128)
            return kind == 129 || kind == 135 || kind == 136;
    }
    return approved_connection_input(context, slot, family, 1);
}
static __noinline int guard_tcp_input(struct bpf_nf_ctx *context,
                                       const struct tcp_tuple *packet, int owned) {
    struct tcp_tuple reverse = {};
    reverse.netns = packet->netns;
    reverse.family = packet->family;
    reverse.protocol = packet->protocol;
    reverse.zone = packet->zone;
    reverse.source_port = packet->destination_port;
    reverse.destination_port = packet->source_port;
    __builtin_memcpy(reverse.source, packet->destination, 16);
    __builtin_memcpy(reverse.destination, packet->source, 16);
    struct tcp_tuple_route *entry = bpf_map_lookup_elem(&tcp_routes, &reverse);
    if (!entry)
        return !owned;
    struct tcp_route_snapshot snapshot = {};
    if (!tcp_route_read(entry, bpf_ktime_get_ns(), &snapshot))
        return 0;
    struct cached_route *saved = &snapshot.route;
    __u64 action = cached_result(saved, reverse.family);
    if (action == 0)
        return 1;
    if (action < 2)
        return 0;
    struct profile *profile = bpf_map_lookup_elem(&profiles, &saved->decision.profile);
    return profile && profile->network_namespace == reverse.netns &&
           profile->interface_index == (__u32)BPF_CORE_READ(context->state, in, ifindex) &&
           profile->device_identity &&
           profile->device_identity == device_identity(context->state->in);
}
SEC("netfilter") int guard_profile_input(struct bpf_nf_ctx *context) {
    __u32 input_profile =
        owned_interface_profile(BPF_CORE_READ(context->state, net, net_cookie), context->state->in);
    int owned = input_profile != 0;
    struct tcp_tuple packet = {};
    int parsed = netfilter_tcp_tuple(context, &packet);
    if (parsed) {
        if (!owned)
            return 1;
        if (parsed < 0)
            return 0;
        if (packet.protocol == 17)
            return approved_connection_input(context, input_profile, packet.family, 0);
        if (packet.protocol == 1 || packet.protocol == 58)
            return approved_icmp(context, input_profile, packet.family);
        return 0;
    }
    return guard_tcp_input(context, &packet, owned);
}

SEC("netfilter") int guard_profile_forward(struct bpf_nf_ctx *context) {
    return owned_interface_profile(BPF_CORE_READ(context->state, net, net_cookie),
                                   context->state->in)
               ? 0
               : 1;
}
/* Отказ до cgroup не должен закрепить ни разу не принятый UDP-интервал. */
static __noinline int reject_marked_output(struct bpf_nf_ctx *context, __u32 slot,
                                           const struct tcp_tuple *packet) {
    if (packet->protocol != 17 || (packet->family != 4 && packet->family != 6))
        return 0;
    struct sock *socket = BPF_CORE_READ((struct sk_buff___ct *)context->skb, sk);
    if (!socket)
        return 0;
    struct flow_key key = {.cookie = BPF_CORE_READ(socket, __sk_common.skc_cookie.counter),
                           .family = packet->family,
                           .port = packet->destination_port,
                           .protocol = 17};
    if (!key.cookie)
        return 0;
    __builtin_memcpy(key.destination, packet->destination, 16);
    struct cc_entry *entry = bpf_map_lookup_elem(&routing_overrides, &key);
    if (!entry)
        return 0;
    __u64 tag = __sync_fetch_and_add(&entry->admission, 0);
    struct cc_snapshot snapshot = {};
    if (cc_read_attempt(entry, tag, &snapshot) && snapshot.cookie == key.cookie &&
        snapshot.route.decision.action == 2 && snapshot.route.decision.profile == slot)
        cc_packet_admission(entry, tag, 0);
    return 0;
}
SEC("netfilter") int guard_marked_output(struct bpf_nf_ctx *context) {
    struct mark_key key = {.network_namespace = BPF_CORE_READ(context->state, net, net_cookie),
                           .mark = BPF_CORE_READ(context->skb, mark)};
    __u32 *slot = owned_mark_profile(&key);
    if (!slot)
        return 1;
    struct tcp_tuple packet = {0};
    int parsed = netfilter_tcp_tuple(context, &packet);
    struct profile *profile = bpf_map_lookup_elem(&profiles, slot);
    /* Незавершенный перевод служебной метки отклоняется до подтверждения conntrack. */
    if (!profile || !profile_mark_matches(profile, key.mark) || !profile->device_identity ||
        profile->device_identity != device_identity(context->state->out) ||
        profile->interface_index != (__u32)BPF_CORE_READ(context->state, out, ifindex))
        return reject_marked_output(context, *slot, &packet);
    if (parsed < 0)
        return reject_marked_output(context, *slot, &packet);
    if (packet.family == 4) {
        if (!profile->ready4)
            return reject_marked_output(context, *slot, &packet);
        for (unsigned index = 0; index < 4; index++)
            if (packet.source[index] != profile->ipv4[index])
                return reject_marked_output(context, *slot, &packet);
    } else {
        if (!profile->ready6)
            return reject_marked_output(context, *slot, &packet);
        for (unsigned index = 0; index < 16; index++)
            if (packet.source[index] != profile->ipv6[index])
                return reject_marked_output(context, *slot, &packet);
    }
    return 1;
}
#ifdef AP_BINDING_SNAPSHOT
#include "snapshot-output.h"
#endif
static __noinline int transport_final_output(struct bpf_nf_ctx *context, const struct tcp_tuple *tuple) {
    struct sock *transport_socket = BPF_CORE_READ((struct sk_buff___ct *)context->skb, sk);
    if (transport_socket) {
        __u64 cookie = BPF_CORE_READ(transport_socket, __sk_common.skc_cookie.counter);
        int transport = transport_choice(cookie, tuple->netns, tuple->family, tuple->protocol,
                                          tuple->destination_port, tuple->destination, 0);
        if (transport >= 0) {
            const struct transport_registration *registration = bpf_map_lookup_elem(&transport_sockets, &cookie);
            struct mark_key mark = {.network_namespace = tuple->netns, .mark = BPF_CORE_READ(context->skb, mark)};
            return transport && registration && registration->device == device_identity(context->state->out) &&
                   !owned_mark_profile(&mark) && !owned_interface_profile(tuple->netns, context->state->out);
        }
    }
    return -1;
}

/* Проверяется каждый пакет, включая прежние SYSTEM-сокеты до смены DNS ОС. */
static __noinline int dns_final_output(struct bpf_nf_ctx *context, const struct tcp_tuple *tuple) {
    __u32 zero = 0;
    const struct dns_guard_state *guard = bpf_map_lookup_elem(&dns_guard, &zero);
    if (!guard || !guard->active || guard->netns != tuple->netns ||
        (tuple->protocol != 6 && tuple->protocol != 17) ||
        !ar_guarded_dns_destination(tuple->destination_port, tuple->family, tuple->destination))
        return 1;
    struct dns_listener_key endpoint = {.netns = tuple->netns, .family = tuple->family,
                                        .protocol = tuple->protocol, .port = tuple->destination_port};
    __builtin_memcpy(endpoint.address, tuple->destination, 16);
    const struct dns_listener_value *listener = bpf_map_lookup_elem(&dns_listeners, &endpoint);
    if (listener && listener->cookie && listener->device == device_identity(context->state->out)) {
        const struct dns_listener_key *live = bpf_map_lookup_elem(&dns_listener_fds, &listener->cookie);
        if (live && !__builtin_memcmp(live, &endpoint, sizeof(endpoint))) return 1;
    }
    struct sock *socket = BPF_CORE_READ((struct sk_buff___ct *)context->skb, sk);
    if (!socket) return 0;
    struct flow_key key = {.cookie = BPF_CORE_READ(socket, __sk_common.skc_cookie.counter),
                           .family = tuple->family, .protocol = tuple->protocol,
                           .port = tuple->destination_port};
    __builtin_memcpy(key.destination, tuple->destination, 16);
    const struct dns_registration *entry = bpf_map_lookup_elem(&dns_sockets, &key.cookie);
    if (!entry || !dns_registration_allowed(entry, &key) || entry->netns != tuple->netns) return 0;
    const struct profile *profile = bpf_map_lookup_elem(&profiles, &entry->slot);
    if (!profile || profile->interface_index != (__u32)BPF_CORE_READ(context->state, out, ifindex) ||
        profile->device_identity != device_identity(context->state->out) ||
        !profile_mark_matches(profile, BPF_CORE_READ(context->skb, mark))) return 0;
    for (unsigned index = 0; index < 16; index++)
        if ((tuple->family == 6 || index < 4) &&
            tuple->source[index] != (tuple->family == 4 ? profile->ipv4[index] : profile->ipv6[index])) return 0;
    return 1;
}
SEC("netfilter") int guard_final_output(struct bpf_nf_ctx *context) {
    struct tcp_tuple tuple = {0};
    int parsed = netfilter_tcp_tuple(context, &tuple);
    int transport = parsed >= 0 ? transport_final_output(context, &tuple) : -1;
    if (transport >= 0) return transport;
    if (parsed >= 0 && !dns_final_output(context, &tuple)) return 0;
#ifdef AP_BINDING_SNAPSHOT
    if (parsed >= 0 && (tuple.protocol == 6 || tuple.protocol == 17)) {
        int allowed = snapshot_final_output(context, &tuple);
        if (allowed >= 0)
            return allowed;
    }
#endif
    if (parsed)
        return 1;
    struct tcp_tuple_route *entry = bpf_map_lookup_elem(&tcp_routes, &tuple);
    if (!entry)
        return 1;
    struct tcp_route_snapshot snapshot = {};
    if (!tcp_route_read(entry, bpf_ktime_get_ns(), &snapshot))
        return 0;
    struct cached_route *saved = &snapshot.route;
    __u64 action = cached_result(saved, tuple.family);
    if (action == 0)
        return 1;
    if (action < 2)
        return 0;
    struct profile *profile = bpf_map_lookup_elem(&profiles, &saved->decision.profile);
    if (!profile || profile->network_namespace != tuple.netns ||
        profile->interface_index != (__u32)BPF_CORE_READ(context->state, out, ifindex) ||
        !profile_mark_matches(profile, BPF_CORE_READ(context->skb, mark)) || !profile->device_identity ||
        profile->device_identity != device_identity(context->state->out))
        return 0;
    if (tuple.family == 4) {
        for (unsigned index = 0; index < 4; index++)
            if (tuple.source[index] != profile->ipv4[index])
                return 0;
    } else {
        for (unsigned index = 0; index < 16; index++)
            if (tuple.source[index] != profile->ipv6[index])
                return 0;
    }
    return 1;
}
char LICENSE[] SEC("license") = "GPL";
