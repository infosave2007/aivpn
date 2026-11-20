#pragma once

#if defined(__BPF__) && defined(AP_BINDING_SNAPSHOT)
#include "lookup-prefix.h"
#define AP_LOOKUP_PROOF_CAPACITY 65536U
#define AP_LOOKUP_REF_LIMIT (1ULL << 62)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, AP_LOOKUP_PROOF_CAPACITY);
    __type(key, __u64);
    __type(value, struct ap_lookup_proof);
} source_proofs SEC(".maps");
struct lookup_lifetime {
    __u64 created, retired, invalid_release, overflow;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct lookup_lifetime);
} lookup_lifetimes SEC(".maps");

static __always_inline struct lookup_lifetime *lookup_statistics(void) {
    __u32 zero = 0;
    return bpf_map_lookup_elem(&lookup_lifetimes, &zero);
}
static __always_inline struct ap_lookup_proof *lookup_find(__u64 id) {
    return id ? bpf_map_lookup_elem(&source_proofs, &id) : 0;
}
/* При нуле запись уже закрыта. Незавершенный acquire не создает нового владельца. */
static __always_inline __u64 lookup_acquire(__u64 id) {
    struct ap_lookup_proof *proof = lookup_find(id);
    if (!proof)
        return 0;
    __u64 previous = __sync_fetch_and_add(&proof->references, 1);
    if (previous && previous < AP_LOOKUP_REF_LIMIT)
        return id;
    __sync_fetch_and_sub(&proof->references, 1);
    if (previous >= AP_LOOKUP_REF_LIMIT) {
        struct lookup_lifetime *stats = lookup_statistics();
        if (stats) __sync_fetch_and_add(&stats->overflow, 1);
    }
    return 0;
}
static __always_inline void lookup_release(__u64 id) {
    if (!id)
        return;
    struct ap_lookup_proof *proof = lookup_find(id);
    __u64 previous = proof ? __sync_fetch_and_sub(&proof->references, 1) : 0;
    if (previous == 1) {
        lookup_prefix_clear(id, proof->prefix_count);
        bpf_map_delete_elem(&source_proofs, &id);
        struct lookup_lifetime *stats = lookup_statistics();
        if (stats) __sync_fetch_and_add(&stats->retired, 1);
    } else if (!previous) {
        if (proof) {
            __sync_val_compare_and_swap(&proof->references, ~0ULL, 0);
            lookup_prefix_clear(id, proof->prefix_count);
            bpf_map_delete_elem(&source_proofs, &id);
        }
        struct lookup_lifetime *stats = lookup_statistics();
        if (stats) __sync_fetch_and_add(&stats->invalid_release, 1);
    }
}
static __always_inline void lookup_frame_clear(struct exec_frame *frame) {
    __u64 previous = __sync_lock_test_and_set(&frame->lookup, 0);
    lookup_release(previous);
}
static __always_inline void lookup_pending_clear(struct pending_exec *pending) {
    __u64 previous = __sync_lock_test_and_set(&pending->lookup, 0);
    lookup_release(previous);
}
static __always_inline void lookup_pending_commit(struct exec_frame *target,
                                                   struct pending_exec *pending) {
    __u64 id = __sync_lock_test_and_set(&pending->lookup, 0);
    __u64 previous = __sync_lock_test_and_set(&target->lookup, id);
    lookup_release(previous);
}
#elif defined(AP_BINDING_SNAPSHOT)
static __inline void lookup_frame_clear(struct exec_frame *frame) { frame->lookup = 0; }
static __inline void lookup_pending_clear(struct pending_exec *pending) { pending->lookup = 0; }
static __inline void lookup_pending_commit(struct exec_frame *target, struct pending_exec *pending) {
    target->lookup = pending->lookup; pending->lookup = 0;
}
#else
static __inline void lookup_frame_clear(struct exec_frame *frame) { (void)frame; }
static __inline void lookup_pending_clear(struct pending_exec *pending) { (void)pending; }
static __inline void lookup_pending_commit(struct exec_frame *target, struct pending_exec *pending) {
    (void)target; (void)pending;
}
#endif

static __always_inline void copy_exec_frame(struct exec_frame *target, const struct exec_frame *source) {
#if defined(__BPF__) && defined(AP_BINDING_SNAPSHOT)
    __u64 id = lookup_acquire(source->lookup);
    int missing = source->lookup && !id;
    __u64 previous = __sync_lock_test_and_set(&target->lookup, 0);
#endif
    target->source = source->source;
    target->image = source->image;
#if defined(__BPF__) && defined(AP_BINDING_SNAPSHOT)
    target->lookup = id;
    if (missing) target->source.path_flags = 0;
    lookup_release(previous);
#elif defined(AP_BINDING_SNAPSHOT)
    target->lookup = source->lookup;
#endif
}
static __always_inline void copy_history_slot(struct history_slot *target, const struct history_slot *source) {
    copy_exec_frame(&target->parent, &source->parent);
    target->edge_identity = source->edge_identity;
    target->kind = source->kind;
    target->has_carried = source->has_carried;
}
static __always_inline void lookup_state_clear(struct process_state *state) {
    if (!state) return;
    state->snapshot_identity = 0;
    lookup_frame_clear(&state->self);
    AP_FOR(index, AP_PARENT_LIMIT) { lookup_frame_clear(&state->parents[index].parent); }
}
static __always_inline void lookup_companion_clear(struct process_companion *companion) {
    if (!companion) return;
    companion->snapshot_identity = 0;
    companion->available = 0;
    AP_FOR(index, AP_PARENT_LIMIT) { lookup_frame_clear(&companion->carried[index]); }
}
