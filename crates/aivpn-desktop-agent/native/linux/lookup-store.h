#pragma once

#define AP_LOOKUP_OPEN_DEPTH 4U
#define AP_LOOKUP_LINK_LIMIT 40U
#define AP_LOOKUP_EXEC 1U
#define AP_LOOKUP_FILE 2U
#define AP_LOOKUP_SKIP 3U
#define AP_LOOKUP_DIRECTORY 4U
#define AP_LOOKUP_NAME_VALID 1U
#define AP_LOOKUP_USE_CWD 2U
#define AP_LOOKUP_BASE_MERGED 4U

struct lookup_continuation { struct ph_hash hash; __u32 length, flags; };
struct lookup_operation {
    struct ap_lookup_facts proof;
    struct ph_hash filename;
    __u64 token, walk, file;
    __u64 base_lookup;
    __u64 base_fs, base_nonce;
    __u32 base_sequence, base_reserved;
    int expected_fd;
    __u32 kind, fd_state, published;
    __u32 filename_length, flags, file_seen, link_count;
    struct lookup_continuation continuations[AP_LOOKUP_LINK_LIMIT];
    __u32 observations;
};
struct lookup_directory_result { __u64 proof, path; };
struct lookup_capture {
    struct lookup_operation operations[AP_LOOKUP_OPEN_DEPTH];
    __u64 ready;
    __u32 depth, overflow, ready_valid, directory_cursor;
    __u64 ready_operation, ready_file;
    struct lookup_directory_result directories[4];
    struct lookup_fs_work pwd_change, root_change, fs_copy;
};
AP_LOCAL_STORAGE_CHECK(lookup_capture);
struct lookup_stage { struct ap_lookup_observation entries[128]; };
AP_LOCAL_STORAGE_CHECK(lookup_stage);

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct lookup_capture);
} lookup_captures SEC(".maps");
/* Ключ принадлежит живому file, а не номеру FD или inode. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, AP_LOOKUP_PROOF_CAPACITY);
    __type(key, __u64);
    __type(value, __u64);
} lookup_files SEC(".maps");

static __always_inline void lookup_clear_base(struct lookup_operation *operation) {
    __u64 old = __sync_lock_test_and_set(&operation->base_lookup, 0);
    lookup_release(old);
    operation->fd_state = 0;
    operation->base_fs = operation->base_nonce = 0;
    operation->base_sequence = 0;
}
static __always_inline void lookup_clear_operation(struct lookup_operation *operation) {
    lookup_clear_base(operation);
    if (!operation->published)
        lookup_prefix_clear(operation->token, operation->proof.count);
    operation->proof.count = 0;
    operation->published = 0;
}
static __always_inline int lookup_publish_file(struct file *file, __u64 id) {
    __u64 key = (unsigned long)file;
    if (!id || bpf_map_update_elem(&lookup_files, &key, &id, BPF_NOEXIST))
        return -1;
    return 0;
}
#define LOOKUP_STAGE_MAP(name) struct { \
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE); \
    __uint(map_flags, BPF_F_NO_PREALLOC); \
    __type(key, int); \
    __type(value, struct lookup_stage); \
} name SEC(".maps")
LOOKUP_STAGE_MAP(lookup_stage0a); LOOKUP_STAGE_MAP(lookup_stage0b);
LOOKUP_STAGE_MAP(lookup_stage1a); LOOKUP_STAGE_MAP(lookup_stage1b);
LOOKUP_STAGE_MAP(lookup_stage2a); LOOKUP_STAGE_MAP(lookup_stage2b);
LOOKUP_STAGE_MAP(lookup_stage3a); LOOKUP_STAGE_MAP(lookup_stage3b);
#undef LOOKUP_STAGE_MAP

static __always_inline void *lookup_stage_map(unsigned slot, unsigned half) {
    switch (slot * 2 + half) {
    case 0: return &lookup_stage0a;
    case 1: return &lookup_stage0b;
    case 2: return &lookup_stage1a;
    case 3: return &lookup_stage1b;
    case 4: return &lookup_stage2a;
    case 5: return &lookup_stage2b;
    case 6: return &lookup_stage3a;
    case 7: return &lookup_stage3b;
    default: return 0;
    }
}
static __always_inline struct lookup_capture *lookup_current(int create) {
    return bpf_task_storage_get(&lookup_captures, bpf_get_current_task_btf(), 0,
                               create ? BPF_LOCAL_STORAGE_GET_F_CREATE : 0);
}
static __always_inline void lookup_fs_work_clear(struct lookup_fs_work *work) {
    work->active = 0;
    __u64 old = __sync_lock_test_and_set(&work->proof, 0);
    lookup_release(old);
}
static __always_inline void lookup_directory_clear(struct lookup_capture *capture) {
    AP_FOR(index, 4) {
        __u64 old = __sync_lock_test_and_set(&capture->directories[index].proof, 0);
        capture->directories[index].path = 0;
        lookup_release(old);
    }
}
/* Ready принадлежит конкретному output path текущего kernel lookup. */
static __always_inline void lookup_directory_ready(struct lookup_capture *capture, __u64 path,
                                                   __u64 id) {
    unsigned slot = capture->directory_cursor++ & 3U;
    AP_FOR(index, 4) {
        if (capture->directories[index].path == path) { slot = index; break; }
    }
    if (slot >= 4) { lookup_release(id); return; }
    struct lookup_directory_result *entry = &capture->directories[slot];
    __u64 old = __sync_lock_test_and_set(&entry->proof, id);
    entry->path = path;
    lookup_release(old);
}
static __always_inline __u64 lookup_directory_take(struct lookup_capture *capture, __u64 path) {
    AP_FOR(index, 4) {
        struct lookup_directory_result *entry = &capture->directories[index];
        if (entry->path == path) {
            entry->path = 0;
            return __sync_lock_test_and_set(&entry->proof, 0);
        }
    }
    return 0;
}
static __always_inline struct lookup_operation *lookup_top(struct lookup_capture *capture) {
    if (!capture || capture->overflow || !capture->depth || capture->depth > AP_LOOKUP_OPEN_DEPTH)
        return 0;
    return &capture->operations[capture->depth - 1];
}
static __always_inline void lookup_clear_ready(struct lookup_capture *capture) {
    capture->ready_valid = 0;
    __u64 old = __sync_lock_test_and_set(&capture->ready, 0);
    lookup_release(old);
}
static __always_inline void lookup_partial(struct ap_lookup_facts *proof, __u32 domains,
                                          __u32 reason) {
    if (proof) { proof->complete &= ~domains; proof->reasons |= reason; }
}

static __always_inline void lookup_restart_walk(struct lookup_operation *operation) {
    lookup_clear_base(operation);
    if (operation->published)
        operation->token = next_file_cookie();
    else
        lookup_prefix_clear(operation->token, operation->proof.count);
    operation->published = 0;
    operation->flags &= AP_LOOKUP_NAME_VALID;
    operation->proof = (struct ap_lookup_facts){ .version = AP_LOOKUP_VERSION,
        .operation = operation->token, .complete = AP_LOOKUP_COMPLETE };
    operation->file_seen = 0; operation->file = 0;
    operation->link_count = 0; operation->observations = 0;
    AP_FOR(index, (int)AP_LOOKUP_LINK_LIMIT) {
        operation->continuations[index] = (struct lookup_continuation){0};
    }
}
static __always_inline struct lookup_operation *lookup_push(struct lookup_capture *capture,
                                                             __u32 kind, int fd, __u64 path) {
    if (capture->overflow || capture->depth >= AP_LOOKUP_OPEN_DEPTH) {
        struct lookup_operation *outer = lookup_top(capture);
        if (outer)
            lookup_partial(&outer->proof, AP_LOOKUP_COMPLETE, AP_LOOKUP_OVERFLOW);
        capture->overflow++;
        return 0;
    }
    unsigned slot = capture->depth;
    if (slot >= AP_LOOKUP_OPEN_DEPTH)
        return 0;
    struct lookup_operation *operation = &capture->operations[slot];
    lookup_clear_operation(operation);
    operation->token = next_file_cookie();
    operation->filename = (struct ph_hash){0};
    operation->filename_length = 0;
    operation->kind = kind;
    operation->expected_fd = fd;
    operation->flags = operation->file_seen = 0;
    lookup_restart_walk(operation);
    operation->walk = 0;
    operation->file = path;
    capture->depth++;
    return operation;
}
static __always_inline void lookup_stage_append(struct lookup_capture *capture,
                                                struct lookup_operation *operation,
                                                const struct ap_lookup_observation *observation,
                                                struct working_buffer *work,
                                                const struct ap_lookup_scope *scope) {
    struct ap_lookup_facts *proof = &operation->proof;
    /* Повторный chdir(".") не расходует лимит на одинаковые prefix candidates. */
    AP_FOR(offset, (int)AP_LOOKUP_LIMIT) {
        if ((__u32)offset >= proof->count)
            break;
        void *old_map = lookup_stage_map(capture->depth - 1, (__u32)offset / 128);
        struct lookup_stage *old = old_map ? bpf_task_storage_get(old_map, bpf_get_current_task_btf(), 0, 0) : 0;
        if (!old || !ap_lookup_location_equal(&old->entries[(__u32)offset % 128], observation))
            continue;
        if (observation->flags & AP_LOOKUP_LOGICAL) {
            const struct lookup_prefix_value *prefix =
                lookup_prefix_find(operation->token, offset, AP_LOOKUP_LOGICAL);
            if (!prefix || !scope || !ap_lookup_scope_equal(&prefix->scope, scope))
                continue;
        }
        return;
    }
    if (proof->count >= AP_LOOKUP_LIMIT) {
        lookup_partial(proof, AP_LOOKUP_COMPLETE, AP_LOOKUP_OVERFLOW); return;
    }
    unsigned slot = capture->depth - 1;
    void *map = lookup_stage_map(slot, proof->count / 128);
    struct lookup_stage *stage = map ? bpf_task_storage_get(map, bpf_get_current_task_btf(), 0,
                                                          BPF_LOCAL_STORAGE_GET_F_CREATE) : 0;
    if (!stage) { lookup_partial(proof, AP_LOOKUP_COMPLETE, AP_LOOKUP_UNREADABLE); return; }
    unsigned index = proof->count % 128;
    stage->entries[index] = *observation;
    if ((observation->flags & AP_LOOKUP_PHYSICAL) &&
        lookup_prefix_store(operation->token, proof->count, AP_LOOKUP_PHYSICAL,
                            &work->prefix_physical.prefix, 0))
        proof->reasons |= AP_LOOKUP_PREFIX_MISSING;
    if ((observation->flags & AP_LOOKUP_LOGICAL) &&
        lookup_prefix_store(operation->token, proof->count, AP_LOOKUP_LOGICAL,
                            &work->prefix_logical.prefix, scope))
        proof->reasons |= AP_LOOKUP_PREFIX_MISSING;
    proof->count++;
}
static const __u64 lookup_empty_proof[sizeof(struct ap_lookup_proof) / sizeof(__u64)] = {0};
static __always_inline __u64 lookup_freeze(struct lookup_capture *capture,
                                           struct lookup_operation *operation) {
    __u64 id = operation->token;
    if (!id || bpf_map_update_elem(&source_proofs, &id, lookup_empty_proof, BPF_NOEXIST))
        return 0;
    struct ap_lookup_proof *proof = lookup_find(id);
    if (!proof) {
        bpf_map_delete_elem(&source_proofs, &id);
        return 0;
    }
    proof->references = 1;
    proof->prefix_count = operation->proof.count;
    operation->published = 1;
    struct lookup_lifetime *stats = lookup_statistics();
    if (stats) __sync_fetch_and_add(&stats->created, 1);
    proof->facts = operation->proof;
    proof->facts.count = 0;
    AP_FOR(index, (int)AP_LOOKUP_LIMIT) {
        if ((unsigned)index >= operation->proof.count) break;
        void *map = lookup_stage_map(capture->depth - 1, (unsigned)index / 128);
        struct lookup_stage *stage = map ? bpf_task_storage_get(map, bpf_get_current_task_btf(), 0, 0) : 0;
        if (!stage) { lookup_partial(&proof->facts, AP_LOOKUP_COMPLETE, AP_LOOKUP_UNREADABLE); break; }
        proof->entries[index] = stage->entries[(unsigned)index % 128];
        proof->facts.count = index + 1;
    }
    return id;
}
static __always_inline void lookup_stage_clear(unsigned slot) {
    void *a = lookup_stage_map(slot, 0), *b = lookup_stage_map(slot, 1);
    if (a) bpf_task_storage_delete(a, bpf_get_current_task_btf());
    if (b) bpf_task_storage_delete(b, bpf_get_current_task_btf());
}
