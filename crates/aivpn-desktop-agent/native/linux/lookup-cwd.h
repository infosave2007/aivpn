#pragma once

struct lookup_fs_record {
    __u64 writer, transition, nonce, proof;
    __u32 sequence, reserved;
    __u64 dentry, mount;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, AP_LOOKUP_PROOF_CAPACITY);
    __type(key, __u64);
    __type(value, struct lookup_fs_record);
} lookup_filesystems SEC(".maps");
static const __u64 lookup_empty_fs[sizeof(struct lookup_fs_record) / sizeof(__u64)] = {0};

static __always_inline __u32 lookup_fs_sequence(struct fs_struct *fs) {
    return BPF_CORE_READ(fs, seq.seqcount.seqcount.sequence);
}

/* Владение id передается функции даже при отказе публикации. */
static __noinline void lookup_fs_publish(__u64 address, __u64 id, __u32 sequence,
                                          __u64 nonce, const struct lookup_fs_work *source) {
    if (!address || !source->dentry || !source->mount || (sequence & 1) || !nonce) {
        lookup_release(id);
        return;
    }
    struct lookup_fs_record *record = bpf_map_lookup_elem(&lookup_filesystems, &address);
    if (!record) { lookup_release(id); return; }
    __u64 old = 0;
    int accepted = 0;
    if (__sync_val_compare_and_swap(&record->writer, 0, 1)) {
        lookup_release(id);
        return;
    }
    if (__sync_fetch_and_add(&record->transition, 0) == nonce) {
        old = record->proof;
        record->proof = id;
        record->sequence = sequence;
        record->dentry = source->dentry;
        record->mount = source->mount;
        record->nonce = nonce;
        accepted = 1;
    }
    __sync_lock_test_and_set(&record->writer, 0);
    lookup_release(accepted ? old : id);
}

/* Новый nonce не дает запоздавшему fexit присвоить другому переходу свой source. */
static __noinline __u64 lookup_fs_transition(struct fs_struct *fs) {
    __u64 nonce = next_file_cookie(), address = (unsigned long)fs;
    if (!address || !nonce) return 0;
    bpf_map_update_elem(&lookup_filesystems, &address, lookup_empty_fs, BPF_NOEXIST);
    struct lookup_fs_record *record = bpf_map_lookup_elem(&lookup_filesystems, &address);
    if (!record) return 0;
    __sync_lock_test_and_set(&record->transition, nonce);
    return nonce;
}

static __noinline __u64 lookup_fs_acquire(struct fs_struct *fs, __u64 dentry, __u64 mount,
                                           __u32 *sequence, __u64 *nonce) {
    if (!fs || !dentry || !mount)
        return 0;
    __u32 before = lookup_fs_sequence(fs);
    if ((before & 1) || (unsigned long)BPF_CORE_READ(fs, pwd.dentry) != dentry ||
        (unsigned long)BPF_CORE_READ(fs, pwd.mnt) != mount)
        return 0;
    __u64 address = (unsigned long)fs;
    struct lookup_fs_record *record = bpf_map_lookup_elem(&lookup_filesystems, &address);
    if (!record)
        return 0;
    __u64 id = 0, stamp = 0;
    if (__sync_val_compare_and_swap(&record->writer, 0, 1))
        return 0;
    if (record->nonce && record->nonce == __sync_fetch_and_add(&record->transition, 0) &&
        record->sequence == before && record->dentry == dentry && record->mount == mount) {
        id = record->proof;
        stamp = record->nonce;
    }
    __sync_lock_test_and_set(&record->writer, 0);
    id = lookup_acquire(id);
    if (lookup_fs_sequence(fs) != before || __sync_fetch_and_add(&record->transition, 0) != stamp) {
        lookup_release(id); return 0;
    }
    *sequence = before;
    *nonce = stamp;
    return id;
}

static __noinline int lookup_fs_unchanged(const struct lookup_fs_work *source) {
    struct fs_struct *fs = (void *)(unsigned long)source->fs;
    if (!fs || !source->proof || lookup_fs_sequence(fs) != source->sequence)
        return 0;
    __u64 address = source->fs;
    struct lookup_fs_record *record = bpf_map_lookup_elem(&lookup_filesystems, &address);
    if (!record) return 0;
    int matches;
    if (__sync_val_compare_and_swap(&record->writer, 0, 1))
        return 0;
    matches = record->nonce == source->nonce && record->proof == source->proof &&
              __sync_fetch_and_add(&record->transition, 0) == source->nonce &&
              record->sequence == source->sequence && record->dentry == source->dentry && record->mount == source->mount;
    __sync_lock_test_and_set(&record->writer, 0);
    return matches && lookup_fs_sequence(fs) == source->sequence &&
           __sync_fetch_and_add(&record->transition, 0) == source->nonce;
}

/* Результат copy_fs_struct еще не опубликован другим пользователям fs. */
static __noinline void lookup_fs_initialise(struct fs_struct *fs, __u64 id,
                                             const struct lookup_fs_work *source) {
    __u64 address = (unsigned long)fs, nonce = next_file_cookie();
    if (!address || !nonce) { lookup_release(id); return; }
    __u32 sequence = lookup_fs_sequence(fs);
    bpf_map_update_elem(&lookup_filesystems, &address, lookup_empty_fs, BPF_NOEXIST);
    struct lookup_fs_record *record = bpf_map_lookup_elem(&lookup_filesystems, &address);
    if (!record) { lookup_release(id); return; }
    __u64 old;
    if (__sync_val_compare_and_swap(&record->writer, 0, 1)) {
        lookup_release(id);
        return;
    }
    old = record->proof;
    record->proof = id;
    record->nonce = nonce;
    __sync_lock_test_and_set(&record->transition, nonce);
    record->sequence = sequence;
    record->dentry = source->dentry;
    record->mount = source->mount;
    __sync_lock_test_and_set(&record->writer, 0);
    lookup_release(old);
}

static __always_inline __u64 lookup_path_source(struct lookup_capture *capture, struct path *path) {
    __u64 address = (unsigned long)path - bpf_core_field_offset(struct file, f_path);
    __u64 *stored = bpf_map_lookup_elem(&lookup_files, &address);
    __u64 id = stored ? lookup_acquire(*stored) : 0;
    if (!id)
        id = lookup_directory_take(capture, (unsigned long)path);
    const struct ap_lookup_proof *proof = lookup_find(id);
    __u64 inode = (unsigned long)BPF_CORE_READ(path, dentry, d_inode);
    if (id && (!proof || !inode || proof->facts.inode_address != inode)) {
        lookup_release(id);
        id = 0;
    }
    return id;
}

static __always_inline void lookup_fs_start(struct lookup_fs_work *work, struct fs_struct *fs,
                                             struct path *path, __u64 id) {
    lookup_fs_work_clear(work);
    work->fs = (unsigned long)fs;
    work->path = (unsigned long)path;
    work->sequence = lookup_fs_sequence(fs);
    work->dentry = (unsigned long)BPF_CORE_READ(path, dentry);
    work->mount = (unsigned long)BPF_CORE_READ(path, mnt);
    work->proof = id;
    work->nonce = lookup_fs_transition(fs);
    work->active = work->nonce != 0;
}
static __always_inline void lookup_fs_finish(struct lookup_fs_work *work, struct fs_struct *fs,
                                              struct path *path) {
    __u64 id = __sync_lock_test_and_set(&work->proof, 0);
    int active = work->active;
    work->active = 0;
    __u32 after = lookup_fs_sequence(fs);
    if (active && work->fs == (unsigned long)fs && work->path == (unsigned long)path &&
        !(work->sequence & 1) && after == (__u32)(work->sequence + 2) &&
        work->dentry == (unsigned long)BPF_CORE_READ(fs, pwd.dentry) &&
        work->mount == (unsigned long)BPF_CORE_READ(fs, pwd.mnt)) {
        lookup_fs_publish((unsigned long)fs, id, after, work->nonce, work);
    } else {
        lookup_release(id);
    }
}

SEC("fentry/set_fs_pwd")
int BPF_PROG(lookup_pwd_begin, struct fs_struct *fs, struct path *path) {
    (void)ctx;
    struct lookup_capture *capture = lookup_current(1);
    if (capture) lookup_fs_start(&capture->pwd_change, fs, path, lookup_path_source(capture, path));
    return 0;
}
SEC("fexit/set_fs_pwd")
int BPF_PROG(lookup_pwd_end, struct fs_struct *fs, struct path *path) {
    (void)ctx;
    struct lookup_capture *capture = lookup_current(0);
    if (capture) lookup_fs_finish(&capture->pwd_change, fs, path);
    return 0;
}

SEC("fentry/set_fs_root")
int BPF_PROG(lookup_root_begin, struct fs_struct *fs, struct path *path) {
    (void)ctx;
    struct lookup_capture *capture = lookup_current(1);
    if (!capture) return 0;
    __u32 sequence = 0;
    __u64 nonce = 0;
    __u64 dentry = (unsigned long)BPF_CORE_READ(fs, pwd.dentry);
    __u64 mount = (unsigned long)BPF_CORE_READ(fs, pwd.mnt);
    __u64 id = lookup_fs_acquire(fs, dentry, mount, &sequence, &nonce);
    lookup_fs_work_clear(&capture->root_change);
    capture->root_change = (struct lookup_fs_work){.proof = id, .fs = (unsigned long)fs,
        .path = (unsigned long)path, .dentry = dentry, .mount = mount, .sequence = sequence,
        .nonce = lookup_fs_transition(fs), .active = id != 0};
    return 0;
}
SEC("fexit/set_fs_root")
int BPF_PROG(lookup_root_end, struct fs_struct *fs, struct path *path) {
    (void)ctx;
    struct lookup_capture *capture = lookup_current(0);
    if (capture) lookup_fs_finish(&capture->root_change, fs, path);
    return 0;
}

SEC("fentry/copy_fs_struct")
int BPF_PROG(lookup_fs_copy_begin, struct fs_struct *fs) {
    (void)ctx;
    struct lookup_capture *capture = lookup_current(1);
    if (!capture) return 0;
    __u32 sequence = 0;
    __u64 nonce = 0;
    __u64 dentry = (unsigned long)BPF_CORE_READ(fs, pwd.dentry);
    __u64 mount = (unsigned long)BPF_CORE_READ(fs, pwd.mnt);
    __u64 id = lookup_fs_acquire(fs, dentry, mount, &sequence, &nonce);
    lookup_fs_work_clear(&capture->fs_copy);
    capture->fs_copy = (struct lookup_fs_work){.proof = id, .fs = (unsigned long)fs,
        .dentry = dentry, .mount = mount, .sequence = sequence, .nonce = nonce, .active = id != 0};
    return 0;
}
SEC("fexit/copy_fs_struct")
int BPF_PROG(lookup_fs_copy_end, struct fs_struct *fs, struct fs_struct *created) {
    (void)ctx;
    struct lookup_capture *capture = lookup_current(0);
    if (!capture) return 0;
    struct lookup_fs_work *work = &capture->fs_copy;
    int valid_source = work->active && lookup_fs_unchanged(work);
    __u64 id = __sync_lock_test_and_set(&work->proof, 0);
    work->active = 0;
    if (valid_source && created && work->fs == (unsigned long)fs &&
        work->dentry == (unsigned long)BPF_CORE_READ(created, pwd.dentry) &&
        work->mount == (unsigned long)BPF_CORE_READ(created, pwd.mnt)) {
        lookup_fs_initialise(created, id, work);
    } else {
        lookup_release(id);
    }
    return 0;
}

SEC("fentry/free_fs_struct")
int BPF_PROG(lookup_fs_free, struct fs_struct *fs) {
    (void)ctx;
    __u64 address = (unsigned long)fs;
    struct lookup_fs_record *record = bpf_map_lookup_elem(&lookup_filesystems, &address);
    __u64 id = 0;
    if (record) {
        id = __sync_lock_test_and_set(&record->proof, 0);
        bpf_map_delete_elem(&lookup_filesystems, &address);
    }
    lookup_release(id);
    return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(lookup_context_sys_exit, struct pt_regs *registers, long result) {
    (void)ctx; (void)registers; (void)result;
    struct lookup_capture *capture = lookup_current(0);
    if (capture) {
        lookup_directory_clear(capture);
        lookup_fs_work_clear(&capture->pwd_change);
        lookup_fs_work_clear(&capture->root_change);
        lookup_fs_work_clear(&capture->fs_copy);
    }
    return 0;
}
