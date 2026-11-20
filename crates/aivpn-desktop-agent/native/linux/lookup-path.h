#pragma once

struct vfsmount {
    struct dentry *mnt_root;
} __attribute__((preserve_access_index));
struct mount {
    struct mount *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
    int mnt_id;
} __attribute__((preserve_access_index));
struct fs_struct {
    struct seqlock seq;
    struct path root, pwd;
} __attribute__((preserve_access_index));
struct filename {
    const char *name;
} __attribute__((preserve_access_index));
struct saved {
    const char *name;
} __attribute__((preserve_access_index));
struct nameidata {
    struct path path, root;
    struct qstr last;
    struct filename *name;
    struct saved *stack;
    unsigned flags, depth, state;
    int dfd;
} __attribute__((preserve_access_index));
struct open_flags {
    int open_flag;
} __attribute__((preserve_access_index));

extern const void mount_lock __ksym;

static __always_inline struct mount *lookup_mount(struct vfsmount *mount) {
    return (void *)((char *)mount - bpf_core_field_offset(struct mount, mnt));
}

static __always_inline int lookup_mount_sequence(__u32 *sequence) {
    const struct seqlock *lock = (const struct seqlock *)&mount_lock;
    return bpf_core_read(sequence, sizeof(*sequence), &lock->seqcount.seqcount.sequence);
}

/* Относительный lookup может еще не сохранить root в nameidata. */
static __always_inline int lookup_root(struct nameidata *nd, struct path *root) {
    if (bpf_core_read(root, sizeof(*root), &nd->root))
        return -1;
    if (root->mnt && root->dentry)
        return 0;
    struct fs_struct *fs = BPF_CORE_READ((struct task_struct *)bpf_get_current_task_btf(), fs);
    __u32 before = 0, after = 0;
    if (!fs || bpf_core_read(&before, sizeof(before), &fs->seq.seqcount.seqcount.sequence) ||
        (before & 1) || bpf_core_read(root, sizeof(*root), &fs->root) ||
        bpf_core_read(&after, sizeof(after), &fs->seq.seqcount.seqcount.sequence) ||
        before != after || !root->mnt || !root->dentry)
        return -1;
    return 0;
}

/* Вызывающий удерживает RCU. Mount-переходы сравниваются с фактическим root lookup. */
__noinline int lookup_logical_parent(__u64 address,
                                      struct working_buffer *work __arg_nonnull,
                                      struct ap_lookup_facts *proof __arg_nonnull) {
    struct nameidata *nd = (void *)(unsigned long)address;
    struct path root = {0}, path = {0};
    __u32 rename_before = 0, rename_after = 0, mount_before = 0, mount_after = 0;
    if (lookup_root(nd, &root) || bpf_core_read(&path, sizeof(path), &nd->path) ||
        !path.mnt || !path.dentry || physical_rename_sequence(&rename_before) ||
        lookup_mount_sequence(&mount_before) || ((rename_before | mount_before) & 1))
        return 0;
    physical_read_barrier(work);
    __u64 namespace = BPF_CORE_READ((struct task_struct *)bpf_get_current_task_btf(),
                                   nsproxy, mnt_ns, ns.inum);
    __u64 device = BPF_CORE_READ(root.dentry, d_sb, s_dev);
    __u64 inode = BPF_CORE_READ(root.dentry, d_inode, i_ino);
    __u64 mount_id = BPF_CORE_READ(lookup_mount(root.mnt), mnt_id);
    if (!namespace || !inode || !mount_id)
        return 0;
    if (proof->scope.mount_namespace &&
        (proof->scope.mount_namespace != namespace || proof->scope.root_device != device ||
         proof->scope.root_inode != inode || proof->scope.root_mount != mount_id)) {
        lookup_partial(proof, AP_LOOKUP_LOGICAL, AP_LOOKUP_RENAMED);
        return 0;
    }
    proof->scope.mount_namespace = namespace;
    proof->scope.root_device = device;
    proof->scope.root_inode = inode;
    proof->scope.root_mount = mount_id;
    __u32 offset = 4095;
    int length = 0;
    AP_FOR(index, 2048) {
        if (path.mnt == root.mnt && path.dentry == root.dentry) {
            if (offset == 4095)
                work->reverse_path[--offset] = '/';
            length = 4095 - offset;
            break;
        }
        struct dentry *mount_root = BPF_CORE_READ(path.mnt, mnt_root);
        if (path.dentry == mount_root) {
            struct mount *current = lookup_mount(path.mnt);
            struct mount *parent = BPF_CORE_READ(current, mnt_parent);
            struct dentry *point = BPF_CORE_READ(current, mnt_mountpoint);
            if (!parent || parent == current || !point)
                break;
            path.dentry = point;
            path.mnt = &parent->mnt;
            continue;
        }
        struct dentry *parent = BPF_CORE_READ(path.dentry, d_parent);
        const unsigned char *name = BPF_CORE_READ(path.dentry, d_name.name);
        __u32 size = BPF_CORE_READ(path.dentry, d_name.len);
        if (!parent || parent == path.dentry || !name || !size || size >= offset)
            break;
        offset -= size;
        barrier_var(offset);
        if (offset >= 4096 || size > 4095 ||
            bpf_probe_read_kernel(&work->reverse_path[offset], size, name))
            break;
        offset--;
        barrier_var(offset);
        if (offset >= 4096)
            break;
        work->reverse_path[offset] = '/';
        path.dentry = parent;
    }
    physical_read_barrier(work);
    if (physical_rename_sequence(&rename_after) || lookup_mount_sequence(&mount_after) ||
        rename_before != rename_after || mount_before != mount_after)
        return 0;
    barrier_var(length);
    if (length <= 0 || length >= 4096 || offset >= 4096 ||
        bpf_probe_read_kernel(work->path.bytes, length, &work->reverse_path[offset]))
        return 0;
    return length;
}
