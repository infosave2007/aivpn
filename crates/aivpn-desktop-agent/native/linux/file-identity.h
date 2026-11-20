#pragma once

struct seqcount {
    unsigned sequence;
} __attribute__((preserve_access_index));
struct seqcount_spinlock {
    struct seqcount seqcount;
} __attribute__((preserve_access_index));
struct seqlock {
    struct seqcount_spinlock seqcount;
} __attribute__((preserve_access_index));
struct qstr {
    __u32 len;
    const unsigned char *name;
} __attribute__((preserve_access_index));
struct super_block {
    __u32 s_dev;
    struct dentry *s_root;
} __attribute__((preserve_access_index));
struct dentry {
    struct dentry *d_parent;
    struct qstr d_name;
    struct super_block *d_sb;
    struct inode *d_inode;
    unsigned int d_flags;
} __attribute__((preserve_access_index));

/* У символа нет BTF VAR на части ядер. Смещение поля всегда задает CO-RE. */
extern const void rename_lock __ksym;

static __always_inline int physical_rename_sequence(__u32 *sequence) {
    const struct seqlock *lock = (const struct seqlock *)&rename_lock;
    return bpf_core_read(sequence, sizeof(*sequence), &lock->seqcount.seqcount.sequence);
}

static __always_inline void physical_read_barrier(struct working_buffer *work) {
    /* Полный барьер на собственной памяти, в том числе для ARM64 JIT. */
    __sync_val_compare_and_swap(&work->busy, 1, 1);
}

__noinline int physical_dentry_path(__u64 address,
                                   struct working_buffer *work __arg_nonnull,
                                   __u64 *device __arg_nonnull) {
    __u32 before = 0, after = 0, offset = 4095, dev = 0;
    int length = 0;
    struct dentry *cursor = (void *)(unsigned long)address, *root = 0;
    struct super_block *super = 0;
    if (physical_rename_sequence(&before) || (before & 1))
        goto done;
    physical_read_barrier(work);
    if (!cursor || bpf_core_read(&super, sizeof(super), &cursor->d_sb) || !super ||
        bpf_core_read(&root, sizeof(root), &super->s_root) || !root ||
        bpf_core_read(&dev, sizeof(dev), &super->s_dev))
        goto done;
    /* Даже путь из односимвольных компонентов помещается в 2048 шагов. */
    AP_FOR(index, 2048) {
        if (cursor == root) {
            if (offset == 4095) {
                offset--;
                work->reverse_path[offset] = '/';
            }
            length = 4095 - offset;
            break;
        }
        struct dentry *parent = 0;
        const unsigned char *name = 0;
        __u32 size = 0;
        if (bpf_core_read(&parent, sizeof(parent), &cursor->d_parent) || !parent ||
            parent == cursor || bpf_core_read(&name, sizeof(name), &cursor->d_name.name) || !name)
            break;
        /* Публикация нового d_name.name требует acquire перед чтением байтов. */
        physical_read_barrier(work);
        if (bpf_core_read(&size, sizeof(size), &cursor->d_name.len) || !size || size >= offset)
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
        cursor = parent;
    }
    physical_read_barrier(work);
    if (physical_rename_sequence(&after) || before != after)
        length = 0;
    barrier_var(length);
    if (length > 0 && length < 4096 && offset < 4096) {
        if (bpf_probe_read_kernel(work->path.bytes, length, &work->reverse_path[offset]))
            length = 0;
        else
            *device = dev;
    }
done:
    return length;
}

static __always_inline int physical_file_path(struct file *file,
                                               struct working_buffer *work, __u64 *device) {
    struct dentry *cursor = 0;
    bpf_rcu_read_lock();
    int length = bpf_core_read(&cursor, sizeof(cursor), &file->f_path.dentry) ? 0 :
        physical_dentry_path((unsigned long)cursor, work, device);
    bpf_rcu_read_unlock();
    return length;
}
