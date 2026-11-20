#pragma once
#include "lookup-store.h"
#include "lookup-path.h"
#include "lookup-fd.h"

static __always_inline int lookup_error(const void *pointer) {
    return !pointer || (unsigned long)pointer >= (unsigned long)-4095;
}

/* Имя читается целиком, до первого NUL. Усеченное имя доказательством не служит. */
static __noinline int lookup_read_name(struct working_buffer *work, const char *name) {
    if (lookup_error(name))
        return -1;
    long length = bpf_probe_read_kernel_str(work->path.bytes, sizeof(work->path.bytes), name);
    if (length <= 0 || length > 4096)
        return -1;
    if (length == 4096) {
        char last = 1;
        if (bpf_probe_read_kernel(&last, sizeof(last), name + 4095) || last)
            return -1;
    }
    return (int)length - 1;
}

#include "lookup-cwd.h"

static __always_inline int lookup_same_hash(const struct ph_hash *a, const struct ph_hash *b) {
    return a->low == b->low && a->high == b->high;
}

static __always_inline void lookup_save_name(struct lookup_operation *operation, const char *name,
                                             struct working_buffer *work, const struct ph_hash *key) {
    int length = lookup_read_name(work, name);
    if (key && length >= 0) {
        operation->filename_length = length;
        operation->filename = (struct ph_hash){0};
        hash_resolved_path(&work->path, length, key, &operation->filename);
        operation->flags |= AP_LOOKUP_NAME_VALID;
    }
}

/* Source cwd удерживается до path_init, пока ядро еще не выбрало начальный path. */
static __noinline void lookup_bind_walk(struct lookup_capture *capture, struct nameidata *nd,
                                          unsigned mode) {
    struct lookup_operation *operation = lookup_top(capture);
    if (!operation || operation->kind == AP_LOOKUP_SKIP)
        return;
    struct working_buffer *work = scratch_acquire();
    if (!work) {
        lookup_partial(&operation->proof, AP_LOOKUP_COMPLETE, AP_LOOKUP_UNREADABLE);
        return;
    }
    __u32 zero = 0;
    const struct ph_hash *key = bpf_map_lookup_elem(&path_key, &zero);
    const char *name = BPF_CORE_READ(nd, name, name);
    if (operation->kind == AP_LOOKUP_FILE)
        lookup_save_name(operation, name, work, key);
    int length = lookup_read_name(work, name);
    struct ph_hash hash = {0};
    if (!(operation->flags & AP_LOOKUP_NAME_VALID) || !key || length < 0 ||
        operation->filename_length != (unsigned)length)
        goto done;
    hash_resolved_path(&work->path, length, key, &hash);
    if (!lookup_same_hash(&hash, &operation->filename))
        goto done;
    __u64 output = operation->kind == AP_LOOKUP_DIRECTORY ? operation->file : 0;
    lookup_restart_walk(operation);
    operation->file = output;
    operation->walk = (unsigned long)nd;
    operation->expected_fd = BPF_CORE_READ(nd, dfd);
    if (BPF_CORE_READ(nd, state) & 1) {
        lookup_partial(&operation->proof, AP_LOOKUP_COMPLETE, AP_LOOKUP_UNREADABLE);
        goto done;
    }
    if (length && work->path.bytes[0] == '/' && !(mode & (1U << 28)))
        goto done;
    if (operation->expected_fd != -100) {
        operation->fd_state = 1;
        goto done;
    }
    operation->flags |= AP_LOOKUP_USE_CWD;
    struct fs_struct *fs = BPF_CORE_READ((struct task_struct *)bpf_get_current_task_btf(), fs);
    __u64 dentry = (unsigned long)BPF_CORE_READ(fs, pwd.dentry);
    __u64 mount = (unsigned long)BPF_CORE_READ(fs, pwd.mnt);
    __u32 sequence = 0;
    __u64 nonce = 0;
    operation->base_lookup = lookup_fs_acquire(fs, dentry, mount, &sequence, &nonce);
    operation->base_fs = (unsigned long)fs;
    operation->base_sequence = sequence;
    operation->base_nonce = nonce;
    operation->fd_state = operation->base_lookup ? 3 : 4;
done:
    scratch_release(work);
}

static __always_inline void lookup_missing_scratch(struct lookup_capture *capture,
                                                    struct nameidata *nd) {
    struct lookup_operation *operation = lookup_top(capture);
    if (operation && operation->walk == (unsigned long)nd)
        lookup_partial(&operation->proof, AP_LOOKUP_COMPLETE, AP_LOOKUP_UNREADABLE);
}

static __noinline int lookup_tail(struct working_buffer *work, const char *name,
                                   const struct lookup_continuation *expected, unsigned used) {
    int length = lookup_read_name(work, name);
    if (length < 0 || used >= 4096 || (unsigned)length + used + (used != 0) >= 4096)
        return -1;
    if (expected) {
        __u32 zero = 0;
        const struct ph_hash *key = bpf_map_lookup_elem(&path_key, &zero);
        struct ph_hash hash = {0};
        if (!key || expected->length != (unsigned)length)
            return -1;
        hash_resolved_path(&work->path, length, key, &hash);
        if (!lookup_same_hash(&hash, &expected->hash))
            return -1;
    }
    if (used && length)
        work->lookup_suffix[used++] = '/';
    AP_FOR(index, 4096) {
        if (index >= length)
            break;
        unsigned destination = used + (unsigned)index;
        if (destination >= 4095)
            return -1;
        work->lookup_suffix[destination] = work->path.bytes[index];
    }
    return used + length;
}

/* Убираются только пустые компоненты и точка. Dotdot не сворачивается. */
static __noinline int lookup_normalize(struct working_buffer *work, unsigned length,
                                        struct ap_lookup_facts *proof) {
    if (length >= 4096)
        return -1;
    if (!length)
        return 0;
    /* Счетчики в занятом scratch не заставляют verifier перебирать все длины. */
    work->lookup_output = work->lookup_component = 0;
    AP_FOR(index, 4096) {
        if ((unsigned)index >= length)
            break;
        unsigned output = work->lookup_output, component = work->lookup_component;
        if (output >= 4095 || component > output)
            return -1;
        char byte = work->lookup_suffix[index];
        if (byte != '/') {
            work->lookup_suffix[output] = byte;
            work->lookup_output = output + 1;
            continue;
        }
        unsigned size = output - component;
        if (size == 1 && work->lookup_suffix[component] == '.')
            output = component;
        else if (size == 2 && component < 4094 && work->lookup_suffix[component] == '.' &&
                 work->lookup_suffix[component + 1] == '.')
            lookup_partial(proof, AP_LOOKUP_COMPLETE, AP_LOOKUP_DOTDOT);
        if (output && work->lookup_suffix[output - 1] != '/')
            work->lookup_suffix[output++] = '/';
        work->lookup_output = work->lookup_component = output;
    }
    unsigned output = work->lookup_output, component = work->lookup_component;
    if (output >= 4096 || component > output || component >= 4096)
        return -1;
    unsigned size = output - component;
    if (size == 1 && work->lookup_suffix[component] == '.')
        output = component;
    else if (size == 2 && component < 4095 && work->lookup_suffix[component] == '.' &&
             work->lookup_suffix[component + 1] == '.')
        lookup_partial(proof, AP_LOOKUP_COMPLETE, AP_LOOKUP_DOTDOT);
    if (output && work->lookup_suffix[output - 1] == '/')
        output--;
    return (int)output;
}

static __noinline int lookup_suffix(struct nameidata *nd, const char *name,
                                     struct lookup_operation *operation,
                                     struct working_buffer *work) {
    int length = lookup_tail(work, name, 0, 0);
    unsigned depth = BPF_CORE_READ(nd, depth);
    struct saved *stack = BPF_CORE_READ(nd, stack);
    if (length < 0 || depth > AP_LOOKUP_LINK_LIMIT || (depth && !stack))
        return -1;
    /* Сначала ближайшее продолжение, затем внешние уровни. */
    AP_FOR(offset, (int)AP_LOOKUP_LINK_LIMIT) {
        if ((unsigned)offset >= depth)
            break;
        unsigned index = depth - (unsigned)offset - 1;
        if (index >= AP_LOOKUP_LINK_LIMIT)
            return -1;
        const struct lookup_continuation *expected = &operation->continuations[index];
        if (!expected->flags)
            continue;
        const char *continuation = 0;
        struct saved *entry = (void *)((char *)stack + index * bpf_core_type_size(struct saved));
        if (bpf_core_read(&continuation, sizeof(continuation), &entry->name))
            return -1;
        length = lookup_tail(work, continuation, expected, length);
        if (length < 0)
            return -1;
    }
    return lookup_normalize(work, length, &operation->proof);
}

__noinline int lookup_hash_prefix(struct path_buffer *path __arg_nonnull, unsigned length,
                                    const struct ph_hash *key __arg_nonnull,
                                    struct ap_lookup_candidate *out __arg_nonnull) {
    if (!length || length >= 4096)
        return -1;
    ph_stream_init(&out->prefix, key->low, key->high);
    if (ph_stream_write(&out->prefix, (const __u8 *)path->bytes, length))
        return -1;
    out->hash = ph_stream_digest(&out->prefix);
    return 0;
}

static __noinline int lookup_join(struct working_buffer *work, unsigned parent, unsigned suffix,
                                   const struct ph_hash *key, struct ap_lookup_candidate *out) {
    if (!parent || parent >= 4096 || suffix >= 4096)
        return -1;
    if (parent > 1 && suffix)
        work->path.bytes[parent++] = '/';
    if (parent + suffix >= 4096)
        return -1;
    AP_FOR(index, 4096) {
        if ((unsigned)index >= suffix)
            break;
        unsigned destination = parent + (unsigned)index;
        if (destination >= 4095)
            return -1;
        work->path.bytes[destination] = work->lookup_suffix[index];
    }
    return lookup_hash_prefix(&work->path, parent + suffix, key, out);
}

static __noinline int lookup_extend_prefix(struct ap_lookup_candidate *out,
                                             const struct lookup_prefix_value *base,
                                             struct working_buffer *work, unsigned suffix) {
    out->prefix = base->prefix;
    if (!out->prefix.length || out->prefix.length >= 4096 || suffix >= 4096)
        return -1;
    const __u8 slash = '/';
    if (suffix && out->prefix.length > 1 && ph_stream_write(&out->prefix, &slash, 1))
        return -1;
    if (ph_stream_write(&out->prefix, (const __u8 *)work->lookup_suffix, suffix))
        return -1;
    out->hash = ph_stream_digest(&out->prefix);
    return 0;
}

/* Directory source продолжается один раз исходным suffix, до раскрытия новых ссылок. */
static __noinline void lookup_merge_base(struct lookup_capture *capture, struct nameidata *nd,
                                           struct lookup_operation *operation,
                                           struct working_buffer *work, unsigned suffix) {
    if (!operation->fd_state || (operation->flags & AP_LOOKUP_BASE_MERGED))
        return;
    operation->flags |= AP_LOOKUP_BASE_MERGED;
    const struct ap_lookup_proof *base = lookup_find(operation->base_lookup);
    if (operation->fd_state != 3 || !base || !base->facts.count || base->facts.count > AP_LOOKUP_LIMIT) {
        lookup_partial(&operation->proof, AP_LOOKUP_COMPLETE, AP_LOOKUP_UNREADABLE);
        return;
    }
    if (operation->flags & AP_LOOKUP_USE_CWD) {
        work->base_guard = (struct lookup_fs_work){.proof = operation->base_lookup,
            .fs = operation->base_fs, .nonce = operation->base_nonce,
            .sequence = operation->base_sequence,
            .dentry = (unsigned long)BPF_CORE_READ(nd, path.dentry),
            .mount = (unsigned long)BPF_CORE_READ(nd, path.mnt)};
        struct fs_struct *fs = BPF_CORE_READ((struct task_struct *)bpf_get_current_task_btf(), fs);
        if ((unsigned long)fs != operation->base_fs || !lookup_fs_unchanged(&work->base_guard)) {
            lookup_partial(&operation->proof, AP_LOOKUP_COMPLETE, AP_LOOKUP_UNREADABLE);
            return;
        }
    }
    operation->proof.complete &= base->facts.complete;
    operation->proof.reasons |= base->facts.reasons;
    AP_FOR(index, (int)AP_LOOKUP_LIMIT) {
        if ((unsigned)index >= base->facts.count)
            break;
        const struct ap_lookup_observation *source = &base->entries[index];
        struct ap_lookup_observation entry = {.physical_device = source->physical_device,
            .logical_scope = source->logical_scope, .flags = AP_LOOKUP_COMPOSED};
        struct ap_lookup_scope scope = {0};
        if (source->flags & AP_LOOKUP_PHYSICAL) {
            const struct lookup_prefix_value *prefix =
                lookup_prefix_find(operation->base_lookup, index, AP_LOOKUP_PHYSICAL);
            if (prefix && !lookup_extend_prefix(&work->prefix_physical, prefix, work, suffix)) {
                entry.physical = work->prefix_physical.hash;
                entry.flags |= AP_LOOKUP_PHYSICAL;
            } else
                lookup_partial(&operation->proof, AP_LOOKUP_PHYSICAL, AP_LOOKUP_PREFIX_MISSING);
        }
        if (source->flags & AP_LOOKUP_LOGICAL) {
            const struct lookup_prefix_value *prefix =
                lookup_prefix_find(operation->base_lookup, index, AP_LOOKUP_LOGICAL);
            if (prefix && !lookup_extend_prefix(&work->prefix_logical, prefix, work, suffix)) {
                entry.logical = work->prefix_logical.hash;
                entry.flags |= AP_LOOKUP_LOGICAL;
                scope = prefix->scope;
            } else
                lookup_partial(&operation->proof, AP_LOOKUP_LOGICAL, AP_LOOKUP_PREFIX_MISSING);
        }
        lookup_stage_append(capture, operation, &entry, work, &scope);
    }
}

/* ND и его указатели используются только внутри текущего синхронного hook. */
static __always_inline void lookup_observe(struct nameidata *nd, const char *name) {
    struct lookup_capture *capture = lookup_current(0);
    struct working_buffer *work = scratch_acquire();
    if (!capture || !work) {
        if (capture && !work)
            lookup_missing_scratch(capture, nd);
        if (work)
            scratch_release(work);
        return;
    }
    bpf_rcu_read_lock();
    struct lookup_operation *operation = lookup_top(capture);
    struct ap_lookup_facts *proof = operation ? &operation->proof : 0;
    if (!proof || operation->kind == AP_LOOKUP_SKIP || operation->walk != (unsigned long)nd)
        goto done;
    if (++operation->observations > 1024) {
        lookup_partial(proof, AP_LOOKUP_COMPLETE, AP_LOOKUP_OVERFLOW);
        goto done;
    }
    int suffix = lookup_suffix(nd, name, operation, work);
    __u32 zero = 0;
    const struct ph_hash *key = bpf_map_lookup_elem(&path_key, &zero);
    if (suffix < 0 || !key) {
        lookup_partial(proof, AP_LOOKUP_COMPLETE, AP_LOOKUP_UNREADABLE);
        goto done;
    }
    if (operation->filename_length)
        lookup_merge_base(capture, nd, operation, work, suffix);
    struct ap_lookup_observation observation = {
        .flags = operation->link_count ? AP_LOOKUP_EXPANSION : AP_LOOKUP_ORIGINAL,
        .logical_scope = AP_LOGICAL_SCOPE,
    };
    struct dentry *parent = BPF_CORE_READ(nd, path.dentry);
    if (BPF_CORE_READ(parent, d_flags) & 1)
        lookup_partial(proof, AP_LOOKUP_COMPLETE, AP_LOOKUP_UNREADABLE);
    int length = physical_dentry_path((unsigned long)parent, work, &observation.physical_device);
    if (length > 0 && !lookup_join(work, length, suffix, key, &work->prefix_physical)) {
        observation.physical = work->prefix_physical.hash;
        observation.flags |= AP_LOOKUP_PHYSICAL;
    } else
        lookup_partial(proof, AP_LOOKUP_PHYSICAL, AP_LOOKUP_UNREADABLE);
    length = lookup_logical_parent(operation->walk, work, proof);
    if (length > 0 && !lookup_join(work, length, suffix, key, &work->prefix_logical)) {
        observation.logical = work->prefix_logical.hash;
        observation.flags |= AP_LOOKUP_LOGICAL;
    } else
        lookup_partial(proof, AP_LOOKUP_LOGICAL, AP_LOOKUP_UNREADABLE);
    lookup_stage_append(capture, operation, &observation, work, &proof->scope);
done:
    bpf_rcu_read_unlock();
    scratch_release(work);
}

SEC("fentry/do_open_execat")
int BPF_PROG(lookup_exec_open, int fd, struct filename *filename, int flags) {
    (void)ctx; (void)flags;
    struct lookup_capture *capture = lookup_current(1);
    if (!capture)
        return 0;
    lookup_clear_ready(capture);
    struct lookup_operation *operation = lookup_push(capture, AP_LOOKUP_EXEC, fd, 0);
    if (!operation)
        return 0;
    struct working_buffer *work = scratch_acquire();
    __u32 zero = 0;
    const struct ph_hash *key = bpf_map_lookup_elem(&path_key, &zero);
    const char *name = BPF_CORE_READ(filename, name);
    if (work)
        lookup_save_name(operation, name, work, key);
    if (work)
        scratch_release(work);
    return 0;
}

SEC("fentry/path_openat")
int BPF_PROG(lookup_walk_begin, struct nameidata *nd, const struct open_flags *flags, unsigned mode) {
    (void)ctx;
    int executable = !!(BPF_CORE_READ(flags, open_flag) & (1 << 5));
    int eligible = executable || owner_needs_capture((__u32)bpf_get_current_uid_gid());
    struct lookup_capture *capture = lookup_current(!executable && eligible);
    if (!capture)
        return 0;
    if (!executable) {
        struct lookup_operation *opened = lookup_push(capture,
            eligible ? AP_LOOKUP_FILE : AP_LOOKUP_SKIP, BPF_CORE_READ(nd, dfd), 0);
        if (!opened)
            return 0;
        opened->walk = (unsigned long)nd;
        if (!eligible)
            return 0;
    } else if (capture->overflow) {
        return 0;
    }
    lookup_bind_walk(capture, nd, mode);
    return 0;
}

SEC("fentry/filename_lookup")
int BPF_PROG(lookup_directory_begin, int fd, struct filename *filename, unsigned flags,
             struct path *path, const struct path *root) {
    (void)ctx; (void)root;
    int eligible = (flags & 2) && owner_needs_capture((__u32)bpf_get_current_uid_gid());
    struct lookup_capture *capture = lookup_current(eligible);
    if (!capture)
        return 0;
    struct lookup_operation *operation = lookup_push(capture,
        eligible ? AP_LOOKUP_DIRECTORY : AP_LOOKUP_SKIP, fd, (unsigned long)path);
    if (!operation || !eligible)
        return 0;
    struct working_buffer *work = scratch_acquire();
    if (work) {
        __u32 zero = 0;
        const struct ph_hash *key = bpf_map_lookup_elem(&path_key, &zero);
        lookup_save_name(operation, BPF_CORE_READ(filename, name), work, key);
        scratch_release(work);
    }
    return 0;
}

SEC("fentry/path_lookupat")
int BPF_PROG(lookup_directory_walk, struct nameidata *nd, unsigned flags, struct path *path) {
    (void)ctx;
    struct lookup_capture *capture = lookup_current(0);
    struct lookup_operation *operation = lookup_top(capture);
    if (operation && ((operation->kind == AP_LOOKUP_DIRECTORY && operation->file == (unsigned long)path) ||
                      (operation->kind == AP_LOOKUP_FILE && operation->walk == (unsigned long)nd)))
        lookup_bind_walk(capture, nd, flags);
    return 0;
}

SEC("fexit/filename_lookup")
int BPF_PROG(lookup_directory_end, int fd, struct filename *filename, unsigned flags,
             struct path *path, const struct path *root, int result) {
    (void)ctx; (void)fd; (void)filename; (void)flags; (void)root;
    struct lookup_capture *capture = lookup_current(0);
    if (!capture)
        return 0;
    if (capture->overflow) {
        capture->overflow--;
        return 0;
    }
    struct lookup_operation *operation = lookup_top(capture);
    if (operation && operation->kind == AP_LOOKUP_DIRECTORY && !result &&
        operation->file == (unsigned long)path) {
        operation->proof.inode_address = (unsigned long)BPF_CORE_READ(path, dentry, d_inode);
        __u64 id = operation->proof.inode_address ? lookup_freeze(capture, operation) : 0;
        if (id)
            lookup_directory_ready(capture, (unsigned long)path, id);
    }
    if (capture->depth) {
        if (operation)
            lookup_clear_operation(operation);
        capture->depth--;
        lookup_stage_clear(capture->depth);
    }
    return 0;
}

/* Magic link без удержанного source не может доказать отсутствие выбранного alias. */
SEC("fentry/nd_jump_link")
int BPF_PROG(lookup_magic_link, const struct path *path) {
    (void)ctx; (void)path;
    struct lookup_capture *capture = lookup_current(0);
    struct nameidata *nd = BPF_CORE_READ((struct task_struct *)bpf_get_current_task_btf(), nameidata);
    lookup_missing_scratch(capture, nd);
    return 0;
}

SEC("fentry/link_path_walk")
int BPF_PROG(lookup_walk_segment, const char *name, struct nameidata *nd) {
    (void)ctx;
    lookup_observe(nd, name);
    return 0;
}

SEC("fentry/lookup_fast")
int BPF_PROG(lookup_fast_component, struct nameidata *nd) {
    (void)ctx;
    lookup_observe(nd, (const char *)BPF_CORE_READ(nd, last.name));
    return 0;
}

SEC("fentry/lookup_open")
int BPF_PROG(lookup_open_component, struct nameidata *nd, struct file *file,
             const struct open_flags *flags) {
    (void)ctx; (void)file; (void)flags;
    lookup_observe(nd, (const char *)BPF_CORE_READ(nd, last.name));
    return 0;
}

SEC("fentry/pick_link")
int BPF_PROG(lookup_follow_link, struct nameidata *nd, struct path *link,
             struct inode *inode, int flags) {
    (void)ctx; (void)link; (void)inode;
    struct lookup_capture *capture = lookup_current(0);
    struct working_buffer *work = scratch_acquire();
    if (!capture || !work) {
        if (capture && !work)
            lookup_missing_scratch(capture, nd);
        if (work)
            scratch_release(work);
        return 0;
    }
    bpf_rcu_read_lock();
    struct lookup_operation *operation = lookup_top(capture);
    if (!operation || operation->kind == AP_LOOKUP_SKIP || operation->walk != (unsigned long)nd)
        goto done;
    unsigned depth = BPF_CORE_READ(nd, depth);
    if (depth >= AP_LOOKUP_LINK_LIMIT || ++operation->link_count > AP_LOOKUP_LINK_LIMIT) {
        lookup_partial(&operation->proof, AP_LOOKUP_COMPLETE, AP_LOOKUP_OVERFLOW);
        goto done;
    }
    operation->continuations[depth] = (struct lookup_continuation){0};
    if (!(flags & 2))
        goto done;
    const char *name = (const char *)BPF_CORE_READ(nd, last.name);
    unsigned component = BPF_CORE_READ(nd, last.len);
    if (component >= 4096) {
        lookup_partial(&operation->proof, AP_LOOKUP_COMPLETE, AP_LOOKUP_UNREADABLE);
        goto done;
    }
    name += component;
    int found = 0;
    AP_FOR(index, 4096) {
        char byte = 0;
        if (bpf_probe_read_kernel(&byte, 1, name))
            break;
        if (byte != '/') { found = 1; break; }
        name++;
    }
    int length = found ? lookup_read_name(work, name) : -1;
    __u32 zero = 0;
    const struct ph_hash *key = bpf_map_lookup_elem(&path_key, &zero);
    if (!key || length <= 0) {
        lookup_partial(&operation->proof, AP_LOOKUP_COMPLETE, AP_LOOKUP_UNREADABLE);
        goto done;
    }
    hash_resolved_path(&work->path, length, key, &operation->continuations[depth].hash);
    operation->continuations[depth].length = length;
    operation->continuations[depth].flags = 1;
done:
    bpf_rcu_read_unlock();
    scratch_release(work);
    return 0;
}

/* Пустое имя использует доказательство фактически полученного file. */
static __always_inline __u64 lookup_open_proof(struct lookup_capture *capture,
                                               struct lookup_operation *operation,
                                               struct file *file) {
    __u64 inode = (unsigned long)BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;
    if (!operation->filename_length && operation->fd_state) {
        const struct ap_lookup_proof *base = lookup_find(operation->base_lookup);
        return operation->fd_state == 3 && base && base->facts.inode_address == inode
            ? lookup_acquire(operation->base_lookup) : 0;
    }
    if (operation->fd_state && !(operation->flags & AP_LOOKUP_BASE_MERGED))
        lookup_partial(&operation->proof, AP_LOOKUP_COMPLETE, AP_LOOKUP_UNREADABLE);
    operation->proof.inode_address = inode;
    return lookup_freeze(capture, operation);
}

SEC("fexit/path_openat")
int BPF_PROG(lookup_walk_end, struct nameidata *nd, const struct open_flags *flags,
             unsigned mode, struct file *file) {
    (void)ctx; (void)mode;
    struct lookup_capture *capture = lookup_current(0);
    if (!capture)
        return 0;
    bpf_rcu_read_lock();
    if (capture->overflow) {
        if (!(BPF_CORE_READ(flags, open_flag) & (1 << 5)))
            capture->overflow--;
        goto done;
    }
    struct lookup_operation *operation = lookup_top(capture);
    if (operation && operation->walk == (unsigned long)nd) {
        int executable = operation->kind == AP_LOOKUP_EXEC;
        if (operation->kind == AP_LOOKUP_SKIP) {
            operation->walk = 0;
            lookup_clear_operation(operation);
            if (capture->depth) {
                capture->depth--;
                lookup_stage_clear(capture->depth);
            }
            goto done;
        }
        if (executable)
            lookup_clear_ready(capture);
        __u64 id = !lookup_error(file) ? lookup_open_proof(capture, operation, file) : 0;
        if (id && lookup_publish_file(file, id)) {
            lookup_release(id);
            id = 0;
        }
        operation->walk = 0;
        operation->file = (unsigned long)file;
        operation->file_seen = id != 0;
        if (executable) {
            capture->ready = lookup_acquire(id);
            capture->ready_valid = 0;
            capture->ready_operation = operation->token;
            capture->ready_file = (unsigned long)file;
        }
        lookup_clear_base(operation);
        if (!executable && capture->depth) {
            lookup_clear_operation(operation);
            capture->depth--;
            lookup_stage_clear(capture->depth);
        }
    }
done:
    bpf_rcu_read_unlock();
    return 0;
}

SEC("fexit/do_open_execat")
int BPF_PROG(lookup_exec_opened, int fd, struct filename *filename, int flags, struct file *file) {
    (void)ctx; (void)fd; (void)filename; (void)flags;
    struct lookup_capture *capture = lookup_current(0);
    if (!capture)
        return 0;
    if (capture->overflow) {
        capture->overflow--;
        return 0;
    }
    struct lookup_operation *operation = lookup_top(capture);
    capture->ready_valid = operation && !lookup_error(file) && operation->file_seen &&
        operation->file == (unsigned long)file && capture->ready_operation == operation->token &&
        capture->ready_file == (unsigned long)file;
    if (!capture->ready_valid)
        lookup_clear_ready(capture);
    if (capture->depth) {
        if (operation)
            lookup_clear_operation(operation);
        capture->depth--;
        lookup_stage_clear(capture->depth);
    }
    return 0;
}

static __always_inline void lookup_take_source(struct pending_exec *pending, struct file *file) {
    struct lookup_capture *capture = lookup_current(0);
    if (!capture) return;
    int valid = capture->ready_valid;
    capture->ready_valid = 0;
    __u64 id = __sync_lock_test_and_set(&capture->ready, 0);
    struct ap_lookup_proof *proof = lookup_find(id);
    __u64 inode = (unsigned long)BPF_CORE_READ(file, f_inode);
    __u64 cookie = pending->source.file_cookie;
    int bound = 0;
    if (valid && proof && inode && cookie && proof->facts.inode_address == inode) {
        __u64 previous = __sync_val_compare_and_swap(&proof->bound_cookie, 0, cookie);
        bound = !previous || previous == cookie;
    }
    if (id && !bound) {
        lookup_release(id);
        id = 0;
    }
    __u64 old = __sync_lock_test_and_set(&pending->lookup, id);
    lookup_release(old);
}

SEC("lsm/file_free_security")
int BPF_PROG(lookup_file_free, struct file *file) {
    (void)ctx;
    __u64 key = (unsigned long)file;
    __u64 *stored = bpf_map_lookup_elem(&lookup_files, &key);
    if (stored) {
        __u64 id = *stored;
        bpf_map_delete_elem(&lookup_files, &key);
        lookup_release(id);
    }
    return 0;
}

SEC("fexit/bprm_execve")
int BPF_PROG(lookup_exec_finished, struct linux_binprm *bprm, int ret) {
    (void)ctx; (void)bprm; (void)ret;
    struct task_capture *process = capture_current(0);
    if (process) {
        process->pending.active = 0;
        lookup_pending_clear(&process->pending);
    }
    struct lookup_capture *capture = lookup_current(0);
    if (capture)
        lookup_clear_ready(capture);
    return 0;
}
