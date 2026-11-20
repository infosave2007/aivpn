#pragma once

/* Этот ключ принадлежит уже занятому scratch текущего evaluation. */
static __always_inline const struct bs_value *
bs_origin_lookup(const struct ap_policy_view *view, const struct ap_context *context,
                 __u64 kind, __u64 owner, __u64 a, __u64 b, __u64 c) {
    struct working_buffer *work = (void *)((char *)context - offsetof(struct working_buffer, context));
    struct bs_key *key = &work->lookup_key;
    *key = (struct bs_key){kind, owner, {a, b, c}};
    return bpf_map_lookup_elem(view->binding, key);
}

static __always_inline void bs_add_markers(__u64 bits[4], const struct bs_value *value) {
    if (value) {
#ifdef __clang__
#pragma clang loop unroll(full)
#endif
        for (unsigned word = 0; word < 4; word++)
            bits[word] |= value->words[word];
    }
}

/* Неизменяемый source проверяется по текущему снимку политики. */
static __always_inline int bs_source_markers(const struct ap_policy_view *view,
                                              const struct ap_lookup_proof *proof,
                                              const struct ap_context *context, __u64 bits[4]) {
    const struct bs_value *meta = bs_origin_lookup(view, context, BS_SOURCE_META, view->owner, 0, 0, 0);
    if (!meta)
        return 0;
    if (meta->words[0] != AP_LOOKUP_VERSION || meta->words[5] != AP_LOOKUP_LIMIT ||
        meta->words[6] != AP_LOOKUP_COMPLETE || meta->words[7] || !proof ||
        proof->facts.version != AP_LOOKUP_VERSION || !proof->facts.operation || !proof->facts.inode_address ||
        !proof->facts.count || proof->facts.count > AP_LOOKUP_LIMIT)
        return 1;
    int logical = proof->facts.scope.mount_namespace == meta->words[1] && proof->facts.scope.root_device == meta->words[2] &&
                  proof->facts.scope.root_inode == meta->words[3] && proof->facts.scope.root_mount == meta->words[4];
    int partial = !(proof->facts.complete & AP_LOOKUP_PHYSICAL) ||
                  (logical && !(proof->facts.complete & AP_LOOKUP_LOGICAL));
    AP_FOR(index, (int)AP_LOOKUP_LIMIT) {
        if ((unsigned)index >= proof->facts.count)
            break;
        const struct ap_lookup_observation *entry = &proof->entries[index];
        if (entry->flags & AP_LOOKUP_PHYSICAL)
            bs_add_markers(bits, bs_origin_lookup(view, context, BS_SOURCE_PHYSICAL, view->owner,
                                                  entry->physical.low, entry->physical.high,
                                                  entry->physical_device));
        int entry_logical = logical;
        if ((entry->flags & (AP_LOOKUP_LOGICAL | AP_LOOKUP_COMPOSED)) ==
            (AP_LOOKUP_LOGICAL | AP_LOOKUP_COMPOSED)) {
            const struct lookup_prefix_value *prefix =
                lookup_prefix_find(proof->facts.operation, index, AP_LOOKUP_LOGICAL);
            if (!prefix) {
                partial = 1;
                entry_logical = 0;
            } else {
                entry_logical = prefix->scope.mount_namespace == meta->words[1] &&
                    prefix->scope.root_device == meta->words[2] &&
                    prefix->scope.root_inode == meta->words[3] && prefix->scope.root_mount == meta->words[4];
            }
        }
        if (entry_logical && (entry->flags & AP_LOOKUP_LOGICAL))
            bs_add_markers(bits, bs_origin_lookup(view, context, BS_SOURCE_LOGICAL, view->owner,
                                                  entry->logical.low, entry->logical.high,
                                                  entry->logical_scope));
    }
    return partial;
}

static __always_inline int bs_negative(const struct ap_policy_view *view, const struct ap_context *context,
                                       unsigned depth, __u32 group, const __u64 bits[4], int partial) {
    AP_FOR(index, AP_RULE_LIMIT) {
        if ((unsigned)index >= view->policy->count)
            break;
        const struct bs_value *value = bs_origin_lookup(view, context, BS_RULE, view->owner, index, 0, 0);
        if (!value || value->words[7])
            return 1;
        const struct ap_rule *rule = (const struct ap_rule *)value;
        if ((depth && !rule->inherit) || !ap_network(rule, context))
            continue;
        /* Нижнее отрицательное правило не отменяет уже решающее верхнее. */
        if (!rule->selector)
            return 0;
        const struct bs_value *member = group && rule->selector == 1 && rule->application
            ? bs_origin_lookup(view, context, BS_MEMBERSHIP, view->owner, rule->application, group, 0) : 0;
        if (member && member->words[0] == 1)
            return 0;
        unsigned word = (unsigned)index / 64;
        if (word >= 4 || (rule->selector == 1 &&
            (partial || (bits[word] & (1ULL << ((unsigned)index % 64))))))
            return 1;
    }
    return 0;
}
static __noinline void bs_fill_origin(struct ap_origin *origin, const struct origin_hash *source,
                                       const struct ap_policy_view *view,
                                       const struct ap_context *context, unsigned depth) {
    origin->owner_kind = 1;
    origin->owner = source->uid;
    origin->package = 0;
    origin->application = 0;
    origin->resolved = source->path_flags == AP_PATH_COMPLETE;
    const struct bs_value *file = source->file_cookie
        ? bs_origin_lookup(view, context, BS_FILE, 0, source->file_cookie, 0, 0) : 0;
    if (file && file->words[0] && file->words[0] <= 0xffffffffULL)
        origin->application = file->words[0];
    struct working_buffer *work = (void *)((char *)context - offsetof(struct working_buffer, context));
    __u64 *bits = work->source_markers;
    __builtin_memset(bits, 0, sizeof(work->source_markers));
    if (source->path_flags & AP_PATH_PHYSICAL)
        bs_add_markers(bits, bs_origin_lookup(view, context, BS_PHYSICAL, view->owner, source->path.low,
                                              source->path.high, source->filesystem_device));
    if (source->path_flags & AP_PATH_LOGICAL)
        bs_add_markers(bits, bs_origin_lookup(view, context, BS_LOGICAL, view->owner, source->logical_path.low,
                                              source->logical_path.high, AP_LOGICAL_SCOPE));
    if (bs_negative(view, context, depth, origin->application, bits, 0)) {
        origin->application = 0;
        origin->resolved = 0;
    }
}
/* Сбор source markers и выбор правила используют последовательные stack frames. */
static __noinline int bs_collect_source(const struct ap_lookup_proof *proof,
                                         const struct ap_policy_view *view,
                                         const struct ap_context *context) {
    struct working_buffer *work = (void *)((char *)context - offsetof(struct working_buffer, context));
    __builtin_memset(work->source_markers, 0, sizeof(work->source_markers));
    return bs_source_markers(view, proof, context, work->source_markers);
}
static __noinline void bs_fill_source(struct ap_origin *origin, const struct ap_policy_view *view,
                                       const struct ap_context *context, unsigned depth, int partial) {
    struct working_buffer *work = (void *)((char *)context - offsetof(struct working_buffer, context));
    if (bs_negative(view, context, depth, origin->application, work->source_markers, partial)) {
        origin->application = 0;
        origin->resolved = 0;
    }
}
