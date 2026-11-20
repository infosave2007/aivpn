#pragma once

static __always_inline int same_origin(const struct origin_hash *stored,
                                       const struct origin_hash *candidate) {
    return candidate && stored->task_identity && stored->file_cookie &&
           stored->exec_identity && stored->owner_epoch &&
           stored->task_identity == candidate->task_identity && stored->uid == candidate->uid &&
           stored->file_cookie == candidate->file_cookie &&
           stored->exec_identity == candidate->exec_identity &&
           stored->owner_epoch == candidate->owner_epoch;
}

static __always_inline int same_path_facts(const struct origin_hash *stored,
                                           const struct origin_hash *candidate) {
    if ((stored->path_flags & AP_PATH_PHYSICAL) &&
        (stored->filesystem_device != candidate->filesystem_device ||
         stored->path.low != candidate->path.low || stored->path.high != candidate->path.high))
        return 0;
    if ((stored->path_flags & AP_PATH_LOGICAL) &&
        (stored->logical_path.low != candidate->logical_path.low ||
         stored->logical_path.high != candidate->logical_path.high))
        return 0;
    return 1;
}

static __always_inline const struct process_state *
current_creator(const struct process_state *stored) {
    if (stored->self.image.path_flags == AP_PATH_COMPLETE)
        return 0;
    struct task_capture *capture =
        bpf_task_storage_get(&processes, bpf_get_current_task_btf(), 0, 0);
    if (!capture)
        return 0;
    const struct process_state *candidate = &capture->committed;
    return same_origin(&stored->self.source, &candidate->self.source) &&
           same_origin(&stored->self.image, &candidate->self.image) ? candidate : 0;
}

static __always_inline const struct origin_hash *
available_origin(const struct origin_hash *stored, const struct origin_hash *candidate) {
    if (stored->path_flags != AP_PATH_COMPLETE && same_origin(stored, candidate) &&
        candidate->path_flags == AP_PATH_COMPLETE && same_path_facts(stored, candidate))
        return candidate;
    return stored;
}

/* Выбор правила общий для исходящего пакета и нового входящего запроса. */
#ifdef AP_BINDING_SNAPSHOT
#define AR_FILL_ORIGIN(origin, source, view, context, depth) bs_fill_origin(origin, source, view, context, depth)
#else
#define AR_FILL_ORIGIN(origin, source, view, context, depth) fill_origin(origin, source, (view)->policy, context, depth)
#endif

/* True означает, что следующий origin уже не может изменить этот поиск. */
static __noinline int origin_stops(const struct ap_origin *origin,
                                        const struct ap_policy_view *view,
                                        const struct ap_context *context, unsigned depth) {
    if (depth && !ap_same_owner(origin, &context->process))
        return 1;
    if (!origin->resolved && ap_view_requires_identity(view, context, depth != 0))
        return 1;
    return ap_view_origin_matches(view, context, origin, depth);
}

static __always_inline void fill_frame(struct ap_origin *out, const struct exec_frame *frame,
                                   const struct ap_policy_view *view,
                                   const struct ap_context *context, unsigned depth,
                                   const struct origin_hash *candidate_image) {
#ifdef AP_BINDING_SNAPSHOT
    bs_fill_origin(out, &frame->source, view, context, depth);
    struct ap_lookup_proof *proof = lookup_find(frame->lookup);
    if (proof && proof->bound_cookie != frame->source.file_cookie)
        proof = 0;
    int partial = bs_collect_source(proof, view, context);
    bs_fill_source(out, view, context, depth, partial);
#else
    AR_FILL_ORIGIN(out, &frame->source, view, context, depth);
#endif
    if (!origin_stops(out, view, context, depth))
        AR_FILL_ORIGIN(out, available_origin(&frame->image, candidate_image), view, context, depth);
}

static __noinline int fill_context(const struct process_state *state,
                                    const struct process_companion *companion,
                                    const struct ap_policy_view *view, struct ap_context *context) {
    if (!process_pair_valid(state, companion)) {
        context->process = (struct ap_origin){ .owner_kind = 1, .owner = state->self.source.uid };
        context->parent_count = 0;
        return 0;
    }
#ifdef AP_BINDING_SNAPSHOT
    bpf_rcu_read_lock();
#endif
    const struct process_state *current = current_creator(state);
    fill_frame(&context->process, &state->self, view, context, 0, current ? &current->self.image : 0
               );
    context->parent_count = 0;
    int stopped = origin_stops(&context->process, view, context, 0);
    AP_FOR(index, AP_PARENT_LIMIT) {
        if (stopped || (unsigned)index >= state->parent_count)
            break;
        const struct history_slot *slot = &state->parents[index];
        struct ap_origin *origin = &context->parents[index];
        if (slot->has_carried) {
            if (state->snapshot_identity && companion->snapshot_identity == state->snapshot_identity &&
                (companion->available & (1U << (unsigned)index))) {
                fill_frame(origin, &companion->carried[index], view, context, index + 1, 0
                           );
            } else {
                *origin = (struct ap_origin){ .owner_kind = context->process.owner_kind,
                                             .owner = context->process.owner };
            }
            stopped = origin_stops(origin, view, context, index + 1);
        }
        if (!stopped) {
            fill_frame(origin, &slot->parent, view, context, index + 1, 0
                       );
            stopped = origin_stops(origin, view, context, index + 1);
        }
        context->parent_count = index + 1;
    }
#ifdef AP_BINDING_SNAPSHOT
    bpf_rcu_read_unlock();
#endif
    return !stopped && (state->ancestry_flags & (AP_ANCESTRY_OVERFLOW | AP_ANCESTRY_EXEC_OVERFLOW |
                                                AP_ANCESTRY_OWNER_OVERFLOW));
}

static __noinline void evaluate_context(const struct ap_policy_view *view,
                                        const struct ap_context *context,
                                        struct ap_decision *decision, int unknown_tail) {
    *decision = ap_evaluate_view(view, context);
    /* Дальний хвост нужен только после исчерпания известных origins. */
    if (unknown_tail && ap_view_requires_identity(view, context, 1)) {
        decision->action = 1;
        decision->profile = 0;
        decision->rule = AP_NO_RULE;
        decision->unresolved = 1;
    }
}

#ifdef AP_BINDING_SNAPSHOT
/* Временный ключ метаданных не занимает стек во время обхода origins. */
static __noinline __u64 snapshot_binding_epoch(const struct ap_policy_view *view) {
    const struct bs_value *meta = bs_lookup(view->binding, BS_META, 0, 0, 0, 0);
    return meta ? meta->words[1] : 0;
}
__noinline int choose_snapshot_policy(const struct process_state *state __arg_nonnull,
                                      const struct process_companion *companion __arg_nonnull,
                                      const struct flow_key *key __arg_nonnull,
                                      struct cached_route *out __arg_nonnull) {
    struct ap_policy_view view = {0};
    int selected = bs_begin(&view, state->self.source.uid);
    if (selected < 0) return -1;
    out->binding_epoch = snapshot_binding_epoch(&view);
    if (!out->binding_epoch) return -1;
    if (!selected) { out->decision.rule = AP_NO_RULE; return 0; }
#else
static __noinline int choose_flow_policy(const struct process_state *state,
                                         const struct process_companion *companion,
                                         const struct flow_key *key, const struct ap_policy *policy,
                                         struct cached_route *out) {
    if (!policy) {
        out->decision.rule = AP_NO_RULE;
        return 0;
    }
    if (!state)
        return -1;
    const struct ap_policy_view view = { .policy = policy };
#endif
    struct working_buffer *work = scratch_acquire();
    if (!work)
        return -1;
    struct ap_context *context = &work->context;
#ifdef AP_BINDING_SNAPSHOT
    view.lookup = &work->lookup_key;
#endif
    context->family = key->family;
    __builtin_memcpy(context->destination, key->destination, sizeof(context->destination));
    int unknown_tail = fill_context(state, companion, &view, context);
    evaluate_context(&view, context, &out->decision, unknown_tail);
    scratch_release(work);
    return 0;
}
#undef AR_FILL_ORIGIN
