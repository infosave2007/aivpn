#pragma once

static __always_inline int ar_retire(const struct flow_key *key, __u64 epoch, __u64 id);
#define SS_RETIRE_FLOW(key, epoch, id) ar_retire(key, epoch, id)
#include "socket-state.h"
#include "cache-state.h"

#ifndef AR_CACHE_LIMIT
#define AR_CACHE_LIMIT 65536
#endif
struct ar_record {
    struct ss_record flow;
    __u64 epoch;
};
struct ar_resolution_work {
#ifndef AP_BINDING_SNAPSHOT
    struct process_companion companion;
#endif
    struct ss_request lookup;
    struct cached_route proposed;
    __u32 incoming, retry_rejected, proposal_ready, publish;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, AR_CACHE_LIMIT);
    __type(key, struct flow_key);
    __type(value, struct cc_entry);
} routing_overrides SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, AR_CACHE_LIMIT);
    __type(key, struct flow_key);
    __type(value, struct cc_entry);
} routing_system SEC(".maps");

static __always_inline int ar_retire(const struct flow_key *key, __u64 epoch, __u64 id) {
    int protected = cc_retire(&routing_overrides, key, epoch, id);
    int system = cc_retire(&routing_system, key, epoch, id);
    return protected || system ? -1 : 0;
}

#ifndef AP_BINDING_SNAPSHOT
static __always_inline struct ap_policy *ar_policy(__u32 uid) {
    __u64 owner = 3ULL << 32;
    struct ap_policy *policy = bpf_map_lookup_elem(&policies, &owner);
    if (policy)
        return policy;
    owner = (1ULL << 32) | uid;
    return bpf_map_lookup_elem(&policies, &owner);
}

#endif

static __noinline int ar_has_policy(__u32 uid) {
#ifdef AP_BINDING_SNAPSHOT
    struct ap_policy_view view = {0};
    return bs_begin(&view, uid) != 0;
#else
    return ar_policy(uid) != 0;
#endif
}
static __always_inline int ar_choose(const struct process_state *state,
                                     const struct process_companion *companion, const struct flow_key *key,
                                     struct cached_route *out) {
#ifdef AP_BINDING_SNAPSHOT
    if (!companion) {
        struct ap_policy_view view = {0};
        int selected = bs_begin(&view, state->self.source.uid);
        if (selected)
            return -1;
        out->decision.rule = AP_NO_RULE;
        dns_socket_choice(state, key, out);
        return 0;
    }
    int result = choose_snapshot_policy(state, companion, key, out);
#else
    int result = choose_flow_policy(state, companion, key, ar_policy(state->self.source.uid), out);
#endif
    if (!result) dns_socket_choice(state, key, out);
    return result;
}

static __always_inline __u64 ar_generation(const struct cached_route *route, __u32 family) {
    if (route->decision.action != 2 || !route->decision.profile)
        return 0;
    struct profile *profile = bpf_map_lookup_elem(&profiles, &route->decision.profile);
    return profile && (family == 4 ? profile->ready4 : profile->ready6) ? profile->generation : 0;
}

#ifdef AP_BINDING_SNAPSHOT
#define AR_DESIRED_INLINE __always_inline
#else
#define AR_DESIRED_INLINE __noinline
#endif
static AR_DESIRED_INLINE int ar_desired(struct ss_state *state, const struct flow_key *key,
                                 struct cached_route *out, const struct process_companion *companion) {
    if (state->kind == SS_PRESERVED) {
        out->decision.rule = AP_NO_RULE;
        return 0;
    }
    if (state->kind != SS_CLASSIFIED)
        return -1;
    if (ar_choose(&state->creator, companion, key, out))
        return -1;
    out->network_generation = ar_generation(out, key->family);
    return 0;
}

/* Привязка выполняется только к прочитанному id, а не к следующему UDP-интервалу. */
static __noinline int ar_bind(struct ss_state *state, struct ss_table *table,
                              const struct flow_key *key, struct ss_request *request,
                              struct ss_record *record) {
    __u32 set_device = request->set_device;
    for (unsigned attempt = 0; attempt < 2; attempt++) {
        request->expected_id = record->id;
        request->set_device = set_device && record->route.decision.action == 0;
        request->network_generation =
            record->route.decision.action == 2 && !record->route.network_generation
                ? ar_generation(&record->route, key->family)
                : 0;
        if (!request->network_generation && !request->set_device && !request->parent_id)
            return 0;
        if (ss_lookup(state, table, key, request, record) != 1)
            return -1;
        if (record->id == request->expected_id)
            return 0;
    }
    return -1;
}

static __always_inline int ar_pending(const struct cached_route *route) {
    return route->decision.action == 1 ||
           (route->decision.action == 2 && !route->network_generation);
}

#ifdef AP_BINDING_SNAPSHOT
static __noinline int ar_update_flow(struct ss_flow *flow, struct ss_lifetime *token,
                                           struct ss_request *request, struct ss_record *record) {
    request->expected_id = record->id;
    request->now = SS_NOW();
    request->new_id = ss_reserve_id(token, flow->key.cookie, flow->epoch);
    if (!request->new_id || ss_update_node(flow, request, &record->route) != 1) return -1;
    return ss_flow_read(flow, record, 0) == 1 ? 0 : -1;
}
static __noinline int ar_bind_flow(struct ss_flow *flow, struct ss_lifetime *token,
                                         struct ss_request *request, struct ss_record *record) {
    __u32 set_device = request->set_device;
    for (unsigned attempt = 0; attempt < 2; attempt++) {
        request->set_device = set_device && record->route.decision.action == 0;
        request->network_generation = record->route.decision.action == 2 && !record->route.network_generation
            ? ar_generation(&record->route, flow->key.family) : 0;
        if (!request->network_generation && !request->set_device && !request->parent_id) return 0;
        if (ar_update_flow(flow, token, request, record)) return -1;
        if (record->id == request->expected_id) return 0;
    }
    return -1;
}
struct ss_flow;
static __noinline int ar_publish_flow(struct ss_state *state, const struct flow_key *key,
                                      const struct ar_record *record,
                                      const struct process_companion *companion, struct ss_flow *flow);
/* Один owned payload остается authority через resolve и publish, без повторного поиска. */
static __always_inline int ar_snapshot_resolve(struct ss_state *state, const struct flow_key *key,
                                          struct ss_request *request, struct ar_record *out,
                                          struct ar_resolution_work *work,
                                          const struct process_companion *companion) {
    struct ss_table *table = ss_table_acquire(state);
    if (!table) return -1;
    struct ss_lifetime *token = ss_lifetime_acquire(state, key->cookie, table->epoch);
    struct ss_flow *flow = 0;
    int error = 1, proposed = work->proposal_ready;
    if (!token) goto done;
    out->epoch = table->epoch;
    ss_clear_request(&work->lookup);
    struct cc_entry *cached = bpf_map_lookup_elem(&routing_overrides, key);
    if (cached) flow = cc_acquire_admitted_flow(cached, key, token);
    if (!flow) {
        cached = bpf_map_lookup_elem(&routing_system, key);
        if (cached) flow = cc_acquire_admitted_flow(cached, key, token);
    }
    if (flow) {
        int current = ss_flow_read(flow, &out->flow, 1);
        if (current == 1 && out->flow.admitted) goto cached_ready;
        bpf_obj_drop_impl(flow, 0);
        flow = 0;
    }
    struct ss_node *wrapper = ss_wrapper_acquire(table, key);
    if (wrapper) {
        flow = ss_payload_acquire(wrapper);
        bpf_obj_drop_impl(wrapper, 0);
        if (!flow) goto done;
    } else {
        if (!proposed) {
            __builtin_memset(&work->proposed, 0, sizeof(work->proposed));
            if (ar_desired(state, key, &work->proposed, companion)) goto done;
            proposed = 1;
        }
        if (ar_pending(&work->proposed) || (work->incoming && work->proposed.decision.action != 0)) {
            ss_copy_route(&out->flow.route, &work->proposed);
            out->flow.id = 0;
            out->flow.admitted = 0;
            error = 0;
            goto done;
        }
        ss_collect(state, table, table->count >= SS_FLOW_LIMIT);
        if (ss_freeze(token, table, key, &work->proposed, &out->flow)) goto done;
        flow = ss_find_acquire(table, key);
        if (!flow) goto done;
    }
    if (flow->epoch != table->epoch) goto done;
    ss_clear_request(&work->lookup);
    int found = ss_flow_read(flow, &out->flow, 1);
    if (found < 0) goto done;
    if (found == 1 && ss_logical_admitted(state, &out->flow)) out->flow.admitted = 1;
    if (found != 1 || !out->flow.admitted) {
        if (!proposed) {
            __builtin_memset(&work->proposed, 0, sizeof(work->proposed));
            if (ar_desired(state, key, &work->proposed, companion)) goto done;
        }
        found = ss_flow_read(flow, &out->flow, 1);
        if (found < 0) goto done;
        if (found == 1 && !out->flow.admitted &&
            (!route_choice_equal(&out->flow.route, &work->proposed) ||
             out->flow.route.network_generation != work->proposed.network_generation)) {
            sa_retire(&flow->publication, out->flow.id << 2);
            found = ss_flow_read(flow, &out->flow, 1);
            if (found < 0) goto done;
        }
        if (found == 2) {
            if (ar_pending(&work->proposed) || (work->incoming && work->proposed.decision.action != 0)) {
                ss_copy_route(&out->flow.route, &work->proposed);
                out->flow.id = 0;
                out->flow.admitted = 0;
            } else {
                work->lookup.renew = 1;
                ss_copy_route(&out->flow.route, &work->proposed);
                if (ar_update_flow(flow, token, &work->lookup, &out->flow)) goto done;
            }
        }
    }
cached_ready:
    if (out->flow.id && ar_bind_flow(flow, token, request, &out->flow)) goto done;
    if (ss_logical_admitted(state, &out->flow)) out->flow.admitted = 1;
    error = !token->alive;
    if (!error && work->publish && out->flow.id)
        error = ar_publish_flow(state, key, out, companion, flow);
done:
    if (flow) bpf_obj_drop_impl(flow, 0);
    if (token) bpf_obj_drop_impl(token, 0);
    bpf_obj_drop_impl(table, 0);
    return error ? -1 : 0;
}
#endif

/* Источник решения принадлежит сокету. Кеш публикуется отдельным вызовом. */
static __always_inline int ar_resolve(struct ss_state *state, const struct flow_key *key,
                                 struct ss_request *request, struct ar_record *out,
                                 struct ar_resolution_work *work,
                                 const struct process_companion *companion) {
    if (!state || state->cookie != key->cookie ||
        (state->kind != SS_CLASSIFIED && state->kind != SS_PRESERVED))
        return -1;
#ifdef AP_BINDING_SNAPSHOT
    return ar_snapshot_resolve(state, key, request, out, work, companion);
#else
    (void)companion;
    if (key->protocol == 17) {
        const struct cached_route *desired = 0;
        if ((work->retry_rejected & 2) && cc_prepared(&routing_overrides, key)) {
            __builtin_memset(&work->proposed, 0, sizeof(work->proposed));
            if (ar_desired(state, key, &work->proposed, &work->companion))
                return -1;
            desired = &work->proposed;
        }
        if (cc_recover_rejected(&routing_overrides, key, state, work->retry_rejected, desired) < 0)
            return -1;
    }
    struct ss_table *table = ss_table_acquire(state);
    if (!table)
        return -1;
    out->epoch = table->epoch;
    ss_clear_request(&work->lookup);
    int found = ss_lookup(state, table, key, &work->lookup, &out->flow);
    int error = found < 0;
    if (!found || found == 2) {
        __builtin_memset(&work->proposed, 0, sizeof(work->proposed));
        if (ar_desired(state, key, &work->proposed, &work->companion))
            error = 1;
        else {
            if (found == 2 && ar_retire(key, table->epoch, out->flow.id))
                error = 1;
            if (!error && (ar_pending(&work->proposed) ||
                           (work->incoming && work->proposed.decision.action != 0))) {
                /* Отказ еще не создал соединение и не закрепляет следующее решение. */
                ss_copy_route(&out->flow.route, &work->proposed);
                out->flow.id = 0;
            } else if (!error && found == 2) {
                work->lookup.renew = 1;
                work->lookup.expected_id = out->flow.id;
                ss_copy_route(&out->flow.route, &work->proposed);
                if (ss_lookup(state, table, key, &work->lookup, &out->flow) != 1)
                    error = 1;
            } else if (!error) {
                ss_collect(state, table, table->count >= SS_FLOW_LIMIT);
                if (ss_freeze_for(state, table, key, &work->proposed, &out->flow))
                    error = 1;
            }
        }
    }
    if (!error && out->flow.id && ar_bind(state, table, key, request, &out->flow))
        error = 1;
    bpf_obj_drop_impl(table, 0);
    return error ? -1 : 0;
#endif
}

#ifndef AR_BEFORE_PUBLISH
#define AR_BEFORE_PUBLISH(state, key, record) ((void)(state), (void)(key), (void)(record))
#endif
#ifdef AP_BINDING_SNAPSHOT
/* map_update не копирует владение kptr. Сначала создается пустая запись. */
static const __u64 ar_empty_companion[sizeof(struct process_companion) / sizeof(__u64)] = {0};
static const __u64 ar_empty_subject[sizeof(struct process_state) / sizeof(__u64)] = {0};
static __always_inline int ar_remember_creator(const struct ss_state *state, __u64 cookie,
                                               const struct process_companion *companion) {
    if (!process_pair_valid(&state->creator, companion))
        return -1;
    int inserted = !bpf_map_update_elem(&routing_companions, &cookie, ar_empty_companion,
                                        BPF_NOEXIST);
    struct process_companion *mate = bpf_map_lookup_elem(&routing_companions, &cookie);
    if (!mate)
        return -1;
    if (inserted)
        copy_process_companion(mate, companion);
    if (mate->snapshot_identity != companion->snapshot_identity)
        return -1;
    inserted = !bpf_map_update_elem(&routing_subjects, &cookie, ar_empty_subject, BPF_NOEXIST);
    struct process_state *subject = bpf_map_lookup_elem(&routing_subjects, &cookie);
    if (!subject)
        return -1;
    if (inserted)
        copy_process_state(subject, &state->creator);
    return process_pair_valid(subject, mate) &&
           subject->snapshot_identity == state->creator.snapshot_identity ? 0 : -1;
}
#endif
struct ss_flow;
#ifdef AP_BINDING_SNAPSHOT
static __noinline int ar_publish_flow(struct ss_state *state, const struct flow_key *key,
                                 const struct ar_record *record,
                                 const struct process_companion *companion, struct ss_flow *flow) {
#else
static __noinline int ar_publish(struct ss_state *state, const struct flow_key *key,
                                 const struct ar_record *record,
                                 const struct process_companion *companion) {
#endif
    if (!record->flow.id)
        return 0;
    AR_BEFORE_PUBLISH(state, key, record);
#ifdef AP_BINDING_SNAPSHOT
    if (!flow || ss_install_tcp(state, flow, key, &record->flow)) return -1;
#endif
    if (record->flow.route.decision.action == 2) {
        if (key->protocol == 17
#ifdef AP_BINDING_SNAPSHOT
            || key->protocol == 6
#endif
        ) {
            if (state->kind != SS_CLASSIFIED)
                return -1;
#ifdef AP_BINDING_SNAPSHOT
            if (ar_remember_creator(state, key->cookie, companion))
                return -1;
#else
            int inserted = !bpf_map_update_elem(&routing_companions, &key->cookie, companion, BPF_NOEXIST);
            const struct process_companion *mate = bpf_map_lookup_elem(&routing_companions, &key->cookie);
            if (!mate || mate->snapshot_identity != companion->snapshot_identity)
                goto subject_failed;
            if (bpf_map_update_elem(&routing_subjects, &key->cookie, &state->creator,
                                    BPF_NOEXIST) &&
                !bpf_map_lookup_elem(&routing_subjects, &key->cookie)) {
              subject_failed:
                if (inserted)
                    bpf_map_delete_elem(&routing_companions, &key->cookie);
                return -1;
            }
            const struct process_state *subject = bpf_map_lookup_elem(&routing_subjects, &key->cookie);
            if (!subject || subject->snapshot_identity != state->creator.snapshot_identity)
                return -1;
#endif
        }
        if (record->flow.route.decision.action == 2)
            return
#ifdef AP_BINDING_SNAPSHOT
                cc_store_plain(&routing_overrides, key, state, flow, &record->flow);
#else
                cc_store(&routing_overrides, key, state, &record->flow, record->epoch);
#endif
    }
    if (!
#ifdef AP_BINDING_SNAPSHOT
        cc_store_plain(&routing_system, key, state, flow, &record->flow)
#else
        cc_store(&routing_system, key, state, &record->flow, record->epoch)
#endif
    )
        return 0;
#ifdef AP_BINDING_SNAPSHOT
    return -1;
#else
    return key->protocol == 17
               ? ss_prepare(state, key, &record->flow.route, record->epoch, record->flow.id)
               : 0;
#endif
}

#ifdef AP_BINDING_SNAPSHOT
static __noinline int ar_publish(struct ss_state *state, const struct flow_key *key,
                                 const struct ar_record *record, const struct process_companion *companion) {
    if (!record->flow.id) return 0;
    struct ss_table *table = ss_table_acquire(state);
    if (!table) return -1;
    struct ss_flow *flow = table->epoch == record->epoch ? ss_find_acquire(table, key) : 0;
    bpf_obj_drop_impl(table, 0);
    if (!flow) return -1;
    int result = ar_publish_flow(state, key, record, companion, flow);
    bpf_obj_drop_impl(flow, 0);
    return result;
}
#endif

#ifdef AP_BINDING_SNAPSHOT
static __always_inline int ar_admit(const struct flow_key *key, struct ar_record *record,
                                    struct ss_request *request) {
    if (!record->flow.id) return 0;
    void *map = record->flow.route.decision.action == 2 ? (void *)&routing_overrides
                                                      : (void *)&routing_system;
    struct cc_entry *entry = bpf_map_lookup_elem(map, key);
    ss_clear_request(request);
    request->no_touch = 1;
    request->confirm = 3;
    request->expected_id = record->flow.id;
    request->expected_epoch = record->epoch;
    if (!entry || cc_proof(entry, key, request, &record->flow, 0) != 1 || !record->flow.admitted)
        return 0;
    cc_sync_proof(entry, key, &record->flow, record->epoch);
    return 1;
}
#endif

/* Ранний socket filter только читает снимок, не создает решение. */
static __noinline int ar_read(const struct flow_key *key, struct cc_snapshot *out) {
    struct cc_entry *entry = bpf_map_lookup_elem(&routing_overrides, key);
    int protected = entry ? cc_read(entry, out) : 0;
#ifdef AP_BINDING_SNAPSHOT
    int invalid_protected = entry && !protected;
#else
    if (entry && !protected)
        return -1;
#endif
    if (protected && key->protocol == 17 && out->admission >= 2)
        return -1;
  protected
    = protected && out->alive && out->cookie == key->cookie;
    struct cc_snapshot system = {};
    entry = bpf_map_lookup_elem(&routing_system, key);
    int ordinary = entry && cc_read(entry, &system) && system.alive && system.cookie == key->cookie;
    if (ordinary && protected && system.epoch == out->epoch && system.id == out->id &&
        !route_choice_equal(&system.route, &out->route))
        return -1;
    if (ordinary && (!protected || system.epoch > out->epoch ||
                     (system.epoch == out->epoch && system.id > out->id))) {
        *out = system;
        return 1;
    }
#ifdef AP_BINDING_SNAPSHOT
    /* Terminal ref не закрывает новую подлинную authority после GC/rotation. */
    return protected ? 1 : invalid_protected ? -1 : 0;
#else
    return protected ? 1 : 0;
#endif
}

static __always_inline __u64 ar_result(const struct cached_route *route, __u32 family) {
    if (route->decision.action != 2)
        return route->decision.action == 0 ? 0 : 1;
    __u64 current = ar_generation(route, family);
    if (!current || current != route->network_generation)
        return 1;
    return (__u64)route->decision.profile + 2;
}

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cache_reap_request);
} cache_reap_requests SEC(".maps");
SEC("socket") int reap_routing_cache(struct __sk_buff *packet) {
    (void)packet;
    __u32 zero = 0;
    struct cache_reap_request *request = bpf_map_lookup_elem(&cache_reap_requests, &zero);
    if (!request)
        return 0;
    if (request->system)
        return cc_reap(&routing_system, &request->key, request->cookie, request->epoch);
    return cc_reap(&routing_overrides, &request->key, request->cookie, request->epoch);
}
