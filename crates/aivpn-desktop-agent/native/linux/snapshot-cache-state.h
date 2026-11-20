#pragma once
#include "snapshot-cache-read.h"

static __noinline int cc_proof(struct cc_entry *entry, const struct flow_key *key,
                               const struct ss_request *request, struct ss_record *out, int logical) {
    bpf_rcu_read_lock();
    int result = -1;
    __u64 version = route_version_read(&entry->sequence);
    if (version & 1) goto done;
    struct ss_lifetime *token = logical ? entry->logical_lifetime : entry->lifetime;
    struct ss_flow *node = logical ? entry->logical_node : entry->node;
    __u64 epoch = entry->epoch;
    struct ss_lifetime *child = entry->lifetime;
    struct ss_flow *child_flow = entry->node;
    int retired = entry->retired;
    if (retired || epoch != request->expected_epoch ||
        !child || !child->alive || child->epoch != epoch ||
        !token || !node || !token->alive ||
        token->cookie != key->cookie ||
        node->epoch != token->epoch || (!logical && token->epoch != epoch) ||
        ss_key_order(&node->key, key)) goto done;
    if (logical && (!child_flow || child_flow->parent_cookie != token->cookie ||
        child_flow->parent_epoch != token->epoch || (child_flow->parent_id != request->expected_id && request->confirm == 3))) goto done;
    __u64 word = sa_read(&node->publication);
    if (!sa_stable(word)) { result = 2; goto done; }
    struct cached_route expected = {};
    if (request->confirm == 3) ss_copy_route(&expected, &out->route);
    ss_copy_route(&out->route, &node->route);
    out->id = word >> 2;
    out->parent_id = node->parent_id;
    out->parent_epoch = node->parent_epoch;
    out->parent_cookie = node->parent_cookie;
    out->source_port = node->source_port;
    __builtin_memcpy(out->system_source, node->system_source, 16);
    if (word != sa_read(&node->publication) || version != route_version_read(&entry->sequence)) goto done;
    if (request->confirm == 3) {
        if (out->id != request->expected_id || !route_choice_equal(&expected, &out->route) ||
            expected.network_generation != out->route.network_generation ||
            expected.system_device != out->route.system_device ||
            !sa_admit(&node->publication, word)) goto done;
        word |= SA_ADMITTED;
    }
    if (!token->alive || !child->alive) goto done;
    out->admitted = (word & 3) == SA_ADMITTED;
    if (out->admitted) ss_touch(node, SS_NOW());
    if (token->alive && child->alive && word == sa_read(&node->publication) &&
        version == route_version_read(&entry->sequence)) result = 1;
done:
    bpf_rcu_read_unlock();
    return result;
}

static __noinline int cc_sync_proof(struct cc_entry *entry, const struct flow_key *key,
                                    const struct ss_record *record, __u64 epoch) {
    __u64 version = route_version_read(&entry->sequence);
    __u64 admission = __sync_fetch_and_add(&entry->admission, 0);
    /* Подтвержденный снимок не требует новой публикации на каждом пакете. */
    if (!(version & 1) && !entry->retired && entry->cookie == key->cookie &&
        entry->epoch == epoch && entry->id == record->id &&
        (admission >> 2) == record->id && (admission & 3) < SA_RETIRED &&
        (!record->admitted || (admission & 3) == SA_ADMITTED) &&
        route_choice_equal(&entry->route, &record->route) &&
        entry->route.network_generation == record->route.network_generation &&
        entry->route.system_device == record->route.system_device &&
        version == route_version_read(&entry->sequence)) return 0;
    if (__sync_val_compare_and_swap(&entry->lock, 0, 1)) return -1;
    int result = -1;
    if (!entry->retired && entry->cookie == key->cookie && entry->epoch == epoch &&
        entry->id <= record->id && !route_version_begin(&entry->sequence)) {
        ss_copy_route(&entry->route, &record->route);
        entry->id = record->id;
        __u64 admitted = record->admitted ||
            ((entry->admission >> 2) == record->id && (entry->admission & 3) == SA_ADMITTED);
        __sync_lock_test_and_set(&entry->admission, (record->id << 2) | admitted);
        route_version_end(&entry->sequence);
        result = 0;
    }
    __sync_lock_test_and_set(&entry->lock, 0);
    return result;
}

static __noinline int cc_unchanged(struct cc_entry *entry, const struct flow_key *key,
                                   const struct ss_record *record, __u64 epoch) {
    struct cc_snapshot saved = {};
    return entry->id == record->id && route_choice_equal(&entry->route, &record->route) &&
           entry->route.system_device == record->route.system_device &&
           cc_read(entry, &saved) && saved.alive && saved.cookie == key->cookie &&
           saved.epoch == epoch && saved.id == record->id && saved.admission < 2 &&
           route_choice_equal(&saved.route, &record->route) &&
           saved.route.network_generation == record->route.network_generation &&
           saved.route.system_device == record->route.system_device;
}

static __always_inline struct cc_entry *cc_find_or_insert(void *map, const struct flow_key *key,
                                                          int *held) {
    struct cc_entry *entry = bpf_map_lookup_elem(map, key);
    *held = 0;
    if (entry)
        return entry;
    static const __u64 empty[sizeof(struct cc_entry) / sizeof(__u64)] = {1};
    if (!bpf_map_update_elem(map, key, empty, BPF_NOEXIST))
        *held = 1;
    return bpf_map_lookup_elem(map, key);
}

static __always_inline int cc_reap(void *map, const struct flow_key *key, __u64 cookie,
                                   __u64 epoch) {
    struct cc_entry *entry = bpf_map_lookup_elem(map, key);
    if (!entry)
        return 0;
    if (__sync_val_compare_and_swap(&entry->lock, 0, 1))
        return 3;
    struct ss_lifetime *token = entry->lifetime;
    if (entry->cookie != cookie || entry->epoch != epoch || (token && token->alive)) {
        __sync_lock_test_and_set(&entry->lock, 0);
        return 0;
    }
    route_version_retire(&entry->sequence);
    entry->retired = 1;
    __sync_lock_test_and_set(&entry->admission, 3);
    if (!bpf_map_delete_elem(map, key))
        return 1;
    __sync_lock_test_and_set(&entry->lock, 0);
    return 2;
}

static __always_inline int cc_retire(void *map, const struct flow_key *key, __u64 epoch, __u64 id) {
    struct cc_entry *entry = bpf_map_lookup_elem(map, key);
    if (!entry)
        return 0;
    if (__sync_val_compare_and_swap(&entry->lock, 0, 1))
        return -1;
    if (entry->cookie != key->cookie || entry->epoch > epoch ||
        (entry->epoch == epoch && entry->id > id)) {
        __sync_lock_test_and_set(&entry->lock, 0);
        return 0;
    }
    route_version_retire(&entry->sequence);
    entry->retired = 1;
    __sync_lock_test_and_set(&entry->admission, 3);
    if (!bpf_map_delete_elem(map, key))
        return 0;
    __sync_lock_test_and_set(&entry->lock, 0);
    return -1;
}

static __always_inline int cc_packet_admission(struct cc_entry *entry, __u64 expected,
                                               int accepted) {
    __u64 previous = __sync_fetch_and_add(&entry->admission, 0);
    if ((previous >> 2) != (expected >> 2))
        return 0;
    if (!accepted) {
        if (previous && !(previous & 3))
            __sync_val_compare_and_swap(&entry->admission, previous, previous | 2);
        return 0;
    }
    for (unsigned attempt = 0; attempt < 3; attempt++) {
        if ((previous & 3) == 1)
            return 1;
        if (!previous || (previous & 3) == 3)
            return 0;
        __u64 admitted = (previous & ~3ULL) | 1;
        __u64 found = __sync_val_compare_and_swap(&entry->admission, previous, admitted);
        if (found == previous || found == admitted)
            return 1;
        if ((found >> 2) != (previous >> 2))
            return 0;
        previous = found;
    }
    return 0;
}

static __always_inline int cc_prepared(void *map, const struct flow_key *key) {
    struct cc_entry *entry = bpf_map_lookup_elem(map, key);
    if (!entry)
        return 0;
    __u64 tag = __sync_fetch_and_add(&entry->admission, 0);
    return tag && !(tag & 3);
}

/* Этот publisher принимает только plain refs; весь error path допустим в tracing. */
static __noinline int cc_publish_plain(struct cc_entry *entry, struct ss_state *state,
                                        struct ss_flow *flow, const struct ss_record *record,
                                        __u64 epoch) {
    struct ss_lifetime *token = state->lifetime;
    token = token ? bpf_refcount_acquire_impl(token, 0) : 0;
    struct ss_flow *owned = bpf_refcount_acquire_impl(flow, 0);
    struct ss_flow *parent = state->logical_node;
    struct ss_lifetime *parent_token = state->logical_lifetime;
    parent = parent ? bpf_refcount_acquire_impl(parent, 0) : 0;
    parent_token = parent_token ? bpf_refcount_acquire_impl(parent_token, 0) : 0;
    int result = -1;
    __u64 word = sa_read(&flow->publication);
    if (!token || !owned || !token->alive || token->cookie != flow->key.cookie ||
        token->epoch != epoch || flow->epoch != epoch || !sa_stable(word) ||
        (word >> 2) != record->id || !route_choice_equal(&flow->route, &record->route) ||
        word != sa_read(&flow->publication)) goto done;
    if (record->parent_id && (!parent || !parent_token || !parent_token->alive ||
        parent->key.cookie != record->parent_cookie || parent_token->cookie != record->parent_cookie ||
        parent->epoch != record->parent_epoch || parent_token->epoch != record->parent_epoch)) goto done;
    if (entry->retired || (entry->cookie && (entry->cookie != state->cookie || entry->epoch > epoch ||
        (entry->epoch == epoch && entry->id > record->id)))) goto done;
    if (route_version_begin(&entry->sequence)) goto done;
    __sync_lock_test_and_set(&entry->admission, SA_UPDATING);
    ss_copy_route(&entry->route, &record->route);
    entry->cookie = state->cookie;
    entry->kind = state->kind;
    entry->epoch = epoch;
    entry->id = record->id;
    ss_copy_key(&entry->logical_key, &state->logical_key);
    owned = bpf_kptr_xchg(&entry->node, owned);
    token = bpf_kptr_xchg(&entry->lifetime, token);
    if (parent) {
        /* Сохраняем проверенную nonnull ветвь для verifier, не сливаем с NULL transfer. */
        asm volatile("" : "+r"(parent));
        parent = bpf_kptr_xchg(&entry->logical_node, parent);
    }
    else parent = bpf_kptr_xchg(&entry->logical_node, 0);
    if (parent_token) {
        asm volatile("" : "+r"(parent_token));
        parent_token = bpf_kptr_xchg(&entry->logical_lifetime, parent_token);
    }
    else parent_token = bpf_kptr_xchg(&entry->logical_lifetime, 0);
    __sync_lock_test_and_set(&entry->admission, (record->id << 2) | !!record->admitted);
    route_version_end(&entry->sequence);
    result = 0;
done:
    if (owned) bpf_obj_drop_impl(owned, 0);
    if (token) bpf_obj_drop_impl(token, 0);
    if (parent) bpf_obj_drop_impl(parent, 0);
    if (parent_token) bpf_obj_drop_impl(parent_token, 0);
    return result;
}
static __always_inline int cc_store_plain(void *map, const struct flow_key *key, struct ss_state *state,
                                           struct ss_flow *flow, const struct ss_record *record) {
    if (key->cookie != state->cookie || ss_key_order(key, &flow->key)) return -1;
    int held;
    struct cc_entry *entry = cc_find_or_insert(map, key, &held);
    if (!entry) return -1;
    if (!held && cc_unchanged(entry, key, record, flow->epoch)) return 0;
    if (!held && __sync_val_compare_and_swap(&entry->lock, 0, 1)) return -1;
    int result = cc_publish_plain(entry, state, flow, record, flow->epoch);
    if (result && !entry->cookie && !entry->lifetime) {
        route_version_retire(&entry->sequence);
        entry->retired = 1;
        if (!bpf_map_delete_elem(map, key)) return -1;
    }
    __sync_lock_test_and_set(&entry->lock, 0);
    return result;
}
static __always_inline int cc_store(void *map, const struct flow_key *key, struct ss_state *state,
                                    const struct ss_record *record, __u64 epoch) {
    struct ss_table *table = ss_table_acquire(state);
    if (!table) return -1;
    struct ss_flow *flow = table->epoch == epoch ? ss_find_acquire(table, key) : 0;
    bpf_obj_drop_impl(table, 0);
    if (!flow) return -1;
    int result = cc_store_plain(map, key, state, flow, record);
    bpf_obj_drop_impl(flow, 0);
    return result;
}

static __always_inline int cc_read_attempt(struct cc_entry *entry, __u64 expected,
                                           struct cc_snapshot *out) {
    return entry && expected && cc_read(entry, out) && out->alive &&
           out->id == (expected >> 2) && out->admission < 2;
}
