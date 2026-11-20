#pragma once
#ifdef AP_BINDING_SNAPSHOT
#include "snapshot-cache-state.h"
#else
#pragma once
#include "route-version.h"

struct cc_entry {
    __u32 lock, retired;
    struct cached_route route;
    __u64 cookie, epoch, id;
    struct ss_lifetime __kptr *lifetime;
    __u64 admission, sequence;
    struct ss_table __kptr *table;
    struct ss_node __kptr *node;
    struct ss_table __kptr *logical_table;
    struct ss_node __kptr *logical_node;
    struct ss_lifetime __kptr *logical_lifetime;
    struct flow_key logical_key;
    __u32 kind, reserved;
};
struct cc_snapshot {
    struct cached_route route;
    __u64 cookie, epoch, id;
    __u32 alive, admission;
};

#ifdef AP_BINDING_SNAPSHOT
/* Вызывающий держит CAS кеша. Смена lifetime делает прежние refs недействительными. */
static __noinline int cc_attach_proof(struct cc_entry *entry, struct ss_state *state,
                                       const struct flow_key *key, __u64 epoch) {
    bpf_rcu_read_lock();
    struct ss_table *table = state->table;
    struct ss_node *query = 0;
    table = table ? bpf_refcount_acquire_impl(table, 0) : 0;
    bpf_rcu_read_unlock();
    if (table)
        query = ss_find_acquire(table, key);
    if (!table || !query || table->epoch != epoch || query->epoch != epoch) {
        if (table) bpf_obj_drop_impl(table, 0);
        if (query) bpf_obj_drop_impl(query, 0);
        return -1;
    }
    table = bpf_kptr_xchg(&entry->table, table);
    query = bpf_kptr_xchg(&entry->node, query);
    if (table) bpf_obj_drop_impl(table, 0);
    if (query) bpf_obj_drop_impl(query, 0);
    if (!state->logical_cookie)
        return 0;
    bpf_rcu_read_lock();
    table = state->logical_table;
    query = state->logical_node;
    struct ss_lifetime *lifetime = state->logical_lifetime;
    table = table ? bpf_refcount_acquire_impl(table, 0) : 0;
    query = query ? bpf_refcount_acquire_impl(query, 0) : 0;
    lifetime = lifetime ? bpf_refcount_acquire_impl(lifetime, 0) : 0;
    bpf_rcu_read_unlock();
    if (!table || !query || !lifetime || !lifetime->alive ||
        table->epoch != query->epoch || table->epoch != lifetime->epoch ||
        lifetime->cookie != state->logical_cookie) {
        if (table) bpf_obj_drop_impl(table, 0);
        if (query) bpf_obj_drop_impl(query, 0);
        if (lifetime) bpf_obj_drop_impl(lifetime, 0);
        return -1;
    }
    ss_copy_key(&entry->logical_key, &state->logical_key);
    table = bpf_kptr_xchg(&entry->logical_table, table);
    query = bpf_kptr_xchg(&entry->logical_node, query);
    lifetime = bpf_kptr_xchg(&entry->logical_lifetime, lifetime);
    if (table) bpf_obj_drop_impl(table, 0);
    if (query) bpf_obj_drop_impl(query, 0);
    if (lifetime) bpf_obj_drop_impl(lifetime, 0);
    return 0;
}

/* NF читает только borrowed refs и скаляры, без RB/acquire/drop/spinlock. */
static __noinline int cc_proof(struct cc_entry *entry, const struct flow_key *key,
                               const struct ss_request *request, struct ss_record *out, int logical) {
    if (__sync_val_compare_and_swap(&entry->lock, 0, 1)) return -1;
    struct ss_lifetime *token = logical ? entry->logical_lifetime : entry->lifetime;
    struct ss_table *table = logical ? entry->logical_table : entry->table;
    struct ss_node *node = logical ? entry->logical_node : entry->node;
    __u64 epoch = entry->epoch;
    struct ss_lifetime *child = entry->lifetime;
    struct flow_key exact_key;
    ss_copy_key(&exact_key, key);
    int retired = entry->retired;
    __sync_lock_test_and_set(&entry->lock, 0);
    if (retired || !request->expected_epoch || epoch != request->expected_epoch ||
        !child || !child->alive || child->epoch != epoch ||
        !token || !table || !node || !token->alive ||
        token->cookie != exact_key.cookie || table->epoch != token->epoch ||
        node->epoch != token->epoch || (!logical && token->epoch != epoch) ||
        ss_key_order(&node->key, &exact_key)) return -1;
    __u64 word = sa_read(&node->publication);
    if (!sa_stable(word)) return 2;
    struct cached_route expected = {};
    if (request->confirm == 3) ss_copy_route(&expected, &out->route);
    ss_copy_route(&out->route, &node->route);
    out->id = word >> 2;
    out->parent_id = node->parent_id;
    out->source_port = node->source_port;
    __builtin_memcpy(out->system_source, node->system_source, 16);
    if (word != sa_read(&node->publication)) return -1;
    if (request->confirm == 3) {
        if (out->id != request->expected_id || !route_choice_equal(&expected, &out->route) ||
            expected.network_generation != out->route.network_generation ||
            expected.system_device != out->route.system_device ||
            !sa_admit(&node->publication, word)) return -1;
        word |= SA_ADMITTED;
    }
    if (!token->alive || !child->alive) return -1;
    out->admitted = (word & 3) == SA_ADMITTED;
    if (out->admitted) ss_touch(node, SS_NOW());
    return 1;
}

static __always_inline int cc_parent_admitted(struct ss_node *parent, struct ss_lifetime *token,
                                               __u64 parent_id, const struct cached_route *route) {
    if (!parent || !token || !token->alive || parent->epoch != token->epoch ||
        parent->key.cookie != token->cookie) return 0;
    __u64 word = sa_read(&parent->publication);
    return word == ((parent_id << 2) | SA_ADMITTED) &&
           route_choice_equal(&parent->route, route) &&
           word == sa_read(&parent->publication) && token->alive;
}

/* Hint обновляется после canonical lock и не подтверждает иной token. */
static __noinline int cc_sync_proof(struct cc_entry *entry, const struct flow_key *key,
                                    const struct ss_record *record, __u64 epoch) {
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
#endif

/* held разрешен только создателю новой записи с lock=1. */
static __always_inline int cc_update(void *map, struct cc_entry *entry, const struct flow_key *key,
                                     struct ss_state *state, const struct cached_route *route,
                                     __u64 expected_epoch, __u64 id, int held, int admitted) {
    if (!held && __sync_val_compare_and_swap(&entry->lock, 0, 1))
        return -1;
    if (entry->retired)
        goto reject;
    bpf_rcu_read_lock();
    struct ss_lifetime *borrowed = state->lifetime;
    struct ss_lifetime *token = borrowed ? bpf_refcount_acquire_impl(borrowed, 0) : 0;
    bpf_rcu_read_unlock();
    if (!token)
        goto reject;
    if (!token->alive || token->epoch != expected_epoch || token->cookie != state->cookie)
        goto reject_token;
    if (entry->cookie) {
        if (entry->cookie != state->cookie || entry->epoch > expected_epoch)
            goto reject_token;
        if (entry->epoch == expected_epoch && entry->id > id)
            goto reject_token;
        if (entry->epoch == expected_epoch && entry->id == id &&
            !route_choice_equal(&entry->route, route))
            goto reject_token;
        struct ss_lifetime *previous = entry->lifetime;
        if (entry->epoch != expected_epoch && previous && previous->alive)
            goto reject_token;
    }
    if (ss_prepare(state, key, route, expected_epoch, id))
        goto reject_token;
#ifdef AP_BINDING_SNAPSHOT
    if (cc_attach_proof(entry, state, key, expected_epoch))
        goto reject_token;
#endif
    if (route_version_begin(&entry->sequence))
        goto reject_token;
    int replaced =
        entry->cookie != state->cookie || entry->epoch != expected_epoch || entry->id != id;
    if (replaced)
        __sync_lock_test_and_set(&entry->admission, 3);
    ss_copy_route(&entry->route, route);
    entry->cookie = state->cookie;
    entry->kind = state->kind;
    entry->epoch = expected_epoch;
    entry->id = id;
    struct ss_lifetime *old = bpf_kptr_xchg(&entry->lifetime, token);
    if (old)
        bpf_obj_drop_impl(old, 0);
    if (replaced)
        __sync_lock_test_and_set(
            &entry->admission,
#ifdef AP_BINDING_SNAPSHOT
            (id << 2) | (admitted ? 1 : 0));
#else
            (id << 2) | ((key->protocol == 17 && route->decision.action == 2) ? 0 : 1));
    (void)admitted;
#endif
    route_version_end(&entry->sequence);
    __sync_lock_test_and_set(&entry->lock, 0);
    return 0;

reject_token:
    bpf_obj_drop_impl(token, 0);
reject:
    /* Пустая запись удаляется под тем же CAS до допуска другого писателя. */
    if (!entry->cookie && !entry->lifetime) {
        route_version_retire(&entry->sequence);
        entry->retired = 1;
        __sync_lock_test_and_set(&entry->admission, 3);
        if (!bpf_map_delete_elem(map, key))
            return -1;
    }
    __sync_lock_test_and_set(&entry->lock, 0);
    return -1;
}

/* Читатели не блокируют друг друга и не меняют подтвержденное решение. */
static __noinline int cc_read(struct cc_entry *entry, struct cc_snapshot *out) {
#ifdef AP_BINDING_SNAPSHOT
    if (__sync_val_compare_and_swap(&entry->lock, 0, 1)) return 0;
    struct ss_node *node = entry->node;
    struct ss_lifetime *token = entry->lifetime;
    struct ss_table *table = entry->table;
    out->cookie = entry->cookie;
    out->epoch = entry->epoch;
    struct ss_node *parent = entry->logical_node;
    struct ss_lifetime *parent_token = entry->logical_lifetime;
    int retired = entry->retired;
    __sync_lock_test_and_set(&entry->lock, 0);
    if (retired || !node || !token || !table || !token->alive ||
        token->cookie != out->cookie || node->key.cookie != out->cookie ||
        token->epoch != out->epoch || node->epoch != out->epoch || table->epoch != out->epoch)
        return 0;
    __u64 word = sa_read(&node->publication);
    if (!sa_stable(word)) return 0;
    ss_copy_route(&out->route, &node->route);
    out->id = word >> 2;
    out->admission = (word & 3) == SA_ADMITTED ||
                     (node->parent_id && cc_parent_admitted(parent, parent_token, node->parent_id, &out->route));
    out->alive = token->alive;
    return word == sa_read(&node->publication) && out->alive;
#else
    for (unsigned attempt = 0; attempt < 2; attempt++) {
        __u64 before = route_version_read(&entry->sequence);
        if (before & 1)
            continue;
        ss_copy_route(&out->route, &entry->route);
        out->cookie = entry->cookie;
        out->epoch = entry->epoch;
        out->id = entry->id;
        out->admission = (__u32)(__sync_fetch_and_add(&entry->admission, 0) & 3);
        bpf_rcu_read_lock();
        struct ss_lifetime *token = entry->lifetime;
        int valid =
            !entry->retired && token && token->cookie == out->cookie && token->epoch == out->epoch;
        out->alive = valid ? token->alive : 0;
        bpf_rcu_read_unlock();
        __u64 after = route_version_read(&entry->sequence);
        if (before == after && !entry->retired)
            return valid;
    }
    return 0;
#endif
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

static __always_inline int cc_store(void *map, const struct flow_key *key, struct ss_state *state,
                                    const struct ss_record *record, __u64 epoch) {
    if (key->cookie != state->cookie)
        return -1;
    int held;
    struct cc_entry *entry = cc_find_or_insert(map, key, &held);
    if (entry && !held && cc_unchanged(entry, key, record, epoch))
        return 0;
    return entry ? cc_update(map, entry, key, state, &record->route, epoch, record->id, held,
                            record->admitted) : -1;
}


/* Удаление идет под тем же CAS, что и публикация нового поколения. */
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

/* Смена UDP-интервала удаляет только прежнее решение, не более новое. */
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

/* Первое решение считается принятым после последнего собственного output guard. */
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

#ifndef AP_BINDING_SNAPSHOT
/* Непринятая попытка меняет выбор лишь после отказа либо изменения желаемого пути. */
static __noinline int cc_recover_rejected(void *map, const struct flow_key *key,
                                          struct ss_state *state, int recover,
                                          const struct cached_route *desired) {
    struct cc_entry *entry = bpf_map_lookup_elem(map, key);
    if (!entry)
        return 0;
    __u64 admission = __sync_fetch_and_add(&entry->admission, 0);
    __u32 status = admission & 3;
    if (status == 1)
        return 0;
    if (status == 3)
        return -1;
    if (!admission)
        return recover ? -1 : 0;
    if (status == 2 && !(recover & 1))
        return -1;
    if (status == 0 && !(recover & 2))
        return 0;
    if (status == 0 && !desired)
        return -1;
    if (__sync_val_compare_and_swap(&entry->lock, 0, 1))
        return -1;
    admission = entry->admission;
    status = admission & 3;
    if ((status != 0 && status != 2) || entry->cookie != key->cookie ||
        (admission >> 2) != entry->id) {
        __sync_lock_test_and_set(&entry->lock, 0);
        return status == 3 ? -1 : 0;
    }
    if (status == 2 && !(recover & 1)) {
        __sync_lock_test_and_set(&entry->lock, 0);
        return -1;
    }
    if (status == 0) {
        if (!(recover & 2)) {
            __sync_lock_test_and_set(&entry->lock, 0);
            return 0;
        }
        if (!desired) {
            __sync_lock_test_and_set(&entry->lock, 0);
            return -1;
        }
        if (route_choice_equal(&entry->route, desired) &&
            entry->route.network_generation == desired->network_generation &&
            entry->route.system_device == desired->system_device) {
            __sync_lock_test_and_set(&entry->lock, 0);
            return 0;
        }
    }
    if (__sync_val_compare_and_swap(&entry->admission, admission, (admission & ~3ULL) | 3) !=
        admission) {
        __sync_lock_test_and_set(&entry->lock, 0);
        return 0;
    }
    route_version_retire(&entry->sequence);
    entry->retired = 1;
    ss_confirmation(state, key, &entry->route, entry->epoch, (entry->id << 2) | 2);
    if (!bpf_map_delete_elem(map, key))
        return 1;
    __sync_lock_test_and_set(&entry->lock, 0);
    return -1;
}

#endif

/* Эта ссылка и tag захвачены до проверки пакета. Решение принимает финальный CAS. */
static __always_inline int cc_read_attempt(struct cc_entry *entry, __u64 expected,
                                           struct cc_snapshot *out) {
    if (!entry || !expected || !cc_read(entry, out))
        return 0;
#ifdef AP_BINDING_SNAPSHOT
    return out->alive && out->id == (expected >> 2) && out->admission < 2;
#else
    __u64 after = __sync_fetch_and_add(&entry->admission, 0);
    return out->alive && out->id == (expected >> 2) && (after >> 2) == (expected >> 2) &&
           out->admission != 3 && (after & 3) != 3;
#endif
}

#endif
