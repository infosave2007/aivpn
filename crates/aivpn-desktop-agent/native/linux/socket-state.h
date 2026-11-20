#pragma once
#ifdef AP_BINDING_SNAPSHOT
#include "snapshot-socket-state.h"
#else
#pragma once
#include <stdbool.h>
#include "admission-word.h"
#define SS_CONTAINS(type, field) __attribute__((btf_decl_tag("contains:" #type ":" #field)))

enum ss_kind { SS_EMPTY, SS_CLASSIFIED, SS_PRESERVED, SS_INITIALIZING, SS_UNAVAILABLE };
#ifndef SS_STORAGE_FLAGS
#define SS_STORAGE_FLAGS (BPF_F_NO_PREALLOC | BPF_F_CLONE)
#endif
#ifndef SS_ALLOW_ADOPT
#define SS_ALLOW_ADOPT() 1
#endif
#ifndef SS_FLOW_LIMIT
#define SS_FLOW_LIMIT 65536
#endif
_Static_assert(SS_FLOW_LIMIT > 0, "SS_FLOW_LIMIT must be positive");
struct ss_lifetime {
    struct bpf_refcount references;
    __u32 alive;
    __u64 cookie, epoch, udp_options;
};
#ifndef SS_TOKEN_PUBLISHED
#define SS_TOKEN_PUBLISHED() ((void)0)
#endif
#ifndef SS_RELEASE_UDP_OPTIONS
#define SS_RELEASE_UDP_OPTIONS(flags) ((void)(flags))
#endif
#ifndef SS_NOW
#define SS_NOW() bpf_ktime_get_ns()
#endif
#ifndef SS_IDLE_NS
#define SS_IDLE_NS 180000000000ULL
#endif
#ifndef SS_RETIRE_FLOW
#define SS_RETIRE_FLOW(key, epoch, id) 0
#endif
#define SS_SWEEP_NS (SS_IDLE_NS / 4)
#define SS_ID_LIMIT (~0ULL >> 2)
#ifndef SS_AFTER_COLLECT_MOVE
#define SS_AFTER_COLLECT_MOVE(state, table, key) ((void)(state), (void)(table), (void)(key))
#endif
struct ss_record {
    struct cached_route route;
    __u64 id;
    __u32 admitted, source_port;
    __u8 system_source[16];
    __u64 parent_id;
};
struct ss_request {
    __u64 network_generation, system_device, now, expected_id, new_id, expected_epoch;
    __u32 set_device, renew, no_touch, confirm;
    __u8 system_source[16];
    __u64 parent_id;
    __u32 source_port, reserved;
};
struct ss_node {
    struct bpf_rb_node link;
    struct bpf_refcount references;
    struct flow_key key;
    struct cached_route route;
    struct ss_request request;
    __u64 id, last_seen;
    __u64 epoch, publication;
    __u8 system_source[16];
    __u64 parent_id;
    __u32 source_port, reserved;
    /* Подготовка записи и допуск пакета имеют разные точки фиксации. */
    __u32 matched, retiring, prepared, admitted;
};
struct ss_table {
    struct bpf_spin_lock lock;
    struct bpf_refcount references;
    struct bpf_rb_root flows SS_CONTAINS(ss_node, link);
    struct bpf_rb_root other_flows SS_CONTAINS(ss_node, link);
    __u64 epoch, count, next_id, next_sweep;
    __u32 active, gc_busy;
};
struct ss_state {
    struct process_state creator;
    __u32 kind, known_creator;
    __u64 cookie;
    struct ss_lifetime __kptr *lifetime;
    struct ss_table __kptr *table;
    struct ss_node __kptr *query;
    struct flow_key stream_peer;
    __u32 stream_peer_state, derived_stream;
    __u64 logical_cookie;
    struct ss_table __kptr *logical_table;
    struct ss_node __kptr *logical_node;
    struct ss_lifetime __kptr *logical_lifetime;
    struct flow_key logical_key;
};
AP_LOCAL_STORAGE_CHECK(ss_state);
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, SS_STORAGE_FLAGS);
    __type(key, int);
    __type(value, struct ss_state);
} socket_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, SS_STORAGE_FLAGS);
    __type(key, int);
    __type(value, struct process_companion);
} socket_companions SEC(".maps");

static __always_inline int ss_copy_companion(void *sock, const struct process_companion *source) {
    struct process_companion *mate =
        bpf_sk_storage_get(&socket_companions, sock, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!mate)
        return -1;
    copy_process_companion(mate, source);
    return 0;
}

extern void *bpf_obj_new_impl(__u64 type, void *meta) __ksym;
extern void *bpf_refcount_acquire_impl(void *object, void *meta) __ksym;
extern void bpf_obj_drop_impl(void *object, void *meta) __ksym;
extern int bpf_rbtree_add_impl(struct bpf_rb_root *root, struct bpf_rb_node *node,
                               bool (*less)(struct bpf_rb_node *, const struct bpf_rb_node *),
                               void *meta, __u64 offset) __ksym;
extern struct bpf_rb_node *bpf_rbtree_root(struct bpf_rb_root *root) __ksym;
extern struct bpf_rb_node *bpf_rbtree_left(struct bpf_rb_root *root, struct bpf_rb_node *node) __ksym;
extern struct bpf_rb_node *bpf_rbtree_right(struct bpf_rb_root *root, struct bpf_rb_node *node) __ksym;
#ifdef AP_BINDING_SNAPSHOT

static __noinline struct ss_node *ss_find_acquire(struct ss_table *table,
                                                 const struct flow_key *key);
#endif
extern struct bpf_rb_node *bpf_rbtree_remove(struct bpf_rb_root *root,
                                             struct bpf_rb_node *node) __ksym;

static __always_inline void ss_copy_route(volatile struct cached_route *to,
                                          const volatile struct cached_route *from) {
    to->decision.action = from->decision.action;
    to->decision.profile = from->decision.profile;
    to->decision.rule = from->decision.rule;
    to->decision.depth = from->decision.depth;
    to->decision.unresolved = from->decision.unresolved;
    to->decision.generation = from->decision.generation;
    to->network_generation = from->network_generation;
    to->system_device = from->system_device;
    to->binding_epoch = from->binding_epoch;
}

static __always_inline void ss_copy_key(struct flow_key *to, const struct flow_key *from) {
    to->cookie = from->cookie;
    __builtin_memcpy(to->destination, from->destination, sizeof(to->destination));
    *(volatile __u32 *)&to->family = from->family;
    *(volatile __u32 *)&to->port = from->port;
    *(volatile __u32 *)&to->protocol = from->protocol;
    *(volatile __u32 *)&to->padding = from->padding;
}

static __always_inline void ss_clear_request(volatile struct ss_request *request) {
    request->network_generation = 0;
    request->system_device = 0;
    request->set_device = 0;
    request->renew = 0;
    request->no_touch = 0;
    request->confirm = 0;
    request->now = 0;
    request->expected_id = 0;
    request->expected_epoch = 0;
    request->new_id = 0;
    request->parent_id = 0;
    request->source_port = 0;
    request->reserved = 0;
    __builtin_memset((void *)request->system_source, 0, 16);
}

static __always_inline struct ss_node *ss_new_query(__u64 epoch) {
    struct ss_node *node = bpf_obj_new_impl(bpf_core_type_id_local(struct ss_node), 0);
    if (!node)
        return 0;
    struct flow_key empty_key = {};
    struct cached_route empty_route = {};
    ss_copy_key(&node->key, &empty_key);
    ss_copy_route(&node->route, &empty_route);
    ss_clear_request(&node->request);
    node->epoch = epoch;
    node->matched = 0;
    *(volatile __u32 *)&node->prepared = 0;
    *(volatile __u32 *)&node->admitted = 0;
    *(volatile __u32 *)&node->retiring = 0;
    node->id = 0;
    node->publication = 0;
    node->parent_id = 0;
    node->source_port = 0;
    __builtin_memset(node->system_source, 0, 16);
    node->last_seen = 0;
    return node;
}

static __always_inline struct ss_table *ss_new_table(__u64 epoch) {
    struct ss_table *table = bpf_obj_new_impl(bpf_core_type_id_local(struct ss_table), 0);
    if (table) {
        table->epoch = epoch;
        table->count = 0;
        table->next_id = 0;
        table->next_sweep = 0;
        *(volatile __u32 *)&table->active = 0;
        *(volatile __u32 *)&table->gc_busy = 0;
    }
    return table;
}

static __always_inline struct ss_lifetime *ss_new_lifetime(__u64 cookie, __u64 epoch) {
    struct ss_lifetime *token = bpf_obj_new_impl(bpf_core_type_id_local(struct ss_lifetime), 0);
    if (token) {
        token->cookie = cookie;
        token->epoch = epoch;
        token->alive = 1;
        token->udp_options = 0;
    }
    return token;
}

static __always_inline void ss_publish(struct ss_state *state, struct ss_table *table,
                                       struct ss_node *query, struct ss_lifetime *token) {
    SS_TOKEN_PUBLISHED();
    struct ss_lifetime *old_token = bpf_kptr_xchg(&state->lifetime, token);
    if (old_token) {
        if (__sync_val_compare_and_swap(&old_token->alive, 1, 0) == 1)
            SS_RELEASE_UDP_OPTIONS(old_token->udp_options);
        bpf_obj_drop_impl(old_token, 0);
    }
    struct ss_table *old_table = bpf_kptr_xchg(&state->table, table);
    if (old_table)
        bpf_obj_drop_impl(old_table, 0);
    struct ss_node *old_query = bpf_kptr_xchg(&state->query, query);
    if (old_query)
        bpf_obj_drop_impl(old_query, 0);
}

static __noinline int ss_rotate(struct ss_state *state, __u64 epoch) {
    struct ss_table *table = ss_new_table(epoch);
    if (!table)
        return -1;
    struct ss_node *query = ss_new_query(epoch);
    if (!query) {
        bpf_obj_drop_impl(table, 0);
        return -1;
    }
    struct ss_lifetime *token = ss_new_lifetime(state->cookie, epoch);
    if (!token) {
        bpf_obj_drop_impl(query, 0);
        bpf_obj_drop_impl(table, 0);
        return -1;
    }
    ss_publish(state, table, query, token);
    return 0;
}

static __noinline struct ss_state *ss_initialize_cookie(void *sock, __u64 cookie,
                                                        const struct process_state *creator,
                                                        enum ss_kind kind,
                                                        const struct process_companion *companion) {
    struct ss_state *state =
        bpf_sk_storage_get(&socket_states, sock, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!state)
        return 0;
    __u32 previous = __sync_val_compare_and_swap(&state->kind, SS_EMPTY, SS_INITIALIZING);
    if (previous)
        return previous == SS_CLASSIFIED || previous == SS_PRESERVED ? state : 0;
    if (ss_copy_companion(sock, companion)) {
        __sync_lock_test_and_set(&state->kind, SS_EMPTY);
        return 0;
    }
    state->cookie = cookie;
    state->known_creator = kind == SS_CLASSIFIED;
    if (!state->cookie || ss_rotate(state, 0)) {
        __sync_lock_test_and_set(&state->kind, SS_EMPTY);
        return 0;
    }
    if (creator)
        copy_process_state(&state->creator, creator);
    __sync_lock_test_and_set(&state->kind, kind);
    return state;
}

/* Этот вариант подходит hook, где helper принимает сам переданный socket context. */
static __always_inline struct ss_state *
ss_initialize(void *sock, const struct process_state *creator, enum ss_kind kind,
              const struct process_companion *companion) {
    return ss_initialize_cookie(sock, bpf_get_socket_cookie(sock), creator, kind, companion);
}

/* После kernel clone личность сохранена, но у нового сокета еще нет своих kptr. */
static __always_inline struct ss_state *ss_adopt_cookie(void *sock, __u64 cookie) {
    struct ss_state *state = bpf_sk_storage_get(&socket_states, sock, 0, 0);
    if (!state)
        return ss_initialize_cookie(sock, cookie, 0, SS_PRESERVED, 0);
    const struct process_companion *mate = bpf_sk_storage_get(&socket_companions, sock, 0, 0);
    if (!mate)
        return 0;
    __u32 kind = __sync_val_compare_and_swap(&state->kind, SS_EMPTY, SS_EMPTY);
    if (!cookie || kind == SS_INITIALIZING)
        return 0;
    bpf_rcu_read_lock();
    int has_objects = (state->lifetime ? 1 : 0) | (state->table ? 2 : 0) | (state->query ? 4 : 0);
    bpf_rcu_read_unlock();
    if (state->cookie == cookie && has_objects == 7 &&
        (kind == SS_CLASSIFIED || kind == SS_PRESERVED))
        return state;
    if (has_objects || __sync_val_compare_and_swap(&state->kind, kind, SS_INITIALIZING) != kind)
        return 0;
    __u32 known = state->known_creator || kind == SS_CLASSIFIED;
    state->cookie = cookie;
    state->known_creator = known;
    state->derived_stream = 0;
    state->logical_cookie = 0;
    __sync_lock_test_and_set(&state->stream_peer_state, 0);
    if (!SS_ALLOW_ADOPT() || ss_rotate(state, 0)) {
        __sync_lock_test_and_set(&state->kind, SS_UNAVAILABLE);
        return 0;
    }
    __sync_lock_test_and_set(&state->kind, known ? SS_CLASSIFIED : SS_PRESERVED);
    return state;
}

static __always_inline struct ss_state *ss_adopt_clone(void *sock) {
    return ss_adopt_cookie(sock, bpf_get_socket_cookie(sock));
}

/* В tracing хранится только личность. Граф создается вне tracing до допуска пакета. */
static __noinline struct ss_state *ss_identity_cookie(void *sock, __u64 cookie,
                                                      const struct process_state *creator,
                                                      enum ss_kind kind,
                                                        const struct process_companion *companion) {
    struct ss_state *state =
        bpf_sk_storage_get(&socket_states, sock, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!state || !cookie)
        return 0;
    __u32 previous = __sync_val_compare_and_swap(&state->kind, SS_EMPTY, SS_INITIALIZING);
    if (previous)
        return previous == SS_CLASSIFIED || previous == SS_PRESERVED ? state : 0;
    if (ss_copy_companion(sock, companion)) {
        __sync_lock_test_and_set(&state->kind, SS_EMPTY);
        return 0;
    }
    state->cookie = cookie;
    state->known_creator = kind == SS_CLASSIFIED;
    if (creator)
        copy_process_state(&state->creator, creator);
    __sync_lock_test_and_set(&state->kind, kind);
    return state;
}

static __always_inline int ss_restart_tcp(struct ss_state *state) {
    bpf_rcu_read_lock();
    struct ss_lifetime *token = state->lifetime;
    __u64 epoch = token ? token->epoch : ~0ULL;
    bpf_rcu_read_unlock();
    if (epoch == ~0ULL || ss_rotate(state, epoch + 1))
        return -1;
    __sync_lock_test_and_set(&state->stream_peer_state, 0);
    return 0;
}

static __always_inline struct ss_table *ss_table_acquire(struct ss_state *state) {
    bpf_rcu_read_lock();
    struct ss_table *table = state->table;
    struct ss_table *reference = table ? bpf_refcount_acquire_impl(table, 0) : 0;
    bpf_rcu_read_unlock();
    return reference;
}

static __always_inline struct ss_lifetime *ss_lifetime_acquire(struct ss_state *state, __u64 cookie,
                                                               __u64 epoch) {
    bpf_rcu_read_lock();
    struct ss_lifetime *borrowed = state->lifetime;
    struct ss_lifetime *token = borrowed ? bpf_refcount_acquire_impl(borrowed, 0) : 0;
    bpf_rcu_read_unlock();
    if (token && (!token->alive || token->cookie != cookie || token->epoch != epoch)) {
        bpf_obj_drop_impl(token, 0);
        return 0;
    }
    return token;
}

#ifdef AP_BINDING_SNAPSHOT
/* Связь направлена только от подпотока к живому логическому соединению. */
static __noinline int ss_link_logical(struct ss_state *child, struct ss_state *parent) {
    bpf_rcu_read_lock();
    struct ss_table *table = parent->table;
    struct ss_node *query = 0;
    struct ss_lifetime *token = parent->lifetime;
    table = table ? bpf_refcount_acquire_impl(table, 0) : 0;
    token = token ? bpf_refcount_acquire_impl(token, 0) : 0;
    bpf_rcu_read_unlock();
    if (table)
        query = ss_find_acquire(table, &parent->stream_peer);
    if (!table || !query || !token || !token->alive || token->cookie != parent->cookie ||
        table->epoch != query->epoch || table->epoch != token->epoch ||
        parent->stream_peer_state != 2) {
        if (table) bpf_obj_drop_impl(table, 0);
        if (query) bpf_obj_drop_impl(query, 0);
        if (token) bpf_obj_drop_impl(token, 0);
        return -1;
    }
    ss_copy_key(&child->logical_key, &parent->stream_peer);
    child->logical_cookie = parent->cookie;
    table = bpf_kptr_xchg(&child->logical_table, table);
    query = bpf_kptr_xchg(&child->logical_node, query);
    token = bpf_kptr_xchg(&child->logical_lifetime, token);
    if (table) bpf_obj_drop_impl(table, 0);
    if (query) bpf_obj_drop_impl(query, 0);
    if (token) bpf_obj_drop_impl(token, 0);
    return 0;
}
#endif

static __always_inline void ss_mark_closed(void *sock) {
    struct ss_state *state = bpf_sk_storage_get(&socket_states, sock, 0, 0);
    if (!state)
        return;
    bpf_rcu_read_lock();
    struct ss_lifetime *token = state->lifetime;
    if (token && __sync_val_compare_and_swap(&token->alive, 1, 0) == 1)
        SS_RELEASE_UDP_OPTIONS(token->udp_options);
    bpf_rcu_read_unlock();
}

static __always_inline int ss_node_admitted(const struct ss_node *node) {
#ifdef AP_BINDING_SNAPSHOT
    return (sa_read((__u64 *)&node->publication) & 3) == SA_ADMITTED;
#else
    return node->admitted;
#endif
}
static __always_inline int ss_interval_expired(const struct ss_node *node, __u64 now) {
#ifdef AP_BINDING_SNAPSHOT
    if ((sa_read((__u64 *)&node->publication) & 3) == SA_RETIRED) return 1;
#endif
    return node->key.protocol != 6 &&
           (node->retiring || node->route.decision.action == 1 ||
            (now >= node->last_seen && now - node->last_seen >= SS_IDLE_NS));
}

static __always_inline int ss_expired(const struct ss_node *node, __u64 now) {
#ifdef AP_BINDING_SNAPSHOT
    return !sa_stable(sa_read((__u64 *)&node->publication)) || ss_interval_expired(node, now);
#else
    return !node->prepared || ss_interval_expired(node, now);
#endif
}

static __always_inline void ss_touch(struct ss_node *node, __u64 now) {
    for (unsigned attempt = 0; attempt < 3; attempt++) {
        __u64 old = __sync_fetch_and_add(&node->last_seen, 0);
        if (old >= now || __sync_val_compare_and_swap(&node->last_seen, old, now) == old) break;
    }
}

static __always_inline int route_choice_equal(const struct cached_route *left,
                                              const struct cached_route *right) {
    __u64 different = left->binding_epoch ^ right->binding_epoch;
    different |= left->decision.action ^ right->decision.action;
    different |= left->decision.profile ^ right->decision.profile;
    different |= left->decision.rule ^ right->decision.rule;
    different |= left->decision.depth ^ right->decision.depth;
    different |= left->decision.unresolved ^ right->decision.unresolved;
    different |= left->decision.generation ^ right->decision.generation;
    return !different;
}

#include "flow-order.h"

/* Parent остается единственным admission для подпотока. */
static __always_inline int ss_logical_admitted(struct ss_state *state, const struct ss_record *record) {
    struct ss_node *parent = state->logical_node;
    struct ss_lifetime *token = state->logical_lifetime;
    if (!record->parent_id || !parent || !token || !token->alive ||
        token->cookie != state->logical_cookie || parent->epoch != token->epoch) return 0;
    __u64 word = sa_read(&parent->publication);
    return word == ((record->parent_id << 2) | SA_ADMITTED) &&
           route_choice_equal(&parent->route, &record->route) && word == sa_read(&parent->publication);
}

/* Обе операции меняют один node только под lock его table. */
static __always_inline int ss_update_node(struct ss_node *existing, const struct ss_request *request,
                                          const struct cached_route *proposed) {
#ifdef AP_BINDING_SNAPSHOT
    __u64 word = sa_read(&existing->publication);
    if (!(word >> 2) || (word & 3) == SA_UPDATING) return 2;
    int same = request->expected_id == (word >> 2);
    int expired = ss_interval_expired(existing, request->now);
    if (request->confirm == 3 && same && !expired && route_choice_equal(proposed, &existing->route)) {
        if (!sa_admit(&existing->publication, word)) return 2;
        word |= SA_ADMITTED;
    }
    if (request->confirm == 2 && same && (word & 3) == SA_PREPARED &&
        route_choice_equal(proposed, &existing->route)) {
        if (!sa_retire(&existing->publication, word)) return 2;
        word = (word & ~3ULL) | SA_RETIRED;
        expired = 1;
    }
    int renew = request->renew && same && expired;
    int bind = same && (word & 3) == SA_PREPARED &&
        ((request->set_device && (existing->route.system_device != request->system_device ||
          existing->source_port != request->source_port || __builtin_memcmp(existing->system_source, request->system_source, 16))) ||
         (request->network_generation && !existing->route.network_generation) ||
         (request->parent_id && existing->parent_id != request->parent_id));
    if (bind && !renew && existing->parent_id && existing->parent_id == request->parent_id &&
        existing->route.system_device) return 2;
    if (renew || bind) {
        if ((word & 3) == SA_ADMITTED) {
            if (!expired || !sa_retire(&existing->publication, word)) return 2;
            word = (word & ~3ULL) | SA_RETIRED;
        }
        if (!request->new_id || request->new_id <= (word >> 2) ||
            !sa_claim(&existing->publication, word)) return 2;
        if (renew) ss_copy_route(&existing->route, proposed);
        if (request->network_generation && !existing->route.network_generation)
            existing->route.network_generation = request->network_generation;
        if (request->set_device && existing->route.decision.action == 0) {
            existing->route.system_device = request->system_device;
            existing->source_port = request->source_port;
            __builtin_memcpy(existing->system_source, request->system_source, 16);
        }
        if (request->parent_id) existing->parent_id = request->parent_id;
        existing->id = request->new_id;
        existing->retiring = 0;
        ss_touch(existing, request->now);
        if (!sa_publish(&existing->publication, word, request->new_id)) return 2;
        expired = 0;
    }
    if (!expired && !request->no_touch) ss_touch(existing, request->now);
    return expired ? 2 : 1;
#else
    int interval_expired = ss_interval_expired(existing, request->now);
    if (request->confirm == 1 && !interval_expired &&
        request->expected_id == existing->id &&
        route_choice_equal(proposed, &existing->route))
        *(volatile __u32 *)&existing->prepared = 1;
    if (request->confirm == 3 && !interval_expired && !existing->retiring &&
        request->expected_id == existing->id &&
        route_choice_equal(proposed, &existing->route)) {
        *(volatile __u32 *)&existing->admitted = 1;
        *(volatile __u32 *)&existing->prepared = 1;
    }
    if (request->confirm == 2 && !existing->admitted && request->expected_id == existing->id &&
        route_choice_equal(proposed, &existing->route)) {
        *(volatile __u32 *)&existing->prepared = 0;
        *(volatile __u32 *)&existing->retiring = 1;
    }
    int expired = interval_expired ||
                  (!existing->prepared &&
                   (request->renew || request->expected_id != existing->id));
    if (expired && request->renew && request->expected_id == existing->id) {
        ss_copy_route(&existing->route, proposed);
        existing->id = request->new_id;
        existing->last_seen = request->now;
        existing->retiring = 0;
#ifdef AP_BINDING_SNAPSHOT
        *(volatile __u32 *)&existing->prepared = 0;
#else
        *(volatile __u32 *)&existing->prepared = existing->key.protocol != 17;
#endif
        *(volatile __u32 *)&existing->admitted = 0;
        expired = 0;
    }
    if (!expired && !request->no_touch) {
        if (existing->route.decision.action == 2 && request->network_generation &&
            request->expected_id == existing->id && !existing->route.network_generation)
            existing->route.network_generation = request->network_generation;
        if (existing->route.decision.action == 0 && request->set_device &&
            request->expected_id == existing->id)
            existing->route.system_device = request->system_device;
        if (request->now > existing->last_seen)
            existing->last_seen = request->now;
    }
    return expired ? 2 : 1;
#endif
}

static bool ss_less(struct bpf_rb_node *left, const struct bpf_rb_node *right) {
    struct ss_node *candidate = container_of(left, struct ss_node, link);
    struct ss_node *existing = container_of(right, struct ss_node, link);
    int order = ss_key_order(&candidate->key, &existing->key);
    if (order) return order < 0;
#ifndef AP_BINDING_SNAPSHOT
    int matched = ss_update_node(existing, &candidate->request, &candidate->route);
    ss_copy_route(&candidate->route, &existing->route);
    candidate->id = existing->id;
    candidate->admitted = ss_node_admitted(existing);
    candidate->parent_id = existing->parent_id;
    candidate->source_port = existing->source_port;
    __builtin_memcpy(candidate->system_source, existing->system_source, 16);
    candidate->last_seen = existing->last_seen;
    candidate->matched = matched;
#endif
    return false;
}

#ifdef AP_BINDING_SNAPSHOT
/* Вызывающий держит owned table lock. Высота при cap65536 меньше 36. */
static __always_inline struct ss_node *ss_find_locked(struct ss_table *table,
                                                      const struct flow_key *key) {
    for (unsigned tree = 0; tree < 2; tree++) {
        struct bpf_rb_root *root = tree ? &table->other_flows : &table->flows;
        struct bpf_rb_node *link = bpf_rbtree_root(root);
        for (unsigned depth = 0; depth < 36 && link; depth++) {
            struct ss_node *node = container_of(link, struct ss_node, link);
            int order = ss_key_order(key, &node->key);
            if (!order) return node;
            link = order < 0 ? bpf_rbtree_left(root, link) : bpf_rbtree_right(root, link);
        }
    }
    return 0;
}
/* Чтение не получает права confirm/renew/bind, last_seen остается монотонным. */
static __noinline int ss_read(struct ss_table *table, const struct flow_key *key,
                               struct ss_record *out, int touch) {
    __u64 now = SS_NOW();
    int found = 0;
    bpf_spin_lock(&table->lock);
    struct ss_node *node = ss_find_locked(table, key);
    if (node) {
        found = ss_expired(node, now) ? 2 : 1;
        if (found == 1 && touch) ss_touch(node, now);
        ss_copy_route(&out->route, &node->route);
        out->id = node->id;
        out->admitted = ss_node_admitted(node);
        out->parent_id = node->parent_id;
        out->source_port = node->source_port;
        __builtin_memcpy(out->system_source, node->system_source, 16);
    }
    bpf_spin_unlock(&table->lock);
    return found;
}

static __noinline struct ss_node *ss_find_acquire(struct ss_table *table,
                                                 const struct flow_key *key) {
    bpf_spin_lock(&table->lock);
    struct ss_node *node = ss_find_locked(table, key);
    struct ss_node *owned = node ? bpf_refcount_acquire_impl(node, 0) : 0;
    bpf_spin_unlock(&table->lock);
    return owned;
}
#endif

static __always_inline int ss_add(struct ss_table *table, struct ss_node *node, __u32 index) {
    if (index)
        return bpf_rbtree_add_impl(&table->other_flows, &node->link, ss_less, 0,
                                   offsetof(struct ss_node, link));
    return bpf_rbtree_add_impl(&table->flows, &node->link, ss_less, 0,
                               offsetof(struct ss_node, link));
}

static __always_inline struct bpf_rb_node *ss_remove(struct ss_table *table, struct ss_node *node,
                                                     __u32 index) {
    if (index)
        return bpf_rbtree_remove(&table->other_flows, &node->link);
    return bpf_rbtree_remove(&table->flows, &node->link);
}

#ifndef AP_BINDING_SNAPSHOT
static __always_inline struct bpf_rb_node *ss_probe(struct ss_table *table, struct ss_node *probe,
                                                    __u32 index, int *error) {
    struct ss_node *copy = bpf_refcount_acquire_impl(probe, 0);
    if (!copy) {
        *error = -1;
        return 0;
    }
    if (ss_add(table, copy, index)) {
        *error = -1;
        return 0;
    }
    struct bpf_rb_node *removed = ss_remove(table, probe, index);
    if (!removed)
        *error = -1;
    return removed;
}

#endif

static __always_inline void ss_drop_node(struct bpf_rb_node *node) {
    if (node)
        bpf_obj_drop_impl(container_of(node, struct ss_node, link), 0);
}

static __always_inline void ss_copy_request(volatile struct ss_request *to,
                                            const volatile struct ss_request *from) {
    to->network_generation = from->network_generation;
    to->system_device = from->system_device;
    to->now = from->now;
    to->expected_id = from->expected_id;
    to->expected_epoch = from->expected_epoch;
    to->new_id = from->new_id;
    to->set_device = from->set_device;
    to->renew = from->renew;
    to->no_touch = from->no_touch;
    to->confirm = from->confirm;
    to->parent_id = from->parent_id;
    to->source_port = from->source_port;
    to->reserved = 0;
    __builtin_memcpy((void *)to->system_source, (const void *)from->system_source, 16);
}

/* probe принадлежит вызывающему и используется только под lock своего table. */
static __noinline int ss_lookup_held(struct ss_table *table, struct ss_node *probe,
                                     const struct flow_key *key, const struct ss_request *request,
                                     struct ss_record *out) {
    if (!probe)
        return -1;
    if (probe->epoch != table->epoch) {
        bpf_obj_drop_impl(probe, 0);
        return -1;
    }
    __u64 now = SS_NOW();
#ifndef AP_BINDING_SNAPSHOT
    struct bpf_rb_node *removed = 0, *other_removed = 0;
#endif
    int error = 0, found = 0;
    bpf_spin_lock(&table->lock);
    ss_copy_key(&probe->key, key);
    ss_copy_request(&probe->request, request);
    probe->request.now = now;
    probe->matched = 0;
    if (request->confirm)
        ss_copy_route(&probe->route, &out->route);
    if (request->renew || request->set_device || request->network_generation || request->parent_id) {
        if (table->next_id >= SS_ID_LIMIT)
            error = -1;
        else {
            probe->request.new_id = ++table->next_id;
            ss_copy_route(&probe->route, &out->route);
        }
    }
#ifdef AP_BINDING_SNAPSHOT
    struct ss_node *node = error ? 0 : ss_find_locked(table, key);
    if (node) {
        found = ss_update_node(node, &probe->request, &probe->route);
        ss_copy_route(&out->route, &node->route);
        out->id = node->id;
        out->admitted = ss_node_admitted(node);
        out->parent_id = node->parent_id;
        out->source_port = node->source_port;
        __builtin_memcpy(out->system_source, node->system_source, 16);
    }
    bpf_spin_unlock(&table->lock);
#else
    if (!error)
        removed = ss_probe(table, probe, table->active, &error);
    if (!error && !probe->matched)
        other_removed = ss_probe(table, probe, !table->active, &error);
    if (!error && probe->matched) {
        found = probe->matched;
        ss_copy_route(&out->route, &probe->route);
        out->id = probe->id;
        out->admitted = probe->admitted;
        out->parent_id = probe->parent_id;
        out->source_port = probe->source_port;
        __builtin_memcpy(out->system_source, probe->system_source, 16);
    }
    bpf_spin_unlock(&table->lock);
    ss_drop_node(removed);
    ss_drop_node(other_removed);
#endif
    bpf_obj_drop_impl(probe, 0);
    return error ? -1 : found;
}

static __always_inline int ss_lookup(struct ss_state *state, struct ss_table *table,
                                     const struct flow_key *key, const struct ss_request *request,
                                     struct ss_record *out) {
    bpf_rcu_read_lock();
    struct ss_node *borrowed = state->query;
    struct ss_node *probe = borrowed ? bpf_refcount_acquire_impl(borrowed, 0) : 0;
    bpf_rcu_read_unlock();
    return ss_lookup_held(table, probe, key, request, out);
}

static __noinline int ss_confirmation(struct ss_state *state, const struct flow_key *key,
                                      const struct cached_route *route, __u64 epoch, __u64 tag) {
    struct ss_table *table = ss_table_acquire(state);
    if (!table)
        return -1;
    __u64 id = tag >> 2;
    struct ss_request request = {.no_touch = 1, .confirm = tag & 3, .expected_id = id};
    struct ss_record current = {};
    ss_copy_route(&current.route, route);
    int found = -1;
    if (table->epoch == epoch) {
#ifdef AP_BINDING_SNAPSHOT
        found = (tag & 3) == 1 ? ss_read(table, key, &current, 0)
                               : ss_lookup(state, table, key, &request, &current);
#else
        found = ss_lookup(state, table, key, &request, &current);
#endif
    }
    bpf_obj_drop_impl(table, 0);
    return found == 1 && current.id == id && route_choice_equal(&current.route, route) &&
           ((tag & 3) != 3 || current.admitted) ? 0 : -1;
}

static __always_inline int ss_prepare(struct ss_state *state, const struct flow_key *key,
                                      const struct cached_route *route, __u64 epoch, __u64 id) {
    return ss_confirmation(state, key, route, epoch, (id << 2) | 1);
}

static __noinline int ss_freeze(struct ss_table *table, const struct flow_key *key,
                                const struct cached_route *proposed, struct ss_record *out) {
    struct ss_node *candidate = ss_new_query(table->epoch);
    if (!candidate)
        return -1;
    ss_copy_key(&candidate->key, key);
    ss_copy_route(&candidate->route, proposed);
    candidate->request.network_generation = proposed->network_generation;
    candidate->request.system_device = proposed->system_device;
    candidate->request.set_device = proposed->system_device != 0;
    candidate->request.now = SS_NOW();
    candidate->last_seen = candidate->request.now;
#ifndef AP_BINDING_SNAPSHOT
    *(volatile __u32 *)&candidate->prepared = key->protocol != 17;
#endif
    struct ss_node *held = bpf_refcount_acquire_impl(candidate, 0);
    if (!held) {
        bpf_obj_drop_impl(candidate, 0);
        return -1;
    }
#ifdef AP_BINDING_SNAPSHOT
    struct ss_node *unused = candidate;
    int error = 0, found = 0;
    /* Новый node еще не опубликован: под table lock его admission всегда PREP. */
    unsigned admitted = 0;
    bpf_spin_lock(&table->lock);
    struct ss_node *existing = ss_find_locked(table, key);
    struct ss_node *selected = existing ? existing : held;
    if (existing) {
        found = ss_expired(existing, candidate->request.now) ? 2 : 1;
        if (found == 1) ss_touch(existing, candidate->request.now);
        admitted = ss_node_admitted(existing);
    } else if (table->next_id >= SS_ID_LIMIT || table->count >= SS_FLOW_LIMIT) {
        error = -1;
    } else {
        candidate->id = ++table->next_id;
        candidate->publication = candidate->id << 2;
        error = ss_add(table, candidate, table->active);
        unused = 0;
        if (!error) table->count++;
    }
    ss_copy_route(&out->route, &selected->route);
    out->id = selected->id;
    out->admitted = admitted;
    out->parent_id = selected->parent_id;
    out->source_port = selected->source_port;
    __builtin_memcpy(out->system_source, selected->system_source, 16);
    bpf_spin_unlock(&table->lock);
    if (unused) bpf_obj_drop_impl(unused, 0);
    bpf_obj_drop_impl(held, 0);
    return error ? -1 : found == 2 ? 2 : 0;
#else
    struct bpf_rb_node *removed = 0, *other_removed = 0;
    struct ss_node *unused = 0;
    int error = 0, found = 0;
    bpf_spin_lock(&table->lock);
    if (table->next_id >= SS_ID_LIMIT)
        error = -1;
    else {
        candidate->id = ++table->next_id;
        candidate->publication = candidate->id << 2;
    }
    if (!error)
        other_removed = ss_probe(table, candidate, !table->active, &error);
    if (!error && !candidate->matched) {
        error = ss_add(table, candidate, table->active);
        if (!error) {
            if (held->matched)
                removed = ss_remove(table, held, table->active);
            else if (table->count >= SS_FLOW_LIMIT) {
                removed = ss_remove(table, held, table->active);
                error = -1;
            } else
                table->count++;
        }
    } else
        unused = candidate;
    found = held->matched;
    ss_copy_route(&out->route, &held->route);
    out->id = held->id;
    out->admitted = held->matched ? held->admitted : ss_node_admitted(held);
    out->parent_id = held->parent_id;
    out->source_port = held->source_port;
    __builtin_memcpy(out->system_source, held->system_source, 16);
    bpf_spin_unlock(&table->lock);
    ss_drop_node(removed);
    ss_drop_node(other_removed);
    if (unused)
        bpf_obj_drop_impl(unused, 0);
    bpf_obj_drop_impl(held, 0);
    return error ? -1 : found == 2 ? 2 : 0;
#endif
}

extern struct bpf_rb_node *bpf_rbtree_first(struct bpf_rb_root *root) __ksym;
static __noinline void ss_collect(struct ss_state *state, struct ss_table *table, int force) {
    if (__sync_val_compare_and_swap(&table->gc_busy, 0, 1))
        return;
    __u64 now = SS_NOW();
    int sweep = 1;
    bpf_spin_lock(&table->lock);
    struct bpf_rb_node *first =
        table->active ? bpf_rbtree_first(&table->flows) : bpf_rbtree_first(&table->other_flows);
    if (!first) {
        if (!table->count || (!force && now < table->next_sweep))
            sweep = 0;
        else
            table->active = !table->active;
        table->next_sweep = now + SS_SWEEP_NS;
    }
    bpf_spin_unlock(&table->lock);
    if (sweep)
        for (unsigned step = 0; step < 8; step++) {
            struct ss_node *held = 0;
            struct bpf_rb_node *removed = 0;
            __u64 id = 0;
            int expired = 0, moved = 0;
            bpf_spin_lock(&table->lock);
            struct bpf_rb_node *link = table->active ? bpf_rbtree_first(&table->flows)
                                                     : bpf_rbtree_first(&table->other_flows);
            if (link) {
                struct ss_node *node = container_of(link, struct ss_node, link);
                held = bpf_refcount_acquire_impl(node, 0);
                removed = ss_remove(table, node, !table->active);
                if (removed) {
                    struct ss_node *moving = container_of(removed, struct ss_node, link);
                    moving->matched = 0;
                    if (!ss_add(table, moving, table->active)) {
                        moved = 1;
                        if (held) {
                            id = held->id;
                            expired = ss_expired(held, now);
                            if (expired) {
#ifdef AP_BINDING_SNAPSHOT
                                __u64 word = sa_read(&held->publication);
                                expired = (word & 3) == SA_RETIRED || sa_retire(&held->publication, word);
#else
                                held->retiring = 1;
#endif
                            }
                        }
                    } else if (table->count)
                        table->count--;
                    removed = 0;
                }
            }
            bpf_spin_unlock(&table->lock);
            ss_drop_node(removed);
            if (!held)
                break;
            struct flow_key retiring;
            ss_copy_key(&retiring, &held->key);
            if (moved && expired)
                SS_AFTER_COLLECT_MOVE(state, table, &retiring);
            if (moved && expired && !SS_RETIRE_FLOW(&retiring, table->epoch, id)) {
                removed = 0;
                bpf_spin_lock(&table->lock);
                if (held->id == id && ss_expired(held, now)) {
                    removed = ss_remove(table, held, table->active);
                    if (removed && table->count)
                        table->count--;
                }
                bpf_spin_unlock(&table->lock);
                ss_drop_node(removed);
            }
            bpf_obj_drop_impl(held, 0);
        }
    __sync_lock_test_and_set(&table->gc_busy, 0);
}

#endif

#ifndef AP_BINDING_SNAPSHOT
static __always_inline int ss_freeze_for(struct ss_state *state, struct ss_table *table,
                                          const struct flow_key *key, const struct cached_route *route,
                                          struct ss_record *out) {
    (void)state;
    return ss_freeze(table, key, route, out);
}
#endif
