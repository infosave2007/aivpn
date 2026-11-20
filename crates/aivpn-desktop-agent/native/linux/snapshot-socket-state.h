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
    __u64 cookie, epoch, udp_options, next_id;
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
    __u64 parent_id, parent_epoch, parent_cookie;
};
struct ss_request {
    __u64 network_generation, system_device, now, expected_id, new_id, expected_epoch;
    __u32 set_device, renew, no_touch, confirm;
    __u8 system_source[16];
    __u64 parent_id, parent_epoch, parent_cookie;
    __u32 source_port, reserved;
};
/* Payload не владеет graph/kptr: tracing может acquire/drop этот тип. */
struct ss_flow {
    struct bpf_refcount references;
    struct flow_key key;
    struct cached_route route;
    struct ss_request request;
    __u64 id, last_seen, epoch, publication;
    __u8 system_source[16];
    __u64 parent_id, parent_epoch, parent_cookie;
    __u32 source_port, reserved;
};
/* Единственная route authority находится в payload, wrapper хранит только индекс. */
struct ss_node {
    struct bpf_rb_node link;
    struct bpf_refcount references;
    struct flow_key key;
    struct ss_flow __kptr *flow;
};
struct ss_table {
    struct bpf_spin_lock lock;
    struct bpf_refcount references;
    struct bpf_rb_root flows SS_CONTAINS(ss_node, link);
    struct bpf_rb_root other_flows SS_CONTAINS(ss_node, link);
    __u64 epoch, count, next_sweep;
    __u32 active, gc_busy;
};
struct ss_state {
    struct process_state creator;
    __u32 kind, known_creator;
    __u64 cookie;
    struct ss_lifetime __kptr *lifetime;
    struct ss_table __kptr *table;
    struct ss_flow __kptr *query;
    struct flow_key stream_peer;
    __u32 stream_peer_state, derived_stream;
    __u64 logical_cookie;
    struct ss_flow __kptr *direct_flow;
    struct ss_flow __kptr *logical_node;
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
extern struct bpf_rb_node *bpf_rbtree_remove(struct bpf_rb_root *root,
                                             struct bpf_rb_node *node) __ksym;
extern struct bpf_rb_node *bpf_rbtree_first(struct bpf_rb_root *root) __ksym;
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
    request->parent_epoch = 0;
    request->parent_cookie = 0;
    request->source_port = 0;
    request->reserved = 0;
    __builtin_memset((void *)request->system_source, 0, 16);
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
    to->parent_epoch = from->parent_epoch;
    to->parent_cookie = from->parent_cookie;
    to->source_port = from->source_port;
    to->reserved = 0;
    __builtin_memcpy((void *)to->system_source, (const void *)from->system_source, 16);
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

static __always_inline struct ss_lifetime *ss_new_lifetime(__u64 cookie, __u64 epoch) {
    struct ss_lifetime *token = bpf_obj_new_impl(bpf_core_type_id_local(struct ss_lifetime), 0);
    if (token) {
        token->cookie = cookie;
        token->epoch = epoch;
        token->alive = 1;
        token->udp_options = 0;
        token->next_id = 0;
    }
    return token;
}

static __always_inline struct ss_flow *ss_new_query(__u64 epoch) {
    struct ss_flow *flow = bpf_obj_new_impl(bpf_core_type_id_local(struct ss_flow), 0);
    if (!flow) return 0;
    /* Специальные поля готовит ядро, обычные данные инициализируем до публикации. */
    struct flow_key empty_key = {};
    struct cached_route empty_route = {};
    ss_copy_key(&flow->key, &empty_key);
    ss_copy_route(&flow->route, &empty_route);
    ss_clear_request(&flow->request);
    flow->id = 0;
    flow->last_seen = 0;
    flow->epoch = epoch;
    flow->publication = 0;
    __builtin_memset(flow->system_source, 0, sizeof(flow->system_source));
    flow->parent_id = 0;
    flow->parent_epoch = 0;
    flow->parent_cookie = 0;
    *(volatile __u32 *)&flow->source_port = 0;
    *(volatile __u32 *)&flow->reserved = 0;
    return flow;
}
static __always_inline struct ss_table *ss_new_table(__u64 epoch) {
    struct ss_table *table = bpf_obj_new_impl(bpf_core_type_id_local(struct ss_table), 0);
    if (table) {
        table->epoch = epoch;
        table->count = 0;
        table->next_sweep = 0;
        *(volatile __u32 *)&table->active = 0;
        *(volatile __u32 *)&table->gc_busy = 0;
    }
    return table;
}
static __always_inline void ss_clear_handles(struct ss_state *state) {
    struct ss_flow *flow = bpf_kptr_xchg(&state->direct_flow, 0);
    if (flow) bpf_obj_drop_impl(flow, 0);
    flow = bpf_kptr_xchg(&state->logical_node, 0);
    if (flow) bpf_obj_drop_impl(flow, 0);
    struct ss_lifetime *token = bpf_kptr_xchg(&state->logical_lifetime, 0);
    if (token) bpf_obj_drop_impl(token, 0);
}
static __always_inline void ss_publish(struct ss_state *state, struct ss_table *table,
                                       struct ss_flow *query, struct ss_lifetime *token) {
    SS_TOKEN_PUBLISHED();
    struct ss_lifetime *old_token = bpf_kptr_xchg(&state->lifetime, token);
    if (old_token) {
        if (__sync_val_compare_and_swap(&old_token->alive, 1, 0) == 1)
            SS_RELEASE_UDP_OPTIONS(old_token->udp_options);
        bpf_obj_drop_impl(old_token, 0);
    }
    ss_clear_handles(state);
    struct ss_table *old_table = bpf_kptr_xchg(&state->table, table);
    if (old_table)
        bpf_obj_drop_impl(old_table, 0);
    struct ss_flow *old_query = bpf_kptr_xchg(&state->query, query);
    if (old_query)
        bpf_obj_drop_impl(old_query, 0);
}

static __noinline int ss_rotate(struct ss_state *state, __u64 epoch) {
    struct ss_lifetime *token = ss_new_lifetime(state->cookie, epoch);
    if (!token) return -1;
    struct ss_table *table = ss_new_table(epoch);
    if (!table) { bpf_obj_drop_impl(token, 0); return -1; }
    struct ss_flow *query = ss_new_query(epoch);
    if (!query) {
        bpf_obj_drop_impl(table, 0);
        bpf_obj_drop_impl(token, 0);
        return -1;
    }
    ss_publish(state, table, query, token);
    return 0;
}
static __noinline int ss_adopt_preserved_graph(struct ss_state *state);
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

static __always_inline struct ss_state *
ss_initialize(void *sock, const struct process_state *creator, enum ss_kind kind,
              const struct process_companion *companion) {
    return ss_initialize_cookie(sock, bpf_get_socket_cookie(sock), creator, kind, companion);
}

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
    if (state->cookie == cookie && kind == SS_PRESERVED && !state->known_creator && has_objects == 1)
        return ss_adopt_preserved_graph(state) ? 0 : state;
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


static __always_inline void ss_touch(struct ss_flow *flow, __u64 now) {
    for (unsigned attempt = 0; attempt < 3; attempt++) {
        __u64 old = sa_read(&flow->last_seen);
        if (old >= now || __sync_val_compare_and_swap(&flow->last_seen, old, now) == old) break;
    }
}
static __always_inline int ss_interval_expired(const struct ss_flow *flow, __u64 now) {
    __u64 word = sa_read((__u64 *)&flow->publication);
    if ((word & 3) == SA_UPDATING) return 0;
    return (word & 3) == SA_RETIRED || (flow->key.protocol != 6 &&
        (flow->route.decision.action == 1 || (now >= flow->last_seen && now - flow->last_seen >= SS_IDLE_NS)));
}
static __always_inline void ss_flow_record(struct ss_flow *flow, __u64 word, struct ss_record *out) {
    ss_copy_route(&out->route, &flow->route);
    out->id = word >> 2;
    out->admitted = (word & 3) == SA_ADMITTED;
    out->parent_id = flow->parent_id;
    out->parent_epoch = flow->parent_epoch;
    out->parent_cookie = flow->parent_cookie;
    out->source_port = flow->source_port;
    __builtin_memcpy(out->system_source, flow->system_source, 16);
}
static __always_inline int ss_flow_read(struct ss_flow *flow, struct ss_record *out, int touch) {
    for (unsigned attempt = 0; attempt < 2; attempt++) {
        __u64 word = sa_read(&flow->publication), now = SS_NOW();
        if (!(word >> 2) || (word & 3) == SA_UPDATING) return -1;
        int expired = ss_interval_expired(flow, now);
        ss_flow_record(flow, word, out);
        if (touch && !expired) ss_touch(flow, now);
        /* Допуск первого пакета мог завершиться во время копирования. */
        if (word != sa_read(&flow->publication)) continue;
        return expired ? 2 : 1;
    }
    return -1;
}
/* Истекший принятый UDP становится новым интервалом только через GC claim. */
static __always_inline int ss_end_interval(struct ss_flow *flow, __u64 word, __u64 now) {
    if (flow->key.protocol == 6 || (word & 3) != SA_ADMITTED ||
        !ss_interval_expired(flow, now) || !sa_gc_claim(&flow->publication, word)) return 0;
    __u64 seen = sa_read(&flow->last_seen);
    int expired = now >= seen && now - seen >= SS_IDLE_NS;
    __u64 next = expired ? (word & ~3ULL) | SA_RETIRED : word;
    if (__sync_val_compare_and_swap(&flow->publication, (word & ~3ULL) | SA_UPDATING, next) !=
        ((word & ~3ULL) | SA_UPDATING)) return 0;
    return expired;
}
/* Все payload writers используют один claim, независимо от владения RB wrapper. */
static __always_inline int ss_update_node(struct ss_flow *flow, const struct ss_request *request,
                                          const struct cached_route *proposed) {
    __u64 word = sa_read(&flow->publication);
    if (!(word >> 2) || (word & 3) == SA_UPDATING) return -1;
    int same = request->expected_id == (word >> 2);
    int expired = ss_interval_expired(flow, request->now);
    if (request->confirm == 3 && same && !expired && route_choice_equal(proposed, &flow->route)) {
        if (!sa_admit(&flow->publication, word)) return -1;
        word |= SA_ADMITTED;
    }
    if (request->confirm == 2 && same && (word & 3) == SA_PREPARED &&
        route_choice_equal(proposed, &flow->route)) {
        if (!sa_retire(&flow->publication, word)) return -1;
        word = (word & ~3ULL) | SA_RETIRED;
        expired = 1;
    }
    if (request->renew && same && expired && (word & 3) == SA_ADMITTED) {
        if (!ss_end_interval(flow, word, request->now)) return -1;
        word = (word & ~3ULL) | SA_RETIRED;
    }
    int renew = request->renew && same && expired;
    int bind = same && (word & 3) == SA_PREPARED &&
        ((request->set_device && (flow->route.system_device != request->system_device ||
          flow->source_port != request->source_port || __builtin_memcmp(flow->system_source, request->system_source, 16))) ||
         (request->network_generation && !flow->route.network_generation) ||
         (request->parent_id && (flow->parent_id != request->parent_id ||
           flow->parent_epoch != request->parent_epoch || flow->parent_cookie != request->parent_cookie)));
    if (renew || bind) {
        /* Принятый UDP интервал завершает только GC; refresh не меняет ADMITTED. */
        if ((word & 3) == SA_ADMITTED || !request->new_id || request->new_id <= (word >> 2) ||
            !sa_claim(&flow->publication, word)) return -1;
        if (renew) ss_copy_route(&flow->route, proposed);
        if (request->network_generation && !flow->route.network_generation)
            flow->route.network_generation = request->network_generation;
        if (request->set_device && flow->route.decision.action == 0) {
            flow->route.system_device = request->system_device;
            flow->source_port = request->source_port;
            __builtin_memcpy(flow->system_source, request->system_source, 16);
        }
        if (request->parent_id) {
            flow->parent_id = request->parent_id;
            flow->parent_epoch = request->parent_epoch;
            flow->parent_cookie = request->parent_cookie;
        }
        flow->id = request->new_id;
        ss_touch(flow, request->now);
        if (!sa_publish(&flow->publication, word, request->new_id)) return -1;
        expired = 0;
    }
    if (!expired && !request->no_touch) ss_touch(flow, request->now);
    return expired ? 2 : 1;
}
static bool ss_less(struct bpf_rb_node *left, const struct bpf_rb_node *right) {
    struct ss_node *candidate = container_of(left, struct ss_node, link);
    struct ss_node *existing = container_of(right, struct ss_node, link);
    return ss_key_order(&candidate->key, &existing->key) < 0;
}
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

static __always_inline void ss_drop_node(struct bpf_rb_node *node) {
    if (node)
        bpf_obj_drop_impl(container_of(node, struct ss_node, link), 0);
}

static __noinline struct ss_node *ss_wrapper_acquire(struct ss_table *table, const struct flow_key *key) {
    bpf_spin_lock(&table->lock);
    struct ss_node *node = ss_find_locked(table, key);
    struct ss_node *owned = node ? bpf_refcount_acquire_impl(node, 0) : 0;
    bpf_spin_unlock(&table->lock);
    return owned;
}
/* Heap kptr читается передачей владения, никогда прямым load. Slot NULL означает BUSY. */
static __always_inline struct ss_flow *ss_payload_acquire(struct ss_node *wrapper) {
    struct ss_flow *owner = bpf_kptr_xchg(&wrapper->flow, 0);
    if (!owner) return 0;
    struct ss_flow *owned = bpf_refcount_acquire_impl(owner, 0);
    struct ss_flow *unexpected = bpf_kptr_xchg(&wrapper->flow, owner);
    if (unexpected) bpf_obj_drop_impl(unexpected, 0);
    return owned;
}
static __noinline struct ss_flow *ss_find_acquire(struct ss_table *table, const struct flow_key *key) {
    struct ss_node *wrapper = ss_wrapper_acquire(table, key);
    if (!wrapper) return 0;
    struct ss_flow *flow = ss_payload_acquire(wrapper);
    bpf_obj_drop_impl(wrapper, 0);
    return flow;
}
static __noinline int ss_read(struct ss_table *table, const struct flow_key *key,
                               struct ss_record *out, int touch) {
    struct ss_node *wrapper = ss_wrapper_acquire(table, key);
    if (!wrapper) return 0;
    struct ss_flow *flow = ss_payload_acquire(wrapper);
    bpf_obj_drop_impl(wrapper, 0);
    if (!flow) return -1;
    int result = flow->epoch == table->epoch ? ss_flow_read(flow, out, touch) : -1;
    bpf_obj_drop_impl(flow, 0);
    return result;
}
static __always_inline __u64 ss_reserve_id(struct ss_lifetime *token, __u64 cookie, __u64 epoch) {
    return token && token->alive && token->cookie == cookie && token->epoch == epoch ?
        sa_next_id(&token->next_id) : 0;
}
static __noinline int ss_lookup(struct ss_state *state, struct ss_table *table,
                                 const struct flow_key *key, const struct ss_request *request,
                                 struct ss_record *out) {
    struct ss_flow *flow = ss_find_acquire(table, key);
    if (!flow) return 0;
    bpf_rcu_read_lock();
    struct ss_flow *scratch = state->query;
    scratch = scratch ? bpf_refcount_acquire_impl(scratch, 0) : 0;
    struct ss_lifetime *token = state->lifetime;
    token = token ? bpf_refcount_acquire_impl(token, 0) : 0;
    bpf_rcu_read_unlock();
    int result = -1;
    if (!scratch || !token || !token->alive || token->cookie != key->cookie ||
        token->epoch != table->epoch || flow->epoch != table->epoch || scratch->epoch != table->epoch)
        goto done;
    /* query сериализуется table lock, но payload claim защищает от tracing/NF. */
    __u64 now = SS_NOW();
    bpf_spin_lock(&table->lock);
    ss_copy_request(&scratch->request, request);
    scratch->request.now = now;
    if (request->renew || request->set_device || request->network_generation || request->parent_id)
        scratch->request.new_id = ss_reserve_id(token, key->cookie, table->epoch);
    result = ss_update_node(flow, &scratch->request, &out->route);
    bpf_spin_unlock(&table->lock);
    if (result > 0) result = ss_flow_read(flow, out, 0);
done:
    if (scratch) bpf_obj_drop_impl(scratch, 0);
    if (token) bpf_obj_drop_impl(token, 0);
    bpf_obj_drop_impl(flow, 0);
    return result;
}
static __noinline int ss_confirmation(struct ss_state *state, const struct flow_key *key,
                                      const struct cached_route *route, __u64 epoch, __u64 tag) {
    struct ss_table *table = ss_table_acquire(state);
    if (!table)
        return -1;
    struct confirmation_work { struct ss_request request; struct ss_record current; };
#ifdef __BPF__
    /* Выбор правила уже завершен, временные данные занимают свободный path buffer. */
    struct working_buffer *buffer = scratch_acquire();
    if (!buffer) { bpf_obj_drop_impl(table, 0); return -1; }
    _Static_assert(sizeof(struct confirmation_work) <= sizeof(buffer->path), "confirmation scratch bound");
    struct confirmation_work *work = (void *)&buffer->path;
#else
    struct confirmation_work local;
    struct confirmation_work *work = &local;
#endif
    __builtin_memset(work, 0, sizeof(*work));
    __u64 id = tag >> 2;
    work->request.no_touch = 1;
    work->request.confirm = tag & 3;
    work->request.expected_id = id;
    ss_copy_route(&work->current.route, route);
    int found = -1;
    if (table->epoch == epoch) {
#ifdef AP_BINDING_SNAPSHOT
        found = (tag & 3) == 1 ? ss_read(table, key, &work->current, 0)
                               : ss_lookup(state, table, key, &work->request, &work->current);
#else
        found = ss_lookup(state, table, key, &work->request, &work->current);
#endif
    }
    bpf_obj_drop_impl(table, 0);
    int result = found == 1 && work->current.id == id && route_choice_equal(&work->current.route, route) &&
                 ((tag & 3) != 3 || work->current.admitted) ? 0 : -1;
#ifdef __BPF__
    scratch_release(buffer);
#endif
    return result;
}

static __always_inline int ss_prepare(struct ss_state *state, const struct flow_key *key,
                                      const struct cached_route *route, __u64 epoch, __u64 id) {
    return ss_confirmation(state, key, route, epoch, (id << 2) | 1);
}

static __always_inline struct ss_node *ss_wrap(struct ss_flow *flow) {
    struct ss_node *node = bpf_obj_new_impl(bpf_core_type_id_local(struct ss_node), 0);
    if (!node) return 0;
    struct ss_flow *owned = bpf_refcount_acquire_impl(flow, 0);
    if (!owned) { bpf_obj_drop_impl(node, 0); return 0; }
    ss_copy_key(&node->key, &flow->key);
    owned = bpf_kptr_xchg(&node->flow, owned);
    if (owned) bpf_obj_drop_impl(owned, 0);
    return node;
}

static __noinline int ss_freeze(struct ss_lifetime *token, struct ss_table *table, const struct flow_key *key,
                                const struct cached_route *proposed, struct ss_record *out) {
    struct ss_flow *flow = ss_new_query(table->epoch);
    if (!flow) return -1;
    ss_copy_key(&flow->key, key);
    ss_copy_route(&flow->route, proposed);
    flow->last_seen = SS_NOW();
    flow->id = ss_reserve_id(token, key->cookie, table->epoch);
    if (!flow->id) { bpf_obj_drop_impl(flow, 0); return -1; }
    flow->publication = flow->id << 2;
    struct ss_node *candidate = ss_wrap(flow);
    if (!candidate) { bpf_obj_drop_impl(flow, 0); return -1; }
    int result = 0;
    struct ss_node *unused = candidate;
    struct ss_flow *existing = 0;
    struct ss_node *existing_wrapper = 0;
    bpf_spin_lock(&table->lock);
    struct ss_node *node = ss_find_locked(table, key);
    if (node) {
        existing_wrapper = bpf_refcount_acquire_impl(node, 0);
        result = existing_wrapper ? 0 : -1;
    } else if (table->count >= SS_FLOW_LIMIT) result = -1;
    else {
        /* Fresh PREP опубликован лишь после полного payload и wrapper kptr. */
        result = ss_add(table, candidate, table->active);
        unused = 0;
        if (!result) table->count++;
    }
    bpf_spin_unlock(&table->lock);
    if (unused) bpf_obj_drop_impl(unused, 0);
    if (existing_wrapper) {
        existing = ss_payload_acquire(existing_wrapper);
        bpf_obj_drop_impl(existing_wrapper, 0);
        if (!existing) result = -1;
    }
    if (!result) {
        int read = ss_flow_read(existing ? existing : flow, out, 1);
        result = read == 1 ? 0 : read == 2 ? 2 : -1;
    }
    if (existing) bpf_obj_drop_impl(existing, 0);
    bpf_obj_drop_impl(flow, 0);
    return result;
}

static __always_inline int ss_freeze_for(struct ss_state *state, struct ss_table *table,
                                          const struct flow_key *key, const struct cached_route *route,
                                          struct ss_record *out) {
    struct ss_lifetime *token = ss_lifetime_acquire(state, key->cookie, table->epoch);
    if (!token) return -1;
    int result = ss_freeze(token, table, key, route, out);
    bpf_obj_drop_impl(token, 0);
    return result;
}

/* Direct handle создается вне tracing до любого выхода с первым TCP пакетом. */
static __always_inline int ss_install_tcp(struct ss_state *state, struct ss_flow *source,
                                            const struct flow_key *key, const struct ss_record *record) {
    if (key->protocol != 6) return 0;
    struct ss_flow *flow = bpf_refcount_acquire_impl(source, 0);
    if (!flow) return -1;
    __u64 epoch = source->epoch;
    struct ss_lifetime *token = state->lifetime;
    __u64 word = sa_read(&flow->publication);
    if (!token || !token->alive || token->cookie != key->cookie || token->epoch != epoch ||
        flow->epoch != epoch || (word >> 2) != record->id || !sa_stable(word) ||
        !route_choice_equal(&flow->route, &record->route) || word != sa_read(&flow->publication)) {
        bpf_obj_drop_impl(flow, 0);
        return -1;
    }
    flow = bpf_kptr_xchg(&state->direct_flow, flow);
    if (flow) bpf_obj_drop_impl(flow, 0);
    return 0;
}

static __noinline int ss_publish_tcp(struct ss_state *state, const struct flow_key *key,
                                      const struct ss_record *record, __u64 epoch) {
    if (key->protocol != 6) return 0;
    struct ss_table *table = ss_table_acquire(state);
    if (!table) return -1;
    struct ss_flow *flow = table->epoch == epoch ? ss_find_acquire(table, key) : 0;
    bpf_obj_drop_impl(table, 0);
    if (!flow) return -1;
    int result = ss_install_tcp(state, flow, key, record);
    bpf_obj_drop_impl(flow, 0);
    return result;
}

static __noinline int ss_link_logical(struct ss_state *child, struct ss_state *parent) {
    struct ss_flow *flow = parent->direct_flow;
    struct ss_lifetime *token = parent->lifetime;
    flow = flow ? bpf_refcount_acquire_impl(flow, 0) : 0;
    token = token ? bpf_refcount_acquire_impl(token, 0) : 0;
    if (!flow || !token || !token->alive || token->cookie != parent->cookie ||
        flow->epoch != token->epoch || ss_key_order(&flow->key, &parent->stream_peer) ||
        parent->stream_peer_state != 2) {
        if (flow) bpf_obj_drop_impl(flow, 0);
        if (token) bpf_obj_drop_impl(token, 0);
        return -1;
    }
    ss_copy_key(&child->logical_key, &parent->stream_peer);
    child->logical_cookie = parent->cookie;
    flow = bpf_kptr_xchg(&child->logical_node, flow);
    token = bpf_kptr_xchg(&child->logical_lifetime, token);
    if (flow) bpf_obj_drop_impl(flow, 0);
    if (token) bpf_obj_drop_impl(token, 0);
    return 0;
}
static __always_inline int ss_logical_admitted(struct ss_state *state, const struct ss_record *record) {
    struct ss_flow *parent = state->logical_node;
    struct ss_lifetime *token = state->logical_lifetime;
    if (!record->parent_id || !parent || !token || !token->alive ||
        token->cookie != state->logical_cookie || token->cookie != record->parent_cookie ||
        token->epoch != record->parent_epoch || parent->epoch != token->epoch) return 0;
    __u64 word = sa_read(&parent->publication);
    return word == ((record->parent_id << 2) | SA_ADMITTED) &&
           route_choice_equal(&parent->route, &record->route) && word == sa_read(&parent->publication);
}

/* Payload старого сокета уже авторитетен: добавление индекса его не меняет. */
static __noinline int ss_adopt_preserved_graph(struct ss_state *state) {
    if (__sync_val_compare_and_swap(&state->kind, SS_PRESERVED, SS_INITIALIZING) != SS_PRESERVED)
        return -1;
    struct ss_lifetime *token = state->lifetime;
    struct ss_flow *flow = state->direct_flow;
    token = token ? bpf_refcount_acquire_impl(token, 0) : 0;
    flow = flow ? bpf_refcount_acquire_impl(flow, 0) : 0;
    struct ss_table *table = 0;
    struct ss_flow *query = 0;
    int error = -1;
    if (!token || !flow || !token->alive || token->cookie != state->cookie ||
        flow->epoch != token->epoch || flow->key.cookie != token->cookie || !sa_stable(sa_read(&flow->publication)))
        goto done;
    table = ss_new_table(token->epoch);
    query = ss_new_query(token->epoch);
    if (!table || !query) goto done;
    struct ss_node *wrapper = ss_wrap(flow);
    if (!wrapper) goto done;
    bpf_spin_lock(&table->lock);
    error = ss_add(table, wrapper, 0);
    if (!error) table->count = 1;
    bpf_spin_unlock(&table->lock);
    if (error) goto done;
    table = bpf_kptr_xchg(&state->table, table);
    query = bpf_kptr_xchg(&state->query, query);
done:
    if (table) bpf_obj_drop_impl(table, 0);
    if (query) bpf_obj_drop_impl(query, 0);
    if (flow) bpf_obj_drop_impl(flow, 0);
    if (token) bpf_obj_drop_impl(token, 0);
    __sync_lock_test_and_set(&state->kind, SS_PRESERVED);
    return error;
}

/* Только прежний неизвестный TCP: missing classified proof не дает этот режим. */
static __noinline struct ss_state *ss_bootstrap_preserved(void *socket, const struct flow_key *key,
                                                          const struct ss_request *request) {
    struct ss_state *state = bpf_sk_storage_get(&socket_states, socket, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!state || !key->cookie || key->protocol != 6) return 0;
    __u32 kind = state->kind;
    if ((kind != SS_EMPTY && kind != SS_PRESERVED) || state->known_creator ||
        (state->cookie && state->cookie != key->cookie) || state->lifetime || state->direct_flow ||
        state->table || state->query || __sync_val_compare_and_swap(&state->kind, kind, SS_INITIALIZING) != kind)
        return 0;
    struct ss_lifetime *token = ss_new_lifetime(key->cookie, 0);
    struct ss_flow *flow = ss_new_query(0);
    if (!token || !flow || ss_copy_companion(socket, 0)) {
        if (token) bpf_obj_drop_impl(token, 0);
        if (flow) bpf_obj_drop_impl(flow, 0);
        __sync_lock_test_and_set(&state->kind, kind);
        return 0;
    }
    state->cookie = key->cookie;
    flow->id = sa_next_id(&token->next_id);
    ss_copy_key(&flow->key, key);
    flow->route.decision.rule = AP_NO_RULE;
    flow->route.system_device = request->system_device;
    flow->source_port = request->source_port;
    __builtin_memcpy(flow->system_source, request->system_source, 16);
    flow->last_seen = SS_NOW();
    flow->publication = flow->id << 2;
    token = bpf_kptr_xchg(&state->lifetime, token);
    flow = bpf_kptr_xchg(&state->direct_flow, flow);
    if (token) bpf_obj_drop_impl(token, 0);
    if (flow) bpf_obj_drop_impl(flow, 0);
    __sync_lock_test_and_set(&state->kind, SS_PRESERVED);
    return state;
}

static __noinline void ss_collect(struct ss_state *state, struct ss_table *table, int force) {
    if (__sync_val_compare_and_swap(&table->gc_busy, 0, 1)) return;
    __u64 now = SS_NOW();
    int sweep = 1;
    bpf_spin_lock(&table->lock);
    struct bpf_rb_node *first = table->active ? bpf_rbtree_first(&table->flows)
                                             : bpf_rbtree_first(&table->other_flows);
    if (!first) {
        if (!table->count || (!force && now < table->next_sweep)) sweep = 0;
        else table->active = !table->active;
        table->next_sweep = now + SS_SWEEP_NS;
    }
    bpf_spin_unlock(&table->lock);
#ifdef __BPF__
    if (sweep) AP_FOR(step, 8) {
#else
    if (sweep) for (unsigned step = 0; step < 8; step++) {
#endif
        struct ss_node *held = 0;
        bpf_spin_lock(&table->lock);
        struct bpf_rb_node *link = table->active ? bpf_rbtree_first(&table->flows)
                                                 : bpf_rbtree_first(&table->other_flows);
        if (link) held = bpf_refcount_acquire_impl(container_of(link, struct ss_node, link), 0);
        bpf_spin_unlock(&table->lock);
        if (!held) break;
        struct ss_flow *flow = ss_payload_acquire(held);
        if (!flow) { bpf_obj_drop_impl(held, 0); break; }
        int expired = 0;
        if (flow->key.protocol != 6) {
            __u64 word = sa_read(&flow->publication);
            if (ss_interval_expired(flow, now) && sa_gc_claim(&flow->publication, word)) {
                __u64 seen = sa_read(&flow->last_seen);
                expired = (word & 3) == SA_RETIRED || flow->route.decision.action == 1 ||
                          (now >= seen && now - seen >= SS_IDLE_NS);
                if (!sa_gc_finish(&flow->publication, word, expired)) expired = 0;
            }
        }
        struct bpf_rb_node *removed = 0;
        bpf_spin_lock(&table->lock);
        struct ss_node *current = ss_find_locked(table, &held->key);
        if (current == held) {
            removed = ss_remove(table, held, !table->active);
            if (removed && !expired) {
                struct ss_node *moving = container_of(removed, struct ss_node, link);
                if (ss_add(table, moving, table->active) && table->count) table->count--;
                removed = 0;
            } else if (removed && table->count) table->count--;
        }
        bpf_spin_unlock(&table->lock);
        ss_drop_node(removed);
        if (expired) {
            struct flow_key retiring;
            ss_copy_key(&retiring, &held->key);
            SS_AFTER_COLLECT_MOVE(state, table, &retiring);
            (void)SS_RETIRE_FLOW(&retiring, table->epoch, flow->id);
        }
        bpf_obj_drop_impl(flow, 0);
        bpf_obj_drop_impl(held, 0);
    }
    __sync_lock_test_and_set(&table->gc_busy, 0);
}
