#pragma once
struct request_sock {
    struct sock_common __req_common;
} __attribute__((preserve_access_index));
struct sk_buff;
#ifdef AP_BINDING_SNAPSHOT
static __noinline int request_interface_allowed(struct sk_buff *packet, struct sock *socket);
#endif
static __noinline void route_accept(struct sock *sock, const struct request_sock *request);

struct ar_work {
    __u32 busy, reserved;
    struct flow_key key, owner_key;
    struct ss_request request;
    struct ar_record resolved;
    struct ar_record logical;
    __u64 logical_cookie;
    struct tcp_tuple tuple;
    struct ar_resolution_work resolution;
    struct cc_snapshot cached;
    struct ct_snapshot connection;
    __u64 empty_connection[sizeof(struct ct_entry) / sizeof(__u64)];
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, struct ar_work);
} route_work SEC(".maps");

SEC("cgroup/sock_create") int route_socket(struct bpf_sock *sock) {
    if (sock->family != 2 && sock->family != 10)
        return 1;
    struct task_capture *capture =
        bpf_task_storage_get(&processes, bpf_get_current_task_btf(), 0, 0);
    return capture && ss_initialize(sock, &capture->committed, SS_CLASSIFIED,
                                    task_companion(bpf_get_current_task_btf(), 0)) ? 1 : 0;
}

#ifdef AP_BINDING_SNAPSHOT
static __always_inline void lookup_adopt_cloned_frame(struct exec_frame *frame, int valid) {
    __u64 original = frame->lookup;
    __u64 id = valid ? lookup_acquire(original) : 0;
    frame->lookup = id;
    if (original && !id) frame->source.path_flags = 0;
}
/* Kernel копирует id как данные; новая socket-копия удерживает отдельные ссылки. */
SEC("fexit/sk_clone")
int BPF_PROG(lookup_socket_clone, const struct sock *source, unsigned priority, bool lock, struct sock *target) {
    (void)ctx; (void)source; (void)priority; (void)lock;
    if (!target) return 0;
    struct ss_state *child = bpf_sk_storage_get(&socket_states, target, 0, 0);
    struct process_companion *mate = bpf_sk_storage_get(&socket_companions, target, 0, 0);
    if (child) {
        lookup_adopt_cloned_frame(&child->creator.self, 1);
        AP_FOR(index, AP_PARENT_LIMIT) {
            lookup_adopt_cloned_frame(&child->creator.parents[index].parent, 1);
        }
        child->cookie = bpf_get_socket_cookie(target);
        if (!child->cookie) lookup_state_clear(&child->creator);
    }
    if (mate) {
        AP_FOR(index, AP_PARENT_LIMIT) { lookup_adopt_cloned_frame(&mate->carried[index], child != 0); }
        if (child && !child->cookie) lookup_companion_clear(mate);
        if (!child) { mate->snapshot_identity = 0; mate->available = 0; }
    }
    return 0;
}
#endif

SEC("lsm/inet_csk_clone")
int BPF_PROG(route_clone, struct sock *sock, const struct request_sock *request) {
    (void)ctx;
    route_accept(sock, request);
    return 0;
}



SEC("fentry/sk_destruct") int BPF_PROG(route_free, struct sock *sock) {
    (void)ctx;
    __u64 cookie = BPF_CORE_READ(sock, __sk_common.skc_cookie.counter);
    bpf_map_delete_elem(&transport_sockets, &cookie);
    bpf_map_delete_elem(&dns_sockets, &cookie);
    dns_listener_closed(cookie);
    ss_mark_closed(sock);
#ifdef AP_BINDING_SNAPSHOT
    struct ss_state *state = bpf_sk_storage_get(&socket_states, sock, 0, 0);
    struct process_companion *mate = bpf_sk_storage_get(&socket_companions, sock, 0, 0);
    /* Ошибка sk_clone оставляет сырые id родителя без новых владельцев. */
    if (state && cookie && state->cookie == cookie) {
        lookup_state_clear(&state->creator);
        lookup_companion_clear(mate);
    }
    struct process_state *saved = bpf_map_lookup_elem(&routing_subjects, &cookie);
    struct process_companion *saved_mate = bpf_map_lookup_elem(&routing_companions, &cookie);
    lookup_state_clear(saved);
    lookup_companion_clear(saved_mate);
#endif
    bpf_map_delete_elem(&routing_subjects, &cookie);
    bpf_map_delete_elem(&routing_companions, &cookie);
    return 0;
}

static __always_inline struct ar_work *route_slot(__u32 slot) {
    struct ar_work *work = bpf_map_lookup_elem(&route_work, &slot);
    return work && !__sync_val_compare_and_swap(&work->busy, 0, 1) ? work : 0;
}
static __always_inline struct ar_work *route_begin(struct ss_state *state, void *socket) {
    struct ar_work *work = route_slot(0);
    if (!work)
        work = route_slot(1);
    if (!work)
        work = route_slot(2);
    if (!work)
        work = route_slot(3);
    if (!work)
        return 0;
    struct flow_key empty = {};
    ss_copy_key(&work->key, &empty);
    ss_clear_request(&work->request);
#ifndef AP_BINDING_SNAPSHOT
    const struct process_companion *companion = socket ?
        bpf_sk_storage_get(&socket_companions, socket, 0, 0) : 0;
    if (!companion || !state || !state->creator.snapshot_identity ||
        companion->snapshot_identity != state->creator.snapshot_identity) {
        work->resolution.companion.snapshot_identity = 0;
        work->resolution.companion.available = 0;
    } else if (work->resolution.companion.snapshot_identity != companion->snapshot_identity) {
        copy_process_companion(&work->resolution.companion, companion);
    }
#else
    (void)socket;
#endif
    work->resolution.incoming = 0;
    work->resolution.retry_rejected = 0;
    work->resolution.proposal_ready = 0;
    work->resolution.publish = 0;
    work->logical_cookie = 0;
    work->key.cookie = state ? state->cookie : 0;
    return work;
}
/* Снимок принадлежит сокету; per-CPU scratch не удерживает его ссылки. */
static __always_inline const struct process_companion *
route_companion(const struct ss_state *state, void *socket) {
    const struct process_companion *companion = socket ?
        bpf_sk_storage_get(&socket_companions, socket, 0, 0) : 0;
    return state && process_pair_valid(&state->creator, companion) ? companion : 0;
}
static __always_inline int route_evaluate(struct ss_state *state, struct ar_work *work,
                                          int restart, const struct process_companion *companion) {
    int result = restart ? ss_restart_tcp(state) : 0;
#ifdef AP_BINDING_SNAPSHOT
    work->resolution.publish = 1;
#endif
    if (!result)
        result = ar_resolve(state, &work->key, &work->request, &work->resolved, &work->resolution, companion);
#ifdef AP_BINDING_SNAPSHOT
    work->resolution.publish = 0;
#else
    if (!result)
        result = ar_publish(state, &work->key, &work->resolved, &work->resolution.companion);
#endif
    return result;
}
static __always_inline int route_finish(struct ss_state *state, struct ar_work *work, int restart,
                                         const struct process_companion *companion) {
    int result = route_evaluate(state, work, restart, companion);
    int action = result ? 1 : ar_result(&work->resolved.flow.route, work->key.family);
    __sync_lock_test_and_set(&work->busy, 0);
    return action;
}
/* Адрес ребенка до clone берется только из настоящего request. */
static __always_inline int request_key(const struct request_sock *request, struct flow_key *key) {
    unsigned family = BPF_CORE_READ(request, __req_common.skc_family);
    key->protocol = 6;
    key->port = __builtin_bswap16(BPF_CORE_READ(request, __req_common.skc_dport));
    if (family == 2) {
        key->family = 4;
        __u32 address = BPF_CORE_READ(request, __req_common.skc_daddr);
        __builtin_memcpy(key->destination, &address, 4);
    } else if (family == 10) {
        key->family = 6;
        BPF_CORE_READ_INTO(&key->destination, request, __req_common.skc_v6_daddr);
        __u8 *bytes = key->destination;
        __u32 *words = (void *)bytes;
        if (!words[0] && !words[1] && !bytes[8] && !bytes[9] && bytes[10] == 255 &&
            bytes[11] == 255) {
            __u32 address = words[3];
            __builtin_memset(bytes, 0, 16);
            __builtin_memcpy(bytes, &address, 4);
            key->family = 4;
        }
    } else
        return -1;
    return 0;
}

#ifdef AP_BINDING_SNAPSHOT
struct request_route {
    struct cached_route route;
    struct flow_key key;
    __u64 epoch, id, creator;
    struct ss_lifetime __kptr *lifetime;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, AR_CACHE_LIMIT);
    __type(key, __u64);
    __type(value, struct request_route);
} request_routes SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, AR_CACHE_LIMIT);
    __type(key, struct flow_key);
    __type(value, __u64);
} request_peers SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} request_ids SEC(".maps");

static __always_inline int request_live(const struct request_route *proof) {
    bpf_rcu_read_lock();
    struct ss_lifetime *token = proof->lifetime;
    int valid = token && token->alive && token->cookie == proof->key.cookie &&
                token->epoch == proof->epoch && proof->id && proof->id <= SS_ID_LIMIT;
    bpf_rcu_read_unlock();
    return valid;
}

static __always_inline int request_peer_admitted(const struct flow_key *key) {
    __u64 *address = bpf_map_lookup_elem(&request_peers, key);
    const struct request_route *proof = address ? bpf_map_lookup_elem(&request_routes, address) : 0;
    return proof && request_live(proof) && proof->key.cookie == key->cookie;
}

static __noinline int request_inherit(struct ss_state *state, const struct request_sock *request,
                                       struct ar_work *work, const struct process_companion *companion) {
    __u64 key = (unsigned long)request;
    const struct request_route *proof = bpf_map_lookup_elem(&request_routes, &key);
    if (!proof || !request_live(proof) || proof->creator != state->creator.snapshot_identity ||
        proof->key.family != work->key.family || proof->key.port != work->key.port)
        return -1;
    for (unsigned i = 0; i < 16; i++)
        if (proof->key.destination[i] != work->key.destination[i])
            return -1;
    struct ss_table *table = ss_table_acquire(state);
    if (!table)
        return -1;
    work->resolved.epoch = table->epoch;
    int failed = ss_freeze_for(state, table, &work->key, &proof->route, &work->resolved.flow);
    bpf_obj_drop_impl(table, 0);
    if (failed || ss_confirmation(state, &work->key, &work->resolved.flow.route,
                                  work->resolved.epoch, (work->resolved.flow.id << 2) | 3))
        return -1;
    work->resolved.flow.admitted = 1;
    return ar_publish(state, &work->key, &work->resolved, companion);
}
#endif

static __noinline void route_accept(struct sock *sock, const struct request_sock *request) {
    struct ss_state *state = ss_adopt_clone(sock);
    if (!state || !request)
        return;
    struct ar_work *work = route_begin(state, sock);
    if (!work)
        return;
    if (!request_key(request, &work->key)) {
#ifdef AP_BINDING_SNAPSHOT
        if (!request_inherit(state, request, work, route_companion(state, sock))) {
            __sync_lock_test_and_set(&work->busy, 0);
            return;
        }
#endif
        route_finish(state, work, 0, route_companion(state, sock));
    } else
        __sync_lock_test_and_set(&work->busy, 0);
}

struct tcp_sock___mp {
    __u8 is_mptcp : 1;
} __attribute__((preserve_access_index));
struct inet_connection_sock___mp {
    void *icsk_ulp_data;
} __attribute__((preserve_access_index));
struct mptcp_subflow_context {
    struct sock *conn;
} __attribute__((preserve_access_index));

#ifdef AP_BINDING_SNAPSHOT
/* Временная запись запроса не занимает стек во время поиска правила. */
static __noinline int request_remember(struct ss_state *state, struct ar_work *work,
                                      struct request_sock *request) {
    __u32 zero = 0;
    __u64 *counter = bpf_map_lookup_elem(&request_ids, &zero);
    if (!counter)
        return -1;
    __u64 id = 0;
    for (unsigned i = 0; i < 3; i++) {
        __u64 previous = __sync_fetch_and_add(counter, 0);
        if (previous >= SS_ID_LIMIT)
            break;
        if (__sync_val_compare_and_swap(counter, previous, previous + 1) == previous) {
            id = previous + 1;
            break;
        }
    }
    if (!id)
        return -1;
    struct ss_table *table = ss_table_acquire(state);
    if (!table)
        return -1;
    __u64 epoch = table->epoch;
    bpf_obj_drop_impl(table, 0);
    struct ss_lifetime *token = ss_lifetime_acquire(state, state->cookie, epoch);
    if (!token)
        return -1;
    struct request_route value = {.key = work->key, .epoch = epoch, .id = id,
                                   .creator = state->creator.snapshot_identity};
    ss_copy_route(&value.route, &work->resolution.proposed);
    __u64 address = (unsigned long)request;
    int inserted = !bpf_map_update_elem(&request_routes, &address, &value, BPF_NOEXIST);
    struct request_route *entry = bpf_map_lookup_elem(&request_routes, &address);
    if (!inserted || !entry) {
        bpf_obj_drop_impl(token, 0);
        return -1;
    }
    struct ss_lifetime *old = bpf_kptr_xchg(&entry->lifetime, token);
    if (old)
        bpf_obj_drop_impl(old, 0);
    if (bpf_map_update_elem(&request_peers, &work->key, &address, BPF_NOEXIST)) {
        bpf_map_delete_elem(&request_routes, &address);
        return -1;
    }
    return 0;
}
#endif

SEC("lsm/inet_conn_request")
int BPF_PROG(route_request, struct sock *sock, struct sk_buff *packet,
             struct request_sock *request, int ret) {
    (void)ctx;
#ifdef AP_BINDING_SNAPSHOT
    if (ret)
        return ret;
    struct ss_state *state = ss_adopt_clone(sock);
    if (!state || !request_interface_allowed(packet, sock))
        return -1;
    struct ar_work *work = route_begin(state, sock);
    if (!work)
        return -1;
    int allowed = 0;
    if (request_key(request, &work->key))
        goto done;
    __builtin_memset(&work->resolution.proposed, 0, sizeof(work->resolution.proposed));
    if (ar_desired(state, &work->key, &work->resolution.proposed, route_companion(state, sock)) ||
        work->resolution.proposed.decision.action != 0)
        goto done;
    allowed = !request_remember(state, work, request);
done:
    __sync_lock_test_and_set(&work->busy, 0);
    return allowed ? 0 : -1;
#else
    (void)sock;
    (void)packet;
    (void)request;
    return ret;
#endif
}

SEC("fentry/__reqsk_free")
int BPF_PROG(route_request_free, struct request_sock *request) {
    (void)ctx;
#ifdef AP_BINDING_SNAPSHOT
    __u64 address = (unsigned long)request;
    const struct request_route *proof = bpf_map_lookup_elem(&request_routes, &address);
    if (proof) {
        __u64 *owner = bpf_map_lookup_elem(&request_peers, &proof->key);
        if (owner && *owner == address)
            bpf_map_delete_elem(&request_peers, &proof->key);
    }
    bpf_map_delete_elem(&request_routes, &address);
#else
    (void)request;
#endif
    return 0;
}
/* Публикация подпотока выполняется после выбора маршрута логического соединения. */
static __always_inline int route_mptcp_publish(struct bpf_sock_addr *address, struct ss_state *parent,
                                          struct ar_work *work, const struct process_companion *companion) {
#ifdef AP_BINDING_SNAPSHOT
    if (ss_prepare(parent, &work->owner_key, &work->resolved.flow.route,
                   work->resolved.epoch, work->resolved.flow.id) ||
        ss_publish_tcp(parent, &work->owner_key, &work->resolved.flow, work->resolved.epoch))
        return -1;
#endif
    if (ar_result(&work->resolved.flow.route, work->key.family) == 1)
        return -1;
    __u64 parent_id = work->resolved.flow.id;
#ifdef AP_BINDING_SNAPSHOT
    __u64 parent_epoch = work->resolved.epoch;
#endif
    ss_copy_route(&work->resolution.proposed, &work->resolved.flow.route);
    struct ss_state *child =
        ss_initialize_cookie(address->sk, work->key.cookie,
                             parent->kind == SS_CLASSIFIED ? &parent->creator : 0, parent->kind,
                             companion);
    if (!child)
        return -1;
    child->derived_stream = 1;
    child->logical_cookie = parent->cookie;
    if (ss_restart_tcp(child))
        return -1;
#ifdef AP_BINDING_SNAPSHOT
    if (ss_link_logical(child, parent))
        return -1;
#endif
    struct ss_table *table = ss_table_acquire(child);
    if (!table)
        return -1;
    work->resolved.epoch = table->epoch;
    int result = ss_freeze_for(child, table, &work->key, &work->resolution.proposed, &work->resolved.flow);
    bpf_obj_drop_impl(table, 0);
    if (result)
        return -1;
#ifdef AP_BINDING_SNAPSHOT
    work->request.parent_id = parent_id;
    work->request.parent_epoch = parent_epoch;
    work->request.parent_cookie = parent->cookie;
    table = ss_table_acquire(child);
    if (!table) return -1;
    result = ar_bind(child, table, &work->key, &work->request, &work->resolved.flow);
    bpf_obj_drop_impl(table, 0);
    if (result) return -1;
    work->resolved.flow.admitted = ss_logical_admitted(child, &work->resolved.flow);
#else
    (void)parent_id;
#endif
    result = ar_publish(child, &work->key, &work->resolved, companion);
    return result;
}

/* Подпоток наследует решение логического соединения до первого SYN. */
static __always_inline int route_mptcp(struct bpf_sock_addr *address, struct ss_state *parent,
                                  struct ar_work *work, const struct process_companion *companion) {
    if (!parent || (parent->kind != SS_CLASSIFIED && parent->kind != SS_PRESERVED))
        return -1;
    __u32 ready = __sync_val_compare_and_swap(&parent->stream_peer_state, 0, 1);
    if (!ready) {
        ss_copy_key(&parent->stream_peer, &work->key);
        parent->stream_peer.cookie = parent->cookie;
        __sync_lock_test_and_set(&parent->stream_peer_state, 2);
    } else if (ready != 2)
        return -1;
    ss_copy_key(&work->owner_key, &parent->stream_peer);
    if (ar_resolve(parent, &work->owner_key, &work->request, &work->resolved, &work->resolution, companion))
        return -1;
    return route_mptcp_publish(address, parent, work, companion);
}

struct mp_listen_context {
    struct process_state creator;
    __u64 owner, owner_cookie;
    __u32 kind, active;
};
AP_LOCAL_STORAGE_CHECK(mp_listen_context);
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct mp_listen_context);
} mptcp_listeners SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct process_companion);
} mptcp_companions SEC(".maps");
SEC("lsm/socket_listen")
int BPF_PROG(route_mptcp_prepare_listener, struct socket *socket, int backlog, int ret) {
    (void)ctx;
    (void)backlog;
    struct task_struct *task = bpf_get_current_task_btf();
    struct mp_listen_context *work = bpf_task_storage_get(&mptcp_listeners, task, 0, 0);
    if (work)
        work->active = 0;
    if (ret)
        return ret;
    struct sock *sock = socket->sk;
    if (!sock || BPF_CORE_READ(sock, sk_protocol) != 262)
        return 0;
    struct ss_state *state = ss_adopt_clone(sock);
    if (!state)
        return -12;
    if (!work)
        work = bpf_task_storage_get(&mptcp_listeners, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!work)
        return -12;
    struct process_companion *mate =
        bpf_task_storage_get(&mptcp_companions, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    const struct process_companion *source = bpf_sk_storage_get(&socket_companions, sock, 0, 0);
    if (!mate || !source)
        return -12;
    copy_process_companion(mate, source);
    copy_process_state(&work->creator, &state->creator);
    work->owner = (unsigned long)sock;
    work->owner_cookie = state->cookie;
    work->kind = state->kind;
    work->active = 1;
    return 0;
}
/* Личность передается в пределах одного listen, до публикации TCP listen hash. */
SEC("fentry/__inet_listen_sk") int BPF_PROG(route_mptcp_listen, struct sock *sock, int backlog) {
    (void)ctx;
    (void)backlog;
    if (BPF_CORE_READ(sock, sk_protocol) != 6 ||
        !BPF_CORE_READ_BITFIELD_PROBED((struct tcp_sock___mp *)sock, is_mptcp))
        return 0;
    struct mp_listen_context *work =
        bpf_task_storage_get(&mptcp_listeners, bpf_get_current_task_btf(), 0, 0);
    if (!work || !work->active)
        return 0;
    struct mptcp_subflow_context *subflow =
        BPF_CORE_READ((struct inet_connection_sock___mp *)sock, icsk_ulp_data);
    struct sock *owner = subflow ? BPF_CORE_READ(subflow, conn) : 0;
    if (!owner || (unsigned long)owner != work->owner ||
        (__u64)BPF_CORE_READ(owner, __sk_common.skc_cookie.counter) != work->owner_cookie)
        return 0;
    work->active = 0;
    const struct process_companion *mate =
        bpf_task_storage_get(&mptcp_companions, bpf_get_current_task_btf(), 0, 0);
    if (!mate || mate->snapshot_identity != work->creator.snapshot_identity)
        return 0;
    struct ss_state *state =
        ss_identity_cookie(sock, bpf_get_socket_cookie(sock),
                           work->kind == SS_CLASSIFIED ? &work->creator : 0, work->kind, mate);
    if (state)
        state->derived_stream = 1;

    return 0;
}
SEC("fexit/mptcp_listen")
int BPF_PROG(route_mptcp_listen_done, struct socket *socket, int backlog, int result) {
    (void)ctx;
    (void)socket;
    (void)backlog;
    (void)result;
    struct mp_listen_context *work =
        bpf_task_storage_get(&mptcp_listeners, bpf_get_current_task_btf(), 0, 0);
    if (work) {
        work->active = 0;
#ifdef AP_BINDING_SNAPSHOT
        lookup_state_clear(&work->creator);
        struct process_companion *mate = bpf_task_storage_get(&mptcp_companions,
            bpf_get_current_task_btf(), 0, 0);
        lookup_companion_clear(mate);
#endif
    }
    return 0;
}
#ifdef AP_BINDING_SNAPSHOT
/* task_free вызывается до освобождения task storage, включая неудачный fork. */
SEC("lsm/task_free")
int BPF_PROG(release_lookup_task, struct task_struct *task) {
    (void)ctx;
    struct task_capture *capture = bpf_task_storage_get(&processes, task, 0, 0);
    if (capture) {
        lookup_state_clear(&capture->committed);
        lookup_pending_clear(&capture->pending);
    }
    struct process_companion *mate = bpf_task_storage_get(&process_companions, task, 0, 0);
    lookup_companion_clear(mate);
    struct lookup_capture *lookup = bpf_task_storage_get(&lookup_captures, task, 0, 0);
    if (lookup) {
        lookup_clear_ready(lookup);
        lookup_directory_clear(lookup);
        lookup_fs_work_clear(&lookup->pwd_change);
        lookup_fs_work_clear(&lookup->root_change);
        lookup_fs_work_clear(&lookup->fs_copy);
        AP_FOR(index, (int)AP_LOOKUP_OPEN_DEPTH) { lookup_clear_operation(&lookup->operations[index]); }
    }
    struct mp_listen_context *listener = bpf_task_storage_get(&mptcp_listeners, task, 0, 0);
    if (listener) lookup_state_clear(&listener->creator);
    mate = bpf_task_storage_get(&mptcp_companions, task, 0, 0);
    lookup_companion_clear(mate);
    return 0;
}
#endif

struct sockaddr___mp {
    unsigned short family;
} __attribute__((preserve_access_index));
SEC("lsm/socket_connect")
int BPF_PROG(route_mptcp_epoch, struct socket *socket, struct sockaddr___mp *address, int length,
             int ret) {
    (void)ctx;
    if (ret)
        return ret;
    struct sock *sock = socket->sk;
    if (!sock || BPF_CORE_READ(sock, sk_protocol) != 262 ||
        BPF_CORE_READ(sock, __sk_common.skc_state) != 7)
        return 0;
    unsigned short family = 0;
    if (length < 2 || bpf_probe_read_kernel(&family, 2, address) || (family != 2 && family != 10) ||
        length < (family == 2 ? 16 : 28))
        return 0;
    struct ss_state *state = ss_adopt_clone(sock);
    return !state || ss_restart_tcp(state) ? -12 : 0;
}
static __always_inline void route_address_key(struct bpf_sock_addr *address, struct ar_work *work,
                                              int family) {
    work->key.cookie = bpf_get_socket_cookie(address);
    work->key.family = family == 2 ? 4 : 6;
    work->key.protocol = address->protocol;
    work->key.port = __builtin_bswap16((__u16)address->user_port);
    if (family == 2)
        __builtin_memcpy(work->key.destination, &address->user_ip4, 4);
    else {
        __builtin_memcpy(work->key.destination, address->user_ip6, 16);
        __u8 *bytes = work->key.destination;
        if (!address->user_ip6[0] && !address->user_ip6[1] && bytes[8] == 0 && bytes[9] == 0 &&
            bytes[10] == 255 && bytes[11] == 255) {
            __u32 ipv4 = address->user_ip6[3];
            __builtin_memset(work->key.destination, 0, 16);
            __builtin_memcpy(work->key.destination, &ipv4, 4);
            work->key.family = 4;
        }
    }
}
static __noinline int transport_address_guard4(struct bpf_sock_addr *address) {
    __u32 peer[4] = {address->user_ip4, 0, 0, 0};
    return transport_choice(bpf_get_socket_cookie(address), bpf_get_netns_cookie(address),
                            4, address->protocol,
                            __builtin_bswap16((__u16)address->user_port), (const void *)peer, 1);
}
static __noinline int transport_address_guard6(struct bpf_sock_addr *address) {
    __u32 peer[4] = {address->user_ip6[0], address->user_ip6[1],
                     address->user_ip6[2], address->user_ip6[3]};
    return transport_choice(bpf_get_socket_cookie(address), bpf_get_netns_cookie(address),
                            6, address->protocol,
                            __builtin_bswap16((__u16)address->user_port), (const void *)peer, 1);
}
static __always_inline int route_address(struct bpf_sock_addr *address, int family, int restart) {
    int transport = family == 2 ? transport_address_guard4(address) : transport_address_guard6(address);
    if (transport >= 0) return transport == 1;
    struct mptcp_sock *owner = restart ? bpf_skc_to_mptcp_sock(address->sk) : 0;
    if (owner) {
        struct ss_state *parent = bpf_sk_storage_get(&socket_states, owner, 0, 0);
        if (parent) {
            struct ar_work *work = route_begin(parent, owner);
            if (!work)
                return 0;
            route_address_key(address, work, family);
            int result = route_mptcp(address, parent, work, route_companion(parent, owner));
            __sync_lock_test_and_set(&work->busy, 0);
            return result == 0;
        }
        if (BPF_CORE_READ_BITFIELD_PROBED((struct sock *)owner, sk_kern_sock))
            return 0;
    }
    struct ss_state *state = bpf_sk_storage_get(&socket_states, address->sk, 0, 0);
    if (!state)
        state = ss_initialize_cookie(address->sk, bpf_get_socket_cookie(address), 0, SS_PRESERVED, 0);
    if (!state)
        return 0;
    /* Старый логический SYSTEM сохраняет путь и для автономного нового подпотока. */
    if (owner) {
        if (state->kind != SS_PRESERVED)
            return 0;
        state->derived_stream = 1;
    }
    struct ar_work *work = route_begin(state, address->sk);
    if (!work)
        return 0;
    route_address_key(address, work, family);
    work->resolution.retry_rejected = 3;
    return route_finish(state, work, restart && address->protocol == 6,
                        route_companion(state, address->sk)) != 1;
}
SEC("cgroup/connect4") int route_connect4(struct bpf_sock_addr *address) {
    return route_address(address, 2, 1);
}
SEC("cgroup/connect6") int route_connect6(struct bpf_sock_addr *address) {
    return route_address(address, 10, 1);
}
SEC("cgroup/sendmsg4") int route_send4(struct bpf_sock_addr *address) {
    return route_address(address, 2, 0);
}
SEC("cgroup/sendmsg6") int route_send6(struct bpf_sock_addr *address) {
    return route_address(address, 10, 0);
}
struct msghdr___ar {
    void *msg_name;
    int msg_namelen;
} __attribute__((preserve_access_index));
SEC("lsm/socket_sendmsg")
int BPF_PROG(route_before_send, struct socket *socket, struct msghdr___ar *message, int size,
             int ret) {
    (void)ctx;
    (void)size;
    if (ret)
        return ret;
    struct sock *sock = socket->sk;
    if (!sock)
        return 0;
    unsigned family = BPF_CORE_READ(sock, __sk_common.skc_family);
    if (family != 2 && family != 10)
        return 0;
    /* Классификация должна предшествовать собственному отказу sendmsg. */
    ensure_identity();
    struct ss_state *state = ss_adopt_clone(sock);
    if (!state)
        return -12;
    struct ar_work *work = route_begin(state, sock);
    if (!work)
        return -12;
    work->resolution.retry_rejected = 3;
    work->key.protocol = BPF_CORE_READ(sock, sk_protocol);
    if (work->key.protocol == 262)
        work->key.protocol = 6;
    void *name = BPF_CORE_READ(message, msg_name);
    if (name) {
        __u8 address[28] = {};
        int length = BPF_CORE_READ(message, msg_namelen);
        if (length < 8 || bpf_probe_read_kernel(address, length >= 28 ? 28 : 8, name))
            goto skip;
        __u16 address_family;
        __builtin_memcpy(&address_family, address, 2);
        if (address_family == 2) {
            work->key.family = 4;
            __builtin_memcpy(work->key.destination, address + 4, 4);
        } else if (address_family == 10 && length >= 28) {
            work->key.family = 6;
            __builtin_memcpy(work->key.destination, address + 8, 16);
        } else
            goto skip;
        if (work->key.protocol == 6 || work->key.protocol == 17)
            work->key.port = ((__u32)address[2] << 8) | address[3];
    } else {
        work->key.family = family == 2 ? 4 : 6;
        if (family == 2) {
            __u32 ip = BPF_CORE_READ(sock, __sk_common.skc_daddr);
            __builtin_memcpy(work->key.destination, &ip, 4);
        } else
            BPF_CORE_READ_INTO(&work->key.destination, sock, __sk_common.skc_v6_daddr);
        if (work->key.protocol == 6 || work->key.protocol == 17)
            work->key.port = __builtin_bswap16(BPF_CORE_READ(sock, __sk_common.skc_dport));
    }
    if (work->key.family == 6) {
        __u8 *bytes = work->key.destination;
        __u32 *words = (void *)bytes;
        if (!words[0] && !words[1] && !bytes[8] && !bytes[9] && bytes[10] == 255 &&
            bytes[11] == 255) {
            __u32 ipv4 = words[3];
            __builtin_memset(bytes, 0, 16);
            __builtin_memcpy(bytes, &ipv4, 4);
            work->key.family = 4;
        }
    }
    int transport = transport_choice(work->key.cookie, transport_socket_netns(sock), work->key.family,
                                     work->key.protocol, work->key.port, work->key.destination, 1);
    if (transport >= 0) {
        __sync_lock_test_and_set(&work->busy, 0);
        return transport ? 0 : -13;
    }
    if (BPF_CORE_READ(sock, sk_protocol) == 262) {
        /* Логический MPTCP socket не является отправителем TCP-пакета. */
        int result =
            ar_resolve(state, &work->key, &work->request, &work->resolved, &work->resolution,
                       route_companion(state, sock));
        int action = result ? 1 : ar_result(&work->resolved.flow.route, work->key.family);
        __sync_lock_test_and_set(&work->busy, 0);
        return action == 1 ? -13 : 0;
    }
    return route_finish(state, work, 0, route_companion(state, sock)) == 1 ? -13 : 0;
skip:
    __sync_lock_test_and_set(&work->busy, 0);
    return 0;
}
