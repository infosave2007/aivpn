#pragma once
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct ct_entry);
} connection_routes SEC(".maps");
struct nf_conn;
SEC("fentry/nf_conntrack_free") int BPF_PROG(forget_connection, struct nf_conn *connection) {
    (void)ctx;
    __u64 key = (unsigned long)connection;
    bpf_map_delete_elem(&connection_routes, &key);
    return 0;
}
static __always_inline int connection_read(struct ct_entry *entry, struct ct_snapshot *out) {
    if (__sync_val_compare_and_swap(&entry->lock, 0, 1))
        return 0;
    out->data = entry->data;
    out->alive = 0;
    out->udp_options = 0;
    out->reserved = 0;
    struct ss_lifetime *token = entry->lifetime;
    if (!entry->retired && token && token->cookie == out->data.key.cookie &&
        token->epoch == out->data.epoch) {
        out->alive = token->alive;
        out->udp_options = token->udp_options;
    }
    __sync_lock_test_and_set(&entry->lock, 0);
    return 1;
}
/* Для ошибки UDP требуется текущее решение. Данные дополнительно проверяет socket ingress. */
static __always_inline int connection_current(struct ar_work *work, __u32 family, int error) {
    struct ct_snapshot *snapshot = &work->connection;
    struct ct_record *data = &snapshot->data;
    if (!snapshot->alive || data->ambiguous)
        return 0;
#ifdef AP_BINDING_SNAPSHOT
    if (!data->admitted)
        return 0;
#endif
    if (data->key.protocol != 17)
        return 1;
    __u64 now = bpf_ktime_get_ns();
    if (now >= data->last_seen && now - data->last_seen >= SS_IDLE_NS)
        return 0;
    if (error && data->route.decision.action == 2 && snapshot->udp_options != 1)
        return 0;
    int found = ar_read(&data->key, &work->cached);
    if (found < 0)
        return 0;
    if (found && work->cached.alive) {
        return work->cached.epoch == data->epoch && work->cached.id == data->id &&
#ifdef AP_BINDING_SNAPSHOT
               work->cached.admission == 1 &&
#endif
               route_choice_equal(&work->cached.route, &data->route) &&
               work->cached.route.network_generation == data->route.network_generation &&
               ar_result(&work->cached.route, family) == ar_result(&data->route, family);
    }
#ifdef AP_BINDING_SNAPSHOT
    return 0;
#else
    return !error || data->route.decision.action == 0;
#endif
}
#ifdef AP_BINDING_SNAPSHOT
__noinline int observe_connection(struct __sk_buff *packet __arg_ctx, __u64 action,
                                   const struct admission_work *admission __arg_nonnull) {
#else
static __noinline int observe_connection(struct __sk_buff *packet, __u64 action,
                                         const struct admission_work *admission) {
#endif
    /* SYN-ACK listener еще не является принятым child и не создает его flow state. */
    struct bpf_sock *listener = packet->sk;
    if (listener && listener->state == 10)
        return action == 0 &&
               !owned_interface_profile(bpf_get_netns_cookie(packet), packet_device(packet));
    struct sk_buff *internal = bpf_cast_to_kern_ctx(packet);
    __u64 connection = BPF_CORE_READ(internal, _nfct) & ~7ULL;
    if (!connection)
        return action == 0;
    struct ct_entry *entry = bpf_map_lookup_elem(&connection_routes, &connection);
    if (action == 0 && !entry) {
        const struct net_device *device = packet_device(packet);
        if (!owned_interface_profile(bpf_get_netns_cookie(packet), device))
            return 1;
    }
    struct bpf_sock *socket = packet->sk;
    if (!socket)
        return action == 0;
    struct ss_state *state = bpf_sk_storage_get(&socket_states, socket, 0, 0);
    if (!state)
        return action == 0;
    struct ar_work *work = route_begin(state, socket);
    if (!work)
        return action == 0;
    int allowed = action == 0;
#ifdef AP_BINDING_SNAPSHOT
    if (admission->key.protocol == 6 || admission->key.protocol == 17) {
        if (!admission->record.flow.admitted || !admission->record.flow.id) goto done;
        ss_copy_key(&work->key, &admission->key);
        ss_copy_route(&work->cached.route, &admission->record.flow.route);
        work->cached.cookie = admission->key.cookie;
        work->cached.epoch = admission->record.epoch;
        work->cached.id = admission->record.flow.id;
        work->cached.alive = 1;
        work->cached.admission = 1;
    } else {
#endif
    if (packet_key(packet, &work->key, 0, 0) || !work->key.cookie)
        goto done;
    int found;
    if (action >= 2 && work->key.protocol == 17) {
        struct cc_entry *attempt =
            admission ? bpf_map_lookup_elem(&routing_overrides, &admission->key) : 0;
        found = attempt && attempt->epoch == admission->epoch &&
                        cc_read_attempt(attempt, admission->tag, &work->cached)
                    ? 1
                    : -1;
    } else
        found = ar_read(&work->key, &work->cached);
    if (found != 1 || !work->cached.alive) {
        if (action ||
            ar_resolve(state, &work->key, &work->request, &work->resolved, &work->resolution,
                       route_companion(state, socket)))
            goto done;
        ss_copy_route(&work->cached.route, &work->resolved.flow.route);
        work->cached.cookie = work->key.cookie;
        work->cached.epoch = work->resolved.epoch;
        work->cached.id = work->resolved.flow.id;
        work->cached.alive = 1;
    }
#ifdef AP_BINDING_SNAPSHOT
    }
#endif
    if (ar_result(&work->cached.route, work->key.family) != action) {
        allowed = 0;
        goto done;
    }
#ifdef AP_BINDING_SNAPSHOT
    if (work->cached.admission != 1) {
        allowed = 0;
        goto done;
    }
#endif
    if (!entry) {
        __builtin_memset(work->empty_connection, 0, sizeof(work->empty_connection));
        bpf_map_update_elem(&connection_routes, &connection, work->empty_connection, BPF_NOEXIST);
        entry = bpf_map_lookup_elem(&connection_routes, &connection);
        if (!entry)
            goto done;
    }
    if (__sync_val_compare_and_swap(&entry->lock, 0, 1))
        goto done;
    if (entry->retired)
        goto unlock;
    struct ss_lifetime *token = ss_lifetime_acquire(state, work->key.cookie, work->cached.epoch);
    if (!token)
        goto unlock;
    if (action >= 2 && work->key.protocol == 17) {
        __u64 previous = __sync_fetch_and_or(&token->udp_options, 1);
        if (!previous)
            udp_flags_created();
    }
    struct ct_record *old = &entry->data;
    struct ss_lifetime *previous = entry->lifetime;
    int live = previous && previous->alive && previous->cookie == old->key.cookie &&
               previous->epoch == old->epoch;
    if (live && old->key.cookie == work->key.cookie &&
        (old->epoch > work->cached.epoch ||
         (old->epoch == work->cached.epoch && old->id > work->cached.id))) {
        bpf_obj_drop_impl(token, 0);
        allowed = 0;
        goto unlock;
    }
    __u64 netns = bpf_get_netns_cookie(packet), device = device_identity(packet_device(packet));
    int same = old->route.decision.action == work->cached.route.decision.action &&
               old->route.decision.profile == work->cached.route.decision.profile &&
               old->route.network_generation == work->cached.route.network_generation &&
               old->network_namespace == netns && old->device == device;
    if (!live)
        old->ambiguous = 0;
    else if (old->key.cookie != work->key.cookie && !same)
        old->ambiguous = 1;
    if (!old->ambiguous) {
        ss_copy_route(&old->route, &work->cached.route);
        ss_copy_key(&old->key, &work->key);
        old->epoch = work->cached.epoch;
        old->id = work->cached.id;
        old->network_namespace = netns;
        old->device = device;
        old->last_seen = bpf_ktime_get_ns();
#ifdef AP_BINDING_SNAPSHOT
        old->admitted = 1;
#else
        old->admitted = 0;
#endif
        previous = bpf_kptr_xchg(&entry->lifetime, token);
        if (previous)
            bpf_obj_drop_impl(previous, 0);
        allowed = 1;
    } else
        bpf_obj_drop_impl(token, 0);
unlock:
    __sync_lock_test_and_set(&entry->lock, 0);
done:
    __sync_lock_test_and_set(&work->busy, 0);
    return allowed;
}
static __always_inline void connection_received(struct __sk_buff *packet,
                                                const struct flow_key *key,
                                                const struct ar_record *record) {
    struct sk_buff *internal = bpf_cast_to_kern_ctx(packet);
    __u64 connection = BPF_CORE_READ(internal, _nfct) & ~7ULL;
    struct ct_entry *entry = bpf_map_lookup_elem(&connection_routes, &connection);
    if (!entry || __sync_val_compare_and_swap(&entry->lock, 0, 1))
        return;
    if (!entry->retired && !entry->data.ambiguous && entry->data.key.cookie == key->cookie &&
        entry->data.epoch == record->epoch && entry->data.id == record->flow.id)
        entry->data.last_seen = bpf_ktime_get_ns();
    __sync_lock_test_and_set(&entry->lock, 0);
}
