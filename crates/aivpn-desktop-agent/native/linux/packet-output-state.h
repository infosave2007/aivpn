#pragma once
struct net_device;
static __always_inline __u32 owned_interface_profile(__u64 network_namespace,
                                                     const struct net_device *device);
static __always_inline __u64 device_identity(const struct net_device *device);
static __always_inline const struct net_device *packet_device(struct __sk_buff *packet);
#ifdef AP_BINDING_SNAPSHOT
__noinline __u64 packet_route(struct __sk_buff *packet __arg_ctx,
                               struct admission_work *admission __arg_nonnull) {
#else
static __noinline __u64 packet_route(struct __sk_buff *packet, struct admission_work *admission) {
#endif
    struct bpf_sock *socket = packet->sk;
    struct ss_state *state = socket ? bpf_sk_storage_get(&socket_states, socket, 0, 0) : 0;
    struct ar_work *work = route_begin(state, socket);
    if (!work)
        return 1;
    struct tcp_tuple *tuple = &work->tuple;
    __builtin_memset(tuple, 0, sizeof(*tuple));
    __u64 action = 1;
    if (packet_key(packet, &work->key, 0, tuple)) {
        action =
            state && state->kind == SS_CLASSIFIED && ar_has_policy(state->creator.self.source.uid) ? 1 : 0;
        goto done;
    }
    struct sk_buff___ct *internal = bpf_cast_to_kern_ctx(packet);
    struct sock *kernel_socket = BPF_CORE_READ(internal, sk);
#ifdef AP_BINDING_SNAPSHOT
    if (kernel_socket && BPF_CORE_READ(kernel_socket, __sk_common.skc_state) == 12) {
        __u64 address = (unsigned long)kernel_socket;
        const struct request_route *proof = bpf_map_lookup_elem(&request_routes, &address);
        action = proof && request_live(proof) ? ar_result(&proof->route, work->key.family) : 1;
        goto done;
    }
#endif
    int control = 0;
    if (kernel_socket && socket && socket->state != 6 && socket->state != 12)
        control = BPF_CORE_READ_BITFIELD_PROBED(kernel_socket, sk_kern_sock);
    if (work->key.protocol == 6 && (!socket || socket->state == 6 || control)) {
        struct tcp_tuple_route *route = control_tuple_route(tuple, socket);
        if (route) {
            action = finish_timewait(route, work->key.family);
            goto done;
        }
    }
    if (!socket || socket->state == 6 || socket->state == 12) {
        action = 0;
        goto done;
    }
    if (!state)
        state = ss_initialize_cookie(socket, work->key.cookie, 0, SS_PRESERVED, 0);
    if (!state)
        goto done;
    if (work->key.protocol == 6 && socket->state == 10) {
#ifdef AP_BINDING_SNAPSHOT
        if (request_peer_admitted(&work->key) &&
            !owned_interface_profile(bpf_get_netns_cookie(packet), packet_device(packet))) {
            action = 0;
            goto done;
        }
#endif
        __builtin_memset(&work->resolution.proposed, 0, sizeof(work->resolution.proposed));
        if (!ar_desired(state, &work->key, &work->resolution.proposed, route_companion(state, socket)) &&
            work->resolution.proposed.decision.action == 0 &&
            !owned_interface_profile(bpf_get_netns_cookie(packet), packet_device(packet)))
            action = 0;
        goto done;
    }
#ifdef AP_BINDING_SNAPSHOT
    if (work->key.protocol == 6 || work->key.protocol == 17) {
        if (ar_read(&work->key, &work->cached) != 1 || work->cached.admission != 1) goto done;
        struct cc_entry *entry = bpf_map_lookup_elem(&routing_overrides, &work->key);
        work->request.no_touch = 1;
        work->request.expected_epoch = work->cached.epoch;
        int found = entry ? cc_proof(entry, &work->key, &work->request, &work->resolved.flow, 0) : 0;
        if (found != 1 || work->resolved.flow.id != work->cached.id) {
            entry = bpf_map_lookup_elem(&routing_system, &work->key);
            found = entry ? cc_proof(entry, &work->key, &work->request, &work->resolved.flow, 0) : 0;
        }
        if (found != 1 || work->resolved.flow.id != work->cached.id ||
            !route_choice_equal(&work->resolved.flow.route, &work->cached.route)) goto done;
        work->resolved.flow.admitted = 1;
        work->resolved.epoch = work->cached.epoch;
        action = ar_result(&work->resolved.flow.route, work->key.family);
        if (admission) {
            ss_copy_key(&admission->key, &work->key);
            admission->record = work->resolved;
            admission->tuple = *tuple;
            admission->epoch = work->resolved.epoch;
            admission->tag = (work->resolved.flow.id << 2) | SA_ADMITTED;
        }
        goto done;
    }
#endif
    work->request.set_device = 1;
    work->request.system_device = device_identity(packet_device(packet));
    work->resolution.retry_rejected = 2;
    if (route_evaluate(state, work, 0, route_companion(state, socket)))
        goto done;
    action = ar_result(&work->resolved.flow.route, work->key.family);
#ifdef AP_BINDING_SNAPSHOT
    if (admission && (work->key.protocol == 17 || work->key.protocol == 6)) {
        ss_copy_key(&admission->key, &work->key);
        admission->record = work->resolved;
        admission->epoch = work->resolved.epoch;
        admission->tag = work->resolved.flow.id << 2;
    }
#else
    if (admission && work->key.protocol == 17 && action >= 2 && work->resolved.flow.id) {
        ss_copy_key(&admission->key, &work->key);
        admission->epoch = work->resolved.epoch;
        admission->tag = work->resolved.flow.id << 2;
    }
    if (work->key.protocol == 6 && action != 1 &&
        (remember_tcp_tuple(tuple, state, &work->resolved) ||
         remember_socket_tuple(packet, state, &work->resolved)))
        action = 1;
#endif
done:
    __sync_lock_test_and_set(&work->busy, 0);
    return action;
}
