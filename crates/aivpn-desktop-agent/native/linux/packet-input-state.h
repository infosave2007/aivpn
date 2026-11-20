#pragma once
static __noinline int transport_input(struct __sk_buff *packet) {
    struct flow_key key = {};
    if (packet_key(packet, &key, 1, 0)) return -1;
    int choice = transport_choice(key.cookie, bpf_get_netns_cookie(packet), key.family,
                                   key.protocol, key.port, key.destination, 0);
    if (choice < 0) return choice;
    const struct transport_registration *registration = bpf_map_lookup_elem(&transport_sockets, &key.cookie);
    return choice && registration && registration->device == device_identity(packet_device(packet));
}
SEC("cgroup_skb/ingress")
int record_incoming_datagram(struct __sk_buff *packet) {
    int transport = transport_input(packet);
    if (transport >= 0) return transport;
    const struct net_device *device = packet_device(packet);
    __u32 slot = owned_interface_profile(bpf_get_netns_cookie(packet), device);
    struct flow_key key = {};
    if (packet_key(packet, &key, 1, 0) || !key.cookie)
        return slot ? 0 : 1;
    struct bpf_sock *socket = packet->sk;
    if (!socket)
        return slot ? 0 : 1;
    struct ss_state *state = bpf_sk_storage_get(&socket_states, socket, 0, 0);
    if (key.protocol == 6 && socket->state == 10) {
        struct sk_buff___ct *internal = bpf_cast_to_kern_ctx(packet);
        struct sock *sock = BPF_CORE_READ(internal, sk);
        if (sock && BPF_CORE_READ_BITFIELD_PROBED((struct tcp_sock___mp *)sock, is_mptcp) &&
            !state) {
            struct mptcp_sock *owner = bpf_skc_to_mptcp_sock(socket);
            if (!owner || BPF_CORE_READ_BITFIELD_PROBED((struct sock *)owner, sk_kern_sock))
                return 0;
            struct ss_state *parent = bpf_sk_storage_get(&socket_states, owner, 0, 0);
            /* Новый owner обязан иметь личность; отсутствие допустимо лишь до активации. */
            if (parent)
                return 0;
            state = ss_initialize_cookie(socket, key.cookie, 0, SS_PRESERVED, 0);
            if (!state)
                return 0;
            state->derived_stream = 1;
        }
    }
    if (state)
        state = ss_adopt_cookie(socket, key.cookie);
    else
        state = ss_initialize_cookie(socket, key.cookie, 0, SS_PRESERVED, 0);
    if (!state)
        return 0;
    struct ar_work *work = route_begin(state, socket);
    if (!work)
        return 0;
    ss_copy_key(&work->key, &key);
    work->resolution.incoming = 1;
    /* Listener проверяет новую заявку, но не хранит поток принятого ребенка. */
    if (key.protocol == 6 && socket->state == 10) {
#ifdef AP_BINDING_SNAPSHOT
        if (!slot && request_peer_admitted(&work->key)) {
            __sync_lock_test_and_set(&work->busy, 0);
            return 1;
        }
#endif
        __builtin_memset(&work->resolution.proposed, 0, sizeof(work->resolution.proposed));
        int allowed = !ar_desired(state, &work->key, &work->resolution.proposed, route_companion(state, socket)) &&
                      work->resolution.proposed.decision.action == 0 && !slot;
        __sync_lock_test_and_set(&work->busy, 0);
        return allowed;
    }
    int allowed = 0;
    if (route_evaluate(state, work, 0, route_companion(state, socket)) || !work->resolved.flow.id)
        goto done;
    struct cached_route *route = &work->resolved.flow.route;
    if (route->decision.action == 0) {
        allowed =
            !slot || (route->system_device && route->system_device == device_identity(device));
    } else {
        __u64 action = ar_result(route, key.family);
        allowed = slot && action >= 2 && action - 2 == slot;
        if (allowed
#ifndef AP_BINDING_SNAPSHOT
            && key.protocol == 17
#endif
        ) {
            struct cc_entry *entry = bpf_map_lookup_elem(&routing_overrides, &key);
            allowed = entry && cc_read(entry, &work->cached) && work->cached.admission == 1 &&
                      work->cached.cookie == key.cookie &&
                      work->cached.epoch == work->resolved.epoch &&
                      work->cached.id == work->resolved.flow.id &&
                      route_choice_equal(&work->cached.route, route) &&
                      work->cached.route.network_generation == route->network_generation;
        }
    }
done:
#ifdef AP_BINDING_SNAPSHOT
    /* У SYSTEM-ответа исходящий адрес и интерфейс определяет первая отправка. */
    if (allowed && (state->kind == SS_PRESERVED ||
                    work->resolved.flow.route.decision.action != 0 ||
                    work->resolved.flow.route.system_device))
        allowed = ar_admit(&work->key, &work->resolved, &work->request);
#endif
    if (allowed)
        connection_received(packet, &work->key, &work->resolved);
    __sync_lock_test_and_set(&work->busy, 0);
    return allowed;
}
