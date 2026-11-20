#pragma once
struct system_zone_check { __u64 netns; __u32 zone, owned; };
static long snapshot_owned_zone(void *map, const __u32 *key, const __u32 *zone, void *context) {
    (void)map;
    struct system_zone_check *check = context;
    const struct profile *profile = bpf_map_lookup_elem(&profiles, key);
    if (*zone && *zone == check->zone && profile && profile->network_namespace == check->netns) {
        check->owned = 1;
        return 1;
    }
    return 0;
}

/* Чужой SNAT допустим по реальному conntrack tuple, владение не выводится из адреса. */
static __noinline int snapshot_system_source(struct bpf_nf_ctx *context,
                                              const struct tcp_tuple *tuple,
                                              const struct ss_record *record) {
    if (!record->route.system_device || record->route.system_device != device_identity(context->state->out) ||
        owned_interface_profile(tuple->netns, context->state->out)) return 0;
    struct system_zone_check zone = {.netns = tuple->netns, .zone = tuple->zone};
    if (zone.zone) bpf_for_each_map_elem(&profile_zones, snapshot_owned_zone, &zone, 0);
    if (zone.owned) return 0;
    int same = 1;
    for (unsigned i = 0; i < 16; i++)
        if ((tuple->family == 6 || i < 4) && tuple->source[i] != record->system_source[i]) same = 0;
    if (same && tuple->source_port == record->source_port) return 1;
    __u64 tagged = BPF_CORE_READ(context->skb, _nfct);
    struct nf_conn *connection = (void *)(unsigned long)(tagged & ~7ULL);
    if (!connection) return 0;
    __u8 original[16], reply[16], destination[16];
    BPF_CORE_READ_INTO(&original, connection, tuplehash[0].tuple.src.u3);
    BPF_CORE_READ_INTO(&destination, connection, tuplehash[0].tuple.dst.u3);
    BPF_CORE_READ_INTO(&reply, connection, tuplehash[1].tuple.dst.u3);
    if (__builtin_bswap16(BPF_CORE_READ(connection, tuplehash[0].tuple.src.u.all)) != record->source_port ||
        __builtin_bswap16(BPF_CORE_READ(connection, tuplehash[0].tuple.dst.u.all)) != tuple->destination_port ||
        __builtin_bswap16(BPF_CORE_READ(connection, tuplehash[1].tuple.dst.u.all)) != tuple->source_port) return 0;
    for (unsigned i = 0; i < 16; i++)
        if ((tuple->family == 6 || i < 4) && (original[i] != record->system_source[i] ||
            reply[i] != tuple->source[i] || destination[i] != tuple->destination[i])) return 0;
    return 1;
}

static __always_inline int snapshot_output_path(struct bpf_nf_ctx *context,
                                                const struct tcp_tuple *tuple,
                                                const struct ss_record *record) {
    const struct cached_route *route = &record->route;
    __u64 action = ar_result(route, tuple->family);
    struct mark_key mark = {.network_namespace = tuple->netns,
                            .mark = BPF_CORE_READ(context->skb, mark)};
    if (!action)
        return !owned_mark_profile(&mark) && snapshot_system_source(context, tuple, record);
    if (action < 2)
        return 0;
    struct profile *profile = bpf_map_lookup_elem(&profiles, &route->decision.profile);
    if (!profile || profile->network_namespace != tuple->netns || !profile_mark_matches(profile, mark.mark) ||
        profile->interface_index != (__u32)BPF_CORE_READ(context->state, out, ifindex) ||
        !profile->device_identity || profile->device_identity != device_identity(context->state->out))
        return 0;
    for (unsigned i = 0; i < 16; i++) {
        if (tuple->family == 4) {
            if (i < 4 && tuple->source[i] != profile->ipv4[i])
                return 0;
        } else if (tuple->source[i] != profile->ipv6[i])
            return 0;
    }
    return 1;
}

/* TRACING читает линейный IP header без сетевых dynptr kfuncs. */
static __noinline int dispatch_tuple(struct sk_buff *packet, const struct nf_hook_state *state,
                                      struct tcp_tuple *tuple) {
    __u8 head[40] = {};
    unsigned start = BPF_CORE_READ(packet, network_header);
    unsigned tail = BPF_CORE_READ(packet, tail);
    unsigned offset, protocol;
    __u8 *base = BPF_CORE_READ(packet, head);
    if (start > tail || tail - start < 20 || bpf_probe_read_kernel(head, 20, base + start)) return -1;
    if ((head[0] >> 4) == 4) {
        tuple->family = 4; offset = (head[0] & 15) * 4; protocol = head[9];
        if (offset < 20 || (head[6] & 31) || head[7]) return -1;
        __builtin_memcpy(tuple->source, head + 12, 4);
        __builtin_memcpy(tuple->destination, head + 16, 4);
    } else if ((head[0] >> 4) == 6) {
        if (tail - start < 40 || bpf_probe_read_kernel(head, 40, base + start)) return -1;
        tuple->family = 6; offset = 40; protocol = head[6];
        __builtin_memcpy(tuple->source, head + 8, 16);
        __builtin_memcpy(tuple->destination, head + 24, 16);
        for (unsigned i = 0; i < 8; i++) {
            if (protocol != 0 && protocol != 43 && protocol != 60 && protocol != 44 && protocol != 51) break;
            __u8 extension[8];
            if (offset > tail - start || tail - start - offset < 8 ||
                bpf_probe_read_kernel(extension, 8, base + start + offset)) return -1;
            if (protocol == 44 && (extension[2] || (extension[3] & 0xf8))) return -1;
            offset += protocol == 44 ? 8 : protocol == 51 ? ((unsigned)extension[1] + 2) * 4
                                                          : ((unsigned)extension[1] + 1) * 8;
            protocol = extension[0];
        }
    } else return -1;
    if (protocol != 6 && protocol != 17) return -1;
    __u8 ports[4];
    if (offset > tail - start || tail - start - offset < 4 ||
        bpf_probe_read_kernel(ports, 4, base + start + offset)) return -1;
    tuple->protocol = protocol;
    tuple->source_port = ((__u32)ports[0] << 8) | ports[1];
    tuple->destination_port = ((__u32)ports[2] << 8) | ports[3];
    tuple->netns = BPF_CORE_READ(state, net, net_cookie);
    return 0;
}
SEC("netfilter") int ensure_local_dispatch(struct bpf_nf_ctx *context) {
    (void)context;
    return 1;
}

static __always_inline int dispatch_needs_system_source(const struct cached_route *route) {
    return route->decision.action == 0 && !route->system_device;
}

/* Входящий SYSTEM уже принят, но первая отправка еще не закрепила source.
 * Дополняем только это доказательство. Решение, id и lifetime не меняются. */
static __noinline int dispatch_bind_system_source(struct ss_flow *flow, struct ss_lifetime *token,
                                                  const struct ss_request *request,
                                                  struct ss_record *record) {
    __u64 word = sa_read(&flow->publication);
    if (!request->system_device || !request->source_port ||
        word != ((record->id << 2) | SA_ADMITTED) || !sa_gc_claim(&flow->publication, word)) return -1;
    int allowed = token->alive && token->cookie == flow->key.cookie && token->epoch == flow->epoch &&
                  flow->route.decision.action == 0;
    if (allowed && !flow->route.system_device) {
        flow->source_port = request->source_port;
        __builtin_memcpy(flow->system_source, request->system_source, 16);
        flow->route.system_device = request->system_device;
    }
    if (__sync_val_compare_and_swap(&flow->publication, (word & ~3ULL) | SA_UPDATING, word) !=
        ((word & ~3ULL) | SA_UPDATING)) return -1;
    return allowed && token->alive && ss_flow_read(flow, record, 0) == 1 ? 0 : -1;
}

/* Pure payload refresh не получает ссылок на graph. */
static __noinline int dispatch_refresh(struct ss_flow *flow, struct ss_lifetime *token,
                                        struct ar_work *work, int logical) {
    struct ss_record *record = logical ? &work->logical.flow : &work->resolved.flow;
    struct ss_request *request = &work->request;
    struct cached_route *proposed = &work->resolution.proposed;
    if (!token->alive || token->cookie != flow->key.cookie || token->epoch != flow->epoch) return -1;
    int found = ss_flow_read(flow, record, 1);
    if (found < 1) return -1;
    if (found == 1 && record->admitted) {
        if (!logical && dispatch_needs_system_source(&record->route))
            return dispatch_bind_system_source(flow, token, request, record);
        return 0;
    }
    __u64 word = sa_read(&flow->publication);
    if ((word >> 2) != record->id) return -1;
    if ((word & 3) == SA_ADMITTED) {
        if (!ss_end_interval(flow, word, SS_NOW())) return -1;
        word = (word & ~3ULL) | SA_RETIRED;
    }
    int same = route_choice_equal(&record->route, proposed) &&
               record->route.network_generation == proposed->network_generation;
    if (!logical && proposed->decision.action == 0)
        same = same && record->route.system_device == request->system_device &&
               record->source_port == request->source_port &&
               !__builtin_memcmp(record->system_source, request->system_source, 16);
    if (!logical && request->parent_id)
        same = same && record->parent_id == request->parent_id &&
               record->parent_epoch == request->parent_epoch && record->parent_cookie == request->parent_cookie;
    if (same && (word & 3) == SA_PREPARED) return 0;
    __u64 id = ss_reserve_id(token, flow->key.cookie, flow->epoch);
    if (!id || id <= (word >> 2) || !sa_claim(&flow->publication, word)) return -1;
    ss_copy_route(&flow->route, proposed);
    if (!logical && proposed->decision.action == 0) {
        flow->route.system_device = request->system_device;
        flow->source_port = request->source_port;
        __builtin_memcpy(flow->system_source, request->system_source, 16);
    }
    if (!logical && request->parent_id) {
        flow->parent_id = request->parent_id;
        flow->parent_epoch = request->parent_epoch;
        flow->parent_cookie = request->parent_cookie;
    }
    flow->id = id;
    ss_touch(flow, SS_NOW());
    if (!sa_publish(&flow->publication, word, id)) return -1;
    return token->alive && ss_flow_read(flow, record, 0) == 1 ? 0 : -1;
}

static __always_inline int dispatch_parent(struct ss_state *saved, struct ar_work *work,
                                       const struct process_companion *companion) {
    struct ss_flow *parent = saved->logical_node;
    struct ss_lifetime *token = saved->logical_lifetime;
    parent = parent ? bpf_refcount_acquire_impl(parent, 0) : 0;
    token = token ? bpf_refcount_acquire_impl(token, 0) : 0;
    int result = -1;
    if (!parent || !token || !token->alive || token->cookie != saved->logical_cookie ||
        parent->epoch != token->epoch || ss_key_order(&parent->key, &saved->logical_key)) goto done;
    if (ss_flow_read(parent, &work->logical.flow, 1) != 1) goto done;
    if (!work->logical.flow.admitted) {
        __builtin_memset(&work->resolution.proposed, 0, sizeof(work->resolution.proposed));
        if (ar_desired(saved, &saved->logical_key, &work->resolution.proposed, companion) ||
            dispatch_refresh(parent, token, work, 1)) goto done;
    }
    ss_copy_route(&work->resolution.proposed, &work->logical.flow.route);
    work->request.parent_id = work->logical.flow.id;
    work->request.parent_epoch = token->epoch;
    work->request.parent_cookie = token->cookie;
    result = 0;
done:
    if (parent) bpf_obj_drop_impl(parent, 0);
    if (token) bpf_obj_drop_impl(token, 0);
    return result;
}

static __noinline int dispatch_payload(struct ss_state *saved, struct ar_work *work, int post,
                                        const struct process_companion *companion) {
    struct ss_flow *flow = 0;
    struct ss_lifetime *token = saved->lifetime;
    token = token ? bpf_refcount_acquire_impl(token, 0) : 0;
    if (work->key.protocol == 6) {
        flow = saved->direct_flow;
        flow = flow ? bpf_refcount_acquire_impl(flow, 0) : 0;
    }
    else {
        struct cc_entry *entry = bpf_map_lookup_elem(&routing_overrides, &work->key);
        if (!entry) entry = bpf_map_lookup_elem(&routing_system, &work->key);
        if (entry && !__sync_val_compare_and_swap(&entry->lock, 0, 1)) {
            flow = entry->node;
            flow = flow ? bpf_refcount_acquire_impl(flow, 0) : 0;
            __sync_lock_test_and_set(&entry->lock, 0);
        }
    }
    int result = -1;
    if (!flow || !token || !token->alive || token->cookie != saved->cookie ||
        flow->epoch != token->epoch || ss_key_order(&flow->key, &work->key)) goto done;
    if (ss_flow_read(flow, &work->resolved.flow, 1) < 1) goto done;
    if (!post && (!work->resolved.flow.admitted ||
                  dispatch_needs_system_source(&work->resolved.flow.route))) {
        if (saved->logical_cookie) {
            if (dispatch_parent(saved, work, companion)) goto done;
        } else {
            __builtin_memset(&work->resolution.proposed, 0, sizeof(work->resolution.proposed));
            if (ar_desired(saved, &work->key, &work->resolution.proposed, companion)) goto done;
        }
        if (dispatch_refresh(flow, token, work, 0)) goto done;
    }
    if (saved->logical_cookie) work->resolved.flow.admitted = ss_logical_admitted(saved, &work->resolved.flow);
    void *map = work->resolved.flow.route.decision.action == 2 ? (void *)&routing_overrides : (void *)&routing_system;
    result = cc_store_plain(map, &work->key, saved, flow, &work->resolved.flow);
done:
    if (flow) bpf_obj_drop_impl(flow, 0);
    if (token) bpf_obj_drop_impl(token, 0);
    return result;
}

/* Anchor гарантирует LOCAL_OUT dispatch; nf_reinject не создает новую подготовку. */
SEC("fentry/nf_hook_slow")
int BPF_PROG(prepare_packet_dispatch, struct sk_buff *packet, const struct nf_hook_state *state,
             const void *entries, unsigned start_index) {
    (void)ctx; (void)entries; (void)start_index;
    if (!state || (state->pf != 2 && state->pf != 10) || (state->hook != 3 && state->hook != 4)) return 0;
    struct sock *socket = state->sk;
    if (!socket) return 0;
    unsigned status = socket->__sk_common.skc_state;
    if (status == 6 || status == 10 || status == 12 || BPF_CORE_READ_BITFIELD_PROBED(socket, sk_kern_sock)) return 0;
    struct ss_state *saved = bpf_sk_storage_get(&socket_states, socket, 0, 0);
    struct ar_work *work = route_begin(saved, socket);
    if (!work) return 0;
    __builtin_memset(&work->tuple, 0, sizeof(work->tuple));
    if (dispatch_tuple(packet, state, &work->tuple)) goto done;
    work->key.cookie = bpf_get_socket_cookie(socket);
    work->key.family = work->tuple.family;
    work->key.protocol = work->tuple.protocol;
    work->key.port = work->tuple.destination_port;
    __builtin_memcpy(work->key.destination, work->tuple.destination, 16);
    if (transport_choice(work->key.cookie, work->tuple.netns, work->key.family,
                         work->key.protocol, work->key.port, work->key.destination, 0) >= 0) goto done;
    if (saved && (saved->cookie != work->key.cookie ||
        (saved->kind != SS_CLASSIFIED && saved->kind != SS_PRESERVED && saved->kind != SS_EMPTY))) goto done;
    int found = ar_read(&work->key, &work->cached);
    if (found == 1 && ((work->cached.admission == 1 &&
                       !dispatch_needs_system_source(&work->cached.route)) || state->hook == 4)) goto done;
    work->request.source_port = work->tuple.source_port;
    work->request.set_device = 1;
    work->request.system_device = device_identity(state->out);
    __builtin_memcpy(work->request.system_source, work->tuple.source, 16);
    if ((!saved || !saved->lifetime) && state->hook == 3 && work->key.protocol == 6)
        saved = ss_bootstrap_preserved(socket, &work->key, &work->request);
    if (!saved || (saved->kind != SS_CLASSIFIED && saved->kind != SS_PRESERVED) ||
        saved->cookie != work->key.cookie) goto done;
    dispatch_payload(saved, work, state->hook == 4, route_companion(saved, socket));
done:
    __sync_lock_test_and_set(&work->busy, 0);
    return 0;
}

/* Только final guard подтверждает exact подготовку до conntrack confirm. */
static __noinline int snapshot_final_output(struct bpf_nf_ctx *context,
                                             const struct tcp_tuple *tuple) {
    struct sock *socket = BPF_CORE_READ((struct sk_buff___ct *)context->skb, sk);
    if (!socket) return -1;
    unsigned status = BPF_CORE_READ(socket, __sk_common.skc_state);
    if (status == 6 || status == 10 || status == 12 || BPF_CORE_READ_BITFIELD_PROBED(socket, sk_kern_sock)) return -1;
    struct ar_work *work = route_slot(0);
    if (!work) work = route_slot(1);
    if (!work) work = route_slot(2);
    if (!work) work = route_slot(3);
    if (!work) return 0;
    struct flow_key *key = &work->key;
    __builtin_memset(key, 0, sizeof(*key));
    key->cookie = BPF_CORE_READ(socket, __sk_common.skc_cookie.counter);
    key->family = tuple->family; key->protocol = tuple->protocol; key->port = tuple->destination_port;
    __builtin_memcpy(key->destination, tuple->destination, 16);
    int allowed = 0;
    if (ar_read(key, &work->cached) != 1) goto done;
    struct cc_entry *entry = bpf_map_lookup_elem(&routing_overrides, key);
    struct ss_request *request = &work->request;
    struct ss_record *current = &work->resolved.flow, *logical = &work->logical.flow;
    ss_clear_request(request); request->no_touch = 1; request->expected_epoch = work->cached.epoch;
    int found = entry ? cc_proof(entry, key, request, current, 0) : 0;
    if (found != 1 || current->id != work->cached.id) {
        entry = bpf_map_lookup_elem(&routing_system, key);
        found = entry ? cc_proof(entry, key, request, current, 0) : 0;
    }
    if (!entry || found != 1 || current->id != work->cached.id) goto done;
    int derived = current->parent_id != 0;
    if (derived) {
        if (cc_proof(entry, &entry->logical_key, request, logical, 1) != 1 ||
            logical->id != current->parent_id || !route_choice_equal(&logical->route, &current->route)) goto done;
        current->admitted = logical->admitted;
    }
    if (!current->admitted && entry->kind != SS_PRESERVED) {
        __u32 zero = 0;
        void *inner = bpf_map_lookup_elem(&binding_root, &zero);
        const struct bs_value *meta = inner ? bs_lookup(inner, BS_META, 0, 0, 0, 0) : 0;
        if (!meta || meta->words[0] != 2 || !meta->words[1] || !meta->words[2] || !meta->words[3] ||
            !bs_lookup(inner, BS_IDENTITY, 0, 0, 0, 0) || meta->words[1] != current->route.binding_epoch) goto done;
    }
    if (!snapshot_output_path(context, tuple, current)) goto done;
    request->confirm = 3;
    request->expected_id = derived ? logical->id : current->id;
    if (derived) {
        if (cc_proof(entry, &entry->logical_key, request, logical, 1) != 1 || !logical->admitted) goto done;
        current->admitted = 1;
    } else if (cc_proof(entry, key, request, current, 0) != 1 || !current->admitted) goto done;
    cc_sync_proof(entry, key, current, work->cached.epoch);
    allowed = 1;
done:
    __sync_lock_test_and_set(&work->busy, 0);
    return allowed;
}
