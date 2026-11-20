#pragma once

struct dns_epoch {
    __u64 epoch;
    __u32 slot, reserved;
};
struct dns_registration {
    __u64 epoch, generation, netns, expires;
    __u32 slot, family, protocol, port;
    __u8 destination[16];
    __u32 pid, uid;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dns_epoch);
} dns_epochs SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, __u64);
    __type(value, struct dns_registration);
} dns_sockets SEC(".maps");

struct dns_guard_state { __u64 netns; __u32 active, reserved; };
struct dns_listener_key {
    __u64 netns;
    __u32 family, protocol, port, reserved;
    __u8 address[16];
};
struct dns_listener_value { __u64 cookie, device; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dns_guard_state);
} dns_guard SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, struct dns_listener_key);
    __type(value, struct dns_listener_value);
} dns_listeners SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u64);
    __type(value, struct dns_listener_key);
} dns_listener_fds SEC(".maps");

static __always_inline int dns_registration_allowed(const struct dns_registration *entry,
                                                      const struct flow_key *key) {
    __u32 zero = 0;
    const struct dns_epoch *epoch = bpf_map_lookup_elem(&dns_epochs, &zero);
    const struct profile *profile = bpf_map_lookup_elem(&profiles, &entry->slot);
    int allowed = epoch && epoch->epoch && !epoch->reserved && entry->epoch == epoch->epoch &&
        entry->slot && (key->protocol == 6 || key->protocol == 17) &&
        entry->slot == epoch->slot && entry->pid && !entry->uid &&
        entry->expires > bpf_ktime_get_ns() && entry->family == key->family &&
        entry->protocol == key->protocol && entry->port == key->port && profile &&
        entry->netns == profile->network_namespace && entry->generation &&
        entry->generation == profile->generation &&
        (key->family == 4 ? profile->ready4 : key->family == 6 && profile->ready6);
    for (unsigned index = 0; index < 16; index++)
        if (entry->destination[index] != key->destination[index]) allowed = 0;
    return allowed;
}

static __always_inline void dns_listener_closed(__u64 cookie) {
    const struct dns_listener_key *key = bpf_map_lookup_elem(&dns_listener_fds, &cookie);
    if (!key) return;
    const struct dns_listener_value *listener = bpf_map_lookup_elem(&dns_listeners, key);
    if (listener && listener->cookie == cookie) bpf_map_delete_elem(&dns_listeners, key);
    bpf_map_delete_elem(&dns_listener_fds, &cookie);
}

/* Только конкретный зарегистрированный сокет получает DNS-путь профиля. */
static __always_inline void dns_socket_choice(const struct process_state *state,
                                               const struct flow_key *key,
                                               struct cached_route *out) {
    const struct dns_registration *entry = bpf_map_lookup_elem(&dns_sockets, &key->cookie);
    if (!entry) return;
    int allowed = state->self.source.uid == entry->uid && dns_registration_allowed(entry, key);
    out->decision.rule = AP_NO_RULE;
    out->decision.action = allowed ? 2 : 1;
    out->decision.profile = allowed ? entry->slot : 0;
    out->system_device = 0;
}
