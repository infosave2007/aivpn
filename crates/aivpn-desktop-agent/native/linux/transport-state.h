#pragma once
struct net___transport { __u64 net_cookie; } __attribute__((preserve_access_index));
struct possible_net_t___transport { struct net___transport *net; } __attribute__((preserve_access_index));
struct sock_common___transport { struct possible_net_t___transport skc_net; } __attribute__((preserve_access_index));
struct sock___transport { struct sock_common___transport __sk_common; } __attribute__((preserve_access_index));
static __always_inline __u64 transport_socket_netns(const void *socket) {
    return BPF_CORE_READ((const struct sock___transport *)socket, __sk_common.skc_net.net, net_cookie);
}
struct transport_registration {
    __u64 lease, netns, device, expires;
    __u32 slot, pid, uid, family, protocol, port;
    __u8 destination[16];
};
struct transport_lease { __u64 id; __u32 pid, uid; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, struct transport_registration);
} transport_sockets SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct transport_lease);
} transport_leases SEC(".maps");

/* -1 означает обычный сокет. Отозванный известный cookie всегда дает отказ. */
static __always_inline int transport_choice(__u64 cookie, __u64 netns, __u32 family,
                                             __u32 protocol, __u32 port,
                                             const __u8 *destination, int actor) {
    const struct transport_registration *registration = bpf_map_lookup_elem(&transport_sockets, &cookie);
    if (!registration) return -1;
    const struct transport_lease *lease = bpf_map_lookup_elem(&transport_leases, &registration->slot);
    if (!lease || !lease->id || lease->id != registration->lease || lease->pid != registration->pid ||
        lease->uid != registration->uid || registration->netns != netns ||
        registration->family != family || registration->protocol != protocol || registration->port != port ||
        registration->expires <= bpf_ktime_get_ns()) return 0;
    if (actor && ((__u32)(bpf_get_current_pid_tgid() >> 32) != registration->pid ||
                  (__u32)bpf_get_current_uid_gid() != registration->uid)) return 0;
    for (unsigned i = 0; i < 16; i++)
        if (registration->destination[i] != destination[i]) return 0;
    return 1;
}
