#pragma once
struct ct_record {
    struct cached_route route;
    struct flow_key key;
    __u64 epoch, id, network_namespace, device, last_seen;
    __u32 ambiguous, admitted;
};
struct ct_entry {
    __u32 lock, retired;
    struct ct_record data;
    struct ss_lifetime __kptr *lifetime;
};
struct ct_snapshot {
    struct ct_record data;
    __u64 udp_options;
    __u32 alive, reserved;
};
