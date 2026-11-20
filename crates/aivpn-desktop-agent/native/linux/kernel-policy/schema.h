#pragma once
#ifdef AIVPN_BPF
#define AP_U8 __u8
#define AP_U32 __u32
#define AP_U64 __u64
#else
#include <stdint.h>
#define AP_U8 uint8_t
#define AP_U32 uint32_t
#define AP_U64 uint64_t
#endif
#define AP_RULE_LIMIT 256
#define AP_PARENT_LIMIT 32
#define AP_NO_RULE 0xffffffffu
struct ap_rule {
    AP_U32 selector, application, family, inherit, action, profile;
    AP_U8 address[16], mask[16];
};
struct ap_policy {
    AP_U32 version, owner_kind, owner, count;
    AP_U64 generation;
    AP_U32 default_action, default_profile, dns_profile, reserved;
    struct ap_rule rules[AP_RULE_LIMIT];
};
struct ap_origin {
    AP_U32 owner_kind, owner, application, package, resolved;
};
struct ap_context {
    struct ap_origin process;
    AP_U32 parent_count, family;
    AP_U8 destination[16];
    struct ap_origin parents[AP_PARENT_LIMIT];
};
struct ap_decision {
    AP_U32 action, profile, rule, depth, unresolved;
    AP_U64 generation;
};
