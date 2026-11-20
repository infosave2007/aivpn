#pragma once
#include "kernel-policy/view.h"

#define BS_CAPACITY 401408
#define BS_HEADER 1
#define BS_RULE 2
#define BS_FILE 3
#define BS_MEMBERSHIP 4
#define BS_PHYSICAL 5
#define BS_LOGICAL 6
#define BS_META 7
#define BS_IDENTITY 8
#define BS_SOURCE_PHYSICAL 9
#define BS_SOURCE_LOGICAL 10
#define BS_SOURCE_META 11
struct bs_key { __u64 kind, owner, payload[3]; };
struct bs_value { __u64 words[8]; };
struct bs_inner {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BS_CAPACITY);
    __uint(map_flags, BPF_F_RDONLY_PROG | BPF_F_NO_PREALLOC);
    __type(key, struct bs_key);
    __type(value, struct bs_value);
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, __u32);
    __array(values, struct bs_inner);
} binding_root SEC(".maps");

static __always_inline const struct bs_value *bs_lookup(void *inner, __u64 kind, __u64 owner,
                                                        __u64 a, __u64 b, __u64 c) {
    struct bs_key key = {kind, owner, {a, b, c}};
    return bpf_map_lookup_elem(inner, &key);
}
static __always_inline const struct ap_rule *bs_rule(const struct ap_policy_view *view, unsigned index) {
    if (!view->binding)
        return &view->policy->rules[index];
    if (!view->lookup)
        return 0;
    *view->lookup = (struct bs_key){BS_RULE, view->owner, {index, 0, 0}};
    const struct bs_value *value = bpf_map_lookup_elem(view->binding, view->lookup);
    return value && !value->words[7] ? (const struct ap_rule *)value : 0;
}
static __always_inline int bs_member(const struct ap_policy_view *view, __u32 selector, __u32 group) {
    if (!group || !selector || !view->lookup)
        return 0;
    *view->lookup = (struct bs_key){BS_MEMBERSHIP, view->owner, {selector, group, 0}};
    const struct bs_value *value = bpf_map_lookup_elem(view->binding, view->lookup);
    return value && value->words[0] == 1;
}
static __always_inline int bs_application(const struct ap_policy_view *view,
                                          const struct ap_rule *rule, const struct ap_origin *origin) {
    if (rule->selector == 1) {
        if (view->binding)
            return bs_member(view, rule->application, origin->application);
        return origin->application && rule->application == origin->application;
    }
    return rule->selector == 2 && origin->package && rule->application == origin->package;
}
#define AP_VIEW_RULE(view, index) bs_rule(view, index)
#define AP_VIEW_APPLICATION(view, rule, origin) bs_application(view, rule, origin)

/* Один inner pointer для header, всех origins, правил и negative facts. */
static __noinline int bs_begin(struct ap_policy_view *view, __u32 uid) {
    __u32 zero = 0;
    void *inner = bpf_map_lookup_elem(&binding_root, &zero);
    if (!inner)
        return -1;
    const struct bs_value *meta = bs_lookup(inner, BS_META, 0, 0, 0, 0);
    if (!meta || meta->words[0] != 2 || !meta->words[1] || !meta->words[2] || !meta->words[3])
        return -1;
    if (!bs_lookup(inner, BS_IDENTITY, 0, 0, 0, 0))
        return -1;
    view->binding = inner;
    view->owner = 3ULL << 32;
    const struct bs_value *header = bs_lookup(inner, BS_HEADER, view->owner, 0, 0, 0);
    if (!header) {
        view->owner = (1ULL << 32) | uid;
        header = bs_lookup(inner, BS_HEADER, view->owner, 0, 0, 0);
    }
    if (!header)
        return 0;
    view->policy = (const struct ap_policy *)header;
    const struct ap_policy *policy = view->policy;
    if (policy->version != 1 || policy->count > AP_RULE_LIMIT || !policy->generation ||
        policy->reserved || !policy->dns_profile || policy->default_action > 2 ||
        (policy->default_action == 2 ? !policy->default_profile : policy->default_profile != 0) ||
        (((__u64)policy->owner_kind << 32) | policy->owner) != view->owner ||
        header->words[5] || header->words[6] || header->words[7])
        return -1;
    return 1;
}
