#pragma once

#define AP_LOOKUP_PREFIX_CAPACITY 262144U
struct lookup_prefix_key {
    __u64 proof;
    __u32 index, domain;
};
struct lookup_prefix_value {
    struct ph_stream prefix;
    struct ap_lookup_scope scope;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, AP_LOOKUP_PREFIX_CAPACITY);
    __type(key, struct lookup_prefix_key);
    __type(value, struct lookup_prefix_value);
} lookup_prefixes SEC(".maps");

/* Эти записи живут ровно столько же, сколько их immutable proof. */
static __noinline void lookup_prefix_clear(__u64 id, __u32 count) {
    if (!id || !count)
        return;
    AP_FOR(index, (int)AP_LOOKUP_LIMIT) {
        if ((__u32)index >= count)
            break;
        struct lookup_prefix_key key = {id, index, AP_LOOKUP_PHYSICAL};
        bpf_map_delete_elem(&lookup_prefixes, &key);
        key.domain = AP_LOOKUP_LOGICAL;
        bpf_map_delete_elem(&lookup_prefixes, &key);
    }
}

static __noinline int lookup_prefix_store(__u64 id, __u32 index, __u32 domain,
                                          const struct ph_stream *prefix,
                                          const struct ap_lookup_scope *scope) {
    if (!id || index >= AP_LOOKUP_LIMIT || !prefix->length || prefix->length > 4095)
        return -1;
    struct lookup_prefix_key key = {id, index, domain};
    struct lookup_prefix_value value = {.prefix = *prefix};
    if (domain == AP_LOOKUP_LOGICAL && scope) {
        value.scope = *scope;
    }
    return bpf_map_update_elem(&lookup_prefixes, &key, &value, BPF_NOEXIST);
}

static __always_inline const struct lookup_prefix_value *
lookup_prefix_find(__u64 id, __u32 index, __u32 domain) {
    struct lookup_prefix_key key = {id, index, domain};
    return bpf_map_lookup_elem(&lookup_prefixes, &key);
}
