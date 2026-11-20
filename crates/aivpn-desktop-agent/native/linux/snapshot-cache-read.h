#pragma once
#include "route-version.h"

struct cc_entry {
    __u32 lock, retired;
    struct cached_route route;
    __u64 cookie, epoch, id;
    struct ss_lifetime __kptr *lifetime;
    __u64 admission, sequence;
    struct ss_flow __kptr *node;
    struct ss_flow __kptr *logical_node;
    struct ss_lifetime __kptr *logical_lifetime;
    struct flow_key logical_key;
    __u32 kind, reserved;
};
struct cc_snapshot {
    struct cached_route route;
    __u64 cookie, epoch, id;
    __u32 alive, admission;
};

static __always_inline int cc_parent_admitted(struct ss_flow *parent, struct ss_lifetime *token,
                                               const struct ss_flow *child, const struct cached_route *route) {
    if (!parent || !token || !token->alive || parent->epoch != token->epoch ||
        parent->key.cookie != token->cookie || child->parent_cookie != token->cookie || child->parent_epoch != token->epoch) return 0;
    __u64 word = sa_read(&parent->publication);
    return word == ((child->parent_id << 2) | SA_ADMITTED) &&
           route_choice_equal(&parent->route, route) &&
           word == sa_read(&parent->publication) && token->alive;
}

static __noinline int cc_read(struct cc_entry *entry, struct cc_snapshot *out) {
    bpf_rcu_read_lock();
    int result = 0;
    __u64 version = route_version_read(&entry->sequence);
    if (version & 1) goto done;
    struct ss_flow *node = entry->node;
    struct ss_lifetime *token = entry->lifetime;
    out->cookie = entry->cookie;
    out->epoch = entry->epoch;
    struct ss_flow *parent = entry->logical_node;
    struct ss_lifetime *parent_token = entry->logical_lifetime;
    int retired = entry->retired;
    if (retired || !node || !token || !token->alive ||
        token->cookie != out->cookie || node->key.cookie != out->cookie ||
        token->epoch != out->epoch || node->epoch != out->epoch)
        goto done;
    /* Читатели не блокируют друг друга; писатель меняет версию до замены полей. */
    for (unsigned attempt = 0; attempt < 2; attempt++) {
        __u64 word = sa_read(&node->publication);
        if (!sa_stable(word)) goto done;
        ss_copy_route(&out->route, &node->route);
        out->id = word >> 2;
        out->admission = (word & 3) == SA_ADMITTED ||
                         (node->parent_id && cc_parent_admitted(parent, parent_token, node, &out->route));
        out->alive = token->alive;
        if (word != sa_read(&node->publication)) continue;
        result = out->alive && version == route_version_read(&entry->sequence);
        break;
    }
done:
    bpf_rcu_read_unlock();
    return result;
}


/* Ссылка из map kptr не исчезает на время чтения другого участника. */
static __noinline struct ss_flow *cc_acquire_admitted_flow(struct cc_entry *entry,
                                     const struct flow_key *key, const struct ss_lifetime *expected) {
    bpf_rcu_read_lock();
    __u64 version = route_version_read(&entry->sequence);
    struct ss_flow *node = entry->node;
    struct ss_lifetime *token = entry->lifetime;
    struct ss_flow *owned = 0;
    if (!node || !token) goto done;
    asm volatile("" : "+r"(token), "+r"(node));
    if ((version & 1) || entry->retired || token != expected ||
        !token->alive || entry->cookie != key->cookie || token->cookie != key->cookie ||
        entry->epoch != token->epoch || node->epoch != token->epoch || ss_key_order(&node->key, key))
        goto done;
    __u64 publication = sa_read(&node->publication);
    if ((publication & 3) != SA_ADMITTED || !(publication >> 2)) goto done;
    owned = bpf_refcount_acquire_impl(node, 0);
    if (owned && (!token->alive || version != route_version_read(&entry->sequence) ||
        publication != sa_read(&node->publication))) {
        bpf_obj_drop_impl(owned, 0);
        owned = 0;
    }
done:
    bpf_rcu_read_unlock();
    return owned;
}
