#pragma once
#include "kernel-policy/schema.h"
#include "kernel-policy/path_hash.h"
#define AP_PATH_PHYSICAL 1U
#define AP_PATH_LOGICAL 2U
#define AP_PATH_COMPLETE (AP_PATH_PHYSICAL | AP_PATH_LOGICAL)
#define AP_LOGICAL_SCOPE (~(AP_U64)0)
#define AP_ANCESTRY_OVERFLOW 1U
#define AP_ANCESTRY_PENDING 2U
#define AP_ANCESTRY_EXEC_OVERFLOW 4U
#define AP_ANCESTRY_OWNER_OVERFLOW 8U
#define AP_HISTORY_FORK 1U
#define AP_HISTORY_EXEC 2U
#define AP_HISTORY_OWNER 3U
#define AP_EXEC_OWNER_CHANGED 2U

struct origin_hash {
    AP_U32 uid, path_flags;
    AP_U64 filesystem_device;
    struct ph_hash path;
    AP_U64 file_cookie;
    struct ph_hash logical_path;
    AP_U64 task_identity;
    AP_U64 exec_identity, owner_epoch;
};
#include "lookup-evidence.h"
struct exec_frame {
    struct origin_hash source, image;
#ifdef AP_BINDING_SNAPSHOT
    AP_U64 lookup;
#endif
};
struct history_slot {
    struct exec_frame parent;
    AP_U64 edge_identity;
    AP_U32 kind, has_carried;
};
struct process_state {
    struct exec_frame self;
    AP_U64 snapshot_identity;
    AP_U32 parent_count, ancestry_flags;
    struct history_slot parents[AP_PARENT_LIMIT];
};
struct process_companion {
    AP_U64 snapshot_identity;
    AP_U32 available, reserved;
    struct exec_frame carried[AP_PARENT_LIMIT];
};
struct fork_witness {
    AP_U64 edge_identity, parent_task, child_task, copied_exec, owner_epoch;
    AP_U32 owner, armed;
};
struct pending_exec {
    struct origin_hash source;
    AP_U64 attempt;
    AP_U32 active, previous_owner;
#ifdef AP_BINDING_SNAPSHOT
    AP_U64 lookup;
#endif
};
struct task_capture {
    struct process_state committed;
    struct pending_exec pending;
    struct fork_witness witness;
};
/* В проверенном ядре selem->sdata.data начинается с байта 72; запас покрывает заголовок. */
#define AP_LOCAL_STORAGE_HEADER_BUDGET 128U
#define AP_LOCAL_STORAGE_CHECK(type) \
    _Static_assert(sizeof(struct type) + AP_LOCAL_STORAGE_HEADER_BUDGET <= 8192, \
                   #type " exceeds local storage allocation budget")
AP_LOCAL_STORAGE_CHECK(task_capture);
AP_LOCAL_STORAGE_CHECK(process_companion);
struct application_key {
    struct ph_hash path;
    AP_U64 filesystem_device;
};
struct interface_key {
    AP_U64 network_namespace;
    AP_U32 interface_index, reserved;
};
struct mark_key {
    AP_U64 network_namespace;
    AP_U32 mark, reserved;
};
struct profile {
    AP_U32 mark, ready4, ready6, interface_index;
    AP_U64 generation;
    AP_U8 ipv4[4], ipv6[16];
    AP_U32 mark_mask;
    AP_U64 network_namespace, device_identity;
};
struct flow_key {
    AP_U64 cookie;
    AP_U8 destination[16];
    AP_U32 family, port, protocol, padding;
};

struct cached_route {
    struct ap_decision decision;
    AP_U64 network_generation, system_device, binding_epoch;
};
struct tcp_tuple {
    AP_U64 netns;
    AP_U8 source[16], destination[16];
    AP_U32 family, source_port, destination_port, protocol, zone, reserved;
};
struct tcp_tuple_route {
    AP_U32 lock, retired;
    struct cached_route route;
    AP_U64 cookie, expires, epoch, id;
#ifdef __BPF__
    struct ss_lifetime __kptr *lifetime;
#else
    AP_U64 lifetime;
#endif
    AP_U64 sequence;
};
struct tcp_reap_request {
    struct tcp_tuple tuple;
    AP_U64 cookie, expires, epoch;
};
#define TCP_TUPLE_LIFETIME_NS 120000000000ULL

struct lifetime_events {
    AP_U64 active, created, retired;
};
struct cache_reap_request {
    struct flow_key key;
    AP_U64 cookie, epoch;
    AP_U32 system, reserved;
};
struct route_cache_value {
    AP_U32 lock, retired;
    struct cached_route route;
    AP_U64 cookie, epoch, id, lifetime, admission, sequence;
#ifdef AP_BINDING_SNAPSHOT
    AP_U64 node, logical_node, logical_lifetime;
#else
    AP_U64 table, node, logical_table, logical_node, logical_lifetime;
#endif
    struct flow_key logical_key;
    AP_U32 kind, reserved;
};
