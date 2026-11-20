#pragma once
#include "packet_path_key.h"

#define PC_PATH_LIMIT 257u
#define PC_ANY_PROFILE MAXULONG
typedef struct {
    PEPROCESS process, socket_owner;
    UINT32 observed_owner, family;
    UINT16 port;
    UINT64 session, generation, endpoint;
    BOOLEAN alive;
    UCHAR peer[16];
} PC_TRANSPORT;
typedef struct {
    BOOLEAN used;
    UINT32 profile;
    AR_PACKET_CONFIG config;
    AIVPN_PATH_ROUTE route;
    UINT64 epoch, worker_session, worker_generation;
    PC_TRANSPORT transport;
} PC_PATH;
static PC_PATH pc_paths[PC_PATH_LIMIT];
static UINT64 pc_next_path_epoch;

/* Вызывается только под pc_state_lock. Нулевой профиль оставлен для staging ABI. */
static PC_PATH *pc_path_locked(UINT32 profile, BOOLEAN create)
{
    PC_PATH *empty = NULL;
    for (ULONG i = 0; i < PC_PATH_LIMIT; i++) {
        if (pc_paths[i].used && pc_paths[i].profile == profile) return &pc_paths[i];
        if (!pc_paths[i].used && !empty) empty = &pc_paths[i];
    }
    if (!create || !empty || profile == PC_ANY_PROFILE) return NULL;
    RtlZeroMemory(empty, sizeof(*empty));
    empty->used = TRUE;
    empty->profile = profile;
    return empty;
}

static PC_PATH *pc_flow_path_locked(const FLOW *flow)
{
    return pc_path_locked(flow->path_profile, FALSE);
}

static BOOLEAN pc_flow_route_locked(const FLOW *flow)
{
    PC_PATH *path = pc_flow_path_locked(flow);
    return !pc_stopping && pc_writer && path && aivpn_path_route_matches(&path->route, flow->path_epoch) && path->config.interface_index;
}

static BOOLEAN pc_flow_ready_locked(const FLOW *flow)
{
    PC_PATH *path = pc_flow_path_locked(flow);
    return !flow->endpoint_closed && pc_flow_route_locked(flow) &&
        (flow->tuple.version == 4 ? path->config.ready4 : path->config.ready6);
}

static void pc_paths_block_locked(void)
{
    for (ULONG i = 0; i < PC_PATH_LIMIT; i++) pc_paths[i].config.ready4 = pc_paths[i].config.ready6 = 0;
}
