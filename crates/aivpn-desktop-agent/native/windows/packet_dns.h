#pragma once
#include "../dns_ports.h"

#define PD_LIMIT 268
typedef struct {
    UINT64 endpoint;
    UINT32 family, protocol;
    UINT16 port;
    BOOLEAN listener;
    BOOLEAN bootstrap;
    UINT64 epoch, expires;
    UCHAR peer[16];
} PD_SOCKET;

static BOOLEAN pd_guard;
static UINT32 pd_compartment, pd_profile;
static UINT64 pd_session, pd_generation, pd_epoch;
static UINT64 pd_bootstrap_epoch;
static PEPROCESS pd_owner;
static PD_SOCKET pd_sockets[PD_LIMIT];

static BOOLEAN pd_loopback(const UCHAR *address, UINT32 family)
{
    static const UCHAR v4[4] = {127, 0, 0, 3};
    static const UCHAR v6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    return pc_same_address(address, family == 4 ? v4 : v6, family);
}

/* Вызывается под pc_state_lock из resource release. Endpoint не переживает socket. */
static void pd_release_locked(UINT64 endpoint)
{
    for (ULONG i = 0; i < PD_LIMIT; i++)
        if (pd_sockets[i].endpoint == endpoint) RtlZeroMemory(&pd_sockets[i], sizeof(pd_sockets[i]));
}

static void pd_disconnect(void)
{
    KIRQL old;
    KeAcquireSpinLock(&pc_state_lock, &old);
    PEPROCESS owner = pd_owner;
    pd_owner = NULL;
    pd_session = pd_generation = pd_epoch = 0;
    pd_bootstrap_epoch = 0;
    pd_profile = 0;
    RtlZeroMemory(pd_sockets, sizeof(pd_sockets));
    /* Guard остается до owned restore, в том числе после смерти службы. */
    KeReleaseSpinLock(&pc_state_lock, old);
    if (owner) ObDereferenceObject(owner);
}

static NTSTATUS pd_control(const AR_DNS *request)
{
    UINT32 op = request->operation;
    if (op < 1 || op > 8 || request->reserved || !request->compartment)
        return STATUS_INVALID_PARAMETER;
    if ((op <= 3 || op == 6 || op == 8) && (request->endpoint || request->family || request->protocol || request->port ||
        !pt_zero(request->peer, sizeof(request->peer)))) return STATUS_INVALID_PARAMETER;
    if (op <= 2 && (request->generation || request->epoch || request->profile)) return STATUS_INVALID_PARAMETER;
    if ((op == 3 || op == 4) && (!request->generation || !request->epoch || !request->profile))
        return STATUS_INVALID_PARAMETER;
    if ((op == 4 || op == 5 || op == 7) && (!request->endpoint || (request->family != 4 && request->family != 6) ||
        (request->protocol != 6 && request->protocol != 17) || !request->port ||
        pt_zero(request->peer, request->family == 4 ? 4 : 16) ||
        (request->family == 4 && !pt_zero(request->peer + 4, 12)))) return STATUS_INVALID_PARAMETER;
    if (op == 5 && (request->generation || request->epoch || request->profile || request->port != 53 ||
        !pd_loopback(request->peer, request->family))) return STATUS_INVALID_PARAMETER;
    if ((op == 6 || op == 7) && (!request->epoch || request->generation || request->profile))
        return STATUS_INVALID_PARAMETER;
    if (op == 8 && (request->epoch || request->generation || request->profile))
        return STATUS_INVALID_PARAMETER;

    PEPROCESS caller = PsGetCurrentProcess();
    ObReferenceObject(caller);
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL old;
    KeAcquireSpinLock(&pc_state_lock, &old);
    if (pc_stopping || ((pd_guard || pd_owner) && pd_compartment != request->compartment) ||
        (pd_owner && pd_owner != caller)) status = STATUS_ACCESS_DENIED;
    else if (op == 1) {
        if (!pd_owner) { pd_owner = caller; caller = NULL; }
        pd_guard = TRUE; pd_compartment = request->compartment;
    } else if (op == 2) {
        pd_guard = FALSE;
    } else if (op == 6) {
        if (pd_bootstrap_epoch) status = STATUS_INVALID_DEVICE_STATE;
        else {
            if (!pd_owner) { pd_owner = caller; caller = NULL; }
            pd_compartment = request->compartment;
            pd_bootstrap_epoch = request->epoch;
        }
    } else if (op == 8) {
        if (pd_owner != caller) status = STATUS_ACCESS_DENIED;
        else pd_bootstrap_epoch = 0;
    } else if (!pd_guard || pd_owner != caller || (pd_session && pd_session != session_id))
        { if (op != 7 || pd_owner != caller || !pd_bootstrap_epoch) status = STATUS_INVALID_DEVICE_STATE; }
    if (NT_SUCCESS(status) && op == 3) {
        PC_PATH *path = pc_path_locked(request->profile, FALSE);
        if (!path || !pt_ready_locked(request->profile, request->generation, path->transport.endpoint) ||
            request->compartment != path->config.compartment ||
            (pd_session == session_id && request->epoch <= pd_epoch)) status = STATUS_REVISION_MISMATCH;
        else {
            for (ULONG i = 0; i < PD_LIMIT; i++)
                if (!pd_sockets[i].listener && !pd_sockets[i].bootstrap) RtlZeroMemory(&pd_sockets[i], sizeof(pd_sockets[i]));
            pd_session = session_id; pd_generation = request->generation;
            pd_epoch = request->epoch; pd_profile = request->profile;
        }
    } else if (NT_SUCCESS(status) && (op == 4 || op == 5 || op == 7)) {
        PC_PATH *path = pc_path_locked(pd_profile, FALSE);
        if (op == 4 && (pd_session != session_id || request->generation != pd_generation ||
            request->epoch != pd_epoch || request->profile != pd_profile || !path ||
            !pt_ready_locked(pd_profile, pd_generation, path->transport.endpoint) || request->compartment != path->config.compartment))
            status = STATUS_REVISION_MISMATCH;
        if (op == 7 && (!pd_bootstrap_epoch || pd_bootstrap_epoch != request->epoch))
            status = STATUS_REVISION_MISMATCH;
        PD_SOCKET *slot = NULL;
        for (ULONG i = 0; NT_SUCCESS(status) && i < PD_LIMIT; i++) {
            if (pd_sockets[i].endpoint == request->endpoint) { status = STATUS_OBJECT_NAME_COLLISION; break; }
            if (!slot && !pd_sockets[i].endpoint) slot = &pd_sockets[i];
        }
        if (NT_SUCCESS(status) && !slot) status = STATUS_INSUFFICIENT_RESOURCES;
        if (NT_SUCCESS(status)) {
            slot->endpoint = request->endpoint; slot->family = request->family;
            slot->protocol = request->protocol; slot->port = request->port;
            slot->listener = op == 5;
            slot->bootstrap = op == 7;
            slot->epoch = op == 7 ? request->epoch : 0;
            slot->expires = op == 7 ? KeQueryInterruptTime() + 60000000ULL : 0;
            RtlCopyMemory(slot->peer, request->peer, sizeof(slot->peer));
        }
    }
    KeReleaseSpinLock(&pc_state_lock, old);
    if (caller) ObDereferenceObject(caller);
    if (NT_SUCCESS(status) && op == 2) pd_disconnect();
    return status;
}

static BOOLEAN pd_bootstrap_ready_locked(const PD_SOCKET *socket, const AIVPN_PACKET *tuple)
{
    return socket->bootstrap && pd_owner && socket->epoch && socket->epoch == pd_bootstrap_epoch &&
        socket->expires > KeQueryInterruptTime() && socket->family == tuple->version &&
        socket->protocol == tuple->protocol && socket->port == tuple->destination_port &&
        pc_same_address(socket->peer, tuple->destination, tuple->version);
}

static BOOLEAN pd_local_locked(const AIVPN_PACKET *tuple)
{
    for (ULONG i = 0; i < PD_LIMIT; i++) {
        const PD_SOCKET *socket = &pd_sockets[i];
        if (socket->endpoint && socket->listener && socket->family == tuple->version &&
            socket->protocol == tuple->protocol && socket->port == tuple->destination_port &&
            pc_same_address(socket->peer, tuple->destination, tuple->version)) return TRUE;
    }
    return FALSE;
}

/* 0 - обычная политика,1 - свой local listener,2 - точный VPN upstream,3 - запрет. */
static unsigned pd_decision(const FWPS_INCOMING_METADATA_VALUES0 *metadata, UINT64 endpoint,
    const AIVPN_PACKET *tuple, struct ap_decision *decision)
{
    KIRQL old;
    ULONG compartment = metadata->currentMetadataValues & FWPS_METADATA_FIELD_COMPARTMENT_ID ?
        metadata->compartmentId : UNSPECIFIED_COMPARTMENT_ID;
    KeAcquireSpinLock(&pc_state_lock, &old);
    BOOLEAN scoped = (pd_guard || pd_bootstrap_epoch) && compartment == pd_compartment;
    BOOLEAN candidate = FALSE;
    if (scoped && endpoint) {
        for (ULONG i = 0; i < PD_LIMIT; i++)
            if (pd_sockets[i].endpoint == endpoint && !pd_sockets[i].listener) { candidate = TRUE; break; }
    }
    KeReleaseSpinLock(&pc_state_lock, old);
    BOOLEAN guarded = ar_guarded_dns_destination(tuple->destination_port, tuple->version, tuple->destination);
    if (!scoped || (!candidate && !guarded)) return 0;
    AR_PROCESS identity = {0};
    if (candidate) pi_observe(metadata, &identity);
    KeAcquireSpinLock(&pc_state_lock, &old);
    unsigned result = 0;
    if ((pd_guard || pd_bootstrap_epoch) && compartment == pd_compartment) {
        if (pd_guard && guarded)
            result = tuple->destination_port == 53 && pd_local_locked(tuple) ? 1 : 3;
        for (ULONG i = 0; i < PD_LIMIT; i++) {
            const PD_SOCKET *socket = &pd_sockets[i];
            if (!endpoint || socket->endpoint != endpoint || socket->listener) continue;
            result = 3;
            if (identity.self && identity.self->process == pd_owner && pd_bootstrap_ready_locked(socket, tuple)) {
                RtlZeroMemory(decision, sizeof(*decision)); decision->rule = AP_NO_RULE;
                result = 1;
            }
            else if (!socket->bootstrap && pd_owner && identity.self && identity.self->process == pd_owner && pd_session == session_id &&
                pc_path_locked(pd_profile, FALSE) && pt_ready_locked(pd_profile, pd_generation, pc_path_locked(pd_profile, FALSE)->transport.endpoint) &&
                socket->family == tuple->version && socket->protocol == tuple->protocol &&
                socket->port == tuple->destination_port && pc_same_address(socket->peer, tuple->destination, tuple->version)) {
                RtlZeroMemory(decision, sizeof(*decision));
                decision->action = 2; decision->profile = pd_profile; decision->rule = AP_NO_RULE;
                result = 2;
            }
            break;
        }
    }
    KeReleaseSpinLock(&pc_state_lock, old);
    process_release(&identity);
    return result;
}

static BOOLEAN pd_packet_blocked(const AIVPN_PACKET *tuple, ULONG compartment)
{
    if ((tuple->protocol != 6 && tuple->protocol != 17) ||
        !ar_guarded_dns_destination(tuple->destination_port, tuple->version, tuple->destination)) return FALSE;
    KIRQL old;
    KeAcquireSpinLock(&pc_state_lock, &old);
    BOOLEAN blocked = pd_guard && compartment == pd_compartment && !pd_local_locked(tuple);
    for (ULONG i = 0; blocked && i < FLOW_LIMIT; i++) {
        const FLOW *flow = &pc_flows[i];
        if (flow->used && !flow->endpoint_closed && flow->transport_generation &&
            flow->compartment == compartment && pc_equal_tuple(&flow->tuple, tuple) &&
            pt_ready_locked(flow->transport_profile, flow->transport_generation, flow->endpoint)) blocked = FALSE;
        if (flow->used && !flow->endpoint_closed && flow->compartment == compartment && pc_equal_tuple(&flow->tuple, tuple)) {
            for (ULONG socket = 0; blocked && socket < PD_LIMIT; socket++)
                if (pd_sockets[socket].endpoint == flow->endpoint && pd_bootstrap_ready_locked(&pd_sockets[socket], tuple))
                    blocked = FALSE;
        }
    }
    KeReleaseSpinLock(&pc_state_lock, old);
    return blocked;
}
