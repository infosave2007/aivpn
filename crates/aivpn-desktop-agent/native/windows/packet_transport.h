#pragma once

static BOOLEAN pt_zero(const UCHAR *bytes, SIZE_T count)
{
    for (SIZE_T i = 0; i < count; i++) if (bytes[i]) return FALSE;
    return TRUE;
}


static BOOLEAN pt_ready_locked(UINT32 profile, UINT64 generation, UINT64 endpoint)
{
    PC_PATH *path = pc_path_locked(profile, FALSE);
    const PC_TRANSPORT *transport = path ? &path->transport : NULL;
    return !pc_stopping && pc_writer && transport && transport->alive && transport->process &&
        transport->session == session_id && transport->generation == generation && endpoint && transport->endpoint == endpoint;
}

static void packet_process_exit(PEPROCESS process)
{
    KIRQL old;
    KeAcquireSpinLock(&pc_state_lock, &old);
    for (ULONG i = 0; i < PC_PATH_LIMIT; i++) {
        PC_PATH *path = &pc_paths[i];
        if (path->used && path->transport.process == process) {
            path->transport.alive = FALSE;
            path->transport.endpoint = 0;
            path->config.ready4 = path->config.ready6 = 0;
        }
    }
    KeReleaseSpinLock(&pc_state_lock, old);
}

static void pt_clear(void)
{
    for (ULONG i = 0; i < PC_PATH_LIMIT; i++) {
        KIRQL old;
        KeAcquireSpinLock(&pc_state_lock, &old);
        PC_PATH *path = &pc_paths[i];
        PEPROCESS previous = path->transport.process, owner = path->transport.socket_owner;
        RtlZeroMemory(&path->transport, sizeof(path->transport));
        path->config.ready4 = path->config.ready6 = 0;
        KeReleaseSpinLock(&pc_state_lock, old);
        if (previous) ObDereferenceObject(previous);
        if (owner) ObDereferenceObject(owner);
    }
}

static NTSTATUS pt_control(const AR_TRANSPORT *request, UINT32 profile)
{
    if (!request->generation || request->reserved || request->tail_reserved || request->operation < 1 || request->operation > 3)
        return STATUS_INVALID_PARAMETER;
    PEPROCESS process = NULL, previous = NULL, socket_owner = NULL, previous_owner = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    if (request->operation == 1) {
        if (!request->process_handle || !request->image_handle || request->endpoint || request->family || request->port ||
            !pt_zero(request->peer, sizeof(request->peer))) return STATUS_INVALID_PARAMETER;
        status = ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)request->process_handle, AR_PROCESS_QUERY,
            *PsProcessType, UserMode, (PVOID *)&process, NULL);
        if (!NT_SUCCESS(status)) return status;
        PACCESS_TOKEN token = PsReferencePrimaryToken(process);
        BOOLEAN restricted = SeTokenIsRestricted(token);
        PsDereferencePrimaryToken(token);
        status = restricted ? process_running(process) : STATUS_ACCESS_DENIED;
        if (NT_SUCCESS(status)) {
            PFILE_OBJECT image = NULL;
            status = ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)request->image_handle, FILE_READ_DATA | FILE_READ_ATTRIBUTES,
                *IoFileObjectType, UserMode, (PVOID *)&image, NULL);
            if (NT_SUCCESS(status)) {
                AR_PROCESS identity = {0};
                status = process_snapshot(process, &identity);
                if (NT_SUCCESS(status) && (!identity.self || !same_stream(identity.self->image, image) || image->SharedWrite))
                    status = STATUS_ACCESS_DENIED;
                process_release(&identity);
                ObDereferenceObject(image);
            }
        }
        if (!NT_SUCCESS(status)) { ObDereferenceObject(process); return status; }
    } else if (request->process_handle || request->image_handle) return STATUS_INVALID_PARAMETER;
    if (request->operation == 2 && (!request->endpoint || !request->port ||
        (request->family != 4 && request->family != 6) ||
        (request->family == 4 && !pt_zero(request->peer + 4, 12)))) return STATUS_INVALID_PARAMETER;
    if (request->operation == 3 && (request->endpoint || request->family || request->port ||
        !pt_zero(request->peer, sizeof(request->peer)))) return STATUS_INVALID_PARAMETER;
    if (request->operation == 2) {
        socket_owner = PsGetCurrentProcess();
        ObReferenceObject(socket_owner);
    }
    KIRQL old;
    KeAcquireSpinLock(&pc_state_lock, &old);
    PC_PATH *path = pc_path_locked(profile, request->operation == 1);
    PC_TRANSPORT *transport = path ? &path->transport : NULL;
    if (!transport) status = request->operation == 1 ? STATUS_INSUFFICIENT_RESOURCES : STATUS_NOT_FOUND;
    else if (request->operation == 1) {
        if (transport->session == session_id && request->generation <= transport->generation) status = STATUS_REVISION_MISMATCH;
        for (ULONG i = 0; NT_SUCCESS(status) && i < PC_PATH_LIMIT; i++)
            if (&pc_paths[i] != path && pc_paths[i].used && pc_paths[i].transport.process == process && pc_paths[i].transport.alive)
                status = STATUS_OBJECT_NAME_COLLISION;
        if (NT_SUCCESS(status)) {
            previous = transport->process; transport->process = process; process = NULL;
            previous_owner = transport->socket_owner; transport->socket_owner = NULL; transport->observed_owner = 0;
            transport->session = session_id; transport->generation = request->generation;
            transport->endpoint = 0; transport->alive = TRUE;
            path->config.ready4 = path->config.ready6 = 0;
        }
    } else if (transport->session != session_id || transport->generation != request->generation || !transport->process)
        status = STATUS_REVISION_MISMATCH;
    else if (request->operation == 3) {
        transport->endpoint = 0;
        transport->observed_owner = 0;
        path->config.ready4 = path->config.ready6 = 0;
    } else if (!transport->alive || transport->endpoint) status = STATUS_INVALID_DEVICE_STATE;
    else {
        previous_owner = transport->socket_owner; transport->socket_owner = socket_owner; socket_owner = NULL;
        transport->observed_owner = 0;
        transport->endpoint = request->endpoint; transport->family = request->family; transport->port = request->port;
        RtlCopyMemory(transport->peer, request->peer, sizeof(transport->peer));
    }
    KeReleaseSpinLock(&pc_state_lock, old);
    if (previous) ObDereferenceObject(previous);
    if (process) ObDereferenceObject(process);
    if (previous_owner) ObDereferenceObject(previous_owner);
    if (socket_owner) ObDereferenceObject(socket_owner);
    return status;
}

static void pt_receipt(UINT32 profile, AR_TRANSPORT_RECEIPT *receipt)
{
    RtlZeroMemory(receipt, sizeof(*receipt));
    receipt->version = 1; receipt->size = sizeof(*receipt);
    KIRQL old;
    KeAcquireSpinLock(&pc_state_lock, &old);
    PC_PATH *path = pc_path_locked(profile, FALSE);
    if (path) {
        const PC_TRANSPORT *transport = &path->transport;
        receipt->session = transport->session; receipt->generation = transport->generation; receipt->endpoint = transport->endpoint;
        receipt->observed_owner = transport->observed_owner;
        if (transport->socket_owner) receipt->socket_owner_pid = (UINT64)(ULONG_PTR)PsGetProcessId(transport->socket_owner);
        if (transport->process) receipt->worker_pid = (UINT64)(ULONG_PTR)PsGetProcessId(transport->process);
    }
    KeReleaseSpinLock(&pc_state_lock, old);
}

static unsigned pt_decision(const FWPS_INCOMING_METADATA_VALUES0 *metadata, UINT64 *endpoint, UINT64 flow_handle,
    const AIVPN_PACKET *tuple, UINT32 *profile, UINT64 *generation)
{
    AR_PROCESS identity = {0};
    pi_observe(metadata, &identity);
    KIRQL old;
    KeAcquireSpinLock(&pc_state_lock, &old);
    if (!*endpoint && flow_handle) {
        for (ULONG i = 0; i < FLOW_LIMIT; i++) {
            FLOW *flow = &pc_flows[i];
            if (flow->used && flow->transport_generation && flow->flow_handle == flow_handle && pc_equal_tuple(&flow->tuple, tuple)) {
                *endpoint = flow->endpoint;
                break;
            }
        }
    }
    unsigned result = 0;
    for (ULONG i = 0; i < PC_PATH_LIMIT; i++) {
        PC_PATH *path = &pc_paths[i];
        PC_TRANSPORT *transport = &path->transport;
        if (!path->used || !transport->process) continue;
        BOOLEAN same_process = identity.self && identity.self->process == transport->process;
        BOOLEAN same_owner = identity.self && identity.self->process == transport->socket_owner;
        if (same_process || (*endpoint && *endpoint == transport->endpoint)) {
            result = 2;
            if ((same_process || same_owner) && pt_ready_locked(path->profile, transport->generation, *endpoint) && tuple->protocol == 17 &&
                tuple->version == transport->family && tuple->destination_port == transport->port &&
                pc_same_address(tuple->destination, transport->peer, transport->family)) {
                *generation = transport->generation;
                *profile = path->profile;
                transport->observed_owner = same_owner ? 1 : 2;
                result = 1;
            }
            break;
        }
    }
    KeReleaseSpinLock(&pc_state_lock, old);
    process_release(&identity);
    return result;
}

static BOOLEAN pt_packet_blocked(const AIVPN_PACKET *packet, ULONG compartment)
{
    KIRQL old;
    KeAcquireSpinLock(&pc_state_lock, &old);
    BOOLEAN blocked = FALSE;
    for (ULONG i = 0; i < FLOW_LIMIT; i++) {
        FLOW *flow = &pc_flows[i];
        if (flow->used && flow->transport_generation && flow->compartment == compartment && pc_equal_tuple(packet, &flow->tuple)) {
            blocked = !pt_ready_locked(flow->transport_profile, flow->transport_generation, flow->endpoint);
            break;
        }
    }
    KeReleaseSpinLock(&pc_state_lock, old);
    return blocked;
}
