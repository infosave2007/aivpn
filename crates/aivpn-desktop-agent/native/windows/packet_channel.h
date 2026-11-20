#pragma once
#include "packet_protocol.h"
#include "packet.c"
#include "packet_ndp.h"
#include "fragment.c"
#include "reassembly.c"
#include "packet_nat.h"

#define FLOW_LIMIT 512
#define FLOW_BUCKETS 1024
#define PACKET_LIMIT 65535
#define INJECTION_LIMIT 512
#define QUEUE_LIMIT 4096
#define BATCH_LIMIT 1024
#define TAG 'rpVA'

typedef struct {
    BOOLEAN used, endpoint_closed, resource_released;
    UCHAR association;
    USHORT original_next;
    ULONG injections;
    AIVPN_PACKET tuple;
    UINT64 endpoint, parent_endpoint, flow_handle;
    UINT64 transport_generation;
    UINT32 transport_profile, path_profile;
    UINT64 path_epoch;
    ULONG compartment;
    ULONG interface_index;
    ULONG subinterface_index;
    USHORT translated_port;
    struct ap_decision decision;
} FLOW;

typedef struct {
    MDL *mdl;
    UCHAR *bytes;
    FLOW *reservation;
} INJECTION;


static KSPIN_LOCK pc_state_lock;
static KSPIN_LOCK pc_assembly_lock;
static AIVPN_REASSEMBLER pc_reassembler;
static FLOW pc_flows[FLOW_LIMIT];
static USHORT pc_original[FLOW_BUCKETS], pc_reverse[65536];
static PC_NAT_ALLOCATOR pc_nat;
typedef struct { LIST_ENTRY link; ULONG length, profile; UINT64 generation, epoch; UCHAR data[]; } QUEUED_PACKET;
static LIST_ENTRY pc_packets;
static ULONG pc_packet_count, pc_packet_bytes;
static PKEVENT pc_packet_event;
static HANDLE pc_inject[2];
static NDIS_HANDLE pc_pool;
static UINT32 pc_callout_ids[12];
static ULONG pc_registered;

static volatile LONG pc_redirected4, pc_redirected6, pc_blocked, pc_last_status;
static volatile LONG pc_seen_out, pc_seen_in, pc_active_flows, pc_parse_failed, pc_completed, pc_inflight;
static volatile LONG pc_stopping;
static BOOLEAN pc_armed;
static volatile LONG pc_maximum_batch;
static PFILE_OBJECT pc_writer;
static void pc_block_ready(void);

#include "packet_paths.h"

static void pc_block(FWPS_CLASSIFY_OUT0 *out)
{
    out->actionType = FWP_ACTION_BLOCK;
    out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    InterlockedIncrement(&pc_blocked);
}

static BOOLEAN pc_same_address(const UCHAR *left, const UCHAR *right, unsigned version)
{
    SIZE_T size = version == 4 ? 4 : 16;
    return RtlCompareMemory(left, right, size) == size;
}

static BOOLEAN pc_equal_peer(const AIVPN_PACKET *left, const AIVPN_PACKET *right)
{
    return left->version == right->version && left->protocol == right->protocol &&
        pc_same_address(left->source, right->source, left->version) &&
        pc_same_address(left->destination, right->destination, left->version);
}

static BOOLEAN pc_equal_tuple(const AIVPN_PACKET *left, const AIVPN_PACKET *right)
{
    return pc_equal_peer(left, right) && left->source_port == right->source_port &&
        left->destination_port == right->destination_port;
}

static void pc_complete_close(UINT64 endpoint);
static void pd_release_locked(UINT64 endpoint);

#include "packet_lifetime.h"

#include "packet_transport.h"
#include "packet_dns.h"
#include "packet_admission.h"
#include "packet_closure.h"
#include "packet_lab.h"

static BOOLEAN pc_icmp_tuple(NET_BUFFER_LIST *packet, ULONG flags,
    const FWPS_INCOMING_METADATA_VALUES0 *metadata, AIVPN_PACKET *tuple)
{
    UCHAR storage[8] = {0};
    if (packet) {
        NET_BUFFER *buffer = NET_BUFFER_LIST_FIRST_NB(packet);
        UCHAR *header = buffer && NET_BUFFER_DATA_LENGTH(buffer) >= sizeof(storage) ?
            NdisGetDataBuffer(buffer, sizeof(storage), storage, 1, 0) : NULL;
        if (!header || header[0] != tuple->source_port || header[1] != tuple->destination_port) return FALSE;
        return aivpn_icmp_echo_parameters(tuple, header, sizeof(storage));
    }
    /* При reauthorization WFP может не передать NBL. ID берется только из
       уже известного того же OS flow, а не из type/code или произвольного PID. */
    if (!(flags & FWP_CONDITION_FLAG_IS_REAUTHORIZE) ||
        !(metadata->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) || !metadata->flowHandle ||
        tuple->source_port > 255 || tuple->destination_port > 255) return FALSE;
    storage[0] = (UCHAR)tuple->source_port;
    storage[1] = (UCHAR)tuple->destination_port;
    if (!aivpn_icmp_echo_parameters(tuple, storage, sizeof(storage))) return FALSE;
    KIRQL old;
    BOOLEAN found = FALSE;
    KeAcquireSpinLock(&pa_lock, &old);
    for (LIST_ENTRY *entry = pa_active.Flink; entry != &pa_active; entry = entry->Flink) {
        PA_OPERATION *operation = CONTAINING_RECORD(entry, PA_OPERATION, active);
        if (!operation->cancelled && operation->flow == metadata->flowHandle && pc_equal_peer(&operation->tuple, tuple)) {
            tuple->source_port = operation->tuple.source_port;
            tuple->destination_port = operation->tuple.destination_port;
            found = TRUE; break;
        }
    }
    KeReleaseSpinLock(&pa_lock, old);
    if (found) return TRUE;
    KeAcquireSpinLock(&pc_state_lock, &old);
    for (ULONG i = 0; i < FLOW_LIMIT; i++) {
        FLOW *flow = &pc_flows[i];
        if (flow->used && !flow->endpoint_closed && flow->flow_handle == metadata->flowHandle && pc_equal_peer(&flow->tuple, tuple)) {
            tuple->source_port = flow->tuple.source_port;
            tuple->destination_port = flow->tuple.destination_port;
            found = TRUE; break;
        }
    }
    KeReleaseSpinLock(&pc_state_lock, old);
    return found;
}

static void pc_auth(const FWPS_INCOMING_VALUES0 *values, const FWPS_INCOMING_METADATA_VALUES0 *metadata,
    NET_BUFFER_LIST *packet, FWPS_CLASSIFY_OUT0 *out)
{
    AR_LAB_HIT(23);
    BOOLEAN ipv4 = values->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4;
    ULONG auth_flags = values->incomingValue[ipv4 ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS : FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS].value.uint32;
    if (auth_flags & FWP_CONDITION_FLAG_IS_REAUTHORIZE) {
        AR_LAB_HIT(24); AR_LAB_SET(48, metadata->currentMetadataValues); AR_LAB_SET(49, auth_flags);
    }
    AIVPN_PACKET tuple = {0};
    tuple.version = ipv4 ? 4 : 6;
    unsigned local_address = ipv4 ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS : FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS;
    unsigned remote_address = ipv4 ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS : FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS;
    if (ipv4) {
        ULONG local = RtlUlongByteSwap(values->incomingValue[local_address].value.uint32);
        ULONG remote = RtlUlongByteSwap(values->incomingValue[remote_address].value.uint32);
        RtlCopyMemory(tuple.source, &local, 4);
        RtlCopyMemory(tuple.destination, &remote, 4);
    } else {
        RtlCopyMemory(tuple.source, values->incomingValue[local_address].value.byteArray16->byteArray16, 16);
        RtlCopyMemory(tuple.destination, values->incomingValue[remote_address].value.byteArray16->byteArray16, 16);
    }

    tuple.source_port = values->incomingValue[ipv4 ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT : FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT].value.uint16;
    tuple.destination_port = values->incomingValue[ipv4 ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT : FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT].value.uint16;
    tuple.protocol = values->incomingValue[ipv4 ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL : FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL].value.uint8;
    // NDP создает само ядро. Обычный процесс не получает исключение для raw ICMP.
    BOOLEAN kernel_control = (metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) &&
        metadata->processId == (UINT64)(ULONG_PTR)PsGetProcessId(PsInitialSystemProcess);
    if (aivpn_ndp_control_allowed(&tuple, kernel_control)) return;
    if (tuple.protocol != 6 && tuple.protocol != 17) {
        /* В ALE echo ID относится к OS flow, а поля port содержат ICMP type/code. */
        if (!pc_icmp_tuple(packet, auth_flags, metadata, &tuple)) {
            AR_LAB_HIT(26); pc_block(out); return;
        }
    }
    UINT64 endpoint = metadata->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE ? metadata->transportEndpointHandle : 0;
    UINT64 flow_handle = metadata->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE ? metadata->flowHandle : 0;
    UINT64 parent_endpoint = metadata->currentMetadataValues & FWPS_METADATA_FIELD_PARENT_ENDPOINT_HANDLE ? metadata->parentEndpointHandle : 0;
    UINT64 transport_generation = 0;
    UINT32 transport_profile = 0;
    unsigned transport = pt_decision(metadata, &endpoint, flow_handle, &tuple, &transport_profile, &transport_generation);
    if (transport == 2) { pc_block(out); return; }
    if (!endpoint) AR_LAB_HIT(25);
    struct ap_decision decision = {0};
    unsigned dns = transport == 1 ? 0 : pd_decision(metadata, endpoint, &tuple, &decision);
    if (dns == 3) { pc_block(out); return; }
    unsigned pending = dns ? 0 : pa_decision(&endpoint, &parent_endpoint, flow_handle, &tuple, &decision);
    if (pending == 2) { pc_block(out); return; }
    if (pending && decision.action != 0 && decision.action != 2) {
        pc_block(out); pa_admitted(endpoint, &tuple, FALSE); return;
    }
    KIRQL saved_irql;
    KeAcquireSpinLock(&pc_state_lock, &saved_irql);
    BOOLEAN retained = FALSE, retained_ready = FALSE;
    for (ULONG i = 0; i < FLOW_LIMIT; i++) if (pc_flows[i].used &&
        flow_handle && pc_flows[i].flow_handle == flow_handle &&
        (!endpoint || pc_flows[i].endpoint == endpoint) && pc_equal_tuple(&pc_flows[i].tuple, &tuple)) {
        retained = TRUE;
        endpoint = pc_flows[i].endpoint;
        retained_ready = !pc_flows[i].endpoint_closed && (pc_flows[i].decision.action == 0 ||
            pc_flow_route_locked(&pc_flows[i]));
        if (pc_flows[i].transport_generation)
            retained_ready = !pc_flows[i].endpoint_closed && pt_ready_locked(pc_flows[i].transport_profile, pc_flows[i].transport_generation, endpoint);
        break;
    }
    KeReleaseSpinLock(&pc_state_lock, saved_irql);
    if (retained) {
        if (!retained_ready) pc_block(out); else out->actionType = FWP_ACTION_PERMIT;
        pa_admitted(endpoint, &tuple, retained_ready);
        return;
    }
    if (!endpoint || !flow_handle) { pc_block(out); return; }
    BOOLEAN known = dns || pending || transport == 1;
    if (transport == 1) { RtlZeroMemory(&decision, sizeof(decision)); decision.rule = AP_NO_RULE; }
    else if (!pending && !dns) decision = packet_decision(metadata, tuple.version, tuple.destination, &known);
    if (known) { AR_LAB_HIT(29); AR_LAB_SET(30, decision.action); }
    if (!known) {
        pc_block(out);
        if (pa_pend(values, metadata, packet, &tuple)) out->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        return;
    }
    if (decision.action != 0 && decision.action != 2) {
        pc_block(out); pa_admitted(endpoint, &tuple, FALSE); return;
    }
    KIRQL previous;
    KeAcquireSpinLock(&pc_state_lock, &previous);
    PC_PATH *path = pc_path_locked(pi_runtime ? decision.profile : 0, FALSE);
    BOOLEAN ready = decision.action == 0 ||
        (!pc_stopping && path && path->config.interface_index && (ipv4 ? path->config.ready4 : path->config.ready6));
    if (transport == 1) ready = pt_ready_locked(transport_profile, transport_generation, endpoint);
    LONG slot = -1;
    for (ULONG index = 0; ready && index < FLOW_LIMIT; index++) {
        if (pc_flows[index].used && pc_equal_tuple(&pc_flows[index].tuple, &tuple)) {
            BOOLEAN same = pc_flows[index].endpoint == endpoint && pc_flows[index].flow_handle == flow_handle &&
                !pc_flows[index].endpoint_closed;
            /* ICMP API повторно использует ID для новых endpoint. Два решения
               SYSTEM не меняют пакетный путь и могут жить до разных flowDelete.
               При наличии VPN совпадение остается запрещенным. */
            if (!same && (tuple.protocol == 1 || tuple.protocol == 58) &&
                decision.action == 0 && pc_flows[index].decision.action == 0) continue;
            if (!same) ready = FALSE;
            slot = (LONG)index; break;
        }
        if (!pc_flows[index].used && !pc_flows[index].injections && slot < 0) slot = (LONG)index;
    }
    USHORT translated_port = 0;
    if (ready && slot >= 0 && !pc_flows[slot].used && decision.action == 2) {
        translated_port = pc_nat_reserve(&pc_nat, KeQueryInterruptTime());
        if (!translated_port) {
            ready = FALSE;
            InterlockedExchange(&pc_last_status, STATUS_INSUFFICIENT_RESOURCES);
        }
    }
    if (ready && slot >= 0) {
        FLOW *flow = &pc_flows[slot];
        BOOLEAN fresh = !flow->used;
        if (fresh) { RtlZeroMemory(flow, sizeof(*flow)); InterlockedIncrement(&pc_active_flows); }
        flow->used = TRUE;
        flow->tuple = tuple;
        flow->endpoint = endpoint;
        flow->parent_endpoint = parent_endpoint;
        flow->flow_handle = flow_handle;
        flow->transport_generation = transport_generation;
        flow->transport_profile = transport_profile;
        flow->path_profile = path ? path->profile : 0;
        flow->path_epoch = path ? path->route.epoch : 0;
        flow->compartment = metadata->currentMetadataValues & FWPS_METADATA_FIELD_COMPARTMENT_ID ? metadata->compartmentId : UNSPECIFIED_COMPARTMENT_ID;
        flow->interface_index = values->incomingValue[ipv4 ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_INTERFACE_INDEX : FWPS_FIELD_ALE_AUTH_CONNECT_V6_INTERFACE_INDEX].value.uint32;
        flow->subinterface_index = values->incomingValue[ipv4 ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_SUB_INTERFACE_INDEX : FWPS_FIELD_ALE_AUTH_CONNECT_V6_SUB_INTERFACE_INDEX].value.uint32;
        if (fresh && decision.action == 2) flow->translated_port = translated_port;
        flow->decision = decision;
        if (fresh) { pc_index_insert(flow); pc_lifetime_trace(1, metadata, flow); }
    }
    KeReleaseSpinLock(&pc_state_lock, previous);
    if (!ready || slot < 0) pc_block(out); else out->actionType = FWP_ACTION_PERMIT;
    pa_admitted(endpoint, &tuple, ready && slot >= 0);
}

static void pc_release_injection(INJECTION *owned, NET_BUFFER_LIST *nbl)
{
    if (owned->reservation) {
        KIRQL old;
        KeAcquireSpinLock(&pc_state_lock, &old);
        UINT64 endpoint = owned->reservation->endpoint;
        owned->reservation->injections--;
        pc_try_retire(owned->reservation);
        KeReleaseSpinLock(&pc_state_lock, old);
        pc_complete_close(endpoint);
    }
    if (nbl) FwpsFreeNetBufferList0(nbl);
    if (owned->mdl) IoFreeMdl(owned->mdl);
    if (owned->bytes) ExFreePoolWithTag(owned->bytes, TAG);
    ExFreePoolWithTag(owned, TAG);
    InterlockedDecrement(&pc_inflight);
}

static void NTAPI pc_injection_complete(void *context, NET_BUFFER_LIST *nbl, BOOLEAN dispatch_level)
{
    UNREFERENCED_PARAMETER(dispatch_level);
    if (!NT_SUCCESS(NET_BUFFER_LIST_STATUS(nbl))) InterlockedExchange(&pc_last_status, NET_BUFFER_LIST_STATUS(nbl));
    InterlockedIncrement(&pc_completed);
    pc_release_injection(context, nbl);
}

static BOOLEAN pc_owned_packet(NET_BUFFER_LIST *nbl)
{
    for (ULONG index = 0; index < 2; index++) {
        FWPS_PACKET_INJECTION_STATE state = FwpsQueryPacketInjectionState0(pc_inject[index], nbl, NULL);
        if (state == FWPS_PACKET_INJECTED_BY_SELF || state == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) return TRUE;
    }
    return FALSE;
}

static BOOLEAN pc_find_flow(const AIVPN_PACKET *packet, BOOLEAN inbound, ULONG compartment,
    ULONG arrival_interface, UINT32 profile, FLOW *result, AR_PACKET_CONFIG *current)
{
    KIRQL previous;
    BOOLEAN found = FALSE;
    KeAcquireSpinLock(&pc_state_lock, &previous);
    const FLOW *selected = NULL;
    if (!inbound) {
        for (USHORT link = pc_original[pc_tuple_hash(packet, compartment)]; link; link = pc_flows[link - 1].original_next) {
            const FLOW *flow = &pc_flows[link - 1];
            if (flow->used && flow->decision.action == 2 && flow->compartment == compartment && pc_equal_tuple(&flow->tuple, packet)) {
                selected = flow; break;
            }
        }
    } else {
        USHORT link = pc_reverse[packet->destination_port];
        if (link) {
            const FLOW *flow = &pc_flows[link - 1];
            PC_PATH *path = pc_flow_path_locked(flow);
            if (flow->used && !flow->endpoint_closed && flow->decision.action == 2 && path && flow->compartment == compartment &&
                arrival_interface == path->config.interface_index && flow->tuple.version == packet->version &&
                flow->tuple.protocol == packet->protocol && flow->tuple.destination_port == packet->source_port &&
                pc_same_address(flow->tuple.destination, packet->source, packet->version) &&
                pc_same_address(packet->destination, packet->version == 4 ? path->config.address4 : path->config.address6, packet->version))
                selected = flow;
        }
    }
    if (selected) {
        PC_PATH *path = pc_flow_path_locked(selected);
        BOOLEAN ready = pc_flow_ready_locked(selected);
        if (!inbound || (path && (profile == PC_ANY_PROFILE || path->profile == profile) && ready)) {
            *result = *selected;
            RtlZeroMemory(current, sizeof(*current));
            if (path) *current = path->config;
            // Защищенный исходящий поток остается защищенным и без readiness.
            if (!ready) current->ready4 = current->ready6 = 0;
            found = TRUE;
        }
    }
    KeReleaseSpinLock(&pc_state_lock, previous);
    return found;
}

static void pc_free_packet_list(LIST_ENTRY *head)
{
    while (!IsListEmpty(head)) {
        LIST_ENTRY *entry = RemoveHeadList(head);
        ExFreePoolWithTag(CONTAINING_RECORD(entry, QUEUED_PACKET, link), TAG);
    }
}

static NTSTATUS pc_enqueue_packet(const UCHAR *bytes, const AIVPN_PACKET *packet, const FLOW *flow, const AR_PACKET_CONFIG *current)
{
    UCHAR *translated = ExAllocatePool2(POOL_FLAG_NON_PAGED, packet->size, TAG);
    if (!translated) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(translated, bytes, packet->size);
    const UCHAR *address = packet->version == 4 ? current->address4 : current->address6;
    if (!aivpn_packet_rewrite(translated, packet->size, 0, address, flow->translated_port) || !aivpn_packet_clamp_mss(translated, packet->size, current->packet_mtu)) {
        ExFreePoolWithTag(translated, TAG); return STATUS_INVALID_PARAMETER;
    }
    unsigned count = aivpn_packet_fragment_count(translated, packet->size, current->packet_mtu);
    if (!count || count > INJECTION_LIMIT) { ExFreePoolWithTag(translated, TAG); return STATUS_INVALID_BUFFER_SIZE; }
    LIST_ENTRY pending; InitializeListHead(&pending);
    ULONG total_bytes = 0;
    static volatile LONG fragment_id;
    ULONG id = (ULONG)InterlockedIncrement(&fragment_id);
    NTSTATUS status = STATUS_SUCCESS;
    for (unsigned index = 0; index < count; index++) {
        QUEUED_PACKET *owned = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*owned) + current->packet_mtu, TAG);
        if (!owned) { status = STATUS_INSUFFICIENT_RESOURCES; break; }
        owned->length = (ULONG)aivpn_packet_fragment_write(translated, packet->size, current->packet_mtu,
            id, index, owned->data, current->packet_mtu);
        if (!owned->length) { ExFreePoolWithTag(owned, TAG); status = STATUS_INVALID_BUFFER_SIZE; break; }
        total_bytes += owned->length;
        InsertTailList(&pending, &owned->link);
    }
    ExFreePoolWithTag(translated, TAG);
    if (!NT_SUCCESS(status)) { pc_free_packet_list(&pending); return status; }
    KIRQL previous;
    KeAcquireSpinLock(&pc_state_lock, &previous);
    PC_PATH *path = pc_flow_path_locked(flow);
    BOOLEAN ready = pc_writer && pc_packet_event && pc_flow_ready_locked(flow);
    BOOLEAN fits = pc_packet_count + count <= QUEUE_LIMIT && pc_packet_bytes + total_bytes <= 4 * 1024 * 1024;
    if (ready && fits) {
        while (!IsListEmpty(&pending)) {
            LIST_ENTRY *entry = RemoveHeadList(&pending);
            QUEUED_PACKET *queued = CONTAINING_RECORD(entry, QUEUED_PACKET, link);
            queued->profile = path->profile; queued->generation = path->transport.generation; queued->epoch = path->epoch;
            InsertTailList(&pc_packets, entry);
        }
        pc_packet_count += count; pc_packet_bytes += total_bytes;
        KeSetEvent(pc_packet_event, IO_NO_INCREMENT, FALSE);
    }
    KeReleaseSpinLock(&pc_state_lock, previous);
    pc_free_packet_list(&pending);
    return ready && fits ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

static NTSTATUS pc_inject_copy(const UCHAR *bytes, const AIVPN_PACKET *packet, const FLOW *flow,
    const AR_PACKET_CONFIG *current, BOOLEAN inbound)
{
    if (InterlockedIncrement(&pc_inflight) > INJECTION_LIMIT) {
        InterlockedDecrement(&pc_inflight);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    INJECTION *owned = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*owned), TAG);
    if (!owned) { InterlockedDecrement(&pc_inflight); return STATUS_INSUFFICIENT_RESOURCES; }
    owned->bytes = ExAllocatePool2(POOL_FLAG_NON_PAGED, packet->size, TAG);
    if (!owned->bytes) { pc_release_injection(owned, NULL); return STATUS_INSUFFICIENT_RESOURCES; }
    RtlCopyMemory(owned->bytes, bytes, packet->size);
    const UCHAR *address = inbound ? flow->tuple.source : packet->source;
    AIVPN_PACKET echo = *packet;
    BOOLEAN icmp_error = (packet->protocol == 1 || packet->protocol == 58) &&
        !aivpn_icmp_echo_parameters(&echo, owned->bytes + packet->transport, packet->size - packet->transport);
    BOOLEAN rewritten = icmp_error ? (inbound && aivpn_icmp_error_rewrite(owned->bytes, packet->size, address, (USHORT)flow->tuple.source_port)) :
        aivpn_packet_rewrite(owned->bytes, packet->size, inbound, address,
            inbound ? (USHORT)flow->tuple.source_port : (USHORT)packet->source_port);
    if (!rewritten) {
        pc_release_injection(owned, NULL); return STATUS_DATA_ERROR;
    }
    if (inbound && !icmp_error && !aivpn_packet_clamp_mss(owned->bytes, packet->size, current->packet_mtu)) {
        pc_release_injection(owned, NULL); return STATUS_DATA_ERROR;
    }
    owned->mdl = IoAllocateMdl(owned->bytes, (ULONG)packet->size, FALSE, FALSE, NULL);
    if (!owned->mdl) { pc_release_injection(owned, NULL); return STATUS_INSUFFICIENT_RESOURCES; }
    MmBuildMdlForNonPagedPool(owned->mdl);
    NET_BUFFER_LIST *copy = NULL;
    NTSTATUS status = FwpsAllocateNetBufferAndNetBufferList0(pc_pool, 0, 0, owned->mdl, 0, packet->size, &copy);
    if (!NT_SUCCESS(status)) { pc_release_injection(owned, NULL); return status; }
    HANDLE handle = pc_inject[packet->version == 4 ? 0 : 1];
    if (inbound) {
        KIRQL old;
        KeAcquireSpinLock(&pc_state_lock, &old);
        BOOLEAN ready = pc_writer && pc_flow_ready_locked(flow);
        BOOLEAN retained = FALSE;
        for (ULONG i = 0; ready && i < FLOW_LIMIT; i++) {
            FLOW *live = &pc_flows[i];
            if (live->used && !live->endpoint_closed && live->endpoint == flow->endpoint && live->flow_handle == flow->flow_handle &&
                live->path_epoch == flow->path_epoch && pc_equal_tuple(&live->tuple, &flow->tuple)) {
                live->injections++;
                owned->reservation = live;
                retained = TRUE;
                break;
            }
        }
        /* Допуск фиксируется здесь. CLOSE удерживает сам endpoint до completion. */
        KeReleaseSpinLock(&pc_state_lock, old);
        /* TCP/IP может сразу вызвать classify и completion. После успеха owned уже может быть освобожден. */
        status = ready && retained ? pc_lab_before_receive(flow) : STATUS_NOT_FOUND;
        if (NT_SUCCESS(status)) status = FwpsInjectNetworkReceiveAsync0(handle, NULL, 0, flow->compartment,
            flow->interface_index, flow->subinterface_index, copy, pc_injection_complete, owned);
    } else status = FwpsInjectNetworkSendAsync0(handle, NULL, 0, flow->compartment, copy, pc_injection_complete, owned);
    if (!NT_SUCCESS(status)) pc_release_injection(owned, copy);
    return status;
}

static BOOLEAN pc_protected_addresses(const FWPS_INCOMING_VALUES0 *values, ULONG compartment, BOOLEAN ipv4)
{
    UCHAR source[16] = {0}, destination[16] = {0};
    unsigned local = ipv4 ? FWPS_FIELD_OUTBOUND_IPPACKET_V4_IP_LOCAL_ADDRESS : FWPS_FIELD_OUTBOUND_IPPACKET_V6_IP_LOCAL_ADDRESS;
    unsigned remote = ipv4 ? FWPS_FIELD_OUTBOUND_IPPACKET_V4_IP_REMOTE_ADDRESS : FWPS_FIELD_OUTBOUND_IPPACKET_V6_IP_REMOTE_ADDRESS;
    if (ipv4) {
        ULONG left = RtlUlongByteSwap(values->incomingValue[local].value.uint32);
        ULONG right = RtlUlongByteSwap(values->incomingValue[remote].value.uint32);
        RtlCopyMemory(source, &left, 4); RtlCopyMemory(destination, &right, 4);
    } else {
        RtlCopyMemory(source, values->incomingValue[local].value.byteArray16->byteArray16, 16);
        RtlCopyMemory(destination, values->incomingValue[remote].value.byteArray16->byteArray16, 16);
    }
    KIRQL previous;
    BOOLEAN found = FALSE;
    KeAcquireSpinLock(&pc_state_lock, &previous);
    for (ULONG index = 0; index < FLOW_LIMIT; index++) {
        FLOW *flow = &pc_flows[index];
        if (flow->used && flow->compartment == compartment && flow->tuple.version == (ipv4 ? 4u : 6u) &&
            pc_same_address(source, flow->tuple.source, flow->tuple.version) && pc_same_address(destination, flow->tuple.destination, flow->tuple.version)) { found = TRUE; break; }
    }
    KeReleaseSpinLock(&pc_state_lock, previous);
    return found;
}

static unsigned pc_inspect_buffer(NET_BUFFER *buffer, BOOLEAN inbound, BOOLEAN ipv4, ULONG retreat,
    ULONG compartment, ULONG arrival, BOOLEAN potential, BOOLEAN apply, BOOLEAN mixed)
{
    if (retreat && NdisRetreatNetBufferDataStart(buffer, retreat, 0, NULL) != NDIS_STATUS_SUCCESS) return 2;
    ULONG length = NET_BUFFER_DATA_LENGTH(buffer);
    UCHAR *storage = NULL;
    UCHAR *bytes = length && length <= PACKET_LIMIT ? NdisGetDataBuffer(buffer, length, NULL, 1, 0) : NULL;
    if (!bytes && length && length <= PACKET_LIMIT) {
        storage = ExAllocatePool2(POOL_FLAG_NON_PAGED, length, TAG);
        if (storage) bytes = NdisGetDataBuffer(buffer, length, storage, 1, 0);
    }
    AIVPN_PACKET packet;
    unsigned result = 0;
    if (bytes && aivpn_packet_parse(bytes, length, &packet)) {
        if (!inbound && pt_packet_blocked(&packet, compartment)) {
            if (storage) ExFreePoolWithTag(storage, TAG);
            if (retreat) NdisAdvanceNetBufferDataStart(buffer, retreat, FALSE, NULL);
            return 2;
        }
        FLOW flow = {0};
        AR_PACKET_CONFIG current;
        if (pc_find_flow(&packet, inbound, compartment, arrival, PC_ANY_PROFILE, &flow, &current)) {
            result = 1;
            if (apply) {
                BOOLEAN ready = !pc_stopping && flow.association != 4 && (ipv4 ? current.ready4 : current.ready6);
                NTSTATUS status = ready ? (inbound ? pc_inject_copy(bytes, &packet, &flow, &current, TRUE) : pc_enqueue_packet(bytes, &packet, &flow, &current)) : STATUS_NETWORK_UNREACHABLE;
                if (NT_SUCCESS(status)) {
                    if (ipv4) InterlockedIncrement(&pc_redirected4); else InterlockedIncrement(&pc_redirected6);
                } else InterlockedExchange(&pc_last_status, status);
            }
        } else if (!inbound && pd_packet_blocked(&packet, compartment)) {
            result = 2;
        } else if (apply && mixed && !inbound) {
            flow.compartment = compartment;
            NTSTATUS status = pc_inject_copy(bytes, &packet, &flow, &current, FALSE);
            if (!NT_SUCCESS(status)) InterlockedExchange(&pc_last_status, status);
        }
    } else {
        if (!apply) InterlockedIncrement(&pc_parse_failed);
        if (potential) result = 2;
    }
    if (storage) ExFreePoolWithTag(storage, TAG);
    if (retreat) NdisAdvanceNetBufferDataStart(buffer, retreat, FALSE, NULL);
    return result;
}

static void pc_packet_classify(const FWPS_INCOMING_VALUES0 *values, const FWPS_INCOMING_METADATA_VALUES0 *metadata,
    NET_BUFFER_LIST *nbl, FWPS_CLASSIFY_OUT0 *out)
{
    if (!nbl || pc_owned_packet(nbl)) return;
    BOOLEAN inbound = values->layerId == FWPS_LAYER_INBOUND_IPPACKET_V4 || values->layerId == FWPS_LAYER_INBOUND_IPPACKET_V6;
    BOOLEAN ipv4 = values->layerId == FWPS_LAYER_INBOUND_IPPACKET_V4 || values->layerId == FWPS_LAYER_OUTBOUND_IPPACKET_V4;
    if (inbound) InterlockedIncrement(&pc_seen_in); else InterlockedIncrement(&pc_seen_out);
    ULONG arrival = inbound ? values->incomingValue[ipv4 ? FWPS_FIELD_INBOUND_IPPACKET_V4_INTERFACE_INDEX : FWPS_FIELD_INBOUND_IPPACKET_V6_INTERFACE_INDEX].value.uint32 : 0;
    ULONG compartment = metadata->currentMetadataValues & FWPS_METADATA_FIELD_COMPARTMENT_ID ? metadata->compartmentId : UNSPECIFIED_COMPARTMENT_ID;
    ULONG retreat = inbound && (metadata->currentMetadataValues & FWPS_METADATA_FIELD_IP_HEADER_SIZE) ? metadata->ipHeaderSize : 0;
    BOOLEAN potential = !inbound && pc_protected_addresses(values, compartment, ipv4);
    BOOLEAN selected = FALSE;
    ULONG count = 0;
    NET_BUFFER_LIST *list;
    NET_BUFFER *buffer;
    for (list = nbl; list && count <= BATCH_LIMIT; list = NET_BUFFER_LIST_NEXT_NBL(list)) {
        for (buffer = NET_BUFFER_LIST_FIRST_NB(list); buffer && count <= BATCH_LIMIT; buffer = NET_BUFFER_NEXT_NB(buffer)) {
            unsigned result = pc_inspect_buffer(buffer, inbound, ipv4, retreat, compartment, arrival, potential, FALSE, FALSE);
            if (result) selected = TRUE;
            count++;
        }
    }
    if ((LONG)count > pc_maximum_batch) InterlockedExchange(&pc_maximum_batch, (LONG)count);
    if (count > BATCH_LIMIT) { if (selected || potential) pc_block(out); return; }
    if (!selected) return;
    pc_block(out);
    out->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
    for (list = nbl; list; list = NET_BUFFER_LIST_NEXT_NBL(list)) {
        for (buffer = NET_BUFFER_LIST_FIRST_NB(list); buffer; buffer = NET_BUFFER_NEXT_NB(buffer))
            pc_inspect_buffer(buffer, inbound, ipv4, retreat, compartment, arrival, potential, TRUE, TRUE);
    }
}

static void NTAPI pc_classify(const FWPS_INCOMING_VALUES0 *values, const FWPS_INCOMING_METADATA_VALUES0 *metadata,
    void *layer_data, const void *context, const FWPS_FILTER1 *filter, UINT64 flow_context, FWPS_CLASSIFY_OUT0 *out)
{
    UNREFERENCED_PARAMETER(flow_context);
    if (values->layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4 || values->layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6) {
        pc_established(values, metadata);
        if (out->rights & FWPS_RIGHT_ACTION_WRITE) out->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    if (values->layerId == FWPS_LAYER_ALE_RESOURCE_RELEASE_V4 || values->layerId == FWPS_LAYER_ALE_RESOURCE_RELEASE_V6) {
        pc_resource_release(metadata);
        if (out->rights & FWPS_RIGHT_ACTION_WRITE) out->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    if (!(out->rights & FWPS_RIGHT_ACTION_WRITE)) return;
    out->actionType = FWP_ACTION_CONTINUE;
    if (values->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4 || values->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6)
        pc_auth(values, metadata, layer_data, out);
    else if (values->layerId == FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4 || values->layerId == FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V6)
        pc_close_endpoint(metadata, context, filter, out);
    else pc_packet_classify(values, metadata, layer_data, out);
}

static NTSTATUS NTAPI pc_notify(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID *key, FWPS_FILTER1 *filter)
{
    UNREFERENCED_PARAMETER(type); UNREFERENCED_PARAMETER(key); UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

static NTSTATUS pc_result(ULONG_PTR *returned, NTSTATUS status, ULONG_PTR count)
{
    *returned = NT_SUCCESS(status) ? count : 0;
    return status;
}

static void pc_take_profile_queue_locked(UINT32 profile, LIST_ENTRY *old)
{
    LIST_ENTRY *entry = pc_packets.Flink;
    while (entry != &pc_packets) {
        LIST_ENTRY *next = entry->Flink;
        QUEUED_PACKET *packet = CONTAINING_RECORD(entry, QUEUED_PACKET, link);
        if (packet->profile == profile) {
            RemoveEntryList(entry); InsertTailList(old, entry);
            pc_packet_count--; pc_packet_bytes -= packet->length;
        }
        entry = next;
    }
    if (IsListEmpty(&pc_packets) && pc_packet_event) KeClearEvent(pc_packet_event);
}

static NTSTATUS pc_control(PIRP irp, PIO_STACK_LOCATION stack, ULONG_PTR *returned)
{
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    if (code == AR_PACKET_IOCTL_BLOCK) {
        if (stack->Parameters.DeviceIoControl.InputBufferLength || stack->Parameters.DeviceIoControl.OutputBufferLength)
            return pc_result(returned, STATUS_INVALID_PARAMETER, 0);
        pc_block_ready();
        return pc_result(returned, STATUS_SUCCESS, 0);
    }
    if (code == AR_PACKET_IOCTL_BLOCK_PROFILE) {
        if (stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(AR_PACKET_ROUTE) ||
            stack->Parameters.DeviceIoControl.OutputBufferLength || !irp->AssociatedIrp.SystemBuffer)
            return pc_result(returned, STATUS_INVALID_PARAMETER, 0);
        const AR_PACKET_ROUTE *route = irp->AssociatedIrp.SystemBuffer;
        if (!route->profile || route->profile == PC_ANY_PROFILE || route->reserved || !route->generation)
            return pc_result(returned, STATUS_INVALID_PARAMETER, 0);
        LIST_ENTRY old; InitializeListHead(&old);
        KIRQL previous;
        KeAcquireSpinLock(&pc_state_lock, &previous);
        PC_PATH *path = pc_path_locked(route->profile, FALSE);
        NTSTATUS status = path && path->transport.generation == route->generation && path->transport.session == session_id ?
            STATUS_SUCCESS : STATUS_REVISION_MISMATCH;
        if (NT_SUCCESS(status)) {
            path->config.ready4 = path->config.ready6 = 0;
            pc_take_profile_queue_locked(route->profile, &old);
        }
        KeReleaseSpinLock(&pc_state_lock, previous);
        pc_free_packet_list(&old);
        return pc_result(returned, status, 0);
    }
    if (code == AR_PACKET_IOCTL_CONFIG) {
        ULONG input_size = stack->Parameters.DeviceIoControl.InputBufferLength;
        if (input_size != sizeof(AR_PACKET_CONFIG) && input_size != sizeof(AR_PACKET_CONFIG_V2)) return pc_result(returned, STATUS_INVALID_PARAMETER, 0);
        AR_PACKET_CONFIG *input = irp->AssociatedIrp.SystemBuffer;
        BOOLEAN runtime_config = input_size == sizeof(AR_PACKET_CONFIG_V2);
        UINT32 profile = runtime_config ? ((AR_PACKET_CONFIG_V2 *)input)->profile : 0;
        if (input->version != (runtime_config ? 2u : 1u) || input->size != input_size || input->ready4 > 1 || input->ready6 > 1 || !input->interface_index || input->packet_mtu < 1280 || input->packet_mtu > 1500 ||
            profile == PC_ANY_PROFILE || (runtime_config && (((AR_PACKET_CONFIG_V2 *)input)->reserved || ((input->ready4 || input->ready6) && !profile))))
            return pc_result(returned, STATUS_INVALID_PARAMETER, 0);
        PKEVENT event = NULL;
        NTSTATUS status = ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)input->event_handle, EVENT_MODIFY_STATE,
            *ExEventObjectType, UserMode, (PVOID *)&event, NULL);
        if (!NT_SUCCESS(status)) return pc_result(returned, status, 0);
        PI_SNAPSHOT *snapshot = NULL;
        status = pi_snapshot_create(&snapshot);
        if (!NT_SUCCESS(status)) { ObDereferenceObject(event); return pc_result(returned, status, 0); }
        if ((snapshot->runtime != NULL) != runtime_config) {
            pi_snapshot_free(snapshot); ObDereferenceObject(event); return pc_result(returned, STATUS_INVALID_PARAMETER, 0);
        }
        LIST_ENTRY old_packets; InitializeListHead(&old_packets);
        KIRQL previous;
        KeAcquireSpinLock(&pc_state_lock, &previous);
        PC_PATH *path = pc_path_locked(profile, TRUE);
        PC_TRANSPORT *transport = path ? &path->transport : NULL;
        BOOLEAN conflict = !path || (pc_writer && pc_writer != stack->FileObject);
        if (runtime_config && (input->ready4 || input->ready6) && (!transport || !transport->process)) conflict = TRUE;
        if ((input->ready4 || input->ready6) && transport && transport->process &&
            (!pt_ready_locked(profile, transport->generation, transport->endpoint) || !transport->observed_owner)) conflict = TRUE;
        BOOLEAN changed = path && (!path->epoch || path->worker_session != transport->session || path->worker_generation != transport->generation ||
            path->config.interface_index != input->interface_index || path->config.compartment != input->compartment ||
            path->config.packet_mtu != input->packet_mtu || RtlCompareMemory(path->config.address4, input->address4, 4) != 4 ||
            RtlCompareMemory(path->config.address6, input->address6, 16) != 16);
        AIVPN_PATH_KEY route_key = {0};
        route_key.interface_index = input->interface_index; route_key.compartment = input->compartment; route_key.mtu = input->packet_mtu;
        RtlCopyMemory(route_key.address4, input->address4, 4); RtlCopyMemory(route_key.address6, input->address6, 16);
        BOOLEAN route_changed = path && aivpn_path_route_changed(&path->route, &route_key);
        unsigned epochs = (changed ? 1u : 0u) + (route_changed ? 1u : 0u);
        if (pc_next_path_epoch > MAXUINT64 - epochs) conflict = TRUE;
        PKEVENT previous_event = NULL;
        RS_SNAPSHOT *previous_runtime = NULL;
        if (!conflict) {
            if (route_changed) {
                path->route.key = route_key;
                path->route.epoch = ++pc_next_path_epoch;
            }
            if (changed) {
                path->epoch = ++pc_next_path_epoch;
                path->worker_session = transport->session; path->worker_generation = transport->generation;
                pc_take_profile_queue_locked(profile, &old_packets);
            }
            KeAcquireSpinLockAtDpcLevel(&pi_lock);
            pi_policy = snapshot->policy;
            pi_session = snapshot->session;
            pi_runtime = snapshot->runtime;
            pi_published = TRUE;
            KeReleaseSpinLockFromDpcLevel(&pi_lock);
            PI_SNAPSHOT *previous_snapshot = pi_snapshot;
            pi_snapshot = snapshot;
            if (snapshot->runtime && rs_pending == snapshot->runtime) {
                previous_runtime = rs_current;
                rs_current = rs_pending; rs_pending = NULL;
            }
            snapshot = previous_snapshot;
            path->config = *input; pc_writer = stack->FileObject; pc_armed = TRUE;
            previous_event = pc_packet_event; pc_packet_event = event;
            if (!IsListEmpty(&pc_packets)) KeSetEvent(event, IO_NO_INCREMENT, FALSE);
        }
        KeReleaseSpinLock(&pc_state_lock, previous);
        pc_free_packet_list(&old_packets);
        pi_snapshot_free(snapshot);
        rs_release(previous_runtime);
        if (conflict) ObDereferenceObject(event);
        if (previous_event) ObDereferenceObject(previous_event);
        return pc_result(returned, conflict ? STATUS_SHARING_VIOLATION : STATUS_SUCCESS, 0);
    }
    if (code == AR_PACKET_IOCTL_POP || code == AR_PACKET_IOCTL_SEND || code == AR_PACKET_IOCTL_POP_PROFILE || code == AR_PACKET_IOCTL_SEND_PROFILE) {
        BOOLEAN pop = code == AR_PACKET_IOCTL_POP || code == AR_PACKET_IOCTL_POP_PROFILE;
        BOOLEAN scoped = code == AR_PACKET_IOCTL_POP_PROFILE || code == AR_PACKET_IOCTL_SEND_PROFILE;
        ULONG prefix = pop && scoped ? sizeof(AR_PACKET_ROUTE) : 0;
        ULONG length = stack->Parameters.DeviceIoControl.OutputBufferLength;
        ULONG input_length = stack->Parameters.DeviceIoControl.InputBufferLength;
        AR_PACKET_ROUTE route = {0};
        if (input_length != (scoped && !pop ? sizeof(route) : 0)) return pc_result(returned, STATUS_INVALID_PARAMETER, 0);
        if (scoped && !pop) {
            if (!irp->AssociatedIrp.SystemBuffer) return pc_result(returned, STATUS_INVALID_PARAMETER, 0);
            route = *(const AR_PACKET_ROUTE *)irp->AssociatedIrp.SystemBuffer;
            if (!route.profile || route.profile == PC_ANY_PROFILE || route.reserved || !route.generation)
                return pc_result(returned, STATUS_INVALID_PARAMETER, 0);
        }
        if (!irp->MdlAddress || length <= prefix || length > PACKET_LIMIT + prefix) return pc_result(returned, STATUS_INVALID_PARAMETER, 0);
        UCHAR *bytes = MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);
        if (!bytes) return pc_result(returned, STATUS_INSUFFICIENT_RESOURCES, 0);
        KIRQL previous;
        KeAcquireSpinLock(&pc_state_lock, &previous);
        BOOLEAN allowed = pc_writer == stack->FileObject && pc_writer != NULL && (scoped || !pi_runtime);
        QUEUED_PACKET *packet = NULL;
        NTSTATUS status = STATUS_ACCESS_DENIED;
        AR_PACKET_CONFIG current = {0};
        UINT64 epoch = 0;
        if (allowed && pop) {
            status = STATUS_NO_MORE_ENTRIES;
            while (!IsListEmpty(&pc_packets)) {
                QUEUED_PACKET *head = CONTAINING_RECORD(pc_packets.Flink, QUEUED_PACKET, link);
                PC_PATH *path = pc_path_locked(head->profile, FALSE);
                BOOLEAN valid = path && path->epoch == head->epoch && path->transport.generation == head->generation &&
                    !pc_stopping && (head->data[0] >> 4 == 4 ? path->config.ready4 : path->config.ready6);
                if (!valid) {
                    RemoveEntryList(&head->link); pc_packet_count--; pc_packet_bytes -= head->length;
                    ExFreePoolWithTag(head, TAG); continue;
                }
                if (!scoped && head->profile) { status = STATUS_INVALID_DEVICE_STATE; break; }
                if (length - prefix < head->length) { status = STATUS_BUFFER_TOO_SMALL; break; }
                RemoveEntryList(&head->link); pc_packet_count--; pc_packet_bytes -= head->length;
                packet = head; status = STATUS_SUCCESS; break;
            }
            if (IsListEmpty(&pc_packets) && pc_packet_event) KeClearEvent(pc_packet_event);
        } else if (allowed) {
            PC_PATH *path = pc_path_locked(route.profile, FALSE);
            if (!path || (scoped && (path->transport.generation != route.generation || path->transport.session != session_id))) allowed = FALSE;
            else { current = path->config; epoch = path->epoch; }
            status = allowed ? STATUS_SUCCESS : STATUS_NOT_FOUND;
        }
        KeReleaseSpinLock(&pc_state_lock, previous);
        if (!allowed) return pc_result(returned, status, 0);
        if (pop) {
            ULONG count = 0;
            if (packet) {
                if (scoped) {
                    AR_PACKET_ROUTE output = {packet->profile, 0, packet->generation};
                    RtlCopyMemory(bytes, &output, sizeof(output));
                }
                count = packet->length + prefix;
                RtlCopyMemory(bytes + prefix, packet->data, packet->length); ExFreePoolWithTag(packet, TAG);
            }
            return pc_result(returned, status, count);
        }
        UCHAR *copy = ExAllocatePool2(POOL_FLAG_NON_PAGED, length, TAG);
        if (!copy) return pc_result(returned, STATUS_INSUFFICIENT_RESOURCES, 0);
        RtlCopyMemory(copy, bytes, length);
        int fragment = aivpn_fragment_kind(copy, length);
        if (fragment < 0) { ExFreePoolWithTag(copy, TAG); return pc_result(returned, STATUS_DATA_ERROR, 0); }
        if (fragment) {
            UCHAR *assembled = ExAllocatePool2(POOL_FLAG_NON_PAGED, PACKET_LIMIT, TAG);
            if (!assembled) { ExFreePoolWithTag(copy, TAG); return pc_result(returned, STATUS_INSUFFICIENT_RESOURCES, 0); }
            size_t assembled_length = 0;
            KeAcquireSpinLock(&pc_assembly_lock, &previous);
            int assembled_status = aivpn_reassemble_scoped(&pc_reassembler, epoch, copy, length,
                KeQueryInterruptTime() / 10000, assembled, PACKET_LIMIT, &assembled_length);
            KeReleaseSpinLock(&pc_assembly_lock, previous);
            ExFreePoolWithTag(copy, TAG);
            copy = assembled;
            if (assembled_status != 2) {
                ExFreePoolWithTag(copy, TAG);
                return pc_result(returned, assembled_status == 1 ? STATUS_SUCCESS : STATUS_DATA_ERROR, 0);
            }
            length = (ULONG)assembled_length;
        }
        AIVPN_PACKET parsed;
        FLOW flow;
        status = STATUS_DATA_ERROR;
        if (aivpn_packet_parse(copy, length, &parsed)) {
            status = STATUS_NOT_FOUND;
            if (pc_find_flow(&parsed, TRUE, current.compartment, current.interface_index, route.profile, &flow, &current))
                status = pc_inject_copy(copy, &parsed, &flow, &current, TRUE);
        } else {
            AIVPN_ICMP_ERROR error;
            if (aivpn_icmp_error_parse(copy, length, &error)) {
                status = STATUS_NOT_FOUND;
                if (pc_find_flow(&error.reply, TRUE, current.compartment, current.interface_index, route.profile, &flow, &current))
                    status = pc_inject_copy(copy, &error.packet, &flow, &current, TRUE);
            }
        }
        if (status == STATUS_DATA_ERROR) InterlockedIncrement(&pc_parse_failed);
        ExFreePoolWithTag(copy, TAG);
        return pc_result(returned, status, 0);
    }
    if (code == AR_PACKET_IOCTL_STATS) {
        if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(AR_PACKET_STATS)) return pc_result(returned, STATUS_BUFFER_TOO_SMALL, 0);
        AR_PACKET_STATS *output = irp->AssociatedIrp.SystemBuffer;
        output->version = 1; output->redirected4 = pc_redirected4; output->redirected6 = pc_redirected6;
        output->blocked = pc_blocked; output->last_status = pc_last_status;
        output->seen_out = pc_seen_out; output->seen_in = pc_seen_in; output->active_flows = pc_active_flows;
        output->parse_failed = pc_parse_failed; output->completed = pc_completed; output->maximum_batch = pc_maximum_batch;
        return pc_result(returned, STATUS_SUCCESS, sizeof(*output));
    }
    return pc_result(returned, STATUS_INVALID_DEVICE_REQUEST, 0);
}

static void pc_block_ready(void)
{
    LIST_ENTRY old_packets;
    InitializeListHead(&old_packets);
    KIRQL old;
    KeAcquireSpinLock(&pc_state_lock, &old);
    pc_paths_block_locked();
    while (!IsListEmpty(&pc_packets)) InsertTailList(&old_packets, RemoveHeadList(&pc_packets));
    pc_packet_count = pc_packet_bytes = 0;
    if (pc_packet_event) KeClearEvent(pc_packet_event);
    KeReleaseSpinLock(&pc_state_lock, old);
    pc_free_packet_list(&old_packets);
}

static void pc_disconnect(void)
{
    pc_lab_cancel();
    KIRQL previous;
    LIST_ENTRY old_packets;
    InitializeListHead(&old_packets);
    KeAcquireSpinLock(&pc_state_lock, &previous);
    pc_paths_block_locked();
    for (ULONG i = 0; i < PC_PATH_LIMIT; i++) pc_paths[i].transport.endpoint = 0;
    pc_writer = NULL;
    PKEVENT event = pc_packet_event;
    pc_packet_event = NULL;
    if (event) KeSetEvent(event, IO_NO_INCREMENT, FALSE);
    while (!IsListEmpty(&pc_packets)) InsertTailList(&old_packets, RemoveHeadList(&pc_packets));
    pc_packet_count = pc_packet_bytes = 0;
    KeReleaseSpinLock(&pc_state_lock, previous);
    pc_free_packet_list(&old_packets);
    pd_disconnect();
    if (event) ObDereferenceObject(event);
}

static void pc_stop(void)
{
    InterlockedExchange(&pc_stopping, 1);
    pa_stop();
    while (pc_registered) FwpsCalloutUnregisterById0(pc_callout_ids[--pc_registered]);
    pc_disconnect();
    pt_clear();
    for (ULONG i = 0; i < 2; i++) if (pc_inject[i]) {
        FwpsInjectionHandleDestroy0(pc_inject[i]); pc_inject[i] = NULL;
    }
    if (pc_pool) { NdisFreeNetBufferListPool(pc_pool); pc_pool = NULL; }
}

static NTSTATUS pc_start(void)
{
    NET_BUFFER_LIST_POOL_PARAMETERS parameters = {0};
    parameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    parameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    parameters.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    parameters.fAllocateNetBuffer = TRUE;
    parameters.PoolTag = TAG;
    pc_pool = NdisAllocateNetBufferListPool(NULL, &parameters);
    if (!pc_pool) return STATUS_INSUFFICIENT_RESOURCES;
    NTSTATUS status;
    for (ULONG i = 0; i < 2; i++) {
        status = FwpsInjectionHandleCreate0(i == 0 ? AF_INET : AF_INET6, FWPS_INJECTION_TYPE_NETWORK, &pc_inject[i]);
        if (!NT_SUCCESS(status)) return status;
    }
    status = pa_start();
    if (!NT_SUCCESS(status)) return status;
    const GUID *keys[] = {&AR_PACKET_AUTH4, &AR_PACKET_AUTH6, &AR_PACKET_CONNECT4, &AR_PACKET_CONNECT6,
        &AR_PACKET_BIND4, &AR_PACKET_BIND6, &AR_PACKET_CLOSE4, &AR_PACKET_CLOSE6,
        &AR_PACKET_FLOW4, &AR_PACKET_FLOW6, &AR_PACKET_RELEASE4, &AR_PACKET_RELEASE6};
    for (ULONG i = 0; i < RTL_NUMBER_OF(keys); i++) {
        FWPS_CALLOUT1 callout = {0};
        callout.calloutKey = *keys[i]; callout.classifyFn = pc_classify; callout.notifyFn = pc_notify;
        if (i == 8 || i == 9) callout.flowDeleteFn = pc_flow_deleted;
        status = FwpsCalloutRegister1(device, &callout, &pc_callout_ids[pc_registered]);
        if (!NT_SUCCESS(status)) return status;
        pc_registered++;
    }
    return STATUS_SUCCESS;
}
