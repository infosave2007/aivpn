#pragma once

#ifdef AIVPN_LAB
typedef struct {
    UINT64 time, endpoint, parent, flow, retained_parent, flags;
    ULONG event, protocol, source_port, destination_port, action;
} PC_LIFETIME_TRACE;
static PC_LIFETIME_TRACE pc_lifetime_log[256];
static ULONG pc_lifetime_count;
/* Только lab: bounded ring под pc_state_lock, без имен и произвольной памяти. */
static void pc_lifetime_trace(ULONG event, const FWPS_INCOMING_METADATA_VALUES0 *metadata, const FLOW *flow)
{
    PC_LIFETIME_TRACE *record = &pc_lifetime_log[pc_lifetime_count++ % RTL_NUMBER_OF(pc_lifetime_log)];
    RtlZeroMemory(record, sizeof(*record));
    record->time = KeQueryInterruptTime(); record->event = event;
    if (metadata) {
        record->flags = metadata->currentMetadataValues;
        if (metadata->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE) record->endpoint = metadata->transportEndpointHandle;
        if (metadata->currentMetadataValues & FWPS_METADATA_FIELD_PARENT_ENDPOINT_HANDLE) record->parent = metadata->parentEndpointHandle;
        if (metadata->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) record->flow = metadata->flowHandle;
    }
    if (flow) {
        if (!metadata) { record->endpoint = flow->endpoint; record->flow = flow->flow_handle; }
        record->retained_parent = flow->parent_endpoint;
        record->protocol = flow->tuple.protocol; record->source_port = flow->tuple.source_port;
        record->destination_port = flow->tuple.destination_port; record->action = flow->decision.action;
    }
}
#else
#define pc_lifetime_trace(event, metadata, flow) ((void)0)
#endif

static ULONG pc_tuple_hash(const AIVPN_PACKET *tuple, ULONG compartment)
{
    ULONG hash = 2166136261u ^ compartment;
    unsigned bytes = tuple->version == 4 ? 4 : 16;
    for (unsigned i = 0; i < bytes; i++) {
        hash = (hash ^ tuple->source[i]) * 16777619u;
        hash = (hash ^ tuple->destination[i]) * 16777619u;
    }
    hash = (hash ^ tuple->source_port) * 16777619u;
    hash = (hash ^ tuple->destination_port) * 16777619u;
    return (hash ^ tuple->version ^ tuple->protocol) & (FLOW_BUCKETS - 1);
}

/* Индексы хранят только ссылки на допуск, уже полученный по OS endpoint/flow. */
static void pc_index_insert(FLOW *flow)
{
    ULONG bucket = pc_tuple_hash(&flow->tuple, flow->compartment);
    USHORT link = (USHORT)(flow - pc_flows + 1);
    flow->original_next = pc_original[bucket];
    pc_original[bucket] = link;
    if (flow->decision.action == 2) pc_reverse[flow->translated_port] = link;
}

static void pc_try_retire(FLOW *flow)
{
    if (!flow->used || !flow->endpoint_closed || !flow->resource_released || flow->injections || flow->association == 1 || flow->association == 2) return;
    ULONG bucket = pc_tuple_hash(&flow->tuple, flow->compartment);
    USHORT own = (USHORT)(flow - pc_flows + 1);
    USHORT *link = &pc_original[bucket];
    while (*link && *link != own) link = &pc_flows[*link - 1].original_next;
    if (*link == own) *link = flow->original_next;
    if (flow->decision.action == 2 && pc_reverse[flow->translated_port] == own) {
        pc_reverse[flow->translated_port] = 0;
        UINT64 delay = (flow->tuple.protocol == 6 ? 240ull : 120ull) * 10000000ull;
        UINT64 now = KeQueryInterruptTime();
        if (now >= MAXUINT64 - delay || !pc_nat_retire(&pc_nat, flow->translated_port, now + delay))
            InterlockedExchange(&pc_last_status, STATUS_INTEGER_OVERFLOW);
    }
    /* Quarantine начинается после OS resource release и flowDelete, не по idle
       живого socket. На протяжении окна старый reverse mapping отсутствует. */
    pc_lifetime_trace(6, NULL, flow);
    flow->used = FALSE;
    InterlockedDecrement(&pc_active_flows);
}

static void NTAPI pc_flow_deleted(UINT16 layer, UINT32 callout, UINT64 context)
{
    UNREFERENCED_PARAMETER(layer);
    UNREFERENCED_PARAMETER(callout);
    FLOW *flow = (FLOW *)(ULONG_PTR)context;
    KIRQL old;
    KeAcquireSpinLock(&pc_state_lock, &old);
    pc_lifetime_trace(5, NULL, flow);
    flow->association = 3;
    /* Echo принадлежит ICMP ALE flow, а не TCP/UDP endpoint. Его удаление
       завершает допуск; ожидающих инъекций и quarantine это не отменяет. */
    if (flow->tuple.protocol == 1 || flow->tuple.protocol == 58) {
        flow->endpoint_closed = TRUE;
        flow->resource_released = TRUE;
    }
    pc_try_retire(flow);
    KeReleaseSpinLock(&pc_state_lock, old);
}

static void pc_established(const FWPS_INCOMING_VALUES0 *values,
    const FWPS_INCOMING_METADATA_VALUES0 *metadata)
{
    if (!(metadata->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) || !metadata->flowHandle) return;
    UINT64 endpoint = metadata->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE ?
        metadata->transportEndpointHandle : 0;
    FLOW *flow = NULL;
    KIRQL old;
    KeAcquireSpinLock(&pc_state_lock, &old);
    for (ULONG i = 0; i < FLOW_LIMIT; i++) {
        FLOW *candidate = &pc_flows[i];
        if (candidate->used && candidate->flow_handle == metadata->flowHandle &&
            (!endpoint || candidate->endpoint == endpoint)) {
            if (!candidate->association && !candidate->resource_released) {
                pc_lifetime_trace(2, metadata, candidate);
                candidate->association = 1;
                candidate->injections++;
                flow = candidate;
            }
            break;
        }
    }
    KeReleaseSpinLock(&pc_state_lock, old);
    if (!flow) return;
    /* WFP может вызвать flowDelete до возврата. Pin не дает переиспользовать slot. */
    ULONG index = values->layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4 ? 8 : 9;
    NTSTATUS status = FwpsFlowAssociateContext0(metadata->flowHandle, values->layerId,
        pc_callout_ids[index], (UINT64)(ULONG_PTR)flow);
    KeAcquireSpinLock(&pc_state_lock, &old);
    if (NT_SUCCESS(status)) {
        if (flow->association == 1) flow->association = 2;
    } else {
        flow->association = 4;
        flow->endpoint_closed = TRUE;
        InterlockedExchange(&pc_last_status, status);
    }
    flow->injections--;
    UINT64 retained_endpoint = flow->endpoint;
    pc_try_retire(flow);
    KeReleaseSpinLock(&pc_state_lock, old);
    pc_complete_close(retained_endpoint);
}

static void pc_resource_release(const FWPS_INCOMING_METADATA_VALUES0 *metadata)
{
    if (!(metadata->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE)) return;
    KIRQL old;
    KeAcquireSpinLock(&pc_state_lock, &old);
    pc_lifetime_trace(4, metadata, NULL);
    pd_release_locked(metadata->transportEndpointHandle);
    for (ULONG i = 0; i < FLOW_LIMIT; i++) {
        FLOW *flow = &pc_flows[i];
        if (flow->used && (flow->endpoint == metadata->transportEndpointHandle ||
            (flow->parent_endpoint && flow->parent_endpoint == metadata->transportEndpointHandle))) {
            if (flow->endpoint == metadata->transportEndpointHandle) flow->endpoint_closed = TRUE;
            flow->resource_released = TRUE;
            pc_try_retire(flow);
        }
    }
    KeReleaseSpinLock(&pc_state_lock, old);
}
