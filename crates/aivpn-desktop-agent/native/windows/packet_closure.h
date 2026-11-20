#pragma once

typedef struct { UINT64 endpoint, handle; } PC_CLOSURE;
/* Каждый pending CLOSE соответствует хотя бы одному из ограниченных FLOW/PA. */
static PC_CLOSURE pc_closures[FLOW_LIMIT + PA_LIMIT];

static BOOLEAN pc_close_busy(UINT64 endpoint)
{
    for (ULONG i = 0; i < FLOW_LIMIT; i++)
        if (pc_flows[i].endpoint == endpoint && pc_flows[i].injections) return TRUE;
    return pa_close_pending(endpoint, FALSE);
}

static void pc_complete_close(UINT64 endpoint)
{
    UINT64 handle = 0;
    KIRQL old;
    KeAcquireSpinLock(&pc_state_lock, &old);
    for (ULONG i = 0; i < RTL_NUMBER_OF(pc_closures); i++) {
        PC_CLOSURE *closure = &pc_closures[i];
        if (closure->endpoint == endpoint && !pc_close_busy(endpoint)) {
            handle = closure->handle;
            RtlZeroMemory(closure, sizeof(*closure));
            break;
        }
    }
    KeReleaseSpinLock(&pc_state_lock, old);
    /* Complete может синхронно вызвать flowDelete или resource release. */
    if (handle) {
        FWPS_CLASSIFY_OUT0 output = {0}; output.actionType = FWP_ACTION_CONTINUE;
        FwpsCompleteClassify0(handle, 0, &output);
        FwpsReleaseClassifyHandle0(handle);
    }
}

static void pc_close_endpoint(const FWPS_INCOMING_METADATA_VALUES0 *metadata,
    const void *context, const FWPS_FILTER1 *filter, FWPS_CLASSIFY_OUT0 *out)
{
    if (!(metadata->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE)) return;
    UINT64 endpoint = metadata->transportEndpointHandle, handle = 0;
    NTSTATUS status = FwpsAcquireClassifyHandle0((PVOID)context, 0, &handle);
    KIRQL old;
    KeAcquireSpinLock(&pc_state_lock, &old);
    pc_lifetime_trace(3, metadata, NULL);
    for (ULONG i = 0; i < FLOW_LIMIT; i++) {
        FLOW *flow = &pc_flows[i];
        if (flow->used && flow->endpoint == endpoint) {
            flow->endpoint_closed = TRUE;
            pc_try_retire(flow);
        }
    }
    (void)pa_close_pending(endpoint, TRUE);
    if (pc_close_busy(endpoint)) {
        PC_CLOSURE *slot = NULL;
        for (ULONG i = 0; i < RTL_NUMBER_OF(pc_closures); i++) {
            if (pc_closures[i].endpoint == endpoint) { status = STATUS_INVALID_DEVICE_STATE; break; }
            if (!slot && !pc_closures[i].endpoint) slot = &pc_closures[i];
        }
        if (NT_SUCCESS(status) && !slot) status = STATUS_INSUFFICIENT_RESOURCES;
        if (NT_SUCCESS(status)) status = FwpsPendClassify0(handle, filter->filterId, 0, out);
        if (NT_SUCCESS(status)) { slot->endpoint = endpoint; slot->handle = handle; handle = 0; }
        else {
            pc_paths_block_locked();
            InterlockedExchange(&pc_stopping, 1);
            InterlockedExchange(&pc_last_status, status);
        }
    }
    KeReleaseSpinLock(&pc_state_lock, old);
    if (handle) FwpsReleaseClassifyHandle0(handle);
}
