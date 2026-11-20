#pragma once

#define PA_LIMIT 128u
#define PA_BYTES (4u * 1024u * 1024u)
#define PA_CONTROL 1024u
#define PA_DEADLINE (2ull * 1000ull * 10000ull)
typedef struct {
    LIST_ENTRY active, queued;
    AR_PROCESS process;
    AIVPN_PACKET tuple;
    UINT64 endpoint, parent_endpoint, flow, generation, session, deadline;
    ULONG compartment, charged;
    HANDLE completion;
    NET_BUFFER_LIST *packet;
    FWPS_TRANSPORT_SEND_PARAMS0 send;
    UCHAR control[PA_CONTROL];
    struct ap_decision decision;
    KEVENT reauthorized;
    BOOLEAN ready, admitted, cancelled;
} PA_OPERATION;
static KSPIN_LOCK pa_lock;
static LIST_ENTRY pa_active, pa_queue;
static ULONG pa_count, pa_bytes;
static BOOLEAN pa_stopping;
static KEVENT pa_event;
static HANDLE pa_thread, pa_inject[2];
static EX_RUNDOWN_REF pa_rundown;
static BOOLEAN pa_initialized;

static PA_OPERATION *pa_find(UINT64 endpoint, const AIVPN_PACKET *tuple)
{
    for (LIST_ENTRY *entry = pa_active.Flink; entry != &pa_active; entry = entry->Flink) {
        PA_OPERATION *operation = CONTAINING_RECORD(entry, PA_OPERATION, active);
        if (operation->endpoint == endpoint && (!tuple || pc_equal_tuple(&operation->tuple, tuple))) return operation;
    }
    return NULL;
}

static unsigned pa_decision(UINT64 *endpoint, UINT64 *parent_endpoint, UINT64 flow, const AIVPN_PACKET *tuple, struct ap_decision *decision)
{
    KIRQL old;
    BOOLEAN inconsistent = FALSE;
    KeAcquireSpinLock(&pa_lock, &old);
    PA_OPERATION *operation = NULL;
    for (LIST_ENTRY *entry = pa_active.Flink; entry != &pa_active; entry = entry->Flink) {
        PA_OPERATION *candidate = CONTAINING_RECORD(entry, PA_OPERATION, active);
        if (!flow || candidate->flow != flow) continue;
        operation = candidate;
        if ((*endpoint && candidate->endpoint != *endpoint) || !pc_equal_tuple(&candidate->tuple, tuple)) {
            // OS flow уже принадлежит этой pending operation. Ошибка consistency
            // не разрешает новую оценку через PI cache и не оставляет очередь ждать ack.
            AR_LAB_HIT(28);
#ifdef AIVPN_LAB
            UINT32 initial_address = 0, reauth_address = 0;
            if (candidate->tuple.version == 4) RtlCopyMemory(&initial_address, candidate->tuple.source, 4);
            if (tuple->version == 4) RtlCopyMemory(&reauth_address, tuple->source, 4);
            AR_LAB_SET(36, initial_address); AR_LAB_SET(37, reauth_address);
            AR_LAB_SET(38, candidate->tuple.source_port | ((UINT32)tuple->source_port << 16));
            AR_LAB_SET(39, (*endpoint ? 1u : 0u) | ((*endpoint && candidate->endpoint != *endpoint) ? 2u : 0u));
            AR_LAB_SET(44, candidate->endpoint); AR_LAB_SET(45, candidate->endpoint >> 32);
            AR_LAB_SET(46, *endpoint); AR_LAB_SET(47, *endpoint >> 32);
            AR_LAB_SET(50, candidate->tuple.protocol | (candidate->tuple.version << 8));
            AR_LAB_SET(51, tuple->protocol | (tuple->version << 8));
#endif
            operation->cancelled = TRUE;
            inconsistent = TRUE;
            KeSetEvent(&operation->reauthorized, IO_NO_INCREMENT, FALSE);
        } else { *endpoint = candidate->endpoint; *parent_endpoint = candidate->parent_endpoint; }
        break;
    }
    if (!operation && !IsListEmpty(&pa_active)) AR_LAB_HIT(27);
    if (operation) {
        AR_LAB_HIT(15);
        RtlZeroMemory(decision, sizeof(*decision));
        decision->action = 1; decision->unresolved = 1; decision->rule = AP_NO_RULE;
        KeAcquireSpinLockAtDpcLevel(&pi_lock);
        BOOLEAN current = pi_published && pi_policy.generation == operation->generation && pi_session == operation->session;
        KeReleaseSpinLockFromDpcLevel(&pi_lock);
        if (current && operation->ready && !operation->cancelled && !pa_stopping &&
            KeQueryInterruptTime() < operation->deadline) *decision = operation->decision;
    }
    KeReleaseSpinLock(&pa_lock, old);
    // При ошибке consistency завершена именно найденная по OS flow операция.
    // Caller не должен повторно подтверждать другой endpoint из этого classify.
    return inconsistent ? 2u : operation ? 1u : 0u;
}

static void pa_admitted(UINT64 endpoint, const AIVPN_PACKET *tuple, BOOLEAN admitted)
{
    KIRQL old;
    KeAcquireSpinLock(&pa_lock, &old);
    PA_OPERATION *operation = pa_find(endpoint, tuple);
    if (operation && operation->ready) {
        AR_LAB_HIT(16); AR_LAB_SET(17, admitted);
        operation->admitted = admitted && !operation->cancelled;
        KeSetEvent(&operation->reauthorized, IO_NO_INCREMENT, FALSE);
    }
    KeReleaseSpinLock(&pa_lock, old);
}

static void pa_free(PA_OPERATION *operation)
{
    if (operation->packet) FwpsFreeCloneNetBufferList0(operation->packet, 0);
    process_release(&operation->process);
    KIRQL old;
    KeAcquireSpinLock(&pa_lock, &old);
    RemoveEntryList(&operation->active);
    pa_count--; pa_bytes -= operation->charged;
    UINT64 endpoint = operation->endpoint;
    KeReleaseSpinLock(&pa_lock, old);
    pc_complete_close(endpoint);
    ExFreePoolWithTag(operation, TAG);
}

static void NTAPI pa_injected(PVOID context, NET_BUFFER_LIST *packet, BOOLEAN dispatch)
{
    UNREFERENCED_PARAMETER(dispatch);
    AR_LAB_SET(20, NET_BUFFER_LIST_STATUS(packet)); AR_LAB_HIT(21);
    if (!NT_SUCCESS(NET_BUFFER_LIST_STATUS(packet))) InterlockedExchange(&pc_last_status, NET_BUFFER_LIST_STATUS(packet));
    pa_free(context);
}

static void pa_worker(PVOID unused)
{
    UNREFERENCED_PARAMETER(unused);
    for (;;) {
        KeWaitForSingleObject(&pa_event, Executive, KernelMode, FALSE, NULL);
        for (;;) {
            KIRQL old;
            KeAcquireSpinLock(&pa_lock, &old);
            BOOLEAN stopping_now = pa_stopping;
            PA_OPERATION *operation = IsListEmpty(&pa_queue) ? NULL :
                CONTAINING_RECORD(RemoveHeadList(&pa_queue), PA_OPERATION, queued);
            KeReleaseSpinLock(&pa_lock, old);
            if (!operation) { if (stopping_now) PsTerminateSystemThread(STATUS_SUCCESS); break; }
            AR_LAB_HIT(11);
#ifdef AIVPN_LAB
            ULONG lab_index = min((ULONG)InterlockedCompareExchange(&ar_lab[11], 0, 0) - 1, 3u);
#endif
            struct ap_decision decision = {0}; decision.action = 1; decision.unresolved = 1; decision.rule = AP_NO_RULE;
            session_lock();
            NTSTATUS status = STATUS_CANCELLED;
            AR_LAB_SET(31, pi_snapshot != NULL);
#ifdef AIVPN_LAB
            AR_LAB_SET(52 + lab_index, (KeQueryInterruptTime() + PA_DEADLINE - operation->deadline) / 10000);
#endif
            if (!stopping_now && pi_snapshot && pi_snapshot->policy.generation == operation->generation &&
                pi_snapshot->session == operation->session && KeQueryInterruptTime() < operation->deadline)
                status = pi_prepare_snapshot(operation->process.self->process, &operation->process, pi_snapshot);
            AR_LAB_SET(12, status);
#ifdef AIVPN_LAB
            AR_LAB_SET(32 + lab_index, status);
#endif
            if (NT_SUCCESS(status) && KeQueryInterruptTime() < operation->deadline) {
                BOOLEAN known;
                decision = pi_decision(operation->process.self->process, operation->tuple.version,
                    operation->tuple.destination, &known);
                if (!known) status = STATUS_NOT_FOUND;
            }
#ifdef AIVPN_LAB
            AR_LAB_SET(40 + lab_index, decision.action);
#endif
            AR_LAB_SET(13, decision.action); AR_LAB_SET(14, decision.unresolved);
            session_unlock();
            KeAcquireSpinLock(&pa_lock, &old);
            if (NT_SUCCESS(status) && !operation->cancelled && !pa_stopping) operation->decision = decision;
            else { operation->decision.action = 1; operation->decision.unresolved = 1; operation->decision.rule = AP_NO_RULE; }
            operation->ready = TRUE;
            KeReleaseSpinLock(&pa_lock, old);
            FwpsCompleteOperation0(operation->completion, NULL);
            operation->completion = NULL;
            LARGE_INTEGER timeout; timeout.QuadPart = -10000000;
            KeWaitForSingleObject(&operation->reauthorized, Executive, KernelMode, FALSE, &timeout);
            KeAcquireSpinLock(&pa_lock, &old);
            BOOLEAN inject = operation->admitted && !operation->cancelled && !pa_stopping &&
                KeQueryInterruptTime() < operation->deadline;
            KeReleaseSpinLock(&pa_lock, old);
            if (inject && operation->packet) {
                status = FwpsInjectTransportSendAsync0(pa_inject[operation->tuple.version == 4 ? 0 : 1], NULL,
                    operation->endpoint, 0, &operation->send, operation->tuple.version == 4 ? AF_INET : AF_INET6,
                    operation->compartment, operation->packet, pa_injected, operation);
                AR_LAB_SET(18, status);
                if (NT_SUCCESS(status)) { AR_LAB_HIT(19); continue; }
                InterlockedExchange(&pc_last_status, status);
            }
            pa_free(operation);
        }
    }
}

/* Вызывается с pc_state_lock. Обратного порядка блокировок нет. */
static BOOLEAN pa_close_pending(UINT64 endpoint, BOOLEAN cancel)
{
    KeAcquireSpinLockAtDpcLevel(&pa_lock);
    BOOLEAN pending = FALSE;
    for (LIST_ENTRY *entry = pa_active.Flink; entry != &pa_active; entry = entry->Flink) {
        PA_OPERATION *operation = CONTAINING_RECORD(entry, PA_OPERATION, active);
        if (operation->endpoint == endpoint) {
            pending = TRUE;
            if (cancel) { operation->cancelled = TRUE; KeSetEvent(&operation->reauthorized, IO_NO_INCREMENT, FALSE); }
        }
    }
    KeReleaseSpinLockFromDpcLevel(&pa_lock);
    return pending;
}

static BOOLEAN pa_pend(const FWPS_INCOMING_VALUES0 *values,
    const FWPS_INCOMING_METADATA_VALUES0 *metadata, NET_BUFFER_LIST *packet, const AIVPN_PACKET *tuple)
{
    AR_LAB_HIT(0);
    BOOLEAN ipv4 = tuple->version == 4;
    ULONG flags = values->incomingValue[ipv4 ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS : FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS].value.uint32;
    AR_LAB_SET(1, flags); AR_LAB_SET(2, metadata->currentMetadataValues);
    if (flags & FWP_CONDITION_FLAG_IS_REAUTHORIZE) { AR_LAB_HIT(3); return FALSE; }
    if (!(metadata->currentMetadataValues & FWPS_METADATA_FIELD_COMPLETION_HANDLE)) { AR_LAB_HIT(4); return FALSE; }
    if (!ExAcquireRundownProtection(&pa_rundown)) { AR_LAB_HIT(5); return FALSE; }
    AR_LAB_SET(6, 1);
    if (!(metadata->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) || !metadata->flowHandle) goto reject;
    ULONG bytes = 0;
    if (packet) {
        NET_BUFFER *buffer = NET_BUFFER_LIST_FIRST_NB(packet);
        if ((tuple->protocol != 17 && tuple->protocol != 1 && tuple->protocol != 58) ||
            NET_BUFFER_LIST_NEXT_NBL(packet) || !buffer || NET_BUFFER_NEXT_NB(buffer) ||
            (metadata->currentMetadataValues & FWPS_METADATA_FIELD_IP_HEADER_SIZE && metadata->ipHeaderSize)) goto reject;
        bytes = NET_BUFFER_DATA_LENGTH(buffer);
        if (bytes > PACKET_LIMIT || bytes < 8) goto reject;
    } else if (tuple->protocol != 6) goto reject;
    ULONG control_length = metadata->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_CONTROL_DATA ? metadata->controlDataLength : 0;
    AR_LAB_SET(6, 2); AR_LAB_SET(7, control_length);
    if (control_length > PA_CONTROL || (control_length && !metadata->controlData)) goto reject;
    AR_LAB_SET(6, 3);
    PA_OPERATION *operation = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*operation), TAG);
    if (!operation) goto reject;
    operation->tuple = *tuple;
    operation->endpoint = metadata->transportEndpointHandle;
    operation->parent_endpoint = metadata->currentMetadataValues & FWPS_METADATA_FIELD_PARENT_ENDPOINT_HANDLE ? metadata->parentEndpointHandle : 0;
    operation->flow = metadata->flowHandle;
    KIRQL publication_irql;
    KeAcquireSpinLock(&pi_lock, &publication_irql);
    operation->generation = pi_policy.generation;
    operation->session = pi_session;
    KeReleaseSpinLock(&pi_lock, publication_irql);
    operation->deadline = KeQueryInterruptTime() + PA_DEADLINE;
    operation->charged = bytes;
    operation->compartment = metadata->currentMetadataValues & FWPS_METADATA_FIELD_COMPARTMENT_ID ?
        metadata->compartmentId : UNSPECIFIED_COMPARTMENT_ID;
    operation->send.remoteAddress = operation->tuple.destination;
    if (metadata->currentMetadataValues & FWPS_METADATA_FIELD_REMOTE_SCOPE_ID)
        operation->send.remoteScopeId = metadata->remoteScopeId;
    operation->send.controlDataLength = control_length;
    if (control_length) {
        RtlCopyMemory(operation->control, metadata->controlData, control_length);
        operation->send.controlData = (WSACMSGHDR *)operation->control;
    }
    KeInitializeEvent(&operation->reauthorized, NotificationEvent, FALSE);
    AR_LAB_SET(6, 4);
    if (!pi_observe(metadata, &operation->process)) { ExFreePoolWithTag(operation, TAG); goto reject; }
    KIRQL old;
    KeAcquireSpinLock(&pa_lock, &old);
    BOOLEAN allowed = !pa_stopping && pa_count < PA_LIMIT && bytes <= PA_BYTES - pa_bytes &&
        !pa_find(operation->endpoint, NULL);
    if (allowed) { pa_count++; pa_bytes += bytes; InsertTailList(&pa_active, &operation->active); }
    KeReleaseSpinLock(&pa_lock, old);
    AR_LAB_SET(6, 5);
    if (!allowed) { process_release(&operation->process); ExFreePoolWithTag(operation, TAG); goto reject; }
    NTSTATUS status = packet ? FwpsAllocateCloneNetBufferList0(packet, NULL, NULL, 0, &operation->packet) : STATUS_SUCCESS;
    AR_LAB_SET(8, status); AR_LAB_SET(6, 6);
    if (NT_SUCCESS(status)) status = FwpsPendOperation0(metadata->completionHandle, &operation->completion);
    AR_LAB_SET(9, status); AR_LAB_SET(6, 7);
    if (!NT_SUCCESS(status)) { pa_free(operation); goto reject; }
    KeAcquireSpinLock(&pa_lock, &old);
    InsertTailList(&pa_queue, &operation->queued);
    KeReleaseSpinLock(&pa_lock, old);
    AR_LAB_HIT(10);
    KeSetEvent(&pa_event, IO_NO_INCREMENT, FALSE);
    ExReleaseRundownProtection(&pa_rundown);
    return TRUE;
reject:
    AR_LAB_HIT(22);
    ExReleaseRundownProtection(&pa_rundown);
    return FALSE;
}

static NTSTATUS pa_start(void)
{
    KeInitializeSpinLock(&pa_lock);
    InitializeListHead(&pa_active); InitializeListHead(&pa_queue);
    KeInitializeEvent(&pa_event, SynchronizationEvent, FALSE);
    ExInitializeRundownProtection(&pa_rundown);
    pa_initialized = TRUE;
    for (ULONG i = 0; i < 2; i++) {
        NTSTATUS status = FwpsInjectionHandleCreate0(i ? AF_INET6 : AF_INET, FWPS_INJECTION_TYPE_TRANSPORT, &pa_inject[i]);
        if (!NT_SUCCESS(status)) return status;
    }
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    return PsCreateSystemThread(&pa_thread, SYNCHRONIZE, &attributes, NULL, NULL, pa_worker, NULL);
}

static void pa_stop(void)
{
    if (!pa_initialized) return;
    ExWaitForRundownProtectionRelease(&pa_rundown);
    KIRQL old;
    KeAcquireSpinLock(&pa_lock, &old);
    pa_stopping = TRUE;
    KeReleaseSpinLock(&pa_lock, old);
    KeSetEvent(&pa_event, IO_NO_INCREMENT, FALSE);
    if (pa_thread) { ZwWaitForSingleObject(pa_thread, FALSE, NULL); ZwClose(pa_thread); pa_thread = NULL; }
    for (ULONG i = 0; i < 2; i++) if (pa_inject[i]) { FwpsInjectionHandleDestroy0(pa_inject[i]); pa_inject[i] = NULL; }
    pa_initialized = FALSE;
}
