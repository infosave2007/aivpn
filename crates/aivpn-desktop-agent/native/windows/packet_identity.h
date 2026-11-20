#pragma once
#include "runtime_identity.h"

#define PI_LIMIT 128u
typedef struct {
    PEPROCESS process;
    UINT64 generation, session;
    struct ap_context context;
    BOOLEAN truncated;
    BOOLEAN runtime;
    UINT32 policy_index;
} PI_RECORD;
typedef struct {
    struct ap_policy policy;
    UINT64 session;
    ULONG count;
    RS_SNAPSHOT *runtime;
    AR_BINDING bindings[];
} PI_SNAPSHOT;
static KSPIN_LOCK pi_lock;
static PI_RECORD pi_records[PI_LIMIT];
static struct ap_policy pi_policy;
static BOOLEAN pi_published;
static UINT64 pi_session;
static RS_SNAPSHOT *pi_runtime;
/* Доступ к refs и provenance только при PASSIVE под session mutex. */
static PI_SNAPSHOT *pi_snapshot;

static void pi_snapshot_free(PI_SNAPSHOT *snapshot)
{
    if (!snapshot) return;
    rs_release(snapshot->runtime);
    for (ULONG i = 0; i < snapshot->count; i++) {
        AR_BINDING *binding = &snapshot->bindings[i];
        if (binding->file) ZwClose(binding->file);
        if (binding->image) ObDereferenceObject(binding->image);
        if (binding->volume_device) ObDereferenceObject(binding->volume_device);
    }
    ExFreePoolWithTag(snapshot, AR_POOL_TAG);
}

static NTSTATUS pi_snapshot_create(PI_SNAPSHOT **result)
{
    *result = NULL;
    RS_SNAPSHOT *runtime = rs_pending ? rs_pending : rs_current;
    if (runtime) {
        if (!runtime->sealed || runtime->session != session_id) return STATUS_DEVICE_NOT_READY;
        PI_SNAPSHOT *snapshot = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*snapshot), AR_POOL_TAG);
        if (!snapshot) return STATUS_INSUFFICIENT_RESOURCES;
        InterlockedIncrement(&runtime->references);
        snapshot->runtime = runtime;
        snapshot->session = runtime->session;
        snapshot->policy.generation = runtime->epoch;
        *result = snapshot;
        return STATUS_SUCCESS;
    }
    if (!staged || !policy_bound(&policy)) return STATUS_DEVICE_NOT_READY;
    PI_SNAPSHOT *snapshot = ExAllocatePool2(POOL_FLAG_NON_PAGED,
        sizeof(*snapshot) + binding_count * sizeof(AR_BINDING), AR_POOL_TAG);
    if (!snapshot) return STATUS_INSUFFICIENT_RESOURCES;
    snapshot->policy = policy;
    snapshot->session = session_id;
    NTSTATUS status = STATUS_SUCCESS;
    for (ULONG i = 0; i < binding_count; i++) {
        AR_BINDING *binding = &snapshot->bindings[i];
        *binding = bindings[i];
        binding->file = NULL;
        if (binding->image) ObReferenceObject(binding->image);
        if (binding->volume_device) ObReferenceObject(binding->volume_device);
        snapshot->count++;
        if (bindings[i].file) {
            status = ZwDuplicateObject(NtCurrentProcess(), bindings[i].file, NtCurrentProcess(),
                &binding->file, 0, OBJ_KERNEL_HANDLE, DUPLICATE_SAME_ACCESS);
            if (!NT_SUCCESS(status)) break;
        }
    }
    if (!NT_SUCCESS(status)) { pi_snapshot_free(snapshot); return status; }
    *result = snapshot;
    return STATUS_SUCCESS;
}

static void pi_reap(void)
{
    for (ULONG i = 0; i < PI_LIMIT; i++) {
        PEPROCESS process = pi_records[i].process;
        if (!process || NT_SUCCESS(process_running(process))) continue;
        KIRQL old;
        KeAcquireSpinLock(&pi_lock, &old);
        pi_records[i].process = NULL;
        KeReleaseSpinLock(&pi_lock, old);
        ObDereferenceObject(process);
    }
}

static NTSTATUS pi_prepare_snapshot(PEPROCESS process, AR_PROCESS *snapshot, const PI_SNAPSHOT *published)
{
    const struct ap_policy *current = published ? &published->policy : &policy;
    const AR_BINDING *table = published ? published->bindings : bindings;
    ULONG count = published ? published->count : binding_count;
    UINT64 session = published ? published->session : session_id;
    if (!published && (!staged || !policy_bound(current))) return STATUS_DEVICE_NOT_READY;
    pi_reap();
    ObReferenceObject(process);
    PI_RECORD record = {0};
    record.generation = current->generation;
    record.session = session;
    AR_DIAGNOSTIC self = {0};
    NTSTATUS status = process_running(process);
    const RS_SNAPSHOT *runtime = published ? published->runtime : NULL;
    record.runtime = runtime != NULL;
    record.policy_index = MAXULONG;
    if (runtime && NT_SUCCESS(status)) {
        status = token_sid(snapshot->self->token, TokenUser, self.user, &self.user_length);
        if (NT_SUCCESS(status) && !self.user_length) status = STATUS_INVALID_SID;
        if (NT_SUCCESS(status)) {
            record.policy_index = rs_policy_index(runtime, rs_sid_slot(runtime, AR_BIND_OWNER, self.user, self.user_length));
            status = rs_resolve_origin(snapshot->self, &record.context.process, &self, runtime, record.policy_index);
        }
    } else if (NT_SUCCESS(status)) status = resolve_origin_in(snapshot->self, &record.context.process, &self,
        current, session, table, count);
#ifdef AIVPN_LAB
    ULONG operation = (ULONG)InterlockedCompareExchange(&ar_lab[11], 0, 0);
    AR_LAB_SET(56 + min(operation ? operation - 1 : 0, 3u), snapshot->self->provenance_state);
#endif
    for (UINT32 i = 0; NT_SUCCESS(status) && i < snapshot->parent_count; i++) {
        AR_DIAGNOSTIC parent = {0};
        status = runtime ? rs_resolve_origin(snapshot->parents[i], &record.context.parents[i], &parent, runtime, record.policy_index) :
            resolve_origin_in(snapshot->parents[i], &record.context.parents[i], &parent, current, session, table, count);
        if (NT_SUCCESS(status) && (parent.user_length != self.user_length ||
            RtlCompareMemory(parent.user, self.user, self.user_length) != self.user_length)) break;
        record.context.parent_count++;
    }
    record.truncated = snapshot->ancestry_truncated && record.context.parent_count == snapshot->parent_count;
    if (NT_SUCCESS(status)) {
        KIRQL old;
        KeAcquireSpinLock(&pi_lock, &old);
        ULONG slot = PI_LIMIT;
        for (ULONG i = 0; i < PI_LIMIT; i++) {
            if (pi_records[i].process == process) { slot = i; break; }
            if (!pi_records[i].process && slot == PI_LIMIT) slot = i;
        }
        if (slot == PI_LIMIT) status = STATUS_INSUFFICIENT_RESOURCES;
        else {
            record.process = process;
            PEPROCESS previous = pi_records[slot].process;
            pi_records[slot] = record;
            process = previous;
        }
        KeReleaseSpinLock(&pi_lock, old);
    }
    if (process) ObDereferenceObject(process);
    return status;
}

static NTSTATUS packet_prepare(const AR_DIAGNOSE *request)
{
    if (request->reserved) return STATUS_INVALID_PARAMETER;
    PEPROCESS process = NULL;
    NTSTATUS status = ObReferenceObjectByHandle((HANDLE)request->process_handle, AR_PROCESS_QUERY,
        *PsProcessType, UserMode, (PVOID *)&process, NULL);
    if (!NT_SUCCESS(status)) return status;
    AR_PROCESS snapshot = {0};
    status = process_snapshot(process, &snapshot);
    if (NT_SUCCESS(status)) status = pi_prepare_snapshot(process, &snapshot, NULL);
    process_release(&snapshot);
    ObDereferenceObject(process);
    return status;
}

/* PID используется лишь для поиска уже удержанного process instance в notify cache. */
static BOOLEAN pi_observe(const FWPS_INCOMING_METADATA_VALUES0 *metadata, AR_PROCESS *snapshot)
{
    if (!(metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)) return FALSE;
    InterlockedIncrement(&readers);
    for (ULONG i = 0; i < AR_PROCESS_LIMIT; i++) {
        AR_PROCESS *record = InterlockedCompareExchangePointer((PVOID volatile *)&processes[i], NULL, NULL);
        if (record && PsGetProcessId(record->self->process) == (HANDLE)(ULONG_PTR)metadata->processId) {
            process_copy(snapshot, record);
            break;
        }
    }
    readers_leave();
    return snapshot->self != NULL;
}

static struct ap_decision pi_decision(PEPROCESS process, UINT32 family, const UCHAR *destination, BOOLEAN *known)
{
    struct ap_decision decision = {0};
    *known = FALSE;
    decision.action = 1;
    decision.unresolved = 1;
    decision.rule = AP_NO_RULE;
    KIRQL old;
    KeAcquireSpinLock(&pi_lock, &old);
    if (!pi_published) { decision.action = 0; *known = TRUE; }
    else for (ULONG i = 0; i < PI_LIMIT; i++) {
        PI_RECORD *record = &pi_records[i];
        if (!process || record->process != process || record->generation != pi_policy.generation || record->session != pi_session) continue;
        *known = TRUE;
        struct ap_context context = record->context;
        context.family = family;
        RtlCopyMemory(context.destination, destination, family == 4 ? 4 : 16);
        if (record->runtime && pi_runtime) {
            if (record->policy_index == MAXULONG) {
                RtlZeroMemory(&decision, sizeof(decision)); decision.rule = AP_NO_RULE; decision.generation = pi_runtime->epoch;
            } else if (record->policy_index < pi_runtime->count) {
                AR_MEMBERSHIP_VIEW memberships = {pi_runtime->registry->members, pi_runtime->registry->member_count};
                decision = ar_evaluate_memberships(&pi_runtime->policies[record->policy_index].policy,
                    &memberships, &context, record->truncated);
            }
        } else if (!record->runtime && !pi_runtime) decision = evaluate_identity(&pi_policy, &context, record->truncated);
        break;
    }
    KeReleaseSpinLock(&pi_lock, old);
    return decision;
}

static struct ap_decision packet_decision(const FWPS_INCOMING_METADATA_VALUES0 *metadata,
    UINT32 family, const UCHAR *destination, BOOLEAN *known)
{
    AR_PROCESS snapshot = {0};
    pi_observe(metadata, &snapshot);
    struct ap_decision decision = pi_decision(snapshot.self ? snapshot.self->process : NULL, family, destination, known);
    process_release(&snapshot);
    return decision;
}

static void packet_identity_clear(void)
{
    for (ULONG i = 0; i < PI_LIMIT; i++) {
        PEPROCESS process = pi_records[i].process;
        pi_records[i].process = NULL;
        if (process) ObDereferenceObject(process);
    }
    pi_snapshot_free(pi_snapshot);
    pi_snapshot = NULL;
    pi_runtime = NULL;
}
