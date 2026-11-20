#pragma once

#ifdef AIVPN_LAB
static PKEVENT pc_lab_started, pc_lab_release;

static NTSTATUS pc_lab_arm(const AR_LAB_BARRIER *request)
{
    if (!request->started || !request->release || request->started == request->release) return STATUS_INVALID_PARAMETER;
    PKEVENT started = NULL, release = NULL;
    NTSTATUS status = ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)request->started, EVENT_MODIFY_STATE,
        *ExEventObjectType, UserMode, (PVOID *)&started, NULL);
    if (NT_SUCCESS(status)) status = ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)request->release, SYNCHRONIZE,
        *ExEventObjectType, UserMode, (PVOID *)&release, NULL);
    if (NT_SUCCESS(status) && started == release) status = STATUS_INVALID_PARAMETER;
    if (NT_SUCCESS(status)) {
        KIRQL old;
        KeAcquireSpinLock(&pc_state_lock, &old);
        if (pc_lab_started || pc_lab_release) status = STATUS_DEVICE_BUSY;
        else { pc_lab_started = started; pc_lab_release = release; started = release = NULL; }
        KeReleaseSpinLock(&pc_state_lock, old);
    }
    if (started) ObDereferenceObject(started);
    if (release) ObDereferenceObject(release);
    return status;
}

static void pc_lab_cancel(void)
{
    KIRQL old;
    KeAcquireSpinLock(&pc_state_lock, &old);
    PKEVENT started = pc_lab_started, release = pc_lab_release;
    pc_lab_started = pc_lab_release = NULL;
    KeReleaseSpinLock(&pc_state_lock, old);
    if (started) ObDereferenceObject(started);
    if (release) ObDereferenceObject(release);
}

/* Один UDP receive: reservation уже удерживает FLOW, API еще не вызван.
   Приватные events принадлежат текущей SYSTEM/session0 службе. */
static NTSTATUS pc_lab_before_receive(const FLOW *flow)
{
    if (flow->tuple.protocol != 17) return STATUS_SUCCESS;
    KIRQL old;
    KeAcquireSpinLock(&pc_state_lock, &old);
    PKEVENT started = pc_lab_started, release = pc_lab_release;
    pc_lab_started = pc_lab_release = NULL;
    if (started) pc_lifetime_trace(7, NULL, flow);
    KeReleaseSpinLock(&pc_state_lock, old);
    if (!started) return STATUS_SUCCESS;
    KeSetEvent(started, IO_NO_INCREMENT, FALSE);
    LARGE_INTEGER timeout; timeout.QuadPart = -5ll * 10000000ll;
    NTSTATUS status = KeWaitForSingleObject(release, Executive, KernelMode, FALSE, &timeout);
    ObDereferenceObject(started); ObDereferenceObject(release);
    KeAcquireSpinLock(&pc_state_lock, &old);
    pc_lifetime_trace(8, NULL, flow);
    KeReleaseSpinLock(&pc_state_lock, old);
    return status == STATUS_SUCCESS ? STATUS_SUCCESS : STATUS_IO_TIMEOUT;
}
#else
#define pc_lab_cancel() ((void)0)
#define pc_lab_before_receive(flow) STATUS_SUCCESS
#endif
