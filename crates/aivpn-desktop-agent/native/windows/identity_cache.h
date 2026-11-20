#pragma once

#define AR_RECORD_LIMIT (AR_PROCESS_LIMIT + 64u)
static AR_PROCESS *volatile processes[AR_PROCESS_LIMIT];
static SLIST_HEADER retired_records, retired_origins;
static LONG readers, record_count, origin_count, stopping;
static KEVENT reap_event;
static HANDLE reaper_thread;

/* Последняя ссылка лишь публикует retirement. Уничтожение объектов может вызвать FS. */
static void origin_release(AR_ORIGIN *origin)
{
    if (!origin || InterlockedDecrement(&origin->references)) return;
    InterlockedPushEntrySList(&retired_origins, &origin->retired);
    KeSetEvent(&reap_event, IO_NO_INCREMENT, FALSE);
}

static void process_release(AR_PROCESS *record)
{
    origin_release(record->self);
    for (UINT32 i = 0; i < record->parent_count; i++) origin_release(record->parents[i]);
    RtlZeroMemory(record, sizeof(*record));
}

static void process_copy(AR_PROCESS *target, const AR_PROCESS *source)
{
    *target = *source;
    InterlockedIncrement(&target->self->references);
    for (UINT32 i = 0; i < target->parent_count; i++)
        InterlockedIncrement(&target->parents[i]->references);
}

static void readers_leave(void)
{
    if (!InterlockedDecrement(&readers)) KeSetEvent(&reap_event, IO_NO_INCREMENT, FALSE);
}

/* Вызывается только внутри reader epoch. Records неизменяемы после публикации. */
static AR_PROCESS *process_find(PEPROCESS process)
{
    for (UINT32 i = 0; i < AR_PROCESS_LIMIT; i++) {
        AR_PROCESS *record = InterlockedCompareExchangePointer((PVOID volatile *)&processes[i], NULL, NULL);
        if (record && record->self->process == process) return record;
    }
    return NULL;
}

static void record_retire(AR_PROCESS *record)
{
    InterlockedPushEntrySList(&retired_records, &record->retired);
    KeSetEvent(&reap_event, IO_NO_INCREMENT, FALSE);
}

static void origins_free(void)
{
    PSLIST_ENTRY entry = InterlockedFlushSList(&retired_origins);
    while (entry) {
        AR_ORIGIN *origin = CONTAINING_RECORD(entry, AR_ORIGIN, retired);
        entry = entry->Next;
        provenance_proof_free(origin->provenance);
        if (origin->image) ObDereferenceObject(origin->image);
        if (origin->opening_token) {
            if (origin->opening_impersonation) PsDereferenceImpersonationToken(origin->opening_token);
            else PsDereferencePrimaryToken(origin->opening_token);
        }
        PsDereferencePrimaryToken(origin->token);
        ObDereferenceObject(origin->process);
        ExFreePoolWithTag(origin, AR_POOL_TAG);
        InterlockedDecrement(&origin_count);
    }
}

static void reaper(PVOID unused)
{
    UNREFERENCED_PARAMETER(unused);
    PSLIST_ENTRY pending = NULL;
    for (;;) {
        KeWaitForSingleObject(&reap_event, Executive, KernelMode, FALSE, NULL);
        if (!pending) pending = InterlockedFlushSList(&retired_records);
        /* Flush предшествует проверке epoch: новые readers уже не найдут эти records. */
        if (!InterlockedCompareExchange(&readers, 0, 0)) {
            while (pending) {
                AR_PROCESS *record = CONTAINING_RECORD(pending, AR_PROCESS, retired);
                pending = pending->Next;
                process_release(record);
                ExFreePoolWithTag(record, AR_POOL_TAG);
                InterlockedDecrement(&record_count);
            }
        }
        origins_free();
        if (InterlockedCompareExchange(&stopping, 0, 0) && !record_count && !origin_count) break;
        if (!pending && QueryDepthSList(&retired_records)) KeSetEvent(&reap_event, IO_NO_INCREMENT, FALSE);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static void cache_stop(void)
{
    for (UINT32 i = 0; i < AR_PROCESS_LIMIT; i++) {
        AR_PROCESS *record = InterlockedExchangePointer((PVOID volatile *)&processes[i], NULL);
        if (record) record_retire(record);
    }
    InterlockedExchange(&stopping, 1);
    KeSetEvent(&reap_event, IO_NO_INCREMENT, FALSE);
    ZwWaitForSingleObject(reaper_thread, FALSE, NULL);
    ZwClose(reaper_thread);
    reaper_thread = NULL;
}

static NTSTATUS cache_start(void)
{
    InitializeSListHead(&retired_records);
    InitializeSListHead(&retired_origins);
    KeInitializeEvent(&reap_event, SynchronizationEvent, FALSE);
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    return PsCreateSystemThread(&reaper_thread, SYNCHRONIZE, &attributes, NULL, NULL, reaper, NULL);
}
