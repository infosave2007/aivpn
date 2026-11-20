#pragma once
#include "provenance_memory.h"

/* Историческое имя принадлежит exact FILE_OBJECT и никогда не восстанавливается по DOS mapping. */
#define PV_UNITS 4096u
#define PV_TAG 'pRvA'

typedef enum {
    PV_UNREAD, PV_CAPTURED_EXACT_FO, PV_NO_IMAGE, PV_NO_CONTEXT, PV_UNSUPPORTED,
    PV_QUERY_FAILED, PV_BAD_ECP, PV_NAME_TOO_LONG, PV_REPARSE_LIMIT, PV_CROSS_VOLUME,
    PV_CAPACITY, PV_AMBIGUOUS, PV_ALREADY_CLAIMED, PV_STALE_EPOCH, PV_DETACHED,
    PV_STOPPING, PV_ID_EXHAUSTED
} PV_STATE;
typedef struct {
    UINT32 version, size, state, hops;
    UINT64 epoch, operation, initial_instance, final_instance;
    UINT32 units, reserved;
} PV_CAPTURE_HEADER;
typedef struct { PV_CAPTURE_HEADER info; WCHAR name[PV_UNITS]; } PV_CAPTURE;
typedef struct {
    PV_CAPTURE_HEADER capture;
    UINT64 claim;
    SIZE_T size;
    BOOLEAN ambiguous;
    WCHAR name[];
} PV_OPEN;
typedef struct { UINT64 epoch, id; BOOLEAN active; } PV_INSTANCE;
typedef struct { SIZE_T bytes; UINT64 kind; } PV_POOL;

static PFLT_FILTER pv_filter;
static KSPIN_LOCK pv_lock;
static UINT64 pv_epoch, pv_operation, pv_origin, pv_instance;
static PV_MEMORY pv_memory;
static BOOLEAN pv_stopping;
static const GUID pv_ecp_guid = {0x955b5108, 0x62f8, 0x4b88, {0x86,0xd2,0x14,0x6b,0x19,0x05,0x9a,0xa3}};
static UNICODE_STRING pv_instance_name = RTL_CONSTANT_STRING(L"Aivpn App Routing Instance");

static UINT64 pv_next(UINT64 *counter)
{
    KIRQL old;
    KeAcquireSpinLock(&pv_lock, &old);
    UINT64 result = *counter == MAXUINT64 ? 0 : ++*counter;
    KeReleaseSpinLock(&pv_lock, old);
    return result;
}

static BOOLEAN pv_reserve(ULONG kind, SIZE_T bytes)
{
    KIRQL old;
    KeAcquireSpinLock(&pv_lock, &old);
    BOOLEAN allowed = !pv_stopping && pv_memory_reserve(&pv_memory, kind, bytes);
    KeReleaseSpinLock(&pv_lock, old);
    return allowed;
}

static void pv_release(ULONG kind, SIZE_T bytes)
{
    KIRQL old;
    KeAcquireSpinLock(&pv_lock, &old);
    BOOLEAN released = pv_memory_release(&pv_memory, kind, bytes);
    NT_ASSERT(released);
    UNREFERENCED_PARAMETER(released);
    KeReleaseSpinLock(&pv_lock, old);
}

static PVOID FLTAPI pv_allocate_context(POOL_TYPE pool, SIZE_T size, FLT_CONTEXT_TYPE type)
{
    UNREFERENCED_PARAMETER(pool);
    ULONG kind = type == FLT_INSTANCE_CONTEXT ? PV_MEMORY_INSTANCE : PV_MEMORY_OPEN;
    if ((type != FLT_INSTANCE_CONTEXT && type != FLT_STREAMHANDLE_CONTEXT) ||
        size > sizeof(PV_OPEN) + PV_UNITS * sizeof(WCHAR) + 4096 ||
        !pv_reserve(kind, size + sizeof(PV_POOL))) return NULL;
    PV_POOL *allocation = ExAllocatePool2(POOL_FLAG_NON_PAGED, size + sizeof(*allocation), PV_TAG);
    if (!allocation) { pv_release(kind, size + sizeof(PV_POOL)); return NULL; }
    allocation->bytes = size + sizeof(*allocation);
    allocation->kind = kind;
    return allocation + 1;
}

static void FLTAPI pv_free_context(PVOID context, FLT_CONTEXT_TYPE type)
{
    UNREFERENCED_PARAMETER(type);
    PV_POOL *allocation = (PV_POOL *)context - 1;
    SIZE_T size = allocation->bytes;
    ULONG kind = (ULONG)allocation->kind;
    ExFreePoolWithTag(allocation, PV_TAG);
    pv_release(kind, size);
}

static void NTAPI pv_ecp_cleanup(PVOID context, LPCGUID guid)
{
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(guid);
    /* Это возврат собственного payload, а не наблюдение внутреннего pool FltMgr. */
    pv_release(PV_MEMORY_ECP, sizeof(PV_CAPTURE));
}

static BOOLEAN pv_native(PCUNICODE_STRING name)
{
    UNICODE_STRING prefix = RTL_CONSTANT_STRING(L"\\Device\\");
    if (!name || !name->Buffer || !name->Length || name->Length % sizeof(WCHAR) ||
        name->Length > PV_UNITS * sizeof(WCHAR) || name->MaximumLength < name->Length ||
        !RtlPrefixUnicodeString(&prefix, name, TRUE)) return FALSE;
    UINT32 component = 0, units = name->Length / sizeof(WCHAR);
    for (UINT32 i = 0; i <= units; i++) {
        if (i < units && (!name->Buffer[i] || name->Buffer[i] == L'/')) return FALSE;
        if (i == units || name->Buffer[i] == L'\\') {
            UINT32 length = i - component;
            if ((length == 1 && name->Buffer[component] == L'.') ||
                (length == 2 && name->Buffer[component] == L'.' && name->Buffer[component + 1] == L'.'))
                return FALSE;
            component = i + 1;
        }
    }
    return TRUE;
}

static NTSTATUS pv_create_ecp(PFLT_CALLBACK_DATA data, PECP_LIST list, UINT64 instance, PV_CAPTURE **out)
{
    if (!pv_reserve(PV_MEMORY_ECP, sizeof(PV_CAPTURE))) return STATUS_INSUFFICIENT_RESOURCES;
    PV_CAPTURE *capture = NULL;
    NTSTATUS status = FltAllocateExtraCreateParameter(pv_filter, &pv_ecp_guid, sizeof(*capture),
        FSRTL_ALLOCATE_ECP_FLAG_NONPAGED_POOL, pv_ecp_cleanup, PV_TAG, (PVOID *)&capture);
    if (!NT_SUCCESS(status)) { pv_release(PV_MEMORY_ECP, sizeof(PV_CAPTURE)); return status; }
    RtlZeroMemory(capture, sizeof(*capture));
    capture->info.version = 1;
    capture->info.size = sizeof(*capture);
    capture->info.epoch = pv_epoch;
    capture->info.operation = pv_next(&pv_operation);
    capture->info.initial_instance = instance;
    capture->info.state = capture->info.operation ? PV_QUERY_FAILED : PV_ID_EXHAUSTED;
    PFLT_FILE_NAME_INFORMATION name = NULL;
    if (capture->info.operation) {
        status = FltGetFileNameInformation(data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
        if (NT_SUCCESS(status)) {
            if (name->Name.Length > sizeof(capture->name)) capture->info.state = PV_NAME_TOO_LONG;
            else if (pv_native(&name->Name)) {
                capture->info.units = name->Name.Length / sizeof(WCHAR);
                RtlCopyMemory(capture->name, name->Name.Buffer, name->Name.Length);
                capture->info.state = PV_CAPTURED_EXACT_FO;
            } else capture->info.state = PV_UNSUPPORTED;
            FltReleaseFileNameInformation(name);
        }
    }
    PECP_LIST created = NULL;
    if (!list) {
        status = FltAllocateExtraCreateParameterList(pv_filter, 0, &created);
        if (!NT_SUCCESS(status)) { FltFreeExtraCreateParameter(pv_filter, capture); return status; }
        list = created;
    }
    status = FltInsertExtraCreateParameter(pv_filter, list, capture);
    if (!NT_SUCCESS(status)) {
        FltFreeExtraCreateParameter(pv_filter, capture);
        if (created) FltFreeExtraCreateParameterList(pv_filter, created);
        return status;
    }
    if (created) {
        status = FltSetEcpListIntoCallbackData(pv_filter, data, created);
        if (!NT_SUCCESS(status)) { FltFreeExtraCreateParameterList(pv_filter, created); return status; }
    }
    *out = capture;
    return STATUS_SUCCESS;
}

static FLT_PREOP_CALLBACK_STATUS pv_pre_create(PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS objects, PVOID *completion)
{
    *completion = NULL;
    PV_INSTANCE *instance = NULL;
    if (!NT_SUCCESS(FltGetInstanceContext(objects->Instance, (PFLT_CONTEXT *)&instance)))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    KIRQL old;
    KeAcquireSpinLock(&pv_lock, &old);
    BOOLEAN active = !pv_stopping && instance->active && instance->epoch == pv_epoch;
    UINT64 id = instance->id;
    KeReleaseSpinLock(&pv_lock, old);
    FltReleaseContext(instance);
    if (!active) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    PECP_LIST list = NULL;
    if (!NT_SUCCESS(FltGetEcpListFromCallbackData(pv_filter, data, &list))) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    PV_CAPTURE *capture = NULL;
    ULONG size = 0;
    if (list && NT_SUCCESS(FltFindExtraCreateParameter(pv_filter, list, &pv_ecp_guid, (PVOID *)&capture, &size))) {
        if (size != sizeof(*capture) || FltIsEcpFromUserMode(pv_filter, capture) ||
            capture->info.version != 1 || capture->info.size != sizeof(*capture) || capture->info.epoch != pv_epoch ||
            !capture->info.operation || capture->info.units > PV_UNITS || capture->info.reserved)
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        if (capture->info.initial_instance != id) capture->info.state = PV_CROSS_VOLUME;
        if (capture->info.hops >= 32) capture->info.state = PV_REPARSE_LIMIT;
    } else if (!NT_SUCCESS(pv_create_ecp(data, list, id, &capture))) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (capture->info.hops < MAXULONG) capture->info.hops++;
    capture->info.final_instance = id;
    *completion = capture;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS pv_post_create(PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS objects, PVOID completion, FLT_POST_OPERATION_FLAGS flags)
{
    if ((flags & FLTFL_POST_OPERATION_DRAINING) || data->IoStatus.Status == STATUS_REPARSE ||
        !NT_SUCCESS(data->IoStatus.Status) || !FltSupportsStreamHandleContexts(objects->FileObject))
        return FLT_POSTOP_FINISHED_PROCESSING;
    PV_CAPTURE *capture = completion;
    if (capture->info.units > PV_UNITS) return FLT_POSTOP_FINISHED_PROCESSING;
    SIZE_T size = sizeof(PV_OPEN) + capture->info.units * sizeof(WCHAR);
    PV_OPEN *context = NULL, *existing = NULL;
    if (!NT_SUCCESS(FltAllocateContext(pv_filter, FLT_STREAMHANDLE_CONTEXT,
        size, NonPagedPoolNx, (PFLT_CONTEXT *)&context))) return FLT_POSTOP_FINISHED_PROCESSING;
    RtlZeroMemory(context, size);
    context->size = size;
    context->capture = capture->info;
    RtlCopyMemory(context->name, capture->name, capture->info.units * sizeof(WCHAR));
    PV_INSTANCE *instance = NULL;
    BOOLEAN active = FALSE;
    KIRQL old;
    if (NT_SUCCESS(FltGetInstanceContext(objects->Instance, (PFLT_CONTEXT *)&instance))) {
        KeAcquireSpinLock(&pv_lock, &old);
        active = !pv_stopping && instance->active && instance->epoch == capture->info.epoch &&
            instance->id == capture->info.final_instance;
        KeReleaseSpinLock(&pv_lock, old);
        FltReleaseContext(instance);
    }
    if (active) {
        NTSTATUS status = FltSetStreamHandleContext(objects->Instance, objects->FileObject,
            FLT_SET_CONTEXT_KEEP_IF_EXISTS, context, (PFLT_CONTEXT *)&existing);
        if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED && existing) {
            KeAcquireSpinLock(&pv_lock, &old);
            if (existing->capture.epoch != capture->info.epoch || existing->capture.operation != capture->info.operation)
                existing->ambiguous = TRUE;
            KeReleaseSpinLock(&pv_lock, old);
        }
        if (existing) FltReleaseContext(existing);
    }
    FltReleaseContext(context);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static NTSTATUS pv_setup(PCFLT_RELATED_OBJECTS objects, FLT_INSTANCE_SETUP_FLAGS flags,
    DEVICE_TYPE type, FLT_FILESYSTEM_TYPE filesystem)
{
    UNREFERENCED_PARAMETER(flags);
    if (type != FILE_DEVICE_DISK_FILE_SYSTEM || filesystem != FLT_FSTYPE_NTFS)
        return STATUS_FLT_DO_NOT_ATTACH;
    PV_INSTANCE *context = NULL;
    NTSTATUS status = FltAllocateContext(pv_filter, FLT_INSTANCE_CONTEXT,
        sizeof(*context), NonPagedPoolNx, (PFLT_CONTEXT *)&context);
    if (!NT_SUCCESS(status)) return status;
    RtlZeroMemory(context, sizeof(*context));
    context->epoch = pv_epoch;
    context->id = pv_next(&pv_instance);
    KIRQL old;
    KeAcquireSpinLock(&pv_lock, &old);
    BOOLEAN allowed = context->id && !pv_stopping;
    if (allowed) context->active = TRUE;
    KeReleaseSpinLock(&pv_lock, old);
    status = allowed ? FltSetInstanceContext(objects->Instance, FLT_SET_CONTEXT_KEEP_IF_EXISTS, context, NULL) :
        STATUS_FLT_DO_NOT_ATTACH;
    FltReleaseContext(context);
    return status;
}

static void pv_teardown(PCFLT_RELATED_OBJECTS objects, FLT_INSTANCE_TEARDOWN_FLAGS flags)
{
    UNREFERENCED_PARAMETER(flags);
    PV_INSTANCE *instance = NULL;
    if (!NT_SUCCESS(FltGetInstanceContext(objects->Instance, (PFLT_CONTEXT *)&instance))) return;
    KIRQL old;
    KeAcquireSpinLock(&pv_lock, &old);
    instance->active = FALSE;
    KeReleaseSpinLock(&pv_lock, old);
    FltReleaseContext(instance);
}

static void provenance_proof_free(PV_CAPTURE *proof)
{
    if (!proof) return;
    ExFreePoolWithTag(proof, PV_TAG);
    pv_release(PV_MEMORY_PROOF, sizeof(*proof));
}

static PV_STATE provenance_get_copy(PFILE_OBJECT image, UINT64 token, PV_CAPTURE **out)
{
    if (!image) return PV_NO_IMAGE;
    if (!token) return PV_ID_EXHAUSTED;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return PV_QUERY_FAILED;
    if (!pv_reserve(PV_MEMORY_PROOF, sizeof(PV_CAPTURE))) return PV_CAPACITY;
    PV_CAPTURE *copy = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*copy), PV_TAG);
    if (!copy) { pv_release(PV_MEMORY_PROOF, sizeof(PV_CAPTURE)); return PV_CAPACITY; }
    PFLT_VOLUME volume = NULL;
    PFLT_INSTANCE instance = NULL;
    PV_INSTANCE *instance_context = NULL;
    PV_OPEN *context = NULL;
    PV_STATE state = PV_NO_CONTEXT;
    NTSTATUS status = FltGetVolumeFromFileObject(pv_filter, image, &volume);
    if (NT_SUCCESS(status)) status = FltGetVolumeInstanceFromName(pv_filter, volume, &pv_instance_name, &instance);
    if (NT_SUCCESS(status)) status = FltGetInstanceContext(instance, (PFLT_CONTEXT *)&instance_context);
    if (NT_SUCCESS(status)) status = FltGetStreamHandleContext(instance, image, (PFLT_CONTEXT *)&context);
    if (NT_SUCCESS(status)) {
        KIRQL old;
        KeAcquireSpinLock(&pv_lock, &old);
        if (pv_stopping) state = PV_STOPPING;
        else if (!instance_context->active) state = PV_DETACHED;
        else if (context->size < sizeof(PV_OPEN) || context->capture.units > PV_UNITS ||
            context->capture.units > (context->size - sizeof(PV_OPEN)) / sizeof(WCHAR)) state = PV_BAD_ECP;
        else if (context->capture.epoch != pv_epoch || instance_context->epoch != pv_epoch ||
            context->capture.final_instance != instance_context->id) state = PV_STALE_EPOCH;
        else if (context->ambiguous) state = PV_AMBIGUOUS;
        else if (context->capture.state != PV_CAPTURED_EXACT_FO) state =
            context->capture.state <= PV_ID_EXHAUSTED ? (PV_STATE)context->capture.state : PV_BAD_ECP;
        else if (context->claim && context->claim != token) state = PV_ALREADY_CLAIMED;
        else { context->claim = token; state = PV_CAPTURED_EXACT_FO; }
        KeReleaseSpinLock(&pv_lock, old);
        if (state == PV_CAPTURED_EXACT_FO) {
            copy->info = context->capture;
            RtlCopyMemory(copy->name, context->name, context->capture.units * sizeof(WCHAR));
            *out = copy; copy = NULL;
        }
    }
    if (context) FltReleaseContext(context);
    if (instance_context) FltReleaseContext(instance_context);
    if (instance) FltObjectDereference(instance);
    if (volume) FltObjectDereference(volume);
    provenance_proof_free(copy);
    if (state == PV_CAPTURED_EXACT_FO) AR_LAB_HIT(60);
    else if (state == PV_ALREADY_CLAIMED) AR_LAB_HIT(61);
    else AR_LAB_HIT(62);
    return state;
}

static NTSTATUS FLTAPI filter_unload(FLT_FILTER_UNLOAD_FLAGS flags);
static const FLT_CONTEXT_REGISTRATION pv_contexts[] = {
    {FLT_STREAMHANDLE_CONTEXT, 0, NULL, FLT_VARIABLE_SIZED_CONTEXTS, PV_TAG, pv_allocate_context, pv_free_context, NULL},
    {FLT_INSTANCE_CONTEXT, 0, NULL, sizeof(PV_INSTANCE), PV_TAG, pv_allocate_context, pv_free_context, NULL},
    {.ContextType = FLT_CONTEXT_END}
};
static const FLT_OPERATION_REGISTRATION pv_operations[] = {
    {IRP_MJ_CREATE, 0, pv_pre_create, pv_post_create, NULL},
    {.MajorFunction = IRP_MJ_OPERATION_END}
};
static const FLT_REGISTRATION pv_registration = {
    .Size = sizeof(FLT_REGISTRATION), .Version = FLT_REGISTRATION_VERSION,
    .Flags = FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP,
    .ContextRegistration = pv_contexts, .OperationRegistration = pv_operations,
    .FilterUnloadCallback = filter_unload, .InstanceSetupCallback = pv_setup,
    .InstanceTeardownStartCallback = pv_teardown
};
