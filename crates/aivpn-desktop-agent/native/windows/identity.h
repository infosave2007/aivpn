#pragma once
#include "membership.h"

#define AR_PROCESS_LIMIT 512u
#define AR_BIND_LIMIT (AP_RULE_LIMIT + 1u)
#define AR_ORIGIN_LIMIT (AR_PROCESS_LIMIT * (AP_PARENT_LIMIT + 1u) + 64u)
#define AR_POOL_TAG 'iRvA'
/* Windows SDK winnt.h: PROCESS_QUERY_LIMITED_INFORMATION. */
#define AR_PROCESS_QUERY 0x1000u

/* Снимок не содержит цепочку ссылок: потомок удерживает максимум 32 предка. */
typedef struct {
    SLIST_ENTRY retired;
    LONG references;
    PEPROCESS process;
    PFILE_OBJECT image;
    PACCESS_TOKEN opening_token;
    BOOLEAN opening_impersonation;
    PACCESS_TOKEN token;
    UINT64 origin_token;
    PV_STATE provenance_state;
    PV_CAPTURE *provenance;
    UINT64 marker_session;
    UINT32 negative[(AR_BIND_LIMIT + 31u) / 32u];
    UINT32 runtime_negative[(AR_ALIAS_LIMIT + 31u) / 32u];
    USHORT path_length;
    WCHAR path[];
} AR_ORIGIN;
typedef struct {
    SLIST_ENTRY retired;
    AR_ORIGIN *self;
    UINT32 parent_count;
    BOOLEAN ancestry_truncated;
    AR_ORIGIN *parents[AP_PARENT_LIMIT];
} AR_PROCESS;
typedef struct {
    UINT32 kind, slot, sid_length;
    UCHAR sid[AR_SID_BYTES];
    HANDLE file;
    PFILE_OBJECT image;
    PDEVICE_OBJECT volume_device;
    FILE_ID_INFORMATION identity;
    UINT32 path_units;
    WCHAR path[AR_PATH_UNITS];
} AR_BINDING;

static AR_BINDING bindings[AR_BIND_LIMIT];
static UINT32 binding_count;
static void packet_process_exit(PEPROCESS process);
#include "identity_cache.h"

static USHORT image_path_length(PCUNICODE_STRING path)
{
    if (!path || !path->Buffer || !path->Length || path->Length % sizeof(WCHAR) ||
        path->Length > AR_PATH_UNITS * sizeof(WCHAR) || path->MaximumLength < path->Length) return 0;
    for (UINT32 i = 0; i < path->Length / sizeof(WCHAR); i++) if (!path->Buffer[i]) return 0;
    return path->Length;
}

static AR_ORIGIN *origin_capture(PEPROCESS process, PFILE_OBJECT image, PCUNICODE_STRING path)
{
    if ((UINT32)InterlockedIncrement(&origin_count) > AR_ORIGIN_LIMIT) {
        InterlockedDecrement(&origin_count);
        return NULL;
    }
    USHORT length = image_path_length(path);
    AR_ORIGIN *origin = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*origin) + length, AR_POOL_TAG);
    if (!origin) { InterlockedDecrement(&origin_count); return NULL; }
    origin->references = 1;
    origin->origin_token = pv_next(&pv_origin);
    origin->provenance_state = origin->origin_token ? PV_UNREAD : PV_ID_EXHAUSTED;
    origin->process = process;
    ObReferenceObject(process);
    origin->token = PsReferencePrimaryToken(process);
    origin->path_length = length;
    if (length) RtlCopyMemory(origin->path, path->Buffer, length);
    if (image && image->DeviceObject && image->SectionObjectPointer) {
        origin->image = image;
        ObReferenceObject(image);
        BOOLEAN copied, effective;
        SECURITY_IMPERSONATION_LEVEL level;
        origin->opening_token = PsReferenceImpersonationToken(PsGetCurrentThread(), &copied, &effective, &level);
        origin->opening_impersonation = origin->opening_token != NULL;
        if (!origin->opening_token) origin->opening_token = PsReferencePrimaryToken(PsGetCurrentProcess());
    }
    return origin;
}

/* System существует до регистрации process notify. Его реальный process instance
   нужен для пакетов ядра и системных посредников, в том числе ICMP API. */
static NTSTATUS cache_seed_system(void)
{
    AR_PROCESS *record = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*record), AR_POOL_TAG);
    if (!record) return STATUS_INSUFFICIENT_RESOURCES;
    record->self = origin_capture(PsInitialSystemProcess, NULL, NULL);
    if (!record->self) { ExFreePoolWithTag(record, AR_POOL_TAG); return STATUS_INSUFFICIENT_RESOURCES; }
    InterlockedIncrement(&record_count);
    /* Вызывается один раз до установки process notify: таблица еще пуста. */
    InterlockedExchangePointer((PVOID volatile *)&processes[0], record);
    return STATUS_SUCCESS;
}

static void process_notify(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO info)
{
    UNREFERENCED_PARAMETER(pid);
    if (!info) {
        packet_process_exit(process);
        InterlockedIncrement(&readers);
        for (UINT32 i = 0; i < AR_PROCESS_LIMIT; i++) {
            AR_PROCESS *record = InterlockedCompareExchangePointer((PVOID volatile *)&processes[i], NULL, NULL);
            if (record && record->self->process == process &&
                InterlockedCompareExchangePointer((PVOID volatile *)&processes[i], NULL, record) == record) {
                record_retire(record);
                break;
            }
        }
        readers_leave();
        return;
    }
    if ((UINT32)InterlockedIncrement(&record_count) > AR_RECORD_LIMIT) {
        InterlockedDecrement(&record_count);
        return;
    }
    AR_PROCESS *record = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*record), AR_POOL_TAG);
    if (!record) { InterlockedDecrement(&record_count); return; }
    record->self = origin_capture(process, info->FileObject, info->FileOpenNameAvailable ? info->ImageFileName : NULL);
    if (!record->self) { record_retire(record); return; }
    InterlockedIncrement(&readers);
    AR_PROCESS *parent = process_find(PsGetCurrentProcess());
    /* Actual creator, а не подменяемый ParentProcessId. */
    if (parent && info->CreatingThreadId.UniqueProcess == PsGetCurrentProcessId()) {
        record->ancestry_truncated = parent->ancestry_truncated || parent->parent_count == AP_PARENT_LIMIT;
        record->parents[record->parent_count++] = parent->self;
        InterlockedIncrement(&parent->self->references);
        for (UINT32 i = 0; i < parent->parent_count && record->parent_count < AP_PARENT_LIMIT; i++) {
            record->parents[record->parent_count++] = parent->parents[i];
            InterlockedIncrement(&parent->parents[i]->references);
        }
    }
    readers_leave();
    if (!record->parent_count) {
        AR_ORIGIN *unknown = origin_capture(PsGetCurrentProcess(), NULL, NULL);
        if (!unknown) { record_retire(record); return; }
        record->parents[record->parent_count++] = unknown;
    }
    for (UINT32 i = 0; i < AR_PROCESS_LIMIT; i++)
        if (!InterlockedCompareExchangePointer((PVOID volatile *)&processes[i], record, NULL)) return;
    record_retire(record);
}

static NTSTATUS token_sid(PACCESS_TOKEN token, TOKEN_INFORMATION_CLASS kind, UCHAR *sid, UINT32 *length)
{
    PVOID information = NULL;
    NTSTATUS status = SeQueryInformationToken(token, kind, &information);
    if (!NT_SUCCESS(status)) return status;
    PSID actual = kind == TokenUser ? ((PTOKEN_USER)information)->User.Sid :
        ((PTOKEN_APPCONTAINER_INFORMATION)information)->TokenAppContainer;
    *length = 0;
    if (actual) {
        if (!RtlValidSid(actual) || RtlLengthSid(actual) > AR_SID_BYTES) status = STATUS_INVALID_SID;
        else { *length = RtlLengthSid(actual); RtlCopyMemory(sid, actual, *length); }
    }
    ExFreePool(information);
    return status;
}

static NTSTATUS query_file_identity(HANDLE handle, FILE_ID_INFORMATION *identity)
{
    IO_STATUS_BLOCK result = {0};
    NTSTATUS status = ZwQueryInformationFile(handle, &result, identity, sizeof(*identity), FileIdInformation);
    UCHAR empty[16] = {0};
    if (NT_SUCCESS(status) && (result.Information != sizeof(*identity) ||
        RtlCompareMemory(identity->FileId.Identifier, empty, sizeof(empty)) == sizeof(empty)))
        status = STATUS_NOT_SUPPORTED;
    return status;
}

static NTSTATUS file_identity(PFILE_OBJECT file, HANDLE *handle, FILE_ID_INFORMATION *identity)
{
    if (!(file->Flags & FO_HANDLE_CREATED) || !file->Vpb || !file->DeviceObject)
        return STATUS_NOT_SUPPORTED;
    NTSTATUS status = ObOpenObjectByPointer(file, OBJ_KERNEL_HANDLE, NULL,
        FILE_READ_ATTRIBUTES, *IoFileObjectType, KernelMode, handle);
    if (!NT_SUCCESS(status)) return status;
    status = query_file_identity(*handle, identity);
    if (!NT_SUCCESS(status)) { ZwClose(*handle); *handle = NULL; }
    return status;
}

typedef struct {
    HANDLE handle;
    PFILE_OBJECT file;
    FILE_ID_INFORMATION identity;
} AR_FILE_VIEW;

static void file_view_close(AR_FILE_VIEW *view)
{
    if (view->file) ObDereferenceObject(view->file);
    if (view->handle) ZwClose(view->handle);
}

static NTSTATUS file_view_open(const WCHAR *path, UINT32 units, AR_FILE_VIEW *view)
{
    UNICODE_STRING name = {(USHORT)(units * sizeof(WCHAR)), (USHORT)(units * sizeof(WCHAR)), (PWCHAR)path};
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | OBJ_FORCE_ACCESS_CHECK,
        NULL, NULL);
    IO_STATUS_BLOCK result = {0};
    NTSTATUS status = ZwCreateFile(&view->handle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes, &result,
        NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(status)) return status;
    status = ObReferenceObjectByHandle(view->handle, FILE_READ_ATTRIBUTES, *IoFileObjectType, KernelMode,
        (PVOID *)&view->file, NULL);
    if (!NT_SUCCESS(status)) return status;
    if (!view->file->Vpb || !view->file->DeviceObject) return STATUS_NOT_SUPPORTED;
    return query_file_identity(view->handle, &view->identity);
}

/* SOP идентифицирует stream. Оба FILE_OBJECT удерживаются до конца сравнения. */
static BOOLEAN same_stream(PFILE_OBJECT a, PFILE_OBJECT b)
{
    return a && b && a->DeviceObject && a->DeviceObject == b->DeviceObject &&
        a->SectionObjectPointer && a->SectionObjectPointer == b->SectionObjectPointer;
}

static void bindings_clear(void)
{
    for (UINT32 i = 0; i < binding_count; i++) {
        if (bindings[i].image) ObDereferenceObject(bindings[i].image);
        if (bindings[i].file) ZwClose(bindings[i].file);
        if (bindings[i].volume_device) ObDereferenceObject(bindings[i].volume_device);
    }
    RtlZeroMemory(bindings, sizeof(bindings));
    binding_count = 0;
}

static BOOLEAN bytes_zero(const UCHAR *bytes, UINT32 length)
{
    for (UINT32 i = 0; i < length; i++) if (bytes[i]) return FALSE;
    return TRUE;
}

static NTSTATUS bind_token(const AR_BIND *request, AR_BINDING *binding)
{
    if (request->path_units || !bytes_zero((const UCHAR *)request->path, sizeof(request->path)) ||
        request->sid_length < 8 || request->sid_length > AR_SID_BYTES ||
        !bytes_zero(request->sid + request->sid_length, AR_SID_BYTES - request->sid_length) ||
        request->sid[1] > 15 || 8u + 4u * request->sid[1] != request->sid_length ||
        !RtlValidSid((PSID)request->sid)) return STATUS_INVALID_PARAMETER;
    PACCESS_TOKEN token = NULL;
    NTSTATUS status = ObReferenceObjectByHandle((HANDLE)request->handle, TOKEN_QUERY,
        *SeTokenObjectType, UserMode, (PVOID *)&token, NULL);
    if (!NT_SUCCESS(status)) return status;
    status = token_sid(token, request->kind == AR_BIND_OWNER ? TokenUser : TokenAppContainerSid,
        binding->sid, &binding->sid_length);
    ObDereferenceObject(token);
    if (NT_SUCCESS(status) && (binding->sid_length != request->sid_length ||
        RtlCompareMemory(binding->sid, request->sid, request->sid_length) != request->sid_length))
        status = STATUS_INVALID_SID;
    return status;
}

static NTSTATUS bind_file(const AR_BIND *request, AR_BINDING *binding)
{
    if (request->sid_length || !bytes_zero(request->sid, AR_SID_BYTES)) return STATUS_INVALID_PARAMETER;
    if (!request->path_units || request->path_units > AR_PATH_UNITS ||
        !bytes_zero((const UCHAR *)(request->path + request->path_units),
            (AR_PATH_UNITS - request->path_units) * sizeof(WCHAR))) return STATUS_INVALID_PARAMETER;
    UNICODE_STRING name = {(USHORT)(request->path_units * sizeof(WCHAR)),
        (USHORT)(request->path_units * sizeof(WCHAR)), (PWSTR)request->path};
    UNICODE_STRING prefix = RTL_CONSTANT_STRING(L"\\Device\\");
    if (!image_path_length(&name) || !RtlPrefixUnicodeString(&prefix, &name, TRUE)) return STATUS_INVALID_PARAMETER;
    PFILE_OBJECT file = NULL;
    NTSTATUS status = ObReferenceObjectByHandle((HANDLE)request->handle, FILE_READ_DATA | FILE_READ_ATTRIBUTES,
        *IoFileObjectType, UserMode, (PVOID *)&file, NULL);
    if (!NT_SUCCESS(status)) return status;
    /* Запись в объект запрещена, rename/delete updater остаются доступны. */
    if (!file->ReadAccess || file->WriteAccess || file->DeleteAccess || file->SharedWrite || !file->SharedDelete)
        status = STATUS_INVALID_PARAMETER;
    else if (!file->SectionObjectPointer) status = STATUS_NOT_SUPPORTED;
    else status = file_identity(file, &binding->file, &binding->identity);
    if (NT_SUCCESS(status)) {
        binding->image = file;
        ObReferenceObject(file);
        binding->volume_device = file->DeviceObject;
        ObReferenceObject(binding->volume_device);
        binding->path_units = request->path_units;
        RtlCopyMemory(binding->path, request->path, name.Length);
        AR_FILE_VIEW target = {0};
        status = file_view_open(binding->path, binding->path_units, &target);
        if (NT_SUCCESS(status) && (!same_stream(target.file, binding->image))) status = STATUS_RETRY;
        file_view_close(&target);
    }
    ObDereferenceObject(file);
    return status;
}

static BOOLEAN same_binding(const AR_BINDING *a, const AR_BINDING *b)
{
    if (a->kind != b->kind) return FALSE;
    if (a->kind == AR_BIND_FILE) return same_stream(a->image, b->image);
    return a->sid_length == b->sid_length &&
        RtlCompareMemory(a->sid, b->sid, a->sid_length) == a->sid_length;
}

static BOOLEAN equal_path(const WCHAR *a, UINT32 a_units, const WCHAR *b, UINT32 b_units)
{
    UNICODE_STRING left = {(USHORT)(a_units * sizeof(WCHAR)), (USHORT)(a_units * sizeof(WCHAR)), (PWSTR)a};
    UNICODE_STRING right = {(USHORT)(b_units * sizeof(WCHAR)), (USHORT)(b_units * sizeof(WCHAR)), (PWSTR)b};
    return RtlEqualUnicodeString(&left, &right, TRUE);
}

static NTSTATUS binding_insert(AR_BINDING *binding)
{
    for (UINT32 i = 0; i < binding_count; i++) {
        BOOLEAN same = same_binding(&bindings[i], binding);
        if (bindings[i].slot == binding->slot || same) {
            BOOLEAN same_path = binding->kind != AR_BIND_FILE ||
                equal_path(bindings[i].path, bindings[i].path_units, binding->path, binding->path_units);
            return same && same_path && bindings[i].slot == binding->slot ? STATUS_SUCCESS : STATUS_OBJECT_NAME_COLLISION;
        }
    }
    if (binding_count == AR_BIND_LIMIT) return STATUS_INSUFFICIENT_RESOURCES;
    bindings[binding_count++] = *binding;
    binding->file = NULL;
    binding->image = NULL;
    binding->volume_device = NULL;
    return STATUS_SUCCESS;
}

static NTSTATUS bind_identity(const AR_BIND *request)
{
    if (!request->slot || !request->handle || request->reserved || request->tail_reserved ||
        request->path_reserved ||
        request->kind < AR_BIND_FILE || request->kind > AR_BIND_PACKAGE) return STATUS_INVALID_PARAMETER;
    AR_BINDING *binding = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*binding), AR_POOL_TAG);
    if (!binding) return STATUS_INSUFFICIENT_RESOURCES;
    binding->kind = request->kind;
    binding->slot = request->slot;
    NTSTATUS status = request->kind == AR_BIND_FILE ? bind_file(request, binding) : bind_token(request, binding);
    if (NT_SUCCESS(status)) status = binding_insert(binding);
    if (binding->image) ObDereferenceObject(binding->image);
    if (binding->file) ZwClose(binding->file);
    if (binding->volume_device) ObDereferenceObject(binding->volume_device);
    ExFreePoolWithTag(binding, AR_POOL_TAG);
    return status;
}

static UINT32 sid_slot(const AR_BINDING *bindings, UINT32 binding_count, const UCHAR *sid, UINT32 length, UINT32 kind)
{
    if (!length) return 0;
    for (UINT32 i = 0; i < binding_count; i++)
        if (bindings[i].kind == kind && bindings[i].sid_length == length &&
            RtlCompareMemory(bindings[i].sid, sid, length) == length) return bindings[i].slot;
    return 0;
}

static UINT32 file_slot(const AR_BINDING *bindings, UINT32 binding_count, PFILE_OBJECT image)
{
    for (UINT32 i = 0; i < binding_count; i++)
        if (bindings[i].kind == AR_BIND_FILE && same_stream(bindings[i].image, image)) return bindings[i].slot;
    return 0;
}

static BOOLEAN slot_bound(UINT32 slot, UINT32 kind)
{
    for (UINT32 i = 0; i < binding_count; i++)
        if (bindings[i].slot == slot && bindings[i].kind == kind) return TRUE;
    return FALSE;
}

static BOOLEAN policy_bound(const struct ap_policy *value)
{
    if (value->owner_kind == 2 && !slot_bound(value->owner, AR_BIND_OWNER)) return FALSE;
    for (UINT32 i = 0; i < value->count; i++) {
        UINT32 selector = value->rules[i].selector;
        if (selector && !slot_bound(value->rules[i].application,
            selector == 1 ? AR_BIND_FILE : AR_BIND_PACKAGE)) return FALSE;
    }
    return TRUE;
}

static BOOLEAN file_selected(const struct ap_policy *value, UINT32 slot)
{
    for (UINT32 i = 0; i < value->count; i++)
        if (value->rules[i].selector == 1 && value->rules[i].application == slot) return TRUE;
    return FALSE;
}

typedef struct { UINT32 units; WCHAR path[AR_PATH_UNITS]; } AR_OPENED_NAME;

/* Вызывается только под session mutex при PASSIVE_LEVEL. Результат terminal для origin. */
static BOOLEAN opened_name(AR_ORIGIN *source, AR_OPENED_NAME *out)
{
    if (source->provenance_state == PV_UNREAD)
        source->provenance_state = provenance_get_copy(source->image, source->origin_token, &source->provenance);
    if (source->provenance_state != PV_CAPTURED_EXACT_FO || !source->provenance) return FALSE;
    out->units = source->provenance->info.units;
    RtlCopyMemory(out->path, source->provenance->name, out->units * sizeof(WCHAR));
    return TRUE;
}

static BOOLEAN negative_path(AR_ORIGIN *source, const AR_OPENED_NAME *name,
    const struct ap_policy *value, UINT64 session, const AR_BINDING *bindings, UINT32 binding_count)
{
    if (source->marker_session != session) {
        RtlZeroMemory(source->negative, sizeof(source->negative));
        source->marker_session = session;
    }
    for (UINT32 i = 0; i < binding_count; i++) {
        const AR_BINDING *binding = &bindings[i];
        if (binding->kind != AR_BIND_FILE) continue;
        if (same_stream(source->image, binding->image)) continue;
        UINT32 bit = 1u << (i % 32u);
        BOOLEAN changed = (source->negative[i / 32u] & bit) != 0 ||
            equal_path(name->path, name->units, binding->path, binding->path_units);
        if (!changed) {
            AR_FILE_VIEW target = {0};
            NTSTATUS status = file_view_open(binding->path, binding->path_units, &target);
            changed = NT_SUCCESS(status) && same_stream(source->image, target.file);
            file_view_close(&target);
        }
        if (changed) {
            /* Факт относится к binding, даже если текущая policy его не выбирает. */
            source->negative[i / 32u] |= bit;
        }
    }
    /* Текущая policy влияет только на результат, не на сохранение наблюдений. */
    for (UINT32 i = 0; i < binding_count; i++)
        if ((source->negative[i / 32u] & (1u << (i % 32u))) && file_selected(value, bindings[i].slot)) return TRUE;
    return FALSE;
}

static NTSTATUS resolve_origin_in(AR_ORIGIN *source, struct ap_origin *origin, AR_DIAGNOSTIC *details,
    const struct ap_policy *value, UINT64 session, const AR_BINDING *bindings, UINT32 binding_count)
{
    UCHAR user[AR_SID_BYTES] = {0}, package[AR_SID_BYTES] = {0};
    UINT32 user_length = 0, package_length = 0;
    NTSTATUS status = token_sid(source->token, TokenUser, user, &user_length);
    if (!NT_SUCCESS(status) || !user_length) return STATUS_INVALID_SID;
    status = token_sid(source->token, TokenAppContainerSid, package, &package_length);
    if (!NT_SUCCESS(status)) return status;
    origin->owner_kind = 2;
    origin->owner = sid_slot(bindings, binding_count, user, user_length, AR_BIND_OWNER);
    origin->package = sid_slot(bindings, binding_count, package, package_length, AR_BIND_PACKAGE);
    /* Объект корневого процесса дает ядро. У него нет пользовательского образа
     * и предков приложения; подменяемый ParentProcessId здесь не используется. */
    origin->resolved = source->process == PsInitialSystemProcess;
    FILE_ID_INFORMATION image = {0};
    HANDLE handle = NULL;
    BOOLEAN available = source->image && source->image->DeviceObject && source->image->SectionObjectPointer;
    if (available) {
        origin->application = file_slot(bindings, binding_count, source->image);
        /* FileID - только метаданные. Cleanup образа может уже запретить новый handle. */
        for (UINT32 i = 0; i < binding_count; i++)
            if (bindings[i].kind == AR_BIND_FILE && same_stream(source->image, bindings[i].image)) {
                image = bindings[i].identity;
                break;
            }
        if (!origin->application) {
            if (NT_SUCCESS(file_identity(source->image, &handle, &image))) ZwClose(handle);
            else RtlZeroMemory(&image, sizeof(image));
        }
        AR_OPENED_NAME *name = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*name), AR_POOL_TAG);
        if (name) {
            origin->resolved = opened_name(source, name) && !negative_path(source, name, value, session, bindings, binding_count);
            ExFreePoolWithTag(name, AR_POOL_TAG);
        }
    }
    if (details) {
        details->created = PsGetProcessCreateTimeQuadPart(source->process);
        details->image_available = available ? 1 : 0;
        details->path_available = source->path_length ? 1 : 0;
        details->image = image;
        details->user_length = user_length;
        details->package_length = package_length;
        RtlCopyMemory(details->user, user, user_length);
        RtlCopyMemory(details->package, package, package_length);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS resolve_origin(AR_ORIGIN *source, struct ap_origin *origin, AR_DIAGNOSTIC *details,
    const struct ap_policy *value, UINT64 session)
{
    return resolve_origin_in(source, origin, details, value, session, bindings, binding_count);
}

static NTSTATUS process_snapshot(PEPROCESS process, AR_PROCESS *record)
{
    InterlockedIncrement(&readers);
    AR_PROCESS *found = process_find(process);
    if (found) process_copy(record, found);
    readers_leave();
    if (!record->self) record->self = origin_capture(process, NULL, NULL);
    return record->self ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

static void diagnostic_destination(const AR_DIAGNOSE *request, struct ap_context *context)
{
    context->family = request->family;
    RtlCopyMemory(context->destination, request->destination, 16);
    if (request->family == 6 && bytes_zero(request->destination, 10) &&
        request->destination[10] == 0xff && request->destination[11] == 0xff) {
        context->family = 4;
        RtlZeroMemory(context->destination, 16);
        RtlCopyMemory(context->destination, request->destination + 12, 4);
    }
}

static NTSTATUS process_running(PEPROCESS process)
{
    HANDLE handle = NULL;
    NTSTATUS status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL, SYNCHRONIZE,
        *PsProcessType, KernelMode, &handle);
    if (!NT_SUCCESS(status)) return status;
    LARGE_INTEGER now = {0};
    status = ZwWaitForSingleObject(handle, FALSE, &now);
    ZwClose(handle);
    /* Exit code 259 допустим у завершенного процесса и не заменяет состояние объекта. */
    return status == STATUS_TIMEOUT ? STATUS_SUCCESS : STATUS_PROCESS_IS_TERMINATING;
}

/* Неизвестный хвост важен лишь до первого доказанного совпадения или смены владельца. */
static struct ap_decision evaluate_identity(const struct ap_policy *value,
    const struct ap_context *context, BOOLEAN truncated)
{
    struct ap_decision decision = ap_evaluate(value, context);
    if (!truncated || decision.unresolved || !ap_requires_identity(value, context, 1)) return decision;
    if (value->owner_kind != 3 && (value->owner_kind != context->process.owner_kind ||
        value->owner != context->process.owner)) return decision;
    if (ap_origin_matches(value, context, &context->process, 0)) return decision;
    for (UINT32 i = 0; i < context->parent_count; i++) {
        if (!ap_same_owner(&context->parents[i], &context->process)) return decision;
        if (ap_origin_matches(value, context, &context->parents[i], i + 1)) return decision;
    }
    RtlZeroMemory(&decision, sizeof(decision));
    decision.action = 1;
    decision.rule = AP_NO_RULE;
    decision.unresolved = 1;
    decision.generation = value->generation;
    return decision;
}

static NTSTATUS diagnose(const AR_DIAGNOSE *request, const struct ap_policy *value, UINT64 session, AR_DIAGNOSTIC *output)
{
    if (request->reserved || (request->family != 4 && request->family != 6) ||
        (request->family == 4 && !bytes_zero(request->destination + 4, 12))) return STATUS_INVALID_PARAMETER;
    if (!policy_bound(value)) return STATUS_DEVICE_NOT_READY;
    PEPROCESS process = NULL;
    NTSTATUS status = ObReferenceObjectByHandle((HANDLE)request->process_handle,
        AR_PROCESS_QUERY, *PsProcessType, UserMode, (PVOID *)&process, NULL);
    if (!NT_SUCCESS(status)) return status;
    status = process_running(process);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        return status;
    }
    AR_PROCESS record = {0};
    status = process_snapshot(process, &record);
    ObDereferenceObject(process);
    if (!NT_SUCCESS(status)) return status;
    struct ap_context context = {0};
    diagnostic_destination(request, &context);
    status = resolve_origin(record.self, &context.process, output, value, session);
    for (UINT32 i = 0; NT_SUCCESS(status) && i < record.parent_count; i++) {
        AR_DIAGNOSTIC parent = {0};
        status = resolve_origin(record.parents[i], &context.parents[i], &parent, value, session);
        if (NT_SUCCESS(status) && (parent.user_length != output->user_length ||
            RtlCompareMemory(parent.user, output->user, output->user_length) != output->user_length)) break;
        context.parent_count++;
    }
    if (NT_SUCCESS(status)) {
        output->header.version = AR_ABI_VERSION;
        output->header.size = sizeof(*output);
        output->header.session = session;
        output->origin = context.process;
        output->parent_count = context.parent_count;
        struct ap_decision decision = evaluate_identity(value, &context,
            record.ancestry_truncated && context.parent_count == record.parent_count);
        /* Padding shared struct не копируется в пользовательский ответ. */
        output->decision.action = decision.action;
        output->decision.profile = decision.profile;
        output->decision.rule = decision.rule;
        output->decision.depth = decision.depth;
        output->decision.unresolved = decision.unresolved;
        output->decision.generation = decision.generation;
        /* Диагностика не имеет готового packet worker. VPN всегда остается BLOCK. */
        if (output->decision.action == 2) output->decision.action = 1;
    }
    process_release(&record);
    return status;
}
