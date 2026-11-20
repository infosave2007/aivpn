#define INITGUID
#include <fltKernel.h>
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <wdmsec.h>
#include "protocol.h"
#include "lab.h"
#include "../linux/kernel-policy/validate.h"
#include "provenance.h"

DEFINE_GUID(AR_DEVICE_CLASS, 0x9a8c093a, 0x4713, 0x4348, 0xb1, 0xc2, 0xc9, 0x69, 0xf1, 0x9f, 0x06, 0x26);

static PDEVICE_OBJECT device;
static KMUTEX mutex;
static PFILE_OBJECT owner_file;
static PEPROCESS owner_process;
static UINT64 session_id;
static BOOLEAN staged;
static struct ap_policy policy;
static KSPIN_LOCK lifecycle_lock;
static EX_RUNDOWN_REF dispatch_rundown;
static ULONG cdo_open_refs;
static BOOLEAN admission, linked, notify_registered, cache_started, packet_started;
static UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\AivpnAppRouting");
static UNICODE_STRING link_name = RTL_CONSTANT_STRING(L"\\DosDevices\\AivpnAppRouting");

static void session_lock(void)
{
    KeWaitForSingleObject(&mutex, Executive, KernelMode, FALSE, NULL);
}

static void session_unlock(void)
{
    KeReleaseMutex(&mutex, FALSE);
}

#include "identity.h"
#include "runtime_snapshot.h"
#include "packet_identity.h"
#include "packet_channel.h"

static NTSTATUS complete(PIRP irp, NTSTATUS status, ULONG_PTR bytes)
{
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = NT_SUCCESS(status) ? bytes : 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static BOOLEAN no_impersonation(void)
{
    BOOLEAN copied, effective;
    SECURITY_IMPERSONATION_LEVEL level;
    PACCESS_TOKEN token = PsReferenceImpersonationToken(PsGetCurrentThread(), &copied, &effective, &level);
    if (!token) return TRUE;
    PsDereferenceImpersonationToken(token);
    return FALSE;
}

static BOOLEAN service_session(void)
{
    HANDLE token;
    NTSTATUS status = ZwOpenProcessTokenEx(NtCurrentProcess(), TOKEN_QUERY, OBJ_KERNEL_HANDLE, &token);
    if (!NT_SUCCESS(status)) return FALSE;
    ULONG session = MAXULONG, returned = 0;
    status = ZwQueryInformationToken(token, TokenSessionId, &session, sizeof(session), &returned);
    ZwClose(token);
    return NT_SUCCESS(status) && returned == sizeof(session) && session == 0;
}

static BOOLEAN system_token(PACCESS_TOKEN token)
{
    PTOKEN_USER user = NULL;
    NTSTATUS status = SeQueryInformationToken(token, TokenUser, (PVOID *)&user);
    if (!NT_SUCCESS(status)) return FALSE;
    BOOLEAN allowed = RtlEqualSid(user->User.Sid, SeExports->SeLocalSystemSid);
    ExFreePool(user);
    if (!allowed || SeTokenIsRestricted(token)) return FALSE;
    PTOKEN_GROUPS groups = NULL;
    status = SeQueryInformationToken(token, TokenGroups, (PVOID *)&groups);
    if (!NT_SUCCESS(status)) return FALSE;
    for (ULONG index = 0; index < groups->GroupCount; index++) {
        if (RtlEqualSid(groups->Groups[index].Sid, SeExports->SeInteractiveSid)) allowed = FALSE;
    }
    ExFreePool(groups);
    return allowed;
}

static BOOLEAN trusted_caller(PIRP irp)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || irp->RequestorMode != UserMode || IoGetRequestorProcess(irp) != PsGetCurrentProcess() ||
        !no_impersonation() || !service_session()) return FALSE;
    PACCESS_TOKEN token = PsReferencePrimaryToken(PsGetCurrentProcess());
    BOOLEAN allowed = system_token(token);
    PsDereferencePrimaryToken(token);
    return allowed;
}

static NTSTATUS open_session(PIRP irp, PIO_STACK_LOCATION stack)
{
    if (stack->FileObject->FileName.Length || !trusted_caller(irp)) return STATUS_ACCESS_DENIED;
    NTSTATUS status = STATUS_SUCCESS;
    session_lock();
    KIRQL previous;
    KeAcquireSpinLock(&lifecycle_lock, &previous);
    if (!admission) status = STATUS_DELETE_PENDING;
    else if (owner_file) status = STATUS_SHARING_VIOLATION;
    else if (session_id == MAXUINT64) status = STATUS_INTEGER_OVERFLOW;
    KeReleaseSpinLock(&lifecycle_lock, previous);
    /* Захват создается до SCM, а TCP/IP нужен только проверенной службе.
     * Mutex не позволяет двум открытиям одновременно создавать packet runtime. */
    if (NT_SUCCESS(status) && !packet_started) {
        InterlockedExchange(&pc_stopping, 0);
        pa_stopping = FALSE;
        status = pc_start();
        if (NT_SUCCESS(status)) packet_started = TRUE;
        else pc_stop();
    }
    KeAcquireSpinLock(&lifecycle_lock, &previous);
    if (NT_SUCCESS(status) && !admission) status = STATUS_DELETE_PENDING;
    if (NT_SUCCESS(status)) {
        session_id++;
        owner_file = stack->FileObject;
        owner_process = PsGetCurrentProcess();
        ObReferenceObject(owner_process);
        cdo_open_refs++;
        stack->FileObject->FsContext = device;
        staged = FALSE;
        RtlZeroMemory(&policy, sizeof(policy));
    }
    KeReleaseSpinLock(&lifecycle_lock, previous);
    session_unlock();
    return status;
}

static void cleanup_session(PFILE_OBJECT file)
{
    PEPROCESS process = NULL;
    session_lock();
    if (owner_file == file) {
        pc_disconnect();
        rs_abort();
        owner_file = NULL;
        process = owner_process;
        owner_process = NULL;
        staged = FALSE;
        RtlSecureZeroMemory(&policy, sizeof(policy));
        bindings_clear();
    }
    session_unlock();
    if (process) ObDereferenceObject(process);
}

static BOOLEAN valid_request(const AR_REQUEST *header, ULONG size)
{
    return header->version == AR_ABI_VERSION && header->size == size &&
        header->flags == 0 && header->reserved == 0;
}

static NTSTATUS stage_policy(const AR_STAGE *request)
{
    if (!ap_policy_valid(&request->policy, 2)) return STATUS_INVALID_PARAMETER;
    if (staged && request->policy.generation < policy.generation) return STATUS_REVISION_MISMATCH;
    if (staged && request->policy.generation == policy.generation &&
        RtlCompareMemory(&request->policy, &policy, sizeof(policy)) != sizeof(policy))
        return STATUS_REVISION_MISMATCH;
    policy = request->policy;
    staged = TRUE;
    return STATUS_SUCCESS;
}

static void write_status(PVOID buffer)
{
    AR_STATUS output = {0};
    output.header.version = AR_ABI_VERSION;
    output.header.size = sizeof(output);
    output.header.session = session_id;
    output.generation = staged ? policy.generation : 0;
    output.staged = staged ? 1 : 0;
    output.capabilities = AR_CAP_POLICY_STAGING;
    /* Наличие policy не означает, что WFP, packet worker или DNS активны. */
    RtlCopyMemory(buffer, &output, sizeof(output));
}

static NTSTATUS control(PIRP irp, PIO_STACK_LOCATION stack, ULONG_PTR *returned)
{
    *returned = 0;
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG input = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG output = stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG expected, result_size = sizeof(AR_STATUS);
    switch (code) {
#ifdef AIVPN_LAB
    case AR_IOCTL_LAB_BARRIER: expected = sizeof(AR_LAB_BARRIER); break;
    case AR_IOCTL_LAB: expected = sizeof(AR_REQUEST); result_size = AR_LAB_WORDS * sizeof(UINT32); break;
#endif
    case AR_IOCTL_QUERY: expected = sizeof(AR_REQUEST); break;
    case AR_IOCTL_STAGE: expected = sizeof(AR_STAGE); break;
    case AR_IOCTL_BIND: expected = sizeof(AR_BIND); break;
    case AR_IOCTL_PREPARE: expected = sizeof(AR_DIAGNOSE); break;
    case AR_IOCTL_TRANSPORT: expected = sizeof(AR_TRANSPORT); break;
    case AR_IOCTL_PROFILE_TRANSPORT: expected = sizeof(AR_PROFILE_TRANSPORT); break;
    case AR_IOCTL_PROFILE_TRANSPORT_QUERY: expected = sizeof(AR_PROFILE_REQUEST); result_size = sizeof(AR_PROFILE_TRANSPORT_RECEIPT); break;
    case AR_IOCTL_TRANSPORT_QUERY: expected = sizeof(AR_REQUEST); result_size = sizeof(AR_TRANSPORT_RECEIPT); break;
    case AR_IOCTL_DIAGNOSE: expected = sizeof(AR_DIAGNOSE); result_size = sizeof(AR_DIAGNOSTIC); break;
    case AR_IOCTL_RUNTIME_BEGIN: expected = sizeof(AR_RUNTIME_BEGIN); result_size = sizeof(AR_RUNTIME_RECEIPT); break;
    case AR_IOCTL_RUNTIME_POLICY: expected = sizeof(AR_RUNTIME_POLICY); result_size = sizeof(AR_RUNTIME_RECEIPT); break;
    case AR_IOCTL_RUNTIME_SID: expected = sizeof(AR_RUNTIME_SID); result_size = sizeof(AR_RUNTIME_RECEIPT); break;
    case AR_IOCTL_RUNTIME_CLAIM: expected = sizeof(AR_RUNTIME_CLAIM); result_size = sizeof(AR_RUNTIME_RECEIPT); break;
    case AR_IOCTL_RUNTIME_SEAL: expected = sizeof(AR_RUNTIME_SEAL); result_size = sizeof(AR_RUNTIME_RECEIPT); break;
    case AR_IOCTL_DNS: expected = sizeof(AR_DNS); break;
    default: return STATUS_INVALID_DEVICE_REQUEST;
    }
    if (input != expected || output != result_size || !irp->AssociatedIrp.SystemBuffer)
        return STATUS_INVALID_BUFFER_SIZE;
    const AR_REQUEST *header = irp->AssociatedIrp.SystemBuffer;
    if (!valid_request(header, expected)) return STATUS_INVALID_PARAMETER;
    if (!trusted_caller(irp)) return STATUS_ACCESS_DENIED;
    NTSTATUS status = IoValidateDeviceIoControlAccess(irp, FILE_READ_DATA | FILE_WRITE_DATA);
    if (!NT_SUCCESS(status)) return status;
    session_lock();
    UINT32 verified_group = 0;
    UINT32 runtime_flags = 0;
    UINT64 verified_claim = 0;
    BOOLEAN runtime = code >= AR_IOCTL_RUNTIME_BEGIN && code <= AR_IOCTL_RUNTIME_SEAL;
    BOOLEAN runtime_authorized = runtime && !irp->Cancel && owner_file == stack->FileObject &&
        owner_process == PsGetCurrentProcess() && header->session == session_id;
    if (irp->Cancel) status = STATUS_CANCELLED;
    else if (owner_file != stack->FileObject || owner_process != PsGetCurrentProcess())
        status = STATUS_ACCESS_DENIED;
    else if (header->session != session_id && !(code == AR_IOCTL_QUERY && header->session == 0))
        status = STATUS_INVALID_HANDLE;
    #ifdef AIVPN_LAB
    else if (code == AR_IOCTL_LAB_BARRIER) status = pc_lab_arm(irp->AssociatedIrp.SystemBuffer);
#endif
    else if (code == AR_IOCTL_STAGE) status = stage_policy(irp->AssociatedIrp.SystemBuffer);
    else if (code == AR_IOCTL_BIND) status = bind_identity(irp->AssociatedIrp.SystemBuffer);
    else if (code == AR_IOCTL_PREPARE) status = packet_prepare(irp->AssociatedIrp.SystemBuffer);
    else if (code == AR_IOCTL_TRANSPORT) status = pt_control(irp->AssociatedIrp.SystemBuffer, 0);
    else if (code == AR_IOCTL_PROFILE_TRANSPORT) {
        const AR_PROFILE_TRANSPORT *request = irp->AssociatedIrp.SystemBuffer;
        status = !request->profile || request->profile == PC_ANY_PROFILE || request->reserved ?
            STATUS_INVALID_PARAMETER : pt_control(&request->transport, request->profile);
    }
    else if (code == AR_IOCTL_PROFILE_TRANSPORT_QUERY) {
        const AR_PROFILE_REQUEST *request = irp->AssociatedIrp.SystemBuffer;
        if (!request->profile || request->profile == PC_ANY_PROFILE || request->reserved) status = STATUS_INVALID_PARAMETER;
        else {
            AR_PROFILE_TRANSPORT_RECEIPT receipt = {0};
            pt_receipt(request->profile, &receipt.transport);
            receipt.transport.version = 2; receipt.transport.size = sizeof(receipt);
            receipt.profile = request->profile;
            RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &receipt, sizeof(receipt));
        }
    }
    else if (code == AR_IOCTL_TRANSPORT_QUERY) pt_receipt(0, irp->AssociatedIrp.SystemBuffer);
    else if (code == AR_IOCTL_DNS) status = pd_control(irp->AssociatedIrp.SystemBuffer);
    else if (code == AR_IOCTL_RUNTIME_BEGIN) status = rs_begin(irp->AssociatedIrp.SystemBuffer);
    else if (code == AR_IOCTL_RUNTIME_POLICY) {
        status = rs_policy(irp->AssociatedIrp.SystemBuffer);
        if (NT_SUCCESS(status) && rs_pending->policies[rs_pending->count - 1].carried) runtime_flags = 1;
    }
    else if (code == AR_IOCTL_RUNTIME_SID) status = rs_sid(irp->AssociatedIrp.SystemBuffer);
    else if (code == AR_IOCTL_RUNTIME_CLAIM) status = rs_claim(irp->AssociatedIrp.SystemBuffer, &verified_group, &verified_claim);
    else if (code == AR_IOCTL_RUNTIME_SEAL) status = rs_seal(irp->AssociatedIrp.SystemBuffer);
    else if (code == AR_IOCTL_DIAGNOSE) {
        AR_DIAGNOSTIC result = {0};
        status = staged ? diagnose(irp->AssociatedIrp.SystemBuffer, &policy, session_id, &result) :
            STATUS_DEVICE_NOT_READY;
        if (NT_SUCCESS(status)) RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &result, sizeof(result));
    }
#ifdef AIVPN_LAB
    if (NT_SUCCESS(status) && code == AR_IOCTL_LAB) {
        for (ULONG i = 0; i < AR_LAB_WORDS; i++)
            ((UINT32 *)irp->AssociatedIrp.SystemBuffer)[i] = (UINT32)InterlockedCompareExchange(&ar_lab[i], 0, 0);
    } else
#endif
    if (runtime) {
        if (NT_SUCCESS(status)) rs_receipt(irp->AssociatedIrp.SystemBuffer, verified_group, verified_claim, runtime_flags);
        else if (runtime_authorized && status != STATUS_REVISION_MISMATCH) rs_abort();
    } else if (NT_SUCCESS(status) && code != AR_IOCTL_DIAGNOSE && code != AR_IOCTL_TRANSPORT_QUERY && code != AR_IOCTL_PROFILE_TRANSPORT_QUERY) write_status(irp->AssociatedIrp.SystemBuffer);
    session_unlock();
    if (NT_SUCCESS(status)) *returned = result_size;
    return status;
}

static NTSTATUS dispatch(PDEVICE_OBJECT object, PIRP irp)
{
    UNREFERENCED_PARAMETER(object);
    if (!ExAcquireRundownProtection(&dispatch_rundown)) return complete(irp, STATUS_DELETE_PENDING, 0);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR bytes = 0;
    switch (stack->MajorFunction) {
    case IRP_MJ_CREATE:
        status = open_session(irp, stack);
        break;
    case IRP_MJ_CLEANUP:
        cleanup_session(stack->FileObject);
        status = STATUS_SUCCESS;
        break;
    case IRP_MJ_CLOSE:
        {
            KIRQL previous;
            KeAcquireSpinLock(&lifecycle_lock, &previous);
            if (stack->FileObject->FsContext) {
                stack->FileObject->FsContext = NULL;
                NT_ASSERT(cdo_open_refs);
                cdo_open_refs--;
            }
            KeReleaseSpinLock(&lifecycle_lock, previous);
        }
        status = STATUS_SUCCESS;
        break;
    case IRP_MJ_DEVICE_CONTROL:
        if (stack->Parameters.DeviceIoControl.IoControlCode == AR_PACKET_IOCTL_CONFIG ||
            stack->Parameters.DeviceIoControl.IoControlCode == AR_PACKET_IOCTL_BLOCK ||
            stack->Parameters.DeviceIoControl.IoControlCode == AR_PACKET_IOCTL_POP ||
            stack->Parameters.DeviceIoControl.IoControlCode == AR_PACKET_IOCTL_SEND ||
            stack->Parameters.DeviceIoControl.IoControlCode == AR_PACKET_IOCTL_STATS ||
            stack->Parameters.DeviceIoControl.IoControlCode == AR_PACKET_IOCTL_POP_PROFILE ||
            stack->Parameters.DeviceIoControl.IoControlCode == AR_PACKET_IOCTL_SEND_PROFILE ||
            stack->Parameters.DeviceIoControl.IoControlCode == AR_PACKET_IOCTL_BLOCK_PROFILE) {
            if (!trusted_caller(irp)) { status = STATUS_ACCESS_DENIED; break; }
            session_lock();
            status = owner_file == stack->FileObject && owner_process == PsGetCurrentProcess() ?
                pc_control(irp, stack, &bytes) : STATUS_ACCESS_DENIED;
            session_unlock();
            break;
        }
        status = control(irp, stack, &bytes);
        break;
    default:
        break;
    }
    complete(irp, status, bytes);
    ExReleaseRundownProtection(&dispatch_rundown);
    return status;
}

static void driver_stop(void)
{
    KIRQL previous;
    KeAcquireSpinLock(&lifecycle_lock, &previous);
    admission = FALSE;
    KeReleaseSpinLock(&lifecycle_lock, previous);
    KeAcquireSpinLock(&pv_lock, &previous);
    pv_stopping = TRUE;
    KeReleaseSpinLock(&pv_lock, previous);
    if (linked) { IoDeleteSymbolicLink(&link_name); linked = FALSE; }
    if (notify_registered) { PsSetCreateProcessNotifyRoutineEx(process_notify, TRUE); notify_registered = FALSE; }
    ExWaitForRundownProtectionRelease(&dispatch_rundown);
    pc_stop();
    packet_started = FALSE;
    packet_identity_clear();
    rs_abort(); rs_release(rs_current); rs_current = NULL;
    PEPROCESS process = owner_process;
    owner_process = NULL;
    owner_file = NULL;
    staged = FALSE;
    RtlSecureZeroMemory(&policy, sizeof(policy));
    bindings_clear();
    if (process) ObDereferenceObject(process);
    if (pv_filter) { FltUnregisterFilter(pv_filter); pv_filter = NULL; }
    if (cache_started) { cache_stop(); cache_started = FALSE; }
    if (device) { IoDeleteDevice(device); device = NULL; }
}

static NTSTATUS FLTAPI filter_unload(FLT_FILTER_UNLOAD_FLAGS flags)
{
    /* SERVICE_STOP запрещен registration flag до входа в этот callback. */
    if (flags & FLTFL_FILTER_UNLOAD_MANDATORY) return STATUS_FLT_DO_NOT_DETACH;
    KIRQL previous;
    KeAcquireSpinLock(&lifecycle_lock, &previous);
    if (cdo_open_refs || pc_armed || !admission) {
        KeReleaseSpinLock(&lifecycle_lock, previous);
        return STATUS_FLT_DO_NOT_DETACH;
    }
    admission = FALSE;
    KeReleaseSpinLock(&lifecycle_lock, previous);
    driver_stop();
    return STATUS_SUCCESS;
}

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry_path)
{
    UNREFERENCED_PARAMETER(registry_path);
    KeInitializeMutex(&mutex, 0);
    KeInitializeSpinLock(&lifecycle_lock);
    KeInitializeSpinLock(&pv_lock);
    KeInitializeSpinLock(&pi_lock);
    KeInitializeSpinLock(&pc_state_lock);
    KeInitializeSpinLock(&pc_assembly_lock);
    InitializeListHead(&pc_packets);
    ExInitializeRundownProtection(&dispatch_rundown);
    pv_epoch = KeQueryInterruptTime();
    if (!pv_epoch) return STATUS_INTEGER_OVERFLOW;
    NTSTATUS status = cache_start();
    if (!NT_SUCCESS(status)) return status;
    cache_started = TRUE;
    status = cache_seed_system();
    if (!NT_SUCCESS(status)) { driver_stop(); return status; }
    status = FltRegisterFilter(driver, &pv_registration, &pv_filter);
    if (!NT_SUCCESS(status)) { driver_stop(); return status; }
    status = IoCreateDeviceSecure(driver, 0, &device_name, FILE_DEVICE_NETWORK,
        FILE_DEVICE_SECURE_OPEN, FALSE, &SDDL_DEVOBJ_SYS_ALL, &AR_DEVICE_CLASS, &device);
    if (!NT_SUCCESS(status)) { driver_stop(); return status; }
    for (ULONG index = 0; index <= IRP_MJ_MAXIMUM_FUNCTION; index++) driver->MajorFunction[index] = dispatch;
    status = IoCreateSymbolicLink(&link_name, &device_name);
    if (!NT_SUCCESS(status)) { driver_stop(); return status; }
    linked = TRUE;
    status = PsSetCreateProcessNotifyRoutineEx(process_notify, FALSE);
    if (!NT_SUCCESS(status)) { driver_stop(); return status; }
    notify_registered = TRUE;
    status = FltStartFiltering(pv_filter);
    if (!NT_SUCCESS(status)) { driver_stop(); return status; }
    admission = TRUE;
    device->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
