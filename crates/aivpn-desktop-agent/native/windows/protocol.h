#pragma once
#include "../linux/kernel-policy/schema.h"

#define AR_ABI_VERSION 1u
#define AR_IOCTL_QUERY CTL_CODE(FILE_DEVICE_NETWORK, 0x900, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define AR_IOCTL_STAGE CTL_CODE(FILE_DEVICE_NETWORK, 0x901, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define AR_CAP_POLICY_STAGING 1u
#define AR_IOCTL_BIND CTL_CODE(FILE_DEVICE_NETWORK, 0x902, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define AR_IOCTL_DIAGNOSE CTL_CODE(FILE_DEVICE_NETWORK, 0x903, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define AR_IOCTL_PREPARE CTL_CODE(FILE_DEVICE_NETWORK, 0x904, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define AR_IOCTL_TRANSPORT CTL_CODE(FILE_DEVICE_NETWORK, 0x905, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define AR_IOCTL_TRANSPORT_QUERY CTL_CODE(FILE_DEVICE_NETWORK, 0x906, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define AR_IOCTL_RUNTIME_BEGIN CTL_CODE(FILE_DEVICE_NETWORK, 0x907, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define AR_IOCTL_RUNTIME_POLICY CTL_CODE(FILE_DEVICE_NETWORK, 0x908, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define AR_IOCTL_RUNTIME_SID CTL_CODE(FILE_DEVICE_NETWORK, 0x909, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define AR_IOCTL_RUNTIME_CLAIM CTL_CODE(FILE_DEVICE_NETWORK, 0x90a, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define AR_IOCTL_RUNTIME_SEAL CTL_CODE(FILE_DEVICE_NETWORK, 0x90b, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define AR_IOCTL_DNS CTL_CODE(FILE_DEVICE_NETWORK, 0x90c, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define AR_IOCTL_PROFILE_TRANSPORT CTL_CODE(FILE_DEVICE_NETWORK, 0x90d, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define AR_IOCTL_PROFILE_TRANSPORT_QUERY CTL_CODE(FILE_DEVICE_NETWORK, 0x90e, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define AR_SID_BYTES 68u
#define AR_BIND_FILE 1u
#define AR_BIND_OWNER 2u
#define AR_BIND_PACKAGE 3u
#define AR_PATH_UNITS 4096u

/* Размеры фиксированы; указателей в сообщениях нет, handles и padding проверяются явно. */
typedef struct {
    UINT32 version, size;
    UINT64 session;
    UINT32 flags, reserved;
} AR_REQUEST;

/* DNS upstream получает VPN capability отдельно от физического transport. */
typedef struct {
    AR_REQUEST header;
    UINT64 generation, epoch, endpoint;
    UINT32 operation, compartment, profile, family, protocol;
    UINT16 port, reserved;
    UCHAR peer[16];
} AR_DNS;
C_ASSERT(sizeof(AR_DNS) == 88);

typedef struct {
    AR_REQUEST header;
    UINT64 generation;
    UINT32 staged, capabilities, enforcement, reserved;
} AR_STATUS;

typedef struct {
    AR_REQUEST header;
    struct ap_policy policy;
} AR_STAGE;

/* Схема runtime не меняет прежний staging ABI. BEGIN создает отдельную копию,
 * SEAL проверяет полноту; публикация выполняется вместе с packet config. */
typedef struct {
    AR_REQUEST header;
    UCHAR namespace_id[16];
    UINT64 serial;
    UINT32 policy_count, reserved;
} AR_RUNTIME_BEGIN;
typedef struct {
    AR_STAGE stage;
    UCHAR document_digest[32];
} AR_RUNTIME_POLICY;
typedef struct {
    AR_REQUEST header;
    UINT32 kind, slot, sid_length, reserved;
    UCHAR sid[AR_SID_BYTES];
    UINT32 tail_reserved;
    UINT64 epoch;
} AR_RUNTIME_SID;
typedef struct { AR_REQUEST header; UINT64 epoch; } AR_RUNTIME_SEAL;
typedef struct {
    AR_REQUEST header;
    UINT64 epoch, serial;
    UINT32 group, flags;
    UINT64 claim;
} AR_RUNTIME_RECEIPT;

/* Handle принадлежит приватной таблице службы и проверяется с UserMode. */
typedef struct {
    AR_REQUEST header;
    UINT32 kind, slot;
    UINT64 handle;
    UINT32 sid_length, reserved;
    UCHAR sid[AR_SID_BYTES];
    UINT32 tail_reserved;
    UINT32 path_units, path_reserved;
    WCHAR path[AR_PATH_UNITS];
} AR_BIND;
typedef struct {
    AR_BIND binding;
    UINT32 owner_kind, owner;
    UINT64 epoch;
} AR_RUNTIME_CLAIM;

typedef struct {
    AR_REQUEST header;
    UINT64 process_handle;
    UINT32 family, reserved;
    UCHAR destination[16];
} AR_DIAGNOSE;

typedef struct {
    AR_REQUEST header;
    UINT64 generation, process_handle, endpoint;
    UINT32 operation, family;
    UINT16 port, reserved;
    UCHAR peer[16];
    UINT32 tail_reserved;
    UINT64 image_handle;
} AR_TRANSPORT;
typedef struct {
    AR_TRANSPORT transport;
    UINT32 profile, reserved;
} AR_PROFILE_TRANSPORT;
typedef struct {
    AR_REQUEST header;
    UINT32 profile, reserved;
} AR_PROFILE_REQUEST;
C_ASSERT(sizeof(AR_PROFILE_TRANSPORT) == 96);
C_ASSERT(sizeof(AR_PROFILE_REQUEST) == 32);

/* Read-only receipt точной регистрации. PID выводятся только для наблюдаемости. */
typedef struct {
    UINT32 version, size;
    UINT64 session, generation, endpoint;
    UINT32 observed_owner, reserved;
    UINT64 socket_owner_pid, worker_pid;
} AR_TRANSPORT_RECEIPT;
typedef struct {
    AR_TRANSPORT_RECEIPT transport;
    UINT32 profile, reserved;
} AR_PROFILE_TRANSPORT_RECEIPT;
C_ASSERT(sizeof(AR_PROFILE_TRANSPORT_RECEIPT) == 64);

/* Только диагностика. Не является допуском socket/flow и не меняет сеть. */
typedef struct {
    AR_REQUEST header;
    struct ap_decision decision;
    struct ap_origin origin;
    UINT32 parent_count;
    UINT32 image_available, path_available;
    UINT64 created;
    FILE_ID_INFORMATION image;
    UINT32 user_length, package_length;
    UCHAR user[AR_SID_BYTES], package[AR_SID_BYTES];
} AR_DIAGNOSTIC;

C_ASSERT(sizeof(AR_REQUEST) == 24);
C_ASSERT(sizeof(AR_STATUS) == 48);
C_ASSERT(sizeof(struct ap_policy) == 14376);
C_ASSERT(sizeof(AR_STAGE) == 14400);
C_ASSERT(sizeof(AR_RUNTIME_BEGIN) == 56);
C_ASSERT(sizeof(AR_RUNTIME_POLICY) == 14432);
C_ASSERT(sizeof(AR_RUNTIME_SID) == 120);
C_ASSERT(sizeof(AR_RUNTIME_SEAL) == 32);
C_ASSERT(sizeof(AR_RUNTIME_RECEIPT) == 56);
C_ASSERT(sizeof(AR_RUNTIME_CLAIM) == 8336);
C_ASSERT(sizeof(AR_BIND) == 8320);
C_ASSERT(sizeof(AR_DIAGNOSE) == 56);
C_ASSERT(sizeof(AR_TRANSPORT) == 88);
C_ASSERT(sizeof(AR_TRANSPORT_RECEIPT) == 56);
C_ASSERT(sizeof(AR_DIAGNOSTIC) == 264);
C_ASSERT(FIELD_OFFSET(AR_DIAGNOSTIC, origin) == 56);
C_ASSERT(FIELD_OFFSET(AR_DIAGNOSTIC, image) == 96);
