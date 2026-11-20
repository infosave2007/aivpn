#pragma once

#ifdef AIVPN_LAB
#define AR_IOCTL_LAB CTL_CODE(FILE_DEVICE_NETWORK, 0x9f1, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define AR_IOCTL_LAB_BARRIER CTL_CODE(FILE_DEVICE_NETWORK, 0x9f2, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
typedef struct { AR_REQUEST header; UINT64 started, release; } AR_LAB_BARRIER;
#define AR_LAB_WORDS 64u
static volatile LONG ar_lab[AR_LAB_WORDS];
#define AR_LAB_SET(index, value) InterlockedExchange(&ar_lab[index], (LONG)(value))
static void ar_lab_hit(ULONG index)
{
    LONG value = InterlockedCompareExchange(&ar_lab[index], 0, 0);
    for (;;) {
        if (value == MAXLONG) { InterlockedExchange(&ar_lab[AR_LAB_WORDS - 1], 1); return; }
        LONG old = InterlockedCompareExchange(&ar_lab[index], value + 1, value);
        if (old == value) return;
        value = old;
    }
}
#define AR_LAB_HIT(index) ar_lab_hit(index)
#else
#define AR_LAB_SET(index, value) ((void)0)
#define AR_LAB_HIT(index) ((void)0)
#endif
