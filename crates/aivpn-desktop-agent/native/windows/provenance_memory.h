#pragma once
#include <stdint.h>

#define PV_MEMORY_LIMIT 512u
#define PV_MEMORY_INSTANCE_LIMIT 64u
#define PV_MEMORY_BUDGET 13631488u
#define PV_MEMORY_OPEN_BUDGET (PV_MEMORY_BUDGET / 3u)

enum { PV_MEMORY_ECP, PV_MEMORY_OPEN, PV_MEMORY_PROOF, PV_MEMORY_INSTANCE, PV_MEMORY_KINDS };
typedef struct {
    uint32_t counts[PV_MEMORY_KINDS];
    uint64_t kind_bytes[PV_MEMORY_KINDS], bytes;
} PV_MEMORY;

static int pv_memory_reserve(PV_MEMORY *memory, unsigned kind, uint64_t bytes)
{
    if (kind >= PV_MEMORY_KINDS || !bytes || bytes > PV_MEMORY_BUDGET ||
        memory->bytes > PV_MEMORY_BUDGET - bytes) return 0;
    /* Короткие пути занимают фактическую память, а не отдельную квоту файлов. */
    unsigned limit = kind == PV_MEMORY_INSTANCE ? PV_MEMORY_INSTANCE_LIMIT :
        kind == PV_MEMORY_OPEN ? UINT32_MAX : PV_MEMORY_LIMIT;
    if (memory->counts[kind] >= limit) return 0;
    if (kind == PV_MEMORY_OPEN && (bytes > PV_MEMORY_OPEN_BUDGET ||
        memory->kind_bytes[kind] > PV_MEMORY_OPEN_BUDGET - bytes)) return 0;
    memory->counts[kind]++;
    memory->kind_bytes[kind] += bytes;
    memory->bytes += bytes;
    return 1;
}

static int pv_memory_release(PV_MEMORY *memory, unsigned kind, uint64_t bytes)
{
    if (kind >= PV_MEMORY_KINDS || !bytes || !memory->counts[kind] ||
        memory->kind_bytes[kind] < bytes || memory->bytes < bytes) return 0;
    memory->counts[kind]--;
    memory->kind_bytes[kind] -= bytes;
    memory->bytes -= bytes;
    return 1;
}
