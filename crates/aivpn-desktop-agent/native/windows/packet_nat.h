#pragma once
#include <stdint.h>

#define PC_NAT_FIRST 32768u
#define PC_NAT_COUNT (65536u - PC_NAT_FIRST)

typedef struct { uint64_t available[PC_NAT_COUNT]; } PC_NAT_ALLOCATOR;

/* UINT64_MAX означает живой OS flow. Время считается только от его retirement. */
static uint16_t pc_nat_reserve(PC_NAT_ALLOCATOR *allocator, uint64_t now)
{
    for (uint32_t i = 0; i < PC_NAT_COUNT; i++) {
        if (allocator->available[i] != UINT64_MAX && allocator->available[i] <= now) {
            allocator->available[i] = UINT64_MAX;
            return (uint16_t)(PC_NAT_FIRST + i);
        }
    }
    return 0;
}

static int pc_nat_retire(PC_NAT_ALLOCATOR *allocator, uint16_t port, uint64_t until)
{
    if (port < PC_NAT_FIRST || until == UINT64_MAX ||
        allocator->available[port - PC_NAT_FIRST] != UINT64_MAX) return 0;
    allocator->available[port - PC_NAT_FIRST] = until;
    return 1;
}
