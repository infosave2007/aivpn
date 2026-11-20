#include "packet_nat.h"
#include <assert.h>
#include <stdlib.h>

int main(void)
{
    PC_NAT_ALLOCATOR *allocator = calloc(1, sizeof(*allocator));
    assert(allocator);
    for (uint32_t i = 0; i < PC_NAT_COUNT; i++)
        assert(pc_nat_reserve(allocator, 10) == PC_NAT_FIRST + i);
    assert(pc_nat_reserve(allocator, 1000) == 0);
    assert(pc_nat_reserve(allocator, UINT64_MAX) == 0);
    assert(!pc_nat_retire(allocator, 1, 20));
    assert(pc_nat_retire(allocator, PC_NAT_FIRST, 120));
    assert(!pc_nat_retire(allocator, PC_NAT_FIRST, 121));
    assert(pc_nat_reserve(allocator, 119) == 0);
    assert(pc_nat_reserve(allocator, 120) == PC_NAT_FIRST);
    assert(pc_nat_reserve(allocator, 1000) == 0);
    assert(pc_nat_retire(allocator, 65535, 240));
    assert(pc_nat_reserve(allocator, 239) == 0);
    assert(pc_nat_reserve(allocator, 240) == 65535);
    free(allocator);
    return 0;
}
