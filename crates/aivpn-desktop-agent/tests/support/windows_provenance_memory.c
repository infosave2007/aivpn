#include "../../native/windows/provenance_memory.h"
#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "provenance memory check failed at line %d: %s\n", __LINE__, #condition); \
    return 1; \
} } while (0)

int main(void)
{
    PV_MEMORY memory = {0};
    for (unsigned i = 0; i < 600; i++)
        CHECK(pv_memory_reserve(&memory, 1, 256));
    CHECK(memory.counts[1] == 600 && memory.bytes == 600 * 256);
    CHECK(pv_memory_reserve(&memory, 2, 8248));
    CHECK(pv_memory_release(&memory, 2, 8248));
    for (unsigned i = 0; i < 600; i++)
        CHECK(pv_memory_release(&memory, 1, 256));
    CHECK(memory.bytes == 0 && memory.kind_bytes[1] == 0 && memory.counts[1] == 0);

    for (unsigned i = 0; i < PV_MEMORY_OPEN_BUDGET / 256; i++)
        CHECK(pv_memory_reserve(&memory, 1, 256));
    uint64_t remainder = PV_MEMORY_OPEN_BUDGET % 256;
    if (remainder) CHECK(pv_memory_reserve(&memory, 1, remainder));
    CHECK(!pv_memory_reserve(&memory, 1, 1));
    for (unsigned i = 0; i < PV_MEMORY_LIMIT; i++) {
        CHECK(pv_memory_reserve(&memory, 0, 8248));
        CHECK(pv_memory_reserve(&memory, 2, 8248));
    }
    for (unsigned i = 0; i < PV_MEMORY_INSTANCE_LIMIT; i++)
        CHECK(pv_memory_reserve(&memory, 3, 136));
    CHECK(memory.bytes < PV_MEMORY_BUDGET);
    PV_MEMORY before = memory;
    CHECK(!pv_memory_reserve(&memory, 0, 1));
    CHECK(!pv_memory_reserve(&memory, 2, 1));
    CHECK(!pv_memory_reserve(&memory, 3, 1));
    CHECK(!pv_memory_reserve(&memory, 4, 1));
    CHECK(!pv_memory_reserve(&memory, 1, UINT64_MAX));
    CHECK(!pv_memory_reserve(&memory, 1, 0));
    CHECK(!pv_memory_release(&memory, 4, 1));
    CHECK(!pv_memory_release(&memory, 0, UINT64_MAX));
    CHECK(memcmp(&before, &memory, sizeof(memory)) == 0);
    for (unsigned i = 0; i < PV_MEMORY_LIMIT; i++) {
        CHECK(pv_memory_release(&memory, 0, 8248));
        CHECK(pv_memory_release(&memory, 2, 8248));
    }
    for (unsigned i = 0; i < PV_MEMORY_INSTANCE_LIMIT; i++)
        CHECK(pv_memory_release(&memory, 3, 136));
    for (unsigned i = 0; i < PV_MEMORY_OPEN_BUDGET / 256; i++)
        CHECK(pv_memory_release(&memory, 1, 256));
    if (remainder) CHECK(pv_memory_release(&memory, 1, remainder));
    CHECK(memory.bytes == 0);
    CHECK(pv_memory_reserve(&memory, 0, PV_MEMORY_BUDGET));
    before = memory;
    CHECK(!pv_memory_reserve(&memory, 2, 1));
    CHECK(memcmp(&before, &memory, sizeof(memory)) == 0);
    CHECK(pv_memory_release(&memory, 0, PV_MEMORY_BUDGET));
    CHECK(memory.bytes == 0);
    puts("WINDOWS_PROVENANCE_MEMORY_PASS");
    return 0;
}
