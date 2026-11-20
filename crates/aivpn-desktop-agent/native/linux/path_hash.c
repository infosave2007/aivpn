#include "kernel-policy/path_hash.h"

void aivpn_path_hash(const uint8_t *path, uint32_t length, uint64_t k0, uint64_t k1,
                     uint64_t output[2]) {
    struct ph_hash hash = ph_path(path, length, k0, k1);
    output[0] = hash.low;
    output[1] = hash.high;
}
