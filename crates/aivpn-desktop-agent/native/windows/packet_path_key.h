#pragma once
#include <stdint.h>

typedef struct {
    uint32_t interface_index, compartment, mtu;
    unsigned char address4[4], address6[16];
} AIVPN_PATH_KEY;
typedef struct { AIVPN_PATH_KEY key; uint64_t epoch; } AIVPN_PATH_ROUTE;

static int aivpn_path_route_changed(const AIVPN_PATH_ROUTE *route, const AIVPN_PATH_KEY *key)
{
    unsigned present = 0, equal = 1;
    for (unsigned i = 0; i < 4; i++) { present |= key->address4[i]; equal &= key->address4[i] == route->key.address4[i]; }
    for (unsigned i = 0; i < 16; i++) { present |= key->address6[i]; equal &= key->address6[i] == route->key.address6[i]; }
    if (!present) return 0;
    return !route->epoch || !equal || key->interface_index != route->key.interface_index ||
        key->compartment != route->key.compartment || key->mtu != route->key.mtu;
}

static int aivpn_path_route_matches(const AIVPN_PATH_ROUTE *route, uint64_t epoch)
{
    return epoch && epoch == route->epoch;
}
