#pragma once

/* Обычный DNS идет только через свой listener или подтвержденный VPN upstream.
 * mDNS и LLMNR не должны раскрывать запросы через общую службу резолвера.
 * Их loopback-соединения остаются локальными. */
static inline int ar_guarded_dns_destination(unsigned port, unsigned family,
                                            const unsigned char address[16])
{
    if (port == 53) return 1;
    if (port != 5353 && port != 5355) return 0;
    if (family == 4) return address[0] != 127;
    if (family != 6) return 1;
    unsigned loopback = address[15] == 1;
    for (unsigned i = 0; i < 15; i++)
        if (address[i]) loopback = 0;
    return !loopback;
}
