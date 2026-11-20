#include <assert.h>
#include <stdio.h>
#include "../../native/dns_ports.h"

int main(void)
{
    const unsigned char remote4[16] = {198, 51, 100, 1};
    const unsigned char multicast4[16] = {224, 0, 0, 251};
    const unsigned char local4[16] = {127, 42, 0, 1};
    const unsigned char remote6[16] = {0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const unsigned char multicast6[16] = {0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb};
    const unsigned char local6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    for (unsigned port = 0; port <= 65535; port++) {
        int expected = port == 53 || port == 5353 || port == 5355;
        assert(ar_guarded_dns_destination(port, 4, remote4) == expected);
        assert(ar_guarded_dns_destination(port, 4, multicast4) == expected);
        assert(ar_guarded_dns_destination(port, 6, remote6) == expected);
        assert(ar_guarded_dns_destination(port, 6, multicast6) == expected);
        assert(ar_guarded_dns_destination(port, 4, local4) == (port == 53));
        assert(ar_guarded_dns_destination(port, 6, local6) == (port == 53));
    }
    puts("DNS_PORT_GUARD_PASS");
    return 0;
}
