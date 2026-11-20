#pragma once
#include "packet.h"

/* Исключение для NDP разрешено только пакету, который WFP относит к ядру ОС. */
static int aivpn_ndp_control_allowed(const AIVPN_PACKET *packet, int from_kernel)
{
    if (!packet || !from_kernel || packet->version != 6 || packet->protocol != 58 ||
        packet->destination_port || packet->source_port < 133 || packet->source_port > 136) return 0;
    unsigned any = 0;
    for (unsigned i = 0; i < 16; i++) any |= packet->destination[i];
    if (!any) return 0;
    if (packet->destination[0] == 0xff && packet->destination[1] != 2) return 0;
    return 1;
}
