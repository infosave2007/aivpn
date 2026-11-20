#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t size;
    size_t transport;
    size_t checksum;
    unsigned version;
    unsigned protocol;
    unsigned source_port;
    unsigned destination_port;
    uint8_t source[16];
    uint8_t destination[16];
} AIVPN_PACKET;

typedef struct {
    AIVPN_PACKET packet;
    AIVPN_PACKET reply;
    size_t quote;
    size_t quoted_transport;
} AIVPN_ICMP_ERROR;

int aivpn_packet_parse(const uint8_t *data, size_t size, AIVPN_PACKET *packet);
int aivpn_icmp_echo_parameters(AIVPN_PACKET *packet, const uint8_t *header, size_t size);
int aivpn_packet_rewrite(uint8_t *data, size_t size, int reverse,
    const uint8_t address[16], unsigned short port);

int aivpn_icmp_error_parse(const uint8_t *data, size_t size, AIVPN_ICMP_ERROR *error);
int aivpn_icmp_error_rewrite(uint8_t *data, size_t size,
    const uint8_t address[16], unsigned short port);

unsigned aivpn_packet_fragment_count(const uint8_t *data, size_t size, unsigned mtu);
size_t aivpn_packet_fragment_write(const uint8_t *data, size_t size, unsigned mtu,
    uint32_t id, unsigned index, uint8_t *out, size_t capacity);

int aivpn_packet_clamp_mss(uint8_t *data, size_t size, unsigned mtu);
