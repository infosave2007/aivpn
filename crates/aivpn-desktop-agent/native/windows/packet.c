#include "packet.h"

static unsigned read16(const uint8_t *data)
{
    return ((unsigned)data[0] << 8) | data[1];
}

static void write16(uint8_t *data, unsigned value)
{
    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)value;
}

static uint32_t sum_bytes(uint32_t sum, const uint8_t *data, size_t size)
{
    while (size >= 2) {
        sum += read16(data);
        data += 2;
        size -= 2;
    }
    if (size) sum += (uint32_t)data[0] << 8;
    return sum;
}

static unsigned finish_sum(uint32_t sum)
{
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    return (~sum) & 65535;
}

int aivpn_icmp_echo_parameters(AIVPN_PACKET *packet, const uint8_t *header, size_t size)
{
    if (!packet || !header || size < 8 || header[1]) return 0;
    int request, reply;
    if (packet->version == 4 && packet->protocol == 1) {
        request = header[0] == 8; reply = header[0] == 0;
    } else if (packet->version == 6 && packet->protocol == 58) {
        request = header[0] == 128; reply = header[0] == 129;
    } else return 0;
    if (!request && !reply) return 0;
    packet->source_port = request ? read16(header + 4) : 0;
    packet->destination_port = reply ? read16(header + 4) : 0;
    packet->checksum = packet->transport + 2;
    return 1;
}

int aivpn_packet_parse(const uint8_t *data, size_t size, AIVPN_PACKET *packet)
{
    AIVPN_PACKET result = {0};
    size_t address_offset, address_size;
    if (!data || !packet || !size) return 0;
    result.version = data[0] >> 4;
    if (result.version == 4) {
        if (size < 20 || (data[0] & 15) < 5) return 0;
        result.transport = (data[0] & 15) * 4;
        result.size = read16(data + 2);
        if ((read16(data + 6) & 0x3fff) != 0) return 0;
        result.protocol = data[9];
        address_offset = 12;
        address_size = 4;
    } else if (result.version == 6) {
        if (size < 40) return 0;
        result.transport = 40;
        result.size = 40 + read16(data + 4);
        result.protocol = data[6];
        address_offset = 8;
        address_size = 16;
        if (result.size > size) return 0;
        for (unsigned depth = 0; result.protocol == 0 || result.protocol == 60; depth++) {
            if (depth >= 8 || result.transport + 2 > result.size) return 0;
            size_t extension_size = ((size_t)data[result.transport + 1] + 1) * 8;
            if (extension_size > result.size - result.transport) return 0;
            result.protocol = data[result.transport];
            result.transport += extension_size;
        }
    } else return 0;
    if (result.size > size || result.size < result.transport) return 0;
    size_t remaining = result.size - result.transport;
    if (result.protocol == 6) {
        if (remaining < 20) return 0;
        size_t tcp_size = (size_t)(data[result.transport + 12] >> 4) * 4;
        if (tcp_size < 20 || tcp_size > remaining) return 0;
        result.checksum = result.transport + 16;
    } else if (result.protocol == 17) {
        if (remaining < 8 || read16(data + result.transport + 4) != remaining) return 0;
        result.checksum = result.transport + 6;
    } else if (!aivpn_icmp_echo_parameters(&result, data + result.transport, remaining)) return 0;
    if (result.protocol == 6 || result.protocol == 17) {
        result.source_port = read16(data + result.transport);
        result.destination_port = read16(data + result.transport + 2);
    }
    for (size_t index = 0; index < address_size; index++) {
        result.source[index] = data[address_offset + index];
        result.destination[index] = data[address_offset + address_size + index];
    }
    *packet = result;
    return 1;
}

int aivpn_packet_rewrite(uint8_t *data, size_t size, int reverse,
    const uint8_t address[16], unsigned short port)
{
    AIVPN_PACKET packet;
    if (!address || !aivpn_packet_parse(data, size, &packet)) return 0;
    size_t length = packet.version == 4 ? 4 : 16;
    size_t offset = packet.version == 4 ? 12 : 8;
    size_t target = offset + (reverse ? length : 0);
    for (size_t index = 0; index < length; index++) data[target + index] = address[index];
    int echo = packet.protocol == 1 || packet.protocol == 58;
    write16(data + packet.transport + (echo ? 4 : (reverse ? 2 : 0)), port);
    write16(data + packet.checksum, 0);
    unsigned transport_size = (unsigned)(packet.size - packet.transport);
    uint32_t sum = 0;
    if (packet.protocol != 1) {
        sum = sum_bytes(0, data + offset, length * 2);
        sum += packet.protocol + transport_size;
    }
    sum = sum_bytes(sum, data + packet.transport, transport_size);
    unsigned value = finish_sum(sum);
    write16(data + packet.checksum, value ? value : 65535);
    if (packet.version == 4) {
        write16(data + 10, 0);
        write16(data + 10, finish_sum(sum_bytes(0, data, packet.transport)));
    }
    return 1;
}

/* Цитата в ICMP может содержать только IP-заголовок и восемь байт транспорта. */
static int icmp_ip_header(const uint8_t *data, size_t size, int quoted, AIVPN_PACKET *packet)
{
    AIVPN_PACKET result = {0};
    if (!data || !size) return 0;
    result.version = data[0] >> 4;
    size_t offset, width;
    if (result.version == 4) {
        if (size < 20 || (data[0] & 15) < 5) return 0;
        result.transport = (data[0] & 15) * 4;
        result.size = read16(data + 2);
        if (result.transport > size || (read16(data + 6) & 0x1fff) ||
            (!quoted && (read16(data + 6) & 0x2000)) ||
            finish_sum(sum_bytes(0, data, result.transport))) return 0;
        result.protocol = data[9]; offset = 12; width = 4;
    } else if (result.version == 6) {
        if (size < 40) return 0;
        result.transport = 40; result.size = 40 + read16(data + 4);
        result.protocol = data[6]; offset = 8; width = 16;
        for (unsigned depth = 0; result.protocol == 0 || result.protocol == 43 || result.protocol == 60 || result.protocol == 44; depth++) {
            if (depth >= 8 || result.transport + 2 > size || result.transport + 2 > result.size) return 0;
            size_t length = result.protocol == 44 ? 8 : ((size_t)data[result.transport + 1] + 1) * 8;
            if (length > size - result.transport || length > result.size - result.transport) return 0;
            if (result.protocol == 44 && (!quoted || (read16(data + result.transport + 2) & 0xfff8))) return 0;
            result.protocol = data[result.transport]; result.transport += length;
        }
    } else return 0;
    if (result.size < result.transport || (!quoted && result.size > size)) return 0;
    for (size_t i = 0; i < width; i++) {
        result.source[i] = data[offset + i]; result.destination[i] = data[offset + width + i];
    }
    *packet = result;
    return 1;
}

static uint32_t icmp_pseudo_sum(const uint8_t *data, const AIVPN_PACKET *packet)
{
    if (packet->version == 4) return 0;
    return sum_bytes(0, data + 8, 32) + packet->protocol + (uint32_t)(packet->size - packet->transport);
}

int aivpn_icmp_error_parse(const uint8_t *data, size_t size, AIVPN_ICMP_ERROR *error)
{
    AIVPN_ICMP_ERROR result = {0};
    if (!error || !icmp_ip_header(data, size, 0, &result.packet)) return 0;
    AIVPN_PACKET *packet = &result.packet;
    if (packet->size - packet->transport < 8 ||
        packet->protocol != (packet->version == 4 ? 1u : 58u)) return 0;
    unsigned type = data[packet->transport];
    if (packet->version == 4 ? (type != 3 && type != 11 && type != 12) : (type < 1 || type > 4)) return 0;
    if (finish_sum(sum_bytes(icmp_pseudo_sum(data, packet), data + packet->transport, packet->size - packet->transport))) return 0;
    result.quote = packet->transport + 8;
    AIVPN_PACKET quoted;
    size_t available = packet->size - result.quote;
    if (!icmp_ip_header(data + result.quote, available, 1, &quoted) || quoted.version != packet->version ||
        available - quoted.transport < 8 || quoted.size - quoted.transport < 8) return 0;
    if (quoted.protocol == 6 && quoted.size - quoted.transport < 20) return 0;
    if (quoted.protocol == 17 && read16(data + result.quote + quoted.transport + 4) < 8) return 0;
    size_t width = packet->version == 4 ? 4 : 16;
    result.reply.version = quoted.version;
    result.reply.protocol = quoted.protocol;
    const uint8_t *transport = data + result.quote + quoted.transport;
    if (quoted.protocol == 6 || quoted.protocol == 17) {
        quoted.source_port = read16(transport);
        quoted.destination_port = read16(transport + 2);
    } else if (!aivpn_icmp_echo_parameters(&quoted, transport, available - quoted.transport) ||
        transport[0] != (quoted.version == 4 ? 8 : 128)) return 0;
    result.reply.source_port = quoted.destination_port;
    result.reply.destination_port = quoted.source_port;
    for (size_t i = 0; i < width; i++) {
        if (packet->destination[i] != quoted.source[i]) return 0;
        result.reply.source[i] = quoted.destination[i]; result.reply.destination[i] = quoted.source[i];
    }
    result.quoted_transport = result.quote + quoted.transport;
    *error = result;
    return 1;
}

int aivpn_icmp_error_rewrite(uint8_t *data, size_t size, const uint8_t address[16], unsigned short port)
{
    AIVPN_ICMP_ERROR error;
    if (!address || !aivpn_icmp_error_parse(data, size, &error)) return 0;
    const AIVPN_PACKET *packet = &error.packet;
    size_t width = packet->version == 4 ? 4 : 16;
    size_t source = error.quote + (packet->version == 4 ? 12 : 8);
    size_t destination = packet->version == 4 ? 16 : 24;
    int echo = error.reply.protocol == 1 || error.reply.protocol == 58;
    size_t port_offset = error.quoted_transport + (echo ? 4 : 0);
    size_t checksum = error.quoted_transport + (echo ? 2 : (error.reply.protocol == 6 ? 16 : 6));
    if (checksum + 2 <= packet->size) {
        unsigned before = read16(data + checksum);
        if (before || packet->version == 6 || error.reply.protocol == 6 || echo) {
            uint32_t sum = (~before) & 65535;
            if (error.reply.protocol != 1)
                for (size_t i = 0; i < width; i += 2) sum += ((~read16(data + source + i)) & 65535) + read16(address + i);
            sum += ((~read16(data + port_offset)) & 65535) + port;
            unsigned after = finish_sum(sum);
            write16(data + checksum, after ? after : 65535);
        }
    }
    for (size_t i = 0; i < width; i++) { data[source + i] = address[i]; data[destination + i] = address[i]; }
    write16(data + port_offset, port);
    if (packet->version == 4) {
        write16(data + error.quote + 10, 0);
        write16(data + error.quote + 10, finish_sum(sum_bytes(0, data + error.quote, error.quoted_transport - error.quote)));
        write16(data + 10, 0);
        write16(data + 10, finish_sum(sum_bytes(0, data, packet->transport)));
    }
    write16(data + packet->transport + 2, 0);
    write16(data + packet->transport + 2, finish_sum(sum_bytes(icmp_pseudo_sum(data, packet), data + packet->transport, packet->size - packet->transport)));
    return 1;
}

static int mss_positions(const uint8_t *data, const AIVPN_PACKET *packet, size_t positions[10])
{
    size_t end = packet->transport + (size_t)(data[packet->transport + 12] >> 4) * 4;
    int count = 0;
    for (size_t offset = packet->transport + 20; offset < end;) {
        unsigned kind = data[offset];
        if (!kind) break;
        if (kind == 1) { offset++; continue; }
        if (offset + 2 > end) return -1;
        size_t length = data[offset + 1];
        if (length < 2 || length > end - offset) return -1;
        if (kind == 2) {
            if (length != 4 || count >= 10) return -1;
            positions[count++] = offset + 2;
        }
        offset += length;
    }
    return count;
}

int aivpn_packet_clamp_mss(uint8_t *data, size_t size, unsigned mtu)
{
    AIVPN_PACKET packet;
    if (!aivpn_packet_parse(data, size, &packet)) return 0;
    if (packet.protocol != 6 || !(data[packet.transport + 13] & 2)) return 1;
    unsigned overhead = packet.version == 4 ? 40 : 60;
    if (mtu <= overhead || mtu > 65535) return 0;
    size_t positions[10];
    int count = mss_positions(data, &packet, positions);
    if (count < 0) return 0;
    int changed = 0;
    for (int index = 0; index < count; index++) {
        if (read16(data + positions[index]) > mtu - overhead) {
            write16(data + positions[index], mtu - overhead);
            changed = 1;
        }
    }
    if (changed) return aivpn_packet_rewrite(data, size, 0, packet.source, (unsigned short)packet.source_port);
    return 1;
}
