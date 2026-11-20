#include "packet.h"
#include "packet_ndp.h"
#include "packet_path_key.h"
#include "reassembly.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned read16(const unsigned char *p) { return ((unsigned)p[0] << 8) | p[1]; }
static void write16(unsigned char *p, unsigned value) { p[0] = value >> 8; p[1] = value; }
static unsigned sum(const unsigned char *p, size_t n)
{
    unsigned value = 0;
    while (n > 1) { value += read16(p); p += 2; n -= 2; }
    if (n) value += (unsigned)*p << 8;
    return value;
}
static unsigned finish(unsigned value)
{
    while (value >> 16) value = (value & 65535) + (value >> 16);
    return (~value) & 65535;
}
static void ip4_checksum(unsigned char *p) { write16(p + 10, 0); write16(p + 10, finish(sum(p, (p[0] & 15) * 4))); }
static const unsigned char vpn4[16] = {10,67,0,2}, peer4[16] = {198,18,0,53}, original4[16] = {192,0,2,2};
static const unsigned char vpn6[16] = {0xfd,0x67,0,0,0,0,0,0,0,0,0,0,0,0,0,2};
static const unsigned char peer6[16] = {0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x53};
static const unsigned char original6[16] = {0xfd,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2};

static size_t udp_quote(unsigned char *out, int ipv6, int zero_checksum)
{
    size_t header = ipv6 ? 40 : 20;
    memset(out, 0, 128);
    out[0] = ipv6 ? 0x60 : 0x45;
    write16(out + (ipv6 ? 4 : 2), (ipv6 ? 0 : header) + 11);
    out[ipv6 ? 6 : 9] = 17; out[ipv6 ? 7 : 8] = 64;
    memcpy(out + (ipv6 ? 8 : 12), ipv6 ? vpn6 : vpn4, ipv6 ? 16 : 4);
    memcpy(out + (ipv6 ? 24 : 16), ipv6 ? peer6 : peer4, ipv6 ? 16 : 4);
    write16(out + header, 50000); write16(out + header + 2, 53); write16(out + header + 4, 11);
    memcpy(out + header + 8, "dns", 3);
    if (!zero_checksum) write16(out + header + 6, finish(sum(out + (ipv6 ? 8 : 12), ipv6 ? 32 : 8) + 17 + 11 + sum(out + header, 11)));
    if (!ipv6) ip4_checksum(out);
    return header + 11;
}
static size_t icmp_error(unsigned char *out, int ipv6, const unsigned char *quote, size_t quoted)
{
    size_t header = ipv6 ? 40 : 20;
    memset(out, 0, 512);
    out[0] = ipv6 ? 0x60 : 0x45;
    write16(out + (ipv6 ? 4 : 2), (ipv6 ? 0 : header) + 8 + quoted);
    out[ipv6 ? 6 : 9] = ipv6 ? 58 : 1; out[ipv6 ? 7 : 8] = 64;
    memcpy(out + (ipv6 ? 8 : 12), ipv6 ? peer6 : peer4, ipv6 ? 16 : 4);
    memcpy(out + (ipv6 ? 24 : 16), ipv6 ? vpn6 : vpn4, ipv6 ? 16 : 4);
    out[header] = ipv6 ? 2 : 3; out[header + 1] = ipv6 ? 0 : 3;
    if (ipv6) write16(out + header + 6, 1280);
    memcpy(out + header + 8, quote, quoted);
    unsigned pseudo = ipv6 ? sum(out + 8, 32) + 58 + 8 + quoted : 0;
    write16(out + header + 2, finish(pseudo + sum(out + header, 8 + quoted)));
    if (!ipv6) ip4_checksum(out);
    return header + 8 + quoted;
}
static void udp_error_roundtrip(int ipv6, int zero_checksum)
{
    unsigned char quote[128], bytes[512];
    size_t quoted = udp_quote(quote, ipv6, zero_checksum);
    size_t length = icmp_error(bytes, ipv6, quote, quoted);
    AIVPN_ICMP_ERROR error;
    assert(aivpn_icmp_error_parse(bytes, length, &error));
    assert(error.packet.protocol == (ipv6 ? 58u : 1u));
    assert(error.reply.protocol == 17 && error.reply.source_port == 53 && error.reply.destination_port == 50000);
    assert(!memcmp(error.reply.source, ipv6 ? peer6 : peer4, ipv6 ? 16 : 4));
    assert(!memcmp(error.reply.destination, ipv6 ? vpn6 : vpn4, ipv6 ? 16 : 4));
    assert(aivpn_icmp_error_rewrite(bytes, length, ipv6 ? original6 : original4, 31000));
    assert(aivpn_icmp_error_parse(bytes, length, &error));
    assert(error.reply.destination_port == 31000);
    assert(!memcmp(bytes + (ipv6 ? 24 : 16), ipv6 ? original6 : original4, ipv6 ? 16 : 4));
    const unsigned char *translated = bytes + (ipv6 ? 48 : 28);
    size_t header = ipv6 ? 40 : 20;
    assert(!memcmp(translated + (ipv6 ? 8 : 12), ipv6 ? original6 : original4, ipv6 ? 16 : 4));
    if (zero_checksum) assert(!read16(translated + header + 6));
    else assert(!finish(sum(translated + (ipv6 ? 8 : 12), ipv6 ? 32 : 8) + 17 + 11 + sum(translated + header, 11)));
    bytes[length - 1] ^= 1;
    assert(!aivpn_icmp_error_parse(bytes, length, &error));
}
static void scoped_fragments(void)
{
    AIVPN_REASSEMBLER *state = calloc(1, sizeof(*state));
    assert(state);
    unsigned char first[28] = {0}, last[28] = {0}, output[128] = {0};
    first[0] = 0x45; first[8] = 64; first[9] = 17;
    write16(first + 2, sizeof(first)); write16(first + 4, 77); write16(first + 6, 0x2000);
    memcpy(first + 12, vpn4, 4); memcpy(first + 16, peer4, 4);
    write16(first + 20, 50000); write16(first + 22, 53); write16(first + 24, 16);
    ip4_checksum(first);
    memcpy(last, first, sizeof(last)); write16(last + 6, 1); memset(last + 20, 'b', 8); ip4_checksum(last);
    size_t length = 0;
    assert(aivpn_reassemble_scoped(state, 11, first, sizeof(first), 1, output, sizeof(output), &length) == 1);
    /* Те же IP и fragment ID другого профиля не завершают начатый пакет. */
    assert(aivpn_reassemble_scoped(state, 22, last, sizeof(last), 2, output, sizeof(output), &length) == 1);
    assert(length == 0);
    memset(last + 20, 'a', 8);
    assert(aivpn_reassemble_scoped(state, 11, last, sizeof(last), 3, output, sizeof(output), &length) == 2);
    assert(length == 36 && !memcmp(output + 28, "aaaaaaaa", 8));
    assert(aivpn_reassemble_scoped(state, 22, first, sizeof(first), 4, output, sizeof(output), &length) == 2);
    assert(length == 36 && !memcmp(output + 28, "bbbbbbbb", 8));
    assert(aivpn_reassemble(state, first, sizeof(first), 5, output, sizeof(output), &length) == 1);
    assert(aivpn_reassemble(state, last, sizeof(last), 6, output, sizeof(output), &length) == 2);
    /* Предел общий: отдельный контекст не создает второй большой пул. */
    for (unsigned i = 0; i < AIVPN_ASSEMBLY_LIMIT; i++)
        assert(aivpn_reassemble_scoped(state, 100 + i, first, sizeof(first), 10, output, sizeof(output), &length) == 1);
    assert(aivpn_reassemble_scoped(state, 1000, first, sizeof(first), 11, output, sizeof(output), &length) == -1);
    assert(aivpn_reassemble_scoped(state, 1000, first, sizeof(first), 6010, output, sizeof(output), &length) == 1);
    assert(aivpn_reassemble_scoped(state, 1000, last, sizeof(last), 6011, output, sizeof(output), &length) == 2);
    free(state);
}
static void ndp_kernel_boundary(void)
{
    AIVPN_PACKET packet = {0};
    packet.version = 6; packet.protocol = 58;
    packet.destination[0] = 0xff; packet.destination[1] = 2;
    packet.destination[15] = 2;
    for (unsigned type = 133; type <= 136; type++) {
        packet.source_port = type;
        assert(aivpn_ndp_control_allowed(&packet, 1));
        assert(!aivpn_ndp_control_allowed(&packet, 0));
    }
    packet.source_port = 128;
    assert(!aivpn_ndp_control_allowed(&packet, 1));
    packet.source_port = 135; packet.destination_port = 1;
    assert(!aivpn_ndp_control_allowed(&packet, 1));
    packet.destination_port = 0; packet.destination[1] = 14;
    assert(!aivpn_ndp_control_allowed(&packet, 1));
    memset(packet.destination, 0, sizeof(packet.destination));
    assert(!aivpn_ndp_control_allowed(&packet, 1));
    packet.destination[0] = 0xfe; packet.destination[1] = 0x80;
    packet.destination[15] = 2;
    assert(aivpn_ndp_control_allowed(&packet, 1));
    packet.version = 4;
    assert(!aivpn_ndp_control_allowed(&packet, 1));
    assert(!aivpn_ndp_control_allowed(NULL, 1));
}
static void route_survives_offline_but_never_revives_after_address_reuse(void)
{
    AIVPN_PATH_ROUTE route = {0};
    AIVPN_PATH_KEY key = {0};
    key.interface_index = 4; key.compartment = 1; key.mtu = 1280;
    memcpy(key.address4, vpn4, 4);
    assert(aivpn_path_route_changed(&route, &key));
    route.key = key; route.epoch = 1;
    assert(aivpn_path_route_matches(&route, 1));
    AIVPN_PATH_KEY offline = key;
    memset(offline.address4, 0, 4);
    assert(!aivpn_path_route_changed(&route, &offline));
    assert(!aivpn_path_route_changed(&route, &key));
    assert(aivpn_path_route_matches(&route, 1));
    key.address4[3]++;
    assert(aivpn_path_route_changed(&route, &key));
    route.key = key; route.epoch = 2;
    assert(!aivpn_path_route_matches(&route, 1));
    key.address4[3]--;
    assert(aivpn_path_route_changed(&route, &key));
    route.key = key; route.epoch = 3;
    assert(!aivpn_path_route_matches(&route, 1));
    assert(!aivpn_path_route_matches(&route, 0));
    key.interface_index++;
    assert(aivpn_path_route_changed(&route, &key));
    key.interface_index--; key.compartment++;
    assert(aivpn_path_route_changed(&route, &key));
    key.compartment--; key.address6[0] = 0xfd;
    assert(aivpn_path_route_changed(&route, &key));
}

static void echo_roundtrip(int ipv6, unsigned identifier)
{
    unsigned char bytes[80] = {0};
    size_t header = ipv6 ? 40 : 20, length = header + 13;
    bytes[0] = ipv6 ? 0x60 : 0x45;
    write16(bytes + (ipv6 ? 4 : 2), ipv6 ? 13 : (unsigned)length);
    bytes[ipv6 ? 6 : 9] = ipv6 ? 58 : 1;
    bytes[ipv6 ? 7 : 8] = 64;
    memcpy(bytes + (ipv6 ? 8 : 12), ipv6 ? original6 : original4, ipv6 ? 16 : 4);
    memcpy(bytes + (ipv6 ? 24 : 16), ipv6 ? peer6 : peer4, ipv6 ? 16 : 4);
    bytes[header] = ipv6 ? 128 : 8;
    write16(bytes + header + 4, identifier); write16(bytes + header + 6, 99);
    memcpy(bytes + header + 8, "hello", 5);
    unsigned pseudo = ipv6 ? sum(bytes + 8, 32) + 58 + 13 : 0;
    write16(bytes + header + 2, finish(pseudo + sum(bytes + header, 13)));
    if (!ipv6) ip4_checksum(bytes);
    AIVPN_PACKET request;
    assert(aivpn_packet_parse(bytes, length, &request));
    assert(request.source_port == identifier && request.destination_port == 0);
    assert(aivpn_packet_rewrite(bytes, length, 0, ipv6 ? vpn6 : vpn4, 45678));
    assert(read16(bytes + header + 4) == 45678);
    assert(!memcmp(bytes + header + 8, "hello", 5));
    unsigned char error_bytes[512];
    size_t error_length = icmp_error(error_bytes, ipv6, bytes, length);
    AIVPN_ICMP_ERROR error;
    assert(aivpn_icmp_error_parse(error_bytes, error_length, &error));
    assert(error.reply.source_port == 0 && error.reply.destination_port == 45678);
    assert(aivpn_icmp_error_rewrite(error_bytes, error_length, ipv6 ? original6 : original4, identifier));
    assert(aivpn_icmp_error_parse(error_bytes, error_length, &error));
    assert(error.reply.destination_port == identifier);
    unsigned char *quoted = error_bytes + error.quote;
    unsigned quoted_pseudo = ipv6 ? sum(quoted + 8, 32) + 58 + 13 : 0;
    assert(!finish(quoted_pseudo + sum(quoted + header, 13)));
    /* Ответ использует тот же NAT identifier, номер запроса остается прежним. */
    memcpy(bytes + (ipv6 ? 8 : 12), ipv6 ? peer6 : peer4, ipv6 ? 16 : 4);
    memcpy(bytes + (ipv6 ? 24 : 16), ipv6 ? vpn6 : vpn4, ipv6 ? 16 : 4);
    bytes[header] = ipv6 ? 129 : 0;
    write16(bytes + header + 2, 0);
    pseudo = ipv6 ? sum(bytes + 8, 32) + 58 + 13 : 0;
    write16(bytes + header + 2, finish(pseudo + sum(bytes + header, 13)));
    if (!ipv6) ip4_checksum(bytes);
    AIVPN_PACKET reply;
    assert(aivpn_packet_parse(bytes, length, &reply));
    assert(reply.source_port == 0 && reply.destination_port == 45678);
    assert(aivpn_packet_rewrite(bytes, length, 1, ipv6 ? original6 : original4, identifier));
    assert(read16(bytes + header + 4) == identifier && read16(bytes + header + 6) == 99);
    assert(!memcmp(bytes + (ipv6 ? 24 : 16), ipv6 ? original6 : original4, ipv6 ? 16 : 4));
    pseudo = ipv6 ? sum(bytes + 8, 32) + 58 + 13 : 0;
    assert(!finish(pseudo + sum(bytes + header, 13)));
    if (!ipv6) assert(!finish(sum(bytes, 20)));
    bytes[header + 1] = 1;
    assert(!aivpn_packet_parse(bytes, length, &reply));
    bytes[header + 1] = 0;
    assert(!aivpn_packet_parse(bytes, header + 7, &reply));
}

int main(void)
{
    const unsigned identifiers[] = {0, 1, 1234, 65535};
    for (unsigned i = 0; i < sizeof(identifiers) / sizeof(identifiers[0]); i++) {
        echo_roundtrip(0, identifiers[i]); echo_roundtrip(1, identifiers[i]);
    }
    ndp_kernel_boundary();
    route_survives_offline_but_never_revives_after_address_reuse();
    scoped_fragments();
    udp_error_roundtrip(0, 0); udp_error_roundtrip(0, 1); udp_error_roundtrip(1, 0);
    unsigned char quote[128], bytes[512];
    udp_quote(quote, 0, 0);
    quote[9] = 6; write16(quote + 2, 40); write16(quote + 22, 443); ip4_checksum(quote);
    size_t length = icmp_error(bytes, 0, quote, 28);
    AIVPN_ICMP_ERROR error;
    assert(aivpn_icmp_error_parse(bytes, length, &error));
    assert(error.reply.protocol == 6 && error.reply.source_port == 443);
    memset(bytes + length, 0xa5, 16);
    assert(aivpn_icmp_error_rewrite(bytes, length, original4, 12345));
    assert(aivpn_icmp_error_parse(bytes, length, &error));
    for (unsigned i = 0; i < 16; i++) assert(bytes[length + i] == 0xa5);
    assert(!aivpn_icmp_error_parse(bytes, length - 1, &error));
    udp_quote(quote, 0, 0); write16(quote + 6, 1); ip4_checksum(quote);
    length = icmp_error(bytes, 0, quote, 31);
    assert(!aivpn_icmp_error_parse(bytes, length, &error));
    udp_quote(quote, 1, 0); length = icmp_error(bytes, 0, quote, 51);
    assert(!aivpn_icmp_error_parse(bytes, length, &error));
    udp_quote(quote, 0, 0); length = icmp_error(bytes, 0, quote, 24);
    assert(!aivpn_icmp_error_parse(bytes, length, &error));
    puts("ICMP error flow lookup, NAT, checksums, truncated TCP and rejection cases passed");
    return 0;
}
