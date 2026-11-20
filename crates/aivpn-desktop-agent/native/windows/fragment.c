#include "packet.h"

typedef struct {
    AIVPN_PACKET packet;
    size_t first_header;
    size_t next_header;
    size_t next_header_field;
    size_t payload;
    size_t first_max;
    size_t next_max;
    unsigned count;
    uint8_t options[40];
} FRAGMENT_PLAN;

static unsigned frag_read16(const uint8_t *data) { return ((unsigned)data[0] << 8) | data[1]; }
static void frag_write16(uint8_t *data, unsigned value) { data[0] = (uint8_t)(value >> 8); data[1] = (uint8_t)value; }
static void frag_copy(uint8_t *out, const uint8_t *in, size_t size) { for (size_t n = 0; n < size; n++) out[n] = in[n]; }

static int copy_ipv4_options(const uint8_t *data, FRAGMENT_PLAN *plan)
{
    size_t output = 0;
    for (size_t offset = 20; offset < plan->first_header;) {
        unsigned type = data[offset];
        if (type == 0) break;
        if (type == 1) { offset++; continue; }
        if (offset + 2 > plan->first_header) return 0;
        size_t size = data[offset + 1];
        if (size < 2 || size > plan->first_header - offset) return 0;
        if (type & 128) {
            if (size > sizeof(plan->options) - output) return 0;
            frag_copy(plan->options + output, data + offset, size);
            output += size;
        }
        offset += size;
    }
    while (output % 4) plan->options[output++] = 0;
    plan->next_header = 20 + output;
    return 1;
}

static int fragment_plan(const uint8_t *data, size_t size, unsigned mtu, FRAGMENT_PLAN *plan)
{
    if (!aivpn_packet_parse(data, size, &plan->packet) || plan->packet.size != size) return 0;
    if (size <= mtu) { plan->count = 1; return 1; }
    if (plan->packet.version == 4) {
        if (mtu < 68 || (frag_read16(data + 6) & 0x4000)) return 0;
        plan->first_header = (data[0] & 15) * 4;
        if (!copy_ipv4_options(data, plan)) return 0;
        plan->payload = plan->first_header;
    } else {
        if (mtu < 1280) return 0;
        plan->payload = 40;
        plan->next_header_field = 6;
        if (data[6] == 0) {
            plan->payload += ((size_t)data[41] + 1) * 8;
            plan->next_header_field = 40;
        }
        plan->first_header = plan->next_header = plan->payload + 8;
    }
    if (mtu <= plan->first_header || mtu <= plan->next_header) return 0;
    plan->first_max = (mtu - plan->first_header) & ~(size_t)7;
    plan->next_max = (mtu - plan->next_header) & ~(size_t)7;
    if (!plan->first_max || !plan->next_max || size <= plan->payload + plan->first_max) return 0;
    size_t remaining = size - plan->payload - plan->first_max;
    plan->count = 1 + (unsigned)((remaining + plan->next_max - 1) / plan->next_max);
    return 1;
}

unsigned aivpn_packet_fragment_count(const uint8_t *data, size_t size, unsigned mtu)
{
    FRAGMENT_PLAN plan = {0};
    return fragment_plan(data, size, mtu, &plan) ? plan.count : 0;
}

size_t aivpn_packet_fragment_write(const uint8_t *data, size_t size, unsigned mtu,
    uint32_t id, unsigned index, uint8_t *out, size_t capacity)
{
    FRAGMENT_PLAN plan = {0};
    if (!out || !fragment_plan(data, size, mtu, &plan) || index >= plan.count) return 0;
    if (plan.count == 1) {
        if (capacity < size) return 0;
        frag_copy(out, data, size);
        return size;
    }
    size_t offset = index ? plan.first_max + (index - 1) * plan.next_max : 0;
    size_t maximum = index ? plan.next_max : plan.first_max;
    size_t content = size - plan.payload - offset;
    if (content > maximum) content = maximum;
    size_t header = index ? plan.next_header : plan.first_header;
    size_t length = header + content;
    if (capacity < length) return 0;
    if (plan.packet.version == 4) {
        frag_copy(out, data, 20);
        if (!index) frag_copy(out + 20, data + 20, header - 20);
        else frag_copy(out + 20, plan.options, header - 20);
        out[0] = (uint8_t)(0x40 | (header / 4));
        frag_write16(out + 2, (unsigned)length);
        frag_write16(out + 4, id & 65535);
        frag_write16(out + 6, (unsigned)(offset / 8) | (index + 1 < plan.count ? 0x2000 : 0));
        frag_write16(out + 10, 0);
        uint32_t sum = 0;
        for (size_t n = 0; n < header; n += 2) sum += frag_read16(out + n);
        while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
        frag_write16(out + 10, (~sum) & 65535);
    } else {
        frag_copy(out, data, plan.payload);
        out[plan.next_header_field] = 44;
        frag_write16(out + 4, (unsigned)(length - 40));
        out[plan.payload] = data[plan.next_header_field];
        out[plan.payload + 1] = 0;
        frag_write16(out + plan.payload + 2, (unsigned)offset | (index + 1 < plan.count ? 1 : 0));
        out[plan.payload + 4] = (uint8_t)(id >> 24);
        out[plan.payload + 5] = (uint8_t)(id >> 16);
        out[plan.payload + 6] = (uint8_t)(id >> 8);
        out[plan.payload + 7] = (uint8_t)id;
    }
    frag_copy(out + header, data + plan.payload + offset, content);
    return length;
}
