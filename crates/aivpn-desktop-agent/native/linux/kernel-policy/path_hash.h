#pragma once
/* SipHash-2-4-128, по CC0 reference veorq/SipHash. */
#ifdef AIVPN_BPF
#define PH_U64 __u64
#define PH_U8 __u8
#else
#include <stdint.h>
#define PH_U64 uint64_t
#define PH_U8 uint8_t
#endif
struct ph_state {
    PH_U64 a, b, c, d;
};
struct ph_hash {
    PH_U64 low, high;
};
/* Состояние до финализации позволяет дописать относительный путь к каталогу. */
struct ph_stream {
    struct ph_state state;
    PH_U64 tail;
    volatile PH_U64 length;
};
static __inline PH_U64 ph_rotate(PH_U64 value, unsigned count) {
    return (value << count) | (value >> (64 - count));
}
static __inline void ph_round(struct ph_state *s) {
    s->a += s->b;
    s->b = ph_rotate(s->b, 13);
    s->b ^= s->a;
    s->a = ph_rotate(s->a, 32);
    s->c += s->d;
    s->d = ph_rotate(s->d, 16);
    s->d ^= s->c;
    s->a += s->d;
    s->d = ph_rotate(s->d, 21);
    s->d ^= s->a;
    s->c += s->b;
    s->b = ph_rotate(s->b, 17);
    s->b ^= s->c;
    s->c = ph_rotate(s->c, 32);
}
static __inline PH_U64 ph_word(const PH_U8 *bytes) {
    PH_U64 word = 0;
    for (unsigned j = 0; j < 8; j++)
        word |= (PH_U64)bytes[j] << (j * 8);
    return word;
}
static __inline void ph_stream_init(struct ph_stream *stream, PH_U64 k0, PH_U64 k1) {
    stream->state = (struct ph_state){
        0x736f6d6570736575ULL ^ k0, 0x646f72616e646f6dULL ^ k1 ^ 0xee,
        0x6c7967656e657261ULL ^ k0, 0x7465646279746573ULL ^ k1,
    };
    stream->tail = stream->length = 0;
}
static __inline int ph_stream_write(struct ph_stream *stream, const PH_U8 *bytes, unsigned length) {
    if (stream->length > 4095 || length > 4095 || length > 4095 - stream->length)
        return -1;
#ifdef AIVPN_BPF
    AP_FOR(offset, 4096) {
#else
    for (unsigned offset = 0; offset < 4096; offset++) {
#endif
        if ((unsigned)offset >= length)
            break;
        unsigned position = (unsigned)stream->length & 7U;
        stream->tail |= (PH_U64)bytes[offset] << (position * 8);
        stream->length++;
        if (position == 7) {
            stream->state.d ^= stream->tail;
            ph_round(&stream->state);
            ph_round(&stream->state);
            stream->state.a ^= stream->tail;
            stream->tail = 0;
        }
    }
    return 0;
}
static __inline __attribute__((always_inline)) struct ph_hash ph_stream_digest(const struct ph_stream *stream) {
    struct ph_state state = stream->state;
    PH_U64 tail = stream->tail | (stream->length << 56);
    state.d ^= tail;
    ph_round(&state);
    ph_round(&state);
    state.a ^= tail;
    state.c ^= 0xee;
    for (unsigned round = 0; round < 4; round++)
        ph_round(&state);
    struct ph_hash hash = {state.a ^ state.b ^ state.c ^ state.d, 0};
    state.b ^= 0xdd;
    for (unsigned round = 0; round < 4; round++)
        ph_round(&state);
    hash.high = state.a ^ state.b ^ state.c ^ state.d;
    return hash;
}
static __inline struct ph_hash ph_path(const PH_U8 *path, unsigned length, PH_U64 k0, PH_U64 k1) {
    struct ph_state s = {0x736f6d6570736575ULL ^ k0, 0x646f72616e646f6dULL ^ k1 ^ 0xee,
                         0x6c7967656e657261ULL ^ k0, 0x7465646279746573ULL ^ k1};
    for (unsigned offset = 0; offset < 4096; offset += 8) {
        if (offset + 8 > length)
            break;
        PH_U64 word = ph_word(path + offset);
        s.d ^= word;
        ph_round(&s);
        ph_round(&s);
        s.a ^= word;
    }
    PH_U64 tail = (PH_U64)length << 56;
    unsigned start = length & ~7U;
    for (unsigned j = 0; j < 7; j++) {
        if (start + j >= length)
            break;
        tail |= (PH_U64)path[start + j] << (j * 8);
    }
    s.d ^= tail;
    ph_round(&s);
    ph_round(&s);
    s.a ^= tail;
    s.c ^= 0xee;
    for (unsigned j = 0; j < 4; j++)
        ph_round(&s);
    struct ph_hash hash = {s.a ^ s.b ^ s.c ^ s.d, 0};
    s.b ^= 0xdd;
    for (unsigned j = 0; j < 4; j++)
        ph_round(&s);
    hash.high = s.a ^ s.b ^ s.c ^ s.d;
    return hash;
}
