#pragma once
#include <stddef.h>
#include <stdint.h>
#define AIVPN_ASSEMBLY_LIMIT 32
#define AIVPN_ASSEMBLY_BYTES 65535
#define AIVPN_ASSEMBLY_HEADER 2096

typedef struct {
    unsigned used, poisoned, family, protocol, id;
    uint64_t created, context;
    uint8_t source[16], destination[16];
    size_t total, received, header_size, next_header_field;
    unsigned have_last, have_first;
    uint8_t covered[1024];
    uint8_t header[AIVPN_ASSEMBLY_HEADER];
    uint8_t data[AIVPN_ASSEMBLY_BYTES];
} AIVPN_ASSEMBLY;
typedef struct { AIVPN_ASSEMBLY slots[AIVPN_ASSEMBLY_LIMIT]; } AIVPN_REASSEMBLER;
size_t aivpn_reassembly_size(void);
int aivpn_fragment_kind(const uint8_t *raw, size_t size);
int aivpn_reassemble(AIVPN_REASSEMBLER *state, const uint8_t *raw, size_t size,
    uint64_t now_ms, uint8_t *out, size_t capacity, size_t *length);
int aivpn_reassemble_scoped(AIVPN_REASSEMBLER *state, uint64_t context,
    const uint8_t *raw, size_t size, uint64_t now_ms,
    uint8_t *out, size_t capacity, size_t *length);
