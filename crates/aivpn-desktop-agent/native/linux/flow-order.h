#pragma once
static __always_inline AP_U64 ss_address_word(const AP_U8 *address) {
    AP_U64 word;
    __builtin_memcpy(&word, address, sizeof(word));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    word = __builtin_bswap64(word);
#endif
    return word;
}
/* Порядок совпадает с побайтовым сравнением, без 16 веток на каждый RB шаг. */
static __always_inline int ss_key_order(const struct flow_key *left, const struct flow_key *right) {
    if (left->cookie != right->cookie) return left->cookie < right->cookie ? -1 : 1;
    if (left->family != right->family) return left->family < right->family ? -1 : 1;
    if (left->protocol != right->protocol) return left->protocol < right->protocol ? -1 : 1;
    if (left->port != right->port) return left->port < right->port ? -1 : 1;
    if (left->padding != right->padding) return left->padding < right->padding ? -1 : 1;
    for (unsigned i = 0; i < 16; i += 8) {
        AP_U64 a = ss_address_word(left->destination + i);
        AP_U64 b = ss_address_word(right->destination + i);
        if (a != b) return a < b ? -1 : 1;
    }
    return 0;
}
