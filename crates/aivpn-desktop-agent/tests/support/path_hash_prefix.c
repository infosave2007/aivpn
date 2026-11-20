#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../../native/linux/kernel-policy/path_hash.h"

static void same(struct ph_hash left, struct ph_hash right) {
    assert(left.low == right.low && left.high == right.high);
}

static void split_path(const unsigned char *bytes, unsigned length, unsigned split) {
    struct ph_stream stream;
    ph_stream_init(&stream, 0x0123456789abcdefULL, 0xfedcba9876543210ULL);
    assert(!ph_stream_write(&stream, bytes, split));
    struct ph_stream saved = stream;
    assert(!ph_stream_write(&stream, bytes + split, length - split));
    struct ph_hash expected = ph_path(bytes, length, 0x0123456789abcdefULL, 0xfedcba9876543210ULL);
    same(ph_stream_digest(&stream), expected);
    same(ph_stream_digest(&stream), expected);
    struct ph_stream again = saved;
    assert(!ph_stream_write(&again, bytes + split, length - split));
    same(ph_stream_digest(&again), expected);
}

int main(void) {
    unsigned char bytes[4096];
    for (unsigned index = 0; index < sizeof(bytes); index++)
        bytes[index] = (unsigned char)(index * 37U + 1U);
    for (unsigned length = 0; length < 130; length++)
        for (unsigned split = 0; split <= length; split++)
            split_path(bytes, length, split);
    const unsigned split[] = {0, 1, 7, 8, 9, 2047, 4087, 4088, 4094, 4095};
    for (unsigned index = 0; index < sizeof(split) / sizeof(split[0]); index++)
        split_path(bytes, 4095, split[index]);

    const unsigned char directory[] = "/home/user/каталог";
    const unsigned char suffix[] = "/bin/tool";
    unsigned char full[256];
    unsigned prefix_length = sizeof(directory) - 1, suffix_length = sizeof(suffix) - 1;
    memcpy(full, directory, prefix_length);
    memcpy(full + prefix_length, suffix, suffix_length);
    struct ph_stream prefix;
    ph_stream_init(&prefix, 1, 2);
    assert(!ph_stream_write(&prefix, directory, prefix_length));
    struct ph_stream child = prefix;
    assert(!ph_stream_write(&child, suffix, suffix_length));
    same(ph_stream_digest(&child), ph_path(full, prefix_length + suffix_length, 1, 2));
    same(ph_stream_digest(&prefix), ph_path(directory, prefix_length, 1, 2));

    ph_stream_init(&prefix, 3, 4);
    assert(!ph_stream_write(&prefix, bytes, 4095));
    struct ph_stream before = prefix;
    assert(ph_stream_write(&prefix, bytes, 1) == -1);
    assert(!memcmp(&prefix, &before, sizeof(prefix)));
    ph_stream_init(&prefix, 3, 4);
    before = prefix;
    assert(ph_stream_write(&prefix, bytes, 4096) == -1);
    assert(!memcmp(&prefix, &before, sizeof(prefix)));
    puts("PREFIX_HASH_PASS");
    return 0;
}
