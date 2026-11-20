#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/cdefs.h>
#include "../../native/linux/admission-word.h"
#include "../../native/linux/routing.h"
#include "../../native/linux/flow-order.h"
#include <string.h>

static unsigned long long word;
static pthread_barrier_t barrier;
static int updated, admitted;
static unsigned long long next_id;
static unsigned long long reserved[2][1024];
static void *allocate_ids(void *argument) {
    unsigned slot = (uintptr_t)argument;
    for (unsigned index = 0; index < 1024; index++) {
        unsigned long long id;
        do { id = sa_next_id(&next_id); } while (!id);
        reserved[slot][index] = id;
    }
    return 0;
}
static void verify_allocator_and_detach(void) {
    pthread_t left, right;
    assert(!pthread_create(&left, 0, allocate_ids, (void *)0));
    assert(!pthread_create(&right, 0, allocate_ids, (void *)1));
    assert(!pthread_join(left, 0) && !pthread_join(right, 0));
    unsigned char seen[2049] = {};
    for (unsigned slot = 0; slot < 2; slot++)
        for (unsigned index = 0; index < 1024; index++) {
            unsigned long long id = reserved[slot][index];
            assert(id && id <= 2048 && !seen[id]);
            seen[id] = 1;
        }
    next_id = SA_ID_LIMIT - 1;
    assert(sa_next_id(&next_id) == SA_ID_LIMIT);
    assert(!sa_next_id(&next_id) && next_id == SA_ID_LIMIT);
    word = 5;
    assert(sa_gc_claim(&word, 5));
    assert(!sa_claim(&word, 5) && !sa_admit(&word, 5));
    assert(sa_gc_finish(&word, 5, 0) && word == 5);
    assert(sa_gc_claim(&word, 5) && sa_gc_finish(&word, 5, 1));
    assert(word == SA_RETIRED && !sa_claim(&word, word));
    assert(!sa_publish(&word, 5, 2) && !sa_admit(&word, 5));
    word = 4;
    assert(sa_claim(&word, 4));
    assert(!sa_gc_claim(&word, word));
    assert(sa_publish(&word, 4, 2));
    assert(!sa_gc_claim(&word, 4));
    assert(sa_gc_claim(&word, 8) && sa_gc_finish(&word, 8, 1));
    assert(!sa_claim(&word, 8));
}
static void *refresh(void *unused) {
    (void)unused;
    pthread_barrier_wait(&barrier);
    updated = sa_claim(&word, 4);
    if (updated) assert(sa_publish(&word, 4, 2));
    return 0;
}
static void *admit(void *unused) {
    (void)unused;
    pthread_barrier_wait(&barrier);
    admitted = sa_admit(&word, 4);
    return 0;
}
static void verify_flow_order(void) {
    struct flow_key left = {}, right = {};
    for (unsigned index = 0; index < 16; index++) {
        for (unsigned value = 1; value < 256; value++) {
            right.destination[index] = value;
            assert(ss_key_order(&left, &right) < 0);
            assert(ss_key_order(&right, &left) > 0);
            assert(ss_key_order(&right, &right) == 0);
            right.destination[index] = 0;
        }
        left.destination[index] = 1;
        right.destination[index] = 2;
        memset(left.destination + index + 1, 255, 15 - index);
        assert(ss_key_order(&left, &right) < 0);
        memset(&left, 0, sizeof(left));
        memset(&right, 0, sizeof(right));
    }
    left.cookie = 1ULL << 63;
    right.cookie = (1ULL << 63) - 1;
    memset(right.destination, 255, sizeof(right.destination));
    assert(ss_key_order(&left, &right) > 0);
    left = right;
    left.protocol = 6; right.protocol = 17;
    left.port = 65535; right.port = 1;
    assert(ss_key_order(&left, &right) < 0);
}
int main(void) {
    verify_flow_order();
    verify_allocator_and_detach();
    for (unsigned i = 0; i < 128; i++) {
        word = 4; updated = admitted = 0;
        pthread_t left, right;
        assert(!pthread_barrier_init(&barrier, 0, 2));
        assert(!pthread_create(&left, 0, refresh, 0));
        assert(!pthread_create(&right, 0, admit, 0));
        assert(!pthread_join(left, 0) && !pthread_join(right, 0));
        assert(!pthread_barrier_destroy(&barrier));
        assert(updated + admitted == 1);
        assert(sa_read(&word) == (admitted ? 5 : 8));
    }
    word = 4;
    assert(sa_retire(&word, 4) && !sa_admit(&word, 4));
    assert(sa_claim(&word, 6) && !sa_admit(&word, 6));
    assert(!sa_publish(&word, 6, 1));
    assert(sa_publish(&word, 6, 2) && !sa_admit(&word, 4));
    assert(!sa_retire(&word, 4) && sa_admit(&word, 8));
    assert(!sa_claim(&word, 9));
    assert(sa_retire(&word, 9) && !sa_admit(&word, 9));
    word = SA_ID_LIMIT << 2;
    assert(sa_claim(&word, word));
    assert(!sa_publish(&word, SA_ID_LIMIT << 2, 0));
    assert(!sa_publish(&word, SA_ID_LIMIT << 2, SA_ID_LIMIT));
    puts("CAS_MODEL_PASS race=128 gc=retirement aba=fresh-id overflow=closed");
}
