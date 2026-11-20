#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/cdefs.h>
#define __u8 unsigned char
#define __u32 unsigned int
#define __u64 unsigned long long
#define __kptr
#define __ksym
#define __noinline __attribute__((noinline))
#define __uint(name, value) int (*name)[value]
#define __type(name, type) type *name
#define SEC(name)
#define BPF_MAP_TYPE_SK_STORAGE 24
#define BPF_F_NO_PREALLOC 1
#define BPF_F_CLONE 512
#define BPF_LOCAL_STORAGE_GET_F_CREATE 1
#define bpf_core_type_id_local(type) sizeof(type)
#define container_of(pointer, type, field) ((type *)((char *)(pointer) - offsetof(type, field)))
#define bpf_kptr_xchg(slot, value) __atomic_exchange_n(slot, value, __ATOMIC_SEQ_CST)
#define AP_BINDING_SNAPSHOT 1
#include "../../native/linux/routing.h"
struct bpf_refcount { unsigned value; };
struct bpf_spin_lock { unsigned value; };
struct bpf_rb_node { struct bpf_rb_node *left, *right; };
struct bpf_rb_root { struct bpf_rb_node *node; };
static unsigned locked;
static unsigned long long now = 1;
static void (*clock_interleave)(void);
static void (*acquire_interleave)(void);
static unsigned long long bpf_ktime_get_ns(void) {
    assert(!locked);
    void (*interleave)(void) = clock_interleave;
    clock_interleave = NULL;
    if (interleave) interleave();
    return now;
}
static void bpf_spin_lock(struct bpf_spin_lock *lock) { (void)lock; assert(!locked); locked = 1; }
static void bpf_spin_unlock(struct bpf_spin_lock *lock) { (void)lock; assert(locked); locked = 0; }
static void bpf_rcu_read_lock(void) {}
static void bpf_rcu_read_unlock(void) {}
static void *bpf_sk_storage_get(void *map, void *socket, void *initial, unsigned flags);
static unsigned long long bpf_get_socket_cookie(void *socket);
static void copy_process_state(struct process_state *to, const struct process_state *from) { *to = *from; }
static void copy_process_companion(struct process_companion *to, const struct process_companion *from) {
    if (from) *to = *from; else memset(to, 0, sizeof(*to));
}
#include "../../native/linux/snapshot-socket-state.h"
#define BPF_NOEXIST 1
extern void *bpf_map_lookup_elem(void *, const void *);
extern int bpf_map_update_elem(void *, const void *, const void *, unsigned long long);
extern int bpf_map_delete_elem(void *, const void *);
#include "../../native/linux/snapshot-cache-state.h"
struct model_socket { unsigned long long cookie; struct ss_state state; struct process_companion mate; };
struct allocation { unsigned refs, size; };
static unsigned allocations, frees, fail_after;
static unsigned model_references(const void *object) {
    return ((const struct allocation *)object - 1)->refs;
}
void *bpf_obj_new_impl(__u64 type, void *meta) {
    (void)meta; assert(!locked);
    if (fail_after && --fail_after == 0) return 0;
    struct allocation *header = calloc(1, sizeof(*header) + type);
    assert(header); header->refs = 1; header->size = type; allocations++;
    void *object = header + 1;
    /* Ядро инициализирует специальные поля, а обычные байты могут остаться от прошлого объекта. */
    if (type == sizeof(struct ss_flow)) {
        struct ss_flow *flow = object;
        flow->references.value = 1;
        memset(&flow->key, 0xa5, type - offsetof(struct ss_flow, key));
    } else if (type == sizeof(struct ss_table)) {
        struct ss_table *table = object;
        table->references.value = 1;
        memset(&table->epoch, 0xa5, type - offsetof(struct ss_table, epoch));
    } else if (type == sizeof(struct ss_lifetime)) {
        struct ss_lifetime *token = object;
        token->references.value = 1;
        memset(&token->alive, 0xa5, type - offsetof(struct ss_lifetime, alive));
    } else if (type == sizeof(struct ss_node)) {
        struct ss_node *node = object;
        node->references.value = 1;
        memset(&node->key, 0xa5, sizeof(node->key));
    } else {
        assert(!"Неизвестный тип объекта BPF в модели");
    }
    return object;
}
void *bpf_refcount_acquire_impl(void *object, void *meta) {
    (void)meta; struct allocation *header = (struct allocation *)object - 1;
    assert(header->refs);
    void (*interleave)(void) = acquire_interleave;
    acquire_interleave = NULL;
    if (interleave) interleave();
    header->refs++; return object;
}
void bpf_obj_drop_impl(void *object, void *meta) {
    (void)meta; assert(!locked);
    struct allocation *header = (struct allocation *)object - 1;
    assert(header->refs); if (--header->refs) return;
    if (header->size == sizeof(struct ss_node)) {
        struct ss_node *node = object;
        if (node->flow) bpf_obj_drop_impl(node->flow, 0);
    } else if (header->size == sizeof(struct ss_table)) {
        struct ss_table *table = object;
        struct bpf_rb_root *roots[] = {&table->flows, &table->other_flows};
        for (unsigned i = 0; i < 2; i++) while (roots[i]->node) {
            struct bpf_rb_node *node = roots[i]->node;
            assert(!node->left && !node->right);
            roots[i]->node = 0;
            bpf_obj_drop_impl(container_of(node, struct ss_node, link), 0);
        }
    }
    frees++; free(header);
}
int bpf_rbtree_add_impl(struct bpf_rb_root *root, struct bpf_rb_node *node,
                       bool (*less)(struct bpf_rb_node *, const struct bpf_rb_node *), void *meta, __u64 offset) {
    (void)less; (void)meta; (void)offset; assert(locked && !root->node);
    root->node = node; return 0;
}
struct bpf_rb_node *bpf_rbtree_root(struct bpf_rb_root *root) { assert(locked); return root->node; }
struct bpf_rb_node *bpf_rbtree_first(struct bpf_rb_root *root) { assert(locked); return root->node; }
struct bpf_rb_node *bpf_rbtree_left(struct bpf_rb_root *root, struct bpf_rb_node *node) { (void)root; return node->left; }
struct bpf_rb_node *bpf_rbtree_right(struct bpf_rb_root *root, struct bpf_rb_node *node) { (void)root; return node->right; }
struct bpf_rb_node *bpf_rbtree_remove(struct bpf_rb_root *root, struct bpf_rb_node *node) {
    assert(locked && root->node == node); root->node = 0; return node;
}
static void *bpf_sk_storage_get(void *map, void *socket, void *initial, unsigned flags) {
    (void)initial; (void)flags;
    struct model_socket *saved = socket;
    return map == &socket_states ? (void *)&saved->state : (void *)&saved->mate;
}
static unsigned long long bpf_get_socket_cookie(void *socket) { return ((struct model_socket *)socket)->cookie; }
static void cleanup(struct model_socket *socket) {
    ss_mark_closed(socket);
    ss_clear_handles(&socket->state);
    if (socket->state.table) bpf_obj_drop_impl(socket->state.table, 0);
    if (socket->state.query) bpf_obj_drop_impl(socket->state.query, 0);
    if (socket->state.lifetime) bpf_obj_drop_impl(socket->state.lifetime, 0);
    memset(&socket->state, 0, sizeof(socket->state));
    assert(allocations == frees);
}
static void preserved_adoption(void) {
    struct model_socket socket = {.cookie = 21};
    struct flow_key key = {.cookie = 21, .protocol = 6, .family = 4, .port = 443};
    struct ss_request request = {.system_device = 33, .source_port = 1200};
    struct ss_state *state = ss_bootstrap_preserved(&socket, &key, &request);
    assert(state && state->kind == SS_PRESERVED && !state->table && !state->query);
    struct ss_flow *payload = state->direct_flow;
    struct ss_lifetime *token = state->lifetime;
    __u64 word = payload->publication;
    assert(sa_admit(&payload->publication, word));
    assert(ss_adopt_cookie(&socket, socket.cookie) == state);
    assert(state->table && state->query && state->direct_flow == payload && state->lifetime == token);
    assert(payload->publication == (word | SA_ADMITTED) && token->next_id == 1);
    assert(!ss_bootstrap_preserved(&socket, &key, &request));
    cleanup(&socket);
    socket.state.kind = SS_CLASSIFIED;
    socket.state.known_creator = 1;
    assert(!ss_bootstrap_preserved(&socket, &key, &request));
    memset(&socket.state, 0, sizeof(socket.state));
    for (unsigned failure = 1; failure <= 2; failure++) {
        fail_after = failure;
        assert(!ss_bootstrap_preserved(&socket, &key, &request));
        assert(socket.state.kind == SS_EMPTY && !socket.state.lifetime && !socket.state.direct_flow);
        assert(allocations == frees);
    }
}
static void payload_gc(void) {
    struct model_socket socket = {.cookie = 25};
    struct ss_state *state = ss_initialize_cookie(&socket, socket.cookie, 0, SS_PRESERVED, 0);
    assert(state);
    struct ss_table *table = state->table;
    struct flow_key key = {.cookie = 25, .protocol = 17, .family = 4, .port = 53};
    struct cached_route route = {.binding_epoch = 100};
    struct ss_record record = {};
    assert(!ss_freeze_for(state, table, &key, &route, &record));
    struct ss_node *wrapper = ss_wrapper_acquire(table, &key);
    assert(wrapper);
    struct ss_flow *transferred = bpf_kptr_xchg(&wrapper->flow, 0);
    assert(transferred && ss_read(table, &key, &record, 0) < 0);
    assert(ss_freeze_for(state, table, &key, &route, &record) < 0 && table->count == 1);
    assert(!bpf_kptr_xchg(&wrapper->flow, transferred));
    bpf_obj_drop_impl(wrapper, 0);
    struct ss_flow *flow = ss_find_acquire(table, &key);
    assert(flow && sa_admit(&flow->publication, flow->publication));
    now += SS_IDLE_NS + 1;
    __u64 word = flow->publication;
    ss_touch(flow, now);
    assert(!ss_end_interval(flow, word, now));
    now += SS_IDLE_NS + 1;
    assert(ss_end_interval(flow, word, now));
    struct ss_request request = {.expected_id = record.id, .renew = 1, .now = now};
    request.new_id = ss_reserve_id(state->lifetime, key.cookie, table->epoch);
    route.binding_epoch++;
    assert(ss_update_node(flow, &request, &route) == 1);
    assert(flow->route.binding_epoch == 101 && flow->id == request.new_id);
    assert(sa_admit(&flow->publication, flow->publication));
    now += SS_IDLE_NS + 1;
    ss_collect(state, table, 1);
    assert(!table->count && flow->publication == SA_RETIRED);
    request.expected_id = flow->id;
    request.new_id = ss_reserve_id(state->lifetime, key.cookie, table->epoch);
    assert(ss_update_node(flow, &request, &route) < 0 && flow->publication == SA_RETIRED);
    assert(!ss_find_acquire(table, &key));
    bpf_obj_drop_impl(flow, 0);
    cleanup(&socket);
}
static struct ss_flow *reading_flow;
static void admit_during_read(void) {
    assert(sa_admit(&reading_flow->publication, reading_flow->publication));
}
static void retire_during_read(void) {
    assert(sa_retire(&reading_flow->publication, reading_flow->publication));
}
static void admission_during_payload_read(void) {
    struct ss_flow flow = {.key = {.protocol = 6}, .id = 1, .publication = 1ULL << 2,
                          .route = {.decision = {.action = 2, .profile = 7}, .network_generation = 9}};
    struct ss_record record = {};
    reading_flow = &flow;
    /* Второй участник допускает тот же маршрут между двумя чтениями publication. */
    clock_interleave = admit_during_read;
    assert(ss_flow_read(&flow, &record, 1) == 1);
    assert(record.admitted && record.id == 1 && record.route.network_generation == 9);
    clock_interleave = retire_during_read;
    int result = ss_flow_read(&flow, &record, 1);
    assert(result != 1);
    if (result > 0) assert(!record.admitted);
    reading_flow = NULL;
}
static void concurrent_cache_readers(void) {
    struct ss_flow flow = {.key = {.cookie = 91, .protocol = 6}, .id = 1,
                          .epoch = 4, .publication = (1ULL << 2) | SA_ADMITTED,
                          .route = {.decision = {.action = 2, .profile = 7}, .network_generation = 9}};
    struct ss_lifetime token = {.alive = 1, .cookie = 91, .epoch = 4};
    struct cc_entry entry = {.lock = 1, .cookie = 91, .epoch = 4, .id = 1,
                             .sequence = 2, .node = &flow, .lifetime = &token};
    struct cc_snapshot snapshot = {};
    /* Другой читатель удерживает lock, опубликованные данные не меняются. */
    assert(cc_read(&entry, &snapshot));
    assert(snapshot.cookie == 91 && snapshot.id == 1 && snapshot.admission == 1);
    /* Незавершенная публикация и отозванный lifetime остаются запрещенными. */
    entry.sequence = 3;
    assert(!cc_read(&entry, &snapshot));
    entry.sequence = 4;
    token.alive = 0;
    assert(!cc_read(&entry, &snapshot));
    token.alive = 1;
    entry.retired = 1;
    assert(!cc_read(&entry, &snapshot));
    entry.retired = 0;
    entry.cookie = 92;
    assert(!cc_read(&entry, &snapshot));
    entry.cookie = 91;
    entry.node = NULL;
    assert(!cc_read(&entry, &snapshot));
}
static struct ss_node *reading_wrapper;
static struct cc_entry reading_cache;
static struct flow_key reading_key;
static struct ss_lifetime *reading_token;
static struct ss_flow *nested_payload;
static void acquire_during_payload_read(void) {
    nested_payload = cc_acquire_admitted_flow(&reading_cache, &reading_key, reading_token);
}
static void expire_during_reference_read(void) {
    reading_token->alive = 0;
}
static void replace_during_reference_read(void) {
    reading_cache.sequence += 2;
}
static void retire_during_proof_read(void) {
    struct ss_flow *flow = reading_cache.node;
    assert(sa_retire(&flow->publication, sa_read(&flow->publication)));
}
static void concurrent_admitted_readers(void) {
    struct model_socket socket = {.cookie = 96};
    struct ss_state *state = ss_initialize_cookie(&socket, socket.cookie, 0, SS_PRESERVED, 0);
    assert(state);
    struct flow_key key = {.cookie = 96, .protocol = 17, .family = 4, .port = 443};
    struct cached_route route = {.binding_epoch = 11};
    struct ss_record record = {};
    assert(!ss_freeze_for(state, state->table, &key, &route, &record));
    reading_wrapper = ss_wrapper_acquire(state->table, &key);
    assert(reading_wrapper);
    struct ss_flow *canonical = ss_payload_acquire(reading_wrapper);
    assert(canonical && sa_admit(&canonical->publication, canonical->publication));
    reading_key = key;
    reading_token = state->lifetime;
    reading_cache = (struct cc_entry){.cookie=key.cookie, .epoch=canonical->epoch,
        .node=canonical, .lifetime=reading_token, .id=record.id, .sequence=2};
    nested_payload = NULL;
    acquire_interleave = acquire_during_payload_read;
    struct ss_flow *first = cc_acquire_admitted_flow(&reading_cache, &reading_key, reading_token);
    /* Прием и отправка одного UDP-сокета читают одну неизменную authority. */
    assert(first && nested_payload && first == nested_payload);
    reading_cache.sequence = 3;
    assert(!cc_acquire_admitted_flow(&reading_cache, &reading_key, reading_token));
    reading_cache.sequence = 4;
    reading_cache.retired = 1;
    assert(!cc_acquire_admitted_flow(&reading_cache, &reading_key, reading_token));
    reading_cache.retired = 0;
    struct ss_lifetime foreign = *reading_token;
    assert(!cc_acquire_admitted_flow(&reading_cache, &reading_key, &foreign));
    reading_key.port++;
    assert(!cc_acquire_admitted_flow(&reading_cache, &reading_key, reading_token));
    reading_key.port--;
    struct ss_request request = {.expected_epoch=canonical->epoch,
        .expected_id=record.id, .confirm=3};
    struct ss_record proof = record;
    proof.admitted = 1;
    reading_cache.admission = (record.id << 2) | SA_ADMITTED;
    reading_cache.route = route;
    /* Параллельный читатель не меняет снимок и не должен мешать приему. */
    reading_cache.lock = 1;
    assert(cc_proof(&reading_cache, &key, &request, &proof, 0) == 1);
    assert(proof.admitted && reading_cache.lock == 1);
    reading_cache.lock = 0;
    __u64 sequence = reading_cache.sequence;
    assert(!cc_sync_proof(&reading_cache, &key, &proof, canonical->epoch));
    assert(reading_cache.sequence == sequence);
    reading_cache.route.network_generation++;
    assert(!cc_sync_proof(&reading_cache, &key, &proof, canonical->epoch));
    assert(reading_cache.sequence == sequence + 2 &&
           reading_cache.route.network_generation == proof.route.network_generation);
    clock_interleave = expire_during_reference_read;
    assert(cc_proof(&reading_cache, &key, &request, &proof, 0) < 0);
    reading_token->alive = 1;
    clock_interleave = replace_during_reference_read;
    assert(cc_proof(&reading_cache, &key, &request, &proof, 0) < 0);
    reading_cache.sequence |= 1;
    assert(cc_proof(&reading_cache, &key, &request, &proof, 0) < 0);
    reading_cache.sequence++;
    request.expected_id++;
    assert(cc_proof(&reading_cache, &key, &request, &proof, 0) < 0);
    unsigned references = model_references(canonical);
    acquire_interleave = expire_during_reference_read;
    assert(!cc_acquire_admitted_flow(&reading_cache, &reading_key, reading_token));
    assert(model_references(canonical) == references);
    reading_token->alive = 1;
    acquire_interleave = replace_during_reference_read;
    assert(!cc_acquire_admitted_flow(&reading_cache, &reading_key, reading_token));
    assert(model_references(canonical) == references);
    request.expected_id = record.id;
    clock_interleave = retire_during_proof_read;
    assert(cc_proof(&reading_cache, &key, &request, &proof, 0) < 0);
    assert((canonical->publication & 3) == SA_RETIRED);
    bpf_obj_drop_impl(canonical, 0);
    bpf_obj_drop_impl(first, 0);
    bpf_obj_drop_impl(nested_payload, 0);
    bpf_obj_drop_impl(reading_wrapper, 0);
    reading_wrapper = NULL;
    nested_payload = NULL;
    cleanup(&socket);
}

static void logical_parent_proof_keeps_child_lifetime_bound(void) {
    struct ss_lifetime parent_token = {.alive=1, .cookie=97, .epoch=2};
    struct ss_lifetime child_token = {.alive=1, .cookie=98, .epoch=3};
    struct ss_flow parent = {.key={.cookie=97, .protocol=6, .family=4, .port=443},
        .epoch=2, .publication=(11ULL << 2) | SA_ADMITTED};
    struct ss_flow child = {.key={.cookie=98, .protocol=6, .family=4, .port=443},
        .epoch=3, .parent_cookie=97, .parent_epoch=2, .parent_id=11};
    struct cc_entry cache = {.cookie=98, .epoch=3, .sequence=2,
        .node=&child, .lifetime=&child_token, .logical_node=&parent,
        .logical_lifetime=&parent_token};
    struct ss_request request = {.expected_epoch=3, .expected_id=11, .confirm=3};
    struct ss_record record = {};
    assert(cc_proof(&cache, &parent.key, &request, &record, 1) == 1);
    assert(record.id == 11 && record.admitted);
    child.parent_id++;
    assert(cc_proof(&cache, &parent.key, &request, &record, 1) < 0);
    child.parent_id--;
    child.parent_cookie++;
    assert(cc_proof(&cache, &parent.key, &request, &record, 1) < 0);
    child.parent_cookie--;
    child.parent_epoch++;
    assert(cc_proof(&cache, &parent.key, &request, &record, 1) < 0);
    child.parent_epoch--;
    parent_token.alive = 0;
    assert(cc_proof(&cache, &parent.key, &request, &record, 1) < 0);
    parent_token.alive = 1;
    child_token.alive = 0;
    assert(cc_proof(&cache, &parent.key, &request, &record, 1) < 0);
    child_token.alive = 1;
    request.expected_epoch++;
    assert(cc_proof(&cache, &parent.key, &request, &record, 1) < 0);
    request.expected_epoch--;
    cache.sequence |= 1;
    assert(cc_proof(&cache, &parent.key, &request, &record, 1) < 0);
}

int main(void) {
    preserved_adoption();
    payload_gc();
    admission_during_payload_read();
    concurrent_cache_readers();
    concurrent_admitted_readers();
    logical_parent_proof_keeps_child_lifetime_bound();
    puts("PAYLOAD_MODEL_PASS preserved=same-token gc=terminal nested-kptr=model-only");
}
