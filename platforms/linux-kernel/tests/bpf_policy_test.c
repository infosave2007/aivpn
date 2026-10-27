// SPDX-License-Identifier: GPL-2.0
/* Реальные XDP/TC функции с userspace-заменами BPF helpers. Сеть не меняется. */
#define _GNU_SOURCE
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

static void *lookup_result;
static __u64 now_ns = 1000000000ULL;
static pthread_mutex_t budget_lock = PTHREAD_MUTEX_INITIALIZER;
static void *mock_lookup(const void *map, const void *key)
{
	(void)map; (void)key;
	return lookup_result;
}
static void *mock_reserve(void *map, __u64 size, __u64 flags)
{
	(void)map; (void)size; (void)flags;
	return NULL;
}
static __u64 mock_time(void) { return now_ns; }
static long mock_store(struct __sk_buff *skb, __u32 offset, const void *from,
		       __u32 len, __u64 flags)
{
	(void)flags;
	memcpy((char *)(uintptr_t)skb->data + offset, from, len);
	return 0;
}
static __attribute__((unused)) long mock_csum(struct __sk_buff *skb,
		__u32 offset, __u64 from, __u64 to, __u64 size)
{
	__u16 *check = (void *)((char *)(uintptr_t)skb->data + offset);
	unsigned int sum;
	assert(size == 2);
	sum = (~*check & 0xffff) + (~from & 0xffff) + (to & 0xffff);
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	*check = ~sum;
	return 0;
}
static __attribute__((unused)) long mock_lock(struct bpf_spin_lock *lock)
{
	(void)lock;
	return pthread_mutex_lock(&budget_lock);
}
static __attribute__((unused)) long mock_unlock(struct bpf_spin_lock *lock)
{
	(void)lock;
	return pthread_mutex_unlock(&budget_lock);
}
#define bpf_map_lookup_elem mock_lookup
#define bpf_ringbuf_reserve mock_reserve
#define bpf_ktime_get_ns mock_time
#define bpf_skb_store_bytes mock_store
#define bpf_l3_csum_replace mock_csum
#define bpf_spin_lock(lock) mock_lock(lock)
#define bpf_spin_unlock(lock) mock_unlock(lock)
#define _license xdp_license
#include "../src/xdp_prog.c"
#undef _license
#include "../../../deploy/ebpf/tc_qos_prog.c"

static int failures;
#define CHECK(cond, name) do { \
	int passed = !!(cond); \
	printf("%s: %s\n", (name), passed ? "PASS" : "FAIL"); \
	if (!passed) failures++; \
} while (0)

static unsigned checksum(const unsigned char *p)
{
	unsigned sum = 0;
	for (int i = 0; i < (p[0] & 15) * 4; i += 2)
		sum += (p[i] << 8) | p[i + 1];
	while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
	return (~sum) & 65535;
}

#define ROUNDS 4000
static pthread_barrier_t turn;
static struct __sk_buff tc_context;
static int decisions[2];
static void *competing_packet(void *arg)
{
	unsigned index = (uintptr_t)arg;
	for (int i = 0; i < ROUNDS; i++) {
		pthread_barrier_wait(&turn);
		decisions[index] = tc_qos_egress(&tc_context);
		pthread_barrier_wait(&turn);
	}
	return NULL;
}

int main(void)
{
	/* __sk_buff хранит userspace-адрес в u32, поэтому нужен низкий диапазон. */
	unsigned char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
	assert(p != MAP_FAILED);
	/* Сдвиг на 2 выравнивает IPv4 после 14-байтного Ethernet. */
	struct ethhdr *eth = (void *)(p + 2);
	struct iphdr *ip = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip + 1);
	eth->h_proto = __builtin_bswap16(ETH_P_IP);
	ip->ihl = 5; ip->version = 4; ip->protocol = IPPROTO_UDP;
	udp->dest = __builtin_bswap16(53);
	udp->len = __builtin_bswap16(20);
	struct xdp_md xdp = {
		.data = (__u32)(uintptr_t)(p + 2),
		.data_end = (__u32)(uintptr_t)(p + 2 + sizeof(*eth) + 20 + 20),
	};
	__u64 port = 0;
	lookup_result = &port;
	CHECK(aivpn_xdp_filter(&xdp) == XDP_PASS, "XDP без порта пропускает DNS");
	lookup_result = NULL;
	CHECK(aivpn_xdp_filter(&xdp) == XDP_PASS, "XDP без config пропускает DNS");
	lookup_result = &port; port = 443;
	CHECK(aivpn_xdp_filter(&xdp) == XDP_PASS, "XDP чужой порт");
	udp->dest = __builtin_bswap16(443);
	CHECK(aivpn_xdp_filter(&xdp) == XDP_DROP, "XDP короткий VPN пакет");

	memset(p, 0, 4096);
	ip = (void *)p; ip->version = 4; ip->ihl = 6; ip->ttl = 64; ip->tos = 3;
	ip->tot_len = __builtin_bswap16(1400); ip->protocol = IPPROTO_UDP;
	ip->check = __builtin_bswap16(checksum(p));
	struct qos_rule rule = { .dscp = 46 };
	lookup_result = &rule;
	tc_context = (struct __sk_buff){ .data = (__u32)(uintptr_t)p,
		.data_end = (__u32)(uintptr_t)(p + 1400), .len = 1400 };
	assert(checksum(p) == 0);
	int verdict = tc_qos_egress(&tc_context);
	CHECK(verdict == TC_ACT_OK && checksum(p) == 0 && ip->tos == 187,
	      "TC DSCP сохраняет checksum, options и ECN");
	rule.dscp = 0; rule.rate_bps = 10000; rule.tokens = 1000;
	for (int i = 0; i < 3; ++i) {
		now_ns += 1000000000ULL;
		CHECK(tc_qos_egress(&tc_context) == TC_ACT_OK, "TC низкая скорость допускает MTU");
	}
	rule.rate_bps = 10; rule.tokens = 0; rule.last_refill_ns = now_ns;
	for (int i = 0; i < 100; ++i) {
		now_ns += 1000000ULL;
		tc_qos_egress(&tc_context);
	}
	CHECK(rule.tokens == 1, "TC частые отказы не теряют дробное пополнение");
	/* Между раундами главный поток сбрасывает бюджет, внутри идут два CPU. */
	pthread_t workers[2];
	pthread_barrier_init(&turn, NULL, 3);
	tc_context.len = 600;
	for (unsigned i = 0; i < 2; i++)
		assert(pthread_create(&workers[i], NULL, competing_packet, (void *)(uintptr_t)i) == 0);
	unsigned overspent = 0;
	for (int i = 0; i < ROUNDS; i++) {
		rule.tokens = 1000; rule.last_refill_ns = now_ns;
		pthread_barrier_wait(&turn);
		pthread_barrier_wait(&turn);
		if (decisions[0] == TC_ACT_OK && decisions[1] == TC_ACT_OK) overspent++;
	}
	for (unsigned i = 0; i < 2; i++) pthread_join(workers[i], NULL);
	pthread_barrier_destroy(&turn);
	CHECK(overspent == 0, "TC параллельные пакеты не расходуют бюджет дважды");
	munmap(p, 4096);
	return failures ? 1 : 0;
}
