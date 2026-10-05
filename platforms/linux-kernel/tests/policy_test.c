/* policy_test.c: userspace проверка общей политики. Модуль ядра не нужен. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "../src/policy.h"

static int fails;

#define CHECK(cond, name) do { \
	if (!(cond)) { \
		fprintf(stderr, "FAIL %s\n", name); \
		fails++; \
	} \
} while (0)

static __u32 raw4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
	uint8_t o[4] = { a, b, c, d };
	__u32 v;

	memcpy(&v, o, 4);
	return v;
}

static void fill_v4(uint8_t *b, unsigned len, __u32 src, __u32 dst)
{
	memset(b, 0, len);
	b[0] = 0x45;
	b[2] = (uint8_t)(len >> 8);
	b[3] = (uint8_t)len;
	memcpy(b + 12, &src, 4);
	memcpy(b + 16, &dst, 4);
}

static void fill_v6(uint8_t *b, unsigned len, const uint8_t src[16],
		    const uint8_t dst[16])
{
	unsigned payload = len - 40;

	memset(b, 0, len);
	b[0] = 0x60;
	b[4] = (uint8_t)(payload >> 8);
	b[5] = (uint8_t)payload;
	b[6] = 6;
	memcpy(b + 8, src, 16);
	memcpy(b + 24, dst, 16);
}

static void prefix64(uint8_t p[16])
{
	memset(p, 0, 16);
	p[0] = 0xfd;
	p[1] = 0x12;
	p[2] = 0x34;
	p[3] = 0x56;
	p[4] = 0x78;
	p[5] = 0x9a;
}

static int peer_only(__u32 ip, void *ctx)
{
	return ip == *(__u32 *)ctx;
}

static void arm(struct aivpn_pol *p, __u32 role, __u32 ip, __u32 flags)
{
	memset(p, 0, sizeof(*p));
	p->version = AIVPN_POLICY_VERSION;
	p->role = role;
	p->flags = flags;
	p->client_ipv4 = ip;
	p->armed = 1;
	prefix64(p->ipv6_prefix);
	p->ipv6_prefix_len = 64;
}

int main(void)
{
	const __u32 self = raw4(10, 0, 0, 2);
	const __u32 other = raw4(10, 0, 0, 3);
	const __u32 inet = raw4(8, 8, 8, 8);
	const __u32 spoof = raw4(10, 0, 0, 9);
	uint8_t pkt[64];
	uint8_t mine[16], peer_v6[16], bad[16], zero[16];
	uint8_t expect[16] = {
		0xfd, 0x12, 0x34, 0x56, 0x78, 0x9a, 0, 0,
		0, 0, 0, 0, 0x0a, 0x00, 0x00, 0x02
	};
	struct aivpn_pol pol;
	struct aivpn_session_policy in;
	uint8_t hdr[32];
	uint8_t tag[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	uint8_t mdh[20];
	unsigned int hdr_len = 0;
	int i;

	_Static_assert(sizeof(struct aivpn_session_add) == 192, "add");
	_Static_assert(sizeof(struct aivpn_session_policy) == 104, "policy");
	_Static_assert(sizeof(struct aivpn_session_sync) == 160, "sync");
	_Static_assert(sizeof(struct aivpn_client_revoke) == 16, "revoke");
	_Static_assert(sizeof(struct aivpn_session_downlink) == 4188, "downlink");
	_Static_assert(offsetof(struct aivpn_session_policy, policy_version) == 16, "pv");
	_Static_assert(offsetof(struct aivpn_session_policy, client_ipv4) == 28, "ip");
	_Static_assert(offsetof(struct aivpn_session_policy, ipv6_prefix) == 32, "p6");
	_Static_assert(offsetof(struct aivpn_session_policy, rate_up_bps) == 52, "ru");
	_Static_assert(offsetof(struct aivpn_session_policy, quota_up_bytes) == 68, "qu");
	_Static_assert(offsetof(struct aivpn_session_policy, max_sessions) == 84, "ms");
	_Static_assert(offsetof(struct aivpn_session_policy, client_key) == 88, "ck");
	_Static_assert(offsetof(struct aivpn_session_sync, replay_hi) == 24, "hi");
	_Static_assert(offsetof(struct aivpn_session_sync, replay_words) == 32, "rw");
	_Static_assert(offsetof(struct aivpn_session_sync, rx_packets) == 96, "rx");
	_Static_assert(offsetof(struct aivpn_session_sync, quota_down_left) == 152, "qd");
	_Static_assert(AIVPN_IOC_SESSION_ADD == 0x40C0AE01u, "ioc add");
	_Static_assert(AIVPN_IOC_GET_VERSION == 0x8004AE07u, "ioc ver");
	_Static_assert(AIVPN_IOC_SESSION_POLICY == 0x4068AE0Bu, "ioc pol");
	_Static_assert(AIVPN_IOC_SESSION_SYNC == 0xC0A0AE0Cu, "ioc sync");
	_Static_assert(AIVPN_IOC_CLIENT_REVOKE == 0x4010AE0Du, "ioc rev");
	_Static_assert(AIVPN_IOC_SESSION_DOWNLINK == 0x505CAE09u, "ioc dl");
	_Static_assert(AIVPN_IOC_REPLAY_CLAIM == 0xC028AE0Eu, "ioc claim");
	_Static_assert(AIVPN_IOC_REPLAY_ROTATE == 0x4018AE0Fu, "ioc rotate");
	_Static_assert(AIVPN_IOC_QOS_CHARGE == 0xC030AE10u, "ioc qos");
	_Static_assert(sizeof(struct aivpn_replay_claim) == 40, "claim");
	_Static_assert(sizeof(struct aivpn_replay_rotate) == 24, "rotate");
	_Static_assert(sizeof(struct aivpn_qos_charge) == 48, "qos");
	_Static_assert(AIVPN_MODULE_API_VERSION == 7u, "api");

	arm(&pol, AIVPN_ROLE_SERVER, self, AIVPN_POL_PEER_ISOLATE);
	aivpn_ipv6_assigned(pol.ipv6_prefix, 64, self, mine);
	CHECK(memcmp(mine, expect, 16) == 0, "mapped v6 fd12:3456:789a::a00:2");

	fill_v4(pkt, 40, self, inet);
	CHECK(aivpn_pol_check_addrs(&pol, AIVPN_DIR_UPLINK, pkt, 40, 40,
				    peer_only, (void *)&other) == AIVPN_VERDICT_ACCEPT,
	      "normal v4 accept");

	fill_v4(pkt, 40, spoof, inet);
	CHECK(aivpn_pol_check_addrs(&pol, AIVPN_DIR_UPLINK, pkt, 40, 40,
				    peer_only, (void *)&other) == AIVPN_VERDICT_DROP,
	      "spoof v4 drop");

	fill_v4(pkt, 40, self, other);
	CHECK(aivpn_pol_check_addrs(&pol, AIVPN_DIR_UPLINK, pkt, 40, 40,
				    peer_only, (void *)&other) == AIVPN_VERDICT_DROP,
	      "peer dest drop");

	fill_v4(pkt, 40, self, inet);
	CHECK(aivpn_pol_check_addrs(&pol, AIVPN_DIR_UPLINK, pkt, 40, 40,
				    peer_only, (void *)&other) == AIVPN_VERDICT_ACCEPT,
	      "other dest accept");

	fill_v4(pkt, 40, self, self);
	CHECK(aivpn_pol_check_addrs(&pol, AIVPN_DIR_UPLINK, pkt, 40, 40,
				    peer_only, (void *)&self) == AIVPN_VERDICT_ACCEPT,
	      "self dest accept");

	fill_v6(pkt, 48, mine, mine);
	CHECK(aivpn_pol_check_addrs(&pol, AIVPN_DIR_UPLINK, pkt, 48, 48,
				    NULL, NULL) == AIVPN_VERDICT_FALLBACK,
	      "v6 flag off fallback");

	pol.flags |= AIVPN_POL_IPV6;
	CHECK(aivpn_pol_check_addrs(&pol, AIVPN_DIR_UPLINK, pkt, 48, 48,
				    NULL, NULL) == AIVPN_VERDICT_ACCEPT,
	      "mapped v6 accept");

	memcpy(bad, mine, 16);
	bad[0] = 0xfe;
	fill_v6(pkt, 48, bad, mine);
	CHECK(aivpn_pol_check_addrs(&pol, AIVPN_DIR_UPLINK, pkt, 48, 48,
				    NULL, NULL) == AIVPN_VERDICT_DROP,
	      "v6 wrong prefix drop");

	aivpn_ipv6_assigned(pol.ipv6_prefix, 64, other, peer_v6);
	fill_v6(pkt, 48, mine, peer_v6);
	CHECK(aivpn_pol_check_addrs(&pol, AIVPN_DIR_UPLINK, pkt, 48, 48,
				    peer_only, (void *)&other) == AIVPN_VERDICT_DROP,
	      "v6 peer dest drop");

	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 0x40;
	CHECK(aivpn_pol_check_addrs(&pol, AIVPN_DIR_UPLINK, pkt, 20, 20,
				    NULL, NULL) == AIVPN_VERDICT_DROP,
	      "malformed v4 drop");

	arm(&pol, AIVPN_ROLE_CLIENT, self, 0);
	fill_v4(pkt, 40, spoof, self);
	CHECK(aivpn_pol_check_addrs(&pol, AIVPN_DIR_UPLINK, pkt, 40, 40,
				    peer_only, (void *)&other) == AIVPN_VERDICT_ACCEPT,
	      "client dest match ignores source");
	fill_v4(pkt, 40, self, inet);
	CHECK(aivpn_pol_check_addrs(&pol, AIVPN_DIR_UPLINK, pkt, 40, 40,
				    NULL, NULL) == AIVPN_VERDICT_DROP,
	      "client dest mismatch drop");
	fill_v6(pkt, 48, mine, mine);
	CHECK(aivpn_pol_check_addrs(&pol, AIVPN_DIR_UPLINK, pkt, 48, 48,
				    NULL, NULL) == AIVPN_VERDICT_FALLBACK,
	      "client v6 flag off fallback");
	pol.flags |= AIVPN_POL_IPV6;
	CHECK(aivpn_pol_check_addrs(&pol, AIVPN_DIR_UPLINK, pkt, 48, 48,
				    NULL, NULL) == AIVPN_VERDICT_ACCEPT,
	      "client mapped v6 dest accept");
	aivpn_ipv6_assigned(pol.ipv6_prefix, 64, other, peer_v6);
	fill_v6(pkt, 48, mine, peer_v6);
	CHECK(aivpn_pol_check_addrs(&pol, AIVPN_DIR_UPLINK, pkt, 48, 48,
				    NULL, NULL) == AIVPN_VERDICT_DROP,
	      "client v6 dest spoof");
	fill_v6(pkt, 48, bad, mine);
	CHECK(aivpn_pol_check_addrs(&pol, AIVPN_DIR_UPLINK, pkt, 48, 48,
				    NULL, NULL) == AIVPN_VERDICT_ACCEPT,
	      "client v6 dest match ignores source");

	arm(&pol, AIVPN_ROLE_SERVER, self, AIVPN_POL_QOS_UP);
	pol.rate_up_bps = 0;
	for (i = 0; i < 8; i++)
		CHECK(aivpn_pol_charge(&pol, AIVPN_DIR_UPLINK, 2000, 1000) ==
		      AIVPN_VERDICT_ACCEPT, "qos rate 0 unlimited");

	arm(&pol, AIVPN_ROLE_SERVER, self, AIVPN_POL_QOS_UP);
	pol.rate_up_bps = 10000;
	CHECK(aivpn_pol_charge(&pol, AIVPN_DIR_UPLINK, 1000, 1000000000ull) ==
	      AIVPN_VERDICT_ACCEPT, "qos first packet");
	CHECK(aivpn_pol_charge(&pol, AIVPN_DIR_UPLINK, 1000, 1000000000ull) ==
	      AIVPN_VERDICT_DROP, "qos bucket exhausted");
	CHECK(aivpn_pol_charge(&pol, AIVPN_DIR_UPLINK, 1000, 2000000000ull) ==
	      AIVPN_VERDICT_ACCEPT, "qos refill after one second");

	arm(&pol, AIVPN_ROLE_SERVER, self, AIVPN_POL_QUOTA_UP);
	pol.quota_up = 2000;
	CHECK(aivpn_pol_charge(&pol, AIVPN_DIR_UPLINK, 1500, 5) == AIVPN_VERDICT_ACCEPT,
	      "quota decrement");
	CHECK(pol.quota_up == 500, "quota left 500");
	CHECK(aivpn_pol_charge(&pol, AIVPN_DIR_UPLINK, 1500, 5) == AIVPN_VERDICT_DROP,
	      "quota exhausted drop");
	CHECK(pol.quota_up == 500, "quota not subtracted on drop");
	memset(&in, 0, sizeof(in));
	in.policy_version = AIVPN_POLICY_VERSION;
	in.role = AIVPN_ROLE_SERVER;
	in.flags = AIVPN_POL_QUOTA_UP;
	in.client_ipv4 = self;
	in.quota_up_bytes = 2000;
	CHECK(aivpn_pol_apply(&pol, &in) == 0 && pol.quota_up == 500,
	      "policy refresh preserves consumed quota");
	pol.armed = 0;
	CHECK(aivpn_pol_apply(&pol, &in) == 0 && pol.quota_up == 500,
	      "reinstall preserves consumed quota");
	in.flags |= AIVPN_POL_QUOTA_RESET;
	CHECK(aivpn_pol_apply(&pol, &in) == 0 && pol.quota_up == 2000,
	      "explicit quota reset restores allowance");
	CHECK(!(pol.flags & AIVPN_POL_QUOTA_RESET), "reset is not a sticky policy bit");
	pol.flags |= AIVPN_POL_REVOKED;
	in.flags = 0;
	CHECK(aivpn_pol_apply(&pol, &in) == 0 && aivpn_pol_fast(&pol) == AIVPN_VERDICT_DROP,
	      "stale policy cannot undo revocation");

	memset(&pol, 0, sizeof(pol));
	CHECK(aivpn_replay_observe(&pol, 0) == AIVPN_REPLAY_OK, "replay counter 0 new");
	aivpn_replay_commit(&pol, 0);
	CHECK(aivpn_replay_observe(&pol, 0) == AIVPN_REPLAY_DUP, "replay same counter drop");
	pol.replay_hi = 1000;
	memset(pol.replay_words, 0, sizeof(pol.replay_words));
	pol.replay_words[0] = 1;
	CHECK(aivpn_replay_observe(&pol, 100) == AIVPN_REPLAY_TOO_OLD, "replay too old fallback");
	CHECK(pol.replay_words[0] == 1, "too old does not mark");

	{
		__u64 hi = 5, words[8] = { 1, 0, 0, 0, 0, 0, 0, 0 };
		__u64 other_hi = 3, other_w[8] = { 1, 0, 0, 0, 0, 0, 0, 0 };

		aivpn_replay_merge(&hi, words, other_hi, other_w);
		CHECK(hi == 5, "merge hi");
		CHECK((words[0] & 1ull) != 0, "merge newest");
		CHECK((words[0] & 4ull) != 0, "merge older mark");
		hi = 0;
		memset(words, 0, sizeof(words));
		aivpn_replay_merge(&hi, words, 0, words);
		CHECK(hi == 0 && words[0] == 0, "empty merge stays empty");
	}

	memset(&pol, 0, sizeof(pol));
	pol.flags = AIVPN_POL_REVOKED;
	CHECK(aivpn_pol_fast(&pol) == AIVPN_VERDICT_DROP, "revoked drop");
	memset(&pol, 0, sizeof(pol));
	CHECK(aivpn_pol_fast(&pol) == AIVPN_VERDICT_FALLBACK, "unarmed fallback");
	arm(&pol, AIVPN_ROLE_SERVER, self, AIVPN_POL_SITE);
	CHECK(aivpn_pol_fast(&pol) == AIVPN_VERDICT_FALLBACK, "site fallback");
	pol.flags = AIVPN_POL_MTLS_WAIT;
	CHECK(aivpn_pol_fast(&pol) == AIVPN_VERDICT_FALLBACK, "mtls fallback");
	pol.flags = AIVPN_POL_EXIT;
	CHECK(aivpn_pol_fast(&pol) == AIVPN_VERDICT_FALLBACK, "exit fallback");
	pol.flags = AIVPN_POL_ENROLL_WAIT;
	CHECK(aivpn_pol_fast(&pol) == AIVPN_VERDICT_FALLBACK, "enroll fallback");

	arm(&pol, AIVPN_ROLE_SERVER, self, AIVPN_POL_RX_FALLBACK);
	CHECK(aivpn_pol_direction(&pol, AIVPN_POL_RX_FALLBACK) == AIVPN_VERDICT_FALLBACK, "FEC stays userspace");
	CHECK(aivpn_pol_direction(&pol, AIVPN_POL_TX_FALLBACK) == AIVPN_VERDICT_ACCEPT, "FEC does not block downlink");
	pol.flags = AIVPN_POL_TX_FALLBACK;
	CHECK(aivpn_pol_direction(&pol, AIVPN_POL_TX_FALLBACK) == AIVPN_VERDICT_FALLBACK, "shaping stays userspace");
	CHECK(aivpn_pol_direction(&pol, AIVPN_POL_RX_FALLBACK) == AIVPN_VERDICT_ACCEPT, "shaping does not block uplink");
	pol.flags |= AIVPN_POL_RX_FALLBACK | AIVPN_POL_REVOKED;
	CHECK(aivpn_pol_direction(&pol, AIVPN_POL_TX_FALLBACK) == AIVPN_VERDICT_DROP, "revocation beats TX fallback");
	CHECK(aivpn_pol_direction(&pol, AIVPN_POL_RX_FALLBACK) == AIVPN_VERDICT_DROP, "revocation beats RX fallback");

	CHECK(aivpn_pol_over_cap(5, 5) == 1, "over cap at limit");
	CHECK(aivpn_pol_over_cap(4, 5) == 0, "under cap");
	CHECK(aivpn_pol_over_cap(9, 0) == 0, "zero cap is unlimited");

	memset(&pol, 0, sizeof(pol));
	pol.replay_hi = 9;
	pol.replay_words[0] = 1;
	pol.rx_bytes_synced = 44;
	memset(&in, 0, sizeof(in));
	in.policy_version = AIVPN_POLICY_VERSION;
	in.role = AIVPN_ROLE_SERVER;
	in.flags = AIVPN_POL_QOS_UP;
	in.client_ipv4 = self;
	in.rate_up_bps = 1000;
	in.max_sessions = 5;
	CHECK(aivpn_pol_apply(&pol, &in) == 0, "apply ok");
	CHECK(pol.armed == 1 && pol.replay_hi == 9 && pol.replay_words[0] == 1, "apply keeps replay");
	CHECK(pol.rx_bytes_synced == 44 && pol.bucket_ns == 0, "apply keeps cursor");
	CHECK(pol.rate_up_bps == 1000, "apply replaces rate");
	in.policy_version = 99;
	in.rate_up_bps = 7;
	CHECK(aivpn_pol_apply(&pol, &in) == -1, "bad version rejected");
	CHECK(pol.rate_up_bps == 1000 && pol.replay_hi == 9, "bad version does not mutate");

	pol.tokens_up = 100;
	pol.bucket_ns = 1000;
	pol.flags = AIVPN_POL_QOS_UP;
	pol.armed = 1;
	memset(&in, 0, sizeof(in));
	in.policy_version = AIVPN_POLICY_VERSION;
	in.role = AIVPN_ROLE_SERVER;
	in.flags = AIVPN_POL_QOS_UP;
	in.client_ipv4 = self;
	in.rate_up_bps = 10000;
	CHECK(aivpn_pol_apply(&pol, &in) == 0, "refresh apply");
	CHECK(pol.tokens_up == 100 && pol.bucket_ns == 1000, "refresh keeps remainder");
	CHECK(aivpn_pol_charge(&pol, AIVPN_DIR_UPLINK, 1000, 1000) == AIVPN_VERDICT_DROP,
	      "refresh does not refill");
	pol.tokens_up = 5000;
	pol.bucket_ns = 1000;
	CHECK(aivpn_pol_apply(&pol, &in) == 0, "clamp apply");
	CHECK(pol.tokens_up == 1500 && pol.bucket_ns == 1000, "clamp to new cap");
	pol.tokens_up = 100;
	CHECK(aivpn_pol_apply(&pol, &in) == 0, "under cap apply");
	CHECK(pol.tokens_up == 100 && pol.bucket_ns == 1000, "under cap stays");

	{
		struct aivpn_bucket_state shared;
		__u64 left;

		memset(&shared, 0, sizeof(shared));
		aivpn_bucket_adopt(&shared, 10000, 0, AIVPN_POL_QOS_UP);
		CHECK(aivpn_bucket_charge(&shared, AIVPN_DIR_UPLINK, 1000,
					  1000000000ull) == AIVPN_VERDICT_ACCEPT,
		      "shared first charge");
		left = shared.tokens_up;
		CHECK(left == 500, "shared remainder 500");
		CHECK(aivpn_bucket_charge(&shared, AIVPN_DIR_UPLINK, 1000,
					  1000000000ull) == AIVPN_VERDICT_DROP,
		      "shared second sees debit");
		CHECK(shared.tokens_up == left, "shared drop keeps remainder");
		aivpn_bucket_adopt(&shared, 10000, 0, AIVPN_POL_QOS_UP);
		CHECK(shared.tokens_up == left && shared.bucket_ns == 1000000000ull,
		      "adopt keeps remainder");
	}

	{
		struct aivpn_epoch_win win;

		memset(&win, 0, sizeof(win));
		CHECK(aivpn_epoch_claim(&win, 1, 5) == AIVPN_CLAIM_EPOCH, "claim before rotate");
		CHECK(win.epoch == 0 && win.hi == 0, "unbound claim mutates nothing");
		CHECK(aivpn_epoch_rotate(&win, 0) != 0, "rotate epoch 0 fails");
		CHECK(aivpn_epoch_rotate(&win, 1) == 0, "rotate to 1");
		CHECK(aivpn_epoch_claim(&win, 1, 5) == AIVPN_CLAIM_OK, "user then kernel claim");
		CHECK(aivpn_epoch_claim(&win, 1, 5) == AIVPN_CLAIM_DUP, "kernel sees user claim");
		CHECK(aivpn_epoch_claim(&win, 1, 6) == AIVPN_CLAIM_OK, "kernel then user claim");
		CHECK(aivpn_epoch_claim(&win, 1, 6) == AIVPN_CLAIM_DUP, "user sees kernel claim");
		CHECK(aivpn_epoch_rotate(&win, 1) == 0, "same epoch keeps window");
		CHECK(aivpn_epoch_claim(&win, 1, 5) == AIVPN_CLAIM_DUP, "noop keeps dup");
		CHECK(aivpn_epoch_rotate(&win, 2) == 0, "rekey rotate");
		CHECK(aivpn_epoch_claim(&win, 1, 5) == AIVPN_CLAIM_DUP, "old epoch still dup");
		CHECK(aivpn_epoch_claim(&win, 2, 5) == AIVPN_CLAIM_OK, "new epoch counter fresh");
		CHECK(aivpn_epoch_claim(&win, 3, 1) == AIVPN_CLAIM_EPOCH, "foreign epoch");
		CHECK(win.epoch == 2 && win.hi == 5, "foreign epoch does not mutate");
		CHECK(aivpn_epoch_claim(&win, 2, 1) == AIVPN_CLAIM_OK, "current not poisoned");
		CHECK(aivpn_epoch_rotate(&win, 1) != 0, "rotate back fails");
		CHECK(win.epoch == 2, "failed rotate does not mix");
		CHECK(aivpn_epoch_claim(&win, 1, 7) == AIVPN_CLAIM_OK, "prev epoch fresh");
		CHECK(aivpn_epoch_claim(&win, 2, 7) == AIVPN_CLAIM_OK, "epochs stay separate");
		CHECK(aivpn_epoch_claim(&win, 0, 1) == AIVPN_CLAIM_EPOCH, "epoch 0 rejected");
	}

	memset(&pol, 0, sizeof(pol));
	pol.flags = AIVPN_POL_REVOKED;
	pol.armed = 1;
	CHECK(aivpn_pol_fast(&pol) == AIVPN_VERDICT_DROP, "revoked armed still drop");

	memset(mdh, 0xab, sizeof(mdh));
	CHECK(aivpn_place_header(hdr, sizeof(hdr), tag, mdh, 12, 0xffffu, &hdr_len) == 0,
	      "legacy header");
	CHECK(hdr_len == 20 && memcmp(hdr, tag, 8) == 0 && hdr[8] == 0xab, "legacy layout");
	CHECK(aivpn_place_header(hdr, sizeof(hdr), tag, mdh, 20, 4, &hdr_len) == 0,
	      "embedded header");
	CHECK(hdr_len == 20 && memcmp(hdr + 4, tag, 8) == 0, "embedded tag offset");
	CHECK(aivpn_place_header(hdr, sizeof(hdr), tag, mdh, 8, 4, &hdr_len) == -1,
	      "embedded tag does not fit");

	memset(zero, 0, sizeof(zero));
	(void)zero;
	if (fails) {
		fprintf(stderr, "%d checks failed\n", fails);
		return 1;
	}
	printf("policy_test ok\n");
	return 0;
}
