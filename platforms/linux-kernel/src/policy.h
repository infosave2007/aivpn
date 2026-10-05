/* SPDX-License-Identifier: GPL-2.0 */
/*
 * policy.h: общие решения datapath для aivpn.ko и userspace теста.
 *
 * Функции не вызывают криптографию и не трогают skb. Ядро и тест
 * подключают один и тот же заголовок, поэтому вердикт спойфа, IPv6,
 * изоляции пиров, квоты, скорости и replay совпадает с тестом.
 *
 * Вердикт ACCEPT: ядро может забрать пакет.
 * Вердикт DROP: нарушение политики, в userspace не возвращать.
 * Вердикт FALLBACK: режим не поддержан, пакет остается userspace.
 */
#ifndef AIVPN_POLICY_H
#define AIVPN_POLICY_H

#include "../include/uapi/aivpn.h"

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#define AIVPN_VERDICT_ACCEPT    0
#define AIVPN_VERDICT_DROP      1
#define AIVPN_VERDICT_FALLBACK  2

#define AIVPN_REPLAY_OK         0
#define AIVPN_REPLAY_DUP        1
#define AIVPN_REPLAY_TOO_OLD    2

#define AIVPN_DIR_UPLINK        0
#define AIVPN_DIR_DOWNLINK      1

/* Биты окна: бит 0 это replay_hi, старшие биты старше. 8 слов по 64. */
#define AIVPN_REPLAY_BITS       512u

typedef int (*aivpn_peer_fn)(__u32 ipv4_raw, void *ctx);

struct aivpn_ip_view {
	int version;
	__u32 src_v4;
	__u32 dst_v4;
	__u8 src_v6[16];
	__u8 dst_v6[16];
	unsigned int length;
};

/* Состояние, которое ядро хранит в сессии. Не является ioctl payload. */
struct aivpn_pol {
	__u32 version;
	__u32 role;
	__u32 flags;
	__u32 client_ipv4;
	__u8 ipv6_prefix[16];
	__u8 ipv6_prefix_len;
	__u8 armed;
	__u8 _pad[2];
	__u64 rate_up_bps;
	__u64 rate_down_bps;
	__u64 quota_up;
	__u64 quota_down;
	__u64 tokens_up;
	__u64 tokens_down;
	__u64 bucket_ns;
	__u64 replay_hi;
	__u64 replay_words[AIVPN_REPLAY_WORDS];
	__u64 rx_bytes_synced;
	__u64 tx_bytes_synced;
	__u32 max_sessions;
	__u8 client_key[16];
};

static inline __u64 aivpn_bucket_capacity(__u64 rate)
{
	__u64 tenth = rate / 10ull;

	return tenth > 1500ull ? tenth : 1500ull;
}

static inline int aivpn_pol_over_cap(__u32 others_armed, __u32 max_sessions)
{
	return max_sessions > 0 && others_armed >= max_sessions;
}

static inline int aivpn_pol_fast(const struct aivpn_pol *p)
{
	if (p->flags & AIVPN_POL_REVOKED)
		return AIVPN_VERDICT_DROP;
	if (!p->armed || p->version != AIVPN_POLICY_VERSION)
		return AIVPN_VERDICT_FALLBACK;
	if (p->role != AIVPN_ROLE_SERVER && p->role != AIVPN_ROLE_CLIENT)
		return AIVPN_VERDICT_FALLBACK;
	if (p->flags & (AIVPN_POL_FALLBACK | AIVPN_POL_MTLS_WAIT | AIVPN_POL_EXIT |
			AIVPN_POL_ENROLL_WAIT | AIVPN_POL_SITE))
		return AIVPN_VERDICT_FALLBACK;
	return AIVPN_VERDICT_ACCEPT;
}

/* Отзыв проверяется раньше перехода в userspace для отдельного направления. */
static inline int aivpn_pol_direction(const struct aivpn_pol *p, __u32 fallback)
{
	int v = aivpn_pol_fast(p);

	if (v != AIVPN_VERDICT_ACCEPT)
		return v;
	return p->flags & fallback ? AIVPN_VERDICT_FALLBACK : AIVPN_VERDICT_ACCEPT;
}

static inline int aivpn_pol_apply(struct aivpn_pol *p,
				  const struct aivpn_session_policy *in)
{
	__u64 hi, words[AIVPN_REPLAY_WORDS], rx_s, tx_s;
	__u64 tokens_up, tokens_down, bucket_ns, cap, quota_up, quota_down;
	__u32 old_flags;

	if (in->policy_version != AIVPN_POLICY_VERSION)
		return -1;
	if ((in->flags & AIVPN_POL_IPV6) &&
	    (in->ipv6_prefix_len == 0 || in->ipv6_prefix_len > 96))
		return -1;
	if (in->role != AIVPN_ROLE_SERVER && in->role != AIVPN_ROLE_CLIENT)
		return -1;

	old_flags = p->flags;
	quota_up = p->quota_up;
	quota_down = p->quota_down;
	hi = p->replay_hi;
	rx_s = p->rx_bytes_synced;
	tx_s = p->tx_bytes_synced;
	tokens_up = p->tokens_up;
	tokens_down = p->tokens_down;
	bucket_ns = p->bucket_ns;
	memcpy(words, p->replay_words, sizeof(words));

	memset(p, 0, sizeof(*p));
	p->version = in->policy_version;
	p->role = in->role;
	/* Отозванную сессию нельзя оживить запоздавшим refresh. */
	p->flags = in->flags | (old_flags & AIVPN_POL_REVOKED);
	p->client_ipv4 = in->client_ipv4;
	memcpy(p->ipv6_prefix, in->ipv6_prefix, 16);
	p->ipv6_prefix_len = in->ipv6_prefix_len;
	p->rate_up_bps = in->rate_up_bps;
	p->rate_down_bps = in->rate_down_bps;
	p->quota_up = in->quota_up_bytes;
	p->quota_down = in->quota_down_bytes;
	if (!(in->flags & AIVPN_POL_QUOTA_RESET)) {
		if ((old_flags & AIVPN_POL_QUOTA_UP) && quota_up < p->quota_up)
			p->quota_up = quota_up;
		if ((old_flags & AIVPN_POL_QUOTA_DOWN) && quota_down < p->quota_down)
			p->quota_down = quota_down;
	}
	p->flags &= ~AIVPN_POL_QUOTA_RESET;
	p->max_sessions = in->max_sessions;
	memcpy(p->client_key, in->client_key, 16);
	p->replay_hi = hi;
	memcpy(p->replay_words, words, sizeof(words));
	p->rx_bytes_synced = rx_s;
	p->tx_bytes_synced = tx_s;
	p->tokens_up = tokens_up;
	p->tokens_down = tokens_down;
	p->bucket_ns = bucket_ns;
	p->armed = 1;
	/* bucket_ns == 0: ведро еще не списывали, первое списание наполнит его.
	 * Ненулевая метка сохраняет остаток. Обновление только обрезает его новым потолком. */
	if (bucket_ns != 0) {
		if (p->flags & AIVPN_POL_QOS_UP) {
			cap = aivpn_bucket_capacity(p->rate_up_bps);
			if (p->tokens_up > cap)
				p->tokens_up = cap;
		}
		if (p->flags & AIVPN_POL_QOS_DOWN) {
			cap = aivpn_bucket_capacity(p->rate_down_bps);
			if (p->tokens_down > cap)
				p->tokens_down = cap;
		}
	}
	return 0;
}

static inline void aivpn_ipv6_assigned(const __u8 prefix[16], __u8 prefix_len,
				       __u32 ipv4_raw, __u8 out[16])
{
	__u8 addr[16];
	unsigned int keep = prefix_len;
	unsigned int i;
	__u8 raw[4];

	memcpy(addr, prefix, 16);
	for (i = 0; i < 16; i++) {
		if (keep >= 8) {
			keep -= 8;
			continue;
		}
		if (keep == 0)
			addr[i] = 0;
		else {
			addr[i] &= (__u8)(0xffu << (8 - keep));
			keep = 0;
		}
	}
	memcpy(raw, &ipv4_raw, 4);
	out[0] = addr[0];
	for (i = 1; i < 12; i++)
		out[i] = addr[i];
	out[12] = (__u8)(addr[12] | raw[0]);
	out[13] = (__u8)(addr[13] | raw[1]);
	out[14] = (__u8)(addr[14] | raw[2]);
	out[15] = (__u8)(addr[15] | raw[3]);
}

static inline int aivpn_ipv6_matches(const __u8 prefix[16], __u8 prefix_len,
				     __u32 ipv4_raw, const __u8 addr[16])
{
	__u8 expect[16];

	if (prefix_len == 0 || prefix_len > 96)
		return 0;
	aivpn_ipv6_assigned(prefix, prefix_len, ipv4_raw, expect);
	return memcmp(expect, addr, 16) == 0;
}

static inline int aivpn_ip_parse(const __u8 *p, unsigned int buf_len,
				 unsigned int pkt_len, struct aivpn_ip_view *o)
{
	unsigned int i;

	memset(o, 0, sizeof(*o));
	if (!p || buf_len == 0 || pkt_len == 0 || buf_len > pkt_len)
		return -1;
	if ((p[0] >> 4) == 4) {
		unsigned int ihl, total;

		if (buf_len < 20)
			return -1;
		ihl = (unsigned int)(p[0] & 0x0f) * 4u;
		total = ((unsigned int)p[2] << 8) | p[3];
		if (ihl < 20 || total < ihl || total > pkt_len)
			return -1;
		if (buf_len >= total) {
			for (i = total; i < buf_len; i++) {
				if (p[i] != 0)
					return -1;
			}
		}
		o->version = 4;
		memcpy(&o->src_v4, p + 12, 4);
		memcpy(&o->dst_v4, p + 16, 4);
		o->length = total;
		return 0;
	}
	if ((p[0] >> 4) == 6) {
		unsigned int payload, total;

		if (buf_len < 40)
			return -1;
		payload = ((unsigned int)p[4] << 8) | p[5];
		if (payload == 0 && p[6] != 59)
			return -1;
		total = 40u + payload;
		if (total > pkt_len)
			return -1;
		if (buf_len >= total) {
			for (i = total; i < buf_len; i++) {
				if (p[i] != 0)
					return -1;
			}
		}
		o->version = 6;
		memcpy(o->src_v6, p + 8, 16);
		memcpy(o->dst_v6, p + 24, 16);
		o->length = total;
		return 0;
	}
	return -1;
}

static inline int aivpn_replay_marked(__u64 hi, const __u64 *words, __u64 counter)
{
	__u64 diff;
	__u32 bit;

	if (counter > hi)
		return 0;
	diff = hi - counter;
	if (diff >= AIVPN_REPLAY_BITS)
		return 0;
	bit = (__u32)(diff % 64ull);
	return (words[diff / 64ull] >> bit) & 1ull ? 1 : 0;
}

static inline int aivpn_replay_observe_win(__u64 hi, const __u64 *words, __u64 counter)
{
	__u64 diff;

	if (counter > hi)
		return AIVPN_REPLAY_OK;
	diff = hi - counter;
	if (diff >= AIVPN_REPLAY_BITS)
		return AIVPN_REPLAY_TOO_OLD;
	if (aivpn_replay_marked(hi, words, counter))
		return AIVPN_REPLAY_DUP;
	return AIVPN_REPLAY_OK;
}

static inline int aivpn_replay_observe(const struct aivpn_pol *p, __u64 counter)
{
	return aivpn_replay_observe_win(p->replay_hi, p->replay_words, counter);
}

static inline void aivpn_replay_set(__u64 *hi, __u64 *words, __u64 counter)
{
	__u64 diff;

	if (counter > *hi) {
		diff = counter - *hi;
		if (diff >= AIVPN_REPLAY_BITS) {
			memset(words, 0, sizeof(__u64) * AIVPN_REPLAY_WORDS);
		} else {
			__u64 next[AIVPN_REPLAY_WORDS];
			unsigned int i;

			memset(next, 0, sizeof(next));
			for (i = 0; i < AIVPN_REPLAY_BITS; i++) {
				if (i + diff >= AIVPN_REPLAY_BITS)
					break;
				if (aivpn_replay_marked(*hi, words, *hi - i)) {
					__u64 nd = i + diff;

					next[nd / 64ull] |= 1ull << (nd % 64ull);
				}
			}
			memcpy(words, next, sizeof(next));
		}
		*hi = counter;
		words[0] |= 1ull;
		return;
	}
	diff = *hi - counter;
	if (diff < AIVPN_REPLAY_BITS)
		words[diff / 64ull] |= 1ull << (diff % 64ull);
}

static inline void aivpn_replay_commit(struct aivpn_pol *p, __u64 counter)
{
	aivpn_replay_set(&p->replay_hi, p->replay_words, counter);
}

static inline void aivpn_replay_merge(__u64 *hi, __u64 *words,
				      __u64 other_hi, const __u64 *other)
{
	__u64 new_hi = *hi > other_hi ? *hi : other_hi;
	__u64 out[AIVPN_REPLAY_WORDS];
	unsigned int i;

	memset(out, 0, sizeof(out));
	for (i = 0; i < AIVPN_REPLAY_BITS; i++) {
		__u64 counter;

		if (new_hi < i)
			break;
		counter = new_hi - i;
		if (aivpn_replay_marked(*hi, words, counter) ||
		    aivpn_replay_marked(other_hi, other, counter))
			out[i / 64u] |= 1ull << (i % 64u);
	}
	memcpy(words, out, sizeof(out));
	*hi = new_hi;
}

/* Окно эпох живет отдельно от aivpn_pol: смена политики его не обнуляет.
 * Текущая эпоха это установленный ключ. Предыдущая держит один grace rekey. */
struct aivpn_epoch_win {
	__u32 epoch;
	__u32 prev_epoch;
	__u8 prev_valid;
	__u8 _pad[3];
	__u64 hi;
	__u64 words[AIVPN_REPLAY_WORDS];
	__u64 prev_hi;
	__u64 prev_words[AIVPN_REPLAY_WORDS];
};

/* Захват не привязывает эпоху. Пока rotate не вызван, эпоха 0 дает EPOCH. */
static inline int aivpn_epoch_claim(struct aivpn_epoch_win *w, __u32 epoch,
				    __u64 counter)
{
	int r;
	__u64 *hi;
	__u64 *words;

	if (epoch == 0 || w->epoch == 0)
		return AIVPN_CLAIM_EPOCH;
	if (epoch == w->epoch) {
		hi = &w->hi;
		words = w->words;
	} else if (w->prev_valid && epoch == w->prev_epoch) {
		hi = &w->prev_hi;
		words = w->prev_words;
	} else {
		return AIVPN_CLAIM_EPOCH;
	}
	r = aivpn_replay_observe_win(*hi, words, counter);
	if (r == AIVPN_REPLAY_DUP)
		return AIVPN_CLAIM_DUP;
	if (r == AIVPN_REPLAY_TOO_OLD)
		return AIVPN_CLAIM_TOO_OLD;
	aivpn_replay_set(hi, words, counter);
	return AIVPN_CLAIM_OK;
}

/* 0 и откат не смешивают окна. Та же эпоха оставляет биты на месте.
 * Большая эпоха прячет текущее окно в prev и начинает пустое. */
static inline int aivpn_epoch_rotate(struct aivpn_epoch_win *w, __u32 epoch)
{
	if (epoch == 0)
		return -1;
	if (w->epoch == epoch)
		return 0;
	if (w->epoch != 0 && epoch < w->epoch)
		return -1;
	if (w->epoch != 0) {
		w->prev_epoch = w->epoch;
		w->prev_hi = w->hi;
		memcpy(w->prev_words, w->words, sizeof(w->prev_words));
		w->prev_valid = 1;
	}
	w->epoch = epoch;
	w->hi = 0;
	memset(w->words, 0, sizeof(w->words));
	return 0;
}

static inline __u64 aivpn_add_tokens(__u64 elapsed_ns, __u64 rate)
{
	__u64 sec, rem, add;

	if (rate == 0 || elapsed_ns == 0)
		return 0;
	sec = elapsed_ns / 1000000000ull;
	rem = elapsed_ns % 1000000000ull;
	if (sec > ~0ull / rate)
		return ~0ull;
	add = sec * rate;
	if (rate <= ~0ull / 1000000000ull) {
		__u64 extra = (rem * rate) / 1000000000ull;

		if (~0ull - add < extra)
			return ~0ull;
		add += extra;
	} else {
		__u64 hi = (rate / 1000000000ull) * rem;
		__u64 lo = ((rate % 1000000000ull) * rem) / 1000000000ull;

		if (~0ull - add < hi)
			return ~0ull;
		add += hi;
		if (~0ull - add < lo)
			return ~0ull;
		add += lo;
	}
	return add;
}

static inline void aivpn_bucket_refill(struct aivpn_pol *p, __u64 now_ns)
{
	__u64 cap_up = 0, cap_down = 0, elapsed, add;

	if (p->flags & AIVPN_POL_QOS_UP)
		cap_up = aivpn_bucket_capacity(p->rate_up_bps);
	if (p->flags & AIVPN_POL_QOS_DOWN)
		cap_down = aivpn_bucket_capacity(p->rate_down_bps);
	if (p->bucket_ns == 0) {
		p->bucket_ns = now_ns ? now_ns : 1;
		p->tokens_up = cap_up;
		p->tokens_down = cap_down;
		return;
	}
	if (now_ns < p->bucket_ns)
		return;
	elapsed = now_ns - p->bucket_ns;
	p->bucket_ns = now_ns;
	if (cap_up) {
		add = aivpn_add_tokens(elapsed, p->rate_up_bps);
		if (~0ull - p->tokens_up < add)
			p->tokens_up = cap_up;
		else {
			p->tokens_up += add;
			if (p->tokens_up > cap_up)
				p->tokens_up = cap_up;
		}
	}
	if (cap_down) {
		add = aivpn_add_tokens(elapsed, p->rate_down_bps);
		if (~0ull - p->tokens_down < add)
			p->tokens_down = cap_down;
		else {
			p->tokens_down += add;
			if (p->tokens_down > cap_down)
				p->tokens_down = cap_down;
		}
	}
}

/* Списывает квоту и ведро. Вызывать только под замком сессии, после ACCEPT адресов. */
static inline int aivpn_pol_charge(struct aivpn_pol *p, int dir,
				   unsigned int nbytes, __u64 now_ns)
{
	int uplink = dir == AIVPN_DIR_UPLINK;
	__u32 qflag = uplink ? AIVPN_POL_QUOTA_UP : AIVPN_POL_QUOTA_DOWN;
	__u32 rflag = uplink ? AIVPN_POL_QOS_UP : AIVPN_POL_QOS_DOWN;
	__u64 *quota = uplink ? &p->quota_up : &p->quota_down;
	__u64 *tokens = uplink ? &p->tokens_up : &p->tokens_down;
	__u64 rate = uplink ? p->rate_up_bps : p->rate_down_bps;

	aivpn_bucket_refill(p, now_ns);
	if ((p->flags & qflag) && *quota < nbytes)
		return AIVPN_VERDICT_DROP;
	if ((p->flags & rflag) && rate > 0 && *tokens < nbytes)
		return AIVPN_VERDICT_DROP;
	if (p->flags & qflag)
		*quota -= nbytes;
	if ((p->flags & rflag) && rate > 0)
		*tokens -= nbytes;
	return AIVPN_VERDICT_ACCEPT;
}

/* Квота сессии после успешного списания общего ведра. Токены здесь не трогаем. */
static inline int aivpn_pol_take_quota(struct aivpn_pol *p, int dir,
				       unsigned int nbytes)
{
	int uplink = dir == AIVPN_DIR_UPLINK;
	__u32 qflag = uplink ? AIVPN_POL_QUOTA_UP : AIVPN_POL_QUOTA_DOWN;
	__u64 *quota = uplink ? &p->quota_up : &p->quota_down;

	if ((p->flags & qflag) && *quota < nbytes)
		return AIVPN_VERDICT_DROP;
	if (p->flags & qflag)
		*quota -= nbytes;
	return AIVPN_VERDICT_ACCEPT;
}

/* Общее ведро клиента. bucket_ns == 0 значит, что списаний еще не было. */
struct aivpn_bucket_state {
	__u64 tokens_up;
	__u64 tokens_down;
	__u64 bucket_ns;
	__u64 rate_up_bps;
	__u64 rate_down_bps;
	__u32 flags;
	__u32 _pad;
};

static inline void aivpn_bucket_clamp(struct aivpn_bucket_state *b)
{
	__u64 cap;

	if (b->flags & AIVPN_POL_QOS_UP) {
		cap = aivpn_bucket_capacity(b->rate_up_bps);
		if (b->tokens_up > cap)
			b->tokens_up = cap;
	}
	if (b->flags & AIVPN_POL_QOS_DOWN) {
		cap = aivpn_bucket_capacity(b->rate_down_bps);
		if (b->tokens_down > cap)
			b->tokens_down = cap;
	}
}

/* Повторная политика не обнуляет метку времени и не доливает ведро до полного. */
static inline void aivpn_bucket_adopt(struct aivpn_bucket_state *b, __u64 rate_up,
				      __u64 rate_down, __u32 qos_flags)
{
	b->rate_up_bps = rate_up;
	b->rate_down_bps = rate_down;
	b->flags = qos_flags & (AIVPN_POL_QOS_UP | AIVPN_POL_QOS_DOWN);
	if (b->bucket_ns != 0)
		aivpn_bucket_clamp(b);
}

static inline int aivpn_bucket_charge(struct aivpn_bucket_state *b, int dir,
				      unsigned int nbytes, __u64 now_ns)
{
	struct aivpn_pol tmp;
	int v;

	memset(&tmp, 0, sizeof(tmp));
	tmp.flags = b->flags;
	tmp.rate_up_bps = b->rate_up_bps;
	tmp.rate_down_bps = b->rate_down_bps;
	tmp.tokens_up = b->tokens_up;
	tmp.tokens_down = b->tokens_down;
	tmp.bucket_ns = b->bucket_ns;
	v = aivpn_pol_charge(&tmp, dir, nbytes, now_ns);
	b->tokens_up = tmp.tokens_up;
	b->tokens_down = tmp.tokens_down;
	b->bucket_ns = tmp.bucket_ns;
	return v;
}

static inline int aivpn_peer_hit(__u32 ipv4_raw, aivpn_peer_fn peer, void *ctx)
{
	if (!ipv4_raw || !peer)
		return 0;
	return peer(ipv4_raw, ctx) ? 1 : 0;
}

static inline int aivpn_pol_check_addrs(const struct aivpn_pol *p, int dir,
					const __u8 *ip, unsigned int buf_len,
					unsigned int pkt_len, aivpn_peer_fn peer,
					void *ctx)
{
	struct aivpn_ip_view view;
	int isolate = (p->flags & AIVPN_POL_PEER_ISOLATE) != 0;
	int v6_on = (p->flags & AIVPN_POL_IPV6) != 0;

	if (aivpn_ip_parse(ip, buf_len, pkt_len, &view) != 0)
		return AIVPN_VERDICT_DROP;
	if (p->client_ipv4 == 0)
		return AIVPN_VERDICT_FALLBACK;

	if (p->role == AIVPN_ROLE_CLIENT) {
		if (view.version == 4)
			return view.dst_v4 == p->client_ipv4 ? AIVPN_VERDICT_ACCEPT
							    : AIVPN_VERDICT_DROP;
		if (view.version == 6) {
			if (!v6_on)
				return AIVPN_VERDICT_FALLBACK;
			return aivpn_ipv6_matches(p->ipv6_prefix, p->ipv6_prefix_len,
						  p->client_ipv4, view.dst_v6)
				       ? AIVPN_VERDICT_ACCEPT
				       : AIVPN_VERDICT_DROP;
		}
		return AIVPN_VERDICT_DROP;
	}

	/* Сервер, uplink: источник обязан быть адресом этой сессии. */
	if (dir == AIVPN_DIR_UPLINK) {
		if (view.version == 4) {
			if (view.src_v4 != p->client_ipv4)
				return AIVPN_VERDICT_DROP;
			if (isolate && view.dst_v4 != p->client_ipv4 &&
			    aivpn_peer_hit(view.dst_v4, peer, ctx))
				return AIVPN_VERDICT_DROP;
			return AIVPN_VERDICT_ACCEPT;
		}
		if (view.version == 6) {
			__u32 mapped = 0;

			if (!v6_on)
				return AIVPN_VERDICT_FALLBACK;
			if (!aivpn_ipv6_matches(p->ipv6_prefix, p->ipv6_prefix_len,
						p->client_ipv4, view.src_v6))
				return AIVPN_VERDICT_DROP;
			if (isolate &&
			    aivpn_ipv6_matches(p->ipv6_prefix, p->ipv6_prefix_len,
					       0, view.dst_v6) == 0) {
				memcpy(&mapped, view.dst_v6 + 12, 4);
				if (aivpn_ipv6_matches(p->ipv6_prefix, p->ipv6_prefix_len,
						       mapped, view.dst_v6) &&
				    mapped != p->client_ipv4 &&
				    aivpn_peer_hit(mapped, peer, ctx))
					return AIVPN_VERDICT_DROP;
			}
			return AIVPN_VERDICT_ACCEPT;
		}
		return AIVPN_VERDICT_DROP;
	}

	/* Сервер, downlink: пакет уже выбран по VPN адресу назначения. */
	if (view.version == 4) {
		if (view.dst_v4 != p->client_ipv4)
			return AIVPN_VERDICT_FALLBACK;
		if (isolate && view.src_v4 != p->client_ipv4 &&
		    aivpn_peer_hit(view.src_v4, peer, ctx))
			return AIVPN_VERDICT_DROP;
		return AIVPN_VERDICT_ACCEPT;
	}
	if (view.version == 6) {
		__u32 mapped = 0;

		if (!v6_on)
			return AIVPN_VERDICT_FALLBACK;
		if (!aivpn_ipv6_matches(p->ipv6_prefix, p->ipv6_prefix_len,
					p->client_ipv4, view.dst_v6))
			return AIVPN_VERDICT_DROP;
		memcpy(&mapped, view.src_v6 + 12, 4);
		if (isolate &&
		    aivpn_ipv6_matches(p->ipv6_prefix, p->ipv6_prefix_len, mapped,
				       view.src_v6) &&
		    mapped != p->client_ipv4 && aivpn_peer_hit(mapped, peer, ctx))
			return AIVPN_VERDICT_DROP;
		return AIVPN_VERDICT_ACCEPT;
	}
	return AIVPN_VERDICT_DROP;
}

/* 0xFFFF: tag || mdh || ciphertext. Иначе tag внутри mdh, ciphertext с mdh_len. */
static inline int aivpn_place_header(__u8 *out, unsigned int cap,
				     const __u8 tag[8], const __u8 *mdh,
				     unsigned int mdh_len, unsigned int tag_pos,
				     unsigned int *hdr_len)
{
	if (tag_pos == 0xffffu) {
		if (cap < 8u + mdh_len)
			return -1;
		memcpy(out, tag, 8);
		if (mdh_len && mdh)
			memcpy(out + 8, mdh, mdh_len);
		*hdr_len = 8u + mdh_len;
		return 0;
	}
	if (tag_pos + 8u > mdh_len || cap < mdh_len)
		return -1;
	if (mdh_len && mdh)
		memcpy(out, mdh, mdh_len);
	else if (mdh_len)
		return -1;
	memcpy(out + tag_pos, tag, 8);
	*hdr_len = mdh_len;
	return 0;
}

#endif /* AIVPN_POLICY_H */
