// SPDX-License-Identifier: GPL-2.0
/*
 * session_table.c — two-table RCU session store for aivpn.ko
 *
 * aivpn_tag_htable    (128K RCU buckets) — tag→session, read from BH/softirq
 * aivpn_session_htable  (512 buckets)    — session_id→session, mgmt only
 *
 * Locking discipline:
 *   aivpn_table_lock  DEFINE_SPINLOCK  — write-side for both tables;
 *                                        always entered with spin_lock_bh
 *   session->lock     spinlock         — anti-replay window + stats;
 *                                        entered with spin_lock_bh everywhere
 *                                        (safe from both BH and process context)
 *
 * Tag lookup hot path: rcu_read_lock() → hash_for_each_possible_rcu() → rcu_read_unlock()
 * No sleepable code is called on the RX fast path.
 */

#include <linux/slab.h>
#include <linux/jhash.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/bitmap.h>
#include <linux/rcupdate.h>
#include <linux/atomic.h>
#include <linux/mutex.h>
#include <linux/timekeeping.h>
#include <crypto/aead.h>
#include <crypto/algapi.h>
#include "session_table.h"
#include "egress.h"
#include "udp_hook.h"
#include "tun_inject.h"
#include "stats.h"
#include "helpers.h"

static DEFINE_HASHTABLE(aivpn_tag_htable,     AIVPN_TAG_HASH_BITS);
static DEFINE_HASHTABLE(aivpn_session_htable, AIVPN_SESSION_HASH_BITS);
/* client-VPN-IP -> session, RCU on the read side (egress hot path). Shares the
 * write-side aivpn_table_lock with the other two tables. */
static DEFINE_HASHTABLE(aivpn_ip_htable,      AIVPN_SESSION_HASH_BITS);
static DEFINE_SPINLOCK(aivpn_table_lock);
/* Смена объекта сессии и flush не должны пересекаться между ioctl. */
static DEFINE_MUTEX(aivpn_lifecycle_lock);
static atomic_t aivpn_session_count = ATOMIC_INIT(0);

/* Общее ведро на client_key. Слот живет дольше сессии: reinstall не наполняет бюджет заново. */
#define AIVPN_QOS_HASH_BITS 8

struct aivpn_qos_slot {
	struct hlist_node node;
	spinlock_t lock;
	u8 client_key[16];
	struct aivpn_pol budget;
};

static DEFINE_HASHTABLE(aivpn_qos_htable, AIVPN_QOS_HASH_BITS);
static DEFINE_SPINLOCK(aivpn_qos_lock);

static struct aivpn_kern_session *aivpn_session_detach(const u8 *session_id);
static void aivpn_qos_flush(void);

/* Bitmap of tag byte offsets in use (Variant A). Written under the table lock,
 * read lock-free on the RX path via READ_ONCE. Only grows, so a stale read is
 * safe. Offsets >= 64 (never produced by real masks) fold onto legacy offset 0
 * so a valid tag is still probed. */
static u64 aivpn_probe_offsets_bitmap;

u64 aivpn_tag_probe_offsets(void)
{
	u64 v = READ_ONCE(aivpn_probe_offsets_bitmap);
	/* Always probe offset 0 so a brand-new table (or an unusual mask) still
	 * catches legacy-framed packets. */
	return v | 1ull;
}

/* ── Init / fini ─────────────────────────────────────────────────────────── */

int aivpn_session_table_init(void)
{
	int ret;

	BUILD_BUG_ON(AIVPN_TAG_WINDOW_SLOTS < 32 || AIVPN_TAG_WINDOW_SLOTS > 1024);
	BUILD_BUG_ON(sizeof(struct aivpn_session_policy) != 104);
	BUILD_BUG_ON(sizeof(struct aivpn_session_sync) != 160);
	BUILD_BUG_ON(sizeof(struct aivpn_client_revoke) != 16);
	BUILD_BUG_ON(sizeof(struct aivpn_session_downlink) != 4188);
	BUILD_BUG_ON(sizeof(struct aivpn_session_add) != 192);
	BUILD_BUG_ON(sizeof(struct aivpn_replay_claim) != 40);
	BUILD_BUG_ON(sizeof(struct aivpn_replay_rotate) != 24);
	BUILD_BUG_ON(sizeof(struct aivpn_qos_charge) != 48);
	BUILD_BUG_ON(AIVPN_REPLAY_WORDS != 8);
	hash_init(aivpn_tag_htable);
	hash_init(aivpn_session_htable);
	hash_init(aivpn_ip_htable);
	hash_init(aivpn_qos_htable);
	ret = aivpn_stats_init();
	if (ret)
		return ret;
	aivpn_info("session table ready (tag: %u, session: %u buckets)\n",
		   1u << AIVPN_TAG_HASH_BITS, 1u << AIVPN_SESSION_HASH_BITS);
	return 0;
}

void aivpn_session_owner_release(void)
{
	aivpn_udp_hook_uninstall();
	aivpn_egress_fini();
	aivpn_session_flush();
	aivpn_qos_flush();
	aivpn_tun_clear();
}

void aivpn_session_table_fini(void)
{
	/* Teardown order matters:
	 * 1. Uninstall the UDP RX hook FIRST — it restores the socket's original
	 *    sk_data_ready/sk_user_data and waits (synchronize_rcu) for in-flight
	 *    softirq invocations, so no RX fast path can run module code or touch
	 *    the session table afterward.  Without this, rmmod left a dangling
	 *    function pointer on the hooked socket → UAF panic on the next
	 *    datagram.
	 * 2. Disable egress: it looks up sessions, so it must stop before the
	 *    table is torn down. aivpn_egress_fini() unregisters the hook and
	 *    waits for in-flight invocations.
	 * 3. Flush sessions (both packet paths are quiesced by now).
	 * 4. Release the TUN net_device reference — otherwise the dev_hold taken
	 *    by SET_TUN is orphaned forever and netdev/netns teardown hangs on
	 *    "waiting for tunX to become free". */
	aivpn_udp_hook_uninstall();
	aivpn_egress_fini();
	aivpn_session_flush();
	/* Хуки уже сняты, слоты QoS больше никто не держит. */
	aivpn_qos_flush();
	aivpn_tun_clear();
	aivpn_stats_fini();
}

/* ── Hash helpers ────────────────────────────────────────────────────────── */

static u32 tag_hash_key(const u8 *tag)
{
	return jhash(tag, AIVPN_TAG_SIZE, 0);
}

static u32 sid_hash_key(const u8 *session_id)
{
	return jhash(session_id, 16, 0);
}

static u32 ip_hash_key(u32 client_ip)
{
	return jhash_1word(client_ip, 0);
}

/* ── RCU callback: free a single tag entry ───────────────────────────────── */

static void tag_entry_free_rcu(struct rcu_head *head)
{
	struct aivpn_tag_entry *e = container_of(head, struct aivpn_tag_entry, rcu);
	kfree_sensitive(e);
}

/* ── Session object lifecycle ────────────────────────────────────────────── */

static void session_free(struct aivpn_kern_session *s)
{
	if (s->tfm) {
		crypto_free_aead(s->tfm);
		s->tfm = NULL;
	}
	if (s->tfm_s2c) {
		crypto_free_aead(s->tfm_s2c);
		s->tfm_s2c = NULL;
	}
	memzero_explicit(s->nonce_suffix, sizeof(s->nonce_suffix));
	kfree(s);
}

/* Allocate a ChaCha20-Poly1305 AEAD transform with @key (32 bytes) loaded and a
 * 16-byte auth size. Returns an ERR_PTR on failure. */
static struct crypto_aead *aivpn_alloc_tfm(const u8 *key)
{
	struct crypto_aead *tfm;
	int ret;

	/* Mask CRYPTO_ALG_ASYNC: force a SYNCHRONOUS implementation so
	 * crypto_wait_req() always completes inline and never sleeps. Both data
	 * paths that use this tfm — RX decrypt (softirq via sk_data_ready) and the
	 * downlink egress hook (softirq via NF_INET_POST_ROUTING) — run in atomic
	 * context where sleeping on an async crypto backend would BUG. */
	tfm = crypto_alloc_aead("rfc7539(chacha20,poly1305)", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm))
		return tfm;
	ret = crypto_aead_setkey(tfm, key, 32);
	if (!ret)
		ret = crypto_aead_setauthsize(tfm, 16);
	if (ret) {
		crypto_free_aead(tfm);
		return ERR_PTR(ret);
	}
	return tfm;
}

/* ── aivpn_session_insert ────────────────────────────────────────────────── */

static int aivpn_session_insert_locked(const struct aivpn_session_add *add)
{
	struct aivpn_kern_session *s, *old;
	struct crypto_aead *tfm;
	int ret;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	memcpy(s->session_id,   add->session_id,  sizeof(s->session_id));
	memcpy(s->nonce_suffix, add->nonce_suffix, sizeof(s->nonce_suffix));
	memcpy(s->client_addr,  add->client_addr, sizeof(s->client_addr));
	s->client_ip = add->client_ip;
	/* Downlink block starts empty. kzalloc обнуляет политику (armed = 0) и
	 * dl_tag_pos, поэтому legacy sentinel ставим явно: ноль значил бы встройку. */
	s->dl_tag_pos = 0xFFFF;

	/* Derive the Variant A wire offsets. Legacy (u16::MAX): 8-byte tag prefix
	 * at offset 0, ciphertext at TAG_SIZE + mdh_len. Embedded: tag inside the
	 * mimic header at tag_offset, ciphertext right after the header (mdh_len). */
	if (add->tag_offset == (u16)0xFFFF) {
		s->tag_pos = 0;
		s->ct_pos  = AIVPN_TAG_SIZE + add->mdh_len;
	} else {
		s->tag_pos = add->tag_offset;
		s->ct_pos  = add->mdh_len;
	}

	spin_lock_init(&s->lock);
	/* counter_base остается в ABI. Отдельный tx_counter больше не нужен:
	 * aivpn_encrypt удален, downlink берет счетчики из зарезервированного блока. */

	/* c2s uplink key — the direction the kernel currently decrypts. */
	tfm = aivpn_alloc_tfm(add->session_key);
	if (IS_ERR(tfm)) {
		ret = PTR_ERR(tfm);
		kfree(s);
		return ret;
	}
	s->tfm = tfm;

	/* s2c downlink key — used by kernel downlink encryption. */
	tfm = aivpn_alloc_tfm(add->session_key_s2c);
	if (IS_ERR(tfm)) {
		ret = PTR_ERR(tfm);
		crypto_free_aead(s->tfm);
		kfree(s);
		return ret;
	}
	s->tfm_s2c = tfm;

	/* Все операции, которые могут не выделить память, завершены до detach. */
	old = aivpn_session_detach(add->session_id);
	if (old) {
		synchronize_rcu();
		spin_lock_bh(&old->lock);
		s->replay = old->replay;
		s->rx_packets = old->rx_packets;
		s->rx_bytes = old->rx_bytes;
		s->tx_packets = old->tx_packets;
		s->tx_bytes = old->tx_bytes;
		s->pol = old->pol;
		s->pol.armed = 0;
		spin_unlock_bh(&old->lock);
		session_free(old);
	}

	spin_lock_bh(&aivpn_table_lock);
	if (atomic_read(&aivpn_session_count) >= MAX_SESSIONS) {
		spin_unlock_bh(&aivpn_table_lock);
		/* session_free() releases BOTH transforms (c2s + s2c) and zeroes
		 * the key material; freeing only the local s2c tfm here leaked
		 * s->tfm and its 32-byte key on every rejected add. */
		session_free(s);
		return -ENOSPC;
	}
	hash_add(aivpn_session_htable, &s->mgmt_node, sid_hash_key(s->session_id));
	/* Publish in the IP table for the egress hot path. RCU add: readers see a
	 * fully-initialised node (client_addr/keys set above). Only IPv4 sessions
	 * (client_ip != 0) are routable by the downlink egress hook. */
	if (s->client_ip)
		hash_add_rcu(aivpn_ip_htable, &s->ip_node, ip_hash_key(s->client_ip));
	else
		INIT_HLIST_NODE(&s->ip_node);
	atomic_inc(&aivpn_session_count);
	/* Record this session's tag offset so the RX path probes it. Offsets >= 64
	 * (never produced by real masks) fold onto legacy offset 0. */
	if (s->tag_pos < 64)
		aivpn_probe_offsets_bitmap |= 1ull << s->tag_pos;
	else
		aivpn_probe_offsets_bitmap |= 1ull;
	spin_unlock_bh(&aivpn_table_lock);
	return 0;
}

int aivpn_session_insert(const struct aivpn_session_add *add)
{
	int ret;

	mutex_lock(&aivpn_lifecycle_lock);
	ret = aivpn_session_insert_locked(add);
	mutex_unlock(&aivpn_lifecycle_lock);
	return ret;
}

/* ── aivpn_session_tags_update ───────────────────────────────────────────── */

int aivpn_session_tags_update(const struct aivpn_session_update_tags *upd)
{
	struct aivpn_kern_session *s, *candidate;
	struct aivpn_tag_entry **new_entries;
	int old_count = 0;
	u32 count, i;

	count = upd->count;
	if (count > AIVPN_TAG_WINDOW_SLOTS)
		return -EINVAL;

	/* 256 pointers = 2 KiB: too much to stack on an ioctl path whose Rust
	 * dispatcher already carries the 4 KiB payload copy on its stack, so
	 * keep the pre-allocation array off-stack. */
	new_entries = kcalloc(AIVPN_TAG_WINDOW_SLOTS, sizeof(*new_entries),
			      GFP_KERNEL);
	if (!new_entries)
		return -ENOMEM;

	/* Pre-allocate all new tag entries before acquiring any lock */
	for (i = 0; i < count; i++) {
		new_entries[i] = kzalloc(sizeof(*new_entries[i]), GFP_KERNEL);
		if (!new_entries[i]) {
			while (i--)
				kfree(new_entries[i]);
			kfree(new_entries);
			return -ENOMEM;
		}
		memcpy(new_entries[i]->tag, upd->entries[i].tag, AIVPN_TAG_SIZE);
		new_entries[i]->counter = upd->entries[i].counter;
	}

	/* Locate the session; hold table lock so it cannot be concurrently removed */
	spin_lock_bh(&aivpn_table_lock);
	s = NULL;
	hash_for_each_possible(aivpn_session_htable, candidate, mgmt_node,
			       sid_hash_key(upd->session_id)) {
		if (!crypto_memneq(candidate->session_id, upd->session_id, 16)) {
			s = candidate;
			break;
		}
	}
	if (!s) {
		spin_unlock_bh(&aivpn_table_lock);
		for (i = 0; i < count; i++)
			kfree(new_entries[i]);
		kfree(new_entries);
		return -ENOENT;
	}

	/* Unlink old tag entries from the RCU table.  Freeing is deferred to
	 * call_rcu (safe under the spinlock — it never sleeps), which removes
	 * the need for a second on-stack pointer snapshot. */
	old_count = s->tag_entry_count;
	for (i = 0; i < (u32)old_count; i++) {
		if (s->tag_entries[i]) {
			hash_del_rcu(&s->tag_entries[i]->hnode);
			call_rcu(&s->tag_entries[i]->rcu, tag_entry_free_rcu);
		}
	}

	/* Link new entries into the RCU table and update session bookkeeping */
	for (i = 0; i < count; i++) {
		new_entries[i]->session = s;
		hash_add_rcu(aivpn_tag_htable, &new_entries[i]->hnode,
			     tag_hash_key(new_entries[i]->tag));
		s->tag_entries[i] = new_entries[i];
	}
	for (i = count; i < (u32)old_count; i++)
		s->tag_entries[i] = NULL;
	s->tag_entry_count = (int)count;
	spin_unlock_bh(&aivpn_table_lock);

	kfree(new_entries);
	return 0;
}

/* ── aivpn_session_downlink_update — arm/refresh the downlink block ──────── */

int aivpn_session_downlink_update(const struct aivpn_session_downlink *dl)
{
	struct aivpn_kern_session *s, *candidate;
	u32 count, mdh_len, i;

	count   = dl->count;
	mdh_len = dl->mdh_len;
	if (count > AIVPN_TAG_WINDOW_SLOTS)
		return -EINVAL;
	if (mdh_len > AIVPN_DL_MDH_MAX)
		return -EINVAL;

	spin_lock_bh(&aivpn_table_lock);
	s = NULL;
	hash_for_each_possible(aivpn_session_htable, candidate, mgmt_node,
			       sid_hash_key(dl->session_id)) {
		if (!crypto_memneq(candidate->session_id, dl->session_id, 16)) {
			s = candidate;
			break;
		}
	}
	if (!s) {
		spin_unlock_bh(&aivpn_table_lock);
		return -ENOENT;
	}

	/* Replace the block wholesale under the session lock so a concurrent
	 * egress reserve sees either the whole old block or the whole new one.
	 * The consume cursor resets to 0: the new block is a fresh disjoint range
	 * of counters, so unconsumed counters from the previous block are simply
	 * skipped (equivalent to downlink packet loss — the client tolerates gaps).
	 */
	spin_lock_bh(&s->lock);
	s->dl_mdh_len  = (u16)mdh_len;
	s->dl_seq_base = dl->seq_base;
	if (mdh_len)
		memcpy(s->dl_mdh, dl->mdh, mdh_len);
	for (i = 0; i < count; i++) {
		memcpy(s->dl_entries[i].tag, dl->entries[i].tag, AIVPN_TAG_SIZE);
		s->dl_entries[i].counter = dl->entries[i].counter;
	}
	s->dl_count = count;
	s->dl_next  = 0;
	s->dl_tag_pos = dl->dl_tag_pos;
	spin_unlock_bh(&s->lock);
	spin_unlock_bh(&aivpn_table_lock);
	return 0;
}

/* ── aivpn_session_lookup_by_ip — egress hot path, rcu_read_lock() held ─── */

struct aivpn_kern_session *aivpn_session_lookup_by_ip(u32 client_ip)
{
	struct aivpn_kern_session *s;
	u32 h = ip_hash_key(client_ip);

	hash_for_each_possible_rcu(aivpn_ip_htable, s, ip_node, h) {
		if (s->client_ip == client_ip)
			return s;
	}
	return NULL;
}

/* Сосед это другая живая сессия с тем же VPN IPv4. Вызывать под rcu_read_lock,
 * не беря table lock (datapath уже может держать session lock). */
static int aivpn_peer_is_other(__u32 ipv4_raw, void *ctx)
{
	struct aivpn_kern_session *self = ctx;
	struct aivpn_kern_session *other;

	other = aivpn_session_lookup_by_ip(ipv4_raw);
	return other && other != self;
}

static int aivpn_key_nonzero(const u8 key[16])
{
	u8 acc = 0;
	int i;

	for (i = 0; i < 16; i++)
		acc |= key[i];
	return acc != 0;
}

/* Вызывать под aivpn_qos_lock. */
static struct aivpn_qos_slot *aivpn_qos_lookup(const u8 key[16])
{
	struct aivpn_qos_slot *slot;

	hash_for_each_possible(aivpn_qos_htable, slot, node, jhash(key, 16, 0)) {
		if (!crypto_memneq(slot->client_key, key, 16))
			return slot;
	}
	return NULL;
}

/* Вызывать под aivpn_qos_lock. GFP_ATOMIC: замок уже взят. */
static struct aivpn_qos_slot *aivpn_qos_create(const u8 key[16])
{
	struct aivpn_qos_slot *slot;

	slot = kzalloc(sizeof(*slot), GFP_ATOMIC);
	if (!slot)
		return NULL;
	memcpy(slot->client_key, key, 16);
	spin_lock_init(&slot->lock);
	hash_add(aivpn_qos_htable, &slot->node, jhash(key, 16, 0));
	return slot;
}

/* Session lock уже взят. Дальше qos lock, затем lock слота. Обратный порядок запрещен. */
static void aivpn_qos_reconfigure(const struct aivpn_session_policy *in)
{
	struct aivpn_qos_slot *slot;

	if (!aivpn_key_nonzero(in->client_key))
		return;
	spin_lock_bh(&aivpn_qos_lock);
	slot = aivpn_qos_lookup(in->client_key);
	if (!slot)
		slot = aivpn_qos_create(in->client_key);
	if (slot) {
		spin_lock(&slot->lock);
		aivpn_pol_apply(&slot->budget, in);
		spin_unlock(&slot->lock);
	}
	spin_unlock_bh(&aivpn_qos_lock);
}

static void aivpn_qos_flush(void)
{
	struct aivpn_qos_slot *slot;
	struct hlist_node *tmp;
	int bkt;

	spin_lock_bh(&aivpn_qos_lock);
	hash_for_each_safe(aivpn_qos_htable, bkt, tmp, slot, node) {
		hash_del(&slot->node);
		kfree(slot);
	}
	spin_unlock_bh(&aivpn_qos_lock);
}

/* Нулевой ключ списывает бюджет сессии, ненулевой общий бюджет клиента.
 * Проверка квоты и скорости выполняется одним атомарным действием. */
static int aivpn_session_account(struct aivpn_kern_session *s, int dir,
				 unsigned int nbytes, u64 now_ns)
{
	struct aivpn_qos_slot *slot;
	int v;

	if (!aivpn_key_nonzero(s->pol.client_key))
		return aivpn_pol_charge(&s->pol, dir, nbytes, now_ns);

	spin_lock_bh(&aivpn_qos_lock);
	slot = aivpn_qos_lookup(s->pol.client_key);
	if (!slot) {
		spin_unlock_bh(&aivpn_qos_lock);
		return AIVPN_VERDICT_DROP;
	}
	spin_lock(&slot->lock);
	spin_unlock_bh(&aivpn_qos_lock);
	v = aivpn_pol_charge(&slot->budget, dir, nbytes, now_ns);
	s->pol.quota_up = slot->budget.quota_up;
	s->pol.quota_down = slot->budget.quota_down;
	spin_unlock(&slot->lock);
	if (v != AIVPN_VERDICT_ACCEPT)
		return v;
	return AIVPN_VERDICT_ACCEPT;
}

static __u64 aivpn_qos_budget_left(const u8 key[16], int dir, __u64 session_tokens, __u64 *quota)
{
	struct aivpn_qos_slot *slot;
	__u64 left = session_tokens;

	if (!aivpn_key_nonzero(key))
		return session_tokens;
	spin_lock_bh(&aivpn_qos_lock);
	slot = aivpn_qos_lookup(key);
	if (!slot) {
		spin_unlock_bh(&aivpn_qos_lock);
		return 0;
	}
	spin_lock(&slot->lock);
	spin_unlock_bh(&aivpn_qos_lock);
	left = dir == AIVPN_DIR_UPLINK ? slot->budget.tokens_up : slot->budget.tokens_down;
	*quota = dir == AIVPN_DIR_UPLINK ? slot->budget.quota_up : slot->budget.quota_down;
	spin_unlock(&slot->lock);
	return left;
}

/* Слот лимита занимает только вооруженная серверная сессия без fallback. */
static int aivpn_pol_slot_armed(const struct aivpn_pol *p)
{
	if (!p->armed || p->version != AIVPN_POLICY_VERSION)
		return 0;
	if (p->role != AIVPN_ROLE_SERVER)
		return 0;
	if (p->flags & (AIVPN_POL_REVOKED | AIVPN_POL_FALLBACK | AIVPN_POL_MTLS_WAIT |
			AIVPN_POL_EXIT | AIVPN_POL_ENROLL_WAIT | AIVPN_POL_SITE))
		return 0;
	return 1;
}

static struct aivpn_kern_session *aivpn_find_session(const u8 *session_id)
{
	struct aivpn_kern_session *candidate;

	hash_for_each_possible(aivpn_session_htable, candidate, mgmt_node,
			       sid_hash_key(session_id)) {
		if (!crypto_memneq(candidate->session_id, session_id, 16))
			return candidate;
	}
	return NULL;
}

/* ── aivpn_session_dl_reserve - политика, затем слот ─────────────────────── */

int aivpn_session_dl_reserve(struct aivpn_kern_session *s, const u8 *ip,
			     unsigned int buf_len, unsigned int pkt_len,
			     struct aivpn_dl_reservation *out)
{
	struct aivpn_ip_view view;
	unsigned int nbytes;
	int v;
	u32 idx;

	/* Caller holds rcu_read_lock(). Слот не занимаем, пока политика не ACCEPT. */
	spin_lock_bh(&s->lock);
	v = aivpn_pol_direction(&s->pol, AIVPN_POL_TX_FALLBACK);
	if (v == AIVPN_VERDICT_DROP) {
		spin_unlock_bh(&s->lock);
		return -EPERM;
	}
	if (v != AIVPN_VERDICT_ACCEPT) {
		spin_unlock_bh(&s->lock);
		return -EAGAIN;
	}
	if (s->dl_tag_pos != 0xFFFF &&
	    (unsigned int)s->dl_tag_pos + AIVPN_TAG_SIZE > s->dl_mdh_len) {
		spin_unlock_bh(&s->lock);
		return -EAGAIN;
	}
	if (s->dl_next >= s->dl_count) {
		spin_unlock_bh(&s->lock);
		return -EAGAIN;
	}
	if (aivpn_ip_parse(ip, buf_len, pkt_len, &view) != 0) {
		spin_unlock_bh(&s->lock);
		return -EPERM;
	}
	v = aivpn_pol_check_addrs(&s->pol, AIVPN_DIR_DOWNLINK, ip, buf_len, pkt_len,
				  aivpn_peer_is_other, s);
	if (v == AIVPN_VERDICT_DROP) {
		spin_unlock_bh(&s->lock);
		return -EPERM;
	}
	if (v != AIVPN_VERDICT_ACCEPT) {
		spin_unlock_bh(&s->lock);
		return -EAGAIN;
	}
	nbytes = view.length ? view.length : pkt_len;
	v = aivpn_session_account(s, AIVPN_DIR_DOWNLINK, nbytes, ktime_get_ns());
	if (v != AIVPN_VERDICT_ACCEPT) {
		spin_unlock_bh(&s->lock);
		return -EPERM;
	}
	idx = s->dl_next++;
	memcpy(out->tag, s->dl_entries[idx].tag, AIVPN_TAG_SIZE);
	out->counter = s->dl_entries[idx].counter;
	out->seq_num = (u16)(s->dl_seq_base + idx);
	out->mdh_len = s->dl_mdh_len;
	out->tag_pos = s->dl_tag_pos;
	if (s->dl_mdh_len)
		memcpy(out->mdh, s->dl_mdh, s->dl_mdh_len);
	else
		memset(out->mdh, 0, sizeof(out->mdh));
	memcpy(out->client_addr, s->client_addr, sizeof(out->client_addr));
	s->tx_packets++;
	/* Учет сервера совпадает с длиной UDP payload в userspace. */
	s->tx_bytes += nbytes + s->dl_mdh_len + AIVPN_PADLEN_SIZE + AIVPN_INNER_HDR_SIZE + AIVPN_AUTH_SIZE +
		(s->dl_tag_pos == 0xFFFF ? AIVPN_TAG_SIZE : 0U);
	spin_unlock_bh(&s->lock);
	return 0;
}

int aivpn_session_rx_prepare(struct aivpn_kern_session *s, u64 counter,
			     int *replay_dup)
{
	int v, r;

	*replay_dup = 0;
	v = aivpn_pol_direction(&s->pol, AIVPN_POL_RX_FALLBACK);
	if (v != AIVPN_VERDICT_ACCEPT)
		return v;
	v = aivpn_pol_fast(&s->pol);
	if (v != AIVPN_VERDICT_ACCEPT)
		return v;
	/* Эпоха еще не привязана: не смотрим чужое окно и не отмечаем счетчик. */
	if (s->replay.epoch == 0)
		return AIVPN_VERDICT_FALLBACK;
	r = aivpn_replay_observe_win(s->replay.hi, s->replay.words, counter);
	if (r == AIVPN_REPLAY_DUP) {
		*replay_dup = 1;
		return AIVPN_VERDICT_DROP;
	}
	if (r == AIVPN_REPLAY_TOO_OLD)
		return AIVPN_VERDICT_FALLBACK;
	return AIVPN_VERDICT_ACCEPT;
}

int aivpn_session_rx_finish(struct aivpn_kern_session *s, u64 counter,
			    const u8 *plain, unsigned int plain_len,
			    unsigned int wire_len, int *replay_dup)
{
	struct aivpn_ip_view view;
	int v, r, claim;

	*replay_dup = 0;
	v = aivpn_pol_direction(&s->pol, AIVPN_POL_RX_FALLBACK);
	if (v != AIVPN_VERDICT_ACCEPT)
		return v;
	if (s->replay.epoch == 0)
		return AIVPN_VERDICT_FALLBACK;
	r = aivpn_replay_observe_win(s->replay.hi, s->replay.words, counter);
	if (r == AIVPN_REPLAY_DUP) {
		*replay_dup = 1;
		return AIVPN_VERDICT_DROP;
	}
	if (r == AIVPN_REPLAY_TOO_OLD)
		return AIVPN_VERDICT_FALLBACK;
	v = aivpn_pol_fast(&s->pol);
	if (v != AIVPN_VERDICT_ACCEPT)
		return v;
	if (aivpn_ip_parse(plain, plain_len, plain_len, &view) != 0)
		return AIVPN_VERDICT_DROP;
	v = aivpn_pol_check_addrs(&s->pol, AIVPN_DIR_UPLINK, plain, plain_len,
				  plain_len, aivpn_peer_is_other, s);
	if (v != AIVPN_VERDICT_ACCEPT)
		return v;
	/* Захват только после адресов: FALLBACK не сжигает счетчик для userspace. */
	claim = aivpn_epoch_claim(&s->replay, s->replay.epoch, counter);
	if (claim == AIVPN_CLAIM_DUP) {
		*replay_dup = 1;
		return AIVPN_VERDICT_DROP;
	}
	if (claim != AIVPN_CLAIM_OK)
		return AIVPN_VERDICT_FALLBACK;
	v = aivpn_session_account(s, AIVPN_DIR_UPLINK, view.length, ktime_get_ns());
	if (v != AIVPN_VERDICT_ACCEPT)
		return AIVPN_VERDICT_DROP;
	s->rx_packets++;
	s->rx_bytes += s->pol.role == AIVPN_ROLE_CLIENT ? view.length : wire_len;
	return AIVPN_VERDICT_ACCEPT;
}

int aivpn_session_policy_set(const struct aivpn_session_policy *in)
{
	struct aivpn_kern_session *s, *cand;
	u32 others = 0;
	int bkt, ret;

	if (!in)
		return -EINVAL;
	spin_lock_bh(&aivpn_table_lock);
	s = aivpn_find_session(in->session_id);
	if (!s) {
		spin_unlock_bh(&aivpn_table_lock);
		return -ENOENT;
	}
	/* Считаем чужие слоты под table lock, без их session lock: писатель
	 * флагов тоже держит table lock, datapath эти поля не меняет. */
	if (aivpn_key_nonzero(in->client_key)) {
		hash_for_each(aivpn_session_htable, bkt, cand, mgmt_node) {
			if (cand == s)
				continue;
			if (!aivpn_key_nonzero(cand->pol.client_key))
				continue;
			if (crypto_memneq(cand->pol.client_key, in->client_key, 16))
				continue;
			if (aivpn_pol_slot_armed(&cand->pol))
				others++;
		}
	}
	spin_lock_bh(&s->lock);
	ret = aivpn_pol_apply(&s->pol, in);
	if (!ret && aivpn_pol_over_cap(others, s->pol.max_sessions)) {
		/* Лимит не валит ioctl: новая сессия остается без ускорения. */
		s->pol.armed = 0;
		s->pol.flags |= AIVPN_POL_FALLBACK;
	}
	if (!ret)
		aivpn_qos_reconfigure(in);
	spin_unlock_bh(&s->lock);
	spin_unlock_bh(&aivpn_table_lock);
	return ret ? -EINVAL : 0;
}

int aivpn_session_sync(struct aivpn_session_sync *io)
{
	struct aivpn_kern_session *s;
	__u64 rx_d, tx_d;

	if (!io)
		return -EINVAL;
	spin_lock_bh(&aivpn_table_lock);
	s = aivpn_find_session(io->session_id);
	if (!s) {
		spin_unlock_bh(&aivpn_table_lock);
		return -ENOENT;
	}
	spin_lock_bh(&s->lock);
	/* PUSH не вливается: анти-replay это только claim под этим замком. */
	rx_d = s->rx_bytes >= s->pol.rx_bytes_synced ?
		s->rx_bytes - s->pol.rx_bytes_synced : 0;
	tx_d = s->tx_bytes >= s->pol.tx_bytes_synced ?
		s->tx_bytes - s->pol.tx_bytes_synced : 0;
	if (io->flags & AIVPN_SYNC_ACK_STATS) {
		s->pol.rx_bytes_synced = s->rx_bytes;
		s->pol.tx_bytes_synced = s->tx_bytes;
	}
	io->replay_hi = s->replay.hi;
	memcpy(io->replay_words, s->replay.words, sizeof(io->replay_words));
	io->rx_packets = s->rx_packets;
	io->tx_packets = s->tx_packets;
	io->rx_bytes = s->rx_bytes;
	io->tx_bytes = s->tx_bytes;
	io->rx_bytes_delta = rx_d;
	io->tx_bytes_delta = tx_d;
	io->quota_up_left = s->pol.quota_up;
	io->quota_down_left = s->pol.quota_down;
	{
		__u64 quota = io->quota_up_left;
		aivpn_qos_budget_left(s->pol.client_key, AIVPN_DIR_UPLINK, 0, &quota);
		io->quota_up_left = quota;
		quota = io->quota_down_left;
		aivpn_qos_budget_left(s->pol.client_key, AIVPN_DIR_DOWNLINK, 0, &quota);
		io->quota_down_left = quota;
	}
	spin_unlock_bh(&s->lock);
	spin_unlock_bh(&aivpn_table_lock);
	return 0;
}

int aivpn_session_replay_claim(struct aivpn_replay_claim *io)
{
	struct aivpn_kern_session *s;

	if (!io)
		return -EINVAL;
	spin_lock_bh(&aivpn_table_lock);
	s = aivpn_find_session(io->session_id);
	if (!s) {
		spin_unlock_bh(&aivpn_table_lock);
		return -ENOENT;
	}
	spin_lock_bh(&s->lock);
	/* Unarmed тоже фиксирует бит: userspace отмечает пакет раньше, чем ядро возьмет RX. */
	io->result = aivpn_epoch_claim(&s->replay, io->epoch, io->counter);
	spin_unlock_bh(&s->lock);
	spin_unlock_bh(&aivpn_table_lock);
	return 0;
}

int aivpn_session_replay_rotate(const struct aivpn_replay_rotate *in)
{
	struct aivpn_kern_session *s;
	int ret;

	if (!in)
		return -EINVAL;
	spin_lock_bh(&aivpn_table_lock);
	s = aivpn_find_session(in->session_id);
	if (!s) {
		spin_unlock_bh(&aivpn_table_lock);
		return -ENOENT;
	}
	spin_lock_bh(&s->lock);
	ret = aivpn_epoch_rotate(&s->replay, in->epoch);
	spin_unlock_bh(&s->lock);
	spin_unlock_bh(&aivpn_table_lock);
	return ret ? -EINVAL : 0;
}

int aivpn_session_qos_charge(struct aivpn_qos_charge *io)
{
	struct aivpn_kern_session *s;
	int v;
	__u64 tokens, quota;

	if (!io)
		return -EINVAL;
	if (io->dir != AIVPN_QOS_DIR_UP && io->dir != AIVPN_QOS_DIR_DOWN)
		return -EINVAL;
	spin_lock_bh(&aivpn_table_lock);
	s = aivpn_find_session(io->session_id);
	if (!s) {
		spin_unlock_bh(&aivpn_table_lock);
		return -ENOENT;
	}
	spin_lock_bh(&s->lock);
	if (s->pol.flags & AIVPN_POL_REVOKED) {
		io->result = AIVPN_QOS_DROP;
		io->tokens_left = 0;
		io->quota_left = io->dir == AIVPN_QOS_DIR_UP ? s->pol.quota_up
							    : s->pol.quota_down;
		spin_unlock_bh(&s->lock);
		spin_unlock_bh(&aivpn_table_lock);
		return 0;
	}
	v = aivpn_pol_fast(&s->pol);
	if (v != AIVPN_VERDICT_ACCEPT) {
		io->result = AIVPN_QOS_FALLBACK;
		io->tokens_left = 0;
		io->quota_left = io->dir == AIVPN_QOS_DIR_UP ? s->pol.quota_up
							    : s->pol.quota_down;
		spin_unlock_bh(&s->lock);
		spin_unlock_bh(&aivpn_table_lock);
		return 0;
	}
	v = aivpn_session_account(s, (int)io->dir, io->nbytes, ktime_get_ns());
	tokens = io->dir == AIVPN_QOS_DIR_UP ? s->pol.tokens_up : s->pol.tokens_down;
	quota = io->dir == AIVPN_QOS_DIR_UP ? s->pol.quota_up : s->pol.quota_down;
	tokens = aivpn_qos_budget_left(s->pol.client_key, (int)io->dir, tokens, &quota);
	io->result = v == AIVPN_VERDICT_ACCEPT ? AIVPN_QOS_ACCEPT : AIVPN_QOS_DROP;
	io->tokens_left = tokens;
	io->quota_left = quota;
	spin_unlock_bh(&s->lock);
	spin_unlock_bh(&aivpn_table_lock);
	return 0;
}

int aivpn_client_revoke(const struct aivpn_client_revoke *rv)
{
	struct aivpn_kern_session *s;
	int bkt;

	if (!rv || !aivpn_key_nonzero(rv->client_key))
		return -EINVAL;
	spin_lock_bh(&aivpn_table_lock);
	hash_for_each(aivpn_session_htable, bkt, s, mgmt_node) {
		if (!aivpn_key_nonzero(s->pol.client_key))
			continue;
		if (crypto_memneq(s->pol.client_key, rv->client_key, 16))
			continue;
		spin_lock_bh(&s->lock);
		s->pol.flags |= AIVPN_POL_REVOKED;
		spin_unlock_bh(&s->lock);
	}
	spin_unlock_bh(&aivpn_table_lock);
	return 0;
}

/* ── aivpn_tag_lookup - hot path, called with rcu_read_lock() held ─────── */

struct aivpn_kern_session *aivpn_tag_lookup(const u8 *tag, u64 *counter)
{
	struct aivpn_tag_entry *e;
	u32 h = tag_hash_key(tag);

	hash_for_each_possible_rcu(aivpn_tag_htable, e, hnode, h) {
		if (!crypto_memneq(e->tag, tag, AIVPN_TAG_SIZE)) {
			*counter = e->counter;
			return e->session;
		}
	}
	return NULL;
}

/* ── aivpn_session_remove ────────────────────────────────────────────────── */

static struct aivpn_kern_session *aivpn_session_detach(const u8 *session_id)
{
	struct aivpn_kern_session *s;
	int i;

	spin_lock_bh(&aivpn_table_lock);
	s = aivpn_find_session(session_id);
	if (!s) {
		spin_unlock_bh(&aivpn_table_lock);
		return NULL;
	}
	hash_del(&s->mgmt_node);
	if (!hlist_unhashed(&s->ip_node))
		hash_del_rcu(&s->ip_node);
	atomic_dec(&aivpn_session_count);
	/* Теги уходят в call_rcu. Слот QoS не освобождаем: следующая сессия того
	 * же клиента должна увидеть оставшийся бюджет, а не полное ведро. */
	for (i = 0; i < s->tag_entry_count; i++) {
		if (s->tag_entries[i]) {
			hash_del_rcu(&s->tag_entries[i]->hnode);
			call_rcu(&s->tag_entries[i]->rcu, tag_entry_free_rcu);
			s->tag_entries[i] = NULL;
		}
	}
	s->tag_entry_count = 0;
	spin_unlock_bh(&aivpn_table_lock);
	return s;
}

static int aivpn_session_remove_locked(const u8 *session_id)
{
	struct aivpn_kern_session *s;

	s = aivpn_session_detach(session_id);
	if (!s)
		return -ENOENT;

	/* Wait for all in-flight RCU readers before freeing.  The RX fast path
	 * holds rcu_read_lock() across its whole tag-lookup → decrypt → window
	 * update sequence, so after this returns no data-path CPU can still
	 * hold a pointer to this session. */
	synchronize_rcu();

	/*
	 * Belt and braces: any straggler that took session->lock just before
	 * the grace period completed has long released it, but draining the
	 * lock is free and keeps the invariant obvious.
	 */
	spin_lock_bh(&s->lock);
	spin_unlock_bh(&s->lock);

	session_free(s);
	return 0;
}

int aivpn_session_remove(const u8 *session_id)
{
	int ret;

	mutex_lock(&aivpn_lifecycle_lock);
	ret = aivpn_session_remove_locked(session_id);
	mutex_unlock(&aivpn_lifecycle_lock);
	return ret;
}

/* ── aivpn_session_flush ─────────────────────────────────────────────────── */

static void aivpn_session_flush_locked(void)
{
	struct aivpn_kern_session *s;
	struct hlist_node *tmp;
	HLIST_HEAD(to_free);
	int bkt, i;

	spin_lock_bh(&aivpn_table_lock);
	hash_for_each_safe(aivpn_session_htable, bkt, tmp, s, mgmt_node) {
		hash_del(&s->mgmt_node);
		if (!hlist_unhashed(&s->ip_node))
			hash_del_rcu(&s->ip_node);
		for (i = 0; i < s->tag_entry_count; i++) {
			if (s->tag_entries[i])
				hash_del_rcu(&s->tag_entries[i]->hnode);
		}
		/* Re-use mgmt_node (removed from htable) to chain the free list */
		hlist_add_head(&s->mgmt_node, &to_free);
	}
	atomic_set(&aivpn_session_count, 0);
	spin_unlock_bh(&aivpn_table_lock);

	synchronize_rcu();

	hlist_for_each_entry_safe(s, tmp, &to_free, mgmt_node) {
		hlist_del(&s->mgmt_node);
		/* Drain any in-progress decrypt before freeing (see session_remove). */
		spin_lock_bh(&s->lock);
		spin_unlock_bh(&s->lock);
		for (i = 0; i < s->tag_entry_count; i++) {
			if (s->tag_entries[i]) {
				kfree_sensitive(s->tag_entries[i]);
				s->tag_entries[i] = NULL;
			}
		}
		session_free(s);
	}
}

void aivpn_session_flush(void)
{
	mutex_lock(&aivpn_lifecycle_lock);
	aivpn_session_flush_locked();
	mutex_unlock(&aivpn_lifecycle_lock);
}

/* ── aivpn_session_stat ──────────────────────────────────────────────────── */

int aivpn_session_stat(struct aivpn_session_stat *stat)
{
	struct aivpn_kern_session *s, *candidate;
	u32 h = sid_hash_key(stat->session_id);

	spin_lock_bh(&aivpn_table_lock);
	s = NULL;
	hash_for_each_possible(aivpn_session_htable, candidate, mgmt_node, h) {
		if (!crypto_memneq(candidate->session_id, stat->session_id, 16)) {
			s = candidate;
			break;
		}
	}
	if (!s) {
		spin_unlock_bh(&aivpn_table_lock);
		return -ENOENT;
	}
	spin_lock_bh(&s->lock);
	stat->active     = 1;
	stat->rx_packets = s->rx_packets;
	stat->tx_packets = s->tx_packets;
	stat->rx_bytes   = s->rx_bytes;
	stat->tx_bytes   = s->tx_bytes;
	spin_unlock_bh(&s->lock);
	spin_unlock_bh(&aivpn_table_lock);
	return 0;
}
