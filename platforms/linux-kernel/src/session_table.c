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
static atomic_t aivpn_session_count = ATOMIC_INIT(0);

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
	hash_init(aivpn_tag_htable);
	hash_init(aivpn_session_htable);
	hash_init(aivpn_ip_htable);
	ret = aivpn_stats_init();
	if (ret)
		return ret;
	aivpn_info("session table ready (tag: %u, session: %u buckets)\n",
		   1u << AIVPN_TAG_HASH_BITS, 1u << AIVPN_SESSION_HASH_BITS);
	return 0;
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

int aivpn_session_insert(const struct aivpn_session_add *add)
{
	struct aivpn_kern_session *s;
	struct crypto_aead *tfm;
	int ret;

	/* Idempotent install: evict any existing session with this id first, so a
	 * re-add (the client switched masks, or the keys rotated) refreshes the
	 * wire offsets and keys instead of leaving a stale duplicate whose frozen
	 * mdh_len/tfm would silently fail every decrypt. Cheap no-op (returns
	 * -ENOENT before any grace period) on a first-time add. */
	aivpn_session_remove(add->session_id);

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	memcpy(s->session_id,   add->session_id,  sizeof(s->session_id));
	memcpy(s->nonce_suffix, add->nonce_suffix, sizeof(s->nonce_suffix));
	memcpy(s->client_addr,  add->client_addr, sizeof(s->client_addr));
	s->client_ip = add->client_ip;
	/* Downlink block starts empty: a session is not downlink-accelerated until
	 * AIVPN_IOC_SESSION_DOWNLINK arms it. kzalloc already zeroed dl_*. */

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
	atomic64_set(&s->tx_counter, (s64)add->counter_base);
	/* recv_counter and replay_window are zero-initialised by kzalloc */

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

/* ── aivpn_session_dl_reserve — claim one reserved downlink slot ─────────── */

int aivpn_session_dl_reserve(struct aivpn_kern_session *s,
			     struct aivpn_dl_reservation *out)
{
	u32 idx;

	/* Caller holds rcu_read_lock() so s cannot be freed under us. Take s->lock
	 * only to consume a slot — the AEAD runs after we return, lock-free. */
	spin_lock_bh(&s->lock);
	if (s->dl_next >= s->dl_count) {
		spin_unlock_bh(&s->lock);
		return -EAGAIN; /* block exhausted — fall back to user-space */
	}
	idx = s->dl_next++;
	memcpy(out->tag, s->dl_entries[idx].tag, AIVPN_TAG_SIZE);
	out->counter = s->dl_entries[idx].counter;
	out->seq_num = (u16)(s->dl_seq_base + idx);
	out->mdh_len = s->dl_mdh_len;
	if (s->dl_mdh_len)
		memcpy(out->mdh, s->dl_mdh, s->dl_mdh_len);
	memcpy(out->client_addr, s->client_addr, sizeof(out->client_addr));
	spin_unlock_bh(&s->lock);
	return 0;
}

/* ── aivpn_tag_lookup — hot path, called with rcu_read_lock() held ─────── */

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

/* ── WireGuard-style anti-replay: check, then update after auth ─────────── */

/*
 * Split check/update (WireGuard ordering): the RX path CHECKS the window
 * before decrypting but only UPDATES it after the packet authenticates as
 * Data.  Packets that fall back to user-space (Control/Ack/keepalive, auth
 * failures) must not advance the kernel window — user-space maintains its own
 * window over the same counter space, and burning counters here made the two
 * diverge, dropping legitimately-reordered Data packets.
 */

bool aivpn_counter_check(const struct aivpn_kern_session *s, u64 counter)
{
	u64 diff;

	/* Caller must hold s->lock (via spin_lock_bh) */

	if (counter > s->recv_counter)
		return true;

	diff = s->recv_counter - counter;
	if (diff >= AIVPN_REPLAY_WINDOW)
		return false; /* too old */

	return !test_bit((u32)diff, s->replay_window); /* false on replay */
}

void aivpn_counter_update(struct aivpn_kern_session *s, u64 counter)
{
	u64 diff;

	/* Caller must hold s->lock (via spin_lock_bh) */

	if (counter > s->recv_counter) {
		/* Advance window; shift left so bit 0 = recv_counter */
		diff = counter - s->recv_counter;
		if (diff < AIVPN_REPLAY_WINDOW) {
			bitmap_shift_left(s->replay_window, s->replay_window,
					  (unsigned int)diff, AIVPN_REPLAY_WINDOW);
		} else {
			bitmap_zero(s->replay_window, AIVPN_REPLAY_WINDOW);
		}
		s->recv_counter = counter;
		set_bit(0, s->replay_window);
		return;
	}

	diff = s->recv_counter - counter;
	if (diff < AIVPN_REPLAY_WINDOW)
		set_bit((u32)diff, s->replay_window);
}

/* ── aivpn_session_remove ────────────────────────────────────────────────── */

int aivpn_session_remove(const u8 *session_id)
{
	struct aivpn_kern_session *s, *candidate;
	int i;

	spin_lock_bh(&aivpn_table_lock);
	s = NULL;
	hash_for_each_possible(aivpn_session_htable, candidate, mgmt_node,
			       sid_hash_key(session_id)) {
		if (!crypto_memneq(candidate->session_id, session_id, 16)) {
			s = candidate;
			break;
		}
	}
	if (!s) {
		spin_unlock_bh(&aivpn_table_lock);
		return -ENOENT;
	}

	hash_del(&s->mgmt_node);
	if (!hlist_unhashed(&s->ip_node))
		hash_del_rcu(&s->ip_node);
	atomic_dec(&aivpn_session_count);
	/* Unlink the tag entries and hand each to call_rcu (safe under the
	 * spinlock): they are freed after a grace period, exactly as the old
	 * kfree_sensitive-after-synchronize_rcu did, but without a 2 KiB
	 * on-stack pointer snapshot and without any allocation that could
	 * fail the remove path. */
	for (i = 0; i < s->tag_entry_count; i++) {
		if (s->tag_entries[i]) {
			hash_del_rcu(&s->tag_entries[i]->hnode);
			call_rcu(&s->tag_entries[i]->rcu, tag_entry_free_rcu);
			s->tag_entries[i] = NULL;
		}
	}
	s->tag_entry_count = 0;
	spin_unlock_bh(&aivpn_table_lock);

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

/* ── aivpn_session_flush ─────────────────────────────────────────────────── */

void aivpn_session_flush(void)
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
