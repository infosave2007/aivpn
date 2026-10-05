/* SPDX-License-Identifier: GPL-2.0 */
/*
 * session_table.h — kernel-side session table for aivpn.ko
 *
 * Two hash tables:
 *   aivpn_tag_htable    — keyed by 8-byte resonance tag (RCU, read from softirq)
 *   aivpn_session_htable — keyed by 16-byte session_id (spinlock, management only)
 *
 * Anti-replay uses the shared 512-bit window in policy.h (bit 0 = newest).
 */

#ifndef AIVPN_SESSION_TABLE_H
#define AIVPN_SESSION_TABLE_H

#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/atomic.h>
#include <crypto/aead.h>
#include "../include/uapi/aivpn.h"
#include "policy.h"

/* Размеры полей зашифрованного Data. */
#define AIVPN_AUTH_SIZE 16
#define AIVPN_PADLEN_SIZE 2
#define AIVPN_INNER_HDR_SIZE 4

/* Hash table sizes */
#define AIVPN_TAG_HASH_BITS      17   /* 128K buckets for tag entries */
#define AIVPN_SESSION_HASH_BITS   9   /* 512 buckets for session objects */

/**
 * struct aivpn_tag_entry - one (tag, counter) entry in the per-session tag window.
 *
 * Installed by AIVPN_IOC_SESSION_UPDATE_TAGS.  The kernel looks up incoming
 * packets by their 8-byte resonance tag; matching an entry gives both the
 * session pointer and the counter needed to build the AEAD nonce.
 *
 * Protected by RCU on the read side (softirq); spinlock_bh on writes.
 */
struct aivpn_tag_entry {
	u8                       tag[8];      /* wire resonance tag (hash key) */
	u64                      counter;     /* counter that generated this tag */
	struct aivpn_kern_session *session;   /* owning session (non-owning ptr) */
	struct hlist_node        hnode;       /* aivpn_tag_htable linkage */
	struct rcu_head          rcu;         /* for call_rcu on removal */
};

/**
 * struct aivpn_kern_session - per-VPN-session state
 *
 * Allocated by AIVPN_IOC_SESSION_ADD, freed after all RCU grace periods
 * following AIVPN_IOC_SESSION_DEL / flush.
 */
/**
 * struct aivpn_dl_entry - one reserved downlink (tag, counter) slot.
 *
 * Installed by AIVPN_IOC_SESSION_DOWNLINK. The counter is owned exclusively by
 * the kernel (user-space advanced its send_counter past it), so using it for
 * the s2c AEAD nonce can never collide with a user-space downlink packet.
 */
struct aivpn_dl_entry {
	u8   tag[8];      /* pre-computed resonance tag for this counter */
	u64  counter;     /* reserved downlink send-counter (AEAD nonce basis) */
};

struct aivpn_kern_session {
	/* management hash table linkage — keyed on session_id */
	struct hlist_node  mgmt_node;

	/* client-VPN-IP hash linkage (RCU) — keyed on client_ip, for egress */
	struct hlist_node  ip_node;

	/* identity */
	u8   session_id[16];

	/* crypto material — zeroed on removal */
	struct crypto_aead *tfm;      /* c2s uplink key (ChaCha20-Poly1305) */
	struct crypto_aead *tfm_s2c;  /* s2c downlink key (ChaCha20-Poly1305) */
	u8   nonce_suffix[4];         /* bytes 8-11 of the 12-byte nonce */

	/* Variant A wire layout (derived from tag_offset + mdh_len at insert) */
	u16  tag_pos;                 /* byte offset of the resonance tag in the packet */
	u16  ct_pos;                  /* byte offset where the ciphertext begins */

	/* VPN routing */
	u32  client_ip;               /* VPN IPv4 (network byte order) */
	u8   client_addr[28];         /* sockaddr_storage of the UDP peer (downlink dst) */

	/* Downlink (s2c) acceleration — reserved counter block + MDH template.
	 * dl_entries/dl_count/dl_mdh are replaced wholesale under s->lock by
	 * AIVPN_IOC_SESSION_DOWNLINK; dl_next is the monotonic consume cursor. When
	 * dl_next >= dl_count the block is exhausted and downlink falls back. */
	u8   dl_mdh[AIVPN_DL_MDH_MAX];
	u16  dl_mdh_len;
	u16  dl_seq_base;
	/* 0xFFFF пока downlink ioctl не задал реальное положение тега.
	 * Ноль означает встройку с начала заголовка, а не legacy. */
	u16  dl_tag_pos;
	u32  dl_count;
	u32  dl_next;                 /* next unused entry (protected by s->lock) */
	struct aivpn_dl_entry dl_entries[AIVPN_TAG_WINDOW_SLOTS];

	/* Политика, replay и остатки квоты. Писатели флагов держат table lock
	 * и этот lock. Datapath меняет квоту, токены и replay только под этим lock. */
	spinlock_t        lock;
	struct aivpn_pol  pol;
	/* Окно эпох не входит в pol: обновление политики его не стирает. */
	struct aivpn_epoch_win replay;

	/* stats (updated under lock) */
	u64  rx_packets;
	u64  rx_bytes;
	u64  tx_packets;
	u64  tx_bytes;

	/* tag window: pointers to tag entries installed in aivpn_tag_htable */
	struct aivpn_tag_entry   *tag_entries[AIVPN_TAG_WINDOW_SLOTS];
	int                       tag_entry_count;
};

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

int  aivpn_session_table_init(void);
void aivpn_session_table_fini(void);
void aivpn_session_owner_release(void);

/* ── CRUD ────────────────────────────────────────────────────────────────── */

int  aivpn_session_insert(const struct aivpn_session_add *add);
int  aivpn_session_tags_update(const struct aivpn_session_update_tags *upd);
int  aivpn_session_downlink_update(const struct aivpn_session_downlink *dl);
int  aivpn_session_policy_set(const struct aivpn_session_policy *in);
int  aivpn_session_sync(struct aivpn_session_sync *io);
int  aivpn_session_replay_claim(struct aivpn_replay_claim *io);
int  aivpn_session_replay_rotate(const struct aivpn_replay_rotate *in);
int  aivpn_session_qos_charge(struct aivpn_qos_charge *io);
int  aivpn_client_revoke(const struct aivpn_client_revoke *rv);
int  aivpn_session_remove(const u8 *session_id);
void aivpn_session_flush(void);
int  aivpn_session_stat(struct aivpn_session_stat *stat);

/**
 * struct aivpn_dl_reservation - a claimed downlink slot returned to the caller.
 *
 * Snapshot of everything the crypto/transmit path needs, copied out while
 * s->lock is held so the AEAD (which must run lock-free) never touches the
 * session again.
 */
struct aivpn_dl_reservation {
	u8   tag[8];
	u64  counter;
	u16  seq_num;
	u16  mdh_len;
	u16  tag_pos;                 /* копия dl_tag_pos на момент резерва */
	u8   mdh[AIVPN_DL_MDH_MAX];
	u8   client_addr[28];
};

/**
 * aivpn_session_lookup_by_ip - find an RCU-protected session by client VPN IP.
 *
 * Called from the egress hook (softirq/process). Must be wrapped in
 * rcu_read_lock(); the returned pointer stays valid until rcu_read_unlock().
 * Returns NULL if no session owns @client_ip (network byte order).
 */
struct aivpn_kern_session *aivpn_session_lookup_by_ip(u32 client_ip);

/**
 * aivpn_session_dl_reserve - проверить политику и занять слот downlink.
 *
 * Caller holds rcu_read_lock(). @buf_len это длина уже скопированного префикса
 * (обычно 40), @pkt_len это skb->len. 0: слот занят и квота списана.
 * -EAGAIN: fallback, слот не занят. -EPERM: drop, слот не занят.
 * Встройка, в которую тег не помещается, дает -EAGAIN до занятия слота.
 */
int aivpn_session_dl_reserve(struct aivpn_kern_session *s, const u8 *ip,
			     unsigned int buf_len, unsigned int pkt_len,
			     struct aivpn_dl_reservation *out);

/**
 * aivpn_session_rx_prepare - быстрый вердикт и просмотр replay до расшифровки.
 *
 * Caller holds s->lock. Не двигает окно. Эпоха 0 дает FALLBACK без отметки.
 * DUP это DROP, слишком старый счетчик это FALLBACK.
 * *replay_dup = 1 только для уже виденного счетчика текущей эпохи.
 */
int aivpn_session_rx_prepare(struct aivpn_kern_session *s, u64 counter,
			     int *replay_dup);

/**
 * aivpn_session_rx_finish - повтор replay, адреса, квота и фиксация ACCEPT.
 *
 * Caller holds s->lock and rcu_read_lock() (поиск соседа идет через RCU).
 * Захват счетчика стоит сразу перед списанием. Если списание не удалось,
 * счетчик уже занят и вердикт DROP, не FALLBACK.
 */
int aivpn_session_rx_finish(struct aivpn_kern_session *s, u64 counter,
			    const u8 *plain, unsigned int plain_len,
			    unsigned int wire_len, int *replay_dup);

/**
 * aivpn_tag_lookup - find a session by its wire resonance tag.
 *
 * Called from softirq.  Returns a pointer with rcu_read_lock held by the
 * caller; fills *counter with the nonce counter for this tag.  Returns NULL
 * if the tag is not in the table.
 *
 * Caller must hold rcu_read_lock() across the returned pointer's use and
 * call rcu_read_unlock() when done.
 */
struct aivpn_kern_session *aivpn_tag_lookup(const u8 *tag, u64 *counter);

/**
 * aivpn_tag_probe_offsets - bitmap of packet byte offsets at which a resonance
 * tag might sit, across all installed sessions (Variant A).
 *
 * The kernel finds a session BY its tag, but the tag's position depends on that
 * session's mask — a chicken-and-egg the RX path resolves by probing every
 * offset that any live session uses. Bit N set means "some session reads its
 * tag at byte offset N". Offsets are small (legacy=0, quic=6, webrtc=8), so the
 * set is tiny; it only ever grows, so a stale extra bit just costs one wasted
 * lookup that misses. Read lock-free on the hot path.
 */
u64 aivpn_tag_probe_offsets(void);

#endif /* AIVPN_SESSION_TABLE_H */
