/* SPDX-License-Identifier: GPL-2.0 */
/*
 * crypto_ops.h — ChaCha20-Poly1305 AEAD wrappers for aivpn.ko
 */

#ifndef AIVPN_CRYPTO_OPS_H
#define AIVPN_CRYPTO_OPS_H

#include <linux/skbuff.h>
#include "session_table.h"

/**
 * aivpn_decrypt - decrypt an inbound skb, leaving the plaintext in @skb.
 * @s:        session. Caller holds rcu_read_lock() (which keeps @s alive) but
 *            NOT s->lock — only the immutable fields (tfm, nonce_suffix) are
 *            read here, so the AEAD runs without serializing the session.
 *            RX stats are accounted by the caller under s->lock afterwards.
 * @skb:      full wire packet; the ciphertext + 16-byte Poly1305 tag begin at
 *            byte offset @ct_start (Variant A layout, per session).
 * @counter:  counter from the tag-window lookup (NOT extracted from wire bytes).
 * @ct_start: byte offset of the ciphertext within the packet.
 *
 * Decrypts OUT OF PLACE into a scratch buffer so the original skb is left
 * untouched on authentication failure — the caller can then hand the packet to
 * user-space, which has decode paths (quic-initial coalescing, ratchet
 * transitions, catalog-mask window) the kernel fast path deliberately does not
 * replicate.
 *
 * Returns:
 *   0        success — skb->data now holds the decrypted inner plaintext.
 *   -EBADMSG authentication failed; skb is INTACT — caller should fall back.
 *   other <0 malformed/allocation error — caller should drop.
 */
int aivpn_decrypt(struct aivpn_kern_session *s, struct sk_buff *skb, u64 counter,
		  unsigned int ct_start);

/**
 * aivpn_encrypt - encrypt an outbound skb in-place.
 * @s:   session (spinlock held by caller).
 * @skb: plaintext IP packet; caller ensures headroom >= 8 and
 *       tailroom >= 16 bytes.
 *
 * Prepends 8-byte resonance tag and appends 16-byte auth tag.
 * Returns 0 on success, -errno on failure.
 */
int aivpn_encrypt(struct aivpn_kern_session *s, struct sk_buff *skb);

/**
 * aivpn_downlink_encrypt - build one server->client Data packet into @out.
 * @s:       session (caller holds rcu_read_lock(); no spinlock held).
 * @r:       reservation from aivpn_session_dl_reserve() (tag/counter/seq/mdh).
 * @ip:      inner cleartext IP packet.
 * @ip_len:  its length (> 0).
 * @out:     wire buffer of @out_cap bytes.
 * @out_len: filled with the wire length on success.
 *
 * Produces: tag || mdh || AEAD_s2c(pad_len=0 || Data || seq || ip).
 * Returns 0 on success, -errno otherwise.
 */
int aivpn_downlink_encrypt(struct aivpn_kern_session *s,
			   const struct aivpn_dl_reservation *r,
			   const u8 *ip, unsigned int ip_len,
			   u8 *out, unsigned int out_cap,
			   unsigned int *out_len);

#endif /* AIVPN_CRYPTO_OPS_H */
