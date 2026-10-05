// SPDX-License-Identifier: GPL-2.0
/*
 * crypto_ops.c — per-session ChaCha20-Poly1305 AEAD for aivpn.ko
 *
 * Nonce layout (12 bytes):
 *   nonce[0..8]  = counter (little-endian u64)
 *   nonce[8..12] = session->nonce_suffix[0..4]
 *
 * AAD = 8-byte resonance tag.  Auth tag = 16 bytes (Poly1305).
 *
 * CRITICAL: the counter used for the nonce comes from the tag-window lookup
 * (aivpn_tag_lookup), NOT from the wire.  Extracting the counter from the
 * wire would let an attacker force arbitrary nonces and break AEAD security.
 */

#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/skbuff.h>
#include <crypto/aead.h>
#include "crypto_ops.h"
#include "helpers.h"
#include "policy.h"

#define AIVPN_NONCE_SIZE  12

/* Inner plaintext framing (matches user-space encode_payload):
 *   pad_len(2 LE) || inner_header(4) || inner payload || pad(pad_len)
 * inner_header = inner_type(2 LE) || seq_num(2 LE). */
#define AIVPN_INNER_TYPE_DATA  0x0001

static void build_nonce(u8 nonce[AIVPN_NONCE_SIZE],
			u64 counter, const u8 nonce_suffix[4])
{
	__le64 ctr_le = cpu_to_le64(counter);
	memcpy(nonce, &ctr_le, 8);
	memcpy(nonce + 8, nonce_suffix, 4);
}

int aivpn_decrypt(struct aivpn_kern_session *s, struct sk_buff *skb, u64 counter,
		  unsigned int ct_start, u8 **plain_out, unsigned int *plain_len_out)
{
	struct aead_request *req;
	struct scatterlist sg_data;
	DECLARE_CRYPTO_WAIT(wait);
	u8 nonce[AIVPN_NONCE_SIZE];
	unsigned int data_len, plain_len;
	u8 *scratch;
	int ret;

	if (plain_out)
		*plain_out = NULL;
	if (plain_len_out)
		*plain_len_out = 0;

	/* Need at least the ciphertext offset plus a Poly1305 tag. */
	if (skb->len < ct_start + AIVPN_AUTH_SIZE)
		return -EINVAL;

	if (skb_linearize(skb))
		return -ENOMEM;

	data_len  = skb->len - ct_start;          /* ciphertext + auth tag */
	plain_len = data_len - AIVPN_AUTH_SIZE;    /* decrypted plaintext   */

	/* Out-of-place: copy the ciphertext into a scratch buffer and decrypt
	 * there, so an auth failure leaves the wire skb byte-for-byte intact for
	 * user-space fallback. */
	scratch = kmalloc(data_len, GFP_ATOMIC);
	if (!scratch)
		return -ENOMEM;
	skb_copy_bits(skb, ct_start, scratch, data_len);

	/* Nonce from tag-window counter, not from wire bytes */
	build_nonce(nonce, counter, s->nonce_suffix);

	/* User-space encrypt_payload() uses no AAD; assoclen must be 0. */
	sg_init_one(&sg_data, scratch, data_len);

	req = aead_request_alloc(s->tfm, GFP_ATOMIC);
	if (!req) {
		kfree_sensitive(scratch);
		return -ENOMEM;
	}

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_ad(req, 0);
	aead_request_set_crypt(req, &sg_data, &sg_data, data_len, nonce);

	ret = crypto_wait_req(crypto_aead_decrypt(req), &wait);
	aead_request_free(req);
	memzero_explicit(nonce, sizeof(nonce));
	if (ret) {
		/* Authentication failed. Leave skb intact and signal fallback. */
		aivpn_dbg("decrypt failed: %d\n", ret);
		kfree_sensitive(scratch);
		return -EBADMSG;
	}

	/* Decrypt succeeded. Strip the inner framing and inject ONLY Data packets;
	 * everything else (Control / Ack / Fragment / keepalive, or any malformed
	 * framing) is handed to user-space, which owns the control plane. The skb is
	 * still the untouched wire packet at this point, so -ENOMSG lets the caller
	 * fall back cleanly. */
	{
		u16 pad_len, inner_type;
		unsigned int inner_len, ip_len;

		if (plain_len < AIVPN_PADLEN_SIZE + AIVPN_INNER_HDR_SIZE) {
			kfree_sensitive(scratch);
			return -ENOMSG;
		}
		/* Little-endian, alignment-free reads from the scratch buffer. */
		pad_len    = (u16)scratch[0] | ((u16)scratch[1] << 8);
		inner_type = (u16)scratch[2] | ((u16)scratch[3] << 8);

		if ((unsigned int)AIVPN_PADLEN_SIZE + pad_len > plain_len) {
			kfree_sensitive(scratch);
			return -ENOMSG;
		}
		inner_len = plain_len - AIVPN_PADLEN_SIZE - pad_len; /* inner_header + IP */
		if (inner_len < AIVPN_INNER_HDR_SIZE ||
		    inner_type != AIVPN_INNER_TYPE_DATA) {
			kfree_sensitive(scratch);
			return -ENOMSG;
		}
		ip_len = inner_len - AIVPN_INNER_HDR_SIZE;
		if (ip_len == 0) {
			kfree_sensitive(scratch);
			return -ENOMSG;
		}

		/* IP в начало scratch. skb остается проводом до вердикта ACCEPT. */
		memmove(scratch,
			scratch + AIVPN_PADLEN_SIZE + AIVPN_INNER_HDR_SIZE, ip_len);
		if (plain_out)
			*plain_out = scratch;
		else
			kfree_sensitive(scratch);
		if (plain_len_out)
			*plain_len_out = ip_len;
	}
	return 0;
}

/* aivpn_downlink_encrypt — build one server->client Data packet.
 *
 * @s:      session; caller holds rcu_read_lock() so s (and s->tfm_s2c) stay
 *          valid. NO spinlock is held: the AEAD may not run under a spinlock,
 *          and the egress context cannot sleep, so the s2c cipher must be
 *          synchronous (rfc7539(chacha20,poly1305) completes inline).
 * @r:      a reservation claimed via aivpn_session_dl_reserve() — supplies the
 *          pre-computed tag, the reserved counter (AEAD nonce basis, owned
 *          exclusively by the kernel), the seq_num and the MDH template.
 * @ip:     inner cleartext IP packet.
 * @ip_len: its length (> 0).
 * @out:    destination wire buffer; @out_cap bytes of capacity.
 * @out_len: on success, the number of wire bytes written.
 *
 * Раскладка задается r->tag_pos. pad_len фиксирован нулем.
 */
int aivpn_downlink_encrypt(struct aivpn_kern_session *s,
			   const struct aivpn_dl_reservation *r,
			   const u8 *ip, unsigned int ip_len,
			   u8 *out, unsigned int out_cap,
			   unsigned int *out_len)
{
	struct aead_request *req;
	struct scatterlist sg;
	DECLARE_CRYPTO_WAIT(wait);
	u8 nonce[AIVPN_NONCE_SIZE];
	unsigned int hdr_len = 0, plain_len, ct_len, total;
	u8 *pt;
	int ret;

	if (!s->tfm_s2c || ip_len == 0 || r->mdh_len > AIVPN_DL_MDH_MAX)
		return -EINVAL;

	plain_len = AIVPN_PADLEN_SIZE + AIVPN_INNER_HDR_SIZE + ip_len;
	ct_len    = plain_len + AIVPN_AUTH_SIZE;
	if (aivpn_place_header(out, out_cap, r->tag, r->mdh, r->mdh_len,
			       r->tag_pos, &hdr_len))
		return -EINVAL;
	total = hdr_len + ct_len;
	if (total > out_cap)
		return -EMSGSIZE;

	/* Assemble the inner plaintext in place at the ciphertext offset. The AEAD
	 * encrypts it there and appends the 16-byte auth tag (covered by ct_len). */
	pt = out + hdr_len;
	pt[0] = 0;                                  /* pad_len LE = 0 */
	pt[1] = 0;
	pt[2] = (u8)(AIVPN_INNER_TYPE_DATA & 0xff); /* inner_type LE = Data */
	pt[3] = (u8)(AIVPN_INNER_TYPE_DATA >> 8);
	pt[4] = (u8)(r->seq_num & 0xff);            /* seq_num LE */
	pt[5] = (u8)(r->seq_num >> 8);
	memcpy(pt + AIVPN_PADLEN_SIZE + AIVPN_INNER_HDR_SIZE, ip, ip_len);

	/* Nonce = reserved counter (LE64) || nonce_suffix; the reserved counter is
	 * never used by any other downlink packet, so this nonce is unique. */
	build_nonce(nonce, r->counter, s->nonce_suffix);

	sg_init_one(&sg, pt, ct_len);
	req = aead_request_alloc(s->tfm_s2c, GFP_ATOMIC);
	if (!req) {
		memzero_explicit(nonce, sizeof(nonce));
		return -ENOMEM;
	}
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_ad(req, 0);
	aead_request_set_crypt(req, &sg, &sg, plain_len, nonce);

	ret = crypto_wait_req(crypto_aead_encrypt(req), &wait);
	aead_request_free(req);
	memzero_explicit(nonce, sizeof(nonce));
	if (ret) {
		aivpn_dbg("downlink encrypt failed: %d\n", ret);
		return ret;
	}
	*out_len = total;
	return 0;
}
