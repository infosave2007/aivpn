/* SPDX-License-Identifier: GPL-2.0 */
/*
 * crypto_ops.h — ChaCha20-Poly1305 AEAD wrappers for aivpn.ko
 */

#ifndef AIVPN_CRYPTO_OPS_H
#define AIVPN_CRYPTO_OPS_H

#include <linux/skbuff.h>
#include "session_table.h"

/**
 * aivpn_decrypt - расшифровать пакет в отдельный буфер, skb не менять.
 *
 * Успех: *plain_out это один kmalloc с внутренним IP в начале, вызывающий
 * освобождает его через kfree_sensitive. skb остается проводом, чтобы отказ
 * политики мог вернуть пакет в userspace. -EBADMSG и -ENOMSG тоже оставляют
 * skb целым и ставят *plain_out в NULL.
 */
int aivpn_decrypt(struct aivpn_kern_session *s, struct sk_buff *skb, u64 counter,
		  unsigned int ct_start, u8 **plain_out, unsigned int *plain_len);

/**
 * aivpn_downlink_encrypt - собрать один server to client Data пакет в @out.
 *
 * Раскладка берется из r->tag_pos. 0xFFFF: tag, затем mdh, затем AEAD.
 * Иначе tag лежит внутри mdh, шифротекст начинается с mdh_len.
 * Возвращает 0 или -errno. При ошибке вызывающий сам решает судьбу skb.
 */
int aivpn_downlink_encrypt(struct aivpn_kern_session *s,
			   const struct aivpn_dl_reservation *r,
			   const u8 *ip, unsigned int ip_len,
			   u8 *out, unsigned int out_cap,
			   unsigned int *out_len);

#endif /* AIVPN_CRYPTO_OPS_H */
