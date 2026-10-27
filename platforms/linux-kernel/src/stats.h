/* SPDX-License-Identifier: GPL-2.0 */
/*
 * stats.h — global data-plane counters for aivpn.ko observability.
 *
 * All counters are process-wide atomics incremented on the RX/TX fast path.
 * They are exported read-only via /proc/aivpn/stats so an operator can see, on
 * a live stand, how many packets the kernel actually handled versus how many
 * fell back to user-space. This is diagnostic only — no packet routing depends
 * on these values.
 */

#ifndef AIVPN_STATS_H
#define AIVPN_STATS_H

#include <linux/atomic.h>

enum aivpn_stat_id {
	AIVPN_STAT_RX_TOTAL = 0,   /* skbs entering the RX hook             */
	AIVPN_STAT_TAG_HIT,        /* tag matched a kernel session          */
	AIVPN_STAT_FALLBACK,       /* returned to user-space (miss/too-short)*/
	AIVPN_STAT_REPLAY_DROP,    /* anti-replay rejected                  */
	AIVPN_STAT_DECRYPT_FAIL,   /* AEAD auth failed → fell back          */
	AIVPN_STAT_CTRL_FALLBACK,  /* decrypted non-Data → fell back        */
	AIVPN_STAT_INJECT_OK,      /* injected into TUN via netif_rx        */
	AIVPN_STAT_INJECT_FAIL,    /* TUN inject failed (no dev)            */
	AIVPN_STAT_TX_ENCRYPT_OK,  /* downlink encrypt succeeded            */
	AIVPN_STAT_TX_ENCRYPT_FAIL,/* downlink encrypt failed               */
	AIVPN_STAT_POLICY_DROP,    /* политика запретила пакет              */
	AIVPN_STAT_POLICY_FALLBACK,/* режим не поддержан, пакет в userspace */
	AIVPN_STAT__COUNT
};

extern atomic64_t aivpn_stat_counters[AIVPN_STAT__COUNT];

static inline void aivpn_stat_inc(enum aivpn_stat_id id)
{
	atomic64_inc(&aivpn_stat_counters[id]);
}

/* Create/remove /proc/aivpn/stats. Called from module init/fini. */
int  aivpn_stats_init(void);
void aivpn_stats_fini(void);

#endif /* AIVPN_STATS_H */
