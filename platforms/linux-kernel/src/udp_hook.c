// SPDX-License-Identifier: GPL-2.0
/*
 * udp_hook.c — intercept UDP socket RX for in-kernel VPN fast path
 *
 * After AIVPN_IOC_SET_UDP_SOCK, sk->sk_data_ready is replaced with
 * aivpn_sk_data_ready.  On wakeup we atomically drain the receive queue,
 * process recognised packets (tag lookup → anti-replay → decrypt → TUN
 * inject) and return unrecognised packets to the queue so user-space sees them.
 *
 * HIGH-2 fix: we do NOT use skb_recv_datagram for fallback — that dequeues
 * unconditionally.  Instead we splice the entire receive queue into a local
 * list, categorise in-process, then prepend any fallback packets back to the
 * head of sk_receive_queue (before new arrivals) before waking user-space.
 */

#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <net/sock.h>
#include "udp_hook.h"
#include "session_table.h"
#include "crypto_ops.h"
#include "tun_inject.h"
#include "stats.h"
#include "helpers.h"

struct aivpn_hook_state {
	void (*orig_data_ready)(struct sock *sk);
};

/*
 * The single currently-hooked UDP socket. We sock_hold() it while the hook
 * is installed so the struct sock cannot be freed under us even if user-space
 * closes the fd, and we restore sk_data_ready/sk_user_data from
 * aivpn_udp_hook_uninstall() — wired into module teardown — so no dangling
 * pointer into module text can survive rmmod.
 *
 * Install/uninstall run in process context only (ioctl / module_exit), so a
 * mutex is fine. The RX softirq never touches these globals.
 */
static struct sock *aivpn_hooked_sk;
static DEFINE_MUTEX(aivpn_hook_mutex);

/*
 * aivpn_udp_skb_uncharge — release the UDP receive-memory charge of one skb
 * we CONSUME off sk_receive_queue (decrypt+inject, replay drop, hard error).
 *
 * A datagram sitting on sk_receive_queue was charged against sk_rmem_alloc
 * and sk_forward_alloc by __udp_enqueue_schedule_skb(); modern UDP releases
 * that charge only on the recvmsg path (udp_skb_destructor →
 * udp_rmem_release), NOT via an skb destructor. So a plain kfree_skb()/
 * netif_rx() of a dequeued datagram leaks its truesize: once the leaked
 * total reaches sk_rcvbuf every further datagram is dropped before the hook
 * ever sees it (tunnel stall) and inet_sock_destruct() WARNs at close.
 *
 * udp_rmem_release()/udp_skb_destructor() are not exported to modules, so
 * mirror them with exported primitives: give the truesize back to
 * sk_forward_alloc and reclaim whole pages (sk_mem_uncharge →
 * __sk_mem_reclaim) under the receive-queue lock — UDP's convention for
 * protecting forward-alloc — then drop the sk_rmem_alloc charge.
 *
 * @size must be the truesize the packet was charged with, i.e. captured at
 * dequeue time BEFORE anything (pskb_may_pull/skb_linearize) can grow it.
 * Fallback skbs re-spliced onto sk_receive_queue must NOT be uncharged —
 * recvmsg releases them using the enqueue-time truesize from dev_scratch.
 */
static void aivpn_udp_skb_uncharge(struct sock *sk, unsigned int size)
{
	spin_lock(&sk->sk_receive_queue.lock);
	sk_mem_uncharge(sk, size);
	atomic_sub(size, &sk->sk_rmem_alloc);
	spin_unlock(&sk->sk_receive_queue.lock);
}

static void aivpn_sk_data_ready(struct sock *sk)
{
	struct aivpn_hook_state *hs = sk->sk_user_data;
	struct sk_buff_head process_q, fallback_q;
	struct sk_buff *skb;

	skb_queue_head_init(&process_q);
	skb_queue_head_init(&fallback_q);

	/* Atomically splice the entire receive queue into our local list */
	spin_lock(&sk->sk_receive_queue.lock);
	skb_queue_splice_init(&sk->sk_receive_queue, &process_q);
	spin_unlock(&sk->sk_receive_queue.lock);

	while ((skb = __skb_dequeue(&process_q)) != NULL) {
		struct aivpn_kern_session *session = NULL;
		u64 counter = 0;
		unsigned int ct_start = 0;
		u64 offbits;
		unsigned int off;
		/* Enqueue-time charge; skb->truesize may grow later (pull/linearize). */
		unsigned int rmem_charge = skb->truesize;
		int ret;

		aivpn_stat_inc(AIVPN_STAT_RX_TOTAL);

		if (skb->len < AIVPN_TAG_SIZE) {
			aivpn_stat_inc(AIVPN_STAT_FALLBACK);
			__skb_queue_tail(&fallback_q, skb);
			continue;
		}

		/*
		 * Variant A: the resonance tag may sit at packet offset 0 (legacy
		 * prefix) or embedded inside the mimic header (webrtc=8, quic=6),
		 * and the offset is a property of the session's mask — which we can
		 * only know AFTER identifying the session, which we do BY the tag.
		 * Resolve the cycle by probing every offset any live session uses.
		 *
		 * aivpn_tag_lookup() reads AIVPN_TAG_SIZE bytes from skb->data + off;
		 * a paged/non-linear datagram may keep fewer than that in the linear
		 * header, so pull each candidate window in before reading (GFP_ATOMIC,
		 * non-sleeping — safe under rcu_read_lock).
		 */
		/* Iterate the probe bitmap as a full u64: for_each_set_bit walks
		 * unsigned longs, which on a 32-bit kernel would silently drop
		 * offsets >= 32. */
		offbits = aivpn_tag_probe_offsets();
		rcu_read_lock();
		for (off = 0; off < 64; off++) {
			if (!(offbits & (1ULL << off)))
				continue;
			if (!pskb_may_pull(skb, off + AIVPN_TAG_SIZE))
				continue;
			session = aivpn_tag_lookup(skb->data + off, &counter);
			if (session) {
				ct_start = session->ct_pos;
				break;
			}
		}
		if (!session) {
			rcu_read_unlock();
			aivpn_stat_inc(AIVPN_STAT_FALLBACK);
			__skb_queue_tail(&fallback_q, skb);
			continue;
		}
		aivpn_stat_inc(AIVPN_STAT_TAG_HIT);
		/*
		 * Stay inside rcu_read_lock() for the whole check → decrypt →
		 * update sequence: aivpn_session_remove() unlinks the tag
		 * entries and then waits in synchronize_rcu() before freeing
		 * the session, so the session cannot go away while we are in
		 * this read-side critical section.  Everything below is
		 * non-sleeping (GFP_ATOMIC allocations, synchronous AEAD), as
		 * both softirq context and RCU require.
		 *
		 * WireGuard-style lock split: the replay window is CHECKED
		 * under session->lock, the expensive AEAD decrypt then runs
		 * with the lock DROPPED (it only touches immutable session
		 * fields — tfm, nonce_suffix — and a private scratch buffer),
		 * and the lock is re-acquired to re-validate the counter and
		 * ADVANCE the window.  Keeping the AEAD out of the spinlock
		 * keeps the BH-disabled critical section short and lets
		 * packets of the same session decrypt in parallel.
		 *
		 * Окно смотрим до расшифровки и не двигаем его. Повтор (бит уже
		 * стоит) отбрасываем: userspace не должен принять его второй раз.
		 * Слишком старый счетчик и невооруженная политика уходят в fallback,
		 * skb остается проводом. Отзыв отбрасывается даже без armed.
		 */
		spin_lock_bh(&session->lock);
		{
			int replay_dup = 0;
			int verdict = aivpn_session_rx_prepare(session, counter,
							       &replay_dup);
			spin_unlock_bh(&session->lock);
			if (verdict != AIVPN_VERDICT_ACCEPT) {
				rcu_read_unlock();
				if (verdict == AIVPN_VERDICT_DROP) {
					aivpn_stat_inc(replay_dup ? AIVPN_STAT_REPLAY_DROP
								  : AIVPN_STAT_POLICY_DROP);
					aivpn_udp_skb_uncharge(sk, rmem_charge);
					kfree_skb(skb);
				} else {
					aivpn_stat_inc(AIVPN_STAT_POLICY_FALLBACK);
					__skb_queue_tail(&fallback_q, skb);
				}
				continue;
			}
		}

		{
			u8 *plain = NULL;
			unsigned int plain_len = 0;

			ret = aivpn_decrypt(session, skb, counter, ct_start,
					    &plain, &plain_len);
			if (ret) {
				rcu_read_unlock();
				/*
				 * skb все еще провод. -EBADMSG и -ENOMSG не отмечают
				 * replay и возвращаются в userspace.
				 */
				if (ret == -EBADMSG) {
					aivpn_stat_inc(AIVPN_STAT_DECRYPT_FAIL);
					__skb_queue_tail(&fallback_q, skb);
				} else if (ret == -ENOMSG) {
					aivpn_stat_inc(AIVPN_STAT_CTRL_FALLBACK);
					__skb_queue_tail(&fallback_q, skb);
				} else {
					aivpn_stat_inc(AIVPN_STAT_DECRYPT_FAIL);
					aivpn_udp_skb_uncharge(sk, rmem_charge);
					kfree_skb(skb);
				}
				continue;
			}

			spin_lock_bh(&session->lock);
			{
				int replay_dup = 0;
				int verdict = aivpn_session_rx_finish(session, counter,
								      plain, plain_len,
								      skb->len, &replay_dup);
				spin_unlock_bh(&session->lock);
				rcu_read_unlock();
				if (verdict != AIVPN_VERDICT_ACCEPT) {
					kfree_sensitive(plain);
					if (verdict == AIVPN_VERDICT_FALLBACK) {
						aivpn_stat_inc(AIVPN_STAT_POLICY_FALLBACK);
						__skb_queue_tail(&fallback_q, skb);
					} else {
						aivpn_stat_inc(replay_dup ? AIVPN_STAT_REPLAY_DROP
									  : AIVPN_STAT_POLICY_DROP);
						aivpn_udp_skb_uncharge(sk, rmem_charge);
						kfree_skb(skb);
					}
					continue;
				}
			}

			/* ACCEPT: только теперь кладем внутренний IP в skb. */
			if (skb_linearize(skb) ||
			    (skb->len < plain_len &&
			     (pskb_expand_head(skb, 0, plain_len - skb->len, GFP_ATOMIC) ||
			      !skb_put(skb, plain_len - skb->len)))) {
				kfree_sensitive(plain);
				aivpn_stat_inc(AIVPN_STAT_INJECT_FAIL);
				aivpn_udp_skb_uncharge(sk, rmem_charge);
				kfree_skb(skb);
				continue;
			}
			memcpy(skb->data, plain, plain_len);
			skb_trim(skb, plain_len);
			kfree_sensitive(plain);
		}

		aivpn_udp_skb_uncharge(sk, rmem_charge);
		if (aivpn_tun_inject(skb)) {
			aivpn_stat_inc(AIVPN_STAT_INJECT_FAIL);
			kfree_skb(skb);
		} else {
			aivpn_stat_inc(AIVPN_STAT_INJECT_OK);
		}
	}

	/*
	 * Return fallback packets to the head of the receive queue so they
	 * appear before any new packets that arrived while we were processing.
	 * Then wake user-space once.
	 */
	if (!skb_queue_empty(&fallback_q)) {
		spin_lock(&sk->sk_receive_queue.lock);
		skb_queue_splice(&fallback_q, &sk->sk_receive_queue);
		spin_unlock(&sk->sk_receive_queue.lock);

		if (hs && hs->orig_data_ready)
			hs->orig_data_ready(sk);
	}
}

/*
 * __aivpn_udp_hook_teardown — restore @sk's callbacks and drop our references.
 * Caller holds aivpn_hook_mutex; @sk is the socket stored in aivpn_hooked_sk.
 *
 * UDP RX invokes sk_data_ready directly from softirq without any callback
 * lock, so after restoring the pointer an in-flight softirq may still be
 * executing aivpn_sk_data_ready.  synchronize_rcu() waits for all pre-existing
 * BH-disabled regions (RCU flavors are consolidated), so once it returns no
 * CPU can be inside our callback or still see the old sk_user_data — only
 * then is it safe to kfree(hs) and (at module unload) free module text.
 */
static void __aivpn_udp_hook_teardown(struct sock *sk)
{
	struct aivpn_hook_state *hs = NULL;

	lock_sock(sk);
	if (sk->sk_data_ready == aivpn_sk_data_ready) {
		hs = sk->sk_user_data;
		if (hs)
			sk->sk_data_ready = hs->orig_data_ready;
		sk->sk_user_data = NULL;
	} else {
		/*
		 * A third party re-hooked sk_data_ready after us (chained on
		 * top of our callback).  We cannot restore the chain — their
		 * saved pointer to aivpn_sk_data_ready is unreachable and will
		 * dangle once the module unloads — so warn loudly.  sk_user_data
		 * is still our hook state (the install path only ever hooks a
		 * socket whose sk_user_data was NULL), so reclaim it below
		 * instead of leaking it.
		 */
		WARN_ONCE(1,
			  "aivpn: sk_data_ready was re-hooked by a third party (%ps); cannot restore the callback chain\n",
			  sk->sk_data_ready);
		hs = sk->sk_user_data;
		sk->sk_user_data = NULL;
	}
	release_sock(sk);

	synchronize_rcu();
	kfree(hs);
	sock_put(sk);
}

int aivpn_udp_hook_install(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct aivpn_hook_state *hs;

	if (!sk)
		return -EINVAL;

	/* Only plain IPv4 UDP sockets may be hooked (same contract as
	 * aivpn_egress_set): hooking a TCP/AF_UNIX socket would splice a
	 * foreign receive queue and corrupt its rmem accounting (uncharge
	 * without charge). AF_INET6 is not supported by the egress path. */
	if (sk->sk_family != AF_INET || sk->sk_protocol != IPPROTO_UDP)
		return -EINVAL;

	hs = kzalloc(sizeof(*hs), GFP_KERNEL);
	if (!hs)
		return -ENOMEM;

	mutex_lock(&aivpn_hook_mutex);

	/*
	 * Idempotent re-arm: a second SET_UDP_SOCK on the already-hooked socket
	 * is a no-op.  Without this guard the re-install would capture
	 * orig_data_ready = aivpn_sk_data_ready itself, and the next fallback
	 * wakeup would recurse into our own callback unboundedly (stack
	 * overflow panic).
	 */
	if (aivpn_hooked_sk == sk) {
		mutex_unlock(&aivpn_hook_mutex);
		kfree(hs);
		aivpn_info("UDP hook already installed on this socket\n");
		return 0;
	}

	/* Hooking a NEW socket (client reconnect): tear the old one down first
	 * so we never track two sockets or leak the old hook state. */
	if (aivpn_hooked_sk) {
		__aivpn_udp_hook_teardown(aivpn_hooked_sk);
		aivpn_hooked_sk = NULL;
	}

	lock_sock(sk);
	/* Defence in depth: never chain onto ourselves (tracking lost) and
	 * never hijack a socket some other kernel user owns (encap/reuseport
	 * consumers keep state in sk_user_data). */
	if (sk->sk_data_ready == aivpn_sk_data_ready || sk->sk_user_data) {
		release_sock(sk);
		mutex_unlock(&aivpn_hook_mutex);
		kfree(hs);
		aivpn_err("UDP hook install: socket already claimed\n");
		return -EBUSY;
	}
	hs->orig_data_ready = sk->sk_data_ready;
	sk->sk_user_data    = hs;
	sk->sk_data_ready   = aivpn_sk_data_ready;
	sock_hold(sk);
	aivpn_hooked_sk = sk;
	release_sock(sk);

	mutex_unlock(&aivpn_hook_mutex);

	aivpn_info("UDP hook installed\n");
	return 0;
}

void aivpn_udp_hook_uninstall(void)
{
	mutex_lock(&aivpn_hook_mutex);
	if (aivpn_hooked_sk) {
		__aivpn_udp_hook_teardown(aivpn_hooked_sk);
		aivpn_hooked_sk = NULL;
		aivpn_info("UDP hook removed\n");
	}
	mutex_unlock(&aivpn_hook_mutex);
}

int aivpn_udp_hook_install_by_fd(int fd)
{
	struct socket *sock;
	int err = 0;

	/* fd < 0 is the explicit clear path: unhook whatever is hooked. */
	if (fd < 0) {
		aivpn_udp_hook_uninstall();
		return 0;
	}

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		return err ? err : -EBADF;

	err = aivpn_udp_hook_install(sock);
	sockfd_put(sock);
	return err;
}
