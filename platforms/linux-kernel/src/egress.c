// SPDX-License-Identifier: GPL-2.0
/*
 * egress.c — kernel downlink (server->client) fast path for aivpn.ko
 *
 * A netfilter POST_ROUTING hook intercepts packets the server routes toward a
 * client VPN IP (i.e. onto the TUN device). For a session that has been armed
 * for downlink acceleration (AIVPN_IOC_SESSION_DOWNLINK) the packet is:
 *
 *   1. matched by destination VPN IP  -> aivpn_session_lookup_by_ip()
 *   2. assigned a reserved (tag,counter) slot -> aivpn_session_dl_reserve()
 *   3. encrypted with the s2c key      -> aivpn_downlink_encrypt()
 *   4. transmitted to the client's public UDP address from the server socket
 *      -> udp_tunnel_xmit_skb(), NF_STOLEN (the original TUN-bound skb is freed)
 *
 * Any packet that is not a plain IPv4 unicast for an armed, non-exhausted
 * session is passed through (NF_ACCEPT) so the existing user-space downlink
 * path handles it unchanged. Every failure after the packet is claimed is
 * fail-safe: the reserved counter is simply skipped (a downlink gap the client
 * tolerates) and the original skb is dropped rather than double-sent.
 *
 * CONTEXT: POST_ROUTING runs in softirq for forwarded packets, so nothing here
 * may sleep — all allocations use GFP_ATOMIC, the route lookup and transmit are
 * non-sleeping, and the s2c AEAD is synchronous.
 *
 * SAFETY: the hook is unregistered (nf_unregister_net_hook, which waits for
 * in-flight invocations) BEFORE the server socket reference is dropped, so the
 * data path can never touch a freed socket.
 */

#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/sock.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/inet_sock.h>
#include <net/udp_tunnel.h>
#include <net/net_namespace.h>

#include "egress.h"
#include "session_table.h"
#include "crypto_ops.h"
#include "stats.h"
#include "helpers.h"

/* Upper bound on the inner IP packet we will accelerate. Larger packets fall
 * back to user-space. Comfortably above any standard MTU. */
#define AIVPN_DL_MAX_IP   1600
/* Wire overhead: tag(8) + max MDH + pad_len(2) + inner_hdr(4) + auth(16). */
#define AIVPN_DL_OVERHEAD (8 + AIVPN_DL_MDH_MAX + 2 + 4 + 16)

static DEFINE_MUTEX(aivpn_egress_lock);
static struct sock       *aivpn_egress_sk;          /* server UDP sock (held) — netns anchor + wire src */
static struct net        *aivpn_egress_net;         /* netns of that socket   */
static u32                aivpn_egress_tun_ifindex;  /* 0 = any out device     */
static bool               aivpn_egress_registered;
/* DEDICATED kernel UDP socket used SOLELY to transmit downlink datagrams.
 * The server's userspace socket must NOT be reused for kernel-side xmit: doing
 * so corrupted its socket accounting and panicked in inet_sock_destruct when
 * that socket was later torn down. This is the wireguard/vxlan pattern — the
 * xmit vehicle is a socket the module owns. Bound to an ephemeral port; the
 * wire source addr/port are taken from the server socket and passed explicitly
 * to udp_tunnel_xmit_skb, so the client still sees the expected src ip:port. */
static struct socket     *aivpn_egress_ksock;
static __be32             aivpn_egress_saddr;        /* wire source addr (server sock) */
static __be16             aivpn_egress_sport;        /* wire source port (server sock) */

/* Diagnostic: when set, the egress hook encrypts the downlink packet (so
 * tx_encrypt_ok increments) but SKIPS the actual xmit and drops the skb. Lets
 * the encrypt path be validated in isolation from the socket xmit path.
 * Toggle live via /sys/module/aivpn/parameters/egress_dryrun. */
static bool aivpn_egress_dryrun;
module_param_named(egress_dryrun, aivpn_egress_dryrun, bool, 0644);
MODULE_PARM_DESC(egress_dryrun,
		 "downlink egress: encrypt but skip xmit (diagnostic, default 0)");

static unsigned int aivpn_egress_hook(void *priv, struct sk_buff *skb,
				      const struct nf_hook_state *state);

static struct nf_hook_ops aivpn_egress_ops = {
	.hook     = aivpn_egress_hook,
	.pf       = NFPROTO_IPV4,
	.hooknum  = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_LAST,
};

/* Transmit an already-built wire buffer to @daddr:@dport from the server sock.
 * Consumes nothing on the caller's behalf on error paths except the skb it
 * allocates. Returns 0 on success, -errno otherwise. Never sleeps. */
static int aivpn_egress_xmit(struct net *net,
			     __be32 daddr, __be16 dport,
			     const u8 *wire, unsigned int wire_len)
{
	struct socket *ksock = READ_ONCE(aivpn_egress_ksock);
	struct sock *sk = ksock ? ksock->sk : NULL;
	struct sk_buff *tx;
	struct rtable *rt;
	struct flowi4 fl4;
	__be32 saddr = READ_ONCE(aivpn_egress_saddr);
	__be16 sport = READ_ONCE(aivpn_egress_sport);
	__u8 ttl;
	unsigned int headroom;
	u8 *data;

	if (!sk || !net || wire_len == 0)
		return -EINVAL;

	headroom = LL_MAX_HEADER + sizeof(struct iphdr) + sizeof(struct udphdr);
	tx = alloc_skb(headroom + wire_len, GFP_ATOMIC);
	if (!tx)
		return -ENOMEM;
	skb_reserve(tx, headroom);
	data = skb_put(tx, wire_len);
	memcpy(data, wire, wire_len);
	tx->ip_summed = CHECKSUM_NONE;

	/* saddr/sport come from the SERVER socket (captured at set_egress), NOT
	 * from the kernel xmit socket (which is bound to an ephemeral port). This
	 * keeps the wire src ip:port exactly what the client expects. */

	memset(&fl4, 0, sizeof(fl4)); /* DSCP/tos left 0 (best-effort) */
	fl4.flowi4_oif   = sk->sk_bound_dev_if;
	fl4.daddr        = daddr;
	fl4.saddr        = saddr;
	fl4.flowi4_proto = IPPROTO_UDP;
	fl4.fl4_dport    = dport;
	fl4.fl4_sport    = sport;

	rt = ip_route_output_key(net, &fl4);
	if (IS_ERR(rt)) {
		kfree_skb(tx);
		return PTR_ERR(rt);
	}

	/* Let the route pick the source address if the socket was bound to ANY. */
	saddr = fl4.saddr;
	ttl = ip4_dst_hoplimit(&rt->dst);

	/* Do NOT skb_dst_set(tx, &rt->dst) here: udp_tunnel_xmit_skb() → iptunnel_xmit()
	 * takes ownership of the single @rt reference and installs it on @tx itself
	 * (after skb_scrub_packet()'s skb_dst_drop). Pre-setting the dst made the one
	 * route reference get released twice → rcuref_put_slowpath underflow panic on
	 * kernels where dst_entry uses rcuref_t. Correct callers (vxlan_xmit_one,
	 * geneve, wireguard send4) pass @rt and never pre-set the skb dst.
	 *
	 * nocheck=true: zero UDP checksum (legal for IPv4), avoids any checksum
	 * arithmetic on this path. udp_tunnel_xmit_skb pushes the UDP + IP headers
	 * and hands the skb to ip_local_out. It consumes @tx unconditionally. */
	udp_tunnel_xmit_skb(rt, sk, tx, saddr, daddr, /*tos=*/0, ttl, /*df=*/0,
			    sport, dport,
			    /*xnet=*/false, /*nocheck=*/true, /*ipcb_flags=*/0);
	return 0;
}

static unsigned int aivpn_egress_hook(void *priv, struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	struct aivpn_kern_session *s;
	struct aivpn_dl_reservation r;
	const struct iphdr *iph;
	struct iphdr _iph;
	u32 tun_ifindex;
	__be32 vpn_daddr, client_daddr;
	__be16 client_dport;
	unsigned int ip_len, wire_len = 0;
	u8 *ipbuf, *wire;
	int ret;

	if (!skb)
		return NF_ACCEPT;

	/* Only intercept egress toward the configured TUN device (if set). */
	tun_ifindex = READ_ONCE(aivpn_egress_tun_ifindex);
	if (tun_ifindex && (!state->out || state->out->ifindex != tun_ifindex))
		return NF_ACCEPT;

	/* IPv4 unicast only. */
	if (skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;
	iph = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
	if (!iph || iph->version != 4 || iph->ihl < 5)
		return NF_ACCEPT;
	/* Skip fragments — we cannot re-frame a partial datagram. */
	if (iph->frag_off & htons(IP_MF | IP_OFFSET))
		return NF_ACCEPT;
	vpn_daddr = iph->daddr;

	ip_len = skb->len;
	if (ip_len == 0 || ip_len > AIVPN_DL_MAX_IP)
		return NF_ACCEPT;

	/* GSO packets can be small enough to pass the length check (e.g. two
	 * GRO-merged TCP segments), but skb_checksum_help() rejects any GSO skb
	 * via skb_warn_bad_offload() — a WARN with a full call trace — and we
	 * cannot re-frame a multi-segment datagram anyway. Fall back to user
	 * space BEFORE a downlink slot is reserved: validate_xmit_skb() will
	 * software-segment it on the way to the TUN device, exactly as it does
	 * for the pure user-space path. */
	if (skb_is_gso(skb))
		return NF_ACCEPT;

	rcu_read_lock();
	s = aivpn_session_lookup_by_ip(vpn_daddr);
	if (!s) {
		rcu_read_unlock();
		return NF_ACCEPT; /* not a kernel-known client — user-space path */
	}

	/* Claim a reserved downlink slot. -EAGAIN => block exhausted, fall back. */
	ret = aivpn_session_dl_reserve(s, &r);
	if (ret) {
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	/* From here the slot is committed. Any failure drops this packet (a
	 * tolerated downlink gap) rather than passing it on, to avoid the
	 * user-space path re-sending the same IP packet under a different counter. */

	/* Finalise any deferred (offloaded) L4 checksum before we snapshot the
	 * packet bytes for encryption. A packet egressing the TUN can still carry
	 * CHECKSUM_PARTIAL: the L4 checksum field holds only the pseudo-header sum
	 * and the real checksum is normally computed later by the "device". The
	 * TUN driver does exactly this (skb_checksum_help in tun_put_user) when it
	 * hands a packet to user space, which is why the user-space downlink path
	 * produces valid packets. We intercept at POST_ROUTING *before* that step,
	 * so without this the client receives an inner segment with a stale
	 * pseudo-header checksum, its TCP/UDP stack drops it, and the handshake
	 * never completes. skb_checksum_help() writes the completed checksum into
	 * the linear data in place; it is non-sleeping and safe under rcu_read_lock.
	 * GSO skbs never reach this point (rejected with NF_ACCEPT above), so the
	 * skb_warn_bad_offload() path inside the helper is never taken here.
	 *
	 * skb_checksum_help() additionally requires the checksummed region to
	 * START in the linear area: a forwarded/GRO skb is frequently non-linear
	 * with csum_start past skb_headlen(), which trips the helper's
	 * WARN_ONCE("offset >= skb_headlen()") and fails. Linearize first —
	 * skb_linearize() uses GFP_ATOMIC internally, never sleeps, and is safe
	 * in softirq under rcu_read_lock; after it skb_headlen() == skb->len so
	 * both headlen WARNs in the helper are structurally unreachable. */
	if (skb->ip_summed == CHECKSUM_PARTIAL &&
	    (skb_linearize(skb) || skb_checksum_help(skb))) {
		rcu_read_unlock();
		aivpn_stat_inc(AIVPN_STAT_TX_ENCRYPT_FAIL);
		kfree_skb(skb);
		return NF_STOLEN;
	}

	ipbuf = kmalloc(ip_len, GFP_ATOMIC);
	if (!ipbuf) {
		rcu_read_unlock();
		aivpn_stat_inc(AIVPN_STAT_TX_ENCRYPT_FAIL);
		kfree_skb(skb);
		return NF_STOLEN;
	}
	if (skb_copy_bits(skb, 0, ipbuf, ip_len) < 0) {
		kfree(ipbuf);
		rcu_read_unlock();
		aivpn_stat_inc(AIVPN_STAT_TX_ENCRYPT_FAIL);
		kfree_skb(skb);
		return NF_STOLEN;
	}

	wire = kmalloc(ip_len + AIVPN_DL_OVERHEAD, GFP_ATOMIC);
	if (!wire) {
		kfree_sensitive(ipbuf);
		rcu_read_unlock();
		aivpn_stat_inc(AIVPN_STAT_TX_ENCRYPT_FAIL);
		kfree_skb(skb);
		return NF_STOLEN;
	}

	ret = aivpn_downlink_encrypt(s, &r, ipbuf, ip_len, wire,
				     ip_len + AIVPN_DL_OVERHEAD, &wire_len);
	/* Session no longer needed after encryption. */
	rcu_read_unlock();
	kfree_sensitive(ipbuf);
	if (ret) {
		kfree_sensitive(wire);
		aivpn_stat_inc(AIVPN_STAT_TX_ENCRYPT_FAIL);
		kfree_skb(skb);
		return NF_STOLEN;
	}

	/* Resolve the client's public UDP endpoint from the stored sockaddr.
	 * Layout (see make_kernel_session_add): [0..2] family (native),
	 * [2..4] port (big-endian), [4..8] IPv4 (network order). */
	{
		u16 fam = (u16)r.client_addr[0] | ((u16)r.client_addr[1] << 8);
		if (fam != AF_INET) {
			kfree_sensitive(wire);
			aivpn_stat_inc(AIVPN_STAT_TX_ENCRYPT_FAIL);
			kfree_skb(skb);
			return NF_STOLEN;
		}
		memcpy(&client_dport, &r.client_addr[2], sizeof(client_dport));
		memcpy(&client_daddr, &r.client_addr[4], sizeof(client_daddr));
	}

	if (READ_ONCE(aivpn_egress_dryrun)) {
		/* Diagnostic: encryption already succeeded; skip the socket xmit
		 * entirely and drop the packet. Isolates the encrypt path from the
		 * xmit path so the former can be validated without the latter. */
		kfree_sensitive(wire);
		aivpn_stat_inc(AIVPN_STAT_TX_ENCRYPT_OK);
		kfree_skb(skb);
		return NF_STOLEN;
	}

	ret = aivpn_egress_xmit(READ_ONCE(aivpn_egress_net),
				client_daddr, client_dport, wire, wire_len);
	kfree_sensitive(wire);
	if (ret)
		aivpn_stat_inc(AIVPN_STAT_TX_ENCRYPT_FAIL);
	else
		aivpn_stat_inc(AIVPN_STAT_TX_ENCRYPT_OK);

	/* We own the original TUN-bound skb now; drop it either way. */
	kfree_skb(skb);
	return NF_STOLEN;
}

int aivpn_egress_set(int udp_fd, u32 tun_ifindex, u32 enable)
{
	int ret = 0;

	mutex_lock(&aivpn_egress_lock);

	if (!enable) {
		if (aivpn_egress_registered) {
			nf_unregister_net_hook(aivpn_egress_net, &aivpn_egress_ops);
			aivpn_egress_registered = false;
			/* Only after the hook is gone (nf_unregister_net_hook waits for
			 * in-flight invocations) is it safe to drop the sockets. */
			if (aivpn_egress_ksock) {
				sock_release(aivpn_egress_ksock);
				aivpn_egress_ksock = NULL;
			}
			if (aivpn_egress_sk) {
				sock_put(aivpn_egress_sk);
				aivpn_egress_sk = NULL;
			}
			if (aivpn_egress_net) {
				put_net(aivpn_egress_net);
				aivpn_egress_net = NULL;
			}
			WRITE_ONCE(aivpn_egress_tun_ifindex, 0);
			aivpn_info("downlink egress hook disabled\n");
		}
		mutex_unlock(&aivpn_egress_lock);
		return 0;
	}

	/* Enable: reject a double-enable to keep the sock refcount balanced. */
	if (aivpn_egress_registered) {
		mutex_unlock(&aivpn_egress_lock);
		return -EBUSY;
	}

	{
		struct socket *sock;
		int err = 0;

		sock = sockfd_lookup(udp_fd, &err);
		if (!sock) {
			mutex_unlock(&aivpn_egress_lock);
			return err ? err : -EBADF;
		}
		if (!sock->sk || sock->sk->sk_family != AF_INET ||
		    sock->sk->sk_protocol != IPPROTO_UDP) {
			sockfd_put(sock);
			mutex_unlock(&aivpn_egress_lock);
			return -EINVAL;
		}
		aivpn_egress_sk  = sock->sk;
		sock_hold(aivpn_egress_sk);
		/* Take our own netns reference: the cached pointer must stay
		 * valid for nf_unregister_net_hook() at disable/fini time even
		 * if the socket's implicit hold ever stops covering it. */
		aivpn_egress_net = get_net(sock_net(aivpn_egress_sk));
		/* Capture the wire source ip:port from the server socket; the kernel
		 * xmit socket (created below) carries a different, ephemeral port. */
		aivpn_egress_saddr = inet_sk(aivpn_egress_sk)->inet_saddr;
		aivpn_egress_sport = inet_sk(aivpn_egress_sk)->inet_sport;
		sockfd_put(sock);
	}

	/* Dedicated kernel UDP socket used only to transmit downlink datagrams —
	 * never the server's userspace socket (reusing it corrupts sk accounting
	 * and panics inet_sock_destruct). Ephemeral port; the wire src ip:port is
	 * overridden per-packet from aivpn_egress_saddr/sport. */
	{
		struct udp_port_cfg cfg;
		int cerr;

		memset(&cfg, 0, sizeof(cfg));
		cfg.family = AF_INET;
		cfg.local_ip.s_addr = htonl(INADDR_ANY);
		cfg.local_udp_port = 0;
		cerr = udp_sock_create(aivpn_egress_net, &cfg, &aivpn_egress_ksock);
		if (cerr) {
			aivpn_egress_ksock = NULL;
			sock_put(aivpn_egress_sk);
			aivpn_egress_sk  = NULL;
			put_net(aivpn_egress_net);
			aivpn_egress_net = NULL;
			mutex_unlock(&aivpn_egress_lock);
			aivpn_err("downlink egress kernel socket create failed: %d\n",
				  cerr);
			return cerr;
		}
	}

	WRITE_ONCE(aivpn_egress_tun_ifindex, tun_ifindex);

	ret = nf_register_net_hook(aivpn_egress_net, &aivpn_egress_ops);
	if (ret) {
		sock_release(aivpn_egress_ksock);
		aivpn_egress_ksock = NULL;
		sock_put(aivpn_egress_sk);
		aivpn_egress_sk  = NULL;
		put_net(aivpn_egress_net);
		aivpn_egress_net = NULL;
		WRITE_ONCE(aivpn_egress_tun_ifindex, 0);
		mutex_unlock(&aivpn_egress_lock);
		aivpn_err("downlink egress hook register failed: %d\n", ret);
		return ret;
	}
	aivpn_egress_registered = true;
	aivpn_info("downlink egress hook enabled (tun ifindex %u)\n", tun_ifindex);

	mutex_unlock(&aivpn_egress_lock);
	return 0;
}

void aivpn_egress_fini(void)
{
	aivpn_egress_set(0, 0, 0);
}
