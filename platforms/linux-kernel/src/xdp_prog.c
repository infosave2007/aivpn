// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_prog.c — AIVPN XDP early-filter program.
 *
 * Compiled with: clang -O2 -target bpf -c xdp_prog.c -o xdp_prog.o
 * Attached with: ip link set dev <iface> xdp obj xdp_prog.o sec xdp
 *
 * Purpose:
 *   First-stage DDoS protection at NIC RX level, before socket buffer
 *   allocation.  Validates that UDP packets on the configured VPN port carry
 *   a plausible AIVPN resonance-tag header (correct size, non-expired
 *   timestamp).  Clearly invalid packets are dropped in XDP before any
 *   kernel networking work is done.
 *
 *   Legitimate packets are forwarded with XDP_PASS to the normal network
 *   stack, where the kernel module's sk_data_ready hook performs full
 *   tag validation and decryption.
 *
 * Configuration (BPF ARRAY map "xdp_config", pinned at
 *   /sys/fs/bpf/aivpn/xdp_config):
 *   key 0 → u64  VPN UDP destination port (host byte order; 0 = pass all UDP)
 *   key 1 → u64  reserved (was: tag window ms — removed; tag validation is in kernel module)
 *
 * Protocol layout at UDP payload offset 0:
 *   [8 bytes]  resonance tag  (BLAKE3 keyed hash — opaque to XDP)
 *   [N bytes]  mask-dependent header (MDH, variable length per active mask)
 *   [2 bytes]  pad_len
 *   [1 byte]   inner_type / control sub-type
 *   [...]      encrypted payload + Poly1305 tag
 *
 * Minimum valid payload: tag(8) + pad_len(1) + inner_type(1) +
 *                        Poly1305(16) = 26 bytes.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Minimum AIVPN UDP payload: tag + pad_len + inner_type + Poly1305 auth tag */
#define AIVPN_MIN_PAYLOAD 26

/* Drop reason codes (index into drop_stats map) */
#define DROP_TOO_SHORT   0
#define DROP_TAG_EXPIRED 1
#define DROP_RESERVED    2
#define DROP_TOTAL       3

/* BPF ARRAY map: 2 slots (index 0 = port, index 1 = window_ms) */
struct {
	__uint(type,        BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key,         __u32);
	__type(value,       __u64);
} xdp_config SEC(".maps");

/* Per-reason + total drop counters.
 * Pinned at /sys/fs/bpf/aivpn/drop_stats by the loader.
 * userspace reads key DROP_TOTAL (3) for aggregate drop monitoring. */
struct {
	__uint(type,        BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key,         __u32);
	__type(value,       __u64);
} drop_stats SEC(".maps");

/* Real-time event ring buffer (256 KB).
 * Pinned at /sys/fs/bpf/aivpn/events by the loader. */
struct bpf_event {
	__u32 type;        /* 1 = xdp_drop */
	__u32 session_id;  /* 0 for non-session drops */
	__u64 count;
	__u32 drop_reason;
	__u32 pad;
};

struct {
	__uint(type,        BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Increment a drop_stats counter and emit a ring-buffer event.
 * Both operations are best-effort (failure is silent — XDP must not stall). */
static __always_inline void
record_drop(__u32 reason)
{
	__u32 k_reason = reason, k_total = DROP_TOTAL;
	__u64 *c;

	c = bpf_map_lookup_elem(&drop_stats, &k_reason);
	if (c)
		__sync_fetch_and_add(c, 1);

	c = bpf_map_lookup_elem(&drop_stats, &k_total);
	if (c)
		__sync_fetch_and_add(c, 1);

	struct bpf_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (ev) {
		ev->type        = 1;
		ev->session_id  = 0;
		ev->count       = 1;
		ev->drop_reason = reason;
		ev->pad         = 0;
		bpf_ringbuf_submit(ev, 0);
	}
}

SEC("xdp")
int aivpn_xdp_filter(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* ── Ethernet ─────────────────────────────────────────────────── */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS; /* non-IPv4: ignore */

	/* ── IPv4 ─────────────────────────────────────────────────────── */
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	__u32 ip_hlen = (__u32)ip->ihl * 4;
	if (ip_hlen < sizeof(*ip))
		return XDP_DROP;

	/* ── UDP ──────────────────────────────────────────────────────── */
	struct udphdr *udp = (void *)ip + ip_hlen;
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;

	/* ── Port check ───────────────────────────────────────────────── */
	__u32  key0    = 0;
	__u64 *pcfg    = bpf_map_lookup_elem(&xdp_config, &key0);
	__u16  vpn_port = pcfg ? (__u16)*pcfg : 0;
	if (vpn_port == 0 || udp->dest != bpf_htons(vpn_port))
		return XDP_PASS; /* not our port: leave untouched */

	/* ── Minimum size check ───────────────────────────────────────── */
	__u16 udp_total = bpf_ntohs(udp->len); /* includes UDP header */
	if (udp_total < sizeof(*udp) + AIVPN_MIN_PAYLOAD) {
		record_drop(DROP_TOO_SHORT);
		return XDP_DROP;
	}

	/* Resonance-tag validation requires the session key and is performed
	 * by the kernel module's sk_data_ready hook.  XDP only checks port
	 * and minimum payload size — both already done above.
	 */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
