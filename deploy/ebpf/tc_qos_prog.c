// SPDX-License-Identifier: GPL-2.0
// AIVPN TC egress QoS program — per-client token bucket rate limiting + DSCP marking.
//
// Attached to the TUN egress path (tc qdisc add ... bpf obj tc_qos_prog.o sec tc).
// BPF map `aivpn_qos_rules` (HASH): key = client VPN IP (u32 BE), value =
// struct qos_rule. Graceful degradation: if the map is absent the kernel refuses
// to load — server falls back to userspace-only enforcement (no crash).

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define NS_PER_SEC  1000000000ULL
#define MAX_CLIENTS 512

struct qos_rule {
    __u64 rate_bps;         // bytes per second limit (0 = unlimited)
    __u64 tokens;           // current token bucket fill (bytes)
    __u64 last_refill_ns;   // last refill timestamp (bpf_ktime_get_ns)
    __u8  dscp;             // DSCP value to mark (0 = no mark)
    __u8  pad[3];
    struct bpf_spin_lock lock;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CLIENTS);
    __type(key, __u32);          // client VPN IP (network byte order)
    __type(value, struct qos_rule);
    // tc/libbpf публикует эту карту в /sys/fs/bpf/tc/globals/.
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} aivpn_qos_rules SEC(".maps");

SEC("tc")
int tc_qos_egress(struct __sk_buff *skb) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // This program is attached to a TUN device (ARPHRD_NONE, hard_header_len=0):
    // on tc egress skb->data points directly at the L3 header — there is NO
    // Ethernet header to skip. Parse IPv4 straight from skb->data and pass
    // anything that is not IPv4 (e.g. IPv6) untouched.
    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;
    if (iph->version != 4)
        return TC_ACT_OK;

    // Egress: destination IP = client VPN IP
    __u32 dst_ip = iph->daddr;
    struct qos_rule *rule = bpf_map_lookup_elem(&aivpn_qos_rules, &dst_ip);
    if (!rule)
        return TC_ACT_OK;

    __u64 now = bpf_ktime_get_ns();

    // DSCP marking (tos is byte 1 of the IP header — no Ethernet offset here)
    if (rule->dscp) {
        __u8 new_tos = (iph->tos & 0x03) | (rule->dscp << 2);
        if (iph->tos != new_tos) {
            /* TOS входит в младший байт первого сетевого слова IPv4. */
            __u16 old_word = bpf_htons((__u16)iph->tos);
            __u16 new_word = bpf_htons((__u16)new_tos);
            if (bpf_l3_csum_replace(skb, offsetof(struct iphdr, check),
                                   old_word, new_word, sizeof(__u16)) ||
                bpf_skb_store_bytes(skb, offsetof(struct iphdr, tos),
                                    &new_tos, 1, BPF_F_RECOMPUTE_CSUM))
                return TC_ACT_SHOT;
        }
    }

    /* Общий бюджет меняется атомарно, даже если clsact работает на разных CPU. */
    bpf_spin_lock(&rule->lock);
    __u64 rate = rule->rate_bps;
    if (rate == 0) {
        bpf_spin_unlock(&rule->lock);
        return TC_ACT_OK;
    }
    __u64 burst = rate / 10;
    if (burst < 1500)
        burst = 1500;
    __u64 elapsed = now > rule->last_refill_ns ? now - rule->last_refill_ns : 0;
    __u64 add = elapsed >= NS_PER_SEC ? rate :
        (rate / NS_PER_SEC) * elapsed + (rate % NS_PER_SEC) * elapsed / NS_PER_SEC;
    __u64 new_tokens = add >= burst || rule->tokens >= burst - add ?
        burst : rule->tokens + add;
    __u32 pkt_len = skb->len;
    int verdict = new_tokens < pkt_len ? TC_ACT_SHOT : TC_ACT_OK;
    rule->tokens = verdict == TC_ACT_OK ? new_tokens - pkt_len : new_tokens;
    if (now > rule->last_refill_ns) {
        /* Остаток меньше байта не теряется при каждом отклоненном пакете. */
        __u64 residue = elapsed >= NS_PER_SEC ? 0 :
            ((rate % NS_PER_SEC) * elapsed % NS_PER_SEC) / rate;
        rule->last_refill_ns = now - residue;
    }
    bpf_spin_unlock(&rule->lock);
    return verdict;
}

char _license[] SEC("license") = "GPL";
