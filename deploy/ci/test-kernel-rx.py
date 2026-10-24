#!/usr/bin/env python3
"""Проверяет реальные prepare/finish функции без загрузки kernel module."""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'platforms/linux-kernel/src/session_table.c').read_text()
start = source.index('int aivpn_session_rx_prepare(')
end = source.index('int aivpn_session_policy_set(', start)
functions = source[start:end]
epoch_arg = '1, ' if 'u32 epoch' in functions else ''
test = r'''
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "policy.h"
typedef __u8 u8;
typedef __u32 u32;
typedef __u64 u64;
struct aivpn_kern_session {
    struct aivpn_pol pol;
    struct aivpn_epoch_win replay;
    u64 rx_packets, rx_bytes;
};
static int aivpn_peer_is_other(__u32 ip, void *ctx) { (void)ip; (void)ctx; return 0; }
static u64 ktime_get_ns(void) { return 1000000000; }
static int accounting_result = AIVPN_VERDICT_ACCEPT;
static int aivpn_session_account(struct aivpn_kern_session *s, int dir,
                                unsigned int bytes, u64 now)
{ (void)s; (void)dir; (void)bytes; (void)now; return accounting_result; }
''' + functions + r'''
int main(void) {
    struct aivpn_kern_session s = {0};
    u8 ip[20] = {0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17};
    u8 src[4] = {10,0,0,2}, dst[4] = {8,8,8,8};
    memcpy(ip+12, src, 4); memcpy(ip+16, dst, 4);
    s.pol.version = AIVPN_POLICY_VERSION;
    s.pol.role = AIVPN_ROLE_SERVER;
    s.pol.armed = 1;
    memcpy(&s.pol.client_ipv4, src, 4);
    aivpn_epoch_rotate(&s.replay, 1);
    int dup, before = aivpn_session_rx_prepare(&s, EPOCH_ARG 7, &dup);
    if (before != AIVPN_VERDICT_ACCEPT) return 2;
    /* Ротация проходит, пока RX отпустил spinlock ради AEAD. */
    aivpn_epoch_rotate(&s.replay, 2);
    int after = aivpn_session_rx_finish(&s, EPOCH_ARG 7, ip, sizeof(ip), 64, &dup);
    if (after != AIVPN_VERDICT_FALLBACK || s.replay.hi != 0 || s.rx_packets != 0) {
        fprintf(stderr, "RX сменил эпоху во время decrypt: verdict=%d hi=%llu packets=%llu\n",
                after, (unsigned long long)s.replay.hi, (unsigned long long)s.rx_packets);
        return 1;
    }
    puts("RX смена эпохи между prepare/finish: PASS");
    accounting_result = AIVPN_VERDICT_FALLBACK;
    after = aivpn_session_rx_finish(&s, 2, 9, ip, sizeof(ip), 64, &dup);
    if (after != AIVPN_VERDICT_FALLBACK || s.replay.hi != 0 || s.rx_packets != 0) return 3;
    accounting_result = AIVPN_VERDICT_ACCEPT;
    after = aivpn_session_rx_finish(&s, 2, 9, ip, sizeof(ip), 64, &dup);
    if (after != AIVPN_VERDICT_ACCEPT || s.replay.hi != 9 || s.rx_packets != 1) return 4;
    after = aivpn_session_rx_finish(&s, 2, 9, ip, sizeof(ip), 64, &dup);
    if (after != AIVPN_VERDICT_DROP || !dup || s.rx_packets != 1) return 5;
    accounting_result = AIVPN_VERDICT_DROP;
    after = aivpn_session_rx_finish(&s, 2, 10, ip, sizeof(ip), 64, &dup);
    if (after != AIVPN_VERDICT_DROP || s.replay.hi != 10 || s.rx_packets != 1) return 6;
    puts("RX отсутствие QoS: fallback без claim, quota drop с claim: PASS");
    return 0;
}
'''
test = test.replace('EPOCH_ARG ', epoch_arg)
with tempfile.TemporaryDirectory(prefix='aivpn-rx-test-') as tmp:
    src = Path(tmp) / 'rx.c'
    binary = Path(tmp) / 'rx'
    src.write_text(test)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra',
                    '-Werror', '-fsanitize=address,undefined',
                    '-I', str(root / 'platforms/linux-kernel/src'),
                    str(src), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
