#!/usr/bin/env python3
"""Проверяет ограничение и освобождение настоящей таблицы QoS без загрузки модуля."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / "platforms/linux-kernel/src/session_table.c").read_text()
slots = source[source.index("#define AIVPN_QOS_HASH_BITS"):source.index("static struct aivpn_kern_session *aivpn_session_detach")]
functions = source[source.index("static int aivpn_key_nonzero("):source.index("/* Нулевой ключ списывает бюджет")]
harness = r'''
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "policy.h"
typedef unsigned char u8;
typedef int spinlock_t;
#define MAX_SESSIONS 500
#define GFP_ATOMIC 0
struct hlist_node { struct hlist_node *next; struct hlist_node **prev; };
#define DEFINE_HASHTABLE(name,bits) struct hlist_node *name
#define DEFINE_SPINLOCK(name) spinlock_t name
#define spin_lock_init(p) ((void)(p))
#define spin_lock(p) ((void)(p))
#define spin_unlock(p) ((void)(p))
#define spin_lock_bh(p) ((void)(p))
#define spin_unlock_bh(p) ((void)(p))
#define crypto_memneq memcmp
#define jhash(key,size,seed) ((void)(key), (void)(size), (void)(seed), 0)
#define hash_add(table,node,key) do { (void)(key); (node)->next = (table); (node)->prev = &(table); if (table) (table)->prev = &(node)->next; (table) = (node); } while(0)
#define hash_del(node) do { *(node)->prev = (node)->next; if ((node)->next) (node)->next->prev = (node)->prev; } while(0)
#define item(ptr,member) ((struct aivpn_qos_slot *)((char *)(ptr)-offsetof(struct aivpn_qos_slot,member)))
#define hash_for_each_possible(table,slot,member,key) for (struct hlist_node *n = ((void)(key),(table)); n && ((slot)=item(n,member),1); n=n->next)
#define hash_for_each_safe(table,bkt,tmp,slot,member) for (struct hlist_node *n = ((bkt)=0,(table)); n && ((tmp)=n->next,(slot)=item(n,member),1); n=(tmp))
static size_t live_allocations;
static void *kzalloc(size_t n, int flags) { (void)flags; void *p=calloc(1,n); if(p) live_allocations++; return p; }
static void kfree(void *p) { if(p) { live_allocations--; free(p); } }
''' + slots + functions + r'''
static void fill_key(u8 key[16], unsigned value) { memset(key,0,16); memcpy(key,&value,sizeof(value)); }
int main(void) {
    const size_t cap = MAX_SESSIONS * 8;
    struct aivpn_session_policy policy = {0};
    policy.policy_version = AIVPN_POLICY_VERSION;
    policy.role = AIVPN_ROLE_SERVER;
    for (unsigned i=1;i<=cap;i++) {
        fill_key(policy.client_key,i);
        assert(aivpn_qos_reconfigure(&policy)==0);
    }
    fill_key(policy.client_key,(unsigned)cap+1);
    if (aivpn_qos_reconfigure(&policy) != -ENOMEM || live_allocations != cap) {
        fprintf(stderr,"Таблица QoS растет после лимита: %zu\n",live_allocations);
        return 1;
    }
    fill_key(policy.client_key,1);
    assert(aivpn_qos_reconfigure(&policy)==0);
    for (unsigned i=1;i<=cap;i++) {
        fill_key(policy.client_key,i);
        aivpn_qos_forget(policy.client_key);
        aivpn_qos_forget(policy.client_key);
    }
    assert(live_allocations==0);
    assert(aivpn_qos_reconfigure(&policy)==0);
    aivpn_qos_flush();
    assert(live_allocations==0);
    assert(aivpn_qos_reconfigure(&policy)==0);
    aivpn_qos_flush();
    assert(live_allocations==0);
    puts("QoS: предел памяти, существующий клиент, повторное удаление и flush: PASS");
}
'''
with tempfile.TemporaryDirectory(prefix="aivpn-qos-test-") as tmp:
    src = Path(tmp) / "qos.c"
    binary = Path(tmp) / "qos"
    src.write_text(harness)
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-but-set-variable",
                    "-fsanitize=address,undefined", "-I", str(ROOT / "platforms/linux-kernel/src"), str(src), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
