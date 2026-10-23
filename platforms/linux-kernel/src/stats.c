// SPDX-License-Identifier: GPL-2.0
/*
 * stats.c — /proc/aivpn/stats data-plane observability for aivpn.ko
 *
 * Exposes the global RX/TX counters declared in stats.h as a read-only proc
 * file so operators can confirm on a live stand whether packets actually
 * traverse the kernel fast path or fall back to user-space.
 */

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/atomic.h>
#include "stats.h"
#include "helpers.h"

atomic64_t aivpn_stat_counters[AIVPN_STAT__COUNT];

static struct proc_dir_entry *aivpn_proc_dir;

static const char *const aivpn_stat_names[AIVPN_STAT__COUNT] = {
	[AIVPN_STAT_RX_TOTAL]        = "rx_total",
	[AIVPN_STAT_TAG_HIT]         = "tag_hit",
	[AIVPN_STAT_FALLBACK]        = "fallback",
	[AIVPN_STAT_REPLAY_DROP]     = "replay_drop",
	[AIVPN_STAT_DECRYPT_FAIL]    = "decrypt_fail",
	[AIVPN_STAT_CTRL_FALLBACK]   = "ctrl_fallback",
	[AIVPN_STAT_INJECT_OK]       = "inject_ok",
	[AIVPN_STAT_INJECT_FAIL]     = "inject_fail",
	[AIVPN_STAT_TX_ENCRYPT_OK]   = "tx_encrypt_ok",
	[AIVPN_STAT_TX_ENCRYPT_FAIL] = "tx_encrypt_fail",
	[AIVPN_STAT_POLICY_DROP]     = "policy_drop",
	[AIVPN_STAT_POLICY_FALLBACK] = "policy_fallback",
};

static int aivpn_stats_show(struct seq_file *m, void *v)
{
	int i;

	for (i = 0; i < AIVPN_STAT__COUNT; i++)
		seq_printf(m, "%-16s %llu\n", aivpn_stat_names[i],
			   (unsigned long long)atomic64_read(&aivpn_stat_counters[i]));
	return 0;
}

static int aivpn_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, aivpn_stats_show, NULL);
}

static const struct proc_ops aivpn_stats_proc_ops = {
	.proc_open    = aivpn_stats_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

int aivpn_stats_init(void)
{
	int i;

	for (i = 0; i < AIVPN_STAT__COUNT; i++)
		atomic64_set(&aivpn_stat_counters[i], 0);

	aivpn_proc_dir = proc_mkdir("aivpn", NULL);
	if (!aivpn_proc_dir)
		return -ENOMEM;

	if (!proc_create("stats", 0444, aivpn_proc_dir, &aivpn_stats_proc_ops)) {
		proc_remove(aivpn_proc_dir);
		aivpn_proc_dir = NULL;
		return -ENOMEM;
	}

	aivpn_info("observability: /proc/aivpn/stats ready\n");
	return 0;
}

void aivpn_stats_fini(void)
{
	if (aivpn_proc_dir) {
		remove_proc_entry("stats", aivpn_proc_dir);
		proc_remove(aivpn_proc_dir);
		aivpn_proc_dir = NULL;
	}
}
