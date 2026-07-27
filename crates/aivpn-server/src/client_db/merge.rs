//! Anti-entropy / CRDT-style pool-sync protocol: `merge_from_json` (upsert-
//! by-id merge with LWW + sticky-tombstone conflict resolution and
//! deterministic vpn_ip collision re-homing), plus the digest machinery
//! (`state_digest`, `bucket_digests`, `differing_pool_buckets`) that lets
//! two pool nodes cheaply detect whether they need to run a merge at all.
//!
//! Kept as one file (rather than split further) because the digest
//! machinery and `merge_from_json` share a single invariant — they must
//! agree EXACTLY on which fields converge — that is much easier to keep
//! honest when the code enforcing it lives together; see
//! `write_record_canonical_fields`'s doc comment.

use tracing::warn;

use aivpn_common::error::{Error, Result};

use super::*;

/// Encode an `Option<DateTime<Utc>>` as 8 little-endian bytes for
/// [`ClientDatabase::state_digest`]: `Some(t)` becomes `t`'s millisecond
/// timestamp, `None` becomes the sentinel `i64::MIN` (unreachable by any
/// real `DateTime<Utc>` value relevant here), so the two cases can never
/// collide.
fn encode_opt_millis(dt: Option<DateTime<Utc>>) -> [u8; 8] {
    match dt {
        Some(t) => t.timestamp_millis().to_le_bytes(),
        None => i64::MIN.to_le_bytes(),
    }
}

/// Number of buckets used by [`ClientDatabase::bucket_digests`] /
/// [`ClientDatabase::clients_json_for_buckets`] — see [`ClientDatabase::BUCKETS`].
pub const POOL_SYNC_BUCKETS: usize = 64;

/// Write EXACTLY the same per-record canonical field bytes, in the same
/// order, that [`ClientDatabase::state_digest`] folds into its running
/// hasher — the single source of truth for "which fields converge" shared by
/// `state_digest` (whole-DB digest) and `bucket_digests` (per-bucket digest).
/// Keeping this as one function is what makes the
/// state_digest-iff-bucket_digests invariant hold: both call sites hash
/// identical bytes, just grouped differently (one running hash over the
/// whole sorted list vs. one hash per record folded into a per-bucket hash).
fn write_record_canonical_fields(hasher: &mut blake3::Hasher, c: &ClientConfig) {
    // id (length-prefixed)
    let id_bytes = c.id.as_bytes();
    hasher.update(&(id_bytes.len() as u32).to_le_bytes());
    hasher.update(id_bytes);

    // psk (fixed 32 bytes — the credential anchor)
    hasher.update(&c.psk);

    // name (length-prefixed)
    let name_bytes = c.name.as_bytes();
    hasher.update(&(name_bytes.len() as u32).to_le_bytes());
    hasher.update(name_bytes);

    // enabled / deleted / one_time (fixed 1 byte each)
    hasher.update(&[c.enabled as u8, c.deleted as u8, c.one_time as u8]);

    // updated_at / expires_at (Option<DateTime<Utc>> -> i64 millis, sentinel)
    hasher.update(&encode_opt_millis(c.updated_at));
    hasher.update(&encode_opt_millis(c.expires_at));

    // device_pubkey (present-flag byte + fixed 32 bytes)
    match c.device_pubkey {
        Some(ref key) => {
            hasher.update(&[1u8]);
            hasher.update(key);
        }
        None => {
            hasher.update(&[0u8]);
            hasher.update(&[0u8; 32]);
        }
    }

    // qos (canonical: ClientQos is a flat struct of plain scalar
    // Option fields, so its serde_json encoding is deterministic;
    // length-prefixed like the other variable-length fields)
    let qos_json = serde_json::to_vec(&c.qos).unwrap_or_default();
    hasher.update(&(qos_json.len() as u32).to_le_bytes());
    hasher.update(&qos_json);

    // role (fixed 1 byte — a management-relevant field like enabled/deleted,
    // must converge in the digest so a pool node can't silently retain a
    // stale role after another node elevates/demotes a client)
    hasher.update(&[c.role.rank()]);

    // exit_node (Wave B2a: present-flag byte + length-prefixed string, same
    // shape as device_pubkey's present-flag pattern above but variable
    // length — must converge in the digest so a pool node can't silently
    // retain a stale per-client exit-node override after another node
    // changes or clears it)
    match c.exit_node {
        Some(ref addr) => {
            hasher.update(&[1u8]);
            let bytes = addr.as_bytes();
            hasher.update(&(bytes.len() as u32).to_le_bytes());
            hasher.update(bytes);
        }
        None => {
            hasher.update(&[0u8]);
        }
    }
}

/// Deterministic bucket assignment for a client `id`: the first 8 bytes of
/// `blake3(id)`, reduced mod [`POOL_SYNC_BUCKETS`]. Shared by
/// `bucket_digests` (building the digest) and `clients_json_for_buckets`
/// (selecting records for a given set of bucket indices) so both always
/// agree on which bucket a record belongs to.
fn bucket_index_for_id(id: &str) -> usize {
    let h = blake3::hash(id.as_bytes());
    let n = u64::from_le_bytes(h.as_bytes()[0..8].try_into().unwrap());
    (n % POOL_SYNC_BUCKETS as u64) as usize
}

/// Compare two `bucket_digests()` outputs and return the indices of buckets
/// that differ. Used by both the server (`gateway.rs`) and the dialer
/// (`pool_dialer.rs`) on receipt of a peer's `PoolBucketDigests` to decide
/// exactly which records to push back in the `PoolSync` reply.
///
/// Defensive against a bucket-count mismatch (e.g. a peer running a
/// different build with a different `POOL_SYNC_BUCKETS`): rather than
/// panicking on an out-of-range chunk, a length mismatch is treated as
/// "nothing to compare" (empty result) — the root `state_digest` gate this
/// sits behind will simply keep firing every beacon until both nodes are
/// upgraded, which is a visible, safe degradation rather than a crash.
pub fn differing_pool_buckets(local: &[u8], peer: &[u8]) -> Vec<u16> {
    if local.len() != peer.len() || local.len() % 8 != 0 {
        return Vec::new();
    }
    local
        .chunks_exact(8)
        .zip(peer.chunks_exact(8))
        .enumerate()
        .filter_map(|(i, (l, p))| if l != p { Some(i as u16) } else { None })
        .collect()
}

/// How long a tombstone (deleted client record) is kept before being hard-
/// deleted. Must be well beyond any plausible pool-node downtime so every
/// peer receives the revocation first — a peer that was offline less than
/// this still converges on the tombstone via pool sync. Without a TTL,
/// tombstones accumulate forever: `clients.json` and every 5-second sync
/// payload grow unbounded, and revoked records would otherwise pin state
/// permanently.
const TOMBSTONE_TTL: chrono::Duration = chrono::Duration::days(30);

/// Drop tombstones older than [`TOMBSTONE_TTL`] (by `updated_at`, i.e. the
/// deletion time). Untimestamped tombstones (written by pre-`updated_at`
/// versions) are kept — they cannot be aged, and are rare enough not to
/// matter for growth. Returns `true` if anything was removed.
pub(crate) fn reap_expired_tombstones(clients: &mut Vec<ClientConfig>) -> bool {
    let cutoff = Utc::now() - TOMBSTONE_TTL;
    let before = clients.len();
    clients.retain(|c| !(c.deleted && c.updated_at.is_some_and(|t| t < cutoff)));
    before != clients.len()
}

impl ClientDatabase {
    /// Merge clients received from a pool peer into the local database.
    /// Upserts by client ID — adds new clients, updates existing ones if PSK matches.
    ///
    /// Convergent revocation: local deletions are tombstones (see
    /// `remove_client`) and revocation is STICKY — an incoming tombstone
    /// always beats a live local record, and a local tombstone is never
    /// overwritten by a live incoming record, regardless of timestamps (a
    /// clock-skewed or later admin edit on a peer must not un-revoke).
    /// Between records of the same liveness, conflicts are resolved
    /// last-writer-wins on `updated_at`. Records without `updated_at` (older
    /// peer versions) are treated as older than any timestamped record;
    /// between two untimestamped live records the legacy overwrite behavior
    /// is kept.
    ///
    /// Tombstones past `TOMBSTONE_TTL` are reaped at the end of every merge
    /// (and at load), so `clients.json` and the sync payload stay bounded.
    ///
    /// ## TOCTOU note (A2)
    /// `clients.json` is a file SHARED with other processes — short-lived
    /// admin CLI invocations (`--add-client` etc.) load -> mutate -> save ->
    /// exit against the same path while this (daemon) process is running.
    /// If this merge computed its result purely against the in-memory
    /// snapshot and then blindly `save()`d, a concurrent external write
    /// landing between the daemon's last `reload_if_changed()` poll (every
    /// ~10s) and this merge's save would be silently clobbered: the daemon's
    /// stale in-memory copy would overwrite the external addition on disk
    /// AND reset the cached mtime, so the next scheduled reload would see
    /// "unchanged" and the externally-added client would be gone for good.
    /// To close that window, this pulls in any external on-disk change
    /// FIRST (via the same `reload_if_changed` logic the daemon's poll loop
    /// uses), so the merge below is computed against the latest known state
    /// and the subsequent `save()` carries the external change forward
    /// instead of overwriting it. `reload_if_changed` takes and releases its
    /// own lock internally and returns before this function acquires
    /// `self.data`'s write lock below, so there is no double-acquisition /
    /// deadlock risk (see its doc comment).
    ///
    /// This does not close the window completely: another external write
    /// landing between this reload and this function's own `save()` a few
    /// lines below is still possible (there is no OS-level file lock across
    /// processes) and would still be clobbered, but that window shrinks from
    /// "up to one poll interval" (~10s) to "the duration of one merge call"
    /// (microseconds), which is the best achievable without adding
    /// cross-process file locking (`flock`) around the whole
    /// read-modify-write sequence.
    ///
    /// Returns the number of clients merged.
    pub fn merge_from_json(&self, json: &str) -> Result<usize> {
        let incoming: Vec<ClientConfig> = serde_json::from_str(json)
            .map_err(|e| Error::Session(format!("merge_from_json parse: {}", e)))?;

        // A2: pick up any external on-disk change (e.g. a concurrent admin
        // CLI `--add-client`) before computing/saving this merge, so it
        // isn't clobbered. Must happen BEFORE `self.data.write()` below —
        // `reload_if_changed` -> `reload_from_disk` takes its own
        // `self.data.write()` internally and releases it on return, so
        // sequencing this first avoids any double-acquisition/deadlock.
        self.reload_if_changed();

        let mut data = self.data.write();
        let mut merged = 0usize;
        for mut inc in incoming {
            if let Some(existing) = data.clients.iter_mut().find(|c| c.id == inc.id) {
                // Only update if PSK matches (same logical client)
                if existing.psk == inc.psk {
                    // Revocation is STICKY: timestamps decide only between two
                    // records of the same liveness. A tombstone always beats a
                    // live record — otherwise a peer's later admin edit (or a
                    // fast-skewed clock) could out-timestamp the tombstone and
                    // silently un-revoke the client pool-wide. Concretely:
                    //  - local tombstone: only a strictly-newer incoming
                    //    tombstone (a re-issued deletion) may replace it;
                    //  - incoming tombstone vs live local: always wins;
                    //  - live vs live: normal last-writer-wins on `updated_at`.
                    let strictly_newer = match (inc.updated_at, existing.updated_at) {
                        (Some(i), Some(e)) => i > e,
                        (Some(_), None) => true,
                        (None, _) => false,
                    };
                    // Same-liveness timestamp tie (both None — legacy
                    // records — or the same millisecond): break it
                    // DETERMINISTICALLY by canonical content hash, so both
                    // nodes independently pick the SAME winner. The old
                    // "incoming always wins when both are untimestamped"
                    // rule made two legacy records with divergent content
                    // swap places on EVERY anti-entropy round (A adopts B's
                    // copy while B adopts A's) — digests never converged and
                    // both nodes re-saved to disk each beacon, forever. An
                    // equal-`Some` tie previously just diverged silently
                    // (neither side ever won), keeping the bucket exchange
                    // hot as well. Records whose canonical content is equal
                    // hash identically → no winner needed (vpn_ip is
                    // deliberately outside the canonical fields; divergence
                    // there is allowed by design).
                    let tie_break_wins = || {
                        inc.updated_at == existing.updated_at
                            && Self::record_canonical_hash(&inc)
                                < Self::record_canonical_hash(existing)
                    };
                    let incoming_wins = match (existing.deleted, inc.deleted) {
                        (true, false) => false,
                        (false, true) => true,
                        (true, true) => strictly_newer || tie_break_wins(),
                        (false, false) => strictly_newer || tie_break_wins(),
                    };
                    if !incoming_wins {
                        continue;
                    }
                    existing.name = inc.name;
                    // A deleted record is never "enabled", whatever the peer sent.
                    existing.enabled = inc.enabled && !inc.deleted;
                    existing.qos = inc.qos;
                    existing.deleted = inc.deleted;
                    existing.updated_at = inc.updated_at;
                    // MEDIUM (server-sec): these three were previously never
                    // synced, silently reverting a security-relevant admin
                    // change made on ONE pool node back to its old value on
                    // every other node — e.g. a shortened `expires_at`
                    // (temporary access) or a `reset_device` (device_pubkey
                    // cleared to re-enable one-time enrollment) done on node
                    // A would never take effect on node B, leaving a client
                    // that should be locked out (or re-bindable) reachable
                    // there indefinitely. They follow the exact same
                    // `incoming_wins` decision already computed above — no
                    // change to the conflict-resolution policy itself.
                    existing.expires_at = inc.expires_at;
                    existing.device_pubkey = inc.device_pubkey;
                    existing.one_time = inc.one_time;
                    // `role` is management-relevant exactly like the fields
                    // above (an admin elevation/demotion done on one pool
                    // node must converge everywhere) — same `incoming_wins`
                    // LWW/tombstone-sticky gate, no separate policy.
                    existing.role = inc.role;
                    // Wave B2a: `exit_node` follows the exact same policy —
                    // a per-client routing override set (or cleared) on one
                    // pool node must converge everywhere, and must not be
                    // resurrected by a stale peer copy once tombstoned.
                    existing.exit_node = inc.exit_node;
                    merged += 1;
                }
            } else if inc.deleted {
                // Unknown id arriving already tombstoned: keep the tombstone so
                // the deletion keeps propagating through the pool. No IP
                // conflict check — tombstones are invisible to lookups.
                data.clients.push(inc);
                merged += 1;
            } else {
                // H-S-2 / Wave B-IP: reject-and-reassign incoming records
                // whose vpn_ip is already assigned to a *different* client —
                // prevents pool sync from overwriting IP assignments and
                // causing routing collisions. Tombstones don't hold their IP
                // (allocate_vpn_ip may have reassigned it), so they don't
                // conflict.
                //
                // With hard per-node partitioning (`set_node_partition`) in
                // place, two DIFFERENT nodes' independent allocations can no
                // longer land on the same offset in the first place, so this
                // branch is now a backstop for residual/legacy cases: a
                // node_id hash collision, an explicit-partition-override
                // misconfiguration, or clients that predate partitioning.
                //
                // The winner is chosen DETERMINISTICALLY from record content
                // alone — earlier `created_at` wins, ties broken by
                // lexicographically smaller `id` — never from "which side
                // happens to already be resident locally". That means two
                // nodes merging the same colliding pair independently reach
                // the IDENTICAL decision without a coordinator. Whichever
                // side turns out to be the loser (the already-resident local
                // record, or the freshly-incoming one) is re-homed via
                // `deterministic_reassign_offset`, a pure function of the
                // loser's own `id` + this node's partition + current data,
                // so both nodes also compute the SAME reassigned IP for the
                // loser in the common one-collision case (a rarer multi-way
                // conflict may need an extra sync round to fully settle, but
                // never drops a client). The winner's vpn_ip is never
                // touched by this branch on either node — that is what keeps
                // its already-issued connection key valid (no churn).
                // Hardening: an incoming record must never squat on THIS
                // node's own server VPN IP. A peer with a DIFFERENT
                // `server_vpn_ip` in the same subnet can legitimately
                // allocate that address for one of its clients (its own
                // allocator only filters ITS server IP) — but locally,
                // `find_by_vpn_ip(server_ip)` suddenly resolving to a client
                // corrupts routing lookups. Re-home it here exactly like a
                // client-vs-client collision below (divergent per-node
                // vpn_ip is allowed by design — `state_digest` excludes it).
                if inc.vpn_ip == self.network_config().server_vpn_ip {
                    match self.deterministic_reassign_offset(&inc.id, &data) {
                        Some(new_ip) => {
                            warn!(
                                "merge_from_json: client '{}' vpn_ip {} collides with this node's server VPN IP — re-homed to {}",
                                inc.id, inc.vpn_ip, new_ip
                            );
                            inc.vpn_ip = new_ip;
                        }
                        None => {
                            warn!(
                                "merge_from_json: skipping client '{}' — vpn_ip {} collides with this node's server VPN IP and no free IP to re-home",
                                inc.id, inc.vpn_ip
                            );
                            continue;
                        }
                    }
                }
                if let Some(conflict_idx) = data
                    .clients
                    .iter()
                    .position(|c| c.vpn_ip == inc.vpn_ip && c.id != inc.id && !c.deleted)
                {
                    let incoming_wins =
                        match inc.created_at.cmp(&data.clients[conflict_idx].created_at) {
                            std::cmp::Ordering::Less => true,
                            std::cmp::Ordering::Greater => false,
                            std::cmp::Ordering::Equal => inc.id < data.clients[conflict_idx].id,
                        };
                    if incoming_wins {
                        // The already-resident local record loses: re-home
                        // IT in place; the incoming (winning) record keeps
                        // its vpn_ip unchanged when pushed below.
                        let loser_id = data.clients[conflict_idx].id.clone();
                        match self.deterministic_reassign_offset(&loser_id, &data) {
                            Some(new_ip) => {
                                warn!(
                                    "merge_from_json: incoming client '{}' (created {}) beats locally-resident '{}' (created {}) for vpn_ip {} — re-homed loser to {}",
                                    inc.id,
                                    inc.created_at,
                                    loser_id,
                                    data.clients[conflict_idx].created_at,
                                    inc.vpn_ip,
                                    new_ip
                                );
                                // Deliberately does NOT touch `updated_at`
                                // (or any other LWW-governed field): this is
                                // a routing-layer vpn_ip fix-up, not a
                                // content change, and must produce a
                                // byte-identical record to the one the OTHER
                                // node computes for the same loser via the
                                // `else` branch below (which also leaves
                                // `updated_at` alone) — touching it here
                                // only would make the two sides' converged
                                // records diverge on `updated_at` even
                                // though their `vpn_ip` correctly converged.
                                data.clients[conflict_idx].vpn_ip = new_ip;
                            }
                            None => {
                                warn!(
                                    "merge_from_json: client '{}' vpn_ip {} conflicts with locally-resident '{}' and no free IP to re-home the loser — dropping incoming",
                                    inc.id, inc.vpn_ip, loser_id
                                );
                                continue;
                            }
                        }
                    } else {
                        // The incoming record loses: re-home it before
                        // insertion, leaving the winning local record
                        // untouched.
                        match self.deterministic_reassign_offset(&inc.id, &data) {
                            Some(new_ip) => {
                                warn!(
                                    "merge_from_json: client '{}' vpn_ip {} conflicts locally — re-homed to {}",
                                    inc.id, inc.vpn_ip, new_ip
                                );
                                inc.vpn_ip = new_ip;
                            }
                            None => {
                                warn!(
                                    "merge_from_json: skipping client '{}' — vpn_ip {} conflicts and no free IP to re-home",
                                    inc.id, inc.vpn_ip
                                );
                                continue;
                            }
                        }
                    }
                }
                data.clients.push(inc);
                merged += 1;
            }
        }
        // Reap AFTER the merge loop: an expired tombstone a peer still
        // advertises is re-added above and immediately dropped here, so it
        // can't ping-pong back into the database forever.
        let reaped = reap_expired_tombstones(&mut data.clients);

        // A3: `add_client`/`update_client` enforce unique `name` among live
        // clients, but this merge loop upserts by `id` only and never checks
        // it — a peer's independently-created record can leave two live
        // clients sharing a `name`. `find_by_name` returns only the first
        // match in iteration order, so a silent duplicate could make a
        // name-addressed admin/API operation target the wrong record. This
        // does NOT drop or rename either record (that would break
        // convergence — the id-keyed content on both sides must still
        // propagate); it only surfaces the collision so operators notice.
        if merged > 0 {
            Self::warn_duplicate_live_names(&data.clients);
        }

        drop(data);
        if merged > 0 || reaped {
            self.save()?;
        }
        Ok(merged)
    }

    /// Log a warning for each live (non-tombstoned) client `name` that is
    /// shared by more than one record. Read-only — never modifies the list.
    /// See the A3 comment in `merge_from_json`, the only caller: a peer
    /// merge upserts by `id` and never enforces name uniqueness the way
    /// `add_client`/`update_client` do, so a collision here is a real,
    /// operator-visible gap between "two distinct ids converged" and "one
    /// name resolves unambiguously".
    fn warn_duplicate_live_names(clients: &[ClientConfig]) {
        let mut seen: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        for client in clients {
            if client.deleted {
                continue;
            }
            match seen.get(client.name.as_str()) {
                Some(first_id) => {
                    warn!(
                        "merge_from_json: duplicate live client name '{}' — ids '{}' and '{}' \
                         both now hold this name; find_by_name resolves only the first match, \
                         so name-addressed operations may target the wrong client",
                        client.name, first_id, client.id
                    );
                }
                None => {
                    seen.insert(client.name.as_str(), client.id.as_str());
                }
            }
        }
    }

    /// Deterministic content-hash of the full converged client-database
    /// state, including tombstones.
    ///
    /// ## Purpose
    /// Feeds the pool-sync anti-entropy gate: two nodes exchange this digest
    /// and only pay for a full `export_json()` / `merge_from_json()`
    /// round-trip when the digests differ. For that gate to be sound, the
    /// digest must change if and only if there is real reconciling work to
    /// do — so it hashes EXACTLY the fields `merge_from_json`'s
    /// existing-record branch treats as authoritative/converging, no more
    /// and no less:
    ///
    /// Included (each is explicitly assigned from the incoming record in
    /// `merge_from_json`'s `if let Some(existing) = ...` branch, under its
    /// LWW / tombstone-sticky conflict rule):
    /// - `id` — primary key / stable identity; the match key for merging.
    /// - `psk` — the credential anchor. `merge_from_json` requires
    ///   `existing.psk == inc.psk` before it will reconcile a record at
    ///   all, and never rewrites `psk` once set — two correctly-synced
    ///   nodes always agree on it, and a mismatch is a real (if
    ///   pathological) divergence worth surfacing, not one anti-entropy
    ///   could paper over anyway.
    /// - `name` — `existing.name = inc.name`.
    /// - `enabled` — the persisted field (post tombstone-derived rule:
    ///   `inc.enabled && !inc.deleted`).
    /// - `deleted` — the tombstone flag; exactly the convergent state a
    ///   peer's revocation must propagate.
    /// - `updated_at` — the LWW timestamp that decides convergence order.
    /// - `expires_at`, `device_pubkey`, `one_time` — synced explicitly per
    ///   the server-sec MEDIUM fix (previously silently dropped by merge,
    ///   see the comment above `existing.expires_at = inc.expires_at` in
    ///   `merge_from_json`).
    /// - `qos` — `existing.qos = inc.qos`.
    ///
    /// Excluded:
    /// - `stats` (bytes_in/out, last_connected, last_handshake,
    ///   total_connections) — purely local runtime counters.
    ///   `merge_from_json` never touches `stats` on an existing record, and
    ///   every node's traffic differs by definition, so including it would
    ///   make the digest differ between two fully-converged nodes forever,
    ///   permanently defeating the sync gate.
    /// - `vpn_ip` — despite looking like admin/identity state, this is NOT
    ///   part of the converging set: `merge_from_json`'s existing-record
    ///   branch never assigns `vpn_ip` (conspicuously absent from the field
    ///   list above), and by design the SAME logical client can legitimately
    ///   hold a DIFFERENT `vpn_ip` on two pool nodes forever — each node
    ///   allocates IPs from its own local counter, and an incoming record
    ///   whose `vpn_ip` collides with an unrelated local client is re-homed
    ///   onto a free local IP (see the comment in `merge_from_json`: "the
    ///   reassignment stays local ... so it doesn't churn"). Hashing
    ///   `vpn_ip` would make two nodes that have already reconciled every
    ///   field merge actually propagates show a perpetual digest mismatch,
    ///   triggering endless, pointless full-payload exchanges.
    /// - `created_at` — set once at creation and never reconciled by merge
    ///   (absent from its assignment list); excluded for the same
    ///   "not part of the authoritative/converging set" reason, though in
    ///   practice it never diverges once the initial record has propagated.
    ///
    /// ## Determinism
    /// - Records are sorted by `id` first, so the result does not depend on
    ///   in-memory/on-disk ordering (insertion/merge order is otherwise
    ///   whatever order operations happened in).
    /// - Every variable-length field (`id`, `name`, the `qos` JSON blob) is
    ///   length-prefixed with a little-endian `u32` before its bytes, and a
    ///   leading record count frames the whole structure — so e.g.
    ///   `[{id:"a"},{id:"bc"}]` cannot hash the same as
    ///   `[{id:"ab"},{id:"c"}]`.
    /// - `Option<DateTime<Utc>>` fields (`updated_at`, `expires_at`) are
    ///   encoded as an `i64` millisecond timestamp, with `i64::MIN` reserved
    ///   as the "None" sentinel (a real timestamp can never legitimately
    ///   encode to `i64::MIN` here).
    /// - `device_pubkey: Option<[u8; 32]>` is encoded as a single
    ///   present-flag byte followed by either the 32 key bytes or 32 zero
    ///   bytes, so "present with all-zero key" (impossible in practice, but
    ///   not ruled out by the type) can never collide with "absent".
    pub fn state_digest(&self) -> [u8; 32] {
        let mut records = self.list_clients_including_deleted();
        records.sort_by(|a, b| a.id.cmp(&b.id));

        let mut hasher = blake3::Hasher::new();
        hasher.update(&(records.len() as u64).to_le_bytes());

        for c in &records {
            write_record_canonical_fields(&mut hasher, c);
        }

        *hasher.finalize().as_bytes()
    }

    /// Per-record canonical content hash — the SAME converging field set and
    /// byte encoding as [`Self::state_digest`] (via
    /// [`write_record_canonical_fields`]), but hashed independently per
    /// record rather than folded into one running hasher over the whole
    /// sorted list. This is the building block [`Self::bucket_digests`] uses
    /// so that "two DBs agree on `state_digest()`" and "two DBs agree on
    /// `bucket_digests()`" are the same statement (see the invariant test
    /// `state_digest_equal_iff_bucket_digests_equal`).
    fn record_canonical_hash(c: &ClientConfig) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        write_record_canonical_fields(&mut hasher, c);
        *hasher.finalize().as_bytes()
    }

    /// Number of buckets [`Self::bucket_digests`] partitions the client list
    /// into. A fixed compile-time constant shared by both pool nodes — the
    /// wire format ([`aivpn_common::protocol::ControlPayload::PoolBucketDigests`])
    /// has no explicit bucket-count field, so both ends of a pool-sync link
    /// MUST run the same binary version's value of this constant for the
    /// bucket-index arithmetic to line up. A mismatch is defensively handled
    /// by [`differing_pool_buckets`] (returns "nothing differs" rather than
    /// panicking on a length mismatch), not by any wire negotiation.
    pub const BUCKETS: usize = POOL_SYNC_BUCKETS;

    /// Bucketed (Merkle-lite) digest of the full converged client-DB state —
    /// the Phase 2 anti-entropy delta. Every record (including tombstones) is
    /// assigned to one of [`POOL_SYNC_BUCKETS`] buckets by hashing its `id`;
    /// each bucket's digest is the first 8 bytes of a BLAKE3 hash over that
    /// bucket's records' [`Self::record_canonical_hash`] values, sorted by id
    /// for order-independence. An empty bucket digests to 8 zero bytes.
    ///
    /// The result is `POOL_SYNC_BUCKETS * 8` bytes: bucket `i`'s digest lives
    /// at `result[i*8 .. i*8+8]`.
    ///
    /// ## Invariant with `state_digest`
    /// Two databases have equal `state_digest()` if and only if they have
    /// equal `bucket_digests()` — both hash exactly the same per-record
    /// canonical fields, and the bucketing function is a deterministic,
    /// content-independent partition of the (sorted) record set. See the
    /// `state_digest_equal_iff_bucket_digests_equal` test.
    pub fn bucket_digests(&self) -> Vec<u8> {
        let records = self.list_clients_including_deleted();

        // Group per-record hashes by bucket, keeping the id alongside for the
        // final per-bucket sort (order-independence within a bucket).
        let mut buckets: Vec<Vec<(&str, [u8; 32])>> = vec![Vec::new(); POOL_SYNC_BUCKETS];
        for c in &records {
            let idx = bucket_index_for_id(&c.id);
            buckets[idx].push((c.id.as_str(), Self::record_canonical_hash(c)));
        }

        let mut out = Vec::with_capacity(POOL_SYNC_BUCKETS * 8);
        for bucket in &mut buckets {
            if bucket.is_empty() {
                out.extend_from_slice(&[0u8; 8]);
                continue;
            }
            bucket.sort_by(|a, b| a.0.cmp(b.0));
            let mut hasher = blake3::Hasher::new();
            hasher.update(&(bucket.len() as u32).to_le_bytes());
            for (_, h) in bucket.iter() {
                hasher.update(h);
            }
            let digest = hasher.finalize();
            out.extend_from_slice(&digest.as_bytes()[..8]);
        }
        out
    }

    /// Export exactly the records (including tombstones) whose bucket index
    /// (per [`bucket_index_for_id`], the same function `bucket_digests` uses)
    /// is in `buckets`, as a JSON array — the Phase 2 delta payload for
    /// `ControlPayload::PoolSync`. Used instead of a full `export_json()` /
    /// `list_clients_including_deleted()` dump once a peer's root digest has
    /// already told us which buckets actually differ.
    pub fn clients_json_for_buckets(&self, buckets: &[u16]) -> String {
        let wanted: std::collections::HashSet<u16> = buckets.iter().copied().collect();
        let records: Vec<ClientConfig> = self
            .list_clients_including_deleted()
            .into_iter()
            .filter(|c| wanted.contains(&(bucket_index_for_id(&c.id) as u16)))
            .collect();
        serde_json::to_string(&records).unwrap_or_else(|_| "[]".to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::client_db::test_support::test_network_config;

    /// MED-2 regression: a peer's later (or clock-skewed) live edit must not
    /// out-timestamp and silently reverse a revocation.
    #[test]
    fn merge_never_unrevokes_a_local_tombstone() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();

        let client = db.add_client("alice").unwrap();
        db.remove_client(&client.id).unwrap();

        // Peer record: same client, live, timestamped WELL AFTER the tombstone
        // (e.g. a QoS edit on a peer with a fast clock).
        let mut incoming = db.list_clients_including_deleted()[0].clone();
        incoming.deleted = false;
        incoming.enabled = true;
        incoming.updated_at = Some(Utc::now() + chrono::Duration::minutes(10));
        let json = serde_json::to_string(&vec![incoming]).unwrap();
        db.merge_from_json(&json).unwrap();

        assert!(
            db.find_by_id(&client.id).is_none(),
            "revocation must be sticky: a newer live record must not un-delete"
        );
        assert!(db.list_clients_including_deleted()[0].deleted);
    }

    /// MED-2 regression (other direction): an incoming tombstone revokes even
    /// when its timestamp is OLDER than the local live record's.
    #[test]
    fn merge_incoming_tombstone_beats_newer_live_record() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();

        let client = db.add_client("bob").unwrap();

        let mut incoming = db.list_clients_including_deleted()[0].clone();
        incoming.deleted = true;
        incoming.enabled = false;
        incoming.updated_at = Some(Utc::now() - chrono::Duration::hours(1));
        let json = serde_json::to_string(&vec![incoming]).unwrap();
        db.merge_from_json(&json).unwrap();

        assert!(
            db.find_by_id(&client.id).is_none(),
            "an incoming revocation must apply regardless of timestamp order"
        );
    }

    /// MED-1 regression: expired tombstones are reaped (bounded clients.json /
    /// sync payload) while fresh ones are kept for propagation.
    #[test]
    fn expired_tombstones_are_reaped_on_merge() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();

        let old = db.add_client("old").unwrap();
        let fresh = db.add_client("fresh").unwrap();
        db.remove_client(&old.id).unwrap();
        db.remove_client(&fresh.id).unwrap();

        // Age the first tombstone beyond the TTL.
        db.data
            .write()
            .clients
            .iter_mut()
            .find(|c| c.id == old.id)
            .unwrap()
            .updated_at = Some(Utc::now() - TOMBSTONE_TTL - chrono::Duration::days(1));

        // Any merge (even empty) runs the reaper.
        db.merge_from_json("[]").unwrap();

        let all = db.list_clients_including_deleted();
        assert!(
            !all.iter().any(|c| c.id == old.id),
            "expired tombstone must be hard-deleted"
        );
        assert!(
            all.iter().any(|c| c.id == fresh.id && c.deleted),
            "fresh tombstone must be kept so the revocation still propagates"
        );

        // A peer still advertising the expired tombstone must not resurrect
        // it past the same merge call.
        let mut stale = old.clone();
        stale.deleted = true;
        stale.updated_at = Some(Utc::now() - TOMBSTONE_TTL - chrono::Duration::days(1));
        db.merge_from_json(&serde_json::to_string(&vec![stale]).unwrap())
            .unwrap();
        assert!(
            !db.list_clients_including_deleted()
                .iter()
                .any(|c| c.id == old.id),
            "re-advertised expired tombstone must be reaped in the same merge"
        );
    }

    /// MED-1 regression: a tombstone no longer pins its VPN IP — the address
    /// is reusable by allocation, and pool sync accepts a live record on it.
    #[test]
    fn tombstoned_vpn_ip_is_reusable() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();

        let a = db.add_client("a").unwrap(); // gets 10.99.0.2
        db.remove_client(&a.id).unwrap();

        // Rewind the allocation cursor so the tombstone's address is the
        // first candidate again.
        db.data.write().next_host_offset = 2;
        let b = db.add_client("b").unwrap();
        assert_eq!(
            b.vpn_ip, a.vpn_ip,
            "a revoked client's IP must be allocatable again"
        );

        // And merge must not treat the tombstone as an IP conflict for an
        // incoming live client either.
        let mut peer_client = b.clone();
        peer_client.id = "peer-new-id".to_string();
        peer_client.name = "peer-new".to_string();
        peer_client.psk = [0x42; 32];
        // Remove b locally first so the IP is only held by the tombstone.
        db.remove_client(&b.id).unwrap();
        db.merge_from_json(&serde_json::to_string(&vec![peer_client]).unwrap())
            .unwrap();
        assert!(
            db.find_by_id("peer-new-id").is_some(),
            "tombstone must not block an incoming live client on the same IP"
        );
    }

    /// 2b regression: two pool nodes independently add a client and both
    /// allocate the SAME vpn_ip (the reported bug — both start at
    /// `x.x.0.2`). `merge_from_json` must re-home the incoming record onto a
    /// free local IP rather than silently dropping it (the old behavior,
    /// which left the credential permanently un-synced to this node).
    #[test]
    fn merge_from_json_rehomes_ip_conflicting_incoming_client() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();

        // Locally added client — gets the first offset, 10.99.0.2.
        let local = db.add_client("local-alice").unwrap();

        // A DIFFERENT client, added independently on another pool node whose
        // allocator also started at the same default offset, so it too got
        // 10.99.0.2 — a genuine cross-node collision on the wire.
        let mut incoming = local.clone();
        incoming.id = "peer-node-client-id".to_string();
        incoming.name = "peer-bob".to_string();
        incoming.psk = [0x77; 32];
        incoming.vpn_ip = local.vpn_ip;
        assert_eq!(
            incoming.vpn_ip, local.vpn_ip,
            "test setup: both records must collide on the same vpn_ip"
        );

        let merged = db
            .merge_from_json(&serde_json::to_string(&vec![incoming]).unwrap())
            .unwrap();
        assert_eq!(merged, 1, "the colliding incoming client must still merge");

        // The credential (id + PSK) must have propagated — this is the
        // actual bug: it used to be silently dropped instead.
        let rehomed = db
            .find_by_id("peer-node-client-id")
            .expect("colliding incoming client must be present after merge, not dropped");
        assert_ne!(
            rehomed.vpn_ip, local.vpn_ip,
            "the incoming client must be re-homed to a DIFFERENT local vpn_ip, \
             not silently overwrite or share the existing client's IP"
        );

        // The original local client must be completely untouched.
        let local_after = db.find_by_id(&local.id).unwrap();
        assert_eq!(local_after.vpn_ip, local.vpn_ip);

        // No two live (non-tombstoned) clients may share a vpn_ip after the
        // merge — the whole point of the fix.
        let all = db.list_clients();
        for a in &all {
            for b in &all {
                if a.id != b.id {
                    assert_ne!(
                        a.vpn_ip, b.vpn_ip,
                        "no two live clients may share a vpn_ip after merge"
                    );
                }
            }
        }
    }

    /// LWW tie-break: two LEGACY records (same id+psk, `updated_at: None`
    /// on both sides) with divergent content must converge to the SAME
    /// deterministic winner on both nodes, and stay stable afterwards.
    /// The old rule ("incoming always wins when both are untimestamped")
    /// made the two nodes SWAP contents on every anti-entropy round —
    /// digests never converged and both sides re-saved forever.
    #[test]
    fn merge_from_json_untimestamped_tie_breaks_deterministically() {
        let dir = tempfile::tempdir().unwrap();
        let db_a = ClientDatabase::load(&dir.path().join("a.json"), test_network_config()).unwrap();
        let db_b = ClientDatabase::load(&dir.path().join("b.json"), test_network_config()).unwrap();

        // Same logical client (id + psk), no timestamps, divergent names —
        // seeded into each db via the merge insert path so BOTH copies stay
        // untimestamped (add_client would stamp updated_at).
        let template = {
            let seed_dir = tempfile::tempdir().unwrap();
            let seed_db =
                ClientDatabase::load(&seed_dir.path().join("s.json"), test_network_config())
                    .unwrap();
            let mut c = seed_db.add_client("seed").unwrap();
            c.updated_at = None;
            c
        };
        let mut variant_a = template.clone();
        variant_a.name = "as-seen-on-node-a".to_string();
        let mut variant_b = template.clone();
        variant_b.name = "as-seen-on-node-b".to_string();

        db_a.merge_from_json(&serde_json::to_string(&vec![variant_a.clone()]).unwrap())
            .unwrap();
        db_b.merge_from_json(&serde_json::to_string(&vec![variant_b.clone()]).unwrap())
            .unwrap();

        // One full bidirectional anti-entropy round: each side receives the
        // OTHER side's copy.
        db_a.merge_from_json(&serde_json::to_string(&vec![variant_b.clone()]).unwrap())
            .unwrap();
        db_b.merge_from_json(&serde_json::to_string(&vec![variant_a.clone()]).unwrap())
            .unwrap();

        let name_a = db_a.find_by_id(&template.id).unwrap().name;
        let name_b = db_b.find_by_id(&template.id).unwrap().name;
        assert_eq!(
            name_a, name_b,
            "both nodes must independently converge on the SAME winner"
        );

        // Second round with the SAME inputs must change nothing (stability —
        // this is what rules out the old A↔B content swap every round).
        let merged_a2 = db_a
            .merge_from_json(&serde_json::to_string(&vec![variant_b]).unwrap())
            .unwrap();
        let merged_b2 = db_b
            .merge_from_json(&serde_json::to_string(&vec![variant_a]).unwrap())
            .unwrap();
        assert_eq!(merged_a2, 0, "converged state must be a merge no-op");
        assert_eq!(merged_b2, 0, "converged state must be a merge no-op");
        assert_eq!(db_a.find_by_id(&template.id).unwrap().name, name_a);
        assert_eq!(db_b.find_by_id(&template.id).unwrap().name, name_b);
    }

    /// Hardening: an incoming record squatting on THIS node's server VPN IP
    /// must be re-homed (or skipped), never inserted as-is — otherwise
    /// `find_by_vpn_ip(server_ip)` starts resolving to a client.
    #[test]
    fn merge_from_json_rehomes_record_squatting_server_vpn_ip() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();
        let server_ip = Ipv4Addr::new(10, 99, 0, 1);

        let mut incoming = db.add_client("template").unwrap();
        db.remove_client(&incoming.id.clone()).unwrap();
        incoming.id = "squatter-id".to_string();
        incoming.name = "squatter".to_string();
        incoming.psk = [0x55; 32];
        incoming.vpn_ip = server_ip;

        let merged = db
            .merge_from_json(&serde_json::to_string(&vec![incoming]).unwrap())
            .unwrap();
        assert_eq!(merged, 1, "the record itself must still propagate");
        let stored = db.find_by_id("squatter-id").expect("record must merge");
        assert_ne!(
            stored.vpn_ip, server_ip,
            "an incoming record must never keep this node's server VPN IP"
        );
    }

    #[test]
    fn state_digest_is_stable_across_repeated_calls() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();
        db.add_client("alice").unwrap();
        db.add_client("bob").unwrap();

        let d1 = db.state_digest();
        let d2 = db.state_digest();
        assert_eq!(d1, d2, "digest must be deterministic across repeated calls");
    }

    /// The digest must not depend on the in-memory/on-disk record order —
    /// two databases holding the exact same logical records, inserted in
    /// opposite order, must hash identically.
    #[test]
    fn state_digest_is_order_independent() {
        let dir = tempfile::tempdir().unwrap();
        let db_a = ClientDatabase::load(&dir.path().join("a.json"), test_network_config()).unwrap();
        let db_b = ClientDatabase::load(&dir.path().join("b.json"), test_network_config()).unwrap();

        let a1 = db_a.add_client("alice").unwrap();
        let a2 = db_a.add_client("bob").unwrap();

        // Build db_b with the identical records but pushed in reverse order,
        // bypassing add_client's own allocation so insertion order is fully
        // controlled (mirrors how other tests in this file reach into
        // `db.data` directly, e.g. `tombstoned_vpn_ip_is_reusable`).
        {
            let mut data = db_b.data.write();
            data.clients.push(a2.clone());
            data.clients.push(a1.clone());
        }

        assert_eq!(
            db_a.state_digest(),
            db_b.state_digest(),
            "digest must not depend on insertion/storage order"
        );
    }

    /// Changing a stable, merge-converging field (here: `enabled`) must
    /// change the digest, and adding a tombstone must too — otherwise a real
    /// divergence would be invisible to the anti-entropy gate and never
    /// sync.
    #[test]
    fn state_digest_changes_on_stable_field_change_and_tombstone() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();
        let alice = db.add_client("alice").unwrap();

        let baseline = db.state_digest();

        // enabled: flip via the public update path.
        db.update_client(
            &alice.id,
            UpdateClientParams {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
        let after_disable = db.state_digest();
        assert_ne!(
            baseline, after_disable,
            "flipping `enabled` must change the digest"
        );

        // vpn_ip: a stable field but NOT one merge_from_json reconciles for
        // existing records — changing it must NOT be required to converge,
        // but is included here only to document it is excluded: mutate it
        // directly and confirm the digest is unaffected.
        db.data.write().clients[0].vpn_ip = Ipv4Addr::new(10, 99, 0, 250);
        let after_ip_change = db.state_digest();
        assert_eq!(
            after_disable, after_ip_change,
            "vpn_ip is not part of merge_from_json's converging set and must be excluded from the digest"
        );

        // Tombstone: removing the client must change the digest (a
        // revocation is exactly the kind of convergent state that must
        // propagate).
        db.remove_client(&alice.id).unwrap();
        let after_tombstone = db.state_digest();
        assert_ne!(
            after_ip_change, after_tombstone,
            "creating a tombstone must change the digest"
        );
    }

    /// Recording traffic (a purely local, volatile runtime counter that
    /// `merge_from_json` never reconciles) must NOT change the digest — if
    /// it did, two nodes that have converged on every field merge actually
    /// synchronizes would show different digests forever purely because
    /// their traffic volumes differ, permanently defeating the sync gate.
    #[test]
    fn state_digest_is_insensitive_to_volatile_stats() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();
        let alice = db.add_client("alice").unwrap();

        let before = db.state_digest();
        db.record_traffic(&alice.id, 12_345, 67_890);
        db.record_handshake(&alice.id);
        let after = db.state_digest();

        assert_eq!(
            before, after,
            "recording traffic/handshake stats must not change the digest"
        );
    }

    /// Phase 2 core invariant: `state_digest()` and `bucket_digests()` must
    /// agree on convergence — equal for two DBs holding the same records
    /// (regardless of insertion order), and BOTH must change together when a
    /// converging field changes. If this ever broke (root digest says
    /// "equal" but buckets differ, or vice versa), anti-entropy would either
    /// loop forever re-exchanging buckets that are actually identical, or
    /// silently miss a real divergence.
    #[test]
    fn state_digest_equal_iff_bucket_digests_equal() {
        let dir = tempfile::tempdir().unwrap();
        let db_a = ClientDatabase::load(&dir.path().join("a.json"), test_network_config()).unwrap();
        let db_b = ClientDatabase::load(&dir.path().join("b.json"), test_network_config()).unwrap();

        let a1 = db_a.add_client("alice").unwrap();
        let a2 = db_a.add_client("bob").unwrap();

        // db_b: identical records, opposite insertion order.
        {
            let mut data = db_b.data.write();
            data.clients.push(a2.clone());
            data.clients.push(a1.clone());
        }

        assert_eq!(db_a.state_digest(), db_b.state_digest());
        assert_eq!(
            db_a.bucket_digests(),
            db_b.bucket_digests(),
            "equal state_digest must imply equal bucket_digests"
        );
        assert_eq!(
            db_a.bucket_digests().len(),
            POOL_SYNC_BUCKETS * 8,
            "bucket_digests must be exactly POOL_SYNC_BUCKETS * 8 bytes"
        );

        // Diverge db_b on a converging field (enabled) — both digests must
        // change, and change TOGETHER (bucket digests must now differ too).
        db_b.update_client(
            &a1.id,
            UpdateClientParams {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .unwrap();

        assert_ne!(
            db_a.state_digest(),
            db_b.state_digest(),
            "diverging a converging field must change state_digest"
        );
        assert_ne!(
            db_a.bucket_digests(),
            db_b.bucket_digests(),
            "state_digest divergence must be visible in bucket_digests too"
        );
    }

    /// `clients_json_for_buckets` must return exactly the records whose
    /// bucket the caller asked for — not more (leaking unrelated records is
    /// wasted bandwidth) and not fewer (the peer would never converge).
    #[test]
    fn clients_json_for_buckets_returns_exact_subset() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();
        let a = db.add_client("alice").unwrap();
        let b = db.add_client("bob").unwrap();
        let c = db.add_client("carol").unwrap();

        let bucket_of = |id: &str| bucket_index_for_id(id) as u16;
        let all_ids = [
            (&a.id, bucket_of(&a.id)),
            (&b.id, bucket_of(&b.id)),
            (&c.id, bucket_of(&c.id)),
        ];

        // Pick a single bucket that holds at least one record (there always
        // is one — every record maps to exactly one bucket) and confirm the
        // returned JSON contains exactly (and only) the records in it.
        let target_bucket = all_ids[0].1;
        let expected_ids: std::collections::HashSet<&str> = all_ids
            .iter()
            .filter(|(_, b)| *b == target_bucket)
            .map(|(id, _)| id.as_str())
            .collect();

        let json = db.clients_json_for_buckets(&[target_bucket]);
        let returned: Vec<ClientConfig> = serde_json::from_str(&json).unwrap();
        let returned_ids: std::collections::HashSet<&str> =
            returned.iter().map(|c| c.id.as_str()).collect();

        assert_eq!(
            returned_ids, expected_ids,
            "clients_json_for_buckets must return exactly the records in the requested bucket(s)"
        );

        // Requesting a bucket index that (almost certainly) holds nothing
        // must return an empty array, never panic.
        let mut empty_bucket = 0u16;
        while all_ids.iter().any(|(_, b)| *b == empty_bucket) {
            empty_bucket += 1;
        }
        let empty_json = db.clients_json_for_buckets(&[empty_bucket]);
        let empty_returned: Vec<ClientConfig> = serde_json::from_str(&empty_json).unwrap();
        assert!(empty_returned.is_empty());
    }

    /// `differing_pool_buckets` must pinpoint exactly the buckets that
    /// changed between two digest snapshots, and treat a length mismatch
    /// (e.g. a peer on a different build) as "nothing to compare" rather
    /// than panicking.
    #[test]
    fn differing_pool_buckets_detects_exact_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();
        let alice = db.add_client("alice").unwrap();
        db.add_client("bob").unwrap();

        let before = db.bucket_digests();

        // Change a converging field on one client only.
        db.update_client(
            &alice.id,
            UpdateClientParams {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
        let after = db.bucket_digests();

        let differing = differing_pool_buckets(&before, &after);
        assert!(
            !differing.is_empty(),
            "changing a client must produce at least one differing bucket"
        );
        // The only bucket that legitimately differs is alice's.
        let alice_bucket = bucket_index_for_id(&alice.id) as u16;
        assert!(differing.contains(&alice_bucket));
        // And every reported differing bucket must actually have changed.
        for idx in &differing {
            let i = *idx as usize * 8;
            assert_ne!(
                &before[i..i + 8],
                &after[i..i + 8],
                "reported differing bucket {} must actually differ",
                idx
            );
        }

        // Identical digests: no differing buckets.
        assert!(differing_pool_buckets(&after, &after).is_empty());

        // Length mismatch: must return empty, not panic.
        assert!(differing_pool_buckets(&before, &before[..8]).is_empty());
    }

    /// Both-directions convergence property, in miniature: two independent
    /// DBs each hold exactly one record the other lacks. `differing_pool_buckets`
    /// must catch both buckets, and `clients_json_for_buckets(differing)` on
    /// EACH side must yield exactly that side's own record — i.e. the record
    /// the peer is missing — never the other side's record and never both.
    /// This is what the Phase 2 `PoolBucketDigests { reply_requested }`
    /// exchange relies on to reconcile both directions over one session
    /// (see `pool_dialer.rs::anti_entropy` / `gateway.rs`'s matching arm).
    #[test]
    fn bucket_digests_diff_yields_each_sides_own_missing_record() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let db_a = ClientDatabase::load(&dir_a.path().join("clients.json"), test_network_config())
            .unwrap();
        let db_b = ClientDatabase::load(&dir_b.path().join("clients.json"), test_network_config())
            .unwrap();

        // Pick two candidate names that land in different buckets so the
        // two "missing" records are distinguishable by bucket index (a
        // real-world collision would just merge the delta into one
        // PoolSync round, but the point of this test is to show the
        // per-bucket attribution is exact).
        let name_a = "alice".to_string();
        let mut name_b = "bob".to_string();
        let mut n = 0u32;
        while bucket_index_for_id(&name_a) == bucket_index_for_id(&name_b) {
            n += 1;
            name_b = format!("bob{n}");
        }

        let alice = db_a.add_client(&name_a).unwrap();
        let bob = db_b.add_client(&name_b).unwrap();
        assert_ne!(
            bucket_index_for_id(&alice.id) % POOL_SYNC_BUCKETS,
            bucket_index_for_id(&bob.id) % POOL_SYNC_BUCKETS
        );

        let buckets_a = db_a.bucket_digests();
        let buckets_b = db_b.bucket_digests();

        // Symmetric: the differing set computed from either side is the
        // same pair of bucket indices (only a's and b's buckets changed).
        let differing_from_a = differing_pool_buckets(&buckets_a, &buckets_b);
        let differing_from_b = differing_pool_buckets(&buckets_b, &buckets_a);
        assert_eq!(differing_from_a, differing_from_b);
        assert_eq!(differing_from_a.len(), 2);

        // A's delta for the differing buckets must contain ONLY alice
        // (bob does not exist in db_a at all).
        let json_a = db_a.clients_json_for_buckets(&differing_from_a);
        let returned_a: Vec<ClientConfig> = serde_json::from_str(&json_a).unwrap();
        let ids_a: std::collections::HashSet<&str> =
            returned_a.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids_a, std::collections::HashSet::from([alice.id.as_str()]));

        // B's delta for the SAME differing buckets must contain ONLY bob —
        // this is the reverse direction the `reply_requested` round trip
        // exists to pull out of the peer.
        let json_b = db_b.clients_json_for_buckets(&differing_from_b);
        let returned_b: Vec<ClientConfig> = serde_json::from_str(&json_b).unwrap();
        let ids_b: std::collections::HashSet<&str> =
            returned_b.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids_b, std::collections::HashSet::from([bob.id.as_str()]));

        // Sanity: merging each side's delta into the other converges both
        // DBs to hold both records.
        db_a.merge_from_json(&json_b).unwrap();
        db_b.merge_from_json(&json_a).unwrap();
        assert_eq!(db_a.state_digest(), db_b.state_digest());
    }

    /// Repeatedly rewrite `path` with `content` until the file's mtime is
    /// observed to change from `original`, or give up after a bounded
    /// number of attempts. Mirrors the loop already used by
    /// `reload_if_changed_applies_psk_rotation` — needed because some
    /// filesystems have coarse mtime resolution, so a single rewrite
    /// immediately after the original write can land on an identical
    /// timestamp and be invisible to `reload_if_changed`'s mtime-compare
    /// gate.
    fn write_until_mtime_advances(path: &Path, content: &str, original: std::time::SystemTime) {
        let mut advanced = false;
        for _ in 0..40 {
            std::fs::write(path, content).unwrap();
            let new_mtime = std::fs::metadata(path).unwrap().modified().unwrap();
            if new_mtime != original {
                advanced = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(60));
        }
        assert!(advanced, "test setup failed to advance client DB mtime");
    }

    /// A2 regression: a concurrent EXTERNAL writer (e.g. a short-lived admin
    /// CLI `--add-client` process) adds a client directly to the shared
    /// `clients.json` file while a second, long-lived `ClientDatabase`
    /// instance (standing in for the daemon) still holds a stale in-memory
    /// snapshot from before that write. Before the A2 fix, the daemon's next
    /// `merge_from_json` (e.g. from an unrelated peer PoolSync round) would
    /// `save()` its stale snapshot, silently overwriting the externally
    /// added client on disk and resetting the cached mtime so the daemon's
    /// own polling reload would never notice the loss. The fix makes
    /// `merge_from_json` pull in external changes (via `reload_if_changed`)
    /// before computing/saving its own merge, so the externally-added client
    /// must survive.
    #[test]
    fn merge_from_json_does_not_clobber_concurrent_external_write() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("clients.json");

        // "Daemon" instance: adds a baseline client, then keeps running with
        // this in-memory snapshot.
        let daemon = ClientDatabase::load(&db_path, test_network_config()).unwrap();
        daemon.add_client("existing").unwrap();
        let mtime_after_daemon_write = std::fs::metadata(&db_path).unwrap().modified().unwrap();

        // "Admin CLI" instance: a SEPARATE ClientDatabase handle on the SAME
        // path, exactly like a short-lived `--add-client` process would be.
        // It loads the current on-disk state (which already has "existing"),
        // adds "alice", and writes back out — all while `daemon` above still
        // only knows about "existing" in memory.
        let admin = ClientDatabase::load(&db_path, test_network_config()).unwrap();
        let alice = admin.add_client("alice").unwrap();

        // Guarantee the on-disk mtime actually advanced past what `daemon`
        // cached, so this test exercises the real race and isn't a no-op on
        // a filesystem with coarse mtime resolution. `admin.add_client`
        // above already wrote the file once; if that alone didn't move the
        // mtime, rewrite the same (already-correct) content until it does.
        let current_content = std::fs::read_to_string(&db_path).unwrap();
        write_until_mtime_advances(&db_path, &current_content, mtime_after_daemon_write);

        // `daemon` is still unaware of "alice" in memory at this point.
        assert!(
            daemon.find_by_name("alice").is_none(),
            "test setup: daemon's in-memory snapshot must still be stale"
        );

        // Now the daemon receives an unrelated peer merge (a brand new
        // client neither side has seen) — this is what used to trigger the
        // clobbering `save()`.
        let peer_client = ClientConfig {
            id: "peer-bob-id".to_string(),
            name: "peer-bob".to_string(),
            psk: [0x55; 32],
            vpn_ip: Ipv4Addr::new(10, 99, 0, 250),
            enabled: true,
            created_at: Utc::now(),
            stats: ClientStats::default(),
            qos: None,
            device_pubkey: None,
            one_time: false,
            expires_at: None,
            updated_at: Some(Utc::now()),
            deleted: false,
            role: ClientRole::User,
            exit_node: None,
        };
        let merged = daemon
            .merge_from_json(&serde_json::to_string(&vec![peer_client]).unwrap())
            .unwrap();
        assert_eq!(merged, 1, "the new peer client must merge");

        // The externally-added "alice" must have survived the daemon's
        // save() — both in the daemon's own in-memory view...
        assert!(
            daemon.find_by_name("alice").is_some(),
            "A2: concurrent external add must survive a subsequent merge_from_json save"
        );
        assert_eq!(daemon.find_by_id(&alice.id).unwrap().name, "alice");

        // ...and on disk, read back through a completely fresh instance.
        let reloaded = ClientDatabase::load(&db_path, test_network_config()).unwrap();
        let names: std::collections::HashSet<String> = reloaded
            .list_clients()
            .into_iter()
            .map(|c| c.name)
            .collect();
        assert_eq!(
            names,
            std::collections::HashSet::from([
                "existing".to_string(),
                "alice".to_string(),
                "peer-bob".to_string(),
            ]),
            "A2: all three clients (pre-existing, concurrently-added, and peer-merged) must be present on disk"
        );
    }

    /// A3 regression: `merge_from_json` upserts by `id`, not `name`, so a
    /// peer's independently-created record can converge into a live `name`
    /// collision with an existing local record. The fix does not drop or
    /// rename either record (both ids must still converge across the pool)
    /// but must detect and surface the collision. Exercised here via the
    /// `warn_duplicate_live_names` helper directly (its only caller is
    /// `merge_from_json`, and its effect — a `tracing::warn!` — isn't
    /// observable through the public API), while also confirming
    /// `merge_from_json` itself does not lose or mutate either record.
    #[test]
    fn merge_from_json_detects_duplicate_live_name_without_losing_either_record() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();

        let local = db.add_client("shared-name").unwrap();

        // A peer's record: different id/psk, but the SAME live name.
        let incoming = ClientConfig {
            id: "peer-duplicate-name-id".to_string(),
            name: "shared-name".to_string(),
            psk: [0x99; 32],
            vpn_ip: Ipv4Addr::new(10, 99, 0, 200),
            enabled: true,
            created_at: Utc::now(),
            stats: ClientStats::default(),
            qos: None,
            device_pubkey: None,
            one_time: false,
            expires_at: None,
            updated_at: Some(Utc::now()),
            deleted: false,
            role: ClientRole::User,
            exit_node: None,
        };

        let merged = db
            .merge_from_json(&serde_json::to_string(&vec![incoming]).unwrap())
            .unwrap();
        assert_eq!(
            merged, 1,
            "the name-colliding incoming record must still merge"
        );

        // Neither record was dropped or renamed — convergence must not be
        // sacrificed to resolve the name collision.
        assert!(
            db.find_by_id(&local.id).is_some(),
            "the local record must survive a name collision"
        );
        assert!(
            db.find_by_id("peer-duplicate-name-id").is_some(),
            "the incoming record must survive a name collision, not be dropped or renamed"
        );
        let all_live = db.list_clients();
        assert_eq!(
            all_live.iter().filter(|c| c.name == "shared-name").count(),
            2,
            "both live records legitimately share the name after merge — this IS the bug surface \
             that warn_duplicate_live_names must report"
        );

        // The detection helper itself: given this exact merged state, it
        // must recognize the two ids sharing "shared-name" as a duplicate
        // (i.e. it does not silently pass over a real collision). This is a
        // white-box check on the same logic `merge_from_json` invokes.
        let ids_named_shared: Vec<&str> = all_live
            .iter()
            .filter(|c| c.name == "shared-name")
            .map(|c| c.id.as_str())
            .collect();
        assert_eq!(
            ids_named_shared.len(),
            2,
            "sanity: exactly two distinct ids hold the duplicate name"
        );
        // Exercise the same code path merge_from_json calls, directly, so a
        // regression that makes it stop detecting collisions (e.g. an
        // accidental early-return) would fail this test even though it has
        // no other externally observable effect.
        ClientDatabase::warn_duplicate_live_names(&all_live);
    }

    /// Pool-sync convergence: an Admin elevation made on one node (with a
    /// newer `updated_at`) must propagate to a peer node via
    /// `merge_from_json`, exactly like `enabled`/`expires_at`/etc.
    #[test]
    fn merge_from_json_converges_role_elevation_last_writer_wins() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let db_a = ClientDatabase::load(&dir_a.path().join("clients.json"), test_network_config())
            .unwrap();
        let db_b = ClientDatabase::load(&dir_b.path().join("clients.json"), test_network_config())
            .unwrap();

        // Same logical client on both "nodes" (shared id/psk), starting as
        // a plain User but already device-bound so the elevation below is
        // legal.
        let client = db_a.add_client("shared").unwrap();
        db_a.enroll_device(&client.id, &[0x11; 32]).unwrap();
        db_b.merge_from_json(&db_a.export_json().unwrap()).unwrap();
        assert_eq!(db_b.find_by_id(&client.id).unwrap().role, ClientRole::User);

        // Elevate to Admin on node A — `update_client` stamps a fresh
        // `updated_at`, guaranteeing it's strictly newer than B's copy.
        db_a.update_client(
            &client.id,
            UpdateClientParams {
                role: Some(ClientRole::Admin),
                ..Default::default()
            },
        )
        .unwrap();

        // Merge A's state into B: the elevation must converge.
        let merged = db_b.merge_from_json(&db_a.export_json().unwrap()).unwrap();
        assert_eq!(merged, 1, "the role elevation must merge");
        assert_eq!(
            db_b.find_by_id(&client.id).unwrap().role,
            ClientRole::Admin,
            "role must converge pool-wide via merge_from_json"
        );
    }

    /// A tombstoned (revoked) client must not have its role "come back" via
    /// a merge from a peer that still holds an older, live copy — the
    /// sticky-tombstone policy that already protects `enabled`/`deleted`
    /// must equally protect `role`.
    #[test]
    fn merge_from_json_tombstone_does_not_resurrect_role() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();

        let client = db.add_client("revoked-admin").unwrap();
        db.enroll_device(&client.id, &[0x22; 32]).unwrap();
        db.update_client(
            &client.id,
            UpdateClientParams {
                role: Some(ClientRole::Admin),
                ..Default::default()
            },
        )
        .unwrap();

        // Revoke locally (tombstone). remove_client bumps updated_at.
        db.remove_client(&client.id).unwrap();
        assert!(
            db.find_by_id(&client.id).is_none(),
            "tombstoned clients are invisible to lookups"
        );

        // A peer's OLDER live copy (still role=Admin, not yet aware of the
        // revocation) arrives — it must not resurrect the client or its role.
        let stale_peer_copy = ClientConfig {
            id: client.id.clone(),
            name: client.name.clone(),
            psk: client.psk,
            vpn_ip: client.vpn_ip,
            enabled: true,
            created_at: client.created_at,
            stats: ClientStats::default(),
            qos: None,
            device_pubkey: Some([0x22; 32]),
            one_time: false,
            expires_at: None,
            updated_at: Some(client.created_at), // older than the tombstone's updated_at
            deleted: false,
            role: ClientRole::Admin,
            exit_node: None,
        };
        let merged = db
            .merge_from_json(&serde_json::to_string(&vec![stale_peer_copy]).unwrap())
            .unwrap();
        assert_eq!(
            merged, 0,
            "an older live peer record must not beat a tombstone"
        );
        assert!(
            db.find_by_id(&client.id).is_none(),
            "the client must remain revoked (invisible) after the merge"
        );
        let raw = db
            .list_clients_including_deleted()
            .into_iter()
            .find(|c| c.id == client.id)
            .unwrap();
        assert!(raw.deleted, "the tombstone itself must survive");
        assert_eq!(
            raw.role,
            ClientRole::Admin,
            "the tombstone keeps whatever role it already had locally — it was not overwritten \
             by the stale peer, and it was certainly not silently un-revoked"
        );
    }

    /// Pool-sync convergence: an exit_node override set on one node (with a
    /// newer `updated_at`) must propagate to a peer node via
    /// `merge_from_json`, exactly like `role`.
    #[test]
    fn merge_from_json_converges_exit_node_last_writer_wins() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let db_a = ClientDatabase::load(&dir_a.path().join("clients.json"), test_network_config())
            .unwrap();
        let db_b = ClientDatabase::load(&dir_b.path().join("clients.json"), test_network_config())
            .unwrap();

        let client = db_a.add_client("shared-exit").unwrap();
        db_b.merge_from_json(&db_a.export_json().unwrap()).unwrap();
        assert_eq!(db_b.find_by_id(&client.id).unwrap().exit_node, None);

        db_a.update_client(
            &client.id,
            UpdateClientParams {
                exit_node: Some(Some("exit-a.example.com:51820".to_string())),
                ..Default::default()
            },
        )
        .unwrap();

        let merged = db_b.merge_from_json(&db_a.export_json().unwrap()).unwrap();
        assert_eq!(merged, 1, "the exit_node change must merge");
        assert_eq!(
            db_b.find_by_id(&client.id).unwrap().exit_node,
            Some("exit-a.example.com:51820".to_string()),
            "exit_node must converge pool-wide via merge_from_json"
        );
    }

    /// Tombstone-sticky policy must equally protect `exit_node`: a stale
    /// peer's older live copy must not resurrect a revoked client or
    /// reintroduce its old exit_node value.
    #[test]
    fn merge_from_json_tombstone_does_not_resurrect_exit_node() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();

        let client = db.add_client("revoked-exit").unwrap();
        db.update_client(
            &client.id,
            UpdateClientParams {
                exit_node: Some(Some("exit-old.example.com:51820".to_string())),
                ..Default::default()
            },
        )
        .unwrap();

        db.remove_client(&client.id).unwrap();
        assert!(db.find_by_id(&client.id).is_none());

        let stale_peer_copy = ClientConfig {
            id: client.id.clone(),
            name: client.name.clone(),
            psk: client.psk,
            vpn_ip: client.vpn_ip,
            enabled: true,
            created_at: client.created_at,
            stats: ClientStats::default(),
            qos: None,
            device_pubkey: None,
            one_time: false,
            expires_at: None,
            updated_at: Some(client.created_at), // older than the tombstone's updated_at
            deleted: false,
            role: ClientRole::User,
            exit_node: Some("exit-stale.example.com:51820".to_string()),
        };
        let merged = db
            .merge_from_json(&serde_json::to_string(&vec![stale_peer_copy]).unwrap())
            .unwrap();
        assert_eq!(
            merged, 0,
            "an older live peer record must not beat a tombstone"
        );
        assert!(db.find_by_id(&client.id).is_none());
        let raw = db
            .list_clients_including_deleted()
            .into_iter()
            .find(|c| c.id == client.id)
            .unwrap();
        assert!(raw.deleted);
        assert_eq!(
            raw.exit_node,
            Some("exit-old.example.com:51820".to_string()),
            "the tombstone keeps whatever exit_node it already had locally — it was not \
             overwritten by the stale peer"
        );
    }
}
