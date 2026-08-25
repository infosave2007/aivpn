//! Pool-node identity binding store (Phase 4 — per-node cryptographic
//! identity, RECEIVE/BIND side).
//!
//! Analogous to the client device-binding model in `client_db.rs`
//! (`ClientConfig::device_pubkey` / one-time enrollment), but at the pool
//! level: a peer's self-asserted `node_id` (a plain string, e.g. its
//! `host:port`) is otherwise unauthenticated — anyone who can complete the
//! masked pool-client handshake can claim to BE any `node_id`. This module
//! binds `node_id` to a durable Ed25519 `node_pub` the first time a peer
//! proves ownership of it via a valid `ControlPayload::NodeEnrollment` (see
//! `aivpn_common::crypto::{node_identity_from_seed,
//! node_enrollment_signing_bytes, verify_node_enrollment}`), and rejects any
//! later claim of the same `node_id` from a different key — Trust-On-First-
//! Use (TOFU), same trust model as client device binding.
//!
//! Persisted to `pool_nodes.json`, sibling to `clients.json`. Two on-disk
//! shapes are understood:
//!
//! - Legacy (pre-revocation) flat form, still the load-compat target for
//!   any file written before this module gained durable revocation:
//!   `{ "<node_id>": "<base64 32-byte pubkey>" }`.
//! - Current structured form, written by `persist()`:
//!   `{ "nodes": { "<node_id>": "<base64 32-byte pubkey>" }, "revoked": ["<node_id>", ...] }`.
//!
//! `load()` tries the structured form first and falls back to the legacy
//! flat form so an existing deployment's `pool_nodes.json` keeps working
//! across the upgrade with no migration step.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use aivpn_common::crypto;

/// On-disk structured form written by `NodeRegistry::persist`. See the
/// module doc for the legacy flat form this is loaded alongside.
#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedStore {
    nodes: HashMap<String, String>,
    #[serde(default)]
    revoked: Vec<String>,
}

/// Freshness window for `NodeEnrollment` proofs — mirrors the resonance-tag
/// time-window pattern used elsewhere in the protocol. A `time_window` more
/// than 2 windows away from "now" (60s each — see `compute_time_window`) is
/// rejected as stale, bounding how long a captured enrollment message can be
/// replayed.
const NODE_ENROLL_WINDOW_MS: u64 = 60_000;

/// Result of `NodeRegistry::authenticate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeAuthOutcome {
    /// `node_id` was already bound to this exact `node_pub` — proof checks
    /// out against the existing pin.
    Verified,
    /// `node_id` was not previously bound; this proof bound it to `node_pub`
    /// for the first time (TOFU).
    BoundNew,
    /// The proof was rejected. The `&'static str` is a short, log-friendly
    /// reason — never attacker-controlled text.
    Rejected(&'static str),
}

/// Thread-safe, file-persisted store of `node_id -> node_pub` bindings,
/// plus a durable set of revoked `node_id`s (see the D3 fix note on
/// `revoke`).
pub struct NodeRegistry {
    path: PathBuf,
    nodes: RwLock<HashMap<String, [u8; 32]>>,
    /// `node_id`s an operator has explicitly revoked. Checked in
    /// `authenticate` *before* the TOFU auto-add path, so a revoked
    /// identity cannot be silently re-bound by whoever next completes a
    /// masked handshake claiming that `node_id` — durable protection,
    /// not just "unbound until the next arrival".
    revoked: RwLock<HashSet<String>>,
    allow_auto_add: bool,
    /// Per-process counter mixed into the persist-temp-file name so two
    /// concurrent `persist()` calls (e.g. two TOFU binds racing in
    /// different tasks) never collide on `{path}.{pid}.tmp` and fail the
    /// rename with ENOENT (D5 fix).
    tmp_counter: AtomicU64,
    /// Serializes `persist()` end to end — snapshot, write and rename under
    /// one lock.
    ///
    /// Unique temp names stopped the two writers from clobbering each
    /// other's file, but not from inverting: a thread that snapshots the map
    /// and is then descheduled can rename its stale copy over a newer one,
    /// dropping every binding added in between. Taking this lock before the
    /// snapshot makes the last rename always carry the newest state.
    ///
    /// It is not the `nodes` lock: holding that across file I/O would block
    /// every reader for the duration of a write.
    persist_lock: Mutex<()>,
}

/// Decode a base64-encoded 32-byte Ed25519 public key, logging and
/// returning `None` on any malformed entry rather than failing the whole
/// load.
fn decode_pubkey(node_id: &str, b64: &str) -> Option<[u8; 32]> {
    match base64::engine::general_purpose::STANDARD
        .decode(b64)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    {
        Some(pub_bytes) => Some(pub_bytes),
        None => {
            warn!(
                "pool_nodes.json: skipping node '{}' with malformed pubkey",
                node_id
            );
            None
        }
    }
}

impl NodeRegistry {
    /// Load `pool_nodes.json` from `path`. A missing file is treated as an
    /// empty registry (fresh deployment); a malformed file is logged and
    /// treated as empty as well — this store gates an anti-entropy control
    /// channel, not the data plane, so failing to load it must never block
    /// server startup the way a corrupt `clients.json` would.
    ///
    /// Accepts either on-disk shape described in the module doc: the
    /// current structured `{ "nodes": {...}, "revoked": [...] }` form is
    /// tried first, falling back to the legacy flat `{node_id: pubkey}`
    /// form (which has no revocation data, so `revoked` starts empty).
    pub fn load(path: PathBuf, allow_auto_add: bool) -> Self {
        let (nodes, revoked) = match std::fs::read_to_string(&path) {
            Ok(content) if content.trim().is_empty() => (HashMap::new(), HashSet::new()),
            Ok(content) => Self::parse_persisted(&content, &path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (HashMap::new(), HashSet::new()),
            Err(e) => {
                error!(
                    "Failed to read pool_nodes.json at {:?}: {} — starting with an empty node registry",
                    path, e
                );
                (HashMap::new(), HashSet::new())
            }
        };

        Self {
            path,
            nodes: RwLock::new(nodes),
            revoked: RwLock::new(revoked),
            allow_auto_add,
            tmp_counter: AtomicU64::new(0),
            persist_lock: Mutex::new(()),
        }
    }

    /// Parse file contents in either on-disk shape. Tries the structured
    /// form first (it has a required `nodes` field, so it simply fails to
    /// deserialize — no ambiguity risk — against a legacy flat file whose
    /// top-level values are base64 strings, not an object/array) and falls
    /// back to the legacy flat `{node_id: pubkey}` map.
    fn parse_persisted(
        content: &str,
        path: &std::path::Path,
    ) -> (HashMap<String, [u8; 32]>, HashSet<String>) {
        if let Ok(store) = serde_json::from_str::<PersistedStore>(content) {
            let mut map = HashMap::with_capacity(store.nodes.len());
            for (node_id, b64) in store.nodes {
                if let Some(pub_bytes) = decode_pubkey(&node_id, &b64) {
                    map.insert(node_id, pub_bytes);
                }
            }
            let revoked: HashSet<String> = store.revoked.into_iter().collect();
            return (map, revoked);
        }

        match serde_json::from_str::<HashMap<String, String>>(content) {
            Ok(raw) => {
                let mut map = HashMap::with_capacity(raw.len());
                for (node_id, b64) in raw {
                    if let Some(pub_bytes) = decode_pubkey(&node_id, &b64) {
                        map.insert(node_id, pub_bytes);
                    }
                }
                (map, HashSet::new())
            }
            Err(e) => {
                error!(
                    "Failed to parse pool_nodes.json at {:?}: {} — starting with an empty node registry",
                    path, e
                );
                (HashMap::new(), HashSet::new())
            }
        }
    }

    /// Authenticate a `NodeEnrollment` proof and, depending on prior state,
    /// bind, verify, or reject it. Never overwrites an existing binding —
    /// a mismatch is always `Rejected`, never a silent re-pin.
    ///
    /// `server_eph_pub`/`client_eph_pub` are the CALLER's session's ephemeral
    /// X25519 transcript (see `Session::server_eph_pub`/`Session::eph_pub`
    /// in `gateway.rs`'s masked pool-peer handling) — passed straight through
    /// to [`crypto::verify_node_enrollment`] so a proof captured on one
    /// session can never be replayed onto another (B2/D2 fix).
    pub fn authenticate(
        &self,
        node_id: &str,
        node_pub: &[u8; 32],
        time_window: u64,
        signature: &[u8; 64],
        server_eph_pub: &[u8; 32],
        client_eph_pub: &[u8; 32],
    ) -> NodeAuthOutcome {
        let cur =
            crypto::compute_time_window(crypto::current_timestamp_ms(), NODE_ENROLL_WINDOW_MS);
        if time_window.abs_diff(cur) > 2 {
            return NodeAuthOutcome::Rejected("stale enrollment");
        }

        if !crypto::verify_node_enrollment(
            node_pub,
            node_id,
            time_window,
            signature,
            server_eph_pub,
            client_eph_pub,
        ) {
            return NodeAuthOutcome::Rejected("bad signature");
        }

        // D3 fix: a revoked node_id must never be silently re-bound via
        // TOFU by whoever next completes a masked handshake claiming it —
        // check the durable revocation tombstone before any bound-check or
        // auto-add logic runs. This also wins over an existing binding: a
        // node_id that is both revoked and still bound (revoke() normally
        // clears the binding too, but a legacy/partial-write state could
        // leave both) is rejected here, never silently re-verified.
        if self.revoked.read().contains(node_id) {
            return NodeAuthOutcome::Rejected("revoked node — re-approval required");
        }

        // Look up first under a read lock; only take the write lock (and
        // persist) on the TOFU bind path, so the common "already bound,
        // verified" case never blocks concurrent readers against each other.
        {
            let nodes = self.nodes.read();
            if let Some(stored) = nodes.get(node_id) {
                return if stored == node_pub {
                    NodeAuthOutcome::Verified
                } else {
                    NodeAuthOutcome::Rejected("node_pub mismatch — impostor or key rotation")
                };
            }
        }

        if !self.allow_auto_add {
            return NodeAuthOutcome::Rejected("unknown node, auto-add disabled");
        }

        {
            let mut nodes = self.nodes.write();
            // Re-check under the write lock: another thread may have bound
            // this node_id between the read-lock check above and here.
            match nodes.get(node_id) {
                Some(stored) if stored == node_pub => return NodeAuthOutcome::Verified,
                Some(_) => {
                    return NodeAuthOutcome::Rejected(
                        "node_pub mismatch — impostor or key rotation",
                    )
                }
                None => {
                    nodes.insert(node_id.to_string(), *node_pub);
                }
            }
        }

        if let Err(e) = self.persist() {
            warn!(
                "Failed to persist pool_nodes.json after binding '{}': {}",
                node_id, e
            );
        }
        info!("pool node '{}' bound (TOFU) to a new identity key", node_id);
        NodeAuthOutcome::BoundNew
    }

    /// Remove a bound node AND add it to the durable revocation tombstone
    /// (D3 fix), persisting the change. Unlike the pre-fix behavior (which
    /// only removed the binding), this makes revocation stick: `authenticate`
    /// rejects any later `NodeEnrollment` for this `node_id` — even from the
    /// legitimate node itself — until an operator calls `unrevoke`. Without
    /// this, `allow_auto_add=true` (the default) meant the very next
    /// enrollment for the node_id — from anyone who can complete the masked
    /// handshake, not necessarily the original owner — would instantly
    /// re-bind it via TOFU, giving a revoke no durable effect.
    ///
    /// Returns `true` if either the binding was removed or the node_id was
    /// newly added to the revoked set (i.e. state actually changed).
    pub fn revoke(&self, node_id: &str) -> bool {
        let mut changed = false;
        {
            let mut nodes = self.nodes.write();
            if nodes.remove(node_id).is_some() {
                changed = true;
            }
        }
        {
            let mut revoked = self.revoked.write();
            if revoked.insert(node_id.to_string()) {
                changed = true;
            }
        }
        if changed {
            if let Err(e) = self.persist() {
                warn!(
                    "Failed to persist pool_nodes.json after revoking '{}': {}",
                    node_id, e
                );
            }
        }
        changed
    }

    /// Remove `node_id` from the revoked set, persisting the change, so an
    /// operator can deliberately re-allow a node to (re-)bind via TOFU (or
    /// simply be `Verified` again if it somehow retained its old binding).
    /// Needed as the counterpart to `revoke` now that revocation is durable
    /// rather than just "unbound until next arrival". Returns `true` if the
    /// node_id was in the revoked set and was removed.
    pub fn unrevoke(&self, node_id: &str) -> bool {
        let removed = {
            let mut revoked = self.revoked.write();
            revoked.remove(node_id)
        };
        if removed {
            if let Err(e) = self.persist() {
                warn!(
                    "Failed to persist pool_nodes.json after unrevoking '{}': {}",
                    node_id, e
                );
            }
        }
        removed
    }

    /// All bound nodes, sorted by `node_id`.
    pub fn list(&self) -> Vec<(String, [u8; 32])> {
        let nodes = self.nodes.read();
        let mut out: Vec<(String, [u8; 32])> = nodes.iter().map(|(k, v)| (k.clone(), *v)).collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// All revoked `node_id`s, sorted.
    pub fn list_revoked(&self) -> Vec<String> {
        let revoked = self.revoked.read();
        let mut out: Vec<String> = revoked.iter().cloned().collect();
        out.sort();
        out
    }

    /// Serialize and atomically persist the current bindings AND the
    /// revoked-set tombstone to `self.path` via a temp-file-then-rename,
    /// mirroring `ClientDatabase::save`. Takes its own read locks internally
    /// (never called while a caller already holds `nodes`/`revoked` locked)
    /// so this can never deadlock against the RwLocks.
    fn persist(&self) -> std::io::Result<()> {
        // Held across snapshot, write and rename: see `persist_lock`.
        let _serialize = self.persist_lock.lock();

        let encoded_nodes: HashMap<String, String> = {
            let nodes = self.nodes.read();
            nodes
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        base64::engine::general_purpose::STANDARD.encode(v),
                    )
                })
                .collect()
        };
        let mut revoked_list: Vec<String> = {
            let revoked = self.revoked.read();
            revoked.iter().cloned().collect()
        };
        revoked_list.sort();

        let store = PersistedStore {
            nodes: encoded_nodes,
            revoked: revoked_list,
        };
        let content = serde_json::to_string_pretty(&store)
            .map_err(|e| std::io::Error::other(format!("serialize pool_nodes.json: {}", e)))?;

        // D5 fix: mix a per-process, monotonically increasing counter into
        // the temp-file name alongside the PID. Two concurrent TOFU binds
        // in the same process (e.g. two `authenticate` calls racing on
        // different node_ids) previously both wrote `{path}.{pid}.tmp`; the
        // second `fs::write` would clobber the first's temp file mid-write
        // (or the first `fs::rename` would find its source already gone,
        // returning ENOENT), corrupting the persisted state or spuriously
        // failing. The PID alone only disambiguates across processes.
        let suffix = self.tmp_counter.fetch_add(1, Ordering::Relaxed);
        let tmp_path = self
            .path
            .with_extension(format!("{}.{}.tmp", std::process::id(), suffix));
        std::fs::write(&tmp_path, &content)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) =
                std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))
            {
                warn!("Failed to set pool_nodes.json permissions to 0600: {}", e);
            }
        }
        std::fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed test session transcript — every test below authenticates
    /// against this same (server_eph_pub, client_eph_pub) pair unless it is
    /// specifically exercising cross-session-replay rejection, so the
    /// existing TOFU/impostor/revoke/stale coverage holds unchanged under a
    /// consistent transcript.
    const TEST_SERVER_EPH: [u8; 32] = [0xD1u8; 32];
    const TEST_CLIENT_EPH: [u8; 32] = [0xD2u8; 32];

    /// Build a valid enrollment tuple `(node_pub, time_window, signature)`
    /// for `node_id`, signed with the identity derived from `seed`, bound to
    /// the fixed `TEST_SERVER_EPH`/`TEST_CLIENT_EPH` test transcript.
    fn build_enrollment(seed: &[u8; 32], node_id: &str) -> ([u8; 32], u64, [u8; 64]) {
        let signing_key = crypto::node_identity_from_seed(seed);
        let node_pub = signing_key.verifying_key().to_bytes();
        let time_window =
            crypto::compute_time_window(crypto::current_timestamp_ms(), NODE_ENROLL_WINDOW_MS);
        let msg = crypto::node_enrollment_signing_bytes(
            node_id,
            &node_pub,
            time_window,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        let signature = {
            use ed25519_dalek::Signer;
            signing_key.sign(&msg).to_bytes()
        };
        (node_pub, time_window, signature)
    }

    fn registry_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("pool_nodes.json")
    }

    #[test]
    fn tofu_binds_new_node_then_verifies_on_reauth() {
        let dir = tempfile::tempdir().unwrap();
        let reg = NodeRegistry::load(registry_path(&dir), true);
        let seed = [0x11u8; 32];
        let (node_pub, time_window, signature) = build_enrollment(&seed, "node-a:443");

        let first = reg.authenticate(
            "node-a:443",
            &node_pub,
            time_window,
            &signature,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        assert_eq!(first, NodeAuthOutcome::BoundNew);

        let second = reg.authenticate(
            "node-a:443",
            &node_pub,
            time_window,
            &signature,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        assert_eq!(second, NodeAuthOutcome::Verified);
    }

    #[test]
    fn rejects_unknown_node_when_auto_add_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let reg = NodeRegistry::load(registry_path(&dir), false);
        let seed = [0x22u8; 32];
        let (node_pub, time_window, signature) = build_enrollment(&seed, "node-b:443");

        let outcome = reg.authenticate(
            "node-b:443",
            &node_pub,
            time_window,
            &signature,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        assert_eq!(
            outcome,
            NodeAuthOutcome::Rejected("unknown node, auto-add disabled")
        );
        assert!(reg.list().is_empty());
    }

    #[test]
    fn rejects_impostor_with_different_key_for_bound_node() {
        let dir = tempfile::tempdir().unwrap();
        let reg = NodeRegistry::load(registry_path(&dir), true);

        let seed_legit = [0x33u8; 32];
        let (pub_legit, tw_legit, sig_legit) = build_enrollment(&seed_legit, "node-c:443");
        assert_eq!(
            reg.authenticate(
                "node-c:443",
                &pub_legit,
                tw_legit,
                &sig_legit,
                &TEST_SERVER_EPH,
                &TEST_CLIENT_EPH
            ),
            NodeAuthOutcome::BoundNew
        );

        let seed_impostor = [0x44u8; 32];
        let (pub_impostor, tw_impostor, sig_impostor) =
            build_enrollment(&seed_impostor, "node-c:443");
        let outcome = reg.authenticate(
            "node-c:443",
            &pub_impostor,
            tw_impostor,
            &sig_impostor,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        assert_eq!(
            outcome,
            NodeAuthOutcome::Rejected("node_pub mismatch — impostor or key rotation")
        );

        // The original binding must be untouched.
        let legit_recheck = reg.authenticate(
            "node-c:443",
            &pub_legit,
            tw_legit,
            &sig_legit,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        assert_eq!(legit_recheck, NodeAuthOutcome::Verified);
    }

    #[test]
    fn rejects_bad_signature() {
        let dir = tempfile::tempdir().unwrap();
        let reg = NodeRegistry::load(registry_path(&dir), true);
        let seed = [0x55u8; 32];
        let (node_pub, time_window, mut signature) = build_enrollment(&seed, "node-d:443");
        signature[0] ^= 0xFF; // tamper

        let outcome = reg.authenticate(
            "node-d:443",
            &node_pub,
            time_window,
            &signature,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        assert_eq!(outcome, NodeAuthOutcome::Rejected("bad signature"));
    }

    #[test]
    fn rejects_stale_time_window() {
        let dir = tempfile::tempdir().unwrap();
        let reg = NodeRegistry::load(registry_path(&dir), true);
        let seed = [0x66u8; 32];
        let signing_key = crypto::node_identity_from_seed(&seed);
        let node_pub = signing_key.verifying_key().to_bytes();
        let cur =
            crypto::compute_time_window(crypto::current_timestamp_ms(), NODE_ENROLL_WINDOW_MS);
        let stale_window = cur.saturating_sub(10);
        let msg = crypto::node_enrollment_signing_bytes(
            "node-e:443",
            &node_pub,
            stale_window,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        let signature = {
            use ed25519_dalek::Signer;
            signing_key.sign(&msg).to_bytes()
        };

        let outcome = reg.authenticate(
            "node-e:443",
            &node_pub,
            stale_window,
            &signature,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        assert_eq!(outcome, NodeAuthOutcome::Rejected("stale enrollment"));
    }

    #[test]
    fn revoke_removes_binding() {
        let dir = tempfile::tempdir().unwrap();
        let reg = NodeRegistry::load(registry_path(&dir), true);
        let seed = [0x77u8; 32];
        let (node_pub, time_window, signature) = build_enrollment(&seed, "node-f:443");
        assert_eq!(
            reg.authenticate(
                "node-f:443",
                &node_pub,
                time_window,
                &signature,
                &TEST_SERVER_EPH,
                &TEST_CLIENT_EPH
            ),
            NodeAuthOutcome::BoundNew
        );
        assert_eq!(reg.list().len(), 1);

        assert!(reg.revoke("node-f:443"));
        assert!(reg.list().is_empty());
        assert!(!reg.revoke("node-f:443")); // already gone
    }

    #[test]
    fn list_is_sorted_by_node_id() {
        let dir = tempfile::tempdir().unwrap();
        let reg = NodeRegistry::load(registry_path(&dir), true);
        for id in ["zeta:443", "alpha:443", "mid:443"] {
            let seed = blake3::hash(id.as_bytes());
            let seed_bytes: [u8; 32] = *seed.as_bytes();
            let (node_pub, time_window, signature) = build_enrollment(&seed_bytes, id);
            reg.authenticate(
                id,
                &node_pub,
                time_window,
                &signature,
                &TEST_SERVER_EPH,
                &TEST_CLIENT_EPH,
            );
        }
        let ids: Vec<String> = reg.list().into_iter().map(|(id, _)| id).collect();
        assert_eq!(ids, vec!["alpha:443", "mid:443", "zeta:443"]);
    }

    #[test]
    fn persists_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = registry_path(&dir);
        let seed = [0x88u8; 32];
        let (node_pub, time_window, signature) = build_enrollment(&seed, "node-g:443");
        {
            let reg = NodeRegistry::load(path.clone(), true);
            assert_eq!(
                reg.authenticate(
                    "node-g:443",
                    &node_pub,
                    time_window,
                    &signature,
                    &TEST_SERVER_EPH,
                    &TEST_CLIENT_EPH
                ),
                NodeAuthOutcome::BoundNew
            );
        }

        let reloaded = NodeRegistry::load(path, true);
        assert_eq!(reloaded.list(), vec![("node-g:443".to_string(), node_pub)]);
    }

    /// D3 regression test: revoking a node must make the revocation stick
    /// even against a re-enrollment with the SAME valid key and signature —
    /// before the fix, `revoke` only removed the binding, so this next
    /// `authenticate` call would return `BoundNew` again via TOFU.
    #[test]
    fn revoke_blocks_reenrollment_even_with_valid_signature() {
        let dir = tempfile::tempdir().unwrap();
        let reg = NodeRegistry::load(registry_path(&dir), true);
        let seed = [0x99u8; 32];
        let (node_pub, time_window, signature) = build_enrollment(&seed, "node-h:443");
        assert_eq!(
            reg.authenticate(
                "node-h:443",
                &node_pub,
                time_window,
                &signature,
                &TEST_SERVER_EPH,
                &TEST_CLIENT_EPH
            ),
            NodeAuthOutcome::BoundNew
        );

        assert!(reg.revoke("node-h:443"));
        assert!(reg.list().is_empty());

        let (node_pub2, time_window2, signature2) = build_enrollment(&seed, "node-h:443");
        let outcome = reg.authenticate(
            "node-h:443",
            &node_pub2,
            time_window2,
            &signature2,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        assert_eq!(
            outcome,
            NodeAuthOutcome::Rejected("revoked node — re-approval required")
        );
        assert!(reg.list().is_empty());
        assert_eq!(reg.list_revoked(), vec!["node-h:443".to_string()]);
    }

    #[test]
    fn unrevoke_allows_rebinding() {
        let dir = tempfile::tempdir().unwrap();
        let reg = NodeRegistry::load(registry_path(&dir), true);
        let seed = [0xaau8; 32];
        let (node_pub, time_window, signature) = build_enrollment(&seed, "node-i:443");
        assert_eq!(
            reg.authenticate(
                "node-i:443",
                &node_pub,
                time_window,
                &signature,
                &TEST_SERVER_EPH,
                &TEST_CLIENT_EPH
            ),
            NodeAuthOutcome::BoundNew
        );
        assert!(reg.revoke("node-i:443"));

        let (node_pub2, time_window2, signature2) = build_enrollment(&seed, "node-i:443");
        assert_eq!(
            reg.authenticate(
                "node-i:443",
                &node_pub2,
                time_window2,
                &signature2,
                &TEST_SERVER_EPH,
                &TEST_CLIENT_EPH
            ),
            NodeAuthOutcome::Rejected("revoked node — re-approval required")
        );

        assert!(reg.unrevoke("node-i:443"));
        assert!(!reg.unrevoke("node-i:443")); // already gone
        assert!(reg.list_revoked().is_empty());

        let (node_pub3, time_window3, signature3) = build_enrollment(&seed, "node-i:443");
        assert_eq!(
            reg.authenticate(
                "node-i:443",
                &node_pub3,
                time_window3,
                &signature3,
                &TEST_SERVER_EPH,
                &TEST_CLIENT_EPH
            ),
            NodeAuthOutcome::BoundNew
        );
        assert_eq!(reg.list().len(), 1);
    }

    /// Load-compat regression test: a `pool_nodes.json` written before this
    /// module gained durable revocation (flat `{node_id: pubkey}` shape)
    /// must still load correctly, and persisting from a legacy-loaded
    /// registry must upgrade the on-disk shape without losing data.
    #[test]
    fn legacy_flat_format_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = registry_path(&dir);
        let seed = [0xbbu8; 32];
        let signing_key = crypto::node_identity_from_seed(&seed);
        let node_pub = signing_key.verifying_key().to_bytes();
        let b64 = base64::engine::general_purpose::STANDARD.encode(node_pub);
        let legacy_json = format!("{{\"node-j:443\": \"{}\"}}", b64);
        std::fs::write(&path, legacy_json).unwrap();

        let reg = NodeRegistry::load(path.clone(), true);
        assert_eq!(reg.list(), vec![("node-j:443".to_string(), node_pub)]);
        assert!(reg.list_revoked().is_empty());

        // Re-authenticating against the legacy-loaded binding must Verify,
        // not re-bind.
        let time_window =
            crypto::compute_time_window(crypto::current_timestamp_ms(), NODE_ENROLL_WINDOW_MS);
        let msg = crypto::node_enrollment_signing_bytes(
            "node-j:443",
            &node_pub,
            time_window,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        let signature = {
            use ed25519_dalek::Signer;
            signing_key.sign(&msg).to_bytes()
        };
        assert_eq!(
            reg.authenticate(
                "node-j:443",
                &node_pub,
                time_window,
                &signature,
                &TEST_SERVER_EPH,
                &TEST_CLIENT_EPH
            ),
            NodeAuthOutcome::Verified
        );

        // Persisting from a legacy-loaded registry (structured-form
        // upgrade) must still reload correctly, including the revoked set.
        assert!(reg.revoke("node-j:443"));
        let reloaded = NodeRegistry::load(path, true);
        assert!(reloaded.list().is_empty());
        assert_eq!(reloaded.list_revoked(), vec!["node-j:443".to_string()]);
    }

    #[test]
    fn revoked_set_persists_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = registry_path(&dir);
        let seed = [0xccu8; 32];
        let (node_pub, time_window, signature) = build_enrollment(&seed, "node-k:443");
        {
            let reg = NodeRegistry::load(path.clone(), true);
            assert_eq!(
                reg.authenticate(
                    "node-k:443",
                    &node_pub,
                    time_window,
                    &signature,
                    &TEST_SERVER_EPH,
                    &TEST_CLIENT_EPH
                ),
                NodeAuthOutcome::BoundNew
            );
            assert!(reg.revoke("node-k:443"));
        }

        let reloaded = NodeRegistry::load(path, true);
        assert!(reloaded.list().is_empty());
        assert_eq!(reloaded.list_revoked(), vec!["node-k:443".to_string()]);

        // The revocation must still block re-enrollment after reload.
        let (node_pub2, time_window2, signature2) = build_enrollment(&seed, "node-k:443");
        assert_eq!(
            reloaded.authenticate(
                "node-k:443",
                &node_pub2,
                time_window2,
                &signature2,
                &TEST_SERVER_EPH,
                &TEST_CLIENT_EPH
            ),
            NodeAuthOutcome::Rejected("revoked node — re-approval required")
        );
    }

    /// B2/D2 regression test: `authenticate` must reject a captured, otherwise
    /// valid enrollment tuple when it is replayed with a DIFFERENT session
    /// transcript — the cross-peer replay this fix closes. Before the fix,
    /// `authenticate` had no transcript parameters at all, so this exact
    /// tuple would have verified (and TOFU-bound) identically on any session.
    #[test]
    fn authenticate_rejects_cross_session_replay() {
        let dir = tempfile::tempdir().unwrap();
        let reg = NodeRegistry::load(registry_path(&dir), true);
        let seed = [0xddu8; 32];
        let (node_pub, time_window, signature) = build_enrollment(&seed, "node-l:443");

        // Binds fine under the transcript it was actually signed for.
        assert_eq!(
            reg.authenticate(
                "node-l:443",
                &node_pub,
                time_window,
                &signature,
                &TEST_SERVER_EPH,
                &TEST_CLIENT_EPH
            ),
            NodeAuthOutcome::BoundNew
        );

        // A fresh registry (simulating a different, un-bound session's
        // peer) must reject the exact same tuple when the caller supplies a
        // different session transcript.
        let other_server_eph = [0xE5u8; 32];
        let other_client_eph = [0xE6u8; 32];
        let dir2 = tempfile::tempdir().unwrap();
        let reg2 = NodeRegistry::load(registry_path(&dir2), true);
        assert_eq!(
            reg2.authenticate(
                "node-l:443",
                &node_pub,
                time_window,
                &signature,
                &other_server_eph,
                &other_client_eph
            ),
            NodeAuthOutcome::Rejected("bad signature")
        );
        assert!(
            reg2.list().is_empty(),
            "a cross-session-replayed proof must never TOFU-bind"
        );
    }

    /// D5 regression test: concurrent TOFU binds in the same process must
    /// not collide on the persist-temp-file name. Before the fix, the temp
    /// path was named only `{path}.{pid}.tmp`, so two concurrent `persist()`
    /// calls from different threads could race on the same temp file and
    /// corrupt state or fail the rename.
    #[test]
    fn concurrent_binds_do_not_collide_on_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = registry_path(&dir);
        let reg = std::sync::Arc::new(NodeRegistry::load(path.clone(), true));

        let handles: Vec<_> = (0..8u8)
            .map(|i| {
                let reg = reg.clone();
                std::thread::spawn(move || {
                    let seed = [i; 32];
                    let node_id = format!("node-concurrent-{}:443", i);
                    let (node_pub, time_window, signature) = build_enrollment(&seed, &node_id);
                    reg.authenticate(
                        &node_id,
                        &node_pub,
                        time_window,
                        &signature,
                        &TEST_SERVER_EPH,
                        &TEST_CLIENT_EPH,
                    )
                })
            })
            .collect();

        for h in handles {
            assert_eq!(h.join().unwrap(), NodeAuthOutcome::BoundNew);
        }

        assert_eq!(reg.list().len(), 8);
        let reloaded = NodeRegistry::load(path, true);
        assert_eq!(reloaded.list().len(), 8);
    }
}
