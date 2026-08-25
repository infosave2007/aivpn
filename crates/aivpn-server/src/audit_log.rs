//! Append-only admin audit log.
//!
//! Each administrative action is recorded as a JSON line in the audit log path.
//! Rotation is handled externally via logrotate.
//!
//! ## Hash chain (tamper evidence)
//!
//! Every entry carries `prev_hash` (the previous entry's `hash`, hex) and
//! `hash` (hex SHA-256 over this entry's own fields, canonically joined as
//! `ts|actor|action|target|result|prev_hash`, EXCLUDING `hash` itself but
//! INCLUDING `prev_hash`). The very first entry ever written by a given
//! [`AuditLogger`] chains onto [`GENESIS_HASH`] (64 hex zero chars) rather
//! than a prior entry's hash.
//!
//! This makes the log tamper-EVIDENT, not tamper-PROOF: a node with write
//! access to the log file can always truncate it and start a fresh chain,
//! or rewrite the whole file with a self-consistent forged chain. What the
//! chain protects against is a *partial*, *silent* edit — flipping one
//! field of one historical entry without recomputing every hash after it —
//! which [`verify_chain`] detects. Full tamper-proofing would require an
//! external anchor (e.g. periodically publishing the tip hash somewhere the
//! node itself can't rewrite), which is out of scope here.
//!
//! Old log lines written before this field existed deserialize fine
//! (`#[serde(default)]` gives them `prev_hash == "" ` and `hash == ""`);
//! [`AuditLogger::new`] treats such a line as if the file were empty when
//! seeding the in-memory chain tip, so the FIRST post-upgrade entry chains
//! onto [`GENESIS_HASH`] again rather than an empty string — i.e. upgrading
//! a live log starts a fresh, independently-verifiable chain segment rather
//! than silently linking onto un-hashed history.
//!
//! ## Pool note
//!
//! Audit logs are **never** merged across pool nodes. Each node keeps its
//! own local, independently-chained audit log; pool anti-entropy sync
//! (`pool_sync.rs`) only ever touches the client database, never
//! `audit_log_path`. A hash chain that spanned nodes would need a total
//! order across independently-writing peers (a distributed log), which
//! this file deliberately does not attempt — verifying node A's chain only
//! proves node A's own history wasn't silently edited, nothing about node
//! B.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditActor {
    Cli,
    Api,
    System,
}

impl AuditActor {
    /// Stable string form used as one field of the hash-chain's canonical
    /// join — kept independent of `#[serde(rename_all)]` so a future serde
    /// attribute change on this enum can never silently change what
    /// existing chain hashes were computed over.
    fn as_str(&self) -> &'static str {
        match self {
            AuditActor::Cli => "cli",
            AuditActor::Api => "api",
            AuditActor::System => "system",
        }
    }
}

/// `prev_hash` of the very first entry in a chain: hex of 32 zero bytes.
/// Chosen (over an empty-string sentinel) so it's visually distinct from
/// the backward-compat "no hash chain" default (`""`) that old,
/// pre-hash-chain log lines deserialize to.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// `GENESIS_HASH` above is intentionally verified by a test to be exactly
// 64 hex chars (SHA-256 output width) — see `genesis_hash_is_64_hex_zeros`.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: String,
    pub actor: AuditActor,
    pub action: String,
    pub target: String,
    pub result: String,
    /// Hex hash of the previous entry in this node's chain (or
    /// [`GENESIS_HASH`] for the first entry). Defaults to `""` so log lines
    /// written before this field existed still deserialize.
    #[serde(default)]
    pub prev_hash: String,
    /// Hex SHA-256 over this entry's own fields (see module doc). Defaults
    /// to `""` for the same backward-compat reason as `prev_hash`.
    #[serde(default)]
    pub hash: String,
}

/// Canonical join of an entry's fields used as the hash-chain input.
/// `|`-separated; excludes `hash` itself, includes `prev_hash`.
fn canonical_join(
    ts: &str,
    actor: &AuditActor,
    action: &str,
    target: &str,
    result: &str,
    prev_hash: &str,
) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        ts,
        actor.as_str(),
        action,
        target,
        result,
        prev_hash
    )
}

fn compute_hash(
    ts: &str,
    actor: &AuditActor,
    action: &str,
    target: &str,
    result: &str,
    prev_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_join(ts, actor, action, target, result, prev_hash).as_bytes());
    hex::encode(hasher.finalize())
}

/// Verify the hash chain of a (possibly windowed/tail-read) sequence of
/// entries, oldest first. Returns `Err(index)` for the first entry `i`
/// such that either:
/// - its recomputed hash (over its own `ts/actor/action/target/result` and
///   its OWN stored `prev_hash`) doesn't match its stored `hash` (a
///   self-consistency break — the entry's body was edited without
///   recomputing its hash), or
/// - (for `i > 0`) its `prev_hash` doesn't equal `entries[i-1].hash` (a
///   linkage break — an entry between them was removed/reordered, or the
///   neighbor's hash was recomputed without updating this `prev_hash`).
///
/// Note this does NOT require `entries[0].prev_hash == GENESIS_HASH`: the
/// slice may be a bounded tail read (see `audit_tail`/`audit_verify`) that
/// doesn't start at the true beginning of the log, in which case
/// `entries[0]` is trusted as the verified window's root and only its own
/// self-consistency is checked. A caller that read the FULL log from the
/// start can additionally assert `entries[0].prev_hash == GENESIS_HASH` to
/// confirm the window really is the whole chain.
pub fn verify_chain(entries: &[AuditEntry]) -> Result<(), usize> {
    for (i, e) in entries.iter().enumerate() {
        if i > 0 && e.prev_hash != entries[i - 1].hash {
            return Err(i);
        }
        let expected = compute_hash(
            &e.ts,
            &e.actor,
            &e.action,
            &e.target,
            &e.result,
            &e.prev_hash,
        );
        if e.hash != expected {
            return Err(i);
        }
    }
    Ok(())
}

/// Thread-safe append-only audit logger.
#[derive(Clone)]
pub struct AuditLogger {
    inner: Arc<Mutex<AuditLoggerInner>>,
}

struct AuditLoggerInner {
    path: PathBuf,
    /// Hash of the last entry successfully written to `path`, or
    /// [`GENESIS_HASH`] if none has been written yet (fresh/empty file, or
    /// the existing last line predates the hash-chain field and so has no
    /// usable hash — see the module doc's "upgrading a live log" note).
    /// Cached here so `log()` never has to re-read the file to find the
    /// chain tip.
    last_hash: String,
}

/// Read the hash of the last JSON line in `path`, or [`GENESIS_HASH`] if
/// the file doesn't exist, is empty, its last line fails to parse, or that
/// line predates the hash-chain fields (empty `hash`). Called once, at
/// [`AuditLogger::new`].
fn read_last_hash(path: &Path) -> String {
    if path == Path::new("/dev/null") {
        return GENESIS_HASH.to_string();
    }
    let Ok(content) = std::fs::read_to_string(path) else {
        return GENESIS_HASH.to_string();
    };
    let last_line = content.lines().rev().find(|l| !l.trim().is_empty());
    match last_line.and_then(|l| serde_json::from_str::<AuditEntry>(l).ok()) {
        Some(entry) if !entry.hash.is_empty() => entry.hash,
        _ => GENESIS_HASH.to_string(),
    }
}

impl AuditLogger {
    pub fn new(path: &Path) -> Self {
        // `disabled()` points this at `/dev/null`, whose parent is the
        // system `/dev` directory — never touch permissions in that case
        // (chmod-ing a system directory would be catastrophic). Only harden
        // permissions for a real, operator-configured audit log path.
        let is_disabled_sentinel = path == Path::new("/dev/null");
        if let Some(dir) = path.parent() {
            let created = !dir.exists();
            let _ = std::fs::create_dir_all(dir);
            // MEDIUM (server-sec): harden the audit log directory — it
            // previously inherited the process umask (commonly world-
            // readable under root). Only chmod a directory THIS call
            // created (or the log file's own directory when it already
            // exists but isn't a system path), never an arbitrary
            // pre-existing directory that might be shared with unrelated
            // files. The file itself is hardened in `log()`.
            #[cfg(unix)]
            if !is_disabled_sentinel && created {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        let last_hash = read_last_hash(path);
        Self {
            inner: Arc::new(Mutex::new(AuditLoggerInner {
                path: path.to_path_buf(),
                last_hash,
            })),
        }
    }

    pub fn disabled() -> Self {
        Self::new(Path::new("/dev/null"))
    }

    pub fn log(&self, actor: AuditActor, action: &str, target: &str, result: &str) {
        let mut inner = self.inner.lock().unwrap();
        let ts = Utc::now().to_rfc3339();
        let prev_hash = inner.last_hash.clone();
        let hash = compute_hash(&ts, &actor, action, target, result, &prev_hash);
        let entry = AuditEntry {
            ts,
            actor,
            action: action.to_string(),
            target: target.to_string(),
            result: result.to_string(),
            prev_hash,
            hash: hash.clone(),
        };
        let line = match serde_json::to_string(&entry) {
            Ok(s) => s,
            Err(e) => {
                warn!("audit_log serialize: {}", e);
                return;
            }
        };
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&inner.path)
        {
            Ok(mut f) => {
                // MEDIUM (server-sec): audit entries can include admin
                // actions and target identifiers; harden the file's
                // permissions rather than inheriting the process umask
                // (commonly world-readable under root). Cheap relative to
                // admin-action call volume — set on every append rather
                // than tracking "did we just create it" so an operator who
                // manually loosens permissions gets them re-hardened on the
                // next audit event too. NEVER touch `/dev/null` itself
                // (the `disabled()` sentinel) — chmod-ing a shared system
                // device node would be catastrophic for every other
                // process/user on the host.
                #[cfg(unix)]
                if inner.path != Path::new("/dev/null") {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
                }
                match writeln!(f, "{}", line) {
                    Ok(()) => {
                        // Only advance the in-memory chain tip once the
                        // entry actually landed on disk — otherwise a
                        // write failure here would desync `last_hash` from
                        // what's really the last entry on disk, breaking
                        // every subsequent `prev_hash` link.
                        inner.last_hash = hash;
                    }
                    Err(e) => {
                        warn!("audit_log write {:?}: {}", inner.path, e);
                        eprintln!(
                            "AUDIT LOG WRITE FAILED ({:?}): {} — entry lost: {}",
                            inner.path, e, line
                        );
                    }
                }
            }
            Err(e) => {
                // MEDIUM (server-sec): audit logging fails open by design
                // (an admin action must not be blocked by a logging
                // outage), but that must never be SILENT. `warn!` alone can
                // be filtered out entirely by the tracing subscriber's
                // level/module config, making a persistent audit-write
                // failure invisible; eprintln! guarantees an operator
                // watching stderr sees it regardless of log configuration.
                warn!("audit_log write {:?}: {}", inner.path, e);
                eprintln!(
                    "AUDIT LOG WRITE FAILED ({:?}): {} — entry lost: {}",
                    inner.path, e, line
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_entries(path: &Path) -> Vec<AuditEntry> {
        let content = std::fs::read_to_string(path).unwrap();
        content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn genesis_hash_is_64_hex_zeros() {
        assert_eq!(GENESIS_HASH.len(), 64);
        assert!(GENESIS_HASH.chars().all(|c| c == '0'));
    }

    #[test]
    fn appended_entries_chain_prev_hash_to_previous_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(&path);

        logger.log(AuditActor::Api, "ClientAdd", "alice", "ok");
        logger.log(AuditActor::Api, "ClientAdd", "bob", "ok");
        logger.log(AuditActor::Cli, "ClientRemove", "alice", "ok");

        let entries = read_entries(&path);
        assert_eq!(entries.len(), 3);

        // Genesis: first entry chains onto the sentinel, not a real hash.
        assert_eq!(entries[0].prev_hash, GENESIS_HASH);
        assert!(!entries[0].hash.is_empty());

        // Each subsequent entry's prev_hash == previous entry's hash.
        assert_eq!(entries[1].prev_hash, entries[0].hash);
        assert_eq!(entries[2].prev_hash, entries[1].hash);

        // Every entry's own hash is internally consistent.
        for e in &entries {
            let expected = compute_hash(
                &e.ts,
                &e.actor,
                &e.action,
                &e.target,
                &e.result,
                &e.prev_hash,
            );
            assert_eq!(e.hash, expected);
        }
    }

    #[test]
    fn verify_chain_ok_for_untampered_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(&path);
        logger.log(AuditActor::Api, "ClientAdd", "alice", "ok");
        logger.log(AuditActor::Api, "ClientAdd", "bob", "ok");
        logger.log(AuditActor::Cli, "ClientRemove", "alice", "ok");

        let entries = read_entries(&path);
        assert_eq!(verify_chain(&entries), Ok(()));
    }

    /// Mutating `entries[1].target` without recomputing its hash breaks
    /// SELF-consistency of entry 1 first (its stored `hash` was computed
    /// over the original `target`) — `verify_chain` catches this at index
    /// 1, before it ever gets to checking whether entry 2's `prev_hash`
    /// still points at (the now-stale) entry 1 hash. Documented here as
    /// the specific index this implementation yields.
    #[test]
    fn verify_chain_detects_tampering_at_the_tampered_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(&path);
        logger.log(AuditActor::Api, "ClientAdd", "alice", "ok");
        logger.log(AuditActor::Api, "ClientAdd", "bob", "ok");
        logger.log(AuditActor::Cli, "ClientRemove", "alice", "ok");

        let mut entries = read_entries(&path);
        entries[1].target = "mallory".to_string();

        assert_eq!(verify_chain(&entries), Err(1));
    }

    #[test]
    fn backward_compat_line_without_hash_fields_deserializes() {
        let json = r#"{"ts":"2026-01-01T00:00:00Z","actor":"api","action":"ClientAdd","target":"alice","result":"ok"}"#;
        let entry: AuditEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.prev_hash, "");
        assert_eq!(entry.hash, "");
        assert_eq!(entry.target, "alice");
    }

    #[test]
    fn upgrading_a_log_without_hash_fields_starts_a_fresh_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        // Simulate a log file written by a pre-hash-chain build.
        std::fs::write(
            &path,
            r#"{"ts":"2026-01-01T00:00:00Z","actor":"api","action":"ClientAdd","target":"alice","result":"ok"}
"#,
        )
        .unwrap();

        let logger = AuditLogger::new(&path);
        logger.log(AuditActor::Api, "ClientAdd", "bob", "ok");

        let entries = read_entries(&path);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].prev_hash, GENESIS_HASH);
    }
}
