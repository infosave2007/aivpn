//! Append-only admin audit log.
//!
//! Each administrative action is recorded as a JSON line in the audit log path.
//! Rotation is handled externally via logrotate.
//!
//! ## Hash chain (tamper evidence)
//!
//! Every entry carries `prev_hash` (the previous entry's `hash`, hex) and
//! `hash` (SHA-256 полей с длиной каждого поля перед его байтами).
//! Версия 1 исключает неоднозначность разделителей; старые строки версии 0
//! проверяются в исходном формате с разделителем `|`.
//! Первая запись файла ссылается на
//! [`GENESIS_HASH`] (64 нуля). Последующие записи используют хеш последней
//! строки, включая записи других экземпляров журнала.
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
//! Старые строки без хеша читаются с пустыми `prev_hash` и `hash`.
//! После такой строки новая цепочка начинается с [`GENESIS_HASH`].
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

use std::io::{Read, Seek, SeekFrom, Write};
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
    /// Версия кодирования полей перед хешированием; 0 относится к старым строкам.
    #[serde(default)]
    pub hash_version: u8,
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

fn compute_hash_legacy(
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

// Длины полей входят в хеш: перенос разделителя между полями меняет подпись.
fn compute_hash(
    ts: &str,
    actor: &AuditActor,
    action: &str,
    target: &str,
    result: &str,
    prev_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"aivpn-audit-v1\0");
    for field in [ts, actor.as_str(), action, target, result, prev_hash] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
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
        let hash_fn = match e.hash_version {
            0 => compute_hash_legacy,
            1 => compute_hash,
            _ => return Err(i),
        };
        let expected = hash_fn(
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
}

/// Читаем последнюю строку под той же блокировкой, что защищает добавление.
/// Размер всего журнала не влияет на объем чтения при обычной длине записи.
fn read_last_hash(file: &mut std::fs::File) -> std::io::Result<String> {
    let length = file.metadata()?.len();
    let mut budget = 8192u64;
    loop {
        let start = length.saturating_sub(budget);
        file.seek(SeekFrom::Start(start))?;
        let mut bytes = Vec::new();
        file.take(length - start).read_to_end(&mut bytes)?;
        let terminated = bytes.last() == Some(&b'\n');
        let end = bytes
            .iter()
            .rposition(|byte| !byte.is_ascii_whitespace())
            .map_or(0, |index| index + 1);
        let bytes = &bytes[..end];
        let line_start = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map(|index| index + 1);
        if let Some(line_start) = line_start.or((start == 0).then_some(0)) {
            let line = &bytes[line_start..];
            if line.is_empty() {
                return Ok(GENESIS_HASH.to_owned());
            }
            let entry: AuditEntry = match serde_json::from_slice(line) {
                Ok(entry) => entry,
                Err(_) if !terminated => {
                    let valid_end = start + line_start as u64;
                    file.set_len(valid_end)?;
                    warn!(
                        bytes = length - valid_end,
                        "Удален оборванный хвост записи аудита"
                    );
                    return read_last_hash(file);
                }
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Повреждена последняя запись аудита",
                    ))
                }
            };
            if !terminated {
                file.write_all(b"\n")?;
            }
            return Ok(if entry.hash.is_empty() {
                GENESIS_HASH.to_owned()
            } else {
                entry.hash
            });
        }
        if budget >= 4 * 1024 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Последняя запись аудита превышает лимит",
            ));
        }
        budget *= 2;
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
        Self {
            inner: Arc::new(Mutex::new(AuditLoggerInner {
                path: path.to_path_buf(),
            })),
        }
    }

    pub fn disabled() -> Self {
        Self::new(Path::new("/dev/null"))
    }

    pub fn log(&self, actor: AuditActor, action: &str, target: &str, result: &str) {
        let inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        if inner.path == Path::new("/dev/null") {
            return;
        }
        let write = (|| -> std::io::Result<()> {
            let mut options = std::fs::OpenOptions::new();
            options.create(true).read(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
            }
            let mut file = options.open(&inner.path)?;
            if !file.metadata()?.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Журнал аудита должен быть обычным файлом",
                ));
            }
            file.lock()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            let ts = Utc::now().to_rfc3339();
            let prev_hash = read_last_hash(&mut file)?;
            let hash = compute_hash(&ts, &actor, action, target, result, &prev_hash);
            let entry = AuditEntry {
                ts,
                actor,
                action: action.to_owned(),
                target: target.to_owned(),
                result: result.to_owned(),
                prev_hash,
                hash,
                hash_version: 1,
            };
            let mut line = serde_json::to_vec(&entry).map_err(std::io::Error::other)?;
            line.push(b'\n');
            file.write_all(&line)
        })();
        if let Err(error) = write {
            warn!("audit_log write {:?}: {}", inner.path, error);
            eprintln!("AUDIT LOG WRITE FAILED ({:?}): {}", inner.path, error);
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
    fn incomplete_tail_recovers_without_stopping_future_audit_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(&path);
        logger.log(AuditActor::Api, "update", "alice", "ok");
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"ts\":")
            .unwrap();
        logger.log(AuditActor::Api, "update", "bob", "ok");
        let entries = read_entries(&path);
        assert_eq!(entries.len(), 2);
        assert_eq!(verify_chain(&entries), Ok(()));
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(file.metadata().unwrap().len() - 1).unwrap();
        logger.log(AuditActor::Api, "update", "carol", "ok");
        assert_eq!(read_entries(&path).len(), 3);
        assert_eq!(verify_chain(&read_entries(&path)), Ok(()));
    }

    #[test]
    fn complete_corrupt_record_is_preserved_and_hashless_history_is_not_verified() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, b"{broken}\n").unwrap();
        AuditLogger::new(&path).log(AuditActor::Api, "update", "alice", "ok");
        assert_eq!(std::fs::read(&path).unwrap(), b"{broken}\n");
        std::fs::write(
            &path,
            br#"{"ts":"old","actor":"api","action":"update","target":"alice","result":"ok"}
"#,
        )
        .unwrap();
        let logger = AuditLogger::new(&path);
        logger.log(AuditActor::Api, "update", "bob", "ok");
        assert_eq!(verify_chain(&read_entries(&path)), Err(0));
        assert_eq!(verify_chain(&read_entries(&path)[1..]), Ok(()));
    }

    #[test]
    fn field_delimiters_cannot_hide_a_changed_target() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        AuditLogger::new(&path).log(AuditActor::Api, "update", "alice|bob", "ok");
        let mut entries = read_entries(&path);
        entries[0].target = "alice".into();
        entries[0].result = "bob|ok".into();
        assert_eq!(verify_chain(&entries), Err(0));
    }

    #[test]
    fn legacy_entries_can_be_followed_by_unambiguous_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(&path);
        logger.log(AuditActor::Api, "update", "alice", "ok");
        let mut entries = read_entries(&path);
        let entry = &mut entries[0];
        entry.hash_version = 0;
        entry.hash = compute_hash_legacy(
            &entry.ts,
            &entry.actor,
            &entry.action,
            &entry.target,
            &entry.result,
            &entry.prev_hash,
        );
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string(entry).unwrap()),
        )
        .unwrap();
        logger.log(AuditActor::Api, "update", "bob", "ok");
        assert_eq!(verify_chain(&read_entries(&path)), Ok(()));
    }

    #[test]
    fn reading_the_tip_does_not_load_the_entire_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(&path);
        logger.log(AuditActor::Api, "first", "test", "ok");
        let entry = std::fs::read(&path).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.set_len(128 * 1024 * 1024).unwrap();
        file.seek(SeekFrom::End(0)).unwrap();
        file.write_all(b"\n").unwrap();
        file.write_all(&entry).unwrap();
        let last: AuditEntry = serde_json::from_slice(&entry).unwrap();
        assert_eq!(read_last_hash(&mut file).unwrap(), last.hash);
    }

    #[test]
    fn independent_writers_share_the_current_chain_tip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let first = AuditLogger::new(&path);
        let second = AuditLogger::new(&path);
        first.log(AuditActor::Api, "ClientAdd", "alice", "ok");
        second.log(AuditActor::Cli, "ClientAdd", "bob", "ok");
        first.log(AuditActor::Api, "ClientRemove", "alice", "ok");
        let entries = read_entries(&path);
        assert_eq!(entries.len(), 3);
        assert_eq!(verify_chain(&entries), Ok(()));
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
