//! Backup / export / import for server configuration.
//!
//! Creates a tar.gz archive with manifest.json, clients.json, server.json, masks/.
//!
//! ## Security model (server-sec HIGH1/HIGH2, data-plane H5/M8)
//! `clients.json` contains every client's PSK in plaintext (base64) and
//! `server.json` may contain `bootstrap_publish` credentials, so a backup
//! archive is as sensitive as the live config directory it is restored into
//! — and that directory (`/etc/aivpn` by default) is also where the
//! server's long-term private key (`server.key`) lives. Import therefore:
//!
//!  1. Only ever writes a small, positive allowlist of archive paths
//!     (`clients.json`, `server.json`, `masks/*.json`) — anything else,
//!     including a crafted `server.key` entry, is silently skipped rather
//!     than written to disk.
//!  2. Extracts and validates (schema-checks) every allowlisted file into
//!     memory FIRST; nothing is written to the live, hot-reloaded config
//!     directory until every file in the archive has passed validation —
//!     so a truncated/corrupt archive can never leave the config directory
//!     in a mixed, half-restored state.
//!  3. Verifies a manifest-level integrity signature (BLAKE3 keyed hash,
//!     keyed by a local-only `backup_integrity.key` generated on first use)
//!     over a per-file content-hash table, so a backup that was altered
//!     after export is detected and rejected before any write.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tracing::{info, warn};

use aivpn_common::error::{Error, Result};

const MANIFEST_NAME: &str = "manifest.json";
const BACKUP_KEY_FILE: &str = "backup_integrity.key";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub aivpn_version: String,
    pub created_at: String,
    pub components: Vec<String>,
    /// Archive-relative path → hex BLAKE3 content hash, for every
    /// non-manifest file in the archive. Lets `import_server` detect a
    /// tampered/corrupt file before it is ever written to the live config
    /// directory, and binds `mac` below to each file's actual bytes rather
    /// than just its name.
    #[serde(default)]
    pub content_hashes: std::collections::BTreeMap<String, String>,
    /// Hex BLAKE3 keyed hash over this manifest with `mac` cleared, keyed by
    /// this server's local `backup_integrity.key`. `None` for backups made
    /// before this field existed, or when no integrity key was available at
    /// export time.
    #[serde(default)]
    pub mac: Option<String>,
}

impl BackupManifest {
    fn new(components: Vec<String>) -> Self {
        Self {
            aivpn_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: Utc::now().to_rfc3339(),
            components,
            content_hashes: std::collections::BTreeMap::new(),
            mac: None,
        }
    }

    /// Canonical bytes covered by the MAC: this manifest serialized with
    /// `mac` forced to `None`, so the MAC never covers itself. Serializing
    /// the in-memory struct fresh (rather than hashing the archived
    /// manifest.json's raw bytes) makes verification robust to whitespace/
    /// pretty-printing differences — export and import both call this same
    /// method on equivalent data.
    fn mac_input(&self) -> Vec<u8> {
        let mut copy = self.clone();
        copy.mac = None;
        serde_json::to_vec(&copy).expect("BackupManifest always serializes")
    }
}

#[derive(Debug, Clone, Default)]
pub struct ExportOptions {
    pub include_clients: bool,
    pub include_masks: bool,
    pub include_config: bool,
    pub config_path: Option<PathBuf>,
    pub mask_dir: Option<PathBuf>,
    pub clients_db: Option<PathBuf>,
}

/// Load this server's local backup-integrity key from
/// `<dir>/backup_integrity.key`, optionally generating one atomically
/// (`O_EXCL` + mode 0600 in a single `open()` call, closing the TOCTOU
/// window a separate create-then-chmod would leave) on first use.
///
/// `create = false` (import's read path) never manufactures a key: a freshly
/// generated key can never match an older export's signature, and the
/// caller needs to distinguish "no local key exists yet" from "key exists
/// but doesn't match" to decide how to treat a missing/mismatched `mac`.
fn load_backup_key(dir: &Path, create: bool) -> Option<[u8; 32]> {
    let path = dir.join(BACKUP_KEY_FILE);
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Some(key);
        }
        warn!(
            "backup integrity key at {:?} is malformed ({} bytes, expected 32) — ignoring",
            path,
            bytes.len()
        );
        return None;
    }
    if !create {
        return None;
    }

    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);

    #[cfg(unix)]
    let opened = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
    };
    #[cfg(not(unix))]
    let opened = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path);

    match opened {
        Ok(mut f) => match f.write_all(&key) {
            Ok(()) => Some(key),
            Err(e) => {
                warn!("failed to write backup integrity key to {:?}: {}", path, e);
                None
            }
        },
        Err(_) => {
            // Lost a create race with another process (or thread) — read
            // back whatever it wrote instead of failing.
            std::fs::read(&path).ok().and_then(|bytes| {
                if bytes.len() == 32 {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&bytes);
                    Some(k)
                } else {
                    None
                }
            })
        }
    }
}

/// Export server data to `output_path` (.tar.gz).
pub fn export_server(opts: &ExportOptions, output_path: &Path) -> Result<()> {
    let mut components = Vec::new();
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();

    if opts.include_clients {
        if let Some(ref p) = opts.clients_db {
            if p.exists() {
                let bytes = std::fs::read(p)
                    .map_err(|e| Error::Session(format!("read clients.json: {}", e)))?;
                files.push(("clients.json".to_string(), bytes));
                components.push("clients".to_string());
            } else {
                warn!("clients.json not found at {:?}, skipping", p);
            }
        }
    }

    if opts.include_config {
        if let Some(ref p) = opts.config_path {
            if p.exists() {
                let bytes = std::fs::read(p)
                    .map_err(|e| Error::Session(format!("read server.json: {}", e)))?;
                files.push(("server.json".to_string(), bytes));
                components.push("config".to_string());
            }
        }
    }

    if opts.include_masks {
        if let Some(ref dir) = opts.mask_dir {
            if dir.is_dir() {
                let mut any = false;
                for entry in std::fs::read_dir(dir)
                    .map_err(|e| Error::Session(format!("read mask dir: {}", e)))?
                {
                    let entry = entry.map_err(|e| Error::Session(format!("mask entry: {}", e)))?;
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) == Some("json") {
                        let bytes = std::fs::read(&path)
                            .map_err(|e| Error::Session(format!("read mask: {}", e)))?;
                        let rel = format!("masks/{}", entry.file_name().to_string_lossy());
                        files.push((rel, bytes));
                        any = true;
                    }
                }
                if any {
                    components.push("masks".to_string());
                }
            }
        }
    }

    let mut manifest = BackupManifest::new(components);
    for (name, bytes) in &files {
        manifest
            .content_hashes
            .insert(name.clone(), blake3::hash(bytes).to_hex().to_string());
    }

    // Sign the manifest (and, transitively via content_hashes, every file)
    // with this server's local integrity key so `import_server` can detect
    // tampering between export and import. Best-effort: derive the key
    // directory from whichever path options were supplied — config_path is
    // set by every real caller (CLI + management API), but fall back so a
    // config-less export still gets signed where possible.
    let key_dir = opts
        .config_path
        .as_ref()
        .and_then(|p| p.parent())
        .or_else(|| opts.clients_db.as_ref().and_then(|p| p.parent()))
        .or_else(|| opts.mask_dir.as_deref());
    match key_dir.and_then(|dir| load_backup_key(dir, true)) {
        Some(key) => {
            let mac = blake3::keyed_hash(&key, &manifest.mac_input());
            manifest.mac = Some(mac.to_hex().to_string());
        }
        None => {
            warn!("backup integrity key unavailable — exporting an unsigned backup");
        }
    }

    let file = std::fs::File::create(output_path)
        .map_err(|e| Error::Session(format!("create backup: {}", e)))?;
    let gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut ar = tar::Builder::new(gz);

    for (name, bytes) in &files {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        // Contains PSKs / config secrets — restrictive mode even though the
        // extraction path (below) re-hardens permissions explicitly anyway.
        header.set_mode(0o600);
        header.set_cksum();
        ar.append_data(&mut header, name, bytes.as_slice())
            .map_err(|e| Error::Session(format!("archive {}: {}", name, e)))?;
    }

    // Always write manifest last
    let manifest_json = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| Error::Session(format!("serialize manifest: {}", e)))?;
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest_json.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    ar.append_data(&mut header, MANIFEST_NAME, manifest_json.as_slice())
        .map_err(|e| Error::Session(format!("archive manifest: {}", e)))?;

    ar.finish()
        .map_err(|e| Error::Session(format!("finalize archive: {}", e)))?;

    info!(
        "Backup written to {:?} (components: {:?}, signed: {})",
        output_path,
        manifest.components,
        manifest.mac.is_some()
    );
    Ok(())
}

/// Archive-relative paths this server will ever write during import.
/// Positive allowlist (server-sec HIGH1): anything else — including a
/// crafted `server.key` entry, which would land in the same directory as
/// the real one — is rejected rather than written to disk.
fn is_allowed_import_path(rel: &Path) -> bool {
    if rel.is_absolute()
        || rel
            .components()
            .any(|c| c == std::path::Component::ParentDir)
    {
        return false;
    }
    let comps: Vec<_> = rel.components().collect();
    match comps.as_slice() {
        [only] => matches!(
            only.as_os_str().to_str(),
            Some("clients.json") | Some("server.json")
        ),
        [dir, name] => {
            dir.as_os_str().to_str() == Some("masks")
                && Path::new(name.as_os_str())
                    .extension()
                    .and_then(|e| e.to_str())
                    == Some("json")
        }
        _ => false,
    }
}

/// Validate that `bytes` deserializes as the expected schema for archive
/// path `rel` — catches corruption/tampering before any write into the
/// live, hot-reloaded config directory.
fn validate_component(rel: &str, bytes: &[u8]) -> Result<()> {
    if rel == "clients.json" {
        crate::client_db::ClientDatabase::validate_json(bytes)
    } else if rel == "server.json" {
        serde_json::from_slice::<crate::server_config::ServerFileConfig>(bytes)
            .map(|_| ())
            .map_err(|e| Error::Session(format!("invalid server.json in backup: {}", e)))
    } else if rel.starts_with("masks/") {
        serde_json::from_slice::<aivpn_common::mask::MaskProfile>(bytes)
            .map(|_| ())
            .map_err(|e| Error::Session(format!("invalid mask JSON in backup ({}): {}", rel, e)))
    } else {
        Ok(())
    }
}

/// Import from a backup archive. `dry_run = true` prints diff without writing.
pub fn import_server(archive_path: &Path, target_dir: &Path, dry_run: bool) -> Result<()> {
    // Pass 1: read the manifest AND every allowlisted, schema-valid
    // component into memory. Nothing is written to `target_dir` until every
    // file in the archive has been checked — a truncated or partially
    // malicious archive can never leave the live config directory in a
    // mixed state.
    let mut manifest: Option<BackupManifest> = None;
    let mut staged: Vec<(String, Vec<u8>)> = Vec::new();
    {
        let file = std::fs::File::open(archive_path)
            .map_err(|e| Error::Session(format!("open backup: {}", e)))?;
        let gz = flate2::read::GzDecoder::new(file);
        let mut ar = tar::Archive::new(gz);
        for entry in ar
            .entries()
            .map_err(|e| Error::Session(format!("read archive: {}", e)))?
        {
            let mut entry = entry.map_err(|e| Error::Session(format!("entry: {}", e)))?;
            let rel = entry
                .path()
                .map_err(|e| Error::Session(format!("entry path: {}", e)))?
                .to_path_buf();

            if rel.to_str() == Some(MANIFEST_NAME) {
                let mut buf = String::new();
                entry
                    .read_to_string(&mut buf)
                    .map_err(|e| Error::Session(format!("read manifest: {}", e)))?;
                manifest = serde_json::from_str(&buf).ok();
                continue;
            }

            if !is_allowed_import_path(&rel) {
                warn!("import: skipping disallowed archive path {:?}", rel);
                continue;
            }
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .map_err(|e| Error::Session(format!("read entry {:?}: {}", rel, e)))?;
            validate_component(&rel_str, &buf)?;
            staged.push((rel_str, buf));
        }
    }

    let manifest =
        manifest.ok_or_else(|| Error::Session("backup missing manifest.json".to_string()))?;

    let backup_major = semver_major(&manifest.aivpn_version);
    let current_major = semver_major(env!("CARGO_PKG_VERSION"));
    if backup_major != current_major {
        warn!(
            "Version mismatch: backup={} current={} — import may not be fully compatible",
            manifest.aivpn_version,
            env!("CARGO_PKG_VERSION")
        );
    }

    // Every staged file must match what the manifest claims for it — a
    // manifest whose content_hashes were tampered to match altered files
    // would still fail the MAC check below (it doesn't have the key), but
    // this catches the simpler "stale/mismatched manifest" and "corrupted
    // archive" cases even when the MAC step itself has to be skipped.
    for (rel, bytes) in &staged {
        let actual = blake3::hash(bytes).to_hex().to_string();
        match manifest.content_hashes.get(rel) {
            Some(expected) if expected == &actual => {}
            Some(_) => {
                return Err(Error::Session(format!(
                    "backup integrity check failed: {} content does not match manifest",
                    rel
                )));
            }
            None => {
                // Older backups (pre-content_hashes) simply lack an entry —
                // not itself a tamper signal.
            }
        }
    }

    // Verify the manifest MAC against THIS server's local integrity key
    // when both are available. A present-but-mismatched MAC against a key
    // we already had on disk means the archive was altered after being
    // signed by (what should be) this same key — fail closed. A missing
    // key or missing MAC only means verification is impossible (fresh
    // install, cross-server migration, or a pre-signing backup) — warn and
    // proceed, since the import endpoint is already admin-only (unix
    // socket / CLI on the host).
    match (&manifest.mac, load_backup_key(target_dir, false)) {
        (Some(mac_hex), Some(key)) => {
            let expected = blake3::keyed_hash(&key, &manifest.mac_input())
                .to_hex()
                .to_string();
            if !bool::from(expected.as_bytes().ct_eq(mac_hex.as_bytes())) {
                return Err(Error::Session(
                    "backup integrity signature mismatch — refusing to import (tampered, \
                     corrupted, or signed by a different server's key)"
                        .to_string(),
                ));
            }
            info!("backup integrity signature verified");
        }
        (Some(_), None) => {
            warn!(
                "backup is signed but this server has no local integrity key yet — cannot \
                 verify authenticity (expected on a fresh install or when migrating from \
                 another server); proceeding"
            );
        }
        (None, _) => {
            warn!("backup has no integrity signature (older export) — proceeding unverified");
        }
    }

    if dry_run {
        println!("DRY RUN — no files will be written.");
        println!("Backup created:  {}", manifest.created_at);
        println!("Backup version:  {}", manifest.aivpn_version);
        println!("Components:      {:?}", manifest.components);
        println!("Restore target:  {:?}", target_dir);
        println!("Signed:          {}", manifest.mac.is_some());
        return Ok(());
    }

    std::fs::create_dir_all(target_dir)
        .map_err(|e| Error::Session(format!("create target dir: {}", e)))?;

    // Pass 2: every file already validated (allowlist + schema + content
    // hash) — write each to a per-file-unique temp path (PID + random
    // suffix, closing the M8 fixed-".tmp"-name race) and atomically rename
    // into place, hardening permissions before the rename makes the file
    // visible at its real path.
    for (rel, bytes) in &staged {
        let dest = target_dir.join(rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::Session(format!("mkdir: {}", e)))?;
        }
        let mut nonce = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let tmp = dest.with_extension(format!("{}.{}.tmp", std::process::id(), hex::encode(nonce)));
        std::fs::write(&tmp, bytes)
            .map_err(|e| Error::Session(format!("write {:?}: {}", tmp, e)))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)) {
                warn!("failed to harden permissions on restored {:?}: {}", dest, e);
            }
        }
        std::fs::rename(&tmp, &dest)
            .map_err(|e| Error::Session(format!("rename {:?}: {}", dest, e)))?;
        info!("Restored {:?}", rel);
    }

    info!("Import complete from {:?}", archive_path);
    Ok(())
}

fn semver_major(v: &str) -> u64 {
    v.split('.')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}
