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
//!     directory until every file in the archive has passed validation.
//!     После проверки файлы ставятся через журнал: staging/backup рядом
//!     с каждым dest, fsync файла и каталога, идемпотентный recovery.
//!     Смешанное поколение до чтения config/DB не допускается.
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

mod transaction;

pub use transaction::{
    lock_shared_restore, recover_config_sidecar, recover_pending_restore, with_restore_fault,
    SharedRestoreLock,
};

pub(crate) fn has_clients_journal(path: &Path) -> Result<bool> {
    transaction::has_clients_journal(path)
}

pub(crate) fn recover_clients_journal(path: &Path) -> Result<()> {
    transaction::recover_clients_sidecar(path)
}

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

/// Пути назначения задает оператор, а не содержимое архива.
#[derive(Debug, Clone)]
pub struct ImportOptions {
    pub config_path: PathBuf,
    pub clients_db: PathBuf,
    pub mask_dir: PathBuf,
}

#[derive(Clone, Copy)]
struct ImportLimits {
    manifest: u64,
    entry: u64,
    total: u64,
    entries: usize,
}

impl Default for ImportLimits {
    fn default() -> Self {
        Self {
            manifest: 1024 * 1024,
            entry: 64 * 1024 * 1024,
            total: 256 * 1024 * 1024,
            entries: 4096,
        }
    }
}

pub fn import_server_with_options(
    archive_path: &Path,
    opts: &ImportOptions,
    dry_run: bool,
) -> Result<ImportSummary> {
    import_with_limits(archive_path, opts, dry_run, ImportLimits::default())
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

struct ExportGuards {
    _live: Option<crate::client_db::LiveDbGuard>,
    _shared: SharedRestoreLock,
}

/// Один снимок: live-lock DB, затем shared lock общих компонент.
/// Если после захвата журнал еще лежит, exclusive recovery и повтор.
fn consistent_export_guards(opts: &ExportOptions) -> Result<ExportGuards> {
    for _ in 0..4 {
        let live = opts
            .clients_db
            .as_deref()
            .map(crate::client_db::LiveDbGuard::shared)
            .transpose()?;
        let shared = transaction::lock_shared_restore(
            opts.config_path.as_deref(),
            opts.mask_dir.as_deref(),
        )?;
        if shared.journal_pending()? {
            let config = opts.config_path.clone();
            drop(shared);
            drop(live);
            if let Some(config) = config {
                recover_config_sidecar(&config)?;
                continue;
            }
            return Err(Error::Session(
                "незавершенное восстановление мешает экспорту".into(),
            ));
        }
        return Ok(ExportGuards {
            _live: live,
            _shared: shared,
        });
    }
    Err(Error::Session(
        "незавершенное восстановление мешает экспорту".into(),
    ))
}

/// Export server data to `output_path` (.tar.gz).
pub fn export_server(opts: &ExportOptions, output_path: &Path) -> Result<()> {
    // DB shared, затем config shared, затем mask shared. Держим только на время чтения.
    let _snapshot = consistent_export_guards(opts)?;
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
        .or(opts.mask_dir.as_deref());
    match key_dir.and_then(|dir| load_backup_key(dir, true)) {
        Some(key) => {
            let mac = blake3::keyed_hash(&key, &manifest.mac_input());
            manifest.mac = Some(mac.to_hex().to_string());
        }
        None => {
            warn!("backup integrity key unavailable — exporting an unsigned backup");
        }
    }

    let file = open_private_output(output_path)
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
    ar.into_inner()
        .and_then(|gz| gz.finish())
        .and_then(|file| file.sync_all())
        .map_err(|e| Error::Session(format!("finalize backup: {}", e)))?;

    info!(
        "Backup written to {:?} (components: {:?}, signed: {})",
        output_path,
        manifest.components,
        manifest.mac.is_some()
    );
    Ok(())
}

fn open_private_output(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("backup output is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.set_len(0)?;
    Ok(file)
}

/// Archive-relative paths this server will ever write during import.
/// Positive allowlist (server-sec HIGH1): anything else — including a
/// crafted `server.key` entry, which would land in the same directory as
/// the real one — is rejected rather than written to disk.
fn is_allowed_import_path(rel: &Path) -> bool {
    if rel.to_str().is_none_or(|s| s.contains('\\'))
        || rel.is_absolute()
        || rel
            .components()
            .any(|c| c == std::path::Component::ParentDir)
    {
        return false;
    }
    let comps: Vec<_> = rel.components().collect();
    match comps.as_slice() {
        [_only] => matches!(rel.to_str(), Some("clients.json") | Some("server.json")),
        [dir, name] => {
            dir.as_os_str().to_str() == Some("masks")
                && rel.to_str()
                    == name
                        .as_os_str()
                        .to_str()
                        .map(|name| format!("masks/{name}"))
                        .as_deref()
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

/// Summary of what an import did (or, for a dry run, would do) — returned to
/// both the CLI (`--import --dry-run`) and the management API
/// (`POST /backup/import?dry_run=true`) so both surfaces can preview a
/// restore without writing files.
#[derive(Debug, Clone, Serialize)]
pub struct ImportSummary {
    pub aivpn_version: String,
    pub created_at: String,
    pub components: Vec<String>,
    /// Whether the manifest carried a verified integrity signature.
    pub signed: bool,
    /// True if this summary describes a dry run (no files written).
    pub dry_run: bool,
}

/// Import from a backup archive. `dry_run = true` validates the archive and
/// returns the summary of what would be restored, without writing any files.
pub fn import_server(
    archive_path: &Path,
    target_dir: &Path,
    dry_run: bool,
) -> Result<ImportSummary> {
    import_server_with_options(
        archive_path,
        &ImportOptions {
            config_path: target_dir.join("server.json"),
            clients_db: target_dir.join("clients.json"),
            mask_dir: target_dir.join("masks"),
        },
        dry_run,
    )
}

fn import_with_limits(
    archive_path: &Path,
    opts: &ImportOptions,
    dry_run: bool,
    limits: ImportLimits,
) -> Result<ImportSummary> {
    // Pass 1: read the manifest AND every allowlisted, schema-valid
    // component into memory. Nothing is written to `target_dir` until every
    // file in the archive has been checked — a truncated or partially
    // malicious archive can never leave the live config directory in a
    // mixed state.
    let mut manifest: Option<BackupManifest> = None;
    let mut staged: Vec<(String, Vec<u8>)> = Vec::new();
    let mut decoded_size = 0u64;
    let mut seen = std::collections::HashSet::new();
    {
        let file = std::fs::File::open(archive_path)
            .map_err(|e| Error::Session(format!("open backup: {}", e)))?;
        let gz = flate2::read::GzDecoder::new(file);
        let mut ar = tar::Archive::new(gz);
        for entry in ar
            .entries()
            .map_err(|e| Error::Session(format!("read archive: {}", e)))?
            .raw(true)
            .enumerate()
        {
            let (index, entry) = entry;
            if index >= limits.entries {
                return Err(Error::Session("backup entry count limit exceeded".into()));
            }
            let mut entry = entry.map_err(|e| Error::Session(format!("entry: {}", e)))?;
            let size = entry.size();
            decoded_size = decoded_size
                .checked_add(size)
                .ok_or_else(|| Error::Session("backup decoded size limit exceeded".into()))?;
            if size > limits.entry || decoded_size > limits.total {
                return Err(Error::Session("backup decoded size limit exceeded".into()));
            }
            // Не обрабатываем GNU/PAX расширения внутри tar: их размер должен
            // пройти те же ограничения, что и размер обычной записи.
            if !entry.header().entry_type().is_file() {
                return Err(Error::Session("backup contains a non-regular entry".into()));
            }
            let rel = entry
                .path()
                .map_err(|e| Error::Session(format!("entry path: {}", e)))?
                .to_path_buf();

            if rel.to_str() == Some(MANIFEST_NAME) {
                if size > limits.manifest {
                    return Err(Error::Session("backup manifest size limit exceeded".into()));
                }
                if manifest.is_some() {
                    return Err(Error::Session("duplicate backup manifest".into()));
                }
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
            let rel_str = rel.to_string_lossy().into_owned();
            if !seen.insert(rel_str.clone()) {
                return Err(Error::Session("duplicate backup component".into()));
            }
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
                if manifest.mac.is_some() {
                    // A SIGNED manifest binds the exact file SET, not just
                    // per-file contents: an attacker with write access to the
                    // backup store must not be able to slip an extra
                    // clients.json (with their own PSKs) into an archive
                    // exported without clients. Unsigned (legacy) backups
                    // keep the lenient behavior below.
                    return Err(Error::Session(format!(
                        "backup integrity check failed: {} is not listed in the signed manifest",
                        rel
                    )));
                }
                // Older backups (pre-content_hashes) simply lack an entry —
                // not itself a tamper signal.
            }
        }
    }

    // The reverse direction for signed archives: every manifest entry must
    // correspond to a staged file, so deleting a file from the archive
    // (e.g. stripping server.json to keep an old config) is detected too.
    if manifest.mac.is_some() {
        for rel in manifest.content_hashes.keys() {
            if !staged.iter().any(|(staged_rel, _)| staged_rel == rel) {
                return Err(Error::Session(format!(
                    "backup integrity check failed: {} is listed in the signed manifest \
                     but missing from the archive",
                    rel
                )));
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
    let key_dir = opts.config_path.parent().unwrap_or(Path::new("."));
    let mac_verified = match (&manifest.mac, load_backup_key(key_dir, false)) {
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
            true
        }
        (Some(_), None) => {
            warn!(
                "backup is signed but this server has no local integrity key yet — cannot \
                 verify authenticity (expected on a fresh install or when migrating from \
                 another server); proceeding"
            );
            false
        }
        (None, _) => {
            warn!("backup has no integrity signature (older export) — proceeding unverified");
            false
        }
    };

    // Проверяли исходные bytes архива. Только после hash/MAC привязываем
    // восстановленный JSON к выбранным оператором путям следующего запуска.
    for (rel, bytes) in &mut staged {
        if rel == "server.json" {
            let mut config: serde_json::Value = serde_json::from_slice(bytes)
                .map_err(|_| Error::Session("invalid server.json in backup".into()))?;
            let object = config
                .as_object_mut()
                .ok_or_else(|| Error::Session("invalid server.json in backup".into()))?;
            for (field, path) in [
                ("clients_db", &opts.clients_db),
                ("mask_dir", &opts.mask_dir),
            ] {
                let path = path.to_str().ok_or_else(|| {
                    Error::Session(format!("{field}: путь восстановления должен быть UTF-8"))
                })?;
                object.insert(field.into(), serde_json::Value::String(path.into()));
            }
            *bytes = serde_json::to_vec(&config)
                .map_err(|_| Error::Session("serialize restored server.json".into()))?;
        }
    }

    if dry_run {
        return Ok(ImportSummary {
            aivpn_version: manifest.aivpn_version.clone(),
            created_at: manifest.created_at.clone(),
            components: manifest.components.clone(),
            // `signed` means the signature was actually VERIFIED against the
            // local key — a mac that was present but unverifiable (no local
            // key) must not be reported as verified.
            signed: mac_verified,
            dry_run: true,
        });
    }

    // Полная проверка завершена. Ни один DB owner не должен пережить restore
    // со старой памятью и вернуть прежние записи следующим LWW/flush.
    let _restore_guard = crate::client_db::OfflineRestoreGuard::try_acquire(&opts.clients_db)?;
    transaction::install_restored_files(opts, &staged)?;
    info!("Import complete from {:?}", archive_path);
    Ok(ImportSummary {
        aivpn_version: manifest.aivpn_version.clone(),
        created_at: manifest.created_at.clone(),
        components: manifest.components.clone(),
        signed: mac_verified,
        dry_run: false,
    })
}

fn semver_major(v: &str) -> u64 {
    v.split('.')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_paths_have_one_unambiguous_spelling() {
        for path in [
            "masks//escape.json",
            "masks/./escape.json",
            "./server.json",
            "masks/../escape.json",
            r"masks/..\escape.json",
        ] {
            assert!(!is_allowed_import_path(Path::new(path)), "accepted {path}");
        }
        assert!(is_allowed_import_path(Path::new("masks/valid.json")));
    }

    fn import_options(root: &Path) -> ImportOptions {
        ImportOptions {
            config_path: root.join("config/custom.json"),
            clients_db: root.join("db/records.json"),
            mask_dir: root.join("profiles"),
        }
    }

    #[test]
    fn import_uses_explicit_component_paths() {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("paths.tar.gz");
        let profile = aivpn_common::mask::preset_masks::webrtc_zoom_v3();
        let mask_path = format!("masks/{}.json", profile.mask_id);
        write_archive(
            &archive,
            &[
                ("server.json", b"{}".to_vec()),
                ("clients.json", b"{\"clients\":[]}".to_vec()),
                (&mask_path, serde_json::to_vec(&profile).unwrap()),
                (
                    MANIFEST_NAME,
                    serde_json::to_vec(&BackupManifest::new(vec![])).unwrap(),
                ),
            ],
        );
        let opts = import_options(root.path());
        import_server_with_options(&archive, &opts, false).unwrap();
        assert!(
            opts.config_path.exists(),
            "configured filename was not restored"
        );
        assert!(opts.clients_db.exists());
        assert!(opts
            .mask_dir
            .join(format!("{}.json", profile.mask_id))
            .exists());
        assert!(!root.path().join("config/server.json").exists());
        assert!(!root.path().join("config/clients.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn export_is_private_for_new_and_existing_outputs() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("backup.tar.gz");
        export_server(&ExportOptions::default(), &output).unwrap();
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o644)).unwrap();
        export_server(&ExportOptions::default(), &output).unwrap();
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn export_refuses_symlink_output() {
        let root = tempfile::tempdir().unwrap();
        let victim = root.path().join("victim");
        let output = root.path().join("backup.tar.gz");
        std::fs::write(&victim, b"sentinel").unwrap();
        std::os::unix::fs::symlink(&victim, &output).unwrap();
        assert!(export_server(&ExportOptions::default(), &output).is_err());
        assert!(std::fs::read(&victim).unwrap() == b"sentinel");
    }

    #[test]
    fn import_bounds_decoded_manifest_entry_total_and_count() {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("limits.tar.gz");
        let opts = import_options(root.path());
        let manifest = serde_json::to_vec(&BackupManifest::new(vec![])).unwrap();
        let defaults = ImportLimits {
            manifest: 1024,
            entry: 1024,
            total: 4096,
            entries: 10,
        };
        for (entries, limits) in [
            (
                vec![(MANIFEST_NAME, manifest.clone())],
                ImportLimits {
                    manifest: 16,
                    ..defaults
                },
            ),
            (
                vec![
                    (MANIFEST_NAME, manifest.clone()),
                    ("clients.json", vec![b' '; 1025]),
                ],
                defaults,
            ),
            (
                vec![
                    (MANIFEST_NAME, manifest.clone()),
                    ("clients.json", vec![b' '; 700]),
                ],
                ImportLimits {
                    total: 256,
                    ..defaults
                },
            ),
            (
                vec![
                    (MANIFEST_NAME, manifest.clone()),
                    ("clients.json", b"{}".to_vec()),
                ],
                ImportLimits {
                    entries: 1,
                    ..defaults
                },
            ),
        ] {
            write_archive(&archive, &entries);
            let error = import_with_limits(&archive, &opts, false, limits).unwrap_err();
            assert!(
                error.to_string().contains("limit"),
                "unexpected error: {error}"
            );
            assert!(!opts.clients_db.exists());
        }
    }

    #[test]
    fn import_rejects_large_declared_payload_before_reading_it() {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("header-only.tar.gz");
        for (name, entry_type) in [
            ("clients.json", tar::EntryType::Regular),
            ("manifest.json", tar::EntryType::Regular),
            ("extension", tar::EntryType::GNULongName),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).unwrap();
            header.set_entry_type(entry_type);
            header.set_size(1 << 40);
            header.set_cksum();
            let file = std::fs::File::create(&archive).unwrap();
            let mut gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            gz.write_all(header.as_bytes()).unwrap();
            gz.finish().unwrap();
            let error = import_server_with_options(&archive, &import_options(root.path()), false)
                .unwrap_err();
            assert!(
                error.to_string().contains("limit"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn import_does_not_escape_through_backslash_path() {
        let root = tempfile::tempdir().unwrap();
        let dst = root.path().join("restore");
        std::fs::create_dir(&dst).unwrap();
        let victim = root.path().join("victim.json");
        std::fs::write(&victim, b"sentinel").unwrap();
        let archive = root.path().join("traversal.tar.gz");
        write_archive(
            &archive,
            &[
                (
                    r"masks/..\..\victim.json",
                    serde_json::to_vec(&aivpn_common::mask::preset_masks::webrtc_zoom_v3())
                        .unwrap(),
                ),
                (
                    MANIFEST_NAME,
                    serde_json::to_vec(&BackupManifest::new(vec![])).unwrap(),
                ),
            ],
        );
        let _ = import_server(&archive, &dst, false);
        assert!(
            std::fs::read(&victim).unwrap() == b"sentinel",
            "external file changed"
        );
    }

    fn write_archive(path: &Path, entries: &[(&str, Vec<u8>)]) {
        let file = std::fs::File::create(path).unwrap();
        let gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut ar = tar::Builder::new(gz);
        for (name, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            ar.append_data(&mut header, name, bytes.as_slice()).unwrap();
        }
        ar.finish().unwrap();
    }

    fn read_archive(path: &Path) -> Vec<(String, Vec<u8>)> {
        let file = std::fs::File::open(path).unwrap();
        let gz = flate2::read::GzDecoder::new(file);
        let mut ar = tar::Archive::new(gz);
        let mut out = Vec::new();
        for entry in ar.entries().unwrap() {
            let mut e = entry.unwrap();
            let name = e.path().unwrap().to_string_lossy().replace('\\', "/");
            let mut buf = Vec::new();
            e.read_to_end(&mut buf).unwrap();
            out.push((name, buf));
        }
        out
    }

    /// Signed export from `src`, imported into `dst` (which must receive a
    /// copy of the integrity key for verification to be possible).
    fn make_signed_backup(src: &Path, archive: &Path) {
        std::fs::write(src.join("clients.json"), "{\"clients\":[]}").unwrap();
        std::fs::write(src.join("server.json"), "{}").unwrap();
        let opts = ExportOptions {
            include_clients: true,
            include_config: true,
            config_path: Some(src.join("server.json")),
            clients_db: Some(src.join("clients.json")),
            ..Default::default()
        };
        export_server(&opts, archive).unwrap();
    }

    #[test]
    fn import_verified_signed_backup_reports_signed() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let archive = src.path().join("backup.tar.gz");
        make_signed_backup(src.path(), &archive);
        std::fs::copy(
            src.path().join(BACKUP_KEY_FILE),
            dst.path().join(BACKUP_KEY_FILE),
        )
        .unwrap();

        let summary = import_server(&archive, dst.path(), false).unwrap();
        assert!(summary.signed, "a MAC-verified import must report signed");
        assert!(dst.path().join("clients.json").exists());
        assert!(dst.path().join("server.json").exists());
    }

    #[test]
    fn destination_rebase_does_not_hide_tampered_archive_config_paths() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let archive = src.path().join("backup.tar.gz");
        make_signed_backup(src.path(), &archive);
        std::fs::copy(
            src.path().join(BACKUP_KEY_FILE),
            dst.path().join(BACKUP_KEY_FILE),
        )
        .unwrap();
        let original = read_archive(&archive);
        let sentinel = b"existing-config";
        std::fs::write(dst.path().join("server.json"), sentinel).unwrap();
        for replace_hash in [false, true] {
            let mut entries = original.clone();
            let config = entries
                .iter_mut()
                .find(|(name, _)| name == "server.json")
                .unwrap();
            config.1 = serde_json::to_vec(&serde_json::json!({
                "clients_db":"altered-source","mask_dir":"altered-masks",
            }))
            .unwrap();
            let altered_hash = blake3::hash(&config.1).to_hex().to_string();
            if replace_hash {
                let manifest = entries
                    .iter_mut()
                    .find(|(name, _)| name == MANIFEST_NAME)
                    .unwrap();
                let mut value: BackupManifest = serde_json::from_slice(&manifest.1).unwrap();
                value
                    .content_hashes
                    .insert("server.json".into(), altered_hash);
                manifest.1 = serde_json::to_vec(&value).unwrap();
            }
            let refs: Vec<_> = entries
                .iter()
                .map(|(name, bytes)| (name.as_str(), bytes.clone()))
                .collect();
            let tampered = src.path().join("tampered-paths.tar.gz");
            write_archive(&tampered, &refs);
            let error = import_server(&tampered, dst.path(), false)
                .unwrap_err()
                .to_string();
            assert!(error.contains(if replace_hash {
                "signature mismatch"
            } else {
                "content does not match"
            }));
            assert_eq!(
                std::fs::read(dst.path().join("server.json")).unwrap(),
                sentinel
            );
            assert!(!dst.path().join("clients.json").exists());
            assert!(!dst.path().join("masks").exists());
        }
    }

    /// Regression (MAC must bind the file SET): an attacker with write
    /// access to the backup store adds a valid, schema-clean file that the
    /// signed manifest does not list (e.g. a masks/*.json — or, for an
    /// archive exported without clients, a clients.json full of their own
    /// PSKs). The old code treated "not in content_hashes" as a benign
    /// legacy backup and accepted the file.
    #[test]
    fn import_rejects_signed_archive_with_unlisted_extra_file() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let archive = src.path().join("backup.tar.gz");
        make_signed_backup(src.path(), &archive);
        std::fs::copy(
            src.path().join(BACKUP_KEY_FILE),
            dst.path().join(BACKUP_KEY_FILE),
        )
        .unwrap();

        let mut entries = read_archive(&archive);
        let evil_mask =
            serde_json::to_vec(&aivpn_common::mask::preset_masks::webrtc_zoom_v3()).unwrap();
        entries.push(("masks/evil.json".to_string(), evil_mask));
        let tampered = src.path().join("tampered.tar.gz");
        let refs: Vec<(&str, Vec<u8>)> = entries
            .iter()
            .map(|(n, b)| (n.as_str(), b.clone()))
            .collect();
        write_archive(&tampered, &refs);

        let err = import_server(&tampered, dst.path(), true).unwrap_err();
        assert!(
            err.to_string()
                .contains("not listed in the signed manifest"),
            "unexpected error: {}",
            err
        );
    }

    /// The reverse direction: a file REMOVED from a signed archive must also
    /// be rejected (the manifest still lists it).
    #[test]
    fn import_rejects_signed_archive_with_missing_file() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let archive = src.path().join("backup.tar.gz");
        make_signed_backup(src.path(), &archive);
        std::fs::copy(
            src.path().join(BACKUP_KEY_FILE),
            dst.path().join(BACKUP_KEY_FILE),
        )
        .unwrap();

        let entries = read_archive(&archive);
        let kept: Vec<(&str, Vec<u8>)> = entries
            .iter()
            .filter(|(n, _)| n != "server.json")
            .map(|(n, b)| (n.as_str(), b.clone()))
            .collect();
        let tampered = src.path().join("tampered.tar.gz");
        write_archive(&tampered, &kept);

        let err = import_server(&tampered, dst.path(), true).unwrap_err();
        assert!(
            err.to_string().contains("missing from the archive"),
            "unexpected error: {}",
            err
        );
    }

    /// A signed backup imported on a host WITHOUT the integrity key cannot be
    /// verified — import proceeds (documented migration path) but the summary
    /// must not claim the signature was verified.
    #[test]
    fn import_signed_backup_without_local_key_reports_unsigned() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap(); // no key copied
        let archive = src.path().join("backup.tar.gz");
        make_signed_backup(src.path(), &archive);

        let summary = import_server(&archive, dst.path(), true).unwrap();
        assert!(
            !summary.signed,
            "a mac that could not be verified must not be reported as signed"
        );
    }

    /// Genuinely-unsigned (legacy, pre-content_hashes) archives keep the
    /// lenient behavior: extra/unlisted files are accepted with a warning.
    #[test]
    fn import_unsigned_legacy_backup_still_accepted() {
        let dst = tempfile::tempdir().unwrap();
        let manifest = BackupManifest {
            aivpn_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: Utc::now().to_rfc3339(),
            components: vec!["clients".to_string()],
            content_hashes: Default::default(),
            mac: None,
        };
        let archive = dst.path().join("legacy.tar.gz");
        write_archive(
            &archive,
            &[
                ("clients.json", b"{\"clients\":[]}".to_vec()),
                (
                    "manifest.json",
                    serde_json::to_vec_pretty(&manifest).unwrap(),
                ),
            ],
        );

        let summary = import_server(&archive, dst.path(), false).unwrap();
        assert!(!summary.signed);
        assert!(dst.path().join("clients.json").exists());
    }

    static FAULT_TEST_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[derive(Debug, PartialEq, Eq)]
    struct Generation {
        config: Option<Vec<u8>>,
        clients: Option<Vec<u8>>,
        masks: std::collections::BTreeMap<String, Vec<u8>>,
    }

    fn read_generation(opts: &ImportOptions) -> Generation {
        let read = |path: &Path| std::fs::read(path).ok();
        let mut masks = std::collections::BTreeMap::new();
        if let Ok(entries) = std::fs::read_dir(&opts.mask_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    if let Ok(bytes) = std::fs::read(&path) {
                        masks.insert(entry.file_name().to_string_lossy().into_owned(), bytes);
                    }
                }
            }
        }
        Generation {
            config: read(&opts.config_path),
            clients: read(&opts.clients_db),
            masks,
        }
    }

    fn classify(current: &Generation, old: &Generation, new: &Generation) -> &'static str {
        if current == old {
            "old"
        } else if current == new {
            "new"
        } else {
            "mixed"
        }
    }

    fn signed_restore_fixture(root: &Path) -> (PathBuf, ImportOptions, Generation, Generation) {
        let src = root.join("src");
        let dst = root.join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(dst.join("masks")).unwrap();
        std::fs::write(src.join("server.json"), b"{\"log_level\":\"error\"}").unwrap();
        let src_db =
            crate::client_db::ClientDatabase::load(&src.join("clients.json"), Default::default())
                .unwrap();
        src_db.add_client("archived-client").unwrap();
        drop(src_db);
        let profile = aivpn_common::mask::preset_masks::webrtc_zoom_v3();
        let mask_name = format!("{}.json", profile.mask_id);
        std::fs::create_dir(src.join("masks")).unwrap();
        std::fs::write(
            src.join("masks").join(&mask_name),
            serde_json::to_vec(&profile).unwrap(),
        )
        .unwrap();
        let archive = root.join("restore.tar.gz");
        export_server(
            &ExportOptions {
                include_config: true,
                include_clients: true,
                include_masks: true,
                config_path: Some(src.join("server.json")),
                clients_db: Some(src.join("clients.json")),
                mask_dir: Some(src.join("masks")),
            },
            &archive,
        )
        .unwrap();
        std::fs::copy(src.join(BACKUP_KEY_FILE), dst.join(BACKUP_KEY_FILE)).unwrap();
        let opts = ImportOptions {
            config_path: dst.join("server.json"),
            clients_db: dst.join("clients.json"),
            mask_dir: dst.join("masks"),
        };
        let old_config = b"{\"log_level\":\"warn\"}".to_vec();
        std::fs::write(&opts.config_path, &old_config).unwrap();
        let live_db =
            crate::client_db::ClientDatabase::load(&opts.clients_db, Default::default()).unwrap();
        live_db.add_client("live-old").unwrap();
        drop(live_db);
        let old_mask = dst.join("masks").join("kept-old.json");
        std::fs::write(&old_mask, b"{\"old\":true}").unwrap();
        let old = read_generation(&opts);
        import_server_with_options(&archive, &opts, false).unwrap();
        let new = read_generation(&opts);
        std::fs::write(&opts.config_path, &old_config).unwrap();
        std::fs::write(&opts.clients_db, old.clients.as_ref().unwrap()).unwrap();
        std::fs::write(&old_mask, b"{\"old\":true}").unwrap();
        let restored_mask = opts.mask_dir.join(&mask_name);
        if restored_mask.exists() {
            std::fs::remove_file(restored_mask).unwrap();
        }
        assert_eq!(classify(&read_generation(&opts), &old, &new), "old");
        (archive, opts, old, new)
    }

    #[test]
    fn baseline_mid_commit_fault_is_mixed_before_recovery() {
        let _gate = FAULT_TEST_GATE.lock().unwrap();
        let root = tempfile::tempdir().unwrap();
        let (archive, opts, old, new) = signed_restore_fixture(root.path());
        let err = super::with_restore_fault("commit-0", false, || {
            import_server_with_options(&archive, &opts, false)
        })
        .unwrap_err();
        assert!(err.to_string().contains("прервано"), "{err}");
        let mid = read_generation(&opts);
        assert_eq!(
            classify(&mid, &old, &new),
            "mixed",
            "точка commit-0 должна оставлять смесь до recovery"
        );
        super::recover_pending_restore(&opts).unwrap();
        assert_eq!(classify(&read_generation(&opts), &old, &new), "new");
    }

    #[test]
    fn unprepared_fault_rolls_back_to_old_generation() {
        let _gate = FAULT_TEST_GATE.lock().unwrap();
        let root = tempfile::tempdir().unwrap();
        let (archive, opts, old, new) = signed_restore_fixture(root.path());
        for step in ["journal-preparing", "backup-0", "stage-0", "stage-1"] {
            std::fs::write(&opts.config_path, old.config.as_ref().unwrap()).unwrap();
            std::fs::write(&opts.clients_db, old.clients.as_ref().unwrap()).unwrap();
            let err = super::with_restore_fault(step, false, || {
                import_server_with_options(&archive, &opts, false)
            })
            .unwrap_err();
            assert!(err.to_string().contains("прервано"), "{step}: {err}");
            super::recover_pending_restore(&opts).unwrap();
            assert_eq!(
                classify(&read_generation(&opts), &old, &new),
                "old",
                "{step}"
            );
        }
    }

    #[test]
    fn identical_archive_recovers_before_all_backups_are_written() {
        let root = tempfile::tempdir().unwrap();
        let (archive, opts, _, _) = signed_restore_fixture(root.path());
        import_server_with_options(&archive, &opts, false).unwrap();
        let expected = read_generation(&opts);
        for step in ["journal-preparing", "backup-0", "stage-0", "stage-1"] {
            assert!(super::with_restore_fault(step, false, || {
                import_server_with_options(&archive, &opts, false)
            })
            .is_err());
            super::recover_pending_restore(&opts).unwrap();
            assert_eq!(read_generation(&opts), expected, "{step}");
        }
    }

    #[test]
    fn interrupted_cleanup_never_reinstalls_already_committed_data() {
        for step in ["cleanup-file-0", "cleanup-journal-0"] {
            let root = tempfile::tempdir().unwrap();
            let (archive, opts, _, _) = signed_restore_fixture(root.path());
            assert!(super::with_restore_fault(step, false, || {
                import_server_with_options(&archive, &opts, false)
            })
            .is_err());
            let mut changed = std::fs::read(&opts.clients_db).unwrap();
            changed.push(b'\n');
            std::fs::write(&opts.clients_db, &changed).unwrap();
            super::recover_pending_restore(&opts).unwrap();
            assert_eq!(std::fs::read(&opts.clients_db).unwrap(), changed);
        }
    }

    #[cfg(unix)]
    #[test]
    fn identical_restored_files_still_receive_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let (archive, opts, _, _) = signed_restore_fixture(root.path());
        import_server_with_options(&archive, &opts, false).unwrap();
        for path in [&opts.config_path, &opts.clients_db] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        import_server_with_options(&archive, &opts, false).unwrap();
        for path in [&opts.config_path, &opts.clients_db] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn restore_rejects_mask_directory_symlink_without_writing_target() {
        let root = tempfile::tempdir().unwrap();
        let (archive, mut opts, _, _) = signed_restore_fixture(root.path());
        let original = read_generation(&opts);
        let alias = root.path().join("mask-alias");
        std::os::unix::fs::symlink(&opts.mask_dir, &alias).unwrap();
        opts.mask_dir = alias;
        assert!(import_server_with_options(&archive, &opts, false).is_err());
        assert_eq!(read_generation(&opts), original);
    }

    #[test]
    fn prepared_fault_completes_to_new_generation() {
        let _gate = FAULT_TEST_GATE.lock().unwrap();
        let root = tempfile::tempdir().unwrap();
        let (archive, opts, old, new) = signed_restore_fixture(root.path());
        for step in ["prepared", "committing", "commit-0", "commit-1"] {
            std::fs::write(&opts.config_path, old.config.as_ref().unwrap()).unwrap();
            std::fs::write(&opts.clients_db, old.clients.as_ref().unwrap()).unwrap();
            let _ = super::with_restore_fault(step, false, || {
                import_server_with_options(&archive, &opts, false)
            });
            super::recover_pending_restore(&opts).unwrap();
            assert_eq!(
                classify(&read_generation(&opts), &old, &new),
                "new",
                "{step}"
            );
        }
    }

    #[test]
    fn partial_prepared_journal_keeps_new_generation_recoverable() {
        let _gate = FAULT_TEST_GATE.lock().unwrap();
        let root = tempfile::tempdir().unwrap();
        let (archive, opts, old, new) = signed_restore_fixture(root.path());
        let result = super::with_restore_fault("journal-prepared-config", false, || {
            import_server_with_options(&archive, &opts, false)
        });
        assert!(result.is_err());
        super::recover_pending_restore(&opts).unwrap();
        assert_eq!(classify(&read_generation(&opts), &old, &new), "new");
    }

    #[test]
    fn overlapping_restore_destinations_leave_existing_files_unchanged() {
        let root = tempfile::tempdir().unwrap();
        let (archive, mut opts, _, _) = signed_restore_fixture(root.path());
        let before = std::fs::read(&opts.config_path).unwrap();
        opts.clients_db = opts.config_path.clone();
        assert!(import_server_with_options(&archive, &opts, false).is_err());
        assert_eq!(std::fs::read(&opts.config_path).unwrap(), before);
    }

    #[test]
    fn component_reader_blocks_restore_and_lock_inode_is_preserved() {
        let root = tempfile::tempdir().unwrap();
        let (archive, opts, old, _) = signed_restore_fixture(root.path());
        let lock =
            super::lock_shared_restore(Some(&opts.config_path), Some(&opts.mask_dir)).unwrap();
        assert!(import_server_with_options(&archive, &opts, false).is_err());
        assert_eq!(read_generation(&opts), old);
        let path = opts
            .config_path
            .with_file_name("server.json.aivpn-restore.lock");
        #[cfg(unix)]
        let inode = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(&path).unwrap().ino()
        };
        drop(lock);
        import_server_with_options(&archive, &opts, false).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
        }
    }

    #[test]
    fn oversized_or_nonregular_journal_blocks_database_read() {
        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("clients.json");
        let journal = root.path().join("clients.json.aivpn-restore.journal");
        std::fs::File::create(&journal)
            .unwrap()
            .set_len(1024 * 1024 * 1024)
            .unwrap();
        assert!(super::has_clients_journal(&db).is_err());
        std::fs::remove_file(&journal).unwrap();
        std::fs::create_dir(&journal).unwrap();
        assert!(super::has_clients_journal(&db).is_err());
    }

    #[test]
    fn committed_fault_still_reports_success() {
        let _gate = FAULT_TEST_GATE.lock().unwrap();
        let root = tempfile::tempdir().unwrap();
        let (archive, opts, old, new) = signed_restore_fixture(root.path());
        let summary = super::with_restore_fault("committed", false, || {
            import_server_with_options(&archive, &opts, false)
        })
        .unwrap();
        assert!(!summary.dry_run);
        assert_eq!(classify(&read_generation(&opts), &old, &new), "new");
    }

    #[cfg(unix)]
    #[test]
    fn restore_refuses_symlink_dest_and_leaves_victim() {
        let root = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let archive = src.path().join("backup.tar.gz");
        make_signed_backup(src.path(), &archive);
        let victim = root.path().join("victim");
        std::fs::write(&victim, b"sentinel").unwrap();
        std::os::unix::fs::symlink(&victim, root.path().join("clients.json")).unwrap();
        std::fs::copy(
            src.path().join(BACKUP_KEY_FILE),
            root.path().join(BACKUP_KEY_FILE),
        )
        .unwrap();
        let err = import_server(&archive, root.path(), false).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
        assert_eq!(std::fs::read(&victim).unwrap(), b"sentinel");
    }

    #[test]
    fn restore_does_not_delete_foreign_staging() {
        let _gate = FAULT_TEST_GATE.lock().unwrap();
        let root = tempfile::tempdir().unwrap();
        let (archive, opts, old, new) = signed_restore_fixture(root.path());
        let foreign = opts
            .config_path
            .parent()
            .unwrap()
            .join(".server.json.aivpn-restore-staging-deadbeef");
        std::fs::write(&foreign, b"foreign").unwrap();
        import_server_with_options(&archive, &opts, false).unwrap();
        assert_eq!(std::fs::read(&foreign).unwrap(), b"foreign");
        assert_eq!(classify(&read_generation(&opts), &old, &new), "new");
    }

    #[test]
    fn restore_across_separate_directories() {
        let config_root = tempfile::TempDir::new_in("/tmp").unwrap();
        let db_root =
            tempfile::TempDir::new_in("/var/tmp").unwrap_or_else(|_| tempfile::tempdir().unwrap());
        let mask_root = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let archive = src.path().join("backup.tar.gz");
        make_signed_backup(src.path(), &archive);
        std::fs::copy(
            src.path().join(BACKUP_KEY_FILE),
            config_root.path().join(BACKUP_KEY_FILE),
        )
        .unwrap();
        let opts = ImportOptions {
            config_path: config_root.path().join("server.json"),
            clients_db: db_root.path().join("clients.json"),
            mask_dir: mask_root.path().join("masks"),
        };
        std::fs::write(&opts.config_path, b"{\"listen\":\"old\"}").unwrap();
        std::fs::write(&opts.clients_db, b"{\"clients\":[]}").unwrap();
        import_server_with_options(&archive, &opts, false).unwrap();
        assert!(opts.config_path.exists());
        assert!(opts.clients_db.exists());
        let listed = crate::client_db::ClientDatabase::load(&opts.clients_db, Default::default())
            .unwrap()
            .list_clients();
        assert!(listed.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn restored_files_keep_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let (archive, opts, _, _) = signed_restore_fixture(root.path());
        import_server_with_options(&archive, &opts, false).unwrap();
        for path in [&opts.config_path, &opts.clients_db] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn recover_rejects_journal_that_retargets_server_key() {
        let root = tempfile::tempdir().unwrap();
        let (archive, opts, old, new) = signed_restore_fixture(root.path());
        let _ = (archive, new);
        let victim = root.path().join("server.key");
        std::fs::write(&victim, b"secret-key").unwrap();
        let journal = serde_json::json!({
            "version": 1,
            "op_id": "abcd1234abcd1234",
            "phase": "prepared",
            "config_path": opts.config_path,
            "clients_db": opts.clients_db,
            "mask_dir": opts.mask_dir,
            "files": [{
                "role": "config",
                "dest": victim,
                "staging": root.path().join(".server.key.aivpn-restore-staging-abcd1234abcd1234"),
                "backup": serde_json::Value::Null,
                "new_hash": "00",
                "old_hash": serde_json::Value::Null,
                "created": true
            }]
        });
        let mut journal_path = opts.config_path.as_os_str().to_os_string();
        journal_path.push(".aivpn-restore.journal");
        std::fs::write(journal_path, serde_json::to_vec(&journal).unwrap()).unwrap();
        let err = super::recover_pending_restore(&opts).unwrap_err();
        assert!(
            err.to_string().contains("ключ") || err.to_string().contains("подменил"),
            "{err}"
        );
        assert_eq!(std::fs::read(&victim).unwrap(), b"secret-key");
        assert_eq!(read_generation(&opts), old);
    }

    #[cfg(unix)]
    #[test]
    fn restore_unwritable_mask_dir_does_not_mix_config_and_db() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let (archive, opts, old, new) = signed_restore_fixture(root.path());
        std::fs::set_permissions(&opts.mask_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let err = import_server_with_options(&archive, &opts, false);
        std::fs::set_permissions(&opts.mask_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(err.is_err());
        super::recover_pending_restore(&opts).unwrap();
        let generation = classify(&read_generation(&opts), &old, &new);
        assert_ne!(generation, "mixed");
    }
}
