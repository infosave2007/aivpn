//! Mask Store — Storage and Rating System for Auto-Generated Masks
//!
//! Stores MaskProfile + MaskStats pairs with automatic deactivation
//! when success rate drops below threshold. Persists to disk.

use std::path::PathBuf;
use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use aivpn_common::error::{Error, Result};
use aivpn_common::mask::{
    verify_mask_artifact, MaskProfile, MaskVerifyDetail, MaskVerifyMode, MaskVerifyResult,
};

use crate::gateway::MaskCatalog;

/// Success rate threshold — masks below this are deactivated
const DEACTIVATION_THRESHOLD: f32 = 0.80;

/// Minimum usages before deactivation can trigger
const MIN_USAGES_FOR_DEACTIVATION: u64 = 100;

/// Mask statistics for rating system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskStats {
    pub mask_id: String,
    pub times_used: u64,
    pub times_failed: u64,
    pub success_rate: f32,
    pub confidence: f32,
    pub is_active: bool,
    pub created_by: String,
    pub created_at: u64,
    pub last_used: Option<u64>,
}

/// Combined mask profile + statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskEntry {
    pub profile: MaskProfile,
    pub stats: MaskStats,
}

/// Mask store with rating system and disk persistence
pub struct MaskStore {
    /// All masks (mask_id → MaskEntry)
    masks: DashMap<String, MaskEntry>,
    mutation: std::sync::Mutex<()>,
    /// Reference to the gateway's mask catalog for registration
    catalog: Arc<MaskCatalog>,
    /// Storage directory for mask files
    storage_dir: PathBuf,
    /// Monotonic version of the selectable mask set, bumped on add/delete.
    /// The gateway pushes a fresh client-facing `MaskCatalog` whenever this
    /// moves past what a session was last sent, so newly auto-generated masks
    /// reach connected clients live (see gateway Keepalive handler).
    version: portable_atomic::AtomicU64,
    /// Приватный ключ оператора. Если он есть, генератор подписывает маску
    /// после самопроверки. В production-secure отсутствие ключа запрещает
    /// генерацию. Обычная сборка без ключа по-прежнему пишет нулевую подпись.
    signing_key: Option<ed25519_dalek::SigningKey>,
    /// Публичный ключ оператора для проверки подписи на диске и при записи.
    /// Если в конструктор передали только приватный ключ, публичный выводится
    /// из него.
    operator_pubkey: Option<[u8; 32]>,
    /// Режим проверки. В production-secure конструктор фиксирует enforce.
    verify_mode: MaskVerifyMode,
}

impl MaskStore {
    /// Создает хранилище и сразу читает маски с диска.
    ///
    /// `signing_key` подписывает новые маски. `operator_pubkey` проверяет
    /// подпись при чтении и записи. Если публичный ключ не передан, он
    /// выводится из приватного. `verify_mode` в обычной сборке применяется
    /// как есть. В production-secure режим всегда enforce: переданный off
    /// или warn не открывает загрузку неподписанных масок.
    pub fn new(
        catalog: Arc<MaskCatalog>,
        storage_dir: PathBuf,
        signing_key: Option<ed25519_dalek::SigningKey>,
        operator_pubkey: Option<[u8; 32]>,
        verify_mode: MaskVerifyMode,
    ) -> Self {
        let operator_pubkey = operator_pubkey.or_else(|| {
            signing_key
                .as_ref()
                .map(|key| key.verifying_key().to_bytes())
        });
        #[cfg(feature = "production-secure")]
        if verify_mode != MaskVerifyMode::Enforce {
            error!(
                "production-secure: mask_verify_mode={:?} не применяется, действует только enforce",
                verify_mode
            );
        }
        #[cfg(feature = "production-secure")]
        if signing_key.is_none() {
            error!(
                "production-secure: ключ подписи масок не задан. Генерация будет отклонена, \
                 загрузка примет только маски с верной подписью оператора"
            );
        }
        let verify_mode = crate::server_config::effective_mask_verify_mode(verify_mode);
        let store = Self {
            masks: DashMap::new(),
            mutation: std::sync::Mutex::new(()),
            catalog,
            storage_dir,
            // Start at 1 so a session that has never been sent a catalog
            // (version_sent = 0) always receives one.
            version: portable_atomic::AtomicU64::new(1),
            signing_key,
            operator_pubkey,
            verify_mode,
        };
        // С диска, без встроенных пресетов: пресет это код клиента и сервера,
        // а не файл, который можно подменить в каталоге.
        store.load_from_disk();
        store
    }

    /// Operator mask-signing key, if configured (R2 Phase B sign side).
    pub fn operator_signing_key(&self) -> Option<&ed25519_dalek::SigningKey> {
        self.signing_key.as_ref()
    }

    /// Добавляет маску в каталог и на диск.
    ///
    /// Та же проверка, что и при чтении с диска. В enforce неподписанная,
    /// чужая или битая подпись не попадает в каталог. В warn маска
    /// сохраняется, сбой подписи пишется в журнал. Производные маски сессии
    /// (`polymorphic:` и `bootstrap:`) здесь не исключаются: на диск их
    /// класть нельзя, канал сессии их и так подтверждает отдельно.
    pub fn add_mask(&self, entry: MaskEntry) -> Result<()> {
        let _guard = self.mutation.lock().unwrap_or_else(|e| e.into_inner());
        self.ensure_profile_allowed(&entry.profile)?;
        let mask_id = entry.stats.mask_id.clone();
        info!(
            "Storing mask '{}' (confidence: {:.2})",
            mask_id, entry.stats.confidence
        );

        // Save to disk
        if entry.profile.mask_id != mask_id {
            return Err(Error::InvalidPacket("Mask ID does not match metadata"));
        }
        self.save_to_disk(&mask_id, &entry)?;

        // Register in catalog for neural resonance
        self.catalog.register_mask(entry.profile.clone());

        // Insert into in-memory store
        self.masks.insert(mask_id, entry);
        self.version
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Current version of the selectable mask set (bumped on add/delete).
    pub fn catalog_version(&self) -> u64 {
        self.version.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Register mask in the gateway catalog
    pub fn register_in_catalog(&self, mask_id: &str) -> Result<()> {
        if let Some(entry) = self.masks.get(mask_id) {
            self.catalog.register_mask(entry.value().profile.clone());
        }
        Ok(())
    }

    /// Record successful usage of a mask
    pub fn record_usage(&self, mask_id: &str) {
        if let Some(mut entry) = self.masks.get_mut(mask_id) {
            entry.stats.times_used += 1;
            entry.stats.success_rate = if entry.stats.times_used > 0 {
                1.0 - entry.stats.times_failed as f32 / entry.stats.times_used as f32
            } else {
                1.0
            };
            entry.stats.last_used = Some(current_unix_secs());
            self.save_stats_to_disk(mask_id, &entry.stats);
        }
    }

    /// Record a failure (DPI block detected)
    pub fn record_failure(&self, mask_id: &str) {
        if let Some(mut entry) = self.masks.get_mut(mask_id) {
            entry.stats.times_used += 1;
            entry.stats.times_failed += 1;
            entry.stats.success_rate = if entry.stats.times_used > 0 {
                1.0 - entry.stats.times_failed as f32 / entry.stats.times_used as f32
            } else {
                1.0
            };

            // Auto-deactivation check
            if entry.stats.success_rate < DEACTIVATION_THRESHOLD
                && entry.stats.times_used > MIN_USAGES_FOR_DEACTIVATION
            {
                entry.stats.is_active = false;
                self.catalog.remove_mask(mask_id);
                warn!(
                    "Mask '{}' deactivated: success={:.1}% ({}/{} failures)",
                    mask_id,
                    entry.stats.success_rate * 100.0,
                    entry.stats.times_failed,
                    entry.stats.times_used
                );
            }
            self.save_stats_to_disk(mask_id, &entry.stats);
        }
    }

    /// List all masks with their stats
    pub fn list_masks(&self) -> Vec<MaskEntry> {
        self.masks.iter().map(|e| e.value().clone()).collect()
    }

    /// Get a specific mask entry
    pub fn get_mask(&self, mask_id: &str) -> Option<MaskEntry> {
        self.masks.get(mask_id).map(|e| e.value().clone())
    }

    /// Delete a mask
    pub fn delete_mask(&self, mask_id: &str) -> Result<()> {
        let _guard = self.mutation.lock().unwrap_or_else(|e| e.into_inner());
        let path = self
            .safe_mask_path(mask_id, "json")
            .ok_or(Error::InvalidPacket("Invalid mask ID"))?;
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        self.masks.remove(mask_id);
        self.catalog.remove_mask(mask_id);
        self.version
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Some(path) = self.safe_mask_path(mask_id, "stats") {
            let _ = std::fs::remove_file(path);
        }
        info!("Deleted mask '{}'", mask_id);
        Ok(())
    }

    /// Build the on-disk path for a mask file, or `None` when `mask_id` is not a
    /// safe single path component. This is a defence-in-depth guard: mask IDs
    /// derived from recording service names are already sanitised at the source
    /// (`mask_gen::sanitize_service_slug`), but validating again at the
    /// filesystem boundary ensures no future caller can trigger a path-traversal
    /// write/delete as root (`../`, absolute paths, separators are all rejected).
    fn safe_mask_path(&self, mask_id: &str, ext: &str) -> Option<PathBuf> {
        let safe = !mask_id.is_empty()
            && mask_id.len() <= 128
            && mask_id != "."
            && mask_id != ".."
            && mask_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if !safe {
            error!(
                "Refusing unsafe mask_id '{}' for on-disk {} file",
                mask_id, ext
            );
            return None;
        }
        Some(self.storage_dir.join(format!("{}.{}", mask_id, ext)))
    }

    /// Make a newly stored mask available to connected clients.
    ///
    /// This does **not** push a `ControlPayload::MaskUpdate` to live sessions —
    /// `MaskStore` holds no UDP socket, session table, or per-session key
    /// material, so it cannot frame/sign/encrypt a per-session control message.
    /// It also would not be desirable to force every connected client onto a
    /// brand-new, still-unproven (`times_used = 0`) auto-generated mask.
    ///
    /// The real live-distribution path is the monotonic catalog `version`,
    /// which `add_mask` bumps when the mask is stored. The gateway compares that
    /// version against each session's `mask_catalog_version_sent` on every
    /// keepalive and pushes a fresh `MaskCatalog` (see the `Keepalive` arm in
    /// `gateway::handle_control_message`), so the mask reaches connected clients
    /// as *selectable* without any action here. Clients then opt into it via
    /// `MaskPreference`.
    ///
    /// This method only validates that the stored profile serialises cleanly
    /// (so a later catalog push cannot fail on it) and logs the outcome. It is
    /// intentionally a no-op with respect to session traffic — the log must not
    /// claim a broadcast that did not happen.
    pub async fn broadcast_mask_update(&self, mask_id: &str) -> Result<()> {
        if let Some(entry) = self.masks.get(mask_id) {
            // Validate the profile is serialisable so the catalog push can't
            // later fail on it. This does not transmit anything.
            let _profile_data = rmp_serde::to_vec(&entry.value().profile)
                .map_err(|e| aivpn_common::error::Error::Serialization(e.to_string()))?;
            info!(
                "Mask '{}' registered (catalog v{}); it will be pushed to \
                 connected clients as selectable on their next keepalive — no \
                 forced per-session MaskUpdate is sent",
                mask_id,
                self.catalog_version()
            );
        } else {
            warn!(
                "broadcast_mask_update called for unknown mask '{}' — nothing to distribute",
                mask_id
            );
        }
        Ok(())
    }

    fn save_stats_to_disk(&self, mask_id: &str, stats: &MaskStats) {
        let Some(stats_path) = self.safe_mask_path(mask_id, "stats") else {
            return;
        };
        let _ = std::fs::create_dir_all(&self.storage_dir);
        match serde_json::to_string_pretty(stats) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&stats_path, json) {
                    error!("Failed to save mask stats {}: {}", mask_id, e);
                }
            }
            Err(e) => error!("Failed to serialize mask stats {}: {}", mask_id, e),
        }
    }

    /// Save mask entry to disk
    fn save_to_disk(&self, mask_id: &str, entry: &MaskEntry) -> Result<()> {
        let json_path = self
            .safe_mask_path(mask_id, "json")
            .ok_or(Error::InvalidPacket("Invalid mask ID"))?;
        std::fs::create_dir_all(&self.storage_dir)?;
        let bytes = serde_json::to_vec_pretty(&entry.profile)
            .map_err(|error| Error::Serialization(error.to_string()))?;
        let temporary = self
            .storage_dir
            .join(format!(".mask-{:016x}.tmp", rand::random::<u64>()));
        let result = (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut options = std::fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&temporary, &json_path)?;
            #[cfg(unix)]
            std::fs::File::open(&self.storage_dir)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result?;
        self.save_stats_to_disk(mask_id, &entry.stats);
        Ok(())
    }

    /// Load masks from disk on startup
    fn load_from_disk(&self) {
        let dir = &self.storage_dir;
        if !dir.exists() {
            return;
        }

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                let mask_id = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string();

                if mask_id.is_empty() {
                    continue;
                }

                // Load profile
                let profile: MaskProfile = match std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|json| serde_json::from_str(&json).ok())
                {
                    Some(p) => p,
                    None => continue,
                };

                if profile.mask_id != mask_id {
                    warn!(
                        "Mask file name does not match its signed ID: {}",
                        path.display()
                    );
                    continue;
                }
                // Диск не является каналом сессии. Префикс polymorphic: или
                // bootstrap: не освобождает файл от проверки подписи.
                let verdict = assess_stored_profile(
                    &profile,
                    self.operator_pubkey.as_ref(),
                    self.verify_mode,
                );
                if !verdict.accept {
                    error!(
                        "Mask '{}' REJECTED (mask_verify_mode={}): {} , file: {}",
                        mask_id,
                        verify_mode_name(self.verify_mode),
                        verify_detail_str(verdict.detail),
                        path.display()
                    );
                    continue;
                }
                if verdict.is_failure() && self.operator_pubkey.is_some() {
                    warn!(
                        "Mask '{}' failed operator signature verification ({}) , \
                         accepted because mask_verify_mode=warn. Re-sign it or set \
                         mask_verify_mode=enforce once the corpus is signed.",
                        mask_id,
                        verify_detail_str(verdict.detail)
                    );
                }

                // Load stats
                let stats_path = dir.join(format!("{}.stats", mask_id));
                let stats: MaskStats = std::fs::read_to_string(&stats_path)
                    .ok()
                    .and_then(|json| serde_json::from_str(&json).ok())
                    .unwrap_or(MaskStats {
                        mask_id: mask_id.clone(),
                        times_used: 0,
                        times_failed: 0,
                        success_rate: 1.0,
                        confidence: 0.0,
                        is_active: true,
                        created_by: "loaded".into(),
                        created_at: 0,
                        last_used: None,
                    });

                info!(
                    "Loaded mask '{}' from disk (success: {:.1}%)",
                    mask_id,
                    stats.success_rate * 100.0
                );

                // Register only active masks in the live catalog
                if stats.is_active {
                    self.catalog.register_mask(profile.clone());
                }

                self.masks.insert(mask_id, MaskEntry { profile, stats });
            }
        }
    }
}

/// Проверка маски, которую кладут в хранилище: внешний профиль и, если он
/// есть, обратный профиль. Обратный профиль подписывается отдельно, чтобы его
/// можно было проверить и после извлечения. Внешняя подпись при этом тоже
/// покрывает уже подписанный обратный профиль.
fn assess_stored_profile(
    profile: &MaskProfile,
    operator_pubkey: Option<&[u8; 32]>,
    mode: MaskVerifyMode,
) -> MaskVerifyResult {
    let outer = verify_mask_artifact(profile, operator_pubkey, mode);
    if !outer.accept {
        return outer;
    }
    if let Some(reverse) = profile.reverse_profile.as_deref() {
        let inner = verify_mask_artifact(reverse, operator_pubkey, mode);
        if !inner.accept || (inner.is_failure() && !outer.is_failure()) {
            return inner;
        }
    }
    outer
}

impl MaskStore {
    fn ensure_profile_allowed(&self, profile: &MaskProfile) -> Result<()> {
        let verdict =
            assess_stored_profile(profile, self.operator_pubkey.as_ref(), self.verify_mode);
        if !verdict.accept {
            return Err(Error::Mask(format!(
                "маска '{}' отклонена (mask_verify_mode={}): {}",
                profile.mask_id,
                verify_mode_name(self.verify_mode),
                verify_detail_str(verdict.detail)
            )));
        }
        if verdict.is_failure() && self.operator_pubkey.is_some() {
            warn!(
                "Mask '{}' failed operator signature verification ({}) , \
                 accepted because mask_verify_mode={}",
                profile.mask_id,
                verify_detail_str(verdict.detail),
                verify_mode_name(self.verify_mode)
            );
        }
        Ok(())
    }
}

fn verify_mode_name(mode: MaskVerifyMode) -> &'static str {
    match mode {
        MaskVerifyMode::Off => "off",
        MaskVerifyMode::Warn => "warn",
        MaskVerifyMode::Enforce => "enforce",
    }
}

/// Human-readable reason for mask verification log lines.
fn verify_detail_str(detail: MaskVerifyDetail) -> &'static str {
    match detail {
        MaskVerifyDetail::ModeOff => "verification disabled",
        MaskVerifyDetail::Valid => "valid operator signature",
        MaskVerifyDetail::NoOperatorKey => "no operator public key configured",
        MaskVerifyDetail::Unsigned => "unsigned (all-zero legacy signature)",
        MaskVerifyDetail::Invalid => "invalid signature",
    }
}

/// Get current Unix timestamp in seconds
fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> MaskStore {
        let dir = corpus_dir("unit");
        let _ = std::fs::create_dir_all(&dir);
        MaskStore {
            masks: DashMap::new(),
            mutation: std::sync::Mutex::new(()),
            catalog: Arc::new(MaskCatalog::new()),
            storage_dir: dir,
            version: portable_atomic::AtomicU64::new(1),
            signing_key: None,
            operator_pubkey: None,
            verify_mode: MaskVerifyMode::default(),
        }
    }

    #[test]
    fn failed_persistence_does_not_publish_and_ids_must_match() {
        let mut store = make_store();
        store.verify_mode = MaskVerifyMode::Off;
        let profile = aivpn_common::mask::preset_masks::webrtc_zoom_v3();
        let entry = MaskEntry {
            stats: MaskStats {
                mask_id: profile.mask_id.clone(),
                times_used: 0,
                times_failed: 0,
                success_rate: 1.0,
                confidence: 1.0,
                is_active: true,
                created_by: "test".into(),
                created_at: 0,
                last_used: None,
            },
            profile,
        };
        let directory = store.storage_dir.clone();
        let mut mismatch = entry.clone();
        mismatch.stats.mask_id = "other".into();
        assert!(store.add_mask(mismatch).is_err());
        let blocker = directory.join("not-a-directory");
        std::fs::write(&blocker, b"fixture").unwrap();
        store.storage_dir = blocker;
        let version = store.catalog_version();
        assert!(store.add_mask(entry.clone()).is_err());
        assert!(store.get_mask(&entry.profile.mask_id).is_none());
        assert_eq!(store.catalog_version(), version);
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn corpus_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aivpn-maskstore-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_profile(dir: &std::path::Path, profile: &aivpn_common::mask::MaskProfile) {
        std::fs::write(
            dir.join(format!("{}.json", profile.mask_id)),
            serde_json::to_string(profile).unwrap(),
        )
        .unwrap();
    }

    /// Подписанная, неподписанная и подделанная маски в одном каталоге.
    fn write_signature_corpus(dir: &std::path::Path, sk: &ed25519_dalek::SigningKey) {
        use aivpn_common::mask::preset_masks;

        let mut signed = preset_masks::all()[0].clone();
        signed.mask_id = "signed_m".into();
        signed.sign(sk);
        write_profile(dir, &signed);

        let mut unsigned = preset_masks::all()[0].clone();
        unsigned.mask_id = "unsigned_m".into();
        unsigned.signature = [0u8; 64];
        write_profile(dir, &unsigned);

        let mut tampered = signed.clone();
        tampered.mask_id = "tampered_m".into();
        tampered.signature[0] ^= 0xff;
        write_profile(dir, &tampered);

        let mut reverse_broken = preset_masks::all()[0].clone();
        reverse_broken.mask_id = "reverse_broken_m".into();
        let mut reverse = preset_masks::all()[0].clone();
        reverse.mask_id = "reverse_broken_m_rev".into();
        reverse.signature = [0u8; 64];
        reverse_broken.reverse_profile = Some(Box::new(reverse));
        reverse_broken.sign(sk);
        write_profile(dir, &reverse_broken);
    }

    #[test]
    fn enforce_load_rejects_unsigned_tampered_and_unsigned_reverse() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let dir = corpus_dir("enforce");
        write_signature_corpus(&dir, &sk);

        let store = MaskStore::new(
            Arc::new(MaskCatalog::new()),
            dir.clone(),
            None,
            Some(pk),
            MaskVerifyMode::Enforce,
        );
        assert!(store.get_mask("signed_m").is_some());
        assert!(store.get_mask("unsigned_m").is_none());
        assert!(store.get_mask("tampered_m").is_none());
        assert!(
            store.get_mask("reverse_broken_m").is_none(),
            "enforce must reject a mask whose reverse profile is unsigned"
        );

        let closed = MaskStore::new(
            Arc::new(MaskCatalog::new()),
            dir.clone(),
            None,
            None,
            MaskVerifyMode::Enforce,
        );
        assert!(
            closed.get_mask("signed_m").is_none(),
            "enforce without an operator key must fail closed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(not(feature = "production-secure"))]
    #[test]
    fn dev_warn_and_off_still_load_unsigned() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let dir = corpus_dir("dev-modes");
        write_signature_corpus(&dir, &sk);

        let warn = MaskStore::new(
            Arc::new(MaskCatalog::new()),
            dir.clone(),
            None,
            Some(pk),
            MaskVerifyMode::Warn,
        );
        assert!(warn.get_mask("signed_m").is_some());
        assert!(warn.get_mask("unsigned_m").is_some());
        assert!(warn.get_mask("tampered_m").is_some());

        let off = MaskStore::new(
            Arc::new(MaskCatalog::new()),
            dir.clone(),
            None,
            Some(pk),
            MaskVerifyMode::Off,
        );
        assert!(off.get_mask("signed_m").is_some());
        assert!(off.get_mask("unsigned_m").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "production-secure")]
    #[test]
    fn production_secure_load_ignores_warn_and_off() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let dir = corpus_dir("locked");
        write_signature_corpus(&dir, &sk);

        for mode in [
            MaskVerifyMode::Warn,
            MaskVerifyMode::Off,
            MaskVerifyMode::Enforce,
        ] {
            let store = MaskStore::new(
                Arc::new(MaskCatalog::new()),
                dir.clone(),
                None,
                Some(pk),
                mode,
            );
            assert!(store.get_mask("signed_m").is_some(), "{mode:?}");
            assert!(store.get_mask("unsigned_m").is_none(), "{mode:?}");
            assert!(store.get_mask("tampered_m").is_none(), "{mode:?}");
            assert!(store.get_mask("reverse_broken_m").is_none(), "{mode:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn sample_entry(mask_id: &str, profile: aivpn_common::mask::MaskProfile) -> MaskEntry {
        MaskEntry {
            stats: MaskStats {
                mask_id: mask_id.to_string(),
                times_used: 0,
                times_failed: 0,
                success_rate: 1.0,
                confidence: 1.0,
                is_active: true,
                created_by: "test".into(),
                created_at: 1,
                last_used: None,
            },
            profile,
        }
    }

    #[test]
    fn enforce_add_rejects_unsigned_and_accepts_signed() {
        use aivpn_common::mask::preset_masks;

        let sk = ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let dir = corpus_dir("add");
        let store = MaskStore::new(
            Arc::new(MaskCatalog::new()),
            dir.clone(),
            None,
            Some(pk),
            MaskVerifyMode::Enforce,
        );

        let mut unsigned = preset_masks::quic_https_v2();
        unsigned.mask_id = "add_unsigned".into();
        unsigned.signature = [0u8; 64];
        let err = store
            .add_mask(sample_entry("add_unsigned", unsigned))
            .expect_err("unsigned mask must not enter an enforce store");
        assert!(err.to_string().contains("отклонена"), "{err}");
        assert!(store.get_mask("add_unsigned").is_none());

        let mut signed = preset_masks::quic_https_v2();
        signed.mask_id = "add_signed".into();
        signed.sign(&sk);
        store
            .add_mask(sample_entry("add_signed", signed))
            .expect("signed mask must be stored");
        assert!(store.get_mask("add_signed").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(not(feature = "production-secure"))]
    #[test]
    fn dev_warn_add_still_accepts_unsigned() {
        use aivpn_common::mask::preset_masks;

        let dir = corpus_dir("add-warn");
        let store = MaskStore::new(
            Arc::new(MaskCatalog::new()),
            dir.clone(),
            None,
            None,
            MaskVerifyMode::Warn,
        );
        let mut unsigned = preset_masks::quic_https_v2();
        unsigned.mask_id = "dev_unsigned".into();
        unsigned.signature = [0u8; 64];
        store
            .add_mask(sample_entry("dev_unsigned", unsigned))
            .expect("dev warn mode keeps unsigned generation and import");
        assert!(store.get_mask("dev_unsigned").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn safe_mask_path_rejects_traversal() {
        let store = make_store();
        assert!(store.safe_mask_path("../../etc/passwd", "json").is_none());
        assert!(store.safe_mask_path("a/b", "json").is_none());
        assert!(store.safe_mask_path("..", "stats").is_none());
        assert!(store.safe_mask_path("", "json").is_none());
    }

    #[test]
    fn safe_mask_path_accepts_normal_ids() {
        let store = make_store();
        let p = store.safe_mask_path("auto_zoom_v1", "json").unwrap();
        assert!(p.starts_with(&store.storage_dir));
        assert!(p.ends_with("auto_zoom_v1.json"));
    }
}
