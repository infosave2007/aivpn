use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use aivpn_common::error::{Error, Result};
use aivpn_common::mask::{
    current_unix_secs, derive_bootstrap_candidates, BootstrapDescriptor, MaskProfile,
};

/// Sticky last-known-good mask (client). Set on the first real DATA RX of a
/// session and reused in AUTO mode across reconnects instead of re-deriving from
/// the churning bootstrap-descriptor set. FIX (Jul 15): a data-plane stall makes
/// the client reconnect while the handshake still succeeds, so the old resolver
/// hopped masks each reconnect and never let the data plane settle. Mirrors the
/// mobile cores' `LAST_GOOD_MASK`.
pub static LAST_GOOD_MASK: Mutex<Option<MaskProfile>> = Mutex::new(None);

/// Liveness half of the sticky-mask fix (client). Counts consecutive SHORT
/// sessions that ended on the data watchdog while a sticky mask was in use, so a
/// mask that keeps getting throttled is abandoned (LAST_GOOD_MASK cleared) and
/// AUTO explores a different one, instead of looping on it forever.
static DATA_STALL_STREAK: AtomicU32 = AtomicU32::new(0);
/// A session that stayed up at least this long is a working mask; a later stall
/// is a transient hiccup, so the streak resets and the mask stays sticky.
const HEALTHY_SESSION_MIN: Duration = Duration::from_secs(45);
/// Abandon the sticky mask after this many consecutive short data-stall sessions.
const DATA_STALL_EXPLORE_THRESHOLD: u32 = 4;

/// Call when a session ends on the data watchdog: a healthy-length session
/// resets the stall streak; repeated short stalls clear the sticky mask so AUTO
/// can explore alternatives.
pub fn note_data_stall_and_maybe_explore(established: Instant) {
    if established.elapsed() >= HEALTHY_SESSION_MIN {
        DATA_STALL_STREAK.store(0, Ordering::Relaxed);
        return;
    }
    let n = DATA_STALL_STREAK.fetch_add(1, Ordering::Relaxed) + 1;
    if n >= DATA_STALL_EXPLORE_THRESHOLD {
        *LAST_GOOD_MASK.lock().unwrap_or_else(|e| e.into_inner()) = None;
        DATA_STALL_STREAK.store(0, Ordering::Relaxed);
        tracing::warn!(
            "sticky mask produced {n} short data-stall sessions — clearing it so auto-mask can try a different mask"
        );
    }
}

const CACHE_FILE_NAME: &str = "bootstrap_descriptors.json";
const MAX_CACHED_DESCRIPTORS: usize = 8;

/// Bootstrap descriptor ids excluded from `select_initial_mask` for the
/// lifetime of this process. `production-secure` builds must never fall back
/// to an unsigned builtin mask, but without any resilience net a cached
/// descriptor whose signer rotated its key (or an epoch the server no longer
/// retains) wedges the client on the same dead handshake forever — selection
/// is otherwise a deterministic newest-`created_at`-first pick. Excluding a
/// proven-unmatchable descriptor id (without deleting it from disk — a
/// multi-epoch server may still accept it later) lets selection advance to
/// the next-newest still-valid SIGNED descriptor instead. See main.rs's
/// `#[cfg(feature = "production-secure")]` handshake-fallback block.
static EXCLUDED_DESCRIPTOR_IDS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Mark a descriptor id as unmatchable for this run's `select_initial_mask`.
/// Idempotent. Returns `true` if this was a new exclusion.
pub fn exclude_descriptor(descriptor_id: &str) -> bool {
    let mut ids = EXCLUDED_DESCRIPTOR_IDS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if ids.iter().any(|id| id == descriptor_id) {
        false
    } else {
        ids.push(descriptor_id.to_string());
        true
    }
}

fn is_excluded(descriptor_id: &str) -> bool {
    EXCLUDED_DESCRIPTOR_IDS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .any(|id| id == descriptor_id)
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct BootstrapCacheFile {
    descriptors: Vec<BootstrapDescriptor>,
}

fn cache_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".aivpn");
    }
    std::env::temp_dir().join("aivpn")
}

fn cache_path() -> PathBuf {
    cache_dir().join(CACHE_FILE_NAME)
}

fn load_cache_file() -> BootstrapCacheFile {
    let path = cache_path();
    fs::read_to_string(path)
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

pub fn load_descriptors() -> Vec<BootstrapDescriptor> {
    let now = current_unix_secs();
    let mut descriptors = load_cache_file().descriptors;
    descriptors.retain(|descriptor| descriptor.expires_at.saturating_add(24 * 3600) >= now);
    descriptors.sort_by(|left, right| right.created_at.cmp(&left.created_at));
    descriptors
}

pub fn select_initial_mask(preshared_key: Option<&[u8; 32]>) -> Option<MaskProfile> {
    let now = current_unix_secs();
    for descriptor in load_descriptors() {
        if is_excluded(&descriptor.descriptor_id) {
            continue;
        }
        if !descriptor.is_valid_at(now) {
            continue;
        }
        if let Some(mask) = derive_bootstrap_candidates(&descriptor, preshared_key)
            .into_iter()
            .next()
        {
            return Some(mask);
        }
    }
    None
}

/// Advisory file lock guarding `store_descriptor`'s read-modify-write of the
/// cache file. Without it, two client processes against the same `$HOME`
/// (two profiles, GUI + manual CLI, or a startup multi-channel refresh
/// racing a server-pushed `BootstrapDescriptorUpdate`) can both read the
/// same pre-mutation state and each write back a version missing the
/// other's newly-fetched descriptor — a silent lost update (the atomic
/// tmp+rename already prevents outright file corruption, just not this).
/// Held for the lifetime of the returned guard; released automatically when
/// the underlying fd is closed on Drop. Unix-only (flock) — best-effort
/// no-op elsewhere.
#[cfg(unix)]
struct CacheFileLock {
    _file: std::fs::File,
}

#[cfg(unix)]
impl CacheFileLock {
    fn acquire() -> Option<Self> {
        use std::os::unix::io::AsRawFd;
        let dir = cache_dir();
        let _ = fs::create_dir_all(&dir);
        let lock_path = dir.join("bootstrap_descriptors.lock");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&lock_path)
            .ok()?;
        // SAFETY: flock(2) on a valid, owned fd with a plain integer
        // operation flag. LOCK_EX blocks until the lock is available, so
        // concurrent store_descriptor calls serialize their
        // read-modify-write instead of interleaving. The lock is released
        // automatically (by the kernel) when this fd is closed, including
        // on process crash — no stale-lock cleanup needed.
        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if ret != 0 {
            return None;
        }
        Some(Self { _file: file })
    }
}

pub fn store_descriptor(descriptor: BootstrapDescriptor) -> Result<()> {
    #[cfg(unix)]
    let _lock = CacheFileLock::acquire();
    let mut cache = load_cache_file();
    cache
        .descriptors
        .retain(|existing| existing.descriptor_id != descriptor.descriptor_id);
    cache.descriptors.push(descriptor);
    cache
        .descriptors
        .sort_by(|left, right| right.created_at.cmp(&left.created_at));
    cache.descriptors.truncate(MAX_CACHED_DESCRIPTORS);

    let dir = cache_dir();
    fs::create_dir_all(&dir).map_err(Error::Io)?;
    // Lock the cache directory to the owner (0700). This matters most on the
    // no-$HOME fallback to a shared, predictable /tmp/aivpn path: without it a
    // local attacker could pre-create or symlink the directory and plant
    // bootstrap descriptors (which select the initial mask, and are stored
    // without signature verification when no signing key is configured). Owner
    // dirs like ~/.aivpn are equally fine at 0700.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    let json = serde_json::to_string_pretty(&cache)
        .map_err(|e| Error::Session(format!("Failed to serialize bootstrap cache: {}", e)))?;
    let final_path = cache_path();
    let tmp_path = final_path.with_extension("tmp");
    fs::write(&tmp_path, json).map_err(Error::Io)?;
    fs::rename(&tmp_path, &final_path).map_err(Error::Io)
}

fn validate_descriptor_signature(
    descriptor: &BootstrapDescriptor,
    trusted_key: Option<&[u8; 32]>,
) -> Result<()> {
    let sig_is_zero = descriptor.signature == [0u8; 64];

    match trusted_key {
        Some(key) => {
            if sig_is_zero {
                return Err(aivpn_common::error::Error::Session(format!(
                    "Bootstrap descriptor {} has no signature (all-zero) — rejecting under trusted key configuration",
                    descriptor.descriptor_id
                )));
            }
            match descriptor.verify_signature(key)? {
                true => {}
                false => {
                    return Err(aivpn_common::error::Error::Session(format!(
                        "Bootstrap descriptor {} has invalid ed25519 signature — rejecting",
                        descriptor.descriptor_id
                    )))
                }
            }
        }
        None => {
            if !sig_is_zero {
                tracing::debug!(
                    descriptor_id = %descriptor.descriptor_id,
                    "Bootstrap descriptor has signature but no trusted key provided — storing without verification"
                );
            }
        }
    }

    Ok(())
}

/// Store a bootstrap descriptor after verifying its ed25519 signature.
///
/// `trusted_key` should be the operator's ed25519 signing public key. When `Some`, the
/// signature is verified and unsigned/invalid descriptors are rejected. When `None` the
/// descriptor is stored without signature verification — callers must only pass `None` in
/// development/test contexts where a signing key is not yet available.
///
/// TODO(production-secure): all call sites should supply the operator signing key once
/// a dedicated ed25519 signing keypair is added to the connection-key format.
pub fn store_verified_descriptor(
    descriptor: BootstrapDescriptor,
    trusted_key: Option<&[u8; 32]>,
) -> Result<()> {
    validate_descriptor_signature(&descriptor, trusted_key)?;
    store_descriptor(descriptor)
}

pub async fn refresh_from_urls(urls: &[String], signing_key: Option<&[u8; 32]>) -> usize {
    // Descriptors fetched from CDN/GitHub/Telegram travel over unauthenticated
    // transport, so without an operator signing key we cannot tell a genuine
    // descriptor from one planted by whoever controls the URL/asset — a
    // cache-poisoning vector that could steer the client onto an attacker's
    // initial mask. Refuse to fetch-and-store any network descriptor unless a
    // trusted key is configured to verify its signature. (The session-delivered
    // descriptor path is already authenticated by the AEAD channel and is
    // unaffected.)
    if signing_key.is_none() {
        tracing::warn!(
            "Bootstrap URL refresh skipped: no operator signing key configured — \
             network-fetched descriptors cannot be authenticated (set a server \
             signing key to enable URL bootstrap)"
        );
        return 0;
    }

    let mut stored = 0usize;
    for url in urls {
        // Same SSRF guard as the active loader channels: these URLs come from
        // the connection key / config, i.e. they are attacker-influenceable.
        if let Err(e) = crate::bootstrap_loader::validate_bootstrap_url(url) {
            tracing::warn!("Bootstrap descriptor URL rejected: {}", e);
            continue;
        }
        let Ok(response) = reqwest::get(url).await else {
            continue;
        };
        let Ok(body) = crate::bootstrap_loader::read_body_capped(response).await else {
            continue;
        };

        let descriptors = serde_json::from_str::<Vec<BootstrapDescriptor>>(&body)
            .ok()
            .or_else(|| {
                serde_json::from_str::<BootstrapDescriptor>(&body)
                    .ok()
                    .map(|descriptor| vec![descriptor])
            });

        let Some(descriptors) = descriptors else {
            continue;
        };

        for descriptor in descriptors {
            if store_verified_descriptor(descriptor, signing_key).is_ok() {
                stored += 1;
            }
        }
    }
    stored
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivpn_common::mask::BootstrapDescriptor;

    fn make_desc() -> BootstrapDescriptor {
        BootstrapDescriptor {
            descriptor_id: "test_desc".to_string(),
            version: 1,
            created_at: 0,
            expires_at: 9999999999,
            base_mask_ids: vec![],
            embedded_masks: vec![],
            candidate_count: 1,
            kdf_salt: [0u8; 32],
            signature: [0u8; 64],
        }
    }

    #[test]
    fn test_descriptor_signature_validation() {
        let mut desc = make_desc();

        // 1. None trusted key -> should succeed even with zero signature
        assert!(validate_descriptor_signature(&desc, None).is_ok());

        // 2. Some trusted key, zero signature -> should fail
        let dummy_key = [0u8; 32];
        let res = validate_descriptor_signature(&desc, Some(&dummy_key));
        assert!(res.is_err());
        if let Err(e) = res {
            assert!(e.to_string().contains("no signature") || e.to_string().contains("all-zero"));
        }

        // 3. Some trusted key, non-zero invalid signature -> should fail
        desc.signature = [1u8; 64];
        let res = validate_descriptor_signature(&desc, Some(&dummy_key));
        assert!(res.is_err());
    }
}
