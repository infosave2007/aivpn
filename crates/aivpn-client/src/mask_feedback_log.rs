//! §2 crowdsourced blocking feedback — persistent outcome log.
//!
//! The VPN client is recreated on every reconnect (see `main.rs`'s reconnect
//! loop), so an in-memory-only outcome buffer loses all failure history the
//! moment a blocked mask forces a reconnect — exactly the case §2 needs to
//! capture. This module persists the outcome log to a small JSON file under the
//! per-user client state dir (`~/.config/aivpn/mask_feedback.json`, matching how
//! `device.key` and the bootstrap cache are stored) so failures accumulated
//! across several failed attempts survive until the next *successful*
//! connection can report them ("batch failed pre-handshake attempts; report on
//! the next success").
//!
//! Design constraints honored here:
//! - **Per-user path.** Uses `$HOME` (or `%USERPROFILE%` on Windows). When HOME
//!   is unset the log degrades to in-memory only (no path), never panicking.
//! - **Privacy.** Only the base mask *family* id (already collapsed by
//!   `base_mask_family` before it reaches this module) and an **hour-granularity**
//!   timestamp are stored — never finer-grained times, never per-session ids.
//! - **Bounded.** Retained entries are capped (`MAX_ENTRIES`); oldest evicted
//!   first.
//! - **Robust.** A corrupt or missing file yields an empty log rather than an
//!   error — feedback is best-effort telemetry, never load-bearing.
//! - **Single-process concurrency.** Only this process touches the file; the
//!   client instance and the reconnect loop access it sequentially (a client is
//!   dropped before the loop appends a failure, and the next client is created
//!   after), so no cross-process locking is required.

use std::path::PathBuf;

use aivpn_common::mask::current_unix_secs;
use aivpn_common::protocol::MaskOutcome;
use serde::{Deserialize, Serialize};

/// Cap on retained (unreported) outcome entries. Bounded so a long series of
/// failed reconnects can't grow the file unboundedly; oldest evicted first.
pub const MAX_ENTRIES: usize = 128;

/// Default `report_failure_threshold` when the server has not (yet) pushed a
/// `FeedbackConfig`. Kept in sync with the server default in `gateway.rs`.
pub const DEFAULT_FAILURE_THRESHOLD: u8 = 3;
/// Default `report_interval_secs` when the server has not (yet) pushed a
/// `FeedbackConfig`.
pub const DEFAULT_REPORT_INTERVAL_SECS: u32 = 3600;

/// Upper bound on a server-pushed `report_interval_secs` (7 days). A
/// malicious or misconfigured server could otherwise push an arbitrarily
/// large value; clamping keeps the client from silently going years between
/// reports.
pub const MAX_REPORT_INTERVAL_SECS: u32 = 7 * 24 * 3600;
/// Lower bound on a server-pushed `report_interval_secs` (60 s). The interval
/// is the ONLY throttle on how often mask feedback goes out across reconnects,
/// so it doubles as anti-fingerprinting spacing. A malicious server could
/// otherwise push a tiny value (e.g. `1`) to make the client emit a MaskFeedback
/// control message on essentially every reconnect, defeating that spacing;
/// clamping to a sane floor keeps the throttle meaningful.
pub const MIN_REPORT_INTERVAL_SECS: u32 = 60;
/// Upper bound on a server-pushed `report_failure_threshold`. A malicious
/// server pushing an absurdly high threshold would effectively disable
/// failure reporting; clamping keeps the feature meaningfully bounded.
pub const MAX_FAILURE_THRESHOLD: u8 = 10;

/// One recorded outcome: a base mask family, whether that attempt succeeded, and
/// the hour (unix-secs / 3600) it happened. Hour granularity only, by design.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutcomeEntry {
    /// Base mask family id (already collapsed by `base_mask_family`).
    #[serde(rename = "m")]
    pub mask_family: String,
    /// Whether the connection attempt using this mask succeeded.
    #[serde(rename = "s")]
    pub success: bool,
    /// Timestamp rounded to the hour (`current_unix_secs() / 3600`).
    #[serde(rename = "h")]
    pub hour: u64,
}

/// Persisted feedback log. Serialized as `mask_feedback.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskFeedbackLog {
    /// Unreported outcome entries (bounded by `MAX_ENTRIES`).
    #[serde(default)]
    entries: Vec<OutcomeEntry>,
    /// Unix seconds of the last successful feedback send. Used to honor the
    /// server-pushed `report_interval_secs` across reconnects.
    #[serde(default)]
    last_report_unix: u64,
    /// Server-pushed `report_failure_threshold` (persisted so the reconnect
    /// loop can honor it even though the control message arrives on a prior,
    /// now-dropped client instance).
    #[serde(default = "default_failure_threshold")]
    report_failure_threshold: u8,
    /// Server-pushed `report_interval_secs`.
    #[serde(default = "default_report_interval")]
    report_interval_secs: u32,
    /// Filesystem path this log persists to. `None` = in-memory only (HOME
    /// unset). Skipped during (de)serialization.
    #[serde(skip)]
    path: Option<PathBuf>,
}

fn default_failure_threshold() -> u8 {
    DEFAULT_FAILURE_THRESHOLD
}
fn default_report_interval() -> u32 {
    DEFAULT_REPORT_INTERVAL_SECS
}

impl Default for MaskFeedbackLog {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            last_report_unix: 0,
            report_failure_threshold: DEFAULT_FAILURE_THRESHOLD,
            report_interval_secs: DEFAULT_REPORT_INTERVAL_SECS,
            path: None,
        }
    }
}

/// `~/.config/aivpn/mask_feedback.json` (or `%USERPROFILE%\.config\aivpn\...`),
/// matching the `device.key` convention. `None` when HOME/USERPROFILE is unset.
pub fn default_path() -> Option<PathBuf> {
    #[cfg(windows)]
    let home = std::env::var_os("USERPROFILE").map(PathBuf::from)?;
    #[cfg(not(windows))]
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    Some(
        home.join(".config")
            .join("aivpn")
            .join("mask_feedback.json"),
    )
}

impl MaskFeedbackLog {
    /// Load from the default per-user path. A missing or corrupt file yields an
    /// empty log bound to that path so the next `save` recreates it cleanly.
    pub fn load_default() -> Self {
        match default_path() {
            Some(path) => Self::load(path),
            None => Self::default(),
        }
    }

    /// Load from an explicit path. Never fails: corrupt/missing → empty log.
    pub fn load(path: PathBuf) -> Self {
        let mut log = crate::secure_write::read_state_file(&path, 8 * 1024 * 1024)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<MaskFeedbackLog>(&bytes).ok())
            .unwrap_or_default();
        // Enforce the cap on load in case an older/hand-edited file exceeds it.
        if log.entries.len() > MAX_ENTRIES {
            let overflow = log.entries.len() - MAX_ENTRIES;
            log.entries.drain(0..overflow);
        }
        log.path = Some(path);
        log
    }

    /// Number of unreported entries currently buffered.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether there are unreported outcome entries buffered.
    pub fn has_unreported(&self) -> bool {
        !self.entries.is_empty()
    }

    /// Server-pushed failure threshold (or default).
    pub fn failure_threshold(&self) -> u8 {
        self.report_failure_threshold
    }

    /// Server-pushed report interval in seconds (or default).
    pub fn report_interval_secs(&self) -> u32 {
        self.report_interval_secs
    }

    /// Whether enough time has elapsed since the last send to send again.
    pub fn interval_elapsed(&self, now_unix: u64) -> bool {
        now_unix.saturating_sub(self.last_report_unix) >= self.report_interval_secs as u64
    }

    /// Append an outcome for `mask_family` (hour-rounded), enforce the cap, and
    /// persist. `mask_family` must already be collapsed via `base_mask_family`.
    pub fn append(&mut self, mask_family: String, success: bool) {
        let hour = current_unix_secs() / 3600;
        if self.entries.len() >= MAX_ENTRIES {
            self.entries.remove(0);
        }
        self.entries.push(OutcomeEntry {
            mask_family,
            success,
            hour,
        });
        self.save();
    }

    /// Aggregate all unreported entries into per-family `MaskOutcome` counters,
    /// summing success/fail. Does NOT clear them — call `mark_reported` after a
    /// successful send.
    pub fn aggregate_unreported(&self) -> Vec<MaskOutcome> {
        use std::collections::HashMap;
        let mut by_mask: HashMap<&str, (u16, u16)> = HashMap::new();
        for e in &self.entries {
            let counters = by_mask.entry(e.mask_family.as_str()).or_insert((0, 0));
            if e.success {
                counters.0 = counters.0.saturating_add(1);
            } else {
                counters.1 = counters.1.saturating_add(1);
            }
        }
        by_mask
            .into_iter()
            .map(|(mask_id, (success, fail))| MaskOutcome {
                mask_id: mask_id.to_string(),
                success,
                fail,
            })
            .collect()
    }

    /// Clear the reported entries and record the send time, then persist. Call
    /// after `aggregate_unreported`'s result has been successfully sent.
    pub fn mark_reported(&mut self, now_unix: u64) {
        self.entries.clear();
        self.last_report_unix = now_unix;
        self.save();
    }

    /// Update the persisted tuning parameters from a server `FeedbackConfig`
    /// and persist. A `report_interval_secs` of 0 is coerced to the default so
    /// a misconfigured server can't disable spacing entirely; a non-zero value
    /// is clamped into `[MIN_REPORT_INTERVAL_SECS, MAX_REPORT_INTERVAL_SECS]`.
    /// The lower clamp matters as much as the upper one: the interval is the
    /// only throttle across reconnects, so a malicious server pushing `1` would
    /// otherwise defeat the anti-fingerprinting spacing. The failure threshold
    /// is likewise clamped into `[1, MAX_FAILURE_THRESHOLD]`.
    pub fn set_tuning(&mut self, report_failure_threshold: u8, report_interval_secs: u32) {
        self.report_failure_threshold = report_failure_threshold.clamp(1, MAX_FAILURE_THRESHOLD);
        self.report_interval_secs = if report_interval_secs == 0 {
            DEFAULT_REPORT_INTERVAL_SECS
        } else {
            report_interval_secs.clamp(MIN_REPORT_INTERVAL_SECS, MAX_REPORT_INTERVAL_SECS)
        };
        self.save();
    }

    /// Persist to disk (best-effort). Creates the parent dir (0700 on unix).
    /// No-op when `path` is `None` (HOME unset → in-memory only).
    pub fn save(&self) {
        let Some(path) = &self.path else {
            return;
        };
        if let Some(dir) = path.parent() {
            if std::fs::create_dir_all(dir).is_err() {
                return;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        let Ok(json) = serde_json::to_vec(self) else {
            return;
        };
        crate::secure_write::write_status_best_effort(path, &json);
    }
}

/// §2 crowdsourced blocking feedback — persisted regional mask hints.
///
/// `RegionalMaskHints` arrive on a live client instance, but mask selection
/// happens in the reconnect loop (`main.rs`) on a *fresh* client instance one
/// iteration later. Persisting the most recent hints per region to disk lets
/// the loop softly bias the initial mask toward what is currently working in
/// the client's country. Best-effort: corrupt/missing → no hints.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegionalHintsStore {
    /// country_code (as a 2-char string key) → (mask_id, success_rate) list.
    #[serde(default)]
    regions: std::collections::HashMap<String, Vec<(String, f32)>>,
    #[serde(skip)]
    path: Option<PathBuf>,
}

/// `~/.config/aivpn/regional_hints.json`. `None` when HOME/USERPROFILE unset.
pub fn hints_default_path() -> Option<PathBuf> {
    #[cfg(windows)]
    let home = std::env::var_os("USERPROFILE").map(PathBuf::from)?;
    #[cfg(not(windows))]
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    Some(
        home.join(".config")
            .join("aivpn")
            .join("regional_hints.json"),
    )
}

fn country_key(country_code: [u8; 2]) -> String {
    String::from_utf8_lossy(&country_code).to_string()
}

impl RegionalHintsStore {
    pub fn load_default() -> Self {
        match hints_default_path() {
            Some(path) => Self::load(path),
            None => Self::default(),
        }
    }

    pub fn load(path: PathBuf) -> Self {
        let mut store = crate::secure_write::read_state_file(&path, 8 * 1024 * 1024)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<RegionalHintsStore>(&bytes).ok())
            .unwrap_or_default();
        store.path = Some(path);
        store
    }

    /// Store (and persist) the latest hints for one region.
    pub fn set_region(&mut self, country_code: [u8; 2], masks: Vec<(String, f32)>) {
        self.regions.insert(country_key(country_code), masks);
        self.save();
    }

    /// Hints for a region, sorted by descending success rate.
    pub fn for_region(&self, country_code: [u8; 2]) -> Vec<(String, f32)> {
        let mut v = self
            .regions
            .get(&country_key(country_code))
            .cloned()
            .unwrap_or_default();
        v.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        v
    }

    pub fn save(&self) {
        let Some(path) = &self.path else {
            return;
        };
        if let Some(dir) = path.parent() {
            if std::fs::create_dir_all(dir).is_err() {
                return;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        let Ok(json) = serde_json::to_vec(self) else {
            return;
        };
        crate::secure_write::write_status_best_effort(path, &json);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn saving_feedback_and_hints_does_not_overwrite_a_temporary_symlink_target() {
        let dir =
            std::env::temp_dir().join(format!("aivpn-cache-link-{:032x}", rand::random::<u128>()));
        std::fs::create_dir(&dir).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, b"original").unwrap();
        for name in ["feedback.json", "hints.json"] {
            let path = dir.join(name);
            std::os::unix::fs::symlink(&victim, path.with_extension("tmp")).unwrap();
            if name == "feedback.json" {
                MaskFeedbackLog::load(path.clone()).save();
            } else {
                RegionalHintsStore::load(path.clone()).save();
            }
            assert_eq!(std::fs::read(&victim).unwrap(), b"original");
            assert!(path.is_file());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn temp_path(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "aivpn_mask_feedback_test_{}_{}.json",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn load_missing_file_is_empty() {
        let path = temp_path("missing");
        let log = MaskFeedbackLog::load(path);
        assert!(log.is_empty());
        assert_eq!(log.failure_threshold(), DEFAULT_FAILURE_THRESHOLD);
        assert_eq!(log.report_interval_secs(), DEFAULT_REPORT_INTERVAL_SECS);
    }

    #[test]
    fn load_corrupt_file_is_empty() {
        let path = temp_path("corrupt");
        std::fs::write(&path, b"this is not json {{{").unwrap();
        let log = MaskFeedbackLog::load(path.clone());
        assert!(log.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_and_persistence_roundtrip() {
        let path = temp_path("roundtrip");
        {
            let mut log = MaskFeedbackLog::load(path.clone());
            log.append("webrtc_zoom_v3".to_string(), true);
            log.append("webrtc_zoom_v3".to_string(), false);
            log.append("quic_https".to_string(), true);
        }
        // Reload from disk in a fresh instance — history must survive.
        let log = MaskFeedbackLog::load(path.clone());
        assert_eq!(log.len(), 3);
        let mut outcomes = log.aggregate_unreported();
        outcomes.sort_by(|a, b| a.mask_id.cmp(&b.mask_id));
        assert_eq!(outcomes.len(), 2);
        let zoom = outcomes
            .iter()
            .find(|o| o.mask_id == "webrtc_zoom_v3")
            .unwrap();
        assert_eq!(zoom.success, 1);
        assert_eq!(zoom.fail, 1);
        let quic = outcomes.iter().find(|o| o.mask_id == "quic_https").unwrap();
        assert_eq!(quic.success, 1);
        assert_eq!(quic.fail, 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn aggregation_sums_per_family() {
        let path = temp_path("agg");
        let mut log = MaskFeedbackLog::load(path.clone());
        for _ in 0..5 {
            log.append("mask_a".to_string(), true);
        }
        for _ in 0..3 {
            log.append("mask_a".to_string(), false);
        }
        for _ in 0..2 {
            log.append("mask_b".to_string(), false);
        }
        let outcomes = log.aggregate_unreported();
        let a = outcomes.iter().find(|o| o.mask_id == "mask_a").unwrap();
        assert_eq!(a.success, 5);
        assert_eq!(a.fail, 3);
        let b = outcomes.iter().find(|o| o.mask_id == "mask_b").unwrap();
        assert_eq!(b.success, 0);
        assert_eq!(b.fail, 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn mark_reported_clears_and_records_time() {
        let path = temp_path("marked");
        let mut log = MaskFeedbackLog::load(path.clone());
        log.append("mask_a".to_string(), true);
        assert!(!log.is_empty());
        log.mark_reported(10_000);
        assert!(log.is_empty());
        // Reload: cleared state persists, interval-elapsed reflects last send.
        let log = MaskFeedbackLog::load(path.clone());
        assert!(log.is_empty());
        assert!(!log.interval_elapsed(10_000)); // 0 elapsed < interval
        assert!(log.interval_elapsed(10_000 + DEFAULT_REPORT_INTERVAL_SECS as u64));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn cap_evicts_oldest() {
        let path = temp_path("cap");
        let mut log = MaskFeedbackLog::load(path.clone());
        for i in 0..(MAX_ENTRIES + 10) {
            log.append(format!("mask_{i}"), true);
        }
        assert_eq!(log.len(), MAX_ENTRIES);
        // Oldest entries (mask_0..mask_9) evicted; newest retained.
        let outcomes = log.aggregate_unreported();
        assert!(outcomes.iter().all(|o| o.mask_id != "mask_0"));
        assert!(outcomes
            .iter()
            .any(|o| o.mask_id == format!("mask_{}", MAX_ENTRIES + 9)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn regional_hints_roundtrip_and_sorted() {
        let path = temp_path("hints");
        {
            let mut store = RegionalHintsStore::load(path.clone());
            store.set_region(
                *b"DE",
                vec![
                    ("quic_https".to_string(), 0.60),
                    ("webrtc_zoom_v3".to_string(), 0.95),
                ],
            );
        }
        let store = RegionalHintsStore::load(path.clone());
        let de = store.for_region(*b"DE");
        assert_eq!(de.len(), 2);
        // sorted descending by score
        assert_eq!(de[0].0, "webrtc_zoom_v3");
        assert_eq!(de[1].0, "quic_https");
        // unknown region → empty
        assert!(store.for_region(*b"JP").is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn set_tuning_persists_and_coerces() {
        let path = temp_path("tuning");
        let mut log = MaskFeedbackLog::load(path.clone());
        log.set_tuning(5, 0); // interval 0 coerced to default
        assert_eq!(log.failure_threshold(), 5);
        assert_eq!(log.report_interval_secs(), DEFAULT_REPORT_INTERVAL_SECS);
        log.set_tuning(0, 120); // threshold 0 coerced to 1
        assert_eq!(log.failure_threshold(), 1);
        assert_eq!(log.report_interval_secs(), 120);
        // A non-zero interval below the floor is clamped UP to the minimum, so a
        // malicious server pushing `1` can't defeat the anti-fingerprinting
        // spacing (the only throttle across reconnects).
        log.set_tuning(3, 1);
        assert_eq!(log.report_interval_secs(), MIN_REPORT_INTERVAL_SECS);
        // Reload confirms persistence of the clamped value.
        let log = MaskFeedbackLog::load(path.clone());
        assert_eq!(log.failure_threshold(), 3);
        assert_eq!(log.report_interval_secs(), MIN_REPORT_INTERVAL_SECS);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn set_tuning_upper_clamps_malicious_server_values() {
        // A malicious/misconfigured server pushing pathological values must
        // be clamped, not trusted verbatim.
        let path = temp_path("tuning_upper_clamp");
        let mut log = MaskFeedbackLog::load(path.clone());
        log.set_tuning(u8::MAX, u32::MAX);
        assert_eq!(log.failure_threshold(), MAX_FAILURE_THRESHOLD);
        assert_eq!(log.report_interval_secs(), MAX_REPORT_INTERVAL_SECS);
        // Reload confirms the clamped values (not the raw ones) persisted.
        let log = MaskFeedbackLog::load(path.clone());
        assert_eq!(log.failure_threshold(), MAX_FAILURE_THRESHOLD);
        assert_eq!(log.report_interval_secs(), MAX_REPORT_INTERVAL_SECS);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn saved_files_are_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_path("perms_feedback");
        let mut log = MaskFeedbackLog::load(path.clone());
        log.set_tuning(3, 60);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mask_feedback.json must be 0600");
        let _ = std::fs::remove_file(&path);

        let hints_path = temp_path("perms_hints");
        let mut store = RegionalHintsStore::load(hints_path.clone());
        store.set_region(*b"US", vec![("mask_a".to_string(), 0.5)]);
        let mode = std::fs::metadata(&hints_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "regional_hints.json must be 0600");
        let _ = std::fs::remove_file(&hints_path);
    }
}
