//! Apply-with-rollback ("commit-confirmed") for heavy management-config
//! changes — P1.5 of
//! `docs/superpowers/plans/2026-07-22-phase-a-admin-core.md`.
//!
//! Modeled on network-gear "commit confirmed": a heavy setting (one that
//! could plausibly lock an admin out — wrong active mask, wrong port,
//! wrong exit node) is applied immediately, but the PRIOR value is kept
//! and a deadline starts. If the admin doesn't re-confirm the change
//! within the window over a still-working session, a background sweep
//! rolls it back automatically. If confirmed, the change is permanent
//! and the prior value is discarded.
//!
//! **Deliberately storage-agnostic and free of wall-clock reads.** This
//! module never calls `Instant::now()` itself — every timing decision
//! (`begin`, `is_expired`, `tick`) takes `now: Instant` as an explicit
//! argument, so the pure expiry logic is fully deterministic under test.
//! It also never performs file I/O: a `PendingConfig` only carries enough
//! information (`target_path` + `prior` bytes) for the CALLER to perform
//! the actual restore — see `mgmt_service::apply_heavy` (which persists
//! the new value and registers the pending entry) and `gateway.rs`'s
//! periodic sweep task (which calls `tick()` and, for every entry it gets
//! back, writes `prior` back to `target_path` — or removes the file when
//! `prior` is `None`, meaning it didn't exist before `begin()`).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Default confirm window: how long an applied heavy change stays
/// "pending" before an unconfirmed change is auto-rolled-back by the
/// gateway's sweep task.
pub const PENDING_CONFIG_TIMEOUT: Duration = Duration::from_secs(120);

/// One in-flight "apply now, confirm within the window, else rollback"
/// change.
#[derive(Debug, Clone)]
pub struct PendingConfig {
    token: String,
    /// The file the change was written to — what the rollback restores.
    target_path: PathBuf,
    /// The file's content immediately before this change was applied.
    /// `None` means the file did not exist before — rollback deletes it.
    prior: Option<Vec<u8>>,
    /// Human-readable description of what changed, for audit logging.
    descriptor: String,
    expires_at: Instant,
    confirmed: bool,
}

impl PendingConfig {
    /// Begin tracking a newly-applied heavy change. `now` is the caller's
    /// observation of the current time (real `Instant::now()` in
    /// production, an injected fixed value in tests); `timeout` is
    /// typically [`PENDING_CONFIG_TIMEOUT`].
    pub fn begin(
        token: String,
        target_path: PathBuf,
        prior: Option<Vec<u8>>,
        descriptor: String,
        now: Instant,
        timeout: Duration,
    ) -> Self {
        Self {
            token,
            target_path,
            prior,
            descriptor,
            expires_at: now + timeout,
            confirmed: false,
        }
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn target_path(&self) -> &Path {
        &self.target_path
    }

    pub fn descriptor(&self) -> &str {
        &self.descriptor
    }

    /// The value to restore on rollback: `None` means "the file did not
    /// exist before `begin()` — delete it", `Some(bytes)` means "write
    /// these bytes back".
    pub fn rollback_value(&self) -> Option<&[u8]> {
        self.prior.as_deref()
    }

    /// Mark this change as confirmed — it must never be rolled back after
    /// this, even if `is_expired` would otherwise say so past the
    /// deadline (kept for `PendingConfig`-level unit tests; the manager
    /// additionally removes confirmed entries from its map immediately so
    /// a live server never needs to rely on this flag alone).
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    /// True when `now` has passed the deadline AND the change was never
    /// confirmed. A confirmed change is never "expired" — it has nothing
    /// left to roll back.
    pub fn is_expired(&self, now: Instant) -> bool {
        !self.confirmed && now >= self.expires_at
    }
}

/// Tracks every in-flight [`PendingConfig`] by token, keyed for O(1)
/// confirm-by-token and swept by `tick()`. Cheap to clone (wraps an
/// `Arc`-free `DashMap` directly — callers share it behind their own
/// `Arc`, matching every other cross-task map on `Gateway`, e.g.
/// `mgmt_request_throttle`).
#[derive(Default)]
pub struct PendingConfigManager {
    inner: DashMap<String, PendingConfig>,
}

impl PendingConfigManager {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    /// Register a newly-applied heavy change. Overwrites any prior entry
    /// with the same token (tokens are expected to be unique per call —
    /// see `mgmt_service::apply_heavy`'s token generation).
    pub fn begin(&self, pending: PendingConfig) {
        self.inner.insert(pending.token.clone(), pending);
    }

    /// Confirm a pending change by token: removes it from the map (a
    /// confirmed change has nothing left to track — the new value is now
    /// permanent) and returns whether a matching, still-tracked entry was
    /// found. Returns `false` for an unknown token OR one that already
    /// expired-and-was-swept (both surface as "not found" to the caller —
    /// see `mgmt_service::confirm_config`).
    pub fn confirm(&self, token: &str) -> bool {
        self.inner.remove(token).is_some()
    }

    /// Sweep every tracked entry: remove and return every unconfirmed
    /// entry whose deadline has passed as of `now`. Confirmed entries are
    /// never returned (they were already removed by `confirm()`); a token
    /// already returned by a previous `tick()` call is gone from the map
    /// and so is never returned twice.
    pub fn tick(&self, now: Instant) -> Vec<PendingConfig> {
        let expired_tokens: Vec<String> = self
            .inner
            .iter()
            .filter(|entry| entry.value().is_expired(now))
            .map(|entry| entry.key().clone())
            .collect();
        expired_tokens
            .into_iter()
            .filter_map(|token| self.inner.remove(&token).map(|(_, v)| v))
            .collect()
    }

    /// Number of currently-tracked (unconfirmed, unexpired-as-of-last-tick)
    /// pending changes — test/observability helper.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pc(now: Instant, timeout: Duration) -> PendingConfig {
        PendingConfig::begin(
            "tok-1".into(),
            PathBuf::from("/tmp/aivpn-test.mask"),
            Some(b"old-mask".to_vec()),
            "active mask alice -> new-mask".into(),
            now,
            timeout,
        )
    }

    #[test]
    fn not_expired_before_timeout_expired_after() {
        let start = Instant::now();
        let timeout = Duration::from_secs(120);
        let entry = pc(start, timeout);

        assert!(!entry.is_expired(start));
        assert!(!entry.is_expired(start + Duration::from_secs(119)));
        assert!(entry.is_expired(start + Duration::from_secs(120)));
        assert!(entry.is_expired(start + Duration::from_secs(121)));
    }

    #[test]
    fn confirm_prevents_expiry() {
        let start = Instant::now();
        let timeout = Duration::from_secs(120);
        let mut entry = pc(start, timeout);
        entry.confirm();

        assert!(entry.is_confirmed());
        assert!(
            !entry.is_expired(start + Duration::from_secs(1000)),
            "a confirmed entry must never report expired, however long after the deadline"
        );
    }

    #[test]
    fn rollback_value_returns_prior_bytes_or_none_for_new_file() {
        let start = Instant::now();
        let with_prior = pc(start, Duration::from_secs(120));
        assert_eq!(with_prior.rollback_value(), Some(b"old-mask".as_slice()));

        let created_fresh = PendingConfig::begin(
            "tok-2".into(),
            PathBuf::from("/tmp/aivpn-test2.mask"),
            None,
            "active mask bob -> first-mask".into(),
            start,
            Duration::from_secs(120),
        );
        assert_eq!(created_fresh.rollback_value(), None);
    }

    // ── PendingConfigManager ─────────────────────────────────────────────

    #[test]
    fn manager_confirm_prevents_rollback_on_later_tick() {
        let start = Instant::now();
        let mgr = PendingConfigManager::new();
        mgr.begin(pc(start, Duration::from_secs(120)));

        assert!(mgr.confirm("tok-1"), "confirm must find the pending token");

        let expired = mgr.tick(start + Duration::from_secs(1000));
        assert!(
            expired.is_empty(),
            "a confirmed token must never be returned by tick(), even long past its deadline"
        );
        assert!(mgr.is_empty());
    }

    #[test]
    fn manager_tick_returns_unconfirmed_expired_token_exactly_once() {
        let start = Instant::now();
        let mgr = PendingConfigManager::new();
        mgr.begin(pc(start, Duration::from_secs(120)));

        // Not expired yet.
        assert!(mgr.tick(start + Duration::from_secs(60)).is_empty());
        assert_eq!(mgr.len(), 1, "still-live entry must remain tracked");

        // Past the deadline: returned exactly once.
        let expired = mgr.tick(start + Duration::from_secs(121));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].token(), "tok-1");
        assert_eq!(expired[0].rollback_value(), Some(b"old-mask".as_slice()));

        // A second tick sees nothing more — already swept.
        let again = mgr.tick(start + Duration::from_secs(200));
        assert!(again.is_empty());
        assert!(mgr.is_empty());
    }

    #[test]
    fn manager_confirm_unknown_token_returns_false() {
        let mgr = PendingConfigManager::new();
        assert!(!mgr.confirm("does-not-exist"));
    }

    #[test]
    fn manager_tick_leaves_other_unrelated_entries_untouched() {
        let start = Instant::now();
        let mgr = PendingConfigManager::new();
        mgr.begin(pc(start, Duration::from_secs(120))); // "tok-1", expires at +120s
        mgr.begin(PendingConfig::begin(
            "tok-2".into(),
            PathBuf::from("/tmp/aivpn-test3.mask"),
            None,
            "active mask carol -> other-mask".into(),
            start,
            Duration::from_secs(300), // expires later
        ));

        let expired = mgr.tick(start + Duration::from_secs(121));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].token(), "tok-1");
        assert_eq!(
            mgr.len(),
            1,
            "tok-2 (not yet expired) must still be tracked"
        );
    }
}
