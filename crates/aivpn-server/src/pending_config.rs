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
use parking_lot::{Mutex, MutexGuard};

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
    /// Serializes the complete read/write/register transaction for a heavy
    /// config apply with confirmation and timeout rollback. The map alone
    /// cannot protect the target file: REST and tunnel requests may mutate
    /// the same path concurrently, while the cleanup task can restore it.
    mutation_lock: Mutex<()>,
}

impl PendingConfigManager {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
            mutation_lock: Mutex::new(()),
        }
    }

    /// Acquire the transaction lock used by apply and rollback callers while
    /// they also touch a target file.
    pub(crate) fn lock_mutation(&self) -> MutexGuard<'_, ()> {
        self.mutation_lock.lock()
    }

    /// Register a newly-applied heavy change.
    ///
    /// **Supersedes any existing unconfirmed entry for the SAME
    /// `target_path`.** Without this, two chained applies to one file
    /// before either is confirmed (e.g. active-mask A, then active-mask B
    /// before confirming A) would track two independent `PendingConfig`s
    /// against the same path. If the admin then confirms only the newer
    /// one, the OLDER entry is still sitting in the map — when ITS
    /// deadline passes, the sweep task (`gateway.rs`'s cleanup task) would
    /// blindly restore ITS `prior` (an intermediate value, not even the
    /// true original), silently clobbering the change the admin already
    /// confirmed. Superseding instead carries the OLDER entry's `prior`
    /// forward onto the new one (so rollback always restores the TRUE
    /// pre-chain original, not an intermediate step) and drops the older
    /// token entirely, so there is only ever one live token — and one
    /// correct rollback value — per `target_path`.
    pub fn begin(&self, pending: PendingConfig) {
        let guard = self.lock_mutation();
        self.begin_locked(pending, &guard);
    }

    /// [`Self::begin`] for callers already holding the mutation lock across
    /// the target-file read/write transaction.
    pub(crate) fn begin_locked(&self, mut pending: PendingConfig, _guard: &MutexGuard<'_, ()>) {
        // Deliberately NOT `if let Some(tok) = self.inner.iter().find(...) {
        // self.inner.remove(&tok) }` — under Rust 2021's temporary-lifetime
        // rules, a temporary created in an `if let` scrutinee (here,
        // `DashMap::iter()`'s internal shard guard) lives until the END of
        // the `if let` body, not just the condition. `.remove()` on the SAME
        // shard inside that body would then deadlock waiting for a write
        // lock the still-alive read guard from `.iter()` never releases
        // (the classic DashMap `if let`/`match` deadlock footgun). Binding
        // to an owned `let` first forces the iterator (and its shard guard)
        // to drop at the end of THIS statement, before `.remove()` ever
        // runs.
        let superseded_token: Option<String> = self
            .inner
            .iter()
            .find(|e| e.value().target_path == pending.target_path)
            .map(|e| e.key().clone());
        if let Some(token) = superseded_token {
            if let Some((_, superseded)) = self.inner.remove(&token) {
                pending.prior = superseded.prior;
            }
        }
        self.inner.insert(pending.token.clone(), pending);
    }

    /// Confirm a pending change by token: removes it from the map (a
    /// confirmed change has nothing left to track — the new value is now
    /// permanent) and returns whether a matching, still-tracked entry was
    /// found. Returns `false` for an unknown token OR one that already
    /// expired-and-was-swept (both surface as "not found" to the caller —
    /// see `mgmt_service::confirm_config`).
    pub fn confirm(&self, token: &str) -> bool {
        self.confirm_and_take(token).is_some()
    }

    /// [`Self::confirm`] variant that also returns the confirmed entry, so a
    /// caller can tell WHAT was confirmed (e.g. gate a live-apply side effect
    /// on the confirmed change's `target_path` — confirming a mask override
    /// must not take an unrelated, still-pending `server.json` exit-node
    /// change live).
    pub fn confirm_and_take(&self, token: &str) -> Option<PendingConfig> {
        let _guard = self.lock_mutation();
        self.inner.remove(token).map(|(_, v)| v)
    }

    /// True when a still-pending (unconfirmed, unswept) change targets
    /// `path`. Lets a caller that wraps a whole `mgmt_service::dispatch`
    /// detect "THIS request confirmed a change to that file" as
    /// pending-before ∧ gone-after.
    pub fn has_pending_for_path(&self, path: &Path) -> bool {
        let _guard = self.lock_mutation();
        self.inner.iter().any(|e| e.value().target_path == path)
    }

    /// Sweep every tracked entry: remove and return every unconfirmed
    /// entry whose deadline has passed as of `now`. Confirmed entries are
    /// never returned (they were already removed by `confirm()`); a token
    /// already returned by a previous `tick()` call is gone from the map
    /// and so is never returned twice.
    pub fn tick(&self, now: Instant) -> Vec<PendingConfig> {
        let guard = self.lock_mutation();
        self.tick_locked(now, &guard)
    }

    /// [`Self::tick`] for the cleanup task, which keeps the same guard held
    /// until every returned entry has been restored on disk.
    pub(crate) fn tick_locked(
        &self,
        now: Instant,
        _guard: &MutexGuard<'_, ()>,
    ) -> Vec<PendingConfig> {
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
        let _guard = self.lock_mutation();
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        let _guard = self.lock_mutation();
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
    fn manager_begin_waits_for_an_in_progress_file_transaction() {
        let start = Instant::now();
        let mgr = std::sync::Arc::new(PendingConfigManager::new());
        let transaction = mgr.lock_mutation();
        let worker_mgr = mgr.clone();
        let (attempted_tx, attempted_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();

        let worker = std::thread::spawn(move || {
            attempted_tx.send(()).unwrap();
            worker_mgr.begin(pc(start, Duration::from_secs(120)));
            done_tx.send(()).unwrap();
        });

        attempted_rx.recv().unwrap();
        assert!(
            matches!(
                done_rx.recv_timeout(Duration::from_millis(50)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ),
            "begin must not register while another caller is mutating the target file"
        );

        drop(transaction);
        done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("begin should complete after the file transaction releases its lock");
        worker.join().unwrap();
        assert_eq!(mgr.len(), 1);
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
    fn manager_begin_supersedes_earlier_unconfirmed_entry_for_the_same_path() {
        // Regression for a real double-apply/rollback-timeout bug: applying
        // mask A, then (before confirming) applying mask B to the SAME
        // target_path, then confirming ONLY the second apply, must leave
        // NOTHING pending for that path — in particular the first apply's
        // token must not survive to roll back over the confirmed change
        // once ITS OWN deadline (measured from the first apply) passes.
        let start = Instant::now();
        let mgr = PendingConfigManager::new();
        let path = PathBuf::from("/tmp/aivpn-test-supersede.mask");

        mgr.begin(PendingConfig::begin(
            "tok-a".into(),
            path.clone(),
            Some(b"original".to_vec()),
            "active mask alice -> maskA".into(),
            start,
            Duration::from_secs(120),
        ));
        mgr.begin(PendingConfig::begin(
            "tok-b".into(),
            path.clone(),
            Some(b"maskA".to_vec()), // what the caller re-read after apply A
            "active mask alice -> maskB".into(),
            start + Duration::from_secs(10),
            Duration::from_secs(120),
        ));

        assert_eq!(
            mgr.len(),
            1,
            "superseded tok-a must be dropped, not stacked"
        );
        assert!(!mgr.confirm("tok-a"), "tok-a must no longer be trackable");
        assert!(mgr.confirm("tok-b"), "tok-b (the live entry) must confirm");
        assert!(mgr.is_empty());

        // Ticking well past tok-a's ORIGINAL deadline (start + 120s) must
        // return nothing — there is nothing left to roll back, confirmed
        // or superseded.
        let expired = mgr.tick(start + Duration::from_secs(200));
        assert!(
            expired.is_empty(),
            "a superseded-then-confirmed change must never resurface via tick()"
        );
    }

    #[test]
    fn manager_begin_supersede_carries_forward_the_true_original_prior() {
        // If the SECOND (superseding) apply is left unconfirmed and expires,
        // rollback must restore the ORIGINAL value from before the first
        // apply — not the intermediate value the first apply produced.
        let start = Instant::now();
        let mgr = PendingConfigManager::new();
        let path = PathBuf::from("/tmp/aivpn-test-supersede2.mask");

        mgr.begin(PendingConfig::begin(
            "tok-a".into(),
            path.clone(),
            Some(b"original".to_vec()),
            "active mask alice -> maskA".into(),
            start,
            Duration::from_secs(120),
        ));
        mgr.begin(PendingConfig::begin(
            "tok-b".into(),
            path.clone(),
            Some(b"maskA".to_vec()),
            "active mask alice -> maskB".into(),
            start + Duration::from_secs(10),
            Duration::from_secs(120),
        ));

        let expired = mgr.tick(start + Duration::from_secs(300));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].token(), "tok-b");
        assert_eq!(
            expired[0].rollback_value(),
            Some(b"original".as_slice()),
            "rollback must restore the TRUE original, not the intermediate maskA value"
        );
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

    #[test]
    fn confirm_and_take_returns_the_confirmed_entry_exactly_once() {
        let start = Instant::now();
        let mgr = PendingConfigManager::new();
        mgr.begin(pc(start, Duration::from_secs(120)));

        let confirmed = mgr
            .confirm_and_take("tok-1")
            .expect("confirm_and_take must find the pending token");
        assert_eq!(confirmed.token(), "tok-1");
        assert_eq!(confirmed.target_path(), Path::new("/tmp/aivpn-test.mask"));
        assert!(mgr.is_empty());
        assert!(
            mgr.confirm_and_take("tok-1").is_none(),
            "an already-taken token must not confirm twice"
        );
    }

    #[test]
    fn has_pending_for_path_matches_only_live_entries_targeting_that_path() {
        // Backs the "did THIS request confirm a change to server.json?" gate
        // in the REST/tunnel confirm handlers: pending-before ∧ gone-after.
        let start = Instant::now();
        let mgr = PendingConfigManager::new();
        mgr.begin(pc(start, Duration::from_secs(120))); // /tmp/aivpn-test.mask

        assert!(mgr.has_pending_for_path(Path::new("/tmp/aivpn-test.mask")));
        assert!(!mgr.has_pending_for_path(Path::new("/tmp/other.mask")));

        assert!(mgr.confirm("tok-1"));
        assert!(
            !mgr.has_pending_for_path(Path::new("/tmp/aivpn-test.mask")),
            "a confirmed (removed) entry must no longer report as pending"
        );
    }
}
