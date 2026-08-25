//! Pure job-registry/event-queue mechanics behind the SSH-install JNI bridge
//! (`sshInstallStart` / `sshInstallPoll` / `sshInstallFree` in `lib.rs`).
//!
//! No JNI, no SSH, no async here on purpose — this is a plain in-memory store
//! keyed by an opaque `i64` handle, so the handle lifecycle (create → push
//! events → mark done → poll drains → free) is unit-testable without a JNI
//! runtime or a live SSH server. `lib.rs`'s `sshInstallStart` spawns a plain
//! `std::thread` that drives `aivpn_common::ssh_install::run_install` and
//! calls [`push_event`]/[`mark_done`] from inside its `on_event` callback and
//! after it returns; `sshInstallPoll` calls [`poll`] on an arbitrary JNI
//! caller thread.
//!
//! # Poll semantics (mirrored 1:1 by the JNI layer in `lib.rs`)
//!
//! [`poll`] returns a [`PollOutcome`], which the JNI wrapper maps to a
//! nullable Kotlin `String?`:
//!  - [`PollOutcome::Event`] → the next queued event JSON string.
//!  - [`PollOutcome::Pending`] → Kotlin `null` — the queue is empty but the
//!    job is still running; poll again later.
//!  - [`PollOutcome::Done`] → Kotlin `""` — the queue is empty AND the job
//!    has finished; safe to call `sshInstallFree` now.
//!  - [`PollOutcome::NotFound`] → Kotlin `""` — same wire value as `Done`
//!    (an unknown/already-freed handle has nothing further to report), but
//!    kept as a distinct variant here so a caller bug (double-poll after
//!    free, wrong handle) is visible to Rust-side tests/logs even though
//!    Kotlin can't tell it apart from `Done` on the wire.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Mutex, OnceLock};

/// Outcome of a single [`poll`] call. See the module doc for the exact
/// Kotlin-visible semantics each variant maps to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    /// One queued event, in FIFO order.
    Event(String),
    /// Queue is empty, job still running.
    Pending,
    /// Queue is empty, job finished ([`mark_done`] was called).
    Done,
    /// No job registered under this handle (never created, or already freed).
    NotFound,
}

struct Job {
    queue: VecDeque<String>,
    done: bool,
}

/// The handle-keyed job store. Exists as a plain struct (rather than only
/// free functions over a single process-global instance) so the unit tests
/// below can each construct their own isolated registry instead of sharing
/// process-global state across `#[test]` threads.
pub struct JobRegistry {
    next_handle: AtomicI64,
    jobs: Mutex<HashMap<i64, Job>>,
}

impl JobRegistry {
    /// Handles start at 1 (0 is never issued, so callers can't confuse a
    /// freshly-zeroed Kotlin `Long` field with a real handle).
    pub fn new() -> Self {
        Self {
            next_handle: AtomicI64::new(1),
            jobs: Mutex::new(HashMap::new()),
        }
    }

    /// Registers a new empty, not-done job and returns its handle.
    pub fn create(&self) -> i64 {
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.jobs.lock().unwrap_or_else(|e| e.into_inner()).insert(
            handle,
            Job {
                queue: VecDeque::new(),
                done: false,
            },
        );
        handle
    }

    /// Appends `event_json` to `handle`'s queue. A no-op if `handle` is
    /// unknown (already freed, or never created) — the background job thread
    /// has no way to observe a `sshInstallFree` race and must not panic on
    /// one.
    pub fn push_event(&self, handle: i64, event_json: String) {
        if let Some(job) = self
            .jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&handle)
        {
            job.queue.push_back(event_json);
        }
    }

    /// Marks `handle`'s job as finished — once its queue drains, [`poll`]
    /// starts returning [`PollOutcome::Done`] instead of
    /// [`PollOutcome::Pending`]. A no-op if `handle` is unknown.
    pub fn mark_done(&self, handle: i64) {
        if let Some(job) = self
            .jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&handle)
        {
            job.done = true;
        }
    }

    /// Pops and returns the next queued event for `handle`, or reports
    /// pending/done/not-found per the module doc.
    pub fn poll(&self, handle: i64) -> PollOutcome {
        let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        match jobs.get_mut(&handle) {
            None => PollOutcome::NotFound,
            Some(job) => match job.queue.pop_front() {
                Some(event) => PollOutcome::Event(event),
                None if job.done => PollOutcome::Done,
                None => PollOutcome::Pending,
            },
        }
    }

    /// Removes `handle`'s job entirely. Returns `true` if a job was actually
    /// removed, `false` if `handle` was already unknown. The background job
    /// thread (if the caller freed a handle before the thread finished) is
    /// unaffected — it only ever calls [`push_event`]/[`mark_done`], both
    /// no-ops against a missing handle; per the caller-facing contract there
    /// is no cancellation, the SSH/install work simply runs to completion in
    /// the background with its output now discarded.
    pub fn free(&self, handle: i64) -> bool {
        self.jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&handle)
            .is_some()
    }
}

impl Default for JobRegistry {
    fn default() -> Self {
        Self::new()
    }
}

static REGISTRY: OnceLock<JobRegistry> = OnceLock::new();

/// The process-global registry backing the `sshInstall*` JNI exports.
pub fn registry() -> &'static JobRegistry {
    REGISTRY.get_or_init(JobRegistry::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_start_at_one_and_increment() {
        let reg = JobRegistry::new();
        assert_eq!(reg.create(), 1);
        assert_eq!(reg.create(), 2);
        assert_eq!(reg.create(), 3);
    }

    #[test]
    fn poll_pending_when_empty_and_not_done() {
        let reg = JobRegistry::new();
        let h = reg.create();
        assert_eq!(reg.poll(h), PollOutcome::Pending);
    }

    #[test]
    fn poll_returns_events_fifo_then_pending_again() {
        let reg = JobRegistry::new();
        let h = reg.create();
        reg.push_event(h, "a".to_string());
        reg.push_event(h, "b".to_string());
        assert_eq!(reg.poll(h), PollOutcome::Event("a".to_string()));
        assert_eq!(reg.poll(h), PollOutcome::Event("b".to_string()));
        assert_eq!(reg.poll(h), PollOutcome::Pending);
    }

    #[test]
    fn poll_done_only_after_queue_drains() {
        let reg = JobRegistry::new();
        let h = reg.create();
        reg.push_event(h, "a".to_string());
        reg.mark_done(h);
        // Queued event must be delivered before the Done signal, even though
        // the job is already marked done.
        assert_eq!(reg.poll(h), PollOutcome::Event("a".to_string()));
        assert_eq!(reg.poll(h), PollOutcome::Done);
        // Done is sticky/repeatable — polling again must not panic or flip
        // back to Pending.
        assert_eq!(reg.poll(h), PollOutcome::Done);
    }

    #[test]
    fn poll_unknown_handle_is_not_found() {
        let reg = JobRegistry::new();
        assert_eq!(reg.poll(999), PollOutcome::NotFound);
    }

    #[test]
    fn push_event_and_mark_done_on_unknown_handle_are_noops() {
        let reg = JobRegistry::new();
        // Must not panic.
        reg.push_event(999, "x".to_string());
        reg.mark_done(999);
        assert_eq!(reg.poll(999), PollOutcome::NotFound);
    }

    #[test]
    fn free_removes_job_and_reports_whether_one_existed() {
        let reg = JobRegistry::new();
        let h = reg.create();
        assert!(reg.free(h));
        assert!(
            !reg.free(h),
            "second free of the same handle must report false"
        );
        assert_eq!(reg.poll(h), PollOutcome::NotFound);
    }

    #[test]
    fn free_unknown_handle_reports_false() {
        let reg = JobRegistry::new();
        assert!(!reg.free(42));
    }

    #[test]
    fn process_global_registry_is_reachable_and_stable() {
        let h1 = registry().create();
        let h2 = registry().create();
        assert_ne!(h1, h2);
        // Same underlying instance across calls.
        registry().push_event(h1, "x".to_string());
        assert_eq!(registry().poll(h1), PollOutcome::Event("x".to_string()));
        registry().free(h1);
        registry().free(h2);
    }
}
