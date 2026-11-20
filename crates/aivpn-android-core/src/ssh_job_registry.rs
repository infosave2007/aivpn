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

use std::sync::OnceLock;

use aivpn_common::ssh_install::job_registry::JobRegistry as SharedRegistry;
use aivpn_common::ssh_install::job_registry::PollOutcome as SharedPoll;

/// Outcome of a single [`JobRegistry::poll`] call. See the module doc for the
/// exact Kotlin-visible semantics each variant maps to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    /// One queued event, in FIFO order.
    Event(String),
    /// Queue is empty, job still running.
    Pending,
    /// Queue is empty, job finished ([`JobRegistry::mark_done`] was called).
    Done,
    /// No job registered under this handle (never created, or already freed).
    NotFound,
}

/// The handle-keyed job store. Exists as a plain struct (rather than only
/// free functions over a single process-global instance) so the unit tests
/// below can each construct their own isolated registry instead of sharing
/// process-global state across `#[test]` threads.
///
/// Хранение и ограничения очереди находятся в
/// [`aivpn_common::ssh_install::job_registry`]. Здесь сохранены имена методов
/// JNI: `push_event` и `poll` без ограничения буфера.
pub struct JobRegistry {
    inner: SharedRegistry,
}

impl JobRegistry {
    /// Handles start at 1 (0 is never issued, so callers can't confuse a
    /// freshly-zeroed Kotlin `Long` field with a real handle).
    pub fn new() -> Self {
        Self {
            inner: SharedRegistry::new(),
        }
    }

    /// Registers a new empty, not-done job and returns its handle.
    pub fn create(&self) -> i64 {
        self.inner.create()
    }

    /// Appends `event_json` to `handle`'s queue. A no-op if `handle` is
    /// unknown (already freed, or never created) — the background job thread
    /// has no way to observe a `sshInstallFree` race and must not panic on
    /// one.
    pub fn push_event(&self, handle: i64, event_json: String) {
        self.inner.push(handle, event_json);
    }

    /// Marks `handle`'s job as finished — once its queue drains, [`Self::poll`]
    /// starts returning [`PollOutcome::Done`] instead of
    /// [`PollOutcome::Pending`]. A no-op if `handle` is unknown.
    pub fn mark_done(&self, handle: i64) {
        self.inner.mark_done(handle);
    }

    /// Pops and returns the next queued event for `handle`, or reports
    /// pending/done/not-found per the module doc. JNI delivers the whole
    /// string, so there is no byte cap and no peek.
    pub fn poll(&self, handle: i64) -> PollOutcome {
        match self.inner.poll_next(handle) {
            SharedPoll::Event(event) => PollOutcome::Event(event),
            SharedPoll::Pending => PollOutcome::Pending,
            SharedPoll::Done => PollOutcome::Done,
            SharedPoll::NotFound => PollOutcome::NotFound,
            // `poll_next` читает событие целиком и не возвращает этот вариант.
            SharedPoll::NeedsCapacity(_) => PollOutcome::Pending,
        }
    }

    /// Removes `handle`'s job entirely. Returns `true` if a job was actually
    /// removed, `false` if `handle` was already unknown. The background job
    /// thread (if the caller freed a handle before the thread finished) is
    /// unaffected — it only ever calls [`Self::push_event`]/[`Self::mark_done`],
    /// both no-ops against a missing handle; per the caller-facing contract
    /// there is no cancellation, the SSH/install work simply runs to
    /// completion in the background with its output now discarded.
    pub fn free(&self, handle: i64) -> bool {
        self.inner.free(handle)
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

    #[test]
    fn overflow_bounds_old_lines_and_keeps_finished_connection_key() {
        let reg = JobRegistry::new();
        let handle = reg.create();
        let line = format!("{{\"line\":\"{}\",\"type\":\"line\"}}", "x".repeat(4096));
        for _ in 0..1000 {
            reg.push_event(handle, line.clone());
        }
        let key = format!("aivpn://{}", "k".repeat(300_000));
        let finished = serde_json::json!({
            "connection_key": &key,
            "exit_code": 0,
            "type": "finished"
        })
        .to_string();
        reg.push_event(handle, finished);

        let mut events = Vec::new();
        loop {
            match reg.poll(handle) {
                PollOutcome::Event(event) => events.push(event),
                PollOutcome::Pending => break,
                other => panic!("неожиданный исход опроса: {other:?}"),
            }
        }

        let discarded_bytes: usize = events
            .iter()
            .filter(|event| !event.contains(&key))
            .map(String::len)
            .sum();
        assert!(
            events.len() <= 256,
            "очередь событий не ограничена по количеству: {}",
            events.len()
        );
        assert!(
            discarded_bytes <= 256 * 1024,
            "очередь событий не ограничена по байтам: {discarded_bytes}"
        );
        let finished = events.iter().find(|event| {
            serde_json::from_str::<serde_json::Value>(event)
                .ok()
                .is_some_and(|value| {
                    value.get("type").and_then(|kind| kind.as_str()) == Some("finished")
                        && value.get("connection_key").and_then(|item| item.as_str())
                            == Some(key.as_str())
                })
        });
        assert!(
            finished.is_some(),
            "финальное Finished вместе с connection_key потеряно"
        );
        let notices = events
            .iter()
            .filter(|event| event.contains("журнал установки сокращен"))
            .count();
        assert_eq!(
            notices, 1,
            "о потере старых строк должно остаться одно событие журнала, получено {notices}"
        );
        for event in &events {
            serde_json::from_str::<serde_json::Value>(event)
                .unwrap_or_else(|err| panic!("событие перестало быть JSON: {err}: {event}"));
        }
    }

    #[test]
    fn oversized_line_is_cut_without_breaking_json() {
        let reg = JobRegistry::new();
        let handle = reg.create();
        let original = serde_json::json!({
            "line": "ж".repeat(20_000),
            "type": "line"
        })
        .to_string();
        assert!(original.len() > 16 * 1024);
        reg.push_event(handle, original.clone());
        let PollOutcome::Event(event) = reg.poll(handle) else {
            panic!("обрезанная строка не вернулась из очереди");
        };
        assert!(
            event.len() <= 16 * 1024,
            "длинная строка не обрезана: {} байт",
            event.len()
        );
        let parsed: serde_json::Value = serde_json::from_str(&event)
            .unwrap_or_else(|err| panic!("обрезание сломало JSON: {err}: {event}"));
        assert_eq!(parsed["type"], "line");
        let mut end = 16 * 1024;
        while !original.is_char_boundary(end) {
            end -= 1;
        }
        assert!(serde_json::from_str::<serde_json::Value>(&original[..end]).is_err());
    }
}
