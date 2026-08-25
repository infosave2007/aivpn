//! Job registry + event queue mechanics backing `aivpn_ssh_install_start` /
//! `aivpn_ssh_install_poll` / `aivpn_ssh_install_free` (see `super`). Deliberately has no
//! SSH/async/FFI awareness — just the push / peek-pop-or-needs-capacity / done / free
//! bookkeeping — so it's cheap to unit-test without a live SSH server or raw pointers.
//!
//! Buffer contract mirrors the written-len-or-needed-len convention shared by
//! `aivpn_mgmt_request` / `aivpn_qr_png` (see `lib.rs`), with one difference: on a
//! too-small buffer the queued event is left in place (peeked, not popped) rather than
//! reformatted on the next call, so a caller that retries with a bigger buffer gets the
//! exact same event instead of racing a background thread that might enqueue something
//! ahead of it in between.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;

struct Job {
    events: VecDeque<String>,
    done: bool,
}

/// Outcome of [`JobRegistry::poll`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    /// The next queued event (already popped from the queue), `<= cap` bytes.
    Event(String),
    /// The queue is empty but the job is still running — poll again later.
    Pending,
    /// The queue is empty and the job has finished; no more events will ever arrive.
    Done,
    /// The next queued event doesn't fit in `cap` bytes. Left in the queue (NOT popped) —
    /// the wrapped value is the needed length, always `> cap`.
    NeedsCapacity(usize),
    /// No job is registered under this handle (never issued, or already freed).
    NotFound,
}

/// In-memory registry of running SSH-install jobs, keyed by an opaque monotonically
/// increasing handle starting at 1 (so `<= 0` is uniformly "not a valid handle" at the FFI
/// layer, matching the crate's existing `-1` "invalid" convention).
pub struct JobRegistry {
    jobs: Mutex<HashMap<i64, Job>>,
    next_handle: AtomicI64,
}

impl JobRegistry {
    pub fn new() -> Self {
        Self {
            jobs: Mutex::new(HashMap::new()),
            next_handle: AtomicI64::new(1),
        }
    }

    /// Registers a new, empty job and returns its handle.
    pub fn create(&self) -> i64 {
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.jobs.lock().unwrap_or_else(|e| e.into_inner()).insert(
            handle,
            Job {
                events: VecDeque::new(),
                done: false,
            },
        );
        handle
    }

    /// Appends an event to `handle`'s queue. No-op if the handle is unknown (already freed
    /// while the worker thread producing events was still running — see
    /// `aivpn_ssh_install_free`'s doc comment: this is the expected, leak-free outcome, not
    /// an error).
    pub fn push(&self, handle: i64, event: String) {
        if let Some(job) = self
            .jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&handle)
        {
            job.events.push_back(event);
        }
    }

    /// Marks `handle`'s job finished — no more events will ever be pushed for it. No-op if
    /// the handle is unknown.
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

    /// Peek-pop-or-needs-capacity poll — see [`PollOutcome`]. `cap` is the caller's
    /// available buffer size in bytes.
    pub fn poll(&self, handle: i64, cap: usize) -> PollOutcome {
        let mut guard = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        let Some(job) = guard.get_mut(&handle) else {
            return PollOutcome::NotFound;
        };
        match job.events.front() {
            Some(event) if event.len() <= cap => {
                PollOutcome::Event(job.events.pop_front().expect("front() just returned Some"))
            }
            Some(event) => PollOutcome::NeedsCapacity(event.len()),
            None if job.done => PollOutcome::Done,
            None => PollOutcome::Pending,
        }
    }

    /// Removes `handle`'s job from the registry. Returns `true` if it existed.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_handle_is_not_found() {
        let reg = JobRegistry::new();
        assert_eq!(reg.poll(999, 4096), PollOutcome::NotFound);
        assert!(!reg.free(999));
    }

    #[test]
    fn create_returns_increasing_handles_starting_at_one() {
        let reg = JobRegistry::new();
        let h1 = reg.create();
        let h2 = reg.create();
        assert_eq!(h1, 1);
        assert_eq!(h2, 2);
    }

    #[test]
    fn empty_queue_not_done_is_pending() {
        let reg = JobRegistry::new();
        let h = reg.create();
        assert_eq!(reg.poll(h, 4096), PollOutcome::Pending);
    }

    #[test]
    fn push_then_poll_with_enough_capacity_pops_the_event() {
        let reg = JobRegistry::new();
        let h = reg.create();
        reg.push(h, "hello".to_string());
        assert_eq!(reg.poll(h, 5), PollOutcome::Event("hello".to_string()));
        // Popped — a second poll finds the queue empty again.
        assert_eq!(reg.poll(h, 5), PollOutcome::Pending);
    }

    #[test]
    fn poll_with_too_small_buffer_peeks_not_pops() {
        let reg = JobRegistry::new();
        let h = reg.create();
        reg.push(h, "0123456789".to_string()); // 10 bytes
        assert_eq!(reg.poll(h, 4), PollOutcome::NeedsCapacity(10));
        // Still queued — a retry with the reported capacity gets the SAME event, not a
        // reformatted/skipped one.
        assert_eq!(reg.poll(h, 4), PollOutcome::NeedsCapacity(10));
        assert_eq!(
            reg.poll(h, 10),
            PollOutcome::Event("0123456789".to_string())
        );
    }

    #[test]
    fn fifo_order_preserved_across_multiple_events() {
        let reg = JobRegistry::new();
        let h = reg.create();
        reg.push(h, "a".to_string());
        reg.push(h, "b".to_string());
        reg.push(h, "c".to_string());
        assert_eq!(reg.poll(h, 10), PollOutcome::Event("a".to_string()));
        assert_eq!(reg.poll(h, 10), PollOutcome::Event("b".to_string()));
        assert_eq!(reg.poll(h, 10), PollOutcome::Event("c".to_string()));
        assert_eq!(reg.poll(h, 10), PollOutcome::Pending);
    }

    #[test]
    fn done_with_drained_queue_reports_done() {
        let reg = JobRegistry::new();
        let h = reg.create();
        reg.push(h, "only".to_string());
        reg.mark_done(h);
        // Queued event must still be delivered before Done, even though the job already
        // finished producing it.
        assert_eq!(reg.poll(h, 10), PollOutcome::Event("only".to_string()));
        assert_eq!(reg.poll(h, 10), PollOutcome::Done);
        // Done is sticky.
        assert_eq!(reg.poll(h, 10), PollOutcome::Done);
    }

    #[test]
    fn mark_done_before_any_push_then_poll_is_done_not_pending() {
        let reg = JobRegistry::new();
        let h = reg.create();
        reg.mark_done(h);
        assert_eq!(reg.poll(h, 10), PollOutcome::Done);
    }

    #[test]
    fn free_removes_the_job_and_reports_existence() {
        let reg = JobRegistry::new();
        let h = reg.create();
        assert!(reg.free(h));
        assert_eq!(reg.poll(h, 10), PollOutcome::NotFound);
        // Freeing again reports "did not exist".
        assert!(!reg.free(h));
    }

    #[test]
    fn push_and_mark_done_after_free_are_silent_no_ops() {
        let reg = JobRegistry::new();
        let h = reg.create();
        assert!(reg.free(h));
        // Simulates a still-running worker thread that hasn't noticed the handle was
        // freed yet — must not panic or resurrect the job.
        reg.push(h, "late event".to_string());
        reg.mark_done(h);
        assert_eq!(reg.poll(h, 10), PollOutcome::NotFound);
    }

    #[test]
    fn independent_handles_do_not_interfere() {
        let reg = JobRegistry::new();
        let h1 = reg.create();
        let h2 = reg.create();
        reg.push(h1, "for-h1".to_string());
        reg.mark_done(h2);
        assert_eq!(reg.poll(h1, 10), PollOutcome::Event("for-h1".to_string()));
        assert_eq!(reg.poll(h2, 10), PollOutcome::Done);
    }
}
