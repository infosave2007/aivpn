//! Per-session throttle predicates and atomic check-and-claim helpers for
//! `MaskPreference`, `MaskFeedback`, and `MgmtRequest`. Moved out of
//! `gateway/mod.rs` verbatim (pure move, no behavior change) as part of the
//! god-file decomposition.

use dashmap::DashMap;
use std::time::{Duration, Instant};

/// Generic per-session throttle predicate shared by `MaskPreference`
/// (`mask_preference_throttled`) and `MaskFeedback`
/// (`mask_feedback_throttled`): `true` means "a slot for this session was
/// already claimed within `window`, so the caller must drop the request
/// without reaching its expensive path". Factored out so both throttles
/// share one reviewed implementation instead of two hand-copied windows.
fn throttled(last_processed: Option<Instant>, now: Instant, window: Duration) -> bool {
    match last_processed {
        Some(last) => now.duration_since(last) < window,
        None => false,
    }
}

/// Per-session `MaskPreference` throttle predicate: `true` means the gateway
/// should drop this `MaskPreference` without reaching the sign+encrypt
/// `build_mask_update_packet` path, because one was already processed for
/// this session within `MASK_PREFERENCE_THROTTLE`. See that constant's doc
/// comment for why this cannot break the client's legitimate same-id retry
/// loop (those never reach this check — they're caught by the pre-existing
/// idempotency check first).
fn mask_preference_throttled(last_processed: Option<Instant>, now: Instant) -> bool {
    throttled(last_processed, now, MASK_PREFERENCE_THROTTLE)
}

/// Per-session `MaskFeedback` throttle predicate — same shape as
/// `mask_preference_throttled`, gating the `top_masks_for_region` scan +
/// up to two encrypted replies (see `MASK_FEEDBACK_THROTTLE`) instead of the
/// sign+encrypt `MaskUpdate` path.
fn mask_feedback_throttled(last_processed: Option<Instant>, now: Instant) -> bool {
    throttled(last_processed, now, MASK_FEEDBACK_THROTTLE)
}

/// Atomically check-and-claim a per-session throttle slot (LOW #3 hardening:
/// sign-amplification race, generalized — see FIX F's per-session
/// `MaskFeedback` throttle for the second use). The naive way to use
/// `throttled` — `throttle.get(&id)` to read, then `throttle.insert(id, now)`
/// to claim — has a TOCTOU gap: `get` and `insert` each take (and release)
/// the DashMap shard lock separately, so two packets for the *same* session,
/// processed by two different `tokio::spawn`ed tasks from
/// `process_packets_concurrent` (genuinely concurrent, not just
/// interleaved), can both read "not throttled yet" before either has
/// inserted, and both fall through to the expensive path this throttle
/// exists to bound.
///
/// `DashMap::entry()` holds one shard lock across the whole read-decide-write
/// sequence, so this makes the check-and-claim atomic: of any set of callers
/// racing for the same `session_id`, exactly one observes `claimed = true`
/// (and the slot now reflects `now`); every other one — whether truly
/// concurrent or arriving moments later within the window — observes
/// `claimed = false`. Returns `true` if the caller should proceed (the slot
/// is now claimed for `now`), `false` if throttled.
fn try_claim_slot(
    throttle: &DashMap<[u8; 16], Instant>,
    session_id: [u8; 16],
    now: Instant,
    is_throttled: fn(Option<Instant>, Instant) -> bool,
) -> bool {
    let mut claimed = true;
    throttle
        .entry(session_id)
        .and_modify(|last| {
            if is_throttled(Some(*last), now) {
                claimed = false;
            } else {
                *last = now;
            }
        })
        .or_insert(now);
    claimed
}

/// `MaskPreference`-specific wrapper around `try_claim_slot` — see that
/// function's doc comment for the atomicity guarantee.
pub(crate) fn try_claim_mask_preference_slot(
    throttle: &DashMap<[u8; 16], Instant>,
    session_id: [u8; 16],
    now: Instant,
) -> bool {
    try_claim_slot(throttle, session_id, now, mask_preference_throttled)
}

/// `MaskFeedback`-specific wrapper around `try_claim_slot` (FIX F) — bounds
/// the expensive `top_masks_for_region` scan + up to two encrypted replies to
/// at most once per session per `MASK_FEEDBACK_THROTTLE`, regardless of how
/// many `MaskFeedback` packets (with or without entries) the session sends.
pub(crate) fn try_claim_mask_feedback_slot(
    throttle: &DashMap<[u8; 16], Instant>,
    session_id: [u8; 16],
    now: Instant,
) -> bool {
    try_claim_slot(throttle, session_id, now, mask_feedback_throttled)
}

/// Per-session `MgmtRequest` throttle predicate (P1.2) — same shape as
/// `mask_feedback_throttled`, gating the `mgmt_service::dispatch` path
/// (DB IO + JSON encoding) instead of the mask-feedback scan+reply path.
fn mgmt_throttled(last_processed: Option<Instant>, now: Instant) -> bool {
    throttled(last_processed, now, MGMT_THROTTLE)
}

/// `MgmtRequest`-specific wrapper around `try_claim_slot` (P1.2) — see that
/// function's doc comment for the atomicity guarantee.
pub(crate) fn try_claim_mgmt_slot(
    throttle: &DashMap<[u8; 16], Instant>,
    session_id: [u8; 16],
    now: Instant,
) -> bool {
    try_claim_slot(throttle, session_id, now, mgmt_throttled)
}

/// Per-session `MaskPreference` throttle window. `handle_control_message`'s
/// `MaskPreference` arm derives a polymorphic variant and, unless the
/// session's current/pending mask already IS that variant (the pre-existing
/// idempotency check), signs (Ed25519) and encrypts a fresh `MaskUpdate`
/// packet — non-trivial per-packet cost. A client that varies `base_mask_id`
/// on every packet defeats the idempotency check (the derived variant differs
/// every time) and can force that sign+encrypt path on every single packet it
/// sends.
///
/// The legitimate client-side retry loop (see `aivpn-client/src/client.rs`,
/// `polymorphic_base` handling) resends the *same* `base_mask_id` up to 5
/// times over ~5s (immediate, then +0.5s/+1s/+1.5s/+2s) purely for reliability
/// against a lost first packet. Because it always resends the same id, only
/// the first of those ever reaches the sign+encrypt path — every retry after
/// the first hits the idempotency check instead (the variant is already
/// active/pending) and returns before ever consuming this throttle. So a
/// throttle keyed on "was the last *processed* (non-idempotent) request for
/// this session within the window" does not interfere with that retry
/// sequence at all, regardless of how tight the window is.
///
/// What it does bound is a spammer sending a *different* `base_mask_id` on
/// every packet (always missing the idempotency check): at most one
/// sign+encrypt per session per window, no matter how many distinct ids it
/// sends. 2 seconds is comfortably below "a human deliberately changing their
/// mask preference again" cadence, so it costs legitimate usage nothing
/// beyond a sub-2s cooldown between genuinely different preference changes.
pub(crate) const MASK_PREFERENCE_THROTTLE: Duration = Duration::from_secs(2);

/// Per-session `MaskFeedback` throttle window (FIX F, §2 amplification).
/// `handle_control_message`'s `MaskFeedback` arm always runs
/// `MaskFeedbackStore::top_masks_for_region` (which, under the feedback
/// `Mutex`, calls `Hll::estimate` — summing 1024 registers — for every mask
/// bucket in the client's claimed country, plus the continent roll-up) and
/// then sends up to two encrypted replies (`RegionalMaskHints` +
/// `FeedbackConfig`) — regardless of whether the packet carried any real
/// outcome `entries`. A bare "hints-only probe" (empty `entries`, essentially
/// free for the sender to construct) triggers the exact same scan+reply cost
/// as a real report, so without a throttle a client could force that 1-in/2-
/// out amplification on every single packet it sends.
///
/// This throttle guards ONLY the scan+reply path, not `record_feedback`
/// itself (see the `MaskFeedback` arm) — real outcome reporting is cheap
/// (an O(1) HLL update, already bounded by `MAX_BUCKETS` /
/// `MAX_BUCKETS_PER_COUNTRY`) and must never be dropped merely because the
/// same session also asked for hints recently. 5 seconds is far below the
/// server-pushed `feedback_report_interval_secs` (default 3600s) a
/// legitimate opted-in client waits between real reports, so it costs
/// legitimate usage nothing while bounding a spammer to at most one
/// scan+reply pair per session per window.
pub(crate) const MASK_FEEDBACK_THROTTLE: Duration = Duration::from_secs(5);

/// P1.2: per-session floor on `MgmtRequest` dispatch. 200ms is generous for
/// any legitimate admin/viewer UI interaction (list/patch/connection-key
/// calls are human-paced, not a polling loop) while bounding a compromised
/// or buggy client to at most 5 `mgmt_service::dispatch` calls/sec — each of
/// which does DB IO and JSON encoding, unlike the cheap packet-classify path
/// most other throttles guard.
pub(crate) const MGMT_THROTTLE: Duration = Duration::from_millis(200);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_preference_throttle_blocks_within_window() {
        let now = Instant::now();
        // No prior processed request — never throttled.
        assert!(!mask_preference_throttled(None, now));

        // Processed "just now" (elapsed ~0) — must throttle.
        assert!(mask_preference_throttled(Some(now), now));

        // Still within the window a moment later.
        let later = now + Duration::from_millis(500);
        assert!(mask_preference_throttled(Some(now), later));
    }

    #[test]
    fn mask_preference_throttle_allows_after_window_elapses() {
        let now = Instant::now();
        let after_window = now + MASK_PREFERENCE_THROTTLE + Duration::from_millis(1);
        assert!(!mask_preference_throttled(Some(now), after_window));
    }

    #[test]
    fn mask_preference_throttle_window_covers_client_retry_gap_but_retries_are_idempotent_not_throttled(
    ) {
        // Documents why the throttle is safe against the client's retry loop
        // (see `aivpn-client/src/client.rs`'s polymorphic_base resend task):
        // it resends the SAME base_mask_id at cumulative offsets of 0ms,
        // 500ms, 1500ms, 3000ms, 5000ms. Every resend after the first hits
        // the pre-existing idempotency check (the variant is already
        // active/pending) and returns before ever consuming this throttle —
        // so whether this predicate would say "throttled" for those later
        // timestamps is moot. This test just pins down that the 2s window
        // does span most of that retry burst, to make the interaction
        // explicit rather than implicit.
        let first_processed = Instant::now();
        let retry_offsets_ms = [500u64, 1500, 3000, 5000];
        let within_window: Vec<bool> = retry_offsets_ms
            .iter()
            .map(|&ms| {
                let t = first_processed + Duration::from_millis(ms);
                mask_preference_throttled(Some(first_processed), t)
            })
            .collect();
        // The first two retries (500ms, 1500ms) fall inside the 2s window;
        // the last two (3s, 5s) do not. Irrelevant in practice (idempotency
        // catches all of them first) but documented here for clarity.
        assert_eq!(within_window, vec![true, true, false, false]);
    }

    /// §3 F sign-amplification (LOW #3): proves the atomic
    /// `try_claim_mask_preference_slot` check-and-claim means at most one of
    /// two "concurrent" `MaskPreference` packets for the same session can
    /// ever reach the sign+encrypt path — i.e. a retry storm signs once, not
    /// once per packet. True thread-level concurrency isn't reliably
    /// unit-testable, but calling the exact production claim function twice
    /// back-to-back for the same `(session_id, now)` exercises the same
    /// code path two racing tasks would hit (both see the same `now`, only
    /// one can win the DashMap shard lock first) and is what the old
    /// get()-then-insert() sequence could fail on.
    #[test]
    fn try_claim_mask_preference_slot_first_racer_wins_second_is_suppressed() {
        let throttle: DashMap<[u8; 16], Instant> = DashMap::new();
        let session_id = [7u8; 16];
        let now = Instant::now();

        // First packet for this session claims the slot and must proceed.
        assert!(try_claim_mask_preference_slot(&throttle, session_id, now));

        // A second packet for the *same* session and the *same* instant —
        // simulating a genuinely concurrent racer arriving at the same
        // `now` — must observe the slot already claimed and be suppressed.
        assert!(!try_claim_mask_preference_slot(&throttle, session_id, now));

        // A third, later call for the same session while still inside the
        // window must also be suppressed (ordinary throttle behaviour).
        let still_within = now + Duration::from_millis(1);
        assert!(!try_claim_mask_preference_slot(
            &throttle,
            session_id,
            still_within
        ));
    }

    #[test]
    fn try_claim_mask_preference_slot_allows_again_after_window_elapses() {
        let throttle: DashMap<[u8; 16], Instant> = DashMap::new();
        let session_id = [8u8; 16];
        let now = Instant::now();
        assert!(try_claim_mask_preference_slot(&throttle, session_id, now));

        let after_window = now + MASK_PREFERENCE_THROTTLE + Duration::from_millis(1);
        assert!(try_claim_mask_preference_slot(
            &throttle,
            session_id,
            after_window
        ));
    }

    #[test]
    fn try_claim_mask_preference_slot_is_independent_per_session() {
        let throttle: DashMap<[u8; 16], Instant> = DashMap::new();
        let now = Instant::now();
        // One session claiming its slot must not throttle an unrelated
        // session's claim at the same instant.
        assert!(try_claim_mask_preference_slot(&throttle, [1u8; 16], now));
        assert!(try_claim_mask_preference_slot(&throttle, [2u8; 16], now));
    }

    // ========================================================================
    // FIX F: MaskFeedback per-session throttle (§2 amplification)
    // ========================================================================

    /// Same shape as `mask_preference_throttle_blocks_within_window` — the
    /// `MaskFeedback` throttle predicate must behave identically: no prior
    /// slot never throttles, a slot claimed just now throttles, and it stops
    /// throttling once `MASK_FEEDBACK_THROTTLE` has elapsed.
    #[test]
    fn mask_feedback_throttle_blocks_within_window() {
        let now = Instant::now();
        assert!(!mask_feedback_throttled(None, now));
        assert!(mask_feedback_throttled(Some(now), now));

        let later = now + Duration::from_millis(500);
        assert!(mask_feedback_throttled(Some(now), later));

        let after_window = now + MASK_FEEDBACK_THROTTLE + Duration::from_millis(1);
        assert!(!mask_feedback_throttled(Some(now), after_window));
    }

    /// `try_claim_mask_feedback_slot` must give the same atomic
    /// check-and-claim guarantee as `try_claim_mask_preference_slot`: the
    /// first caller for a session claims the slot; a second caller for the
    /// SAME session within the window is throttled; after the window
    /// elapses, the slot can be claimed again.
    #[test]
    fn try_claim_mask_feedback_slot_is_atomic_check_and_claim() {
        let throttle: DashMap<[u8; 16], Instant> = DashMap::new();
        let session_id = [7u8; 16];
        let t0 = Instant::now();

        assert!(
            try_claim_mask_feedback_slot(&throttle, session_id, t0),
            "first claim for a fresh session must succeed"
        );
        assert!(
            !try_claim_mask_feedback_slot(&throttle, session_id, t0),
            "second claim within the window must be throttled"
        );

        let t1 = t0 + MASK_FEEDBACK_THROTTLE + Duration::from_millis(1);
        assert!(
            try_claim_mask_feedback_slot(&throttle, session_id, t1),
            "claim after the window has elapsed must succeed again"
        );
    }

    /// Two DIFFERENT sessions must never interfere with each other's
    /// throttle slot — a flood from one session cannot suppress a
    /// legitimate MaskFeedback reply for a different, unrelated session.
    #[test]
    fn mask_feedback_throttle_is_scoped_per_session() {
        let throttle: DashMap<[u8; 16], Instant> = DashMap::new();
        let session_a = [1u8; 16];
        let session_b = [2u8; 16];
        let now = Instant::now();

        assert!(try_claim_mask_feedback_slot(&throttle, session_a, now));
        // session_a is now throttled, but session_b must be entirely
        // unaffected.
        assert!(try_claim_mask_feedback_slot(&throttle, session_b, now));
        assert!(!try_claim_mask_feedback_slot(&throttle, session_a, now));
        assert!(!try_claim_mask_feedback_slot(&throttle, session_b, now));
    }

    /// `MASK_PREFERENCE_THROTTLE` and `MASK_FEEDBACK_THROTTLE` are
    /// independent windows — sanity check that they're not accidentally
    /// aliased to the same constant (which would make the two throttle maps
    /// redundant and defeat the point of having a dedicated, documented
    /// window for each control message type).
    #[test]
    fn mask_feedback_and_mask_preference_throttles_are_independent_constants() {
        assert_ne!(MASK_FEEDBACK_THROTTLE, MASK_PREFERENCE_THROTTLE);
    }

    // ========================================================================
    // P1.2: MgmtRequest rate-limit + session role resolution
    // ========================================================================

    /// Same shape as `mask_feedback_throttle_blocks_within_window` — the
    /// `MgmtRequest` throttle predicate must behave identically.
    #[test]
    fn mgmt_throttle_blocks_within_window() {
        let now = Instant::now();
        assert!(!mgmt_throttled(None, now));
        assert!(mgmt_throttled(Some(now), now));

        let later = now + Duration::from_millis(50);
        assert!(mgmt_throttled(Some(now), later));

        let after_window = now + MGMT_THROTTLE + Duration::from_millis(1);
        assert!(!mgmt_throttled(Some(now), after_window));
    }

    /// `try_claim_mgmt_slot` must give the same atomic check-and-claim
    /// guarantee as `try_claim_mask_feedback_slot`: first claim for a fresh
    /// session succeeds, a second claim for the SAME session within the
    /// window is throttled (this is what makes a burst of `MgmtRequest`
    /// packets from a single session collapse to one dispatched call plus
    /// N `429` replies), and a claim after the window elapses succeeds
    /// again.
    #[test]
    fn try_claim_mgmt_slot_is_atomic_check_and_claim() {
        let throttle: DashMap<[u8; 16], Instant> = DashMap::new();
        let session_id = [11u8; 16];
        let t0 = Instant::now();

        assert!(
            try_claim_mgmt_slot(&throttle, session_id, t0),
            "first claim for a fresh session must succeed"
        );
        assert!(
            !try_claim_mgmt_slot(&throttle, session_id, t0),
            "second claim within the window must be throttled (429)"
        );

        let t1 = t0 + MGMT_THROTTLE + Duration::from_millis(1);
        assert!(
            try_claim_mgmt_slot(&throttle, session_id, t1),
            "claim after the window has elapsed must succeed again"
        );
    }

    /// Two different sessions must never share a throttle slot — a burst
    /// on session A must not 429 a legitimate `MgmtRequest` from session B.
    #[test]
    fn mgmt_throttle_is_scoped_per_session() {
        let throttle: DashMap<[u8; 16], Instant> = DashMap::new();
        let session_a = [21u8; 16];
        let session_b = [22u8; 16];
        let now = Instant::now();

        assert!(try_claim_mgmt_slot(&throttle, session_a, now));
        assert!(try_claim_mgmt_slot(&throttle, session_b, now));
        assert!(!try_claim_mgmt_slot(&throttle, session_a, now));
        assert!(!try_claim_mgmt_slot(&throttle, session_b, now));
    }
}
