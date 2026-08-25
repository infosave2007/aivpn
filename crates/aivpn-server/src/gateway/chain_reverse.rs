//! PHASE 4 reverse chain-forward routing: records which masked pool-peer
//! session an origin client's uplink `ChainForward` most recently arrived
//! on, so a later downlink reply for that client's VPN IP can be routed
//! back over the same session instead of being dropped. Moved out of
//! `gateway/mod.rs` verbatim (pure move, no behavior change) as part of the
//! god-file decomposition.

use dashmap::DashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// PHASE 4 (reverse chain-forward / exit downlink gap): how long an exit
/// node remembers which masked pool-peer session an origin client's uplink
/// `ChainForward` most recently arrived on (see `Gateway::chain_reverse_routes`
/// and `chain_reverse_route_insert`/`chain_reverse_route_lookup`). A downlink
/// reply for that client's VPN IP arriving after this window has elapsed is
/// treated as if no route exists — the peer may have reconnected under a new
/// session id, or the client may simply have gone idle — and falls through to
/// the pre-existing "TUN: no session for VPN IP" drop instead of being routed
/// to a session that might no longer be the right one (or might not exist).
const CHAIN_REVERSE_ROUTE_TTL: Duration = Duration::from_secs(600);

/// Opportunistic sweep cadence for `chain_reverse_routes`, in inserts: every
/// this-many calls to `chain_reverse_route_insert`, expired entries are
/// purged via `DashMap::retain`. Keeps the map bounded on a long-running exit
/// node without a dedicated timer task.
///
/// BUG C3 fix: this used to be gated on `routes.len() % CHAIN_REVERSE_SWEEP_EVERY
/// == 0`, but `len()` only advances on a brand-new key — once the map's
/// distinct-IP population plateaus (any subnet with <= `CHAIN_REVERSE_SWEEP_EVERY`
/// live hosts, e.g. any /24 or smaller VPN subnet, which is the overwhelmingly
/// common case) `len()` stops changing on refresh-only inserts and the gate
/// never fires again, so the TTL sweep silently stops running for the rest of
/// the exit node's uptime. Fixed by gating on a dedicated monotonic insert
/// counter (`Gateway::chain_reverse_insert_count`) instead, which advances on
/// every insert regardless of whether the key is new.
const CHAIN_REVERSE_SWEEP_EVERY: usize = 256;

/// Record that `src_ip`'s uplink `ChainForward` traffic arrived on the masked
/// pool-peer session `session_id`, so a later downlink reply to `src_ip` can
/// be routed back over that same session instead of being dropped (see
/// `Gateway::chain_reverse_routes`'s doc comment for the full picture).
/// Opportunistically sweeps entries older than `CHAIN_REVERSE_ROUTE_TTL`
/// every `CHAIN_REVERSE_SWEEP_EVERY` inserts (driven by `insert_count`, a
/// monotonic counter of calls to this function — see `CHAIN_REVERSE_SWEEP_EVERY`'s
/// doc comment for why this can't be `routes.len()`).
///
/// BUG C1 fix: does NOT unconditionally overwrite an existing entry anymore.
/// Any masked pool-peer can send a `ChainForward` with an arbitrary inner
/// source IP (only the *subnet* is validated, not that the sender legitimately
/// owns that specific address — see the src-IP-spoofing check's own doc
/// comment in `handle_control_message`'s `ChainForward` arm), so a second,
/// unrelated peer forging a victim client's `inner_src` could previously
/// last-writer-wins hijack that IP's reverse route and silently steal its
/// downlink traffic. Now a LIVE (non-expired) entry for a DIFFERENT
/// `session_id` is left untouched (first-writer-wins-with-TTL); the entry is
/// only inserted/refreshed when there is no existing entry, the existing
/// entry has already expired, or the existing entry belongs to the SAME
/// `session_id` (a legitimate refresh, which still updates the `Instant`).
pub(crate) fn chain_reverse_route_insert(
    routes: &DashMap<Ipv4Addr, ([u8; 16], Instant)>,
    insert_count: &std::sync::atomic::AtomicUsize,
    src_ip: Ipv4Addr,
    session_id: [u8; 16],
    now: Instant,
    incumbent_is_live: impl Fn(&[u8; 16]) -> bool,
) {
    match routes.entry(src_ip) {
        dashmap::mapref::entry::Entry::Vacant(v) => {
            v.insert((session_id, now));
        }
        dashmap::mapref::entry::Entry::Occupied(mut o) => {
            let (existing_session_id, last_seen) = *o.get();
            let expired = now.duration_since(last_seen) >= CHAIN_REVERSE_ROUTE_TTL;
            // An entry whose session no longer exists protects nobody and
            // blocks everybody. `chain_reverse_route_lookup`'s caller already
            // has to drop the packet when the recorded session is gone, so
            // until the TTL expires such an entry is a pure blackhole: a peer
            // that merely RECONNECTED (new session id after a network blip)
            // could not re-claim its own clients' IPs for up to
            // `CHAIN_REVERSE_ROUTE_TTL`, and every downlink reply to them was
            // dropped for that whole window. Treat a dead incumbent exactly
            // like an expired one.
            let dead = !incumbent_is_live(&existing_session_id);
            if existing_session_id == session_id || expired || dead {
                o.insert((session_id, now));
            }
            // else: a LIVE entry for a different LIVE session owns this IP —
            // refuse to overwrite it (BUG C1).
        }
    }
    let n = insert_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if n % CHAIN_REVERSE_SWEEP_EVERY == 0 {
        routes.retain(|_, (_, last_seen)| now.duration_since(*last_seen) < CHAIN_REVERSE_ROUTE_TTL);
    }
}

/// Look up the masked pool-peer session id a downlink reply to `dst_ip`
/// should be routed back over. Returns `None` both when there is no recorded
/// route and when the recorded route is older than `CHAIN_REVERSE_ROUTE_TTL`
/// — a stale entry is left in place for the next opportunistic sweep rather
/// than removed here, keeping this a plain read.
pub(crate) fn chain_reverse_route_lookup(
    routes: &DashMap<Ipv4Addr, ([u8; 16], Instant)>,
    dst_ip: &Ipv4Addr,
    now: Instant,
) -> Option<[u8; 16]> {
    routes.get(dst_ip).and_then(|entry| {
        let (session_id, last_seen) = *entry;
        (now.duration_since(last_seen) < CHAIN_REVERSE_ROUTE_TTL).then_some(session_id)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PHASE 4 (reverse chain-forward): `chain_reverse_route_insert` then
    /// `chain_reverse_route_lookup` for the same VPN IP round-trips the
    /// exact session id recorded, immediately (well within the TTL).
    #[test]
    fn chain_reverse_route_insert_then_lookup_round_trips() {
        let routes: DashMap<Ipv4Addr, ([u8; 16], Instant)> = DashMap::new();
        let counter = std::sync::atomic::AtomicUsize::new(0);
        let src_ip = Ipv4Addr::new(10, 0, 0, 2);
        let session_id = [9u8; 16];
        let now = Instant::now();

        chain_reverse_route_insert(&routes, &counter, src_ip, session_id, now, |_| true);

        assert_eq!(
            chain_reverse_route_lookup(&routes, &src_ip, now),
            Some(session_id)
        );
    }

    /// A peer that merely RECONNECTED must be able to re-claim its own
    /// clients' reverse routes immediately. The incumbent entry is live by
    /// TTL but its session is gone, so it can never route anything — leaving
    /// it in place blackholed every downlink reply to those clients for the
    /// full `CHAIN_REVERSE_ROUTE_TTL` (ten minutes) after any peer blip.
    #[test]
    fn dead_incumbent_session_does_not_block_a_reconnected_peer() {
        let routes: DashMap<Ipv4Addr, ([u8; 16], Instant)> = DashMap::new();
        let counter = std::sync::atomic::AtomicUsize::new(0);
        let src_ip = Ipv4Addr::new(10, 0, 0, 7);
        let old_session = [1u8; 16];
        let reconnected_session = [2u8; 16];
        let t0 = Instant::now();

        chain_reverse_route_insert(&routes, &counter, src_ip, old_session, t0, |_| true);
        // Same peer, new session id after a reconnect; the old session no
        // longer exists in the session manager.
        chain_reverse_route_insert(&routes, &counter, src_ip, reconnected_session, t0, |sid| {
            *sid != old_session
        });

        assert_eq!(
            chain_reverse_route_lookup(&routes, &src_ip, t0),
            Some(reconnected_session),
            "a route pointing at a dead session must not outlive it"
        );
    }

    /// The dead-incumbent rule must not reopen BUG C1: a LIVE incumbent still
    /// wins against a different session claiming the same IP.
    #[test]
    fn live_incumbent_still_wins_against_a_foreign_claim() {
        let routes: DashMap<Ipv4Addr, ([u8; 16], Instant)> = DashMap::new();
        let counter = std::sync::atomic::AtomicUsize::new(0);
        let src_ip = Ipv4Addr::new(10, 0, 0, 8);
        let legit = [3u8; 16];
        let attacker = [4u8; 16];
        let t0 = Instant::now();

        chain_reverse_route_insert(&routes, &counter, src_ip, legit, t0, |_| true);
        chain_reverse_route_insert(&routes, &counter, src_ip, attacker, t0, |_| true);

        assert_eq!(
            chain_reverse_route_lookup(&routes, &src_ip, t0),
            Some(legit)
        );
    }

    /// A lookup for a VPN IP that was never recorded finds nothing.
    #[test]
    fn chain_reverse_route_lookup_unknown_ip_returns_none() {
        let routes: DashMap<Ipv4Addr, ([u8; 16], Instant)> = DashMap::new();
        let now = Instant::now();
        assert_eq!(
            chain_reverse_route_lookup(&routes, &Ipv4Addr::new(10, 0, 0, 9), now),
            None
        );
    }

    /// A route recorded at `now` is still found just before
    /// `CHAIN_REVERSE_ROUTE_TTL` elapses, but is treated as absent once the
    /// TTL has fully elapsed — the exact TTL-eviction boundary the exit
    /// node's TUN read loop relies on to stop routing replies to a peer
    /// session that may no longer be the right (or even a live) one.
    #[test]
    fn chain_reverse_route_lookup_honors_ttl_boundary() {
        let routes: DashMap<Ipv4Addr, ([u8; 16], Instant)> = DashMap::new();
        let counter = std::sync::atomic::AtomicUsize::new(0);
        let src_ip = Ipv4Addr::new(10, 0, 0, 3);
        let session_id = [3u8; 16];
        let inserted_at = Instant::now();
        chain_reverse_route_insert(&routes, &counter, src_ip, session_id, inserted_at, |_| true);

        let just_before_ttl = inserted_at + CHAIN_REVERSE_ROUTE_TTL - Duration::from_millis(1);
        assert_eq!(
            chain_reverse_route_lookup(&routes, &src_ip, just_before_ttl),
            Some(session_id),
            "route must still be honored just before the TTL elapses"
        );

        let at_or_after_ttl = inserted_at + CHAIN_REVERSE_ROUTE_TTL;
        assert_eq!(
            chain_reverse_route_lookup(&routes, &src_ip, at_or_after_ttl),
            None,
            "route must be treated as expired once the TTL has fully elapsed"
        );
    }

    /// A later insert for the same VPN IP from the SAME session_id (e.g. the
    /// client's traffic simply continues arriving on the same masked
    /// pool-peer session) refreshes the recorded `Instant` rather than being
    /// refused — the same-session case of the BUG C1 fix.
    #[test]
    fn chain_reverse_route_insert_refreshes_same_session_for_same_ip() {
        let routes: DashMap<Ipv4Addr, ([u8; 16], Instant)> = DashMap::new();
        let counter = std::sync::atomic::AtomicUsize::new(0);
        let src_ip = Ipv4Addr::new(10, 0, 0, 4);
        let session_id = [1u8; 16];
        let t0 = Instant::now();

        chain_reverse_route_insert(&routes, &counter, src_ip, session_id, t0, |_| true);
        let t1 = t0 + Duration::from_secs(1);
        chain_reverse_route_insert(&routes, &counter, src_ip, session_id, t1, |_| true);

        assert_eq!(
            chain_reverse_route_lookup(&routes, &src_ip, t1),
            Some(session_id)
        );
    }

    /// BUG C1 (reverse-route poisoning): a LIVE (non-expired) entry for a
    /// given VPN IP must NOT be overwritten by an insert from a DIFFERENT
    /// session_id — otherwise any masked pool-peer could forge a victim
    /// client's `inner_src` in a `ChainForward` and hijack that IP's
    /// downlink reverse route out from under the legitimate session. This is
    /// first-writer-wins-with-TTL: the original session keeps the route
    /// until it expires.
    #[test]
    fn chain_reverse_route_insert_refuses_to_overwrite_live_different_session() {
        let routes: DashMap<Ipv4Addr, ([u8; 16], Instant)> = DashMap::new();
        let counter = std::sync::atomic::AtomicUsize::new(0);
        let src_ip = Ipv4Addr::new(10, 0, 0, 4);
        let legit_session = [1u8; 16];
        let attacker_session = [2u8; 16];
        let t0 = Instant::now();

        chain_reverse_route_insert(&routes, &counter, src_ip, legit_session, t0, |_| true);
        let t1 = t0 + Duration::from_secs(1);
        // An unrelated peer forges a ChainForward claiming the same inner
        // source IP while the legitimate route is still live.
        chain_reverse_route_insert(&routes, &counter, src_ip, attacker_session, t1, |_| true);

        assert_eq!(
            chain_reverse_route_lookup(&routes, &src_ip, t1),
            Some(legit_session),
            "a live route must not be hijacked by a different session_id"
        );
    }

    /// BUG C1 companion: once the original session's route has fully
    /// expired (at/past `CHAIN_REVERSE_ROUTE_TTL`), a different session_id
    /// MAY claim the IP — an expired entry is not "live" and is fair game,
    /// otherwise a VPN IP whose original peer session is long gone could
    /// never be routed to again.
    #[test]
    fn chain_reverse_route_insert_allows_overwrite_after_expiry() {
        let routes: DashMap<Ipv4Addr, ([u8; 16], Instant)> = DashMap::new();
        let counter = std::sync::atomic::AtomicUsize::new(0);
        let src_ip = Ipv4Addr::new(10, 0, 0, 4);
        let old_session = [1u8; 16];
        let new_session = [2u8; 16];
        let t0 = Instant::now();

        chain_reverse_route_insert(&routes, &counter, src_ip, old_session, t0, |_| true);
        let t1 = t0 + CHAIN_REVERSE_ROUTE_TTL;
        chain_reverse_route_insert(&routes, &counter, src_ip, new_session, t1, |_| true);

        assert_eq!(
            chain_reverse_route_lookup(&routes, &src_ip, t1),
            Some(new_session),
            "an expired route may be claimed by a different session_id"
        );
    }

    /// The opportunistic sweep (triggered every `CHAIN_REVERSE_SWEEP_EVERY`
    /// inserts, tracked by a monotonic insert counter — see the BUG C3 fix)
    /// purges entries older than `CHAIN_REVERSE_ROUTE_TTL` without needing a
    /// dedicated timer task. Pre-populate the map with one stale entry and
    /// one fresh one, then drive exactly `CHAIN_REVERSE_SWEEP_EVERY` more
    /// inserts (of throwaway IPs, all at a `now` timestamp that is fresh
    /// relative to itself but far past the stale entry's insert time) so the
    /// sweep condition (`insert_count % CHAIN_REVERSE_SWEEP_EVERY == 0`)
    /// fires, and confirm the stale entry is gone while the fresh one
    /// survives.
    #[test]
    fn chain_reverse_route_insert_sweeps_expired_entries_opportunistically() {
        let routes: DashMap<Ipv4Addr, ([u8; 16], Instant)> = DashMap::new();
        let counter = std::sync::atomic::AtomicUsize::new(0);
        let stale_ip = Ipv4Addr::new(10, 0, 0, 5);
        let fresh_ip = Ipv4Addr::new(10, 0, 0, 6);
        let t0 = Instant::now();

        // A route recorded long enough ago to already be past the TTL by
        // the time the sweep runs below.
        chain_reverse_route_insert(&routes, &counter, stale_ip, [1u8; 16], t0, |_| true);

        let sweep_now = t0 + CHAIN_REVERSE_ROUTE_TTL + Duration::from_secs(1);

        // A route recorded fresh (at `sweep_now`) — must survive the sweep.
        chain_reverse_route_insert(&routes, &counter, fresh_ip, [2u8; 16], sweep_now, |_| true);

        // Drive enough additional inserts (distinct throwaway IPs) at
        // `sweep_now` to land exactly on an `insert_count %
        // CHAIN_REVERSE_SWEEP_EVERY == 0` boundary and trigger the
        // opportunistic sweep.
        let mut next_octet: u32 = 10;
        while counter.load(std::sync::atomic::Ordering::Relaxed) % CHAIN_REVERSE_SWEEP_EVERY != 0 {
            let filler_ip = Ipv4Addr::from(0x0A00_0000u32 + next_octet);
            next_octet += 1;
            chain_reverse_route_insert(&routes, &counter, filler_ip, [0u8; 16], sweep_now, |_| {
                true
            });
        }

        assert!(
            !routes.contains_key(&stale_ip),
            "stale entry must be purged by the opportunistic sweep"
        );
        assert!(
            routes.contains_key(&fresh_ip),
            "fresh entry must survive the opportunistic sweep"
        );
    }

    /// BUG C3 regression guard: on a subnet with far fewer distinct hosts
    /// than `CHAIN_REVERSE_SWEEP_EVERY` (the common case — any /24 or
    /// smaller), repeated same-session refresh-only inserts for a small
    /// stable set of IPs must still eventually trigger the sweep. Before the
    /// fix this was gated on `routes.len() % CHAIN_REVERSE_SWEEP_EVERY == 0`,
    /// which never advances once all the distinct keys already exist, so the
    /// sweep would never fire again for the rest of the process's life.
    #[test]
    fn chain_reverse_route_insert_sweep_fires_on_small_stable_subnet() {
        let routes: DashMap<Ipv4Addr, ([u8; 16], Instant)> = DashMap::new();
        let counter = std::sync::atomic::AtomicUsize::new(0);
        let stale_ip = Ipv4Addr::new(10, 0, 0, 5);
        let churn_ip = Ipv4Addr::new(10, 0, 0, 6);
        let churn_session = [7u8; 16];
        let t0 = Instant::now();

        chain_reverse_route_insert(&routes, &counter, stale_ip, [1u8; 16], t0, |_| true);
        let sweep_now = t0 + CHAIN_REVERSE_ROUTE_TTL + Duration::from_secs(1);
        chain_reverse_route_insert(
            &routes,
            &counter,
            churn_ip,
            churn_session,
            sweep_now,
            |_| true,
        );

        // `routes.len()` is now 2 and never grows again — only same-session
        // refreshes for `churn_ip` follow, exactly the low-host-count
        // scenario BUG C3 fixes.
        assert_eq!(routes.len(), 2);
        while counter.load(std::sync::atomic::Ordering::Relaxed) % CHAIN_REVERSE_SWEEP_EVERY != 0 {
            chain_reverse_route_insert(
                &routes,
                &counter,
                churn_ip,
                churn_session,
                sweep_now,
                |_| true,
            );
        }

        assert!(
            !routes.contains_key(&stale_ip),
            "stale entry must be purged even though routes.len() plateaued at 2"
        );
        assert!(
            routes.contains_key(&churn_ip),
            "the actively-refreshed entry must survive the opportunistic sweep"
        );
    }
}
