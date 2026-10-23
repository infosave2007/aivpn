//! §2 Crowdsourced blocking feedback — privacy-preserving mask outcome aggregation.
//!
//! Clients optionally report which masks succeeded/failed for them (see
//! `ControlPayload::MaskFeedback` in `aivpn-common/src/protocol.rs`). The
//! server aggregates these reports by `(country_code, mask_id)` and, once a
//! bucket has been reported by at least `k_anon` (default 20) *distinct*
//! clients, may surface the bucket's success rate back to other clients in
//! the same region via `ControlPayload::RegionalMaskHints`.
//!
//! Privacy properties (see also the design doc, §2):
//! - **No reporter identity is stored.** Distinct-reporter counts are
//!   estimated with a minimal, self-contained HyperLogLog (`Hll` below) whose
//!   state is a fixed array of small counters. Every reporter token is salted
//!   with a per-process-lifetime random secret (see
//!   [`MaskFeedbackStore::reporter_salt`]) before it is folded into the
//!   sketch, and that salt is never persisted or exposed. Without the salt,
//!   an attacker who obtained a bucket's raw register array plus a candidate
//!   list of client ids could probe membership by recomputing
//!   `blake3(client_id)` and checking whether it would have raised any
//!   register — the salt makes that recomputation infeasible, so membership
//!   is not practically decidable from the sketch.
//! - **k-anonymity gate.** `top_masks_for_region` refuses to return a bucket
//!   (country- or continent-level) whose estimated distinct-reporter count is
//!   below `k_anon`. See [`MaskFeedbackStore::k_anon`].
//! - **Continent roll-up for sparse regions.** Rather than silently dropping
//!   feedback for small countries, buckets below the k-anonymity threshold are
//!   merged with same-mask buckets from other countries in the same continent
//!   (via `ISO-3166` alpha-2 → continent table below) before the gate is
//!   re-checked, so sparse regions still benefit without ever exposing a
//!   sub-threshold bucket.
//! - **Hour-granularity timestamps only.** `last_updated_hour` is
//!   `unix_secs / 3600` — no finer-grained timing is retained.
//!
//! ## Data structure & complexity (second-pass review fix)
//!
//! Buckets are stored as a **country-indexed nested map**,
//! `country_code -> mask_id -> MaskBucket`, rather than a single flat map
//! keyed by `(country_code, mask_id)`. This is what makes the per-packet
//! control-plane path (`record_feedback` / `top_masks_for_region`) scale
//! with the number of masks *in the relevant region(s)*, not with the total
//! number of buckets in the whole store:
//! - `record_feedback` only ever touches the one country's inner map.
//! - `top_masks_for_region`'s direct pass only iterates the requested
//!   country's inner map, and its continent roll-up pass only iterates the
//!   (small, fixed) list of countries in the same continent — see
//!   [`continent_members`] — doing an O(1) hash lookup per candidate country
//!   instead of an O(total buckets) scan.
//!
//! See [`MaskFeedbackStore::record_feedback`] for the bucket-count cap and
//! eviction strategy, which is likewise bounded and does not scan the whole
//! store per insert.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use aivpn_common::mask::current_unix_secs;
use aivpn_common::protocol::MaskOutcome;

/// Number of HyperLogLog registers (2^10 = 1024). Each register is one byte,
/// so the whole sketch is 1 KiB per `(country, mask_id)` bucket — cheap
/// enough to keep per-bucket without needing an external HLL crate.
const HLL_REGISTERS: usize = 1024;
const HLL_BITS: u32 = 10; // log2(HLL_REGISTERS)

/// Default k-anonymity threshold: a bucket's aggregate (success rate) is
/// never surfaced to any client unless it has been reported by at least this
/// many *distinct* clients (estimated via HyperLogLog, never counted exactly
/// nor stored as identities). This is the single privacy gate for this
/// feature — keep it easy to find for review.
pub const DEFAULT_K_ANON: u64 = 20;

/// Maximum accepted length (in bytes) of a client-supplied `mask_id`. Both
/// `mask_id` and `country_code` are attacker-controlled (any authenticated
/// client can pick arbitrary values), so without a cap a single client could
/// mint unbounded distinct bucket keys. Dynamic ids such as
/// `polymorphic:...` / `bootstrap:...` are legitimate and expected — this is
/// a length bound, not an allow-list against `preset_masks::by_id`.
pub const MAX_MASK_ID_LEN: usize = 64;

/// Hard cap on the total number of distinct `(country_code, mask_id)`
/// buckets kept in memory at once, across *all* countries. At ~1 KiB per
/// bucket (dominated by the `Hll` sketch) this bounds worst-case memory to
/// ~100 MiB. `total_buckets` (see [`FeedbackMap`]) is maintained incrementally
/// so the cap check itself is O(1); see
/// [`MaskFeedbackStore::record_feedback`] for the eviction strategy used
/// when a new key would exceed it.
pub const MAX_BUCKETS: usize = 100_000;

/// FIX F.2 (§2 amplification + unbounded per-country growth): hard cap on
/// the number of distinct `mask_id` buckets held for any SINGLE
/// `country_code`, independent of and in addition to the global
/// [`MAX_BUCKETS`] cap. `country_code` is entirely client-supplied and never
/// validated against the client's real geography (see
/// [`Self::record_feedback`]'s doc comment on abuse resistance), so without
/// this a single authenticated client could report under one `country_code`
/// with an ever-varying `mask_id` (trivial — every polymorphic variant
/// mask_id is already distinct per client, see the module doc comment) and
/// grow that one country's bucket set all the way up to the entire global
/// budget. That both defeats the intent of [`MAX_BUCKETS`] as a *shared*
/// budget across regions and makes every future `top_masks_for_region` call
/// for that country (which iterates the country's whole inner map) as
/// expensive as an O(total buckets) scan would have been before the
/// country-indexed rewrite documented in the module doc comment.
///
/// Set to `MAX_BUCKETS / 10`: generous enough that no real country's
/// legitimate diversity of preset + polymorphic-variant mask ids is ever
/// throttled in practice, while guaranteeing no single `country_code` can
/// consume more than 10% of the global budget.
pub const MAX_BUCKETS_PER_COUNTRY: usize = MAX_BUCKETS / 10;

/// Number of buckets sampled (across countries, in arbitrary hashmap
/// iteration order) when the store is at capacity and a brand-new bucket
/// needs room. See [`MaskFeedbackStore::record_feedback`] for why this is
/// bounded rather than a full scan, and what guarantee it does (and does
/// not) provide.
const EVICTION_SAMPLE_SIZE: usize = 32;

/// FIX F.3 (§2 amplification): TTL for the [`MaskFeedbackStore::top_masks_for_region`]
/// result cache — see [`MaskFeedbackStore::hints_cache`]. Short enough that
/// a region's surfaced hints stay reasonably fresh (well under the
/// server-pushed `feedback_report_interval_secs` default of 3600s clients
/// wait between real reports), long enough that a burst of probes/reports
/// for the same region within the window reuses one cached scan instead of
/// re-running `Hll::estimate` over every bucket in that country under the
/// shared `buckets` mutex.
pub const REGIONAL_HINTS_CACHE_TTL: Duration = Duration::from_secs(45);

/// Default retention window (in hours) for [`MaskFeedbackStore::sweep_stale`]
/// — buckets not updated within this many hours of "now" are evicted by the
/// periodic sweep task in `gateway.rs`. 7 days.
pub const DEFAULT_RETENTION_HOURS: u64 = 7 * 24;

/// Vote-integrity cap: the maximum number of "votes" (successes, and
/// separately fails) a bucket's score computation will credit *per estimated
/// distinct reporter*. `success_count`/`fail_count` are NOT deduplicated
/// across calls (see [`MaskFeedbackStore::record_feedback`] doc comment — the
/// per-call clamp only stops a single packet from claiming more than one vote
/// per mask; nothing stops the same reporter token from calling
/// `record_feedback` many times). Without a cap here, one persistent reporter
/// with a huge raw count could dominate a bucket's surfaced success ratio
/// even though it can never fake the k-anonymity gate itself (the HLL
/// estimate stays near 1 for a repeated token).
///
/// Scoring therefore clamps `success_count`/`fail_count` to at most
/// `estimate() * MAX_VOTES_PER_REPORTER` each before computing the ratio —
/// i.e. the effective weight of the bucket is bounded as if every *estimated*
/// distinct reporter had voted at most this many times. `4` is a small,
/// generous-but-bounded allowance: a legitimate client reconnecting a few
/// times (or reporting a small batch of outcomes over a session) is not
/// penalized, while a single spamming reporter can contribute at most
/// `MAX_VOTES_PER_REPORTER` "votes" worth of skew no matter how many packets
/// it actually sends.
pub const MAX_VOTES_PER_REPORTER: u64 = 4;

/// Clamp `success_count`/`fail_count` relative to the bucket's estimated
/// distinct-reporter count (see [`MAX_VOTES_PER_REPORTER`]), then compute the
/// success ratio from the clamped counts. Used by both the direct
/// (country-level) and continent roll-up scoring paths in
/// [`MaskFeedbackStore::top_masks_for_region`] so the cap applies uniformly.
fn capped_score(success_count: u64, fail_count: u64, reporter_estimate: u64) -> f32 {
    let cap = reporter_estimate.saturating_mul(MAX_VOTES_PER_REPORTER);
    let effective_success = success_count.min(cap);
    let effective_fail = fail_count.min(cap);
    let total = effective_success + effective_fail;
    if total == 0 {
        0.0
    } else {
        effective_success as f32 / total as f32
    }
}

/// Minimal, dependency-free HyperLogLog for approximate distinct-count
/// estimation. Deliberately does NOT retain any per-reporter state — only a
/// fixed array of small "highest rank seen" counters, which is why it is
/// safe to keep server-side without becoming an identity store.
#[derive(Debug, Clone)]
pub struct Hll {
    registers: [u8; HLL_REGISTERS],
}

impl Default for Hll {
    fn default() -> Self {
        Self::new()
    }
}

impl Hll {
    pub fn new() -> Self {
        Self {
            registers: [0u8; HLL_REGISTERS],
        }
    }

    /// Fold a token into the sketch. The token is hashed with BLAKE3 and
    /// immediately discarded — only a (register index, rank) update survives,
    /// so no reporter identity is ever retained.
    pub fn add(&mut self, token: &[u8]) {
        let hash = blake3::hash(token);
        let bytes = hash.as_bytes();
        let h = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let idx = (h & (HLL_REGISTERS as u64 - 1)) as usize;
        let w = h >> HLL_BITS;
        // Rank = position of the least-significant 1 bit (+1) in the
        // remaining bits; an all-zero remainder saturates at 64 - HLL_BITS + 1.
        let rank = if w == 0 {
            (64 - HLL_BITS + 1) as u8
        } else {
            (w.trailing_zeros() as u8) + 1
        };
        if rank > self.registers[idx] {
            self.registers[idx] = rank;
        }
    }

    /// Elementwise-max merge of another sketch into this one — used to
    /// combine per-country buckets into a continent-level estimate without
    /// ever materializing the underlying tokens.
    pub fn merge(&mut self, other: &Hll) {
        for (a, b) in self.registers.iter_mut().zip(other.registers.iter()) {
            if *b > *a {
                *a = *b;
            }
        }
    }

    /// Estimate the number of distinct tokens added so far.
    pub fn estimate(&self) -> u64 {
        let m = HLL_REGISTERS as f64;
        let alpha = 0.7213 / (1.0 + 1.079 / m);
        let sum: f64 = self.registers.iter().map(|&r| 2f64.powi(-(r as i32))).sum();
        let raw = alpha * m * m / sum;

        // Small-range correction (linear counting) — standard HLL bias fix
        // for cardinalities well below the register count.
        if raw <= 2.5 * m {
            let zeros = self.registers.iter().filter(|&&r| r == 0).count();
            if zeros > 0 {
                return (m * (m / zeros as f64).ln()).round().max(0.0) as u64;
            }
        }
        raw.round().max(0.0) as u64
    }
}

/// Aggregate counters for one `(country_code, mask_id)` bucket.
#[derive(Debug, Clone)]
pub struct MaskBucket {
    pub success_count: u64,
    pub fail_count: u64,
    /// Approximate distinct-reporter count — see [`Hll`]. Never contains raw
    /// reporter identities.
    pub reporters: Hll,
    /// `unix_secs / 3600` of the most recent report folded into this bucket.
    pub last_updated_hour: u64,
}

impl MaskBucket {
    fn new() -> Self {
        Self {
            success_count: 0,
            fail_count: 0,
            reporters: Hll::new(),
            last_updated_hour: 0,
        }
    }

    /// Vote-integrity-capped success rate — see [`capped_score`] /
    /// [`MAX_VOTES_PER_REPORTER`]. This, not the raw counts, is what gets
    /// surfaced to clients.
    fn success_rate(&self) -> f32 {
        capped_score(
            self.success_count,
            self.fail_count,
            self.reporters.estimate(),
        )
    }
}

/// Small static ISO-3166-1 alpha-2 → continent-code table used for the
/// sparse-region roll-up. Covers the ~60 most common client countries;
/// unlisted codes map to themselves (no roll-up benefit, but the gate still
/// applies).
const COUNTRY_CONTINENT: &[(&str, &str)] = &[
    // North America
    ("US", "NA"),
    ("CA", "NA"),
    ("MX", "NA"),
    // South America
    ("BR", "SA"),
    ("AR", "SA"),
    ("CL", "SA"),
    ("CO", "SA"),
    ("PE", "SA"),
    ("VE", "SA"),
    ("EC", "SA"),
    // Europe
    ("GB", "EU"),
    ("DE", "EU"),
    ("FR", "EU"),
    ("IT", "EU"),
    ("ES", "EU"),
    ("NL", "EU"),
    ("PL", "EU"),
    ("SE", "EU"),
    ("NO", "EU"),
    ("FI", "EU"),
    ("DK", "EU"),
    ("CH", "EU"),
    ("AT", "EU"),
    ("BE", "EU"),
    ("PT", "EU"),
    ("IE", "EU"),
    ("GR", "EU"),
    ("CZ", "EU"),
    ("RO", "EU"),
    ("HU", "EU"),
    ("UA", "EU"),
    ("RU", "EU"),
    ("BY", "EU"),
    ("BG", "EU"),
    ("SK", "EU"),
    ("HR", "EU"),
    ("RS", "EU"),
    // Asia
    ("TR", "AS"),
    ("CN", "AS"),
    ("JP", "AS"),
    ("KR", "AS"),
    ("IN", "AS"),
    ("ID", "AS"),
    ("TH", "AS"),
    ("VN", "AS"),
    ("PH", "AS"),
    ("MY", "AS"),
    ("SG", "AS"),
    ("PK", "AS"),
    ("BD", "AS"),
    ("IR", "AS"),
    ("IQ", "AS"),
    ("SA", "AS"),
    ("AE", "AS"),
    ("IL", "AS"),
    ("KZ", "AS"),
    ("UZ", "AS"),
    ("HK", "AS"),
    ("TW", "AS"),
    // Africa
    ("EG", "AF"),
    ("NG", "AF"),
    ("ZA", "AF"),
    ("KE", "AF"),
    ("ET", "AF"),
    ("MA", "AF"),
    ("DZ", "AF"),
    ("TN", "AF"),
    ("GH", "AF"),
    ("UG", "AF"),
    // Oceania
    ("AU", "OC"),
    ("NZ", "OC"),
];

fn continent_for(country_code: &[u8; 2]) -> [u8; 2] {
    if let Ok(code) = std::str::from_utf8(country_code) {
        for (c, continent) in COUNTRY_CONTINENT {
            if *c == code {
                let bytes = continent.as_bytes();
                return [bytes[0], bytes[1]];
            }
        }
    }
    // Unknown code — default to itself (no roll-up benefit, gate still applies).
    *country_code
}

/// List every country in `continent` (per [`COUNTRY_CONTINENT`]), plus
/// `self_country` itself (covers the "unknown code maps to itself" case, and
/// is a harmless no-op if `self_country` is already listed). Bounded by the
/// fixed size of `COUNTRY_CONTINENT` (~60 entries total, at most ~25 for any
/// single continent) — independent of how many buckets are actually stored,
/// which is what keeps the continent roll-up in `top_masks_for_region` from
/// scanning the whole store.
fn continent_members(continent: &[u8; 2], self_country: &[u8; 2]) -> Vec<[u8; 2]> {
    let mut members: Vec<[u8; 2]> = COUNTRY_CONTINENT
        .iter()
        .filter(|(_, cont)| cont.as_bytes() == continent)
        .map(|(c, _)| {
            let bytes = c.as_bytes();
            [bytes[0], bytes[1]]
        })
        .collect();
    if !members.contains(self_country) {
        members.push(*self_country);
    }
    members
}

/// Render a `country_code` for logging. Client-supplied `country_code` bytes
/// are otherwise arbitrary (not validated against ISO-3166), so logging them
/// as raw `char`s risks log injection (control/format characters, ANSI
/// escapes, etc.). Real country codes are always two ASCII alphanumeric
/// characters; anything else is rendered as hex instead.
pub fn sanitize_country_code_for_log(country_code: &[u8; 2]) -> String {
    if country_code.iter().all(|b| b.is_ascii_alphanumeric()) {
        format!("{}{}", country_code[0] as char, country_code[1] as char)
    } else {
        format!("0x{:02x}{:02x}", country_code[0], country_code[1])
    }
}

/// Country-indexed bucket storage: `country_code -> mask_id -> MaskBucket`,
/// plus an incrementally-maintained total bucket count so the [`MAX_BUCKETS`]
/// cap check never has to sum up sizes across the outer map.
#[derive(Default)]
struct FeedbackMap {
    countries: HashMap<[u8; 2], HashMap<String, MaskBucket>>,
    total_buckets: usize,
}

/// One cached [`MaskFeedbackStore::top_masks_for_region`] result — see
/// [`MaskFeedbackStore::hints_cache`].
struct HintsCacheEntry {
    computed_at: Instant,
    hints: Vec<(String, f32)>,
}

/// Server-side aggregation store for crowdsourced mask feedback. Keyed by
/// `(country_code, mask_id)`, stored internally as a country-indexed nested
/// map (see [`FeedbackMap`]) so per-packet operations scale with the number
/// of masks in the relevant region, not the total store size. Behind a
/// `Mutex` — this is only touched on the (rare) control-plane path, never the
/// hot data-plane path.
pub struct MaskFeedbackStore {
    /// k-anonymity threshold — see [`DEFAULT_K_ANON`]. Kept as a field (not
    /// just a constant) so tests and future config plumbing can override it.
    pub k_anon: u64,
    /// Per-store random secret, generated once in [`Self::new`] /
    /// [`Self::with_k_anon`] and never persisted or exposed. Every reporter
    /// token is combined with this salt (see [`Self::record_feedback`])
    /// before being folded into a bucket's `Hll` sketch. Without this salt,
    /// the reporter token fed into the sketch is a deterministic function of
    /// only the client's identity (`blake3(client_id)`, computed in
    /// `gateway.rs`), which would let anyone holding a bucket's register
    /// array plus a candidate list of client ids test membership by
    /// recomputing the same hash. Salting with a value that never leaves the
    /// process makes that recomputation infeasible while still letting
    /// distinct client ids map to distinct sketch updates within a run.
    reporter_salt: [u8; 32],
    buckets: Mutex<FeedbackMap>,
    /// FIX F.3 (§2 amplification): short-TTL cache of
    /// [`Self::top_masks_for_region`]'s result, keyed by `country_code`. A
    /// separate mutex from `buckets` — populating/reading the cache never
    /// needs to hold the buckets lock. Naturally bounded: `country_code` is
    /// a fixed 2-byte key, so this can never hold more than 65,536 entries
    /// (in practice, far fewer — only codes an attacker or real client has
    /// actually queried), no separate cap needed.
    hints_cache: Mutex<HashMap<[u8; 2], HintsCacheEntry>>,
}

impl Default for MaskFeedbackStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MaskFeedbackStore {
    pub fn new() -> Self {
        Self::with_k_anon(DEFAULT_K_ANON)
    }

    pub fn with_k_anon(k_anon: u64) -> Self {
        Self {
            k_anon,
            reporter_salt: rand::random::<[u8; 32]>(),
            buckets: Mutex::new(FeedbackMap::default()),
            hints_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Evict one bucket to make room for a new one, called only when
    /// `total_buckets >= MAX_BUCKETS`. Returns `false` if there was nothing
    /// to evict (only possible if the store is empty, which can't coincide
    /// with being at capacity).
    ///
    /// **Eviction strategy — sampled (approximate) LRU, not exact global
    /// LRU.** A true exact-LRU eviction would need either an O(total
    /// buckets) scan per insert (the original bug this fixes) or an
    /// auxiliary ordered index kept in sync on every read/write. Instead
    /// this samples up to [`EVICTION_SAMPLE_SIZE`] buckets — via a lazy
    /// iterator over the nested map, `.take(N)`, so it stops after at most N
    /// entries regardless of how large any single country's inner map is —
    /// and evicts the least-recently-updated bucket *within that sample*.
    /// This is deliberately the same class of trick as Redis's
    /// approximated-LRU `maxmemory-policy`: cheap, and good enough because
    /// eviction only needs to keep the store roughly fresh, not perfectly
    /// ordered.
    ///
    /// **Guaranteed bound:** because this always runs (and always frees
    /// exactly one slot, or the caller gives up on this particular new key)
    /// before `total_buckets` is allowed to exceed [`MAX_BUCKETS`], the
    /// store never holds more than `MAX_BUCKETS` buckets in total — this is
    /// a hard cap, not just "approximately bounded". The only thing that is
    /// approximate is *which* bucket gets evicted when at capacity.
    fn evict_one(map: &mut FeedbackMap) -> bool {
        let victim = map
            .countries
            .iter()
            .flat_map(|(country, inner)| {
                inner.iter().map(move |(mask_id, bucket)| {
                    (*country, mask_id.clone(), bucket.last_updated_hour)
                })
            })
            .take(EVICTION_SAMPLE_SIZE)
            .min_by_key(|(_, _, hour)| *hour)
            .map(|(country, mask_id, _)| (country, mask_id));

        match victim {
            Some((country, mask_id)) => {
                if let Some(inner) = map.countries.get_mut(&country) {
                    inner.remove(&mask_id);
                    if inner.is_empty() {
                        map.countries.remove(&country);
                    }
                }
                map.total_buckets = map.total_buckets.saturating_sub(1);
                true
            }
            None => false,
        }
    }

    /// FIX F.2: evict the least-recently-updated bucket within a SINGLE
    /// country's inner map, called only when that country is at
    /// [`MAX_BUCKETS_PER_COUNTRY`] and a brand-new key for it would exceed
    /// the cap. Unlike [`Self::evict_one`] this never touches any other
    /// country's buckets — the whole point is that one country's cap
    /// pressure cannot spill over and steal capacity from another region.
    ///
    /// A full (not sampled) scan of the inner map is fine here: it is
    /// bounded by `MAX_BUCKETS_PER_COUNTRY` itself (a small, fixed ceiling),
    /// not by the total store size — cheap even in the worst case, unlike an
    /// unbounded per-insert scan over the whole store would be. Returns
    /// `false` only if the inner map is somehow already empty (impossible
    /// while it is simultaneously reported to be at capacity).
    fn evict_one_within_country(inner: &mut HashMap<String, MaskBucket>) -> bool {
        let victim = inner
            .iter()
            .min_by_key(|(_, bucket)| bucket.last_updated_hour)
            .map(|(mask_id, _)| mask_id.clone());
        match victim {
            Some(mask_id) => {
                inner.remove(&mask_id);
                true
            }
            None => false,
        }
    }

    /// Fold a client's batched mask outcomes into the store.
    ///
    /// `client_reporter_token` must already be a hashed, non-reversible
    /// derivation of the authenticated session's stable identity (see the
    /// gateway call site: `blake3(client_id)` — the gateway now refuses to
    /// call this at all for sessions without a stable `client_id`, see the
    /// `MaskFeedback` arm in `gateway.rs`). Before it is fed into the
    /// HyperLogLog sketch, it is combined with this store's per-process
    /// [`Self::reporter_salt`] (`blake3(salt || token)`) — see
    /// [`Self::reporter_salt`] for why this matters: it turns the sketch
    /// update into something that cannot be recomputed by anyone who does
    /// not already know the salt, closing off the membership-oracle
    /// otherwise possible from an unsalted, deterministic `blake3(client_id)`
    /// token. `Hll::add` re-hashes and discards its input either way — this
    /// store never persists the token or the salted derivation.
    ///
    /// Two abuse-resistance properties are enforced here (both required —
    /// `mask_id` and `country_code` are attacker-controlled):
    /// - **Bounded key growth.** Oversized `mask_id`s are rejected outright;
    ///   the total distinct-bucket count is capped at [`MAX_BUCKETS`] (a hard
    ///   cap across all countries combined), with sampled/approximate LRU
    ///   eviction once at capacity — see [`Self::evict_one`] for the exact
    ///   strategy and the memory bound it guarantees.
    /// - **One reporter, one vote — per call, per mask (NOT a lifetime
    ///   guarantee).** Entries are deduplicated by `mask_id` within a single
    ///   call, and each unique mask's contribution *in this call* is clamped
    ///   to at most one success *and* at most one fail — regardless of the
    ///   client-supplied `u16` magnitude or how many times the same
    ///   `mask_id` appears in the batch. This bounds what a single packet
    ///   can do, but it is not cross-call identity dedup: this store never
    ///   retains reporter identities (by design, for privacy — see the HLL
    ///   sketch above), so nothing here stops the same reporter from calling
    ///   `record_feedback` again and again. A repeat reporter only moves the
    ///   HLL distinct-reporter *estimate* by ~0 (a repeated token saturates
    ///   the sketch near its already-recorded rank), so it cannot manufacture
    ///   k-anonymity — but `success_count`/`fail_count` keep accumulating
    ///   across every call regardless of reporter, so a single persistent
    ///   reporter sending many reports CAN still skew a bucket's success
    ///   ratio even though it can never fake the distinct-reporter gate.
    pub fn record_feedback(
        &self,
        country_code: [u8; 2],
        client_reporter_token: &[u8],
        entries: &[MaskOutcome],
    ) {
        if entries.is_empty() {
            return;
        }
        let hour = current_unix_secs() / 3600;

        // Dedup by mask_id and clamp each unique mask's contribution to at
        // most one success and one fail "vote" for this call, before ever
        // touching the shared map. Oversized mask_ids are dropped here so
        // they never become bucket keys.
        let mut votes: HashMap<&str, (bool, bool)> = HashMap::new();
        for entry in entries.iter().take(64) {
            if entry.mask_id.len() > MAX_MASK_ID_LEN {
                continue;
            }
            let v = votes
                .entry(entry.mask_id.as_str())
                .or_insert((false, false));
            v.0 |= entry.success > 0;
            v.1 |= entry.fail > 0;
        }
        if votes.is_empty() {
            return;
        }

        // Salt the reporter token with this store's per-process secret
        // before it ever touches the HLL sketch — see
        // `Self::reporter_salt` for why. The salted value is only ever
        // passed to `Hll::add`, which immediately re-hashes and discards it.
        let salted_token =
            blake3::hash(&[self.reporter_salt.as_slice(), client_reporter_token].concat());

        let mut map = self.buckets.lock();
        for (mask_id, (success, fail)) in votes {
            // O(1): only looks at this one country's inner map, never the
            // whole store.
            let already_exists = map
                .countries
                .get(&country_code)
                .is_some_and(|inner| inner.contains_key(mask_id));

            if !already_exists {
                if map.total_buckets >= MAX_BUCKETS {
                    // At capacity and this is a brand-new key: evict a
                    // sampled victim to make room (see `evict_one`). If the
                    // store is somehow empty (impossible once at capacity),
                    // drop this report rather than exceeding the cap.
                    if !Self::evict_one(&mut map) {
                        continue;
                    }
                }

                // FIX F.2: also enforce the per-country cap, independent of
                // (and checked after, so it sees any global eviction that
                // just happened to land in this same country) the global
                // one — see `MAX_BUCKETS_PER_COUNTRY`'s doc comment. Only
                // this country's own bucket is ever evicted here; every
                // other country's budget is untouched.
                let country_len = map
                    .countries
                    .get(&country_code)
                    .map(|inner| inner.len())
                    .unwrap_or(0);
                if country_len >= MAX_BUCKETS_PER_COUNTRY {
                    let evicted = match map.countries.get_mut(&country_code) {
                        Some(inner) => Self::evict_one_within_country(inner),
                        None => false,
                    };
                    if evicted {
                        map.total_buckets = map.total_buckets.saturating_sub(1);
                    } else {
                        continue;
                    }
                }
            }

            let inner = map.countries.entry(country_code).or_default();
            let bucket = inner
                .entry(mask_id.to_string())
                .or_insert_with(MaskBucket::new);
            bucket.success_count = bucket.success_count.saturating_add(success as u64);
            bucket.fail_count = bucket.fail_count.saturating_add(fail as u64);
            bucket.reporters.add(salted_token.as_bytes());
            bucket.last_updated_hour = hour;

            if !already_exists {
                map.total_buckets += 1;
            }
        }
        drop(map);

        // FIX F.3 correctness: a write can change `country_code`'s own
        // direct-pass result AND any same-continent neighbor's roll-up
        // result (`top_masks_for_region`'s roll-up scans the whole
        // continent), so invalidate every same-continent member's cached
        // entry — not just `country_code`'s own — to preserve
        // read-after-write consistency. `continent_members` is the same
        // small, fixed (~25 max) table the roll-up itself uses, so this is
        // cheap. (We already returned early above if `votes` was empty, so
        // reaching here means at least one write was attempted.)
        let continent = continent_for(&country_code);
        let affected = continent_members(&continent, &country_code);
        let mut cache = self.hints_cache.lock();
        for member in &affected {
            cache.remove(member);
        }
    }

    /// Evict buckets that have not been updated within `max_age_hours` of
    /// `now_hour`. Intended to be called periodically (see the gateway's
    /// mask-feedback sweep task, which mirrors the existing `rate_limits` /
    /// `handshake_cooldowns` cleanup pattern) so that stale, low-traffic
    /// `(country_code, mask_id)` buckets don't sit in memory forever between
    /// the (already-enforced) capacity-eviction events. Returns the number of
    /// buckets removed.
    pub fn sweep_stale(&self, now_hour: u64, max_age_hours: u64) -> usize {
        let mut map = self.buckets.lock();
        let mut removed = 0usize;
        map.countries.retain(|_, inner| {
            let before = inner.len();
            inner.retain(|_, b| now_hour.saturating_sub(b.last_updated_hour) <= max_age_hours);
            removed += before - inner.len();
            !inner.is_empty()
        });
        map.total_buckets = map.total_buckets.saturating_sub(removed);

        // Also drop expired hints-cache entries here — piggybacks on this
        // same periodic sweep rather than needing its own task. Purely a
        // memory-tidiness measure: an expired entry is already ignored by
        // `cached_hints` (see the TTL check there), this just reclaims the
        // space instead of leaving it until that `country_code` is queried
        // again.
        self.hints_cache
            .lock()
            .retain(|_, entry| entry.computed_at.elapsed() < REGIONAL_HINTS_CACHE_TTL);

        removed
    }

    /// Total number of `(country_code, mask_id)` buckets currently held,
    /// across all countries. Mirrors `FeedbackMap::total_buckets`, which is
    /// maintained incrementally (see `record_feedback` / `sweep_stale`) so
    /// this is O(1) rather than a full-store scan. Exposed for the `metrics`
    /// feature's `aivpn_feedback_buckets` gauge.
    pub fn bucket_count(&self) -> usize {
        self.buckets.lock().total_buckets
    }

    /// Number of distinct countries with at least one bucket. O(1) via
    /// `HashMap::len` on the outer country-indexed map. Exposed for the
    /// `metrics` feature's `aivpn_feedback_regions` gauge.
    pub fn region_count(&self) -> usize {
        self.buckets.lock().countries.len()
    }

    /// Return `(mask_id, success_rate)` pairs for `country_code`, sorted by
    /// success rate descending. Only ever includes a mask if its aggregate
    /// (country-level, or continent roll-up for sparse regions) distinct
    /// reporter estimate is `>= self.k_anon` — the k-anonymity gate, checked
    /// on both surfaces.
    ///
    /// **Roll-up completeness.** The continent roll-up candidate set is the
    /// *union* of every mask_id reported by any same-continent member
    /// country — not just the masks `country_code` itself has a (sub-
    /// threshold) local bucket for. This matters for a country with **zero**
    /// local reports for some mask `Y`: without the union, such a country
    /// would never even attempt the roll-up for `Y` (it has no local entry to
    /// seed `below_threshold` with), so it could never benefit from
    /// same-continent neighbors' reports no matter how many of them there
    /// are. With the union, `Y` is considered as a candidate as soon as *any*
    /// continent member has reported it, and is surfaced once the
    /// continent-aggregated distinct-reporter estimate clears `k_anon` — same
    /// gate as before, just no longer gated on the querying country having a
    /// local (even sub-threshold) bucket to begin with.
    ///
    /// The direct country-level pass remains the priority (a mask satisfied
    /// locally is never re-scored via roll-up); the roll-up only fills gaps
    /// for masks that missed the direct gate or have no local bucket at all.
    ///
    /// Complexity: the direct pass is O(masks reported for `country_code`).
    /// The roll-up pass is O(masks reported across the continent's member
    /// countries) — bounded by the small, fixed member-country list (see
    /// [`continent_members`], ~25 entries at most) times however many masks
    /// each of those countries has reported, each unit of work being an O(1)
    /// hash lookup. This is still country/continent-scoped, not O(total
    /// buckets held for unrelated continents).
    ///
    /// FIX F.3 (§2 amplification): fronted by a short-TTL cache (see
    /// [`Self::hints_cache`] / [`REGIONAL_HINTS_CACHE_TTL`]) — a burst of
    /// calls for the same `country_code` within the TTL reuses one scan
    /// instead of re-locking `buckets` and re-running `Hll::estimate` for
    /// every mask in the region on every call. The k-anonymity gate is
    /// applied exactly once, when the (uncached) scan actually runs; the
    /// cache only ever stores an already-gated result, so caching cannot
    /// leak a sub-threshold bucket that a fresh scan would have withheld.
    pub fn top_masks_for_region(&self, country_code: [u8; 2]) -> Vec<(String, f32)> {
        if let Some(cached) = self.cached_hints(&country_code) {
            return cached;
        }
        let result = self.compute_top_masks_for_region(country_code);
        self.hints_cache.lock().insert(
            country_code,
            HintsCacheEntry {
                computed_at: Instant::now(),
                hints: result.clone(),
            },
        );
        result
    }

    /// Return a still-fresh (`< REGIONAL_HINTS_CACHE_TTL` old) cached
    /// [`Self::top_masks_for_region`] result for `country_code`, if any.
    fn cached_hints(&self, country_code: &[u8; 2]) -> Option<Vec<(String, f32)>> {
        let cache = self.hints_cache.lock();
        let entry = cache.get(country_code)?;
        if entry.computed_at.elapsed() < REGIONAL_HINTS_CACHE_TTL {
            Some(entry.hints.clone())
        } else {
            None
        }
    }

    /// The actual (uncached) region scan — see [`Self::top_masks_for_region`]
    /// for the full contract; this is the same logic, just factored out so
    /// the TTL-cache wrapper above can sit in front of it.
    fn compute_top_masks_for_region(&self, country_code: [u8; 2]) -> Vec<(String, f32)> {
        let map = self.buckets.lock();

        let mut satisfied: Vec<(String, f32)> = Vec::new();

        if let Some(inner) = map.countries.get(&country_code) {
            for (mask_id, bucket) in inner.iter() {
                if bucket.reporters.estimate() >= self.k_anon {
                    satisfied.push((mask_id.clone(), bucket.success_rate()));
                }
            }
        }

        // Roll-up candidate set: every mask_id reported by *any* member of
        // `country_code`'s continent (union, not just `country_code`'s own
        // masks) — see the doc comment above for why this must not be
        // restricted to masks the querying country already knows about.
        let continent = continent_for(&country_code);
        let members = continent_members(&continent, &country_code);
        let mut candidates: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for member in &members {
            if let Some(inner) = map.countries.get(member) {
                candidates.extend(inner.keys().map(String::as_str));
            }
        }

        for mask_id in candidates {
            if satisfied.iter().any(|(m, _)| m == mask_id) {
                // Already satisfied directly — direct pass takes priority,
                // roll-up only fills gaps.
                continue;
            }
            let mut merged = Hll::new();
            let mut success = 0u64;
            let mut fail = 0u64;
            for member in &members {
                if let Some(bucket) = map
                    .countries
                    .get(member)
                    .and_then(|inner| inner.get(mask_id))
                {
                    merged.merge(&bucket.reporters);
                    success = success.saturating_add(bucket.success_count);
                    fail = fail.saturating_add(bucket.fail_count);
                }
            }
            // k-anonymity gate, re-checked on this (continent-level) surface
            // — never surface a merged bucket below k_anon either, same rule
            // as the direct country-level pass above.
            let estimate = merged.estimate();
            if estimate >= self.k_anon {
                // Same vote-integrity cap as the direct pass — see
                // `capped_score` / `MAX_VOTES_PER_REPORTER` — applied to the
                // continent-aggregated counts so one member country
                // dominated by a single spamming reporter cannot skew the
                // whole continent's score either.
                let score = capped_score(success, fail, estimate);
                satisfied.push((mask_id.to_string(), score));
            }
        }

        satisfied.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        satisfied.truncate(32);
        satisfied
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hll_estimate_within_tolerance_for_100_distinct_tokens() {
        let mut hll = Hll::new();
        for i in 0..100u32 {
            hll.add(&i.to_le_bytes());
        }
        let est = hll.estimate();
        let lo = 90u64; // -10%
        let hi = 110u64; // +10%
        assert!(
            (lo..=hi).contains(&est),
            "estimate {} not within 10% of 100",
            est
        );
    }

    #[test]
    fn hll_estimate_within_tolerance_for_1000_distinct_tokens() {
        let mut hll = Hll::new();
        for i in 0..1000u32 {
            hll.add(&i.to_le_bytes());
        }
        let est = hll.estimate();
        let lo = 900u64;
        let hi = 1100u64;
        assert!(
            (lo..=hi).contains(&est),
            "estimate {} not within 10% of 1000",
            est
        );
    }

    #[test]
    fn hll_repeated_token_does_not_inflate_estimate() {
        let mut hll = Hll::new();
        for _ in 0..500 {
            hll.add(b"same-token-every-time");
        }
        assert!(hll.estimate() <= 3, "repeated token should stay near 1");
    }

    #[test]
    fn hll_merge_matches_union_estimate() {
        let mut a = Hll::new();
        let mut b = Hll::new();
        for i in 0..500u32 {
            a.add(&i.to_le_bytes());
        }
        for i in 500..1000u32 {
            b.add(&i.to_le_bytes());
        }
        let mut merged = Hll::new();
        merged.merge(&a);
        merged.merge(&b);

        let mut union = Hll::new();
        for i in 0..1000u32 {
            union.add(&i.to_le_bytes());
        }
        // Merged and directly-built union sketches should agree closely.
        let diff = (merged.estimate() as i64 - union.estimate() as i64).abs();
        assert!(diff <= 5, "merged vs union estimate diverged: {}", diff);
    }

    /// Privacy fix: the reporter token fed to a bucket's HLL must be salted
    /// with a per-store secret, not the raw (unsalted) token an attacker
    /// could recompute themselves (e.g. `blake3(client_id)`, as computed at
    /// the gateway call site). Verify this indirectly, without exposing the
    /// private `reporter_salt` field: two stores seeded with the exact same
    /// sequence of raw reporter tokens must NOT end up with identical HLL
    /// register state, because each store draws its own random salt in
    /// `new()`.
    #[test]
    fn reporter_token_is_salted_differently_per_store() {
        let store_a = MaskFeedbackStore::new();
        let store_b = MaskFeedbackStore::new();
        for i in 0..30u32 {
            let token = format!("reporter-{i}");
            store_a.record_feedback(*b"US", token.as_bytes(), &[outcome("mask_a", 1, 0)]);
            store_b.record_feedback(*b"US", token.as_bytes(), &[outcome("mask_a", 1, 0)]);
        }
        let map_a = store_a.buckets.lock();
        let map_b = store_b.buckets.lock();
        let regs_a = get_bucket(&map_a, b"US", "mask_a")
            .unwrap()
            .reporters
            .registers;
        let regs_b = get_bucket(&map_b, b"US", "mask_a")
            .unwrap()
            .reporters
            .registers;
        assert_ne!(
            regs_a, regs_b,
            "two independently-salted stores fed the identical raw token \
             sequence must not produce identical HLL register state — an \
             unsalted (deterministic) token would make this test flaky-pass \
             by producing identical registers every time"
        );
    }

    /// Salting must not break the store's own ability to count distinct
    /// reporters within a single run — only cross-run/offline recomputation
    /// (the membership-oracle attack) should be defeated. A store salting
    /// consistently with itself must still see ~N distinct reporters for N
    /// distinct raw tokens.
    #[test]
    fn salted_hll_still_counts_distinct_reporters_correctly() {
        let store = MaskFeedbackStore::with_k_anon(1);
        for i in 0..25u32 {
            let token = format!("reporter-{i}");
            store.record_feedback(*b"US", token.as_bytes(), &[outcome("mask_a", 1, 0)]);
        }
        let map = store.buckets.lock();
        let estimate = get_bucket(&map, b"US", "mask_a")
            .unwrap()
            .reporters
            .estimate();
        assert!(
            (20..=30).contains(&estimate),
            "salted estimate {} should still be close to the true 25 distinct reporters",
            estimate
        );
    }

    fn outcome(mask_id: &str, success: u16, fail: u16) -> MaskOutcome {
        MaskOutcome {
            mask_id: mask_id.to_string(),
            success,
            fail,
        }
    }

    /// Look up a bucket directly for test assertions.
    fn get_bucket<'a>(
        map: &'a FeedbackMap,
        country: &[u8; 2],
        mask_id: &str,
    ) -> Option<&'a MaskBucket> {
        map.countries
            .get(country)
            .and_then(|inner| inner.get(mask_id))
    }

    #[test]
    fn record_feedback_ignores_empty_entries() {
        let store = MaskFeedbackStore::new();
        store.record_feedback(*b"US", b"reporter-1", &[]);
        assert!(store.top_masks_for_region(*b"US").is_empty());
    }

    #[test]
    fn top_masks_hidden_below_k_anon_threshold() {
        let store = MaskFeedbackStore::with_k_anon(20);
        // Only 5 distinct reporters — below k=20.
        for i in 0..5u32 {
            let token = format!("reporter-{i}");
            store.record_feedback(
                *b"US",
                token.as_bytes(),
                &[outcome("webrtc_zoom_v3", 10, 0)],
            );
        }
        assert!(
            store.top_masks_for_region(*b"US").is_empty(),
            "sub-threshold country bucket must not surface, and continent \
             roll-up should also stay below k=20 with only 5 reporters"
        );
    }

    #[test]
    fn top_masks_surfaced_once_k_anon_met() {
        let store = MaskFeedbackStore::with_k_anon(20);
        // Each reporter contributes at most one vote per call (see the
        // per-reporter clamp), so build the ~0.9 success ratio out of 23
        // success-only reports and 2 fail-only reports (23/25 = 0.92).
        for i in 0..25u32 {
            let token = format!("reporter-{i}");
            let vote = if i < 23 {
                outcome("quic_https", 1, 0)
            } else {
                outcome("quic_https", 0, 1)
            };
            store.record_feedback(*b"DE", token.as_bytes(), &[vote]);
        }
        let top = store.top_masks_for_region(*b"DE");
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].0, "quic_https");
        assert!((top[0].1 - 0.9).abs() < 0.05);
    }

    #[test]
    fn sparse_country_rolls_up_to_continent_when_threshold_met() {
        let store = MaskFeedbackStore::with_k_anon(20);
        // 12 distinct reporters in Portugal, 12 in Ireland — neither alone
        // meets k=20, but both are EU and together they do.
        for i in 0..12u32 {
            let token = format!("pt-reporter-{i}");
            store.record_feedback(*b"PT", token.as_bytes(), &[outcome("mask_a", 5, 5)]);
        }
        for i in 0..12u32 {
            let token = format!("ie-reporter-{i}");
            store.record_feedback(*b"IE", token.as_bytes(), &[outcome("mask_a", 5, 5)]);
        }
        assert!(!store.top_masks_for_region(*b"PT").is_empty());
        let top = store.top_masks_for_region(*b"PT");
        assert_eq!(top[0].0, "mask_a");
    }

    #[test]
    fn unknown_country_code_has_no_rollup_benefit() {
        let store = MaskFeedbackStore::with_k_anon(20);
        for i in 0..5u32 {
            let token = format!("zz-reporter-{i}");
            store.record_feedback(*b"ZZ", token.as_bytes(), &[outcome("mask_a", 5, 5)]);
        }
        // "ZZ" is not in the continent table, so it maps to itself and never
        // gets a roll-up boost from other countries.
        assert!(store.top_masks_for_region(*b"ZZ").is_empty());
    }

    #[test]
    fn continent_lookup_covers_common_countries() {
        assert_eq!(continent_for(b"US"), *b"NA");
        assert_eq!(continent_for(b"DE"), *b"EU");
        assert_eq!(continent_for(b"JP"), *b"AS");
        assert_eq!(continent_for(b"ZA"), *b"AF");
        assert_eq!(continent_for(b"AU"), *b"OC");
        assert_eq!(continent_for(b"BR"), *b"SA");
        // Unknown code maps to itself.
        assert_eq!(continent_for(b"ZZ"), *b"ZZ");
    }

    #[test]
    fn continent_members_includes_all_table_entries_and_self() {
        let na = continent_members(b"NA", b"US");
        assert!(na.contains(b"US"));
        assert!(na.contains(b"CA"));
        assert!(na.contains(b"MX"));

        // Unknown continent code + unknown self country: falls back to just
        // the self country (mirrors "unknown code has no rollup benefit").
        let unknown = continent_members(b"ZZ", b"ZZ");
        assert_eq!(unknown, vec![*b"ZZ"]);
    }

    /// `bucket_count`/`region_count` back the `aivpn_feedback_buckets` /
    /// `aivpn_feedback_regions` metrics gauges — must track a store that
    /// starts empty, grows across two distinct countries and two distinct
    /// masks, and reflects both dimensions independently (2 buckets, 2
    /// regions here since each country reports a different mask).
    #[test]
    fn bucket_and_region_count_track_store_growth() {
        let store = MaskFeedbackStore::new();
        assert_eq!(store.bucket_count(), 0);
        assert_eq!(store.region_count(), 0);

        store.record_feedback(*b"US", b"reporter-1", &[outcome("mask_a", 1, 0)]);
        assert_eq!(store.bucket_count(), 1);
        assert_eq!(store.region_count(), 1);

        store.record_feedback(*b"DE", b"reporter-2", &[outcome("mask_b", 1, 0)]);
        assert_eq!(store.bucket_count(), 2);
        assert_eq!(store.region_count(), 2);

        // A second report for the same (country, mask) pair updates the
        // existing bucket in place — counts must not double-count it.
        store.record_feedback(*b"US", b"reporter-3", &[outcome("mask_a", 1, 0)]);
        assert_eq!(store.bucket_count(), 2);
        assert_eq!(store.region_count(), 2);
    }

    #[test]
    fn oversized_mask_id_is_rejected() {
        let store = MaskFeedbackStore::new();
        let huge_id = "x".repeat(MAX_MASK_ID_LEN + 1);
        store.record_feedback(*b"US", b"reporter-1", &[outcome(&huge_id, 1, 0)]);
        let map = store.buckets.lock();
        assert_eq!(
            map.total_buckets, 0,
            "oversized mask_id must not create a bucket"
        );
        assert!(map.countries.is_empty());
    }

    #[test]
    fn mask_id_at_max_length_is_accepted() {
        let store = MaskFeedbackStore::new();
        let max_id = "x".repeat(MAX_MASK_ID_LEN);
        store.record_feedback(*b"US", b"reporter-1", &[outcome(&max_id, 1, 0)]);
        let map = store.buckets.lock();
        assert_eq!(map.total_buckets, 1);
    }

    #[test]
    fn bucket_count_is_capped_at_scale() {
        let store = MaskFeedbackStore::new();
        // Fill the store to MAX_BUCKETS, spread across
        // MAX_BUCKETS / MAX_BUCKETS_PER_COUNTRY countries at exactly the
        // per-country cap each (post-FIX-F.2, a single country can never
        // legitimately hold more than MAX_BUCKETS_PER_COUNTRY — see
        // `per_country_bucket_cap_prevents_single_country_concentration`
        // below for that invariant in isolation). We can't literally
        // allocate 100_000 buckets in a unit test in reasonable time via the
        // public API's per-call cost, so instead we pre-seed the map
        // directly (same crate, test has field access) and confirm
        // record_feedback respects the hard global cap at the boundary.
        //
        // Note: global eviction here is a *sampled/approximate* LRU (see
        // `evict_one`'s docs), so we cannot assert which specific bucket
        // gets evicted, or even guarantee only ONE eviction fires — if the
        // global-cap sample happens to miss the target country, the
        // still-full per-country cap fires a second, country-scoped
        // eviction for the same insert (see `record_feedback`). What we can
        // and do assert is the property that actually matters for the DoS
        // fix: the cap is a hard ceiling (never exceeded) and inserting a
        // new key when full always succeeds.
        let countries: Vec<[u8; 2]> = (0..(MAX_BUCKETS / MAX_BUCKETS_PER_COUNTRY) as u8)
            .map(|i| [b'A', b'A' + i])
            .collect();
        {
            let mut map = store.buckets.lock();
            for country in &countries {
                let inner = map.countries.entry(*country).or_default();
                for i in 0..MAX_BUCKETS_PER_COUNTRY {
                    let mut bucket = MaskBucket::new();
                    bucket.last_updated_hour = i as u64; // increasing "recency"
                    inner.insert(format!("mask-{i}"), bucket);
                }
            }
            map.total_buckets = MAX_BUCKETS;
        }

        let target_country = countries[0];
        store.record_feedback(
            target_country,
            b"reporter-1",
            &[outcome("brand-new-mask", 1, 0)],
        );

        let map = store.buckets.lock();
        assert!(
            map.total_buckets <= MAX_BUCKETS,
            "bucket count must never exceed MAX_BUCKETS (was {})",
            map.total_buckets
        );
        assert!(
            get_bucket(&map, &target_country, "brand-new-mask").is_some(),
            "new report should have been accepted after eviction"
        );
        for country in &countries {
            let len = map.countries.get(country).map(|i| i.len()).unwrap_or(0);
            assert!(
                len <= MAX_BUCKETS_PER_COUNTRY,
                "country {:?} must never exceed MAX_BUCKETS_PER_COUNTRY (was {})",
                country,
                len
            );
        }
    }

    /// FIX F.2 regression test: the vulnerability this fix closes. Before
    /// it, `MAX_BUCKETS` was the ONLY cap, so — since `country_code` is
    /// entirely client-supplied — a single authenticated client varying
    /// `mask_id` under one `country_code` (trivial: every polymorphic
    /// variant mask_id is already distinct per client) could grow that one
    /// country's bucket set all the way to the full global budget, starving
    /// every other region and making `top_masks_for_region` scans for that
    /// country as expensive as the pre-country-indexed O(total buckets) bug.
    /// Now growth for a single `country_code` must stop at
    /// `MAX_BUCKETS_PER_COUNTRY`, well below `MAX_BUCKETS`, and other
    /// countries are provably unaffected by one country's cap pressure.
    #[test]
    fn per_country_bucket_cap_prevents_single_country_concentration() {
        let store = MaskFeedbackStore::new();
        // Fill "US" to exactly its per-country cap directly (same
        // pre-seeding trick as `bucket_count_is_capped_at_scale`, well below
        // the global MAX_BUCKETS so only the per-country cap is exercised).
        {
            let mut map = store.buckets.lock();
            let inner = map.countries.entry(*b"US").or_default();
            for i in 0..MAX_BUCKETS_PER_COUNTRY {
                let mut bucket = MaskBucket::new();
                bucket.last_updated_hour = i as u64;
                inner.insert(format!("mask-{i}"), bucket);
            }
            map.total_buckets = MAX_BUCKETS_PER_COUNTRY;
        }

        // One more report for a BRAND NEW mask_id under the SAME
        // (already-at-cap) country must not grow that country past its cap
        // — it must evict a within-country victim instead.
        store.record_feedback(*b"US", b"reporter-1", &[outcome("brand-new-us-mask", 1, 0)]);

        // A completely different country, queried at the same time, must be
        // entirely unaffected by US's cap pressure — proving the cap is
        // per-country, not a disguised global throttle.
        store.record_feedback(*b"DE", b"reporter-2", &[outcome("de-mask", 1, 0)]);

        let map = store.buckets.lock();
        let us_len = map.countries.get(b"US").map(|i| i.len()).unwrap_or(0);
        assert_eq!(
            us_len, MAX_BUCKETS_PER_COUNTRY,
            "US bucket count must stay pinned at the per-country cap, not grow past it"
        );
        assert!(
            get_bucket(&map, b"US", "brand-new-us-mask").is_some(),
            "new US report must still be accepted after within-country eviction"
        );
        assert!(
            get_bucket(&map, b"DE", "de-mask").is_some(),
            "DE must be entirely unaffected by US's per-country cap"
        );
        assert!(
            MAX_BUCKETS_PER_COUNTRY < MAX_BUCKETS,
            "the per-country cap must be strictly below the global cap, \
             otherwise it provides no protection at all"
        );
    }

    #[test]
    fn eviction_picks_least_recently_updated_within_sample() {
        // With a candidate set smaller than EVICTION_SAMPLE_SIZE, the sample
        // covers every bucket, so eviction is deterministic: the globally
        // oldest bucket must be the one removed.
        let store = MaskFeedbackStore::new();
        {
            let mut map = store.buckets.lock();
            let hours = [
                (*b"US", "old", 1u64),
                (*b"US", "mid", 50),
                (*b"DE", "new", 100),
            ];
            for (country, mask_id, hour) in hours {
                let mut bucket = MaskBucket::new();
                bucket.last_updated_hour = hour;
                map.countries
                    .entry(country)
                    .or_default()
                    .insert(mask_id.to_string(), bucket);
                map.total_buckets += 1;
            }
            // Force capacity so the next new key triggers eviction.
            map.total_buckets = MAX_BUCKETS;
        }

        store.record_feedback(*b"FR", b"reporter-1", &[outcome("newest", 1, 0)]);

        let map = store.buckets.lock();
        assert!(
            get_bucket(&map, b"US", "old").is_none(),
            "the globally oldest bucket in the (small) sample must be evicted"
        );
        assert!(get_bucket(&map, b"US", "mid").is_some());
        assert!(get_bucket(&map, b"DE", "new").is_some());
        assert!(get_bucket(&map, b"FR", "newest").is_some());
        assert_eq!(map.total_buckets, MAX_BUCKETS);
    }

    #[test]
    fn sweep_stale_removes_old_buckets_but_keeps_recent_ones() {
        let store = MaskFeedbackStore::new();
        store.record_feedback(*b"US", b"reporter-1", &[outcome("old-mask", 1, 0)]);
        {
            // Backdate the bucket well past the retention window.
            let mut map = store.buckets.lock();
            let bucket = map
                .countries
                .get_mut(b"US")
                .unwrap()
                .get_mut("old-mask")
                .unwrap();
            bucket.last_updated_hour = 0;
        }
        store.record_feedback(*b"US", b"reporter-2", &[outcome("fresh-mask", 1, 0)]);

        let now_hour = 1000u64;
        let removed = store.sweep_stale(now_hour, DEFAULT_RETENTION_HOURS);
        assert_eq!(removed, 1, "only the backdated bucket should be swept");

        let map = store.buckets.lock();
        assert!(get_bucket(&map, b"US", "old-mask").is_none());
        assert!(get_bucket(&map, b"US", "fresh-mask").is_some());
        assert_eq!(map.total_buckets, 1);
    }

    #[test]
    fn sweep_stale_drops_empty_country_maps() {
        let store = MaskFeedbackStore::new();
        store.record_feedback(*b"US", b"reporter-1", &[outcome("old-mask", 1, 0)]);
        {
            let mut map = store.buckets.lock();
            map.countries
                .get_mut(b"US")
                .unwrap()
                .get_mut("old-mask")
                .unwrap()
                .last_updated_hour = 0;
        }
        let removed = store.sweep_stale(1000, DEFAULT_RETENTION_HOURS);
        assert_eq!(removed, 1);
        let map = store.buckets.lock();
        assert!(
            !map.countries.contains_key(b"US"),
            "country map with no remaining buckets should be dropped, not left empty"
        );
    }

    #[test]
    fn sweep_stale_is_noop_when_nothing_is_old() {
        let store = MaskFeedbackStore::new();
        store.record_feedback(*b"US", b"reporter-1", &[outcome("mask_a", 1, 0)]);
        let now_hour = current_unix_secs() / 3600;
        let removed = store.sweep_stale(now_hour, DEFAULT_RETENTION_HOURS);
        assert_eq!(removed, 0);
        assert_eq!(store.buckets.lock().total_buckets, 1);
    }

    #[test]
    fn per_reporter_vote_is_clamped_regardless_of_magnitude() {
        let store = MaskFeedbackStore::with_k_anon(1);
        // A single reporter sends one entry with a huge client-supplied
        // magnitude — this must contribute at most 1 to success_count, not
        // 65535, no matter what the client claims.
        store.record_feedback(*b"US", b"reporter-1", &[outcome("mask_a", 65535, 0)]);
        let map = store.buckets.lock();
        let bucket = get_bucket(&map, b"US", "mask_a").unwrap();
        assert_eq!(bucket.success_count, 1);
        assert_eq!(bucket.fail_count, 0);
    }

    #[test]
    fn repeated_mask_id_within_one_call_is_deduplicated_and_clamped() {
        let store = MaskFeedbackStore::with_k_anon(1);
        // Same mask_id reported 10 times in a single call — must still only
        // contribute one success vote total, not ten.
        let entries: Vec<MaskOutcome> = (0..10).map(|_| outcome("mask_a", 1, 0)).collect();
        store.record_feedback(*b"US", b"reporter-1", &entries);
        let map = store.buckets.lock();
        let bucket = get_bucket(&map, b"US", "mask_a").unwrap();
        assert_eq!(bucket.success_count, 1);
        assert_eq!(bucket.fail_count, 0);
    }

    #[test]
    fn single_call_can_still_contribute_to_multiple_distinct_masks() {
        let store = MaskFeedbackStore::with_k_anon(1);
        store.record_feedback(
            *b"US",
            b"reporter-1",
            &[outcome("mask_a", 1, 0), outcome("mask_b", 0, 1)],
        );
        let map = store.buckets.lock();
        assert_eq!(get_bucket(&map, b"US", "mask_a").unwrap().success_count, 1);
        assert_eq!(get_bucket(&map, b"US", "mask_b").unwrap().fail_count, 1);
    }

    #[test]
    fn repeat_reporter_across_calls_can_still_skew_success_ratio() {
        // Documents the corrected comment on record_feedback: the per-call
        // clamp is not a lifetime one-reporter-one-vote guarantee. The same
        // reporter token calling record_feedback many times keeps
        // accumulating success/fail counts.
        let store = MaskFeedbackStore::with_k_anon(1);
        for _ in 0..50 {
            store.record_feedback(*b"US", b"same-reporter", &[outcome("mask_a", 1, 0)]);
        }
        let map = store.buckets.lock();
        let bucket = get_bucket(&map, b"US", "mask_a").unwrap();
        assert_eq!(
            bucket.success_count, 50,
            "success_count accumulates across calls from the same reporter token"
        );
        // But the HLL distinct-reporter estimate stays near 1 — it cannot be
        // used to manufacture k-anonymity.
        assert!(bucket.reporters.estimate() <= 2);
    }

    #[test]
    fn vote_integrity_cap_bounds_score_for_single_spamming_reporter() {
        // One real (distinct) reporter, but the raw success_count has been
        // driven far above what a single reporter should ever be able to
        // claim (e.g. by resending many packets across many calls — see
        // `repeat_reporter_across_calls_can_still_skew_success_ratio`).
        // Without the vote-integrity cap this would surface as a
        // near-perfect (~0.9999) success rate off of a single reporter.
        let store = MaskFeedbackStore::with_k_anon(1);
        store.record_feedback(*b"US", b"reporter-1", &[outcome("mask_a", 1, 0)]);
        let reporter_estimate = {
            let map = store.buckets.lock();
            get_bucket(&map, b"US", "mask_a")
                .unwrap()
                .reporters
                .estimate()
        };
        {
            let mut map = store.buckets.lock();
            let bucket = map
                .countries
                .get_mut(b"US")
                .unwrap()
                .get_mut("mask_a")
                .unwrap();
            bucket.success_count = 10_000;
            bucket.fail_count = 1;
        }

        let top = store.top_masks_for_region(*b"US");
        assert_eq!(top.len(), 1);
        let score = top[0].1;

        let uncapped_ratio = 10_000.0 / 10_001.0;
        assert!(
            score < uncapped_ratio - 0.1,
            "score {} should be well below the uncapped ratio {} — the vote \
             cap must bound the effective weight of a single reporter",
            score,
            uncapped_ratio
        );

        // Effective success/fail are each clamped to
        // `reporter_estimate * MAX_VOTES_PER_REPORTER` before the ratio is
        // computed — i.e. the score must be exactly as if this bucket had at
        // most `MAX_VOTES_PER_REPORTER` successes per estimated reporter.
        let cap = reporter_estimate * MAX_VOTES_PER_REPORTER;
        let expected = cap as f32 / (cap as f32 + 1.0);
        assert!(
            (score - expected).abs() < 0.01,
            "score {} should equal the capped ratio {} (cap={})",
            score,
            expected,
            cap
        );
    }

    #[test]
    fn capped_score_matches_raw_ratio_when_well_under_cap() {
        // Sanity check that the cap does not distort ordinary, non-abusive
        // traffic: with plenty of estimated reporters relative to the raw
        // counts, capped_score should equal the raw success ratio.
        assert!((capped_score(23, 2, 25) - 23.0 / 25.0).abs() < 1e-6);
    }

    #[test]
    fn capped_score_handles_zero_estimate_without_panic() {
        // Defensive: should never be reachable past the k_anon gate in
        // practice (estimate would be >= k_anon >= 1), but must not panic or
        // divide by zero if it ever is.
        assert_eq!(capped_score(100, 100, 0), 0.0);
    }

    #[test]
    fn continent_rollup_surfaces_mask_with_zero_local_reports() {
        // DE and FR (both EU) each get 12 distinct reporters for a mask that
        // IT has *never* reported at all — IT has no bucket for it, not even
        // a sub-threshold one. Combined, DE+FR clear k_anon=20, so IT must
        // still receive it via the continent roll-up.
        let store = MaskFeedbackStore::with_k_anon(20);
        for i in 0..12u32 {
            let token = format!("de-reporter-{i}");
            store.record_feedback(
                *b"DE",
                token.as_bytes(),
                &[outcome("never_seen_locally_mask", 5, 5)],
            );
        }
        for i in 0..12u32 {
            let token = format!("fr-reporter-{i}");
            store.record_feedback(
                *b"FR",
                token.as_bytes(),
                &[outcome("never_seen_locally_mask", 5, 5)],
            );
        }

        {
            // Confirm the premise: IT has no bucket for this mask (or any
            // mask) at all before querying.
            let map = store.buckets.lock();
            assert!(get_bucket(&map, b"IT", "never_seen_locally_mask").is_none());
        }

        let top = store.top_masks_for_region(*b"IT");
        assert!(
            top.iter().any(|(m, _)| m == "never_seen_locally_mask"),
            "a country with zero local reports for a mask must still receive \
             it once same-continent neighbors collectively clear k-anon"
        );
    }

    #[test]
    fn sanitize_country_code_for_log_accepts_ascii_alphanumeric() {
        assert_eq!(sanitize_country_code_for_log(b"US"), "US");
        assert_eq!(sanitize_country_code_for_log(b"DE"), "DE");
    }

    #[test]
    fn sanitize_country_code_for_log_hex_escapes_non_alphanumeric() {
        // Control character / non-alphanumeric bytes must never be emitted
        // as raw chars into the log stream.
        let malicious = [0x1bu8, b'X']; // ESC + 'X'
        assert_eq!(sanitize_country_code_for_log(&malicious), "0x1b58");
    }

    #[test]
    fn top_masks_for_region_is_country_scoped_and_fast_with_many_unrelated_buckets() {
        // Regression test for the O(buckets) DoS: seed a large number of
        // buckets spread across many *other* countries directly (bypassing
        // the public API for speed — this is just populating a HashMap, not
        // exercising record_feedback), then confirm top_masks_for_region for
        // an unrelated country is both correct and fast. Before the fix this
        // scanned the entire store (both the direct pass and, for each
        // below-threshold mask, the roll-up pass) regardless of how many
        // buckets belonged to other countries.
        let store = MaskFeedbackStore::with_k_anon(20);
        {
            let mut map = store.buckets.lock();
            for i in 0..50_000u32 {
                let country = [b'A' + (i % 26) as u8, b'A' + ((i / 26) % 26) as u8];
                if country == *b"US" || country == *b"CA" || country == *b"MX" {
                    continue; // keep NA (US's continent) untouched by noise
                }
                let mut bucket = MaskBucket::new();
                bucket.last_updated_hour = i as u64;
                map.countries
                    .entry(country)
                    .or_default()
                    .insert(format!("mask-{i}"), bucket);
                map.total_buckets += 1;
            }
        }

        // A satisfied US bucket (23 success + 2 fail across 25 reporters).
        for i in 0..25u32 {
            let token = format!("reporter-{i}");
            let vote = if i < 23 {
                outcome("quic_https", 1, 0)
            } else {
                outcome("quic_https", 0, 1)
            };
            store.record_feedback(*b"US", token.as_bytes(), &[vote]);
        }
        // A below-threshold US bucket that also fails to roll up (no other
        // NA country reports it) — exercises the roll-up path without it
        // being satisfied, still bounded by NA's member list (US/CA/MX).
        for i in 0..3u32 {
            let token = format!("rare-reporter-{i}");
            store.record_feedback(*b"US", token.as_bytes(), &[outcome("rare_mask", 1, 0)]);
        }

        let start = std::time::Instant::now();
        let top = store.top_masks_for_region(*b"US");
        let elapsed = start.elapsed();

        assert_eq!(top.len(), 1);
        assert_eq!(top[0].0, "quic_https");
        assert!((top[0].1 - 0.9).abs() < 0.05);
        assert!(
            elapsed.as_millis() < 200,
            "top_masks_for_region took {:?} with 50k buckets in unrelated \
             countries present — should be O(masks in region), not O(total buckets)",
            elapsed
        );
    }

    /// FIX F.3: a repeated `top_masks_for_region` call for the same region
    /// within `REGIONAL_HINTS_CACHE_TTL` must reuse the cached result rather
    /// than re-scanning `buckets` — proven indirectly (without instrumenting
    /// the lock) by mutating the underlying store directly between the two
    /// calls: if the second call were a fresh scan, it would see the new
    /// mask; if it hit the cache, it must return the exact same result as
    /// the first call.
    #[test]
    fn regional_hints_cache_returns_same_result_within_ttl() {
        let store = MaskFeedbackStore::with_k_anon(1);
        store.record_feedback(*b"US", b"reporter-1", &[outcome("mask_a", 1, 0)]);
        let first = store.top_masks_for_region(*b"US");
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].0, "mask_a");

        // Bypass record_feedback to mutate the store directly — a fresh scan
        // would immediately see this new, k-anon-satisfied bucket.
        {
            let mut map = store.buckets.lock();
            let inner = map.countries.entry(*b"US").or_default();
            let mut b = MaskBucket::new();
            b.success_count = 5;
            b.reporters.add(b"someone-else");
            inner.insert("mask_b".to_string(), b);
            map.total_buckets += 1;
        }

        let second = store.top_masks_for_region(*b"US");
        assert_eq!(
            second, first,
            "a call within the TTL must reuse the cached result, not re-scan"
        );
    }

    /// Companion to the above: once the cache entry is expired, the next
    /// call must recompute and reflect the store's current state. Forces
    /// expiry by backdating the cache entry directly (same-crate test field
    /// access, mirroring how `sweep_stale`'s tests backdate
    /// `last_updated_hour`) instead of sleeping for
    /// `REGIONAL_HINTS_CACHE_TTL` in a unit test.
    #[test]
    fn regional_hints_cache_recomputes_after_ttl_expiry() {
        let store = MaskFeedbackStore::with_k_anon(1);
        store.record_feedback(*b"US", b"reporter-1", &[outcome("mask_a", 1, 0)]);
        let first = store.top_masks_for_region(*b"US");
        assert_eq!(first.len(), 1);

        {
            let mut cache = store.hints_cache.lock();
            let entry = cache
                .get_mut(b"US")
                .expect("cache entry populated by first call");
            entry.computed_at = Instant::now() - REGIONAL_HINTS_CACHE_TTL - Duration::from_secs(1);
        }

        store.record_feedback(*b"US", b"reporter-2", &[outcome("mask_b", 1, 0)]);
        let second = store.top_masks_for_region(*b"US");
        assert!(
            second.iter().any(|(m, _)| m == "mask_b"),
            "an expired cache entry must be recomputed and reflect newly recorded data"
        );
    }

    /// The cache must not weaken the k-anonymity gate: a sub-threshold
    /// bucket must never appear in a cached result, because the gate is
    /// applied by the (only) underlying scan the cache ever stores.
    #[test]
    fn regional_hints_cache_never_caches_a_pre_gate_result() {
        let store = MaskFeedbackStore::with_k_anon(20);
        for i in 0..5u32 {
            let token = format!("reporter-{i}");
            store.record_feedback(*b"US", token.as_bytes(), &[outcome("mask_a", 1, 0)]);
        }
        // Below k_anon=20 — first call must return empty, and that empty
        // result is what gets cached (never a bypassed/ungated one).
        assert!(store.top_masks_for_region(*b"US").is_empty());
        assert!(
            store.top_masks_for_region(*b"US").is_empty(),
            "a cached sub-threshold result must still be empty on the next call"
        );
    }
}
