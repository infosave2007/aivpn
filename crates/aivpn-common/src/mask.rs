//! Mask System (Traffic Mimicry Profiles)
//!
//! Implements Mask profiles that define traffic shaping behavior

use rand::distributions::weighted::WeightedIndex;
use rand::{distributions::Distribution, Rng};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Rotating bootstrap descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapDescriptor {
    pub descriptor_id: String,
    pub version: u16,
    pub created_at: u64,
    pub expires_at: u64,
    pub base_mask_ids: Vec<String>,
    #[serde(default)]
    pub embedded_masks: Vec<MaskProfile>,
    pub candidate_count: u8,
    #[serde(with = "serde_bytes")]
    pub kdf_salt: [u8; 32],
    #[serde(with = "serde_bytes")]
    #[serde(default = "default_signature")]
    pub signature: [u8; 64],
}

impl BootstrapDescriptor {
    pub fn is_valid_at(&self, unix_secs: u64) -> bool {
        unix_secs >= self.created_at && unix_secs <= self.expires_at
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.signature = [0u8; 64];
        rmp_serde::to_vec(&unsigned).expect("bootstrap descriptor serializable")
    }

    /// Verify the ed25519 signature of this descriptor against an operator signing key.
    pub fn verify_signature(&self, public_key: &[u8; 32]) -> Result<bool> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let vk = VerifyingKey::from_bytes(public_key)
            .map_err(|e| Error::Crypto(format!("Invalid Ed25519 public key: {}", e)))?;
        let message = self.signing_bytes();
        let sig = Signature::from_bytes(&self.signature);
        match vk.verify(&message, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// Multi-channel bootstrap descriptor distribution.
///
/// Each channel represents a different method to fetch bootstrap descriptors.
/// Using multiple channels makes it harder for censors to block all distribution points.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BootstrapChannel {
    /// CDN-based distribution (e.g., Cloudflare, AWS CloudFront)
    CDN {
        /// CDN URL endpoint
        url: String,
        /// CDN provider name for logging/analytics
        provider: String,
    },
    /// Telegram bot-based distribution. Uses the authenticated Bot API
    /// (getUpdates + getFile) — matches how the server actually publishes
    /// descriptors (`bootstrap_publish.rs`'s `sendDocument`), which an
    /// unauthenticated public-channel scrape cannot reliably retrieve.
    Telegram {
        /// Bot token (required — authenticates the getUpdates/getFile calls)
        bot_token: String,
        /// Chat/channel ID to filter updates to (optional: if the bot is
        /// only used for bootstrap distribution, omitting this and scanning
        /// all recent updates works fine, same as the mobile clients do)
        chat_id: Option<String>,
    },
    /// GitHub releases/assets distribution
    GitHub {
        /// Repository in format "owner/repo"
        repo: String,
        /// Asset name pattern (e.g., "bootstrap-descriptors-v*.json")
        asset_name: String,
    },
    /// Email-based distribution (for enterprise deployments)
    Email {
        /// Email address to request descriptors from
        address: String,
        /// Subject line pattern for automated requests
        subject_pattern: String,
    },
}

impl BootstrapChannel {
    /// Get a human-readable name for this channel
    pub fn name(&self) -> &str {
        match self {
            BootstrapChannel::CDN { provider, .. } => provider.as_str(),
            // Never surface the bot token here — this feeds logs/UI display.
            BootstrapChannel::Telegram { chat_id, .. } => {
                chat_id.as_deref().unwrap_or("telegram-bot")
            }
            BootstrapChannel::GitHub { repo, .. } => repo.as_str(),
            BootstrapChannel::Email { address, .. } => address.as_str(),
        }
    }

    /// Get the channel type name
    pub fn channel_type(&self) -> &str {
        match self {
            BootstrapChannel::CDN { .. } => "CDN",
            BootstrapChannel::Telegram { .. } => "Telegram",
            BootstrapChannel::GitHub { .. } => "GitHub",
            BootstrapChannel::Email { .. } => "Email",
        }
    }
}

/// Configuration for multi-channel bootstrap descriptor distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapConfig {
    /// List of channels to try (in order of preference)
    pub channels: Vec<BootstrapChannel>,
    /// Maximum age of descriptors to accept (seconds)
    pub max_descriptor_age: u64,
    /// Minimum number of channels that must succeed
    pub min_success_channels: usize,
    /// Background refresh interval (seconds)
    pub refresh_interval: u64,
    /// Whether to use random delay before first refresh
    pub randomize_first_refresh: bool,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            channels: Vec::new(),
            max_descriptor_age: 86400, // 24 hours
            min_success_channels: 1,
            refresh_interval: 3600, // 1 hour
            randomize_first_refresh: true,
        }
    }
}

impl BootstrapConfig {
    /// Create a new bootstrap config with the given channels
    pub fn new(channels: Vec<BootstrapChannel>) -> Self {
        Self {
            channels,
            ..Default::default()
        }
    }

    /// Add a CDN channel
    pub fn with_cdn(mut self, url: impl Into<String>, provider: impl Into<String>) -> Self {
        self.channels.push(BootstrapChannel::CDN {
            url: url.into(),
            provider: provider.into(),
        });
        self
    }

    /// Add a Telegram channel (authenticated Bot API — see `BootstrapChannel::Telegram`)
    pub fn with_telegram(mut self, bot_token: impl Into<String>, chat_id: Option<String>) -> Self {
        self.channels.push(BootstrapChannel::Telegram {
            bot_token: bot_token.into(),
            chat_id,
        });
        self
    }

    /// Add a GitHub channel
    pub fn with_github(mut self, repo: impl Into<String>, asset_name: impl Into<String>) -> Self {
        self.channels.push(BootstrapChannel::GitHub {
            repo: repo.into(),
            asset_name: asset_name.into(),
        });
        self
    }
}

pub fn current_unix_secs() -> u64 {
    crate::crypto::current_timestamp_ms() / 1000
}

fn derive_bootstrap_seed(
    descriptor: &BootstrapDescriptor,
    preshared_key: Option<&[u8; 32]>,
    slot: u8,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&descriptor.kdf_salt);
    hasher.update(descriptor.descriptor_id.as_bytes());
    hasher.update(&[slot]);
    match preshared_key {
        Some(psk) => {
            hasher.update(psk);
        }
        None => {
            hasher.update(&[0u8; 32]);
        }
    };
    let hash = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash.as_bytes()[..32]);
    seed
}

pub fn derive_bootstrap_candidate(
    descriptor: &BootstrapDescriptor,
    preshared_key: Option<&[u8; 32]>,
    slot: u8,
) -> Option<MaskProfile> {
    let embedded_masks = &descriptor.embedded_masks;
    let base_ids = if descriptor.base_mask_ids.is_empty() && embedded_masks.is_empty() {
        preset_masks::all()
            .into_iter()
            .map(|mask| mask.mask_id)
            .collect::<Vec<_>>()
    } else {
        descriptor.base_mask_ids.clone()
    };
    if base_ids.is_empty() && embedded_masks.is_empty() {
        return None;
    }

    let seed = derive_bootstrap_seed(descriptor, preshared_key, slot);
    let selector_len = if !embedded_masks.is_empty() {
        embedded_masks.len()
    } else {
        base_ids.len()
    };
    let base_index = (seed[0] as usize) % selector_len;
    let mut mask = if !embedded_masks.is_empty() {
        embedded_masks[base_index].clone()
    } else {
        preset_masks::by_id(&base_ids[base_index])?
    };
    let extra_gap_len = (seed[1] % 9) as usize;

    if extra_gap_len > 0 {
        let mut fields = mask
            .header_spec
            .as_ref()
            .map(HeaderSpec::fields)
            .unwrap_or_else(|| {
                vec![HeaderField::Fixed {
                    bytes: mask.header_template.clone(),
                }]
            });
        fields.push(HeaderField::Random { len: extra_gap_len });
        mask.header_spec = Some(HeaderSpec::Structured { fields });
        mask.eph_pub_offset = mask.eph_pub_offset.saturating_add(extra_gap_len as u16);
    }

    mask.mask_id = format!(
        "bootstrap:{}:{}:{}:{:02x}{:02x}",
        descriptor.descriptor_id,
        if !embedded_masks.is_empty() {
            &embedded_masks[base_index].mask_id
        } else {
            &base_ids[base_index]
        },
        slot,
        seed[0],
        seed[1]
    );
    Some(mask)
}

pub fn derive_bootstrap_candidates(
    descriptor: &BootstrapDescriptor,
    preshared_key: Option<&[u8; 32]>,
) -> Vec<MaskProfile> {
    (0..descriptor.candidate_count)
        .filter_map(|slot| derive_bootstrap_candidate(descriptor, preshared_key, slot))
        .collect()
}

/// Decode a `BootstrapDescriptor` from the raw bytes of a
/// `ControlPayload::BootstrapDescriptorUpdate` payload (MessagePack, matching
/// the server's encoding and desktop `client.rs`). Returns `None` on any
/// malformed input. Shared so the mobile cores (which have no `bootstrap_cache`
/// crate) decode server-pushed descriptors identically to the desktop client.
pub fn decode_bootstrap_descriptor(bytes: &[u8]) -> Option<BootstrapDescriptor> {
    rmp_serde::from_slice::<BootstrapDescriptor>(bytes).ok()
}

/// Parse a JSON blob of persisted bootstrap descriptors (a JSON array, or a
/// single JSON object) and return only those that are currently valid and —
/// when a `trusted_key` is supplied — carry a verifying ed25519 signature.
///
/// Used by the mobile cores (`aivpn-ios-core`, `aivpn-android-core`) to
/// re-populate their in-process descriptor store from app-layer persistent
/// storage BEFORE the first handshake of a process, so `resolve_handshake_mask`
/// can shape even a cold-start opening burst with a COVERT epoch-rotated
/// descriptor mask instead of a fingerprintable public preset. The desktop
/// client gets the same effect from `bootstrap_cache::select_initial_mask`.
///
/// Verification policy mirrors the desktop's `store_verified_descriptor`:
///  - `trusted_key = Some(k)` → an all-zero (missing) signature is REJECTED and
///    a present-but-invalid signature is REJECTED; only descriptors whose
///    signature verifies against `k` are accepted. A forged/tampered persisted
///    descriptor can never steer the handshake mask.
///  - `trusted_key = None` → signature is not checked (no key to check it
///    against — same trust model as the AEAD-authenticated in-session store
///    path that produced these descriptors in the first place). Only the
///    validity window is enforced.
///
/// Never panics; malformed JSON yields an empty vec. The result is sorted
/// newest-first by `created_at`.
pub fn accept_persisted_descriptors(
    json: &str,
    trusted_key: Option<&[u8; 32]>,
) -> Vec<BootstrapDescriptor> {
    let parsed: Vec<BootstrapDescriptor> = serde_json::from_str::<Vec<BootstrapDescriptor>>(json)
        .ok()
        .or_else(|| {
            serde_json::from_str::<BootstrapDescriptor>(json)
                .ok()
                .map(|d| vec![d])
        })
        .unwrap_or_default();

    let now = current_unix_secs();
    let mut out: Vec<BootstrapDescriptor> = parsed
        .into_iter()
        .filter(|d| d.is_valid_at(now))
        .filter(|d| match trusted_key {
            Some(key) => {
                // Reject unsigned (all-zero) or non-verifying descriptors when a
                // trusted operator key is configured.
                d.signature != [0u8; 64] && matches!(d.verify_signature(key), Ok(true))
            }
            None => true,
        })
        .collect();
    out.sort_by_key(|d| std::cmp::Reverse(d.created_at));
    out
}

/// Resolve the mask a client should shape its handshake / opening burst with,
/// **preferring a COVERT epoch-rotated descriptor mask** over the shipped
/// public presets.
///
/// Every client core (`aivpn-client`, `aivpn-ios-core`, `aivpn-android-core`)
/// must pick the same handshake mask the same way, or the server's per-mask
/// layout-aware tag scan can't match it. The historical per-core snippet was
///
/// ```ignore
/// preferred.and_then(preset_masks::by_id).unwrap_or_else(|| bootstrap_mask_for_psk(psk))
/// ```
///
/// which had a covertness bug: a *descriptor-derived* `preferred` name (e.g.
/// `"bootstrap:epoch-20641:webrtc_yandex_telemost_v1:1:577e"`) is **not** a
/// preset id, so `by_id` returns `None` and the client silently framed the
/// handshake with a PUBLIC, shipped-in-the-binary preset — a fingerprintable
/// shape that defeats the whole point of the signed, epoch-rotated descriptors.
///
/// Resolution order (first match wins):
///  1. `preferred` names a shipped preset → use it. This is only ever an
///     *explicit user choice* (the GUI mask picker), never a descriptor name,
///     so honoring it does not increase preset reliance.
///  2. `preferred` names a descriptor mask we hold a matching descriptor for →
///     derive and return that exact COVERT rotated mask.
///  3. Any valid descriptor is available → derive its first COVERT candidate.
///  4. Last resort only (no preset choice, no descriptor at all) →
///     `bootstrap_mask_for_psk(psk)`. This is the pre-existing fallback and is
///     no more preset-happy than before; it never runs when a covert
///     descriptor mask can be produced.
///
/// `descriptors` should be the client's currently-valid descriptor catalogue
/// (validity is the caller's responsibility). Pass an empty slice when the
/// core has no descriptor store yet — behaviour then matches the legacy
/// preset/PSK path exactly, with no regression.
pub fn resolve_handshake_mask(
    preferred: Option<&str>,
    descriptors: &[BootstrapDescriptor],
    preshared_key: Option<&[u8; 32]>,
) -> MaskProfile {
    let pref = preferred
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "auto");

    // 1. Explicit named preset (user's deliberate mask-picker selection).
    if let Some(name) = pref {
        if let Some(mask) = preset_masks::by_id(name) {
            return mask;
        }
    }

    // 2. `preferred` is a descriptor-derived id — pin it to the descriptor that
    //    produced it (its `descriptor_id` is the token after `bootstrap:`) and
    //    derive the exact covert mask. The full id is
    //    `bootstrap:<descriptor_id>:<base>:<slot>:<hex>`.
    if let Some(name) = pref {
        if let Some(descriptor_id) = name
            .strip_prefix("bootstrap:")
            .and_then(|rest| rest.split(':').next())
        {
            if let Some(descriptor) = descriptors
                .iter()
                .find(|d| d.descriptor_id == descriptor_id)
            {
                let candidates = derive_bootstrap_candidates(descriptor, preshared_key);
                if let Some(exact) = candidates.iter().find(|m| m.mask_id == name) {
                    return exact.clone();
                }
                if let Some(first) = candidates.into_iter().next() {
                    return first;
                }
            }
        }
    }

    // 3. No usable named request, but we do hold descriptor(s): stay covert by
    //    deriving the first candidate of the newest descriptor offered.
    for descriptor in descriptors {
        if let Some(mask) = derive_bootstrap_candidates(descriptor, preshared_key)
            .into_iter()
            .next()
        {
            return mask;
        }
    }

    // 4. Last resort — no preset choice and no descriptor available at all.
    //    PSK-indexed public preset. This mirrors `mimicry::bootstrap_mask_for_psk`
    //    exactly (kept inline so the resolver stays usable without the
    //    `client-upload`-gated `mimicry` module) and is no more preset-happy
    //    than the legacy path: it only runs when no covert mask can be produced.
    let presets = preset_masks::all();
    if presets.is_empty() {
        return preset_masks::bootstrap_default();
    }
    match preshared_key {
        Some(key) => {
            let hash = blake3::derive_key("aivpn-bootstrap-mask-v1", key);
            let idx = hash[0] as usize % presets.len();
            presets[idx].clone()
        }
        None => presets[0].clone(),
    }
}

/// Consecutive never-connected handshake attempts after which a client
/// abandons the descriptor-derived covert mask for a builtin preset. A cached
/// descriptor the server cannot reproduce (server-key change, epoch outside
/// the server's accepted window, client/server derivation skew across
/// versions) makes EVERY handshake fail with a tag mismatch; without this net
/// the client retries the same unmatchable mask forever. Mirrors the desktop
/// client's `HANDSHAKE_FALLBACK_THRESHOLD` (main.rs) for the mobile cores.
pub const HANDSHAKE_FALLBACK_THRESHOLD: u32 = 3;

/// `resolve_handshake_mask` with the desktop client's resilience net: once
/// `fail_streak` reaches `HANDSHAKE_FALLBACK_THRESHOLD`, resolve as if no
/// descriptor were held, so the handshake uses a builtin preset every server
/// matches via its builtin candidate set. An explicit preset in `preferred`
/// (the user's deliberate mask-picker choice) is honored either way. The
/// availability-over-covertness trade is deliberate and bounded: the caller
/// resets the streak on the first real connection, and the server re-pushes
/// fresh descriptors in-session, so subsequent handshakes are covert again.
pub fn resolve_handshake_mask_resilient(
    preferred: Option<&str>,
    descriptors: &[BootstrapDescriptor],
    preshared_key: Option<&[u8; 32]>,
    fail_streak: u32,
) -> MaskProfile {
    if fail_streak >= HANDSHAKE_FALLBACK_THRESHOLD {
        resolve_handshake_mask(preferred, &[], preshared_key)
    } else {
        resolve_handshake_mask(preferred, descriptors, preshared_key)
    }
}

/// BLAKE3 derive-key context for polymorphic-mask perturbation seeds.
const POLYMORPHIC_SEED_CONTEXT: &str = "aivpn-polymorphic-mask-v1";

/// Derive a stable 32-byte perturbation seed for a polymorphic mask variant.
///
/// Both endpoints already hold an identical per-session `prng_seed`
/// (`SessionKeys::prng_seed`), so a variant derived from it is reproducible on
/// either side without any extra key exchange. In the shipping design the
/// server derives the variant and pushes the full profile via `MaskUpdate`, so
/// only the server calls this — but keeping derivation deterministic means a
/// client could reproduce the same variant if we ever want to skip the push.
pub fn polymorphic_seed(prng_seed: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(POLYMORPHIC_SEED_CONTEXT, prng_seed)
}

// ─── Mask artifact verification (R2 Phase B) ─────────────────────────────────

/// Config-gated enforcement level for the embedded operator mask signature.
///
/// Rollout is `off` → `warn` (default) → `enforce`:
/// - `off`     — signatures are ignored entirely.
/// - `warn`    — verify when an operator public key is configured; log-and-accept
///   on failure. With no key configured this is a silent no-op, so the default
///   changes nothing for existing deployments.
/// - `enforce` — reject any mask that does not carry a valid operator
///   signature. Requires an operator public key; enforce with no key
///   configured fails closed (every mask is rejected) because the operator
///   explicitly opted into enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MaskVerifyMode {
    Off,
    #[default]
    Warn,
    Enforce,
}

impl std::str::FromStr for MaskVerifyMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "warn" => Ok(Self::Warn),
            "enforce" => Ok(Self::Enforce),
            other => Err(format!(
                "invalid mask verify mode '{}' (expected off|warn|enforce)",
                other
            )),
        }
    }
}

/// Why a [`verify_mask_artifact`] call accepted or rejected a mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskVerifyDetail {
    /// Verification disabled (`MaskVerifyMode::Off`).
    ModeOff,
    /// Signature present and verified against the operator public key.
    Valid,
    /// No operator public key configured — verification impossible.
    NoOperatorKey,
    /// Legacy/unsigned mask (all-zero signature).
    Unsigned,
    /// Signature present but did not verify (or the configured key is malformed).
    Invalid,
}

/// Result of a config-gated mask artifact verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaskVerifyResult {
    /// Whether the caller should accept (load / apply) the mask.
    pub accept: bool,
    /// Why. Callers use this for log severity: `Unsigned`/`Invalid` under
    /// `warn` deserve a warning line even though `accept` is `true`.
    pub detail: MaskVerifyDetail,
}

impl MaskVerifyResult {
    /// `true` when the signature check itself failed (even if the mode still
    /// accepts the mask) — the caller should log a warning.
    pub fn is_failure(&self) -> bool {
        matches!(
            self.detail,
            MaskVerifyDetail::Unsigned
                | MaskVerifyDetail::Invalid
                | MaskVerifyDetail::NoOperatorKey
        )
    }
}

/// Verify a mask artifact's embedded operator signature, gated by `mode`.
///
/// This is the single shared verification entry point (R2 Phase B) used by the
/// server mask store on disk load, the desktop client on `MaskUpdate`, and the
/// mobile cores (Android/iOS) at their `MaskUpdate` arms — so every platform
/// inherits identical semantics. Never panics.
///
/// NOTE: derived per-session variants (`MaskProfile::is_derived_variant`) are
/// not independently verifiable and must be exempted by the caller *only* on
/// channel-authenticated runtime paths (client `MaskUpdate`), never on disk
/// load paths where an attacker could choose the mask_id prefix.
pub fn verify_mask_artifact(
    profile: &MaskProfile,
    operator_pubkey: Option<&[u8; 32]>,
    mode: MaskVerifyMode,
) -> MaskVerifyResult {
    let detail = match (mode, operator_pubkey) {
        (MaskVerifyMode::Off, _) => MaskVerifyDetail::ModeOff,
        (_, None) => MaskVerifyDetail::NoOperatorKey,
        (_, Some(pk)) => {
            if profile.is_unsigned() {
                MaskVerifyDetail::Unsigned
            } else {
                match profile.verify_signature(pk) {
                    Ok(true) => MaskVerifyDetail::Valid,
                    Ok(false) | Err(_) => MaskVerifyDetail::Invalid,
                }
            }
        }
    };
    let accept = match mode {
        MaskVerifyMode::Off | MaskVerifyMode::Warn => true,
        MaskVerifyMode::Enforce => matches!(detail, MaskVerifyDetail::Valid),
    };
    MaskVerifyResult { accept, detail }
}

/// Perturb `mask` in place into a polymorphic variant, deterministically from
/// `seed`. Only observable-shape parameters within the mask's
/// `PerturbationBounds` are nudged; the FSM graph, spoofed protocol, and
/// ephemeral-key length are never touched. Idempotent for a given `seed`.
///
/// IMPORTANT: this shifts `eph_pub_offset` (a signature-covered field) while
/// leaving `mask.signature` as the base mask's stale signature. A polymorphic
/// variant is therefore NOT independently signature-verifiable and must never
/// be passed to `verify_signature` expecting `true`. In the shipping wiring the
/// server derives the variant from server-trusted inputs (a trusted base preset
/// + the session's own `prng_seed`) and pushes the full profile inside the
/// already-authenticated MaskUpdate channel, so no re-verification is needed.
pub fn apply_polymorphic_perturbation(mask: &mut MaskProfile, seed: &[u8; 32]) {
    let bounds = mask.perturbation_bounds.clone().unwrap_or_default();

    // Expand the seed into an independent byte stream so each perturbation axis
    // draws from decorrelated entropy.
    let mut stream = [0u8; 16];
    let mut xof = blake3::Hasher::new_derive_key("aivpn-polymorphic-perturb-v1");
    xof.update(seed);
    xof.finalize_xof().fill(&mut stream);

    let base_id = mask.mask_id.clone();

    // (1) IAT jitter: multiply the jitter envelope by a factor sampled from the
    // configured scale range. Guard against a malformed/NaN base range.
    let (slo, shi) = bounds.iat_jitter_scale;
    if slo.is_finite() && shi.is_finite() && slo >= 0.0 && shi >= slo {
        let factor = slo + (shi - slo) * (stream[0] as f64 / 255.0);
        let (jlo, jhi) = mask.iat_distribution.jitter_range_ms;
        if jlo.is_finite() && jhi.is_finite() {
            let (nlo, nhi) = ((jlo * factor).max(0.0), (jhi * factor).max(0.0));
            mask.iat_distribution.jitter_range_ms =
                if nlo <= nhi { (nlo, nhi) } else { (nhi, nlo) };
        }
    }

    // (2) Padding: shift sizes by ±padding_shift_pct.
    let pct = if bounds.padding_shift_pct.is_finite() {
        bounds.padding_shift_pct.clamp(0.0, 0.9)
    } else {
        0.0
    };
    if pct > 0.0 {
        // stream[1] → factor in [1-pct, 1+pct]
        let pad_factor = 1.0 - pct + (2.0 * pct) * (stream[1] as f64 / 255.0);
        let scale_u16 = |v: u16| -> u16 {
            let scaled = (v as f64 * pad_factor).round();
            scaled.clamp(0.0, u16::MAX as f64) as u16
        };
        match &mut mask.padding_strategy {
            PaddingStrategy::RandomUniform { min, max } => {
                let (a, b) = (scale_u16(*min), scale_u16(*max));
                *min = a.min(b);
                *max = a.max(b);
            }
            PaddingStrategy::Fixed { size } => {
                *size = scale_u16(*size);
            }
            PaddingStrategy::MatchDistribution => {}
        }
    }

    // (3) Header gap: append 0..=max_header_gap random bytes, mirroring the
    // bootstrap-candidate extra-gap perturbation, and shift the eph-pub offset.
    if bounds.max_header_gap > 0 {
        let extra_gap = (stream[2] as u16 % (bounds.max_header_gap as u16 + 1)) as usize;
        if extra_gap > 0 {
            let mut fields = mask
                .header_spec
                .as_ref()
                .map(HeaderSpec::fields)
                .unwrap_or_else(|| {
                    vec![HeaderField::Fixed {
                        bytes: mask.header_template.clone(),
                    }]
                });
            fields.push(HeaderField::Random { len: extra_gap });
            mask.header_spec = Some(HeaderSpec::Structured { fields });
            mask.eph_pub_offset = mask.eph_pub_offset.saturating_add(extra_gap as u16);
        }
    }

    // (4) FSM dwell timing: scale AfterDuration transition timings by a bounded
    // factor. This nudges *when* behavioral-state transitions fire without
    // touching the state graph (state ids, next_state, condition kinds all stay).
    let (flo, fhi) = bounds.fsm_dwell_scale;
    if flo.is_finite() && fhi.is_finite() && flo > 0.0 && fhi >= flo {
        let dwell_factor = flo + (fhi - flo) * (stream[3] as f64 / 255.0);
        for fsm_state in &mut mask.fsm_states {
            for transition in &mut fsm_state.transitions {
                if let TransitionCondition::AfterDuration(ms) = &mut transition.condition {
                    let scaled = (*ms as f64 * dwell_factor).round();
                    *ms = scaled.clamp(0.0, u64::MAX as f64) as u64;
                }
            }
        }
    }

    mask.mask_id = format!("polymorphic:{}:{:02x}{:02x}", base_id, stream[0], stream[1]);
}

/// Mask profile for traffic mimicry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskProfile {
    /// Unique identifier
    pub mask_id: String,
    /// Profile version
    pub version: u16,
    /// Creation timestamp
    pub created_at: u64,
    /// Expiration timestamp
    pub expires_at: u64,

    /// Protocol to spoof
    pub spoof_protocol: SpoofProtocol,
    /// Header template bytes (static, for legacy compatibility)
    pub header_template: Vec<u8>,
    /// Offset for ephemeral public key in header
    pub eph_pub_offset: u16,
    /// Length of ephemeral public key (always 32)
    pub eph_pub_length: u16,

    /// Packet size distribution
    pub size_distribution: SizeDistribution,
    /// Inter-arrival time distribution
    pub iat_distribution: IATDistribution,
    /// R3: optional JOINT size↔IAT distribution (2-D GMM). When present, the
    /// mimicry engine samples (size, iat) together so their correlation is
    /// reproduced instead of drawing the two independent marginals above. Absent
    /// (`None`) on legacy/unimodal masks and ignored by older clients (unknown
    /// field), which fall back to the two 1-D marginals — always kept populated.
    #[serde(default)]
    pub size_iat_joint: Option<SizeIatGmm2d>,
    /// Padding strategy
    pub padding_strategy: PaddingStrategy,

    /// FSM states for behavioral mimicry
    pub fsm_states: Vec<FSMState>,
    /// Initial FSM state
    pub fsm_initial_state: u16,

    /// Neural resonance signature (64 floats)
    pub signature_vector: Vec<f32>,

    /// Reverse profile for server->client traffic
    pub reverse_profile: Option<Box<MaskProfile>>,

    /// Ed25519 signature (64 bytes)
    #[serde(with = "serde_bytes")]
    #[serde(default = "default_signature")]
    pub signature: [u8; 64],

    /// Dynamic header specification (Issue #30 fix)
    /// If present, clients should use this for per-packet header generation
    /// instead of the static header_template.
    /// Added in version 2, legacy clients ignore this field.
    #[serde(default)]
    pub header_spec: Option<HeaderSpec>,

    /// Polymorphic-mask perturbation bounds (§3 "Polymorphic Masks").
    /// Declares how far a per-session polymorphic variant of this mask may
    /// deviate while still plausibly resembling the mimicked protocol.
    /// Absent → `PerturbationBounds::default()` conservative bounds are used.
    /// Covered by the mask signature (`signing_message` serializes the whole
    /// profile), so a signed mask commits to its perturbation bounds.
    #[serde(default)]
    pub perturbation_bounds: Option<PerturbationBounds>,

    /// Wire-layout selector for the 8-byte resonance tag (Variant A DPI fix).
    ///
    /// * `u16::MAX` (the default, `default_tag_offset`) = **legacy layout**: the
    ///   tag is a separate prefix at packet offset 0, the MDH follows it, then
    ///   the ciphertext — exactly the historical `tag ++ mdh ++ ciphertext`
    ///   wire format. Existing masks/JSON without this field keep this behavior
    ///   and stay byte-for-byte wire-compatible.
    /// * a concrete value `N` = **new layout**: the MDH (a real protocol header,
    ///   e.g. a STUN or QUIC header) sits at packet offset 0 and the tag is
    ///   embedded INSIDE the header at byte offset `N`, overwriting a
    ///   mask-reserved carrier slot. The packet is `mdh ++ ciphertext` with no
    ///   separate tag prefix, so a DPI engine reads a genuine protocol
    ///   discriminator at offset 0 (nDPI can classify STUN/QUIC instead of
    ///   "unknown high-entropy UDP").
    ///
    /// Covered by the mask signature (`signing_message` serializes the whole
    /// profile): the tag position is security-critical, so a signed mask commits
    /// to it and an attacker cannot repoint the tag while keeping the signature.
    #[serde(default = "default_tag_offset")]
    pub tag_offset: u16,

    /// True when this mask was auto-generated from a real-traffic recording by
    /// the server's `mask_gen` (as opposed to a hand-authored preset). Clients
    /// surface it in the mask picker with an "(auto)" marker. Defaults to false
    /// so existing masks/JSON deserialize unchanged.
    #[serde(default)]
    pub generated: bool,
}

fn default_signature() -> [u8; 64] {
    [0u8; 64]
}

/// Sentinel returned for masks that omit `tag_offset`: `u16::MAX` means the
/// legacy layout (resonance tag prefixed at packet offset 0).
pub fn default_tag_offset() -> u16 {
    u16::MAX
}

/// Safe per-mask bounds for polymorphic perturbation (§3).
///
/// A polymorphic variant nudges only observable-shape parameters that stay
/// within a protocol-plausible envelope. It never touches the FSM state graph,
/// the ephemeral-key length, or the spoofed protocol identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerturbationBounds {
    /// Multiplicative envelope `(lo, hi)` applied to the IAT jitter range.
    /// e.g. `(0.7, 1.4)` lets per-session jitter shrink to 70% or grow to 140%.
    #[serde(default = "default_iat_jitter_scale")]
    pub iat_jitter_scale: (f64, f64),
    /// Fractional shift applied to padding sizes. `0.15` = ±15%.
    #[serde(default = "default_padding_shift_pct")]
    pub padding_shift_pct: f64,
    /// Maximum number of extra random header-gap bytes (`0..=max_header_gap`).
    /// Mirrors the bootstrap-candidate extra-gap perturbation.
    #[serde(default = "default_max_header_gap")]
    pub max_header_gap: u8,
    /// Multiplicative envelope `(lo, hi)` applied to FSM `AfterDuration`
    /// transition timings (dwell time). Nudges *when* the mask transitions
    /// between behavioral states without altering the state graph itself.
    /// e.g. `(0.8, 1.25)`.
    #[serde(default = "default_fsm_dwell_scale")]
    pub fsm_dwell_scale: (f64, f64),
}

fn default_iat_jitter_scale() -> (f64, f64) {
    (0.7, 1.4)
}
fn default_padding_shift_pct() -> f64 {
    0.15
}
fn default_max_header_gap() -> u8 {
    4
}
fn default_fsm_dwell_scale() -> (f64, f64) {
    (0.8, 1.25)
}

impl Default for PerturbationBounds {
    fn default() -> Self {
        Self {
            iat_jitter_scale: default_iat_jitter_scale(),
            padding_shift_pct: default_padding_shift_pct(),
            max_header_gap: default_max_header_gap(),
            fsm_dwell_scale: default_fsm_dwell_scale(),
        }
    }
}

/// Protocol spoofing types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum SpoofProtocol {
    None,
    QUIC,
    WebRTC_STUN,
    HTTPS_H2,
    DNS_over_UDP,
}

/// Packet size distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeDistribution {
    pub dist_type: SizeDistType,
    pub bins: Vec<(u16, u16, f32)>, // (min, max, probability)
    pub parametric_type: Option<ParametricType>,
    pub parametric_params: Option<Vec<f64>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SizeDistType {
    Histogram,
    Parametric,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParametricType {
    LogNormal,
    Gamma,
    Bimodal,
    /// BIC-selected Gaussian mixture (design-doc §4 R&D bridge). Encoded in
    /// `parametric_params` as the flat layout `[k, w0, mu0, sigma0, w1, mu1,
    /// sigma1, ...]` in raw byte units. Reproduces real multimodal packet-size
    /// marginals far better than a single Gaussian; see `sample_gaussian_mixture`.
    Gmm,
}

impl SizeDistribution {
    /// Sample a packet size from the distribution
    pub fn sample<R: Rng>(&self, rng: &mut R) -> u16 {
        match self.dist_type {
            SizeDistType::Histogram => {
                if self.bins.is_empty() {
                    return 64; // Default
                }

                // Weighted random selection of bin
                let weights: Vec<f32> = self.bins.iter().map(|(_, _, p)| *p).collect();
                if let Ok(dist) = WeightedIndex::new(&weights) {
                    let bin_idx = dist.sample(rng);
                    let (min, max, _) = self.bins[bin_idx];
                    // A malformed mask may carry an inverted bin (min > max);
                    // gen_range panics on an empty range, so normalize the bounds.
                    let (lo, hi) = if min <= max { (min, max) } else { (max, min) };
                    rng.gen_range(lo..=hi)
                } else {
                    64
                }
            }
            SizeDistType::Parametric => {
                match self.parametric_type {
                    Some(ParametricType::LogNormal) => {
                        if let Some(params) = &self.parametric_params {
                            if params.len() < 2 {
                                return rng.gen_range(64..512);
                            }
                            let mu: f64 = params[0];
                            let sigma: f64 = params[1];
                            // Box-Muller transform: generate standard normal from two uniform samples
                            let u1: f64 = rng.gen::<f64>().max(1e-10); // avoid ln(0)
                            let u2: f64 = rng.gen();
                            let z =
                                (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
                            // LogNormal: exp(mu + sigma * z)
                            let sample = (mu + sigma * z).exp();
                            (sample as u16).max(1)
                        } else {
                            rng.gen_range(64..512)
                        }
                    }
                    Some(ParametricType::Gmm) => {
                        if let Some(params) = &self.parametric_params {
                            // Packet sizes are >= 1 byte; clamp the mixture draw.
                            let v = sample_gaussian_mixture(params, rng, 1.0);
                            if v.is_finite() {
                                (v.round().clamp(1.0, u16::MAX as f64)) as u16
                            } else {
                                rng.gen_range(64..512)
                            }
                        } else {
                            rng.gen_range(64..512)
                        }
                    }
                    _ => rng.gen_range(64..512),
                }
            }
        }
    }
}

/// Upper bound on a sampled base inter-arrival time (10 minutes). A crafted
/// mask must never produce an IAT that overflows `Duration::from_secs_f64` at
/// the mimicry sleep site; no legitimate mask waits this long between packets.
const MAX_BASE_IAT_MS: f64 = 600_000.0;

/// Draw one sample from a 1-D Gaussian mixture encoded as the flat layout
/// `[k, w0, mu0, sigma0, w1, mu1, sigma1, ...]`. Picks a component by weight,
/// then a Gaussian value via Box-Muller, clamped to `>= min_value`. Returns
/// `f64::NAN` when the encoding is malformed so callers can fall back.
///
/// Shared by [`SizeDistribution`] and [`IATDistribution`] so the GMM produced
/// by the server's `mask_gen` samples identically on every client.
pub(crate) fn sample_gaussian_mixture<R: Rng>(flat: &[f64], rng: &mut R, min_value: f64) -> f64 {
    if flat.is_empty() {
        return f64::NAN;
    }
    let k = flat[0];
    // Reject non-finite, <1, or an absurd component count. mask_gen never emits
    // more than GMM_MAX_COMPONENTS (8); a crafted mask claiming a huge k would
    // otherwise (a) overflow the `1 + k*3` length check below and slip a tiny
    // array past it → out-of-bounds panic, or (b) pin a core in the O(k) loop.
    if !k.is_finite() || !(1.0..=64.0).contains(&k) {
        return f64::NAN;
    }
    let k = k as usize;
    // Need at least 1 + 3k entries. Divide (never multiply) so this can't
    // integer-overflow; flat is non-empty here so `len() - 1` is safe.
    if (flat.len() - 1) / 3 < k {
        return f64::NAN;
    }
    // Total weight for component selection (defensive against un-normalised input).
    let mut wsum = 0.0;
    for c in 0..k {
        let w = flat[1 + c * 3];
        if w.is_finite() && w > 0.0 {
            wsum += w;
        }
    }
    if wsum <= 0.0 || !wsum.is_finite() {
        return f64::NAN;
    }
    // Select a component proportional to its weight.
    let target = rng.gen::<f64>() * wsum;
    let mut acc = 0.0;
    let mut chosen = k - 1;
    for c in 0..k {
        let w = flat[1 + c * 3];
        if w.is_finite() && w > 0.0 {
            acc += w;
            if target <= acc {
                chosen = c;
                break;
            }
        }
    }
    let mu = flat[2 + chosen * 3];
    let sigma = flat[3 + chosen * 3];
    if !mu.is_finite() || !sigma.is_finite() || sigma < 0.0 {
        return f64::NAN;
    }
    // Box-Muller standard normal.
    let u1: f64 = rng.gen::<f64>().max(1e-12);
    let u2: f64 = rng.gen();
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    (mu + sigma * z).max(min_value)
}

/// Inter-arrival time distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IATDistribution {
    pub dist_type: IATDistType,
    pub params: Vec<f64>,
    pub jitter_range_ms: (f64, f64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IATDistType {
    Exponential,
    LogNormal,
    Gamma,
    Empirical,
    /// BIC-selected Gaussian mixture (design-doc §4 R&D bridge). `params` holds
    /// the flat layout `[k, w0, mu0, sigma0, ...]` in milliseconds. Captures the
    /// multimodal inter-arrival structure (audio cadence + control tail, DNS
    /// req/resp asymmetry, QUIC ACK-vs-data) that a single Exponential/LogNormal
    /// cannot. See `sample_gaussian_mixture`.
    Gmm,
}

impl IATDistribution {
    /// Sample an inter-arrival time in milliseconds
    pub fn sample<R: Rng>(&self, rng: &mut R) -> f64 {
        let base_iat = match self.dist_type {
            IATDistType::Exponential => {
                if self.params.is_empty() {
                    return 20.0;
                }
                let lambda: f64 = self.params[0];
                let val: f64 = rng.gen::<f64>().max(1e-10);
                -(1.0 - val).ln() / lambda
            }
            IATDistType::LogNormal => {
                if self.params.len() < 2 {
                    return 20.0;
                }
                let mu: f64 = self.params[0];
                let sigma: f64 = self.params[1];
                // Box-Muller transform for proper normal distribution
                let u1: f64 = rng.gen::<f64>().max(1e-10);
                let u2: f64 = rng.gen();
                let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
                (mu + sigma * z).exp()
            }
            IATDistType::Gamma => {
                // Simplified gamma sampling (sum of k exponentials for integer k)
                if self.params.len() < 2 {
                    return 20.0;
                }
                let k: f64 = self.params[0];
                let theta: f64 = self.params[1];
                // Clamp the shape parameter: a malformed mask could carry a huge
                // (or NaN) k that would spin this loop billions of times, hanging
                // the sender. 1..=1024 exponential summands is plenty for mimicry.
                let k_iters = if k.is_finite() {
                    k.clamp(1.0, 1024.0) as i32
                } else {
                    1
                };
                let sum: f64 = (0..k_iters)
                    .map(|_| {
                        let val: f64 = rng.gen::<f64>().max(1e-10);
                        -(1.0 - val).ln()
                    })
                    .sum();
                sum * theta
            }
            IATDistType::Empirical => {
                if self.params.is_empty() {
                    return 20.0;
                }
                let idx = rng.gen_range(0..self.params.len());
                self.params[idx]
            }
            IATDistType::Gmm => {
                // Inter-arrival times are non-negative.
                let v = sample_gaussian_mixture(&self.params, rng, 0.0);
                if v.is_finite() {
                    v
                } else {
                    20.0
                }
            }
        };

        // Clamp the base IAT to a sane ceiling. A crafted mask (GMM component
        // with huge mu/sigma, or LogNormal exp(mu)) could emit an astronomically
        // large value; downstream the mimicry engine feeds this to
        // Duration::from_secs_f64, which PANICS when out of Duration range. No
        // legitimate mask waits minutes between packets. Also drops NaN.
        let base_iat = if base_iat.is_finite() {
            base_iat.clamp(0.0, MAX_BASE_IAT_MS)
        } else {
            0.0
        };

        // Add jitter. A malformed mask may carry an inverted (lo > hi) or NaN
        // jitter range; gen_range panics on those, so fall back to no jitter.
        let (lo, hi) = self.jitter_range_ms;
        let jitter = if lo.is_finite() && hi.is_finite() && lo <= hi {
            rng.gen_range(lo..=hi)
        } else {
            0.0
        };
        (base_iat + jitter).max(0.0)
    }
}

/// Padding strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PaddingStrategy {
    RandomUniform { min: u16, max: u16 },
    MatchDistribution,
    Fixed { size: u16 },
}

impl PaddingStrategy {
    /// Calculate padding length for a given payload
    pub fn calc_padding<R: Rng>(&self, payload_size: usize, target_size: u16, rng: &mut R) -> u16 {
        match self {
            Self::RandomUniform { min, max } => {
                // Normalize an inverted range (min > max) so gen_range never
                // panics on a malformed mask's padding strategy.
                let (lo, hi) = if min <= max {
                    (*min, *max)
                } else {
                    (*max, *min)
                };
                rng.gen_range(lo..=hi)
            }
            Self::MatchDistribution => {
                if target_size as usize > payload_size {
                    (target_size as usize - payload_size) as u16
                } else {
                    0
                }
            }
            Self::Fixed { size } => *size,
        }
    }
}

/// Header Specification for dynamic per-packet header generation
///
/// Instead of storing fixed header bytes, HeaderSpec declares how to generate
/// headers dynamically. This solves Issue #30 (WireGuard detection) by ensuring
/// each packet has a unique but protocol-valid header.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum HeaderSpec {
    /// Structured header semantics expressed as typed fields.
    Structured { fields: Vec<HeaderField> },
    /// Raw prefix with per-packet randomization
    /// Uses fixed bytes with optional random positions
    RawPrefix {
        /// Fixed prefix bytes (hex string)
        prefix_hex: String,
        /// Indices of bytes to randomize on each packet (0-indexed)
        #[serde(default)]
        randomize_indices: Vec<usize>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum HeaderField {
    Fixed {
        bytes: Vec<u8>,
    },
    Random {
        len: usize,
    },
    Length {
        len: usize,
        endian: HeaderEndian,
    },
    Id {
        len: usize,
        mode: IdFieldMode,
    },
    CounterLike {
        len: usize,
        endian: HeaderEndian,
        #[serde(default)]
        start: u64,
        #[serde(default = "default_counter_step")]
        step: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HeaderEndian {
    Big,
    Little,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum IdFieldMode {
    #[default]
    Random,
    Zero,
}

fn default_counter_step() -> u64 {
    1
}

impl HeaderSpec {
    pub fn structured(fields: Vec<HeaderField>) -> Self {
        Self::Structured { fields }
    }

    pub fn stun_binding() -> Self {
        Self::stun_binding_with_cookie(true)
    }

    pub fn stun_binding_with_cookie(magic_cookie: bool) -> Self {
        Self::structured(vec![
            HeaderField::Fixed {
                bytes: vec![0x00, 0x01],
            },
            HeaderField::Length {
                len: 2,
                endian: HeaderEndian::Big,
            },
            HeaderField::Fixed {
                bytes: if magic_cookie {
                    vec![0x21, 0x12, 0xA4, 0x42]
                } else {
                    vec![0x00, 0x00, 0x00, 0x00]
                },
            },
            HeaderField::Id {
                len: 12,
                mode: IdFieldMode::Random,
            },
        ])
    }

    pub fn quic_initial(version: u32, dcid_len: u8) -> Self {
        let dcid_len = dcid_len.clamp(8, 20);
        Self::structured(vec![
            HeaderField::Fixed { bytes: vec![0xC0] },
            HeaderField::Fixed {
                bytes: version.to_be_bytes().to_vec(),
            },
            HeaderField::Fixed {
                bytes: vec![dcid_len],
            },
            HeaderField::Id {
                len: dcid_len as usize,
                mode: IdFieldMode::Random,
            },
        ])
    }

    pub fn dns_query(flags: u16) -> Self {
        Self::structured(vec![
            HeaderField::Id {
                len: 2,
                mode: IdFieldMode::Random,
            },
            HeaderField::Fixed {
                bytes: flags.to_be_bytes().to_vec(),
            },
            HeaderField::Fixed {
                bytes: vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            },
        ])
    }

    pub fn tls_record(content_type: u8, version: u16) -> Self {
        Self::structured(vec![
            HeaderField::Fixed {
                bytes: vec![content_type],
            },
            HeaderField::Fixed {
                bytes: version.to_be_bytes().to_vec(),
            },
            HeaderField::Length {
                len: 2,
                endian: HeaderEndian::Big,
            },
        ])
    }

    pub fn fields(&self) -> Vec<HeaderField> {
        match self {
            Self::Structured { fields } => fields.clone(),
            Self::RawPrefix {
                prefix_hex,
                randomize_indices,
            } => {
                let bytes =
                    hex::decode(prefix_hex).unwrap_or_else(|_| vec![0x00, 0x01, 0x02, 0x03]);
                if randomize_indices.is_empty() {
                    return vec![HeaderField::Fixed { bytes }];
                }
                let mut fields = Vec::new();
                let mut current_fixed = Vec::new();
                for (idx, byte) in bytes.iter().enumerate() {
                    if randomize_indices.contains(&idx) {
                        if !current_fixed.is_empty() {
                            fields.push(HeaderField::Fixed {
                                bytes: std::mem::take(&mut current_fixed),
                            });
                        }
                        fields.push(HeaderField::Random { len: 1 });
                    } else {
                        current_fixed.push(*byte);
                    }
                }
                if !current_fixed.is_empty() {
                    fields.push(HeaderField::Fixed {
                        bytes: current_fixed,
                    });
                }
                fields
            }
        }
    }

    /// Generate a header from this specification
    /// Returns different bytes on each call for randomizable fields
    pub fn generate<R: Rng>(&self, rng: &mut R) -> Vec<u8> {
        let mut header = Vec::new();
        for field in self.fields() {
            match field {
                HeaderField::Fixed { bytes } => header.extend_from_slice(&bytes),
                HeaderField::Random { len } => {
                    // Clamp attacker-controlled field widths: a mask carrying
                    // `len: usize::MAX` would abort on allocation. No real
                    // protocol header field is wider than an MTU.
                    let len = len.min(MAX_HEADER_FIELD_LEN);
                    let start = header.len();
                    header.resize(start + len, 0);
                    rng.fill_bytes(&mut header[start..start + len]);
                }
                HeaderField::Length { len, endian } => {
                    let bytes = encode_semantic_u64(0, len, endian);
                    header.extend_from_slice(&bytes);
                }
                HeaderField::Id { len, mode } => {
                    let len = len.min(MAX_HEADER_FIELD_LEN);
                    match mode {
                        IdFieldMode::Random => {
                            let start = header.len();
                            header.resize(start + len, 0);
                            rng.fill_bytes(&mut header[start..start + len]);
                        }
                        IdFieldMode::Zero => header.extend(std::iter::repeat_n(0u8, len)),
                    }
                }
                HeaderField::CounterLike {
                    len,
                    endian,
                    start,
                    step,
                } => {
                    // saturating_mul: an adversarial `step` near u64::MAX would
                    // otherwise overflow the multiply in an overflow-checked build.
                    let raw =
                        start.saturating_add(rng.gen_range(0..=step.max(1).saturating_mul(1024)));
                    let bytes = encode_semantic_u64(raw, len, endian);
                    header.extend_from_slice(&bytes);
                }
            }
        }
        header
    }

    /// Get the minimum header length for this spec
    pub fn min_length(&self) -> usize {
        self.fields()
            .into_iter()
            .map(|field| match field {
                HeaderField::Fixed { bytes } => bytes.len(),
                HeaderField::Random { len }
                | HeaderField::Length { len, .. }
                | HeaderField::Id { len, .. }
                | HeaderField::CounterLike { len, .. } => len.min(MAX_HEADER_FIELD_LEN),
            })
            .sum()
    }

    /// Byte offset, within a header produced by [`Self::generate`], of the first
    /// [`HeaderField::Length`] field — the sum of the widths of every field that
    /// precedes it — together with that field's width. Returns `None` if the
    /// spec declares no `Length` field.
    ///
    /// Used to locate the protocol length field (e.g. STUN's message-length at
    /// offset 2) for post-assembly patching once the final packet size is known.
    pub fn length_field_offset(&self) -> Option<(usize, usize)> {
        let mut offset = 0usize;
        for field in self.fields() {
            let width = match &field {
                HeaderField::Fixed { bytes } => bytes.len(),
                HeaderField::Random { len }
                | HeaderField::Length { len, .. }
                | HeaderField::Id { len, .. }
                | HeaderField::CounterLike { len, .. } => (*len).min(MAX_HEADER_FIELD_LEN),
            };
            if matches!(field, HeaderField::Length { .. }) {
                return Some((offset, width));
            }
            offset += width;
        }
        None
    }

    /// Generate a static header template for legacy compatibility
    /// Uses a seeded RNG for deterministic output
    pub fn generate_static(&self) -> Vec<u8> {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        self.generate(&mut rng)
    }
}

/// Upper bound on a single header field's width. A `MaskProfile` can be
/// deserialized from a `MaskUpdate` before full signature verification; a field
/// declaring `len: usize::MAX` would otherwise abort the process on allocation.
/// No legitimate protocol header field exceeds an MTU.
const MAX_HEADER_FIELD_LEN: usize = 1500;

fn encode_semantic_u64(value: u64, len: usize, endian: HeaderEndian) -> Vec<u8> {
    let len = len.min(MAX_HEADER_FIELD_LEN);
    let mut bytes = match endian {
        HeaderEndian::Big => value.to_be_bytes().to_vec(),
        HeaderEndian::Little => value.to_le_bytes().to_vec(),
    };
    if len < bytes.len() {
        match endian {
            HeaderEndian::Big => bytes = bytes[bytes.len() - len..].to_vec(),
            HeaderEndian::Little => bytes.truncate(len),
        }
    } else if len > bytes.len() {
        let mut out = vec![0u8; len - bytes.len()];
        match endian {
            HeaderEndian::Big => {
                out.extend(bytes);
                bytes = out;
            }
            HeaderEndian::Little => {
                bytes.extend(out);
            }
        }
    }
    bytes
}

/// R3 — joint size↔IAT distribution: a 2-D Gaussian mixture.
///
/// `params` is the flat layout `[k, then per component (w, mu_size, mu_iat,
/// l00, l10, l11)]`, where `L = [[l00, 0], [l10, l11]]` is the lower-triangular
/// Cholesky factor of that component's 2×2 covariance (`cov = L·Lᵀ`). Sampling a
/// component: draw `z ~ N(0, I₂)` and return `mu + L·z`, so both the per-axis
/// spread AND the size↔IAT correlation (`l10`) are reproduced — which two
/// independent 1-D marginals structurally cannot represent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeIatGmm2d {
    pub params: Vec<f64>,
}

impl SizeIatGmm2d {
    /// Component stride in `params` after the leading `k`.
    const STRIDE: usize = 6;

    /// True if the flat params are well-formed (`[k] + k·6` entries, k ≥ 1).
    pub fn is_valid(&self) -> bool {
        if self.params.is_empty() {
            return false;
        }
        // Mirror `sample_gaussian_mixture`: reject a non-finite or absurd
        // component count BEFORE the usize cast. A hostile k (e.g. 1e30)
        // saturates to usize::MAX and the `k * STRIDE` below would overflow
        // (panic in debug/overflow-checked builds).
        let k = self.params[0];
        if !k.is_finite() || !(1.0..=64.0).contains(&k) {
            return false;
        }
        let k = k as usize;
        self.params.len() >= 1 + k * Self::STRIDE
    }

    /// Sample a joint `(size_bytes, iat_ms)`. Falls back to a benign default if
    /// the params are malformed (never panics on a hostile/blank mask).
    pub fn sample<R: Rng>(&self, rng: &mut R) -> (u16, f64) {
        if !self.is_valid() {
            return (512, 20.0);
        }
        let p = &self.params;
        let k = p[0] as usize;
        // Pick a component by weight.
        let wsum: f64 = (0..k).map(|c| p[1 + c * Self::STRIDE].max(0.0)).sum();
        let mut r = rng.gen::<f64>() * wsum.max(1e-12);
        let mut ci = k - 1;
        for c in 0..k {
            r -= p[1 + c * Self::STRIDE].max(0.0);
            if r <= 0.0 {
                ci = c;
                break;
            }
        }
        let b = 1 + ci * Self::STRIDE;
        let (mu_s, mu_i, l00, l10, l11) = (p[b + 1], p[b + 2], p[b + 3], p[b + 4], p[b + 5]);
        // Two independent standard normals via Box-Muller.
        let u1 = rng.gen::<f64>().max(1e-12);
        let u2 = rng.gen::<f64>();
        let radius = (-2.0 * u1.ln()).sqrt();
        let z0 = radius * (std::f64::consts::TAU * u2).cos();
        let z1 = radius * (std::f64::consts::TAU * u2).sin();
        let size = mu_s + l00 * z0;
        let iat = mu_i + l10 * z0 + l11 * z1;
        // Mirror the 1-D IAT path (`IATDistribution::sample`): clamp to
        // MAX_BASE_IAT_MS and drop non-finite values. `is_valid()` checks only
        // structure, so a crafted mask can carry finite-but-huge (or NaN/Inf)
        // component params; unclamped, the value reaches
        // `Duration::from_secs_f64` at the mimicry sleep site, which PANICS
        // out of Duration range (or silently stalls the sender for hours).
        let iat = if iat.is_finite() {
            iat.clamp(0.0, MAX_BASE_IAT_MS)
        } else {
            20.0
        };
        (size.max(1.0).round().min(65535.0) as u16, iat)
    }
}

/// FSM state for behavioral mimicry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FSMState {
    pub state_id: u16,
    pub transitions: Vec<FSMTransition>,
}

/// FSM transition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FSMTransition {
    pub condition: TransitionCondition,
    pub next_state: u16,
    pub size_override: Option<SizeDistribution>,
    pub iat_override: Option<IATDistribution>,
    pub padding_override: Option<PaddingStrategy>,
}

/// Transition condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransitionCondition {
    AfterPackets(u32),
    AfterDuration(u64), // milliseconds
    OnPayloadType(u8),
    Random(f32), // probability per packet
}

impl MaskProfile {
    /// Downlink MDH byte length a peer frames packets with for this mask: the
    /// `header_spec`'s minimum length when structured, else the static
    /// `header_template` length. This is the single source of truth shared by
    /// the desktop client, both mobile cores, and the server's
    /// `packet_layout_for_mask`, so all sides agree on where the ciphertext
    /// starts. Clients accumulate these values across a session's masks to
    /// decode downlink packets whatever mask the server framed them with.
    pub fn mdh_len(&self) -> usize {
        self.header_spec
            .as_ref()
            .map(|spec| spec.min_length())
            .unwrap_or_else(|| self.header_template.len())
    }

    /// Verify Ed25519 signature over all profile fields except the signature itself
    /// Canonical byte string that the mask signature authenticates. Covers
    /// EVERY field of the mask (the whole struct serialized with the signature
    /// zeroed), so the signature can't be preserved while an attacker repoints
    /// the header layout (`header_spec`), the tag position (`tag_offset`), the
    /// spoof protocol, the distributions, or the FSM. `MaskProfile` contains no
    /// hash maps, so serde field order — and therefore this encoding — is
    /// deterministic.
    ///
    /// NOTE: this is intentionally NOT the pre-0.10 message (which covered only
    /// mask_id/version/header_template/eph_pub_*). Signatures produced before
    /// this change do not verify — an accepted breaking change for 0.10.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut canonical = self.clone();
        canonical.signature = [0u8; 64];
        serde_json::to_vec(&canonical).unwrap_or_default()
    }

    /// Sign this mask in place with the operator's Ed25519 key over
    /// [`Self::signing_message`].
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer;
        self.signature = [0u8; 64];
        let msg = self.signing_message();
        self.signature = signing_key.sign(&msg).to_bytes();
    }

    pub fn verify_signature(&self, public_key: &[u8; 32]) -> Result<bool> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let vk = VerifyingKey::from_bytes(public_key)
            .map_err(|e| Error::Crypto(format!("Invalid Ed25519 public key: {}", e)))?;

        let message = self.signing_message();
        let sig = Signature::from_bytes(&self.signature);
        match vk.verify(&message, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// `true` when this mask carries the legacy all-zero signature — i.e. it was
    /// produced before operator signing existed (R2 Phase B) or by a generator
    /// without a configured `--mask-signing-key`. Such masks are "unsigned",
    /// not "forged": the verify mode decides whether they are accepted.
    pub fn is_unsigned(&self) -> bool {
        self.signature == [0u8; 64]
    }

    /// `true` for per-session derived variants (`polymorphic:*`, `bootstrap:*`).
    /// These are perturbed from a base mask, so signature-covered fields shift
    /// while `signature` keeps the base mask's stale value — they are NOT
    /// independently verifiable (see `apply_polymorphic_perturbation`). They
    /// only ever arrive over the AEAD-authenticated session channel, which is
    /// what authenticates them; artifact verification must skip them.
    pub fn is_derived_variant(&self) -> bool {
        self.mask_id.starts_with("polymorphic:") || self.mask_id.starts_with("bootstrap:")
    }

    /// Produce a per-session polymorphic variant of this mask, deterministically
    /// derived from the session's `prng_seed`. See `apply_polymorphic_perturbation`.
    pub fn to_polymorphic(&self, prng_seed: &[u8; 32]) -> MaskProfile {
        let mut variant = self.clone();
        let seed = polymorphic_seed(prng_seed);
        apply_polymorphic_perturbation(&mut variant, &seed);
        variant
    }

    /// Byte offset within the MDH at which the resonance tag is embedded, or
    /// `None` for the legacy (tag-prefixed) layout. See [`MaskProfile::tag_offset`].
    pub fn embedded_tag_offset(&self) -> Option<usize> {
        if self.tag_offset == u16::MAX {
            None
        } else {
            Some(self.tag_offset as usize)
        }
    }

    /// Byte offset of the STUN message-length field within this mask's header,
    /// or `None` if the mask does not mimic STUN or its header carries no
    /// `Length` field.
    ///
    /// Only STUN-mimicking masks (`spoof_protocol == WebRTC_STUN`) return a
    /// value: the STUN semantics ("bytes after the fixed 20-byte STUN header")
    /// are what [`Self::patch_stun_length`] encodes, and applying them to a
    /// non-STUN `Length` field (e.g. a TLS-record length) would be wrong. For
    /// the shipped STUN presets this resolves to offset 2, width 2, big-endian.
    pub fn stun_length_field_offset(&self) -> Option<usize> {
        if self.spoof_protocol != SpoofProtocol::WebRTC_STUN {
            return None;
        }
        self.header_spec
            .as_ref()?
            .length_field_offset()
            .map(|(offset, _width)| offset)
    }

    /// Post-assembly patch of the STUN message-length field.
    ///
    /// nDPI's `is_stun()` requires an EXACT `msg_len + 20 == udp_payload_len`
    /// (the STUN header is 20 bytes), so the length field must carry
    /// `packet_len - 20` — the number of bytes after the fixed 20-byte STUN
    /// header. The header alone cannot know the final packet size (same
    /// situation as the resonance tag, which is embedded post-assembly), so the
    /// caller invokes this once the full `[mdh][ciphertext]` packet is built.
    ///
    /// No-op unless this mask mimics STUN with a `Length` field
    /// ([`Self::stun_length_field_offset`]) AND the packet is at least the
    /// 20-byte STUN header long. The value is written big-endian as a `u16`.
    ///
    /// MUST only be called on a packet whose STUN header sits at offset 0 (the
    /// Variant A embedded-tag layout). In the legacy tag-prefix layout the
    /// header is shifted past the 8-byte tag prefix, so patching at the header's
    /// internal length offset would corrupt the tag — callers gate this to the
    /// embedded branch.
    ///
    /// LIMITATION: this assumes the STUN header occupies exactly the first 20
    /// bytes. A polymorphic variant that inserts header-gap bytes (see
    /// [`apply_polymorphic_perturbation`]) would push the real STUN header past
    /// offset 20 and break the `+ 20` assumption — polymorphism and STUN DPI
    /// pass-through are therefore in tension and must not be combined for a mask
    /// that has to classify as STUN.
    pub fn patch_stun_length(&self, packet: &mut [u8]) {
        const STUN_HEADER_LEN: usize = 20;
        let Some(offset) = self.stun_length_field_offset() else {
            return;
        };
        if packet.len() < STUN_HEADER_LEN || offset + 2 > packet.len() {
            return;
        }
        let msg_len = (packet.len() - STUN_HEADER_LEN) as u16;
        packet[offset..offset + 2].copy_from_slice(&msg_len.to_be_bytes());
    }

    /// True when the embedded-tag slot `[tag_offset, tag_offset + tag_size)`
    /// overlaps the ephemeral-public-key slot
    /// `[eph_pub_offset, eph_pub_offset + eph_pub_length)`.
    ///
    /// A well-formed new-layout mask keeps these disjoint (the tag hides in an
    /// opaque carrier field, the eph-key lives after the protocol header). A
    /// malformed/adversarial mask that overlaps them would corrupt the embedded
    /// key, so the build path treats an overlap as a signal to fall back to the
    /// legacy layout. Always `false` for legacy masks.
    pub fn tag_overlaps_eph_pub(&self, tag_size: usize) -> bool {
        match self.embedded_tag_offset() {
            None => false,
            Some(tag_start) => {
                let tag_end = tag_start + tag_size;
                let eph_start = self.eph_pub_offset as usize;
                let eph_end = eph_start + self.eph_pub_length as usize;
                tag_start < eph_end && eph_start < tag_end
            }
        }
    }

    /// SINGLE source of truth for the embedded-vs-legacy wire-layout decision.
    ///
    /// Returns `true` when a packet whose mimicry header is `mdh_len` bytes long
    /// hides the 8-byte resonance tag INSIDE that header (no separate tag
    /// prefix); `false` when the mask falls back to the legacy layout that
    /// carries the tag as an 8-byte prefix before the header.
    ///
    /// The embedded layout is used only when the tag slot fits within the
    /// header AND does not overlap the embedded ephemeral key. The client
    /// encoder ([`crate::mimicry`]) and the server uplink decoder
    /// (`aivpn-server` gateway) MUST both route through this method: deciding it
    /// independently on each side is what produced the non-QUIC-mask AEAD
    /// failures (an embedded-tag mask whose tag did not fit `mdh_len` was
    /// encoded with a legacy prefix by the client but decoded at the embedded
    /// offset by the server, so every uplink packet failed authentication).
    pub fn uses_embedded_layout(&self, mdh_len: usize) -> bool {
        use crate::crypto::TAG_SIZE;
        match self.embedded_tag_offset() {
            Some(off) => off + TAG_SIZE <= mdh_len && !self.tag_overlaps_eph_pub(TAG_SIZE),
            None => false,
        }
    }

    /// Effective tag-prefix byte length for a packet with header length
    /// `mdh_len`: `0` for the embedded layout, `TAG_SIZE` for the legacy
    /// prefix layout. Companion to [`Self::uses_embedded_layout`] and the one
    /// value the ciphertext offset must be computed from on both wire ends.
    pub fn effective_tag_prefix_len(&self, mdh_len: usize) -> usize {
        if self.uses_embedded_layout(mdh_len) {
            0
        } else {
            crate::crypto::TAG_SIZE
        }
    }

    /// Get initial FSM state
    pub fn initial_state(&self) -> u16 {
        self.fsm_initial_state
    }

    /// Process FSM transition
    pub fn process_transition(
        &self,
        current_state: u16,
        packets_in_state: u32,
        duration_in_state_ms: u64,
    ) -> (
        u16,
        Option<SizeDistribution>,
        Option<IATDistribution>,
        Option<PaddingStrategy>,
    ) {
        let state = self.fsm_states.iter().find(|s| s.state_id == current_state);
        if let Some(state) = state {
            for transition in &state.transitions {
                let should_transition = match &transition.condition {
                    TransitionCondition::AfterPackets(n) => packets_in_state >= *n,
                    TransitionCondition::AfterDuration(ms) => duration_in_state_ms >= *ms,
                    TransitionCondition::Random(prob) => {
                        rand::thread_rng().gen_range(0.0..1.0) < *prob
                    }
                    TransitionCondition::OnPayloadType(_) => false, // Handled separately
                };

                if should_transition {
                    return (
                        transition.next_state,
                        transition.size_override.clone(),
                        transition.iat_override.clone(),
                        transition.padding_override.clone(),
                    );
                }
            }
        }
        (current_state, None, None, None)
    }
}

#[cfg(test)]
mod distribution_tests {
    use super::{IATDistType, IATDistribution};
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn iat_inverted_jitter_range_does_not_panic() {
        // Inverted jitter range (lo > hi) must not panic; falls back to 0 jitter.
        let dist = IATDistribution {
            dist_type: IATDistType::Empirical,
            params: vec![50.0],
            jitter_range_ms: (10.0, -10.0),
        };
        let mut rng = StdRng::seed_from_u64(11);
        for _ in 0..64 {
            let v = dist.sample(&mut rng);
            assert_eq!(v, 50.0);
        }
    }

    #[test]
    fn iat_nan_jitter_range_does_not_panic() {
        let dist = IATDistribution {
            dist_type: IATDistType::Empirical,
            params: vec![30.0],
            jitter_range_ms: (0.0, f64::NAN),
        };
        let mut rng = StdRng::seed_from_u64(12);
        for _ in 0..16 {
            let v = dist.sample(&mut rng);
            assert_eq!(v, 30.0);
        }
    }

    #[test]
    fn iat_gamma_huge_shape_param_terminates() {
        // A malformed mask with an enormous gamma shape param must not hang.
        let dist = IATDistribution {
            dist_type: IATDistType::Gamma,
            params: vec![1e18, 1.0],
            jitter_range_ms: (0.0, 0.0),
        };
        let mut rng = StdRng::seed_from_u64(13);
        let v = dist.sample(&mut rng);
        assert!(v.is_finite());
    }

    #[test]
    fn iat_sampling_uses_symmetric_jitter_range() {
        let dist = IATDistribution {
            dist_type: IATDistType::Empirical,
            params: vec![50.0],
            jitter_range_ms: (-10.0, 10.0),
        };
        let mut rng = StdRng::seed_from_u64(7);
        let samples: Vec<f64> = (0..256).map(|_| dist.sample(&mut rng)).collect();

        assert!(samples.iter().any(|&value| value < 50.0));
        assert!(samples.iter().any(|&value| value > 50.0));
    }
}

/// File-backed preset mask catalog
pub mod preset_masks {
    use super::*;
    use std::sync::OnceLock;

    static WEBRTC_ZOOM_V3: OnceLock<MaskProfile> = OnceLock::new();
    static QUIC_HTTPS_V2: OnceLock<MaskProfile> = OnceLock::new();
    static WEBRTC_YANDEX_TELEMOST_V1: OnceLock<MaskProfile> = OnceLock::new();
    static WEBRTC_VK_TEAMS_V1: OnceLock<MaskProfile> = OnceLock::new();
    static WEBRTC_SBERJAZZ_V1: OnceLock<MaskProfile> = OnceLock::new();

    fn parse_mask(json: &str) -> MaskProfile {
        serde_json::from_str(json).expect("valid preset mask asset")
    }

    fn load_webrtc_zoom_v3() -> MaskProfile {
        parse_mask(include_str!("../../../assets/masks/webrtc_zoom_v3.json"))
    }

    fn load_quic_https_v2() -> MaskProfile {
        parse_mask(include_str!("../../../assets/masks/quic_https_v2.json"))
    }

    fn load_webrtc_yandex_telemost_v1() -> MaskProfile {
        parse_mask(include_str!(
            "../../../assets/masks/webrtc_yandex_telemost_v1.json"
        ))
    }

    fn load_webrtc_vk_teams_v1() -> MaskProfile {
        parse_mask(include_str!(
            "../../../assets/masks/webrtc_vk_teams_v1.json"
        ))
    }

    fn load_webrtc_sberjazz_v1() -> MaskProfile {
        parse_mask(include_str!(
            "../../../assets/masks/webrtc_sberjazz_v1.json"
        ))
    }

    pub fn webrtc_zoom_v3() -> MaskProfile {
        WEBRTC_ZOOM_V3.get_or_init(load_webrtc_zoom_v3).clone()
    }

    pub fn quic_https_v2() -> MaskProfile {
        QUIC_HTTPS_V2.get_or_init(load_quic_https_v2).clone()
    }

    pub fn webrtc_yandex_telemost_v1() -> MaskProfile {
        WEBRTC_YANDEX_TELEMOST_V1
            .get_or_init(load_webrtc_yandex_telemost_v1)
            .clone()
    }

    pub fn webrtc_vk_teams_v1() -> MaskProfile {
        WEBRTC_VK_TEAMS_V1
            .get_or_init(load_webrtc_vk_teams_v1)
            .clone()
    }

    pub fn webrtc_sberjazz_v1() -> MaskProfile {
        WEBRTC_SBERJAZZ_V1
            .get_or_init(load_webrtc_sberjazz_v1)
            .clone()
    }

    pub fn all() -> Vec<MaskProfile> {
        vec![
            webrtc_zoom_v3(),
            quic_https_v2(),
            webrtc_yandex_telemost_v1(),
            webrtc_vk_teams_v1(),
            webrtc_sberjazz_v1(),
        ]
    }

    pub fn by_id(mask_id: &str) -> Option<MaskProfile> {
        match mask_id {
            "webrtc_zoom_v3" => Some(webrtc_zoom_v3()),
            "quic_https_v2" => Some(quic_https_v2()),
            "webrtc_yandex_telemost_v1" => Some(webrtc_yandex_telemost_v1()),
            "webrtc_vk_teams_v1" => Some(webrtc_vk_teams_v1()),
            "webrtc_sberjazz_v1" => Some(webrtc_sberjazz_v1()),
            _ => None,
        }
    }

    pub fn bootstrap_default() -> MaskProfile {
        webrtc_zoom_v3()
    }

    // Regression: the embedded-vs-legacy wire-layout decision must be
    // length-aware and identical on both wire ends. An embedded-tag mask whose
    // tag does not fit the header length (or overlaps the ephemeral key) is
    // encoded with the 8-byte legacy prefix; before the shared
    // `uses_embedded_layout` fix the server decoded it at the embedded offset
    // and every uplink packet failed AEAD (the Jul-14 aead::Error class).
    #[test]
    fn embedded_layout_decision_is_length_aware() {
        use crate::crypto::TAG_SIZE;
        let mut mask = load_webrtc_vk_teams_v1();

        // Disjoint embedded tag at offset 8, eph key well clear of it.
        mask.tag_offset = 8;
        mask.eph_pub_offset = 40;
        mask.eph_pub_length = 32;

        // Fits (8 + 8 <= 20): embedded layout, no tag prefix.
        assert!(mask.uses_embedded_layout(20));
        assert_eq!(mask.effective_tag_prefix_len(20), 0);

        // Does NOT fit (8 + 8 > 12): legacy fallback, 8-byte prefix — the exact
        // case the client encoder falls back on, so the server must too.
        assert!(!mask.uses_embedded_layout(12));
        assert_eq!(mask.effective_tag_prefix_len(12), TAG_SIZE);

        // Overlaps eph_pub ([10,18) vs tag [8,16)): legacy fallback even though
        // it would fit lengthwise.
        mask.eph_pub_offset = 10;
        mask.eph_pub_length = 8;
        assert!(!mask.uses_embedded_layout(64));
        assert_eq!(mask.effective_tag_prefix_len(64), TAG_SIZE);

        // Legacy mask (no embedded tag): always the 8-byte prefix.
        mask.tag_offset = u16::MAX;
        assert!(!mask.uses_embedded_layout(64));
        assert_eq!(mask.effective_tag_prefix_len(64), TAG_SIZE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn size_iat_joint_reproduces_correlation() {
        // Cholesky L = [[10,0],[8,6]] → cov = LLᵀ, corr = l10/√(l10²+l11²) = 0.8.
        let dist = SizeIatGmm2d {
            params: vec![1.0, 1.0, 500.0, 20.0, 10.0, 8.0, 6.0],
        };
        assert!(dist.is_valid());
        let mut rng = StdRng::seed_from_u64(7);
        let mut xs = Vec::new();
        let mut ys = Vec::new();
        for _ in 0..8000 {
            let (s, i) = dist.sample(&mut rng);
            xs.push(s as f64);
            ys.push(i);
        }
        let n = xs.len() as f64;
        let mx = xs.iter().sum::<f64>() / n;
        let my = ys.iter().sum::<f64>() / n;
        let cov = xs
            .iter()
            .zip(&ys)
            .map(|(x, y)| (x - mx) * (y - my))
            .sum::<f64>()
            / n;
        let sx = (xs.iter().map(|x| (x - mx).powi(2)).sum::<f64>() / n).sqrt();
        let sy = (ys.iter().map(|y| (y - my).powi(2)).sum::<f64>() / n).sqrt();
        let corr = cov / (sx * sy);
        // Empirical correlation must land near the 0.8 the Cholesky encodes —
        // exactly what two independent 1-D marginals cannot reproduce.
        assert!(corr > 0.7 && corr < 0.9, "corr={corr}");
    }

    #[test]
    fn size_iat_joint_rejects_malformed() {
        // Blank / truncated params must degrade to a benign default, not panic.
        let mut rng = StdRng::seed_from_u64(1);
        let empty = SizeIatGmm2d { params: vec![] };
        assert!(!empty.is_valid());
        let _ = empty.sample(&mut rng);
        let truncated = SizeIatGmm2d {
            params: vec![2.0, 1.0, 500.0], // claims k=2, only one partial component
        };
        assert!(!truncated.is_valid());
        let _ = truncated.sample(&mut rng);
        // A hostile component count must be rejected before the usize
        // cast/multiply (overflow panic in debug builds).
        for bad_k in [1e30, f64::NAN, f64::INFINITY, -1.0, 65.0] {
            let hostile = SizeIatGmm2d {
                params: vec![bad_k, 1.0, 500.0, 20.0, 10.0, 0.0, 5.0],
            };
            assert!(!hostile.is_valid());
            let _ = hostile.sample(&mut rng);
        }
    }

    #[test]
    fn size_iat_joint_clamps_hostile_iat() {
        // `is_valid()` checks structure only, so a structurally valid mask can
        // still carry finite-but-huge (or non-finite) component params. The
        // sampled IAT must mirror the 1-D path's MAX_BASE_IAT_MS clamp —
        // unclamped it reaches Duration::from_secs_f64 at the mimicry sleep
        // site and panics (or stalls the sender for hours).
        let mut rng = StdRng::seed_from_u64(7);
        for bad_mu_iat in [1e300, f64::INFINITY, f64::NEG_INFINITY, f64::NAN] {
            let hostile = SizeIatGmm2d {
                params: vec![1.0, 1.0, 500.0, bad_mu_iat, 10.0, 0.0, 5.0],
            };
            assert!(hostile.is_valid(), "structurally valid by design");
            for _ in 0..64 {
                let (_size, iat) = hostile.sample(&mut rng);
                assert!(
                    iat.is_finite() && (0.0..=MAX_BASE_IAT_MS).contains(&iat),
                    "iat={iat} escaped the clamp for mu_iat={bad_mu_iat}"
                );
                // Must never panic downstream.
                let _ = std::time::Duration::from_secs_f64(iat / 1000.0);
            }
        }
        // Hostile Cholesky terms (l10/l11) feed the IAT too.
        let hostile_l = SizeIatGmm2d {
            params: vec![1.0, 1.0, 500.0, 20.0, 10.0, 1e308, 1e308],
        };
        for _ in 0..64 {
            let (_size, iat) = hostile_l.sample(&mut rng);
            assert!(iat.is_finite() && (0.0..=MAX_BASE_IAT_MS).contains(&iat));
        }
    }

    #[test]
    fn test_stun_binding_generation() {
        let spec = HeaderSpec::stun_binding();

        // Generate two headers - they should differ in transaction_id
        let mut rng = StdRng::seed_from_u64(42);
        let header1 = spec.generate(&mut rng);
        let header2 = spec.generate(&mut rng);

        assert_eq!(header1.len(), 20);
        assert_eq!(header2.len(), 20);

        // First 8 bytes should be the same (type + length + magic cookie)
        assert_eq!(&header1[0..2], &[0x00, 0x01]); // Binding Request
        assert_eq!(&header1[4..8], &[0x21, 0x12, 0xA4, 0x42]); // Magic cookie

        // Transaction IDs should differ
        assert_ne!(&header1[8..], &header2[8..]);
    }

    #[test]
    fn test_quic_initial_generation() {
        let spec = HeaderSpec::quic_initial(0x00000001, 8);

        let mut rng = StdRng::seed_from_u64(42);
        let header1 = spec.generate(&mut rng);
        let header2 = spec.generate(&mut rng);

        assert_eq!(header1.len(), 14); // 1 + 4 + 1 + 8
        assert_eq!(header2.len(), 14);

        // First byte should be 0xC0 (long packet)
        assert_eq!(header1[0], 0xC0);

        // Version bytes
        assert_eq!(&header1[1..5], &0x00000001u32.to_be_bytes());

        // DCID length
        assert_eq!(header1[5], 8);

        // DCID should differ between generations
        assert_ne!(&header1[6..], &header2[6..]);
    }

    #[test]
    fn test_dns_query_generation() {
        let spec = HeaderSpec::dns_query(0x0100);

        let mut rng = StdRng::seed_from_u64(42);
        let header1 = spec.generate(&mut rng);
        let header2 = spec.generate(&mut rng);

        assert_eq!(header1.len(), 12);
        assert_eq!(header2.len(), 12);

        // Flags should be consistent
        assert_eq!(&header1[2..4], &[0x01, 0x00]);
        assert_eq!(&header2[2..4], &[0x01, 0x00]);

        // Transaction ID should differ
        assert_ne!(&header1[0..2], &header2[0..2]);

        // Counts should be standard DNS query
        assert_eq!(
            &header1[4..],
            &[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_tls_record_generation() {
        let spec = HeaderSpec::tls_record(0x17, 0x0303);

        let mut rng = StdRng::seed_from_u64(42);
        let header = spec.generate(&mut rng);

        assert_eq!(header.len(), 5);
        assert_eq!(header[0], 0x17); // Application data
        assert_eq!(&header[1..3], &[0x03, 0x03]); // TLS 1.2
        assert_eq!(&header[3..5], &[0x00, 0x00]); // Length (to be filled)
    }

    #[test]
    fn test_raw_prefix_generation() {
        let spec = HeaderSpec::RawPrefix {
            prefix_hex: "010203040506".to_string(),
            randomize_indices: vec![2, 4],
        };

        let mut rng = StdRng::seed_from_u64(42);
        let header1 = spec.generate(&mut rng);
        let header2 = spec.generate(&mut rng);

        assert_eq!(header1.len(), 6);
        assert_eq!(header2.len(), 6);

        // Fixed bytes should be the same
        assert_eq!(header1[0], header2[0]); // 0x01
        assert_eq!(header1[1], header2[1]); // 0x02
        assert_eq!(header1[3], header2[3]); // 0x04
        assert_eq!(header1[5], header2[5]); // 0x06

        // Randomized bytes should differ
        assert_ne!(header1[2], header2[2]);
        assert_ne!(header1[4], header2[4]);
    }

    #[test]
    fn test_header_spec_min_length() {
        let stun = HeaderSpec::stun_binding();
        assert_eq!(stun.min_length(), 20);

        let quic = HeaderSpec::quic_initial(0x00000001, 8);
        // 1 (header_form) + 4 (version) + 1 (dcid_len) + 8 (dcid) = 14
        assert_eq!(quic.min_length(), 14);

        let dns = HeaderSpec::dns_query(0x0100);
        assert_eq!(dns.min_length(), 12);

        let tls = HeaderSpec::tls_record(0x17, 0x0303);
        assert_eq!(tls.min_length(), 5);
    }

    #[test]
    fn test_static_generation_deterministic() {
        let spec = HeaderSpec::stun_binding();

        let static1 = spec.generate_static();
        let static2 = spec.generate_static();

        // Static generation should be deterministic
        assert_eq!(static1, static2);
    }

    #[test]
    fn test_preset_masks_have_header_spec() {
        let mask = preset_masks::webrtc_zoom_v3();
        assert!(mask.header_spec.is_some());
        // Bumped to v3 to signal the Variant A embedded-tag wire layout.
        assert_eq!(mask.version, 3);

        let mask2 = preset_masks::quic_https_v2();
        assert!(mask2.header_spec.is_some());
        assert_eq!(mask2.version, 3);
    }

    #[test]
    fn preset_masks_use_new_embedded_tag_layout() {
        use crate::crypto::TAG_SIZE;
        // Every shipped preset now uses the embedded-tag layout, and its
        // header is long enough to hold the tag without overlapping the
        // ephemeral-public-key slot.
        for mask in preset_masks::all() {
            let off = mask
                .embedded_tag_offset()
                .unwrap_or_else(|| panic!("{} must set tag_offset", mask.mask_id));
            let min_hdr = mask
                .header_spec
                .as_ref()
                .expect("preset has header_spec")
                .min_length();
            assert!(
                off + TAG_SIZE <= min_hdr,
                "{}: tag slot {}..{} exceeds header len {}",
                mask.mask_id,
                off,
                off + TAG_SIZE,
                min_hdr
            );
            assert!(
                !mask.tag_overlaps_eph_pub(TAG_SIZE),
                "{}: embedded tag slot overlaps eph_pub slot",
                mask.mask_id
            );
        }
    }

    #[test]
    fn legacy_mask_without_tag_offset_field_defaults_to_sentinel() {
        // A JSON mask omitting `tag_offset` must deserialize to the legacy
        // sentinel so it stays on the old tag-prefix wire layout.
        let json = r#"{
            "mask_id": "legacy_test",
            "version": 1,
            "created_at": 0,
            "expires_at": 0,
            "spoof_protocol": "None",
            "header_template": [0, 0, 0, 0],
            "eph_pub_offset": 4,
            "eph_pub_length": 32,
            "size_distribution": { "dist_type": "Histogram", "bins": [], "parametric_type": null, "parametric_params": null },
            "iat_distribution": { "dist_type": "Exponential", "params": [0.1], "jitter_range_ms": [0.0, 0.0] },
            "padding_strategy": "MatchDistribution",
            "fsm_states": [],
            "fsm_initial_state": 0,
            "signature_vector": [],
            "reverse_profile": null
        }"#;
        let mask: MaskProfile = serde_json::from_str(json).expect("legacy mask parses");
        assert_eq!(mask.tag_offset, u16::MAX);
        assert_eq!(mask.embedded_tag_offset(), None);
    }

    #[test]
    fn stun_length_field_offset_resolves_to_offset_two() {
        // All shipped STUN presets declare the Length field at byte offset 2.
        for mask in preset_masks::all() {
            match mask.spoof_protocol {
                SpoofProtocol::WebRTC_STUN => {
                    assert_eq!(
                        mask.stun_length_field_offset(),
                        Some(2),
                        "{}: STUN length field must be at offset 2",
                        mask.mask_id
                    );
                }
                _ => {
                    // Non-STUN masks (e.g. QUIC) expose no STUN length field.
                    assert_eq!(
                        mask.stun_length_field_offset(),
                        None,
                        "{}: non-STUN mask must not report a STUN length field",
                        mask.mask_id
                    );
                }
            }
        }
    }

    #[test]
    fn patch_stun_length_writes_packet_len_minus_20_big_endian() {
        let mask = preset_masks::webrtc_zoom_v3();
        // Build a synthetic packet of a known size and patch it.
        for total in [20usize, 21, 40, 170, 1380] {
            let mut packet = vec![0u8; total];
            mask.patch_stun_length(&mut packet);
            let msg_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            assert_eq!(
                msg_len + 20,
                total,
                "patched STUN length must satisfy msg_len + 20 == packet_len"
            );
        }
        // Shorter-than-header packet is left untouched (no panic, no write).
        let mut tiny = vec![0xFFu8; 4];
        mask.patch_stun_length(&mut tiny);
        assert_eq!(tiny, vec![0xFFu8; 4]);
    }

    #[test]
    fn patch_stun_length_is_noop_for_non_stun_mask() {
        // A QUIC mask must never have its bytes rewritten by the STUN patch.
        let mask = preset_masks::quic_https_v2();
        assert_eq!(mask.stun_length_field_offset(), None);
        let mut packet = vec![0xABu8; 200];
        mask.patch_stun_length(&mut packet);
        assert_eq!(packet, vec![0xABu8; 200]);
    }

    #[test]
    fn random_uniform_padding_inverted_range_does_not_panic() {
        // A malformed mask with RandomUniform { min > max } must not panic.
        let strat = PaddingStrategy::RandomUniform { min: 200, max: 10 };
        let mut rng = StdRng::seed_from_u64(3);
        for _ in 0..64 {
            let pad = strat.calc_padding(100, 300, &mut rng);
            assert!((10..=200).contains(&pad));
        }
    }

    #[test]
    fn size_distribution_inverted_bin_does_not_panic() {
        // A malformed mask with an inverted histogram bin (min > max) must not
        // panic the sender's packet-size sampling path.
        let dist = SizeDistribution {
            dist_type: SizeDistType::Histogram,
            bins: vec![(500, 100, 1.0)],
            parametric_type: None,
            parametric_params: None,
        };
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..64 {
            let sz = dist.sample(&mut rng);
            assert!((100..=500).contains(&sz));
        }
    }

    #[test]
    fn bootstrap_derivation_is_deterministic() {
        let descriptor = BootstrapDescriptor {
            descriptor_id: "epoch-1".into(),
            version: 1,
            created_at: 0,
            expires_at: u64::MAX,
            base_mask_ids: vec!["webrtc_zoom_v3".into(), "quic_https_v2".into()],
            embedded_masks: Vec::new(),
            candidate_count: 4,
            kdf_salt: [7u8; 32],
            signature: [0u8; 64],
        };
        let psk = [3u8; 32];
        let left = derive_bootstrap_candidates(&descriptor, Some(&psk));
        let right = derive_bootstrap_candidates(&descriptor, Some(&psk));

        assert_eq!(left.len(), right.len());
        for (lhs, rhs) in left.iter().zip(right.iter()) {
            assert_eq!(lhs.mask_id, rhs.mask_id);
            assert_eq!(lhs.eph_pub_offset, rhs.eph_pub_offset);
            assert_eq!(
                lhs.header_spec.as_ref().map(|s| s.min_length()),
                rhs.header_spec.as_ref().map(|s| s.min_length())
            );
        }
    }

    #[test]
    fn bootstrap_derivation_varies_across_psks() {
        let descriptor = BootstrapDescriptor {
            descriptor_id: "epoch-2".into(),
            version: 1,
            created_at: 0,
            expires_at: u64::MAX,
            base_mask_ids: vec!["webrtc_zoom_v3".into(), "quic_https_v2".into()],
            embedded_masks: Vec::new(),
            candidate_count: 4,
            kdf_salt: [11u8; 32],
            signature: [0u8; 64],
        };

        let first = derive_bootstrap_candidates(&descriptor, Some(&[1u8; 32]));
        let second = derive_bootstrap_candidates(&descriptor, Some(&[2u8; 32]));

        assert_ne!(first[0].mask_id, second[0].mask_id);
    }

    #[test]
    fn bootstrap_derivation_supports_embedded_masks() {
        let descriptor = BootstrapDescriptor {
            descriptor_id: "epoch-3".into(),
            version: 1,
            created_at: 0,
            expires_at: u64::MAX,
            base_mask_ids: Vec::new(),
            embedded_masks: vec![preset_masks::webrtc_zoom_v3()],
            candidate_count: 1,
            kdf_salt: [13u8; 32],
            signature: [0u8; 64],
        };

        let masks = derive_bootstrap_candidates(&descriptor, Some(&[9u8; 32]));
        assert_eq!(masks.len(), 1);
        assert!(masks[0]
            .mask_id
            .starts_with("bootstrap:epoch-3:webrtc_zoom_v3:"));
    }

    #[test]
    fn resolve_handshake_mask_prefers_covert_descriptor_over_preset() {
        let descriptor = BootstrapDescriptor {
            descriptor_id: "epoch-42".into(),
            version: 1,
            created_at: 0,
            expires_at: u64::MAX,
            base_mask_ids: vec!["webrtc_zoom_v3".into(), "quic_https_v2".into()],
            embedded_masks: Vec::new(),
            candidate_count: 4,
            kdf_salt: [5u8; 32],
            signature: [0u8; 64],
        };
        let psk = [9u8; 32];

        // A descriptor-derived name resolves to the EXACT covert mask, not a preset.
        let covert = derive_bootstrap_candidates(&descriptor, Some(&psk))
            .into_iter()
            .next()
            .unwrap();
        let resolved = resolve_handshake_mask(
            Some(&covert.mask_id),
            std::slice::from_ref(&descriptor),
            Some(&psk),
        );
        assert_eq!(resolved.mask_id, covert.mask_id);
        assert!(resolved.mask_id.starts_with("bootstrap:epoch-42:"));

        // No named request but a descriptor is held → still covert (never a preset).
        let auto =
            resolve_handshake_mask(Some("auto"), std::slice::from_ref(&descriptor), Some(&psk));
        assert!(auto.mask_id.starts_with("bootstrap:epoch-42:"));

        // Explicit preset name is honored (deliberate user mask-picker choice).
        let preset = resolve_handshake_mask(
            Some("webrtc_zoom_v3"),
            std::slice::from_ref(&descriptor),
            Some(&psk),
        );
        assert_eq!(preset.mask_id, "webrtc_zoom_v3");
    }

    #[test]
    fn resolve_handshake_mask_falls_back_to_psk_only_without_descriptors() {
        let psk = [4u8; 32];
        // No descriptors and no preset name → legacy PSK-preset last resort:
        // the result IS one of the shipped presets (a covert descriptor mask is
        // never one), and it is stable/deterministic for a given PSK.
        let resolved = resolve_handshake_mask(None, &[], Some(&psk));
        assert!(preset_masks::by_id(&resolved.mask_id).is_some());
        let again = resolve_handshake_mask(None, &[], Some(&psk));
        assert_eq!(resolved.mask_id, again.mask_id);
    }

    #[test]
    fn resolve_handshake_mask_resilient_drops_descriptors_at_threshold() {
        let descriptor = BootstrapDescriptor {
            descriptor_id: "epoch-77".into(),
            version: 1,
            created_at: 0,
            expires_at: u64::MAX,
            base_mask_ids: vec!["webrtc_zoom_v3".into(), "quic_https_v2".into()],
            embedded_masks: Vec::new(),
            candidate_count: 4,
            kdf_salt: [3u8; 32],
            signature: [0u8; 64],
        };
        let psk = [6u8; 32];
        let descriptors = std::slice::from_ref(&descriptor);

        // Below the threshold the covert descriptor mask is still used.
        let covert = resolve_handshake_mask_resilient(
            None,
            descriptors,
            Some(&psk),
            HANDSHAKE_FALLBACK_THRESHOLD - 1,
        );
        assert!(covert.mask_id.starts_with("bootstrap:epoch-77:"));

        // At the threshold the descriptor is abandoned for a builtin preset
        // (the unmatchable-descriptor reconnect-loop breaker).
        let fallback = resolve_handshake_mask_resilient(
            None,
            descriptors,
            Some(&psk),
            HANDSHAKE_FALLBACK_THRESHOLD,
        );
        assert!(preset_masks::by_id(&fallback.mask_id).is_some());

        // An explicit preset choice is honored on both sides of the threshold.
        let chosen = resolve_handshake_mask_resilient(
            Some("webrtc_zoom_v3"),
            descriptors,
            Some(&psk),
            HANDSHAKE_FALLBACK_THRESHOLD,
        );
        assert_eq!(chosen.mask_id, "webrtc_zoom_v3");
    }

    #[test]
    fn polymorphic_variant_is_deterministic_for_same_seed() {
        let base = preset_masks::webrtc_zoom_v3();
        let seed = [7u8; 32];
        let a = base.to_polymorphic(&seed);
        let b = base.to_polymorphic(&seed);
        assert_eq!(a.mask_id, b.mask_id);
        assert_eq!(
            a.iat_distribution.jitter_range_ms,
            b.iat_distribution.jitter_range_ms
        );
        assert!(a.mask_id.starts_with("polymorphic:webrtc_zoom_v3:"));
    }

    #[test]
    fn polymorphic_variant_differs_across_seeds() {
        let base = preset_masks::webrtc_zoom_v3();
        let a = base.to_polymorphic(&[1u8; 32]);
        let b = base.to_polymorphic(&[2u8; 32]);
        // Different sessions must not collapse to an identical observable shape.
        assert_ne!(a.mask_id, b.mask_id);
    }

    #[test]
    fn polymorphic_preserves_invariants_and_bounds() {
        let base = preset_masks::quic_https_v2();
        let bounds = base.perturbation_bounds.clone().unwrap_or_default();
        for s in 0u8..64 {
            let v = base.to_polymorphic(&[s; 32]);
            // Ephemeral-key length is never perturbed.
            assert_eq!(v.eph_pub_length, base.eph_pub_length);
            // Spoofed protocol identity is never perturbed.
            assert_eq!(v.spoof_protocol, base.spoof_protocol);
            // FSM graph structure is never perturbed.
            assert_eq!(v.fsm_states.len(), base.fsm_states.len());
            assert_eq!(v.fsm_initial_state, base.fsm_initial_state);
            // Header offset only ever grows by the bounded gap.
            assert!(v.eph_pub_offset >= base.eph_pub_offset);
            assert!(v.eph_pub_offset - base.eph_pub_offset <= bounds.max_header_gap as u16);
            // Jitter range stays finite and well-ordered.
            let (lo, hi) = v.iat_distribution.jitter_range_ms;
            assert!(lo.is_finite() && hi.is_finite() && lo <= hi && lo >= 0.0);
        }
    }

    #[test]
    fn polymorphic_does_not_touch_base_signed_fields_of_original() {
        // Perturbation operates on a clone; the base mask is unchanged, so its
        // signature-covered fields remain intact.
        let base = preset_masks::webrtc_zoom_v3();
        let before = (
            base.mask_id.clone(),
            base.version,
            base.eph_pub_offset,
            base.eph_pub_length,
        );
        let _ = base.to_polymorphic(&[42u8; 32]);
        assert_eq!(
            (
                base.mask_id.clone(),
                base.version,
                base.eph_pub_offset,
                base.eph_pub_length
            ),
            before
        );
    }

    #[test]
    fn gmm_size_distribution_reproduces_two_modes() {
        // Bimodal mixture: 40 % around 60 bytes, 60 % around 400 bytes.
        let dist = SizeDistribution {
            dist_type: SizeDistType::Parametric,
            bins: Vec::new(),
            parametric_type: Some(ParametricType::Gmm),
            parametric_params: Some(vec![2.0, 0.4, 60.0, 5.0, 0.6, 400.0, 10.0]),
        };
        let mut rng = StdRng::seed_from_u64(1);
        let mut low = 0usize;
        let mut high = 0usize;
        for _ in 0..5000 {
            let s = dist.sample(&mut rng);
            assert!(s >= 1, "size must be >= 1");
            if s < 200 {
                low += 1;
            } else {
                high += 1;
            }
        }
        // Both modes must be populated, roughly in the 40/60 split.
        assert!(low > 1500 && low < 2500, "low mode count {low}");
        assert!(high > 3000, "high mode count {high}");
    }

    #[test]
    fn gmm_iat_distribution_is_non_negative_and_bimodal() {
        let dist = IATDistribution {
            dist_type: IATDistType::Gmm,
            params: vec![2.0, 0.5, 5.0, 1.0, 0.5, 100.0, 15.0],
            jitter_range_ms: (0.0, 0.0),
        };
        let mut rng = StdRng::seed_from_u64(2);
        let mut fast = 0usize;
        let mut slow = 0usize;
        for _ in 0..5000 {
            let v = dist.sample(&mut rng);
            assert!(v >= 0.0, "iat must be non-negative, got {v}");
            if v < 50.0 {
                fast += 1;
            } else {
                slow += 1;
            }
        }
        assert!(fast > 1500, "fast cadence underpopulated: {fast}");
        assert!(slow > 1500, "slow cadence underpopulated: {slow}");
    }

    #[test]
    fn gmm_distributions_json_roundtrip() {
        // Generated GMM masks are distributed as JSON — the new variants must
        // survive a serialize/deserialize cycle unchanged.
        let size = SizeDistribution {
            dist_type: SizeDistType::Parametric,
            bins: Vec::new(),
            parametric_type: Some(ParametricType::Gmm),
            parametric_params: Some(vec![2.0, 0.4, 60.0, 5.0, 0.6, 400.0, 10.0]),
        };
        let json = serde_json::to_string(&size).unwrap();
        let back: SizeDistribution = serde_json::from_str(&json).unwrap();
        assert_eq!(back.parametric_type, Some(ParametricType::Gmm));
        assert_eq!(back.parametric_params, size.parametric_params);

        let iat = IATDistribution {
            dist_type: IATDistType::Gmm,
            params: vec![2.0, 0.5, 5.0, 1.0, 0.5, 100.0, 15.0],
            jitter_range_ms: (-2.0, 2.0),
        };
        let json = serde_json::to_string(&iat).unwrap();
        let back: IATDistribution = serde_json::from_str(&json).unwrap();
        assert_eq!(back.dist_type, IATDistType::Gmm);
        assert_eq!(back.params, iat.params);
    }

    #[test]
    fn gmm_malformed_params_fall_back_safely() {
        // Truncated flat vector (claims k=3 but has no components) → fallback.
        let dist = SizeDistribution {
            dist_type: SizeDistType::Parametric,
            bins: Vec::new(),
            parametric_type: Some(ParametricType::Gmm),
            parametric_params: Some(vec![3.0]),
        };
        let mut rng = StdRng::seed_from_u64(3);
        for _ in 0..100 {
            let s = dist.sample(&mut rng);
            assert!(s >= 1, "fallback size must be valid");
        }
        // Empty params → fallback, no panic.
        let empty = IATDistribution {
            dist_type: IATDistType::Gmm,
            params: Vec::new(),
            jitter_range_ms: (0.0, 0.0),
        };
        let v = empty.sample(&mut rng);
        assert!(v >= 0.0);
    }

    #[test]
    fn mask_signature_covers_tag_offset_and_spoof_protocol() {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().to_bytes();

        let mut mask = preset_masks::all()[0].clone();
        mask.sign(&sk);
        assert!(
            mask.verify_signature(&pk).unwrap(),
            "freshly signed must verify"
        );

        // Repointing the resonance tag must invalidate the signature.
        let mut tampered = mask.clone();
        tampered.tag_offset = tampered.tag_offset.wrapping_add(1);
        assert!(
            !tampered.verify_signature(&pk).unwrap(),
            "tampered tag_offset must fail verification"
        );

        // Changing the spoof protocol must invalidate it too.
        let mut tampered2 = mask.clone();
        tampered2.spoof_protocol = match tampered2.spoof_protocol {
            SpoofProtocol::None => SpoofProtocol::QUIC,
            _ => SpoofProtocol::None,
        };
        assert!(!tampered2.verify_signature(&pk).unwrap());

        // A different key must not verify.
        let other = SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();
        assert!(!mask.verify_signature(&other).unwrap());
    }

    // ── R2 Phase B: config-gated mask artifact verification ─────────────────

    /// A generated-style mask: outer profile + signed reverse profile, like
    /// `mask_gen::generate_and_store_mask` produces.
    fn generated_style_mask() -> MaskProfile {
        let mut mask = preset_masks::all()[0].clone();
        mask.mask_id = "auto_testsvc_v1".into();
        let mut rev = mask.clone();
        rev.mask_id = "auto_testsvc_v1_rev".into();
        mask.reverse_profile = Some(Box::new(rev));
        mask
    }

    #[test]
    fn phase_b_sign_verify_round_trip_generated_style() {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key().to_bytes();

        let mut mask = generated_style_mask();
        // Sign the reverse first, then the outer — the mask_gen order — so the
        // outer signature covers the signed reverse profile.
        mask.reverse_profile.as_mut().unwrap().sign(&sk);
        mask.sign(&sk);

        assert!(!mask.is_unsigned());
        let outer = verify_mask_artifact(&mask, Some(&pk), MaskVerifyMode::Enforce);
        assert!(outer.accept);
        assert_eq!(outer.detail, MaskVerifyDetail::Valid);

        // The reverse profile must be independently verifiable too.
        let rev = mask.reverse_profile.as_ref().unwrap();
        let rev_verdict = verify_mask_artifact(rev, Some(&pk), MaskVerifyMode::Enforce);
        assert_eq!(rev_verdict.detail, MaskVerifyDetail::Valid);

        // JSON round-trip (the mask_store on-disk format) must preserve validity.
        let json = serde_json::to_string(&mask).unwrap();
        let reloaded: MaskProfile = serde_json::from_str(&json).unwrap();
        assert!(reloaded.verify_signature(&pk).unwrap());
    }

    #[test]
    fn phase_b_warn_mode_accepts_bad_signature() {
        use ed25519_dalek::SigningKey;
        let pk = SigningKey::from_bytes(&[1u8; 32])
            .verifying_key()
            .to_bytes();

        // Unsigned (all-zero) legacy mask: accepted, flagged as failure.
        let unsigned = generated_style_mask();
        assert!(unsigned.is_unsigned());
        let v = verify_mask_artifact(&unsigned, Some(&pk), MaskVerifyMode::Warn);
        assert!(v.accept, "warn mode must accept unsigned masks");
        assert_eq!(v.detail, MaskVerifyDetail::Unsigned);
        assert!(v.is_failure(), "caller must get a warn-worthy failure flag");

        // Wrong-key signature: accepted in warn, flagged Invalid.
        let mut wrong = generated_style_mask();
        wrong.sign(&SigningKey::from_bytes(&[2u8; 32]));
        let v = verify_mask_artifact(&wrong, Some(&pk), MaskVerifyMode::Warn);
        assert!(v.accept);
        assert_eq!(v.detail, MaskVerifyDetail::Invalid);
    }

    #[test]
    fn phase_b_enforce_mode_rejects_bad_signature() {
        use ed25519_dalek::SigningKey;
        let pk = SigningKey::from_bytes(&[1u8; 32])
            .verifying_key()
            .to_bytes();

        // Unsigned legacy mask → rejected.
        let unsigned = generated_style_mask();
        let v = verify_mask_artifact(&unsigned, Some(&pk), MaskVerifyMode::Enforce);
        assert!(!v.accept);
        assert_eq!(v.detail, MaskVerifyDetail::Unsigned);

        // Wrong-key signature → rejected.
        let mut wrong = generated_style_mask();
        wrong.sign(&SigningKey::from_bytes(&[2u8; 32]));
        let v = verify_mask_artifact(&wrong, Some(&pk), MaskVerifyMode::Enforce);
        assert!(!v.accept);
        assert_eq!(v.detail, MaskVerifyDetail::Invalid);

        // Enforce with no operator key fails closed.
        let good = generated_style_mask();
        let v = verify_mask_artifact(&good, None, MaskVerifyMode::Enforce);
        assert!(!v.accept);
        assert_eq!(v.detail, MaskVerifyDetail::NoOperatorKey);
    }

    #[test]
    fn phase_b_off_mode_skips_verification() {
        use ed25519_dalek::SigningKey;
        let pk = SigningKey::from_bytes(&[1u8; 32])
            .verifying_key()
            .to_bytes();
        let unsigned = generated_style_mask();
        let v = verify_mask_artifact(&unsigned, Some(&pk), MaskVerifyMode::Off);
        assert!(v.accept);
        assert_eq!(v.detail, MaskVerifyDetail::ModeOff);
        assert!(
            !v.is_failure(),
            "off mode must not produce warn-worthy noise"
        );
    }

    #[test]
    fn phase_b_warn_without_key_is_silent_noop() {
        // Default deployment: warn mode, no operator key configured. Must
        // accept and must NOT be logged as a warn-level failure by callers
        // that gate on pubkey presence (both call sites check
        // `operator_pubkey.is_some()` before warning).
        let unsigned = generated_style_mask();
        let v = verify_mask_artifact(&unsigned, None, MaskVerifyMode::Warn);
        assert!(v.accept);
        assert_eq!(v.detail, MaskVerifyDetail::NoOperatorKey);
    }

    #[test]
    fn phase_b_verify_mode_parsing_and_default() {
        assert_eq!(MaskVerifyMode::default(), MaskVerifyMode::Warn);
        assert_eq!(
            "off".parse::<MaskVerifyMode>().unwrap(),
            MaskVerifyMode::Off
        );
        assert_eq!(
            "WARN".parse::<MaskVerifyMode>().unwrap(),
            MaskVerifyMode::Warn
        );
        assert_eq!(
            " enforce ".parse::<MaskVerifyMode>().unwrap(),
            MaskVerifyMode::Enforce
        );
        assert!("strict".parse::<MaskVerifyMode>().is_err());
    }

    #[test]
    fn phase_b_derived_variants_are_flagged() {
        let mut mask = generated_style_mask();
        assert!(!mask.is_derived_variant());
        mask.mask_id = "polymorphic:webrtc_zoom_v3:abcd".into();
        assert!(mask.is_derived_variant());
        mask.mask_id = "bootstrap:epoch-1:webrtc_zoom_v3:0:1234".into();
        assert!(mask.is_derived_variant());
    }

    #[test]
    fn gmm_hostile_mask_cannot_crash_client() {
        let mut rng = StdRng::seed_from_u64(4);

        // CRIT: a huge `k` must not integer-overflow the length guard and index
        // out of bounds. Try values that would wrap `1 + k*3`.
        for bad_k in [
            6.148914691236517e18_f64, // ~ 2^63 / ... wraps 3k
            f64::from(u32::MAX),
            1e300,
            65.0, // just over the 64 cap
        ] {
            let size = SizeDistribution {
                dist_type: SizeDistType::Parametric,
                bins: Vec::new(),
                parametric_type: Some(ParametricType::Gmm),
                parametric_params: Some(vec![bad_k, 1.0, 0.0, 1.0]),
            };
            for _ in 0..50 {
                let s = size.sample(&mut rng);
                assert!(s >= 1, "hostile size k={bad_k} produced invalid sample");
            }
        }

        // HIGH: a component with astronomically large mu/sigma must not yield an
        // IAT that panics Duration::from_secs_f64 downstream — it is clamped.
        let iat = IATDistribution {
            dist_type: IATDistType::Gmm,
            params: vec![1.0, 1.0, 1e300, 1e300],
            jitter_range_ms: (0.0, 0.0),
        };
        for _ in 0..200 {
            let v = iat.sample(&mut rng);
            assert!(v.is_finite() && (0.0..=MAX_BASE_IAT_MS).contains(&v));
            // Must be convertible to a Duration without panicking.
            let _ = std::time::Duration::from_secs_f64(v / 1000.0);
        }
    }
}

#[cfg(test)]
mod persisted_descriptor_tests {
    use super::{accept_persisted_descriptors, current_unix_secs, BootstrapDescriptor};

    fn valid_descriptor(id: &str, created: u64) -> BootstrapDescriptor {
        let now = current_unix_secs();
        BootstrapDescriptor {
            descriptor_id: id.to_string(),
            version: 1,
            created_at: created,
            expires_at: now + 3600,
            base_mask_ids: vec!["webrtc_zoom_v3".to_string()],
            embedded_masks: vec![],
            candidate_count: 1,
            kdf_salt: [7u8; 32],
            signature: [0u8; 64],
        }
    }

    #[test]
    fn parses_array_filters_expired_sorts_newest_first() {
        let now = current_unix_secs();
        let mut expired = valid_descriptor("old", now - 100);
        expired.expires_at = now - 10; // already expired
        let d1 = valid_descriptor("d1", now - 50);
        let d2 = valid_descriptor("d2", now - 5);
        let json = serde_json::to_string(&vec![expired, d1, d2]).unwrap();

        let accepted = accept_persisted_descriptors(&json, None);
        assert_eq!(accepted.len(), 2, "expired descriptor must be dropped");
        assert_eq!(accepted[0].descriptor_id, "d2", "newest first");
        assert_eq!(accepted[1].descriptor_id, "d1");
    }

    #[test]
    fn accepts_single_object_without_trusted_key() {
        let now = current_unix_secs();
        let json = serde_json::to_string(&valid_descriptor("solo", now - 1)).unwrap();
        let accepted = accept_persisted_descriptors(&json, None);
        assert_eq!(accepted.len(), 1);
    }

    #[test]
    fn rejects_unsigned_and_forged_when_trusted_key_present() {
        let now = current_unix_secs();
        let unsigned = valid_descriptor("unsigned", now - 1); // all-zero signature
        let mut forged = valid_descriptor("forged", now - 1);
        forged.signature = [9u8; 64]; // non-zero but bogus signature
        let json = serde_json::to_string(&vec![unsigned, forged]).unwrap();

        let key = [1u8; 32];
        let accepted = accept_persisted_descriptors(&json, Some(&key));
        assert!(
            accepted.is_empty(),
            "no descriptor verifies against the key"
        );
    }

    #[test]
    fn malformed_json_yields_empty() {
        assert!(accept_persisted_descriptors("not json", None).is_empty());
        assert!(accept_persisted_descriptors("", Some(&[0u8; 32])).is_empty());
    }
}
