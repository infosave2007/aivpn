use super::*;

/// Client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server_addr: String,
    pub server_public_key: [u8; X25519_PUBLIC_KEY_SIZE],
    /// Ed25519 signing public key for verifying ServerHello signatures and mask updates.
    /// When `Some`, the client rejects unsigned or incorrectly signed messages from
    /// the server, preventing MITM attacks.
    pub server_signing_key: Option<[u8; 32]>,
    pub preshared_key: Option<[u8; 32]>,
    pub initial_mask: MaskProfile,
    pub tun_config: TunnelConfig,
    /// When set, run as SOCKS5 proxy on this address instead of a TUN device.
    pub proxy_listen: Option<std::net::SocketAddr>,
    /// Optional 104-byte mTLS certificate sent to the server after session setup.
    /// Required when the server is configured with `mtls.required = true`.
    pub mtls_cert: Option<Vec<u8>>,
    /// Initial adaptive mode level from `--adaptive-level`/GUI selection. The
    /// quality tracker can still raise/lower this automatically afterward,
    /// but the user's explicit choice is honored as the starting point
    /// instead of always starting at `Off`.
    pub initial_adaptive_level: AdaptiveLevel,
    /// When set, request a polymorphic (per-session perturbed) variant of this
    /// base mask id from the server right after the handshake completes. The
    /// server responds with the usual `MaskUpdate` control message — no other
    /// client-side handling is needed.
    pub polymorphic_base: Option<String>,
    /// §2 crowdsourced blocking feedback — opt-in, OFF by default. When true
    /// (and `country_code` is set), the client batches mask success/fail
    /// outcomes in-memory and reports them to the server once per connection
    /// (see `maybe_send_mask_feedback`). No effect unless `country_code` is
    /// also `Some`.
    pub share_mask_feedback: bool,
    /// §2 crowdsourced blocking feedback — opt-in, OFF by default. When true,
    /// the client stores `RegionalMaskHints` pushed by the server (see
    /// `regional_mask_hints()`) for future mask-selection use.
    pub receive_mask_hints: bool,
    /// ISO-3166-1 alpha-2 country code the client believes it is in. Required
    /// for `share_mask_feedback` to have any effect — the server aggregates
    /// feedback per region and never receives one without the other.
    pub country_code: Option<[u8; 2]>,
    /// R2 Phase B: operator Ed25519 mask-verifying public key. Verifies the
    /// embedded `MaskProfile.signature` (artifact provenance: "this mask went
    /// through the operator's gates") of masks received via `MaskUpdate`.
    /// SEPARATE from `server_signing_key`, which authenticates the transport
    /// (the msgpack bytes as pushed by *this* server) — the two are
    /// defense-in-depth layers. Sourced from `--mask-operator-pubkey`, the
    /// config file, or the `mop` field of the aivpn:// connection key.
    pub mask_operator_pubkey: Option<[u8; 32]>,
    /// R2 Phase B: artifact verification mode for received masks:
    /// off | warn (default, log-and-accept) | enforce (reject). Derived
    /// per-session variants (`polymorphic:*`/`bootstrap:*`) are exempt — they
    /// are authenticated by the session channel and are not independently
    /// signature-verifiable.
    pub mask_verify_mode: aivpn_common::mask::MaskVerifyMode,
    /// 3b: shared handle to the process-wide native network-change listener
    /// (see `net_change.rs`), spawned ONCE in `main.rs` before the reconnect
    /// loop and threaded into every `ClientConfig`/`run()` call across
    /// reconnects. `None` when no platform listener is implemented, or the
    /// platform-specific registration failed — the client then relies solely
    /// on the existing poll-based watchdogs (unchanged behavior).
    pub network_change_notify: Option<Arc<tokio::sync::Notify>>,
    /// 3c: true when `main.rs` selected this run's `initial_mask` via the
    /// "3 consecutive handshakes never connected" resilience fallback
    /// (built-in default mask) rather than the normal bootstrap-derived
    /// selection. Threaded through so the stats-writer task can surface it
    /// to file-polling GUIs (Windows) via the `fallback:` key — mirrors how
    /// `ip:` was added for the same "GUI can't read child stdout" reason.
    pub is_bootstrap_fallback: bool,
    /// Headless "control-only" mode: no TUN device, no SOCKS proxy, no local
    /// admin IPC socket, no stats-file writer, and all `InnerType::Data`
    /// packets are dropped on receipt. Used when the aivpn SERVER embeds this
    /// client as a masked pool-peer dialer (completes the handshake and
    /// exchanges CONTROL payloads for DB anti-entropy with a peer node) rather
    /// than by an end-user device. `false` (default) reproduces the exact
    /// pre-existing behavior of every other call site.
    pub control_only: bool,
    /// When set (only meaningful with `control_only = true`), inbound
    /// `ControlPayload::PoolSync` / `PoolStateDigest` / `PoolBucketDigests` /
    /// `RouteSync` messages
    /// are cloned and forwarded to this channel instead of being silently
    /// ignored, so the embedding server can drive its own anti-entropy merge
    /// logic off of them. `None` (default) preserves the previous silent-drop
    /// behavior for these variants.
    pub inbound_control_tap: Option<tokio::sync::mpsc::Sender<ControlPayload>>,
    /// B2/D2 fix (session-bound `NodeEnrollment`, SEND side): this node's own
    /// durable Ed25519 pool-node identity, `Some` only for the embedded
    /// `control_only` pool-peer dialer (`aivpn-server`'s `pool_dialer.rs`)
    /// when `main.rs` resolved a `pool.node_identity_key`. `None` (the
    /// default, and always the value for every ordinary end-user client) is
    /// a complete no-op: no `NodeEnrollment` is ever built or sent. When
    /// `Some`, the `ServerHello` handler signs and sends a `NodeEnrollment`
    /// proof bound to THIS session's ephemeral transcript
    /// (`server_eph_pub`/`client_eph_pub`) right after the PFS ratchet
    /// completes — moved here (out of `pool_dialer.rs`) specifically because
    /// only this handler has that transcript available, and binding to it is
    /// what prevents a captured proof from being replayed onto a different
    /// masked pool-peer session (mirrors `DeviceEnrollment`'s `dh_proof`
    /// scheme just above in this same handler).
    pub node_identity: Option<ed25519_dalek::SigningKey>,
    /// This node's own pool `node_id` string, carried in the `NodeEnrollment`
    /// proof `node_identity` signs. Only meaningful alongside
    /// `node_identity: Some(..)`; `None` there is treated as an empty string
    /// (matching `pool_dialer.rs`'s pre-existing `unwrap_or_default()`
    /// handling for its own `RouteSync`/enrollment payloads).
    pub pool_node_id: Option<String>,
}

/// Client state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientState {
    Unprovisioned,
    Provisioned,
    Connecting,
    Connected,
    Reconnecting,
    Disconnected,
}
