//! AIVPN Wire Protocol
//!
//! Implements packet format, inner payload encoding, and control messages

use bytes::{BufMut, BytesMut};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::{POLY1305_TAG_SIZE, TAG_SIZE};
use crate::error::{Error, Result};
use crate::network_config::ClientNetworkConfig;

/// Maximum UDP packet size (optimized for VPN MTU 1420 + overhead)
pub const MAX_PACKET_SIZE: usize = 1500;

/// UDP receive-buffer size for the client downlink loop. Control packets — most
/// notably `MaskUpdate`, which carries a full serialized `MaskProfile` (several
/// KB) — are far larger than a DATA packet's `MAX_PACKET_SIZE` MTU. Receiving
/// them into a 1500-byte buffer TRUNCATED the datagram, so the AEAD tag never
/// authenticated and the client silently dropped every mask switch (it could
/// never adopt a server-pushed mask). Size the recv buffer for the largest
/// plausible control datagram instead.
pub const UDP_RECV_BUF_SIZE: usize = 65536;

/// Minimum header overhead (tag + pad_len + inner_header + poly1305)
pub const MIN_HEADER_OVERHEAD: usize = TAG_SIZE + 2 + 4 + POLY1305_TAG_SIZE;

/// Maximum payload size
pub const MAX_PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - MIN_HEADER_OVERHEAD;

/// Inner payload types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum InnerType {
    Data = 0x0001,
    Control = 0x0002,
    Fragment = 0x0003,
    Ack = 0x0004,
    /// FEC repair packet — XOR of N preceding data packets
    FecRepair = 0x0005,
}

impl InnerType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::Data),
            0x0002 => Some(Self::Control),
            0x0003 => Some(Self::Fragment),
            0x0004 => Some(Self::Ack),
            0x0005 => Some(Self::FecRepair),
            _ => None,
        }
    }
}

/// Control message subtypes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ControlSubtype {
    KeyRotate = 0x01,
    MaskUpdate = 0x02,
    Keepalive = 0x03,
    TelemetryRequest = 0x04,
    TelemetryResponse = 0x05,
    TimeSync = 0x06,
    Shutdown = 0x07,
    ControlAck = 0x08,
    ServerHello = 0x09,
    RecordingStart = 0x0A,
    RecordingAck = 0x0B,
    RecordingStop = 0x0C,
    RecordingComplete = 0x0D,
    RecordingFailed = 0x0E,
    RecordingStatusRequest = 0x0F,
    RecordingStatus = 0x10,
    BootstrapDescriptorUpdate = 0x11,
    PoolSync = 0x12,
    /// Site-to-site subnet advertisement (0x13)
    RouteSync = 0x13,
    /// Multi-hop forwarded data packet (0x14)
    ChainForward = 0x14,
    /// Client mTLS certificate presentation (0x15)
    ClientCert = 0x15,
    /// Server notification that a ClientCert was rejected (0x16)
    CertRejected = 0x16,
    /// Device enrollment — client proves static X25519 key ownership via DH (0x17)
    DeviceEnrollment = 0x17,
    /// Server echoes keepalive timestamp for RTT measurement (0x18)
    KeepaliveAck = 0x18,
    /// Quality metrics report (0x19)
    QualityReport = 0x19,
    /// Server hints client to change adaptive mode level (0x1A)
    AdaptiveHint = 0x1A,
    /// Client signals which base mask it wants a polymorphic variant of (0x1B)
    MaskPreference = 0x1B,
    /// Client reports aggregated per-mask success/fail outcomes for its region,
    /// privacy-preserving (k-anonymity gated server-side) — §2 crowdsourced blocking feedback (0x1C)
    MaskFeedback = 0x1C,
    /// Server pushes top-performing masks for the client's region, derived from
    /// k-anonymity-gated crowdsourced feedback (0x1D)
    RegionalMaskHints = 0x1D,
    /// Server pushes §2 feedback tuning parameters to an opted-in client (0x1E):
    /// how many consecutive failures warrant recording, and the minimum spacing
    /// between feedback sends. Lets operators tune reporting load without a
    /// client update.
    FeedbackConfig = 0x1E,
    /// Server pushes the catalog of masks the client may select, each tagged
    /// with an auto-generated flag so pickers can mark generated masks (0x1F)
    MaskCatalog = 0x1F,
    HandshakeReject = 0x20,
    /// Pool anti-entropy state-digest beacon — fixed 32-byte BLAKE3 digest (0x21)
    PoolStateDigest = 0x21,
    /// Pool anti-entropy Phase 2 bucketed (Merkle-lite) digest exchange —
    /// sent in reaction to a `PoolStateDigest` mismatch so only the
    /// differing buckets' records need to travel, not the whole DB (0x22)
    PoolBucketDigests = 0x22,
    /// Phase 4 per-node cryptographic identity proof — a pool node signs
    /// `(node_id, node_pub, time_window)` with its long-term Ed25519 identity
    /// key so a peer can bind/pin `node_id` to `node_pub` instead of trusting
    /// a self-asserted `node_id` string (0x23)
    NodeEnrollment = 0x23,
    /// Server → client, sent once per session (typically piggybacked after
    /// ratchet completion / on the Keepalive path): announces the connecting
    /// client's server-assigned role and a reserved feature-flag bitmask so
    /// the client UI can gate admin/viewer management affordances (0x24)
    Capabilities = 0x24,
    /// Client → server: an in-tunnel management API call (Phase A in-app
    /// admin). Proxies a curated REST-shaped request (method/path/body) into
    /// the server's `mgmt_service` layer, correlated by `req_id` (0x25)
    MgmtRequest = 0x25,
    /// Server → client: the response to a `MgmtRequest`, correlated by the
    /// same `req_id` (0x26)
    MgmtResponse = 0x26,
}

impl ControlSubtype {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::KeyRotate),
            0x02 => Some(Self::MaskUpdate),
            0x03 => Some(Self::Keepalive),
            0x04 => Some(Self::TelemetryRequest),
            0x05 => Some(Self::TelemetryResponse),
            0x06 => Some(Self::TimeSync),
            0x07 => Some(Self::Shutdown),
            0x08 => Some(Self::ControlAck),
            0x09 => Some(Self::ServerHello),
            0x0A => Some(Self::RecordingStart),
            0x0B => Some(Self::RecordingAck),
            0x0C => Some(Self::RecordingStop),
            0x0D => Some(Self::RecordingComplete),
            0x0E => Some(Self::RecordingFailed),
            0x0F => Some(Self::RecordingStatusRequest),
            0x10 => Some(Self::RecordingStatus),
            0x11 => Some(Self::BootstrapDescriptorUpdate),
            0x12 => Some(Self::PoolSync),
            0x13 => Some(Self::RouteSync),
            0x14 => Some(Self::ChainForward),
            0x15 => Some(Self::ClientCert),
            0x16 => Some(Self::CertRejected),
            0x17 => Some(Self::DeviceEnrollment),
            0x18 => Some(Self::KeepaliveAck),
            0x19 => Some(Self::QualityReport),
            0x1A => Some(Self::AdaptiveHint),
            0x1B => Some(Self::MaskPreference),
            0x1C => Some(Self::MaskFeedback),
            0x1D => Some(Self::RegionalMaskHints),
            0x1E => Some(Self::FeedbackConfig),
            0x1F => Some(Self::MaskCatalog),
            0x20 => Some(Self::HandshakeReject),
            0x21 => Some(Self::PoolStateDigest),
            0x22 => Some(Self::PoolBucketDigests),
            0x23 => Some(Self::NodeEnrollment),
            0x24 => Some(Self::Capabilities),
            0x25 => Some(Self::MgmtRequest),
            0x26 => Some(Self::MgmtResponse),
            _ => None,
        }
    }
}

/// Inner payload header (after decryption)
#[derive(Debug, Clone)]
pub struct InnerHeader {
    pub inner_type: InnerType,
    pub seq_num: u16,
}

impl InnerHeader {
    pub fn encode(&self) -> [u8; 4] {
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&(self.inner_type as u16).to_le_bytes());
        buf[2..4].copy_from_slice(&self.seq_num.to_le_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::InvalidPacket("Inner header too short"));
        }
        let inner_type = InnerType::from_u16(u16::from_le_bytes([data[0], data[1]]))
            .ok_or(Error::InvalidPacket("Unknown inner type"))?;
        let seq_num = u16::from_le_bytes([data[2], data[3]]);
        Ok(Self {
            inner_type,
            seq_num,
        })
    }
}

/// AIVPN Packet structure
#[derive(Debug, Clone)]
pub struct AivpnPacket {
    pub resonance_tag: [u8; TAG_SIZE],
    pub mask_dependent_header: Vec<u8>,
    pub pad_len: u16,
    pub encrypted_payload: Vec<u8>,
    pub random_padding: Vec<u8>,
}

impl AivpnPacket {
    pub fn new(
        resonance_tag: [u8; TAG_SIZE],
        mask_dependent_header: Vec<u8>,
        encrypted_payload: Vec<u8>,
        padding_len: u16,
    ) -> Self {
        Self {
            resonance_tag,
            mask_dependent_header,
            pad_len: padding_len,
            encrypted_payload,
            random_padding: {
                let mut pad = vec![0u8; padding_len as usize];
                rand::thread_rng().fill_bytes(&mut pad);
                pad
            },
        }
    }

    /// Serialize packet to bytes
    pub fn to_bytes(&self) -> BytesMut {
        let total_len = TAG_SIZE
            + self.mask_dependent_header.len()
            + 2 // pad_len
            + self.encrypted_payload.len()
            + self.random_padding.len();

        let mut buf = BytesMut::with_capacity(total_len);
        buf.put_slice(&self.resonance_tag);
        buf.put_slice(&self.mask_dependent_header);
        buf.put_u16_le(self.pad_len);
        buf.put_slice(&self.encrypted_payload);
        buf.put_slice(&self.random_padding);
        buf
    }

    /// Deserialize packet from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < TAG_SIZE + 2 {
            return Err(Error::InvalidPacket("Packet too short"));
        }

        let mut cursor = 0;

        // Resonance tag
        let mut resonance_tag = [0u8; TAG_SIZE];
        resonance_tag.copy_from_slice(&data[cursor..cursor + TAG_SIZE]);
        cursor += TAG_SIZE;

        // We need to know the mask-dependent header length to parse correctly
        // This is determined by the active Mask profile
        // For now, we'll parse it in the server/client with mask context
        // Return raw data for upper layers to parse
        let _remaining = &data[cursor..];

        Ok(Self {
            resonance_tag,
            mask_dependent_header: Vec::new(),
            pad_len: 0,
            encrypted_payload: Vec::new(),
            random_padding: Vec::new(),
        })
    }

    /// Parse with mask context (knowing MDH length)
    pub fn from_bytes_with_mdh_len(data: &[u8], mdh_len: usize) -> Result<Self> {
        if data.len() < TAG_SIZE + mdh_len + 2 {
            return Err(Error::InvalidPacket("Packet too short"));
        }

        let mut cursor = 0;

        // Resonance tag
        let mut resonance_tag = [0u8; TAG_SIZE];
        resonance_tag.copy_from_slice(&data[cursor..cursor + TAG_SIZE]);
        cursor += TAG_SIZE;

        // Mask-dependent header
        let mask_dependent_header = data[cursor..cursor + mdh_len].to_vec();
        cursor += mdh_len;

        // Pad length
        let pad_len = u16::from_le_bytes([data[cursor], data[cursor + 1]]);
        cursor += 2;

        // Encrypted payload (everything except padding)
        let remaining = data.len().saturating_sub(cursor);
        if pad_len as usize > remaining {
            return Err(Error::InvalidPacket("pad_len exceeds packet bounds"));
        }
        let payload_len = remaining - pad_len as usize;
        let encrypted_payload = data[cursor..cursor + payload_len].to_vec();
        cursor += payload_len;

        // Random padding
        let random_padding = data[cursor..].to_vec();

        Ok(Self {
            resonance_tag,
            mask_dependent_header,
            pad_len,
            encrypted_payload,
            random_padding,
        })
    }
}

/// Control message payload
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ControlPayload {
    KeyRotate {
        new_eph_pub: [u8; 32],
    },
    MaskUpdate {
        mask_data: Vec<u8>,
        #[serde(with = "serde_bytes")]
        signature: [u8; 64],
    },
    Keepalive {
        send_ts: u64,
    },
    TelemetryRequest {
        metric_flags: u8,
    },
    TelemetryResponse {
        packet_loss: u16,
        rtt_ms: u16,
        jitter_ms: u16,
        buffer_pct: u8,
    },
    TimeSync {
        server_ts_ms: u64,
    },
    Shutdown {
        reason: u8,
    },
    /// Handshake-time authenticated reject. Sent ONLY to a peer that has
    /// already proven knowledge of the PSK during the handshake (so probers
    /// without the PSK still get silence — unobservability preserved). Tells
    /// the client WHY it was refused so it can show a message and STOP the
    /// reconnect loop instead of hammering forever. `reason`: 1=one-time key
    /// already used, 2=expired, 3=disabled, 0=unspecified.
    HandshakeReject {
        reason: u8,
    },
    ControlAck {
        ack_seq: u16,
        ack_for_subtype: u8,
    },
    ServerHello {
        server_eph_pub: [u8; 32],
        #[serde(with = "serde_bytes")]
        signature: [u8; 64],
        network_config: Option<ClientNetworkConfig>,
    },
    /// Admin requests recording start for a service
    RecordingStart {
        service: String,
    },
    /// Server acknowledges recording start
    RecordingAck {
        session_id: [u8; 16],
        status: String,
    },
    /// Admin requests recording stop
    RecordingStop {
        session_id: [u8; 16],
    },
    /// Server reports mask generation complete
    RecordingComplete {
        service: String,
        mask_id: String,
        confidence: f32,
    },
    /// Server reports recording/generation failure
    RecordingFailed {
        reason: String,
    },
    /// Client asks whether the current authenticated session may record masks.
    RecordingStatusRequest,
    /// Server reports recording capability and current active recording state.
    RecordingStatus {
        can_record: bool,
        active_service: Option<String>,
    },
    BootstrapDescriptorUpdate {
        descriptor_data: Vec<u8>,
    },
    /// Carries a full clients.json snapshot for pool-node synchronization.
    PoolSync {
        clients_json: Vec<u8>,
    },
    /// Pool anti-entropy beacon: BLAKE3 digest of the sender's canonical
    /// merged client-DB state. Peers compare digests and only exchange a full
    /// PoolSync snapshot when they differ. Fixed 32-byte body.
    PoolStateDigest {
        digest: [u8; 32],
    },
    /// Phase 2 bucketed (Merkle-lite) digest delta: `ClientDatabase::bucket_digests()`
    /// output, `POOL_SYNC_BUCKETS * 8` bytes (8 bytes per bucket). Sent in
    /// reaction to a `PoolStateDigest` mismatch; the receiver diffs it
    /// against its own `bucket_digests()` and replies with a `PoolSync`
    /// containing only the records in the differing buckets.
    ///
    /// `reply_requested` completes the reverse direction of a bucket
    /// exchange over a single (possibly one-way-dialed) session: when set,
    /// the receiver — after sending its own differing-bucket `PoolSync` —
    /// also sends back its own `bucket_digests()` with `reply_requested:
    /// false`, so the original sender can compute ITS differing buckets and
    /// push them too. `reply_requested: false` never triggers another bucket
    /// message, which bounds the exchange and prevents a digest/bucket
    /// ping-pong.
    PoolBucketDigests {
        digests: Vec<u8>,
        reply_requested: bool,
    },
    /// Phase 4 per-node cryptographic identity proof. A pool node proves
    /// ownership of its `node_id` by signing `(node_id, node_pub,
    /// time_window)` — via `aivpn_common::crypto::node_enrollment_signing_bytes`
    /// — with its long-term Ed25519 identity key
    /// (`aivpn_common::crypto::node_identity_from_seed`). The receiver
    /// verifies with `aivpn_common::crypto::verify_node_enrollment` and, on
    /// success, binds/pins `node_id` → `node_pub` (Phase 4 TOFU / operator
    /// manual approval — the binding policy itself is out of scope here).
    /// This message only PROVES identity ownership; it carries no other pool
    /// state.
    NodeEnrollment {
        node_id: String,
        node_pub: [u8; 32],
        time_window: u64,
        #[serde(with = "serde_bytes")]
        signature: [u8; 64],
    },
    /// Site-to-site subnet advertisement — JSON array of CIDR strings.
    RouteSync {
        subnets_json: Vec<u8>,
    },
    /// Multi-hop chain-forward — raw inner IP payload to NAT-forward at exit node.
    ChainForward {
        payload: Vec<u8>,
    },
    /// Client mTLS certificate — 104-byte SimpleCert sent after session setup.
    ClientCert {
        cert_bytes: Vec<u8>,
    },
    /// Server rejection of a ClientCert — client should re-provision its certificate.
    CertRejected {},
    /// Device enrollment — client proves ownership of its static X25519 keypair.
    /// Sent by client after ServerHello using ratcheted session keys.
    ///
    /// `dh_proof` = `device_enrollment_proof(dh_shared, server_eph_pub, client_eph_pub)`
    /// (see `aivpn_common::crypto::device_enrollment_proof`), where
    /// `dh_shared = X25519(static_priv, server_static_pub)` proves private-key
    /// possession, and `server_eph_pub || client_eph_pub` (THIS FIXED ORDER on
    /// both ends) is the ephemeral pair this session's PFS handshake used —
    /// binding the proof to the session so a captured `dh_proof` cannot be
    /// replayed into a different session. The server verifies ONLY this
    /// transcript-bound value — see `verify_device_enrollment_proof` in
    /// `aivpn-server/src/gateway.rs`.
    DeviceEnrollment {
        static_pub: [u8; 32],
        dh_proof: [u8; 32],
    },
    /// Server echoes client's keepalive timestamp for RTT measurement.
    KeepaliveAck {
        /// Echo of the timestamp sent by client in the keepalive
        echo_ts: u64,
    },
    /// Quality metrics report sent by client or server.
    QualityReport {
        /// 0–100 composite quality score
        quality: u8,
        /// Round-trip time (EWMA) in milliseconds
        rtt_ms: u16,
        /// Packet loss in parts-per-million
        loss_ppm: u32,
        /// Jitter (EWMA) in milliseconds
        jitter_ms: u16,
    },
    /// Server instructs client to switch adaptive mode level.
    AdaptiveHint {
        /// 0=Off, 1=Light, 2=Aggressive, 3=Satellite
        level: u8,
    },
    /// Client asks the server to derive and push a per-session polymorphic
    /// variant of the named base mask (§3 Polymorphic masks).
    MaskPreference {
        /// Preset mask id to use as the polymorphic base (e.g. "webrtc_zoom_v3")
        base_mask_id: String,
    },
    /// Client → server: aggregated per-mask success/fail counters for the
    /// client's region, batched client-side (§2 crowdsourced blocking feedback).
    /// Opt-in only; carries no raw identity — the server derives a hashed
    /// reporter token from the authenticated session for k-anonymity counting.
    MaskFeedback {
        /// Capped at 64 entries on encode.
        entries: Vec<MaskOutcome>,
        /// ISO-3166-1 alpha-2 country code the client believes it is in.
        country_code: [u8; 2],
    },
    /// Server → client: top masks for the client's region by recent success
    /// rate, only ever computed from k-anonymity-gated aggregates (§2).
    RegionalMaskHints {
        country_code: [u8; 2],
        /// (mask_id, success_rate 0.0..=1.0), capped at 32 entries on encode.
        masks: Vec<(String, f32)>,
    },
    /// Server → client: §2 feedback tuning, pushed to an opted-in client
    /// (i.e. one that already sent a `MaskFeedback`). Sourced from the server's
    /// optional `"feedback"` config block.
    FeedbackConfig {
        /// Minimum consecutive failed connection attempts with the same mask
        /// family before the client records a failure outcome (noise gate).
        report_failure_threshold: u8,
        /// Minimum spacing, in seconds, between successive feedback sends.
        report_interval_secs: u32,
    },
    /// Server → client: the catalog of masks this client may select. Pushed on
    /// connect and whenever the server's mask store changes, so client pickers
    /// render a live list instead of a hardcoded preset. Each entry is
    /// `(mask_id, label, generated)`; `generated` is true for masks the server
    /// auto-built from a recording (mask_gen), letting the UI mark them
    /// "(авто)". Capped at 64 entries on encode.
    MaskCatalog {
        masks: Vec<(String, String, bool)>,
    },
    /// Server → client, sent once per session: the connecting client's
    /// server-assigned role (see `aivpn_server::client_db::ClientRole::rank`
    /// — 0=User, 1=Viewer, 2=Admin) and a reserved feature-flag bitmask
    /// (currently unused, always 0) for future capability negotiation.
    Capabilities {
        role: u8,
        features: u32,
    },
    /// Client → server: an in-tunnel management API call (Phase A in-app
    /// admin). `method`: 0=GET, 1=POST, 2=PATCH, 3=DELETE, 4=PUT. `path` is
    /// a curated REST-shaped path (e.g. "/api/v1/clients"), capped at 512
    /// bytes on encode. `body` is an optional JSON payload, capped at
    /// 262144 bytes (256 KiB) on encode. `req_id` correlates the eventual
    /// `MgmtResponse`.
    MgmtRequest {
        req_id: u32,
        method: u8,
        path: String,
        body: Vec<u8>,
    },
    /// Server → client: the response to a `MgmtRequest`, correlated by the
    /// same `req_id`. `status` mirrors an HTTP status code (200, 403, 404,
    /// 429, ...). `body` is capped at 262144 bytes (256 KiB) on encode.
    MgmtResponse {
        req_id: u32,
        status: u16,
        body: Vec<u8>,
    },
}

/// Aggregated success/fail outcome counters for a single mask, as reported by
/// a client in a `MaskFeedback` message. Carries no reporter identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MaskOutcome {
    pub mask_id: String,
    pub success: u16,
    pub fail: u16,
}

impl ControlPayload {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        match self {
            Self::KeyRotate { new_eph_pub } => {
                buf.push(ControlSubtype::KeyRotate as u8);
                buf.push(0); // reserved
                buf.extend_from_slice(&(new_eph_pub.len() as u16).to_le_bytes());
                buf.extend_from_slice(new_eph_pub);
            }
            Self::MaskUpdate {
                mask_data,
                signature,
            } => {
                buf.push(ControlSubtype::MaskUpdate as u8);
                buf.extend_from_slice(&(mask_data.len() as u16).to_le_bytes());
                buf.extend_from_slice(mask_data);
                buf.extend_from_slice(signature);
            }
            Self::Keepalive { send_ts } => {
                buf.push(ControlSubtype::Keepalive as u8);
                buf.extend_from_slice(&send_ts.to_le_bytes());
            }
            Self::TelemetryRequest { metric_flags } => {
                buf.push(ControlSubtype::TelemetryRequest as u8);
                buf.push(*metric_flags);
            }
            Self::TelemetryResponse {
                packet_loss,
                rtt_ms,
                jitter_ms,
                buffer_pct,
            } => {
                buf.push(ControlSubtype::TelemetryResponse as u8);
                buf.push(0); // flags
                buf.extend_from_slice(&packet_loss.to_le_bytes());
                buf.extend_from_slice(&rtt_ms.to_le_bytes());
                buf.extend_from_slice(&jitter_ms.to_le_bytes());
                buf.push(*buffer_pct);
                buf.extend_from_slice(&[0u8; 3]); // reserved
            }
            Self::TimeSync { server_ts_ms } => {
                buf.push(ControlSubtype::TimeSync as u8);
                buf.extend_from_slice(&server_ts_ms.to_le_bytes());
            }
            Self::Shutdown { reason } => {
                buf.push(ControlSubtype::Shutdown as u8);
                buf.push(*reason);
            }
            Self::HandshakeReject { reason } => {
                buf.push(ControlSubtype::HandshakeReject as u8);
                buf.push(*reason);
            }
            Self::PoolStateDigest { digest } => {
                buf.push(ControlSubtype::PoolStateDigest as u8);
                buf.extend_from_slice(digest);
            }
            Self::PoolBucketDigests {
                digests,
                reply_requested,
            } => {
                buf.push(ControlSubtype::PoolBucketDigests as u8);
                buf.extend_from_slice(&((1 + digests.len()) as u32).to_le_bytes());
                buf.push(*reply_requested as u8);
                buf.extend_from_slice(digests);
            }
            Self::NodeEnrollment {
                node_id,
                node_pub,
                time_window,
                signature,
            } => {
                buf.push(ControlSubtype::NodeEnrollment as u8);
                let node_id_bytes = node_id.as_bytes();
                let total_len = (4 + node_id_bytes.len() + 32 + 8 + 64) as u32;
                buf.extend_from_slice(&total_len.to_le_bytes());
                buf.extend_from_slice(&(node_id_bytes.len() as u32).to_le_bytes());
                buf.extend_from_slice(node_id_bytes);
                buf.extend_from_slice(node_pub);
                buf.extend_from_slice(&time_window.to_le_bytes());
                buf.extend_from_slice(signature);
            }
            Self::ControlAck {
                ack_seq,
                ack_for_subtype,
            } => {
                buf.push(ControlSubtype::ControlAck as u8);
                buf.extend_from_slice(&ack_seq.to_le_bytes());
                buf.push(*ack_for_subtype);
            }
            Self::ServerHello {
                server_eph_pub,
                signature,
                network_config,
            } => {
                buf.push(ControlSubtype::ServerHello as u8);
                buf.extend_from_slice(server_eph_pub);
                buf.extend_from_slice(signature);
                if let Some(network_config) = network_config {
                    buf.extend_from_slice(&network_config.encode_wire());
                }
            }
            Self::RecordingStart { service } => {
                buf.push(ControlSubtype::RecordingStart as u8);
                let service_bytes = service.as_bytes();
                buf.extend_from_slice(&(service_bytes.len() as u16).to_le_bytes());
                buf.extend_from_slice(service_bytes);
            }
            Self::RecordingAck { session_id, status } => {
                buf.push(ControlSubtype::RecordingAck as u8);
                buf.extend_from_slice(session_id);
                let status_bytes = status.as_bytes();
                buf.extend_from_slice(&(status_bytes.len() as u16).to_le_bytes());
                buf.extend_from_slice(status_bytes);
            }
            Self::RecordingStop { session_id } => {
                buf.push(ControlSubtype::RecordingStop as u8);
                buf.extend_from_slice(session_id);
            }
            Self::RecordingComplete {
                service,
                mask_id,
                confidence,
            } => {
                buf.push(ControlSubtype::RecordingComplete as u8);
                let service_bytes = service.as_bytes();
                buf.extend_from_slice(&(service_bytes.len() as u16).to_le_bytes());
                buf.extend_from_slice(service_bytes);
                let mask_id_bytes = mask_id.as_bytes();
                buf.extend_from_slice(&(mask_id_bytes.len() as u16).to_le_bytes());
                buf.extend_from_slice(mask_id_bytes);
                buf.extend_from_slice(&confidence.to_le_bytes());
            }
            Self::RecordingFailed { reason } => {
                buf.push(ControlSubtype::RecordingFailed as u8);
                let reason_bytes = reason.as_bytes();
                buf.extend_from_slice(&(reason_bytes.len() as u16).to_le_bytes());
                buf.extend_from_slice(reason_bytes);
            }
            Self::RecordingStatusRequest => {
                buf.push(ControlSubtype::RecordingStatusRequest as u8);
            }
            Self::RecordingStatus {
                can_record,
                active_service,
            } => {
                buf.push(ControlSubtype::RecordingStatus as u8);
                let mut flags = 0u8;
                if *can_record {
                    flags |= 0x01;
                }
                if active_service.is_some() {
                    flags |= 0x02;
                }
                buf.push(flags);
                if let Some(service) = active_service {
                    let service_bytes = service.as_bytes();
                    buf.extend_from_slice(&(service_bytes.len() as u16).to_le_bytes());
                    buf.extend_from_slice(service_bytes);
                }
            }
            Self::BootstrapDescriptorUpdate { descriptor_data } => {
                buf.push(ControlSubtype::BootstrapDescriptorUpdate as u8);
                buf.extend_from_slice(&(descriptor_data.len() as u16).to_le_bytes());
                buf.extend_from_slice(descriptor_data);
            }
            Self::PoolSync { clients_json } => {
                buf.push(ControlSubtype::PoolSync as u8);
                buf.extend_from_slice(&(clients_json.len() as u32).to_le_bytes());
                buf.extend_from_slice(clients_json);
            }
            Self::RouteSync { subnets_json } => {
                buf.push(ControlSubtype::RouteSync as u8);
                buf.extend_from_slice(&(subnets_json.len() as u32).to_le_bytes());
                buf.extend_from_slice(subnets_json);
            }
            Self::ChainForward { payload } => {
                buf.push(ControlSubtype::ChainForward as u8);
                buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                buf.extend_from_slice(payload);
            }
            Self::ClientCert { cert_bytes } => {
                buf.push(ControlSubtype::ClientCert as u8);
                buf.extend_from_slice(&(cert_bytes.len() as u32).to_le_bytes());
                buf.extend_from_slice(cert_bytes);
            }
            Self::CertRejected {} => {
                buf.push(ControlSubtype::CertRejected as u8);
            }
            Self::DeviceEnrollment {
                static_pub,
                dh_proof,
            } => {
                buf.push(ControlSubtype::DeviceEnrollment as u8);
                buf.extend_from_slice(static_pub);
                buf.extend_from_slice(dh_proof);
            }
            Self::KeepaliveAck { echo_ts } => {
                buf.push(ControlSubtype::KeepaliveAck as u8);
                buf.extend_from_slice(&echo_ts.to_le_bytes());
            }
            Self::QualityReport {
                quality,
                rtt_ms,
                loss_ppm,
                jitter_ms,
            } => {
                buf.push(ControlSubtype::QualityReport as u8);
                buf.push(*quality);
                buf.extend_from_slice(&rtt_ms.to_le_bytes());
                buf.extend_from_slice(&loss_ppm.to_le_bytes());
                buf.extend_from_slice(&jitter_ms.to_le_bytes());
            }
            Self::AdaptiveHint { level } => {
                buf.push(ControlSubtype::AdaptiveHint as u8);
                buf.push(*level);
            }
            Self::MaskPreference { base_mask_id } => {
                buf.push(ControlSubtype::MaskPreference as u8);
                let id_bytes = base_mask_id.as_bytes();
                buf.extend_from_slice(&(id_bytes.len() as u16).to_le_bytes());
                buf.extend_from_slice(id_bytes);
            }
            Self::MaskFeedback {
                entries,
                country_code,
            } => {
                buf.push(ControlSubtype::MaskFeedback as u8);
                let count = entries.len().min(64);
                buf.push(count as u8);
                for entry in entries.iter().take(count) {
                    let id_bytes = entry.mask_id.as_bytes();
                    buf.extend_from_slice(&(id_bytes.len() as u16).to_le_bytes());
                    buf.extend_from_slice(id_bytes);
                    buf.extend_from_slice(&entry.success.to_le_bytes());
                    buf.extend_from_slice(&entry.fail.to_le_bytes());
                }
                buf.extend_from_slice(country_code);
            }
            Self::RegionalMaskHints {
                country_code,
                masks,
            } => {
                buf.push(ControlSubtype::RegionalMaskHints as u8);
                buf.extend_from_slice(country_code);
                let count = masks.len().min(32);
                buf.push(count as u8);
                for (mask_id, score) in masks.iter().take(count) {
                    let id_bytes = mask_id.as_bytes();
                    buf.extend_from_slice(&(id_bytes.len() as u16).to_le_bytes());
                    buf.extend_from_slice(id_bytes);
                    buf.extend_from_slice(&score.to_le_bytes());
                }
            }
            Self::FeedbackConfig {
                report_failure_threshold,
                report_interval_secs,
            } => {
                buf.push(ControlSubtype::FeedbackConfig as u8);
                buf.push(*report_failure_threshold);
                buf.extend_from_slice(&report_interval_secs.to_le_bytes());
            }
            Self::MaskCatalog { masks } => {
                buf.push(ControlSubtype::MaskCatalog as u8);
                let count = masks.len().min(64);
                buf.push(count as u8);
                for (mask_id, label, generated) in masks.iter().take(count) {
                    let id_bytes = mask_id.as_bytes();
                    buf.extend_from_slice(&(id_bytes.len() as u16).to_le_bytes());
                    buf.extend_from_slice(id_bytes);
                    let label_bytes = label.as_bytes();
                    buf.extend_from_slice(&(label_bytes.len() as u16).to_le_bytes());
                    buf.extend_from_slice(label_bytes);
                    buf.push(if *generated { 1 } else { 0 });
                }
            }
            Self::Capabilities { role, features } => {
                buf.push(ControlSubtype::Capabilities as u8);
                buf.push(*role);
                buf.extend_from_slice(&features.to_le_bytes());
            }
            Self::MgmtRequest {
                req_id,
                method,
                path,
                body,
            } => {
                let path_bytes = path.as_bytes();
                if path_bytes.len() > 512 {
                    return Err(Error::InvalidPacket("MgmtRequest path too long"));
                }
                if body.len() > 262_144 {
                    return Err(Error::InvalidPacket("MgmtRequest body too long"));
                }
                buf.push(ControlSubtype::MgmtRequest as u8);
                buf.extend_from_slice(&req_id.to_le_bytes());
                buf.push(*method);
                buf.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
                buf.extend_from_slice(path_bytes);
                buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
                buf.extend_from_slice(body);
            }
            Self::MgmtResponse {
                req_id,
                status,
                body,
            } => {
                if body.len() > 262_144 {
                    return Err(Error::InvalidPacket("MgmtResponse body too long"));
                }
                buf.push(ControlSubtype::MgmtResponse as u8);
                buf.extend_from_slice(&req_id.to_le_bytes());
                buf.extend_from_slice(&status.to_le_bytes());
                buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
                buf.extend_from_slice(body);
            }
        }

        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::InvalidPacket("Empty control payload"));
        }

        let subtype = ControlSubtype::from_u8(data[0])
            .ok_or(Error::InvalidPacket("Unknown control subtype"))?;

        match subtype {
            ControlSubtype::KeyRotate => {
                if data.len() < 6 {
                    return Err(Error::InvalidPacket("KeyRotate too short"));
                }
                let new_eph_pub_len = u16::from_le_bytes([data[2], data[3]]) as usize;
                if new_eph_pub_len != 32 {
                    return Err(Error::InvalidPacket(
                        "KeyRotate: invalid eph pub key length",
                    ));
                }
                if data.len() < 4 + new_eph_pub_len {
                    return Err(Error::InvalidPacket("KeyRotate invalid length"));
                }
                let mut new_eph_pub = [0u8; 32];
                new_eph_pub.copy_from_slice(&data[4..4 + 32]);
                Ok(Self::KeyRotate { new_eph_pub })
            }
            ControlSubtype::MaskUpdate => {
                if data.len() < 4 {
                    return Err(Error::InvalidPacket("MaskUpdate too short"));
                }
                let mask_len = u16::from_le_bytes([data[1], data[2]]) as usize;
                if data.len() < 3 + mask_len + 64 {
                    return Err(Error::InvalidPacket("MaskUpdate invalid length"));
                }
                let mask_data = data[3..3 + mask_len].to_vec();
                let mut signature = [0u8; 64];
                signature.copy_from_slice(&data[3 + mask_len..3 + mask_len + 64]);
                Ok(Self::MaskUpdate {
                    mask_data,
                    signature,
                })
            }
            ControlSubtype::Keepalive => {
                let send_ts = if data.len() >= 9 {
                    u64::from_le_bytes(data[1..9].try_into().unwrap())
                } else {
                    0
                };
                Ok(Self::Keepalive { send_ts })
            }
            ControlSubtype::TelemetryRequest => {
                if data.len() < 2 {
                    return Err(Error::InvalidPacket("TelemetryRequest too short"));
                }
                Ok(Self::TelemetryRequest {
                    metric_flags: data[1],
                })
            }
            ControlSubtype::TelemetryResponse => {
                if data.len() < 12 {
                    return Err(Error::InvalidPacket("TelemetryResponse too short"));
                }
                Ok(Self::TelemetryResponse {
                    packet_loss: u16::from_le_bytes([data[2], data[3]]),
                    rtt_ms: u16::from_le_bytes([data[4], data[5]]),
                    jitter_ms: u16::from_le_bytes([data[6], data[7]]),
                    buffer_pct: data[8],
                })
            }
            ControlSubtype::TimeSync => {
                if data.len() < 9 {
                    return Err(Error::InvalidPacket("TimeSync too short"));
                }
                Ok(Self::TimeSync {
                    server_ts_ms: u64::from_le_bytes(data[1..9].try_into().unwrap()),
                })
            }
            ControlSubtype::Shutdown => {
                if data.len() < 2 {
                    return Err(Error::InvalidPacket("Shutdown too short"));
                }
                Ok(Self::Shutdown { reason: data[1] })
            }
            ControlSubtype::HandshakeReject => {
                if data.len() < 2 {
                    return Err(Error::InvalidPacket("HandshakeReject too short"));
                }
                Ok(Self::HandshakeReject { reason: data[1] })
            }
            ControlSubtype::PoolStateDigest => {
                if data.len() < 1 + 32 {
                    return Err(Error::InvalidPacket("PoolStateDigest too short"));
                }
                let mut digest = [0u8; 32];
                digest.copy_from_slice(&data[1..1 + 32]);
                Ok(Self::PoolStateDigest { digest })
            }
            ControlSubtype::PoolBucketDigests => {
                if data.len() < 6 {
                    return Err(Error::InvalidPacket("PoolBucketDigests too short"));
                }
                let payload_len = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
                if payload_len < 1 {
                    return Err(Error::InvalidPacket("PoolBucketDigests invalid length"));
                }
                // Overflow-safe on 32-bit targets, same reasoning as PoolSync.
                if data.len().saturating_sub(5) < payload_len {
                    return Err(Error::InvalidPacket("PoolBucketDigests invalid length"));
                }
                let reply_requested = data[5] != 0;
                let digests_len = payload_len - 1;
                Ok(Self::PoolBucketDigests {
                    digests: data[6..6 + digests_len].to_vec(),
                    reply_requested,
                })
            }
            ControlSubtype::NodeEnrollment => {
                // subtype(1) + total_len(4) + node_id_len(4) = 9 minimum to
                // read both length fields.
                if data.len() < 9 {
                    return Err(Error::InvalidPacket("NodeEnrollment too short"));
                }
                let total_len = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
                // Overflow-safe on 32-bit targets, same reasoning as PoolSync.
                if data.len().saturating_sub(5) < total_len {
                    return Err(Error::InvalidPacket("NodeEnrollment invalid length"));
                }
                // total_len must at least cover node_id_len(4) + node_pub(32)
                // + time_window(8) + signature(64), even for an empty node_id.
                if total_len < 4 + 32 + 8 + 64 {
                    return Err(Error::InvalidPacket("NodeEnrollment invalid length"));
                }
                let node_id_len = u32::from_le_bytes([data[5], data[6], data[7], data[8]]) as usize;
                // The declared total_len must exactly account for
                // node_id_len + node_pub + time_window + signature — this
                // rejects an inconsistent (attacker-crafted) pair of length
                // fields instead of silently misreading the trailing bytes.
                if total_len != 4 + node_id_len + 32 + 8 + 64 {
                    return Err(Error::InvalidPacket("NodeEnrollment length mismatch"));
                }

                let mut offset = 9usize;
                if data.len() < offset + node_id_len {
                    return Err(Error::InvalidPacket("NodeEnrollment node_id truncated"));
                }
                let node_id =
                    String::from_utf8_lossy(&data[offset..offset + node_id_len]).to_string();
                offset += node_id_len;

                if data.len() < offset + 32 + 8 + 64 {
                    return Err(Error::InvalidPacket("NodeEnrollment truncated"));
                }
                let mut node_pub = [0u8; 32];
                node_pub.copy_from_slice(&data[offset..offset + 32]);
                offset += 32;

                let time_window = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
                offset += 8;

                let mut signature = [0u8; 64];
                signature.copy_from_slice(&data[offset..offset + 64]);

                Ok(Self::NodeEnrollment {
                    node_id,
                    node_pub,
                    time_window,
                    signature,
                })
            }
            ControlSubtype::ControlAck => {
                if data.len() < 4 {
                    return Err(Error::InvalidPacket("ControlAck too short"));
                }
                Ok(Self::ControlAck {
                    ack_seq: u16::from_le_bytes([data[1], data[2]]),
                    ack_for_subtype: data[3],
                })
            }
            ControlSubtype::ServerHello => {
                if data.len() < 1 + 32 + 64 {
                    return Err(Error::InvalidPacket("ServerHello too short"));
                }
                let mut server_eph_pub = [0u8; 32];
                server_eph_pub.copy_from_slice(&data[1..33]);
                let mut signature = [0u8; 64];
                signature.copy_from_slice(&data[33..97]);
                let network_config = if data.len() >= 97 + 12 {
                    let end = (97 + ClientNetworkConfig::WIRE_SIZE).min(data.len());
                    Some(ClientNetworkConfig::decode_wire(&data[97..end])?)
                } else {
                    None
                };
                Ok(Self::ServerHello {
                    server_eph_pub,
                    signature,
                    network_config,
                })
            }
            ControlSubtype::RecordingStart => {
                if data.len() < 3 {
                    return Err(Error::InvalidPacket("RecordingStart too short"));
                }
                let svc_len = u16::from_le_bytes([data[1], data[2]]) as usize;
                if data.len() < 3 + svc_len {
                    return Err(Error::InvalidPacket("RecordingStart invalid length"));
                }
                let service = String::from_utf8_lossy(&data[3..3 + svc_len]).to_string();
                Ok(Self::RecordingStart { service })
            }
            ControlSubtype::RecordingAck => {
                if data.len() < 1 + 16 + 2 {
                    return Err(Error::InvalidPacket("RecordingAck too short"));
                }
                let mut session_id = [0u8; 16];
                session_id.copy_from_slice(&data[1..17]);
                let status_len = u16::from_le_bytes([data[17], data[18]]) as usize;
                if data.len() < 19 + status_len {
                    return Err(Error::InvalidPacket("RecordingAck invalid length"));
                }
                let status = String::from_utf8_lossy(&data[19..19 + status_len]).to_string();
                Ok(Self::RecordingAck { session_id, status })
            }
            ControlSubtype::RecordingStop => {
                if data.len() < 17 {
                    return Err(Error::InvalidPacket("RecordingStop too short"));
                }
                let mut session_id = [0u8; 16];
                session_id.copy_from_slice(&data[1..17]);
                Ok(Self::RecordingStop { session_id })
            }
            ControlSubtype::RecordingComplete => {
                if data.len() < 3 {
                    return Err(Error::InvalidPacket("RecordingComplete too short"));
                }
                let mut cursor = 1;
                let svc_len = u16::from_le_bytes([data[cursor], data[cursor + 1]]) as usize;
                cursor += 2;
                if data.len() < cursor + svc_len + 2 + 4 {
                    return Err(Error::InvalidPacket("RecordingComplete invalid length"));
                }
                let service = String::from_utf8_lossy(&data[cursor..cursor + svc_len]).to_string();
                cursor += svc_len;
                let mid_len = u16::from_le_bytes([data[cursor], data[cursor + 1]]) as usize;
                cursor += 2;
                if data.len() < cursor + mid_len + 4 {
                    return Err(Error::InvalidPacket("RecordingComplete invalid mask_id"));
                }
                let mask_id = String::from_utf8_lossy(&data[cursor..cursor + mid_len]).to_string();
                cursor += mid_len;
                let confidence = f32::from_le_bytes([
                    data[cursor],
                    data[cursor + 1],
                    data[cursor + 2],
                    data[cursor + 3],
                ]);
                Ok(Self::RecordingComplete {
                    service,
                    mask_id,
                    confidence,
                })
            }
            ControlSubtype::RecordingFailed => {
                if data.len() < 3 {
                    return Err(Error::InvalidPacket("RecordingFailed too short"));
                }
                let reason_len = u16::from_le_bytes([data[1], data[2]]) as usize;
                if data.len() < 3 + reason_len {
                    return Err(Error::InvalidPacket("RecordingFailed invalid length"));
                }
                let reason = String::from_utf8_lossy(&data[3..3 + reason_len]).to_string();
                Ok(Self::RecordingFailed { reason })
            }
            ControlSubtype::RecordingStatusRequest => Ok(Self::RecordingStatusRequest),
            ControlSubtype::RecordingStatus => {
                if data.len() < 2 {
                    return Err(Error::InvalidPacket("RecordingStatus too short"));
                }
                let flags = data[1];
                let can_record = (flags & 0x01) != 0;
                let has_service = (flags & 0x02) != 0;
                let active_service = if has_service {
                    if data.len() < 4 {
                        return Err(Error::InvalidPacket(
                            "RecordingStatus missing service length",
                        ));
                    }
                    let service_len = u16::from_le_bytes([data[2], data[3]]) as usize;
                    if data.len() < 4 + service_len {
                        return Err(Error::InvalidPacket(
                            "RecordingStatus invalid service length",
                        ));
                    }
                    Some(String::from_utf8_lossy(&data[4..4 + service_len]).to_string())
                } else {
                    None
                };
                Ok(Self::RecordingStatus {
                    can_record,
                    active_service,
                })
            }
            ControlSubtype::BootstrapDescriptorUpdate => {
                if data.len() < 3 {
                    return Err(Error::InvalidPacket("BootstrapDescriptorUpdate too short"));
                }
                let descriptor_len = u16::from_le_bytes([data[1], data[2]]) as usize;
                if data.len() < 3 + descriptor_len {
                    return Err(Error::InvalidPacket(
                        "BootstrapDescriptorUpdate invalid length",
                    ));
                }
                Ok(Self::BootstrapDescriptorUpdate {
                    descriptor_data: data[3..3 + descriptor_len].to_vec(),
                })
            }
            ControlSubtype::PoolSync => {
                if data.len() < 5 {
                    return Err(Error::InvalidPacket("PoolSync too short"));
                }
                let payload_len = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
                // NB: `data.len() < 5 + payload_len` would wrap on 32-bit
                // targets (armv7/mipsel musl builds) for a wire-controlled len
                // near u32::MAX — the check passes and the slice below panics.
                if data.len().saturating_sub(5) < payload_len {
                    return Err(Error::InvalidPacket("PoolSync invalid length"));
                }
                Ok(Self::PoolSync {
                    clients_json: data[5..5 + payload_len].to_vec(),
                })
            }
            ControlSubtype::RouteSync => {
                if data.len() < 5 {
                    return Err(Error::InvalidPacket("RouteSync too short"));
                }
                let len = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
                // Overflow-safe on 32-bit targets (see PoolSync above).
                if data.len().saturating_sub(5) < len {
                    return Err(Error::InvalidPacket("RouteSync invalid length"));
                }
                Ok(Self::RouteSync {
                    subnets_json: data[5..5 + len].to_vec(),
                })
            }
            ControlSubtype::ChainForward => {
                if data.len() < 5 {
                    return Err(Error::InvalidPacket("ChainForward too short"));
                }
                let len = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
                // Overflow-safe on 32-bit targets (see PoolSync above).
                if data.len().saturating_sub(5) < len {
                    return Err(Error::InvalidPacket("ChainForward invalid length"));
                }
                Ok(Self::ChainForward {
                    payload: data[5..5 + len].to_vec(),
                })
            }
            ControlSubtype::ClientCert => {
                if data.len() < 5 {
                    return Err(Error::InvalidPacket("ClientCert too short"));
                }
                let len = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
                // Overflow-safe on 32-bit targets (see PoolSync above).
                if data.len().saturating_sub(5) < len {
                    return Err(Error::InvalidPacket("ClientCert invalid length"));
                }
                Ok(Self::ClientCert {
                    cert_bytes: data[5..5 + len].to_vec(),
                })
            }
            ControlSubtype::CertRejected => Ok(Self::CertRejected {}),
            ControlSubtype::DeviceEnrollment => {
                if data.len() < 65 {
                    return Err(Error::InvalidPacket("DeviceEnrollment too short"));
                }
                let mut static_pub = [0u8; 32];
                let mut dh_proof = [0u8; 32];
                static_pub.copy_from_slice(&data[1..33]);
                dh_proof.copy_from_slice(&data[33..65]);
                Ok(Self::DeviceEnrollment {
                    static_pub,
                    dh_proof,
                })
            }
            ControlSubtype::KeepaliveAck => {
                if data.len() < 9 {
                    return Err(Error::InvalidPacket("KeepaliveAck too short"));
                }
                let echo_ts = u64::from_le_bytes(data[1..9].try_into().unwrap());
                Ok(Self::KeepaliveAck { echo_ts })
            }
            ControlSubtype::QualityReport => {
                if data.len() < 10 {
                    return Err(Error::InvalidPacket("QualityReport too short"));
                }
                Ok(Self::QualityReport {
                    quality: data[1],
                    rtt_ms: u16::from_le_bytes([data[2], data[3]]),
                    loss_ppm: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
                    jitter_ms: u16::from_le_bytes([data[8], data[9]]),
                })
            }
            ControlSubtype::AdaptiveHint => {
                if data.len() < 2 {
                    return Err(Error::InvalidPacket("AdaptiveHint too short"));
                }
                Ok(Self::AdaptiveHint { level: data[1] })
            }
            ControlSubtype::MaskPreference => {
                if data.len() < 3 {
                    return Err(Error::InvalidPacket("MaskPreference too short"));
                }
                let id_len = u16::from_le_bytes([data[1], data[2]]) as usize;
                if data.len() < 3 + id_len {
                    return Err(Error::InvalidPacket("MaskPreference invalid length"));
                }
                let base_mask_id = String::from_utf8_lossy(&data[3..3 + id_len]).to_string();
                Ok(Self::MaskPreference { base_mask_id })
            }
            ControlSubtype::MaskFeedback => {
                if data.len() < 2 {
                    return Err(Error::InvalidPacket("MaskFeedback too short"));
                }
                // Reject (don't silently truncate) an over-cap count: clamping
                // the loop bound would leave trailing entry bytes to be misread
                // as the country code.
                let entry_count = data[1] as usize;
                if entry_count > 64 {
                    return Err(Error::InvalidPacket("MaskFeedback entry_count exceeds cap"));
                }
                let mut offset = 2usize;
                let mut entries = Vec::with_capacity(entry_count);
                for _ in 0..entry_count {
                    if data.len() < offset + 2 {
                        return Err(Error::InvalidPacket("MaskFeedback entry truncated"));
                    }
                    let id_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
                    offset += 2;
                    if data.len() < offset + id_len + 4 {
                        return Err(Error::InvalidPacket("MaskFeedback entry truncated"));
                    }
                    let mask_id =
                        String::from_utf8_lossy(&data[offset..offset + id_len]).to_string();
                    offset += id_len;
                    let success = u16::from_le_bytes([data[offset], data[offset + 1]]);
                    offset += 2;
                    let fail = u16::from_le_bytes([data[offset], data[offset + 1]]);
                    offset += 2;
                    entries.push(MaskOutcome {
                        mask_id,
                        success,
                        fail,
                    });
                }
                if data.len() < offset + 2 {
                    return Err(Error::InvalidPacket("MaskFeedback missing country code"));
                }
                let country_code = [data[offset], data[offset + 1]];
                Ok(Self::MaskFeedback {
                    entries,
                    country_code,
                })
            }
            ControlSubtype::RegionalMaskHints => {
                if data.len() < 4 {
                    return Err(Error::InvalidPacket("RegionalMaskHints too short"));
                }
                let country_code = [data[1], data[2]];
                let count = data[3] as usize;
                if count > 32 {
                    return Err(Error::InvalidPacket("RegionalMaskHints count exceeds cap"));
                }
                let mut offset = 4usize;
                let mut masks = Vec::with_capacity(count);
                for _ in 0..count {
                    if data.len() < offset + 2 {
                        return Err(Error::InvalidPacket("RegionalMaskHints entry truncated"));
                    }
                    let id_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
                    offset += 2;
                    if data.len() < offset + id_len + 4 {
                        return Err(Error::InvalidPacket("RegionalMaskHints entry truncated"));
                    }
                    let mask_id =
                        String::from_utf8_lossy(&data[offset..offset + id_len]).to_string();
                    offset += id_len;
                    let score = f32::from_le_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    ]);
                    offset += 4;
                    // Reject a non-finite or out-of-range score: it is a
                    // success rate in [0,1] and feeds a mask-ranking sort, where
                    // a NaN comparator would panic.
                    if !score.is_finite() || !(0.0..=1.0).contains(&score) {
                        return Err(Error::InvalidPacket("RegionalMaskHints score out of range"));
                    }
                    masks.push((mask_id, score));
                }
                Ok(Self::RegionalMaskHints {
                    country_code,
                    masks,
                })
            }
            ControlSubtype::FeedbackConfig => {
                // subtype(1) + threshold(1) + interval(4) = 6 bytes
                if data.len() < 6 {
                    return Err(Error::InvalidPacket("FeedbackConfig too short"));
                }
                let report_failure_threshold = data[1];
                let report_interval_secs = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
                Ok(Self::FeedbackConfig {
                    report_failure_threshold,
                    report_interval_secs,
                })
            }
            ControlSubtype::MaskCatalog => {
                if data.len() < 2 {
                    return Err(Error::InvalidPacket("MaskCatalog too short"));
                }
                let count = data[1] as usize;
                if count > 64 {
                    return Err(Error::InvalidPacket("MaskCatalog count exceeds cap"));
                }
                let mut offset = 2usize;
                let mut masks = Vec::with_capacity(count);
                for _ in 0..count {
                    if data.len() < offset + 2 {
                        return Err(Error::InvalidPacket("MaskCatalog entry truncated"));
                    }
                    let id_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
                    offset += 2;
                    if data.len() < offset + id_len + 2 {
                        return Err(Error::InvalidPacket("MaskCatalog entry truncated"));
                    }
                    let mask_id =
                        String::from_utf8_lossy(&data[offset..offset + id_len]).to_string();
                    offset += id_len;
                    let label_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
                    offset += 2;
                    if data.len() < offset + label_len + 1 {
                        return Err(Error::InvalidPacket("MaskCatalog entry truncated"));
                    }
                    let label =
                        String::from_utf8_lossy(&data[offset..offset + label_len]).to_string();
                    offset += label_len;
                    let generated = data[offset] != 0;
                    offset += 1;
                    masks.push((mask_id, label, generated));
                }
                Ok(Self::MaskCatalog { masks })
            }
            ControlSubtype::Capabilities => {
                if data.len() < 6 {
                    return Err(Error::InvalidPacket("Capabilities too short"));
                }
                let role = data[1];
                let features = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
                Ok(Self::Capabilities { role, features })
            }
            ControlSubtype::MgmtRequest => {
                if data.len() < 8 {
                    return Err(Error::InvalidPacket("MgmtRequest too short"));
                }
                let req_id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
                let method = data[5];
                let path_len = u16::from_le_bytes([data[6], data[7]]) as usize;
                if data.len().saturating_sub(8) < path_len {
                    return Err(Error::InvalidPacket("MgmtRequest path truncated"));
                }
                let path_start = 8;
                let path_end = path_start + path_len;
                let path = String::from_utf8_lossy(&data[path_start..path_end]).to_string();
                if data.len().saturating_sub(path_end) < 4 {
                    return Err(Error::InvalidPacket("MgmtRequest missing body length"));
                }
                let body_len = u32::from_le_bytes([
                    data[path_end],
                    data[path_end + 1],
                    data[path_end + 2],
                    data[path_end + 3],
                ]) as usize;
                let body_start = path_end + 4;
                // Overflow-safe on 32-bit targets (see PoolSync above).
                if data.len().saturating_sub(body_start) < body_len {
                    return Err(Error::InvalidPacket("MgmtRequest body truncated"));
                }
                let body = data[body_start..body_start + body_len].to_vec();
                Ok(Self::MgmtRequest {
                    req_id,
                    method,
                    path,
                    body,
                })
            }
            ControlSubtype::MgmtResponse => {
                if data.len() < 11 {
                    return Err(Error::InvalidPacket("MgmtResponse too short"));
                }
                let req_id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
                let status = u16::from_le_bytes([data[5], data[6]]);
                let body_len = u32::from_le_bytes([data[7], data[8], data[9], data[10]]) as usize;
                // Overflow-safe on 32-bit targets (see PoolSync above).
                if data.len().saturating_sub(11) < body_len {
                    return Err(Error::InvalidPacket("MgmtResponse body truncated"));
                }
                let body = data[11..11 + body_len].to_vec();
                Ok(Self::MgmtResponse {
                    req_id,
                    status,
                    body,
                })
            }
        }
    }
}

/// ACK packet for selective acknowledgment
#[derive(Debug, Clone)]
pub struct AckPacket {
    pub ack_seq: u16,
    pub ack_base: u16,
    pub bitmap: Vec<u8>,
}

impl AckPacket {
    pub fn new(ack_seq: u16, ack_base: u16, bitmap: Vec<u8>) -> Self {
        Self {
            ack_seq,
            ack_base,
            bitmap,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(5 + self.bitmap.len());
        buf.extend_from_slice(&(InnerType::Ack as u16).to_le_bytes());
        buf.extend_from_slice(&self.ack_seq.to_le_bytes());
        buf.extend_from_slice(&self.ack_base.to_le_bytes());
        buf.push(self.bitmap.len() as u8);
        buf.extend_from_slice(&self.bitmap);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 7 {
            return Err(Error::InvalidPacket("ACK too short"));
        }
        let ack_seq = u16::from_le_bytes([data[2], data[3]]);
        let ack_base = u16::from_le_bytes([data[4], data[5]]);
        let bitmap_len = data[6] as usize;
        if data.len() < 7 + bitmap_len {
            return Err(Error::InvalidPacket("ACK invalid length"));
        }
        let bitmap = data[7..7 + bitmap_len].to_vec();
        Ok(Self {
            ack_seq,
            ack_base,
            bitmap,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // InnerType::from_u16
    // -----------------------------------------------------------------------

    #[test]
    fn inner_type_roundtrip_all_variants() {
        let variants = [
            (0x0001u16, InnerType::Data),
            (0x0002, InnerType::Control),
            (0x0003, InnerType::Fragment),
            (0x0004, InnerType::Ack),
            (0x0005, InnerType::FecRepair),
        ];
        for (v, expected) in variants {
            assert_eq!(InnerType::from_u16(v), Some(expected));
        }
        assert_eq!(InnerType::from_u16(0x0000), None);
        assert_eq!(InnerType::from_u16(0x0006), None);
    }

    // -----------------------------------------------------------------------
    // ControlSubtype::from_u8
    // -----------------------------------------------------------------------

    #[test]
    fn control_subtype_from_u8_all_variants() {
        let pairs: &[(u8, ControlSubtype)] = &[
            (0x01, ControlSubtype::KeyRotate),
            (0x02, ControlSubtype::MaskUpdate),
            (0x03, ControlSubtype::Keepalive),
            (0x04, ControlSubtype::TelemetryRequest),
            (0x05, ControlSubtype::TelemetryResponse),
            (0x06, ControlSubtype::TimeSync),
            (0x07, ControlSubtype::Shutdown),
            (0x08, ControlSubtype::ControlAck),
            (0x09, ControlSubtype::ServerHello),
            (0x0A, ControlSubtype::RecordingStart),
            (0x0B, ControlSubtype::RecordingAck),
            (0x0C, ControlSubtype::RecordingStop),
            (0x0D, ControlSubtype::RecordingComplete),
            (0x0E, ControlSubtype::RecordingFailed),
            (0x0F, ControlSubtype::RecordingStatusRequest),
            (0x10, ControlSubtype::RecordingStatus),
            (0x11, ControlSubtype::BootstrapDescriptorUpdate),
            (0x12, ControlSubtype::PoolSync),
            (0x13, ControlSubtype::RouteSync),
            (0x14, ControlSubtype::ChainForward),
            (0x15, ControlSubtype::ClientCert),
            (0x16, ControlSubtype::CertRejected),
            (0x17, ControlSubtype::DeviceEnrollment),
            (0x18, ControlSubtype::KeepaliveAck),
            (0x19, ControlSubtype::QualityReport),
            (0x1A, ControlSubtype::AdaptiveHint),
            (0x1B, ControlSubtype::MaskPreference),
            (0x1C, ControlSubtype::MaskFeedback),
            (0x1D, ControlSubtype::RegionalMaskHints),
            (0x1E, ControlSubtype::FeedbackConfig),
            (0x1F, ControlSubtype::MaskCatalog),
            (0x20, ControlSubtype::HandshakeReject),
            (0x21, ControlSubtype::PoolStateDigest),
            (0x22, ControlSubtype::PoolBucketDigests),
            (0x23, ControlSubtype::NodeEnrollment),
            (0x24, ControlSubtype::Capabilities),
            (0x25, ControlSubtype::MgmtRequest),
            (0x26, ControlSubtype::MgmtResponse),
        ];
        for (byte, expected) in pairs {
            assert_eq!(
                ControlSubtype::from_u8(*byte),
                Some(*expected),
                "byte={:#04x}",
                byte
            );
        }
        assert_eq!(ControlSubtype::from_u8(0x00), None);
        assert_eq!(ControlSubtype::from_u8(0x27), None);
    }

    // -----------------------------------------------------------------------
    // InnerHeader encode / decode
    // -----------------------------------------------------------------------

    #[test]
    fn inner_header_encode_decode_data() {
        let hdr = InnerHeader {
            inner_type: InnerType::Data,
            seq_num: 0x1234,
        };
        let encoded = hdr.encode();
        let decoded = InnerHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.inner_type, InnerType::Data);
        assert_eq!(decoded.seq_num, 0x1234);
    }

    #[test]
    fn inner_header_encode_decode_fragment() {
        let hdr = InnerHeader {
            inner_type: InnerType::Fragment,
            seq_num: 0xFFFF,
        };
        let encoded = hdr.encode();
        let decoded = InnerHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.inner_type, InnerType::Fragment);
        assert_eq!(decoded.seq_num, 0xFFFF);
    }

    #[test]
    fn inner_header_decode_too_short_returns_error() {
        assert!(InnerHeader::decode(&[0x01, 0x00, 0x00]).is_err());
        assert!(InnerHeader::decode(&[]).is_err());
    }

    #[test]
    fn inner_header_decode_unknown_type_returns_error() {
        // type 0x0099 is unknown
        let data = [0x99u8, 0x00, 0x01, 0x00];
        assert!(InnerHeader::decode(&data).is_err());
    }

    // -----------------------------------------------------------------------
    // AivpnPacket encode / decode (from_bytes_with_mdh_len)
    // -----------------------------------------------------------------------

    fn make_tag() -> [u8; TAG_SIZE] {
        [0xAB; TAG_SIZE]
    }

    #[test]
    fn aivpn_packet_data_roundtrip() {
        let tag = make_tag();
        let mdh = vec![0x01, 0x02, 0x03, 0x04];
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11];
        let pkt = AivpnPacket::new(tag, mdh.clone(), payload.clone(), 0);

        let bytes = pkt.to_bytes();
        let decoded = AivpnPacket::from_bytes_with_mdh_len(&bytes, mdh.len()).unwrap();

        assert_eq!(decoded.resonance_tag, tag);
        assert_eq!(decoded.mask_dependent_header, mdh);
        assert_eq!(decoded.pad_len, 0);
        assert_eq!(decoded.encrypted_payload, payload);
        assert!(decoded.random_padding.is_empty());
    }

    #[test]
    fn aivpn_packet_fragment_roundtrip_with_padding() {
        let tag = make_tag();
        let mdh = vec![0xAA, 0xBB];
        let payload = vec![0x01, 0x02, 0x03];
        let padding_len = 8u16;
        let pkt = AivpnPacket::new(tag, mdh.clone(), payload.clone(), padding_len);

        let bytes = pkt.to_bytes();
        let decoded = AivpnPacket::from_bytes_with_mdh_len(&bytes, mdh.len()).unwrap();

        assert_eq!(decoded.resonance_tag, tag);
        assert_eq!(decoded.mask_dependent_header, mdh);
        assert_eq!(decoded.pad_len, padding_len);
        assert_eq!(decoded.encrypted_payload, payload);
        assert_eq!(decoded.random_padding.len(), padding_len as usize);
    }

    #[test]
    fn aivpn_packet_from_bytes_too_short_returns_error() {
        // Fewer than TAG_SIZE + 2 bytes
        let short = vec![0u8; TAG_SIZE + 1];
        assert!(AivpnPacket::from_bytes(&short).is_err());
    }

    #[test]
    fn aivpn_packet_from_bytes_with_mdh_len_too_short_returns_error() {
        // Only tag bytes, no room for mdh=4 + pad_len
        let short = vec![0u8; TAG_SIZE + 2];
        assert!(AivpnPacket::from_bytes_with_mdh_len(&short, 4).is_err());
    }

    #[test]
    fn aivpn_packet_pad_len_overflow_returns_error() {
        // Construct a packet where pad_len > remaining bytes
        let tag = make_tag();
        let mdh = vec![0x01u8; 2];
        let payload = vec![0x00u8; 4];
        let mut bytes = AivpnPacket::new(tag, mdh.clone(), payload, 0)
            .to_bytes()
            .to_vec();

        // Overwrite pad_len field (at offset TAG_SIZE + mdh.len()) with 0xFFFF
        let pad_offset = TAG_SIZE + mdh.len();
        bytes[pad_offset] = 0xFF;
        bytes[pad_offset + 1] = 0xFF;

        assert!(AivpnPacket::from_bytes_with_mdh_len(&bytes, mdh.len()).is_err());
    }

    #[test]
    fn aivpn_packet_from_bytes_minimal_valid() {
        // Exactly TAG_SIZE + 2 bytes: tag + empty mdh + pad_len=0
        let mut data = vec![0u8; TAG_SIZE + 2];
        data[0] = 0xCC;
        let pkt = AivpnPacket::from_bytes(&data).unwrap();
        assert_eq!(pkt.resonance_tag[0], 0xCC);
    }

    // -----------------------------------------------------------------------
    // AckPacket encode / decode
    // -----------------------------------------------------------------------

    #[test]
    fn ack_packet_roundtrip_empty_bitmap() {
        let ack = AckPacket::new(100, 50, vec![]);
        let encoded = ack.encode();
        let decoded = AckPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.ack_seq, 100);
        assert_eq!(decoded.ack_base, 50);
        assert!(decoded.bitmap.is_empty());
    }

    #[test]
    fn ack_packet_roundtrip_with_bitmap() {
        let bitmap = vec![0b10101010, 0b01010101, 0xFF];
        let ack = AckPacket::new(0xBEEF, 0x1234, bitmap.clone());
        let encoded = ack.encode();
        let decoded = AckPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.ack_seq, 0xBEEF);
        assert_eq!(decoded.ack_base, 0x1234);
        assert_eq!(decoded.bitmap, bitmap);
    }

    #[test]
    fn ack_packet_decode_too_short_returns_error() {
        assert!(AckPacket::decode(&[0x04, 0x00, 0x01, 0x00, 0x00]).is_err());
        assert!(AckPacket::decode(&[]).is_err());
    }

    #[test]
    fn ack_packet_decode_truncated_bitmap_returns_error() {
        let ack = AckPacket::new(1, 0, vec![0xAA, 0xBB, 0xCC]);
        let mut encoded = ack.encode();
        // truncate by removing last byte
        encoded.pop();
        assert!(AckPacket::decode(&encoded).is_err());
    }

    // -----------------------------------------------------------------------
    // ControlPayload encode / decode — all variants
    // -----------------------------------------------------------------------

    fn roundtrip(payload: &ControlPayload) -> ControlPayload {
        let encoded = payload.encode().expect("encode failed");
        ControlPayload::decode(&encoded).expect("decode failed")
    }

    #[test]
    fn control_payload_key_rotate_roundtrip() {
        let new_eph_pub = [0x42u8; 32];
        let p = ControlPayload::KeyRotate { new_eph_pub };
        let decoded = roundtrip(&p);
        if let ControlPayload::KeyRotate { new_eph_pub: k } = decoded {
            assert_eq!(k, new_eph_pub);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_mask_update_roundtrip() {
        let mask_data = vec![1u8, 2, 3, 4, 5];
        let signature = [0x7Fu8; 64];
        let p = ControlPayload::MaskUpdate {
            mask_data: mask_data.clone(),
            signature,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::MaskUpdate {
            mask_data: md,
            signature: sig,
        } = decoded
        {
            assert_eq!(md, mask_data);
            assert_eq!(sig, signature);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_keepalive_roundtrip() {
        let p = ControlPayload::Keepalive {
            send_ts: 0xDEAD_BEEF_1234_5678,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::Keepalive { send_ts } = decoded {
            assert_eq!(send_ts, 0xDEAD_BEEF_1234_5678);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_telemetry_request_roundtrip() {
        let p = ControlPayload::TelemetryRequest {
            metric_flags: 0b0000_1111,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::TelemetryRequest { metric_flags } = decoded {
            assert_eq!(metric_flags, 0b0000_1111);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_telemetry_response_roundtrip() {
        let p = ControlPayload::TelemetryResponse {
            packet_loss: 300,
            rtt_ms: 42,
            jitter_ms: 7,
            buffer_pct: 88,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::TelemetryResponse {
            packet_loss,
            rtt_ms,
            jitter_ms,
            buffer_pct,
        } = decoded
        {
            assert_eq!(packet_loss, 300);
            assert_eq!(rtt_ms, 42);
            assert_eq!(jitter_ms, 7);
            assert_eq!(buffer_pct, 88);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_time_sync_roundtrip() {
        let p = ControlPayload::TimeSync {
            server_ts_ms: 1_700_000_000_000,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::TimeSync { server_ts_ms } = decoded {
            assert_eq!(server_ts_ms, 1_700_000_000_000);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_shutdown_roundtrip() {
        let p = ControlPayload::Shutdown { reason: 0x05 };
        let decoded = roundtrip(&p);
        if let ControlPayload::Shutdown { reason } = decoded {
            assert_eq!(reason, 0x05);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_control_ack_roundtrip() {
        let p = ControlPayload::ControlAck {
            ack_seq: 0x1001,
            ack_for_subtype: 0x09,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::ControlAck {
            ack_seq,
            ack_for_subtype,
        } = decoded
        {
            assert_eq!(ack_seq, 0x1001);
            assert_eq!(ack_for_subtype, 0x09);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_server_hello_no_network_config_roundtrip() {
        let server_eph_pub = [0x11u8; 32];
        let signature = [0x22u8; 64];
        let p = ControlPayload::ServerHello {
            server_eph_pub,
            signature,
            network_config: None,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::ServerHello {
            server_eph_pub: k,
            signature: sig,
            network_config: nc,
        } = decoded
        {
            assert_eq!(k, server_eph_pub);
            assert_eq!(sig, signature);
            assert!(nc.is_none());
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_recording_start_roundtrip() {
        let p = ControlPayload::RecordingStart {
            service: "zoom".to_string(),
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::RecordingStart { service } = decoded {
            assert_eq!(service, "zoom");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_recording_ack_roundtrip() {
        let session_id = [0xABu8; 16];
        let p = ControlPayload::RecordingAck {
            session_id,
            status: "ok".to_string(),
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::RecordingAck {
            session_id: sid,
            status,
        } = decoded
        {
            assert_eq!(sid, session_id);
            assert_eq!(status, "ok");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_recording_stop_roundtrip() {
        let session_id = [0x01u8; 16];
        let p = ControlPayload::RecordingStop { session_id };
        let decoded = roundtrip(&p);
        if let ControlPayload::RecordingStop { session_id: sid } = decoded {
            assert_eq!(sid, session_id);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_recording_complete_roundtrip() {
        let p = ControlPayload::RecordingComplete {
            service: "https".to_string(),
            mask_id: "mask-001".to_string(),
            confidence: 0.987_654,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::RecordingComplete {
            service,
            mask_id,
            confidence,
        } = decoded
        {
            assert_eq!(service, "https");
            assert_eq!(mask_id, "mask-001");
            assert!((confidence - 0.987_654f32).abs() < 1e-5);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_recording_failed_roundtrip() {
        let p = ControlPayload::RecordingFailed {
            reason: "disk full".to_string(),
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::RecordingFailed { reason } = decoded {
            assert_eq!(reason, "disk full");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_recording_status_request_roundtrip() {
        let p = ControlPayload::RecordingStatusRequest;
        let decoded = roundtrip(&p);
        assert!(matches!(decoded, ControlPayload::RecordingStatusRequest));
    }

    #[test]
    fn control_payload_recording_status_with_service_roundtrip() {
        let p = ControlPayload::RecordingStatus {
            can_record: true,
            active_service: Some("quic".to_string()),
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::RecordingStatus {
            can_record,
            active_service,
        } = decoded
        {
            assert!(can_record);
            assert_eq!(active_service, Some("quic".to_string()));
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_recording_status_no_service_roundtrip() {
        let p = ControlPayload::RecordingStatus {
            can_record: false,
            active_service: None,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::RecordingStatus {
            can_record,
            active_service,
        } = decoded
        {
            assert!(!can_record);
            assert!(active_service.is_none());
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_bootstrap_descriptor_update_roundtrip() {
        let descriptor_data = vec![0xDE, 0xAD, 0xC0, 0xDE];
        let p = ControlPayload::BootstrapDescriptorUpdate {
            descriptor_data: descriptor_data.clone(),
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::BootstrapDescriptorUpdate {
            descriptor_data: dd,
        } = decoded
        {
            assert_eq!(dd, descriptor_data);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_pool_sync_roundtrip() {
        let clients_json = br#"[{"name":"alice"}]"#.to_vec();
        let p = ControlPayload::PoolSync {
            clients_json: clients_json.clone(),
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::PoolSync { clients_json: cj } = decoded {
            assert_eq!(cj, clients_json);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_pool_state_digest_roundtrip() {
        let digest = [0xABu8; 32];
        let p = ControlPayload::PoolStateDigest { digest };
        let decoded = roundtrip(&p);
        if let ControlPayload::PoolStateDigest { digest: d } = decoded {
            assert_eq!(d, digest);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_pool_bucket_digests_roundtrip() {
        let digests = vec![0xCDu8; 64 * 8]; // POOL_SYNC_BUCKETS * 8
        for reply_requested in [true, false] {
            let p = ControlPayload::PoolBucketDigests {
                digests: digests.clone(),
                reply_requested,
            };
            let decoded = roundtrip(&p);
            if let ControlPayload::PoolBucketDigests {
                digests: d,
                reply_requested: r,
            } = decoded
            {
                assert_eq!(d, digests);
                assert_eq!(r, reply_requested);
            } else {
                panic!("wrong variant");
            }
        }
    }

    #[test]
    fn control_payload_pool_bucket_digests_empty_roundtrip() {
        for reply_requested in [true, false] {
            let p = ControlPayload::PoolBucketDigests {
                digests: vec![],
                reply_requested,
            };
            let decoded = roundtrip(&p);
            if let ControlPayload::PoolBucketDigests {
                digests: d,
                reply_requested: r,
            } = decoded
            {
                assert!(d.is_empty());
                assert_eq!(r, reply_requested);
            } else {
                panic!("wrong variant");
            }
        }
    }

    #[test]
    fn control_payload_node_enrollment_roundtrip() {
        let node_id = "node-alpha-01".to_string();
        let node_pub = [0x5Au8; 32];
        let time_window = 123_456_789u64;
        let signature = [0x7Bu8; 64];

        let p = ControlPayload::NodeEnrollment {
            node_id: node_id.clone(),
            node_pub,
            time_window,
            signature,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::NodeEnrollment {
            node_id: n,
            node_pub: pk,
            time_window: tw,
            signature: sig,
        } = decoded
        {
            assert_eq!(n, node_id);
            assert_eq!(pk, node_pub);
            assert_eq!(tw, time_window);
            assert_eq!(sig, signature);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_node_enrollment_empty_node_id_roundtrips() {
        // Sibling string-bearing variants (e.g. RecordingStart's `service`)
        // allow an empty string to round-trip rather than rejecting it — the
        // wire format has no minimum-length constraint on node_id, so match
        // that convention here.
        let node_pub = [0x11u8; 32];
        let time_window = 1u64;
        let signature = [0x22u8; 64];

        let p = ControlPayload::NodeEnrollment {
            node_id: String::new(),
            node_pub,
            time_window,
            signature,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::NodeEnrollment { node_id: n, .. } = decoded {
            assert!(n.is_empty());
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_route_sync_roundtrip() {
        let subnets_json = br#"["10.0.0.0/8","192.168.0.0/16"]"#.to_vec();
        let p = ControlPayload::RouteSync {
            subnets_json: subnets_json.clone(),
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::RouteSync { subnets_json: sj } = decoded {
            assert_eq!(sj, subnets_json);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_chain_forward_roundtrip() {
        let payload = vec![0x45, 0x00, 0x00, 0x28]; // fake IP header start
        let p = ControlPayload::ChainForward {
            payload: payload.clone(),
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::ChainForward { payload: pl } = decoded {
            assert_eq!(pl, payload);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_client_cert_roundtrip() {
        let cert_bytes = vec![0xCCu8; 104];
        let p = ControlPayload::ClientCert {
            cert_bytes: cert_bytes.clone(),
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::ClientCert { cert_bytes: cb } = decoded {
            assert_eq!(cb, cert_bytes);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_cert_rejected_roundtrip() {
        let p = ControlPayload::CertRejected {};
        let decoded = roundtrip(&p);
        assert!(matches!(decoded, ControlPayload::CertRejected {}));
    }

    #[test]
    fn control_payload_device_enrollment_roundtrip() {
        let static_pub = [0x33u8; 32];
        let dh_proof = [0x44u8; 32];
        let p = ControlPayload::DeviceEnrollment {
            static_pub,
            dh_proof,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::DeviceEnrollment {
            static_pub: sp,
            dh_proof: dp,
        } = decoded
        {
            assert_eq!(sp, static_pub);
            assert_eq!(dp, dh_proof);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_keepalive_ack_roundtrip() {
        let p = ControlPayload::KeepaliveAck {
            echo_ts: 0x0102_0304_0506_0708,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::KeepaliveAck { echo_ts } = decoded {
            assert_eq!(echo_ts, 0x0102_0304_0506_0708);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_quality_report_roundtrip() {
        let p = ControlPayload::QualityReport {
            quality: 95,
            rtt_ms: 12,
            loss_ppm: 500,
            jitter_ms: 3,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::QualityReport {
            quality,
            rtt_ms,
            loss_ppm,
            jitter_ms,
        } = decoded
        {
            assert_eq!(quality, 95);
            assert_eq!(rtt_ms, 12);
            assert_eq!(loss_ppm, 500);
            assert_eq!(jitter_ms, 3);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_adaptive_hint_roundtrip() {
        for level in 0u8..=3 {
            let p = ControlPayload::AdaptiveHint { level };
            let decoded = roundtrip(&p);
            if let ControlPayload::AdaptiveHint { level: l } = decoded {
                assert_eq!(l, level);
            } else {
                panic!("wrong variant for level {level}");
            }
        }
    }

    #[test]
    fn control_payload_mask_preference_roundtrip() {
        let p = ControlPayload::MaskPreference {
            base_mask_id: "webrtc_zoom_v3".to_string(),
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::MaskPreference { base_mask_id } = decoded {
            assert_eq!(base_mask_id, "webrtc_zoom_v3");
        } else {
            panic!("wrong variant");
        }
    }

    // -----------------------------------------------------------------------
    // ControlPayload::decode — malformed / too short inputs
    // -----------------------------------------------------------------------

    #[test]
    fn control_payload_decode_empty_returns_error() {
        assert!(ControlPayload::decode(&[]).is_err());
    }

    #[test]
    fn control_payload_decode_unknown_subtype_returns_error() {
        assert!(ControlPayload::decode(&[0x00]).is_err());
        assert!(ControlPayload::decode(&[0xFF]).is_err());
    }

    #[test]
    fn control_payload_key_rotate_too_short_returns_error() {
        // subtype byte only
        assert!(ControlPayload::decode(&[0x01]).is_err());
    }

    #[test]
    fn control_payload_server_hello_too_short_returns_error() {
        // only 10 bytes — needs 1+32+64=97 minimum
        let data = vec![0x09u8; 10];
        assert!(ControlPayload::decode(&data).is_err());
    }

    #[test]
    fn control_payload_keepalive_ack_too_short_returns_error() {
        // only 5 bytes — needs 9
        assert!(ControlPayload::decode(&[0x18, 0x01, 0x02, 0x03, 0x04]).is_err());
    }

    #[test]
    fn control_payload_adaptive_hint_too_short_returns_error() {
        assert!(ControlPayload::decode(&[0x1A]).is_err());
    }

    #[test]
    fn control_payload_mask_preference_too_short_returns_error() {
        // just the subtype byte — needs 3 for the u16 length prefix
        assert!(ControlPayload::decode(&[0x1B]).is_err());
    }

    #[test]
    fn control_payload_mask_preference_length_exceeds_data_returns_error() {
        // subtype + length=9999 but no payload bytes
        let mut data = vec![0x1Bu8];
        data.extend_from_slice(&9999u16.to_le_bytes());
        assert!(ControlPayload::decode(&data).is_err());
    }

    // -----------------------------------------------------------------------
    // ControlPayload::MaskFeedback / RegionalMaskHints (§2 crowdsourced
    // blocking feedback — privacy-preserving)
    // -----------------------------------------------------------------------

    #[test]
    fn control_payload_mask_feedback_roundtrip() {
        let p = ControlPayload::MaskFeedback {
            entries: vec![
                MaskOutcome {
                    mask_id: "webrtc_zoom_v3".to_string(),
                    success: 12,
                    fail: 3,
                },
                MaskOutcome {
                    mask_id: "quic_https".to_string(),
                    success: 40,
                    fail: 0,
                },
            ],
            country_code: *b"DE",
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::MaskFeedback {
            entries,
            country_code,
        } = decoded
        {
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].mask_id, "webrtc_zoom_v3");
            assert_eq!(entries[0].success, 12);
            assert_eq!(entries[0].fail, 3);
            assert_eq!(entries[1].mask_id, "quic_https");
            assert_eq!(entries[1].success, 40);
            assert_eq!(entries[1].fail, 0);
            assert_eq!(&country_code, b"DE");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_mask_feedback_empty_entries_roundtrip() {
        let p = ControlPayload::MaskFeedback {
            entries: vec![],
            country_code: *b"US",
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::MaskFeedback {
            entries,
            country_code,
        } = decoded
        {
            assert!(entries.is_empty());
            assert_eq!(&country_code, b"US");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_mask_feedback_caps_at_64_entries() {
        let entries: Vec<MaskOutcome> = (0..100)
            .map(|i| MaskOutcome {
                mask_id: format!("mask_{i}"),
                success: 1,
                fail: 0,
            })
            .collect();
        let p = ControlPayload::MaskFeedback {
            entries,
            country_code: *b"FR",
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::MaskFeedback { entries, .. } = decoded {
            assert_eq!(entries.len(), 64);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_mask_feedback_too_short_returns_error() {
        // just the subtype byte — needs at least 2 (subtype + entry_count)
        assert!(ControlPayload::decode(&[0x1C]).is_err());
    }

    #[test]
    fn control_payload_mask_feedback_truncated_entry_returns_error() {
        // subtype + entry_count=1, but no entry bytes at all
        assert!(ControlPayload::decode(&[0x1C, 0x01]).is_err());
    }

    #[test]
    fn control_payload_mask_feedback_missing_country_code_returns_error() {
        // subtype + entry_count=0, but no country code bytes
        assert!(ControlPayload::decode(&[0x1C, 0x00]).is_err());
    }

    #[test]
    fn control_payload_mask_feedback_entry_length_exceeds_data_returns_error() {
        // subtype + entry_count=1 + mask_id_len=9999 but no payload bytes
        let mut data = vec![0x1Cu8, 0x01];
        data.extend_from_slice(&9999u16.to_le_bytes());
        assert!(ControlPayload::decode(&data).is_err());
    }

    #[test]
    fn control_payload_regional_mask_hints_roundtrip() {
        let p = ControlPayload::RegionalMaskHints {
            country_code: *b"JP",
            masks: vec![
                ("webrtc_zoom_v3".to_string(), 0.95),
                ("quic_https".to_string(), 0.80),
            ],
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::RegionalMaskHints {
            country_code,
            masks,
        } = decoded
        {
            assert_eq!(&country_code, b"JP");
            assert_eq!(masks.len(), 2);
            assert_eq!(masks[0].0, "webrtc_zoom_v3");
            assert!((masks[0].1 - 0.95).abs() < f32::EPSILON);
            assert_eq!(masks[1].0, "quic_https");
            assert!((masks[1].1 - 0.80).abs() < f32::EPSILON);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_feedback_config_roundtrip() {
        let p = ControlPayload::FeedbackConfig {
            report_failure_threshold: 3,
            report_interval_secs: 3600,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::FeedbackConfig {
            report_failure_threshold,
            report_interval_secs,
        } = decoded
        {
            assert_eq!(report_failure_threshold, 3);
            assert_eq!(report_interval_secs, 3600);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_mask_catalog_roundtrip() {
        let p = ControlPayload::MaskCatalog {
            masks: vec![
                ("webrtc_zoom_v3".to_string(), "Zoom".to_string(), false),
                ("auto_quic_v1".to_string(), "QUIC (auto)".to_string(), true),
            ],
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::MaskCatalog { masks } = decoded {
            assert_eq!(masks.len(), 2);
            assert_eq!(
                masks[0],
                ("webrtc_zoom_v3".to_string(), "Zoom".to_string(), false)
            );
            assert_eq!(masks[1].0, "auto_quic_v1");
            assert!(masks[1].2, "generated flag must survive roundtrip");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_feedback_config_extremes_roundtrip() {
        let p = ControlPayload::FeedbackConfig {
            report_failure_threshold: 255,
            report_interval_secs: u32::MAX,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::FeedbackConfig {
            report_failure_threshold,
            report_interval_secs,
        } = decoded
        {
            assert_eq!(report_failure_threshold, 255);
            assert_eq!(report_interval_secs, u32::MAX);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_feedback_config_too_short_returns_error() {
        // subtype + threshold but truncated interval
        assert!(ControlPayload::decode(&[0x1E, 0x03, 0x00]).is_err());
    }

    #[test]
    fn control_payload_regional_mask_hints_empty_roundtrip() {
        let p = ControlPayload::RegionalMaskHints {
            country_code: *b"BR",
            masks: vec![],
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::RegionalMaskHints {
            country_code,
            masks,
        } = decoded
        {
            assert_eq!(&country_code, b"BR");
            assert!(masks.is_empty());
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_regional_mask_hints_caps_at_32_entries() {
        let masks: Vec<(String, f32)> = (0..50).map(|i| (format!("mask_{i}"), 0.5)).collect();
        let p = ControlPayload::RegionalMaskHints {
            country_code: *b"CA",
            masks,
        };
        let decoded = roundtrip(&p);
        if let ControlPayload::RegionalMaskHints { masks, .. } = decoded {
            assert_eq!(masks.len(), 32);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn control_payload_regional_mask_hints_too_short_returns_error() {
        // subtype + country_code but no count byte
        assert!(ControlPayload::decode(&[0x1D, b'U', b'S']).is_err());
    }

    #[test]
    fn control_payload_regional_mask_hints_truncated_entry_returns_error() {
        // subtype + country_code + count=1, but no entry bytes
        assert!(ControlPayload::decode(&[0x1D, b'U', b'S', 0x01]).is_err());
    }

    #[test]
    fn control_payload_regional_mask_hints_entry_length_exceeds_data_returns_error() {
        // subtype + country_code + count=1 + mask_id_len=9999 but no payload
        let mut data = vec![0x1Du8, b'U', b'S', 0x01];
        data.extend_from_slice(&9999u16.to_le_bytes());
        assert!(ControlPayload::decode(&data).is_err());
    }

    #[test]
    fn control_payload_pool_sync_too_short_returns_error() {
        // only 3 bytes — needs 5 for length prefix
        assert!(ControlPayload::decode(&[0x12, 0x00, 0x00]).is_err());
    }

    #[test]
    fn control_payload_pool_sync_length_exceeds_data_returns_error() {
        // subtype + length=9999 but no payload bytes
        let mut data = vec![0x12u8];
        data.extend_from_slice(&9999u32.to_le_bytes());
        assert!(ControlPayload::decode(&data).is_err());
    }

    #[test]
    fn control_payload_pool_state_digest_too_short_returns_error() {
        // subtype + 31 bytes — needs 32
        let mut data = vec![0x21u8];
        data.extend_from_slice(&[0xAB; 31]);
        assert!(ControlPayload::decode(&data).is_err());
    }

    #[test]
    fn control_payload_pool_bucket_digests_too_short_returns_error() {
        // only 3 bytes — needs 6 (subtype + u32 len + flag byte)
        assert!(ControlPayload::decode(&[0x22, 0x00, 0x00]).is_err());
    }

    #[test]
    fn control_payload_pool_bucket_digests_length_exceeds_data_returns_error() {
        let mut data = vec![0x22u8];
        data.extend_from_slice(&9999u32.to_le_bytes());
        data.push(0u8); // flag byte present, but payload_len (9999) exceeds actual data
        assert!(ControlPayload::decode(&data).is_err());
    }

    #[test]
    fn control_payload_pool_bucket_digests_zero_length_returns_error() {
        // payload_len = 0 is invalid now: the flag byte alone requires
        // payload_len >= 1.
        let mut data = vec![0x22u8];
        data.extend_from_slice(&0u32.to_le_bytes());
        assert!(ControlPayload::decode(&data).is_err());
    }

    #[test]
    fn control_payload_node_enrollment_too_short_returns_error() {
        // only 8 bytes — needs 9 (subtype + u32 total_len + u32 node_id_len)
        assert!(ControlPayload::decode(&[0x23, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn control_payload_node_enrollment_total_len_exceeds_data_returns_error() {
        let mut data = vec![0x23u8];
        data.extend_from_slice(&9999u32.to_le_bytes()); // total_len far exceeds actual data
        data.extend_from_slice(&0u32.to_le_bytes()); // node_id_len = 0
        assert!(ControlPayload::decode(&data).is_err());
    }

    #[test]
    fn control_payload_node_enrollment_total_len_below_minimum_returns_error() {
        // total_len must be >= 4 + 32 + 8 + 64 = 108 even for an empty node_id.
        let mut data = vec![0x23u8];
        data.extend_from_slice(&10u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        assert!(ControlPayload::decode(&data).is_err());
    }

    #[test]
    fn control_payload_node_enrollment_inconsistent_lengths_returns_error() {
        // total_len says 108 (empty node_id) but node_id_len claims 5 bytes —
        // the two length fields disagree and must be rejected, not misread.
        let mut data = vec![0x23u8];
        data.extend_from_slice(&108u32.to_le_bytes());
        data.extend_from_slice(&5u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 5 + 32 + 8 + 64]);
        assert!(ControlPayload::decode(&data).is_err());
    }

    #[test]
    fn control_payload_u32_len_near_max_returns_error_on_all_targets() {
        // Regression for the 32-bit usize overflow: with `len` near u32::MAX,
        // the old `data.len() < 5 + len` check wrapped on armv7/mipsel
        // (usize == u32), passed, and the `data[5..5+len]` slice panicked —
        // a one-datagram DoS from any authenticated peer. The check must
        // reject with Err on every target width.
        for subtype in [0x12u8, 0x13, 0x14, 0x15] {
            // PoolSync, RouteSync, ChainForward, ClientCert
            for len in [u32::MAX, u32::MAX - 4, u32::MAX - 5] {
                let mut data = vec![subtype];
                data.extend_from_slice(&len.to_le_bytes());
                data.extend_from_slice(&[0u8; 16]);
                assert!(
                    ControlPayload::decode(&data).is_err(),
                    "subtype {subtype:#x} len {len} must be rejected"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Capabilities / MgmtRequest / MgmtResponse (P0.2)
    // -----------------------------------------------------------------------

    #[test]
    fn mgmt_and_caps_roundtrip() {
        let caps = ControlPayload::Capabilities {
            role: 2,
            features: 0,
        };
        assert_eq!(
            ControlPayload::decode(&caps.encode().unwrap()).unwrap(),
            caps
        );

        let req = ControlPayload::MgmtRequest {
            req_id: 7,
            method: 2,
            path: "/api/v1/clients".into(),
            body: vec![1, 2, 3],
        };
        assert_eq!(ControlPayload::decode(&req.encode().unwrap()).unwrap(), req);

        let resp = ControlPayload::MgmtResponse {
            req_id: 7,
            status: 201,
            body: b"{}".to_vec(),
        };
        assert_eq!(
            ControlPayload::decode(&resp.encode().unwrap()).unwrap(),
            resp
        );
    }

    #[test]
    fn mgmt_response_large_body_roundtrips_intact() {
        let body = vec![0xABu8; 40 * 1024];
        let resp = ControlPayload::MgmtResponse {
            req_id: 42,
            status: 200,
            body: body.clone(),
        };
        let encoded = resp.encode().unwrap();
        let decoded = ControlPayload::decode(&encoded).unwrap();
        match decoded {
            ControlPayload::MgmtResponse {
                req_id,
                status,
                body: decoded_body,
            } => {
                assert_eq!(req_id, 42);
                assert_eq!(status, 200);
                assert_eq!(decoded_body, body);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn mgmt_request_rejects_oversized_path_and_body_on_encode() {
        let too_long_path = ControlPayload::MgmtRequest {
            req_id: 1,
            method: 0,
            path: "a".repeat(513),
            body: vec![],
        };
        assert!(too_long_path.encode().is_err());

        let too_long_body = ControlPayload::MgmtRequest {
            req_id: 1,
            method: 0,
            path: "/x".into(),
            body: vec![0u8; 262_145],
        };
        assert!(too_long_body.encode().is_err());
    }

    #[test]
    fn mgmt_request_truncated_bytes_return_error_not_panic() {
        // Well-formed header claiming a path/body that the buffer doesn't
        // actually contain must be rejected, never panic on an out-of-bounds
        // slice.
        let full = ControlPayload::MgmtRequest {
            req_id: 9,
            method: 1,
            path: "/api/v1/status".into(),
            body: vec![9, 9, 9, 9],
        }
        .encode()
        .unwrap();

        // Truncate at every prefix length and assert decode never panics and
        // always returns Err for a genuinely incomplete buffer.
        for cut in 1..full.len() {
            let truncated = &full[..cut];
            let result = std::panic::catch_unwind(|| ControlPayload::decode(truncated));
            assert!(result.is_ok(), "decode panicked at cut={cut}");
            assert!(
                result.unwrap().is_err(),
                "expected Err for truncated MgmtRequest at cut={cut}"
            );
        }

        // Also assert a minimal too-short buffer (just the subtype byte).
        assert!(ControlPayload::decode(&[0x25u8]).is_err());
    }
}
