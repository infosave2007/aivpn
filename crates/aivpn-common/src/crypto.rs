//! Cryptographic primitives for AIVPN
//!
//! Implements:
//! - X25519 key exchange
//! - ChaCha20-Poly1305 AEAD encryption
//! - BLAKE3 hashing and HMAC
//! - Resonance Tag generation

use blake3::Hasher;
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit, OsRng},
    ChaCha20Poly1305, Key as ChachaKey, Nonce,
};
use hmac::Hmac;
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

/// Size of resonance tag in bytes
pub const TAG_SIZE: usize = 8;

/// Size of X25519 public key in bytes
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// Size of X25519 private key in bytes
pub const X25519_PRIVATE_KEY_SIZE: usize = 32;

/// Size of ChaCha20-Poly1305 key in bytes
pub const CHACHA20_KEY_SIZE: usize = 32;

/// Size of Poly1305 tag in bytes
pub const POLY1305_TAG_SIZE: usize = 16;

/// Size of nonce in bytes
pub const NONCE_SIZE: usize = 12;

/// Default time window for tag rotation in milliseconds (optimized: increased from 5s to 10s)
pub const DEFAULT_WINDOW_MS: u64 = 10_000;

/// HKDF context strings
const HKDF_SESSION_KEY_CONTEXT: &str = "aivpn-session-key-v1";
const HKDF_SESSION_KEY_S2C_CONTEXT: &str = "aivpn-session-key-s2c-v1";
const HKDF_TAG_SECRET_CONTEXT: &str = "aivpn-tag-secret-v1";
const HKDF_PRNG_SEED_CONTEXT: &str = "aivpn-prng-seed-v1";

/// Domain-separation contexts for directional peer-link sub-keys (server pool
/// sync, site-to-site, chain forwarding). The lexicographically smaller peer
/// id takes the "client" role: it SENDS with the pair's c2s key and RECEIVES
/// with the s2c key; the larger id does the opposite.
const PEER_DIR_C2S_CONTEXT: &str = "aivpn-peer-dir-c2s-v1";
const PEER_DIR_S2C_CONTEXT: &str = "aivpn-peer-dir-s2c-v1";

/// Domain-separation context for the device-enrollment proof-of-possession
/// (see [`device_enrollment_proof`]). Distinct from every session-key
/// context above so a proof can never be confused with, or substituted for,
/// a session key even though both are derived via BLAKE3 `derive_key` from
/// DH-shaped input.
const DEVICE_ENROLLMENT_PROOF_CONTEXT: &str = "aivpn-device-enrollment-v2";

/// Domain-separation context for the PSK an aivpn server derives from
/// `sync_key` when it dials a pool PEER as a masked pool-client (see
/// [`pool_client_psk`]).
const HKDF_POOL_CLIENT_PSK_CONTEXT: &str = "aivpn-pool-client-psk-v1";
/// Domain-separation context for the pool-wide shared X25519 server static
/// keypair derived from `sync_key` (see [`pool_server_keypair`]).
const HKDF_POOL_SERVER_STATIC_CONTEXT: &str = "aivpn-pool-server-static-v1";

/// Domain-separation context for the canonical `NodeEnrollment` signing
/// message (see [`node_enrollment_signing_bytes`]). Distinct from every other
/// context in this file, so a node-enrollment signature can never be replayed
/// as, or confused with, a signature produced for any other purpose (mask
/// signing, bootstrap descriptors, ServerHello, ...) even if those also use
/// Ed25519 over attacker-influenced bytes.
const NODE_ENROLLMENT_CONTEXT: &str = "aivpn-node-enrollment-v1";

/// Session keys derived from key exchange
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// AEAD key for the client→server (uplink) direction. Named `session_key`
    /// for historical reasons; it is the C2S key.
    ///
    /// Server-to-server peer links (pool sync, site-to-site, chain
    /// forwarding) do NOT share one symmetric key in both directions: each
    /// direction derives its own root via [`derive_directional_peer_keys`]
    /// and builds a separate `SessionKeys` from it, so this field then holds
    /// that one direction's key and the two directions never share a
    /// (key, nonce) space. The kernel offload path mirrors user space:
    /// `session_key` for uplink decrypt, `session_key_s2c` for downlink
    /// encrypt.
    pub session_key: [u8; CHACHA20_KEY_SIZE],
    /// AEAD key for the server→client (downlink) direction. Distinct from
    /// `session_key` so the two directions never share a (key, nonce) pair:
    /// nonces are counter-derived and both directions start their counter at 0
    /// (and reset to 0 on every ratchet/rekey), so a single shared key would
    /// reuse the ChaCha20 keystream across directions — a confidentiality break.
    pub session_key_s2c: [u8; CHACHA20_KEY_SIZE],
    pub tag_secret: [u8; 32],
    pub prng_seed: [u8; 32],
}

/// X25519 keypair for key exchange
///
/// `Debug` is implemented MANUALLY (no derive): a derived `Debug` would print
/// `private_key_bytes`, so any `{:?}` on a struct owning a KeyPair would leak
/// the static private key of the server/device into the logs. The manual impl
/// prints only the public key (mirrors `SessionKeys`, which deliberately has
/// no `Debug` at all).
#[derive(Clone)]
pub struct KeyPair {
    private_key_bytes: [u8; X25519_PRIVATE_KEY_SIZE],
    public_key_bytes: [u8; X25519_PUBLIC_KEY_SIZE],
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key_bytes", &self.public_key_bytes)
            .field("private_key_bytes", &"[redacted]")
            .finish()
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.private_key_bytes.zeroize();
    }
}
impl KeyPair {
    /// Generate a new ephemeral keypair
    pub fn generate() -> Self {
        let mut private_key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut private_key_bytes);

        // X25519 clamping (RFC 7748)
        private_key_bytes[0] &= 248;
        private_key_bytes[31] &= 127;
        private_key_bytes[31] |= 64;

        let public_key_bytes =
            x25519_dalek::x25519(private_key_bytes, x25519_dalek::X25519_BASEPOINT_BYTES);

        Self {
            private_key_bytes,
            public_key_bytes,
        }
    }

    /// Create keypair from existing private key bytes (loaded from file)
    pub fn from_private_key(mut key_bytes: [u8; 32]) -> Self {
        // X25519 clamping (RFC 7748)
        key_bytes[0] &= 248;
        key_bytes[31] &= 127;
        key_bytes[31] |= 64;
        let public_key_bytes =
            x25519_dalek::x25519(key_bytes, x25519_dalek::X25519_BASEPOINT_BYTES);
        Self {
            private_key_bytes: key_bytes,
            public_key_bytes,
        }
    }

    /// Get the public key as bytes
    pub fn public_key_bytes(&self) -> [u8; X25519_PUBLIC_KEY_SIZE] {
        self.public_key_bytes
    }

    /// Export private key bytes for secure persistence (e.g., device.key file).
    pub fn export_private_key(&self) -> [u8; 32] {
        self.private_key_bytes
    }

    /// Compute shared secret with remote public key
    /// Returns error if the result is all-zero (small subgroup attack)
    pub fn compute_shared(&self, remote_public: &[u8; X25519_PUBLIC_KEY_SIZE]) -> Result<[u8; 32]> {
        let shared = x25519_dalek::x25519(self.private_key_bytes, *remote_public);
        // Reject all-zero shared secret (small subgroup / identity point attack)
        if shared.ct_eq(&[0u8; 32]).into() {
            return Err(Error::Crypto(
                "DH result is all-zero (possible small subgroup attack)".into(),
            ));
        }
        Ok(shared)
    }
}

/// Derive session keys from DH result using HKDF-BLAKE3
pub fn derive_session_keys(
    dh_result: &[u8; 32],
    preshared_key: Option<&[u8; 32]>,
    eph_pub: &[u8; X25519_PUBLIC_KEY_SIZE],
) -> SessionKeys {
    // IKM = dh_result || preshared_key (or just dh_result if no PSK)
    let ikm: Vec<u8> = if let Some(psk) = preshared_key {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(dh_result);
        buf[32..].copy_from_slice(psk);
        buf.to_vec()
    } else {
        dh_result.to_vec()
    };

    // Derive keys using BLAKE3 derive_key with different contexts
    // Context strings are combined with key material for domain separation
    let session_key_input: Vec<u8> = [ikm.clone(), eph_pub.to_vec()].concat();
    let tag_secret_input: Vec<u8> = [ikm.clone(), eph_pub.to_vec()].concat();
    let prng_seed_input: Vec<u8> = [ikm, eph_pub.to_vec()].concat();

    let session_key_hash = blake3::derive_key(HKDF_SESSION_KEY_CONTEXT, &session_key_input);
    let session_key_s2c_hash = blake3::derive_key(HKDF_SESSION_KEY_S2C_CONTEXT, &session_key_input);
    let tag_secret_hash = blake3::derive_key(HKDF_TAG_SECRET_CONTEXT, &tag_secret_input);
    let prng_seed_hash = blake3::derive_key(HKDF_PRNG_SEED_CONTEXT, &prng_seed_input);

    SessionKeys {
        session_key: session_key_hash[..CHACHA20_KEY_SIZE].try_into().unwrap(),
        session_key_s2c: session_key_s2c_hash[..CHACHA20_KEY_SIZE]
            .try_into()
            .unwrap(),
        tag_secret: tag_secret_hash[..32].try_into().unwrap(),
        prng_seed: prng_seed_hash[..32].try_into().unwrap(),
    }
}

/// Compute the session-bound device-enrollment proof-of-possession.
///
/// `dh_shared` = X25519(static_priv, peer_static_pub) — the same value on
/// both ends since X25519 is symmetric. The proof additionally binds this
/// session's ephemeral handshake transcript, `server_eph_pub || client_eph_pub`
/// (in that fixed order — both sides MUST hash them in this order, see
/// `ControlPayload::DeviceEnrollment`'s doc comment for the canonical wire
/// meaning), via BLAKE3 `derive_key` under a dedicated domain string. This
/// makes the resulting 32 bytes a single-session value: an observer who
/// captures one valid `dh_proof` off the wire, a log, or a coredump cannot
/// replay it in a *different* session, because that session's ephemeral pair
/// differs and the derived output changes with it. An attacker who has not
/// recovered `static_priv` still cannot forge a valid proof for any session,
/// since `dh_shared` remains the secret input either way.
pub fn device_enrollment_proof(
    dh_shared: &[u8; 32],
    server_eph_pub: &[u8; 32],
    client_eph_pub: &[u8; 32],
) -> [u8; 32] {
    let mut material = Vec::with_capacity(96);
    material.extend_from_slice(dh_shared);
    material.extend_from_slice(server_eph_pub);
    material.extend_from_slice(client_eph_pub);
    blake3::derive_key(DEVICE_ENROLLMENT_PROOF_CONTEXT, &material)
}

/// Derive one directional sub-key of a peer pair.
///
/// `low_id` is length-prefixed so `("ab", "c")` and `("a", "bc")` can never
/// produce identical key material.
fn derive_peer_pair_key(
    context: &str,
    shared_key: &[u8; 32],
    low_id: &str,
    high_id: &str,
) -> [u8; 32] {
    let mut material = Vec::with_capacity(32 + 4 + low_id.len() + high_id.len());
    material.extend_from_slice(shared_key);
    material.extend_from_slice(&(low_id.len() as u32).to_le_bytes());
    material.extend_from_slice(low_id.as_bytes());
    material.extend_from_slice(high_id.as_bytes());
    blake3::derive_key(context, &material)
}

/// Derive directional sub-keys for a symmetric-secret peer link (pool sync,
/// site-to-site, chain forwarding).
///
/// Returns `(send_root, recv_root)` from the LOCAL node's perspective.
/// Roles are assigned deterministically by lexicographic byte order of the
/// two peer identifiers: the smaller id acts as the "client" (sends with the
/// pair's c2s sub-key, receives with s2c), the larger id acts as the
/// "server" (sends s2c, receives c2s). Both peers call this with swapped
/// arguments and the same 32-byte shared key and independently arrive at
/// mirrored results — no handshake needed:
///
/// * `A.send_root == B.recv_root` and `B.send_root == A.recv_root`
/// * `A.send_root != B.send_root` — the two directions never share an AEAD
///   (key, nonce) space even though each node builds nonces from its own
///   independent counter.
///
/// The sub-keys are additionally bound to the (unordered) id pair, so in a
/// pool of 3+ nodes no two links share a key either.
///
/// `local_id` and `peer_id` MUST differ: equal ids would collapse both
/// directions onto one key — with both sides then building AEAD nonces from
/// independent counters starting near the same value, that is ChaCha20
/// (key, nonce) reuse on traffic carrying client PSKs. This fails CLOSED at
/// runtime (`Err`) rather than deriving reused keys; callers must refuse to
/// bring up the peer link.
pub fn derive_directional_peer_keys(
    shared_key: &[u8; 32],
    local_id: &str,
    peer_id: &str,
) -> Result<([u8; 32], [u8; 32])> {
    if local_id == peer_id {
        return Err(Error::Crypto(format!(
            "directional peer keys require distinct peer ids (both are '{}')",
            local_id
        )));
    }
    let local_is_client = local_id < peer_id;
    let (low, high) = if local_is_client {
        (local_id, peer_id)
    } else {
        (peer_id, local_id)
    };
    // c2s = low → high direction; s2c = high → low direction.
    let c2s = derive_peer_pair_key(PEER_DIR_C2S_CONTEXT, shared_key, low, high);
    let s2c = derive_peer_pair_key(PEER_DIR_S2C_CONTEXT, shared_key, low, high);
    Ok(if local_is_client {
        (c2s, s2c)
    } else {
        (s2c, c2s)
    })
}

/// Derive the PSK an aivpn server uses when it dials a pool PEER as a masked
/// pool-client.
///
/// Domain-separated from `sync_key` itself (via BLAKE3 `derive_key` under a
/// dedicated context) and from the directional peer-link keys produced by
/// [`derive_directional_peer_keys`], so this PSK can never be confused with,
/// or substituted for, either of those even though all three are derived from
/// the same 32-byte pool secret.
pub fn pool_client_psk(sync_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(HKDF_POOL_CLIENT_PSK_CONTEXT, sync_key)
}

/// Derive the single pool-wide X25519 server identity every pool node
/// shares (all hold the same `sync_key`).
///
/// A dialing node uses `.public_key_bytes()` of the returned keypair as the
/// peer's `server_public_key` for the masked handshake; the receiving server
/// uses this same keypair to unmask the client ephemeral public key and
/// compute the DH shared secret for the pool-client handshake candidate.
///
/// This works because the trust model for a pool is a single-operator
/// trusted pool (all nodes hold the shared symmetric `sync_key`), so a
/// shared server identity across the whole pool is acceptable — every node
/// derives the identical keypair from `sync_key` and can act as "the" pool
/// server for any peer that dials it. Mutual-distrust, per-node server
/// identities are a possible future extension but are not required by the
/// current trust model.
pub fn pool_server_keypair(sync_key: &[u8; 32]) -> KeyPair {
    let seed = blake3::derive_key(HKDF_POOL_SERVER_STATIC_CONTEXT, sync_key);
    KeyPair::from_private_key(seed)
}

/// Derive a pool node's long-term Ed25519 identity keypair from a 32-byte
/// seed.
///
/// This is the node's durable proof-of-identity key — distinct from any
/// session-scoped X25519 ephemeral key and from the pool-wide shared
/// `pool_server_keypair`. Its `verifying_key().to_bytes()` output is the
/// `node_pub` a peer PINS to a `node_id` the first time it sees a valid
/// [`verify_node_enrollment`] proof for that pair (Phase 4 TOFU / operator
/// manual-approval), so a later impostor who merely knows (or guesses) the
/// `node_id` string cannot re-assert it without also holding this seed.
///
/// Deterministic: the same seed always yields the same keypair, so an
/// operator can persist just the 32-byte seed (e.g. in server config) rather
/// than a full expanded Ed25519 secret key.
pub fn node_identity_from_seed(seed: &[u8; 32]) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(seed)
}

/// Build the canonical, unambiguous byte string a pool node signs (and a
/// peer reconstructs to verify) to prove ownership of `node_id` bound to
/// `node_pub`, for a given `time_window` (see [`compute_time_window`]),
/// SESSION-BOUND to `server_eph_pub || client_eph_pub` — the masked
/// pool-peer session's ephemeral handshake transcript.
///
/// Wire framing (all fields concatenated in this fixed order):
/// 1. `NODE_ENROLLMENT_CONTEXT` bytes ("aivpn-node-enrollment-v1") — domain
///    separation, so this message can never collide with signing input built
///    for any other purpose.
/// 2. `node_id` length-prefixed as 4 bytes little-endian `u32`, followed by
///    the UTF-8 `node_id` bytes themselves. The length prefix — not a
///    delimiter byte — makes the framing unambiguous: without it, ids like
///    `("ab", "c")` and `("a", "bc")` could concatenate to identical bytes
///    once `node_pub`/`time_window` are appended (mirrors the length-prefix
///    reasoning already used by [`derive_peer_pair_key`]).
/// 3. The raw 32 `node_pub` bytes.
/// 4. `time_window` as 8 bytes little-endian `u64` — binds the proof to a
///    coarse time slice so a captured enrollment message cannot be replayed
///    indefinitely (mirrors the resonance-tag time-window pattern).
/// 5. The raw 32 `server_eph_pub` bytes, then the raw 32 `client_eph_pub`
///    bytes (in that fixed order) — this session's ephemeral X25519
///    handshake transcript. Both sides of a masked pool-peer session know
///    both values without either needing to be sent on the wire: the server
///    generates `server_eph_pub` and learns `client_eph_pub` from the
///    handshake it received; the dialing client learns `server_eph_pub` from
///    `ServerHello` and already knows its own `client_eph_pub`. Binding the
///    proof to this pair makes a captured, otherwise-valid
///    `(node_id, node_pub, time_window, signature)` tuple useless if replayed
///    onto a DIFFERENT masked pool-peer session — that session's transcript
///    differs, so the reconstructed message (and therefore the signature
///    check) no longer matches. This mirrors
///    [`device_enrollment_proof`]'s session-binding scheme for the same
///    reason: a time-window alone only bounds replay to a ~2-minute wall-
///    clock slice, not to one session.
///
/// This function is deterministic and produces identical output for
/// identical inputs on both the signer and the verifier.
pub fn node_enrollment_signing_bytes(
    node_id: &str,
    node_pub: &[u8; 32],
    time_window: u64,
    server_eph_pub: &[u8; 32],
    client_eph_pub: &[u8; 32],
) -> Vec<u8> {
    let ctx_bytes = NODE_ENROLLMENT_CONTEXT.as_bytes();
    let node_id_bytes = node_id.as_bytes();
    let mut material =
        Vec::with_capacity(ctx_bytes.len() + 4 + node_id_bytes.len() + 32 + 8 + 32 + 32);
    material.extend_from_slice(ctx_bytes);
    material.extend_from_slice(&(node_id_bytes.len() as u32).to_le_bytes());
    material.extend_from_slice(node_id_bytes);
    material.extend_from_slice(node_pub);
    material.extend_from_slice(&time_window.to_le_bytes());
    material.extend_from_slice(server_eph_pub);
    material.extend_from_slice(client_eph_pub);
    material
}

/// Verify a `NodeEnrollment` proof: that the holder of the Ed25519 private
/// key corresponding to `node_pub` signed
/// `(node_id, node_pub, time_window, server_eph_pub, client_eph_pub)` via
/// [`node_enrollment_signing_bytes`] — i.e. that the proof is valid AND was
/// produced for THIS session's ephemeral transcript, not replayed from a
/// different one.
///
/// Returns `false` — never panics — for a malformed `node_pub` (bytes that
/// are not a valid Ed25519 point) or a signature that fails verification, so
/// callers can treat this as a plain boolean gate without a `Result` match
/// for the "attacker-controlled bytes on the wire" case.
pub fn verify_node_enrollment(
    node_pub: &[u8; 32],
    node_id: &str,
    time_window: u64,
    signature: &[u8; 64],
    server_eph_pub: &[u8; 32],
    client_eph_pub: &[u8; 32],
) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};

    let vk = match VerifyingKey::from_bytes(node_pub) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let message = node_enrollment_signing_bytes(
        node_id,
        node_pub,
        time_window,
        server_eph_pub,
        client_eph_pub,
    );
    let sig = Signature::from_bytes(signature);
    // `verify_strict` rejects small-order / non-canonical verifying keys (e.g.
    // the all-zero point) — both a stricter security posture for node identity
    // and a fail-closed guard against a peer presenting a degenerate node_pub.
    vk.verify_strict(&message, &sig).is_ok()
}

/// Encrypt payload into a caller-owned buffer using ChaCha20-Poly1305.
///
/// This is the allocation-free variant of [`encrypt_payload`]: it clears `out`,
/// copies `plaintext` into it, and encrypts in place, appending the 16-byte
/// Poly1305 tag. On success `out` holds `plaintext.len() + POLY1305_TAG_SIZE`
/// bytes — byte-for-byte identical to what [`encrypt_payload`] returns.
///
/// Reusing the same `out` across calls avoids a heap allocation per packet on
/// the server's hot path. A dirty (non-empty) `out` is handled correctly
/// because it is cleared first.
///
/// On AEAD failure `out` is cleared (never left holding partial ciphertext).
pub fn encrypt_payload_into(
    key: &[u8; CHACHA20_KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    let cipher = ChaCha20Poly1305::new(ChachaKey::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    out.clear();
    out.extend_from_slice(plaintext);
    if let Err(e) = cipher.encrypt_in_place(nonce, b"", out) {
        out.clear();
        return Err(e.into());
    }
    Ok(())
}

/// Encrypt payload using ChaCha20-Poly1305
pub fn encrypt_payload(
    key: &[u8; CHACHA20_KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(plaintext.len() + POLY1305_TAG_SIZE);
    encrypt_payload_into(key, nonce, plaintext, &mut out)?;
    Ok(out)
}

/// Decrypt payload into a caller-owned buffer using ChaCha20-Poly1305.
///
/// Allocation-free variant of [`decrypt_payload`]: clears `out`, copies
/// `ciphertext` into it, and decrypts in place, truncating away the Poly1305
/// tag. On success `out` holds the recovered plaintext — identical to what
/// [`decrypt_payload`] returns.
///
/// On AEAD failure (bad tag / wrong key) `out` is cleared so no partial or
/// unauthenticated plaintext is exposed to the caller.
pub fn decrypt_payload_into(
    key: &[u8; CHACHA20_KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    let cipher = ChaCha20Poly1305::new(ChachaKey::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    out.clear();
    out.extend_from_slice(ciphertext);
    if let Err(e) = cipher.decrypt_in_place(nonce, b"", out) {
        out.clear();
        return Err(e.into());
    }
    Ok(())
}

/// Decrypt payload using ChaCha20-Poly1305
pub fn decrypt_payload(
    key: &[u8; CHACHA20_KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(ciphertext.len());
    decrypt_payload_into(key, nonce, ciphertext, &mut out)?;
    Ok(out)
}

/// Generate Resonance Tag using HMAC-BLAKE3
///
/// Tag = HMAC-BLAKE3(tag_secret, counter_bytes || time_window_bytes)
/// truncated to first 8 bytes.
/// The first byte is guaranteed NOT to be 1–4 (WireGuard message types),
/// preventing heuristic WireGuard detection by Wireshark / DPI (Issue #30).
pub fn generate_resonance_tag(
    tag_secret: &[u8; 32],
    counter: u64,
    time_window: u64,
) -> [u8; TAG_SIZE] {
    let mut hasher = Hasher::new_keyed(tag_secret);
    hasher.update(&counter.to_le_bytes());
    hasher.update(&time_window.to_le_bytes());

    let hash = hasher.finalize();
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&hash.as_bytes()[..TAG_SIZE]);
    // Avoid WireGuard message type signatures: 0x01 (Initiation), 0x02 (Response),
    // 0x03 (Cookie), 0x04 (Transport).  DPI/Wireshark checks byte[0] ∈ {1..4}
    // followed by three zero bytes.  Shifting byte[0] out of that range eliminates
    // the heuristic match without reducing tag entropy (the secret is still 256-bit).
    if tag[0] >= 1 && tag[0] <= 4 {
        tag[0] = tag[0].wrapping_add(5); // 1→6, 2→7, 3→8, 4→9
    }
    tag
}

/// Compute time window from timestamp
pub fn compute_time_window(timestamp_ms: u64, window_ms: u64) -> u64 {
    timestamp_ms / window_ms
}

/// Get current timestamp in milliseconds
pub fn current_timestamp_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Generate random bytes
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Compute BLAKE3 hash
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

/// Obfuscate/deobfuscate ephemeral public key using server's static public key.
/// XOR with BLAKE3-derived mask makes eph_pub indistinguishable from random. (HIGH-9)
pub fn obfuscate_eph_pub(eph_pub: &mut [u8; 32], server_static_pub: &[u8; 32]) {
    let mask = blake3::derive_key("aivpn-eph-obfuscation-v1", server_static_pub);
    for i in 0..32 {
        eph_pub[i] ^= mask[i];
    }
}

/// Compute HMAC-SHA256
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::Mac;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.finalize();
    result.into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() {
        let client_keys = KeyPair::generate();
        let server_keys = KeyPair::generate();

        let client_shared = client_keys
            .compute_shared(&server_keys.public_key_bytes())
            .unwrap();
        let server_shared = server_keys
            .compute_shared(&client_keys.public_key_bytes())
            .unwrap();

        assert_eq!(client_shared, server_shared);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = [1u8; CHACHA20_KEY_SIZE];
        let nonce = [2u8; NONCE_SIZE];
        let plaintext = b"Hello, AIVPN!";

        let ciphertext = encrypt_payload(&key, &nonce, plaintext).unwrap();
        let decrypted = decrypt_payload(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypt_into_matches_allocating() {
        let key = [9u8; CHACHA20_KEY_SIZE];
        let nonce = [4u8; NONCE_SIZE];
        let plaintext = b"in-place equals allocating output";

        let expected = encrypt_payload(&key, &nonce, plaintext).unwrap();

        let mut out = Vec::new();
        encrypt_payload_into(&key, &nonce, plaintext, &mut out).unwrap();
        assert_eq!(out, expected);
        assert_eq!(out.len(), plaintext.len() + POLY1305_TAG_SIZE);
    }

    #[test]
    fn test_decrypt_into_matches_allocating() {
        let key = [9u8; CHACHA20_KEY_SIZE];
        let nonce = [4u8; NONCE_SIZE];
        let plaintext = b"in-place decrypt round-trip";

        let ciphertext = encrypt_payload(&key, &nonce, plaintext).unwrap();

        let mut out = Vec::new();
        decrypt_payload_into(&key, &nonce, &ciphertext, &mut out).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn test_into_roundtrip_with_dirty_reused_buffers() {
        let key = [11u8; CHACHA20_KEY_SIZE];
        let nonce = [5u8; NONCE_SIZE];

        // Pre-fill both buffers with junk to prove they are cleared first and
        // reuse across calls yields correct results (the pooled-buffer case).
        let mut ct_buf = vec![0xAAu8; 4096];
        let mut pt_buf = vec![0xBBu8; 4096];

        for msg in [b"first message".as_slice(), b"second, longer message!!"] {
            encrypt_payload_into(&key, &nonce, msg, &mut ct_buf).unwrap();
            assert_eq!(ct_buf.len(), msg.len() + POLY1305_TAG_SIZE);
            assert_eq!(ct_buf, encrypt_payload(&key, &nonce, msg).unwrap());

            decrypt_payload_into(&key, &nonce, &ct_buf, &mut pt_buf).unwrap();
            assert_eq!(pt_buf, msg);
        }
    }

    #[test]
    fn test_decrypt_into_wrong_key_clears_out() {
        let key = [1u8; CHACHA20_KEY_SIZE];
        let wrong_key = [2u8; CHACHA20_KEY_SIZE];
        let nonce = [0u8; NONCE_SIZE];

        let ciphertext = encrypt_payload(&key, &nonce, b"authenticated").unwrap();

        let mut out = vec![0x77u8; 128];
        let result = decrypt_payload_into(&wrong_key, &nonce, &ciphertext, &mut out);
        assert!(result.is_err());
        // No unauthenticated plaintext must survive in the buffer.
        assert!(out.is_empty());
    }

    #[test]
    fn test_resonance_tag() {
        let tag_secret = [3u8; 32];
        let tag1 = generate_resonance_tag(&tag_secret, 1, 100);
        let tag2 = generate_resonance_tag(&tag_secret, 2, 100);
        let tag3 = generate_resonance_tag(&tag_secret, 1, 100);

        assert_ne!(tag1, tag2); // Different counter
        assert_eq!(tag1, tag3); // Same counter and window
    }

    #[test]
    fn test_decrypt_wrong_key_returns_err() {
        let key = [1u8; CHACHA20_KEY_SIZE];
        let wrong_key = [2u8; CHACHA20_KEY_SIZE];
        let nonce = [0u8; NONCE_SIZE];
        let plaintext = b"secret data";

        let ciphertext = encrypt_payload(&key, &nonce, plaintext).unwrap();
        let result = decrypt_payload(&wrong_key, &nonce, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn test_resonance_tag_deterministic() {
        let tag_secret = [7u8; 32];
        let counter = 42u64;
        let window = 5000u64;

        let tag_a = generate_resonance_tag(&tag_secret, counter, window);
        let tag_b = generate_resonance_tag(&tag_secret, counter, window);

        assert_eq!(tag_a, tag_b);
        assert_eq!(tag_a.len(), TAG_SIZE);
    }

    #[test]
    fn test_resonance_tag_changes_with_counter() {
        let tag_secret = [9u8; 32];
        let window = 1000u64;

        let tags: Vec<_> = (0u64..4)
            .map(|c| generate_resonance_tag(&tag_secret, c, window))
            .collect();

        // All four tags must be distinct
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert_ne!(tags[i], tags[j], "tags[{i}] == tags[{j}]");
            }
        }
    }

    #[test]
    fn test_hmac_sha256_deterministic() {
        let key = b"test-hmac-key";
        let data = b"test-data";

        let mac1 = hmac_sha256(key, data);
        let mac2 = hmac_sha256(key, data);

        assert_eq!(mac1, mac2);
        assert_eq!(mac1.len(), 32);
    }

    #[test]
    fn test_hmac_sha256_different_keys_differ() {
        let data = b"same-data";
        let mac1 = hmac_sha256(b"key-one", data);
        let mac2 = hmac_sha256(b"key-two", data);

        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_derive_session_keys_deterministic() {
        let dh = [0xabu8; 32];
        let psk = [0xcdu8; 32];
        let eph_pub = [0xefu8; X25519_PUBLIC_KEY_SIZE];

        let keys1 = derive_session_keys(&dh, Some(&psk), &eph_pub);
        let keys2 = derive_session_keys(&dh, Some(&psk), &eph_pub);

        assert_eq!(keys1.session_key, keys2.session_key);
        assert_eq!(keys1.tag_secret, keys2.tag_secret);
        assert_eq!(keys1.prng_seed, keys2.prng_seed);
    }

    #[test]
    fn device_enrollment_proof_is_deterministic_for_same_transcript() {
        let dh_shared = [0x11u8; 32];
        let server_eph = [0x22u8; 32];
        let client_eph = [0x33u8; 32];

        let proof1 = device_enrollment_proof(&dh_shared, &server_eph, &client_eph);
        let proof2 = device_enrollment_proof(&dh_shared, &server_eph, &client_eph);
        assert_eq!(
            proof1, proof2,
            "same (dh_shared, transcript) must reproduce the same proof"
        );
    }

    #[test]
    fn device_enrollment_proof_rejects_cross_session_replay() {
        // A proof correctly built for session A's ephemeral transcript must
        // NOT verify against session B's transcript, even with the identical
        // static-key DH secret — this is the whole point of the hardening:
        // an observed proof cannot be replayed into a different session.
        let dh_shared = [0x44u8; 32];
        let server_a = [0x55u8; 32];
        let client_a = [0x66u8; 32];
        let server_b = [0x77u8; 32];
        let client_b = [0x88u8; 32];

        let proof_for_a = device_enrollment_proof(&dh_shared, &server_a, &client_a);
        let proof_for_b = device_enrollment_proof(&dh_shared, &server_b, &client_b);
        assert_ne!(
            proof_for_a, proof_for_b,
            "proofs for different session transcripts must differ"
        );

        // Recomputing what session B expects must not match A's proof.
        let expected_for_b = device_enrollment_proof(&dh_shared, &server_b, &client_b);
        assert_ne!(
            proof_for_a, expected_for_b,
            "replaying session A's proof into session B must fail verification"
        );
    }

    #[test]
    fn device_enrollment_proof_transcript_order_matters() {
        // server_eph_pub || client_eph_pub must NOT equal
        // client_eph_pub || server_eph_pub — verifies both ends really need
        // to agree on byte order, not just on the pair of values.
        let dh_shared = [0x99u8; 32];
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];
        let forward = device_enrollment_proof(&dh_shared, &a, &b);
        let reversed = device_enrollment_proof(&dh_shared, &b, &a);
        assert_ne!(
            forward, reversed,
            "transcript byte order must be significant"
        );
    }

    #[test]
    fn device_enrollment_proof_differs_from_legacy_raw_dh() {
        // The legacy (pre-hardening) scheme sent the bare DH result as the
        // proof. The new scheme must not collapse back to that value, or a
        // captured legacy proof would trivially double as a valid new-scheme
        // proof for an attacker-chosen transcript.
        let dh_shared = [0xCCu8; 32];
        let server_eph = [0xDDu8; 32];
        let client_eph = [0xEEu8; 32];
        let proof = device_enrollment_proof(&dh_shared, &server_eph, &client_eph);
        assert_ne!(
            proof, dh_shared,
            "transcript-bound proof must not equal the raw legacy DH value"
        );
    }

    #[test]
    fn test_directional_peer_keys_mirror_across_roles() {
        let shared = [0x55u8; 32];
        // "a" < "b": a is the client role, b is the server role.
        let (a_send, a_recv) = derive_directional_peer_keys(&shared, "a:443", "b:443").unwrap();
        let (b_send, b_recv) = derive_directional_peer_keys(&shared, "b:443", "a:443").unwrap();

        // Each side's send key is the other side's recv key.
        assert_eq!(a_send, b_recv);
        assert_eq!(b_send, a_recv);
        // The two directions never share a key.
        assert_ne!(a_send, b_send);
        // And neither equals the raw shared key.
        assert_ne!(a_send, shared);
        assert_ne!(b_send, shared);
    }

    #[test]
    fn test_directional_peer_keys_bound_to_pair() {
        let shared = [0x66u8; 32];
        // Same role (client) on two different links must yield different keys,
        // otherwise two "client" senders in a 3-node pool would collide.
        let (ab_send, _) = derive_directional_peer_keys(&shared, "a", "b").unwrap();
        let (ac_send, _) = derive_directional_peer_keys(&shared, "a", "c").unwrap();
        assert_ne!(ab_send, ac_send);
    }

    #[test]
    fn test_directional_peer_keys_equal_ids_fail_closed() {
        // Equal ids would collapse both directions onto one key with both
        // counters starting near the same value → (key, nonce) reuse. The
        // primitive must refuse at runtime, not just debug_assert.
        let shared = [0x88u8; 32];
        assert!(derive_directional_peer_keys(&shared, "node-1", "node-1").is_err());
        assert!(derive_directional_peer_keys(&shared, "", "").is_err());
    }

    #[test]
    fn test_directional_peer_keys_length_prefix_disambiguates() {
        let shared = [0x77u8; 32];
        // ("ab","c") vs ("a","bc") concatenate to the same bytes — the length
        // prefix must keep them distinct.
        let (k1, _) = derive_directional_peer_keys(&shared, "ab", "c").unwrap();
        let (k2, _) = derive_directional_peer_keys(&shared, "a", "bc").unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_derive_session_keys_psk_changes_output() {
        let dh = [0x11u8; 32];
        let eph_pub = [0x22u8; X25519_PUBLIC_KEY_SIZE];

        let with_psk = derive_session_keys(&dh, Some(&[0x33u8; 32]), &eph_pub);
        let without_psk = derive_session_keys(&dh, None, &eph_pub);

        assert_ne!(with_psk.session_key, without_psk.session_key);
    }

    #[test]
    fn test_pool_client_psk_deterministic_and_domain_separated() {
        let sync_key = [0x42u8; 32];

        let psk1 = pool_client_psk(&sync_key);
        let psk2 = pool_client_psk(&sync_key);
        assert_eq!(psk1, psk2, "pool_client_psk must be deterministic");

        // Must not collapse back to the raw sync_key.
        assert_ne!(psk1, sync_key);

        // Must be domain-separated from the directional peer-link keys
        // derived from the same secret.
        let (send, recv) = derive_directional_peer_keys(&sync_key, "node-a", "node-b").unwrap();
        assert_ne!(psk1, send);
        assert_ne!(psk1, recv);
    }

    #[test]
    fn test_pool_client_psk_differs_across_sync_keys() {
        let sync_key_a = [0x11u8; 32];
        let sync_key_b = [0x22u8; 32];

        let psk_a = pool_client_psk(&sync_key_a);
        let psk_b = pool_client_psk(&sync_key_b);
        assert_ne!(psk_a, psk_b);
    }

    #[test]
    fn test_pool_server_keypair_deterministic() {
        let sync_key = [0x77u8; 32];

        let kp1 = pool_server_keypair(&sync_key);
        let kp2 = pool_server_keypair(&sync_key);

        assert_eq!(
            kp1.public_key_bytes(),
            kp2.public_key_bytes(),
            "pool_server_keypair must derive the same identity from the same sync_key"
        );
    }

    #[test]
    fn test_pool_server_keypair_differs_across_sync_keys() {
        let sync_key_a = [0x99u8; 32];
        let sync_key_b = [0xAAu8; 32];

        let kp_a = pool_server_keypair(&sync_key_a);
        let kp_b = pool_server_keypair(&sync_key_b);

        assert_ne!(kp_a.public_key_bytes(), kp_b.public_key_bytes());
    }

    #[test]
    fn test_pool_server_keypair_dh_roundtrip_with_client_ephemeral() {
        // This is exactly what the masked pool-client handshake relies on:
        // the dialing node's ephemeral key and the pool-wide server static
        // key must agree on the same shared secret via X25519 symmetry.
        let sync_key = [0xBBu8; 32];
        let server_kp = pool_server_keypair(&sync_key);
        let client_eph = KeyPair::generate();

        let client_side = client_eph
            .compute_shared(&server_kp.public_key_bytes())
            .unwrap();
        let server_side = server_kp
            .compute_shared(&client_eph.public_key_bytes())
            .unwrap();

        assert_eq!(client_side, server_side);
    }

    /// Fixed test transcript — an arbitrary but consistent
    /// (server_eph_pub, client_eph_pub) pair used by every test below that
    /// doesn't specifically exercise the transcript-binding property itself.
    const TEST_SERVER_EPH: [u8; 32] = [0xE1u8; 32];
    const TEST_CLIENT_EPH: [u8; 32] = [0xE2u8; 32];

    #[test]
    fn test_node_enrollment_verifies_valid_signature() {
        use ed25519_dalek::Signer;

        let seed = [0x01u8; 32];
        let signing_key = node_identity_from_seed(&seed);
        let node_pub = signing_key.verifying_key().to_bytes();
        let node_id = "node-alpha";
        let time_window = 12345u64;

        let msg = node_enrollment_signing_bytes(
            node_id,
            &node_pub,
            time_window,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        let signature = signing_key.sign(&msg).to_bytes();

        assert!(verify_node_enrollment(
            &node_pub,
            node_id,
            time_window,
            &signature,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        ));
    }

    #[test]
    fn test_node_enrollment_rejects_tampered_node_id() {
        use ed25519_dalek::Signer;

        let seed = [0x02u8; 32];
        let signing_key = node_identity_from_seed(&seed);
        let node_pub = signing_key.verifying_key().to_bytes();
        let time_window = 100u64;

        let msg = node_enrollment_signing_bytes(
            "original-id",
            &node_pub,
            time_window,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        let signature = signing_key.sign(&msg).to_bytes();

        assert!(!verify_node_enrollment(
            &node_pub,
            "tampered-id",
            time_window,
            &signature,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        ));
    }

    #[test]
    fn test_node_enrollment_rejects_tampered_time_window() {
        use ed25519_dalek::Signer;

        let seed = [0x03u8; 32];
        let signing_key = node_identity_from_seed(&seed);
        let node_pub = signing_key.verifying_key().to_bytes();
        let node_id = "node-beta";

        let msg = node_enrollment_signing_bytes(
            node_id,
            &node_pub,
            1000,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        let signature = signing_key.sign(&msg).to_bytes();

        assert!(!verify_node_enrollment(
            &node_pub,
            node_id,
            1001,
            &signature,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        ));
    }

    #[test]
    fn test_node_enrollment_rejects_tampered_node_pub() {
        use ed25519_dalek::Signer;

        let seed = [0x04u8; 32];
        let signing_key = node_identity_from_seed(&seed);
        let node_pub = signing_key.verifying_key().to_bytes();
        let node_id = "node-gamma";
        let time_window = 55u64;

        let msg = node_enrollment_signing_bytes(
            node_id,
            &node_pub,
            time_window,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        let signature = signing_key.sign(&msg).to_bytes();

        // A different node_pub than the one actually signed for must fail,
        // even with a byte-valid Ed25519 point.
        let other_signing_key = node_identity_from_seed(&[0x05u8; 32]);
        let other_pub = other_signing_key.verifying_key().to_bytes();

        assert!(!verify_node_enrollment(
            &other_pub,
            node_id,
            time_window,
            &signature,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        ));
    }

    #[test]
    fn test_node_enrollment_rejects_tampered_signature() {
        use ed25519_dalek::Signer;

        let seed = [0x06u8; 32];
        let signing_key = node_identity_from_seed(&seed);
        let node_pub = signing_key.verifying_key().to_bytes();
        let node_id = "node-delta";
        let time_window = 7u64;

        let msg = node_enrollment_signing_bytes(
            node_id,
            &node_pub,
            time_window,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        let mut signature = signing_key.sign(&msg).to_bytes();
        signature[0] ^= 0xFF;

        assert!(!verify_node_enrollment(
            &node_pub,
            node_id,
            time_window,
            &signature,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        ));
    }

    #[test]
    fn test_node_enrollment_rejects_different_nodes_key() {
        use ed25519_dalek::Signer;

        let node_id = "node-epsilon";
        let time_window = 9u64;

        let key_a = node_identity_from_seed(&[0x07u8; 32]);
        let pub_a = key_a.verifying_key().to_bytes();
        let key_b = node_identity_from_seed(&[0x08u8; 32]);
        let pub_b = key_b.verifying_key().to_bytes();

        // Sign the message that claims to be for pub_a's key, but actually
        // sign it with node B's private key (an impostor asserting A's identity).
        let msg = node_enrollment_signing_bytes(
            node_id,
            &pub_a,
            time_window,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        let forged_signature = key_b.sign(&msg).to_bytes();

        assert!(!verify_node_enrollment(
            &pub_a,
            node_id,
            time_window,
            &forged_signature,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        ));

        // Sanity: node B's own key over its own pub does verify.
        let msg_b = node_enrollment_signing_bytes(
            node_id,
            &pub_b,
            time_window,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        let sig_b = key_b.sign(&msg_b).to_bytes();
        assert!(verify_node_enrollment(
            &pub_b,
            node_id,
            time_window,
            &sig_b,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        ));
    }

    #[test]
    fn test_node_enrollment_malformed_node_pub_returns_false_not_panic() {
        // All-zero bytes and other non-canonical byte strings are not
        // guaranteed to be a valid Ed25519 point; verify_node_enrollment must
        // fail closed rather than panic.
        let malformed_pub = [0u8; 32];
        let node_id = "node-zero";
        let time_window = 1u64;
        let signature = [0u8; 64];

        assert!(!verify_node_enrollment(
            &malformed_pub,
            node_id,
            time_window,
            &signature,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        ));

        // 0xFF-filled bytes are also not a canonical compressed point.
        let malformed_pub2 = [0xFFu8; 32];
        assert!(!verify_node_enrollment(
            &malformed_pub2,
            node_id,
            time_window,
            &signature,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        ));
    }

    #[test]
    fn test_node_enrollment_signing_bytes_deterministic_and_length_prefixed() {
        let node_pub = [0xAAu8; 32];
        let msg1 = node_enrollment_signing_bytes(
            "node-x",
            &node_pub,
            42,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        let msg2 = node_enrollment_signing_bytes(
            "node-x",
            &node_pub,
            42,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        assert_eq!(msg1, msg2, "signing bytes must be deterministic");

        // Length-prefix disambiguation: ("ab","c"...) style concatenation
        // collision must not occur once node_pub/time_window differ in
        // position due to the prefix — different node_id strings that would
        // naively concatenate the same way must produce different messages.
        let msg_a =
            node_enrollment_signing_bytes("ab", &node_pub, 42, &TEST_SERVER_EPH, &TEST_CLIENT_EPH);
        let msg_b =
            node_enrollment_signing_bytes("a", &node_pub, 42, &TEST_SERVER_EPH, &TEST_CLIENT_EPH);
        assert_ne!(msg_a, msg_b);
    }

    /// B2/D2 fix — the core anti-replay property: a `NodeEnrollment` proof
    /// captured off one masked pool-peer session must NOT verify when
    /// replayed onto a DIFFERENT session, even with the exact same
    /// `(node_id, node_pub, time_window, signature)` tuple. Before this fix,
    /// `verify_node_enrollment` had no session-transcript input at all, so a
    /// captured valid enrollment tuple verified identically regardless of
    /// which masked pool-peer session it was replayed on — letting an
    /// attacker who observes one peer's enrollment steal its verified node
    /// identity on a session with a different peer.
    #[test]
    fn test_node_enrollment_rejects_cross_session_replay() {
        use ed25519_dalek::Signer;

        let seed = [0x09u8; 32];
        let signing_key = node_identity_from_seed(&seed);
        let node_pub = signing_key.verifying_key().to_bytes();
        let node_id = "node-zeta";
        let time_window = 4242u64;

        let session_a_server_eph = [0x11u8; 32];
        let session_a_client_eph = [0x22u8; 32];
        let msg = node_enrollment_signing_bytes(
            node_id,
            &node_pub,
            time_window,
            &session_a_server_eph,
            &session_a_client_eph,
        );
        let signature = signing_key.sign(&msg).to_bytes();

        // Verifies under the transcript it was signed for.
        assert!(verify_node_enrollment(
            &node_pub,
            node_id,
            time_window,
            &signature,
            &session_a_server_eph,
            &session_a_client_eph,
        ));

        // The exact same tuple replayed onto a session with a different
        // transcript (different server_eph_pub AND/OR client_eph_pub) must
        // be rejected.
        let session_b_server_eph = [0x33u8; 32];
        let session_b_client_eph = [0x44u8; 32];
        assert!(!verify_node_enrollment(
            &node_pub,
            node_id,
            time_window,
            &signature,
            &session_b_server_eph,
            &session_b_client_eph,
        ));

        // Even a one-sided mismatch (only the client_eph_pub differs, as
        // would happen if an attacker dials the SAME server with a fresh
        // ephemeral key while replaying a captured proof) must fail too.
        assert!(!verify_node_enrollment(
            &node_pub,
            node_id,
            time_window,
            &signature,
            &session_a_server_eph,
            &session_b_client_eph,
        ));
    }
}
