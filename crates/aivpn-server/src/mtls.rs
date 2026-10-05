//! Mutual TLS-style certificate layer (mTLS-lite).
//!
//! Adds optional client certificate authentication on top of the existing
//! PSK + X25519 handshake without breaking backward compatibility.
//!
//! ## Certificate format
//! A certificate is a compact, ed25519-signed token:
//!
//! ```text
//! struct SimpleCert {
//!     client_pub_key: [u8; 32],  // X25519 client ephemeral key
//!     expiry_ts:      [u8;  8],  // LE u64 — Unix seconds
//!     ca_signature:   [u8; 64],  // ed25519 over (client_pub_key || expiry_ts)
//! }
//! ```
//! Total: 104 bytes, sent in `ControlPayload::ClientCert` after session setup.
//!
//! ## CA key management
//! Generate a CA key pair (offline):
//! ```bash
//! aivpn-server --gen-ca            # prints ca_public_key_hex + ca_private_key_hex
//! aivpn-server --issue-cert <hex>  # signs a client public key, prints cert_hex
//! ```
//!
//! ## server.json
//! ```json
//! {
//!   "mtls": {
//!     "ca_public_key_hex": "aabbcc...",
//!     "required": false
//!   }
//! }
//! ```
//! `required: false` (default) — PSK-only clients are still accepted; cert is
//! verified when present.  `required: true` — clients without a valid cert are
//! rejected after the initial handshake.

use serde::{Deserialize, Serialize};
use tracing::debug;

use aivpn_common::crypto::current_timestamp_ms;

/// Raw byte length of a `SimpleCert`.
pub const CERT_SIZE: usize = 104; // 32 + 8 + 64

/// Decoded client certificate.
#[derive(Debug, Clone)]
pub struct SimpleCert {
    /// Client X25519 public key the cert is bound to.
    pub client_pub_key: [u8; 32],
    /// Expiry — Unix timestamp in seconds.
    pub expiry_ts: u64,
    /// ed25519 signature from the CA over `(client_pub_key || expiry_ts_le)`.
    pub ca_signature: [u8; 64],
}

/// mTLS configuration (`"mtls"` block in `server.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtlsConfig {
    /// Hex-encoded 32-byte ed25519 CA public key used to verify client certs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_public_key_hex: Option<String>,
    /// When `true`, clients without a valid cert are rejected.
    /// When `false` (default), PSK-only clients are still accepted.
    #[serde(default)]
    pub required: bool,
}

impl SimpleCert {
    /// Parse a 104-byte raw certificate.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != CERT_SIZE {
            return None;
        }
        let mut client_pub_key = [0u8; 32];
        let mut expiry_bytes = [0u8; 8];
        let mut ca_signature = [0u8; 64];
        client_pub_key.copy_from_slice(&bytes[..32]);
        expiry_bytes.copy_from_slice(&bytes[32..40]);
        ca_signature.copy_from_slice(&bytes[40..104]);
        Some(Self {
            client_pub_key,
            expiry_ts: u64::from_le_bytes(expiry_bytes),
            ca_signature,
        })
    }

    /// Serialize to 104 bytes.
    pub fn to_bytes(&self) -> [u8; CERT_SIZE] {
        let mut out = [0u8; CERT_SIZE];
        out[..32].copy_from_slice(&self.client_pub_key);
        out[32..40].copy_from_slice(&self.expiry_ts.to_le_bytes());
        out[40..104].copy_from_slice(&self.ca_signature);
        out
    }

    fn signed_message(client_pub_key: &[u8; 32], expiry_ts: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(40);
        msg.extend_from_slice(client_pub_key);
        msg.extend_from_slice(&expiry_ts.to_le_bytes());
        msg
    }
}

/// Verify a client certificate against the configured CA.
pub fn verify_cert(cert: &SimpleCert, config: &MtlsConfig) -> bool {
    let ca_pub_hex = match config.ca_public_key_hex.as_deref() {
        Some(h) => h,
        None => {
            debug!("mtls: no CA public key configured — cert check skipped");
            return false;
        }
    };

    let ca_pub_bytes: Vec<u8> = match hex::decode(ca_pub_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            debug!("mtls: invalid CA public key hex");
            return false;
        }
    };

    // Check expiry
    let now_secs = current_timestamp_ms() / 1000;
    if cert.expiry_ts < now_secs {
        debug!(
            "mtls: cert expired {} seconds ago",
            now_secs - cert.expiry_ts
        );
        return false;
    }

    let mut ca_key_bytes = [0u8; 32];
    ca_key_bytes.copy_from_slice(&ca_pub_bytes);

    use ed25519_dalek::{Signature, VerifyingKey};
    let vk = match VerifyingKey::from_bytes(&ca_key_bytes) {
        Ok(k) => k,
        Err(e) => {
            debug!("mtls: invalid CA VerifyingKey: {}", e);
            return false;
        }
    };
    let sig = Signature::from_bytes(&cert.ca_signature);
    let msg = SimpleCert::signed_message(&cert.client_pub_key, cert.expiry_ts);
    match vk.verify_strict(&msg, &sig) {
        Ok(()) => {
            debug!(
                "mtls: cert valid (expires in {}s)",
                cert.expiry_ts.saturating_sub(now_secs)
            );
            true
        }
        Err(e) => {
            debug!("mtls: cert signature invalid: {}", e);
            false
        }
    }
}

/// Check whether a client is allowed to proceed given the mTLS policy.
///
/// - No cert + `required = false` → allow (PSK-only path).
/// - No cert + `required = true` → deny.
/// - Cert present → verify; allow only if valid.
pub fn check_client(cert_bytes: Option<&[u8]>, config: &MtlsConfig) -> bool {
    match cert_bytes {
        None => {
            if config.required {
                debug!("mtls: cert required but not presented — rejecting");
                false
            } else {
                true
            }
        }
        Some(bytes) => match SimpleCert::from_bytes(bytes) {
            Some(cert) => verify_cert(&cert, config),
            None => {
                debug!(
                    "mtls: malformed cert ({} bytes, expected {})",
                    bytes.len(),
                    CERT_SIZE
                );
                false
            }
        },
    }
}

/// Sign a client certificate with the CA private key (offline issuance tool).
pub fn issue_cert(
    client_pub_key: [u8; 32],
    expiry_ts: u64,
    ca_private_key: &[u8; 32],
) -> SimpleCert {
    use ed25519_dalek::{Signer, SigningKey};
    let signing_key = SigningKey::from_bytes(ca_private_key);
    let msg = SimpleCert::signed_message(&client_pub_key, expiry_ts);
    let signature = signing_key.sign(&msg);
    SimpleCert {
        client_pub_key,
        expiry_ts,
        ca_signature: signature.to_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_ca_config(required: bool) -> MtlsConfig {
        MtlsConfig {
            ca_public_key_hex: None,
            required,
        }
    }

    #[test]
    fn weak_ca_cannot_authenticate_a_client() {
        let mut weak = [0u8; 32];
        weak[0] = 1;
        let mut signature = [0u8; 64];
        signature[0] = 1;
        let cert = SimpleCert {
            client_pub_key: [7u8; 32],
            expiry_ts: u64::MAX,
            ca_signature: signature,
        };
        let config = MtlsConfig {
            ca_public_key_hex: Some(hex::encode(weak)),
            required: true,
        };
        assert!(!verify_cert(&cert, &config));
    }

    #[test]
    fn psk_only_allowed_when_not_required() {
        assert!(check_client(None, &no_ca_config(false)));
    }

    #[test]
    fn psk_only_denied_when_required() {
        assert!(!check_client(None, &no_ca_config(true)));
    }

    #[test]
    fn cert_roundtrip_and_verify() {
        use ed25519_dalek::SigningKey;
        let ca_key = [42u8; 32];
        let client_key = [7u8; 32];
        let expiry = u64::MAX;
        let cert = issue_cert(client_key, expiry, &ca_key);
        let bytes = cert.to_bytes();
        assert_eq!(bytes.len(), CERT_SIZE);
        let reparsed = SimpleCert::from_bytes(&bytes).unwrap();
        let pub_hex = hex::encode(SigningKey::from_bytes(&ca_key).verifying_key().to_bytes());
        let cfg = MtlsConfig {
            ca_public_key_hex: Some(pub_hex),
            required: true,
        };
        assert!(verify_cert(&reparsed, &cfg));
        assert!(check_client(Some(&bytes), &cfg));
    }

    #[test]
    fn expired_cert_rejected() {
        use ed25519_dalek::SigningKey;
        let ca_key = [99u8; 32];
        let cert = issue_cert([1u8; 32], 1_000_000, &ca_key); // far past
        let pub_hex = hex::encode(SigningKey::from_bytes(&ca_key).verifying_key().to_bytes());
        let cfg = MtlsConfig {
            ca_public_key_hex: Some(pub_hex),
            required: true,
        };
        assert!(!verify_cert(&cert, &cfg));
    }
}
