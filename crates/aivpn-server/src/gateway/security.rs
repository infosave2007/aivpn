//! Small, pure security-adjacent helpers used throughout the gateway's
//! packet-handling paths: privacy-preserving address hashing for logging,
//! and device-enrollment proof-of-possession verification.

use std::net::SocketAddr;

use aivpn_common::crypto;

/// Hash a socket address for privacy-preserving logging (MED-4)
pub(crate) fn hash_addr(addr: &SocketAddr) -> String {
    let hash = crypto::blake3_hash(addr.to_string().as_bytes());
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        hash[0], hash[1], hash[2], hash[3]
    )
}

/// Verify a `DeviceEnrollment` proof-of-possession against this session's
/// ephemeral handshake transcript.
///
/// `dh_shared` = X25519(server_static_priv, client_static_pub) — identical to
/// the client's own X25519(client_static_priv, server_static_pub) since
/// X25519 is symmetric. The expected proof recomputes
/// `crypto::device_enrollment_proof(dh_shared, server_eph_pub, client_eph_pub)`
/// over the EXACT `server_eph_pub || client_eph_pub` pair this session's PFS
/// handshake used (`Session::server_eph_pub` / `Session::eph_pub`), so a
/// `dh_proof` captured from one session can never verify against another.
///
/// `server_eph_pub` is `None` only if `DeviceEnrollment` somehow arrives
/// before the ratchet has recorded a server ephemeral (not reachable in the
/// normal flow, since the client only sends `DeviceEnrollment` after
/// processing `ServerHello`) — that case fails closed rather than panicking.
///
/// Comparison is constant-time (`subtle::ConstantTimeEq`).
pub(crate) fn verify_device_enrollment_proof(
    dh_shared: &[u8; 32],
    server_eph_pub: Option<[u8; 32]>,
    client_eph_pub: [u8; 32],
    received_proof: &[u8; 32],
) -> bool {
    use subtle::ConstantTimeEq;

    let Some(server_eph_pub) = server_eph_pub else {
        return false;
    };
    let expected = crypto::device_enrollment_proof(dh_shared, &server_eph_pub, &client_eph_pub);
    expected.ct_eq(received_proof).unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Crypto hardening: the device-enrollment proof must be bound to THIS
    /// session's ephemeral handshake transcript. A proof correctly built for
    /// session A's (server_eph_pub, client_eph_pub) must be rejected when
    /// replayed against session B's transcript — this is the exact attack
    /// the transcript binding closes (a pool/exit node, log, or coredump that
    /// observed session A's `dh_proof` cannot reuse it in session B).
    #[test]
    fn device_enrollment_proof_rejects_cross_session_replay() {
        use aivpn_common::crypto::device_enrollment_proof;

        let dh_shared = [0x12u8; 32];
        let server_a = [0x34u8; 32];
        let client_a = [0x56u8; 32];
        let server_b = [0x78u8; 32];
        let client_b = [0x9au8; 32];

        let proof_for_session_a = device_enrollment_proof(&dh_shared, &server_a, &client_a);

        // Correctly built for session A: verifies against session A.
        assert!(verify_device_enrollment_proof(
            &dh_shared,
            Some(server_a),
            client_a,
            &proof_for_session_a,
        ));

        // Replayed into session B (different ephemerals, same dh_shared /
        // static keys): must fail.
        assert!(!verify_device_enrollment_proof(
            &dh_shared,
            Some(server_b),
            client_b,
            &proof_for_session_a,
        ));

        // A proof correctly built for session B verifies against session B.
        let proof_for_session_b = device_enrollment_proof(&dh_shared, &server_b, &client_b);
        assert!(verify_device_enrollment_proof(
            &dh_shared,
            Some(server_b),
            client_b,
            &proof_for_session_b,
        ));
    }

    /// A tampered or wrong dh_shared (wrong static keypair) must be rejected
    /// even against the correct session transcript.
    #[test]
    fn device_enrollment_proof_rejects_wrong_dh_shared() {
        let dh_shared = [0x11u8; 32];
        let wrong_dh_shared = [0x22u8; 32];
        let server_eph = [0x33u8; 32];
        let client_eph = [0x44u8; 32];

        let proof = aivpn_common::crypto::device_enrollment_proof(
            &wrong_dh_shared,
            &server_eph,
            &client_eph,
        );
        assert!(!verify_device_enrollment_proof(
            &dh_shared,
            Some(server_eph),
            client_eph,
            &proof,
        ));
    }

    /// Missing `server_eph_pub` (not reachable in the normal flow — the
    /// client only sends `DeviceEnrollment` after processing `ServerHello`)
    /// must fail closed rather than accept unconditionally.
    #[test]
    fn device_enrollment_proof_fails_closed_without_server_eph_pub() {
        let dh_shared = [0x55u8; 32];
        let client_eph = [0x66u8; 32];
        // Any received proof, including a well-formed transcript proof for
        // some OTHER server_eph_pub, must be rejected when the session has
        // no recorded server_eph_pub to check the transcript against.
        let some_proof = [0x77u8; 32];
        assert!(!verify_device_enrollment_proof(
            &dh_shared,
            None,
            client_eph,
            &some_proof,
        ));
    }

    /// The legacy pre-hardening scheme (bare `dh_shared` as the proof, no
    /// transcript binding) must NO LONGER verify — the server accepts only
    /// the new transcript-bound proof (project-owner decision: break
    /// backward compatibility rather than keep a replayable dual-accept
    /// path).
    #[test]
    fn device_enrollment_proof_legacy_raw_dh_no_longer_accepted() {
        let dh_shared = [0x88u8; 32];
        let server_eph = [0x99u8; 32];
        let client_eph = [0xAAu8; 32];
        // Legacy client would have sent the bare dh_shared as dh_proof.
        assert!(!verify_device_enrollment_proof(
            &dh_shared,
            Some(server_eph),
            client_eph,
            &dh_shared,
        ));
    }
}
