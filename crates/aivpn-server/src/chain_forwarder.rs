//! Multi-hop chain forwarder — entry node side.
//!
//! When `pool.exit_node` is set in `server.json`, the gateway wraps every
//! decrypted client IP payload in a `ControlPayload::ChainForward` packet and
//! sends it to the exit node via the shared pool session.  The exit node's
//! gateway receives the packet, decrypts it (same pool session keys), and
//! injects the IP payload into its TUN interface — routing it to the internet
//! on behalf of the origin client.
//!
//! From the client's perspective nothing changes: it only ever speaks to the
//! entry node.  The exit IP address the internet sees belongs to the exit node.
//!
//! ## server.json (entry node only)
//! ```json
//! {
//!   "pool": {
//!     "sync_key": "<base64 32-byte key>",
//!     "exit_node": "exit.example.com:443"
//!   }
//! }
//! ```
//!
//! The exit node needs no additional config — its gateway already handles
//! `ChainForward` in the `handle_control_message()` match.

use portable_atomic::{AtomicBool, AtomicU64};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use rand::Rng;
use tokio::net::UdpSocket;
use tracing::{debug, warn};

use aivpn_common::crypto::{
    self, encrypt_payload, SessionKeys, DEFAULT_WINDOW_MS, NONCE_SIZE, TAG_SIZE,
};
use aivpn_common::error::Result;
use aivpn_common::protocol::{ControlPayload, InnerHeader, InnerType};

use crate::site_sync::{
    lock_counter_state_file, next_send_counter, persist_counter_floor, seed_send_counter,
    DEFAULT_STATE_DIR,
};

/// How far the on-disk send-counter floor is bumped ahead of the value
/// actually consumed.  Amortises disk writes on the per-packet data path
/// (one write per `CHAIN_PERSIST_STRIDE` packets) while keeping the
/// worst-case post-restart jump (`last_used + stride`) safely inside the
/// exit node's forward tag window (±255 counters around its live counter),
/// so forwarding resumes immediately after a crash-restart under load.
const CHAIN_PERSIST_STRIDE: u64 = 128;

/// How often a hostname-form `exit_node` is re-resolved (dynamic DNS: the
/// exit's address may change while this entry node keeps running).  Literal
/// IP:port configs are never re-resolved — nothing to refresh.
const EXIT_ADDR_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Forwards IP payloads to the designated exit node as `ChainForward` control packets.
pub struct ChainForwarder {
    /// The configured `pool.exit_node` string ("ip:port" or "hostname:port").
    /// Retained so a hostname can be re-resolved periodically (dynamic DNS) —
    /// the same per-tick re-resolution `pool_sync::push_to_peer` applies.
    exit_node: String,
    /// Current resolved exit address.  Behind a mutex so the background
    /// refresher can swap in a new DNS answer without restarting the
    /// forwarder.
    exit_addr: Mutex<SocketAddr>,
    session_keys: SessionKeys,
    /// Send counter — doubles as the AEAD nonce (`nonce[..8] = counter`) and
    /// the resonance-tag counter, mirroring `pool_sync.rs`.  Seeded at
    /// max(persisted high-water + 1, current 5-second wall-clock bucket) —
    /// NEVER 0: the exit node's pool peer session centres its expected-tag
    /// window on `unix_ms / 5_000`, so 0-based counters are dropped at tag
    /// lookup before decryption is even attempted.
    send_counter: AtomicU64,
    /// On-disk high-water file guaranteeing restart nonce-uniqueness under
    /// the static entry→exit send key.
    counter_state_path: PathBuf,
    /// Last value durably written to `counter_state_path`.
    persisted_high_water: Mutex<u64>,
    /// Set while persistence is failing, to avoid log spam at line rate.
    persist_warned: AtomicBool,
    /// Advisory exclusive `flock` on `<counter_state_path>.lock`, held for the
    /// process's lifetime (same scheme as `PeerSyncer::_counter_lock_file`):
    /// blocks a second overlapping process from racing this state file and
    /// reusing (key, nonce) pairs under the static entry→exit send key.
    _counter_lock_file: std::fs::File,
    socket: UdpSocket,
}

impl ChainForwarder {
    /// Create a forwarder.  Returns `None` if `sync_key` is all-zero or the
    /// bind fails.
    ///
    /// `node_id` is this (entry) node's `pool.node_id`.  When set, the
    /// forwarder encrypts with the entry→exit DIRECTIONAL sub-key of the
    /// (node_id, exit_node) pair — the same key the exit node registers for
    /// receiving from this node via its pool peer session (the exit node must
    /// therefore list this node in its own `pool.peers` and set its
    /// `pool.node_id` to the `exit_node` string used here).  Roles are
    /// assigned by lexicographic id order, so both ends agree without a
    /// handshake and the two directions never share an AEAD key.  A
    /// `node_id` is REQUIRED: the exit node only registers DIRECTIONAL pool
    /// peer sessions (post-A12), so legacy symmetric-key traffic could never
    /// be decrypted there — and counter-derived AEAD nonces on a key shared
    /// by both directions would additionally risk (key, nonce) reuse.
    pub async fn new(
        exit_node: &str,
        sync_key: [u8; 32],
        node_id: Option<&str>,
    ) -> Option<Arc<Self>> {
        Self::new_with_state_dir(exit_node, sync_key, node_id, Path::new(DEFAULT_STATE_DIR)).await
    }

    async fn new_with_state_dir(
        exit_node: &str,
        sync_key: [u8; 32],
        node_id: Option<&str>,
        state_dir: &Path,
    ) -> Option<Arc<Self>> {
        if sync_key == [0u8; 32] {
            return None;
        }
        // `exit_node` may be "ip:port" or "hostname:port" (the documented
        // example is `exit.example.com:443`). A bare `.parse()` fails on DNS
        // names, silently disabling multi-hop — resolve via the system
        // resolver instead. NOTE: only the socket address is resolved; key
        // derivation below intentionally keeps using the exit_node STRING,
        // which is what the exit node registers as its pool node_id. A
        // hostname-form exit_node is additionally re-resolved periodically
        // (see `refresh_exit_addr_loop`) so a dynamic-DNS exit address change
        // is picked up without a restart.
        let exit_addr: SocketAddr = match exit_node.parse() {
            Ok(addr) => addr,
            Err(_) => match tokio::net::lookup_host(exit_node).await {
                Ok(mut addrs) => match addrs.next() {
                    Some(addr) => addr,
                    None => {
                        warn!(
                            "chain_forward: exit_node '{}' resolved to no addresses — \
                             ChainForward disabled",
                            exit_node
                        );
                        return None;
                    }
                },
                Err(e) => {
                    warn!(
                        "chain_forward: cannot resolve exit_node '{}': {} — \
                         ChainForward disabled",
                        exit_node, e
                    );
                    return None;
                }
            },
        };
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "chain_forward: UDP bind failed: {} — ChainForward disabled",
                    e
                );
                return None;
            }
        };
        let enc_root: [u8; 32] = match node_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|local| crypto::derive_directional_peer_keys(&sync_key, local, exit_node))
        {
            Some(Ok((send_root, _recv_root))) => send_root,
            _ => {
                warn!(
                    "chain_forward: pool.node_id not set (or equal to exit_node) — \
                     ChainForward disabled: directional keys are required (the exit \
                     node only registers directional pool peer sessions, and \
                     counter-derived AEAD nonces on a shared symmetric key would \
                     risk nonce reuse)"
                );
                return None;
            }
        };
        let session_keys = SessionKeys {
            session_key: blake3::derive_key("aivpn-pool-enc-v1", &enc_root),
            session_key_s2c: blake3::derive_key("aivpn-pool-enc-v1", &enc_root),
            tag_secret: blake3::derive_key("aivpn-pool-tag-v1", &enc_root),
            prng_seed: blake3::derive_key("aivpn-pool-prng-v1", &enc_root),
        };

        // Seed at max(persisted high-water + 1, current 5-second bucket) —
        // same model as `PeerSyncer::new`.  The counter is the AEAD nonce, so
        // under the static entry→exit key it must never restart from a value
        // a previous run already consumed.  The flock is taken FIRST (fail
        // closed): the persisted floor only protects sequential restarts, not
        // two overlapping processes racing the same state file.
        let counter_state_path = state_dir.join("chain_forward_counter.state");
        let lock_file = lock_counter_state_file(&counter_state_path, "chain_forward")?;
        let start_counter = seed_send_counter(&counter_state_path, "chain_forward");
        let send_counter = AtomicU64::new(start_counter);
        let persisted_high_water = Mutex::new(start_counter);

        let fwd = Arc::new(Self {
            exit_node: exit_node.to_string(),
            exit_addr: Mutex::new(exit_addr),
            session_keys,
            send_counter,
            counter_state_path,
            persisted_high_water,
            persist_warned: AtomicBool::new(false),
            _counter_lock_file: lock_file,
            socket,
        });

        // Dynamic DNS: a hostname-form exit_node is re-resolved periodically
        // so an exit whose address changed comes back without a restart
        // (mirrors `pool_sync::push_to_peer`'s per-tick re-resolution, but on
        // a timer — `forward` is a per-packet path and cannot afford DNS).
        if exit_node.parse::<SocketAddr>().is_err() {
            let me = fwd.clone();
            tokio::spawn(async move { me.refresh_exit_addr_loop().await });
        }

        Some(fwd)
    }

    /// Periodically re-resolve a hostname-form `exit_node` and swap in the new
    /// address.  Resolution failures keep the last known address.
    async fn refresh_exit_addr_loop(&self) {
        let mut ticker = tokio::time::interval(EXIT_ADDR_REFRESH_INTERVAL);
        loop {
            ticker.tick().await;
            match tokio::net::lookup_host(&self.exit_node).await {
                Ok(mut addrs) => match addrs.next() {
                    Some(addr) => {
                        let mut cur = self.exit_addr.lock();
                        if *cur != addr {
                            tracing::info!(
                                "chain_forward: exit_node '{}' re-resolved {} → {}",
                                self.exit_node,
                                *cur,
                                addr
                            );
                            *cur = addr;
                        }
                    }
                    None => {
                        warn!(
                            "chain_forward: exit_node '{}' re-resolved to no addresses — \
                             keeping last known {}",
                            self.exit_node,
                            *self.exit_addr.lock()
                        );
                    }
                },
                Err(e) => {
                    warn!(
                        "chain_forward: exit_node '{}' re-resolution failed: {} — \
                         keeping last known {}",
                        self.exit_node,
                        e,
                        *self.exit_addr.lock()
                    );
                }
            }
        }
    }

    /// Wrap `ip_payload` in a `ChainForward` control packet and transmit to the exit node.
    pub async fn forward(&self, ip_payload: Vec<u8>) {
        match self.build_packet(ip_payload) {
            Ok(pkt) => {
                let exit_addr = *self.exit_addr.lock();
                if let Err(e) = self.socket.send_to(&pkt, exit_addr).await {
                    debug!("chain_forward: send to {} failed: {}", exit_addr, e);
                }
            }
            Err(e) => debug!("chain_forward: build packet failed: {}", e),
        }
    }

    fn build_packet(&self, ip_payload: Vec<u8>) -> Result<Vec<u8>> {
        let encoded = ControlPayload::ChainForward {
            payload: ip_payload,
        }
        .encode()?;
        let mut inner = InnerHeader {
            inner_type: InnerType::Control,
            seq_num: 0,
        }
        .encode()
        .to_vec();
        inner.extend_from_slice(&encoded);

        // Strictly monotonic, wall-clock-clamped counter.  It is BOTH the
        // resonance-tag counter and the AEAD nonce: the exit node's gateway
        // recovers it from the tag (`validate_tag`) and rebuilds this exact
        // nonce via `compute_nonce(counter)` — a random nonce here can never
        // be reconstructed by the receiver, so every packet would fail
        // Poly1305 authentication even when the tag matched.
        let counter = next_send_counter(&self.send_counter);

        // Durably bump the on-disk floor BEFORE the counter is used as a
        // nonce, amortised to one write per CHAIN_PERSIST_STRIDE packets so
        // the per-packet data path stays off the disk.
        persist_counter_floor(
            &self.counter_state_path,
            &self.persisted_high_water,
            counter,
            CHAIN_PERSIST_STRIDE,
            &self.persist_warned,
            "chain_forward",
        );

        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..8].copy_from_slice(&counter.to_le_bytes());

        let pad_len: u16 = 16;
        let mut padded = Vec::with_capacity(2 + inner.len() + pad_len as usize);
        padded.extend_from_slice(&pad_len.to_le_bytes());
        padded.extend_from_slice(&inner);
        let mut rng = rand::thread_rng();
        for _ in 0..pad_len {
            padded.push(rng.gen::<u8>());
        }

        let ciphertext = encrypt_payload(&self.session_keys.session_key, &nonce, &padded)?;
        let tw = crypto::compute_time_window(crypto::current_timestamp_ms(), DEFAULT_WINDOW_MS);
        let tag = crypto::generate_resonance_tag(&self.session_keys.tag_secret, counter, tw);

        // Fixed, mask-independent cluster framing — the exit node's gateway
        // decodes its pool-peer session with exactly this layout (see
        // `pool_sync::CLUSTER_MDH_LEN`).
        let mdh = crate::pool_sync::cluster_mdh_bytes();
        let mut pkt = Vec::with_capacity(TAG_SIZE + mdh.len() + ciphertext.len());
        pkt.extend_from_slice(&tag);
        pkt.extend_from_slice(&mdh);
        pkt.extend_from_slice(&ciphertext);
        Ok(pkt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivpn_common::crypto::decrypt_payload;
    use std::sync::atomic::Ordering;

    const ENTRY_ID: &str = "10.0.0.1:443";
    const EXIT_NODE: &str = "127.0.0.1:4433";

    /// Derive the `SessionKeys` the exit node's
    /// `SessionManager::create_pool_peer_session` registers from a given
    /// (directional) root — byte-for-byte the same KDF domains.
    fn exit_session_keys(root: &[u8; 32]) -> SessionKeys {
        SessionKeys {
            session_key: blake3::derive_key("aivpn-pool-enc-v1", root),
            session_key_s2c: blake3::derive_key("aivpn-pool-enc-v1", root),
            tag_secret: blake3::derive_key("aivpn-pool-tag-v1", root),
            prng_seed: blake3::derive_key("aivpn-pool-prng-v1", root),
        }
    }

    async fn make_forwarder(dir: &Path) -> Arc<ChainForwarder> {
        ChainForwarder::new_with_state_dir(EXIT_NODE, [7u8; 32], Some(ENTRY_ID), dir)
            .await
            .unwrap()
    }

    /// End-to-end receiver round-trip — the exact double bug this module was
    /// broken by: (1) the AEAD nonce must be reconstructible from the counter
    /// recovered via the resonance tag (it used to be random), and (2) the
    /// counter must sit at the exit node's wall-clock tag window (it used to
    /// start at 0).  The entry node builds a ChainForward packet; the "exit
    /// node" rebuilds the nonce from the counter exactly like
    /// `Gateway::compute_nonce` and decrypts with the RECV-direction keys of
    /// its pool peer session for this entry node.
    #[tokio::test]
    async fn chain_forward_packet_round_trips_to_exit_node() {
        let dir = tempfile::tempdir().unwrap();
        let fwd = make_forwarder(dir.path()).await;

        let ip_payload = vec![0x45, 0x00, 0x00, 0x1c, 0xde, 0xad, 0xbe, 0xef];
        let bucket_before = crypto::current_timestamp_ms() / 5_000;
        let pkt = fwd.build_packet(ip_payload.clone()).unwrap();
        // next_send_counter stores used + 1, so the used value is stored - 1.
        let counter = fwd.send_counter.load(Ordering::Relaxed) - 1;

        // The counter must be pinned to the wall-clock bucket the exit
        // node's pool session window is centred on — never a 0-based value.
        assert!(
            counter >= bucket_before,
            "send counter ({counter}) must be at/above the current 5-second \
             bucket ({bucket_before}), not seeded from 0"
        );

        // Exit node side: its pool.node_id is the EXIT_NODE string and its
        // peers list contains this entry node, so its receive session for
        // this link is keyed by the recv root of (EXIT_NODE, ENTRY_ID).
        let (_exit_send, exit_recv_root) =
            crypto::derive_directional_peer_keys(&[7u8; 32], EXIT_NODE, ENTRY_ID)
                .expect("distinct ids");
        let recv_keys = exit_session_keys(&exit_recv_root);

        // Gateway::compute_nonce: nonce[..8] = counter.to_le_bytes().
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..8].copy_from_slice(&counter.to_le_bytes());
        let ciphertext = &pkt[TAG_SIZE + crate::pool_sync::CLUSTER_MDH_LEN..];
        let plaintext = decrypt_payload(&recv_keys.session_key, &nonce, ciphertext)
            .expect("exit node must decrypt with counter-derived nonce and recv-direction key");

        // Plaintext layout: [pad_len u16][InnerHeader][ControlPayload][padding].
        let pad_len = u16::from_le_bytes([plaintext[0], plaintext[1]]) as usize;
        let inner = &plaintext[2..plaintext.len() - pad_len];
        let header = InnerHeader::decode(inner).unwrap();
        assert_eq!(header.inner_type, InnerType::Control);
        match ControlPayload::decode(&inner[4..]).unwrap() {
            ControlPayload::ChainForward { payload } => assert_eq!(payload, ip_payload),
            other => panic!("expected ChainForward, got {:?}", other),
        }

        // The resonance tag must be generated from the SAME counter the
        // nonce was built from — that is how the receiver recovers it.
        let tw = crypto::compute_time_window(crypto::current_timestamp_ms(), DEFAULT_WINDOW_MS);
        let expected_tag =
            crypto::generate_resonance_tag(&fwd.session_keys.tag_secret, counter, tw);
        assert_eq!(&pkt[..TAG_SIZE], &expected_tag[..]);

        // A12 directionality intact: the REVERSE direction (exit→entry — the
        // keys the ENTRY node would receive with) must NOT decrypt
        // entry→exit traffic.
        let (_entry_send, entry_recv_root) =
            crypto::derive_directional_peer_keys(&[7u8; 32], ENTRY_ID, EXIT_NODE)
                .expect("distinct ids");
        let reverse_keys = exit_session_keys(&entry_recv_root);
        assert_ne!(recv_keys.session_key, reverse_keys.session_key);
        assert!(
            decrypt_payload(&reverse_keys.session_key, &nonce, ciphertext).is_err(),
            "reverse-direction key must not decrypt entry→exit traffic"
        );
    }

    /// Without a `pool.node_id` the forwarder must refuse to start — the
    /// exit node has no symmetric-key session to decrypt with, and counter
    /// nonces on a bidirectional symmetric key would risk (key, nonce) reuse.
    #[tokio::test]
    async fn missing_node_id_disables_chain_forwarding() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            ChainForwarder::new_with_state_dir(EXIT_NODE, [7u8; 32], None, dir.path())
                .await
                .is_none()
        );
        // node_id equal to the exit node string is also symmetric → disabled.
        assert!(ChainForwarder::new_with_state_dir(
            EXIT_NODE,
            [7u8; 32],
            Some(EXIT_NODE),
            dir.path()
        )
        .await
        .is_none());
    }

    /// Restart nonce-reuse regression (same guarantee as
    /// `pool_sync::restart_never_reuses_a_send_counter_value`): the
    /// entry→exit key is static across restarts, so a second forwarder built
    /// against the same state dir — worst case inside the same 5-second
    /// bucket — must resume PAST every counter already consumed, even though
    /// the floor is persisted in strides of `CHAIN_PERSIST_STRIDE`.
    #[tokio::test]
    async fn restart_never_reuses_a_send_counter_value() {
        let dir = tempfile::tempdir().unwrap();

        let fwd1 = make_forwarder(dir.path()).await;
        let mut last_used = 0u64;
        for _ in 0..200 {
            fwd1.build_packet(vec![0x45; 20]).unwrap();
            last_used = fwd1.send_counter.load(Ordering::Relaxed) - 1;
        }

        // Drop process 1's forwarder first to release its advisory
        // counter-file flock — a real restart closes the old process's fd
        // before the new one opens, which is exactly what this drop simulates
        // (mirrors `pool_sync::restart_never_reuses_a_send_counter_value`).
        drop(fwd1);
        let fwd2 = make_forwarder(dir.path()).await;
        let resumed = fwd2.send_counter.load(Ordering::Relaxed);
        assert!(
            resumed > last_used,
            "restarted forwarder must never reuse a counter (last used = \
             {last_used}, resumed at = {resumed})"
        );
        // The stride keeps the post-restart jump bounded, so forwarding
        // resumes inside the exit node's forward tag window (±255).
        assert!(
            resumed <= last_used + CHAIN_PERSIST_STRIDE + 1,
            "post-restart counter jump ({}) must stay within the persist \
             stride bound so tags remain inside the receiver window",
            resumed - last_used
        );
    }

    /// flock regression (mirrors `pool_sync::overlapping_instances_are_refused`):
    /// two genuinely OVERLAPPING forwarders on the same counter-state file
    /// must not both run — the second construction fails closed rather than
    /// racing the first over the static entry→exit (key, nonce) space.
    #[tokio::test]
    async fn overlapping_instances_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let fwd1 = make_forwarder(dir.path()).await;
        assert!(
            ChainForwarder::new_with_state_dir(EXIT_NODE, [7u8; 32], Some(ENTRY_ID), dir.path())
                .await
                .is_none(),
            "a second overlapping ChainForwarder on the same state file must be refused"
        );
        drop(fwd1);
    }
}
