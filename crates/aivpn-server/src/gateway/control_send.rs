//! Control-plane message construction/send helpers factored out of
//! `Gateway`'s methods: encoding+encrypting a `ControlPayload` onto the
//! wire (`send_control_message`/`_via`), the `ServerHello` handshake reply,
//! the client-facing mask catalog payload, and the generic downlink packet
//! builder + entropy helper both of those (and the hot-path dispatcher in
//! `mod.rs`) share. Pure moves out of `gateway/mod.rs` — the
//! `handle_control_message` dispatcher itself, which calls into these,
//! stays in `mod.rs`.

use std::sync::Arc;

use tokio::net::UdpSocket;
use tracing::debug;

use aivpn_common::crypto::{self, encrypt_payload, TAG_SIZE};
use aivpn_common::error::{Error, Result};
use aivpn_common::protocol::{ControlPayload, InnerHeader, InnerType};

use crate::session::Session;

use super::mask_catalog::packet_mdh_bytes_for_mask;
use super::Gateway;

impl Gateway {
    /// Send control message to client
    pub(crate) async fn send_control_message(
        &self,
        payload: &ControlPayload,
        session: &Arc<parking_lot::Mutex<Session>>,
    ) -> Result<()> {
        let socket = self.udp_socket.as_ref().unwrap();
        let mdh = {
            let mut sess = session.lock();
            sess.commit_pending_mask();
            sess.mask
                .as_ref()
                .map(packet_mdh_bytes_for_mask)
                .unwrap_or_else(|| self.mask_catalog.packet_mdh_bytes())
        };
        Self::send_control_message_via(socket, &mdh, payload, session).await
    }

    pub(crate) async fn send_control_message_via(
        socket: &UdpSocket,
        mdh: &[u8],
        payload: &ControlPayload,
        session: &Arc<parking_lot::Mutex<Session>>,
    ) -> Result<()> {
        let encoded = payload.encode()?;
        let (mut inner_payload, nonce, counter, keys, client_addr) = {
            let mut sess = session.lock();
            let inner_header = InnerHeader {
                inner_type: InnerType::Control,
                seq_num: sess.next_seq() as u16,
            };
            let inner_payload = inner_header.encode().to_vec();
            let (nonce, counter) = sess.next_send_nonce();
            let keys = sess.keys.clone();
            let client_addr = sess.client_addr;
            (inner_payload, nonce, counter, keys, client_addr)
        };
        inner_payload.extend_from_slice(&encoded);
        let pad_len = 16u16;
        let mut padded = Vec::with_capacity(2 + inner_payload.len() + pad_len as usize);
        padded.extend_from_slice(&pad_len.to_le_bytes());
        padded.extend_from_slice(&inner_payload);
        {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            for _ in 0..pad_len {
                padded.push(rng.gen::<u8>());
            }
        }
        let ciphertext = encrypt_payload(&keys.session_key_s2c, &nonce, &padded)?; // downlink → S2C key
        let time_window = crypto::compute_time_window(
            crypto::current_timestamp_ms(),
            aivpn_common::crypto::DEFAULT_WINDOW_MS,
        );
        let tag = crypto::generate_resonance_tag(&keys.tag_secret, counter, time_window);
        let mut packet = Vec::with_capacity(TAG_SIZE + mdh.len() + ciphertext.len());
        packet.extend_from_slice(&tag);
        packet.extend_from_slice(mdh);
        packet.extend_from_slice(&ciphertext);
        socket.send_to(&packet, client_addr).await?;
        Ok(())
    }

    pub(crate) async fn send_server_hello(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: std::net::SocketAddr,
    ) -> Result<()> {
        let (server_eph_pub, signature, network_config) = {
            let sess = session.lock();
            match (sess.server_eph_pub, sess.server_hello_signature) {
                (Some(pub_key), Some(sig)) => {
                    let network_config = sess
                        .vpn_ip
                        .and_then(|vpn_ip| self.config.network_config.client_config(vpn_ip).ok());
                    (pub_key, sig, network_config)
                }
                _ => return Err(Error::Session("Missing ratchet data".into())),
            }
        };

        let hello = ControlPayload::ServerHello {
            server_eph_pub,
            signature,
            network_config,
        };
        let encoded = hello.encode()?;
        let inner_header = InnerHeader {
            inner_type: InnerType::Control,
            seq_num: 0,
        };
        let mut inner_payload = inner_header.encode().to_vec();
        inner_payload.extend_from_slice(&encoded);
        let packet = self.build_packet(&inner_payload, session)?;
        let socket = self.udp_socket.as_ref().unwrap();
        let sent = socket.send_to(&packet, client_addr).await?;
        debug!("ServerHello sent: {} bytes to {}", sent, client_addr);
        Ok(())
    }

    /// Build the client-facing mask catalog: every mask a client may select,
    /// each tagged with whether the server auto-generated it (mask_gen). Built-in
    /// presets come first in their stable order, then auto-generated masks from
    /// the store; deduped by id. Drives the client picker + its "(авто)" marker.
    pub(crate) fn build_mask_catalog_payload(&self) -> ControlPayload {
        let mut masks: Vec<(String, String, bool)> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for preset in aivpn_common::mask::preset_masks::all().iter() {
            if seen.insert(preset.mask_id.clone()) {
                masks.push((
                    preset.mask_id.clone(),
                    preset.mask_id.clone(),
                    preset.generated,
                ));
            }
        }
        if let Some(ref store) = self.mask_store {
            for entry in store.list_masks() {
                let id = entry.profile.mask_id.clone();
                if seen.insert(id.clone()) {
                    masks.push((id.clone(), id, entry.profile.generated));
                }
            }
        }
        ControlPayload::MaskCatalog { masks }
    }

    /// Push the current mask catalog to one session over the control plane.
    pub(crate) async fn send_mask_catalog(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
    ) -> Result<()> {
        let payload = self.build_mask_catalog_payload();
        self.send_control_message(&payload, session).await
    }

    /// Build AIVPN packet
    /// Wire format: TAG | MDH | encrypt(pad_len_u16 || plaintext || random_padding)
    pub(crate) fn build_packet(
        &self,
        plaintext: &[u8],
        session: &Arc<parking_lot::Mutex<Session>>,
    ) -> Result<Vec<u8>> {
        let mut sess = session.lock();

        // Use unified counter for both nonce and tag
        let (nonce, counter) = sess.next_send_nonce();

        // Build padded plaintext: pad_len(u16) || plaintext || random_padding
        // pad_len is inside encryption — invisible to DPI (CRIT-5 fix)
        let pad_len = 16u16;
        let mut padded = Vec::with_capacity(2 + plaintext.len() + pad_len as usize);
        padded.extend_from_slice(&pad_len.to_le_bytes());
        padded.extend_from_slice(plaintext);
        use rand::Rng;
        let mut rng = rand::thread_rng();
        for _ in 0..pad_len {
            padded.push(rng.gen::<u8>());
        }

        let ciphertext = encrypt_payload(&sess.keys.session_key_s2c, &nonce, &padded)?; // downlink → S2C key

        // Generate tag
        let time_window = crypto::compute_time_window(
            crypto::current_timestamp_ms(),
            aivpn_common::crypto::DEFAULT_WINDOW_MS,
        );
        let tag = crypto::generate_resonance_tag(&sess.keys.tag_secret, counter, time_window);
        let current_mask = sess.mask.clone();
        drop(sess);

        // Build MDH using the session's current packet mask so the peer can
        // decode bootstrap traffic before any runtime MaskUpdate arrives.
        let mdh = current_mask
            .as_ref()
            .map(packet_mdh_bytes_for_mask)
            .unwrap_or_else(|| self.mask_catalog.packet_mdh_bytes());

        // Assemble packet: TAG | MDH | ciphertext (no cleartext padding)
        let mut packet = Vec::with_capacity(TAG_SIZE + mdh.len() + ciphertext.len());
        packet.extend_from_slice(&tag);
        packet.extend_from_slice(&mdh);
        packet.extend_from_slice(&ciphertext);

        Ok(packet)
    }

    /// Compute Shannon entropy of a byte slice (0.0 = uniform, 8.0 = max)
    pub(crate) fn compute_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut counts = [0u32; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        let len = data.len() as f64;
        let mut entropy = 0.0;
        for &c in &counts {
            if c > 0 {
                let p = c as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }
}
