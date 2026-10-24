//! Control-plane message construction/send helpers factored out of
//! `Gateway`'s methods: encoding+encrypting a `ControlPayload` onto the
//! wire (`send_control_message`/`_via`), the `ServerHello` handshake reply,
//! the client-facing mask catalog payload, and the generic downlink packet
//! builder + entropy helper both of those (and the hot-path dispatcher in
//! `mod.rs`) share. Pure moves out of `gateway/mod.rs` — the
//! `handle_control_message` dispatcher itself, which calls into these,
//! stays in `mod.rs`.

use std::sync::Arc;

#[cfg(test)]
use tokio::net::UdpSocket;
use tracing::debug;

use aivpn_common::crypto::{self, TAG_SIZE};
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
        let socket = self
            .udp_socket
            .as_ref()
            .ok_or_else(|| Error::Session("UDP socket не открыт".into()))?;
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
        socket: &super::MaskSocket,
        mdh: &[u8],
        payload: &ControlPayload,
        session: &Arc<parking_lot::Mutex<Session>>,
    ) -> Result<()> {
        Self::send_inner_message_via(socket, mdh, InnerType::Control, &payload.encode()?, session)
            .await
            .map(|_| ())
    }

    pub(crate) fn build_inner_packets(
        mdh: &[u8],
        kind: InnerType,
        payload: &[u8],
        session: &Arc<parking_lot::Mutex<Session>>,
    ) -> Result<(std::net::SocketAddr, bool, Vec<Vec<u8>>)> {
        let (kind, pieces) = if payload.len() > aivpn_common::fragment::FRAGMENT_DATA_SIZE {
            (
                InnerType::Fragment,
                aivpn_common::fragment::split(kind, payload)?,
            )
        } else {
            (kind, vec![payload.to_vec()])
        };
        let (address, stateful) = {
            let session = session.lock();
            (
                session.client_addr,
                session
                    .mask
                    .as_ref()
                    .is_some_and(aivpn_common::mask_io::needs_state),
            )
        };
        let mut packets = Vec::with_capacity(pieces.len());
        for encoded in pieces {
            let (mut inner_payload, _nonce, counter, keys, _client_addr, mask) = {
                let mut sess = session.lock();
                let inner_header = InnerHeader {
                    inner_type: kind,
                    seq_num: sess.next_seq() as u16,
                };
                let inner_payload = inner_header.encode().to_vec();
                let (nonce, counter) = sess.next_send_nonce();
                let keys = sess.keys.clone();
                let client_addr = sess.client_addr;
                (
                    inner_payload,
                    nonce,
                    counter,
                    keys,
                    client_addr,
                    sess.mask.clone(),
                )
            };
            inner_payload.extend_from_slice(&encoded);
            let base = mdh.len()
                + crypto::session_payload_overhead(&keys)
                + 2
                + inner_payload.len()
                + crypto::POLY1305_TAG_SIZE;
            let pad_len = match mask.as_ref() {
                Some(mask) => mask.wire_padding(base, 16, 19)?,
                None => 16,
            };
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
            let time_window = crypto::compute_time_window(
                crypto::current_timestamp_ms(),
                aivpn_common::crypto::DEFAULT_WINDOW_MS,
            );
            let tag = crypto::generate_resonance_tag(&keys.tag_secret, counter, time_window);
            let ciphertext = crypto::encrypt_session_payload(
                &keys,
                crypto::PacketDirection::ServerToClient,
                counter,
                &tag,
                &padded,
            )?;
            let mut packet = Vec::with_capacity(TAG_SIZE + mdh.len() + ciphertext.len());
            if let Some(mask) = mask.as_ref() {
                mask.assemble_packet_into(&mut packet, mdh, &tag, &ciphertext)?;
            } else {
                packet.extend_from_slice(&tag);
                packet.extend_from_slice(mdh);
                packet.extend_from_slice(&ciphertext);
            }
            packets.push(packet);
        }
        Ok((address, stateful, packets))
    }

    pub(crate) async fn send_inner_message_via(
        socket: &super::MaskSocket,
        mdh: &[u8],
        kind: InnerType,
        payload: &[u8],
        session: &Arc<parking_lot::Mutex<Session>>,
    ) -> Result<usize> {
        let (address, stateful, packets) = Self::build_inner_packets(mdh, kind, payload, session)?;
        let mut sent = 0;
        for (index, packet) in packets.into_iter().enumerate() {
            if index > 0 && index % 16 == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            sent += socket.send_with_mask(&packet, address, stateful).await?;
        }
        Ok(sent)
    }

    pub(crate) async fn send_server_hello(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: std::net::SocketAddr,
    ) -> Result<()> {
        let (server_eph_pub, signature, network_config) = {
            let mut sess = session.lock();
            if !sess.admit_initial_hello(std::time::Instant::now()) {
                return Ok(());
            }
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
        let socket = self
            .udp_socket
            .as_ref()
            .ok_or_else(|| Error::Session("UDP socket не открыт".into()))?;
        let stateful = session
            .lock()
            .mask
            .as_ref()
            .is_some_and(aivpn_common::mask_io::needs_state);
        let rtc_bootstrap = session
            .lock()
            .mask
            .as_ref()
            .is_some_and(aivpn_common::mask_io::uses_rtc);
        let sent = if rtc_bootstrap {
            // Новый клиент за прежним NAT еще не знает ключей старого SRTP.
            socket.raw().send_to(&packet, client_addr).await?
        } else {
            socket
                .send_with_mask(&packet, client_addr, stateful)
                .await?
        };
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
        let (_nonce, counter) = sess.next_send_nonce();

        // Build padded plaintext: pad_len(u16) || plaintext || random_padding
        // pad_len is inside encryption — invisible to DPI (CRIT-5 fix)
        let current_mask = sess.mask.clone();
        let mdh = current_mask
            .as_ref()
            .map(packet_mdh_bytes_for_mask)
            .unwrap_or_else(|| self.mask_catalog.packet_mdh_bytes());
        let base = mdh.len()
            + crypto::session_payload_overhead(&sess.keys)
            + 2
            + plaintext.len()
            + crypto::POLY1305_TAG_SIZE;
        let pad_len = match current_mask.as_ref() {
            Some(mask) => mask.wire_padding(base, 16, 19)?,
            None => 16,
        };
        let mut padded = Vec::with_capacity(2 + plaintext.len() + pad_len as usize);
        padded.extend_from_slice(&pad_len.to_le_bytes());
        padded.extend_from_slice(plaintext);
        use rand::Rng;
        let mut rng = rand::thread_rng();
        for _ in 0..pad_len {
            padded.push(rng.gen::<u8>());
        }

        // Generate tag
        let time_window = crypto::compute_time_window(
            crypto::current_timestamp_ms(),
            aivpn_common::crypto::DEFAULT_WINDOW_MS,
        );
        let tag = crypto::generate_resonance_tag(&sess.keys.tag_secret, counter, time_window);
        let ciphertext = crypto::encrypt_session_payload(
            &sess.keys,
            crypto::PacketDirection::ServerToClient,
            counter,
            &tag,
            &padded,
        )?;
        drop(sess);

        // Build MDH using the session's current packet mask so the peer can
        // decode bootstrap traffic before any runtime MaskUpdate arrives.

        // Assemble packet: TAG | MDH | ciphertext (no cleartext padding)
        let mut packet = Vec::with_capacity(TAG_SIZE + mdh.len() + ciphertext.len());
        if let Some(mask) = current_mask.as_ref() {
            mask.assemble_packet_into(&mut packet, &mdh, &tag, &ciphertext)?;
        } else {
            packet.extend_from_slice(&tag);
            packet.extend_from_slice(&mdh);
            packet.extend_from_slice(&ciphertext);
        }

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

#[cfg(test)]
mod fragment_tests {
    use super::*;
    use aivpn_common::client_wire::{decode_packet_with_layout, RecvWindow};
    use aivpn_common::crypto::SessionKeys;
    use aivpn_common::fragment::Reassembler;

    #[tokio::test]
    async fn maximum_management_response_roundtrips_over_udp() {
        response_roundtrip(false).await;
        response_roundtrip(true).await;
    }

    async fn response_roundtrip(embedded: bool) {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = super::super::MaskSocket::new(Arc::new(sender));
        let keys = SessionKeys {
            packet_cipher: crypto::PacketCipher::Established,
            session_key: [1; 32],
            session_key_s2c: [2; 32],
            tag_secret: [3; 32],
            prng_seed: [4; 32],
        };
        let session = Arc::new(parking_lot::Mutex::new(Session::new(
            [7; 16],
            receiver.local_addr().unwrap(),
            keys.clone(),
            [9; 32],
        )));
        let mask = aivpn_common::mask::preset_masks::webrtc_zoom_v3();
        let mdh = if embedded {
            packet_mdh_bytes_for_mask(&mask)
        } else {
            vec![0; 20]
        };
        let tag_offset = if embedded { mask.tag_offset } else { u16::MAX };
        let mdh_len = mdh.len();
        if embedded {
            session.lock().mask = Some(mask);
        }
        let response = ControlPayload::MgmtResponse {
            req_id: 71,
            status: 200,
            body: vec![b'x'; 262144],
        };
        let expected = response.encode().unwrap();
        let upload = tokio::spawn(async move {
            Gateway::send_control_message_via(&sender, &mdh, &response, &session).await
        });
        let receive = async {
            let mut fragments = Reassembler::default();
            let mut window = RecvWindow::new();
            let mut buffer = [0u8; 1500];
            loop {
                let length = receiver.recv(&mut buffer).await.unwrap();
                let decoded = decode_packet_with_layout(
                    &buffer[..length],
                    &keys,
                    &mut window,
                    mdh_len,
                    tag_offset,
                )
                .unwrap();
                assert_eq!(decoded.header.inner_type, InnerType::Fragment);
                if let Some((kind, bytes)) = fragments
                    .accept(&decoded.payload, std::time::Instant::now())
                    .unwrap()
                {
                    assert_eq!(kind, InnerType::Control);
                    assert_eq!(
                        ControlPayload::decode(&bytes).unwrap().encode().unwrap(),
                        expected
                    );
                    break;
                }
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), receive)
            .await
            .unwrap();
        upload.await.unwrap().unwrap();
    }
}

#[cfg(test)]
mod full_mtu_tests {
    use super::*;
    use aivpn_common::client_wire::{decode_packet_with_layout, RecvWindow};
    use aivpn_common::fragment::Reassembler;
    use aivpn_common::mask::preset_masks;
    use std::time::Instant;

    #[test]
    fn full_mtu_downlink_reassembles_for_every_mask() {
        let keys = crypto::derive_session_keys(&[1; 32], Some(&[2; 32]), &[3; 32]);
        for mask in preset_masks::all() {
            let mut session = Session::new(
                [7; 16],
                "127.0.0.1:9".parse().unwrap(),
                keys.clone(),
                [3; 32],
            );
            session.mask = Some(mask.clone());
            let session = Arc::new(parking_lot::Mutex::new(session));
            let mdh = packet_mdh_bytes_for_mask(&mask);
            for length in [1280, 1346, 1500] {
                let payload: Vec<_> = (0..length).map(|n| (n % 251) as u8).collect();
                let (_, stateful, packets) =
                    Gateway::build_inner_packets(&mdh, InnerType::Data, &payload, &session)
                        .unwrap();
                assert_eq!(stateful, aivpn_common::mask_io::needs_state(&mask));
                let budget = if stateful {
                    aivpn_common::mask_io::MAX_QUIC_INNER
                } else {
                    1380
                };
                let mut window = RecvWindow::new();
                let mut fragments = Reassembler::default();
                let mut received = None;
                for packet in packets {
                    assert!(
                        packet.len() <= budget,
                        "{}: {} > {budget}",
                        mask.mask_id,
                        packet.len()
                    );
                    let decoded = decode_packet_with_layout(
                        &packet,
                        &keys,
                        &mut window,
                        mdh.len(),
                        mask.tag_offset,
                    )
                    .unwrap();
                    assert_eq!(decoded.header.inner_type, InnerType::Fragment);
                    if let Some((kind, bytes)) =
                        fragments.accept(&decoded.payload, Instant::now()).unwrap()
                    {
                        assert_eq!(kind, InnerType::Data);
                        received = Some(bytes);
                    }
                }
                assert_eq!(received, Some(payload));
            }
        }
    }
}
