//! Data-plane TUN/downlink hot path: `tun_read_loop` (drains the TUN
//! device and dispatches to the sharded `downlink_worker`s), the
//! dedicated `tun_write_loop`, ICMP echo-reply synthesis, and the
//! Internet-checksum helper it uses. Pure move out of `gateway/mod.rs`
//! — no behavior change.

use super::*;

impl super::Gateway {
    /// TUN read loop: reads packets from TUN device and routes them back to clients
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn tun_read_loop(
        mut tun_reader: tun::DeviceReader,
        tun_writer: tokio::sync::mpsc::Sender<Vec<u8>>,
        sessions: Arc<SessionManager>,
        socket: Arc<UdpSocket>,
        chain_reverse_routes: Arc<DashMap<Ipv4Addr, ([u8; 16], Instant)>>,
        chain_reverse_rx: Option<mpsc::Receiver<Vec<u8>>>,
        mask: MaskProfile,
        server_vpn_ip: Ipv4Addr,
        recorder: Option<Arc<RecordingManager>>,
        client_db: Option<Arc<ClientDatabase>>,
        qos_enforcer: Arc<crate::qos::QosEnforcer>,
        allow_peer_routing: bool,
        downlink_shaping: ShapingLevel,
    ) {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let server_ip = server_vpn_ip;

        // A1: shard the downlink across workers by destination VPN IP so
        // encryption for different clients runs in parallel. One dst IP always
        // maps to the same worker (one session per VPN IP), so per-client
        // packet order — and thus per-session nonce/seq monotonicity on the
        // wire — is preserved. Mirrors the uplink sharding in
        // process_packets_concurrent.
        let worker_count = Self::receive_worker_count();
        let mut worker_txs = Vec::with_capacity(worker_count);
        for worker_id in 0..worker_count {
            let (tx, rx) = mpsc::channel::<Vec<u8>>(4096);
            worker_txs.push(tx);
            tokio::spawn(Self::downlink_worker(
                rx,
                worker_id,
                sessions.clone(),
                socket.clone(),
                chain_reverse_routes.clone(),
                mask.clone(),
                recorder.clone(),
                client_db.clone(),
                qos_enforcer.clone(),
                downlink_shaping,
            ));
        }
        info!("Downlink sharded across {} workers", worker_count);

        // PHASE 4 (reverse chain-forward, ENTRY side): if this node dials an
        // exit over the masked pool-client transport, `chain_reverse_rx`
        // carries reply packets the exit sent back for one of our clients
        // (see `Gateway::chain_reverse_tx`'s doc comment and
        // `pool_dialer.rs`'s `anti_entropy` inbound `ChainForward` tap).
        // Dispatch each one into the SAME per-worker downlink channels the
        // ordinary TUN reader feeds below — i.e. the normal client-downlink
        // encrypt+send path (session lookup, QoS, encryption, UDP send) —
        // sharded by dst VPN IP exactly like a locally-read TUN packet.
        // Deliberately NOT written to `tun_writer`: that would re-inject the
        // packet into this node's own local TUN/internet egress instead of
        // delivering it to the client. `None` (no exit configured, or not
        // running masked transport) makes this a no-op.
        if let Some(mut rx) = chain_reverse_rx {
            let reverse_worker_txs = worker_txs.clone();
            let reverse_worker_count = worker_count;
            tokio::spawn(async move {
                while let Some(packet) = rx.recv().await {
                    if packet.len() < 20 || (packet[0] >> 4) != 4 {
                        continue; // Not IPv4
                    }
                    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                    let worker_idx = (u32::from(dst_ip) as usize) % reverse_worker_count;
                    if reverse_worker_txs[worker_idx].send(packet).await.is_err() {
                        debug!(
                            "chain_reverse: downlink worker {} channel closed — dropping reply for {}",
                            worker_idx, dst_ip
                        );
                    }
                }
            });
            info!("chain_reverse: reverse-chain-forward downlink dispatch active");
        }

        loop {
            match tun_reader.read(&mut buf).await {
                Ok(0) => continue,
                Ok(n) => {
                    let packet = &buf[..n];

                    // Parse destination IP from IP header
                    if packet.len() < 20 || (packet[0] >> 4) != 4 {
                        continue; // Not IPv4
                    }
                    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

                    // Handle ICMP echo request to server's own IP (ping to gateway)
                    if dst_ip == server_ip && packet.len() >= 28 && packet[9] == 1 {
                        // ICMP packet to server — generate echo reply
                        if let Some(reply) = Self::build_icmp_echo_reply(packet, &server_ip) {
                            let _ = tun_writer.send(reply).await;
                        }
                        continue;
                    }

                    // Guard client-to-client relay (0.9.0+).
                    // If the packet's source IP belongs to a VPN client session,
                    // this is intra-VPN (peer-to-peer) traffic — only forward when
                    // allow_peer_routing is enabled.
                    if !allow_peer_routing {
                        let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
                        if sessions.get_session_by_vpn_ip(&src_ip).is_some() {
                            debug!(
                                "TUN: dropping peer packet {}->{} (allow_peer_routing=false)",
                                src_ip, dst_ip
                            );
                            continue;
                        }
                    }

                    let worker_idx = (u32::from(dst_ip) as usize) % worker_count;
                    if worker_txs[worker_idx].send(packet.to_vec()).await.is_err() {
                        warn!(
                            "Downlink worker {} channel closed — dropping packet for {}",
                            worker_idx, dst_ip
                        );
                    }
                }
                Err(e) => {
                    error!("TUN read error: {}", e);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    /// Per-worker downlink processing (A1): session lookup, QoS, encryption
    /// and UDP send for every packet whose dst VPN IP shards to this worker.
    #[allow(clippy::too_many_arguments)]
    async fn downlink_worker(
        mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        worker_id: usize,
        sessions: Arc<SessionManager>,
        socket: Arc<UdpSocket>,
        chain_reverse_routes: Arc<DashMap<Ipv4Addr, ([u8; 16], Instant)>>,
        mask: MaskProfile,
        recorder: Option<Arc<RecordingManager>>,
        client_db: Option<Arc<ClientDatabase>>,
        qos_enforcer: Arc<crate::qos::QosEnforcer>,
        downlink_shaping: ShapingLevel,
    ) {
        // A7: RNG for downlink padding size sampling + filler bytes. Per-worker
        // (not per-packet) to avoid re-seeding on the hot path.
        let mut rng = rand::rngs::StdRng::from_entropy();

        // Reusable per-packet scratch buffers, hoisted out of the loop to kill
        // per-datagram heap allocations on the downlink hot path (A3). Each is
        // `.clear()`ed and refilled every iteration instead of being allocated
        // fresh. `plaintext_buf` holds cleartext (pad_len || inner_header ||
        // IP packet || padding) and is zeroized after use so no VPN payload
        // lingers in the pooled allocation.
        let mut plaintext_buf: Vec<u8> = Vec::with_capacity(MAX_PACKET_SIZE);
        let mut ciphertext_buf: Vec<u8> =
            Vec::with_capacity(MAX_PACKET_SIZE + aivpn_common::crypto::POLY1305_TAG_SIZE);

        // A2: drain up to MAX_BATCH queued packets per wakeup, encrypt them
        // all into per-slot wire buffers, then push the whole batch out with
        // one sendmmsg. Order within the worker — and therefore per client —
        // is unchanged. Wire buffers are reused across batches.
        let batch_io = crate::batch_io::BatchIo::new(socket.clone());
        let mut wire_bufs: Vec<Vec<u8>> = (0..crate::batch_io::MAX_BATCH)
            .map(|_| Vec::with_capacity(MAX_PACKET_SIZE))
            .collect();
        let mut drained: Vec<Vec<u8>> = Vec::with_capacity(crate::batch_io::MAX_BATCH);
        #[allow(clippy::type_complexity)]
        let mut sends: Vec<(
            SocketAddr,
            Option<([u8; 16], aivpn_common::recording::PacketMetadata)>,
        )> = Vec::with_capacity(crate::batch_io::MAX_BATCH);

        while let Some(first) = rx.recv().await {
            drained.clear();
            drained.push(first);
            while drained.len() < crate::batch_io::MAX_BATCH {
                match rx.try_recv() {
                    Ok(p) => drained.push(p),
                    Err(_) => break,
                }
            }

            sends.clear();
            for packet_vec in drained.drain(..) {
                let packet = packet_vec.as_slice();
                let n = packet.len();
                // Reader already validated this is an IPv4 header of >= 20 bytes.
                let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                // Find session by VPN IP
                let session = match sessions.get_session_by_vpn_ip(&dst_ip) {
                    Some(s) => s,
                    None => {
                        // PHASE 4 (reverse chain-forward): dst_ip may be an
                        // origin client that lives on a different (entry)
                        // node — this exit only ever saw it via a masked
                        // pool-peer's ChainForward uplink (see the
                        // ChainForward RECEIVE arm in
                        // `handle_control_message`, which populates
                        // `chain_reverse_routes`). If a route for it is
                        // still fresh, send this reply back over that SAME
                        // session as a ChainForward control message instead
                        // of silently dropping it — the pre-existing
                        // exit-downlink gap this closes. Falls through to
                        // the original drop+debug when there is no route,
                        // the route is stale, or the peer session is gone.
                        match chain_reverse_route_lookup(
                            &chain_reverse_routes,
                            &dst_ip,
                            Instant::now(),
                        )
                        .and_then(|session_id| sessions.get_session(&session_id))
                        {
                            Some(peer_session) => {
                                let mdh = {
                                    let sess = peer_session.lock();
                                    sess.mask
                                        .as_ref()
                                        .map(packet_mdh_bytes_for_mask)
                                        .unwrap_or_else(|| mask.header_template.clone())
                                };
                                let reverse_payload = ControlPayload::ChainForward {
                                    payload: packet.to_vec(),
                                };
                                if let Err(e) = Self::send_control_message_via(
                                    &socket,
                                    &mdh,
                                    &reverse_payload,
                                    &peer_session,
                                )
                                .await
                                {
                                    debug!(
                                        "chain_reverse: failed to send reverse ChainForward for {}: {}",
                                        dst_ip, e
                                    );
                                }
                            }
                            None => {
                                debug!("TUN: no session for VPN IP {}", dst_ip);
                            }
                        }
                        continue;
                    }
                };

                // QoS: enforce downstream rate limit before expensive encryption
                let qos_cid = { session.lock().client_id.clone() };
                if let Some(ref cid) = qos_cid {
                    if !qos_enforcer.check_downstream(cid, n as u64) {
                        debug!("QoS: downstream rate limited, dropping packet for {}", cid);
                        continue;
                    }
                }

                // Build encrypted response packet
                // Minimize lock duration: extract only what we need under lock, then encrypt outside
                let (session_id, client_addr, downlink_iat_ms, tag, mdh) = {
                    let mut sess = session.lock();
                    // Commit deferred mask switch if grace period has elapsed
                    sess.commit_pending_mask();
                    let session_id = sess.session_id;
                    let client_addr = sess.client_addr;
                    let seq_num = sess.next_seq() as u16;
                    let (nonce, counter) = sess.next_send_nonce();
                    // Downlink (server→client) uses the S2C key so it never
                    // shares a (key, nonce) with the client's uplink packets.
                    let key = sess.keys.session_key_s2c.clone();
                    let tag_secret = sess.keys.tag_secret;
                    let downlink_iat_ms = sess.last_server_send.elapsed().as_secs_f64() * 1000.0;
                    sess.last_server_send = Instant::now();
                    // Use the session's own mask for MDH so the client can
                    // decode with the mask it currently expects (bootstrap
                    // or runtime after MaskUpdate is processed).
                    // 1a: round-robin the session's pre-generated MDH pool
                    // instead of calling the mask's RNG-based generator fresh
                    // on every downlink packet (see `Session::next_mdh`).
                    let session_mdh = if sess.mask.is_some() {
                        sess.next_mdh()
                    } else {
                        mask.header_template.clone()
                    };

                    // A7/1c: size downlink padding from the SESSION mask's own
                    // size distribution — the same distribution + padding
                    // strategy the client applies to uplink — so both
                    // directions share one size signature on the 5-tuple.
                    // Computed under the lock while the mask is borrowed; the
                    // filler bytes are written after the lock is dropped.
                    // Legacy downlink framing: base overhead carries the
                    // TAG_SIZE prefix, the 2-byte pad_len field, and the AEAD
                    // tag. `ShapingLevel::Light` uses the same sampling but
                    // caps the result to a small fixed budget, trading most of
                    // the covertness back for throughput; `Off` skips it
                    // entirely.
                    let pad_len: u16 = match downlink_shaping {
                        ShapingLevel::Off => 0,
                        ShapingLevel::Full | ShapingLevel::Light => {
                            if let Some(ref m) = sess.mask {
                                // `+ 4` accounts for the InnerHeader
                                // (`InnerHeader::encode` — [u8; 4]) that is
                                // part of the encrypted plaintext below (see
                                // the `plaintext_buf` assembly) but was missing
                                // here: without it a max-padded packet ran
                                // SAFE_DOWNLINK_BUDGET + 4 on the wire, and
                                // every shaped packet sat 4 bytes above its
                                // mask's target size.
                                let base_overhead = TAG_SIZE
                                    + session_mdh.len()
                                    + 2
                                    + 4
                                    + n
                                    + aivpn_common::crypto::POLY1305_TAG_SIZE;
                                let target = m.size_distribution.sample(&mut rng);
                                let requested = m.padding_strategy.calc_padding(
                                    base_overhead,
                                    target,
                                    &mut rng,
                                );
                                let max_pad =
                                    SAFE_DOWNLINK_BUDGET.saturating_sub(base_overhead) as u16;
                                let capped = requested.min(max_pad);
                                if downlink_shaping == ShapingLevel::Light {
                                    capped.min(LIGHT_SHAPING_MAX_PAD)
                                } else {
                                    capped
                                }
                            } else {
                                0
                            }
                        }
                    };
                    // Pre-accumulate downlink bytes estimate (IP packet + overhead)
                    // This avoids a second lock after send_to
                    let estimated_out = (n + 64) as u64; // packet + AIVPN overhead
                    sess.pending_bytes_out = sess.pending_bytes_out.saturating_add(estimated_out);
                    // Flush downlink-only traffic to client_db when threshold reached
                    let flush_out = if sess.pending_bytes_out >= 64 * 1024 {
                        let bytes = sess.pending_bytes_out;
                        let cid = sess.client_id.clone();
                        sess.pending_bytes_out = 0;
                        cid.map(|c| (c, bytes))
                    } else {
                        None
                    };
                    drop(sess); // Release lock BEFORE expensive encryption
                                // Flush outside lock
                    if let (Some(ref db), Some((cid, bytes))) = (&client_db, flush_out) {
                        db.record_traffic(&cid, 0, bytes);
                    }

                    // Build inner payload: Data type + IP packet
                    let inner_header = InnerHeader {
                        inner_type: InnerType::Data,
                        seq_num,
                    };

                    // Build MDH using session mask (not global runtime mask)
                    let mdh = session_mdh;

                    // Assemble cleartext into the reused scratch buffer:
                    //   pad_len(LE u16) || inner_header || IP packet || padding
                    // Identical framing to the client's uplink `build_packet`
                    // (`pad_len || plaintext || random_pad`) so the client's
                    // `parse_downlink_inner` strips exactly `pad_len` trailing
                    // bytes. With A7 shaping off, pad_len is 0 and the layout is
                    // byte-identical to the pre-A7 downlink.
                    plaintext_buf.clear();
                    plaintext_buf.extend_from_slice(&pad_len.to_le_bytes());
                    plaintext_buf.extend_from_slice(&inner_header.encode());
                    plaintext_buf.extend_from_slice(packet);
                    if pad_len > 0 {
                        let pad_start = plaintext_buf.len();
                        plaintext_buf.resize(pad_start + pad_len as usize, 0);
                        rng.fill_bytes(&mut plaintext_buf[pad_start..]);
                    }

                    // Encrypt in place into the reused ciphertext buffer
                    // (outside lock). Produces the same bytes as
                    // encrypt_payload(&key, &nonce, &padded) did.
                    if let Err(e) =
                        encrypt_payload_into(&key, &nonce, &plaintext_buf, &mut ciphertext_buf)
                    {
                        debug!("TUN: encrypt error: {}", e);
                        plaintext_buf.zeroize();
                        continue;
                    }
                    // Cleartext VPN payload no longer needed — wipe before
                    // the buffer is reused on the next iteration.
                    plaintext_buf.zeroize();

                    // Generate tag (outside lock)
                    let time_window = crypto::compute_time_window(
                        crypto::current_timestamp_ms(),
                        aivpn_common::crypto::DEFAULT_WINDOW_MS,
                    );
                    let tag = crypto::generate_resonance_tag(&tag_secret, counter, time_window);

                    (session_id, client_addr, downlink_iat_ms, tag, mdh)
                };

                // Assemble: TAG | MDH | ciphertext into this packet's wire slot.
                let wire_buf = &mut wire_bufs[sends.len()];
                wire_buf.clear();
                wire_buf.extend_from_slice(&tag);
                wire_buf.extend_from_slice(&mdh);
                wire_buf.extend_from_slice(&ciphertext_buf);

                // bytes_out already tracked inside the earlier lock scope.
                // Recorder metadata is captured now (entropy needs this
                // packet's ciphertext before the scratch buffer is reused)
                // and emitted after the batch send below.
                let rec_meta = match recorder {
                    Some(ref r) if r.is_recording(&session_id) => Some((
                        session_id,
                        aivpn_common::recording::PacketMetadata {
                            direction: aivpn_common::recording::Direction::Downlink,
                            size: wire_buf.len() as u16,
                            iat_ms: downlink_iat_ms,
                            entropy: Self::compute_entropy(&ciphertext_buf) as f32,
                            // Learn the app header from the cleartext inner IP
                            // packet (`packet`), NOT the encrypted wire framing
                            // — see inner_l7_prefix.
                            header_prefix: inner_l7_prefix(packet),
                            timestamp_ns: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_nanos() as u64,
                        },
                    )),
                    _ => None,
                };
                sends.push((client_addr, rec_meta));
            }

            if sends.is_empty() {
                continue;
            }
            let msgs: Vec<(&[u8], SocketAddr)> = sends
                .iter()
                .enumerate()
                .map(|(i, (addr, _))| (wire_bufs[i].as_slice(), *addr))
                .collect();
            match batch_io.send_batch(&msgs).await {
                Err(e) => debug!("TUN: batched send failed: {}", e),
                Ok(()) => {
                    if let Some(ref recorder) = recorder {
                        drop(msgs);
                        for (_, rec) in sends.drain(..) {
                            if let Some((sid, meta)) = rec {
                                recorder.record_packet(sid, meta);
                            }
                        }
                    }
                }
            }
        }
        warn!("Downlink worker {} ended — channel closed", worker_id);
    }

    /// Build ICMP Echo Reply from Echo Request
    fn build_icmp_echo_reply(request: &[u8], server_ip: &Ipv4Addr) -> Option<Vec<u8>> {
        if request.len() < 28 {
            return None;
        }

        // Parse source IP
        let src_ip = Ipv4Addr::new(request[12], request[13], request[14], request[15]);

        // Parse ICMP type and code
        let icmp_type = request[20];
        if icmp_type != 8 {
            return None; // Not echo request
        }

        // Build reply: swap src/dst IP, change ICMP type to 0 (echo reply)
        let mut reply = Vec::with_capacity(request.len());

        // IP header
        reply.push(0x45); // Version 4, IHL 5
        reply.push(0x00); // DSCP/ECN
        let total_len = (request.len() as u16).to_be_bytes();
        reply.extend_from_slice(&total_len);
        reply.extend_from_slice(&request[4..6]); // Identification
        reply.extend_from_slice(&request[6..8]); // Flags/Fragment
        reply.push(64); // TTL
        reply.push(1); // Protocol: ICMP
        reply.push(0); // Header checksum (will be computed by kernel)
        reply.push(0);
        reply.extend_from_slice(&server_ip.octets()); // Source IP (server)
        reply.extend_from_slice(&src_ip.octets()); // Dest IP (client)

        // ICMP header
        reply.push(0); // Type: Echo Reply
        reply.push(request[21]); // Code
        reply.push(0); // Checksum placeholder
        reply.push(0);
        reply.extend_from_slice(&request[24..28]); // ID + Sequence
        reply.extend_from_slice(&request[28..]); // Data

        // Compute ICMP checksum
        let checksum = Self::compute_checksum(&reply[20..]);
        reply[22] = (checksum >> 8) as u8;
        reply[23] = (checksum & 0xFF) as u8;

        Some(reply)
    }

    /// Compute Internet checksum (RFC 1071)
    fn compute_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;

        // Process 16-bit words
        while i + 1 < data.len() {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            i += 2;
        }

        // Add remaining byte
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }

        // Fold 32-bit sum to 16 bits
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }

    /// Dedicated TUN writer task — owns the DeviceWriter, no Mutex contention
    pub(crate) async fn tun_write_loop(
        mut writer: tun::DeviceWriter,
        mut rx: mpsc::Receiver<Vec<u8>>,
    ) {
        while let Some(packet) = rx.recv().await {
            if let Err(e) = writer.write_all(&packet).await {
                error!("TUN write error: {}", e);
            }
            // No flush() — let the OS buffer writes for throughput
        }
        warn!("TUN write loop ended — channel closed");
    }
}
