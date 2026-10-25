//! Прием и отправка IP-пакетов через TUN, downlink и ответы шлюза на ping.

use super::*;

impl super::Gateway {
    /// TUN read loop: reads packets from TUN device and routes them back to clients
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn tun_read_loop(
        mut tun_reader: tun::DeviceReader,
        tun_writer: tokio::sync::mpsc::Sender<Vec<u8>>,
        sessions: Arc<SessionManager>,
        socket: Arc<MaskSocket>,
        chain_reverse_routes: Arc<DashMap<std::net::IpAddr, ([u8; 16], Instant)>>,
        chain_reverse_rx: Option<mpsc::Receiver<Vec<u8>>>,
        mask: MaskProfile,
        network: aivpn_common::network_config::VpnNetworkConfig,
        recorder: Option<Arc<RecordingManager>>,
        client_db: Option<Arc<ClientDatabase>>,
        qos_enforcer: Arc<crate::qos::QosEnforcer>,
        allow_peer_routing: bool,
        downlink_shaping: ShapingLevel,
        pool_dialer: Option<Arc<crate::pool_dialer::PoolDialer>>,
        site_data_rx: Option<mpsc::Receiver<Vec<u8>>>,
        kernel_accel: Option<Arc<KernelAccel>>,
    ) {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let server_ip = network.server_vpn_ip;

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
                network.clone(),
                kernel_accel.clone(),
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
                    let Some(header) = aivpn_common::ip_packet::IpPacket::parse(&packet) else {
                        continue;
                    };
                    let dst_ip = header.destination;
                    let worker_idx = header.destination_shard(reverse_worker_count);
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

        // SiteData принимается в локальный TUN. Это не ответ клиенту и не NAT.
        if let Some(mut rx) = site_data_rx {
            let tun_inject = tun_writer.clone();
            tokio::spawn(async move {
                while let Some(packet) = rx.recv().await {
                    if tun_inject.send(packet).await.is_err() {
                        break;
                    }
                }
            });
        }

        loop {
            match tun_reader.read(&mut buf).await {
                Ok(0) => continue,
                Ok(n) => {
                    let packet = &buf[..n];

                    let Some(header) = aivpn_common::ip_packet::IpPacket::parse(packet) else {
                        continue;
                    };
                    let packet = &packet[..header.length];
                    let dst_ip = header.destination;

                    // Handle ICMP echo request to server's own IP (ping to gateway)
                    if dst_ip == std::net::IpAddr::V4(server_ip)
                        && packet.len() >= 28
                        && packet[9] == 1
                    {
                        // ICMP packet to server — generate echo reply
                        if let Some(reply) = Self::build_icmp_echo_reply(packet, &server_ip) {
                            let _ = tun_writer.send(reply).await;
                        }
                        continue;
                    }

                    // Адрес ровно одной площадки уходит SiteData и не попадает в NAT.
                    // Две площадки или dialer молчит: пакет дропаем, наружу не выпускаем.
                    {
                        match crate::site_sync::site_destination_for(dst_ip) {
                            Some(crate::site_sync::SiteDestination::Peer(endpoint)) => {
                                if let Some(dialer) = pool_dialer.as_ref() {
                                    let _ = dialer.send_to_peer(
                                        &endpoint,
                                        ControlPayload::SiteData {
                                            payload: packet.to_vec(),
                                        },
                                    );
                                }
                                continue;
                            }
                            Some(crate::site_sync::SiteDestination::Ambiguous) => {
                                debug!(
                                    "TUN: site destination {} matches more than one peer",
                                    dst_ip
                                );
                                continue;
                            }
                            None => {}
                        }
                    }

                    // Guard client-to-client relay (0.9.0+).
                    // If the packet's source IP belongs to a VPN client session,
                    // this is intra-VPN (peer-to-peer) traffic — only forward when
                    // allow_peer_routing is enabled.
                    if !allow_peer_routing {
                        let src_ip = header.source;
                        if inner_client_ipv4(&network, src_ip)
                            .and_then(|ip| sessions.get_session_by_vpn_ip(&ip))
                            .is_some()
                        {
                            debug!(
                                "TUN: dropping peer packet {}->{} (allow_peer_routing=false)",
                                src_ip, dst_ip
                            );
                            continue;
                        }
                    }

                    let worker_idx = header.destination_shard(worker_count);
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
        socket: Arc<MaskSocket>,
        chain_reverse_routes: Arc<DashMap<std::net::IpAddr, ([u8; 16], Instant)>>,
        mask: MaskProfile,
        recorder: Option<Arc<RecordingManager>>,
        client_db: Option<Arc<ClientDatabase>>,
        qos_enforcer: Arc<crate::qos::QosEnforcer>,
        downlink_shaping: ShapingLevel,
        network: aivpn_common::network_config::VpnNetworkConfig,
        kernel_accel: Option<Arc<KernelAccel>>,
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
        let batch_io = crate::batch_io::BatchIo::with_sources(socket.raw(), socket.reply_sources());
        let mut wire_bufs: Vec<Vec<u8>> = (0..crate::batch_io::MAX_BATCH)
            .map(|_| Vec::with_capacity(MAX_PACKET_SIZE))
            .collect();
        let mut drained: Vec<(Vec<u8>, Option<super::downlink_pacing::PacedData>)> =
            Vec::with_capacity(crate::batch_io::MAX_BATCH);
        let mut pacer = super::downlink_pacing::DownlinkPacer::new();
        let mut input_closed = false;
        #[allow(clippy::type_complexity)]
        let mut sends: Vec<(
            SocketAddr,
            Option<([u8; 16], aivpn_common::recording::PacketMetadata)>,
            bool,
        )> = Vec::with_capacity(crate::batch_io::MAX_BATCH);

        loop {
            drained.clear();
            if input_closed && pacer.is_empty() {
                break;
            }
            let deadline = pacer.next_deadline();
            tokio::select! {
                biased;
                _ = async {
                    match deadline {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    while drained.len() < crate::batch_io::MAX_BATCH {
                        let Some(mut ready) = pacer.pop_ready_when(tokio::time::Instant::now(), |session_id| {
                            if input_closed { return true; }
                            sessions.get_session(session_id).is_none_or(|session| {
                                let session = session.lock();
                                !session.mask.as_ref().is_some_and(aivpn_common::mask_io::uses_rtc)
                                    || socket.rtc_data_ready(session.client_addr)
                            })
                        }) else {
                            break;
                        };
                        drained.push((std::mem::take(&mut ready.packet), Some(ready)));
                    }
                }
                incoming = rx.recv(), if !input_closed => {
                    match incoming {
                        Some(packet) => drained.push((packet, None)),
                        None => input_closed = true,
                    }
                }
            }
            while drained.len() < crate::batch_io::MAX_BATCH {
                match rx.try_recv() {
                    Ok(p) => drained.push((p, None)),
                    Err(_) => break,
                }
            }

            sends.clear();
            for (packet_vec, planned) in drained.drain(..) {
                let packet = packet_vec.as_slice();
                let n = packet.len();
                let Some(header) = aivpn_common::ip_packet::IpPacket::parse(packet) else {
                    continue;
                };
                let dst_ip = header.destination;
                let session = match inner_client_ipv4(&network, dst_ip)
                    .and_then(|ip| sessions.get_session_by_vpn_ip(&ip))
                {
                    Some(s) => s,
                    None => {
                        if planned.is_some() {
                            continue;
                        }
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

                // Общий qos_charge до шифрования. PassCharged уже списан ядром.
                let (qos_cid, session_id) = {
                    let mut session = session.lock();
                    let required = session.mtls_required;
                    if session.kernel_faulted
                        || !session_allows_client_data(&session, client_db.as_deref())
                        || session.keys.packet_cipher.is_initial()
                        || !session.refresh_mtls_gate(required)
                    {
                        continue;
                    }
                    session.commit_pending_mask();
                    if planned.as_ref().is_some_and(|plan| {
                        plan.session_id != session.session_id
                            || !plan.matches_profile(session.mask.as_ref().unwrap_or(&mask))
                    }) {
                        continue;
                    }
                    if session
                        .mask
                        .as_ref()
                        .is_some_and(aivpn_common::mask_io::uses_rtc)
                        && !socket.rtc_data_ready(session.client_addr)
                    {
                        if !input_closed {
                            let active = session.mask.as_ref().unwrap_or(&mask);
                            let queued = if downlink_shaping == ShapingLevel::Off {
                                pacer.enqueue_unpaced(
                                    session.session_id,
                                    active,
                                    packet_vec,
                                    tokio::time::Instant::now(),
                                )
                            } else {
                                pacer.enqueue_shaped(
                                    session.session_id,
                                    active,
                                    packet_vec,
                                    tokio::time::Instant::now(),
                                    downlink_shaping,
                                )
                            };
                            if !queued {
                                debug!("Downlink: очередь ожидания RTC заполнена");
                            }
                        }
                        continue;
                    }
                    if planned.is_none() && downlink_shaping != ShapingLevel::Off {
                        session.commit_pending_mask();
                        if !pacer.enqueue_shaped(
                            session.session_id,
                            session.mask.as_ref().unwrap_or(&mask),
                            packet_vec,
                            tokio::time::Instant::now(),
                            downlink_shaping,
                        ) {
                            debug!("Downlink: очередь шейпинга заполнена, пакет отброшен");
                        }
                        continue;
                    }
                    (session.client_id.clone(), session.session_id)
                };
                let nbytes = u32::try_from(n).unwrap_or(u32::MAX);
                match kernel_qos_decide(kernel_accel.as_deref(), &session_id, QOS_DIR_DOWN, nbytes)
                {
                    QosGate::Drop => {
                        debug!("QoS: kernel dropped downstream packet");
                        continue;
                    }
                    QosGate::PassCharged => {}
                    QosGate::Userspace => {
                        if let Some(ref cid) = qos_cid {
                            if !qos_enforcer.check_downstream(cid, n as u64) {
                                debug!("QoS: downstream rate limited, dropping packet for {}", cid);
                                continue;
                            }
                        }
                    }
                }

                let fragment_mdh = {
                    let mut sess = session.lock();
                    sess.commit_pending_mask();
                    let active = sess.mask.as_ref().unwrap_or(&mask);
                    (n > aivpn_common::mimicry::data_payload_limit(active, SAFE_DOWNLINK_BUDGET))
                        .then(|| packet_mdh_bytes_for_mask(active))
                };
                if let Some(mdh) = fragment_mdh {
                    let frames = Self::build_inner_packets(&mdh, InnerType::Data, packet, &session);
                    match frames {
                        Ok((address, stateful, frames)) => {
                            for frame in frames {
                                match socket.send_with_mask(&frame, address, stateful).await {
                                    Ok(bytes) => {
                                        let iat_ms = {
                                            let mut sess = session.lock();
                                            let iat_ms =
                                                sess.last_server_send.elapsed().as_secs_f64()
                                                    * 1000.0;
                                            sess.pending_bytes_out =
                                                sess.pending_bytes_out.saturating_add(bytes as u64);
                                            sess.last_server_send = Instant::now();
                                            iat_ms
                                        };
                                        if let Some(ref recorder) = recorder {
                                            if recorder.is_recording(&session_id) {
                                                recorder.record_packet(session_id, aivpn_common::recording::PacketMetadata {
                                                    direction: aivpn_common::recording::Direction::Downlink,
                                                    size: frame.len() as u16,
                                                    iat_ms,
                                                    entropy: Self::compute_entropy(&frame) as f32,
                                                    header_prefix: inner_l7_prefix(packet),
                                                    timestamp_ns: std::time::SystemTime::now()
                                                        .duration_since(std::time::UNIX_EPOCH)
                                                        .unwrap_or_default().as_nanos() as u64,
                                                });
                                            }
                                        }
                                    }
                                    Err(error) => {
                                        debug!("TUN: ошибка отправки фрагментов: {error}");
                                        break;
                                    }
                                }
                            }
                        }
                        Err(error) => debug!("TUN: ошибка сборки фрагментов: {error}"),
                    }
                    continue;
                }

                // Build encrypted response packet
                // Minimize lock duration: extract only what we need under lock, then encrypt outside
                let (session_id, client_addr, downlink_iat_ms, tag, mdh, framing, stateful) = {
                    let mut sess = session.lock();
                    // Commit deferred mask switch if grace period has elapsed
                    sess.commit_pending_mask();
                    if planned.as_ref().is_some_and(|plan| {
                        !plan.matches_profile(sess.mask.as_ref().unwrap_or(&mask))
                    }) {
                        continue;
                    }
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
                    let framing = sess
                        .mask
                        .as_ref()
                        .unwrap_or(&mask)
                        .packet_framing(session_mdh.len());
                    let base_overhead = framing.prefix_len()
                        + session_mdh.len()
                        + 2
                        + 4
                        + n
                        + aivpn_common::crypto::POLY1305_TAG_SIZE;
                    let stateful = sess
                        .mask
                        .as_ref()
                        .is_some_and(aivpn_common::mask_io::requires_userspace);
                    let packet_budget = if sess
                        .mask
                        .as_ref()
                        .is_some_and(aivpn_common::mask_io::needs_state)
                    {
                        aivpn_common::mask_io::MAX_QUIC_INNER
                    } else if sess
                        .mask
                        .as_ref()
                        .is_some_and(aivpn_common::mask_io::uses_rtc)
                    {
                        aivpn_common::mask_io::rtc_inner_budget(sess.mask.as_ref().unwrap())
                    } else {
                        SAFE_DOWNLINK_BUDGET
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
                        ShapingLevel::Adaptive | ShapingLevel::Full | ShapingLevel::Light => {
                            {
                                let profile = sess.mask.as_ref().unwrap_or(&mask);
                                let m = profile.reverse_profile.as_deref().unwrap_or(profile);
                                // `+ 4` accounts for the InnerHeader
                                // (`InnerHeader::encode` — [u8; 4]) that is
                                // part of the encrypted plaintext below (see
                                // the `plaintext_buf` assembly) but was missing
                                // here: without it a max-padded packet ran
                                // SAFE_DOWNLINK_BUDGET + 4 on the wire, and
                                // every shaped packet sat 4 bytes above its
                                // mask's target size.
                                let target = planned
                                    .as_ref()
                                    .map(|plan| plan.target_size)
                                    .unwrap_or_else(|| m.size_distribution.sample(&mut rng));
                                let strategy = planned
                                    .as_ref()
                                    .and_then(|plan| plan.padding_override.as_ref())
                                    .unwrap_or(&m.padding_strategy);
                                let requested = strategy.calc_padding(
                                    base_overhead
                                        + aivpn_common::mask_io::carrier_overhead(profile),
                                    target,
                                    &mut rng,
                                );
                                let max_pad = packet_budget.saturating_sub(base_overhead) as u16;
                                let capped = requested.min(max_pad);
                                if downlink_shaping == ShapingLevel::Light {
                                    capped.min(LIGHT_SHAPING_MAX_PAD)
                                } else {
                                    capped
                                }
                            }
                        }
                    };
                    let Ok(pad_len) = framing.padding(
                        base_overhead,
                        pad_len,
                        packet_budget.saturating_sub(base_overhead) as u16,
                    ) else {
                        continue;
                    };
                    // Полный UDP payload: тег, заголовок маски, padding и AEAD.
                    let estimated_out = (base_overhead + pad_len as usize) as u64;
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

                    (
                        session_id,
                        client_addr,
                        downlink_iat_ms,
                        tag,
                        mdh,
                        framing,
                        stateful,
                    )
                };

                // Assemble: TAG | MDH | ciphertext into this packet's wire slot.
                let wire_buf = &mut wire_bufs[sends.len()];
                if let Err(error) = framing.assemble_into(wire_buf, &mdh, &tag, &ciphertext_buf) {
                    debug!("TUN: ошибка упаковки downlink: {error}");
                    continue;
                }

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
                sends.push((client_addr, rec_meta, stateful));
            }

            if sends.is_empty() {
                continue;
            }
            let mut masked_failed = false;
            let mut msgs = Vec::with_capacity(sends.len());
            for (index, (addr, _, stateful)) in sends.iter().enumerate() {
                if *stateful || socket.needs_wrapping(&wire_bufs[index], *addr) {
                    if socket
                        .send_data_with_mask(&wire_bufs[index], *addr, *stateful)
                        .await
                        .is_err()
                    {
                        masked_failed = true;
                    }
                } else {
                    msgs.push((wire_bufs[index].as_slice(), *addr));
                }
            }
            match batch_io.send_batch(&msgs).await {
                Err(e) => debug!("TUN: batched send failed: {}", e),
                Ok(()) if !masked_failed => {
                    if let Some(ref recorder) = recorder {
                        drop(msgs);
                        for (_, rec, _) in sends.drain(..) {
                            if let Some((sid, meta)) = rec {
                                recorder.record_packet(sid, meta);
                            }
                        }
                    }
                }
                Ok(()) => debug!("Очередь протокола маски переполнена"),
            }
        }
        warn!("Downlink worker {} ended — channel closed", worker_id);
    }

    /// Формирует полный IPv4-пакет: TUN не пересчитывает контрольные суммы.
    fn build_icmp_echo_reply(request: &[u8], server_ip: &Ipv4Addr) -> Option<Vec<u8>> {
        let parsed = aivpn_common::ip_packet::IpPacket::parse(request)?;
        if request[0] >> 4 != 4 || request[9] != 1 {
            return None;
        }
        let header_len = usize::from(request[0] & 15) * 4;
        let fragment = u16::from_be_bytes([request[6], request[7]]);
        if fragment & 0x3fff != 0 || parsed.length < header_len + 8 {
            return None;
        }
        let icmp = &request[header_len..parsed.length];
        if icmp[0] != 8 || icmp[1] != 0 || Self::compute_checksum(icmp) != 0 {
            return None;
        }
        let mut reply = vec![0; 20];
        reply[0] = 0x45;
        reply[1] = request[1];
        reply[2..4].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
        reply[4..6].copy_from_slice(&request[4..6]);
        reply[6..8].copy_from_slice(&(fragment & 0x4000).to_be_bytes());
        reply[8] = 64;
        reply[9] = 1;
        reply[12..16].copy_from_slice(&server_ip.octets());
        reply[16..20].copy_from_slice(&request[12..16]);
        reply.extend_from_slice(icmp);
        reply[20] = 0;
        reply[22..24].fill(0);
        let checksum = Self::compute_checksum(&reply[20..]);
        reply[22..24].copy_from_slice(&checksum.to_be_bytes());
        let checksum = Self::compute_checksum(&reply[..20]);
        reply[10..12].copy_from_slice(&checksum.to_be_bytes());
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

#[cfg(test)]
mod icmp_tests {
    use super::*;

    fn request(options: bool) -> Vec<u8> {
        let header_len = if options { 24 } else { 20 };
        let mut bytes = vec![0; header_len];
        bytes[0] = 0x40 | (header_len / 4) as u8;
        bytes[8] = 64;
        bytes[9] = 1;
        bytes[12..16].copy_from_slice(&[10, 0, 0, 2]);
        bytes[16..20].copy_from_slice(&[10, 0, 0, 1]);
        if options {
            bytes[20..24].copy_from_slice(&[1, 1, 0, 0]);
        }
        bytes.extend_from_slice(&[8, 0, 0, 0, 0x12, 0x34, 0, 1, 7, 8, 9]);
        let len = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&len.to_be_bytes());
        let checksum = Gateway::compute_checksum(&bytes[header_len..]);
        bytes[header_len + 2..header_len + 4].copy_from_slice(&checksum.to_be_bytes());
        let checksum = Gateway::compute_checksum(&bytes[..header_len]);
        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        bytes
    }

    #[test]
    fn echo_reply_has_valid_ip_and_icmp_checksums_with_or_without_options() {
        for options in [false, true] {
            let original = request(options);
            let reply =
                Gateway::build_icmp_echo_reply(&original, &Ipv4Addr::new(10, 0, 0, 1)).unwrap();
            assert_eq!(reply.len(), 31);
            assert_eq!(Gateway::compute_checksum(&reply[..20]), 0);
            assert_eq!(Gateway::compute_checksum(&reply[20..]), 0);
            assert_eq!(&reply[12..20], &[10, 0, 0, 1, 10, 0, 0, 2]);
            assert_eq!(&reply[24..], &[0x12, 0x34, 0, 1, 7, 8, 9]);
            assert_eq!(reply[20], 0);
        }
    }

    #[test]
    fn echo_reply_rejects_fragments_truncation_and_bad_icmp() {
        let gateway = Ipv4Addr::new(10, 0, 0, 1);
        for fragment in [1u16, 0x2000] {
            let mut bytes = request(false);
            bytes[6..8].copy_from_slice(&fragment.to_be_bytes());
            assert!(Gateway::build_icmp_echo_reply(&bytes, &gateway).is_none());
        }
        let mut bytes = request(true);
        bytes[24] = 0;
        assert!(Gateway::build_icmp_echo_reply(&bytes, &gateway).is_none());
        let bytes = request(false);
        for len in 0..bytes.len() {
            assert!(Gateway::build_icmp_echo_reply(&bytes[..len], &gateway).is_none());
        }
    }
}
