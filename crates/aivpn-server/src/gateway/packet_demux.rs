//! Распределение UDP-пакетов по приемным задачам с учетом сессии и формата тега.

use super::*;

pub(crate) enum SessionLookup {
    Found((Arc<parking_lot::Mutex<Session>>, u64, bool, [u8; TAG_SIZE])),
    NotFound,
    RecoveryLimited,
}

impl super::Gateway {
    /// Candidate resonance tags for a packet — one per distinct layout offset
    /// that fits in the packet. `candidates[0]` is always the legacy offset-0
    /// tag.
    fn candidate_tags(&self, packet_data: &[u8]) -> Vec<[u8; TAG_SIZE]> {
        self.distinct_tag_offsets()
            .into_iter()
            .filter_map(|off| {
                let end = off.checked_add(TAG_SIZE)?;
                if packet_data.len() < end {
                    return None;
                }
                let mut tag = [0u8; TAG_SIZE];
                tag.copy_from_slice(&packet_data[off..end]);
                Some(tag)
            })
            .collect()
    }

    /// Resolve an incoming packet to an existing session, trying the resonance
    /// tag at every layout offset (legacy prefix at 0 plus each embedded mask
    /// offset). Returns the matched session, its validated counter, whether the
    /// matched tag was a ratcheted-key tag, and the resolved 8-byte tag (needed
    /// by the caller for downstream bookkeeping).
    ///
    /// Cheap O(1) `tag_map` probes run first and cover the common in-window case
    /// for BOTH layouts — critical, because an embedded-layout data packet never
    /// matches at offset 0, so relying on the gated scan would drop it under
    /// load or misroute it into the handshake path. Only if every fast probe
    /// misses AND the global fallback budget allows do the expensive
    /// drift-recovery scans run: `refresh_and_find_by_tag` refreshes stale
    /// entries in the `tag_map` (so we re-probe every offset afterwards to
    /// also recover embedded sessions), then `recover_session_by_tag`
    /// brute-forces counter drift per offset.
    ///
    /// A positive `tag_map` hit whose `validate_tag` fails is a replay / out-of
    /// -window packet for a KNOWN session and is dropped (`Err`), exactly like
    /// the original single-offset fast path — it never falls through to
    /// speculative handshake.
    pub(crate) fn find_existing_session(
        &self,
        packet_data: &[u8],
        client_ip: &IpAddr,
    ) -> Result<SessionLookup> {
        let tags = self.candidate_tags(packet_data);

        // 1) Fast O(1) path across all layout offsets — no scan.
        for tag in &tags {
            if let Some((session, counter, is_ratcheted)) =
                self.session_manager.find_session_by_tag(tag)?
            {
                return Ok(SessionLookup::Found((session, counter, is_ratcheted, *tag)));
            }
        }

        if !self.fallback_scan_allowed() {
            return Ok(SessionLookup::RecoveryLimited);
        }

        // 2) Window-drift refresh. `refresh_and_find_by_tag` rebuilds STALE
        //    sessions' tag windows (skipping already-current ones) and
        //    re-inserts current-window tags into `tag_map` as a side effect,
        //    so run it once with the legacy-offset tag, then re-probe every
        //    offset against the freshly refreshed map to also catch
        //    embedded-layout (and roamed-IP) sessions.
        if let Some(first) = tags.first() {
            if let Some((session, counter, is_ratcheted)) = self
                .session_manager
                .refresh_and_find_by_tag(first, client_ip)
            {
                return Ok(SessionLookup::Found((
                    session,
                    counter,
                    is_ratcheted,
                    *first,
                )));
            }
        }
        for tag in &tags {
            if let Some((session, counter, is_ratcheted)) =
                self.session_manager.find_session_by_tag(tag)?
            {
                return Ok(SessionLookup::Found((session, counter, is_ratcheted, *tag)));
            }
        }

        // 3) Counter-drift recovery across every offset.
        for tag in &tags {
            if let Some((session, counter, is_ratcheted)) =
                self.session_manager.recover_session_by_tag(tag, client_ip)
            {
                return Ok(SessionLookup::Found((session, counter, is_ratcheted, *tag)));
            }
        }

        Ok(SessionLookup::NotFound)
    }

    pub(crate) fn receive_worker_count() -> usize {
        std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(4)
            .clamp(2, 16)
    }

    fn worker_index_for_packet(
        &self,
        packet_data: &[u8],
        client_addr: SocketAddr,
        worker_count: usize,
    ) -> usize {
        if worker_count <= 1 {
            return 0;
        }

        let mut shard_addr = client_addr;

        // Resolve the session by trying the resonance tag at every layout
        // offset (legacy prefix at 0 plus each embedded mask offset) so an
        // embedded-layout packet still shards onto its session's worker. A miss
        // falls back to hashing the client address, which is stable per client.
        for tag in self.candidate_tags(packet_data) {
            if let Some(session) = self.session_manager.get_session_by_tag(&tag) {
                shard_addr = session.lock().client_addr;
                break;
            }
        }

        let key = match shard_addr.ip() {
            IpAddr::V4(ip) => ((u32::from(ip) as u64) << 16) | shard_addr.port() as u64,
            IpAddr::V6(ip) => {
                let octets = ip.octets();
                u64::from_le_bytes(octets[..8].try_into().unwrap()) ^ shard_addr.port() as u64
            }
        };

        (key as usize) % worker_count
    }

    /// Concurrent packet processing loop with shard workers.
    /// Packets for the same session stay on the same worker and preserve order,
    /// while different sessions can be processed in parallel.
    pub(crate) async fn process_packets_concurrent(gateway: Arc<Self>) -> Result<()> {
        let socket = gateway.udp_socket.as_ref().unwrap().clone();
        let worker_count = Self::receive_worker_count();
        let queue_depth = 4096;
        let mut worker_txs = Vec::with_capacity(worker_count);

        for worker_id in 0..worker_count {
            let (tx, mut rx) = mpsc::channel::<QueuedPacket>(queue_depth);
            worker_txs.push(tx);

            let gw = gateway.clone();
            tokio::spawn(async move {
                while let Some(packet) = rx.recv().await {
                    let result = if packet.masked {
                        gw.handle_decoded_packet(super::mask_socket::DecodedPacket {
                            payload: packet.packet_data,
                            peer: packet.client_addr,
                            quic: packet.quic_inner,
                            context: packet.quic_context,
                        })
                        .await
                    } else {
                        gw.handle_packet_with_source(
                            &packet.packet_data,
                            packet.client_addr,
                            packet.local,
                        )
                        .await
                    };
                    if let Err(e) = result {
                        debug!(
                            "Worker {} packet error from {}: {}",
                            worker_id,
                            hash_addr(&packet.client_addr),
                            e
                        );
                    }
                }
                warn!("Receive worker {} ended — channel closed", worker_id);
            });
        }

        // A2: pull datagrams in batches (recvmmsg on Linux) — one syscall per
        // up-to-64 packets instead of one per packet. Buffers are reused
        // across iterations; only the per-worker handoff copies.
        let batch_io = crate::batch_io::BatchIo::with_sources(socket.raw(), socket.reply_sources());
        let mut slots: Vec<crate::batch_io::RecvSlot> = (0..crate::batch_io::MAX_BATCH)
            .map(|_| crate::batch_io::RecvSlot::new(MAX_PACKET_SIZE))
            .collect();

        let mut rates = crate::source_rates::UdpIngressRates::default();
        loop {
            let received = tokio::select! {
                payload = socket.decoded() => {
                    if let Some(packet) = payload {
                        let index = gateway.worker_index_for_packet(&packet.payload, packet.peer, worker_count);
                        let _ = worker_txs[index].try_send(QueuedPacket { local: None, packet_data: packet.payload, client_addr: packet.peer, masked: true, quic_inner: packet.quic, quic_context: packet.context });
                    }
                    continue;
                }
                received = batch_io.recv_batch(&mut slots) => received,
            };
            match received {
                Ok(filled) => {
                    for slot in &slots[..filled] {
                        let Some(client_addr) = slot.addr else {
                            continue;
                        };
                        if !rates.allow(
                            client_addr.ip(),
                            Instant::now(),
                            65_536,
                            [
                                gateway.config.per_ip_pps_limit,
                                gateway.config.per_ip_authenticated_pps_limit,
                            ],
                            socket.authenticated_quic_ingress(slot.packet(), client_addr),
                        ) {
                            continue;
                        }

                        if socket.route_incoming(slot.packet(), client_addr) {
                            continue;
                        }

                        let packet_data = slot.packet().to_vec();
                        let worker_idx = gateway.worker_index_for_packet(
                            &packet_data,
                            client_addr,
                            worker_count,
                        );
                        let packet = QueuedPacket {
                            local: slot.local,
                            packet_data,
                            client_addr,
                            masked: false,
                            quic_inner: false,
                            quic_context: None,
                        };

                        // try_send, not send().await: awaiting a FULL worker
                        // queue here would stall the single recv loop — and
                        // with it EVERY session — behind one overloaded shard
                        // (e.g. a slow TUN consumer backing up one worker's
                        // tun_write_tx), defeating the point of sharding.
                        // Dropping the packet degrades just that shard; UDP
                        // peers retransmit naturally.
                        match worker_txs[worker_idx].try_send(packet) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                warn!(
                                    "Receive worker {} queue full — dropping packet from {}",
                                    worker_idx, client_addr
                                );
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                warn!(
                                    "Receive worker {} channel closed — dropping packet from {}",
                                    worker_idx, client_addr
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("UDP recv error: {}", e);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }
}
