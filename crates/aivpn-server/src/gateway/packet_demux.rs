//! Packet demultiplexing: resonance-tag candidate generation, existing-
//! session resolution, and the sharded receive worker pool that dispatches
//! inbound UDP packets to `handle_packet` (worker sizing/indexing plus
//! the concurrent and legacy-sequential processing loops). Pure move out
//! of `gateway/mod.rs` — no behavior change.

use super::*;

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
    ) -> Result<Option<(Arc<parking_lot::Mutex<Session>>, u64, bool, [u8; TAG_SIZE])>> {
        let tags = self.candidate_tags(packet_data);

        // 1) Fast O(1) path across all layout offsets — no scan.
        for tag in &tags {
            if let Some(session) = self.session_manager.get_session_by_tag(tag) {
                // Drop the lock guard before moving `session` into the result.
                let validated = session.lock().validate_tag(tag);
                return match validated {
                    Some((counter, is_ratcheted)) => {
                        Ok(Some((session, counter, is_ratcheted, *tag)))
                    }
                    None => Err(Error::InvalidPacket("Invalid tag")),
                };
            }
        }

        if !self.fallback_scan_allowed() {
            return Ok(None);
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
                return Ok(Some((session, counter, is_ratcheted, *first)));
            }
        }
        for tag in &tags {
            if let Some(session) = self.session_manager.get_session_by_tag(tag) {
                // Drop the lock guard before moving `session` into the result.
                let validated = session.lock().validate_tag(tag);
                return match validated {
                    Some((counter, is_ratcheted)) => {
                        Ok(Some((session, counter, is_ratcheted, *tag)))
                    }
                    None => Err(Error::InvalidPacket("Invalid tag")),
                };
            }
        }

        // 3) Counter-drift recovery across every offset.
        for tag in &tags {
            if let Some((session, counter, is_ratcheted)) =
                self.session_manager.recover_session_by_tag(tag, client_ip)
            {
                return Ok(Some((session, counter, is_ratcheted, *tag)));
            }
        }

        Ok(None)
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
                    if let Err(e) = gw
                        .handle_packet(&packet.packet_data, packet.client_addr)
                        .await
                    {
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
        let batch_io = crate::batch_io::BatchIo::new(socket.clone());
        let mut slots: Vec<crate::batch_io::RecvSlot> = (0..crate::batch_io::MAX_BATCH)
            .map(|_| crate::batch_io::RecvSlot::new(MAX_PACKET_SIZE))
            .collect();

        loop {
            match batch_io.recv_batch(&mut slots).await {
                Ok(filled) => {
                    for slot in &slots[..filled] {
                        let Some(client_addr) = slot.addr else {
                            continue;
                        };
                        // Per-IP rate limiting (fast, stays in recv task)
                        {
                            let now = Instant::now();
                            let mut entry = gateway
                                .rate_limits
                                .entry(client_addr.ip())
                                .or_insert((0, now));
                            if entry.1.elapsed() > Duration::from_secs(1) {
                                entry.0 = 0;
                                entry.1 = now;
                            }
                            entry.0 += 1;
                            if entry.0 > gateway.config.per_ip_pps_limit {
                                continue;
                            }
                        }

                        let packet_data = slot.packet().to_vec();
                        let worker_idx = gateway.worker_index_for_packet(
                            &packet_data,
                            client_addr,
                            worker_count,
                        );
                        let packet = QueuedPacket {
                            packet_data,
                            client_addr,
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

    /// Main packet processing loop (legacy sequential — unused, kept for reference)
    #[allow(dead_code)]
    async fn process_packets(&self) -> Result<()> {
        let socket = self.udp_socket.as_ref().unwrap();
        let mut buf = vec![0u8; MAX_PACKET_SIZE];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, client_addr)) => {
                    // Per-IP rate limiting.
                    {
                        let now = Instant::now();
                        let mut entry =
                            self.rate_limits.entry(client_addr.ip()).or_insert((0, now));
                        if entry.1.elapsed() > Duration::from_secs(1) {
                            entry.0 = 0;
                            entry.1 = now;
                        }
                        entry.0 += 1;
                        if entry.0 > self.config.per_ip_pps_limit {
                            continue;
                        }
                    }

                    let packet_data = &buf[..len];

                    // Process packet
                    if let Err(e) = self.handle_packet(packet_data, client_addr).await {
                        debug!("Packet error from {}: {}", hash_addr(&client_addr), e);
                        // Silent drop - no response for invalid packets
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
