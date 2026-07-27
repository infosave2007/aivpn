//! Gateway main run loop: `run` (the top-level select!-driven task
//! that wires the TUN reader/writer, receive workers, control-plane
//! sockets, and periodic background tasks) plus `resonance_check_loop`
//! (Patent 1 neural resonance background task). Pure move out of
//! `gateway/mod.rs` — no behavior change.

use super::*;

// Cadences and entry TTLs for the periodic background loops spawned by `run`
// below. Named here so each interval's intent is visible at a glance — several
// share a numeric value (the two 5-minute sweeps) yet are independent knobs.
/// How often the recording store is flushed to disk.
const RECORDING_FLUSH_INTERVAL: Duration = Duration::from_secs(5);
/// Age past which a stale per-IP rate-limit entry is pruned.
const RATE_LIMIT_ENTRY_TTL: Duration = Duration::from_secs(30);
/// Age past which a stale per-IP handshake-cooldown entry is pruned.
const HANDSHAKE_COOLDOWN_ENTRY_TTL: Duration = Duration::from_secs(60);
/// Interval of the mask-feedback / metrics / session sweep.
const BACKGROUND_SWEEP_INTERVAL: Duration = Duration::from_secs(300);
/// Fast tick driving rekey retransmits (kept well below the rekey window).
const REKEY_RETRANSMIT_TICK: Duration = Duration::from_secs(2);
/// Interval of the client-DB traffic-stats flush.
const CLIENT_DB_STATS_FLUSH_INTERVAL: Duration = Duration::from_secs(300);
/// Interval of the client-DB reload / exit-route-cache invalidation check.
const CLIENT_DB_RELOAD_INTERVAL: Duration = Duration::from_secs(10);
/// Interval of the bootstrap-epoch rotation check (epochs advance hourly).
const BOOTSTRAP_EPOCH_CHECK_INTERVAL: Duration = Duration::from_secs(3600);

impl super::Gateway {
    /// Start the gateway
    pub async fn run(mut self) -> Result<()> {
        info!("Starting AIVPN Gateway on {}", self.config.listen_addr);
        info!(
            "Per-IP UDP rate limit: {} pps",
            self.config.per_ip_pps_limit
        );

        // Start eBPF observer (no-op when xdp_prog.o is absent)
        Arc::new(EbpfObserver::new(self.event_bus.clone())).start();

        // Create NAT forwarder (requires root — deferred from constructor for testability)
        if self.config.enable_nat {
            let mut nat = NatForwarder::new(
                &self.config.tun_name,
                &self.config.tun_addr,
                &self.config.tun_netmask,
                self.config.tun_mtu,
                self.config.network_config.clone(),
            )?;
            nat.create()?;

            // IPv6 dual-stack (NAT66) — optional, off by default.
            if self.config.network_config.ipv6_enabled {
                let tun = self.config.tun_name.as_str();
                let prefix = self.config.network_config.ipv6_prefix.as_str();
                match crate::nat::setup_nat66(tun, prefix) {
                    Ok(()) => info!("NAT66 configured for prefix {}", prefix),
                    Err(e) => warn!("NAT66 setup failed (non-fatal): {}", e),
                }
                match crate::nat::assign_ipv6_to_tun(tun, "fd10:cafe::1", 48) {
                    Ok(()) => info!("Assigned fd10:cafe::1/48 to {}", tun),
                    Err(e) => warn!("IPv6 TUN address assignment failed (non-fatal): {}", e),
                }
            }

            self.nat_forwarder = Some(Arc::new(nat));
            info!(
                "TUN device: {} ({}/{})",
                self.config.tun_name, self.config.tun_addr, self.config.tun_netmask
            );
        }

        // Create UDP socket with 4MB OS buffers (OPTIMIZATION)
        let bind_addr: SocketAddr =
            self.config
                .listen_addr
                .parse()
                .map_err(|e: std::net::AddrParseError| {
                    Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        e.to_string(),
                    ))
                })?;

        let socket2_sock = socket2::Socket::new(
            if bind_addr.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            },
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .map_err(Error::Io)?;

        socket2_sock.set_nonblocking(true).map_err(Error::Io)?;
        let _ = socket2_sock.set_recv_buffer_size(4 * 1024 * 1024);
        let _ = socket2_sock.set_send_buffer_size(4 * 1024 * 1024);
        socket2_sock.bind(&bind_addr.into()).map_err(Error::Io)?;

        let std_sock: std::net::UdpSocket = socket2_sock.into();
        let socket = UdpSocket::from_std(std_sock).map_err(Error::Io)?;

        info!(
            "UDP listener bound to {} (4MB buffers via socket2)",
            self.config.listen_addr
        );

        self.udp_socket = Some(Arc::new(socket));

        // Wire kernel accelerator to live TUN + UDP socket.
        if let Some(ref ka) = self.kernel_accel {
            let mut tun_ifindex: u32 = 0;
            if self.config.enable_nat {
                let tun_name = self.config.tun_name.as_str();
                if let Ok(cname) = std::ffi::CString::new(tun_name) {
                    let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
                    if ifindex > 0 {
                        tun_ifindex = ifindex;
                        if let Err(e) = ka.set_tun(ifindex) {
                            warn!("aivpn: kernel set_tun failed: {e}");
                        } else {
                            info!(
                                "Kernel acceleration wired to TUN {} (ifindex={ifindex})",
                                tun_name
                            );
                        }
                    }
                }
            }
            use std::os::unix::io::AsRawFd;
            let udp_fd = self.udp_socket.as_ref().unwrap().as_raw_fd();
            if let Err(e) = ka.set_udp_sock(udp_fd) {
                warn!("aivpn: kernel set_udp_sock failed: {e}");
            }

            // Kernel downlink (server->client) encryption is OPT-IN and OFF by
            // default: it is a new, live-unproven fast path. Enable it only when
            // AIVPN_KERNEL_DOWNLINK=1 is set in the environment. With it off, the
            // egress hook is never registered and the user-space downlink path
            // (downlink_worker) runs exactly as before.
            let downlink_enabled = std::env::var("AIVPN_KERNEL_DOWNLINK")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if downlink_enabled {
                if tun_ifindex == 0 {
                    warn!(
                        "aivpn: AIVPN_KERNEL_DOWNLINK set but TUN ifindex unknown \
                         (enable_nat off?) — downlink egress not enabled"
                    );
                } else if let Err(e) = ka.set_egress(udp_fd, tun_ifindex, true) {
                    warn!("aivpn: kernel set_egress (downlink) failed: {e}");
                } else {
                    KERNEL_DOWNLINK_ARMED.store(true, std::sync::atomic::Ordering::Relaxed);
                    info!(
                        "Kernel downlink egress enabled (tun ifindex={tun_ifindex}) \
                         — server->client encryption offloaded to /dev/aivpn"
                    );
                }
            }
        }

        // Spawn neural resonance check loop (Patent 1 — periodic validation)
        if self.config.enable_neural {
            let neural = self.neural_module.clone();
            let sessions = self.session_manager.clone();
            let catalog = self.mask_catalog.clone();
            let metrics = self.metrics.clone();
            let check_interval = self.config.neural_config.check_interval_secs;
            let socket = self.udp_socket.as_ref().unwrap().clone();
            #[cfg(feature = "neural")]
            let dpi_gate = self.dpi_gate.clone();

            tokio::spawn(async move {
                Self::resonance_check_loop(
                    neural,
                    sessions,
                    catalog,
                    metrics,
                    check_interval,
                    socket,
                    #[cfg(feature = "neural")]
                    dpi_gate,
                )
                .await;
            });
            info!(
                "Neural resonance check loop spawned (interval: {}s)",
                check_interval
            );
        }

        // Spawn TUN → Client read loop (reads packets from TUN, routes back to clients)
        // Also set up channel-based TUN writer for upload path (avoids Mutex contention)
        if let Some(ref nat) = self.nat_forwarder {
            if let Some(tun_reader) = nat.take_reader().await {
                let sessions = self.session_manager.clone();
                let socket = self.udp_socket.as_ref().unwrap().clone();
                let Some(mask) = self
                    .mask_catalog
                    .masks
                    .iter()
                    .next()
                    .map(|e| e.value().clone())
                else {
                    error!("No masks loaded — cannot start gateway");
                    return Ok(());
                };
                let server_vpn_ip = self.config.network_config.server_vpn_ip;
                let recorder = self.recording_manager.clone();

                // Channel for writing packets to TUN device (upload + ICMP replies)
                let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>(4096);
                self.tun_write_tx = Some(tun_tx.clone());

                // Spawn dedicated TUN writer task — owns the DeviceWriter, no Mutex needed
                if let Some(tun_writer) = nat.take_writer().await {
                    tokio::spawn(async move {
                        Self::tun_write_loop(tun_writer, tun_rx).await;
                    });
                    info!("TUN write loop spawned (channel-based, no Mutex)");
                } else {
                    warn!("Could not take TUN writer — falling back to forward_packet");
                }

                let client_db = self.client_db.clone();
                let qos_enforcer = self.qos_enforcer.clone();
                let allow_peer_routing = self.config.allow_peer_routing;
                let downlink_shaping = self.config.downlink_shaping;
                // PHASE 4 (reverse chain-forward): hand both halves of the
                // reverse-routing state to `tun_read_loop` — the exit-side
                // route table (read on a local "no session" miss) and the
                // entry-side receiver (drained into the same per-worker
                // downlink dispatch). See the fields' doc comments on
                // `Gateway`.
                let chain_reverse_routes = self.chain_reverse_routes.clone();
                let chain_reverse_rx = self.chain_reverse_rx.take();
                tokio::spawn(async move {
                    Self::tun_read_loop(
                        tun_reader,
                        tun_tx,
                        sessions,
                        socket,
                        chain_reverse_routes,
                        chain_reverse_rx,
                        mask,
                        server_vpn_ip,
                        recorder,
                        client_db,
                        qos_enforcer,
                        allow_peer_routing,
                        downlink_shaping,
                    )
                    .await;
                });
                info!("TUN read loop spawned");
            }
        }

        // Spawn periodic session cleanup task (remove expired/idle sessions and stop recordings)
        {
            let sessions = self.session_manager.clone();
            let recorder = self.recording_manager.clone();
            let socket = self.udp_socket.as_ref().unwrap().clone();
            let mdh = self.mask_catalog.packet_mdh_bytes();
            let neural = self.neural_module.clone();
            let client_db_cleanup = self.client_db.clone();
            #[cfg(feature = "neural")]
            let dpi_gate_cleanup = self.dpi_gate.clone();
            let ka_cleanup = self.kernel_accel.clone();
            let rate_limits_cleanup = self.rate_limits.clone();
            let handshake_cooldowns_cleanup = self.handshake_cooldowns.clone();
            let handshake_locks_cleanup = self.handshake_locks.clone();
            let mask_preference_throttle_cleanup = self.mask_preference_throttle.clone();
            let mask_feedback_throttle_cleanup = self.mask_feedback_throttle.clone();
            let mgmt_request_throttle_cleanup = self.mgmt_request_throttle.clone();
            let mask_catalog_cleanup = self.mask_catalog.clone();
            let pending_config_cleanup = self.pending_config.clone();
            // P1.5 rollback fix: handles for re-applying LIVE state after an
            // auto-rollback restored `server.json` on disk. Without this the
            // sweep only reverted the FILE — the tunnel path's live-swap
            // (`dispatch_mgmt_request` → `apply_global_exit_and_teardown`)
            // had already pointed `masked_exit_addr` at the new (now rolled
            // back) exit, and nothing ever swapped it back: the exact
            // scenario the rollback exists for (admin lost connectivity
            // after a bad exit change, so no further mgmt request will run
            // the re-read) left live routing diverged from disk until a
            // restart.
            let masked_exit_addr_cleanup = self.masked_exit_addr.clone();
            let pool_dialer_cleanup = self.pool_dialer.clone();
            let server_config_path_cleanup = self.config.server_config_path.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(RECORDING_FLUSH_INTERVAL).await;
                    if let Some(ref rec) = recorder {
                        let store = rec.store();
                        for outcome in rec.take_ready_or_stale(
                            aivpn_common::recording::RECORDING_IDLE_TIMEOUT_SECS,
                        ) {
                            let notify_session = match &outcome {
                                RecordingStopOutcome::Completed(completed) => {
                                    sessions.get_session(&completed.session_id)
                                }
                                RecordingStopOutcome::Incomplete(incomplete) => {
                                    sessions.get_session(&incomplete.session_id)
                                }
                                RecordingStopOutcome::NotFound => None,
                            };
                            Self::handle_recording_outcome(
                                &socket,
                                &sessions,
                                &store,
                                &mdh,
                                outcome,
                                notify_session,
                            )
                            .await;
                        }
                    }

                    // Prune stale per-IP rate-limit, handshake-cooldown, and
                    // handshake-lock entries.  handshake_locks is never pruned
                    // elsewhere so it grows without bound under sustained churn.
                    // Entries whose Arc strong_count == 1 have no active waiters
                    // and are safe to remove.
                    rate_limits_cleanup.retain(|_, v| v.1.elapsed() < RATE_LIMIT_ENTRY_TTL);
                    handshake_cooldowns_cleanup
                        .retain(|_, v| v.1.elapsed() < HANDSHAKE_COOLDOWN_ENTRY_TTL);
                    handshake_locks_cleanup.retain(|_, v| std::sync::Arc::strong_count(v) > 1);
                    // Prune expired MaskPreference throttle entries so this
                    // DashMap doesn't grow unbounded across session churn —
                    // same pattern as rate_limits/handshake_cooldowns above.
                    // Entries older than the throttle window are dead weight
                    // (the next MaskPreference for that session would not be
                    // throttled anyway).
                    mask_preference_throttle_cleanup
                        .retain(|_, v| v.elapsed() < MASK_PREFERENCE_THROTTLE);
                    // Same pruning for the FIX F MaskFeedback throttle map.
                    mask_feedback_throttle_cleanup
                        .retain(|_, v| v.elapsed() < MASK_FEEDBACK_THROTTLE);
                    // Same pruning for the P1.2 MgmtRequest throttle map.
                    mgmt_request_throttle_cleanup.retain(|_, v| v.elapsed() < MGMT_THROTTLE);
                    // H1: give masks that tripped the neural/DPI/anomaly
                    // detectors a second chance after COMPROMISED_TTL rather
                    // than excluding them from rotation forever.
                    mask_catalog_cleanup.sweep_expired_compromised();

                    // Enforce client revocation on ALREADY-ACTIVE sessions. The
                    // handshake scan only checks enabled/expires_at when creating a
                    // NEW session; once Active, traffic routes purely via the tag
                    // map, so --remove-client / disable / expiry (picked up by the
                    // 10s client-DB hot-reload) would otherwise let a connected
                    // client keep full access indefinitely (it controls its own
                    // keepalives, so it never idles out). Drop any session whose
                    // client is now missing, disabled, or expired.
                    let mut revoked: Vec<[u8; 16]> = Vec::new();
                    if let Some(ref db) = client_db_cleanup {
                        // P1.3: keep the session handle alongside its id so
                        // the loop below can send `Shutdown{reason:4}`
                        // before dropping it — this is the REST-revoke /
                        // disable / expiry fallback path (the in-tunnel
                        // admin revoke instead calls
                        // `Gateway::force_disconnect_client` synchronously,
                        // see that method's doc comment for the split).
                        // Previously this sweep just called
                        // `sessions.remove_session` silently, so a client
                        // revoked/disabled via the REST API (which has no
                        // `Gateway` handle to force-disconnect immediately)
                        // saw its connection die with no explanation until
                        // this fix.
                        let mut revoked_sessions: Vec<(
                            [u8; 16],
                            Arc<parking_lot::Mutex<Session>>,
                        )> = Vec::new();
                        for entry in sessions.iter_sessions() {
                            let (sid, cid) = {
                                let s = entry.value().lock();
                                (s.session_id, s.client_id.clone())
                            };
                            if let Some(cid) = cid {
                                let live = db
                                    .find_by_id(&cid)
                                    .map(|c| {
                                        c.enabled
                                            && c.expires_at.is_none_or(|t| t > chrono::Utc::now())
                                    })
                                    .unwrap_or(false);
                                if !live {
                                    revoked.push(sid);
                                    revoked_sessions.push((sid, entry.value().clone()));
                                }
                            }
                        }
                        for (sid, session) in &revoked_sessions {
                            warn!(
                                "Dropping active session {:02x}{:02x}{:02x}{:02x} — client revoked/disabled/expired",
                                sid[0], sid[1], sid[2], sid[3]
                            );
                            let shutdown = ControlPayload::Shutdown { reason: 4 };
                            if let Err(e) = Self::send_control_message_via(
                                socket.as_ref(),
                                &mdh,
                                &shutdown,
                                session,
                            )
                            .await
                            {
                                debug!(
                                    "revocation sweep: Shutdown send failed for session {:02x}{:02x}{:02x}{:02x}: {}",
                                    sid[0], sid[1], sid[2], sid[3], e
                                );
                            }
                            sessions.remove_session(sid);
                        }
                    }

                    let expired = sessions.cleanup_expired();
                    // Union of revoked + idle-expired sessions for per-session cleanup.
                    let removed: Vec<[u8; 16]> =
                        revoked.into_iter().chain(expired.into_iter()).collect();
                    for session_id in &removed {
                        // Release per-session neural traffic stats; without this the
                        // neural_module's DashMap grows unbounded as sessions expire.
                        neural.lock().cleanup_stats(*session_id);
                        // Same for the R2 Phase D ML-DPI gate's per-session ring.
                        #[cfg(feature = "neural")]
                        dpi_gate_cleanup.cleanup(session_id);
                        if let Some(ref ka) = ka_cleanup {
                            let _ = ka.session_remove(session_id);
                        }
                    }
                    // Stop active recordings for removed sessions
                    if let Some(ref rec) = recorder {
                        let store = rec.store();
                        for session_id in removed {
                            let outcome = rec.stop_for_session_end(session_id);
                            Self::handle_recording_outcome(
                                &socket, &sessions, &store, &mdh, outcome, None,
                            )
                            .await;
                        }
                    }

                    // P1.5 (apply-with-rollback): sweep every heavy config
                    // change whose confirm deadline passed without a
                    // `confirm_config` call — from EITHER transport (the
                    // tunnel's `MgmtRequest` or the REST `/config/apply`
                    // handler, both of which register into this SAME
                    // shared `PendingConfigManager`; see that field's doc
                    // comment on `Gateway`). Restore each entry's
                    // `target_path` to its `rollback_value()` — `Some(bytes)`
                    // writes the prior content back, `None` means the file
                    // didn't exist before the change, so it's removed.
                    let mut rolled_back_any = false;
                    for entry in pending_config_cleanup.tick(Instant::now()) {
                        let path = entry.target_path().to_path_buf();
                        let restore_result = match entry.rollback_value() {
                            Some(prior_bytes) => std::fs::write(&path, prior_bytes),
                            None => match std::fs::remove_file(&path) {
                                Ok(()) => Ok(()),
                                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                                Err(e) => Err(e),
                            },
                        };
                        match restore_result {
                            Ok(()) => {
                                rolled_back_any = true;
                                warn!(
                                    "Pending config auto-rolled-back (unconfirmed within window): {}",
                                    entry.descriptor()
                                );
                            }
                            Err(e) => {
                                error!(
                                    "Pending config rollback FAILED for '{}' (path {}): {}",
                                    entry.descriptor(),
                                    path.display(),
                                    e
                                );
                            }
                        }
                    }
                    // P1.5 rollback fix (see the `masked_exit_addr_cleanup`
                    // clones above): after restoring the FILE(S), re-run the
                    // same live-swap side effect every mgmt/confirm path
                    // uses, so `masked_exit_addr`/runtime exit dials track
                    // the rolled-back `server.json` instead of staying on
                    // the reverted value. Cheap no-op when nothing exit-
                    // related changed or no masked pool dialer exists.
                    if rolled_back_any {
                        if let Some(ref db) = client_db_cleanup {
                            apply_global_exit_and_teardown(
                                &masked_exit_addr_cleanup,
                                pool_dialer_cleanup.as_ref(),
                                server_config_path_cleanup.as_deref(),
                                db,
                            );
                        }
                    }
                }
            });
            info!("Session cleanup / recording auto-finish task spawned (5s interval)");
        }

        // Spawn periodic §2 mask-feedback bucket sweep. Mirrors the
        // rate_limits/handshake_cooldowns/handshake_locks cleanup pattern
        // above (same "prune stale entries on an interval" shape), but on a
        // much coarser cadence since `MaskFeedbackStore` retention is
        // measured in days, not seconds — this is a backstop for buckets
        // that go quiet well before the store ever hits its hard capacity
        // eviction (see `MaskFeedbackStore::record_feedback`).
        //
        // Also doubles as the refresh point for two `metrics` gauges that
        // are cheapest to maintain by periodic recomputation rather than
        // incrementally at every mutation site:
        //   - `aivpn_feedback_buckets` / `aivpn_feedback_regions`: already
        //     refreshed in real time right after every `record_feedback`
        //     call (see the `MaskFeedback` control-message arm), but that
        //     doesn't observe *evictions* (capacity eviction or this same
        //     sweep's stale-bucket removal) — re-synced here so the gauges
        //     never drift from `bucket_count()`/`region_count()`.
        //   - `aivpn_polymorphic_sessions_active`: counts sessions whose
        //     current mask id starts with `"polymorphic:"`. A session can
        //     leave a polymorphic mask more ways than "session ended" (a
        //     neural-triggered rotation onto a non-polymorphic fallback, a
        //     fresh `MaskPreference` deriving a mask_id — always
        //     `"polymorphic:...")` from a *different* base, etc.), so an
        //     incremental increment/decrement pair would need a correctness
        //     guard at every one of those call sites. A periodic O(active
        //     sessions) scan is simple, always correct, and cheap at the
        //     documented `MAX_SESSIONS = 500` scale — see
        //     `MetricsCollector::set_polymorphic_sessions_active`'s doc
        //     comment for the same rationale.
        {
            let mask_feedback = self.mask_feedback.clone();
            let metrics_sweep = self.metrics.clone();
            let sessions_sweep = self.session_manager.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(BACKGROUND_SWEEP_INTERVAL).await;
                    let now_hour = current_unix_secs() / 3600;
                    let removed = mask_feedback
                        .sweep_stale(now_hour, crate::mask_feedback::DEFAULT_RETENTION_HOURS);
                    if removed > 0 {
                        debug!("Mask-feedback sweep: evicted {} stale bucket(s)", removed);
                    }
                    metrics_sweep.set_feedback_buckets(mask_feedback.bucket_count());
                    metrics_sweep.set_feedback_regions(mask_feedback.region_count());

                    let polymorphic_active = sessions_sweep
                        .iter_sessions()
                        .filter(|entry| {
                            entry
                                .value()
                                .lock()
                                .mask
                                .as_ref()
                                .is_some_and(|m| m.mask_id.starts_with("polymorphic:"))
                        })
                        .count();
                    metrics_sweep.set_polymorphic_sessions_active(polymorphic_active);
                }
            });
            info!(
                "Mask-feedback bucket sweep task spawned (300s interval, {}h retention)",
                crate::mask_feedback::DEFAULT_RETENTION_HOURS
            );
        }

        // Spawn periodic inline rekey task (PFS key rotation every 30s check, 120s actual)
        {
            let sessions = self.session_manager.clone();
            let socket = self.udp_socket.as_ref().unwrap().clone();
            // Fallback MDH only for sessions with no mask assigned yet; the
            // per-session mask (below) is used whenever present so the KeyRotate
            // is framed with the SAME layout as that session's DATA downlink. A
            // frozen catalog snapshot here would frame the rekey with a
            // different mask than the session's data plane, which — before the
            // client's multi-length decode fallback — permanently stranded the
            // tunnel on the first rekey.
            let fallback_mdh = self.mask_catalog.packet_mdh_bytes();
            tokio::spawn(async move {
                // Two cadences share one task: rekey INITIATION every 30 s
                // (15 × 2 s ticks), and a fast retransmit sweep for pending
                // rekeys every 2 s tick. KeyRotate is one-shot UDP; if it (or
                // the client's response) is lost, the retransmit must land
                // BEFORE the client's RX-silence watchdog (12 s floor) trips
                // — riding the 30 s tick cost a reconnect per lost packet.
                let mut tick: u32 = 0;
                loop {
                    tokio::time::sleep(REKEY_RETRANSMIT_TICK).await;
                    tick = tick.wrapping_add(1);
                    let mut due = sessions.rekey_retransmits_due();
                    if tick % 15 == 0 {
                        due.extend(sessions.start_rekeying_sessions());
                    }
                    for (session_id, new_eph_pub) in due {
                        if let Some(session) = sessions.get_session(&session_id) {
                            let payload =
                                aivpn_common::protocol::ControlPayload::KeyRotate { new_eph_pub };
                            let mdh = session
                                .lock()
                                .mask
                                .as_ref()
                                .map(packet_mdh_bytes_for_mask)
                                .unwrap_or_else(|| fallback_mdh.clone());
                            if let Err(e) = Self::send_control_message_via(
                                socket.as_ref(),
                                &mdh,
                                &payload,
                                &session,
                            )
                            .await
                            {
                                warn!("Inline rekey: failed to send KeyRotate to session: {}", e);
                            } else {
                                info!("Inline rekey: KeyRotate sent to session");
                            }
                        }
                    }
                }
            });
            info!(
                "Inline rekey task spawned (30s initiation, 120s rekey period, \
                 2s retransmit sweep)"
            );
        }

        // Spawn client DB stats flush task (persist traffic stats every 5 min)
        if let Some(ref db) = self.client_db {
            let db = db.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(CLIENT_DB_STATS_FLUSH_INTERVAL).await;
                    db.flush_stats();
                }
            });
            info!("Client stats flush task spawned (300s interval)");
        }

        // Spawn client DB hot-reload task (pick up new clients without restart)
        if let Some(ref db) = self.client_db {
            let db = db.clone();
            // B2b: invalidate the exit-resolution cache whenever the
            // on-disk clients DB actually changed (a new/edited/rotated
            // `exit_node` — e.g. `clients.json` edited directly, or a
            // sibling process wrote it) — see `exit_route_cache`'s doc
            // comment for the full invalidation policy.
            let exit_route_cache = self.exit_route_cache.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(CLIENT_DB_RELOAD_INTERVAL).await;
                    if db.reload_if_changed() {
                        exit_route_cache.clear();
                    }
                }
            });
            info!("Client DB hot-reload task spawned (10s interval)");
        }

        // Spawn bootstrap descriptor rotation task. Descriptors were
        // previously only ever built once at Gateway::new() and went stale
        // (expires_at) after ~3 days of uptime; this checks hourly whether
        // the epoch has advanced and rebuilds+swaps the shared descriptors
        // if so. Auto-publish (when configured) only fires on an actual
        // epoch change, not on every hourly check.
        {
            let bootstrap_descriptors = self.bootstrap_descriptors.clone();
            let server_private_key = self.config.server_private_key;
            let bootstrap_masks = self.config.bootstrap_masks.clone();
            let bootstrap_publish = self.config.bootstrap_publish.clone();
            let mut last_epoch = bootstrap_epoch(current_unix_secs());
            tokio::spawn(async move {
                let signing_key = derive_server_signing_key(&server_private_key);
                loop {
                    tokio::time::sleep(BOOTSTRAP_EPOCH_CHECK_INTERVAL).await;
                    let epoch = bootstrap_epoch(current_unix_secs());
                    if epoch == last_epoch {
                        continue;
                    }
                    last_epoch = epoch;
                    let fresh = build_bootstrap_descriptors(
                        &server_private_key,
                        &signing_key,
                        &bootstrap_masks,
                    );
                    *bootstrap_descriptors.write() = fresh.clone();
                    info!("Bootstrap descriptors rotated (epoch {epoch})");

                    if let Some(publish_config) = &bootstrap_publish {
                        match serde_json::to_string(&fresh) {
                            Ok(json) => {
                                crate::bootstrap_publish::publish_all(&json, publish_config).await
                            }
                            Err(e) => error!(
                                "Failed to serialize rotated bootstrap descriptors for publish: {e}"
                            ),
                        }
                    }
                }
            });
            info!("Bootstrap descriptor rotation task spawned (hourly epoch check, 24h rotation)");
        }

        // Use session-aware receive sharding: preserve ordering within one
        // session, but allow different sessions to make progress in parallel.
        let gateway = Arc::new(self);
        Self::process_packets_concurrent(gateway).await?;

        Ok(())
    }

    /// Background task: periodic neural resonance checks (Patent 1)
    ///
    /// For each active session, computes reconstruction error between
    /// observed traffic features and the assigned mask's signature vector.
    /// If MSE exceeds threshold → mask is detected as compromised by DPI.
    /// Triggers automatic mask rotation (Patent 3).
    async fn resonance_check_loop(
        neural: Arc<parking_lot::Mutex<NeuralResonanceModule>>,
        sessions: Arc<SessionManager>,
        catalog: Arc<MaskCatalog>,
        metrics: Arc<MetricsCollector>,
        check_interval_secs: u64,
        socket: Arc<UdpSocket>,
        #[cfg(feature = "neural")] dpi_gate: Arc<crate::dpi_gate::DpiGate>,
    ) {
        let interval = Duration::from_secs(check_interval_secs);

        loop {
            tokio::time::sleep(interval).await;

            // Collect session IDs and their ACTIVE mask profiles. Capturing the
            // full profile (not just the id) lets the loop bake an encoder
            // on-demand for per-session bootstrap/polymorphic masks whose dynamic
            // mask_id is absent from the static startup-baked encoders.
            let session_checks: Vec<([u8; 16], MaskProfile)> = sessions
                .iter_sessions()
                .filter_map(|entry| {
                    let sess = entry.value().lock();
                    sess.mask.as_ref().map(|m| (sess.session_id, m.clone()))
                })
                .collect();

            if session_checks.is_empty() {
                continue;
            }

            // Collect mask update packets to send AFTER releasing the neural lock
            // (parking_lot::MutexGuard is !Send, cannot hold across .await)
            let mut pending_sends: Vec<(Vec<u8>, std::net::SocketAddr, [u8; 16], MaskProfile)> =
                Vec::new();

            {
                let mut neural_guard = neural.lock();

                for (session_id, mask) in &session_checks {
                    let mask_id = &mask.mask_id;
                    // Bake an encoder for this session's active mask if the static
                    // startup set didn't cover it (bootstrap/polymorphic variants).
                    // A short/empty signature_vector legitimately has no encoder
                    // (neural inactive for that mask) — ignore that error.
                    let _ = neural_guard.ensure_encoder(mask);
                    // Check neural resonance (Patent 1: Signal Reconstruction Resonance)
                    match neural_guard.check_resonance(*session_id, mask_id) {
                        Ok(result) => {
                            debug!(
                                "neural check: mask='{}' status={:?} mse={:.6} msg={:?}",
                                mask_id, result.status, result.mse, result.message
                            );
                            metrics
                                .record_neural_check(result.status == ResonanceStatus::Compromised);

                            match result.status {
                                ResonanceStatus::Compromised => {
                                    if !neural_guard.can_rotate(mask_id) {
                                        debug!(
                                            "Mask '{}' compromised (MSE={:.4}) but rotation on cooldown — skipping",
                                            mask_id, result.mse
                                        );
                                        continue;
                                    }
                                    warn!(
                                        "Mask '{}' compromised (MSE={:.4}) — triggering rotation (Patent 3)",
                                        mask_id, result.mse
                                    );

                                    neural_guard.record_rotation(mask_id);

                                    // H1: atomically check-then-mark so a
                                    // single-mask catalog is never emptied.
                                    if let Some(new_mask) =
                                        catalog.mark_compromised_with_fallback(mask_id)
                                    {
                                        info!(
                                            "Auto-rotating to mask '{}' ({} masks remaining)",
                                            new_mask.mask_id,
                                            catalog.available_count()
                                        );

                                        if let Some(session) = sessions.get_session(session_id) {
                                            let client_addr = session.lock().client_addr;
                                            match sessions
                                                .build_mask_update_packet(&session, &new_mask)
                                            {
                                                Ok(packet) => {
                                                    pending_sends.push((
                                                        packet,
                                                        client_addr,
                                                        *session_id,
                                                        new_mask.clone(),
                                                    ));
                                                }
                                                Err(e) => {
                                                    warn!(
                                                        "Failed to build MaskUpdate packet: {}",
                                                        e
                                                    );
                                                }
                                            }
                                        }

                                        metrics.record_mask_rotation();
                                        // Skip the anomaly check below — one MaskUpdate per
                                        // iteration is enough (prevents double rotation).
                                        continue;
                                    } else {
                                        error!(
                                            "No fallback masks available! All masks compromised."
                                        );
                                    }
                                }
                                ResonanceStatus::Warning => {
                                    debug!(
                                        "Mask '{}' warning (MSE={:.4}) — monitoring",
                                        mask_id, result.mse
                                    );
                                }
                                ResonanceStatus::Healthy => {
                                    // All good
                                }
                                ResonanceStatus::Skip => {
                                    // Not enough data or model not loaded
                                }
                            }
                        }
                        Err(e) => {
                            debug!("Resonance check error for session: {}", e);
                        }
                    }

                    // R2 Phase D — inline ML-DPI gate (SIBLING to the neural MSE
                    // check above). Neural resonance detects drift from the
                    // mask's own fingerprint; this detects drift toward a
                    // tunnel/Unknown DPI classification. Same rotate action, same
                    // cooldown. Reached only when the neural branch did NOT
                    // already rotate (Compromised `continue`s), so the two never
                    // double-fire on one session in one pass.
                    // verdict() runs a full GBDT inference over the window, so
                    // compute it ONCE and reuse for both the debug line and the
                    // rotation decision.
                    #[cfg(feature = "neural")]
                    let dpi_verdict = dpi_gate.verdict(session_id);
                    #[cfg(feature = "neural")]
                    match &dpi_verdict {
                        Some(v) => debug!(
                            "dpi_gate verdict: mask='{}' reads_as_tunnel={} p={:.4}",
                            mask_id, v.reads_as_tunnel, v.tunnel_prob
                        ),
                        None => debug!(
                            "dpi_gate verdict: mask='{}' abstain (ring not full)",
                            mask_id
                        ),
                    }
                    #[cfg(feature = "neural")]
                    if let Some(verdict) = dpi_verdict {
                        if verdict.reads_as_tunnel && neural_guard.can_rotate(mask_id) {
                            warn!(
                                "ML-DPI gate: mask '{}' reads as tunnel (p={:.3}) — triggering rotation (R2 Phase D)",
                                mask_id, verdict.tunnel_prob
                            );
                            neural_guard.record_rotation(mask_id);
                            // H1: atomically check-then-mark so a
                            // single-mask catalog is never emptied.
                            if let Some(new_mask) = catalog.mark_compromised_with_fallback(mask_id)
                            {
                                info!(
                                    "ML-DPI-triggered rotation to mask '{}' ({} masks remaining)",
                                    new_mask.mask_id,
                                    catalog.available_count()
                                );
                                if let Some(session) = sessions.get_session(session_id) {
                                    let client_addr = session.lock().client_addr;
                                    if let Ok(packet) =
                                        sessions.build_mask_update_packet(&session, &new_mask)
                                    {
                                        pending_sends.push((
                                            packet,
                                            client_addr,
                                            *session_id,
                                            new_mask.clone(),
                                        ));
                                    }
                                }
                                metrics.record_mask_rotation();
                                // One MaskUpdate per iteration — skip the anomaly
                                // check to avoid double rotation.
                                continue;
                            } else {
                                error!("No fallback masks available! All masks compromised.");
                            }
                        }
                    }

                    // Check anomaly detection (DPI blocking indicators)
                    if neural_guard.is_mask_anomalous(mask_id) {
                        warn!(
                            "Anomaly detected for mask '{}' (packet loss / RTT spike)",
                            mask_id
                        );
                        metrics.record_dpi_attack();
                        // H1: atomically check-then-mark so a single-mask
                        // catalog is never emptied.
                        if let Some(new_mask) = catalog.mark_compromised_with_fallback(mask_id) {
                            info!("Anomaly-triggered rotation to mask '{}'", new_mask.mask_id);
                            if let Some(session) = sessions.get_session(session_id) {
                                let client_addr = session.lock().client_addr;
                                if let Ok(packet) =
                                    sessions.build_mask_update_packet(&session, &new_mask)
                                {
                                    pending_sends.push((
                                        packet,
                                        client_addr,
                                        *session_id,
                                        new_mask.clone(),
                                    ));
                                }
                            }
                            metrics.record_mask_rotation();
                        }
                    }
                }
            } // neural_guard dropped here

            // Send collected MaskUpdate packets (async, safe now)
            for (packet, client_addr, session_id, new_mask) in pending_sends {
                if let Err(e) = socket.send_to(&packet, client_addr).await {
                    warn!("Failed to send MaskUpdate to {}: {}", client_addr, e);
                } else {
                    sessions.update_session_mask(&session_id, new_mask);
                    info!("MaskUpdate control message sent to {}", client_addr);
                }
            }
        }
    }
}
