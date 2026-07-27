use super::*;

impl super::AivpnClient {
    /// Run the client main loop
    pub async fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<()> {
        self.connect().await?;

        // Send initial handshake packet with eph_pub to establish session
        self.send_init().await?;

        // Session start (post-handshake) — tells a working sticky mask (long
        // healthy session) from a throttled one (repeated short data stalls).
        let session_established = std::time::Instant::now();

        info!("Starting client main loop");
        info!("Routing traffic through AIVPN tunnel...");

        // Create channels for TUN -> upload pipeline and UDP -> main loop
        let (tun_to_udp_tx, tun_to_udp_rx) = mpsc::channel::<Vec<u8>>(512);
        let (udp_to_tun_tx, mut udp_to_tun_rx) = mpsc::channel::<Bytes>(512);
        let (admin_tx, mut admin_rx) = mpsc::channel::<String>(16);
        // If `control_handle()` was called before `run()`, its receiver is
        // preset here and reused verbatim (and `self.control_tx` is already
        // set to a clone of the same sender) — otherwise, preserve the
        // original behavior exactly: create a fresh channel and set
        // `self.control_tx` from it.
        let (control_tx, control_rx) = if let Some(rx) = self.preset_control_rx.take() {
            let tx = self
                .control_tx
                .clone()
                .expect("preset_control_rx implies control_tx was set by control_handle()");
            (tx, rx)
        } else {
            let (tx, rx) = mpsc::channel::<ControlPayload>(32);
            self.control_tx = Some(tx.clone());
            (tx, rx)
        };

        // mTLS ClientCert is sent inside the ServerHello handler, after the PFS
        // ratchet completes, so it is protected by the ratcheted session keys.

        // Spawn local IPC listener for CLI commands. Stored in AbortOnDrop so the task
        // (and its bound UDP socket) is cancelled when run() returns. Without this,
        // the orphaned task keeps 127.0.0.1:44301 bound across reconnect iterations,
        // causing the next run() call to fail with "Address already in use".
        let admin_token = crate::record_cmd::ensure_admin_token();
        // P2.3-desktop: the admin socket now also bridges in-tunnel `mgmt`
        // calls (`AdminCommand::Mgmt`/`Role`/`Qr`) for the Windows egui /
        // Linux iced GUIs, which shell out to this binary rather than
        // embedding the crate — they drive the running daemon's tunnel over
        // this same loopback socket via `aivpn-client mgmt`/`role`.
        //
        // `mgmt_call` is `&self` on `AivpnClient` and needs only two pieces
        // of state, both cheaply `Clone`: `self.mgmt` (`MgmtClient`, an
        // `Arc`-wrapped correlation table shared with `run()`'s inbound
        // `MgmtResponse`/`Capabilities` handling) and the outbound
        // `control_tx` sender already constructed above. Cloning those two
        // into the admin task — rather than threading a full
        // `Arc<AivpnClient>` through — avoids taking `&mut self` away from
        // `run()`'s exclusive session loop for the task's lifetime.
        let admin_mgmt = self.mgmt.clone();
        let admin_control_tx = control_tx.clone();
        // Headless control-only mode (server-embedded pool-peer dialer): never
        // bind the admin IPC socket. This is the hard blocker for running N
        // dialers in one process — `admin_tx` is intentionally left un-moved
        // here (not dropped) so `admin_rx.recv()` in the main select loop
        // below simply pends forever instead of spinning on a closed channel.
        let _admin_task = if self.config.control_only {
            AbortOnDrop(tokio::spawn(std::future::pending::<()>()))
        } else {
            AbortOnDrop(tokio::spawn(async move {
                // Bind with a bounded retry, not a single attempt: AbortOnDrop
                // kills the PREVIOUS session's admin loop when its run()
                // returns, but a detached mgmt-reply task that loop spawned
                // (see the `AdminCommand::Mgmt` arm below) keeps a clone of
                // the old socket's `Arc` alive until its `mgmt_call` resolves
                // — up to the full 10s timeout when the tunnel died with the
                // call in flight (exactly the reconnect case). A single
                // failed bind here would leave the admin socket dead for the
                // WHOLE new session, breaking the desktop GUIs' mgmt/record
                // bridge until the next reconnect. 48 x 250ms comfortably
                // covers that 10s worst case.
                let bind_result = async {
                    let mut last_err = None;
                    for _ in 0..48u32 {
                        match tokio::net::UdpSocket::bind("127.0.0.1:44301").await {
                            Ok(s) => return Ok(s),
                            Err(e) => {
                                last_err = Some(e);
                                tokio::time::sleep(Duration::from_millis(250)).await;
                            }
                        }
                    }
                    Err(last_err.expect("loop ran at least once"))
                }
                .await;
                match bind_result {
                    Ok(socket) => {
                        let socket = Arc::new(socket);
                        let mut buf = [0u8; 65536];
                        loop {
                            if let Ok((len, addr)) = socket.recv_from(&mut buf).await {
                                if let Ok(raw) = std::str::from_utf8(&buf[..len]) {
                                    match raw.split_once(':').and_then(|(tok, rest)| {
                                        crate::record_cmd::tokens_match(tok, &admin_token)
                                            .then(|| rest.to_string())
                                    }) {
                                        Some(rest) => {
                                            match crate::record_cmd::parse_admin_command(&rest) {
                                                Some(
                                                    cmd @ (crate::record_cmd::AdminCommand::RecordStart(_)
                                                    | crate::record_cmd::AdminCommand::RecordStop
                                                    | crate::record_cmd::AdminCommand::RecordStatus),
                                                ) => {
                                                    // Preserve pre-existing behavior exactly:
                                                    // forward the raw command string to the main
                                                    // select loop (`admin_rx`), which owns the
                                                    // recording session state and its own
                                                    // fire-and-forget (no socket reply) handling.
                                                    let forwarded = match cmd {
                                                        crate::record_cmd::AdminCommand::RecordStart(service) => {
                                                            format!("record_start:{service}")
                                                        }
                                                        crate::record_cmd::AdminCommand::RecordStop => {
                                                            "record_stop".to_string()
                                                        }
                                                        crate::record_cmd::AdminCommand::RecordStatus => {
                                                            "record_status".to_string()
                                                        }
                                                        _ => unreachable!(),
                                                    };
                                                    let _ = admin_tx.send(forwarded).await;
                                                }
                                                Some(crate::record_cmd::AdminCommand::Role) => {
                                                    let reply = admin_mgmt.cached_role().to_string();
                                                    let _ = socket.send_to(reply.as_bytes(), addr).await;
                                                }
                                                Some(crate::record_cmd::AdminCommand::Qr(text)) => {
                                                    match crate::qr::png_for(&text) {
                                                        Ok(png) => {
                                                            let reply = crate::record_cmd::encode_body_b64(&png);
                                                            let _ = socket.send_to(reply.as_bytes(), addr).await;
                                                        }
                                                        Err(e) => {
                                                            warn!("admin qr command failed: {e}");
                                                        }
                                                    }
                                                }
                                                Some(crate::record_cmd::AdminCommand::Mgmt {
                                                    method,
                                                    path,
                                                    body,
                                                }) => {
                                                    // Spawned so a slow/timed-out mgmt call (up to
                                                    // 10s, see `MgmtClient::mgmt_call`) never blocks
                                                    // this loop from servicing other admin-socket
                                                    // commands (record_*, other mgmt calls) meanwhile.
                                                    let mgmt = admin_mgmt.clone();
                                                    let control_tx = admin_control_tx.clone();
                                                    let socket = socket.clone();
                                                    tokio::spawn(async move {
                                                        let reply = match mgmt
                                                            .mgmt_call(
                                                                &control_tx,
                                                                method,
                                                                &path,
                                                                body,
                                                                Duration::from_secs(10),
                                                            )
                                                            .await
                                                        {
                                                            Ok((status, resp_body)) => {
                                                                crate::record_cmd::format_mgmt_reply(status, &resp_body)
                                                            }
                                                            Err(e) => {
                                                                warn!("admin mgmt command failed: {e}");
                                                                // Status 0 is a synthetic sentinel (no
                                                                // real HTTP-style status is ever < 100)
                                                                // meaning the call itself failed locally
                                                                // — control_tx closed, or no
                                                                // `MgmtResponse` within the 10s
                                                                // `mgmt_call` timeout — as opposed to a
                                                                // real server-returned status. The CLI
                                                                // (`aivpn-client mgmt`) treats 0 as a
                                                                // hard failure (non-zero exit).
                                                                crate::record_cmd::format_mgmt_reply(0, &[])
                                                            }
                                                        };
                                                        let _ = socket.send_to(reply.as_bytes(), addr).await;
                                                    });
                                                }
                                                None => {
                                                    warn!("Rejected admin command: unparseable command");
                                                }
                                            }
                                        }
                                        None => {
                                            warn!(
                                                "Rejected admin command: missing or invalid auth token"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            "Failed to bind local admin UDP socket 127.0.0.1:44301: {}",
                            e
                        );
                    }
                }
            }))
        };

        // Proxy mode: start smoltcp + SOCKS5 instead of creating a TUN device
        if let Some(listen_addr) = self.config.proxy_listen {
            let vpn_ip = self
                .config
                .tun_config
                .tun_addr
                .parse::<std::net::Ipv4Addr>()
                .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;
            let gateway_ip = self
                .config
                .tun_config
                .server_vpn_ip
                .parse::<std::net::Ipv4Addr>()
                .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;
            let proxy_cfg = crate::proxy::ProxyConfig {
                listen_addr,
                vpn_ip,
                gateway_ip,
                prefix_len: self.config.tun_config.prefix_len,
            };
            let handle = crate::proxy::spawn_proxy(proxy_cfg, tun_to_udp_tx.clone())
                .await
                .map_err(Error::Io)?;
            self.proxy_handle = Some(handle);
        }

        // Take the TUN reader for the spawned task (skipped in proxy mode and
        // in headless control-only mode, where no TUN device was created).
        let tun_task = if self.config.proxy_listen.is_none() && !self.config.control_only {
            let mut tun_reader = self
                .tunnel
                .take_reader()
                .ok_or(Error::Session("TUN reader not available".into()))?;
            let tun_to_udp_tx_clone = tun_to_udp_tx.clone();
            let shutdown_for_tasks = shutdown.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; UDP_RECV_BUF_SIZE];
                loop {
                    if shutdown_for_tasks.load(Ordering::SeqCst) {
                        break;
                    }

                    match tun_reader.read(&mut buf).await {
                        Ok(n) => {
                            if n > 0 {
                                debug!("TUN read {} bytes", n);

                                #[cfg(target_os = "macos")]
                                let payload: Vec<u8> = if n > 4 && buf[0] == 0 && buf[1] == 0 {
                                    buf[4..n].to_vec()
                                } else {
                                    buf[..n].to_vec()
                                };

                                #[cfg(not(target_os = "macos"))]
                                let payload: Vec<u8> = buf[..n].to_vec();

                                let _ = tun_to_udp_tx_clone.send(payload).await;
                            }
                        }
                        Err(e) => {
                            error!("TUN read error: {}", e);
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                }
            })
        } else {
            tokio::spawn(std::future::pending::<()>())
        };

        // Spawn UDP reader task
        let udp_socket = self
            .udp_socket
            .as_ref()
            .ok_or(Error::Session(
                "UDP socket not initialized before run()".into(),
            ))?
            .clone();
        let udp_to_tun_tx_clone = udp_to_tun_tx.clone();
        let shutdown_for_tasks = shutdown.clone();
        let udp_task = tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_RECV_BUF_SIZE];
            let mut consecutive_errors: u32 = 0;

            loop {
                if shutdown_for_tasks.load(Ordering::SeqCst) {
                    break;
                }

                match udp_socket.recv(&mut buf).await {
                    Ok(n) => {
                        consecutive_errors = 0;
                        if n > 0 {
                            let _ = udp_to_tun_tx_clone
                                .send(Bytes::copy_from_slice(&buf[..n]))
                                .await;
                        }
                    }
                    Err(e) => {
                        consecutive_errors += 1;
                        error!("UDP recv error: {}", e);
                        if consecutive_errors >= 20 {
                            // Socket is likely dead; let the main loop handle reconnect.
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        });

        // Spawn stats writer task
        let stats_shutdown = shutdown.clone();
        let stats_bytes_sent = self.bytes_sent.clone();
        let stats_bytes_received = self.bytes_received.clone();
        let stats_current_vpn_ip = self.current_vpn_ip.clone();
        // 3c: whether THIS run's initial_mask came from main.rs's
        // "3 consecutive dead handshakes" resilience fallback rather than
        // normal bootstrap selection. Constant for the run's lifetime (set
        // once by main.rs before constructing this ClientConfig), so a
        // plain captured bool is enough — no need for an Arc<AtomicBool>
        // like the live-updated `ip:` field above.
        let stats_bootstrap_fallback = self.config.is_bootstrap_fallback;
        let stats_task = if self.config.control_only {
            // Headless control-only mode: no stats file — there is no GUI or
            // CLI observing this in-process pool-peer dialer.
            tokio::spawn(std::future::pending::<()>())
        } else {
            tokio::spawn(async move {
                // Determine platform-appropriate stats paths
                #[cfg(target_os = "windows")]
                let stats_paths: Vec<std::path::PathBuf> = {
                    let mut paths = Vec::new();
                    if let Some(local_app) = std::env::var_os("LOCALAPPDATA") {
                        let dir = std::path::PathBuf::from(local_app).join("AIVPN");
                        let _ = tokio::fs::create_dir_all(&dir).await;
                        paths.push(dir.join("traffic.stats"));
                    }
                    let tmp = std::env::temp_dir().join("aivpn-traffic.stats");
                    paths.push(tmp);
                    paths
                };
                #[cfg(not(target_os = "windows"))]
                let stats_paths: Vec<std::path::PathBuf> = vec![
                    std::path::PathBuf::from("/var/run/aivpn/traffic.stats"),
                    std::path::PathBuf::from("/tmp/aivpn-traffic.stats"),
                ];

                // Session epoch (unix ms), captured ONCE when this session's stats
                // task starts. GUIs key on a CHANGE in `since` to detect a silent
                // in-process reconnect: it tells them to accept the new (lower)
                // counters and restart the displayed uptime together, instead of
                // freezing on the old totals. The pre-session zero-writes in
                // main.rs deliberately carry NO `since` — no session exists yet.
                let session_since_ms = epoch_ms();

                // Write initial stats. O_NOFOLLOW/create_new-hardened atomic write
                // (secure_write.rs): these paths fall back to predictable
                // world-writable /tmp locations, which a local attacker could
                // pre-plant as a symlink to a file this (possibly root-run)
                // process can write. Uses spawn_blocking (mirroring what
                // tokio::fs::write already does internally) since the hardened
                // write is a handful of sync syscalls, not the tokio async-fs API.
                let initial_ip = stats_current_vpn_ip
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                let initial = format!(
                    "sent:0,received:0,since:{},ip:{},fallback:{}",
                    session_since_ms, initial_ip, stats_bootstrap_fallback as u8
                );
                for path in &stats_paths {
                    let p = path.clone();
                    let data = initial.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        crate::secure_write::write_status_best_effort(&p, data.as_bytes())
                    })
                    .await;
                }
                info!("Initial stats written");

                let mut interval = tokio::time::interval(Duration::from_secs(1));
                loop {
                    interval.tick().await;
                    if stats_shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    let sent = stats_bytes_sent.load(Ordering::Relaxed);
                    let received = stats_bytes_received.load(Ordering::Relaxed);
                    // Re-read on every tick (not just once at task start): a pool
                    // re-home updates `current_vpn_ip` live via
                    // `apply_server_network_override` while this task keeps
                    // running, so the stats file must reflect the change within
                    // one tick for file-polling GUIs (Windows) to pick it up.
                    let ip = stats_current_vpn_ip
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone();
                    let stats = format!(
                        "sent:{},received:{},since:{},ip:{},fallback:{}",
                        sent, received, session_since_ms, ip, stats_bootstrap_fallback as u8
                    );
                    for path in &stats_paths {
                        let p = path.clone();
                        let data = stats.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            crate::secure_write::write_status_best_effort(&p, data.as_bytes())
                        })
                        .await;
                    }
                }
            })
        };

        // ── Spawn upload task using the shared pipeline ──
        let upload_udp = self
            .udp_socket
            .as_ref()
            .ok_or(Error::Session(
                "UDP socket not initialized before upload task".into(),
            ))?
            .clone();
        let upload_keys = self
            .session_keys
            .clone()
            .ok_or(Error::Session("No session keys".into()))?;
        let upload_engine = self
            .mimicry_engine
            .take()
            .ok_or(Error::Session("No mimicry engine".into()))?;
        let upload_seq = self.send_seq as u16;
        let upload_counter = self.counter;
        let upload_bytes_sent = self.bytes_sent.clone();
        let upload_state = Arc::new(Mutex::new(UploadCryptoState {
            keys: upload_keys,
            counter: upload_counter,
            seq: upload_seq,
            rekey_ack: VecDeque::new(),
        }));
        self.upload_state = Some(upload_state.clone());

        let upload_pending_mask = self.pending_mask.clone();

        let mut upload_task = tokio::spawn(Self::spawn_upload(
            tun_to_udp_rx,
            control_rx,
            upload_udp,
            upload_engine,
            upload_state,
            upload_bytes_sent,
            upload_pending_mask,
            self.keepalive_interval,
            self.keepalive_sent_ms.clone(),
            self.adaptive_level.fec_n(),
            self.keepalive_interval_ms.clone(),
            self.last_tx_ms.clone(),
        ));

        // Main loop: download + shutdown + upload health
        let mut shutdown_tick = tokio::time::interval(Duration::from_secs(1));
        shutdown_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // RX silence watchdog: detect silent path failure (NAT rebind, carrier drop).
        // The UDP socket stays open and recv() blocks indefinitely when the path dies,
        // so we track the last received packet and reconnect on silence. The tick is
        // 5 s because the asymmetric threshold below can be as low as 12 s (A4).
        let mut rx_watchdog = tokio::time::interval(Duration::from_secs(5));
        rx_watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_rx = std::time::Instant::now();
        // Post-freeze/suspend liveness probe state (see WAKE_GAP_THRESHOLD):
        // stamp of the previous watchdog tick, and, when a gap was detected,
        // (deadline, armed_at, gap) of the pending probe.
        let mut last_watchdog_tick = std::time::Instant::now();
        let mut wake_probe: Option<(Instant, Instant, Duration)> = None;
        // Reset the DATA-plane liveness markers for THIS connection: they are
        // struct fields (stamped inside process_decoded) and would otherwise
        // carry a stale stall over from a previous session.
        self.last_data_rx = Instant::now();
        self.upload_at_last_data_rx = self.bytes_sent.load(Ordering::Relaxed);
        self.data_stall_started = None;
        self.data_stall_strikes = 0;
        self.data_plane_proven = false;
        // First-contact anchor: a rejected/unmatched handshake (e.g. the client's
        // cached bootstrap descriptor doesn't match the server's) gets NO server
        // packets at all, so `last_rx` never moves off this instant. Detect that
        // in ~10 s (matching the mobile cores' HANDSHAKE_TIMEOUT) instead of
        // waiting the full 24–45 s RX-silence threshold, so main.rs's reconnect
        // loop reaches the bootstrap_default fallback in ~30 s, not ~72 s.
        let connect_instant = last_rx;
        // A4: seed last_tx at loop start so a fresh connection isn't instantly
        // treated as "TX stalled" before the first keepalive goes out.
        self.last_tx_ms.store(epoch_ms(), Ordering::Relaxed);
        // A4: rate-limit for the proactive warmup burst below.
        let mut last_warmup = std::time::Instant::now();
        // Path A carrier-change baseline (iOS/Windows/Linux only — see
        // probe_underlying_source_ip). `server_ep` is the connected socket's
        // peer; `underlying_src_ip` is the physical source IP the kernel picks
        // for it right now. Each watchdog tick re-probes and, on a persistent
        // change (a real interface handover), forces a reconnect long before
        // the passive RX-silence threshold would.
        #[cfg(any(target_os = "ios", target_os = "windows", target_os = "linux"))]
        let server_ep = self.udp_socket.as_ref().and_then(|s| s.peer_addr().ok());
        #[cfg(any(target_os = "ios", target_os = "windows", target_os = "linux"))]
        let mut underlying_src_ip = server_ep.and_then(probe_underlying_source_ip);
        #[cfg(any(target_os = "ios", target_os = "windows", target_os = "linux"))]
        let mut path_change_strikes: u8 = 0;
        // Set when the `join_res` select branch consumes upload_task's output,
        // so the teardown below knows it must not poll the handle again.
        let mut upload_joined = false;

        let run_res: Result<()> = loop {
            tokio::select! {
                // Allow fast shutdown.
                _ = shutdown_tick.tick() => {
                    if shutdown.load(Ordering::SeqCst) {
                        info!("Shutdown requested");
                        stats_task.abort();
                        break Ok(());
                    }
                }

                // 3b: native OS network-change listener (see net_change.rs).
                // Best-effort — `None` when unsupported/unavailable, in
                // which case this branch never fires and the existing
                // poll-based watchdogs below are the only reconnect trigger
                // (today's behavior, unchanged). When it DOES fire, react
                // immediately instead of waiting the 5-10s+ these watchdogs
                // need to notice the same change passively.
                _ = async {
                    match self.config.network_change_notify.as_ref() {
                        Some(n) => n.notified().await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    // The Linux listener subscribes to LINK + IPv4/IPv6 IFADDR
                    // groups, so bringing up OUR OWN tun (link up + its v4 addr
                    // + kernel-assigned v6 link-local) emits exactly those
                    // events every connect. Reacting to them would tear the
                    // session down microseconds after the init handshake goes
                    // out — before the server reply can arrive — and each retry
                    // rebuilds the tun, re-emitting the events: an unbreakable
                    // reconnect loop that never establishes. Only honor the
                    // signal once the tunnel is actually up (≥1 authenticated
                    // RX advanced last_rx off connect_instant); until then the
                    // burst is self-inflicted setup churn — drain and ignore it.
                    // A genuine change during the pre-establishment window is
                    // still covered by the handshake-fallback path and the
                    // poll-based carrier-change watchdog below.
                    if last_rx == connect_instant {
                        tracing::debug!(
                            "Network-change event during connection setup — \
                             ignoring self-inflicted tun churn (tunnel not yet established)"
                        );
                    } else {
                        warn!("Native network-change event detected — reconnecting immediately");
                        break Err(Error::Session("network change detected".into()));
                    }
                }

                _ = rx_watchdog.tick() => {
                    // Post-freeze/suspend liveness probe (see WAKE_GAP_THRESHOLD):
                    // a tick gap ≫ the 5 s watchdog cadence means the process
                    // was frozen or the machine suspended. Arm a probe: unless
                    // ANY decodable RX arrives within the window (keepalives
                    // fire immediately after wake), the session is condemned
                    // now instead of lingering dead until RX silence.
                    let tick_now = Instant::now();
                    let tick_gap = tick_now.duration_since(last_watchdog_tick);
                    last_watchdog_tick = tick_now;
                    if tick_gap > WAKE_GAP_THRESHOLD && wake_probe.is_none() {
                        let window = Duration::from_millis(
                            self.keepalive_interval_ms.load(Ordering::Relaxed),
                        )
                        .saturating_mul(2)
                        .clamp(WAKE_PROBE_WINDOW_MIN, WAKE_PROBE_WINDOW_MAX);
                        info!(
                            "Watchdog tick gap {tick_gap:?} (process frozen or system suspended) — \
                             post-wake liveness probe armed ({window:?})"
                        );
                        wake_probe = Some((tick_now + window, tick_now, tick_gap));
                    }
                    if let Some((deadline, armed_at, gap)) = wake_probe {
                        if last_rx >= armed_at {
                            // Decodable RX after the wake moment — session alive.
                            wake_probe = None;
                        } else if tick_now >= deadline {
                            warn!(
                                "post-wake liveness probe: no RX for {:?} after a {:?} \
                                 freeze/suspend gap — reconnecting",
                                last_rx.elapsed(),
                                gap,
                            );
                            break Err(Error::Session(format!(
                                "post-wake liveness probe: no RX for {:?} after a {:?} \
                                 freeze/suspend gap — reconnecting",
                                last_rx.elapsed(),
                                gap,
                            )));
                        }
                    }

                    // K6: periodic kernel tag-window upkeep. The resonance time
                    // window rotates every 10 s and idle/quiet periods deliver
                    // no fallback packets to drive the receive-path refresh, so
                    // this 5 s tick bounds tag staleness at half a window.
                    #[cfg(target_os = "linux")]
                    self.kernel_push_tags(false);

                    // Path A: proactive reconnect on a real carrier/interface
                    // handover (iOS/Windows/Linux; Android and macOS use their
                    // OS path callbacks). Only armed once the session is
                    // ESTABLISHED (a ServerHello was processed) so a carrier
                    // change DURING the initial handshake is left to the
                    // first-contact timeout below. Requires TWO consecutive
                    // disagreeing probes (~5-10 s) so a momentary route flap
                    // mid-handover — or a transient dual-stack source flip —
                    // does not reconnect prematurely.
                    #[cfg(any(target_os = "ios", target_os = "windows", target_os = "linux"))]
                    if self.ever_connected.load(Ordering::Relaxed) {
                        if let (Some(server), Some(baseline)) = (server_ep, underlying_src_ip) {
                            match probe_underlying_source_ip(server) {
                                Some(now_ip) if now_ip != baseline => {
                                    path_change_strikes = path_change_strikes.saturating_add(1);
                                    if path_change_strikes >= 2 {
                                        warn!(
                                            "Underlying source address changed {} -> {} — \
                                             carrier/interface handover, reconnecting",
                                            baseline, now_ip
                                        );
                                        break Err(Error::Session(
                                            "underlying interface changed".into(),
                                        ));
                                    }
                                }
                                // Back on the baseline path — clear a transient strike.
                                Some(_) => path_change_strikes = 0,
                                // No route right now (interface mid-handover): don't
                                // count it as a change, wait for a definitive new IP.
                                None => {}
                            }
                        } else if underlying_src_ip.is_none() {
                            // Baseline was unavailable at loop start (probe failed
                            // then). Establish it now so later ticks have a reference.
                            underlying_src_ip = server_ep.and_then(probe_underlying_source_ip);
                        }
                    }

                    // A4 asymmetric silence detection. 45 s stays the ceiling
                    // for an idle uplink, but when we are actively SENDING
                    // (keepalives flow every interval) and the server has gone
                    // quiet, the path is dead — NAT rebind or carrier drop —
                    // and waiting the full 45 s only hurts interactivity. Cut
                    // the threshold to ~3× the live keepalive interval, with a
                    // 12 s floor so a server-pushed 1–2 s interval can't make
                    // the watchdog trigger-happy. Satellite (15 s keepalive):
                    // 3×15 = 45 s — behavior there is unchanged by design.
                    const RX_SILENCE_MAX: Duration = Duration::from_secs(45);
                    const RX_SILENCE_MIN: Duration = Duration::from_secs(12);
                    let now_ms = epoch_ms();
                    let ka = Duration::from_millis(
                        self.keepalive_interval_ms.load(Ordering::Relaxed).max(1),
                    );
                    let tx_gap_ms =
                        now_ms.saturating_sub(self.last_tx_ms.load(Ordering::Relaxed));
                    // "Recently sent" = within 2 keepalive intervals (min 10 s).
                    let uplink_active =
                        tx_gap_ms <= (2 * ka.as_millis() as u64).max(10_000);
                    let rx_silence = if uplink_active {
                        (3 * ka).clamp(RX_SILENCE_MIN, RX_SILENCE_MAX)
                    } else {
                        RX_SILENCE_MAX
                    };
                    if last_rx.elapsed() > rx_silence {
                        warn!(
                            "No server traffic for {:?} (threshold {:?}, uplink_active={}) — reconnecting",
                            last_rx.elapsed(),
                            rx_silence,
                            uplink_active
                        );
                        break Err(Error::Session("RX silence timeout".into()));
                    }

                    // Data-plane watchdog: clocked on DATA delivered to the
                    // TUN/proxy, not on any decode — a downlink where only
                    // keepalive-acks / KeyRotate retransmits still
                    // authenticate is DEAD for the user and must reconnect in
                    // tens of seconds (see `data_watchdog_verdict`). Skipped
                    // while kernel RX offload is active: in-kernel-consumed
                    // DATA never reaches process_decoded, so user-space data
                    // liveness would be a false negative there.
                    #[cfg(target_os = "linux")]
                    let data_watchdog_active = !self.kernel_installed;
                    #[cfg(not(target_os = "linux"))]
                    let data_watchdog_active = true;
                    if data_watchdog_active {
                        let uploaded_total = self.bytes_sent.load(Ordering::Relaxed);
                        let data_up_since =
                            uploaded_total.saturating_sub(self.upload_at_last_data_rx);
                        if data_up_since > 0 && self.data_stall_started.is_none() {
                            self.data_stall_started = Some(Instant::now());
                        }
                        let stalled_for = if self.data_plane_proven {
                            self.data_stall_started.map(|t| t.elapsed())
                        } else {
                            // Data plane never proven this session —
                            // unanswerable TUN junk must not condemn a
                            // healthy idle tunnel.
                            None
                        };
                        let verdict = data_watchdog_verdict(stalled_for, data_up_since);
                        let stall_pending = verdict.is_some();
                        if let Some(reason) =
                            data_stall_confirmed(&mut self.data_stall_strikes, verdict)
                        {
                            warn!(
                                "{}: {} bytes of uplink data unanswered for {:?} \
                                 (no downlink data for {:?}) — reconnecting",
                                reason,
                                data_up_since,
                                stalled_for.unwrap_or_default(),
                                self.last_data_rx.elapsed(),
                            );
                            // Liveness: a sticky mask that keeps stalling quickly
                            // gets abandoned so AUTO can explore a different one.
                            crate::bootstrap_cache::note_data_stall_and_maybe_explore(
                                session_established,
                            );
                            break Err(Error::Session(format!("{reason} — reconnecting")));
                        }
                        // Window wash: the stall never reached the byte
                        // threshold — background junk, not a dead downlink.
                        // Forget it so trickle can never accumulate into a
                        // false positive (see DATA_STALL_WINDOW). Never wash
                        // while a strike is pending confirmation, or the
                        // reset would erase the very stall the next tick must
                        // re-observe.
                        if !stall_pending
                            && self
                                .data_stall_started
                                .is_some_and(|t| t.elapsed() >= DATA_STALL_WINDOW)
                        {
                            self.data_stall_started = None;
                            self.upload_at_last_data_rx = uploaded_total;
                        }
                    }
                    // First-contact fast fail: no server packet AT ALL since
                    // connect (last_rx unmoved) within the handshake window means
                    // the handshake was rejected — reconnect fast instead of
                    // burning the full RX-silence threshold on a dead attempt.
                    const HANDSHAKE_FIRST_CONTACT: Duration = Duration::from_secs(10);
                    if last_rx == connect_instant
                        && connect_instant.elapsed() > HANDSHAKE_FIRST_CONTACT
                    {
                        warn!(
                            "No server response to handshake within {:?} — reconnecting fast",
                            HANDSHAKE_FIRST_CONTACT
                        );
                        break Err(Error::Session("handshake first-contact timeout".into()));
                    }

                    // A4 proactive CGNAT warmup: if nothing has been sent for
                    // ~20 s (keepalive stalled by doze/backpressure, or the
                    // server pushed a long interval), refresh the NAT mapping
                    // BEFORE it expires instead of reconnecting after. Satellite
                    // is exempt, mirroring the keepalive cap exemption.
                    if self.adaptive_level != AdaptiveLevel::Satellite
                        && tx_gap_ms >= NAT_WARMUP_AFTER.as_millis() as u64
                        && last_warmup.elapsed() >= KEEPALIVE_NAT_CAP
                    {
                        last_warmup = std::time::Instant::now();
                        debug!(
                            "TX idle for {} ms — proactive CGNAT warmup burst",
                            tx_gap_ms
                        );
                        Self::spawn_warmup_burst(control_tx.clone());
                    }
                }

                // Upload task completed (error or channel closed).
                join_res = &mut upload_task => {
                    // The handle's output is consumed here; awaiting it again
                    // after the loop would panic ("polled after completion").
                    upload_joined = true;
                    break match join_res {
                        Ok(Ok(())) => Err(Error::Channel("Upload loop ended unexpectedly".into())),
                        Ok(Err(e)) => Err(e),
                        Err(e) => Err(Error::Session(format!("Upload task panicked: {e}"))),
                    };
                }

                cmd = admin_rx.recv() => {
                    if let Some(cmd) = cmd {
                        if let Some(service) = cmd.strip_prefix("record_start:") {
                            crate::record_cmd::handle_recording_status(true, Some(service));
                            let payload = ControlPayload::RecordingStart { service: service.to_string() };
                            if let Err(e) = control_tx.send(payload).await {
                                error!("Failed to send RecordingStart to upload task: {}", e);
                            } else {
                                info!("Sent RecordingStart for {}", service);
                            }
                        } else if cmd == "record_stop" {
                            if let Some(session_id) = self.active_recording_session {
                                let current_service = crate::record_cmd::read_local_status().and_then(|status| status.service);
                                crate::record_cmd::mark_recording_stop_requested(current_service.as_deref());
                                let payload = ControlPayload::RecordingStop { session_id };
                                if let Err(e) = control_tx.send(payload).await {
                                    error!("Failed to send RecordingStop to upload task: {}", e);
                                } else {
                                    info!("Sent RecordingStop");
                                }
                            } else {
                                warn!("No active recording session to stop");
                                crate::record_cmd::handle_recording_failed("No active recording session to stop");
                            }
                        } else if cmd == "record_status" {
                            let payload = ControlPayload::RecordingStatusRequest;
                            if let Err(e) = control_tx.send(payload).await {
                                error!("Failed to send RecordingStatusRequest to upload task: {}", e);
                            }
                        }
                    }
                }

                // UDP -> TUN (inbound traffic)
                res = udp_to_tun_rx.recv() => {
                    let packet = match res {
                        Some(p) => p,
                        None => break Err(Error::Channel("UDP->TUN channel closed".into())),
                    };

                    match self.receive_and_write_packet(&packet).await {
                        // Advance last_rx only after the packet authenticated:
                        // stamping it on ANY datagram would let a single
                        // spoofed/garbage packet to the ephemeral port defeat
                        // the first-contact fast-fail above and keep a dead
                        // session alive through the RX-silence watchdog.
                        Ok(()) => last_rx = std::time::Instant::now(),
                        Err(e) => match &e {
                            Error::InvalidPacket(_) => warn!("Receive invalid packet: {}", e),
                            Error::Crypto(_) => warn!("Receive error (crypto): {}", e),
                            _ => {
                                warn!("Receive error: {}", e);
                                break Err(e);
                            }
                        }
                    }
                }
            }
        };

        // Stop background tasks before disconnecting. Abort `upload_task`
        // unconditionally (it is only self-consumed on the `join_res` exit path;
        // abort on an already-finished task is a no-op) so it never lingers as a
        // zombie on a flappy connection. Aborting it also drops the control-plane
        // receiver it owns, which closes the `control_tx` channel — that is what
        // makes the two detached §2/§3 tasks (the MaskPreference retry and the
        // jittered MaskFeedback send) reliably bail out via their "receiver gone"
        // send-error paths instead of outliving `run()`.
        stats_task.abort();
        tun_task.abort();
        udp_task.abort();
        upload_task.abort();
        let _ = stats_task.await;
        let _ = tun_task.await;
        let _ = udp_task.await;
        // Await upload_task too: it holds an Arc<UdpSocket> clone, and the
        // disconnect() below removes the K6 kernel session and drops the
        // socket — the fd must not linger in a detached task past that point.
        // Skip only if the `join_res` select branch already consumed the
        // handle's output (re-polling a consumed JoinHandle panics).
        if !upload_joined {
            let _ = upload_task.await;
        }

        if self.state != ClientState::Disconnected {
            self.disconnect().await;
        }

        run_res
    }

    /// Spawn the upload task using the shared pipeline.
    async fn spawn_upload(
        mut rx: mpsc::Receiver<Vec<u8>>,
        mut control_rx: mpsc::Receiver<ControlPayload>,
        udp: Arc<UdpSocket>,
        engine: MimicryEngine,
        upload_state: Arc<Mutex<UploadCryptoState>>,
        bytes_sent: Arc<AtomicU64>,
        pending_mask: Arc<Mutex<Option<aivpn_common::mask::MaskProfile>>>,
        keepalive_interval: Duration,
        keepalive_sent_ms: Arc<AtomicU64>,
        fec_n: u8,
        keepalive_interval_ms: Arc<AtomicU64>,
        last_tx_ms: Arc<AtomicU64>,
    ) -> Result<()> {
        /// Wraps MimicryEngine to implement the shared PacketEncryptor trait.
        struct MimicryEncryptor {
            engine: MimicryEngine,
            upload_state: Arc<Mutex<UploadCryptoState>>,
            bytes_sent: Arc<AtomicU64>,
            pending_mask: Arc<Mutex<Option<aivpn_common::mask::MaskProfile>>>,
            keepalive_sent_ms: Arc<AtomicU64>,
            /// A4: shared with the RX watchdog — every encrypted outbound
            /// packet stamps this so silence detection knows the uplink is live.
            last_tx_ms: Arc<AtomicU64>,
            fec_encoder: Option<aivpn_common::fec::FecEncoder>,
            pending_fec: Option<Vec<u8>>,
        }

        impl MimicryEncryptor {
            fn check_mask(&mut self) {
                if let Some(mask) = self
                    .pending_mask
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take()
                {
                    self.engine.update_mask(mask);
                }
            }
        }

        impl PacketEncryptor for MimicryEncryptor {
            fn encrypt_data(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
                self.check_mask();
                self.last_tx_ms.store(epoch_ms(), Ordering::Relaxed);
                let mut state = self.upload_state.lock().unwrap_or_else(|e| e.into_inner());
                let inner = build_inner_packet(InnerType::Data, state.seq, payload);
                state.seq = state.seq.wrapping_add(1);
                let keys = state.keys.clone();
                let pkt = self
                    .engine
                    .build_packet(&inner, &keys, &mut state.counter, None)?;
                self.engine.update_fsm();

                // FEC: feed payload; if group complete, pre-encrypt repair datagram
                if let Some(fec) = self.fec_encoder.as_mut() {
                    if let Some(repair) = fec.feed(payload) {
                        let repair_payload = repair.encode();
                        let repair_inner =
                            build_inner_packet(InnerType::FecRepair, state.seq, &repair_payload);
                        state.seq = state.seq.wrapping_add(1);
                        if let Ok(enc_repair) =
                            self.engine
                                .build_packet(&repair_inner, &keys, &mut state.counter, None)
                        {
                            self.pending_fec = Some(enc_repair);
                        }
                    }
                }

                Ok(pkt)
            }

            fn take_fec_repair(&mut self) -> Option<Vec<u8>> {
                self.pending_fec.take()
            }

            fn encrypt_control(&mut self, payload: &ControlPayload) -> Result<Vec<u8>> {
                self.check_mask();
                self.last_tx_ms.store(epoch_ms(), Ordering::Relaxed);
                let mut state = self.upload_state.lock().unwrap_or_else(|e| e.into_inner());
                let bytes = payload.encode()?;
                let inner = build_inner_packet(InnerType::Control, state.seq, &bytes);
                state.seq = state.seq.wrapping_add(1);
                let keys = state.keys.clone();
                let pkt = self
                    .engine
                    .build_packet(&inner, &keys, &mut state.counter, None)?;
                // Confirm to the inline-rekey handler (if waiting) that this
                // KeyRotate response was just encrypted with the keys held
                // above — i.e. still the OLD (pre-ratchet) keys, since the
                // handler has not yet overwritten `state.keys` and is blocked
                // on this exact rendezvous before it does. See `rekey_ack` doc
                // comment on `UploadCryptoState`.
                if matches!(payload, ControlPayload::KeyRotate { .. }) {
                    if let Some(ack) = state.rekey_ack.pop_front() {
                        let _ = ack.send(());
                    }
                }
                Ok(pkt)
            }

            fn encrypt_keepalive(&mut self) -> Result<Vec<u8>> {
                self.check_mask();
                // Record send time for RTT measurement via KeepaliveAck.
                let now_ms = epoch_ms();
                self.keepalive_sent_ms.store(now_ms, Ordering::Relaxed);
                self.last_tx_ms.store(now_ms, Ordering::Relaxed);
                let mut state = self.upload_state.lock().unwrap_or_else(|e| e.into_inner());
                let keepalive = ControlPayload::Keepalive { send_ts: now_ms }.encode()?;
                let inner = build_inner_packet(InnerType::Control, state.seq, &keepalive);
                state.seq = state.seq.wrapping_add(1);
                let keys = state.keys.clone();
                self.engine
                    .build_packet(&inner, &keys, &mut state.counter, None)
            }

            fn on_data_sent(&mut self, payload_len: usize) {
                self.bytes_sent
                    .fetch_add(payload_len as u64, Ordering::Relaxed);
            }
        }

        // R2 Phase D — client-side inline ML-DPI self-gate (opt-in, feature
        // `client-dpi-gate`, OFF by default). Capture the active mask family
        // BEFORE `engine` is moved into the encryptor, so a tunnel verdict can
        // request a fresh variant of exactly the mask this session is shaping to.
        #[cfg(feature = "client-dpi-gate")]
        let base_mask_id = engine.mask().mask_id.clone();

        let mut enc = MimicryEncryptor {
            engine,
            upload_state,
            bytes_sent,
            pending_mask,
            keepalive_sent_ms,
            last_tx_ms,
            fec_encoder: if fec_n > 0 {
                // 1500 == MAX_PACKET_SIZE. TunnelConfig::from_network_config
                // and Tunnel::apply_network_config both clamp the (possibly
                // server-pushed) MTU to this same bound before it's ever
                // applied to the TUN device, so no payload fed here can
                // legitimately exceed it — see the comments there.
                Some(aivpn_common::fec::FecEncoder::new(fec_n, MAX_PACKET_SIZE))
            } else {
                None
            },
            pending_fec: None,
        };
        let config = UploadConfig {
            keepalive_interval,
            keepalive_ms: Some(keepalive_interval_ms),
            ..Default::default()
        };

        // Build the optional outbound inspector: `Some` only under the feature.
        #[cfg(feature = "client-dpi-gate")]
        let mut self_gate = aivpn_common::dpi_gate::ClientSelfGate::new(0.5, base_mask_id);
        #[cfg(feature = "client-dpi-gate")]
        let inspector: Option<&mut dyn upload_pipeline::OutboundInspector> = Some(&mut self_gate);
        #[cfg(not(feature = "client-dpi-gate"))]
        let inspector: Option<&mut dyn upload_pipeline::OutboundInspector> = None;

        upload_pipeline::run_upload_loop(
            &mut rx,
            Some(&mut control_rx),
            &udp,
            &mut enc,
            &config,
            inspector,
        )
        .await
    }

    /// Receive packet from server and write to TUN (using pre-computed mdh_len)
    pub(super) async fn receive_and_write_packet(&mut self, packet: &[u8]) -> Result<()> {
        if self
            .transition_recv_deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.transition_recv_keys = None;
            self.transition_recv_deadline = None;
            self.transition_grace_hard = None;
            self.transition_recv_window.reset();
        }

        let keys = self
            .session_keys
            .as_ref()
            .ok_or(Error::Session("No session keys".into()))?;

        // Try every MDH length this session has used, with the current session
        // keys first. The server frames different downlink packets with
        // different masks (bootstrap vs runtime vs polymorphic; DATA vs
        // control/rekey), so a single fixed length silently drops any packet
        // whose mask differs — the failure that strands the tunnel on the first
        // rekey. See `decode_downlink_any_mdh_len`.
        let decoded = match decode_downlink_any_mdh_len(
            packet,
            keys,
            &mut self.recv_window,
            &mut self.recv_mdh_candidates,
        ) {
            Ok(decoded) => decoded,
            Err(primary_err) => {
                // Fallback: PFS-ratchet transition keys (in-flight packets
                // encrypted with the pre-rekey keys), same candidate lengths.
                if let Some(fallback_keys) = self.transition_recv_keys.as_ref() {
                    if let Ok(decoded) = decode_downlink_any_mdh_len(
                        packet,
                        fallback_keys,
                        &mut self.transition_recv_window,
                        &mut self.recv_mdh_candidates,
                    ) {
                        return self.process_decoded(decoded).await;
                    }
                }
                return Err(primary_err);
            }
        };
        self.process_decoded(decoded).await
    }

    /// Process a successfully decoded packet (shared by primary and fallback paths)
    async fn process_decoded(&mut self, decoded: DecodedPacket) -> Result<()> {
        // K6: every user-space-validated packet is a fresh observation of the
        // downlink counter (kernel-consumed packets never reach here), so use
        // it to opportunistically re-base the kernel tag window. No-op unless
        // the counter advanced ≥ KERNEL_TAG_REFRESH_STRIDE or the 10 s
        // resonance time window rotated.
        #[cfg(target_os = "linux")]
        self.kernel_push_tags(false);

        let inner_header = decoded.header;
        let ip_payload = decoded.payload;

        match inner_header.inner_type {
            InnerType::Data => {
                if ip_payload.is_empty() || (ip_payload[0] >> 4 != 4 && ip_payload[0] >> 4 != 6) {
                    return Err(Error::InvalidPacket("Invalid IP version in payload"));
                }
                if self.config.control_only {
                    // Headless control-only mode: no TUN, no SOCKS proxy — a
                    // pool-peer dialer has nowhere to deliver DATA packets.
                    // Drop silently rather than erroring on the (never
                    // created) TUN device.
                } else if let Some(h) = &self.proxy_handle {
                    {
                        let mut q = h.rx_queue.lock().unwrap_or_else(|e| e.into_inner());
                        // Bound the queue: drop-oldest past the cap so a stalled
                        // SOCKS consumer cannot grow memory without limit
                        // (inner TCP retransmit recovers the dropped packet).
                        while q.len() >= PROXY_RX_QUEUE_MAX {
                            q.pop_front();
                        }
                        q.push_back(ip_payload.to_vec());
                    }
                    let _ = h.wake_tx.try_send(());
                } else {
                    self.tunnel.write_packet_async(&ip_payload).await?;
                }
                self.bytes_received
                    .fetch_add(ip_payload.len() as u64, Ordering::Relaxed);
                // DATA-plane liveness stamp: only here — control traffic must
                // not mask a dead data downlink (see `data_watchdog_verdict`).
                self.last_data_rx = Instant::now();
                self.upload_at_last_data_rx = self.bytes_sent.load(Ordering::Relaxed);
                self.data_stall_started = None;
                self.data_stall_strikes = 0;
                if !self.data_plane_proven {
                    // FIX (Jul 15): remember the mask that just carried real DATA so
                    // AUTO-mode reconnects reuse it instead of re-deriving (and
                    // hopping) from the churning descriptor set.
                    *crate::bootstrap_cache::LAST_GOOD_MASK
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) =
                        Some(self.config.initial_mask.clone());
                }
                self.data_plane_proven = true;
                debug!(
                    "Received {} bytes from server, wrote to TUN",
                    ip_payload.len()
                );
            }
            InnerType::Control => {
                let control = ControlPayload::decode(&ip_payload)?;
                self.handle_server_control(control).await?;
            }
            _ => {
                debug!(
                    "Received non-data packet type: {:?}",
                    inner_header.inner_type
                );
            }
        }

        Ok(())
    }
}
