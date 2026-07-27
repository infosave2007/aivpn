//! Control-plane inbound dispatch: `handle_control_message` (the hot-path
//! decoder+match over every `ControlPayload` variant) and
//! `dispatch_mgmt_request` (in-tunnel management-API bridge). Pure move out
//! of `gateway/mod.rs` — no behavior change.

use super::*;

impl super::Gateway {
    /// Build the `mgmt_service::MgmtCtx` inputs this `Gateway` actually
    /// holds and run `mgmt_service::dispatch` on a blocking thread — it
    /// does synchronous `ClientDatabase` file IO
    /// (`add_client`/`update_client`/`remove_client` all end in
    /// `ClientDatabase::save()`, a blocking `std::fs::write`), so unlike
    /// the cheap in-memory `find_by_id`/`list_clients` reads used
    /// elsewhere in this file, it must never run directly on a tokio
    /// reactor thread.
    ///
    /// `server_pub_key` and `server_signing_pubkey` ARE fully populated —
    /// both are pure functions of `server_private_key`, which is already
    /// on `GatewayConfig` (see `main.rs`'s `mgmt_pub_key`/
    /// `mgmt_signing_pubkey`, computed the exact same way for the REST
    /// API's `ServeConfig`). `server_addr` (the public `host:port` a
    /// client should dial) and `audit_log_path` (the on-disk path
    /// `audit_tail` reads) are sourced from `GatewayConfig::mgmt_server_addr`
    /// / `GatewayConfig::audit_log_path` (P1.2b) — `main.rs` populates both
    /// with the exact same values it computes for `management_api::
    /// ServeConfig::server_addr` / `::audit_log_path`. All curated routes
    /// (status/list/add/get/patch/delete/reset-device/connection-key/
    /// audit-log) are fully functional over the tunnel.
    async fn dispatch_mgmt_request(
        &self,
        method: u8,
        path: String,
        body: Vec<u8>,
    ) -> (u16, Vec<u8>) {
        let Some(db) = self.client_db.clone() else {
            return (503, Vec::new());
        };
        let mask_dir = self.config.mask_dir.clone();
        let mask_operator_pubkey = self.config.mask_operator_pubkey;
        let audit_log = self.audit_log.clone();
        let server_private_key = self.config.server_private_key;
        let server_addr = self.config.mgmt_server_addr.clone();
        let audit_log_path = self.config.audit_log_path.clone();
        let pending_config = self.pending_config.clone();
        // P1 (global exit live-swap): re-read alongside the dispatch call,
        // inside the SAME `spawn_blocking` closure below — small disk IO,
        // kept off the tokio reactor thread exactly like `resolve_heavy_setting`'s
        // own `server.json` read (which runs on this same blocking thread
        // when this request happened to be the `ExitNode` heavy-setting
        // confirm). See `apply_global_exit_and_teardown`.
        let server_config_path = self.config.server_config_path.clone();
        // P1 REST parity fix: cheap `Arc` clones so `apply_global_exit_and_teardown`
        // can run inside the SAME `spawn_blocking` closure below — see that
        // function's doc comment for why this is now shared with the
        // REST/Unix-socket path too.
        let masked_exit_addr = self.masked_exit_addr.clone();
        let pool_dialer_for_exit = self.pool_dialer.clone();

        // Wave B1 (pool topology read endpoints): build the snapshot from
        // live state BEFORE the `spawn_blocking` closure (all its inputs are
        // already owned `Arc`/`Vec`/`String` clones, so this is cheap and
        // doesn't need the blocking pool) — see `mgmt_service`'s "Pool
        // topology views" doc comment for the legacy-transport /
        // no-pool-sync degradation this implements.
        let pool = match self.pool_dialer() {
            Some(dialer) => {
                let (registry_nodes, revoked) = match self.node_registry() {
                    Some(registry) => (registry.list(), registry.list_revoked()),
                    None => (Vec::new(), Vec::new()),
                };
                let statuses = dialer.pool_status_snapshot();
                mgmt_service::build_pool_snapshot(mgmt_service::PoolSnapshotInputs {
                    peers: dialer.peers(),
                    registry_nodes: &registry_nodes,
                    revoked: &revoked,
                    statuses: &statuses,
                    transport: "masked",
                })
            }
            None if self.pool_configured => mgmt_service::PoolSnapshot::empty("legacy"),
            None => mgmt_service::PoolSnapshot::empty("none"),
        };

        let result = tokio::task::spawn_blocking(move || {
            let (server_pub_key, server_signing_pubkey) = if server_private_key != [0u8; 32] {
                (
                    Some(crypto::KeyPair::from_private_key(server_private_key).public_key_bytes()),
                    Some(
                        derive_server_signing_key(&server_private_key)
                            .verifying_key()
                            .to_bytes(),
                    ),
                )
            } else {
                (None, None)
            };
            let ctx = mgmt_service::MgmtCtx {
                db: &db,
                server_pub_key,
                server_addr,
                server_signing_pubkey,
                mask_operator_pubkey,
                audit: Some(&audit_log),
                mask_dir: &mask_dir,
                config_path: None,
                audit_log_path: audit_log_path.as_deref(),
                pending_config: Some(&pending_config),
                pool: Some(pool),
            };
            let response = mgmt_service::dispatch(&ctx, method, &path, &body);
            // P1 (global exit live-swap) + Wave B2c (runtime dial add-peer)
            // + Wave 2 (dial-teardown), unified: re-read `pool.exit_node`
            // from `server.json`, swap `masked_exit_addr` if it changed,
            // pick up any newly-referenced per-client `exit_node`, and prune
            // any now-unreferenced runtime exit dial — all in the SAME
            // blocking-thread pass. A confirmed `HeavySetting::ExitNode`
            // apply (this very request, or an earlier one via the tunnel OR
            // REST) only ever PERSISTS the change to disk (see that
            // variant's doc comment); this is what makes it also take
            // effect on this node's own live routing, without a restart.
            // See `apply_global_exit_and_teardown`'s doc comment — the SAME
            // function `management_api::apply_config`/`confirm_config` call
            // for the REST/Unix-socket path.
            apply_global_exit_and_teardown(
                &masked_exit_addr,
                pool_dialer_for_exit.as_ref(),
                server_config_path.as_deref(),
                &db,
            );
            response
        })
        .await;

        // B2b: any mgmt request that reached `mgmt_service::dispatch` may
        // have mutated the client DB (add/patch/delete, including a client's
        // `exit_node`) — clear the exit-resolution cache unconditionally
        // (cheap: read-only GET/list requests just pay one extra
        // re-resolution on the next packet per active client, and this
        // guarantees an admin's `exit_node` change takes effect live,
        // without the client reconnecting). See `exit_route_cache`'s doc
        // comment for the full invalidation policy.
        self.exit_route_cache.clear();

        match result {
            Ok(r) => r,
            Err(e) => {
                error!("mgmt_service::dispatch panicked: {}", e);
                (500, Vec::new())
            }
        }
    }

    /// Handle control message
    /// Handle an inbound `RouteSync` control message (site-to-site / masked
    /// pool route propagation). Extracted verbatim from the
    /// `handle_control_message` match arm — thin dispatch, no behavior change.
    fn on_route_sync(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: SocketAddr,
        subnets_json: &[u8],
    ) {
        // PHASE 3 (site-to-site over masked transport): accept
        // RouteSync from EITHER the legacy synthetic site-peer role
        // (`is_site_peer`, authenticated via the site_sync directional
        // sync_key) OR a FORK-B masked pool-client (`is_masked_pool_peer`
        // — a sibling node that dialed us through the normal masked
        // handshake, see `pool_dialer.rs`). An ordinary VPN client
        // session has neither flag set and is still rejected below.
        // PHASE 4 (per-node crypto identity): also read the
        // session's `verified_node_id` — set by the NodeEnrollment
        // arm below once this peer's Ed25519 proof verifies against
        // the node registry — so `handle_route_sync` can key the
        // route allowlist to the cryptographically-proven identity
        // instead of trusting the payload's self-asserted node_id.
        let (is_site, is_masked_pool, verified_node_id) = {
            let sess = session.lock();
            (
                sess.is_site_peer,
                sess.is_masked_pool_peer,
                sess.verified_node_id.clone(),
            )
        };
        // BUG D1 fix: when `require_node_enrollment` is set, a masked
        // pool-peer's RouteSync MUST carry a crypto-verified identity
        // — drop it outright rather than falling back to trusting the
        // payload's self-asserted node_id. Without this gate, route
        // authorization ultimately keys off whatever node_id string
        // an unverified peer simply claims in the RouteSync payload
        // itself (see `handle_route_sync`'s fallback), which is not a
        // proof of identity at all. Legacy `is_site_peer` sessions
        // (authenticated via the directional site_sync key, not
        // per-node identity) are unaffected — this gate only applies
        // to `is_masked_pool`. Pulled out into
        // `route_sync_must_be_dropped_unverified` so the gate
        // condition itself is directly unit-testable.
        if route_sync_must_be_dropped_unverified(
            is_masked_pool,
            self.require_node_enrollment,
            &verified_node_id,
        ) {
            warn!(
                "site_sync: RouteSync from masked pool-peer {} dropped — \
                 require_node_enrollment is set and this session has no \
                 crypto-verified node identity",
                hash_addr(&client_addr)
            );
        } else if is_site || is_masked_pool {
            crate::site_sync::handle_route_sync(
                subnets_json,
                &client_addr.to_string(),
                verified_node_id.as_deref(),
            );
        } else {
            warn!(
                "site_sync: RouteSync from non-peer session {} — dropping",
                hash_addr(&client_addr)
            );
        }
    }

    /// Handle an inbound `NodeEnrollment` control message (per-node Ed25519
    /// identity proof for masked pool-peers). Extracted verbatim from the
    /// `handle_control_message` match arm — thin dispatch, no behavior change.
    fn on_node_enrollment(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: SocketAddr,
        node_id: String,
        node_pub: [u8; 32],
        time_window: u64,
        signature: [u8; 64],
    ) {
        // PHASE 4 (per-node identity): a masked pool-peer proves
        // ownership of its self-asserted node_id with a durable Ed25519
        // key. Verify + bind (TOFU / manual pin) via the node registry
        // and, on success, stamp the crypto-authenticated node_id onto
        // the session so route authorization can trust it over the
        // self-asserted string. Only meaningful on a masked pool-peer
        // session with a configured registry; ignored otherwise (the
        // session stays up — an unverified node simply isn't trusted).
        // B2/D2 fix (session-bound proof): the verified transcript is
        // this session's OWN ephemeral X25519 pair — `eph_pub` (the
        // client's, learned during the handshake) and `server_eph_pub`
        // (this server's own, generated in `build_and_insert_session`
        // and set exactly once per session). Reading them off the
        // session under lock, rather than trusting anything from the
        // wire payload, is what makes a captured proof from a
        // DIFFERENT session fail here: its transcript won't match.
        let (is_masked_pool, session_server_eph_pub, session_client_eph_pub) = {
            let sess = session.lock();
            (sess.is_masked_pool_peer, sess.server_eph_pub, sess.eph_pub)
        };
        if !is_masked_pool {
            debug!(
                "NodeEnrollment from {} ignored — not a masked pool-peer session",
                hash_addr(&client_addr)
            );
        } else if let Some(ref registry) = self.node_registry {
            use crate::node_registry::NodeAuthOutcome;
            // `server_eph_pub` is only `None` if this arrives before
            // `build_and_insert_session` ever ran for this session,
            // which cannot happen (the session must already exist to
            // reach this control-payload handler at all) — fail
            // closed with an all-zero transcript on the
            // theoretically-unreachable `None` case rather than
            // panicking or skipping the check.
            let server_eph_pub_for_check = session_server_eph_pub.unwrap_or([0u8; 32]);
            match registry.authenticate(
                &node_id,
                &node_pub,
                time_window,
                &signature,
                &server_eph_pub_for_check,
                &session_client_eph_pub,
            ) {
                NodeAuthOutcome::Verified => {
                    session.lock().verified_node_id = Some(node_id.clone());
                    debug!(
                        "NodeEnrollment from {} verified node_id",
                        hash_addr(&client_addr)
                    );
                }
                NodeAuthOutcome::BoundNew => {
                    session.lock().verified_node_id = Some(node_id.clone());
                    info!(
                        "NodeEnrollment from {} bound a new pool-node identity (TOFU)",
                        hash_addr(&client_addr)
                    );
                }
                NodeAuthOutcome::Rejected(reason) => {
                    warn!(
                        "NodeEnrollment from {} rejected: {}",
                        hash_addr(&client_addr),
                        reason
                    );
                }
            }
        } else {
            debug!(
                "NodeEnrollment from {} ignored — no node registry configured",
                hash_addr(&client_addr)
            );
        }
    }

    /// Handle an inbound `PoolSync` control message (peer pushes its client-DB
    /// delta for CRDT merge). Extracted verbatim from the
    /// `handle_control_message` match arm — thin dispatch, no behavior change.
    fn on_pool_sync(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: SocketAddr,
        clients_json: Vec<u8>,
    ) {
        // Accept PoolSync from sessions registered as EITHER the
        // legacy synthetic pool-peer role, or a FORK-B masked
        // pool-client (a sibling node that dialed us through the
        // normal masked handshake path — see `masked_peer` in
        // `handle_packet`). A regular VPN client sending PoolSync
        // would be able to inject or overwrite arbitrary client
        // records in the database, so both checks still gate on an
        // explicit peer-role flag rather than trusting any session.
        let (is_pool, is_masked_pool) = {
            let sess = session.lock();
            (sess.is_pool_peer, sess.is_masked_pool_peer)
        };
        if !is_pool && !is_masked_pool {
            warn!(
                "pool_sync: rejected from non-pool session {}",
                hash_addr(&client_addr)
            );
            self.audit_log.log(
                AuditActor::System,
                "PoolSync",
                &hash_addr(&client_addr),
                "rejected: not a pool peer",
            );
        } else if let Some(ref db) = self.client_db {
            let json_str = String::from_utf8_lossy(&clients_json);
            match db.merge_from_json(&json_str) {
                Ok(n) => {
                    info!(
                        "pool_sync: merged {} clients from peer {}",
                        n,
                        hash_addr(&client_addr)
                    );
                    // B2b: a peer's merge can change a client's
                    // `exit_node` (e.g. an admin set it on a
                    // DIFFERENT pool node) — clear the local
                    // exit-resolution cache so that takes effect
                    // live here too, not just on the node the
                    // change was made on. See `exit_route_cache`'s
                    // doc comment.
                    self.exit_route_cache.clear();
                    // Wave B2c: same reasoning as the mgmt-mutation
                    // hook above — a merged-in `exit_node` this node
                    // never dialed at startup needs a runtime
                    // add_peer too, or B2b's live-routing decision
                    // would just keep falling back to the global
                    // default forever.
                    self.add_dial_peers_for_client_exits();
                }
                Err(e) => warn!(
                    "pool_sync: merge failed from {}: {}",
                    hash_addr(&client_addr),
                    e
                ),
            }
        }
    }

    /// Handle an inbound `PoolStateDigest` control message (FORK-B reactive
    /// convergence: peer announces its root DB digest; on mismatch we reply
    /// with our bucket digests). Extracted verbatim from the
    /// `handle_control_message` match arm — thin dispatch, no behavior change.
    async fn on_pool_state_digest(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: SocketAddr,
        digest: [u8; 32],
    ) {
        // FORK-B pool-sync reactive convergence, Phase 2: a masked
        // pool-client peer periodically (or on-change) announces its
        // root DB-state digest. If it differs from ours, we no
        // longer push the WHOLE client DB (Phase 1) — instead we
        // send our bucketed (Merkle-lite) digest, with
        // `reply_requested: true`, so the peer can work out exactly
        // which buckets actually differ, push us its delta, AND hand
        // its own bucket digests back to us in turn (see the
        // `PoolBucketDigests` arm below) — one working edge
        // reconciles both directions over a single session. We
        // deliberately do NOT also echo a `PoolStateDigest` here:
        // that echo used to make the peer's own inbound-digest arm
        // fire again and echo back, an unbounded digest ping-pong.
        //
        // Gated strictly on `is_masked_pool_peer` (never the legacy
        // `is_pool_peer` role, and never an ordinary client session):
        // the legacy synthetic pool-peer path has its own push-only
        // pool_sync mechanism and never sends this control message,
        // so treating it as authoritative for a role it doesn't use
        // would be a silent no-op at best; an ordinary client
        // session sending this is not a peer at all.
        let is_masked_pool = session.lock().is_masked_pool_peer;
        if !is_masked_pool {
            debug!(
                "PoolStateDigest from {} ignored — not a masked pool-peer session",
                hash_addr(&client_addr)
            );
        } else if let Some(ref db) = self.client_db {
            let local = db.state_digest();
            if digest != local {
                debug!(
                    "PoolStateDigest mismatch from {} — sending bucket digests for reactive convergence",
                    hash_addr(&client_addr)
                );
                if let Err(e) = self
                    .send_control_message(
                        &ControlPayload::PoolBucketDigests {
                            digests: db.bucket_digests(),
                            reply_requested: true,
                        },
                        session,
                    )
                    .await
                {
                    warn!(
                        "PoolStateDigest: failed to send bucket digests to {}: {}",
                        hash_addr(&client_addr),
                        e
                    );
                }
            }
        } else {
            debug!(
                "PoolStateDigest from {} ignored — no client_db configured",
                hash_addr(&client_addr)
            );
        }
    }

    /// Handle an inbound `PoolBucketDigests` control message (FORK-B Merkle-lite
    /// bucket-diff exchange). Extracted verbatim from the
    /// `handle_control_message` match arm — thin dispatch, no behavior change.
    async fn on_pool_bucket_digests(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: SocketAddr,
        digests: Vec<u8>,
        reply_requested: bool,
    ) {
        // Phase 2: peer sent its bucketed digests in reaction to our
        // root-digest mismatch (or in reply to our own bucket
        // message). Diff against our own bucket_digests() and reply
        // with a PoolSync containing ONLY the records in the buckets
        // that actually differ — the peer's `merge_from_json` folds
        // them in.
        //
        // If `reply_requested` is set, ALSO hand our own
        // bucket_digests() back with `reply_requested: false` — this
        // completes the reverse direction of the exchange (the peer
        // can now compute ITS differing buckets and push them to
        // us). `reply_requested: false` is never itself answered
        // with another `PoolBucketDigests`, which bounds the
        // exchange and prevents a ping-pong.
        let is_masked_pool = session.lock().is_masked_pool_peer;
        if !is_masked_pool {
            debug!(
                "PoolBucketDigests from {} ignored — not a masked pool-peer session",
                hash_addr(&client_addr)
            );
        } else if let Some(ref db) = self.client_db {
            let local_buckets = db.bucket_digests();
            let differing = crate::client_db::differing_pool_buckets(&local_buckets, &digests);
            if differing.is_empty() {
                debug!(
                    "PoolBucketDigests from {} — no differing buckets, nothing to send",
                    hash_addr(&client_addr)
                );
            } else {
                let clients_json = db.clients_json_for_buckets(&differing).into_bytes();
                debug!(
                    "PoolBucketDigests from {} — {} differing bucket(s), sending delta",
                    hash_addr(&client_addr),
                    differing.len()
                );
                if let Err(e) = self
                    .send_control_message(&ControlPayload::PoolSync { clients_json }, session)
                    .await
                {
                    warn!(
                        "PoolBucketDigests: failed to send PoolSync delta to {}: {}",
                        hash_addr(&client_addr),
                        e
                    );
                }
            }
            if reply_requested {
                if let Err(e) = self
                    .send_control_message(
                        &ControlPayload::PoolBucketDigests {
                            digests: local_buckets,
                            reply_requested: false,
                        },
                        session,
                    )
                    .await
                {
                    warn!(
                        "PoolBucketDigests: failed to send reply bucket digests to {}: {}",
                        hash_addr(&client_addr),
                        e
                    );
                }
            }
        } else {
            debug!(
                "PoolBucketDigests from {} ignored — no client_db configured",
                hash_addr(&client_addr)
            );
        }
    }

    /// Handle an inbound `ChainForward` control message (multi-hop exit relay:
    /// NAT-forward a downstream client's inner IP payload at this exit node,
    /// recording the reverse route for masked pool-peer entry sessions).
    /// Extracted verbatim from the `handle_control_message` match arm — thin
    /// dispatch, no behavior change.
    async fn on_chain_forward(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: SocketAddr,
        payload: Vec<u8>,
    ) {
        if self.config.exit_node_enabled {
            let ip_version = payload.first().map(|b| b >> 4);
            let min_len = match ip_version {
                Some(4) => 20,
                Some(6) => 40,
                _ => usize::MAX,
            };
            if payload.len() < min_len {
                warn!(
                    "chain_forward: invalid IP payload from {} (version={:?} len={}) — dropping",
                    hash_addr(&client_addr),
                    ip_version,
                    payload.len()
                );
            } else {
                // C-S-4: Validate that the injected packet's source IP
                // matches the session's assigned VPN IP to prevent
                // IP spoofing through the exit-node relay path.
                //
                // Pool/site peer sessions (chain-forward entry nodes)
                // never carry a per-session vpn_ip — they relay
                // traffic on behalf of many downstream clients that
                // are authenticated by the *entry* node, not by us.
                // The AEAD decrypt that got us here already
                // authenticated the sender as the registered peer
                // under its directional key, so for those sessions
                // we only need to confirm the packet's source IP is
                // plausibly one of our own VPN clients (i.e. inside
                // our configured VPN subnet) rather than requiring
                // an exact match against a field that is always
                // None. Ordinary (non-peer) client sessions keep the
                // strict exact-match check — no relaxation there.
                // PHASE 4 (reverse chain-forward): also surface
                // whether THIS session is a masked pool-peer and, if
                // so, the packet's parsed IPv4 source — needed below
                // to populate `chain_reverse_routes` so a downlink
                // reply to that source can find its way back over
                // this exact session. `pkt_src_ipv4` deliberately
                // mirrors the same parse already done for the
                // src-IP-spoofing check rather than re-parsing the
                // payload a second time.
                let (src_ip_ok, is_masked_pool_entry, pkt_src_ipv4) = {
                    let sess = session.lock();
                    // PHASE 3: also accept a masked pool-peer session
                    // as a chain-forward entry node (a sibling node
                    // that dialed us via `pool_dialer.rs`'s masked
                    // pool-client handshake) — same relaxed
                    // subnet-contains check as the legacy
                    // `is_pool_peer`/`is_site_peer` roles, since it
                    // likewise relays on behalf of many downstream
                    // clients authenticated by the entry node.
                    let is_peer_session =
                        sess.is_pool_peer || sess.is_site_peer || sess.is_masked_pool_peer;
                    match ip_version {
                        Some(4) => {
                            if payload.len() >= 20 {
                                let src: [u8; 4] = payload[12..16].try_into().unwrap();
                                let pkt_src = std::net::Ipv4Addr::from(src);
                                let ok = if is_peer_session {
                                    self.config.network_config.contains(pkt_src)
                                } else {
                                    sess.vpn_ip.map_or(false, |vpn| vpn == pkt_src)
                                };
                                (ok, sess.is_masked_pool_peer, Some(pkt_src))
                            } else {
                                (false, false, None)
                            }
                        }
                        // IPv6: no per-session IPv6 address assigned — reject
                        _ => (false, false, None),
                    }
                };
                if !src_ip_ok {
                    warn!(
                        "chain_forward: source IP mismatch from {} — dropping",
                        hash_addr(&client_addr)
                    );
                } else {
                    // PHASE 4 (reverse chain-forward): remember that
                    // this client VPN IP's uplink traffic arrived on
                    // THIS masked pool-peer session, so the TUN read
                    // loop's downlink worker can route a reply back
                    // here instead of dropping it (see
                    // `Gateway::chain_reverse_routes`'s doc comment).
                    // Strictly gated on `is_masked_pool_peer` — the
                    // legacy dedicated-socket `ChainForwarder` roles
                    // (`is_pool_peer`/`is_site_peer`) have no
                    // session-based return channel to record here.
                    if is_masked_pool_entry {
                        if let Some(src_ip) = pkt_src_ipv4 {
                            let session_id = session.lock().session_id;
                            chain_reverse_route_insert(
                                &self.chain_reverse_routes,
                                &self.chain_reverse_insert_count,
                                src_ip,
                                session_id,
                                Instant::now(),
                            );
                        }
                    }
                    // BUG C4 fix: apply the SAME `allow_peer_routing`
                    // gate ordinary client Data packets already get
                    // (see "Block intra-VPN routing at ingress" in
                    // the DATA arm above) to ChainForward-relayed
                    // packets too. Without this, a masked pool-peer
                    // relaying on behalf of many downstream clients
                    // could reach another LOCAL VPN client's session
                    // via `inner_dst` even when peer routing is
                    // disabled — the exact intra-VPN routing the
                    // DATA-path gate exists to block, just reached
                    // through a different arm. Parses `inner_dst`
                    // straight out of the (already length-validated
                    // for IPv4, `min_len == 20`) payload; IPv6
                    // ChainForward payloads have no per-session VPN
                    // IP to match against here, so they fall through
                    // unaffected by this check (existing IPv6
                    // handling is unchanged).
                    let drop_for_peer_routing = !self.config.allow_peer_routing
                        && payload.len() >= 20
                        && ip_version == Some(4)
                        && {
                            let inner_dst = std::net::Ipv4Addr::new(
                                payload[16],
                                payload[17],
                                payload[18],
                                payload[19],
                            );
                            self.session_manager
                                .get_session_by_vpn_ip(&inner_dst)
                                .is_some()
                        };
                    if drop_for_peer_routing {
                        debug!(
                            "chain_forward: peer routing disabled — dropping relayed packet to local VPN session from {}",
                            hash_addr(&client_addr)
                        );
                    } else if let Some(ref tx) = self.tun_write_tx {
                        let _ = tx.send(payload).await;
                    }
                }
            }
        } else {
            warn!(
                "chain_forward: ChainForward from {} rejected — exit_node_enabled is false",
                hash_addr(&client_addr)
            );
        }
    }

    /// Handle an inbound `PartitionAnnounce` control message (Wave B-IP pool
    /// VPN-IP-partition visibility: log any overlap check and echo our own
    /// partition state back). Extracted verbatim from the
    /// `handle_control_message` match arm — thin dispatch, no behavior change.
    async fn on_partition_announce(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: SocketAddr,
        peer_cidr: String,
        peer_index: u32,
        peer_partition_size: u32,
        peer_num_partitions: u32,
        peer_explicit: bool,
    ) {
        // Wave B-IP.2: a masked pool-peer announces its VPN-IP
        // partition assignment (Wave B-IP's `set_node_partition`/
        // `_explicit`) purely for operator visibility — the
        // disjoint-slice allocation guarantee itself is already
        // enforced deterministically on each node independently,
        // whether or not either side ever sees this message. Gated
        // on `is_masked_pool_peer` like the other pool anti-entropy
        // control types above.
        let (is_masked_pool, verified_node_id) = {
            let sess = session.lock();
            (sess.is_masked_pool_peer, sess.verified_node_id.clone())
        };
        if !is_masked_pool {
            debug!(
                "PartitionAnnounce from {} ignored — not a masked pool-peer session",
                hash_addr(&client_addr)
            );
        } else if let Some(ref db) = self.client_db {
            let local_cidr = db.network_config().cidr_string();
            let local_partition_info = db.partition_info();
            let local_partition = local_partition_info.map(|p| (p.partition_index, p.explicit));
            // Decode the UNPARTITIONED sentinel {index:0, size:0,
            // num_partitions:1} back to `None` — see
            // `decode_peer_partition`'s doc comment.
            let peer_partition = crate::pool_partition::decode_peer_partition(
                peer_index,
                peer_partition_size,
                peer_num_partitions,
                peer_explicit,
            );
            let check = crate::pool_partition::check_partition(
                &local_cidr,
                local_partition,
                &peer_cidr,
                peer_partition,
            );
            let peer_desc = verified_node_id.unwrap_or_else(|| hash_addr(&client_addr));

            let should_log = {
                let mut sess = session.lock();
                let changed = sess.last_partition_check != Some(check);
                sess.last_partition_check = Some(check);
                changed
            };
            if should_log {
                crate::pool_partition::log_partition_check(
                    check,
                    &peer_desc,
                    &local_cidr,
                    &peer_cidr,
                );
            }

            // Reply with our own announce so the dialing peer's
            // anti-entropy loop (which has no other way to learn
            // OUR partition state — the gateway never dials out)
            // can run the same check from its side too, over this
            // same session. `unwrap_or` covers the "this node has
            // no partition configured" case with a self-describing
            // sentinel (num_partitions: 1, explicit: false) rather
            // than skipping the reply.
            let info = local_partition_info.unwrap_or(crate::client_db::PartitionInfo {
                partition_index: 0,
                partition_size: 0,
                num_partitions: 1,
                explicit: false,
            });
            let reply = ControlPayload::PartitionAnnounce {
                subnet_cidr: local_cidr,
                partition_index: info.partition_index,
                partition_size: info.partition_size,
                num_partitions: info.num_partitions,
                explicit: info.explicit,
            };
            if let Err(e) = self.send_control_message(&reply, session).await {
                warn!(
                    "PartitionAnnounce: failed to send reply to {}: {}",
                    hash_addr(&client_addr),
                    e
                );
            }
        } else {
            debug!(
                "PartitionAnnounce from {} ignored — no client_db configured",
                hash_addr(&client_addr)
            );
        }
    }

    /// Handle an inbound `MaskPreference` control message (§3 polymorphic mask
    /// selection: derive+push a per-session polymorphic variant of the
    /// requested base mask, idempotently and rate-limited). Extracted verbatim
    /// from the `handle_control_message` match arm — thin dispatch, no behavior
    /// change; early `return Ok(())` paths are preserved (the fn's only
    /// post-match statement is `Ok(())`, so an arm return is equivalent).
    async fn on_mask_preference(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: SocketAddr,
        base_mask_id: String,
    ) -> Result<()> {
        self.metrics.record_mask_preference_request();
        let Some(base) = aivpn_common::mask::preset_masks::by_id(&base_mask_id) else {
            debug!(
                "MaskPreference from {} references unknown base mask '{}' — ignoring",
                hash_addr(&client_addr),
                base_mask_id
            );
            return Ok(());
        };

        let (session_id, prng_seed, current_mask_id) = {
            let sess = session.lock();
            // Prefer the pending (already-scheduled) mask id if a switch
            // is in flight, else the active mask id.
            let current = sess
                .pending_mask
                .as_ref()
                .map(|(m, _)| m.mask_id.clone())
                .or_else(|| sess.mask.as_ref().map(|m| m.mask_id.clone()));
            (sess.session_id, sess.keys.prng_seed, current)
        };
        let variant = base.to_polymorphic(&prng_seed);

        // §3 F idempotency: MaskPreference is retried by the client for
        // reliability (a single lost packet must not disable polymorphic
        // masks). If the session already has this exact polymorphic
        // variant (active or pending), do NOT re-push a MaskUpdate —
        // re-pushing would reset the mimicry FSM mid-connection, an
        // observable disruption to the very fingerprint §3 protects.
        if polymorphic_variant_already_active(current_mask_id.as_deref(), &variant.mask_id) {
            debug!(
                "MaskPreference from {}: variant '{}' already active/pending — skipping re-push (idempotent)",
                hash_addr(&client_addr),
                variant.mask_id
            );
            return Ok(());
        }

        // Per-session rate limit on the expensive (sign + encrypt)
        // path below — see `MASK_PREFERENCE_THROTTLE`'s doc comment
        // for why this cannot interfere with the client's legitimate
        // same-id retry loop (those are already caught by the
        // idempotency check above, before ever reaching this point).
        // Uses `try_claim_mask_preference_slot` (atomic check-and-claim
        // via `DashMap::entry()`, not a separate get()+insert()) so two
        // MaskPreference packets for the same session processed by two
        // genuinely concurrent `tokio::spawn`ed tasks (see
        // `process_packets_concurrent`) cannot both slip past the
        // throttle before either has claimed it.
        let now = Instant::now();
        if !try_claim_mask_preference_slot(&self.mask_preference_throttle, session_id, now) {
            debug!(
                "MaskPreference from {}: throttled (processed one within the last {:?}) — dropping",
                hash_addr(&client_addr),
                MASK_PREFERENCE_THROTTLE
            );
            return Ok(());
        }

        info!(
            "MaskPreference from {}: deriving polymorphic variant '{}' from base '{}'",
            hash_addr(&client_addr),
            variant.mask_id,
            base_mask_id
        );

        match self
            .session_manager
            .build_mask_update_packet(session, &variant)
        {
            Ok(packet) => {
                // FIX L: `udp_socket` is `None` until `run()` binds
                // it — don't panic if a control message races that
                // window (or a `Gateway` is driven without `run()`,
                // e.g. tests).
                if let Some(sock) = self.udp_socket.as_ref() {
                    if let Err(e) = sock.send_to(&packet, client_addr).await {
                        warn!(
                            "Failed to send polymorphic MaskUpdate to {}: {}",
                            client_addr, e
                        );
                    } else {
                        self.session_manager
                            .update_session_mask(&session_id, variant);
                        self.metrics.record_polymorphic_variant_pushed();
                    }
                } else {
                    warn!(
                        "Dropping polymorphic MaskUpdate for {} — UDP socket not bound",
                        hash_addr(&client_addr)
                    );
                }
            }
            Err(e) => {
                warn!("Failed to build polymorphic MaskUpdate packet: {}", e);
            }
        }
        Ok(())
    }

    /// Handle an inbound `MaskFeedback` control message (§2 k-anonymous mask
    /// outcome reporting + regional-hints/config reply). Extracted verbatim
    /// from the `handle_control_message` match arm — thin dispatch, no behavior
    /// change; the early `return Ok(())` throttle path is preserved (the fn's
    /// only post-match statement is `Ok(())`).
    async fn on_mask_feedback(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: SocketAddr,
        entries: Vec<aivpn_common::protocol::MaskOutcome>,
        country_code: [u8; 2],
    ) -> Result<()> {
        // §2 M1 independent opt-in: an EMPTY MaskFeedback is a
        // receive-only client's hints probe — it shares no outcome data
        // but still carries a country code so the server can reply with
        // RegionalMaskHints. So empty entries are NOT ignored; we simply
        // skip the record step and fall through to the reply below.
        if !entries.is_empty() {
            let client_id = {
                let sess = session.lock();
                sess.client_id.clone()
            };
            // k-anonymity requires a *stable* authenticated reporter
            // identity. Without `client_id` (e.g. `client_db` unset, or
            // an unauthenticated session) the only available fallback
            // would be the ephemeral `session_id`, which lets a single
            // client fake unlimited "distinct reporters" simply by
            // reconnecting — degrading k-anonymity to "distinct
            // sessions". Skip recording in that case rather than
            // silently weakening the guarantee (still reply with hints).
            match client_id {
                Some(client_id) => {
                    // Reporter token: hashed stable client identity,
                    // never the raw identity. Fed only into the
                    // HyperLogLog sketch, which discards it immediately
                    // after updating one register — no raw or hashed
                    // reporter identity is ever persisted server-side.
                    let reporter_token = blake3::hash(client_id.as_bytes());
                    let entry_count = entries.len().min(64);
                    info!(
                        "MaskFeedback from {} ({} entries, country={})",
                        hash_addr(&client_addr),
                        entry_count,
                        crate::mask_feedback::sanitize_country_code_for_log(&country_code)
                    );
                    self.mask_feedback.record_feedback(
                        country_code,
                        reporter_token.as_bytes(),
                        &entries,
                    );
                    self.metrics.record_mask_feedback_received();
                    // Refresh the store-size gauges immediately after a
                    // write — cheap (O(1), see `bucket_count`/
                    // `region_count`) and keeps the live dashboard from
                    // lagging behind the 300s periodic sweep refresh
                    // (see the sweep task in `run()`, which re-syncs
                    // these same gauges after evictions).
                    self.metrics
                        .set_feedback_buckets(self.mask_feedback.bucket_count());
                    self.metrics
                        .set_feedback_regions(self.mask_feedback.region_count());
                }
                None => {
                    debug!(
                        "MaskFeedback outcomes from {} not recorded — no authenticated client_id (k-anonymity requires a stable identity); still replying with hints",
                        hash_addr(&client_addr)
                    );
                }
            }
        } else {
            debug!(
                "Hints-only MaskFeedback probe from {} (country={})",
                hash_addr(&client_addr),
                crate::mask_feedback::sanitize_country_code_for_log(&country_code)
            );
        }

        // FIX F.1 (MEDIUM, §2 amplification): per-session throttle on
        // the scan+reply path below — see `MASK_FEEDBACK_THROTTLE`'s
        // doc comment. Deliberately placed AFTER the recording block
        // above: real outcome recording (cheap, O(1) HLL update,
        // already bounded by MAX_BUCKETS/MAX_BUCKETS_PER_COUNTRY) is
        // never dropped by this throttle, only the expensive
        // `top_masks_for_region` scan and its up-to-two encrypted
        // replies. Uses the same atomic check-and-claim primitive as
        // `MaskPreference` so two genuinely concurrent MaskFeedback
        // packets for the same session cannot both slip past it.
        let feedback_session_id = session.lock().session_id;
        if !try_claim_mask_feedback_slot(
            &self.mask_feedback_throttle,
            feedback_session_id,
            Instant::now(),
        ) {
            debug!(
                "MaskFeedback from {}: hints/reply path throttled (one served within the last {:?}) — skipping scan+reply",
                hash_addr(&client_addr),
                MASK_FEEDBACK_THROTTLE
            );
            return Ok(());
        }

        // Close the loop immediately: the server does not know the
        // client's region ahead of time, so hints are only ever sent
        // right after a MaskFeedback (which carries the country code).
        // If the region's aggregates clear the k-anonymity gate, push
        // them back. Fires for both real reports and empty hints probes.
        let top = self.mask_feedback.top_masks_for_region(country_code);
        if !top.is_empty() {
            match self
                .send_control_message(
                    &ControlPayload::RegionalMaskHints {
                        country_code,
                        masks: top,
                    },
                    session,
                )
                .await
            {
                Ok(()) => self.metrics.record_regional_hints_sent(),
                Err(e) => debug!("RegionalMaskHints send failed: {}", e),
            }
        }

        // §2 M3 server-pushed config: tell the opted-in client how to
        // tune its reporting (failure threshold + report interval).
        // Only opted-in clients ever send MaskFeedback, so this reaches
        // exactly the right audience without extra gating.
        if let Err(e) = self
            .send_control_message(
                &ControlPayload::FeedbackConfig {
                    report_failure_threshold: self.config.feedback_report_failure_threshold,
                    report_interval_secs: self.config.feedback_report_interval_secs,
                },
                session,
            )
            .await
        {
            debug!("FeedbackConfig send failed: {}", e);
        }
        Ok(())
    }

    /// Handle an inbound `Keepalive` control message (pre-ratchet ServerHello
    /// resend, else KeepaliveAck + piggybacked catalog/role pushes). Extracted
    /// verbatim from the `handle_control_message` match arm — thin dispatch, no
    /// behavior change; the early pre-ratchet `return Ok(())` is preserved.
    async fn on_keepalive(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: SocketAddr,
        send_ts: u64,
    ) -> Result<()> {
        debug!("Keepalive from {}", hash_addr(&client_addr));
        if !session.lock().is_ratcheted {
            // The client is still retrying the initial handshake. If the
            // first ServerHello was lost, replying with a normal pre-ratchet
            // ControlAck leaves the client stuck forever.
            self.send_server_hello(session, client_addr).await?;
            return Ok(());
        }
        // Echo the client's own send_ts so it can measure RTT without
        // clock-skew between client and server.
        self.send_control_message(&ControlPayload::KeepaliveAck { echo_ts: send_ts }, session)
            .await?;
        // Piggyback the mask catalog on keepalives: send it only when the
        // global catalog version has moved past what this session last
        // received. Keepalives are always post-ratchet (guarded above),
        // so this never races the PFS key switch, and it self-heals if a
        // push is lost — the next keepalive retries until versions match.
        let current_ver = self
            .mask_store
            .as_ref()
            .map(|s| s.catalog_version())
            .unwrap_or(1);
        if session.lock().mask_catalog_version_sent != current_ver {
            match self.send_mask_catalog(session).await {
                Ok(()) => session.lock().mask_catalog_version_sent = current_ver,
                Err(e) => debug!("MaskCatalog send failed: {}", e),
            }
        }
        // P1.2: announce this session's server-assigned management
        // role once, so the client knows whether to surface
        // admin/viewer management UI. Gated exactly like the
        // MaskCatalog push above — post-ratchet Keepalive only
        // (guarded at the top of this arm), send-once via
        // `capabilities_sent`, self-healing if the send is lost
        // (retried on the next Keepalive).
        if !session.lock().capabilities_sent {
            let role = self.session_role(session);
            let caps = ControlPayload::Capabilities {
                role: role.as_u8(),
                features: 0,
            };
            match self.send_control_message(&caps, session).await {
                Ok(()) => session.lock().capabilities_sent = true,
                Err(e) => debug!("Capabilities send failed: {}", e),
            }
        }
        Ok(())
    }

    /// Handle an inbound `DeviceEnrollment` control message (session-bound DH
    /// proof verify + one-device binding via the client DB). Extracted verbatim
    /// from the `handle_control_message` match arm — thin dispatch, no behavior
    /// change; the early `return Ok(())` reject paths are preserved.
    async fn on_device_enrollment(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: SocketAddr,
        static_pub: [u8; 32],
        dh_proof: [u8; 32],
    ) -> Result<()> {
        let client_id = { session.lock().client_id.clone() };
        if let (Some(ref db), Some(ref cid)) = (&self.client_db, &client_id) {
            // Verify the session-bound proof: dh_shared =
            // X25519(server_static_priv, client_static_pub) ==
            // client's X25519(static_priv, server_static_pub) (X25519
            // is symmetric); dh_proof must equal
            // device_enrollment_proof(dh_shared, server_eph_pub,
            // client_eph_pub) over THIS session's exact ephemeral
            // pair — see `verify_device_enrollment_proof`.
            let server_kp = crypto::KeyPair::from_private_key(self.config.server_private_key);
            let dh_shared = match server_kp.compute_shared(&static_pub) {
                Ok(d) => d,
                Err(e) => {
                    warn!(
                        "DeviceEnrollment from {}: DH error: {}",
                        hash_addr(&client_addr),
                        e
                    );
                    return Ok(());
                }
            };
            let (session_server_eph_pub, session_client_eph_pub) = {
                let sess = session.lock();
                (sess.server_eph_pub, sess.eph_pub)
            };
            let proof_ok = verify_device_enrollment_proof(
                &dh_shared,
                session_server_eph_pub,
                session_client_eph_pub,
                &dh_proof,
            );
            if !proof_ok {
                warn!(
                    "DeviceEnrollment from {}: invalid DH proof — rejecting",
                    hash_addr(&client_addr)
                );
                self.audit_log.log(
                    AuditActor::System,
                    "device_enrollment_rejected",
                    cid,
                    "denied",
                );
                let shutdown = ControlPayload::Shutdown { reason: 3 };
                let _ = self.send_control_message(&shutdown, session).await;
                let session_id = session.lock().session_id;
                self.session_manager.remove_session(&session_id);
                return Ok(());
            }
            match db.enroll_device(cid, &static_pub) {
                Ok(true) => info!("Device enrolled and bound for client {}", cid),
                Ok(false) => debug!("Device binding verified for client {}", cid),
                Err(e) => {
                    // 3f: one-time key already used — a DIFFERENT
                    // device already bound this one_time credential.
                    // The session is already tag-validated/AEAD
                    // established (this is a decrypted, authenticated
                    // in-session control message), so PSK possession
                    // is proven — send the specific, authenticated
                    // HandshakeReject{reason:1} instead of the
                    // generic Shutdown so the client can show why and
                    // stop retrying.
                    warn!("Device binding mismatch for {}: {}", cid, e);
                    self.audit_log.log(
                        AuditActor::System,
                        "device_binding_mismatch",
                        cid,
                        "denied",
                    );
                    let reject = ControlPayload::HandshakeReject { reason: 1 };
                    let _ = self.send_control_message(&reject, session).await;
                    let session_id = session.lock().session_id;
                    self.session_manager.remove_session(&session_id);
                }
            }
        }
        Ok(())
    }

    /// Handle an inbound `MgmtRequest` control message (in-tunnel management-API
    /// dispatch: throttle → role-authorize → dispatch → MgmtResponse, with
    /// revoke follow-through). Extracted verbatim from the
    /// `handle_control_message` match arm — thin dispatch, no behavior change;
    /// the early throttle/deny `return Ok(())` paths are preserved.
    async fn on_mgmt_request(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: SocketAddr,
        req_id: u32,
        method: u8,
        path: String,
        body: Vec<u8>,
    ) -> Result<()> {
        // P1.2: real in-tunnel management dispatch. Every branch
        // below replies with SOME `MgmtResponse` — a caller
        // waiting on `req_id` must never hang, whether the
        // outcome is throttled/denied/dispatched.
        let session_id = session.lock().session_id;
        if !self.try_claim_mgmt_slot(session_id, Instant::now()) {
            let resp = ControlPayload::MgmtResponse {
                req_id,
                status: 429,
                body: Vec::new(),
            };
            if let Err(e) = self.send_control_message(&resp, session).await {
                debug!("MgmtResponse (429 throttled) send failed: {}", e);
            }
            return Ok(());
        }

        // Role resolved server-side from the session's `client_id`
        // — NEVER anything the request itself claims. See
        // `session_role`'s doc comment for why this is re-resolved
        // per request rather than cached.
        let role = self.session_role(session);
        if !mgmt_service::authorize(role.as_u8(), method, &path) {
            debug!(
                "MgmtRequest from {} denied: role={:?} method={} path={}",
                hash_addr(&client_addr),
                role,
                method,
                path
            );
            let resp = ControlPayload::MgmtResponse {
                req_id,
                status: 403,
                body: Vec::new(),
            };
            if let Err(e) = self.send_control_message(&resp, session).await {
                debug!("MgmtResponse (403 denied) send failed: {}", e);
            }
            return Ok(());
        }

        // P1.3: identify a revoke BEFORE dispatching — `path` is
        // moved into `dispatch_mgmt_request` below, and
        // `mgmt_service::revoke_target` needs the original
        // (method, path) pair to recognize the route regardless of
        // outcome.
        let revoke_id = mgmt_service::revoke_target(method, &path);

        let (status, resp_body) = self.dispatch_mgmt_request(method, path, body).await;

        // P1.3: on a successful admin revoke (204), immediately
        // force-disconnect any live session for that client on
        // this node and kick a priority pool beacon so peers
        // converge on the tombstone without waiting for their next
        // scheduled anti-entropy tick. See `force_disconnect_client`
        // / `trigger_priority_pool_beacon`'s doc comments.
        if let Some(client_id) = revoke_id.filter(|_| status == 204) {
            self.force_disconnect_client(&client_id).await;
            self.trigger_priority_pool_beacon();
        }

        let resp = ControlPayload::MgmtResponse {
            req_id,
            status,
            body: resp_body,
        };
        if let Err(e) = self.send_control_message(&resp, session).await {
            debug!("MgmtResponse send failed: {}", e);
        }
        Ok(())
    }

    pub(crate) async fn handle_control_message(
        &self,
        payload: &[u8],
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: SocketAddr,
    ) -> Result<()> {
        let control = ControlPayload::decode(payload)?;

        match control {
            ControlPayload::KeyRotate { new_eph_pub } => {
                let (session_id, has_pending) = {
                    let sess = session.lock();
                    (sess.session_id, sess.pending_rekey_keypair.is_some())
                };
                if has_pending {
                    info!(
                        "Inline rekey response from {} — committing new keys",
                        hash_addr(&client_addr)
                    );
                    self.session_manager
                        .commit_session_rekey(&session_id, &new_eph_pub);
                    // refresh_session_tags is redundant — commit_session_rekey already updates tag_map
                } else {
                    debug!(
                        "KeyRotate from {} ignored — no pending rekey",
                        hash_addr(&client_addr)
                    );
                }
            }
            ControlPayload::MaskUpdate { .. } => {
                warn!("Unexpected MASK_UPDATE from client");
            }
            ControlPayload::Keepalive { send_ts } => {
                self.on_keepalive(session, client_addr, send_ts).await?;
            }
            ControlPayload::TelemetryRequest { metric_flags: _ } => {
                debug!("Telemetry request from {}", hash_addr(&client_addr));
                // Send response
                let response = ControlPayload::TelemetryResponse {
                    packet_loss: 0,
                    rtt_ms: 10,
                    jitter_ms: 2,
                    buffer_pct: 25,
                };
                self.send_control_message(&response, session).await?;
            }
            ControlPayload::TelemetryResponse {
                packet_loss,
                rtt_ms,
                ..
            } => {
                let (mask_id, reporter) = {
                    let sess = session.lock();
                    (
                        sess.mask.as_ref().map(|m| m.mask_id.clone()),
                        sess.session_id,
                    )
                };
                if let Some(ref mid) = mask_id {
                    // Pass the authenticated session id as the reporter so the
                    // anomaly detector can require multi-reporter corroboration
                    // before believing a client-reported compromise (anti-DoS).
                    self.neural_module.lock().record_telemetry(
                        mid,
                        reporter,
                        packet_loss as f64,
                        rtt_ms as f64,
                    );
                }
                debug!("Telemetry response received — recorded to anomaly detector");
            }
            ControlPayload::TimeSync { .. } => {
                debug!("Time sync request");
            }
            ControlPayload::Shutdown { reason } => {
                info!(
                    "Shutdown request from {} (reason: {})",
                    hash_addr(&client_addr),
                    reason
                );
                // Close session and stop active recording if any
                let session_id = session.lock().session_id;
                self.session_manager.remove_session(&session_id);
                self.neural_module.lock().cleanup_stats(session_id);
                #[cfg(feature = "neural")]
                self.dpi_gate.cleanup(&session_id);
                if let Some(ref ka) = self.kernel_accel {
                    let _ = ka.session_remove(&session_id);
                }
                if let Some(ref recorder) = self.recording_manager {
                    let socket = self.udp_socket.as_ref().unwrap().clone();
                    let store = recorder.store();
                    let mdh = self.mask_catalog.packet_mdh_bytes();
                    let outcome = recorder.stop_for_session_end(session_id);
                    Self::handle_recording_outcome(
                        &socket,
                        &self.session_manager,
                        &store,
                        &mdh,
                        outcome,
                        None,
                    )
                    .await;
                }
            }
            ControlPayload::ControlAck { .. } => {
                // ACK received, nothing to do
            }
            ControlPayload::ServerHello { .. } => {
                warn!(
                    "Unexpected ServerHello from client {}",
                    hash_addr(&client_addr)
                );
            }
            ControlPayload::RecordingStart { service } => {
                // Only allow from admin sessions (check client_id)
                let admin_key_id = {
                    let sess = session.lock();
                    sess.client_id.clone()
                };
                if !self.can_start_recording(admin_key_id.as_deref()) {
                    warn!(
                        "Recording rejected: unauthenticated client {}",
                        hash_addr(&client_addr)
                    );
                    let failed = ControlPayload::RecordingFailed {
                        reason: "Recording requires a recording-admin key".into(),
                    };
                    self.send_control_message(&failed, session).await?;
                    return Ok(());
                }
                if let Some(ref recorder) = self.recording_manager {
                    let session_id = session.lock().session_id;
                    recorder.start(
                        session_id,
                        service.clone(),
                        admin_key_id.unwrap_or_else(|| "admin".into()),
                    );
                    let ack = ControlPayload::RecordingAck {
                        session_id,
                        status: "started".into(),
                    };
                    self.send_control_message(&ack, session).await?;
                    info!(
                        "Recording started for '{}' from {}",
                        service,
                        hash_addr(&client_addr)
                    );
                    self.audit_log.log(
                        AuditActor::System,
                        "RecordingStart",
                        &format!("service={} peer={}", service, hash_addr(&client_addr)),
                        "ok",
                    );
                }
            }
            ControlPayload::RecordingStop {
                session_id: rec_session_id,
            } => {
                if let Some(ref recorder) = self.recording_manager {
                    let owner_session_id = session.lock().session_id;
                    if rec_session_id != owner_session_id {
                        let failed = ControlPayload::RecordingFailed {
                            reason: "Recording session does not belong to this client".into(),
                        };
                        self.send_control_message(&failed, session).await?;
                        return Ok(());
                    }

                    let socket = self.udp_socket.as_ref().unwrap().clone();
                    let store = recorder.store();
                    let mdh = self.mask_catalog.packet_mdh_bytes();
                    let outcome = recorder.stop(owner_session_id);
                    Self::handle_recording_outcome(
                        &socket,
                        &self.session_manager,
                        &store,
                        &mdh,
                        outcome,
                        Some(session.clone()),
                    )
                    .await;
                    self.audit_log.log(
                        AuditActor::System,
                        "RecordingStop",
                        &hash_addr(&client_addr),
                        "ok",
                    );
                }
            }
            ControlPayload::RecordingStatusRequest => {
                let client_id = {
                    let sess = session.lock();
                    sess.client_id.clone()
                };
                let can_record = self.can_start_recording(client_id.as_deref());
                let active_service = self
                    .recording_manager
                    .as_ref()
                    .and_then(|recorder| recorder.status(&session.lock().session_id))
                    .map(|status| status.service);
                let response = ControlPayload::RecordingStatus {
                    can_record,
                    active_service,
                };
                self.send_control_message(&response, session).await?;
            }
            ControlPayload::RecordingAck { .. } => {
                // Client-side only, ignore on server
            }
            ControlPayload::RecordingComplete { .. } => {
                // Client-side only, ignore on server
            }
            ControlPayload::RecordingFailed { .. } => {
                // Client-side only, ignore on server
            }
            ControlPayload::RecordingStatus { .. } => {
                // Client-side only, ignore on server
            }
            ControlPayload::BootstrapDescriptorUpdate { .. } => {
                // Client-side only, ignore on server
            }
            ControlPayload::PoolSync { clients_json } => {
                self.on_pool_sync(session, client_addr, clients_json);
            }
            ControlPayload::PoolStateDigest { digest } => {
                self.on_pool_state_digest(session, client_addr, digest)
                    .await;
            }
            ControlPayload::PoolBucketDigests {
                digests,
                reply_requested,
            } => {
                self.on_pool_bucket_digests(session, client_addr, digests, reply_requested)
                    .await;
            }
            ControlPayload::RouteSync { subnets_json } => {
                self.on_route_sync(session, client_addr, &subnets_json);
            }
            ControlPayload::NodeEnrollment {
                node_id,
                node_pub,
                time_window,
                signature,
            } => {
                self.on_node_enrollment(
                    session,
                    client_addr,
                    node_id,
                    node_pub,
                    time_window,
                    signature,
                );
            }
            ControlPayload::PartitionAnnounce {
                subnet_cidr: peer_cidr,
                partition_index: peer_index,
                partition_size: peer_partition_size,
                num_partitions: peer_num_partitions,
                explicit: peer_explicit,
            } => {
                self.on_partition_announce(
                    session,
                    client_addr,
                    peer_cidr,
                    peer_index,
                    peer_partition_size,
                    peer_num_partitions,
                    peer_explicit,
                )
                .await;
            }
            ControlPayload::ChainForward { payload } => {
                self.on_chain_forward(session, client_addr, payload).await;
            }
            ControlPayload::ClientCert { cert_bytes } => {
                if let Some(ref mtls_cfg) = self.config.mtls {
                    let session_eph_pub = session.lock().eph_pub;
                    let ok = crate::mtls::SimpleCert::from_bytes(&cert_bytes)
                        .map(|c| {
                            c.client_pub_key == session_eph_pub
                                && crate::mtls::verify_cert(&c, mtls_cfg)
                        })
                        .unwrap_or(false);
                    session.lock().mtls_ok = ok;
                    if ok {
                        debug!("mtls: client {} cert accepted", hash_addr(&client_addr));
                        self.audit_log.log(
                            AuditActor::System,
                            "ClientCert",
                            &hash_addr(&client_addr),
                            "accepted",
                        );
                    } else {
                        warn!(
                            "mtls: client {} cert rejected — Data will be dropped",
                            hash_addr(&client_addr)
                        );
                        self.audit_log.log(
                            AuditActor::System,
                            "ClientCert",
                            &hash_addr(&client_addr),
                            "rejected",
                        );
                        // Notify client so it can re-provision rather than inferring failure from Data drops.
                        let _ = self
                            .send_control_message(
                                &aivpn_common::protocol::ControlPayload::CertRejected {},
                                session,
                            )
                            .await;
                    }
                }
            }
            ControlPayload::CertRejected {} => {
                // Server-to-client only; the server never receives this from clients.
                debug!(
                    "Unexpected CertRejected from client {}",
                    hash_addr(&client_addr)
                );
            }
            ControlPayload::DeviceEnrollment {
                static_pub,
                dh_proof,
            } => {
                self.on_device_enrollment(session, client_addr, static_pub, dh_proof)
                    .await?;
            }
            ControlPayload::KeepaliveAck { echo_ts } => {
                debug!(
                    "KeepaliveAck from {} echo_ts={}",
                    hash_addr(&client_addr),
                    echo_ts
                );
            }
            ControlPayload::QualityReport {
                quality,
                rtt_ms,
                loss_ppm,
                jitter_ms,
            } => {
                info!(
                    "QualityReport from {}: quality={} rtt={}ms loss={}ppm jitter={}ms",
                    hash_addr(&client_addr),
                    quality,
                    rtt_ms,
                    loss_ppm,
                    jitter_ms
                );
                // Persist quality score on the session for monitoring/metrics,
                // and fold the RTT sample into the smoothed estimate that scales
                // the rekey/ratchet grace window (A5).
                {
                    let mut s = session.lock();
                    s.client_quality = quality;
                    s.observe_client_rtt(rtt_ms as u32);
                }
                // Push adaptive hint back so client adjusts keepalive + FEC immediately.
                let level = aivpn_common::quality::AdaptiveLevel::suggest(quality);
                if let Err(e) = self
                    .send_control_message(
                        &ControlPayload::AdaptiveHint { level: level as u8 },
                        session,
                    )
                    .await
                {
                    debug!("AdaptiveHint send failed: {}", e);
                }
            }
            ControlPayload::AdaptiveHint { .. } => {
                debug!(
                    "AdaptiveHint from client {} ignored",
                    hash_addr(&client_addr)
                );
            }
            ControlPayload::MaskPreference { base_mask_id } => {
                self.on_mask_preference(session, client_addr, base_mask_id)
                    .await?;
            }
            ControlPayload::MaskFeedback {
                entries,
                country_code,
            } => {
                self.on_mask_feedback(session, client_addr, entries, country_code)
                    .await?;
            }
            ControlPayload::RegionalMaskHints { .. } => {
                debug!(
                    "Unexpected RegionalMaskHints from client {} ignored",
                    hash_addr(&client_addr)
                );
            }
            ControlPayload::MaskCatalog { .. } => {
                // Server→client only; a client should never send this. Ignore.
                debug!(
                    "Unexpected MaskCatalog from client {} ignored",
                    hash_addr(&client_addr)
                );
            }
            ControlPayload::FeedbackConfig { .. } => {
                // Server→client only; a client should never send this. Ignore.
                debug!(
                    "Unexpected FeedbackConfig from client {} ignored",
                    hash_addr(&client_addr)
                );
            }
            ControlPayload::HandshakeReject { .. } => {
                // Server→client only (3f); a client should never send this. Ignore.
                debug!(
                    "Unexpected HandshakeReject from client {} ignored",
                    hash_addr(&client_addr)
                );
            }
            ControlPayload::Capabilities { .. } => {
                // Server→client only; a client should never send this. Ignore.
                debug!(
                    "Unexpected Capabilities from client {} ignored",
                    hash_addr(&client_addr)
                );
            }
            ControlPayload::MgmtResponse { .. } => {
                // Server→client only; a client should never send this. Ignore.
                debug!(
                    "Unexpected MgmtResponse from client {} ignored",
                    hash_addr(&client_addr)
                );
            }
            ControlPayload::MgmtRequest {
                req_id,
                method,
                path,
                body,
            } => {
                self.on_mgmt_request(session, client_addr, req_id, method, path, body)
                    .await?;
            }
        }

        Ok(())
    }
}
