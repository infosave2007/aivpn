//! Packet ingress hot path: `handle_packet` (incoming UDP packet
//! decode/session-resolve/decrypt dispatch) and `process_inner_payload`
//! (post-decrypt inner-header routing). Pure move out of `gateway/mod.rs`
//! — no behavior change.

use super::*;

/// M1: validate an FEC-recovered payload and return the real packet length.
///
/// An honest XOR recovery reproduces the missing packet zero-padded up to the
/// group's max length — the encoder XORs only each packet's real bytes
/// (`FecEncoder::feed`), so every byte past the missing packet's end cancels
/// to 0. A false trigger (a reordered/foreign packet counted into the
/// accumulator until `recv == group_size - 1`) XORs ≥3 unrelated payloads
/// whose tails do NOT cancel; its version/IHL/inner-src bytes can still pass
/// the anti-spoof check below, so without this proof the garbage (XOR of
/// plaintext fragments) would be forwarded to NAT.
///
/// Returns `Some(tot_len)` — forward exactly that many bytes — or `None` to
/// drop.
pub(crate) fn fec_recovered_len(recovered: &[u8]) -> Option<usize> {
    if recovered.len() < 20 || (recovered[0] >> 4) != 4 {
        return None;
    }
    let ihl = (recovered[0] & 0x0f) as usize * 4;
    let tot_len = u16::from_be_bytes([recovered[2], recovered[3]]) as usize;
    if ihl < 20 || tot_len < ihl || tot_len > recovered.len() {
        return None;
    }
    if recovered[tot_len..].iter().any(|b| *b != 0) {
        return None;
    }
    Some(tot_len)
}

/// True when `seq` is stale relative to the most recently processed FecRepair
/// seq — i.e. not ahead of it within half a u16 cycle (wrapping-safe). The
/// client numbers all inner packets monotonically, so such a Data packet
/// belongs to an already-closed FEC group.
pub(crate) fn fec_seq_is_stale(repair_seq_hi: u16, seq: u16) -> bool {
    repair_seq_hi.wrapping_sub(seq) < 0x8000
}

impl super::Gateway {
    /// Handle incoming packet
    pub(crate) async fn handle_packet(
        &self,
        packet_data: &[u8],
        client_addr: SocketAddr,
    ) -> Result<()> {
        // Minimum packet size check
        if packet_data.len() < TAG_SIZE + 2 {
            return Err(Error::InvalidPacket("Too short"));
        }

        // Extract the legacy-offset resonance tag. For a new-layout (embedded)
        // packet this is the real protocol header rather than the tag — the
        // actual tag is resolved layout-aware by `find_existing_session` (data
        // path) or per candidate mask in the handshake path below, and `tag` is
        // reassigned to the resolved value there.
        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(&packet_data[0..TAG_SIZE]);

        // Default layout from runtime primary mask (used for handshake fallback).
        let (catalog_mdh_len, catalog_hs_mdh_len, _eph_offset, _eph_len) =
            self.mask_catalog.packet_layout();
        let catalog_tag_offset = self
            .mask_catalog
            .primary_mask()
            .map(|m| m.tag_offset)
            .unwrap_or(u16::MAX);
        let mut is_new_session = false;
        // Existing-session lookup — layout-aware across every tag offset (legacy
        // prefix at 0 plus each embedded mask offset). Returns Err on a replay /
        // out-of-window packet for a known session (dropped, not handshaked).
        let existing = self.find_existing_session(packet_data, &client_addr.ip())?;
        let (session, counter, is_ratcheted_tag) = if let Some((
            session,
            counter,
            is_ratcheted,
            _resolved_tag,
        )) = existing
        {
            // `tag` (offset-0 bytes) is not read again on the existing-session
            // path — the layout-resolved tag was already validated inside
            // `find_existing_session`. It is only reassigned on the handshake
            // path below, where the post-loop re-validation reads it.
            (session, counter, is_ratcheted)
        } else {
            // NOTE: We intentionally do NOT drop packets from the same public IP
            // on a different port. Multiple clients behind the same NAT must be
            // able to handshake independently (different PSKs → different sessions).
            // Mobile carriers (MTS, etc.) change source ports on reconnect — we must
            // not block new handshakes based on port mismatch with an existing session.
            // The handshake_locks mutex below serializes concurrent handshakes from
            // the same IP, preventing the duplicate-session race without blocking
            // legitimate reconnects from a new port.

            // Serialize concurrent handshakes from the same source IP.
            // When a client reconnects rapidly, multiple shard workers may receive
            // init packets on different source ports simultaneously and each enter
            // this branch before any session is registered in tag_map. Without
            // serialization both complete PSK-matching, create sessions for the same
            // VPN IP, and the last cleanup_old_sessions_for_vpn_ip call removes the
            // session the client already ratcheted to, causing aead::Error on all
            // subsequent data packets. try_lock_owned is non-blocking: if another
            // handshake is in progress for this IP we drop the packet silently;
            // the client retransmits naturally and hits the existing-session path.
            let _handshake_guard = {
                let lock = {
                    let entry = self
                        .handshake_locks
                        .entry(client_addr.ip())
                        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())));
                    entry.value().clone()
                };
                match lock.try_lock_owned() {
                    Ok(guard) => guard,
                    Err(_) => return Ok(()),
                }
            };

            // Guard against session pool exhaustion: the handshake path calls
            // create_session() speculatively for every (client × bootstrap_mask)
            // combination before tag validation confirms which one is correct.
            // An attacker spoofing many source IPs can fill the pool with temporary
            // sessions and block legitimate clients. Reserve 10 slots so ratchet
            // renewals for existing sessions always have capacity.
            if self.session_manager.session_count() + 10 >= MAX_SESSIONS {
                debug!("Session pool near capacity ({}/{}), dropping unauthenticated handshake from {}",
                    self.session_manager.session_count(), MAX_SESSIONS, hash_addr(&client_addr));
                return Ok(());
            }

            // No session found — try handshake
            // Rate-limit failed handshake attempts to prevent rapid session-creation loops.
            // After mask rotation or session timeout, stale clients may flood the server
            // with packets that consistently fail tag validation (issue #21, #42).
            // A peer with a live session that lands here is not an unknown host:
            // its packet missed the tag lookup because the window drifted or the
            // global rescan budget was spent this second. Blocking it would deny
            // that client its own reconnect for up to 16s while it keeps sending.
            let peer_has_session = self.session_manager.has_session_for_addr(&client_addr);
            {
                if let Some(entry) = self.handshake_cooldowns.get(&client_addr) {
                    let (fail_count, last_fail) = *entry;
                    // Exponential cooldown: 2s → 4s → 8s → 16s (max)
                    let cooldown = Duration::from_millis((2000 * (1 << fail_count.min(3))) as u64);
                    if !peer_has_session && last_fail.elapsed() < cooldown {
                        debug!("Handshake cooldown active for {}: fail_count={}, elapsed={:?}, cooldown={:?}",
                            hash_addr(&client_addr), fail_count, last_fail.elapsed(), cooldown);
                        return Err(Error::InvalidPacket("Handshake cooldown active"));
                    }
                }
            }

            // Global, source-IP-independent budget on the candidate scan below.
            // The per-IP cooldown is spoof-defeatable; this bounds the aggregate
            // rate of the (clients × masks) DH+tag scan so a spoofed-IP flood
            // can't pin CPU. Legitimate new connections are well under the cap.
            if !self.handshake_scan_allowed() {
                debug!(
                    "Handshake scan budget exhausted this second, dropping unauthenticated handshake from {}",
                    hash_addr(&client_addr)
                );
                return Err(Error::InvalidPacket("Handshake scan budget exhausted"));
            }

            // Try to establish a new session using one of the built-in bootstrap masks.
            // Runtime masks can be server-generated, but bootstrap must remain compatible
            // with clients that only know the shipped presets.
            // If client_db is configured, iterate registered clients and try
            // DH + PSK to find one whose derived tags match.
            // Falls back to no-PSK for backward compatibility.
            let builtin_bootstrap_masks = aivpn_common::mask::preset_masks::all();

            // FORK-B pool-sync redesign: before trying the normal client_db /
            // legacy handshake scans, check whether this packet is a sibling
            // aivpn server dialing us as a masked pool-client. The dialer
            // computes its DH1 side against our shared `pool_server_keypair`
            // (not our real long-term server static key) and its PSK is the
            // shared `pool_client_psk`, so this needs its own candidate scan
            // over the built-in preset masks — the same layout-aware
            // eph/tag extraction as the client_db scan below, just keyed off
            // the pool keypair/PSK instead of a per-client one.
            //
            // Skipped entirely (falls through to the existing client_db /
            // legacy paths unchanged) when either `pool_server_keypair` or
            // `pool_client_psk` is `None` — additive, byte-for-byte
            // unchanged behavior for any deployment that hasn't configured
            // pool sync.
            let masked_peer: Option<(Arc<parking_lot::Mutex<Session>>, MaskProfile)> =
                if let (Some(pool_kp), Some(pool_psk)) =
                    (&self.pool_server_keypair, &self.pool_client_psk)
                {
                    let mut found_peer = None;
                    for candidate_mask in aivpn_common::mask::preset_masks::all() {
                        let (
                            _,
                            candidate_handshake_mdh_len,
                            candidate_eph_offset,
                            candidate_eph_len,
                        ) = packet_layout_for_mask(&candidate_mask);
                        let prefix = tag_prefix_len(candidate_mask.tag_offset);
                        if packet_data.len() < prefix + candidate_handshake_mdh_len {
                            continue;
                        }
                        let eph_start = prefix + candidate_eph_offset;
                        if packet_data.len() < eph_start + candidate_eph_len {
                            continue;
                        }
                        let cand_tag =
                            match extract_tag_for_layout(packet_data, candidate_mask.tag_offset) {
                                Some(t) => t,
                                None => continue,
                            };

                        let mut eph_pub = [0u8; 32];
                        eph_pub.copy_from_slice(
                            &packet_data[eph_start..eph_start + candidate_eph_len],
                        );
                        // Obfuscated against the shared POOL keypair's public
                        // key — NOT `self.session_manager.server_public_key()` —
                        // since the dialer derived its side of DH1 against
                        // that shared static key, not our real server key.
                        crypto::obfuscate_eph_pub(&mut eph_pub, &pool_kp.public_key_bytes());

                        if !self.session_manager.handshake_tag_precheck_with_static(
                            &eph_pub,
                            Some(*pool_psk),
                            &cand_tag,
                            pool_kp,
                        ) {
                            continue;
                        }

                        match self.session_manager.create_masked_pool_peer_session(
                            client_addr,
                            eph_pub,
                            pool_kp,
                            pool_psk,
                        ) {
                            Ok(sess) => {
                                let validation = sess.lock().validate_handshake_tag(&cand_tag);
                                if validation.is_some() {
                                    tag = cand_tag;
                                    sess.lock().mask = Some(candidate_mask.clone());
                                    // BUG B1 fix: a validated masked pool-client
                                    // handshake gets a fresh random session_id
                                    // every time (see
                                    // `cleanup_masked_peer_sessions_for_ip`'s doc
                                    // comment) and none of the existing
                                    // `cleanup_old_sessions_for_ip`/`_vpn_ip`/
                                    // `_client_id` dedup paths ever fire for
                                    // masked peers (no vpn_ip/client_id). Without
                                    // this, a reconnecting dialer — or anyone who
                                    // knows the pool-client PSK — piles up a new
                                    // permanent session per handshake instead of
                                    // collapsing to one live session per source
                                    // IP.
                                    let new_session_id = sess.lock().session_id;
                                    self.session_manager.cleanup_masked_peer_sessions_for_ip(
                                        &client_addr.ip(),
                                        &new_session_id,
                                    );
                                    debug!(
                                        "Masked pool-client handshake SUCCESS from {} via mask {}",
                                        hash_addr(&client_addr),
                                        candidate_mask.mask_id
                                    );
                                    found_peer = Some((sess, candidate_mask));
                                    break;
                                }
                                let sid = sess.lock().session_id;
                                self.session_manager.rollback_failed_session(&sid);
                            }
                            Err(e) => {
                                debug!("create_masked_pool_peer_session failed: {}", e);
                                continue;
                            }
                        }
                    }
                    found_peer
                } else {
                    None
                };

            let (session, matched_client_id, bootstrap_mask) = if let Some((s, m)) = masked_peer {
                (s, None, m)
            } else if let Some(ref db) = self.client_db {
                let clients = db.list_clients();
                let mut found = None;
                // 3f: set when a PSK-PROVEN peer (tag matched) is turned away
                // for one-time-used/expired/disabled — distinguishes an
                // authenticated, explained refusal from a genuine "no client's
                // PSK matches this packet" below, so the latter's cooldown
                // bookkeeping and misleading "tag mismatch" log line don't
                // fire for a legitimate credential holder.
                let mut handshake_rejected: Option<u8> = None;
                // NOTE: disabled/expired clients are NOT pre-filtered out of
                // this scan (unlike before 3f) — their tag must still be
                // checked so a genuinely PSK-proven-but-refused peer can be
                // told WHY (HandshakeReject) instead of silently dropped
                // indistinguishably from an unauthenticated prober. This adds
                // a cheap `handshake_tag_precheck` per disabled/expired client
                // to every unmatched handshake attempt — negligible relative
                // to the existing per-candidate DH/tag cost.
                'bootstrap: for client_cfg in &clients {
                    let psk = client_cfg.psk;
                    let candidate_masks = self
                        .bootstrap_descriptors
                        .read()
                        .iter()
                        .flat_map(|descriptor| derive_bootstrap_candidates(descriptor, Some(&psk)))
                        .chain(builtin_bootstrap_masks.clone().into_iter())
                        .collect::<Vec<_>>();

                    for bootstrap_mask in candidate_masks {
                        let (
                            _,
                            candidate_handshake_mdh_len,
                            candidate_eph_offset,
                            candidate_eph_len,
                        ) = packet_layout_for_mask(&bootstrap_mask);
                        // Layout-aware handshake parse: an embedded mask has NO
                        // tag prefix, so the eph and tag live at their raw MDH
                        // offsets; a legacy mask keeps the TAG_SIZE prefix.
                        // Client and server agree per mask (both key off
                        // `mask.tag_offset`), so a wrong layout simply yields a
                        // wrong eph → wrong keys → tag mismatch → rollback.
                        let prefix = tag_prefix_len(bootstrap_mask.tag_offset);
                        if packet_data.len() < prefix + candidate_handshake_mdh_len {
                            continue;
                        }
                        let eph_start = prefix + candidate_eph_offset;
                        if packet_data.len() < eph_start + candidate_eph_len {
                            continue;
                        }
                        let cand_tag =
                            match extract_tag_for_layout(packet_data, bootstrap_mask.tag_offset) {
                                Some(t) => t,
                                None => continue,
                            };

                        let mut eph_pub = [0u8; 32];
                        eph_pub.copy_from_slice(
                            &packet_data[eph_start..eph_start + candidate_eph_len],
                        );
                        crypto::obfuscate_eph_pub(
                            &mut eph_pub,
                            &self.session_manager.server_public_key(),
                        );

                        // DoS hardening: cheaply reject non-matching (client, mask)
                        // candidates BEFORE the expensive create_session (2 DH +
                        // Ed25519 sign + full tag windows + session-table scans).
                        // Only a genuine match proceeds to session creation.
                        if !self.session_manager.handshake_tag_precheck(
                            &eph_pub,
                            Some(psk),
                            &cand_tag,
                        ) {
                            continue;
                        }

                        match self.session_manager.create_session(
                            client_addr,
                            eph_pub,
                            Some(psk),
                            Some(client_cfg.vpn_ip),
                        ) {
                            Ok(sess) => {
                                let validation = sess.lock().validate_handshake_tag(&cand_tag);
                                if validation.is_some() {
                                    // 3f: PSK is now PROVEN (the handshake tag
                                    // matched THIS client's derived tag) — an
                                    // unauthenticated prober can never reach
                                    // this branch, so telling this specific
                                    // peer WHY it is refused does not leak
                                    // anything to a scanner (unobservability
                                    // is preserved: probers still get total
                                    // silence via the generic no-match path
                                    // below).
                                    let reject_reason: Option<u8> = if !client_cfg.enabled {
                                        Some(3) // disabled
                                    } else if client_cfg
                                        .expires_at
                                        .is_some_and(|t| t <= chrono::Utc::now())
                                    {
                                        Some(2) // expired
                                    } else {
                                        None
                                    };
                                    if let Some(reason) = reject_reason {
                                        let reason_str =
                                            if reason == 3 { "disabled" } else { "expired" };
                                        warn!(
                                            "Handshake from {} matched PSK-proven client '{}' but it is {} — sending authenticated HandshakeReject",
                                            hash_addr(&client_addr),
                                            client_cfg.id,
                                            reason_str
                                        );
                                        self.audit_log.log(
                                            AuditActor::System,
                                            "handshake_rejected",
                                            &client_cfg.id,
                                            reason_str,
                                        );
                                        // Bind the session to the SPECIFIC
                                        // candidate mask that just matched
                                        // before replying — the client parses
                                        // our reply's MDH framing using the
                                        // mask IT sent the handshake with
                                        // (which may not be the server's
                                        // default/primary mask, e.g. a covert
                                        // descriptor-derived candidate).
                                        // `send_control_message` falls back to
                                        // the server's default mask when
                                        // `sess.mask` is unset, which would
                                        // mismatch and leave the client unable
                                        // to decode this reply.
                                        sess.lock().mask = Some(bootstrap_mask.clone());
                                        let _ = self
                                            .send_control_message(
                                                &ControlPayload::HandshakeReject { reason },
                                                &sess,
                                            )
                                            .await;
                                        let sid = sess.lock().session_id;
                                        self.session_manager.rollback_failed_session(&sid);
                                        handshake_rejected = Some(reason);
                                        break 'bootstrap;
                                    }
                                    // `mask_id` is `bootstrap:epoch-<N>:<base>:<slot>:<hex>`
                                    // for a covert descriptor mask, or a bare preset
                                    // name for the public-preset fallback. Surfacing
                                    // which one matched (and thus which epoch, or that
                                    // it fell through to a preset) makes epoch-skew
                                    // diagnosable from the server log alone.
                                    let matched_epoch = bootstrap_mask
                                        .mask_id
                                        .strip_prefix("bootstrap:epoch-")
                                        .and_then(|rest| rest.split(':').next());
                                    match matched_epoch {
                                        Some(ep) => debug!(
                                            "Tag validation SUCCESS for client {} via covert descriptor mask {} (epoch {}, current {})",
                                            client_cfg.id,
                                            bootstrap_mask.mask_id,
                                            ep,
                                            bootstrap_epoch(current_unix_secs())
                                        ),
                                        None => debug!(
                                            "Tag validation SUCCESS for client {} via preset-fallback mask {} (no covert descriptor matched)",
                                            client_cfg.id, bootstrap_mask.mask_id
                                        ),
                                    }
                                    tag = cand_tag;
                                    found =
                                        Some((sess, Some(client_cfg.id.clone()), bootstrap_mask));
                                    break 'bootstrap;
                                }
                                let sid = sess.lock().session_id;
                                self.session_manager.rollback_failed_session(&sid);
                            }
                            Err(e) => {
                                debug!("create_session failed: {}", e);
                                continue;
                            }
                        }
                    }
                }
                match found {
                    Some(f) => f,
                    None => {
                        if let Some(reason) = handshake_rejected {
                            // 3f: this handshake WAS from a PSK-proven client
                            // — it already got an authenticated
                            // HandshakeReject above explaining why. Skip the
                            // generic "no match" cooldown/log path below
                            // (that one is for probers with no valid PSK at
                            // all) and don't surface this as an Err — nothing
                            // about the packet itself was invalid.
                            debug!(
                                "Handshake from {} concluded: authenticated HandshakeReject (reason {}) already sent",
                                hash_addr(&client_addr),
                                reason
                            );
                            return Ok(());
                        }
                        // Track failed handshake for cooldown — but never for a
                        // peer whose session is still up (see `peer_has_session`).
                        if peer_has_session {
                            return Err(Error::InvalidPacket(
                                "Stale packet from an established peer",
                            ));
                        }
                        let fail_count = self
                            .handshake_cooldowns
                            .get(&client_addr)
                            .map(|e| e.0)
                            .unwrap_or(0);
                        self.handshake_cooldowns
                            .insert(client_addr, (fail_count + 1, Instant::now()));
                        warn!(
                            "Handshake failed for {} (attempt #{}) — tag mismatch for all {} registered clients",
                            hash_addr(&client_addr),
                            fail_count + 1,
                            clients.len()
                        );
                        return Err(Error::InvalidPacket(
                            "No registered client matches this handshake",
                        ));
                    }
                }
            } else {
                // No client DB — legacy mode without PSK
                let mut found = None;
                let candidate_masks = self
                    .bootstrap_descriptors
                    .read()
                    .iter()
                    .flat_map(|descriptor| derive_bootstrap_candidates(descriptor, None))
                    .chain(builtin_bootstrap_masks.clone().into_iter())
                    .collect::<Vec<_>>();
                for bootstrap_mask in candidate_masks {
                    let (_, candidate_handshake_mdh_len, candidate_eph_offset, candidate_eph_len) =
                        packet_layout_for_mask(&bootstrap_mask);
                    // Layout-aware handshake parse (see the client_db branch
                    // above): embedded masks drop the TAG_SIZE prefix.
                    let prefix = tag_prefix_len(bootstrap_mask.tag_offset);
                    if packet_data.len() < prefix + candidate_handshake_mdh_len {
                        continue;
                    }
                    let eph_start = prefix + candidate_eph_offset;
                    if packet_data.len() < eph_start + candidate_eph_len {
                        continue;
                    }
                    let cand_tag =
                        match extract_tag_for_layout(packet_data, bootstrap_mask.tag_offset) {
                            Some(t) => t,
                            None => continue,
                        };

                    let mut eph_pub = [0u8; 32];
                    eph_pub.copy_from_slice(&packet_data[eph_start..eph_start + candidate_eph_len]);
                    crypto::obfuscate_eph_pub(
                        &mut eph_pub,
                        &self.session_manager.server_public_key(),
                    );

                    // DoS hardening: cheap tag pre-check before create_session
                    // (see the client_db branch above).
                    if !self
                        .session_manager
                        .handshake_tag_precheck(&eph_pub, None, &cand_tag)
                    {
                        continue;
                    }

                    let sess =
                        self.session_manager
                            .create_session(client_addr, eph_pub, None, None)?;
                    let validation = sess.lock().validate_handshake_tag(&cand_tag);
                    if validation.is_some() {
                        tag = cand_tag;
                        found = Some((sess, None, bootstrap_mask));
                        break;
                    }
                    let sid = sess.lock().session_id;
                    self.session_manager.rollback_failed_session(&sid);
                }

                found.ok_or_else(|| {
                    Error::InvalidPacket("No bootstrap mask matched this handshake")
                })?
            };

            // Validate the tag against the session.
            let validation = {
                let sess = session.lock();
                sess.validate_tag(&tag)
            };
            let (counter, is_ratcheted) = match validation {
                Some(result) => result,
                None => {
                    let session_id = session.lock().session_id;
                    self.session_manager.rollback_failed_session(&session_id);
                    return Err(Error::InvalidPacket("Tag mismatch on new session"));
                }
            };

            // Tag is valid — this is a real handshake.
            // Clean up old sessions for the SAME CLIENT (by VPN IP), not
            // all sessions from this source IP — different clients behind
            // the same NAT must coexist.
            {
                let (session_id, vpn_ip) = {
                    let sess_lock = session.lock();
                    (sess_lock.session_id, sess_lock.vpn_ip)
                };
                if let Some(vpn_ip) = vpn_ip {
                    let removed = self
                        .session_manager
                        .cleanup_old_sessions_for_vpn_ip(&vpn_ip, &session_id);
                    // Re-assert the downlink mapping for the winning session.
                    // create_session inserts vpn_ip_map BEFORE tag validation, so a
                    // concurrent duplicate/reconnect handshake for the same static
                    // VPN IP could have overwritten it (and its own rollback would
                    // not restore THIS session). Without this the client uploads
                    // fine but downlink is a permanent blackhole ("no session for
                    // VPN IP"). Making the validated winner authoritative here
                    // closes that race deterministically.
                    self.session_manager.bind_vpn_ip(&vpn_ip, &session_id);
                    // Stop active recordings for removed stale sessions
                    if let Some(ref recorder) = self.recording_manager {
                        let socket = self.udp_socket.as_ref().unwrap().clone();
                        let store = recorder.store();
                        let mdh = self.mask_catalog.packet_mdh_bytes();
                        for sid in removed {
                            let outcome = recorder.stop_for_session_end(sid);
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
                }
            }

            // CRITICAL (server-sec): do NOT clear the per-IP handshake
            // cooldown here. A bare tag-valid handshake packet proves
            // nothing about the sender's ability to receive traffic at
            // `client_addr` — that address could be a spoofed victim. The
            // cooldown is now only cleared once return-routability is
            // proven (see the `is_ratcheted_tag` branch below), which also
            // gates the bootstrap-descriptor burst.

            {
                let mut sess = session.lock();
                sess.mask = Some(bootstrap_mask.clone());
                // 1a: build the per-session MDH pool for the bootstrap mask
                // now, so the first downlink packet does not pay a lazy-init
                // RNG cost inside the hot path.
                sess.rebuild_mdh_pool();
            }

            // Record handshake in client DB
            if let (Some(ref db), Some(ref cid)) = (&self.client_db, &matched_client_id) {
                db.record_handshake(cid);
                // Store client_id in session for traffic accounting
                session.lock().client_id = Some(cid.clone());
                debug!("Client '{}' authenticated via PSK", cid);
            }

            // Clean up any stale sessions for the same authenticated client
            // (handles WiFi→cellular reconnect where source IP changes but PSK is the same).
            if let Some(ref cid) = matched_client_id {
                let session_id = session.lock().session_id;
                let removed_cid = self
                    .session_manager
                    .cleanup_old_sessions_for_client_id(cid, &session_id);
                if let Some(ref recorder) = self.recording_manager {
                    let socket = self.udp_socket.as_ref().unwrap().clone();
                    let store = recorder.store();
                    let mdh = self.mask_catalog.packet_mdh_bytes();
                    for sid in removed_cid {
                        let outcome = recorder.stop_for_session_end(sid);
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
            }

            self.send_server_hello(&session, client_addr).await?;
            // CRITICAL (server-sec): the bootstrap-descriptor burst (up to 4
            // extra packets) is intentionally NOT sent here. It is deferred
            // to the `is_ratcheted_tag` branch below, once the client has
            // proven receipt of this ServerHello via return-routability.
            // See the field doc on `Session::bootstrap_descriptors_sent`.

            // NOTE: the eager initial runtime-mask auto-switch (added earlier this
            // session to un-inert the neural check) is intentionally NOT performed
            // here. Committing the session onto a runtime mask whose MDH length
            // differs from the bootstrap layout re-frames BOTH directions of the
            // wire — the server then decodes uplink and encodes downlink at the
            // runtime mdh_len while the client, which never adopted the mask, is
            // still on the bootstrap layout — desyncing the ciphertext boundary
            // (server: aead::Error on uplink; client: no MDH length authenticates)
            // and stranding the tunnel into an RX-silence reconnect loop. The
            // session stays on its bootstrap mask for the whole wire path; explicit
            // client-driven switches (MaskPreference) and polymorphic variants still
            // work because the client adopts those before the server reframes.
            // Neural evaluation against the catalog's runtime mask must be decoupled
            // from the wire-framing mask — tracked as a follow-up, not gated on this
            // data-plane fix.
            let _ = &bootstrap_mask;

            // §3.2 "every session polymorphic" server policy: when enabled,
            // derive and push a polymorphic variant for EVERY session right
            // after handshake, without waiting for the client to opt in via
            // `MaskPreference`. Base is the configured preset
            // (`polymorphic_base_mask`) if set, else the session's own
            // just-assigned bootstrap mask.
            //
            // Reuses the exact idempotency (`polymorphic_variant_already_active`)
            // and throttle (`mask_preference_throttle` /
            // `try_claim_mask_preference_slot`) guards as the client-driven
            // `MaskPreference` arm below, so:
            //   - a session that already carries this exact variant is not
            //     re-pushed (idempotent — e.g. reconnect races reusing the
            //     same prng_seed-derived variant id), and
            //   - a client-requested `MaskPreference` still wins: if the
            //     client sends one immediately after ServerHello (processed
            //     concurrently with this handshake-completion code by a
            //     different `tokio::spawn`ed task — see
            //     `process_packets_concurrent`), whichever reaches the
            //     shared per-session throttle slot first proceeds and the
            //     other is silently dropped. In practice this code runs
            //     synchronously moments after session creation, well before
            //     a client could have received ServerHello and replied, so
            //     it wins that race in the overwhelmingly common case — and
            //     a genuinely later, out-of-window client `MaskPreference`
            //     is never throttled by this (see `MASK_PREFERENCE_THROTTLE`'s
            //     doc comment), so it always applies and correctly overrides
            //     the policy-pushed variant.
            if self.config.polymorphic_all_sessions {
                let (poly_session_id, poly_prng_seed, poly_current_mask_id, poly_base) = {
                    let sess = session.lock();
                    let current = sess
                        .pending_mask
                        .as_ref()
                        .map(|(m, _)| m.mask_id.clone())
                        .or_else(|| sess.mask.as_ref().map(|m| m.mask_id.clone()));
                    let base = self
                        .config
                        .polymorphic_base_mask
                        .as_deref()
                        .and_then(aivpn_common::mask::preset_masks::by_id)
                        .or_else(|| sess.mask.clone());
                    (sess.session_id, sess.keys.prng_seed, current, base)
                };

                if let Some(base) = poly_base {
                    let variant = base.to_polymorphic(&poly_prng_seed);
                    if !polymorphic_variant_already_active(
                        poly_current_mask_id.as_deref(),
                        &variant.mask_id,
                    ) {
                        let now = Instant::now();
                        if try_claim_mask_preference_slot(
                            &self.mask_preference_throttle,
                            poly_session_id,
                            now,
                        ) {
                            match self
                                .session_manager
                                .build_mask_update_packet(&session, &variant)
                            {
                                Ok(packet) => {
                                    // FIX L: `udp_socket` is `None` until
                                    // `run()` binds it — a handshake racing
                                    // that startup window (or a future caller
                                    // that constructs a `Gateway` without ever
                                    // calling `run()`, e.g. tests) must not
                                    // panic here.
                                    if let Some(sock) = self.udp_socket.as_ref() {
                                        if let Err(e) = sock.send_to(&packet, client_addr).await {
                                            warn!(
                                                "Failed to send policy-driven polymorphic MaskUpdate to {}: {}",
                                                client_addr, e
                                            );
                                        } else {
                                            self.session_manager
                                                .update_session_mask(&poly_session_id, variant);
                                            self.metrics.record_polymorphic_variant_pushed();
                                        }
                                    } else {
                                        warn!(
                                            "Dropping policy-driven polymorphic MaskUpdate for {} — UDP socket not bound",
                                            hash_addr(&client_addr)
                                        );
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        "Failed to build policy-driven polymorphic MaskUpdate packet: {}",
                                        e
                                    );
                                }
                            }
                        } else {
                            debug!(
                                "Polymorphic-all policy push for {} raced with a concurrent MaskPreference — skipping",
                                hash_addr(&client_addr)
                            );
                        }
                    }
                }
            }

            // NOTE: PFS ratchet is deferred until AFTER decrypting the init packet,
            // which was encrypted with pre-ratchet keys.

            is_new_session = true;
            // When mTLS is required, block Data until the client sends a valid ClientCert.
            // SAFETY: process_inner_payload is skipped for is_new_session packets (see below),
            // so mtls_ok=false is guaranteed to be visible before any Data is processed.
            if self.config.mtls.as_ref().map_or(false, |c| c.required) {
                session.lock().mtls_ok = false;
            }
            debug!(
                "New session from {} (ServerHello sent)",
                hash_addr(&client_addr)
            );
            (session, counter, is_ratcheted)
        };

        // Parse packet — pad_len is inside encrypted area (CRIT-5 fix).
        // Use the session's own mask layout for decryption. This is critical
        // because the client may still be using its bootstrap mask before
        // receiving and applying a MaskUpdate from the server.
        // We try both the session mask layout AND the catalog (runtime) layout
        // to handle the transition window.
        // `session_data_prefix`/`session_hs_prefix` are the effective tag-prefix
        // lengths for a DATA-length and a HANDSHAKE-length packet respectively.
        // They MUST match what the client encoder chose for the same mask+length
        // (see `MaskProfile::uses_embedded_layout`): an embedded-tag mask whose
        // tag does not fit a given header length is encoded with the legacy
        // 8-byte prefix, so a single `tag_prefix_len(tag_offset)` (which ignored
        // the length) computed the wrong ciphertext offset and failed AEAD on
        // every uplink packet for such masks.
        let (session_mdh_len, session_hs_mdh_len, _session_tag_offset, data_prefix, hs_prefix) = {
            let sess = session.lock();
            if sess.is_pool_peer || sess.is_site_peer {
                // Cluster (pool/site/chain) traffic uses a FIXED, mask-
                // independent framing: [8-byte tag prefix][CLUSTER_MDH_LEN
                // random bytes][ciphertext]. It must NOT follow the catalog's
                // primary mask: that mask differs across nodes and over time,
                // and an embedded-tag primary (tag_offset != u16::MAX) would
                // shift the expected ciphertext offset, failing AEAD on every
                // peer packet even though the tag matched.
                (
                    crate::pool_sync::CLUSTER_MDH_LEN,
                    crate::pool_sync::CLUSTER_MDH_LEN,
                    u16::MAX,
                    TAG_SIZE,
                    TAG_SIZE,
                )
            } else if let Some(ref mask) = sess.mask {
                let (p, h, _, _) = packet_layout_for_mask(mask);
                (
                    p,
                    h,
                    mask.tag_offset,
                    mask.effective_tag_prefix_len(p),
                    mask.effective_tag_prefix_len(h),
                )
            } else {
                (
                    catalog_mdh_len,
                    catalog_hs_mdh_len,
                    catalog_tag_offset,
                    tag_prefix_len(catalog_tag_offset),
                    tag_prefix_len(catalog_tag_offset),
                )
            }
        };
        let packet_mdh_len = session_mdh_len;
        let handshake_mdh_len = session_hs_mdh_len;
        // Android retransmits the initial handshake packet with the client
        // eph_pub still embedded inside the MDH. Once a session already exists,
        // those retries validate against the existing tag window, so the
        // ciphertext still starts immediately after the full MDH.
        let is_pre_ratchet_retry = !is_new_session && !is_ratcheted_tag && {
            let sess = session.lock();
            !sess.is_ratcheted && packet_data.len() >= hs_prefix + handshake_mdh_len + 16
        };
        let mut payload_offsets: Vec<usize> = if is_new_session {
            vec![hs_prefix + handshake_mdh_len]
        } else if is_pre_ratchet_retry && handshake_mdh_len != packet_mdh_len {
            vec![data_prefix + packet_mdh_len, hs_prefix + handshake_mdh_len]
        } else {
            vec![data_prefix + packet_mdh_len]
        };
        // During mask transition (bootstrap → runtime), also try the catalog
        // (runtime) layout in case the client already applied MaskUpdate — using
        // the catalog mask's OWN prefix, which may differ from the session's.
        {
            let catalog_offset = tag_prefix_len(catalog_tag_offset) + catalog_mdh_len;
            if !payload_offsets.contains(&catalog_offset) {
                payload_offsets.push(catalog_offset);
            }
        }
        // QUIC-Initial mimic (coalesced datagram): a QUIC-masked DATA packet is
        // a genuine RFC 9001 v1 Initial (DCID carries the resonance tag) with
        // aivpn's real ciphertext appended after the Initial's Length field. The
        // tag was already extracted at DCID offset 6 by the normal layout-aware
        // lookup; here we add the trailing ciphertext offset as a decrypt
        // candidate. The parse is strict (0xC0 long header, version 1, 8-byte
        // DCID) so STUN/legacy packets never match — those paths are unchanged.
        if let Some(layout) = aivpn_common::quic_initial::parse_quic_initial(packet_data) {
            if !payload_offsets.contains(&layout.payload_offset) {
                payload_offsets.insert(0, layout.payload_offset);
            }
        }

        // Set when the packet only authenticated under the retained
        // pre-ratchet keys, i.e. it is a genuine old-epoch straggler. This is
        // the ONLY sound epoch discriminator: the counter spaces of the two
        // epochs overlap after a ratchet (see `pre_ratchet_keys_in_grace`), so
        // AEAD authentication — which cannot succeed under the wrong key — is
        // what tells them apart. Drives the replay bookkeeping below.
        let mut decrypted_with_pre_ratchet = false;
        let (payload_offset, padded_plaintext) = {
            let sess = session.lock();
            let nonce = self.compute_nonce(counter);
            // For new sessions, always use initial keys for decryption since the
            // client hasn't received ServerHello yet and is still sending with
            // initial keys. Only use ratcheted keys when the client proves it
            // has switched by sending a ratcheted tag on an existing session.
            let key = if is_new_session {
                &sess.keys.session_key
            } else if is_ratcheted_tag {
                &sess
                    .ratcheted_keys
                    .as_ref()
                    .ok_or(Error::InvalidPacket("Ratcheted keys missing"))?
                    .session_key
            } else {
                &sess.keys.session_key
            };

            let mut decrypted = None;
            let mut last_error = None;
            for payload_offset in &payload_offsets {
                let payload_offset = *payload_offset;
                if packet_data.len() <= payload_offset {
                    continue;
                }
                let encrypted_payload = &packet_data[payload_offset..];
                match decrypt_payload(key, &nonce, encrypted_payload) {
                    Ok(padded_plaintext) => {
                        decrypted = Some((payload_offset, padded_plaintext));
                        break;
                    }
                    Err(err) => last_error = Some(err),
                }
            }

            // Grace-window retry: a packet the client sent just before it
            // switched keys authenticates only under the retained old keys.
            // Trying them only AFTER the current key failed keeps current-epoch
            // traffic on the single-attempt fast path, and cannot mis-attribute
            // a current-epoch packet — forging one that authenticates under the
            // old key requires that key.
            if decrypted.is_none() {
                if let Some(old_keys) = sess.pre_ratchet_keys_in_grace() {
                    for payload_offset in &payload_offsets {
                        let payload_offset = *payload_offset;
                        if packet_data.len() <= payload_offset {
                            continue;
                        }
                        let encrypted_payload = &packet_data[payload_offset..];
                        if let Ok(padded_plaintext) =
                            decrypt_payload(&old_keys.session_key, &nonce, encrypted_payload)
                        {
                            decrypted = Some((payload_offset, padded_plaintext));
                            decrypted_with_pre_ratchet = true;
                            break;
                        }
                    }
                }
            }

            match decrypted {
                Some(result) => result,
                None => {
                    // A tag that validated pins the counter (and with it the
                    // nonce and key), so reaching here means every candidate
                    // ciphertext offset was wrong — a client/server disagreement
                    // about how this session's mask frames the packet. Name the
                    // mask and the offsets that were tried: the failure is
                    // otherwise a bare "aead::Error" repeated thousands of times,
                    // which says nothing about which side is mis-framing.
                    //
                    // `sess` still holds the session lock for this whole block;
                    // re-locking here would deadlock the worker (parking_lot is
                    // not reentrant) and wedge the packet loop for every session.
                    debug!(
                        "uplink decrypt failed for {}: mask={:?} packet_len={} counter={} \
                         ratcheted={} tried_offsets={:?}",
                        hash_addr(&client_addr),
                        sess.mask.as_ref().map(|m| m.mask_id.as_str()),
                        packet_data.len(),
                        counter,
                        is_ratcheted_tag,
                        payload_offsets,
                    );
                    return Err(
                        last_error.unwrap_or_else(|| Error::InvalidPacket("Invalid length"))
                    );
                }
            }
        };
        let encrypted_payload = &packet_data[payload_offset..];

        // Complete PFS ratchet only when the CLIENT proves it has ratcheted
        // by sending a packet with ratcheted-key tags.
        // Do NOT ratchet on is_new_session — the client hasn't received
        // ServerHello yet and will keep sending packets with initial keys.
        if is_ratcheted_tag {
            let session_id = session.lock().session_id;
            self.session_manager.complete_session_ratchet(&session_id);
            // Install session into kernel accelerator now that keys are stable.
            if let Some(ref ka) = self.kernel_accel {
                let mut sess = session.lock();
                info!(
                    "PFS ratchet complete for {} — send_counter={}, counter={}",
                    hash_addr(&client_addr),
                    sess.send_counter,
                    sess.counter
                );
                let (kernel_tag_offset, kernel_mdh_len) =
                    kernel_wire_layout(&sess, catalog_tag_offset, catalog_mdh_len as u16);
                let add = make_kernel_session_add(&sess, kernel_tag_offset, kernel_mdh_len);
                let upd = make_kernel_update_tags(&sess);
                if let Err(e) = ka.session_add(&add) {
                    warn!("kernel session_add failed: {e}");
                } else {
                    // Record the installed signature so the refresh path only
                    // re-installs once the mask or keys actually change.
                    sess.kernel_install_sig =
                        kernel_session_sig(&sess, kernel_tag_offset, kernel_mdh_len);
                }
                if let Err(e) = ka.session_update_tags(&upd) {
                    warn!("kernel session_update_tags failed: {e}");
                }
                // Arm the kernel downlink fast path with a reserved counter block.
                if let Some(dl) = make_kernel_downlink(&mut sess) {
                    if let Err(e) = ka.session_downlink(&dl) {
                        warn!("kernel session_downlink failed: {e}");
                    }
                }
            } else {
                let sess = session.lock();
                info!(
                    "PFS ratchet complete for {} — send_counter={}, counter={}",
                    hash_addr(&client_addr),
                    sess.send_counter,
                    sess.counter
                );
            }

            // CRITICAL (server-sec): this packet carrying a ratcheted-key tag
            // IS the return-routability proof — the client could only have
            // produced it by actually receiving ServerHello (server_eph_pub)
            // at its real address, not a spoofed one. Send the (possibly
            // multi-packet) bootstrap-descriptor burst now, exactly once, and
            // only now release the per-IP handshake cooldown. `session` is
            // unlocked before calling out since `send_bootstrap_descriptors`
            // locks it internally.
            let needs_descriptors = {
                let mut sess = session.lock();
                if sess.bootstrap_descriptors_sent {
                    false
                } else {
                    sess.bootstrap_descriptors_sent = true;
                    true
                }
            };
            if needs_descriptors {
                self.handshake_cooldowns.remove(&client_addr);
                if let Err(e) = self.send_bootstrap_descriptors(&session).await {
                    warn!(
                        "Failed to send deferred bootstrap descriptors to {}: {}",
                        hash_addr(&client_addr),
                        e
                    );
                }
            }
        }

        // Extract pad_len from inside decrypted data and strip padding
        if padded_plaintext.len() < 2 {
            return Err(Error::InvalidPacket("Decrypted payload too short"));
        }
        let pad_len = u16::from_le_bytes([padded_plaintext[0], padded_plaintext[1]]) as usize;
        if 2 + pad_len > padded_plaintext.len() {
            return Err(Error::InvalidPacket("Invalid padding length"));
        }
        let plaintext = &padded_plaintext[2..padded_plaintext.len() - pad_len];

        // Update session state. Avoid expensive O(window) tag-map rebuild on every packet.
        let mut client_db_flush: Option<(String, u64, u64)> = None;
        let (session_id, refresh_tags, iat_ms) = {
            let mut sess = session.lock();
            // H2: validate_tag() returns the same Some((counter, false)) shape
            // for both a normal current-epoch match AND a pre-ratchet
            // (old-key) match during the post-ratchet grace window — the
            // pre-ratchet counter belongs to the OLD epoch's counter space.
            // Folding it into mark_tag_received() would fast-forward the
            // CURRENT epoch's counter/bitmap to that old (often much larger)
            // value, corrupting the replay window so legitimate new-key
            // packets with small counters then look "out of window" and get
            // rejected — a likely root cause of "invalid tag after rekey".
            // Route pre-ratchet counters exclusively into the dedicated
            // pre-ratchet replay set (C-S-2) and never advance the main
            // counter state for them.
            //
            // The discriminator is which key AUTHENTICATED the packet, not
            // counter membership: `complete_ratchet` resets counter to 0 and
            // both tag sets then cover 0..512, so the old membership test
            // classified nearly every EARLY CURRENT-epoch packet as
            // pre-ratchet. That skipped mark_tag_received() entirely, pinning
            // `counter` at 0 and leaving the replay bitmap empty — and since
            // is_replay() only rejects counters at or below `counter`, the
            // same packet could then be replayed for the rest of the window.
            if decrypted_with_pre_ratchet {
                sess.mark_pre_ratchet_received(counter);
            } else {
                sess.mark_tag_received(counter);
            }
            // Inter-arrival time = gap since the PREVIOUS validated packet. This
            // MUST be measured before overwriting `last_seen`; the neural and
            // recording readers below would otherwise observe ~0 (the value we
            // just wrote), which collapsed recorded IAT distributions to a
            // degenerate near-zero spike.
            let now = std::time::Instant::now();
            let iat_ms = now.duration_since(sess.last_seen).as_secs_f64() * 1000.0;
            sess.last_seen = now;

            // IP migration: update stored client address when a validated packet
            // arrives from a different endpoint (e.g. WiFi → cellular switchover).
            // Safe because the packet passed full cryptographic validation.
            if !is_new_session && sess.client_addr != client_addr {
                info!(
                    "Client endpoint migrated: {} → {} (session keepalive active)",
                    hash_addr(&sess.client_addr),
                    hash_addr(&client_addr)
                );
                sess.client_addr = client_addr;
            }

            // Refresh precomputed tag window only when we've moved far enough.
            // Window size is 512; refreshing every 128 packets keeps ~4× headroom
            // over the refresh stride while reducing CPU spent in HashMap/tag_map
            // maintenance. Stride scales with the window so per-packet precompute
            // and tag_map churn stay flat versus the old 256-window/64-stride.
            let refresh_tags = counter.saturating_sub(sess.tag_window_base) >= 128;
            if refresh_tags {
                sess.update_tag_window();
            }

            // Batch client stats updates to avoid taking a global write lock per packet.
            sess.pending_bytes_in = sess
                .pending_bytes_in
                .saturating_add(packet_data.len() as u64);
            sess.bytes_since_rekey = sess
                .bytes_since_rekey
                .saturating_add(packet_data.len() as u64);
            if sess.pending_bytes_in >= 16 * 1024 || sess.pending_bytes_out >= 16 * 1024 {
                if let Some(cid) = sess.client_id.clone() {
                    client_db_flush = Some((cid, sess.pending_bytes_in, sess.pending_bytes_out));
                }
                sess.pending_bytes_in = 0;
                sess.pending_bytes_out = 0;
            }

            sess.update_fsm();
            (sess.session_id, refresh_tags, iat_ms)
        };

        // Refresh tag_map only when the precomputed window moves.
        if refresh_tags {
            self.session_manager.refresh_session_tags(&session_id);
            if let Some(ref ka) = self.kernel_accel {
                let mut sess = session.lock();
                // Re-install the kernel session so its wire offsets and keys
                // track the session's CURRENT state. The client switches from
                // the bootstrap mask to the runtime mask shortly after connect
                // (different tag_offset/mdh_len) and rotates keys on rekey; the
                // offsets/keys frozen at the initial install would otherwise
                // make every kernel decrypt fail silently. session_add is
                // idempotent (replaces the existing entry). Re-install only when
                // the relevant state changed, so a steady session pays nothing.
                let (kernel_tag_offset, kernel_mdh_len) =
                    kernel_wire_layout(&sess, catalog_tag_offset, catalog_mdh_len as u16);
                let sig = kernel_session_sig(&sess, kernel_tag_offset, kernel_mdh_len);
                let reinstall = sess.kernel_install_sig != sig;
                let add = reinstall
                    .then(|| make_kernel_session_add(&sess, kernel_tag_offset, kernel_mdh_len));
                let upd = make_kernel_update_tags(&sess);
                // Refresh the downlink reserved counter block on the same cadence
                // so its pre-computed resonance tags stay inside the client's
                // current time window and its counters stay near the client's
                // highest-seen downlink counter.
                let dl = make_kernel_downlink(&mut sess);
                drop(sess);
                if let Some(add) = add {
                    if let Err(e) = ka.session_add(&add) {
                        warn!("kernel session_add (refresh) failed: {e}");
                    } else {
                        session.lock().kernel_install_sig = sig;
                    }
                }
                if let Err(e) = ka.session_update_tags(&upd) {
                    warn!("kernel session_update_tags (refresh) failed: {e}");
                }
                if let Some(dl) = dl {
                    if let Err(e) = ka.session_downlink(&dl) {
                        warn!("kernel session_downlink (refresh) failed: {e}");
                    }
                }
            }
        }

        // Keep the kernel-downlink reservation's pre-computed resonance tags
        // fresh against wall-clock time. The signature/`refresh_tags` cadence
        // above only fires on mask/key changes or every 128 uplink packets — but
        // during a pure download the uplink is nearly idle (a few TCP ACKs /
        // keepalives), so it can go a long time without moving. Meanwhile the
        // client only accepts a downlink tag whose time window is within ±1 of
        // its own (≈±10 s), so a reservation armed one or more windows ago has
        // every packet rejected as "Invalid resonance tag" and downlink stalls.
        // Re-arm the instant the wall-clock window advances past the one the
        // reservation was built for. Keepalives (~8 s) run through this path, so
        // the kernel's tags are never more than one window stale. Cheap: a
        // window compare per packet, real work only on a window boundary.
        if let Some(ref ka) = self.kernel_accel {
            let now_window = crypto::compute_time_window(
                crypto::current_timestamp_ms(),
                aivpn_common::crypto::DEFAULT_WINDOW_MS,
            );
            let mut sess = session.lock();
            if sess.kernel_dl_window != 0 && sess.kernel_dl_window != now_window {
                let dl = make_kernel_downlink(&mut sess);
                drop(sess);
                if let Some(dl) = dl {
                    if let Err(e) = ka.session_downlink(&dl) {
                        warn!("kernel session_downlink (window re-arm) failed: {e}");
                    }
                }
            }
        }

        // Record traffic stats for neural resonance (Patent 1)
        if self.config.enable_neural {
            let packet_size = packet_data.len() as u16;
            // Compute byte-level entropy of the encrypted payload
            let entropy = Self::compute_entropy(encrypted_payload);
            // Real inter-arrival gap, measured above before last_seen was updated.
            // Neural model update is expensive under lock. Sampling every 16th packet
            // preserves trends while reducing lock contention in the receive hot path.
            if counter & 0x0f == 0 {
                self.neural_module
                    .lock()
                    // is_rx=true: packet from client → server (uplink direction)
                    .record_traffic(session_id, packet_size, iat_ms, entropy, true);
                // R2 Phase D — feed the same sampled packet's WIRE bytes to the
                // inline ML-DPI gate. `packet_data` is the full UDP datagram a DPI
                // box observes (mask header/tag bytes + ciphertext); the gate's
                // features (STUN/QUIC header form, size, entropy) are computed
                // from exactly these bytes. Lock-free (DashMap), one entropy pass.
                #[cfg(feature = "neural")]
                self.dpi_gate.record_wire(session_id, packet_data);
            }
            self.metrics.record_packet_received(packet_data.len());
        }

        // Record uplink packet metadata for auto mask recording
        if let Some(ref recorder) = self.recording_manager {
            let session_id = session.lock().session_id;
            if recorder.is_recording(&session_id) {
                // Real inter-arrival gap, measured above before last_seen was updated.
                let meta = aivpn_common::recording::PacketMetadata {
                    direction: aivpn_common::recording::Direction::Uplink,
                    size: packet_data.len() as u16,
                    iat_ms,
                    entropy: Self::compute_entropy(encrypted_payload) as f32,
                    // Learn the app header from the DECRYPTED inner packet, not the
                    // encrypted wire packet (`packet_data`, which is near-random
                    // ciphertext). `plaintext` is [InnerHeader(4)][inner IP packet];
                    // skip the 4-byte inner header to reach the IP packet, then
                    // inner_l7_prefix pulls the cleartext L7 app header. Non-Data /
                    // non-IP packets yield an empty prefix (ignored by the fitter).
                    header_prefix: inner_l7_prefix(plaintext.get(4..).unwrap_or(&[])),
                    timestamp_ns: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64,
                };
                recorder.record_packet(session_id, meta);
            }
        }

        // Record traffic in client DB in batches (see pending_bytes_in/out above).
        if let (Some(ref db), Some((cid, bytes_in, bytes_out))) = (&self.client_db, client_db_flush)
        {
            db.record_traffic(&cid, bytes_in, bytes_out);
        }

        // Process inner payload (skip for new sessions — ServerHello is already the response,
        // and any ControlAck sent here would use pre-ratchet keys that the client can't validate)
        if !is_new_session {
            self.process_inner_payload(plaintext, &session, client_addr)
                .await?;
        }

        Ok(())
    }

    /// Process decrypted inner payload
    async fn process_inner_payload(
        &self,
        plaintext: &[u8],
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: SocketAddr,
    ) -> Result<()> {
        if plaintext.len() < 4 {
            return Err(Error::InvalidPacket("Inner payload too short"));
        }

        let inner_header = InnerHeader::decode(plaintext)?;
        let payload = &plaintext[4..];

        match inner_header.inner_type {
            InnerType::Data => {
                // mTLS gate: drop Data packets until cert is verified (when required).
                if !session.lock().mtls_ok {
                    warn!(
                        "mtls: Data from {} rejected — certificate not yet verified",
                        hash_addr(&client_addr)
                    );
                    return Ok(());
                }

                // FEC late-packet suppression: once a FecRepair was processed,
                // any Data packet whose inner seq is not ahead of that repair
                // belongs to an already-closed group — either the late original
                // of a just-FEC-recovered packet (a duplicate) or a straggler
                // that would corrupt the new group's XOR accumulator (a false
                // `recv == group_size - 1` trigger recovers garbage into NAT).
                // Client inner seqs are monotone; the wrapping subtraction
                // treats seq as stale iff it lies within half a u16 cycle
                // behind the repair.
                {
                    let sess = session.lock();
                    if let Some(hi) = sess.fec_repair_seq_hi {
                        if fec_seq_is_stale(hi, inner_header.seq_num) {
                            debug!(
                                "FEC: dropping late Data seq={} from {} \
                                 (repair seq={} already processed)",
                                inner_header.seq_num,
                                hash_addr(&client_addr),
                                hi
                            );
                            return Ok(());
                        }
                    }
                }

                // Anti-spoof + peer routing gate (authoritative, at ingress).
                // Only IPv4 is routed through the VPN; reject everything else to
                // prevent clients from injecting arbitrary layer-3 traffic that
                // bypasses the source-address check.
                if payload.len() < 20 || (payload[0] >> 4) != 4 {
                    debug!(
                        "Anti-spoof: dropping non-IPv4 payload (len={} ver={})",
                        payload.len(),
                        payload.first().map(|b| b >> 4).unwrap_or(0)
                    );
                    return Ok(());
                }
                {
                    let inner_src =
                        std::net::Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
                    let inner_dst =
                        std::net::Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
                    let session_vpn_ip = session.lock().vpn_ip;
                    if let Some(svpn) = session_vpn_ip {
                        if inner_src != svpn {
                            warn!(
                                "Anti-spoof: dropping packet src={} from session owning vpn_ip={}",
                                inner_src, svpn
                            );
                            return Ok(());
                        }
                    }
                    // Block intra-VPN routing at ingress when not opted in.
                    if !self.config.allow_peer_routing
                        && self
                            .session_manager
                            .get_session_by_vpn_ip(&inner_dst)
                            .is_some()
                    {
                        debug!(
                            "Peer routing disabled — dropping {}->{} at ingress",
                            inner_src, inner_dst
                        );
                        return Ok(());
                    }
                }

                // Forward to NAT/internet via TUN write channel (lock-free)
                debug!(
                    "DATA packet from {} ({} bytes)",
                    hash_addr(&client_addr),
                    payload.len()
                );

                // QoS: enforce upstream rate limit before forwarding to TUN
                let upstream_cid = session.lock().client_id.clone();
                if let Some(ref c) = upstream_cid {
                    if !self.qos_enforcer.check_upstream(c, payload.len() as u64) {
                        debug!("QoS: upstream rate limited, dropping packet for {}", c);
                        return Ok(());
                    }
                }

                // Site peers send subnet traffic — never relay to the exit node
                // (masked or legacy chain_forwarder), regardless of any exit
                // configuration; always local TUN/NAT egress. Unchanged by B2b.
                //
                // B2b: for non-site-peer traffic, `exit_decision_for_session`
                // resolves this CLIENT's own `exit_node` override (B2a,
                // cached in `exit_route_cache`), falling back to the node's
                // global default (`self.masked_exit_addr`, sourced from
                // `pool.exit_node`) exactly as before when no per-client
                // override is set — see `choose_exit`'s doc comment for the
                // REGRESSION INVARIANT this preserves.
                let is_site_peer_now = session.lock().is_site_peer;
                if !is_site_peer_now {
                    match self.exit_decision_for_session(session) {
                        ExitDecision::Send {
                            addr,
                            local_fallback,
                        } => {
                            self.forward_via_exit(&addr, local_fallback, payload.to_vec())
                                .await?;
                        }
                        ExitDecision::NoExit => {
                            // No exit configured at all (neither per-client
                            // nor global) — legacy chain_forwarder/local TUN
                            // egress, byte-identical to the pre-B2b
                            // `masked_exit_addr.is_none()` branch.
                            if let Some(ref cf) = self.chain_forwarder {
                                // Multi-hop: relay to exit node instead of local NAT
                                cf.forward(payload.to_vec()).await;
                            } else if let Some(ref tx) = self.tun_write_tx {
                                if tx.send(payload.to_vec()).await.is_err() {
                                    debug!("TUN write channel closed, dropping packet");
                                }
                            } else if let Some(ref nat) = self.nat_forwarder {
                                nat.forward_packet(payload).await?;
                            } else {
                                debug!("NAT disabled, dropping packet");
                            }
                        }
                    }
                } else if let Some(ref tx) = self.tun_write_tx {
                    if tx.send(payload.to_vec()).await.is_err() {
                        debug!("TUN write channel closed, dropping packet");
                    }
                } else if let Some(ref nat) = self.nat_forwarder {
                    nat.forward_packet(payload).await?;
                } else {
                    debug!("NAT disabled, dropping packet");
                }

                // Accumulate payload into FEC XOR buffer for server-side recovery.
                // When FecRepair arrives we can reconstruct exactly one missing packet.
                {
                    let mut sess = session.lock();
                    let len = payload.len().min(1500);
                    if sess.fec_xor_buf.len() < len {
                        sess.fec_xor_buf.resize(len, 0);
                    }
                    for (a, b) in sess.fec_xor_buf[..len].iter_mut().zip(&payload[..len]) {
                        *a ^= b;
                    }
                    if len > sess.fec_xor_len {
                        sess.fec_xor_len = len;
                    }
                    sess.fec_recv_count = sess.fec_recv_count.saturating_add(1);
                }
            }
            InnerType::Control => {
                self.handle_control_message(payload, session, client_addr)
                    .await?;
            }
            InnerType::Fragment => {
                // TODO: Implement fragmentation
                debug!("FRAGMENT packet (not implemented)");
            }
            InnerType::Ack => {
                // Handle ACK
                debug!("ACK packet received");
            }
            InnerType::FecRepair => {
                if let Some(repair) = FecRepair::decode(payload) {
                    if repair.group_size > 0 {
                        let recovered_opt = {
                            let mut sess = session.lock();
                            let recv = sess.fec_recv_count;
                            let seq_ok = repair.group_seq == sess.fec_pending_seq;
                            // Recover only when group_seq matches (XOR buffer is for this
                            // exact group) and exactly one packet is missing.
                            let result = if seq_ok && recv == repair.group_size.saturating_sub(1) {
                                let xor_len = sess.fec_xor_len.max(repair.xor_data.len());
                                let mut out = vec![0u8; xor_len];
                                for i in 0..xor_len {
                                    out[i] = repair.xor_data.get(i).copied().unwrap_or(0)
                                        ^ sess.fec_xor_buf.get(i).copied().unwrap_or(0);
                                }
                                debug!(
                                    "FEC: recovered {} bytes from {} (group seq={} size={})",
                                    out.len(),
                                    hash_addr(&client_addr),
                                    repair.group_seq,
                                    repair.group_size
                                );
                                Some(out)
                            } else {
                                debug!(
                                    "FEC: group seq={} size={} recv={} seq_ok={} — no recovery",
                                    repair.group_seq, repair.group_size, recv, seq_ok
                                );
                                None
                            };
                            // Reset accumulator; advance expected seq to the next group.
                            sess.fec_recv_count = 0;
                            sess.fec_xor_buf.iter_mut().for_each(|b| *b = 0);
                            sess.fec_xor_len = 0;
                            sess.fec_pending_seq = repair.group_seq.wrapping_add(1);
                            // Close all earlier groups: Data packets with inner
                            // seq <= this repair's seq are late duplicates and
                            // are dropped at ingress (see the Data branch).
                            sess.fec_repair_seq_hi = Some(inner_header.seq_num);
                            result
                        };

                        if let Some(mut recovered) = recovered_opt {
                            // Validate recovered packet with the same anti-spoof and
                            // peer-routing checks applied to normal Data packets.
                            // M1: `fec_recovered_len` additionally proves the XOR
                            // really reconstructs one missing packet (all-zero
                            // tail past the IPv4 total length) and trims the
                            // padding; reordered-group garbage fails it here.
                            let valid_len = fec_recovered_len(&recovered);
                            if let Some(tot_len) = valid_len {
                                recovered.truncate(tot_len);
                            }
                            if valid_len.is_none() {
                                debug!(
                                    "FEC anti-spoof: dropping malformed recovered packet \
                                     (len={} ver={})",
                                    recovered.len(),
                                    recovered.first().map(|b| b >> 4).unwrap_or(0)
                                );
                            } else {
                                let inner_src = std::net::Ipv4Addr::new(
                                    recovered[12],
                                    recovered[13],
                                    recovered[14],
                                    recovered[15],
                                );
                                let inner_dst = std::net::Ipv4Addr::new(
                                    recovered[16],
                                    recovered[17],
                                    recovered[18],
                                    recovered[19],
                                );
                                let (session_vpn_ip, is_site_peer) = {
                                    let sess = session.lock();
                                    (sess.vpn_ip, sess.is_site_peer)
                                };
                                let spoof = session_vpn_ip
                                    .map(|svpn| inner_src != svpn)
                                    .unwrap_or(false);
                                if spoof {
                                    warn!(
                                        "FEC anti-spoof: dropping recovered packet \
                                         src={} from session owning vpn_ip={:?}",
                                        inner_src, session_vpn_ip
                                    );
                                } else if !self.config.allow_peer_routing
                                    && self
                                        .session_manager
                                        .get_session_by_vpn_ip(&inner_dst)
                                        .is_some()
                                {
                                    debug!(
                                        "FEC: peer routing disabled — dropping \
                                         {}->{} at ingress",
                                        inner_src, inner_dst
                                    );
                                } else if !is_site_peer {
                                    // B2b: same per-client-exit-then-global
                                    // resolution as the primary Data-packet
                                    // site above — see `choose_exit`'s doc
                                    // comment for the REGRESSION INVARIANT
                                    // this preserves when no per-client
                                    // override is set.
                                    match self.exit_decision_for_session(session) {
                                        ExitDecision::Send {
                                            addr,
                                            local_fallback,
                                        } => {
                                            self.forward_via_exit(&addr, local_fallback, recovered)
                                                .await?;
                                        }
                                        ExitDecision::NoExit => {
                                            if let Some(ref cf) = self.chain_forwarder {
                                                cf.forward(recovered).await;
                                            } else if let Some(ref tx) = self.tun_write_tx {
                                                let _ = tx.send(recovered).await;
                                            } else if let Some(ref nat) = self.nat_forwarder {
                                                nat.forward_packet(&recovered).await?;
                                            }
                                        }
                                    }
                                } else {
                                    // is_site_peer: subnet traffic never relays to an
                                    // exit or the legacy chain_forwarder — local egress
                                    // only, unchanged by B2b.
                                    if let Some(ref tx) = self.tun_write_tx {
                                        let _ = tx.send(recovered).await;
                                    } else if let Some(ref nat) = self.nat_forwarder {
                                        nat.forward_packet(&recovered).await?;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{fec_recovered_len, fec_seq_is_stale};

    /// Minimal IPv4 packet of `len` bytes: version/IHL 0x45, tot_len = len,
    /// fixed src/dst, payload filled with `seed`.
    fn ipv4_packet(len: usize, src: [u8; 4], seed: u8) -> Vec<u8> {
        let mut p = vec![0u8; len];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&[8, 8, 8, 8]);
        for b in &mut p[20..] {
            *b = seed;
        }
        p
    }

    /// M1 regression: an honest XOR recovery (one missing packet, shorter
    /// than a sibling) is zero-padded up to the group's max length — the
    /// validator accepts it and reports the real length to trim to.
    #[test]
    fn fec_recovered_len_accepts_honest_recovery_with_zero_tail() {
        use aivpn_common::fec::FecEncoder;
        let src = [10, 0, 0, 2];
        let pkts = vec![
            ipv4_packet(300, src, 0x11),
            ipv4_packet(120, src, 0x22), // "lost" — recovered below
            ipv4_packet(500, src, 0x33),
        ];
        let mut enc = FecEncoder::new(3, 1500);
        let mut repair = None;
        for p in &pkts {
            repair = enc.feed(p);
        }
        let repair = repair.unwrap();

        // Server-side accumulator over the two received packets (mirrors the
        // Data branch in `process_inner_payload`).
        let mut xor_buf = vec![0u8; 1500];
        let mut xor_len = 0usize;
        for p in [&pkts[0], &pkts[2]] {
            for (a, b) in xor_buf[..p.len()].iter_mut().zip(p.iter()) {
                *a ^= b;
            }
            xor_len = xor_len.max(p.len());
        }
        let out_len = xor_len.max(repair.xor_data.len());
        let mut out = vec![0u8; out_len];
        for i in 0..out_len {
            out[i] =
                repair.xor_data.get(i).copied().unwrap_or(0) ^ xor_buf.get(i).copied().unwrap_or(0);
        }

        assert_eq!(fec_recovered_len(&out), Some(pkts[1].len()));
        out.truncate(pkts[1].len());
        assert_eq!(out, pkts[1]);
    }

    /// M1 regression: the reordered-group false trigger XORs ≥3 unrelated
    /// packets. Version/IHL/inner-src still look right (XOR of an odd count
    /// of identical header bytes), so only the length-consistency proof
    /// drops it.
    #[test]
    fn fec_recovered_len_rejects_reordered_group_garbage() {
        let src = [10, 0, 0, 2];
        let b = ipv4_packet(200, src, 0xBB); // lost member of group N
        let c = ipv4_packet(300, src, 0xCC); // lost member of group N
        let x = ipv4_packet(400, src, 0xDD); // first packet of group N+1
        let mut garbage = vec![0u8; 400];
        for i in 0..garbage.len() {
            garbage[i] = b.get(i).copied().unwrap_or(0)
                ^ c.get(i).copied().unwrap_or(0)
                ^ x.get(i).copied().unwrap_or(0);
        }
        // What the old anti-spoof check saw — and passed.
        assert_eq!(garbage[0] >> 4, 4);
        assert_eq!(garbage[0] & 0x0f, 5);
        assert_eq!(&garbage[12..16], &src);
        assert_eq!(fec_recovered_len(&garbage), None);
    }

    #[test]
    fn fec_recovered_len_rejects_malformed_buffers() {
        let src = [10, 0, 0, 2];
        let p = ipv4_packet(128, src, 0x77);
        // Buffer shorter than the claimed total length.
        assert_eq!(fec_recovered_len(&p[..100]), None);
        // Non-zero tail past tot_len (not an honest recovery).
        let mut padded = p.clone();
        padded.extend_from_slice(&[1, 2, 3]);
        assert_eq!(fec_recovered_len(&padded), None);
        // All-zero tail: accepted, trimmed to tot_len.
        let mut zpad = p.clone();
        zpad.extend_from_slice(&[0, 0, 0]);
        assert_eq!(fec_recovered_len(&zpad), Some(128));
        // Non-IPv4 and too-short buffers.
        let mut v6 = p.clone();
        v6[0] = 0x60;
        assert_eq!(fec_recovered_len(&v6), None);
        assert_eq!(fec_recovered_len(&p[..10]), None);
    }

    #[test]
    fn fec_seq_is_stale_wraps_safely() {
        assert!(fec_seq_is_stale(100, 99));
        // The repair's own seq can never belong to a new Data packet.
        assert!(fec_seq_is_stale(100, 100));
        assert!(!fec_seq_is_stale(100, 101));
        // u16 wrap: 65530 is 11 behind 5.
        assert!(fec_seq_is_stale(5, 65530));
        assert!(!fec_seq_is_stale(5, 6));
        // Exactly half a cycle behind is treated as new.
        assert!(!fec_seq_is_stale(0, 0x8000));
    }
}
