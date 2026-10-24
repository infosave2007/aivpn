//! Packet ingress hot path: `handle_packet` (incoming UDP packet
//! decode/session-resolve/decrypt dispatch) and `process_inner_payload`
//! (post-decrypt inner-header routing). Pure move out of `gateway/mod.rs`
//! — no behavior change.

use super::*;

fn hinted_bootstrap_mask(
    descriptors: &[BootstrapDescriptor],
    preshared_key: &[u8; 32],
    requested_id: &str,
) -> Option<MaskProfile> {
    for descriptor in descriptors {
        let Some(requested) =
            requested_id.strip_prefix(&format!("bootstrap:{}:", descriptor.descriptor_id))
        else {
            continue;
        };
        let bases: Vec<_> = if !descriptor.embedded_masks.is_empty() {
            descriptor.embedded_masks.clone()
        } else if descriptor.base_mask_ids.is_empty() {
            aivpn_common::mask::preset_masks::all()
        } else {
            descriptor
                .base_mask_ids
                .iter()
                .filter_map(|id| aivpn_common::mask::preset_masks::by_id(id))
                .collect()
        };
        for base in bases {
            let Some(tail) = requested.strip_prefix(&format!("{}:", base.mask_id)) else {
                continue;
            };
            let Some(slot) = tail
                .split_once(':')
                .and_then(|(slot, _)| slot.parse::<u8>().ok())
            else {
                continue;
            };
            if slot >= descriptor.candidate_count {
                continue;
            }
            // Старый кеш может выбирать другую базу из того же epoch и соли.
            // Восстанавливаем только известную базу; сам дескриптор не меняется.
            let mut pinned = descriptor.clone();
            pinned.base_mask_ids = vec![base.mask_id.clone()];
            if !pinned.embedded_masks.is_empty() {
                pinned.embedded_masks = vec![base];
            }
            let candidate =
                aivpn_common::mask::derive_bootstrap_candidate(&pinned, Some(preshared_key), slot)?;
            if candidate.mask_id == requested_id {
                return Some(candidate);
            }
        }
    }
    None
}

fn hinted_initial_mask(
    current: &MaskProfile,
    requested_id: &str,
    trusted: &[MaskProfile],
) -> Option<MaskProfile> {
    // Префикс bootstrap сам по себе не дает права заменить операторскую маску.
    let current_message = current.signing_message().ok()?;
    if !trusted.iter().any(|candidate| {
        candidate.mask_id == current.mask_id
            && candidate
                .signing_message()
                .is_ok_and(|message| message == current_message)
    }) {
        return None;
    }
    let requested = trusted
        .iter()
        .find(|candidate| candidate.mask_id == requested_id)?;
    (packet_layout_for_mask(current) == packet_layout_for_mask(&requested)
        && current.tag_offset == requested.tag_offset
        && (current.spoof_protocol == requested.spoof_protocol
            || (current.spoof_protocol.is_stun() && requested.spoof_protocol.is_stun())))
    .then(|| requested.clone())
}

#[cfg(test)]
mod mask_hint_tests {
    use super::*;

    #[test]
    fn bootstrap_hint_stays_within_the_known_descriptor_and_base() {
        let signing_key = derive_server_signing_key(&[7; 32]);
        let base = aivpn_common::mask::preset_masks::webrtc_zoom_v3();
        for embedded in [false, true] {
            let descriptor = super::super::bootstrap::build_bootstrap_descriptor(
                &[7; 32],
                &signing_key,
                1,
                if embedded {
                    std::slice::from_ref(&base)
                } else {
                    &[]
                },
            );
            let unchanged = descriptor.signing_bytes();
            let expected = derive_bootstrap_candidates(&descriptor, Some(&[9; 32]))[0].clone();
            let descriptors = std::slice::from_ref(&descriptor);
            let actual = hinted_bootstrap_mask(descriptors, &[9; 32], &expected.mask_id).unwrap();
            assert_eq!(
                actual.signing_message().unwrap(),
                expected.signing_message().unwrap()
            );
            for invalid in [
                expected.mask_id.replace("epoch-1:", "epoch-2:"),
                format!("{}:extra", expected.mask_id),
                format!("bootstrap:epoch-1:{}:255:0000", base.mask_id),
                "bootstrap:epoch-1:unknown:0:0000".into(),
                "bootstrap:epoch-1:webrtc_zoom_v3:0:zzzz".into(),
            ] {
                assert!(
                    hinted_bootstrap_mask(descriptors, &[9; 32], &invalid).is_none(),
                    "{invalid}"
                );
            }
            assert_eq!(descriptor.signing_bytes(), unchanged);
        }
    }

    #[test]
    fn authenticated_builtin_hint_replaces_ambiguous_generated_bootstrap() {
        let base = aivpn_common::mask::preset_masks::webrtc_sberjazz_v1();
        let desired = aivpn_common::mask::preset_masks::webrtc_zoom_v3();
        let descriptor = super::super::bootstrap::build_bootstrap_descriptor(
            &[7; 32],
            &derive_server_signing_key(&[7; 32]),
            1,
            &[base],
        );
        let current = (0..=255u8)
            .flat_map(|seed| derive_bootstrap_candidates(&descriptor, Some(&[seed; 32])))
            .find(|candidate| packet_layout_for_mask(candidate) == packet_layout_for_mask(&desired))
            .unwrap();
        let trusted = vec![current.clone(), desired.clone()];
        assert!(
            hinted_initial_mask(&current, &desired.mask_id, &trusted).is_some(),
            "Первый совпавший bootstrap не должен подменять запрошенный протокол"
        );
        let mut operator = current;
        operator.iat_distribution.params = vec![123.0];
        assert!(hinted_initial_mask(&operator, &desired.mask_id, &trusted).is_none());
    }
}

/// Проверяет формат восстановленного IP-пакета и нулевой хвост до максимума группы.
/// Принадлежность к группе проверяется отдельно по защищенным метаданным FEC.
pub(crate) fn fec_recovered_len(recovered: &[u8]) -> Option<usize> {
    aivpn_common::ip_packet::IpPacket::parse(recovered).map(|packet| packet.length)
}

impl super::Gateway {
    pub(super) fn refresh_kernel_session(&self, sess: &mut Session) {
        self.refresh_mtls_gate(sess);
        let mtls_required = sess.mtls_required;
        if sess.kernel_faulted {
            return;
        }
        let Some(ka) = self.kernel_accel.as_ref() else {
            return;
        };
        let (catalog_len, _, _, _) = self.mask_catalog.packet_layout();
        let catalog_offset = self
            .mask_catalog
            .primary_mask()
            .map(|m| m.tag_offset)
            .unwrap_or(u16::MAX);
        let (tag_offset, mdh_len) = kernel_wire_layout(sess, catalog_offset, catalog_len as u16);
        let mut input = kernel_input_from_session(
            sess,
            self.client_db.as_deref(),
            &self.config.network_config,
            self.config.allow_peer_routing,
            self.config.exit_node_enabled || self.masked_exit_addr.read().is_some(),
        );
        let recording = self
            .recording_manager
            .as_ref()
            .is_some_and(|r| r.is_recording(&sess.session_id));
        input.userspace_rx |= self.config.enable_neural || recording;
        input.userspace_tx |= recording || self.config.downlink_shaping != ShapingLevel::Off;
        // В ABI ядра нет срока сертификата, поэтому его проверяет userspace.
        input.userspace_rx |= mtls_required;
        input.userspace_tx |= mtls_required;
        // В ABI ядра нет выбора локального IP для UDP-ответа через другой интерфейс.
        input.userspace_tx |= self
            .udp_socket
            .as_ref()
            .is_some_and(|socket| socket.reply_sources().needs_source(sess.client_addr));
        let _ = kernel_maintain(ka, sess, tag_offset, mdh_len, &input, false);
    }

    /// Одинаковые QoS и маршрутизация для Data, восстановленного FEC и ChainForward.
    pub(super) async fn forward_client_data(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        payload: &[u8],
        force_local: bool,
    ) -> Result<()> {
        {
            let mut sess = session.lock();
            if !self.refresh_mtls_gate(&mut sess)
                || !session_allows_client_data(&sess, self.client_db.as_deref())
            {
                return Ok(());
            }
        }
        let (client_id, site, session_id) = {
            let session = session.lock();
            (
                session.client_id.clone(),
                session.is_site_peer,
                session.session_id,
            )
        };
        let mut packet = payload.to_vec();
        let nbytes = u32::try_from(packet.len()).unwrap_or(u32::MAX);
        // Общее списание с fallback. Если ядро уже списало ведро, userspace его не трогает.
        match kernel_qos_decide(
            self.kernel_accel.as_deref(),
            &session_id,
            QOS_DIR_UP,
            nbytes,
        ) {
            QosGate::Drop => return Ok(()),
            QosGate::PassCharged => {}
            QosGate::Userspace => {
                if let Some(ref client_id) = client_id {
                    if !self
                        .qos_enforcer
                        .check_upstream(client_id, packet.len() as u64)
                    {
                        return Ok(());
                    }
                }
            }
        }
        if let Some(ref client_id) = client_id {
            if let Some(dscp) = self.qos_enforcer.get_dscp(client_id) {
                crate::qos::apply_dscp(&mut packet, dscp);
            }
        }
        if !force_local && !site {
            if let ExitDecision::Send {
                addr,
                local_fallback,
            } = self.exit_decision_for_session(session)
            {
                return self.forward_via_exit(&addr, local_fallback, packet).await;
            }
        }
        if let Some(tx) = &self.tun_write_tx {
            let _ = tx.send(packet).await;
        } else if let Some(nat) = &self.nat_forwarder {
            nat.forward_packet(&packet).await?;
        }
        Ok(())
    }

    /// Handle incoming packet
    #[cfg(test)]
    pub(crate) async fn handle_packet(
        &self,
        packet_data: &[u8],
        client_addr: SocketAddr,
    ) -> Result<()> {
        self.handle_packet_with_source(packet_data, client_addr, None)
            .await
    }

    pub(crate) async fn handle_packet_with_source(
        &self,
        packet_data: &[u8],
        client_addr: SocketAddr,
        local: Option<crate::udp_source::LocalEndpoint>,
    ) -> Result<()> {
        if let Some(socket) = self.udp_socket.as_ref() {
            if socket.route_incoming(packet_data, client_addr) {
                return Ok(());
            }
            if let Some(bootstrap) = aivpn_common::quic_mask::QuicMask::bootstrap(packet_data) {
                let Some(_admission) = socket.begin_initial(client_addr, packet_data) else {
                    return Ok(());
                };
                let result = self
                    .handle_unmasked_packet_with_source(bootstrap, client_addr, true, local)
                    .await;
                // Даже ошибка обработки освобождает ограниченный слот admission.
                let accepted = socket.finish_initial(client_addr);
                result?;
                return accepted;
            }
        }
        self.handle_unmasked_packet_with_source(packet_data, client_addr, false, local)
            .await
    }

    pub(super) async fn handle_unmasked_packet(
        &self,
        packet_data: &[u8],
        client_addr: SocketAddr,
        quic_inner: bool,
    ) -> Result<()> {
        self.handle_unmasked_packet_with_source(packet_data, client_addr, quic_inner, None)
            .await
    }

    async fn handle_unmasked_packet_with_source(
        &self,
        packet_data: &[u8],
        client_addr: SocketAddr,
        quic_inner: bool,
        local: Option<crate::udp_source::LocalEndpoint>,
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
        let catalog_primary_mask = self.mask_catalog.primary_mask();
        let catalog_tag_offset = catalog_primary_mask
            .as_ref()
            .map(|m| m.tag_offset)
            .unwrap_or(u16::MAX);
        let mut is_new_session = false;
        // Existing-session lookup — layout-aware across every tag offset (legacy
        // prefix at 0 plus each embedded mask offset). Returns Err on a replay /
        // out-of-window packet for a known session (dropped, not handshaked).
        let existing = match self.find_existing_session(packet_data, &client_addr.ip())? {
            super::packet_demux::SessionLookup::Found(found) => Some(found),
            super::packet_demux::SessionLookup::NotFound => None,
            super::packet_demux::SessionLookup::RecoveryLimited => {
                // Реальный reconnect допускается только через отдельные бюджеты ниже.
                tracing::trace!(
                    "Session recovery limited; handshake requires independent admission"
                );
                None
            }
        };
        let (session, counter, is_ratcheted_tag) = if let Some((
            session,
            counter,
            is_ratcheted,
            _resolved_tag,
        )) = existing
        {
            tag = _resolved_tag;
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

            // Промах тега не доказывает новый handshake. Живому endpoint даем
            // короткую паузу, неизвестному отправителю сохраняем backoff.
            // Линейный поиск адреса нужен только после неудачного перебора.
            let peer_has_session = || self.session_manager.has_session_for_addr(&client_addr);
            {
                if let Some(entry) = self.handshake_cooldowns.get(&client_addr) {
                    let (fail_count, last_fail) = *entry;
                    // Ноль означает короткую паузу живого endpoint, не запрет reconnect.
                    let cooldown = if fail_count == 0 {
                        Duration::from_secs(1)
                    } else {
                        Duration::from_millis((2000 * (1 << fail_count.min(3))) as u64)
                    };
                    if last_fail.elapsed() < cooldown {
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

            let _work_lease =
                super::preauth::PreauthLease::acquire(self.handshake_work_budget.clone())
                    .ok_or(Error::InvalidPacket("Handshake CPU budget exhausted"))?;

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
            let mut masked_key_slots: Vec<(
                aivpn_common::crypto::KeyPair,
                [u8; 32],
                Option<Vec<String>>,
            )> = Vec::new();
            if let (Some(pool_kp), Some(pool_psk)) =
                (&self.pool_server_keypair, self.pool_client_psk.as_ref())
            {
                masked_key_slots.push((pool_kp.clone(), *pool_psk, None));
            }
            for (keypair, psk, node_id) in &self.extra_masked_peer_keys {
                masked_key_slots.push((keypair.clone(), *psk, Some(node_id.clone())));
            }
            let masked_peer: Option<(Arc<parking_lot::Mutex<Session>>, MaskProfile)> =
                if masked_key_slots.is_empty() {
                    None
                } else {
                    let mut found_peer = None;
                    'masked_keys: for (pool_kp, pool_psk, site_node_id) in &masked_key_slots {
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
                            let cand_tag = match extract_tag_for_layout(
                                packet_data,
                                candidate_mask.tag_offset,
                            ) {
                                Some(t) => t,
                                None => continue,
                            };

                            let mut eph_pub = [0u8; 32];
                            eph_pub.copy_from_slice(
                                &packet_data[eph_start..eph_start + candidate_eph_len],
                            );
                            // Obfuscated against the shared POOL keypair's public
                            // key - NOT `self.session_manager.server_public_key()` -
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
                                        {
                                            let mut session = sess.lock();
                                            session.is_site_peer = site_node_id.is_some();
                                            session.site_peer_names =
                                                site_node_id.clone().unwrap_or_default();
                                        }
                                        debug!(
                                        "Masked pool-client handshake SUCCESS from {} via mask {}",
                                        hash_addr(&client_addr),
                                        candidate_mask.mask_id
                                    );
                                        found_peer = Some((sess, candidate_mask));
                                        break 'masked_keys;
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
                    }
                    found_peer
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

                        match self.session_manager.create_authenticated_session(
                            client_addr,
                            eph_pub,
                            psk,
                            client_cfg.vpn_ip,
                            &client_cfg.id,
                            &cand_tag,
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
                        // Живому endpoint оставляем одну новую попытку в секунду.
                        if peer_has_session() {
                            self.handshake_cooldowns
                                .insert(client_addr, (0, Instant::now()));
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
                            .insert(client_addr, (fail_count.saturating_add(1), Instant::now()));
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
                return Err(Error::InvalidPacket("Handshake requires a client database"));
            };

            // Validate the tag against the session. This MUST use the same
            // ±2-window skew budget as the per-candidate scan above
            // (`validate_handshake_tag`, see its doc comment) — not the
            // data-plane `validate_tag` (±1) — or a client whose RTC drifted
            // ~10-25s passes the candidate scan, then fails this narrower
            // gate, rolls back, and ratchets its own handshake cooldown on
            // every retry (permanent lockout).
            let validation = {
                let sess = session.lock();
                sess.validate_handshake_tag(&tag)
            };
            let (counter, is_ratcheted) = match validation {
                Some(result) => result,
                None => {
                    let session_id = session.lock().session_id;
                    self.session_manager.rollback_failed_session(&session_id);
                    return Err(Error::InvalidPacket("Tag mismatch on new session"));
                }
            };

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

            if let Some(ref cid) = matched_client_id {
                session.lock().client_id = Some(cid.clone());
                debug!("Client '{}' authenticated via PSK", cid);
            }

            // CRITICAL (server-sec): the bootstrap-descriptor burst (up to 4
            // extra packets) is intentionally NOT sent here. It is deferred
            // to the `is_ratcheted_tag` branch below, once the client has
            // proven receipt of this ServerHello via return-routability.
            // See the field doc on `Session::bootstrap_descriptors_sent`.

            // NOTE: PFS ratchet is deferred until AFTER decrypting the init packet,
            // which was encrypted with pre-ratchet keys.

            is_new_session = true;
            // When mTLS is required, block Data until the client sends a valid ClientCert.
            // SAFETY: process_inner_payload is skipped for is_new_session packets (see below),
            // so mtls_ok=false is guaranteed to be visible before any Data is processed.
            if self.config.mtls.as_ref().map_or(false, |c| c.required) {
                self.refresh_mtls_gate(&mut session.lock());
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
            if let Some(ref mask) = sess.mask {
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
        // Клиент применяет MaskUpdate сразу. До фиксации сервер принимает обе
        // раскладки, иначе новый Keepalive не сможет завершить переход без downlink.
        // Здесь только читаем кандидата: испорченный ciphertext не меняет маску.
        if let Some((mask, _)) = session.lock().pending_mask.as_ref() {
            let mdh_len = packet_layout_for_mask(mask).0;
            let offset = mask.effective_tag_prefix_len(mdh_len) + mdh_len;
            if !payload_offsets.contains(&offset) {
                payload_offsets.push(offset);
            }
        }
        // During mask transition (bootstrap → runtime), also try the catalog
        // (runtime) layout in case the client already applied MaskUpdate — using
        // the catalog mask's OWN prefix, which may differ from the session's.
        // The prefix MUST be computed length-aware (`effective_tag_prefix_len`)
        // exactly like the session-mask prefixes above: a catalog mask whose
        // embedded tag does not fit `catalog_mdh_len` is encoded by the client
        // with the legacy TAG_SIZE prefix, so the length-blind
        // `tag_prefix_len(catalog_tag_offset)` would point at the wrong
        // ciphertext offset for such masks.
        {
            let catalog_prefix = catalog_primary_mask
                .as_ref()
                .map(|m| m.effective_tag_prefix_len(catalog_mdh_len))
                .unwrap_or_else(|| tag_prefix_len(catalog_tag_offset));
            let catalog_offset = catalog_prefix + catalog_mdh_len;
            if !payload_offsets.contains(&catalog_offset) {
                payload_offsets.push(catalog_offset);
            }
        }
        // Set when the packet only authenticated under the retained
        // pre-ratchet keys, i.e. it is a genuine old-epoch straggler. This is
        // the ONLY sound epoch discriminator: the counter spaces of the two
        // epochs overlap after a ratchet (see `pre_ratchet_keys_in_grace`), so
        // AEAD authentication — which cannot succeed under the wrong key — is
        // what tells them apart. Drives the replay bookkeeping below.
        let mut authenticated_secret = zeroize::Zeroizing::new([0u8; 32]);
        let mut initial_packet;
        let (payload_offset, padded_plaintext) = {
            let sess = session.lock();
            // For new sessions, always use initial keys for decryption since the
            // client hasn't received ServerHello yet and is still sending with
            // initial keys. Only use ratcheted keys when the client proves it
            // has switched by sending a ratcheted tag on an existing session.
            let keys = if is_new_session {
                &sess.keys
            } else if is_ratcheted_tag {
                // Ratchet-seam race: `find_existing_session` validated this tag
                // against `ratcheted_expected_tags`, but a concurrent worker may
                // have run `complete_session_ratchet` since, which TOOK
                // `ratcheted_keys` and folded them INTO `sess.keys` (see
                // `Session::complete_ratchet`). The tag is the same key either
                // way, so fall back to the (now post-ratchet) primary keys
                // instead of dropping a legitimate packet. Replay safety is
                // unaffected: post-completion the same counter→tag pairs live
                // in `expected_tags` and the packet flows through the normal
                // replay-window bookkeeping below.
                match sess.ratcheted_keys.as_ref() {
                    Some(ratcheted) => ratcheted,
                    None => &sess.keys,
                }
            } else {
                &sess.keys
            };
            authenticated_secret.copy_from_slice(&keys.tag_secret);
            initial_packet = matches!(keys.packet_cipher, crypto::PacketCipher::InitialV2 { .. });

            let mut decrypted = None;
            let mut last_error = None;
            for payload_offset in &payload_offsets {
                let payload_offset = *payload_offset;
                if packet_data.len() <= payload_offset {
                    continue;
                }
                let encrypted_payload = &packet_data[payload_offset..];
                match crypto::decrypt_session_payload(
                    keys,
                    crypto::PacketDirection::ClientToServer,
                    counter,
                    &tag,
                    encrypted_payload,
                ) {
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
                        if let Ok(padded_plaintext) = crypto::decrypt_session_payload(
                            old_keys,
                            crypto::PacketDirection::ClientToServer,
                            counter,
                            &tag,
                            encrypted_payload,
                        ) {
                            decrypted = Some((payload_offset, padded_plaintext));
                            authenticated_secret.copy_from_slice(&old_keys.tag_secret);
                            initial_packet = matches!(
                                old_keys.packet_cipher,
                                crypto::PacketCipher::InitialV2 { .. }
                            );
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
            let sess = session.lock();
            info!(
                "PFS ratchet complete for {} - send_counter={}, counter={}",
                hash_addr(&client_addr),
                sess.send_counter,
                sess.counter
            );
        }

        if quic_inner {
            if let Some(socket) = self.udp_socket.as_ref() {
                socket.prepare_authenticated_initial(client_addr)?;
            }
        }

        // Захват до pad, дескрипторов и payload. Слияние bitmap гонку не закрывает.
        let replay = {
            let mut sess = session.lock();
            let Some(previous_epoch) =
                sess.authenticated_counter_epoch(counter, &authenticated_secret)
            else {
                return Ok(());
            };
            let replay = if let Some(ka) = self.kernel_accel.as_ref() {
                self.refresh_kernel_session(&mut sess);
                kernel_claim_deliver(Some(ka.as_ref()), &sess, counter, previous_epoch)
            } else {
                kernel_claim_deliver(None, &sess, counter, previous_epoch)
            };
            if replay == ReplayGate::Drop {
                kernel_note_rejected(&mut sess, counter, previous_epoch);
            } else if previous_epoch {
                sess.mark_pre_ratchet_received(counter);
            } else {
                sess.mark_tag_received(counter);
            }
            if replay != ReplayGate::Drop && sess.commit_pending_mask() {
                // Новая раскладка и ее отпечаток попадают в ядро после AEAD и
                // захвата replay. Idle-сессии больше не нужен исходящий пакет.
                self.refresh_kernel_session(&mut sess);
            }
            replay
        };
        if replay == ReplayGate::Drop {
            return Ok(());
        }

        if let Some(socket) = self.udp_socket.as_ref() {
            if let Some(local) = local {
                if socket.reply_sources().record(client_addr, local, &session) {
                    self.refresh_kernel_session(&mut session.lock());
                }
            }
            {
                let mut sess = session.lock();
                if sess.confirm_mask_protocol(quic_inner) {
                    self.refresh_kernel_session(&mut sess);
                }
            }
            if quic_inner {
                socket.authenticate(client_addr, &session);
            } else if session
                .lock()
                .mask
                .as_ref()
                .is_some_and(aivpn_common::mask_io::uses_rtc)
            {
                let current = session.lock();
                if current.is_ratcheted {
                    socket.retire_other_rtc_session(client_addr, current.session_id);
                }
            } else if session
                .lock()
                .mask
                .as_ref()
                .is_some_and(|mask| !aivpn_common::mask_io::requires_userspace(mask))
            {
                socket.use_plain_mask(client_addr);
            }
        }

        // Дескрипторы только после захвата: повтор ratchet не рассылает их снова.
        if is_ratcheted_tag {
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
                // Политика маски меняет состояние только после подтверждения PFS.
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
                                    .build_mask_update_packets(&session, &variant)
                                {
                                    Ok(packet) => {
                                        // FIX L: `udp_socket` is `None` until
                                        // `run()` binds it — a handshake racing
                                        // that startup window (or a future caller
                                        // that constructs a `Gateway` without ever
                                        // calling `run()`, e.g. tests) must not
                                        // panic here.
                                        if let Some(sock) = self.udp_socket.as_ref() {
                                            if let Err(e) =
                                                sock.send_packets_to(&packet, client_addr).await
                                            {
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

        self.finish_client_admission(&session).await;

        // Extract pad_len from inside decrypted data and strip padding
        if padded_plaintext.len() < 2 {
            return Err(Error::InvalidPacket("Decrypted payload too short"));
        }
        let pad_len = u16::from_le_bytes([padded_plaintext[0], padded_plaintext[1]]) as usize;
        if 2 + pad_len > padded_plaintext.len() {
            return Err(Error::InvalidPacket("Invalid padding length"));
        }
        let plaintext = &padded_plaintext[2..padded_plaintext.len() - pad_len];

        // До подтверждения PFS начальный пакет не выполняет Data или control.
        // Повторный init получает тот же Hello, но с новым случайным nonce.
        if initial_packet {
            // Здесь уже проверены AEAD и replay. Подсказка меняет только
            // встроенный профиль с той же раскладкой, не допуск и не ключи.
            if let Ok(header) = InnerHeader::decode(plaintext) {
                if header.inner_type == InnerType::Control {
                    if let Ok(ControlPayload::ClientHello { mask_id }) =
                        ControlPayload::decode(&plaintext[4..])
                    {
                        let client_id = session.lock().client_id.clone();
                        let mut trusted = aivpn_common::mask::preset_masks::all();
                        if let Some(client) = client_id.as_deref().and_then(|id| {
                            self.client_db
                                .as_ref()
                                .and_then(|database| database.find_by_id(id))
                        }) {
                            let descriptors = self.bootstrap_descriptors.read();
                            trusted.extend(descriptors.iter().flat_map(|descriptor| {
                                derive_bootstrap_candidates(descriptor, Some(&client.psk))
                            }));
                            if let Some(requested) =
                                hinted_bootstrap_mask(&descriptors, &client.psk, &mask_id)
                            {
                                trusted.push(requested);
                            }
                        }
                        let mut sess = session.lock();
                        if sess.initial_hello_sends == 0 {
                            if let Some(current) = sess.mask.as_ref() {
                                if let Some(requested) =
                                    hinted_initial_mask(current, &mask_id, &trusted)
                                {
                                    sess.mask = Some(requested);
                                    sess.rebuild_mdh_pool();
                                }
                            }
                        }
                    }
                }
            }
            let pending = !session.lock().is_ratcheted;
            if pending {
                self.send_server_hello(&session, client_addr).await?;
            }
            return Ok(());
        }

        // Update session state. Avoid expensive O(window) tag-map rebuild on every packet.
        let mut client_db_flush: Option<(String, u64, u64)> = None;
        let (session_id, refresh_tags, iat_ms) = {
            let mut sess = session.lock();
            // Replay уже захвачен и отмечен до первого await под одной блокировкой.
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
                // Ключ и раскладку ставит kernel_maintain до захвата. Здесь только
                // окно тегов и downlink: session_add снял бы уже поставленную политику.
                let upd = make_kernel_update_tags(&sess);
                let dl = make_kernel_downlink(&mut sess);
                drop(sess);
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
            }
            // Для STUN здесь еще доступны внешние байты. QUIC и RTC
            // передают проверенные внешние кадры из движка маски,
            // до снятия оболочки в этом обработчике.
            #[cfg(feature = "neural")]
            if !quic_inner
                && !session
                    .lock()
                    .mask
                    .as_ref()
                    .is_some_and(aivpn_common::mask_io::uses_rtc)
            {
                if let Some(socket) = &self.udp_socket {
                    socket.observe_plain_wire(&session, packet_data);
                }
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
        self.refresh_kernel_session(&mut session.lock());

        Ok(())
    }

    async fn forward_recovered_fec(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        mut recovered: Vec<u8>,
    ) -> Result<()> {
        let Some(length) = fec_recovered_len(&recovered) else {
            return Ok(());
        };
        recovered.truncate(length);
        let header = aivpn_common::ip_packet::IpPacket::parse(&recovered)
            .expect("Проверена длина восстановленного IP-пакета");
        if !self.session_allows_source(&session.lock(), header.source)
            || (!self.config.allow_peer_routing
                && self.session_for_inner_ip(header.destination).is_some())
        {
            return Ok(());
        }
        self.forward_client_data(session, &recovered, false).await
    }

    /// Process decrypted inner payload
    pub(super) async fn process_inner_payload(
        &self,
        plaintext: &[u8],
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: SocketAddr,
    ) -> Result<()> {
        if plaintext.len() < 4 {
            return Err(Error::InvalidPacket("Inner payload too short"));
        }

        let mut inner_header = InnerHeader::decode(plaintext)?;
        let mut fec_metadata = None;
        let assembled;
        let payload = if inner_header.inner_type == InnerType::Fragment {
            if let Some(metadata) = aivpn_common::fragment::fec_metadata(&plaintext[4..]) {
                if session.lock().fec_rx.is_duplicate(metadata) {
                    return Ok(());
                }
            }
            match session
                .lock()
                .fragment_rx
                .accept_detailed(&plaintext[4..], std::time::Instant::now())?
            {
                Some(message) => {
                    inner_header.inner_type = message.kind;
                    fec_metadata = message.fec;
                    assembled = message.payload;
                    &assembled[..]
                }
                None => return Ok(()),
            }
        } else {
            &plaintext[4..]
        };

        match inner_header.inner_type {
            InnerType::Data => {
                {
                    let mut sess = session.lock();
                    if !self.refresh_mtls_gate(&mut sess)
                        || !session_allows_client_data(&sess, self.client_db.as_deref())
                    {
                        return Ok(());
                    }
                }

                let Some(header) = aivpn_common::ip_packet::IpPacket::parse(payload) else {
                    return Ok(());
                };
                let payload = &payload[..header.length];
                if !self.session_allows_source(&session.lock(), header.source) {
                    return Ok(());
                }
                if !self.config.allow_peer_routing
                    && self.session_for_inner_ip(header.destination).is_some()
                {
                    return Ok(());
                }

                let recovered = if let Some(metadata) = fec_metadata {
                    let mut sess = session.lock();
                    let result = sess.fec_rx.record(metadata, payload)?;
                    if result.complete {
                        sess.fragment_rx.discard_fec_group(metadata.group_seq);
                    }
                    if !result.accepted {
                        return Ok(());
                    }
                    result.recovered
                } else {
                    None
                };
                self.forward_client_data(session, payload, false).await?;
                if let Some(recovered) = recovered {
                    self.forward_recovered_fec(session, recovered).await?;
                }
            }
            InnerType::Control => {
                self.handle_control_message(payload, session, client_addr)
                    .await?;
            }
            InnerType::Fragment => return Err(Error::InvalidPacket("Nested fragment")),
            InnerType::Ack => {
                // Handle ACK
                debug!("ACK packet received");
            }
            InnerType::FecRepair => {
                if let Some(repair) = FecRepair::decode(payload) {
                    let recovered = {
                        let mut sess = session.lock();
                        if !self.refresh_mtls_gate(&mut sess)
                            || !session_allows_client_data(&sess, self.client_db.as_deref())
                        {
                            return Ok(());
                        }
                        let group_seq = repair.group_seq;
                        let result = sess.fec_rx.repair(repair)?;
                        if result.complete {
                            sess.fragment_rx.discard_fec_group(group_seq);
                        }
                        result.recovered
                    };
                    if let Some(recovered) = recovered {
                        self.forward_recovered_fec(session, recovered).await?;
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::fec_recovered_len;

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
    fn fec_recovered_len_rejects_nonzero_tail() {
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
}
