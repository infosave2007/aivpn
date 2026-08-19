use super::*;

impl super::AivpnClient {
    /// Handle control messages from server
    pub(super) async fn handle_server_control(&mut self, control: ControlPayload) -> Result<()> {
        match control {
            ControlPayload::MaskUpdate {
                mask_data,
                signature,
            } => {
                // The server signs the raw mask_data bytes (sign_mask() in session.rs).
                // Verify before deserialising so a bad signature is caught immediately.
                // `transport_verified` is true ONLY when a server_signing_key is
                // configured AND the ed25519 signature over THIS exact mask_data
                // payload checked out — never merely because a key is absent.
                let mut transport_verified = false;
                if let Some(signing_key) = &self.config.server_signing_key {
                    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                    match VerifyingKey::from_bytes(signing_key) {
                        Ok(vk) => {
                            let sig = Signature::from_bytes(&signature);
                            if vk.verify(&mask_data, &sig).is_err() {
                                warn!("MaskUpdate rejected: invalid ed25519 signature");
                                return Ok(());
                            }
                            transport_verified = true;
                        }
                        Err(e) => {
                            warn!("MaskUpdate rejected: bad signing key in config: {}", e);
                            return Ok(());
                        }
                    }
                }
                match rmp_serde::from_slice::<MaskProfile>(&mask_data) {
                    Ok(new_mask) => {
                        // R2 Phase B: artifact-level operator signature check,
                        // in ADDITION to the transport check above. Transport
                        // auth proves "pushed by my server"; artifact auth
                        // proves "gated + signed by the operator". Derived
                        // per-session variants are exempt: they arrive only
                        // over the AEAD-authenticated session channel and are
                        // not independently verifiable (their perturbation
                        // shifts signature-covered fields).
                        //
                        // SECURITY: that exemption must NOT be granted on the
                        // mask_id prefix alone. `is_derived_variant()` is a
                        // pure string-prefix test ("polymorphic:"/"bootstrap:")
                        // on content that lives INSIDE mask_data — i.e.
                        // attacker-supplied once transport auth is unavailable
                        // (no server_signing_key configured, or on a build
                        // that never sets one). Without also requiring
                        // transport_verified, anyone able to reach this path
                        // without a valid transport signature could
                        // manufacture a mask_id starting with those prefixes
                        // purely to skip verify_mask_artifact, bypassing the
                        // operator-signature gate entirely regardless of
                        // mask_verify_mode. Gate the exemption on BOTH: the
                        // mask claiming to be a derived variant AND the
                        // transport signature having actually proven this
                        // exact payload came from the real server.
                        if !(new_mask.is_derived_variant() && transport_verified) {
                            let verdict = aivpn_common::mask::verify_mask_artifact(
                                &new_mask,
                                self.config.mask_operator_pubkey.as_ref(),
                                self.config.mask_verify_mode,
                            );
                            if !verdict.accept {
                                warn!(
                                    "MaskUpdate '{}' REJECTED (mask_verify_mode=enforce): {:?}",
                                    new_mask.mask_id, verdict.detail
                                );
                                return Ok(());
                            }
                            if verdict.is_failure() && self.config.mask_operator_pubkey.is_some() {
                                warn!(
                                    "MaskUpdate '{}' failed operator signature verification \
                                     ({:?}) — accepted because mask_verify_mode=warn",
                                    new_mask.mask_id, verdict.detail
                                );
                            }
                        }
                        // §3 F: once a polymorphic variant lands, signal the
                        // MaskPreference retry task to stop resending.
                        if new_mask.mask_id.starts_with("polymorphic:") {
                            self.polymorphic_confirmed.store(true, Ordering::Relaxed);
                        }
                        self.update_mask(new_mask);
                    }
                    Err(e) => warn!("Failed to parse mask update: {}", e),
                }
            }
            ControlPayload::BootstrapDescriptorUpdate { descriptor_data } => {
                if descriptor_data.len() > 512 * 1024 {
                    warn!(
                        "BootstrapDescriptorUpdate rejected: payload too large ({} bytes)",
                        descriptor_data.len()
                    );
                    return Ok(());
                }
                match rmp_serde::from_slice::<BootstrapDescriptor>(&descriptor_data) {
                    Ok(descriptor) => {
                        let trusted = self.config.server_signing_key.as_ref();
                        if let Err(e) =
                            bootstrap_cache::store_verified_descriptor(descriptor, trusted)
                        {
                            warn!("Failed to store bootstrap descriptor: {}", e);
                        }
                    }
                    Err(e) => warn!("Failed to parse bootstrap descriptor update: {}", e),
                }
            }
            ControlPayload::KeyRotate { new_eph_pub } => {
                // Same class of bug as the ServerHello duplicate-processing fix:
                // a duplicated/redelivered KeyRotate request (plain UDP
                // duplication, no server-side resend needed to trigger it) used
                // to be reprocessed unconditionally — generating a fresh random
                // keypair and re-deriving new_keys from the already-once-
                // rotated current key. The server only ever commits the FIRST
                // response it receives (its own pending_rekey_keypair is
                // consumed on first commit), so this second, independently-
                // derived key is one the server never agrees to or learns
                // about — a permanent, unrecoverable desync. Skip entirely if
                // we already ratcheted for this exact server_eph_pub.
                if self.ratcheted_rekey_eph_pub == Some(new_eph_pub) {
                    // A KeyRotate for an eph_pub we ALREADY ratcheted against
                    // can only be a genuine server RETRANSMIT: a plain
                    // network-duplicated copy of the original packet carries
                    // the same transport counter and is dropped by the replay
                    // window before ever reaching this handler, while a
                    // retransmit is a fresh packet under the OLD keys (it
                    // decoded via transition_recv_keys to get here). The
                    // server retransmits because our rekey RESPONSE was lost:
                    // it is still on the old keys with the rekey pending —
                    // silently ignoring the retransmit deadlocked the tunnel
                    // (client on new keys, server on old) until the client's
                    // RX-silence watchdog forced a full reconnect. Re-send
                    // the SAME response (same client eph — never a fresh
                    // keypair, so whichever copy the server commits yields
                    // exactly the keys we already switched to), encrypted
                    // with the OLD keys the server can still read. The upload
                    // counter is shared and monotonic across both keys, so
                    // the temporary swap below cannot reuse a (key, nonce).
                    let (Some(old_keys), Some(response_eph)) =
                        (self.transition_recv_keys.clone(), self.rekey_response_eph)
                    else {
                        debug!(
                            "Duplicate KeyRotate for already-ratcheted eph_pub — \
                             no stored response/old keys, ignoring"
                        );
                        return Ok(());
                    };
                    warn!(
                        "Retransmitted KeyRotate for already-ratcheted eph_pub — \
                         our rekey response was likely lost; re-sending the same \
                         response under the previous keys"
                    );
                    let response = ControlPayload::KeyRotate {
                        new_eph_pub: response_eph,
                    };
                    // Same rendezvous dance as the initial response: swap the
                    // OLD keys into the upload state, block until the upload
                    // task confirms it encrypted THIS response with them, then
                    // restore the live upload keys (still the OLD ones while
                    // the rekey is unconfirmed — M3 staging — so the swap is a
                    // no-op then; the committed new keys once it converged).
                    let rekey_ack_rx = self.upload_state.as_ref().map(|upload_state| {
                        let (ack_tx, ack_rx) = oneshot::channel();
                        let mut state = upload_state.lock().unwrap_or_else(|e| e.into_inner());
                        state.keys = old_keys.clone();
                        state.rekey_ack.push_back(ack_tx);
                        ack_rx
                    });
                    let send_result = self.send_control(&response).await;
                    if let Some(ack_rx) = rekey_ack_rx {
                        if send_result.is_ok() {
                            // Bounded wait: if the upload task died between
                            // dequeuing the KeyRotate and firing the ack, the
                            // sender is stranded in the shared queue and would
                            // never resolve — remove it and move on instead of
                            // hanging the receive loop forever.
                            if tokio::time::timeout(REKEY_ACK_TIMEOUT, ack_rx)
                                .await
                                .is_err()
                            {
                                if let Some(upload_state) = &self.upload_state {
                                    upload_state
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .rekey_ack
                                        .pop_back();
                                }
                                warn!(
                                    "Inline rekey: no old-key re-send confirmation within {:?} — upload task presumed dead",
                                    REKEY_ACK_TIMEOUT
                                );
                            }
                        } else {
                            // Nothing was enqueued — drop the unused rendezvous
                            // so it cannot mis-fire on a future KeyRotate.
                            if let Some(upload_state) = &self.upload_state {
                                upload_state
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .rekey_ack
                                    .pop_back();
                            }
                        }
                    }
                    // Restore the upload keys displaced by the swap above.
                    // While the rekey is still unconfirmed (`pending_upload_keys`
                    // staged) TX must STAY on the old keys (M3: the data stream
                    // keeps advancing the server's inbound counter, so this
                    // re-sent response lands inside its tag band); once the
                    // server has committed, TX runs on the new keys.
                    let restore_keys = if self.pending_upload_keys.is_some() {
                        Some(old_keys.clone())
                    } else {
                        self.session_keys.clone()
                    };
                    if let (Some(upload_state), Some(keys)) = (&self.upload_state, restore_keys) {
                        upload_state.lock().unwrap_or_else(|e| e.into_inner()).keys = keys;
                    }
                    if let Err(e) = send_result {
                        warn!("Inline rekey: failed to re-send response: {}", e);
                        return Ok(());
                    }
                    // Keep accepting old-key downlink until the server commits
                    // (or retransmits again) — but never past the hard cap
                    // armed at the key switch: unbounded re-arms let a never-
                    // converging rekey defer recovery forever.
                    let next = Instant::now() + REKEY_TRANSITION_GRACE;
                    self.transition_recv_deadline = Some(
                        self.transition_grace_hard
                            .map_or(next, |hard| next.min(hard)),
                    );
                    return Ok(());
                }
                let client_rekey_kp = crypto::KeyPair::generate();
                let dh_rekey = match client_rekey_kp.compute_shared(&new_eph_pub) {
                    Ok(dh) => dh,
                    Err(e) => {
                        warn!("Inline rekey: DH failed: {}", e);
                        return Ok(());
                    }
                };
                let current_sk = match self.session_keys.as_ref() {
                    Some(k) => k.session_key,
                    None => {
                        warn!("Inline rekey: no session keys");
                        return Ok(());
                    }
                };
                let new_keys = crypto::derive_session_keys(
                    &dh_rekey,
                    Some(&current_sk),
                    &client_rekey_kp.public_key_bytes(),
                );
                // Send response with OLD keys before switching.
                //
                // send_control() only enqueues the payload onto an mpsc
                // channel to the independently-running upload task — it does
                // NOT wait for that task to actually dequeue and encrypt it.
                // Register a rendezvous first so we can block until the
                // upload task confirms it encrypted THIS response using the
                // still-current (old) keys, before we touch `session_keys` /
                // `upload_state.keys` below. Without this, there is no
                // .await between the enqueue and the key-swap, so the swap
                // would routinely win the race and the response would go out
                // encrypted with the NEW key — a key the server does not yet
                // recognize, permanently desyncing the ratchet.
                let response = ControlPayload::KeyRotate {
                    new_eph_pub: client_rekey_kp.public_key_bytes(),
                };
                let rekey_ack_rx = self.upload_state.as_ref().map(|upload_state| {
                    let (ack_tx, ack_rx) = oneshot::channel();
                    upload_state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .rekey_ack
                        .push_back(ack_tx);
                    ack_rx
                });
                if let Err(e) = self.send_control(&response).await {
                    // Nothing was enqueued — drop the just-registered
                    // rendezvous so it cannot strand in the shared queue and
                    // mis-fire on a FUTURE KeyRotate response (the upload task
                    // pops one ack per KeyRotate it encrypts, regardless of
                    // which handler installed it), starving that handler's own
                    // rendezvous. Mirrors the retransmit path's send-failure
                    // cleanup above.
                    if let Some(upload_state) = &self.upload_state {
                        upload_state
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .rekey_ack
                            .pop_back();
                    }
                    warn!("Inline rekey: failed to send response: {}", e);
                    return Ok(());
                }
                if let Some(ack_rx) = rekey_ack_rx {
                    match tokio::time::timeout(REKEY_ACK_TIMEOUT, ack_rx).await {
                        Ok(Ok(())) => {}
                        Ok(Err(_)) => {
                            warn!(
                                "Inline rekey: upload task ended before confirming old-key send, aborting rekey to avoid desync"
                            );
                            return Ok(());
                        }
                        Err(_) => {
                            // Timed out with no confirmation. Remove the
                            // stranded ack so it cannot mis-fire on a future
                            // KeyRotate — but DO NOT abort the rekey. The
                            // response is already queued and two sub-cases are
                            // indistinguishable from here:
                            //  (a) the upload task already dequeued and
                            //      encrypted it with the OLD keys (consuming
                            //      our ack) without firing it yet — the
                            //      response WILL reach the server, which will
                            //      commit exactly the keys derived below;
                            //  (b) it is still queued and goes out later,
                            //      possibly under the NEW keys — unreadable to
                            //      the server, which then retransmits
                            //      KeyRotate, and the idempotent re-send path
                            //      (guarded by `ratcheted_rekey_eph_pub` /
                            //      `rekey_response_eph`, both armed below)
                            //      re-sends the SAME response under the old
                            //      keys until the server commits.
                            // Aborting here was the key-divergence deadlock:
                            // the queued response still went out (server
                            // commits the eph1 keys) while the guard was never
                            // armed, so the retransmit was processed as a
                            // FRESH request generating eph2 — client on eph2
                            // keys, server on eph1 keys, permanently.
                            // Completing the switch makes both sides always
                            // converge on the same (eph1) key pair; if the
                            // upload task is truly dead no response is ever
                            // sent and the data watchdog reconnects as before.
                            if let Some(upload_state) = &self.upload_state {
                                upload_state
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .rekey_ack
                                    .pop_back();
                            }
                            warn!(
                                "Inline rekey: no old-key send confirmation within {:?} — \
                                 completing the key switch; a lost/unreadable response heals \
                                 via the idempotent re-send on the server's retransmit",
                                REKEY_ACK_TIMEOUT
                            );
                        }
                    }
                }
                // Keep old keys for 2 s to accept in-flight server packets.
                // The transition window is a CLONE (not a move) so the primary
                // downlink recv-window keeps its `highest` counter across the
                // rekey. The server keeps its s2c send counter monotonic, so
                // post-rekey downlink packets continue from that counter with the
                // new tag_secret and land inside the primary window's synced
                // forward span — which slides with the stream. Resetting the
                // window here (highest = -1) put it in the unsynced state whose
                // fixed [0, RECV_FUTURE_SEARCH_WINDOW) search cannot advance,
                // stranding sustained downlink after the first rekey.
                // The uplink (c2s) send counter ALSO stays monotonic across the
                // rekey (only the key changes, so no nonce reuse). Resetting it to
                // 0 mirrored the downlink bug on the server side: the server's c2s
                // expected-tag band is ±TAG_WINDOW_SIZE around the highest received
                // counter, so a from-zero restart under a heavy simultaneous upload
                // (first c2s packets lost, client racing past 511) left the server
                // unable to match any uplink tag — killing uplink, then the
                // download's inner-TCP ACKs, then downlink, then the tunnel.
                self.transition_recv_keys = self.session_keys.clone();
                // Grace must outlive the server's KeyRotate retransmit horizon
                // (lost-response self-heal), not just in-flight packets — see
                // REKEY_TRANSITION_GRACE.
                self.transition_recv_deadline = Some(Instant::now() + REKEY_TRANSITION_GRACE);
                // Absolute re-arm ceiling for THIS rekey (see
                // REKEY_TRANSITION_HARD_CAP).
                self.transition_grace_hard = Some(Instant::now() + REKEY_TRANSITION_HARD_CAP);
                self.transition_recv_window = self.recv_window.clone();
                self.session_keys = Some(new_keys);
                self.ratcheted_rekey_eph_pub = Some(new_eph_pub);
                self.rekey_response_eph = Some(client_rekey_kp.public_key_bytes());
                // M3: stage the new keys for the upload path but do NOT switch
                // TX yet. Until the server proves it committed our response
                // (first downlink packet authenticating under the new keys
                // promotes the staging — see `promote_pending_upload_keys`),
                // uplink keeps riding the OLD keys, so the server's inbound
                // counter keeps advancing with the data stream and a re-sent
                // response (lost-response self-heal) always lands inside its
                // ±TAG_WINDOW_SIZE tag band — no matter how many packets were
                // uploaded in between. The upload counter is monotonic across
                // the later key change, so no (key, nonce) pair is reused.
                if self.session_keys.is_some() {
                    self.pending_upload_keys = self.session_keys.clone();
                } else {
                    warn!("ratchet: session_keys missing, skipping upload key staging");
                }
                info!("Inline PFS rekey complete — new session keys active (upload staged)");

                // K6: re-install the in-kernel downlink session under the
                // rotated s2c key (idempotent same-id replace) and re-push the
                // tag window from the reset downlink counter. Old-key
                // in-flight packets fall back to user-space transition keys.
                #[cfg(target_os = "linux")]
                self.kernel_install_session();
            }
            ControlPayload::ServerHello {
                server_eph_pub,
                signature,
                network_config,
            } => {
                // Verify ed25519 signature over (server_eph_pub || client_eph_pub).
                // The server signs this tuple in session.rs create_session().
                if let Some(signing_key) = &self.config.server_signing_key {
                    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                    match VerifyingKey::from_bytes(signing_key) {
                        Ok(vk) => {
                            let mut msg = Vec::with_capacity(64);
                            msg.extend_from_slice(&server_eph_pub);
                            msg.extend_from_slice(&self.keypair.public_key_bytes());
                            let sig = Signature::from_bytes(&signature);
                            if vk.verify(&msg, &sig).is_err() {
                                error!(
                                    "ServerHello rejected: ed25519 signature verification failed \
                                     — possible MITM attack"
                                );
                                return Err(Error::Crypto("ServerHello signature invalid".into()));
                            }
                        }
                        Err(e) => {
                            error!("ServerHello: invalid signing key in config: {}", e);
                            return Err(Error::Crypto(format!(
                                "Invalid server signing key: {}",
                                e
                            )));
                        }
                    }
                }

                if let Some(network_config) = network_config {
                    if let Some(ka) = network_config.keepalive_secs.filter(|&s| s > 0) {
                        // NAT-safe cap (A4, Satellite exempt) + propagation to
                        // the already-running upload task via the shared atomic
                        // (previously the override never reached it).
                        self.set_keepalive_interval(Duration::from_secs(ka as u64));
                    }
                    self.apply_server_network_override(network_config).await?;
                }

                // The server resends ServerHello whenever it sees a
                // non-ratcheted Keepalive while it still believes the client
                // hasn't switched (its own reliability measure for a lost
                // original ServerHello). If we already completed the ratchet
                // for THIS server_eph_pub, this is that resend arriving after
                // our own confirmation packet was the one actually lost — not
                // a new ratchet event. Re-deriving keys here would use our
                // already-ratcheted session_key as PSK instead of the
                // original pre-ratchet key, permanently diverging from the
                // server's (single) ratchet. So: skip the crypto, just prod
                // the server again with fresh confirmation traffic.
                let is_duplicate_hello = self.ratcheted_server_eph_pub == Some(server_eph_pub);
                // Receiving ANY ServerHello is the real proof the server answered
                // — this is the §2 L2 failure-attribution signal. The optimistic
                // zero-RTT "Connected" transition in connect() happens with no
                // server contact at all (UDP connect never round-trips), so a
                // DPI-blocked mask (server silently dropped) must NOT be counted
                // as a success. Mark here, matching the iOS/Android cores which
                // set EVER_CONNECTED only after processing a ServerHello.
                self.ever_connected.store(true, Ordering::Relaxed);
                if is_duplicate_hello {
                    debug!(
                        "Duplicate ServerHello for already-ratcheted eph_pub — \
                         resending confirmation without re-ratcheting"
                    );
                } else {
                    info!("ServerHello received — completing PFS ratchet");

                    // Compute DH2 = client_eph * server_eph for PFS (CRIT-3)
                    let dh2 = self.keypair.compute_shared(&server_eph_pub)?;

                    // Derive ratcheted keys using current session_key as PSK
                    let current_key = self
                        .session_keys
                        .as_ref()
                        .ok_or(Error::Session("No session keys for ratchet".into()))?
                        .session_key;
                    let ratcheted = crypto::derive_session_keys(
                        &dh2,
                        Some(&current_key),
                        &self.keypair.public_key_bytes(),
                    );

                    // Keep accepting old inbound keys until the server proves it has
                    // switched too. Outbound traffic moves to ratcheted keys now.
                    self.transition_recv_keys = self.session_keys.clone();
                    self.transition_recv_deadline = Some(Instant::now() + Duration::from_secs(2));
                    // Not an inline rekey — no retransmit re-arm loop here, so
                    // no hard cap (and a stale one from a previous rekey must
                    // not clip this fresh window).
                    self.transition_grace_hard = None;
                    self.transition_recv_window = std::mem::take(&mut self.recv_window);

                    // Switch to ratcheted keys — outbound uses the new keys immediately.
                    self.session_keys = Some(ratcheted);
                    self.ratcheted_server_eph_pub = Some(server_eph_pub);
                    // A fresh PFS ratchet supersedes any staged inline-rekey
                    // upload keys (anomalous ordering — the server only sends
                    // KeyRotate to ratcheted sessions — but never let a stale
                    // staging clobber the ratcheted upload keys later).
                    self.pending_upload_keys = None;
                    self.counter = 0;
                    self.recv_window.reset();
                    if let Some(upload_state) = &self.upload_state {
                        let mut state = upload_state.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(ref keys) = self.session_keys {
                            state.keys = keys.clone();
                        } else {
                            warn!("ratchet: session_keys missing, skipping upload key update");
                        }
                        state.counter = 0;
                        info!("Outbound ratchet activated — upload switched to new keys");
                    }
                    info!("PFS ratchet complete — forward secrecy established");

                    // K6: keys are now stable — install (or, on a mid-session
                    // re-ratchet, atomically replace) the in-kernel downlink
                    // session with the NEW s2c key and a fresh tag window.
                    // In-flight old-key packets miss the new kernel tags and
                    // fall back to user-space, where `transition_recv_keys`
                    // still decodes them.
                    #[cfg(target_os = "linux")]
                    self.kernel_install_session();
                }

                // The following client-identity announcements (mTLS cert,
                // recording status, device enrollment) only make sense for an
                // actual end-user device. A headless control-only pool-peer
                // dialer is not a device to enroll — skip them entirely.
                if !self.config.control_only {
                    // Send mTLS ClientCert now that the PFS ratchet is complete.
                    // Sending it here ensures the cert is protected by the ratcheted
                    // session keys, not the initial zero-RTT keys.
                    if let Some(cert) = self.config.mtls_cert.clone() {
                        if let Err(e) = self
                            .send_control(&ControlPayload::ClientCert {
                                cert_bytes: cert.clone(),
                            })
                            .await
                        {
                            warn!("mTLS: failed to queue ClientCert after ratchet: {}", e);
                        } else {
                            debug!(
                                "mTLS: ClientCert queued after PFS ratchet ({} bytes)",
                                cert.len()
                            );
                        }
                    }

                    let _ = self
                        .send_control(&ControlPayload::RecordingStatusRequest)
                        .await;

                    // Device enrollment: prove static key ownership to server.
                    // Sent after ratchet so it is protected by PFS session keys.
                    // dh_proof is bound to THIS session's ephemeral transcript
                    // (server_eph_pub || client_eph_pub, matching the server's
                    // verify_device_enrollment_proof) so it cannot be replayed
                    // into a different session — see
                    // crypto::device_enrollment_proof for the scheme.
                    if let Some(ref skp) = self.static_keypair {
                        match skp.compute_shared(&self.config.server_public_key) {
                            Ok(dh_shared) => {
                                let client_eph_pub = self.keypair.public_key_bytes();
                                let dh_proof = crypto::device_enrollment_proof(
                                    &dh_shared,
                                    &server_eph_pub,
                                    &client_eph_pub,
                                );
                                let enrollment = ControlPayload::DeviceEnrollment {
                                    static_pub: skp.public_key_bytes(),
                                    dh_proof,
                                };
                                if let Err(e) = self.send_control(&enrollment).await {
                                    warn!("DeviceEnrollment send failed: {}", e);
                                }
                            }
                            Err(e) => warn!("DeviceEnrollment DH failed: {}", e),
                        }
                    }
                }

                // B2/D2 fix: session-bound NodeEnrollment for the embedded
                // control_only pool-peer dialer. `node_identity` is `Some`
                // ONLY when `aivpn-server`'s `pool_dialer.rs` constructed
                // this client to dial a fellow pool node (see
                // `ClientConfig::node_identity`'s doc comment) — for every
                // ordinary end-user client it is `None` and this whole block
                // is a no-op, matching pre-fix behavior exactly.
                //
                // The proof is built HERE (not in pool_dialer.rs, where it
                // used to be built pre-fix) because only this handler has
                // this session's ephemeral transcript
                // (server_eph_pub || client_eph_pub): `server_eph_pub` is the
                // value this exact ServerHello just carried, and
                // `client_eph_pub` is `self.keypair.public_key_bytes()` — our
                // own ephemeral public key for this session, fixed for its
                // lifetime. Binding to that pair (mirrors
                // `crypto::device_enrollment_proof`'s scheme above) is what
                // makes a captured `(node_id, node_pub, time_window,
                // signature)` tuple useless if replayed onto a DIFFERENT
                // masked pool-peer session — that session's transcript
                // differs, so `verify_node_enrollment` on the receiving end
                // no longer matches.
                if let Some(node_identity) = self.config.node_identity.clone() {
                    let client_eph_pub = self.keypair.public_key_bytes();
                    let node_pub = node_identity.verifying_key().to_bytes();
                    let node_id = self.config.pool_node_id.clone().unwrap_or_default();

                    // Send immediately — mirrors DeviceEnrollment's
                    // reliability behavior above: this fires on every
                    // ServerHello the client processes (including the
                    // server's lost-original-ServerHello resends), so a
                    // dropped first NodeEnrollment packet self-heals the
                    // next time the server retransmits.
                    let enrollment = build_node_enrollment_payload(
                        &node_identity,
                        &node_id,
                        &node_pub,
                        &server_eph_pub,
                        &client_eph_pub,
                    );
                    if let Err(e) = self.send_control(&enrollment).await {
                        warn!("NodeEnrollment send failed: {}", e);
                    }

                    // Periodic resend: once per REAL ratchet (a full
                    // reconnect spawns a brand-new AivpnClient/task, so this
                    // never accumulates duplicate timers across the client's
                    // lifetime) so a peer whose NodeRegistry restarted (or
                    // that never saw our initial enrollment) re-learns/
                    // re-verifies us without waiting for a fresh dial.
                    // Rebuilt with a fresh time_window every tick but the
                    // SAME session transcript — server_eph_pub/client_eph_pub
                    // are stable for the life of this session.
                    if !is_duplicate_hello {
                        if let Some(tx) = self.control_tx.clone() {
                            Self::spawn_node_enrollment_resend(
                                tx,
                                node_identity,
                                node_id,
                                node_pub,
                                server_eph_pub,
                                client_eph_pub,
                            );
                        } else {
                            warn!(
                                "control_tx not initialized, skipping NodeEnrollment periodic resend"
                            );
                        }
                    }
                }

                // The §2/§3 control messages below must fire ONCE per real
                // ratchet, not on every ServerHello: the server resends
                // ServerHello to recover a lost first copy (normal on lossy
                // mobile links), and re-sending MaskPreference each time makes
                // the server re-push a MaskUpdate whose `update_mask` resets the
                // mimicry FSM mid-connection — an observable disruption to the
                // very traffic fingerprint §3 protects. Gate on the first
                // ratchet only (the pre-existing ClientCert/DeviceEnrollment
                // re-sends above are intentionally left as reliability resends).
                if !is_duplicate_hello {
                    // Polymorphic mask request: ask the server to derive and push
                    // a per-session perturbed variant of the requested base mask.
                    // The server's reply arrives as a normal MaskUpdate, handled
                    // by the existing ControlPayload::MaskUpdate arm below.
                    //
                    // Reliability (§3 F): a single lost MaskPreference packet
                    // would silently disable polymorphic masks for the whole
                    // session. Spawn a bounded retry task that resends until the
                    // client observes its active mask become a `polymorphic:`
                    // variant (`polymorphic_confirmed`, set in the MaskUpdate
                    // arm) — or gives up after a few attempts. The server side is
                    // idempotent (it skips re-pushing a MaskUpdate when the
                    // session mask is already the derived variant), so a resend
                    // that races an already-applied variant does NOT reset the
                    // mimicry FSM. Runs only once per real ratchet (this block is
                    // gated on `!is_duplicate_hello`).
                    if let Some(base_mask_id) = self.config.polymorphic_base.clone() {
                        if let (Some(tx), confirmed) =
                            (self.control_tx.clone(), self.polymorphic_confirmed.clone())
                        {
                            tokio::spawn(async move {
                                // Up to 5 sends over ~5s: immediate, then 0.5s,
                                // 1s, 1.5s, 2s spacing.
                                for attempt in 0..5u8 {
                                    if confirmed.load(Ordering::Relaxed) {
                                        return;
                                    }
                                    if tx
                                        .send(ControlPayload::MaskPreference {
                                            base_mask_id: base_mask_id.clone(),
                                        })
                                        .await
                                        .is_err()
                                    {
                                        // Receiver gone — run() returned; stop.
                                        return;
                                    }
                                    tokio::time::sleep(Duration::from_millis(
                                        500 * (attempt as u64 + 1),
                                    ))
                                    .await;
                                }
                            });
                        }
                    }

                    // §2 crowdsourced blocking feedback (opt-in, OFF by default):
                    // the session is now confirmed connected (PFS ratchet done),
                    // so record a success outcome for the mask this connection is
                    // using and, if enabled, report the batched buffer to the
                    // server. See `record_mask_outcome` / `maybe_send_mask_feedback`
                    // for the privacy-preserving design notes (hour-granularity
                    // timestamps, opt-in only, no effect unless country_code is
                    // also configured).
                    // Report the base mask FAMILY, not the per-session id. A
                    // cached bootstrap id is `bootstrap:{desc}:{base}:{slot}:{seed}`
                    // whose seed is PSK-derived (a stable quasi-identifier), and a
                    // polymorphic id is `polymorphic:{base}:{hex}`. Sending either
                    // raw would leak identity AND fragment the server's k-anon
                    // buckets so they never reach the threshold. Collapse to the
                    // base preset id so feedback aggregates per protocol family.
                    //
                    // Attribute the outcome to the mask family ACTUALLY being
                    // exercised. In polymorphic mode (`--polymorphic-base`) the
                    // initial mask is deliberately the bootstrap-fallback family
                    // (so the opening burst isn't a named preset) while the mask
                    // the session really runs is the server-pushed per-session
                    // variant of `polymorphic_base`. Reporting the fallback family
                    // here would silently attribute every §3 session's success to
                    // the wrong family, defeating §2. So prefer the configured
                    // polymorphic base when set; otherwise fall back to the
                    // bootstrap/initial mask family as before.
                    //
                    // A legitimate mid-session RE-ratchet arrives with a NEW
                    // `server_eph_pub`, so `!is_duplicate_hello` is true again —
                    // guard the append with `mask_success_recorded` so success is
                    // recorded exactly once per connection, not once per ratchet.
                    if !self.mask_success_recorded {
                        let active_mask_id = self.active_feedback_family();
                        self.record_mask_outcome(active_mask_id, true);
                        self.mask_success_recorded = true;
                    }
                    self.maybe_send_mask_feedback().await;
                }

                // Warmup: 4 keepalives (100 ms apart) to force CGNAT to refresh
                // its inbound port mapping after reconnect. Fallback for carriers
                // that delay updating the entry even after local-port reuse.
                //
                // Spawned as a background task (not awaited inline) so this
                // ~400ms sequence doesn't stall the packet-receive loop right
                // during the most sensitive part of the connection — the
                // exact window where the server may also be sending the
                // initial MaskUpdate and the first data packets. Blocking
                // here previously let a backlog build up in the UDP->TUN
                // channel, which then drained in one burst as soon as this
                // handler returned.
                // Only warm up on a real (re)connect, and never on Satellite —
                // matching the proactive watchdog warmup. A lossy link makes the
                // server re-send ServerHello as its reliability mechanism, so
                // firing a 4-keepalive burst on every duplicate would amplify
                // traffic on exactly the worst links (and needlessly on the
                // deliberately-slow Satellite profile).
                if !is_duplicate_hello && self.adaptive_level != AdaptiveLevel::Satellite {
                    if let Some(tx) = self.control_tx.clone() {
                        Self::spawn_warmup_burst(tx);
                    } else {
                        warn!("control_tx not initialized, skipping keepalive warmup");
                    }
                }
            }
            ControlPayload::Keepalive { .. } => {
                debug!("Keepalive from server");
            }
            ControlPayload::TimeSync { server_ts_ms } => {
                debug!("Time sync: server_ts={}", server_ts_ms);
            }
            ControlPayload::Shutdown { reason } => {
                info!("Server requested shutdown (reason: {})", reason);
                self.disconnect().await;
                return Err(Error::Session(format!("server shutdown: {}", reason)));
            }
            ControlPayload::RecordingAck { session_id, status } => {
                if status == "started" {
                    self.active_recording_session = Some(session_id);
                } else if status == "analyzing" {
                    self.active_recording_session = None;
                }
                crate::record_cmd::handle_recording_ack(&session_id, &status);
            }
            ControlPayload::RecordingComplete {
                service,
                mask_id,
                confidence,
            } => {
                self.active_recording_session = None;
                crate::record_cmd::handle_recording_complete(&service, &mask_id, confidence);
            }
            ControlPayload::RecordingFailed { reason } => {
                self.active_recording_session = None;
                crate::record_cmd::handle_recording_failed(&reason);
            }
            ControlPayload::RecordingStatus {
                can_record,
                active_service,
            } => {
                crate::record_cmd::handle_recording_status(can_record, active_service.as_deref());
            }
            ControlPayload::CertRejected {} => {
                warn!("mTLS: server rejected the certificate — re-provision your mTLS cert");
            }
            ControlPayload::KeepaliveAck { echo_ts } => {
                // Use echoed client timestamp for RTT when available (server ≥ 0.9.0),
                // fall back to the stored send-time for older servers.
                let sent_ms = if echo_ts > 0 {
                    echo_ts
                } else {
                    self.keepalive_sent_ms.load(Ordering::Relaxed)
                };
                if sent_ms > 0 {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let rtt_us = now_ms.saturating_sub(sent_ms).saturating_mul(1000);
                    self.quality_tracker.record_rtt(rtt_us);
                    let score = self.quality_tracker.score();
                    Self::write_quality_file(
                        score,
                        self.quality_tracker.rtt_ms(),
                        self.quality_tracker.jitter_ms(),
                        self.adaptive_level as u8,
                    );
                    let new_level = AdaptiveLevel::suggest(score);
                    if new_level != self.adaptive_level {
                        self.adaptive_level = new_level;
                        self.set_keepalive_interval(Duration::from_secs(
                            new_level.keepalive_secs(),
                        ));
                        info!(
                            "Adaptive level → {:?} (score={}), keepalive={}s",
                            new_level,
                            score,
                            self.keepalive_interval.as_secs()
                        );
                    }
                    let _ = self
                        .send_control(&ControlPayload::QualityReport {
                            quality: score,
                            rtt_ms: self.quality_tracker.rtt_ms(),
                            loss_ppm: self.quality_tracker.loss_ppm(),
                            jitter_ms: self.quality_tracker.jitter_ms(),
                        })
                        .await;
                }
            }
            ControlPayload::AdaptiveHint { level } => {
                let new_level = AdaptiveLevel::from_u8(level);
                if new_level != self.adaptive_level {
                    self.adaptive_level = new_level;
                    self.set_keepalive_interval(Duration::from_secs(new_level.keepalive_secs()));
                    info!("Server adaptive hint → {:?}", new_level);
                }
            }
            ControlPayload::RegionalMaskHints {
                country_code,
                masks,
            } => {
                // §2 crowdsourced blocking feedback — opt-in. The server only
                // ever sends this after k-anonymity-gated aggregation (see
                // aivpn-server's mask_feedback.rs); ignore entirely unless
                // the client asked to receive hints.
                if !self.config.receive_mask_hints {
                    debug!("RegionalMaskHints received but receive_mask_hints=false — ignoring");
                    return Ok(());
                }
                info!(
                    "RegionalMaskHints for {}{}: {} masks",
                    country_code[0] as char,
                    country_code[1] as char,
                    masks.len()
                );
                // Keep an in-memory copy for `regional_mask_hints()` and
                // ALSO persist per-region (§2 L3). Mask selection happens in
                // `main.rs`'s reconnect loop on a fresh client instance one
                // iteration later, so the bias must read the hints back from
                // disk (`RegionalHintsStore`).
                let mut store = RegionalHintsStore::load_default();
                store.set_region(country_code, masks.clone());
                self.regional_mask_hints = Some(masks);
            }
            ControlPayload::FeedbackConfig {
                report_failure_threshold,
                report_interval_secs,
            } => {
                // §2 M3 server-pushed config. Persist the tuning so the
                // reconnect loop (a different client instance) honors it. Only
                // meaningful to an opted-in client; the server only sends this
                // in reply to a MaskFeedback, which only opted-in clients emit.
                info!(
                    "FeedbackConfig from server: failure_threshold={}, interval={}s",
                    report_failure_threshold, report_interval_secs
                );
                self.feedback_log
                    .set_tuning(report_failure_threshold, report_interval_secs);
            }
            ControlPayload::MaskCatalog { masks } => {
                // Server pushed the selectable-mask list. Persist it so the GUI
                // pickers (separate processes) render a live list and mark
                // auto-generated masks "(авто)".
                info!("MaskCatalog from server: {} masks", masks.len());
                crate::mask_catalog::write_mask_catalog(&masks);
            }
            ControlPayload::HandshakeReject { reason } => {
                // Authenticated (PSK-proven) terminal refusal — see the
                // doc comment on `ControlPayload::HandshakeReject` in
                // aivpn-common. Log the reason, surface it on stdout as a
                // machine-readable status line (mirrors "AIVPN-STATUS
                // connected <ip>") so the CLI and both desktop GUIs can show
                // it, and set the terminal flag so `main.rs`'s reconnect
                // loop stops instead of retrying forever against a refusal
                // that will never change on its own.
                let message = handshake_reject_message(reason);
                error!(
                    "Handshake rejected by server: {} (reason={})",
                    message, reason
                );
                println!("AIVPN-STATUS rejected {}", handshake_reject_token(reason));
                self.terminal_rejected = true;
                self.reject_reason = reason;
                self.disconnect().await;
                return Err(Error::Session(format!("handshake rejected: {}", message)));
            }
            ControlPayload::PoolSync { .. }
            | ControlPayload::PoolStateDigest { .. }
            | ControlPayload::PoolBucketDigests { .. }
            | ControlPayload::RouteSync { .. }
            | ControlPayload::PartitionAnnounce { .. }
            | ControlPayload::ChainForward { .. } => {
                // Normal end-user clients have no use for these pool
                // anti-entropy messages (or, for `ChainForward`, a reverse
                // exit reply) and silently ignore them, exactly as before —
                // their `inbound_control_tap` is `None`, so the block below
                // is a no-op for them.
                //
                // When the server has embedded this client as a headless
                // control-only pool-peer dialer (see
                // `ClientConfig::control_only`), forward a clone to the
                // configured tap instead so the embedder can drive its own
                // merge logic — never block the receive path on the tap.
                // `ChainForward` in particular is the PHASE-4 reverse path:
                // an exit node's reply for one of this entry's clients arrives
                // here over the masked dial session and MUST reach the tap so
                // `PoolDialer`'s drain loop can hand it to the gateway's
                // client-downlink path (`reverse_downlink_tx`). Without this
                // arm the reply was dropped by the catch-all below and the
                // masked-exit round trip never completed.
                if let Some(tap) = &self.config.inbound_control_tap {
                    if let Err(e) = tap.try_send(control) {
                        warn!(
                            "inbound_control_tap: failed to forward pool control payload: {}",
                            e
                        );
                    }
                }
            }
            ControlPayload::Capabilities { role, features } => {
                // P2.1: server-assigned role, sent once per session after
                // ratchet. `features` is reserved (always 0 today).
                info!(
                    "Capabilities from server: role={} features={}",
                    role, features
                );
                self.mgmt.on_capabilities(role);
            }
            ControlPayload::MgmtResponse {
                req_id,
                status,
                body,
            } => {
                self.mgmt.on_mgmt_response(req_id, status, body);
            }
            ControlPayload::NodeEnrollment { .. }
            | ControlPayload::MaskFeedback { .. }
            | ControlPayload::MgmtRequest { .. }
            | ControlPayload::RecordingStart { .. }
            | ControlPayload::RecordingStop { .. }
            | ControlPayload::RecordingStatusRequest
            | ControlPayload::ClientCert { .. }
            | ControlPayload::DeviceEnrollment { .. }
            | ControlPayload::QualityReport { .. }
            | ControlPayload::MaskPreference { .. } => {
                // Intentionally ignored on the desktop client: these are
                // messages THIS client only ever SENDS (to the server, or to
                // a pool peer for `NodeEnrollment`) — the server is the only
                // side that ever receives and acts on them, so there is no
                // inbound handling here.
            }
            ControlPayload::TelemetryRequest { .. }
            | ControlPayload::TelemetryResponse { .. }
            | ControlPayload::ControlAck { .. } => {
                // Intentionally ignored on the desktop client: reserved
                // telemetry-request/ack subtypes that only the server side
                // (`aivpn-server/src/gateway.rs`) currently exercises; the
                // desktop client neither sends nor needs to act on them.
            }
        }
        Ok(())
    }
}
