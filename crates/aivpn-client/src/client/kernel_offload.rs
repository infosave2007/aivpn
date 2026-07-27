use super::*;

impl super::AivpnClient {
    /// K6: install (or re-install after a rekey/mask change) the client's
    /// in-kernel DOWNLINK session so aivpn.ko decrypts server→client Data
    /// packets and injects them straight into the TUN device.
    ///
    /// Key/layout choices (mirroring `decode_downlink_any_mdh_len`, the
    /// user-space downlink decoder this offloads):
    /// * kernel decrypt key (`session_key` field) = the session's **s2c** key
    ///   — the client's incoming downlink is encrypted with it;
    /// * `tag_offset = u16::MAX` — server→client downlink always uses the
    ///   legacy tag-prefix framing `tag(8) || mdh || ciphertext` (the embedded
    ///   Variant A layout is uplink-only);
    /// * `mdh_len` = the current primary downlink MDH length
    ///   (`recv_mdh_len`). Packets framed with a different mask length fail
    ///   AEAD auth in the kernel (-EBADMSG) and fall back to user-space, whose
    ///   multi-length decoder handles them — correctness never depends on this
    ///   value, only the kernel-offload hit rate does.
    ///
    /// Ordering matters: TUN first (inject target), then the session + tags,
    /// then — exactly once per socket — the UDP hook, so no packet is ever
    /// intercepted before the kernel can actually consume it (a hook with no
    /// session was the 13984c5 starvation regression).
    ///
    /// `session_add` is idempotent by `session_id` (the kernel evicts a
    /// same-id entry first) and `kernel_session_id` is constant for this
    /// client instance, so a rekey re-install atomically replaces the old-key
    /// session instead of leaking it.
    ///
    /// All failures are soft: the user-space path keeps working, at worst the
    /// kernel simply never accelerates.
    #[cfg(target_os = "linux")]
    pub(super) fn kernel_install_session(&mut self) {
        use std::os::unix::io::AsRawFd;
        let Some(ka) = self.kernel_accel.clone() else {
            return;
        };
        // Re-checked full-tunnel gate (belt and braces — connect() already
        // leaves `kernel_accel = None` in proxy mode).
        if self.config.proxy_listen.is_some() {
            return;
        }
        let Some(keys) = self.session_keys.as_ref() else {
            return;
        };
        let (session_key_s2c, tag_secret) = (keys.session_key_s2c, keys.tag_secret);
        let Some(udp) = self.udp_socket.clone() else {
            return;
        };

        // 1. Point the module at our TUN device (once). A TUN that cannot be
        //    resolved means the kernel path is unusable — drop the handle so
        //    the hook is never installed.
        if !self.kernel_tun_set {
            let tun_name = self.tunnel.name();
            let ifindex = std::ffi::CString::new(tun_name)
                .map(|c| unsafe { libc::if_nametoindex(c.as_ptr()) })
                .unwrap_or(0);
            if ifindex == 0 {
                warn!(
                    "kernel accel: cannot resolve TUN ifindex for {tun_name} — \
                     staying on the user-space path"
                );
                self.kernel_accel = None;
                return;
            }
            if let Err(e) = ka.set_tun(ifindex) {
                warn!("kernel accel: set_tun failed: {e} — staying on the user-space path");
                self.kernel_accel = None;
                return;
            }
            self.kernel_tun_set = true;
            info!("kernel accel: TUN {tun_name} (ifindex={ifindex}) registered");
        }

        // 2. Install the downlink-decrypt session.
        let mdh_len = self.recv_mdh_len;
        // Peer address / own VPN IP: not used by the RX+inject path (they feed
        // the egress fast path, which the client never arms via SET_EGRESS) —
        // filled in sanely anyway.
        let mut client_addr_bytes = [0u8; 28];
        if let Ok(peer) = udp.peer_addr() {
            match peer {
                SocketAddr::V4(v4) => {
                    client_addr_bytes[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
                    client_addr_bytes[2..4].copy_from_slice(&v4.port().to_be_bytes());
                    client_addr_bytes[4..8].copy_from_slice(&v4.ip().octets());
                }
                SocketAddr::V6(v6) => {
                    client_addr_bytes[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
                    client_addr_bytes[2..4].copy_from_slice(&v6.port().to_be_bytes());
                    client_addr_bytes[8..24].copy_from_slice(&v6.ip().octets());
                }
            }
        }
        let client_ip = self
            .config
            .tun_config
            .tun_addr
            .parse::<std::net::Ipv4Addr>()
            .map(u32::from)
            .unwrap_or(0);
        let add = SessionAdd {
            session_id: self.kernel_session_id,
            // The kernel's RX path decrypts with `session_key`; for the
            // client's downlink that MUST be the s2c key.
            session_key: session_key_s2c,
            // Egress-encrypt key — never used (client never calls SET_EGRESS);
            // keep it the true s2c key so the field's meaning stays honest.
            session_key_s2c,
            tag_secret,
            // The AIVPN nonce is counter_LE(8) || zeros(4) in both directions —
            // no per-session suffix (see the server's identical comment).
            nonce_suffix: [0u8; 4],
            tag_offset: u16::MAX, // downlink is always legacy tag-prefix framing
            mdh_len: mdh_len as u16,
            _reserved: [0u8; 24],
            // Only seeds the egress tx_counter (unused on the client); the RX
            // anti-replay window starts at zero regardless.
            counter_base: self.recv_window.highest().map(|h| h + 1).unwrap_or(0),
            client_ip,
            client_addr: client_addr_bytes,
            window_ms: crypto::DEFAULT_WINDOW_MS,
        };
        if let Err(e) = ka.session_add(&add) {
            warn!("kernel accel: session_add failed: {e} — staying on the user-space path");
            return;
        }
        self.kernel_installed = true;
        self.kernel_installed_mdh_len = mdh_len;

        // 3. Push the expected downlink tag window before any packet can hit
        //    the hook.
        self.kernel_push_tags(true);

        // 4. Hook the UDP socket — exactly once per socket (the kernel install
        //    is not idempotent; see `kernel_hooked`). From here on, in-window
        //    downlink Data is consumed in softirq; everything else falls back
        //    to this loop via the hook's re-queue + original data_ready wake.
        if !self.kernel_hooked {
            if let Err(e) = ka.set_udp_sock(udp.as_raw_fd()) {
                warn!("kernel accel: set_udp_sock failed: {e} — kernel session installed but idle");
                return;
            }
            self.kernel_hooked = true;
        }
        info!(
            "kernel accel: downlink session installed (mdh_len={mdh_len}, legacy framing) — \
             server→client Data now decrypted in-kernel"
        );
    }

    /// K6: (re)compute and push the client's expected downlink resonance-tag
    /// window `[base, base + 256)` to the kernel, where `base` is one past the
    /// highest downlink counter user-space has validated. Exactly the tag
    /// derivation the server uses to CREATE downlink tags
    /// (`generate_resonance_tag(tag_secret, counter, time_window)`), so the
    /// kernel's byte-exact tag lookup matches the wire.
    ///
    /// Unless `force`d (fresh install/rekey), the push is skipped while the
    /// 10 s resonance time window is unchanged AND the observed counter has
    /// advanced less than `KERNEL_TAG_REFRESH_STRIDE` — callers can therefore
    /// invoke this opportunistically (per fallback packet + 5 s watchdog tick)
    /// at negligible cost.
    ///
    /// Known coverage limitation (same class as the server's K7 note): only
    /// fallback packets advance user-space's view of the downlink counter, so
    /// under sustained downlink the kernel window is consumed and traffic
    /// falls back to user-space until the next refresh re-bases it. That is a
    /// throughput ceiling, never a correctness issue.
    #[cfg(target_os = "linux")]
    pub(super) fn kernel_push_tags(&mut self, force: bool) {
        if !self.kernel_installed {
            return;
        }
        let Some(ka) = self.kernel_accel.clone() else {
            return;
        };
        let Some(keys) = self.session_keys.as_ref() else {
            return;
        };
        let tag_secret = keys.tag_secret;
        let base = self.recv_window.highest().map(|h| h + 1).unwrap_or(0);
        let tw =
            crypto::compute_time_window(crypto::current_timestamp_ms(), crypto::DEFAULT_WINDOW_MS);
        if !force
            && tw == self.kernel_tags_tw
            && base.saturating_sub(self.kernel_tags_base) < KERNEL_TAG_REFRESH_STRIDE
        {
            return;
        }
        // Safety: UpdateTagsPayload is a plain C struct of integers and byte
        // arrays; zeroed is valid for all fields.
        let mut payload: UpdateTagsPayload = unsafe { std::mem::zeroed() };
        payload.session_id = self.kernel_session_id;
        for i in 0..KERNEL_TAG_WINDOW as u64 {
            let counter = base + i;
            let tag = crypto::generate_resonance_tag(&tag_secret, counter, tw);
            payload.entries[i as usize] = TagWindowEntry { tag, counter };
        }
        payload.count = KERNEL_TAG_WINDOW as u32;
        if let Err(e) = ka.session_update_tags(&payload) {
            warn!("kernel accel: session_update_tags failed: {e}");
            return;
        }
        self.kernel_tags_base = base;
        self.kernel_tags_tw = tw;
    }
}
