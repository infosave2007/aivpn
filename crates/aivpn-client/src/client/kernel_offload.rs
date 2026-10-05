//! Клиентский offload downlink. Политика ROLE_CLIENT ставится после session_add:
//! повторный insert сохраняет окно replay и обнуляет политику.
//! Смена ключа s2c это новая монотонная эпоха. Тот же ключ эпоху не трогает.
//! Граница повтора это replay_claim, не слияние bitmap.

#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;

use aivpn_common::kernel_accel::{
    SessionPolicy, CLAIM_OK, POLICY_VERSION, POL_FALLBACK, POL_IPV6, ROLE_CLIENT,
};
use aivpn_common::mask::MaskProfile;

use super::*;

/// Смещение тега для ядра. Встройка только если маска реально кладет тег в заголовок.
pub(super) fn kernel_tag_offset(mask: &MaskProfile, mdh_len: usize) -> u16 {
    if mask.uses_embedded_layout(mdh_len) {
        mask.tag_offset
    } else {
        u16::MAX
    }
}

/// Что сделать с эпохой после insert. None: эпоха больше не растет, ядро ставить нельзя.
pub(super) struct EpochStep {
    pub epoch: u32,
    pub prev_epoch: u32,
    pub rotate: bool,
}

pub(super) fn epoch_step(current: u32, prev: u32, same_key: bool) -> Option<EpochStep> {
    if current != 0 && same_key {
        return Some(EpochStep {
            epoch: current,
            prev_epoch: prev,
            rotate: false,
        });
    }
    let next = current.checked_add(1)?;
    let prev_epoch = if current == 0 { 0 } else { current };
    Some(EpochStep {
        epoch: next,
        prev_epoch,
        rotate: true,
    })
}

/// Отказ claim или обрыв ioctl закрывают пакет. Непривязанная сессия живет в userspace.
pub(super) fn claim_allows(bound: bool, epoch: u32, result: Option<i32>) -> bool {
    if !bound {
        return true;
    }
    if epoch == 0 {
        return false;
    }
    result == Some(CLAIM_OK)
}

/// Политика обычного клиента. Нет IPv4: договориться нельзя, offload не включаем.
/// IPv6 без годной длины не ставит POL_IPV6 и не выключает IPv4.
pub(super) fn client_kernel_policy(
    session_id: [u8; 16],
    tun: &TunnelConfig,
) -> Option<SessionPolicy> {
    let ip: Ipv4Addr = tun.tun_addr.parse().ok()?;
    let client_ipv4 = u32::from_ne_bytes(ip.octets());
    if client_ipv4 == 0 {
        return None;
    }
    let mut policy = SessionPolicy::zeroed();
    policy.session_id = session_id;
    policy.policy_version = POLICY_VERSION;
    policy.role = ROLE_CLIENT;
    policy.client_ipv4 = client_ipv4;
    if let Some((addr, len)) = tun.ipv6 {
        if (1..=96).contains(&len) {
            policy.flags |= POL_IPV6;
            policy.ipv6_prefix = addr.octets();
            policy.ipv6_prefix_len = len;
        }
    }
    if policy.flags & POL_FALLBACK != 0 {
        return None;
    }
    Some(policy)
}

impl super::AivpnClient {
    /// Ставит downlink сессию клиента. Сначала insert (окно эпохи переносится,
    /// политика обнуляется и RX не вооружен), затем rotate только при новом ключе,
    /// затем политика. Пока политика не принята, хук не вешается.
    /// Уже привязанная эпоха остается: userspace берет счетчик через replay_claim.
    pub(super) fn kernel_install_session(&mut self) {
        if self.kernel_faulted {
            return;
        }
        let Some(ka) = self.kernel_accel.clone() else {
            return;
        };
        if self.config.proxy_listen.is_some() || self.config.control_only {
            return;
        }
        let Some(keys) = self.session_keys.as_ref() else {
            return;
        };
        let (session_key_s2c, tag_secret) = (keys.session_key_s2c, keys.tag_secret);
        let Some(transport) = self.transport.clone() else {
            return;
        };
        let Some(policy) = client_kernel_policy(self.kernel_session_id, &self.config.tun_config)
        else {
            warn!("kernel accel: нет адреса клиента, offload не включаем");
            return;
        };

        if !self.kernel_tun_set {
            let tun_name = self.tunnel.name();
            let ifindex = std::ffi::CString::new(tun_name)
                .map(|c| unsafe { libc::if_nametoindex(c.as_ptr()) })
                .unwrap_or(0);
            if ifindex == 0 {
                warn!(
                    "kernel accel: cannot resolve TUN ifindex for {tun_name}, \
                     staying on the user-space path"
                );
                self.kernel_release_unusable(true);
                return;
            }
            if let Err(e) = ka.set_tun(ifindex) {
                warn!("kernel accel: set_tun failed: {e}, staying on the user-space path");
                self.kernel_release_unusable(true);
                return;
            }
            self.kernel_tun_set = true;
            info!("kernel accel: TUN {tun_name} (ifindex={ifindex}) registered");
        }

        let mdh_len = self.recv_mdh_len;
        let tag_offset = if let Some(engine) = self.mimicry_engine.as_ref() {
            kernel_tag_offset(engine.mask(), mdh_len)
        } else {
            kernel_tag_offset(&self.config.initial_mask, mdh_len)
        };
        let mut client_addr_bytes = [0u8; 28];
        if let Some(peer) = transport.peer_addr() {
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
        let add = SessionAdd {
            session_id: self.kernel_session_id,
            // Ядро расшифровывает поле session_key. Для клиента это ключ s2c.
            session_key: session_key_s2c,
            session_key_s2c,
            tag_secret,
            nonce_suffix: [0u8; 4],
            tag_offset,
            mdh_len: mdh_len as u16,
            _reserved: [0u8; 24],
            counter_base: 0,
            client_ip: policy.client_ipv4,
            client_addr: client_addr_bytes,
            window_ms: crypto::DEFAULT_WINDOW_MS,
        };
        if let Err(e) = ka.session_add(&add) {
            warn!("kernel accel: session_add failed: {e}, staying on the user-space path");
            if self.kernel_replay_bound && self.kernel_epoch_key != session_key_s2c {
                let _ = ka.session_remove(&self.kernel_session_id);
                self.kernel_faulted = true;
                self.kernel_installed = false;
            }
            return;
        }

        let same_key = self.kernel_epoch != 0 && self.kernel_epoch_key == session_key_s2c;
        let Some(step) = epoch_step(self.kernel_epoch, self.kernel_prev_epoch, same_key) else {
            warn!("kernel accel: эпоха ключа не растет, сессия снята");
            let _ = ka.session_remove(&self.kernel_session_id);
            self.kernel_installed = false;
            self.kernel_replay_bound = self.kernel_epoch != 0;
            self.kernel_faulted = self.kernel_replay_bound;
            return;
        };
        if step.rotate {
            if let Err(e) = ka.replay_rotate(&self.kernel_session_id, step.epoch) {
                warn!("kernel accel: replay_rotate не принят ({e}), сессия снята");
                let _ = ka.session_remove(&self.kernel_session_id);
                self.kernel_installed = false;
                self.kernel_replay_bound = self.kernel_epoch != 0;
                self.kernel_faulted = self.kernel_replay_bound;
                return;
            }
        }
        self.kernel_epoch = step.epoch;
        self.kernel_prev_epoch = step.prev_epoch;
        self.kernel_epoch_key = session_key_s2c;
        self.kernel_replay_bound = true;

        // Политика после эпохи. До этого RX разоружен и счетчик не жжет.
        if let Err(e) = ka.session_policy(&policy) {
            warn!("kernel accel: session_policy не принята ({e}), ускорение выключено");
            self.kernel_installed = false;
            return;
        }
        self.kernel_installed_mdh_len = mdh_len;
        self.kernel_installed_tag_offset = tag_offset;
        self.kernel_push_tags(true);

        if !self.kernel_hooked {
            let Some(fd) = transport.raw_fd() else {
                self.kernel_installed = false;
                return;
            };
            if let Err(e) = ka.set_udp_sock(fd) {
                warn!("kernel accel: set_udp_sock failed: {e}, session stays idle");
                self.kernel_installed = false;
                return;
            }
            self.kernel_hooked = true;
        }
        self.kernel_installed = true;
        info!(
            "kernel accel: downlink session installed (mdh_len={mdh_len}, tag_offset={tag_offset})"
        );
    }

    /// Захват счетчика до обработки пакета. Отказ закрывает пакет.
    pub(super) fn kernel_accept_counter(&mut self, epoch: u32, counter: u64) -> bool {
        if self.kernel_faulted {
            return false;
        }
        if !self.kernel_replay_bound {
            return true;
        }
        let Some(ka) = self.kernel_accel.clone() else {
            return false;
        };
        if epoch == 0 {
            return false;
        }
        match ka.replay_claim(&self.kernel_session_id, epoch, counter) {
            Ok(code) if claim_allows(true, epoch, Some(code)) => true,
            Ok(code) => {
                debug!(
                    "kernel accel: replay_claim отклонил счетчик {counter} эпохи {epoch}: {code}"
                );
                false
            }
            Err(e) => {
                warn!("kernel accel: replay_claim не выполнен, пакет отклонен: {e}");
                false
            }
        }
    }

    fn kernel_release_unusable(&mut self, drop_handle: bool) {
        if drop_handle {
            self.kernel_accel = None;
        }
        self.kernel_installed = false;
        self.kernel_replay_bound = false;
        self.kernel_tun_set = false;
    }

    /// Статистика ядра поддерживает счетчики, окно тегов и проверку живости туннеля.
    pub(super) fn kernel_harvest(&mut self) -> bool {
        if !self.kernel_replay_bound || self.kernel_faulted {
            return false;
        }
        let Some(ka) = self.kernel_accel.as_ref() else {
            return false;
        };
        let mut snapshot = aivpn_common::kernel_accel::SessionSync::zeroed();
        snapshot.session_id = self.kernel_session_id;
        snapshot.flags = aivpn_common::kernel_accel::SYNC_ACK_STATS;
        if ka.session_sync(&mut snapshot).is_err() {
            return false;
        }
        let same_key = self
            .session_keys
            .as_ref()
            .is_some_and(|k| k.session_key_s2c == self.kernel_epoch_key);
        if same_key {
            let words = snapshot.replay_words;
            for (word_index, word) in words.into_iter().enumerate() {
                for bit in 0..64 {
                    let offset = (word_index * 64 + bit) as u64;
                    if word & (1u64 << bit) != 0 {
                        if let Some(counter) = snapshot.replay_hi.checked_sub(offset) {
                            self.recv_window.mark(counter);
                        }
                    }
                }
            }
        }
        if snapshot.rx_bytes_delta == 0 {
            return false;
        }
        self.bytes_received
            .fetch_add(snapshot.rx_bytes_delta, Ordering::Relaxed);
        self.last_data_rx = Instant::now();
        self.upload_at_last_data_rx = self.bytes_sent.load(Ordering::Relaxed);
        self.data_stall_started = None;
        self.data_stall_strikes = 0;
        self.data_plane_proven = true;
        true
    }

    /// Окно тегов downlink. База это следующий счетчик, который userspace еще не видел.
    pub(super) fn kernel_push_tags(&mut self, force: bool) {
        if !self.kernel_replay_bound {
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

#[cfg(test)]
mod tests {
    use super::{claim_allows, client_kernel_policy, epoch_step, kernel_tag_offset};
    use crate::tunnel::TunnelConfig;
    use aivpn_common::kernel_accel::{
        CLAIM_DUP, CLAIM_EPOCH, CLAIM_FALLBACK, CLAIM_OK, CLAIM_TOO_OLD, POL_FALLBACK, POL_IPV6,
        ROLE_CLIENT,
    };
    use aivpn_common::mask::preset_masks::webrtc_vk_teams_v1;

    fn tun_v4(addr: &str) -> TunnelConfig {
        let mut tun = TunnelConfig::default();
        tun.tun_addr = addr.to_string();
        tun.ipv6 = None;
        tun
    }

    #[test]
    fn policy_uses_assigned_v4_and_v6_without_fallback() {
        let mut tun = tun_v4("10.8.0.5");
        tun.ipv6 = Some(("fd12:3456:789a::a08:5".parse().unwrap(), 64));
        let policy = client_kernel_policy([7u8; 16], &tun).unwrap();
        assert_eq!({ policy.role }, ROLE_CLIENT);
        assert_eq!({ policy.session_id }, [7u8; 16]);
        assert_eq!({ policy.client_ipv4 }, u32::from_ne_bytes([10, 8, 0, 5]));
        assert_ne!({ policy.flags } & POL_IPV6, 0);
        assert_eq!({ policy.flags } & POL_FALLBACK, 0);
        assert_eq!({ policy.ipv6_prefix_len }, 64);
        assert_eq!(
            { policy.ipv6_prefix },
            "fd12:3456:789a::a08:5"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        assert_eq!({ policy.rate_up_bps }, 0);
        assert_eq!({ policy.quota_up_bytes }, 0);
    }

    #[test]
    fn policy_without_ipv6_stays_v4_and_bad_prefix_does_not_disable_v4() {
        let v4 = client_kernel_policy([1u8; 16], &tun_v4("10.0.0.2")).unwrap();
        assert_eq!({ v4.flags } & POL_IPV6, 0);
        assert_eq!({ v4.flags } & POL_FALLBACK, 0);
        assert_eq!({ v4.client_ipv4 }, u32::from_ne_bytes([10, 0, 0, 2]));

        let mut wide = tun_v4("10.0.0.2");
        wide.ipv6 = Some(("fd12:3456:789a::a00:2".parse().unwrap(), 128));
        let kept = client_kernel_policy([1u8; 16], &wide).unwrap();
        assert_eq!({ kept.flags } & POL_IPV6, 0);
        assert_eq!({ kept.flags } & POL_FALLBACK, 0);
        assert_ne!({ kept.client_ipv4 }, 0);
    }

    #[test]
    fn policy_refuses_missing_or_zero_address() {
        assert!(client_kernel_policy([1u8; 16], &tun_v4("not-an-ip")).is_none());
        assert!(client_kernel_policy([1u8; 16], &tun_v4("0.0.0.0")).is_none());
    }

    #[test]
    fn tag_offset_follows_embedded_layout() {
        let mut mask = webrtc_vk_teams_v1();
        mask.tag_offset = 8;
        mask.eph_pub_offset = 40;
        mask.eph_pub_length = 32;
        assert_eq!(kernel_tag_offset(&mask, 20), 8);
        assert_eq!(kernel_tag_offset(&mask, 12), u16::MAX);
        mask.tag_offset = u16::MAX;
        assert_eq!(kernel_tag_offset(&mask, 64), u16::MAX);
    }

    #[test]
    fn same_key_keeps_epoch_and_new_key_rotates() {
        let first = epoch_step(0, 0, false).unwrap();
        assert!(first.rotate);
        assert_eq!(first.epoch, 1);
        assert_eq!(first.prev_epoch, 0);

        let again = epoch_step(4, 3, true).unwrap();
        assert!(!again.rotate);
        assert_eq!(again.epoch, 4);
        assert_eq!(again.prev_epoch, 3);

        let rotated = epoch_step(4, 3, false).unwrap();
        assert!(rotated.rotate);
        assert_eq!(rotated.epoch, 5);
        assert_eq!(rotated.prev_epoch, 4);
        assert!(epoch_step(u32::MAX, 1, false).is_none());
    }

    #[test]
    fn claim_refusal_fails_closed_only_when_kernel_owns_replay() {
        assert!(claim_allows(false, 0, None));
        assert!(claim_allows(false, 1, Some(CLAIM_DUP)));
        assert!(claim_allows(true, 2, Some(CLAIM_OK)));
        assert!(!claim_allows(true, 2, Some(CLAIM_DUP)));
        assert!(!claim_allows(true, 2, Some(CLAIM_TOO_OLD)));
        assert!(!claim_allows(true, 2, Some(CLAIM_EPOCH)));
        assert!(!claim_allows(true, 2, Some(CLAIM_FALLBACK)));
        assert!(!claim_allows(true, 2, None));
        assert!(!claim_allows(true, 0, Some(CLAIM_OK)));
    }
}
