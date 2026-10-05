//! Free builder functions that translate a userspace `Session` into the
//! plain-C payloads the kernel accelerator (`/dev/aivpn`) ioctls expect —
//! session install, downlink counter-block reservation, and tag-window
//! refresh — plus the wire-layout resolution (H7) all three share.

use std::net::SocketAddr;

use aivpn_common::crypto::{self, DEFAULT_WINDOW_MS};
use aivpn_common::kernel_accel::{
    KernelAccel, SessionAdd, SessionDownlink, SessionPolicy, SessionSync, TagWindowEntry,
    UpdateTagsPayload, CLAIM_DUP, CLAIM_EPOCH, CLAIM_OK, CLAIM_TOO_OLD, DL_MDH_MAX, POLICY_VERSION,
    POL_ENROLL_WAIT, POL_EXIT, POL_FALLBACK, POL_IPV6, POL_MTLS_WAIT, POL_PEER_ISOLATE,
    POL_QOS_DOWN, POL_QOS_UP, POL_QUOTA_DOWN, POL_QUOTA_UP, POL_SITE, QOS_ACCEPT, QOS_DROP,
    QOS_FALLBACK, ROLE_SERVER, SYNC_ACK_STATS,
};

use super::mask_catalog::{packet_layout_for_mask, packet_mdh_bytes_for_mask};

/// H7 (conservative fix): resolve the wire layout (tag_offset, mdh_len) to
/// install into the kernel accelerator for `sess`, mirroring EXACTLY the
/// userspace decode path's own layout resolution (the `session_mdh_len`
/// block in `Gateway::handle_packet`) instead of unconditionally using the
/// mask-catalog's PRIMARY mask.
///
/// The doc comment `make_kernel_session_add` used to carry here claimed the
/// client "converges" to the catalog's runtime primary mask shortly after
/// connect — but the handshake-completion path deliberately does NOT
/// perform that auto-switch (see the long comment where ServerHello is
/// sent): a session stays pinned to its bootstrap mask for its entire life.
/// Installing kernel offsets from "whatever the catalog's primary mask
/// currently is" therefore diverges from the layout the client actually
/// speaks whenever the primary differs from the session's own bootstrap
/// mask (e.g. after a mask rotation, or a custom `config.bootstrap_masks`
/// entry that never became primary). The kernel fails closed on the
/// resulting AEAD mismatch (not a spoofing risk), but the session's kernel
/// fast path silently blackholes until the next re-install recomputes the
/// (still-wrong) catalog value again.
pub(crate) fn kernel_wire_layout(
    sess: &crate::session::Session,
    catalog_tag_offset: u16,
    catalog_mdh_len: u16,
) -> (u16, u16) {
    if let Some(ref mask) = sess.mask {
        let (packet_mdh_len, _handshake_mdh_len, _eph_offset, _eph_len) =
            packet_layout_for_mask(mask);
        (mask.tag_offset, packet_mdh_len as u16)
    } else {
        // No mask pinned yet (shouldn't normally happen for a session that
        // has reached the kernel-install call sites) — fall back to the
        // catalog primary, matching the userspace decode path's own
        // fallback for this case.
        (catalog_tag_offset, catalog_mdh_len)
    }
}

/// Build the kernel session-install payload. `tag_offset`/`mdh_len` should be
/// obtained via `kernel_wire_layout` (H7) so they describe the CLIENT's
/// actual wire layout — the session's own pinned mask, not necessarily the
/// mask-catalog's primary.
pub(crate) fn make_kernel_session_add(
    sess: &crate::session::Session,
    tag_offset: u16,
    mdh_len: u16,
) -> SessionAdd {
    // The kernel indexes this session in its IP hash-table by `client_ip` and the
    // downlink egress hook looks it up by the packet's INNER destination
    // (`iph->daddr` = the client's VPN/tunnel IP). It must therefore be the
    // client's VPN IP — NOT the outer transport source address — and in network
    // byte order to match `__be32 iph->daddr`. Using the transport IP (or host
    // byte order) made every egress lookup miss, so K5 downlink never engaged.
    let client_ip = match sess.vpn_ip {
        Some(ip) => u32::from_ne_bytes(ip.octets()),
        None => 0,
    };
    let mut ca = [0u8; 28];
    match sess.client_addr {
        SocketAddr::V4(ref v4) => {
            ca[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            ca[2..4].copy_from_slice(&v4.port().to_be_bytes());
            ca[4..8].copy_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(ref v6) => {
            ca[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            ca[2..4].copy_from_slice(&v6.port().to_be_bytes());
            ca[8..24].copy_from_slice(&v6.ip().octets());
        }
    }
    SessionAdd {
        session_id: sess.session_id,
        // Directional keys: session_key (c2s) decrypts the client uplink the
        // kernel handles; session_key_s2c (s2c) is used by kernel downlink
        // encryption. Matches the userspace data path's directional keys.
        session_key: sess.keys.session_key,
        session_key_s2c: sess.keys.session_key_s2c,
        tag_secret: sess.keys.tag_secret,
        // The AIVPN nonce is counter_LE(8) || zeros(4): both the client
        // (client_wire::counter_to_nonce) and the server (compute_nonce) leave
        // bytes 8..12 zero — there is no per-session nonce suffix. Passing a
        // non-zero suffix here (previously prng_seed[..4]) made the kernel build
        // a different nonce and fail every AEAD auth. Must stay all-zero.
        nonce_suffix: [0u8; 4],
        tag_offset,
        mdh_len,
        _reserved: [0u8; 24],
        counter_base: sess.counter,
        client_ip,
        client_addr: ca,
        window_ms: DEFAULT_WINDOW_MS,
    }
}

/// Cheap change-detector over the kernel-relevant session state: the c2s key
/// (rotates on rekey/ratchet) and the wire layout (tag_offset/mdh_len, which
/// change when the client switches from the bootstrap mask to the runtime mask).
/// When this differs from the last value pushed to the kernel, the kernel
/// session must be re-installed so its frozen key/offsets don't silently fail
/// every decrypt.
pub(crate) fn kernel_session_sig(
    sess: &crate::session::Session,
    tag_offset: u16,
    mdh_len: u16,
) -> u64 {
    let mut k = [0u8; 8];
    k.copy_from_slice(&sess.keys.session_key[..8]);
    u64::from_le_bytes(k) ^ ((tag_offset as u64) << 48) ^ ((mdh_len as u64) << 32)
}

/// Number of downlink send-counters reserved per kernel-downlink arming. Kept
/// below the client's 256-entry reorder window so the reserved counters stay
/// acceptable relative to the highest downlink counter the client has seen, and
/// small enough that the pre-computed resonance tags remain inside the client's
/// current time window (DEFAULT_WINDOW_MS) between refreshes.
const KERNEL_DOWNLINK_BLOCK: u32 = 128;

/// True once the kernel downlink egress hook has been successfully enabled.
/// Reserving downlink counters advances `send_counter`; doing that when the
/// kernel is NOT actually transmitting downlink (egress off) would waste counter
/// space and could push user-space downlink counters past the client's forward
/// search window. So the reservation only runs once this is set.
pub(crate) static KERNEL_DOWNLINK_ARMED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Reserve a fresh block of downlink send-counters for the kernel and build the
/// AIVPN_IOC_SESSION_DOWNLINK payload (reserved (tag,counter) pairs + MDH).
///
/// COUNTER SAFETY: the block `[base, base+N)` is claimed by advancing
/// `sess.send_counter` past it under the session lock, so the user-space
/// downlink path can never emit any counter in the block. Each counter is used
/// at most once (the kernel consumes them strictly in order), so no
/// (s2c-key, nonce) pair is ever reused. Returns `None` — leaving the session
/// on the user-space downlink path — if the session has no mask yet or its MDH
/// is larger than the kernel inline limit.
pub(crate) fn make_kernel_downlink(sess: &mut crate::session::Session) -> Option<SessionDownlink> {
    // Only reserve counters when the kernel is actually transmitting downlink.
    if !KERNEL_DOWNLINK_ARMED.load(std::sync::atomic::Ordering::Relaxed) {
        return None;
    }
    let mask = sess.mask.as_ref()?;
    let mdh = packet_mdh_bytes_for_mask(mask);
    if mdh.is_empty() || mdh.len() > DL_MDH_MAX {
        return None;
    }
    let count = KERNEL_DOWNLINK_BLOCK;
    let base = sess.send_counter;
    let tag_secret = sess.keys.tag_secret;
    let time_window = crypto::compute_time_window(
        crypto::current_timestamp_ms(),
        aivpn_common::crypto::DEFAULT_WINDOW_MS,
    );

    // Ноль в dl_tag_pos значит встройку с начала заголовка, не legacy.
    // Sentinel 0xFFFF ставим явно, затем заменяем реальной раскладкой маски.
    let mut dl: SessionDownlink = unsafe { std::mem::zeroed() };
    dl.session_id = sess.session_id;
    dl.dl_tag_pos = kernel_downlink_tag_pos(mask, mdh.len());
    dl.mdh_len = mdh.len() as u16;
    dl.mdh[..mdh.len()].copy_from_slice(&mdh);
    dl.seq_base = sess.send_seq as u16;
    for i in 0..count as u64 {
        let counter = base + i;
        let tag = crypto::generate_resonance_tag(&tag_secret, counter, time_window);
        dl.entries[i as usize] = TagWindowEntry { tag, counter };
    }
    dl.count = count;

    // Claim the block: user-space will never emit a counter below this value.
    sess.send_counter = base + count as u64;
    sess.send_seq = sess.send_seq.wrapping_add(count);
    // Record the time window these tags were derived for so the receive path can
    // re-arm the moment the wall-clock window advances (keeping the kernel's
    // frozen tags inside the client's ±1-window acceptance range).
    sess.kernel_dl_window = time_window;
    Some(dl)
}

pub(crate) fn make_kernel_update_tags(sess: &crate::session::Session) -> UpdateTagsPayload {
    // Safety: UpdateTagsPayload is a plain C struct of integers and byte arrays;
    // zeroed is valid for all fields.
    let mut payload: UpdateTagsPayload = unsafe { std::mem::zeroed() };
    payload.session_id = sess.session_id;

    // NOTE: the kernel window holds only AIVPN_TAG_WINDOW_SLOTS (256) tags while
    // `expected_tags` spans ~1023 counters ([base-511, base+511]), so only a
    // subset is pushed and many uplink packets currently miss the kernel and
    // fall back to user-space. Tracking the kernel's own recv_counter to keep
    // the pushed window centred ahead of it is a K7 throughput task; do not
    // narrow the subset heuristically here — the arriving counters run ahead of
    // the server's last refreshed base by an unknown amount, so any fixed slice
    // (lowest-256 / highest-256) can sit entirely off the incoming range.
    let mut count = 0usize;
    for (&counter, tag) in sess.expected_tags.iter().take(256) {
        payload.entries[count] = TagWindowEntry { tag: *tag, counter };
        count += 1;
    }
    payload.count = count as u32;
    payload
}

/// Вход сборщика политики. Лимиты берет интегратор: 0 это без ограничения.
/// limits_ready ложь оставляет сессию в fallback, чтобы ядро не обошло неизвестный QoS.
#[derive(Clone, Debug)]
pub(crate) struct KernelPolicyInput {
    pub allow_peer_routing: bool,
    pub ipv6_prefix: Option<[u8; 16]>,
    pub ipv6_prefix_len: u8,
    pub rate_up_bps: u64,
    pub rate_down_bps: u64,
    pub quota_up_bytes: Option<u64>,
    pub quota_down_bytes: Option<u64>,
    pub max_sessions: u32,
    pub client_key: Option<[u8; 16]>,
    pub exit_node: bool,
    pub enroll_pending: bool,
    pub limits_ready: bool,
    pub userspace_rx: bool,
    pub userspace_tx: bool,
    pub revoked: bool,
}

impl Default for KernelPolicyInput {
    fn default() -> Self {
        Self {
            allow_peer_routing: false,
            ipv6_prefix: None,
            ipv6_prefix_len: 0,
            rate_up_bps: 0,
            rate_down_bps: 0,
            quota_up_bytes: None,
            quota_down_bytes: None,
            max_sessions: 0,
            client_key: None,
            exit_node: false,
            enroll_pending: false,
            limits_ready: false,
            userspace_rx: false,
            userspace_tx: false,
            revoked: false,
        }
    }
}

/// Пара install: session_add сбрасывает политику в ядре, ее нужно поставить снова.
#[cfg(test)]
pub(crate) struct KernelInstall {
    pub add: SessionAdd,
    pub policy: SessionPolicy,
}

pub(crate) fn kernel_downlink_tag_pos(
    mask: &aivpn_common::mask::MaskProfile,
    mdh_len: usize,
) -> u16 {
    if mask.uses_embedded_layout(mdh_len) {
        mask.tag_offset
    } else {
        u16::MAX
    }
}

pub(crate) fn make_kernel_session_policy(
    sess: &crate::session::Session,
    input: &KernelPolicyInput,
) -> SessionPolicy {
    let mut policy = SessionPolicy::zeroed();
    policy.session_id = sess.session_id;
    policy.policy_version = POLICY_VERSION;
    policy.role = ROLE_SERVER;
    policy.client_ipv4 = sess
        .vpn_ip
        .map(|ip| u32::from_ne_bytes(ip.octets()))
        .unwrap_or(0);
    policy.max_sessions = input.max_sessions;

    let mut flags = 0u32;
    // FEC должен видеть все Data своей группы. Неизвестный формат тоже остается userspace.
    if !sess
        .client_packet_features
        .is_some_and(|features| features & aivpn_common::protocol::CLIENT_FEC_ACTIVE == 0)
    {
        flags |= aivpn_common::kernel_accel::POL_RX_FALLBACK;
    }

    if sess.is_site_peer {
        flags |= POL_SITE;
    }
    if sess.vpn_ip.is_none() || sess.is_masked_pool_peer {
        flags |= POL_FALLBACK;
    }
    if !sess.mtls_ok {
        flags |= POL_MTLS_WAIT;
    }
    if !sess.is_site_peer && sess.client_id.is_none() {
        flags |= POL_ENROLL_WAIT;
    }
    if input.enroll_pending {
        flags |= POL_ENROLL_WAIT;
    }
    if input.exit_node {
        flags |= POL_EXIT;
    }
    if !input.limits_ready {
        flags |= POL_FALLBACK;
    }
    if !input.allow_peer_routing {
        flags |= POL_PEER_ISOLATE;
    }
    if let Some(prefix) = input.ipv6_prefix {
        if (1..=96).contains(&input.ipv6_prefix_len) {
            flags |= POL_IPV6;
            policy.ipv6_prefix = prefix;
            policy.ipv6_prefix_len = input.ipv6_prefix_len;
        } else {
            flags |= POL_FALLBACK;
        }
    }
    if input.limits_ready {
        policy.rate_up_bps = input.rate_up_bps;
        policy.rate_down_bps = input.rate_down_bps;
        if input.rate_up_bps > 0 {
            flags |= POL_QOS_UP;
        }
        if input.rate_down_bps > 0 {
            flags |= POL_QOS_DOWN;
        }
        if let Some(quota) = input.quota_up_bytes {
            flags |= POL_QUOTA_UP;
            policy.quota_up_bytes = quota;
        }
        if let Some(quota) = input.quota_down_bytes {
            flags |= POL_QUOTA_DOWN;
            policy.quota_down_bytes = quota;
        }
    }

    policy.client_key = if let Some(key) = input.client_key {
        key
    } else if let Some(id) = sess.client_id.as_deref() {
        let hash = aivpn_common::crypto::blake3_hash(id.as_bytes());
        let mut key = [0u8; 16];
        key.copy_from_slice(&hash[..16]);
        key
    } else {
        [0u8; 16]
    };
    if input.userspace_rx {
        flags |= aivpn_common::kernel_accel::POL_RX_FALLBACK;
    }
    if input.userspace_tx {
        flags |= aivpn_common::kernel_accel::POL_TX_FALLBACK;
    }
    if input.revoked {
        flags |= aivpn_common::kernel_accel::POL_REVOKED;
    }
    policy.flags = flags;
    policy
}

#[cfg(test)]
pub(crate) fn make_kernel_install(
    sess: &crate::session::Session,
    tag_offset: u16,
    mdh_len: u16,
    input: &KernelPolicyInput,
) -> KernelInstall {
    KernelInstall {
        add: make_kernel_session_add(sess, tag_offset, mdh_len),
        policy: make_kernel_session_policy(sess, input),
    }
}

/// Ключ клиента для общего ведра и отзыва. Совпадает с полем policy.client_key.
pub(crate) fn kernel_client_key(client_id: &str) -> [u8; 16] {
    let hash = aivpn_common::crypto::blake3_hash(client_id.as_bytes());
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash[..16]);
    key
}

fn kernel_key_tag(sess: &crate::session::Session) -> [u8; 8] {
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&sess.keys.session_key[..8]);
    tag
}

fn ipv6_policy_prefix(
    network: &aivpn_common::network_config::VpnNetworkConfig,
) -> Option<([u8; 16], u8)> {
    if !network.ipv6_enabled {
        return None;
    }
    let (addr, prefix) = network.ipv6_prefix.split_once('/')?;
    let addr: std::net::Ipv6Addr = addr.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    if !(1..=96).contains(&prefix) {
        return None;
    }
    let mask = u128::MAX << (128 - prefix);
    let net = u128::from(addr) & mask;
    Some((net.to_be_bytes(), prefix))
}

/// Лимиты сессии: скорость и квота по client_key, IPv6, изоляция, exit и enrollment.
/// Неизвестный QoS оставляет limits_ready ложью, и ядро не обходит userspace.
pub(crate) fn kernel_limits_for(
    sess: &crate::session::Session,
    client: Option<&crate::client_db::ClientConfig>,
    network: &aivpn_common::network_config::VpnNetworkConfig,
    allow_peer_routing: bool,
    global_exit: bool,
) -> KernelPolicyInput {
    let qos = client.and_then(|item| item.qos.as_ref());
    let enroll_pending = if sess.is_site_peer {
        false
    } else if let Some(item) = client {
        item.one_time && item.device_pubkey.is_none()
    } else {
        sess.client_id.is_none()
    };
    let limits_ready = if sess.is_site_peer {
        true
    } else if sess.client_id.is_none() {
        false
    } else {
        client.is_some()
    };
    let exit_node = global_exit || client.and_then(|item| item.exit_node.as_ref()).is_some();
    let ipv6 = ipv6_policy_prefix(network);
    KernelPolicyInput {
        allow_peer_routing,
        ipv6_prefix: ipv6.map(|(prefix, _)| prefix),
        ipv6_prefix_len: ipv6.map(|(_, len)| len).unwrap_or(0),
        rate_up_bps: qos.and_then(|item| item.bandwidth_limit_up).unwrap_or(0),
        rate_down_bps: qos.and_then(|item| item.bandwidth_limit_down).unwrap_or(0),
        quota_up_bytes: None,
        quota_down_bytes: None,
        max_sessions: 0,
        client_key: sess.client_id.as_deref().map(kernel_client_key),
        exit_node,
        enroll_pending,
        limits_ready,
        userspace_rx: qos.and_then(|q| q.dscp_class).is_some(),
        userspace_tx: false,
        revoked: sess.client_id.is_some()
            && client.is_none_or(|c| {
                c.deleted || !c.enabled || c.expires_at.is_some_and(|t| t <= chrono::Utc::now())
            }),
    }
}

pub(crate) fn kernel_input_from_session(
    sess: &crate::session::Session,
    db: Option<&crate::client_db::ClientDatabase>,
    network: &aivpn_common::network_config::VpnNetworkConfig,
    allow_peer_routing: bool,
    global_exit: bool,
) -> KernelPolicyInput {
    let client = sess
        .client_id
        .as_deref()
        .and_then(|id| db.and_then(|db| db.find_by_id(id)));
    kernel_limits_for(
        sess,
        client.as_ref(),
        network,
        allow_peer_routing,
        global_exit,
    )
}

fn stored_policy_sig(fingerprint: u64) -> u64 {
    let mixed = fingerprint ^ 0xA17F_6E05_C0DE;
    if mixed == 0 {
        1
    } else {
        mixed
    }
}

fn policy_fingerprint(policy: &SessionPolicy) -> u64 {
    let mut hash = blake3::Hasher::new();
    hash.update(&policy.client_key);
    hash.update(&policy.ipv6_prefix);
    for value in [
        policy.flags,
        policy.client_ipv4,
        policy.ipv6_prefix_len as u32,
        policy.max_sessions,
    ] {
        hash.update(&value.to_le_bytes());
    }
    for value in [
        policy.rate_up_bps,
        policy.rate_down_bps,
        policy.quota_up_bytes,
        policy.quota_down_bytes,
    ] {
        hash.update(&value.to_le_bytes());
    }
    u64::from_le_bytes(hash.finalize().as_bytes()[..8].try_into().unwrap())
}

/// План ioctl. add и rotate пустые, если ключ и раскладка не менялись.
/// Смена только раскладки не открывает новую эпоху: окно replay копирует ядро.
pub(crate) struct KernelWirePlan {
    pub add: Option<SessionAdd>,
    pub rotate_to: Option<u32>,
    pub prev_epoch: u32,
    pub key_tag: [u8; 8],
    pub policy: Option<SessionPolicy>,
    pub policy_sig: u64,
    pub tags: Option<UpdateTagsPayload>,
    pub install_sig: u64,
}

pub(crate) fn kernel_reinstall(
    sess: &crate::session::Session,
    tag_offset: u16,
    mdh_len: u16,
    input: &KernelPolicyInput,
    refresh_policy: bool,
) -> Option<KernelWirePlan> {
    let install_sig = kernel_session_sig(sess, tag_offset, mdh_len);
    let key_tag = kernel_key_tag(sess);
    let rotate = sess.kernel_epoch == 0 || sess.kernel_key_tag != key_tag;
    let need_add = rotate || sess.kernel_install_sig != install_sig;
    let policy = make_kernel_session_policy(sess, input);
    // 0 остается признаком "политика еще не записана", поэтому отпечаток не храним сырым.
    let policy_sig = stored_policy_sig(policy_fingerprint(&policy));
    let need_policy = need_add || refresh_policy || sess.kernel_policy_sig != policy_sig;
    if !need_add && !need_policy {
        return None;
    }
    let epoch = if rotate {
        sess.kernel_epoch.saturating_add(1).max(1)
    } else {
        sess.kernel_epoch
    };
    Some(KernelWirePlan {
        add: need_add.then(|| make_kernel_session_add(sess, tag_offset, mdh_len)),
        rotate_to: rotate.then_some(epoch),
        prev_epoch: if sess.kernel_epoch == 0 {
            0
        } else {
            sess.kernel_epoch
        },
        key_tag,
        policy: need_policy.then_some(policy),
        policy_sig,
        tags: need_add.then(|| make_kernel_update_tags(sess)),
        install_sig,
    })
}

/// Остаток квоты. Первый push пишет лимит. Дальше берется меньшее из остатка и лимита.
pub(crate) fn retained_quota(
    previous: Option<u64>,
    configured: Option<u64>,
    observed_left: Option<u64>,
) -> Option<u64> {
    let configured = configured?;
    match previous {
        None => Some(configured),
        Some(prev) => Some(observed_left.unwrap_or(prev).min(configured).min(prev)),
    }
}

fn reset_kernel_binding(sess: &mut crate::session::Session) {
    sess.kernel_faulted = true;
    sess.kernel_epoch = 0;
    sess.kernel_prev_epoch = 0;
    sess.kernel_key_tag = [0u8; 8];
    sess.kernel_epoch_applied = 0;
    sess.kernel_install_sig = 0;
    sess.kernel_policy_sig = 0;
    sess.kernel_quota_up_left = None;
    sess.kernel_quota_down_left = None;
    sess.kernel_dl_window = 0;
}

pub(crate) fn kernel_clear_offload(ka: &KernelAccel, session_id: &[u8; 16]) {
    let _ = ka.session_remove(session_id);
}

pub(crate) fn kernel_push_policy(
    ka: &KernelAccel,
    sess: &mut crate::session::Session,
    policy: &SessionPolicy,
) -> std::io::Result<()> {
    let mut policy = *policy;
    let flags = policy.flags;
    let quota_up_bytes = policy.quota_up_bytes;
    let quota_down_bytes = policy.quota_down_bytes;
    let up_cfg = ((flags & POL_QUOTA_UP) != 0).then_some(quota_up_bytes);
    let down_cfg = ((flags & POL_QUOTA_DOWN) != 0).then_some(quota_down_bytes);
    let observed = if sess.kernel_quota_up_left.is_some() || sess.kernel_quota_down_left.is_some() {
        let mut sync = SessionSync::zeroed();
        sync.session_id = sess.session_id;
        sync.flags = 0;
        ka.session_sync(&mut sync)
            .ok()
            .map(|_| (sync.quota_up_left, sync.quota_down_left))
    } else {
        None
    };
    let up = retained_quota(
        sess.kernel_quota_up_left,
        up_cfg,
        observed.map(|item| item.0),
    );
    let down = retained_quota(
        sess.kernel_quota_down_left,
        down_cfg,
        observed.map(|item| item.1),
    );
    match up {
        Some(value) => policy.quota_up_bytes = value,
        None => {
            policy.flags &= !POL_QUOTA_UP;
            policy.quota_up_bytes = 0;
        }
    }
    match down {
        Some(value) => policy.quota_down_bytes = value,
        None => {
            policy.flags &= !POL_QUOTA_DOWN;
            policy.quota_down_bytes = 0;
        }
    }
    ka.session_policy(&policy)?;
    sess.kernel_quota_up_left = up;
    sess.kernel_quota_down_left = down;
    Ok(())
}

fn kernel_apply_plan(
    ka: &KernelAccel,
    sess: &mut crate::session::Session,
    plan: &KernelWirePlan,
) -> bool {
    if let Some(add) = plan.add.as_ref() {
        if ka.session_add(add).is_err() {
            if plan.rotate_to.is_some() {
                kernel_clear_offload(ka, &sess.session_id);
                reset_kernel_binding(sess);
            }
            return false;
        }
        sess.kernel_install_sig = plan.install_sig;
    }
    if let Some(epoch) = plan.rotate_to {
        if ka.replay_rotate(&sess.session_id, epoch).is_err() {
            // Новый ключ со старым окном небезопасен. Закрываем сессию
            // до нового handshake и не подменяем окно локальным.
            kernel_clear_offload(ka, &sess.session_id);
            reset_kernel_binding(sess);
            return false;
        }
        sess.kernel_prev_epoch = plan.prev_epoch;
        sess.kernel_epoch = epoch;
        sess.kernel_key_tag = plan.key_tag;
        sess.kernel_epoch_applied = epoch;
    }
    if let Some(policy) = plan.policy.as_ref() {
        if kernel_push_policy(ka, sess, policy).is_err() {
            kernel_clear_offload(ka, &sess.session_id);
            reset_kernel_binding(sess);
            return false;
        }
        sess.kernel_policy_sig = plan.policy_sig;
    }
    if let Some(tags) = plan.tags.as_ref() {
        let _ = ka.session_update_tags(tags);
    }
    if plan.add.is_some() {
        if let Some(dl) = make_kernel_downlink(sess) {
            let _ = ka.session_downlink(&dl);
        }
    }
    true
}

/// Ставит сессию, эпоху и политику.
/// false после rotate значит, что ядро снято и эпоха сброшена.
/// false после политики оставляет эпоху, но сессия не вооружена: захват все равно нужен.
pub(crate) fn kernel_maintain(
    ka: &KernelAccel,
    sess: &mut crate::session::Session,
    tag_offset: u16,
    mdh_len: u16,
    input: &KernelPolicyInput,
    refresh_policy: bool,
) -> bool {
    if sess.kernel_faulted {
        return false;
    }
    if sess.kernel_epoch == u32::MAX && sess.kernel_key_tag != kernel_key_tag(sess) {
        kernel_clear_offload(ka, &sess.session_id);
        reset_kernel_binding(sess);
        return false;
    }
    let Some(plan) = kernel_reinstall(sess, tag_offset, mdh_len, input, refresh_policy) else {
        return true;
    };
    kernel_apply_plan(ka, sess, &plan)
}

/// Захват до обработки payload. Локальное окно не заменяет этот ioctl.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplayGate {
    Deliver,
    Drop,
}

pub(crate) fn classify_claim(code: i32) -> ReplayGate {
    match code {
        CLAIM_OK => ReplayGate::Deliver,
        CLAIM_DUP | CLAIM_TOO_OLD | CLAIM_EPOCH => ReplayGate::Drop,
        _ => ReplayGate::Drop,
    }
}

/// Отказ захвата. Счетчик впереди локального окна не отмечаем, чтобы не сжечь повтор.
pub(crate) fn kernel_note_rejected(
    sess: &mut crate::session::Session,
    counter: u64,
    previous_epoch: bool,
) {
    if previous_epoch {
        sess.mark_pre_ratchet_received(counter);
        return;
    }
    if counter > sess.counter {
        return;
    }
    sess.mark_tag_received(counter);
}

pub(crate) fn kernel_claim_deliver(
    ka: Option<&KernelAccel>,
    sess: &crate::session::Session,
    counter: u64,
    previous_epoch: bool,
) -> ReplayGate {
    if sess.kernel_faulted {
        return ReplayGate::Drop;
    }
    let Some(ka) = ka else {
        return ReplayGate::Deliver;
    };
    let epoch = if previous_epoch {
        if sess.kernel_prev_epoch == 0 {
            return ReplayGate::Deliver;
        }
        sess.kernel_prev_epoch
    } else if sess.kernel_epoch == 0 {
        return ReplayGate::Deliver;
    } else {
        sess.kernel_epoch
    };
    match ka.replay_claim(&sess.session_id, epoch, counter) {
        Ok(code) => classify_claim(code),
        Err(err) if err.raw_os_error() == Some(libc::ENOENT) && sess.kernel_epoch == 0 => {
            ReplayGate::Deliver
        }
        Err(_) => ReplayGate::Drop,
    }
}

/// Общее списание. PassCharged уже списало ведро ядра, userspace его не трогает.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QosGate {
    PassCharged,
    Drop,
    Userspace,
}

pub(crate) fn classify_qos(code: i32) -> QosGate {
    match code {
        QOS_ACCEPT => QosGate::PassCharged,
        QOS_DROP => QosGate::Drop,
        QOS_FALLBACK => QosGate::Userspace,
        _ => QosGate::Drop,
    }
}

pub(crate) fn kernel_qos_decide(
    ka: Option<&KernelAccel>,
    session_id: &[u8; 16],
    dir: u32,
    nbytes: u32,
) -> QosGate {
    let Some(ka) = ka else {
        return QosGate::Userspace;
    };
    if nbytes == 0 {
        return QosGate::PassCharged;
    }
    match ka.qos_charge(session_id, dir, nbytes) {
        Ok(code) => classify_qos(code),
        Err(err) if err.raw_os_error() == Some(libc::ENOENT) => QosGate::Userspace,
        Err(_) => QosGate::Drop,
    }
}

/// Снимок счетчиков. Слияние окна только помогает локальному is_replay.
/// Гонку закрывает replay_claim, а не этот периодический снимок.
pub(crate) fn harvest_kernel_counters(
    ka: &KernelAccel,
    sess: &mut crate::session::Session,
) -> (u64, u64) {
    let mut sync = SessionSync::zeroed();
    sync.session_id = sess.session_id;
    sync.flags = SYNC_ACK_STATS;
    if ka.session_sync(&mut sync).is_err() {
        return (0, 0);
    }
    if sess.kernel_epoch != 0 && sess.kernel_epoch_applied == sess.kernel_epoch {
        sess.absorb_shared_replay(sync.replay_hi, sync.replay_words);
    }
    if sync.rx_bytes_delta != 0 {
        sess.last_seen = std::time::Instant::now();
    }
    (sync.rx_bytes_delta, sync.tx_bytes_delta)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use aivpn_common::crypto::{SessionKeys, X25519_PUBLIC_KEY_SIZE};
    use aivpn_common::kernel_accel::{
        POL_ENROLL_WAIT, POL_EXIT, POL_FALLBACK, POL_IPV6, POL_MTLS_WAIT, POL_PEER_ISOLATE,
        POL_QOS_DOWN, POL_QOS_UP, POL_QUOTA_UP, POL_SITE,
    };

    use aivpn_common::kernel_accel::{
        CLAIM_DUP, CLAIM_EPOCH, CLAIM_OK, CLAIM_TOO_OLD, QOS_ACCEPT, QOS_DROP, QOS_FALLBACK,
    };

    use super::{
        classify_claim, classify_qos, kernel_client_key, kernel_downlink_tag_pos,
        kernel_limits_for, kernel_note_rejected, kernel_reinstall, make_kernel_install,
        make_kernel_session_policy, retained_quota, KernelPolicyInput, QosGate, ReplayGate,
    };

    fn bare_session() -> crate::session::Session {
        let keys = SessionKeys {
            session_key: [1u8; 32],
            session_key_s2c: [2u8; 32],
            tag_secret: [3u8; 32],
            prng_seed: [4u8; 32],
        };
        crate::session::Session::new(
            [9u8; 16],
            "127.0.0.1:9".parse::<SocketAddr>().unwrap(),
            keys,
            [0u8; X25519_PUBLIC_KEY_SIZE],
        )
    }

    #[test]
    fn kernel_policy_follows_session_gates() {
        let mut sess = bare_session();
        let cold = make_kernel_session_policy(&sess, &KernelPolicyInput::default());
        assert_ne!(cold.flags & POL_FALLBACK, 0);
        assert_ne!(cold.flags & POL_ENROLL_WAIT, 0);
        assert_ne!(cold.flags & POL_PEER_ISOLATE, 0);
        assert_eq!(cold.flags & POL_IPV6, 0);
        assert_eq!({ cold.client_ipv4 }, 0);

        sess.vpn_ip = Some(Ipv4Addr::new(10, 0, 0, 2));
        sess.client_id = Some("client-a".into());
        let mut prefix = [0u8; 16];
        prefix[0] = 0xfd;
        prefix[1] = 0x12;
        let ready = KernelPolicyInput {
            limits_ready: true,
            allow_peer_routing: false,
            rate_up_bps: 1000,
            rate_down_bps: 0,
            quota_up_bytes: Some(50),
            max_sessions: 5,
            ipv6_prefix: Some(prefix),
            ipv6_prefix_len: 64,
            ..KernelPolicyInput::default()
        };
        let armed = make_kernel_session_policy(&sess, &ready);
        assert_eq!(armed.flags & POL_FALLBACK, 0);
        assert_eq!(armed.flags & POL_ENROLL_WAIT, 0);
        assert_ne!(armed.flags & POL_QOS_UP, 0);
        assert_eq!(armed.flags & POL_QOS_DOWN, 0);
        assert_ne!(armed.flags & POL_QUOTA_UP, 0);
        assert_ne!(armed.flags & POL_IPV6, 0);
        assert_ne!(armed.flags & POL_PEER_ISOLATE, 0);
        assert_eq!({ armed.client_ipv4 }, u32::from_ne_bytes([10, 0, 0, 2]));
        assert_eq!({ armed.max_sessions }, 5);
        assert_eq!({ armed.quota_up_bytes }, 50);
        let hash = aivpn_common::crypto::blake3_hash(b"client-a");
        assert_eq!({ armed.client_key }, hash[..16]);

        sess.mtls_ok = false;
        let blocked = make_kernel_session_policy(
            &sess,
            &KernelPolicyInput {
                limits_ready: false,
                userspace_rx: false,
                userspace_tx: false,
                revoked: false,
                exit_node: true,
                ipv6_prefix: Some(prefix),
                ipv6_prefix_len: 0,
                ..KernelPolicyInput::default()
            },
        );
        assert_ne!(blocked.flags & POL_MTLS_WAIT, 0);
        assert_ne!(blocked.flags & POL_EXIT, 0);
        assert_ne!(blocked.flags & POL_FALLBACK, 0);
        assert_eq!({ blocked.rate_up_bps }, 0);
        assert_eq!(blocked.flags & POL_IPV6, 0);

        sess.mtls_ok = true;
        sess.is_site_peer = true;
        sess.client_id = None;
        let site = make_kernel_session_policy(
            &sess,
            &KernelPolicyInput {
                limits_ready: true,
                allow_peer_routing: true,
                ..KernelPolicyInput::default()
            },
        );
        assert_ne!(site.flags & POL_SITE, 0);
        assert_eq!(site.flags & POL_ENROLL_WAIT, 0);
        assert_eq!(site.flags & POL_PEER_ISOLATE, 0);
        assert_eq!(site.client_key, [0u8; 16]);

        let mask = aivpn_common::mask::preset_masks::quic_https_v2();
        let embedded = kernel_downlink_tag_pos(&mask, 64);
        if mask.uses_embedded_layout(64) {
            assert_eq!(embedded, mask.tag_offset);
            assert_ne!(embedded, u16::MAX);
        } else {
            assert_eq!(embedded, u16::MAX);
        }
        assert_eq!(kernel_downlink_tag_pos(&mask, 0), u16::MAX);
        let install = make_kernel_install(&sess, u16::MAX, 32, &KernelPolicyInput::default());
        assert_eq!({ install.add.session_id }, sess.session_id);
        assert_eq!({ install.add.client_ip }, u32::from_ne_bytes([10, 0, 0, 2]));
        assert_eq!({ install.policy.session_id }, sess.session_id);
    }

    fn sample_client() -> crate::client_db::ClientConfig {
        let json = r#"{"id":"client-a","name":"n","psk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","vpn_ip":"10.0.0.2","enabled":true,"created_at":"2026-01-01T00:00:00Z","stats":{"bytes_in":0,"bytes_out":0,"total_connections":0}}"#;
        let mut client: crate::client_db::ClientConfig = serde_json::from_str(json).unwrap();
        client.qos = Some(crate::qos::ClientQos {
            bandwidth_limit_up: Some(1000),
            bandwidth_limit_down: Some(2000),
            ..crate::qos::ClientQos::default()
        });
        client
    }

    fn accept_plan(sess: &mut crate::session::Session, plan: &super::KernelWirePlan) {
        if let Some(epoch) = plan.rotate_to {
            sess.kernel_prev_epoch = plan.prev_epoch;
            sess.kernel_epoch = epoch;
            sess.kernel_key_tag = plan.key_tag;
            sess.kernel_epoch_applied = epoch;
        }
        if plan.add.is_some() {
            sess.kernel_install_sig = plan.install_sig;
        }
        if plan.policy.is_some() {
            sess.kernel_policy_sig = plan.policy_sig;
        }
    }

    #[test]
    fn kernel_client_key_is_blake3_prefix() {
        let key = kernel_client_key("client-a");
        let hash = aivpn_common::crypto::blake3_hash(b"client-a");
        assert_eq!(key, hash[..16]);
    }

    #[test]
    fn kernel_reinstall_rotates_on_key_and_not_on_layout() {
        let mut sess = bare_session();
        sess.vpn_ip = Some(Ipv4Addr::new(10, 0, 0, 2));
        sess.client_id = Some("client-a".into());
        let input = KernelPolicyInput {
            limits_ready: true,
            quota_up_bytes: Some(100),
            rate_up_bps: 10,
            ..KernelPolicyInput::default()
        };
        let first = kernel_reinstall(&sess, 4, 8, &input, false).unwrap();
        assert_eq!(first.rotate_to, Some(1));
        assert_eq!(first.prev_epoch, 0);
        assert!(first.add.is_some());
        assert!(first.policy.is_some());
        accept_plan(&mut sess, &first);
        assert!(kernel_reinstall(&sess, 4, 8, &input, false).is_none());

        let mut quota_only = input.clone();
        quota_only.quota_up_bytes = Some(1);
        let quota_update = kernel_reinstall(&sess, 4, 8, &quota_only, false).unwrap();
        assert!(quota_update.add.is_none());
        assert!(quota_update.rotate_to.is_none());
        assert_eq!({ quota_update.policy.unwrap().quota_up_bytes }, 1);

        sess.kernel_install_sig = 0;
        let layout = kernel_reinstall(&sess, 4, 8, &input, false).unwrap();
        assert!(layout.rotate_to.is_none());
        assert!(layout.add.is_some());
        assert_eq!(layout.prev_epoch, 1);
        accept_plan(&mut sess, &layout);

        sess.keys.session_key[0] ^= 0xff;
        let rotated = kernel_reinstall(&sess, 4, 8, &input, false).unwrap();
        assert_eq!(rotated.rotate_to, Some(2));
        assert_eq!(rotated.prev_epoch, 1);
        assert!(rotated.add.is_some());

        let mut fresh = bare_session();
        fresh.keys.session_key = [0u8; 32];
        let zero_key = kernel_reinstall(&fresh, 0, 0, &input, false).unwrap();
        assert_eq!(zero_key.rotate_to, Some(1));
        assert!(zero_key.add.is_some());
    }

    #[test]
    fn retained_quota_never_refills() {
        assert_eq!(retained_quota(None, Some(100), Some(0)), Some(100));
        assert_eq!(retained_quota(Some(80), Some(100), Some(50)), Some(50));
        assert_eq!(retained_quota(Some(80), Some(100), None), Some(80));
        assert_eq!(retained_quota(Some(80), Some(40), Some(70)), Some(40));
        assert_eq!(retained_quota(Some(80), Some(200), Some(90)), Some(80));
        assert_eq!(retained_quota(Some(80), None, Some(0)), None);
    }

    #[test]
    fn classify_claim_and_qos_codes() {
        assert_eq!(classify_claim(CLAIM_OK), ReplayGate::Deliver);
        assert_eq!(classify_claim(CLAIM_DUP), ReplayGate::Drop);
        assert_eq!(classify_claim(CLAIM_TOO_OLD), ReplayGate::Drop);
        assert_eq!(classify_claim(CLAIM_EPOCH), ReplayGate::Drop);
        assert_eq!(classify_claim(99), ReplayGate::Drop);
        assert_eq!(classify_qos(QOS_ACCEPT), QosGate::PassCharged);
        assert_eq!(classify_qos(QOS_DROP), QosGate::Drop);
        assert_eq!(classify_qos(QOS_FALLBACK), QosGate::Userspace);
        assert_eq!(classify_qos(9), QosGate::Drop);
    }

    #[test]
    fn kernel_limits_follow_client_network_and_exit() {
        let mut sess = bare_session();
        let plain = aivpn_common::network_config::VpnNetworkConfig::default();
        let cold = kernel_limits_for(&sess, None, &plain, false, false);
        assert!(!cold.limits_ready);
        assert!(cold.enroll_pending);
        assert!(cold.ipv6_prefix.is_none());

        sess.client_id = Some("client-a".into());
        sess.vpn_ip = Some(Ipv4Addr::new(10, 0, 0, 2));
        let mut client = sample_client();
        client.one_time = true;
        client.device_pubkey = None;
        let pending = kernel_limits_for(&sess, Some(&client), &plain, true, false);
        assert!(pending.limits_ready);
        assert!(pending.enroll_pending);
        assert_eq!(pending.rate_up_bps, 1000);
        assert_eq!(pending.rate_down_bps, 2000);

        client.one_time = false;
        let mut v6 = plain.clone();
        v6.ipv6_enabled = true;
        let ready = kernel_limits_for(&sess, Some(&client), &v6, false, true);
        assert_eq!(ready.ipv6_prefix_len, 48);
        assert_eq!(ready.ipv6_prefix.unwrap()[0], 0xfd);
        assert!(ready.exit_node);
        let policy = make_kernel_session_policy(&sess, &ready);
        assert_ne!(policy.flags & POL_EXIT, 0);
        assert_ne!(policy.flags & POL_PEER_ISOLATE, 0);
        assert_ne!(policy.flags & POL_IPV6, 0);
        assert_ne!(policy.flags & POL_QOS_UP, 0);
        assert_ne!(policy.flags & POL_QOS_DOWN, 0);
        assert_eq!(policy.flags & POL_ENROLL_WAIT, 0);
    }

    #[test]
    fn rejected_ahead_counter_does_not_move_window() {
        let mut sess = bare_session();
        kernel_note_rejected(&mut sess, 5, false);
        assert_eq!(sess.counter, 0);
        assert!(!sess.received_bitmap.bit_set(0));
        kernel_note_rejected(&mut sess, 0, false);
        assert_eq!(sess.counter, 0);
        assert!(sess.received_bitmap.bit_set(0));
        kernel_note_rejected(&mut sess, 7, true);
        assert!(sess.pre_ratchet_received.contains(&7));
        assert_eq!(sess.counter, 0);
    }
    #[test]
    fn packet_features_gate_only_the_required_direction() {
        use aivpn_common::kernel_accel::{POL_RX_FALLBACK, POL_TX_FALLBACK};
        let mut sess = bare_session();
        let mut input = KernelPolicyInput {
            limits_ready: true,
            ..Default::default()
        };
        assert_ne!(
            make_kernel_session_policy(&sess, &input).flags & POL_RX_FALLBACK,
            0
        );
        sess.client_packet_features = Some(aivpn_common::protocol::CLIENT_PACKET_FEATURES);
        assert_eq!(
            make_kernel_session_policy(&sess, &input).flags & POL_RX_FALLBACK,
            0
        );
        sess.client_packet_features = Some(
            aivpn_common::protocol::CLIENT_PACKET_FEATURES
                | aivpn_common::protocol::CLIENT_FEC_ACTIVE,
        );
        assert_ne!(
            make_kernel_session_policy(&sess, &input).flags & POL_RX_FALLBACK,
            0
        );
        input.userspace_tx = true;
        assert_ne!(
            make_kernel_session_policy(&sess, &input).flags & POL_TX_FALLBACK,
            0
        );
        sess.client_packet_features = Some(aivpn_common::protocol::CLIENT_PACKET_FEATURES);
        input.userspace_rx = true;
        assert_ne!(
            make_kernel_session_policy(&sess, &input).flags & POL_RX_FALLBACK,
            0
        );
    }

    #[test]
    fn lost_shared_window_never_reopens_local_replay() {
        let mut sess = bare_session();
        sess.kernel_epoch = 3;
        super::reset_kernel_binding(&mut sess);
        assert!(sess.kernel_faulted);
        assert_eq!(
            super::kernel_claim_deliver(None, &sess, 7, false),
            ReplayGate::Drop
        );
        super::reset_kernel_binding(&mut sess);
        assert!(sess.kernel_faulted);
    }

    #[test]
    fn policy_fingerprint_covers_the_full_ipv6_prefix_and_quota() {
        let sess = bare_session();
        let mut policy = make_kernel_session_policy(&sess, &KernelPolicyInput::default());
        let first = super::policy_fingerprint(&policy);
        policy.ipv6_prefix[10] = 1;
        let second = super::policy_fingerprint(&policy);
        assert_ne!(first, second);
        policy.quota_up_bytes = 123;
        assert_ne!(second, super::policy_fingerprint(&policy));
    }
}
