//! Free builder functions that translate a userspace `Session` into the
//! plain-C payloads the kernel accelerator (`/dev/aivpn`) ioctls expect —
//! session install, downlink counter-block reservation, and tag-window
//! refresh — plus the wire-layout resolution (H7) all three share.

use std::net::SocketAddr;

use aivpn_common::crypto::{self, DEFAULT_WINDOW_MS};
use aivpn_common::kernel_accel::{
    SessionAdd, SessionDownlink, TagWindowEntry, UpdateTagsPayload, DL_MDH_MAX,
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
    if sess.is_pool_peer || sess.is_site_peer {
        // Cluster (pool/site/chain) traffic uses the fixed, mask-independent
        // framing described in `pool_sync` — never the catalog primary.
        (u16::MAX, crate::pool_sync::CLUSTER_MDH_LEN as u16)
    } else if let Some(ref mask) = sess.mask {
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
    let mdh = sess.mask.as_ref().map(packet_mdh_bytes_for_mask)?;
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

    // Safety: SessionDownlink is a plain C struct of integers and byte arrays;
    // an all-zero value is valid for every field.
    let mut dl: SessionDownlink = unsafe { std::mem::zeroed() };
    dl.session_id = sess.session_id;
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
