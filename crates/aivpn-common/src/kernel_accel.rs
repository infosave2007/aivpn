//! kernel_accel.rs — optional /dev/aivpn kernel-module acceleration.
//!
//! Call `KernelAccel::try_open()` at startup. Returns `None` if the module
//! is not loaded (`ENODEV`/`ENOENT`), so the caller can fall back to the
//! user-space TUN path transparently.

use std::fs::OpenOptions;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

// ── UAPI ioctl numbers (must match include/uapi/aivpn.h) ─────────────────────
// Kernel _IOC convention (asm-generic/ioctl.h): _IOC_WRITE = 1, _IOC_READ = 2.
// MUST stay identical to platforms/linux-kernel/src/dev.rs (kernel side) —
// change both together or the production data path breaks.

const MAGIC: u64 = 0xAE;
const fn iow(nr: u64, sz: u64) -> u64 {
    (1u64 << 30) | (MAGIC << 8) | nr | (sz << 16)
}
const fn ior(nr: u64, sz: u64) -> u64 {
    (2u64 << 30) | (MAGIC << 8) | nr | (sz << 16)
}
const fn iowr(nr: u64, sz: u64) -> u64 {
    (3u64 << 30) | (MAGIC << 8) | nr | (sz << 16)
}
const fn io_(nr: u64) -> u64 {
    (MAGIC << 8) | nr
}

const IOC_SESSION_ADD: u64 = iow(1, 192);
const IOC_SESSION_DEL: u64 = iow(2, 16);
#[allow(dead_code)]
const IOC_SESSION_STAT: u64 = iowr(3, 52);
const IOC_SET_TUN: u64 = iow(4, 4);
const IOC_SET_UDP_SOCK: u64 = iow(5, 4);
const IOC_FLUSH: u64 = io_(6);
const IOC_GET_VERSION: u64 = ior(7, 4);
const IOC_SESSION_UPDATE_TAGS: u64 = iow(8, 4116);
const IOC_SESSION_DOWNLINK: u64 = iow(9, 4188);
const IOC_SET_EGRESS: u64 = iow(10, 12);
const IOC_SESSION_POLICY: u64 = iow(11, 104);
const IOC_SESSION_SYNC: u64 = iowr(12, 160);
const IOC_CLIENT_REVOKE: u64 = iow(13, 16);
const IOC_REPLAY_CLAIM: u64 = iowr(14, 40);
const IOC_REPLAY_ROTATE: u64 = iow(15, 24);
const IOC_QOS_CHARGE: u64 = iowr(16, 48);

// Encoding anchors: numeric values the C _IOW/_IOR macros produce for two
// representative commands. If iow()/ior() ever drift from the kernel _IOC
// convention again, the build breaks here instead of the data path.
const _: () = assert!(IOC_SESSION_ADD == 0x40C0_AE01);
const _: () = assert!(IOC_GET_VERSION == 0x8004_AE07);
const _: () = assert!(IOC_SESSION_POLICY == 0x4068_AE0B);
const _: () = assert!(IOC_SESSION_SYNC == 0xC0A0_AE0C);
const _: () = assert!(IOC_CLIENT_REVOKE == 0x4010_AE0D);
const _: () = assert!(IOC_SESSION_DOWNLINK == 0x505C_AE09);
const _: () = assert!(IOC_REPLAY_CLAIM == 0xC028_AE0E);
const _: () = assert!(IOC_REPLAY_ROTATE == 0x4018_AE0F);
const _: () = assert!(IOC_QOS_CHARGE == 0xC030_AE10);

pub const API_VERSION: u32 = 7;

pub const POLICY_VERSION: u32 = 1;
pub const ROLE_NONE: u32 = 0;
pub const ROLE_SERVER: u32 = 1;
pub const ROLE_CLIENT: u32 = 2;

pub const POL_IPV6: u32 = 1 << 0;
pub const POL_PEER_ISOLATE: u32 = 1 << 1;
pub const POL_QOS_UP: u32 = 1 << 2;
pub const POL_QOS_DOWN: u32 = 1 << 3;
pub const POL_QUOTA_UP: u32 = 1 << 4;
pub const POL_QUOTA_DOWN: u32 = 1 << 5;
pub const POL_REVOKED: u32 = 1 << 6;
pub const POL_FALLBACK: u32 = 1 << 7;
pub const POL_MTLS_WAIT: u32 = 1 << 8;
pub const POL_EXIT: u32 = 1 << 9;
pub const POL_ENROLL_WAIT: u32 = 1 << 10;
pub const POL_SITE: u32 = 1 << 11;
/// Явное пополнение квоты. Обычный refresh не увеличивает остаток.
pub const POL_QUOTA_RESET: u32 = 1 << 12;
/// Data с FEC остается в userspace; прочие направления могут ускоряться.
pub const POL_RX_FALLBACK: u32 = 1 << 13;
pub const POL_TX_FALLBACK: u32 = 1 << 14;

pub const REPLAY_WORDS: usize = 8;
pub const REPLAY_BITS: u64 = 512;
pub const SYNC_PUSH_REPLAY: u32 = 1;
pub const SYNC_ACK_STATS: u32 = 2;

pub const CLAIM_OK: i32 = 0;
pub const CLAIM_DUP: i32 = 1;
pub const CLAIM_TOO_OLD: i32 = 2;
pub const CLAIM_EPOCH: i32 = 3;
pub const CLAIM_FALLBACK: i32 = 4;

pub const QOS_ACCEPT: i32 = 0;
pub const QOS_DROP: i32 = 1;
pub const QOS_FALLBACK: i32 = 2;
pub const QOS_DIR_UP: u32 = 0;
pub const QOS_DIR_DOWN: u32 = 1;

/// Max MDH (mask header) bytes the kernel downlink path carries inline. Must
/// match `AIVPN_DL_MDH_MAX` in include/uapi/aivpn.h. A session whose downlink
/// MDH exceeds this is simply not armed for kernel downlink.
pub const DL_MDH_MAX: usize = 64;

// ── Wire structs (packed, matching C structs in include/uapi/aivpn.h) ─────────

/// Payload for AIVPN_IOC_SESSION_ADD (192 bytes).
///
/// `session_key` is the c2s (uplink) key the kernel decrypts; `session_key_s2c`
/// is the s2c (downlink) key used by kernel downlink encryption.
///
/// `tag_offset`/`mdh_len` select the Variant A wire layout so the kernel can
/// locate the resonance tag and the ciphertext start: `tag_offset == u16::MAX`
/// means legacy (tag prefixed at offset 0, ciphertext at `TAG_SIZE + mdh_len`);
/// any other value means the tag is embedded at that header byte offset and the
/// ciphertext starts at `mdh_len`.
#[repr(C, packed)]
pub struct SessionAdd {
    pub session_id: [u8; 16],
    pub session_key: [u8; 32],     // c2s uplink key
    pub session_key_s2c: [u8; 32], // s2c downlink key
    pub tag_secret: [u8; 32],
    pub nonce_suffix: [u8; 4], // bytes 8-11 of the 12-byte ChaCha20 nonce
    pub tag_offset: u16,
    pub mdh_len: u16,
    pub _reserved: [u8; 24],
    pub counter_base: u64,
    pub client_ip: u32,
    pub client_addr: [u8; 28],
    pub window_ms: u64,
}

/// One (tag, counter) pair in a tag-window batch.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct TagWindowEntry {
    pub tag: [u8; 8],
    pub counter: u64,
}

/// Payload for AIVPN_IOC_SESSION_UPDATE_TAGS (4116 bytes).
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct UpdateTagsPayload {
    pub session_id: [u8; 16],
    pub count: u32,
    pub entries: [TagWindowEntry; 256],
}

/// Данные AIVPN_IOC_SESSION_DOWNLINK, 4188 байт.
///
/// Arms/refreshes the kernel downlink fast path: `entries` are a block of
/// (tag, counter) pairs the server has RESERVED exclusively for the kernel by
/// advancing its own `send_counter` past them, so the kernel can use each
/// counter as an s2c AEAD nonce with no risk of colliding with a user-space
/// downlink packet. `mdh`/`mdh_len` carry the mask header the kernel prepends.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct SessionDownlink {
    pub session_id: [u8; 16],
    pub mdh_len: u16,
    pub seq_base: u16,
    pub count: u32,
    pub mdh: [u8; DL_MDH_MAX],
    pub entries: [TagWindowEntry; 256],
    /// 0xFFFF: tag перед mdh. Иное значение: tag внутри mdh. Ноль это встройка, не legacy.
    pub dl_tag_pos: u16,
    pub _pad_dl: u16,
}

/// Политика сессии. client_ipv4 это сырые байты адреса в порядке iph->saddr.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct SessionPolicy {
    pub session_id: [u8; 16],
    pub policy_version: u32,
    pub role: u32,
    pub flags: u32,
    pub client_ipv4: u32,
    pub ipv6_prefix: [u8; 16],
    pub ipv6_prefix_len: u8,
    pub _pad: [u8; 3],
    pub rate_up_bps: u64,
    pub rate_down_bps: u64,
    pub quota_up_bytes: u64,
    pub quota_down_bytes: u64,
    pub max_sessions: u32,
    pub client_key: [u8; 16],
}

impl SessionPolicy {
    pub fn zeroed() -> Self {
        // Простая C структура из чисел и массивов байт. Ноль допустим для каждого поля.
        unsafe { std::mem::zeroed() }
    }
}

/// Окно текущей эпохи и дельта байт. Слова replay это родные u64.
/// PUSH ядро игнорирует: захват счетчика делает replay_claim.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct SessionSync {
    pub session_id: [u8; 16],
    pub flags: u32,
    pub _pad: u32,
    pub replay_hi: u64,
    pub replay_words: [u64; REPLAY_WORDS],
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_bytes_delta: u64,
    pub tx_bytes_delta: u64,
    pub quota_up_left: u64,
    pub quota_down_left: u64,
}

impl SessionSync {
    pub fn zeroed() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct ClientRevoke {
    pub client_key: [u8; 16],
}

/// Атомарный захват счетчика. result заполняет ядро.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct ReplayClaim {
    pub session_id: [u8; 16],
    pub epoch: u32,
    pub _pad: u32,
    pub counter: u64,
    pub result: i32,
    pub _pad2: u32,
}

/// Смена эпохи. Та же эпоха оставляет окно, меньшая отклоняется.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct ReplayRotate {
    pub session_id: [u8; 16],
    pub epoch: u32,
    pub _pad: u32,
}

/// Общее списание QoS. result: ACCEPT, DROP или FALLBACK.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct QosCharge {
    pub session_id: [u8; 16],
    pub dir: u32,
    pub nbytes: u32,
    pub result: i32,
    pub _pad: u32,
    pub tokens_left: u64,
    pub quota_left: u64,
}

/// Payload for AIVPN_IOC_SET_EGRESS (12 bytes).
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct SetEgress {
    pub udp_fd: u32,
    pub tun_ifindex: u32,
    pub enable: u32,
}

// The ioctl numbers above bake in the packed struct sizes; a field change that
// altered these would silently corrupt every ioctl. Pin them at compile time.
const _: () = {
    assert!(std::mem::size_of::<SessionAdd>() == 192);
    assert!(std::mem::size_of::<UpdateTagsPayload>() == 4116);
    assert!(std::mem::size_of::<SessionDownlink>() == 4188);
    assert!(std::mem::size_of::<SetEgress>() == 12);
    assert!(std::mem::size_of::<SessionPolicy>() == 104);
    assert!(std::mem::size_of::<SessionSync>() == 160);
    assert!(std::mem::size_of::<ClientRevoke>() == 16);
    assert!(std::mem::size_of::<ReplayClaim>() == 40);
    assert!(std::mem::size_of::<ReplayRotate>() == 24);
    assert!(std::mem::size_of::<QosCharge>() == 48);
};

// ── KernelAccel handle ────────────────────────────────────────────────────────

pub struct KernelAccel {
    file: std::fs::File,
}

impl KernelAccel {
    /// Returns `None` if `/dev/aivpn` is absent (module not loaded).
    pub fn try_open() -> Option<Self> {
        match OpenOptions::new().read(true).write(true).open("/dev/aivpn") {
            Ok(f) => {
                let ka = KernelAccel { file: f };
                match ka.api_version() {
                    Ok(v) if v == API_VERSION => Some(ka),
                    Ok(v) => {
                        tracing::warn!("aivpn: kernel module API version mismatch (got {v}, want {API_VERSION}) — using user-space path");
                        None
                    }
                    Err(e) => {
                        tracing::warn!(
                            "aivpn: GET_VERSION ioctl failed: {e} — using user-space path"
                        );
                        None
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) if e.raw_os_error() == Some(libc::ENODEV) => None,
            Err(e) => {
                tracing::warn!("aivpn: open /dev/aivpn failed: {e} — using user-space path");
                None
            }
        }
    }

    fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    pub fn api_version(&self) -> io::Result<u32> {
        // The kernel WRITES the version into this word (IOC_GET_VERSION is an
        // _IOR). It must be `mut` and passed through a `*mut` pointer: with an
        // immutable `let v` + `&v as *const`, release-mode LLVM is free to
        // assume `v` never changes across the opaque ioctl call and constant-
        // fold the return to the initializer (0), which silently reported an API
        // mismatch and disabled kernel acceleration in optimized builds.
        let mut v: u32 = 0;
        ioctl_mut(self.fd(), IOC_GET_VERSION, &mut v)?;
        Ok(v)
    }

    /// Install a session into the kernel accelerator.
    pub fn session_add(&self, add: &SessionAdd) -> io::Result<()> {
        ioctl_ref(self.fd(), IOC_SESSION_ADD, add)?;
        Ok(())
    }

    /// Push a batch of (tag, counter) pairs for the given session.
    pub fn session_update_tags(&self, payload: &UpdateTagsPayload) -> io::Result<()> {
        ioctl_ref(self.fd(), IOC_SESSION_UPDATE_TAGS, payload)?;
        Ok(())
    }

    /// Remove a session by its 16-byte session_id.
    pub fn session_remove(&self, session_id: &[u8; 16]) -> io::Result<()> {
        ioctl_ref(self.fd(), IOC_SESSION_DEL, session_id)?;
        Ok(())
    }

    /// Arm (or refresh) the kernel downlink fast path for a session with a
    /// reserved counter block + MDH template.
    pub fn session_downlink(&self, dl: &SessionDownlink) -> io::Result<()> {
        ioctl_ref(self.fd(), IOC_SESSION_DOWNLINK, dl)?;
        Ok(())
    }

    /// Enable or disable the kernel downlink egress hook. `udp_fd` is the server
    /// UDP socket downlink datagrams are transmitted from; `tun_ifindex` scopes
    /// interception to that TUN device (0 = match on dst IP only).
    pub fn set_egress(&self, udp_fd: RawFd, tun_ifindex: u32, enable: bool) -> io::Result<()> {
        let payload = SetEgress {
            udp_fd: udp_fd as u32,
            tun_ifindex,
            enable: enable as u32,
        };
        ioctl_ref(self.fd(), IOC_SET_EGRESS, &payload)?;
        Ok(())
    }

    /// Point the kernel accelerator at a TUN interface by its ifindex.
    pub fn set_tun(&self, ifindex: u32) -> io::Result<()> {
        ioctl_ref(self.fd(), IOC_SET_TUN, &ifindex)?;
        Ok(())
    }

    /// Point the kernel accelerator at an existing UDP socket by fd.
    pub fn set_udp_sock(&self, udp_fd: RawFd) -> io::Result<()> {
        let fd_as_u32 = udp_fd as u32;
        ioctl_ref(self.fd(), IOC_SET_UDP_SOCK, &fd_as_u32)?;
        Ok(())
    }

    /// Flush all sessions from the kernel table.
    pub fn flush(&self) -> io::Result<()> {
        ioctl_void(self.fd(), IOC_FLUSH)?;
        Ok(())
    }

    /// Установить политику. Не сбрасывает replay на стороне ядра.
    pub fn session_policy(&self, policy: &SessionPolicy) -> io::Result<()> {
        ioctl_ref(self.fd(), IOC_SESSION_POLICY, policy)?;
        Ok(())
    }

    /// Прочитать окно текущей эпохи и счетчики. Ядро пишет ответ в тот же буфер.
    /// PUSH не сливает bitmap: граница replay это replay_claim.
    pub fn session_sync(&self, sync: &mut SessionSync) -> io::Result<()> {
        ioctl_mut(self.fd(), IOC_SESSION_SYNC, sync)?;
        Ok(())
    }

    /// Отозвать все сессии с ненулевым ключом клиента.
    pub fn client_revoke(&self, client_key: &[u8; 16]) -> io::Result<()> {
        let payload = ClientRevoke {
            client_key: *client_key,
        };
        ioctl_ref(self.fd(), IOC_CLIENT_REVOKE, &payload)?;
        Ok(())
    }

    /// Захватить счетчик в текущей или предыдущей эпохе. Возвращает код CLAIM_*.
    pub fn replay_claim(&self, session_id: &[u8; 16], epoch: u32, counter: u64) -> io::Result<i32> {
        let mut payload = ReplayClaim {
            session_id: *session_id,
            epoch,
            _pad: 0,
            counter,
            result: 0,
            _pad2: 0,
        };
        ioctl_mut(self.fd(), IOC_REPLAY_CLAIM, &mut payload)?;
        Ok(payload.result)
    }

    /// Привязать эпоху. Эпоха 0 и откат назад возвращают ошибку ioctl.
    pub fn replay_rotate(&self, session_id: &[u8; 16], epoch: u32) -> io::Result<()> {
        let payload = ReplayRotate {
            session_id: *session_id,
            epoch,
            _pad: 0,
        };
        ioctl_ref(self.fd(), IOC_REPLAY_ROTATE, &payload)?;
        Ok(())
    }

    /// Списать общий бюджет. Возвращает код QOS_*.
    pub fn qos_charge(&self, session_id: &[u8; 16], dir: u32, nbytes: u32) -> io::Result<i32> {
        let mut payload = QosCharge {
            session_id: *session_id,
            dir,
            nbytes,
            result: 0,
            _pad: 0,
            tokens_left: 0,
            quota_left: 0,
        };
        ioctl_mut(self.fd(), IOC_QOS_CHARGE, &mut payload)?;
        Ok(payload.result)
    }
}

fn replay_marked(hi: u64, words: &[u64; REPLAY_WORDS], counter: u64) -> bool {
    if counter > hi {
        return false;
    }
    let diff = hi - counter;
    if diff >= REPLAY_BITS {
        return false;
    }
    let bit = (diff % 64) as u32;
    ((words[(diff / 64) as usize] >> bit) & 1) == 1
}

/// То же слияние, что aivpn_replay_merge в policy.h. Пустое окно остается пустым.
pub fn merge_replay_window(
    hi: &mut u64,
    words: &mut [u64; REPLAY_WORDS],
    other_hi: u64,
    other: &[u64; REPLAY_WORDS],
) {
    let new_hi = (*hi).max(other_hi);
    let mut out = [0u64; REPLAY_WORDS];
    for i in 0..REPLAY_BITS {
        if new_hi < i {
            break;
        }
        let counter = new_hi - i;
        if replay_marked(*hi, words, counter) || replay_marked(other_hi, other, counter) {
            out[(i / 64) as usize] |= 1u64 << (i % 64);
        }
    }
    *words = out;
    *hi = new_hi;
}

/// Дельта абсолютного счетчика. Повтор снимка до ack дает ту же дельту.
pub fn account_byte_delta(absolute: u64, synced: u64) -> u64 {
    absolute.saturating_sub(synced)
}

impl Drop for KernelAccel {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

// ── XDP early-filter helpers (Linux-only, independent of /dev/aivpn) ─────────

/// Find the compiled XDP BPF program (`xdp_prog.o`).
/// Searches next to the running binary first, then standard install paths.
#[cfg(target_os = "linux")]
pub fn xdp_find_prog() -> Option<std::path::PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("xdp_prog.o");
            if p.exists() {
                return Some(p);
            }
        }
    }
    for path in &[
        "/usr/lib/aivpn/xdp_prog.o",
        "/usr/local/lib/aivpn/xdp_prog.o",
    ] {
        let p = std::path::Path::new(path);
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    None
}

/// Return the network interface carrying the default IPv4 route.
#[cfg(target_os = "linux")]
pub fn xdp_default_iface() -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut iter = text.split_whitespace();
    while let Some(w) = iter.next() {
        if w == "dev" {
            return iter.next().map(str::to_string);
        }
    }
    None
}

/// Attach the XDP early-filter to `ifname` and configure the BPF map.
///
/// Requires `xdp_prog.o` (see [`xdp_find_prog`]), `iproute2 >= 5.17` for
/// `pinmaps`, and bpffs mounted at `/sys/fs/bpf`.  All failures are soft:
/// the VPN continues without XDP if this returns an error.
#[cfg(target_os = "linux")]
pub fn xdp_attach(ifname: &str, port: u16, window_ms: u64) -> io::Result<()> {
    use std::process::Command;
    use tracing::{info, warn};

    const BPF_PIN_DIR: &str = "/sys/fs/bpf/aivpn";

    let prog = xdp_find_prog()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "xdp_prog.o not found"))?;

    let _ = std::fs::create_dir_all(BPF_PIN_DIR);

    let status = Command::new("ip")
        .args([
            "link",
            "set",
            "dev",
            ifname,
            "xdp",
            "obj",
            prog.to_str().unwrap_or(""),
            "sec",
            "xdp",
            "pinmaps",
            BPF_PIN_DIR,
        ])
        .status()?;
    if !status.success() {
        return Err(io::Error::other("ip link xdp attach failed"));
    }

    // Update BPF map: key 0 = VPN port, key 1 = acceptance window (ms)
    let map_path = format!("{BPF_PIN_DIR}/xdp_config");
    match bpf_obj_get(&map_path) {
        Ok(map_fd) => {
            use std::os::unix::io::AsRawFd;
            let fd = map_fd.as_raw_fd();
            if let Err(e) = bpf_map_update_u64(fd, 0, port as u64) {
                warn!("XDP: failed to set port in BPF map: {e}");
            }
            if let Err(e) = bpf_map_update_u64(fd, 1, window_ms) {
                warn!("XDP: failed to set window_ms in BPF map: {e}");
            }
        }
        Err(e) => {
            warn!("XDP: could not open pinned map {map_path}: {e} — filter active with defaults");
        }
    }

    info!("XDP early-filter attached to {ifname} (port={port}, window={window_ms}ms)");
    Ok(())
}

/// Detach the XDP program from `ifname` and remove the pinned BPF map.
#[cfg(target_os = "linux")]
pub fn xdp_detach(ifname: &str) {
    use std::process::Command;
    use tracing::info;

    let _ = Command::new("ip")
        .args(["link", "set", "dev", ifname, "xdp", "off"])
        .status();
    let _ = std::fs::remove_file("/sys/fs/bpf/aivpn/xdp_config");
    info!("XDP early-filter detached from {ifname}");
}

// ── BPF syscall helpers ───────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn bpf_obj_get(path: &str) -> io::Result<std::os::unix::io::OwnedFd> {
    use std::os::unix::io::FromRawFd;
    let cpath =
        std::ffi::CString::new(path).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // BPF_OBJ_GET = 7; attr layout: { pathname: u64, bpf_fd: u32, file_flags: u32 }
    #[repr(C, align(8))]
    struct Attr {
        pathname: u64,
        bpf_fd: u32,
        file_flags: u32,
    }
    let attr = Attr {
        pathname: cpath.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            7i32,
            &attr as *const Attr as *const (),
            std::mem::size_of::<Attr>() as u32,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { std::os::unix::io::OwnedFd::from_raw_fd(fd as i32) })
    }
}

#[cfg(target_os = "linux")]
fn bpf_map_update_u64(map_fd: i32, key: u32, value: u64) -> io::Result<()> {
    // BPF_MAP_UPDATE_ELEM = 2; attr: { map_fd: u32, pad: u32, key ptr: u64, value ptr: u64, flags: u64 }
    #[repr(C, align(8))]
    struct Attr {
        map_fd: u32,
        pad: u32,
        key: u64,
        value: u64,
        flags: u64,
    }
    let k = key;
    let v = value;
    let attr = Attr {
        map_fd: map_fd as u32,
        pad: 0,
        key: &k as *const u32 as u64,
        value: &v as *const u64 as u64,
        flags: 0,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            2i32,
            &attr as *const Attr as *const (),
            std::mem::size_of::<Attr>() as u32,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ── ioctl helpers ─────────────────────────────────────────────────────────────

fn ioctl_ref<T>(fd: RawFd, cmd: u64, arg: &T) -> io::Result<i32> {
    let ret = unsafe { libc::ioctl(fd, cmd as _, arg as *const T) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Like [`ioctl_ref`] but for ioctls where the kernel WRITES back into `arg`
/// (an `_IOR`/`_IOWR`). Passing a `*mut` from a `&mut` forces the optimizer to
/// treat the value as clobbered by the call and reload it afterwards; a
/// `*const` from `&` would let LLVM keep a stale copy in optimized builds.
fn ioctl_mut<T>(fd: RawFd, cmd: u64, arg: &mut T) -> io::Result<i32> {
    let ret = unsafe { libc::ioctl(fd, cmd as _, arg as *mut T) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn ioctl_void(fd: RawFd, cmd: u64) -> io::Result<i32> {
    let ret = unsafe { libc::ioctl(fd, cmd as _, 0usize) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

#[cfg(test)]
mod abi_tests {
    use super::*;

    fn field_off<T>(base: *const T, field: *const u8) -> usize {
        (field as usize).wrapping_sub(base as usize)
    }

    #[test]
    fn policy_layout_matches_uapi() {
        let p = SessionPolicy::zeroed();
        let base = &p as *const SessionPolicy;
        assert_eq!(std::mem::size_of::<SessionPolicy>(), 104);
        assert_eq!(
            field_off(base, std::ptr::addr_of!(p.policy_version).cast()),
            16
        );
        assert_eq!(field_off(base, std::ptr::addr_of!(p.role).cast()), 20);
        assert_eq!(field_off(base, std::ptr::addr_of!(p.flags).cast()), 24);
        assert_eq!(
            field_off(base, std::ptr::addr_of!(p.client_ipv4).cast()),
            28
        );
        assert_eq!(
            field_off(base, std::ptr::addr_of!(p.ipv6_prefix).cast()),
            32
        );
        assert_eq!(
            field_off(base, std::ptr::addr_of!(p.ipv6_prefix_len).cast()),
            48
        );
        assert_eq!(
            field_off(base, std::ptr::addr_of!(p.rate_up_bps).cast()),
            52
        );
        assert_eq!(
            field_off(base, std::ptr::addr_of!(p.rate_down_bps).cast()),
            60
        );
        assert_eq!(
            field_off(base, std::ptr::addr_of!(p.quota_up_bytes).cast()),
            68
        );
        assert_eq!(
            field_off(base, std::ptr::addr_of!(p.quota_down_bytes).cast()),
            76
        );
        assert_eq!(
            field_off(base, std::ptr::addr_of!(p.max_sessions).cast()),
            84
        );
        assert_eq!(field_off(base, std::ptr::addr_of!(p.client_key).cast()), 88);

        let s = SessionSync::zeroed();
        let sb = &s as *const SessionSync;
        assert_eq!(std::mem::size_of::<SessionSync>(), 160);
        assert_eq!(field_off(sb, std::ptr::addr_of!(s.replay_hi).cast()), 24);
        assert_eq!(field_off(sb, std::ptr::addr_of!(s.replay_words).cast()), 32);
        assert_eq!(field_off(sb, std::ptr::addr_of!(s.rx_packets).cast()), 96);
        assert_eq!(
            field_off(sb, std::ptr::addr_of!(s.quota_down_left).cast()),
            152
        );
        assert_eq!(std::mem::size_of::<SessionDownlink>(), 4188);
        assert_eq!(std::mem::size_of::<ReplayClaim>(), 40);
        assert_eq!(std::mem::size_of::<ReplayRotate>(), 24);
        assert_eq!(std::mem::size_of::<QosCharge>(), 48);
        assert_eq!(API_VERSION, 7);
    }

    #[test]
    fn replay_merge_matches_shared_vectors() {
        let mut hi = 5u64;
        let mut words = [1u64, 0, 0, 0, 0, 0, 0, 0];
        let other = [1u64, 0, 0, 0, 0, 0, 0, 0];
        merge_replay_window(&mut hi, &mut words, 3, &other);
        assert_eq!(hi, 5);
        assert_eq!(words[0] & 1, 1);
        assert_eq!(words[0] & 4, 4);

        let mut empty_hi = 0u64;
        let mut empty = [0u64; 8];
        merge_replay_window(&mut empty_hi, &mut empty, 0, &[0u64; 8]);
        assert_eq!(empty_hi, 0);
        assert_eq!(empty, [0u64; 8]);
    }

    #[test]
    fn account_delta_is_idempotent_until_ack() {
        assert_eq!(account_byte_delta(100, 40), 60);
        assert_eq!(account_byte_delta(100, 40), 60);
        assert_eq!(account_byte_delta(100, 100), 0);
        assert_eq!(account_byte_delta(10, 40), 0);
    }
}
