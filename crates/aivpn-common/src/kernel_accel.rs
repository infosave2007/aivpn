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
const IOC_SESSION_DOWNLINK: u64 = iow(9, 4184);
const IOC_SET_EGRESS: u64 = iow(10, 12);

// Encoding anchors: numeric values the C _IOW/_IOR macros produce for two
// representative commands. If iow()/ior() ever drift from the kernel _IOC
// convention again, the build breaks here instead of the data path.
const _: () = assert!(IOC_SESSION_ADD == 0x40C0_AE01);
const _: () = assert!(IOC_GET_VERSION == 0x8004_AE07);

pub const API_VERSION: u32 = 5;

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

/// Payload for AIVPN_IOC_SESSION_DOWNLINK (4184 bytes).
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
    assert!(std::mem::size_of::<SessionDownlink>() == 4184);
    assert!(std::mem::size_of::<SetEgress>() == 12);
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
