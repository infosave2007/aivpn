// SPDX-License-Identifier: GPL-2.0
//! dev.rs — misc device registration and ioctl dispatch for aivpn.ko
//!
//! Updated for the Linux 6.9+/7.x Rust-for-Linux API:
//!   kernel::miscdevice::{MiscDevice, MiscDeviceOptions, MiscDeviceRegistration}
//!   kernel::uaccess::UserSlice
//!   kernel::fs::File

use kernel::prelude::*;
use core::sync::atomic::{AtomicBool, Ordering};
use kernel::miscdevice::{MiscDevice, MiscDeviceOptions, MiscDeviceRegistration};
use kernel::fs::File;
use kernel::uaccess::{UserSlice, UserPtr};

// ── UAPI ioctl numbers (mirrored from include/uapi/aivpn.h) ──────────────────
// Kernel _IOC convention (asm-generic/ioctl.h): _IOC_WRITE = 1, _IOC_READ = 2.
// _IOW(0xAE, nr, size) = (1<<30)|(size<<16)|(magic<<8)|nr
// _IOR(0xAE, nr, size) = (2<<30)|(size<<16)|(magic<<8)|nr
// _IOWR = (3<<30); _IO = magic<<8|nr
// MUST stay identical to crates/aivpn-common/src/kernel_accel.rs (userspace
// side) — change both together or the production data path breaks.

const MAGIC: u32 = 0xAE;
const fn iow(nr: u32, sz: u32) -> u32  { (1 << 30) | (MAGIC << 8) | nr | (sz << 16) }
const fn ior(nr: u32, sz: u32) -> u32  { (2 << 30) | (MAGIC << 8) | nr | (sz << 16) }
const fn iowr(nr: u32, sz: u32) -> u32 { (3 << 30) | (MAGIC << 8) | nr | (sz << 16) }
const fn io(nr: u32) -> u32            { (MAGIC << 8) | nr }

// Packed struct sizes matching C definitions (see include/uapi/aivpn.h)
const IOC_SESSION_ADD:         u32 = iow(1,  192);
const IOC_SESSION_DEL:         u32 = iow(2,   16);
const IOC_SESSION_STAT:        u32 = iowr(3,  52);
const IOC_SET_TUN:             u32 = iow(4,    4);
const IOC_SET_UDP_SOCK:        u32 = iow(5,    4);
const IOC_FLUSH:               u32 = io(6);
const IOC_GET_VERSION:         u32 = ior(7,    4);
const IOC_SESSION_UPDATE_TAGS: u32 = iow(8, 4116);
const IOC_SESSION_DOWNLINK:    u32 = iow(9, 4188);
const IOC_SET_EGRESS:          u32 = iow(10,  12);
const IOC_SESSION_POLICY:      u32 = iow(11, 104);
const IOC_SESSION_SYNC:        u32 = iowr(12, 160);
const IOC_CLIENT_REVOKE:       u32 = iow(13,  16);
const IOC_REPLAY_CLAIM:        u32 = iowr(14, 40);
const IOC_REPLAY_ROTATE:       u32 = iow(15,  24);
const IOC_QOS_CHARGE:          u32 = iowr(16, 48);
const API_VERSION:             u32 = 7;

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

// CAP_NET_ADMIN = 12 (linux/capability.h)
const CAP_NET_ADMIN: i32 = 12;

// Ускоритель имеет один TUN и один UDP hook. Владение привязано к открытому fd.
static OWNER_ACTIVE: AtomicBool = AtomicBool::new(false);

// ── C helper declarations ─────────────────────────────────────────────────────

extern "C" {
    fn aivpn_session_insert(add: *const u8) -> i32;
    fn aivpn_session_remove(session_id: *const u8) -> i32;
    fn aivpn_session_stat(stat: *mut u8) -> i32;
    fn aivpn_session_tags_update(upd: *const u8) -> i32;
    fn aivpn_session_downlink_update(dl: *const u8) -> i32;
    fn aivpn_session_policy_set(pol: *const u8) -> i32;
    fn aivpn_session_sync(io: *mut u8) -> i32;
    fn aivpn_client_revoke(key: *const u8) -> i32;
    fn aivpn_session_replay_claim(io: *mut u8) -> i32;
    fn aivpn_session_replay_rotate(io: *const u8) -> i32;
    fn aivpn_session_qos_charge(io: *mut u8) -> i32;
    fn aivpn_session_flush();
    fn aivpn_session_owner_release();
    fn aivpn_tun_set_device(ifindex: u32) -> i32;
    fn aivpn_udp_hook_install_by_fd(fd: i32) -> i32;
    fn aivpn_egress_set(udp_fd: i32, tun_ifindex: u32, enable: u32) -> i32;
}

// ── Device ────────────────────────────────────────────────────────────────────

#[pin_data]
pub(crate) struct AivpnDev {
    #[pin]
    _reg: MiscDeviceRegistration<AivpnDev>,
}

impl AivpnDev {
    pub(crate) fn new() -> Result<Pin<KBox<Self>>> {
        let opts = MiscDeviceOptions {
            name: kernel::c_str!("aivpn"),
        };
        KBox::pin_init(
            try_pin_init!(AivpnDev {
                _reg <- MiscDeviceRegistration::<AivpnDev>::register(opts),
            }),
            GFP_KERNEL,
        )
    }
}

/// Convert a raw `usize` ioctl argument to `UserPtr`.
/// SAFETY: the kernel ioctl dispatcher provides this as a user-space address.
#[inline]
fn to_user_ptr(arg: usize) -> UserPtr {
    // SAFETY: UserPtr is a usize newtype; kernel guarantees arg is user-space.
    unsafe { core::mem::transmute(arg) }
}

#[vtable]
impl MiscDevice for AivpnDev {
    type Ptr = ();

    fn open(_file: &File, _reg: &MiscDeviceRegistration<AivpnDev>) -> Result<()> {
        // Restrict /dev/aivpn to CAP_NET_ADMIN processes
        if !unsafe { kernel::bindings::capable(CAP_NET_ADMIN) } {
            return Err(EPERM);
        }
        if OWNER_ACTIVE.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return Err(EBUSY);
        }
        Ok(())
    }

    fn release((): (), _file: &File) {
        // Закрытие последнего fd, в том числе после аварии, снимает все перехваты.
        unsafe { aivpn_session_owner_release() };
        OWNER_ACTIVE.store(false, Ordering::Release);
    }

    fn ioctl((): (), _file: &File, cmd: u32, arg: usize) -> Result<isize> {
        match cmd {
            n if n == IOC_SESSION_ADD => {
                let mut buf = [0u8; 192];
                UserSlice::new(to_user_ptr(arg), 192).reader().read_slice(&mut buf)?;
                kernel::error::to_result(unsafe { aivpn_session_insert(buf.as_ptr()) })?;
                Ok(0)
            }
            n if n == IOC_SESSION_DEL => {
                let mut id = [0u8; 16];
                UserSlice::new(to_user_ptr(arg), 16).reader().read_slice(&mut id)?;
                kernel::error::to_result(unsafe { aivpn_session_remove(id.as_ptr()) })?;
                Ok(0)
            }
            n if n == IOC_SESSION_STAT => {
                let mut buf = [0u8; 52];
                let (mut reader, mut writer) =
                    UserSlice::new(to_user_ptr(arg), 52).reader_writer();
                reader.read_slice(&mut buf[..16])?;
                kernel::error::to_result(unsafe { aivpn_session_stat(buf.as_mut_ptr()) })?;
                writer.write_slice(&buf)?;
                Ok(0)
            }
            n if n == IOC_SET_TUN => {
                let mut b = [0u8; 4];
                UserSlice::new(to_user_ptr(arg), 4).reader().read_slice(&mut b)?;
                kernel::error::to_result(unsafe {
                    aivpn_tun_set_device(u32::from_ne_bytes(b))
                })?;
                Ok(0)
            }
            n if n == IOC_SET_UDP_SOCK => {
                let mut b = [0u8; 4];
                UserSlice::new(to_user_ptr(arg), 4).reader().read_slice(&mut b)?;
                kernel::error::to_result(unsafe {
                    aivpn_udp_hook_install_by_fd(i32::from_ne_bytes(b))
                })?;
                Ok(0)
            }
            n if n == IOC_FLUSH => {
                unsafe { aivpn_session_flush() };
                Ok(0)
            }
            n if n == IOC_GET_VERSION => {
                UserSlice::new(to_user_ptr(arg), 4)
                    .writer()
                    .write_slice(&API_VERSION.to_ne_bytes())?;
                Ok(0)
            }
            n if n == IOC_SESSION_UPDATE_TAGS => {
                let mut buf = [0u8; 4116];
                UserSlice::new(to_user_ptr(arg), 4116)
                    .reader()
                    .read_slice(&mut buf)?;
                kernel::error::to_result(unsafe { aivpn_session_tags_update(buf.as_ptr()) })?;
                Ok(0)
            }
            n if n == IOC_SESSION_DOWNLINK => {
                let mut buf = [0u8; 4188];
                UserSlice::new(to_user_ptr(arg), 4188)
                    .reader()
                    .read_slice(&mut buf)?;
                kernel::error::to_result(unsafe { aivpn_session_downlink_update(buf.as_ptr()) })?;
                Ok(0)
            }
            n if n == IOC_SESSION_POLICY => {
                let mut buf = [0u8; 104];
                UserSlice::new(to_user_ptr(arg), 104)
                    .reader()
                    .read_slice(&mut buf)?;
                kernel::error::to_result(unsafe { aivpn_session_policy_set(buf.as_ptr()) })?;
                Ok(0)
            }
            n if n == IOC_SESSION_SYNC => {
                let mut buf = [0u8; 160];
                let (mut reader, mut writer) =
                    UserSlice::new(to_user_ptr(arg), 160).reader_writer();
                reader.read_slice(&mut buf)?;
                kernel::error::to_result(unsafe { aivpn_session_sync(buf.as_mut_ptr()) })?;
                writer.write_slice(&buf)?;
                Ok(0)
            }
            n if n == IOC_CLIENT_REVOKE => {
                let mut key = [0u8; 16];
                UserSlice::new(to_user_ptr(arg), 16)
                    .reader()
                    .read_slice(&mut key)?;
                kernel::error::to_result(unsafe { aivpn_client_revoke(key.as_ptr()) })?;
                Ok(0)
            }
            n if n == IOC_REPLAY_CLAIM => {
                let mut buf = [0u8; 40];
                let (mut reader, mut writer) =
                    UserSlice::new(to_user_ptr(arg), 40).reader_writer();
                reader.read_slice(&mut buf)?;
                kernel::error::to_result(unsafe { aivpn_session_replay_claim(buf.as_mut_ptr()) })?;
                writer.write_slice(&buf)?;
                Ok(0)
            }
            n if n == IOC_REPLAY_ROTATE => {
                let mut buf = [0u8; 24];
                UserSlice::new(to_user_ptr(arg), 24)
                    .reader()
                    .read_slice(&mut buf)?;
                kernel::error::to_result(unsafe { aivpn_session_replay_rotate(buf.as_ptr()) })?;
                Ok(0)
            }
            n if n == IOC_QOS_CHARGE => {
                let mut buf = [0u8; 48];
                let (mut reader, mut writer) =
                    UserSlice::new(to_user_ptr(arg), 48).reader_writer();
                reader.read_slice(&mut buf)?;
                kernel::error::to_result(unsafe { aivpn_session_qos_charge(buf.as_mut_ptr()) })?;
                writer.write_slice(&buf)?;
                Ok(0)
            }
            n if n == IOC_SET_EGRESS => {
                // struct aivpn_set_egress { u32 udp_fd; u32 tun_ifindex; u32 enable; }
                let mut b = [0u8; 12];
                UserSlice::new(to_user_ptr(arg), 12).reader().read_slice(&mut b)?;
                let udp_fd = i32::from_ne_bytes([b[0], b[1], b[2], b[3]]);
                let tun_ifindex = u32::from_ne_bytes([b[4], b[5], b[6], b[7]]);
                let enable = u32::from_ne_bytes([b[8], b[9], b[10], b[11]]);
                kernel::error::to_result(unsafe {
                    aivpn_egress_set(udp_fd, tun_ifindex, enable)
                })?;
                Ok(0)
            }
            _ => Err(EINVAL),
        }
    }
}
