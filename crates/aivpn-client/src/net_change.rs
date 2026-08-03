//! Native OS network-change listener (3b).
//!
//! Best-effort push notification for "the OS just reported a network
//! interface/address change" (Wi-Fi switch, cable unplug, new default
//! route), so the client's reconnect path can react in milliseconds instead
//! of waiting on the poll-based watchdogs in `client.rs` (RX-silence tick is
//! 5 s; the underlying-source-IP carrier-change probe additionally needs two
//! consecutive disagreeing ticks, ~5-10 s).
//!
//! `spawn()` starts a platform-specific OS-level listener ONCE for the whole
//! process lifetime and returns a shared [`tokio::sync::Notify`] handle. The
//! same handle is threaded into every `AivpnClient::run()` call across
//! reconnects (via `ClientConfig::network_change_notify`) so a single OS
//! registration serves the entire process, not one per connection attempt.
//!
//! Deliberately best-effort and non-fatal: if the platform listener can't be
//! started (unsupported platform, permission denied, syscall failure), the
//! `Option` is `None` and callers fall back to the existing poll-based
//! watchdog behavior — this is a latency optimization, not a correctness
//! dependency.
//!
//! macOS already gets equivalent behavior from `NWPathMonitor` in the native
//! GUI/core layer (outside this crate) — no listener is added here for it.

use std::sync::Arc;
use tokio::sync::Notify;

/// Tell the listener which interface index belongs to the client's own TUN
/// device, so its own tunnel setup is not mistaken for the network moving.
///
/// Call with the fresh index every time a TUN is created, and with `0` when it
/// is torn down. Cheap (one relaxed atomic store) and safe to call when no
/// listener is running or on platforms that have none.
///
/// Only the Linux listener consumes this today. The Windows
/// `NotifyIpInterfaceChange` callback receives a `MIB_IPINTERFACE_ROW` it
/// currently ignores; filtering there would mean committing to that struct's
/// binary layout, which the FFI block below is already flagged as unable to
/// verify in this environment — so Windows keeps relying on the
/// `last_rx`-based guard in `client::session` plus the poll-based watchdogs.
pub fn set_own_tun_ifindex(ifindex: u32) {
    #[cfg(target_os = "linux")]
    linux_impl::set_own_tun_ifindex(ifindex);
    #[cfg(not(target_os = "linux"))]
    let _ = ifindex;
}

/// Start the best-effort native network-change listener for this platform.
/// Returns `None` when no listener is implemented for this platform, or the
/// platform-specific setup failed (logged at `debug`/`warn`, never fatal).
pub fn spawn() -> Option<Arc<Notify>> {
    #[cfg(target_os = "linux")]
    {
        linux_impl::spawn()
    }
    #[cfg(windows)]
    {
        windows_impl::spawn()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use std::mem::size_of;
    use std::sync::atomic::{AtomicU32, Ordering};

    // Multicast groups on the NETLINK_ROUTE family. Values from
    // linux/rtnetlink.h — not exposed by the `libc` crate, so declared
    // locally (same pattern as the existing raw-libc use elsewhere in this
    // crate, e.g. `bootstrap_cache.rs`'s `libc::flock`).
    const RTMGRP_LINK: u32 = 0x1; // interface up/down/added/removed
    const RTMGRP_IPV4_IFADDR: u32 = 0x10; // IPv4 address add/remove (DHCP renew, roam)
    const RTMGRP_IPV6_IFADDR: u32 = 0x100; // IPv6 address add/remove

    // rtnetlink message types delivered on the groups above (linux/rtnetlink.h).
    // These are the only ones whose payload starts with a struct carrying an
    // interface index, so they are the only ones that can be attributed to a
    // specific device.
    const RTM_NEWLINK: u16 = 16;
    const RTM_DELLINK: u16 = 17;
    const RTM_NEWADDR: u16 = 20;
    const RTM_DELADDR: u16 = 21;

    /// `struct nlmsghdr`: u32 len + u16 type + u16 flags + u32 seq + u32 pid.
    const NLMSG_HDR_LEN: usize = 16;

    /// Interface index of the TUN device this client currently owns, or 0 when
    /// no tunnel is up.
    ///
    /// Set by `Tunnel` on every create/close (see `set_own_tun_ifindex`).
    /// Process-wide because the netlink listener is a process-wide singleton
    /// spawned once by `spawn()`, while the TUN itself is recreated — under a
    /// fresh random name, hence a fresh index — on every reconnect.
    static OWN_TUN_IFINDEX: AtomicU32 = AtomicU32::new(0);

    pub fn set_own_tun_ifindex(ifindex: u32) {
        OWN_TUN_IFINDEX.store(ifindex, Ordering::Relaxed);
    }

    /// Round up to the 4-byte alignment rtnetlink pads every message to
    /// (`NLMSG_ALIGN` in linux/netlink.h).
    fn nlmsg_align(len: usize) -> usize {
        (len + 3) & !3
    }

    /// Does this netlink datagram describe a change to an interface *other*
    /// than `own_ifindex`?
    ///
    /// The client generates LINK/IFADDR events itself on every connect: the
    /// TUN is created, `ip addr replace` runs during `configure_linux()`, and
    /// runs a SECOND time from `apply_network_config()` once the server's
    /// ServerHello confirms the network config. Treating those as "the network
    /// moved" tore the session down microseconds after it came up, and the
    /// retry re-emitted them — a reconnect loop that never established.
    ///
    /// Every one of those self-inflicted events lands on the client's own TUN
    /// (`configure_linux` touches nothing else, and the Linux IPv6 blackhole
    /// is a *route*, whose group is not subscribed here), so filtering by
    /// interface index removes the whole class deterministically — no timing
    /// window, no heuristic.
    ///
    /// Anything that cannot be attributed with certainty — an unknown message
    /// type, a truncated datagram, an empty read, or `own_ifindex == 0`
    /// meaning no tunnel is up — counts as foreign, preserving the original
    /// "any datagram is the signal" behavior wherever the filter cannot prove
    /// the event is ours.
    fn has_foreign_event(buf: &[u8], own_ifindex: u32) -> bool {
        let mut offset = 0usize;
        let mut attributed_any = false;

        while offset + NLMSG_HDR_LEN <= buf.len() {
            // Both fields are native-endian, as the kernel writes them.
            let len = u32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
            let msg_type = u16::from_ne_bytes(buf[offset + 4..offset + 6].try_into().unwrap());

            // A length that is nonsensical or runs past what we read means the
            // datagram was truncated (the 4096-byte buffer in the listener) or
            // malformed — we cannot rule out a foreign event in the remainder.
            if len < NLMSG_HDR_LEN || offset + len > buf.len() {
                return true;
            }

            match msg_type {
                RTM_NEWLINK | RTM_DELLINK | RTM_NEWADDR | RTM_DELADDR => {
                    // `ifinfomsg.ifi_index` (family/pad/type = 4 bytes ahead)
                    // and `ifaddrmsg.ifa_index` (family/prefixlen/flags/scope =
                    // 4 bytes ahead) both sit at payload offset 4 and are both
                    // 4 bytes wide, so one read serves both message families.
                    let idx_at = offset + NLMSG_HDR_LEN + 4;
                    if idx_at + 4 > offset + len {
                        return true; // header promised a body it did not carry
                    }
                    let ifindex = u32::from_ne_bytes(buf[idx_at..idx_at + 4].try_into().unwrap());
                    if own_ifindex == 0 || ifindex != own_ifindex {
                        return true;
                    }
                    attributed_any = true;
                }
                // Not attributable to an interface — treat as a real change.
                _ => return true,
            }

            offset += nlmsg_align(len);
        }

        // Trailing bytes too short to hold another header, or an empty read:
        // only safe to stay quiet if everything we DID parse was our own TUN.
        !attributed_any || offset != buf.len()
    }

    #[repr(C)]
    struct sockaddr_nl {
        nl_family: libc::sa_family_t,
        nl_pad: u16,
        nl_pid: u32,
        nl_groups: u32,
    }

    pub fn spawn() -> Option<Arc<Notify>> {
        // SAFETY: standard three-syscall netlink route-socket setup
        // (socket/bind), mirroring the well-known `ip monitor` pattern. No
        // pointers escape this function except the raw fd, which is owned
        // exclusively by the spawned thread below and closed on every exit
        // path.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            tracing::debug!(
                "net_change: netlink socket() failed: {}",
                std::io::Error::last_os_error()
            );
            return None;
        }

        let mut addr: sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

        // SAFETY: `addr` is a valid, fully-initialized sockaddr_nl for the
        // duration of this call; `size_of::<sockaddr_nl>()` matches its
        // actual size (repr(C), same layout the kernel expects).
        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const sockaddr_nl as *const libc::sockaddr,
                size_of::<sockaddr_nl>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            tracing::debug!(
                "net_change: netlink bind() failed: {}",
                std::io::Error::last_os_error()
            );
            unsafe { libc::close(fd) };
            return None;
        }

        let notify = Arc::new(Notify::new());
        let notify_for_thread = notify.clone();
        let spawned = std::thread::Builder::new()
            .name("aivpn-netchange".into())
            .spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    // SAFETY: `buf` is a valid, appropriately-sized buffer
                    // for the duration of the call; `fd` is a socket owned
                    // by this thread.
                    let n = unsafe {
                        libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
                    };
                    if n <= 0 {
                        // Socket closed or errored — stop silently
                        // (best-effort listener; the poll-based watchdogs
                        // still cover reconnection).
                        break;
                    }
                    // Signal only for events on interfaces OTHER than our own
                    // TUN. The client reconfigures that device itself on every
                    // connect, and those self-inflicted events are otherwise
                    // indistinguishable from a real interface handover — see
                    // `has_foreign_event`.
                    let own = OWN_TUN_IFINDEX.load(Ordering::Relaxed);
                    if has_foreign_event(&buf[..n as usize], own) {
                        notify_for_thread.notify_one();
                    }
                }
                unsafe { libc::close(fd) };
            });
        match spawned {
            Ok(_join_handle) => {
                // Detached: the listener runs for the whole process
                // lifetime, same as the client's other background threads.
                Some(notify)
            }
            Err(e) => {
                tracing::debug!("net_change: failed to spawn netlink listener thread: {}", e);
                unsafe { libc::close(fd) };
                None
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Build one rtnetlink message: a 16-byte `nlmsghdr` followed by the
        /// first 8 bytes of `ifinfomsg`/`ifaddrmsg` — enough to carry the
        /// interface index, which both structs place at payload offset 4.
        fn msg(ty: u16, ifindex: u32) -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&((NLMSG_HDR_LEN + 8) as u32).to_ne_bytes());
            v.extend_from_slice(&ty.to_ne_bytes());
            v.extend_from_slice(&0u16.to_ne_bytes()); // nlmsg_flags
            v.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_seq
            v.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
            v.extend_from_slice(&0u32.to_ne_bytes()); // family/pad/type (or family..scope)
            v.extend_from_slice(&ifindex.to_ne_bytes());
            v
        }

        #[test]
        fn own_tun_address_event_is_not_a_network_change() {
            // The exact event `configure_linux()`'s `ip addr replace` emits on
            // the client's own TUN — the one that used to kill every session.
            assert!(!has_foreign_event(&msg(RTM_NEWADDR, 7), 7));
        }

        #[test]
        fn own_tun_link_event_is_not_a_network_change() {
            assert!(!has_foreign_event(&msg(RTM_NEWLINK, 7), 7));
        }

        #[test]
        fn event_on_another_interface_is_a_network_change() {
            assert!(has_foreign_event(&msg(RTM_NEWADDR, 3), 7));
        }

        #[test]
        fn batch_of_only_own_tun_events_is_not_a_network_change() {
            let mut buf = msg(RTM_NEWADDR, 7);
            buf.extend_from_slice(&msg(RTM_NEWLINK, 7));
            assert!(!has_foreign_event(&buf, 7));
        }

        #[test]
        fn batch_mixing_own_tun_and_foreign_interface_is_a_network_change() {
            let mut buf = msg(RTM_NEWADDR, 7);
            buf.extend_from_slice(&msg(RTM_DELLINK, 3));
            assert!(has_foreign_event(&buf, 7));
        }

        #[test]
        fn with_no_tun_registered_every_event_is_a_network_change() {
            // ifindex 0 == "no tunnel up", so nothing may be filtered — this
            // preserves the pre-filter behavior outside a live session.
            assert!(has_foreign_event(&msg(RTM_NEWADDR, 3), 0));
            assert!(has_foreign_event(&msg(RTM_DELADDR, 7), 0));
        }

        #[test]
        fn unknown_message_type_is_treated_as_a_network_change() {
            // Conservative: only LINK/ADDR messages can be attributed to an
            // interface here, so anything else must not be silently dropped.
            assert!(has_foreign_event(&msg(9999, 7), 7));
        }

        #[test]
        fn truncated_message_is_treated_as_a_network_change() {
            let mut buf = msg(RTM_NEWADDR, 7);
            // Claim a length past the end of the buffer.
            buf[0..4].copy_from_slice(&4096u32.to_ne_bytes());
            assert!(has_foreign_event(&buf, 7));
        }

        #[test]
        fn empty_datagram_is_treated_as_a_network_change() {
            assert!(has_foreign_event(&[], 7));
        }

        #[test]
        fn trailing_garbage_shorter_than_a_header_is_treated_as_a_network_change() {
            let mut buf = msg(RTM_NEWADDR, 7);
            buf.extend_from_slice(&[0u8; 3]);
            assert!(has_foreign_event(&buf, 7));
        }
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::os::raw::c_void;

    // ── Raw FFI for NotifyIpInterfaceChange (Netioapi.h, exported by
    // Iphlpapi.dll/Iphlpapi.lib) ────────────────────────────────────────────
    //
    // NOT available in the vendored `winapi` 0.3.9 crate already used by
    // this workspace (checked: `winapi::um::netioapi` does not exist in that
    // version; `winapi::um::iphlpapi` only has the legacy
    // NotifyAddrChange/NotifyRouteChange overlapped-I/O API). Declared here
    // by hand against the documented Win32 ABI instead of adding a new
    // top-level dependency (`windows`/`windows-sys`) that can't be resolved
    // or compiled in this sandbox for verification.
    //
    // Reference signature (Microsoft Learn, netioapi.h — unchanged since
    // Windows Vista):
    //   NETIOAPI_API NotifyIpInterfaceChange(
    //       ADDRESS_FAMILY Family,                       // USHORT
    //       PIPINTERFACE_CHANGE_CALLBACK Callback,        // extern "system" fn
    //       PVOID CallerContext,
    //       BOOLEAN InitialNotification,                  // u8
    //       HANDLE *NotificationHandle
    //   ) -> NETIOAPI_API;                                 // DWORD (u32) error code, NO_ERROR=0
    //
    //   typedef VOID (*PIPINTERFACE_CHANGE_CALLBACK)(
    //       PVOID CallerContext,
    //       PMIB_IPINTERFACE_ROW Row,                      // never dereferenced here —
    //       MIB_NOTIFICATION_TYPE NotificationType         // declared as an opaque pointer
    //   );                                                  // and c_int-sized enum below
    //
    // RISK NOTE (see task hand-off): this signature could not be verified
    // against a live Microsoft Learn fetch in this sandbox (network access
    // to learn.microsoft.com was blocked). It is transcribed from stable,
    // extensively-documented Win32 API surface unchanged for over a decade,
    // matching the pattern used by established crates (e.g. `if-watch`,
    // `network-interface`). Flagged for hand-review before a Windows build,
    // per the task's own instruction.
    const AF_UNSPEC: u16 = 0;

    #[link(name = "iphlpapi")]
    extern "system" {
        fn NotifyIpInterfaceChange(
            family: u16,
            callback: extern "system" fn(*mut c_void, *const c_void, i32),
            caller_context: *mut c_void,
            initial_notification: u8,
            notification_handle: *mut *mut c_void,
        ) -> u32;
    }

    // CallerContext round-trips a leaked `Arc<Notify>` clone (see `spawn()`
    // below) so the callback — invoked on an arbitrary OS worker thread, not
    // this crate's tokio runtime — can signal the reconnect path without any
    // shared mutable state.
    extern "system" fn ip_interface_change_callback(
        caller_context: *mut c_void,
        _row: *const c_void,
        _notification_type: i32,
    ) {
        if caller_context.is_null() {
            return;
        }
        // SAFETY: `caller_context` is the raw pointer produced by
        // `Arc::into_raw` in `spawn()` below, passed through unchanged by
        // the OS. Borrowed (not reconstructed into an owning `Arc`) so this
        // callback — which may fire many times over the process lifetime —
        // never decrements the refcount; the registration intentionally
        // leaks one `Arc` clone for the process lifetime (never
        // unregistered — see `spawn()`).
        let notify: &Notify = unsafe { &*(caller_context as *const Notify) };
        notify.notify_one();
    }

    pub fn spawn() -> Option<Arc<Notify>> {
        let notify = Arc::new(Notify::new());
        // Leak one strong reference for the OS callback to borrow from for
        // the process lifetime. This registration is intentionally never
        // cancelled (`CancelMibChangeNotify2` not called) — the client
        // process holds it until exit, mirroring the netlink listener
        // thread on Linux, which is also never joined/torn down.
        let ctx_arc = notify.clone();
        let ctx_ptr = Arc::into_raw(ctx_arc) as *mut c_void;

        let mut handle: *mut c_void = std::ptr::null_mut();
        // SAFETY: `ip_interface_change_callback` matches the declared
        // extern "system" fn pointer type; `ctx_ptr` stays valid for the
        // process lifetime (leaked above); `handle` is a valid out-pointer.
        let ret = unsafe {
            NotifyIpInterfaceChange(
                AF_UNSPEC,
                ip_interface_change_callback,
                ctx_ptr,
                0, // InitialNotification = FALSE — don't fire immediately on register
                &mut handle,
            )
        };
        if ret != 0 {
            tracing::debug!(
                "net_change: NotifyIpInterfaceChange failed, error code {}",
                ret
            );
            // Reclaim and drop the leaked Arc so it doesn't stay leaked
            // forever on the failure path (registration never happened, so
            // no callback will ever borrow it).
            unsafe {
                drop(Arc::from_raw(ctx_ptr as *const Notify));
            }
            return None;
        }
        Some(notify)
    }
}
