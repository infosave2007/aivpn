//! Читает счетчики причин отбрасывания пакетов из карты XDP.
//!
//! When xdp_prog.o is absent (maps not pinned) the observer is a no-op; the
//! server runs fully without it.
//!
//! ## Map layout (defined in xdp_prog.c)
//! `/sys/fs/bpf/aivpn/drop_stats`  — BPF_MAP_TYPE_ARRAY, 4 u64 slots:
//!   0 = DROP_TOO_SHORT, 1 = DROP_TAG_EXPIRED, 2 = reserved, 3 = TOTAL
//!

use portable_atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use aivpn_common::event_log::{AivpnEvent, EventBus, XdpDropReason};

pub struct EbpfObserver {
    events: EventBus,
    poll_interval: Duration,
    /// Предыдущие значения счетчиков причин, отдельно для каждой карты.
    prev_drop_counts: [AtomicU64; 2],
}

impl EbpfObserver {
    pub fn new(events: EventBus) -> Self {
        Self {
            events,
            poll_interval: Duration::from_millis(500),
            prev_drop_counts: [AtomicU64::new(0), AtomicU64::new(0)],
        }
    }

    /// Spawn background polling task.  No-op if BPF maps are unavailable.
    pub fn start(self: Arc<Self>) {
        tokio::spawn(async move {
            self.run_loop().await;
        });
    }

    pub(crate) async fn run_loop(&self) {
        #[cfg(target_os = "linux")]
        {
            const STATS_PATH: &str = "/sys/fs/bpf/aivpn/drop_stats";
            if !std::path::Path::new(STATS_PATH).exists() {
                debug!(
                    "BPF drop_stats map not found at {} — eBPF observer inactive \
                     (load aivpn-linux-kernel XDP module to enable)",
                    STATS_PATH
                );
                return;
            }
            info!(
                "eBPF observer active — polling {} every {:?}",
                STATS_PATH, self.poll_interval
            );
            let mut ticker = tokio::time::interval(self.poll_interval);
            loop {
                ticker.tick().await;
                self.drain_stats();
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            debug!("eBPF observer not supported on this platform");
        }
    }

    fn take_drop_delta(&self, index: usize, total: u64) -> u64 {
        let previous = self.prev_drop_counts[index].swap(total, Ordering::Relaxed);
        total.checked_sub(previous).unwrap_or(total)
    }

    /// Событие содержит прирост счетчика своей причины, включая сброс карты.
    #[cfg(target_os = "linux")]
    fn drain_stats(&self) {
        let fd = match bpf_sys::pinned_map_fd("/sys/fs/bpf/aivpn/drop_stats") {
            Some(fd) => fd,
            None => return,
        };

        let counts = [
            bpf_sys::map_lookup_u64(fd, 0),
            bpf_sys::map_lookup_u64(fd, 1),
        ];
        unsafe { libc::close(fd) };
        for (index, reason) in [XdpDropReason::TooShort, XdpDropReason::WindowExpired]
            .into_iter()
            .enumerate()
        {
            let Some(total) = counts[index] else {
                warn!(index, "Не удалось прочитать счетчик XDP");
                continue;
            };
            let delta = self.take_drop_delta(index, total);
            if delta != 0 {
                self.events.emit(AivpnEvent::XdpDrop {
                    reason,
                    count: delta,
                });
            }
        }
    }
}

/// Raw BPF syscall helpers using the `libc` crate already in scope.
/// No additional crate dependencies required.
#[cfg(target_os = "linux")]
mod bpf_sys {
    use std::ffi::CString;
    use std::os::unix::io::RawFd;

    const BPF_MAP_LOOKUP_ELEM: i64 = 1;
    const BPF_OBJ_GET: i64 = 7;
    const BPF_OBJ_GET_INFO_BY_FD: i64 = 15;

    #[repr(C)]
    struct BpfAttrInfo {
        bpf_fd: u32,
        info_len: u32,
        info: u64,
    }

    fn scalar_array(info: &[u32; 6]) -> bool {
        info[0] == 2 && info[2] == 4 && info[3] == 8
    }

    fn compatible_map(fd: RawFd) -> bool {
        // Первые шесть полей bpf_map_info из linux/bpf.h.
        let mut info = [0u32; 6];
        let attr = BpfAttrInfo {
            bpf_fd: fd as u32,
            info_len: std::mem::size_of_val(&info) as u32,
            info: info.as_mut_ptr() as u64,
        };
        let result = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_OBJ_GET_INFO_BY_FD,
                &attr as *const BpfAttrInfo as *const libc::c_void,
                std::mem::size_of::<BpfAttrInfo>() as libc::c_uint,
            )
        };
        result == 0 && scalar_array(&info)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn lookup_requires_exact_scalar_array_layout() {
            assert!(scalar_array(&[2, 1, 4, 8, 4, 0]));
            for (kind, key, value) in [(6, 4, 8), (2, 8, 8), (2, 4, 16), (2, 4, 4), (27, 4, 8)] {
                assert!(!scalar_array(&[kind, 1, key, value, 4, 0]));
            }
            assert!(!compatible_map(-1));
        }
    }

    /// `bpf_attr` layout for `BPF_OBJ_GET`.
    #[repr(C)]
    struct BpfAttrObjGet {
        pathname: u64,
        bpf_fd: u32,
        file_flags: u32,
    }

    /// `bpf_attr` layout for `BPF_MAP_LOOKUP_ELEM`.
    /// map_fd at offset 0, 4 bytes implicit padding (u64 alignment), key/value
    /// pointers at offsets 8/16, flags at 24.
    #[repr(C)]
    struct BpfAttrMapElem {
        map_fd: u32,
        _pad: u32,
        key: u64,
        value: u64,
        flags: u64,
    }

    /// Open a pinned BPF object by filesystem path and return its fd.
    /// The caller **must** `libc::close(fd)` the returned descriptor.
    pub fn pinned_map_fd(path: &str) -> Option<RawFd> {
        let cpath = CString::new(path).ok()?;
        let attr = BpfAttrObjGet {
            pathname: cpath.as_ptr() as u64,
            bpf_fd: 0,
            file_flags: 0,
        };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_OBJ_GET,
                &attr as *const BpfAttrObjGet as *const libc::c_void,
                std::mem::size_of::<BpfAttrObjGet>() as libc::c_uint,
            )
        };
        if fd < 0 {
            None
        } else {
            Some(fd as RawFd)
        }
    }

    /// Look up a single `u64` value from a BPF ARRAY map by `u32` key.
    pub fn map_lookup_u64(fd: RawFd, key: u32) -> Option<u64> {
        // Ядро пишет value_size байт; неизвестная или per-CPU карта не помещается в u64.
        if !compatible_map(fd) {
            return None;
        }
        let mut value = 0u64;
        let attr = BpfAttrMapElem {
            map_fd: fd as u32,
            _pad: 0,
            key: &key as *const u32 as u64,
            value: &mut value as *mut u64 as u64,
            flags: 0,
        };
        let ret = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_MAP_LOOKUP_ELEM,
                &attr as *const BpfAttrMapElem as *const libc::c_void,
                std::mem::size_of::<BpfAttrMapElem>() as libc::c_uint,
            )
        };
        if ret == 0 {
            Some(value)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counter_reset_does_not_hide_new_drops() {
        let events = EventBus::disabled();
        let observer = EbpfObserver::new(events);
        assert_eq!(observer.take_drop_delta(0, 100), 100);
        assert_eq!(observer.take_drop_delta(0, 105), 5);
        assert_eq!(observer.take_drop_delta(0, 2), 2);
        assert_eq!(observer.take_drop_delta(0, 3), 1);
        assert_eq!(observer.take_drop_delta(0, 3), 0);
    }
}
