//! Ограниченный cursor sweep вызывает существующие проверки lifetime в ядре.
use super::KernelWriter;
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
pub(crate) struct CacheSweep {
    cursors: [[u8; 64]; 3],
    pending: [u32; 3],
    next: usize,
}
impl Default for CacheSweep {
    fn default() -> Self {
        Self {
            cursors: [[0; 64]; 3],
            pending: [0; 3],
            next: 0,
        }
    }
}
impl KernelWriter {
    pub(crate) fn sweep_cache(&mut self, sweep: &mut CacheSweep) -> io::Result<u32> {
        self.check_owner()?;
        if self.kernel.mode() != super::super::BindingMode::Snapshot {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let index = sweep.next;
        sweep.next = (index + 1) % 3;
        let (map, request, program) = match index {
            0 => (
                c"routing_overrides",
                c"cache_reap_requests",
                c"reap_routing_cache",
            ),
            1 => (
                c"routing_system",
                c"cache_reap_requests",
                c"reap_routing_cache",
            ),
            _ => (c"tcp_routes", c"tcp_reap_requests", c"reap_tcp_routes"),
        };
        let result = unsafe {
            ar_reap_cache(
                self.kernel.map(map)?.as_raw_fd(),
                self.kernel.map(request)?.as_raw_fd(),
                self.kernel.program(program)?.as_raw_fd(),
                index as u32,
                sweep.cursors[index].as_mut_ptr(),
                &mut sweep.pending[index],
                32,
            )
        };
        if result < 0 {
            return Err(io::Error::from_raw_os_error(-result));
        }
        Ok(result as u32)
    }
    pub(crate) fn attach_related_icmp(
        &self,
        tunnel: &crate::linux::OwnedTunnel,
    ) -> io::Result<OwnedFd> {
        self.check_owner()?;
        let identity = tunnel.verify()?;
        let program = self.kernel.program(c"route_related_icmp")?;
        let raw = unsafe { ar_attach_tcx(program.as_raw_fd(), identity.index.get()) };
        if raw < 0 {
            return Err(io::Error::from_raw_os_error(-raw));
        }
        let link = unsafe { OwnedFd::from_raw_fd(raw) };
        let id = super::super::objects::ObjectInfo::read(program)?.words[1];
        super::super::image::result(unsafe {
            ar_verify_tcx(link.as_raw_fd(), id, identity.index.get())
        })?;
        if tunnel.verify()? != identity {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(link)
    }
}
unsafe extern "C" {
    fn ar_reap_cache(
        map: i32,
        request: i32,
        program: i32,
        kind: u32,
        cursor: *mut u8,
        pending: *mut u32,
        budget: u32,
    ) -> i32;
    fn ar_attach_tcx(program: i32, index: u32) -> i32;
    fn ar_verify_tcx(link: i32, program: u32, index: u32) -> i32;
}
