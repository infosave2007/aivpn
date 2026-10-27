//! Batched UDP I/O for the gateway hot paths (A2).
//!
//! `PacketBatchIo` abstracts over `recvmmsg(2)`/`sendmmsg(2)` so the receive
//! loop and the downlink workers pay one syscall per *batch* instead of one
//! per datagram. On non-Linux targets (and as a runtime escape hatch) the
//! `SingleIo` implementation degrades to the classic one-datagram-per-call
//! tokio operations with identical semantics.
//!
//! UDP GSO (`UDP_SEGMENT`) / GRO (`UDP_GRO`) are deliberately NOT enabled
//! here yet: GSO only coalesces runs of equal-sized datagrams to one
//! destination, and until A7 (downlink shaping parity) lands, downlink data
//! packets have variable sizes (pad_len=0), so segmentation offload would
//! almost never engage while adding cmsg complexity to every send. Revisit
//! after A7 makes per-mask packet sizes uniform.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::Interest;
use tokio::net::UdpSocket;

/// Max datagrams moved per syscall. 64 matches the design-doc target and
/// keeps the per-call stack arrays comfortably small (~4 KB of headers).
pub const MAX_BATCH: usize = 64;

/// One receive slot: a reusable buffer plus the metadata of the last
/// datagram received into it.
pub struct RecvSlot {
    pub buf: Vec<u8>,
    /// Valid length of `buf` after a successful `recv_batch`.
    pub len: usize,
    /// Peer address of the datagram, set by `recv_batch`.
    pub addr: Option<SocketAddr>,
    pub(crate) local: Option<crate::udp_source::LocalEndpoint>,
}

impl RecvSlot {
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: vec![0u8; capacity],
            len: 0,
            addr: None,
            local: None,
        }
    }

    pub fn packet(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// Batched datagram I/O over a shared tokio `UdpSocket`.
pub trait PacketBatchIo: Send + Sync {
    /// Receive up to `slots.len()` datagrams in one readiness cycle.
    /// Returns how many slots were filled (>= 1; waits until at least one
    /// datagram is available).
    fn recv_batch(
        &self,
        slots: &mut [RecvSlot],
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send;

    /// Send all `msgs` (payload, destination) datagrams, in order.
    fn send_batch(
        &self,
        msgs: &[(&[u8], SocketAddr)],
    ) -> impl std::future::Future<Output = io::Result<()>> + Send;
}

/// Platform-selected implementation. Both variants share the tokio socket
/// with the rest of the gateway (handshakes, control plane, keepalives keep
/// using plain `send_to`).
pub enum BatchIo {
    #[cfg(target_os = "linux")]
    Mmsg(MmsgIo),
    Single(SingleIo),
}

impl BatchIo {
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        #[cfg(target_os = "linux")]
        {
            BatchIo::Mmsg(MmsgIo {
                socket,
                sources: None,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            BatchIo::Single(SingleIo {
                socket,
                sources: None,
            })
        }
    }

    pub(crate) fn with_sources(
        socket: Arc<UdpSocket>,
        sources: Arc<crate::udp_source::ReplySources>,
    ) -> Self {
        #[cfg(target_os = "linux")]
        {
            Self::Mmsg(MmsgIo {
                socket,
                sources: Some(sources),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self::Single(SingleIo {
                socket,
                sources: Some(sources),
            })
        }
    }

    /// Force the portable single-datagram implementation (tests).
    #[allow(dead_code)]
    pub fn new_single(socket: Arc<UdpSocket>) -> Self {
        BatchIo::Single(SingleIo {
            socket,
            sources: None,
        })
    }
}

impl PacketBatchIo for BatchIo {
    async fn recv_batch(&self, slots: &mut [RecvSlot]) -> io::Result<usize> {
        match self {
            #[cfg(target_os = "linux")]
            BatchIo::Mmsg(io) => io.recv_batch(slots).await,
            BatchIo::Single(io) => io.recv_batch(slots).await,
        }
    }

    async fn send_batch(&self, msgs: &[(&[u8], SocketAddr)]) -> io::Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            BatchIo::Mmsg(io) => io.send_batch(msgs).await,
            BatchIo::Single(io) => io.send_batch(msgs).await,
        }
    }
}

// ── Portable fallback ────────────────────────────────────────────────────────

/// One datagram per call, built from tokio's non-blocking primitives.
/// Used on non-Linux targets and directly in unit tests as the semantic
/// reference for `MmsgIo`.
pub struct SingleIo {
    socket: Arc<UdpSocket>,
    sources: Option<Arc<crate::udp_source::ReplySources>>,
}

impl SingleIo {
    async fn recv_batch(&self, slots: &mut [RecvSlot]) -> io::Result<usize> {
        if slots.is_empty() {
            return Ok(0);
        }
        #[cfg(target_os = "linux")]
        {
            let (length, peer, local) =
                crate::udp_source::recv_from(&self.socket, &mut slots[0].buf).await?;
            slots[0].len = length;
            slots[0].addr = Some(peer);
            slots[0].local = local;
            return Ok(1);
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Block for the first datagram, then opportunistically drain
            // whatever else is already queued without waiting.
            let (len, addr) = self.socket.recv_from(&mut slots[0].buf).await?;
            slots[0].len = len;
            slots[0].addr = Some(addr);
            let mut filled = 1;
            while filled < slots.len() {
                match self.socket.try_recv_from(&mut slots[filled].buf) {
                    Ok((len, addr)) => {
                        slots[filled].len = len;
                        slots[filled].addr = Some(addr);
                        filled += 1;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
            Ok(filled)
        }
    }

    async fn send_batch(&self, msgs: &[(&[u8], SocketAddr)]) -> io::Result<()> {
        for (payload, addr) in msgs {
            if let Some(sources) = &self.sources {
                crate::udp_source::send_to(&self.socket, sources, payload, *addr).await?;
            } else {
                self.socket.send_to(payload, *addr).await?;
            }
        }
        Ok(())
    }
}

// ── Linux recvmmsg/sendmmsg ──────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub struct MmsgIo {
    socket: Arc<UdpSocket>,
    sources: Option<Arc<crate::udp_source::ReplySources>>,
}

#[cfg(target_os = "linux")]
impl MmsgIo {
    async fn recv_batch(&self, slots: &mut [RecvSlot]) -> io::Result<usize> {
        use std::os::fd::AsRawFd;

        let count = slots.len().min(MAX_BATCH);
        if count == 0 {
            return Ok(0);
        }
        loop {
            self.socket.readable().await?;
            let result = self.socket.try_io(Interest::READABLE, || {
                let fd = self.socket.as_raw_fd();
                let mut addrs: [libc::sockaddr_storage; MAX_BATCH] = unsafe { std::mem::zeroed() };
                let mut iovecs: [libc::iovec; MAX_BATCH] = unsafe { std::mem::zeroed() };
                let mut hdrs: [libc::mmsghdr; MAX_BATCH] = unsafe { std::mem::zeroed() };
                let mut controls = [crate::udp_source::ControlBuffer([0; 128]); MAX_BATCH];
                for i in 0..count {
                    iovecs[i] = libc::iovec {
                        iov_base: slots[i].buf.as_mut_ptr() as *mut libc::c_void,
                        iov_len: slots[i].buf.len(),
                    };
                    hdrs[i].msg_hdr.msg_iov = &mut iovecs[i];
                    hdrs[i].msg_hdr.msg_iovlen = 1;
                    hdrs[i].msg_hdr.msg_control = controls[i].0.as_mut_ptr().cast();
                    hdrs[i].msg_hdr.msg_controllen = controls[i].0.len() as _;
                    hdrs[i].msg_hdr.msg_name = &mut addrs[i] as *mut _ as *mut libc::c_void;
                    hdrs[i].msg_hdr.msg_namelen =
                        std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                }
                let n = unsafe {
                    libc::recvmmsg(
                        fd,
                        hdrs.as_mut_ptr(),
                        count as libc::c_uint,
                        libc::MSG_DONTWAIT as _,
                        std::ptr::null_mut(),
                    )
                };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                let n = n as usize;
                for i in 0..n {
                    slots[i].len = hdrs[i].msg_len as usize;
                    slots[i].local = crate::udp_source::received_local(&hdrs[i].msg_hdr);
                    slots[i].addr =
                        unsafe { socket2::SockAddr::new(addrs[i], hdrs[i].msg_hdr.msg_namelen) }
                            .as_socket();
                }
                Ok(n)
            });
            match result {
                Ok(n) => return Ok(n),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    async fn send_batch(&self, msgs: &[(&[u8], SocketAddr)]) -> io::Result<()> {
        use std::os::fd::AsRawFd;

        let mut offset = 0;
        while offset < msgs.len() {
            let chunk = &msgs[offset..(offset + MAX_BATCH).min(msgs.len())];
            self.socket.writable().await?;
            let result = self.socket.try_io(Interest::WRITABLE, || {
                let fd = self.socket.as_raw_fd();
                // SockAddr keeps the sockaddr storage alive for the syscall.
                let addrs: Vec<socket2::SockAddr> = chunk
                    .iter()
                    .map(|(_, a)| socket2::SockAddr::from(*a))
                    .collect();
                let mut iovecs: [libc::iovec; MAX_BATCH] = unsafe { std::mem::zeroed() };
                let mut hdrs: [libc::mmsghdr; MAX_BATCH] = unsafe { std::mem::zeroed() };
                let mut controls = [crate::udp_source::ControlBuffer([0; 128]); MAX_BATCH];
                for (i, (payload, _)) in chunk.iter().enumerate() {
                    iovecs[i] = libc::iovec {
                        iov_base: payload.as_ptr() as *mut libc::c_void,
                        iov_len: payload.len(),
                    };
                    hdrs[i].msg_hdr.msg_iov = &mut iovecs[i];
                    hdrs[i].msg_hdr.msg_iovlen = 1;
                    hdrs[i].msg_hdr.msg_name = addrs[i].as_ptr() as *mut libc::c_void;
                    hdrs[i].msg_hdr.msg_namelen = addrs[i].len();
                    let source = self
                        .sources
                        .as_ref()
                        .and_then(|sources| sources.get(chunk[i].1));
                    crate::udp_source::attach_source(
                        &mut hdrs[i].msg_hdr,
                        &mut controls[i],
                        source,
                    );
                }
                let n = unsafe {
                    libc::sendmmsg(fd, hdrs.as_mut_ptr(), chunk.len() as libc::c_uint, 0)
                };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(n as usize)
            });
            match result {
                Ok(sent) => offset += sent,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pair() -> (Arc<UdpSocket>, Arc<UdpSocket>, SocketAddr, SocketAddr) {
        let a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_a = a.local_addr().unwrap();
        let addr_b = b.local_addr().unwrap();
        (a, b, addr_a, addr_b)
    }

    async fn roundtrip(tx_io: BatchIo, rx_io: BatchIo, dst: SocketAddr) {
        let payloads: Vec<Vec<u8>> = (0u8..10).map(|i| vec![i; 100 + i as usize]).collect();
        let msgs: Vec<(&[u8], SocketAddr)> = payloads.iter().map(|p| (p.as_slice(), dst)).collect();
        tx_io.send_batch(&msgs).await.unwrap();

        let mut slots: Vec<RecvSlot> = (0..MAX_BATCH).map(|_| RecvSlot::new(2048)).collect();
        let mut received: Vec<Vec<u8>> = Vec::new();
        while received.len() < payloads.len() {
            let n = rx_io.recv_batch(&mut slots).await.unwrap();
            assert!(n >= 1);
            for slot in &slots[..n] {
                assert!(slot.addr.is_some(), "peer address must be filled in");
                received.push(slot.packet().to_vec());
            }
        }
        // Order within one sender/receiver pair must be preserved.
        assert_eq!(received, payloads);
    }

    #[tokio::test]
    async fn single_io_roundtrip() {
        let (a, b, _addr_a, addr_b) = pair().await;
        roundtrip(BatchIo::new_single(a), BatchIo::new_single(b), addr_b).await;
    }

    #[tokio::test]
    async fn platform_io_roundtrip() {
        let (a, b, _addr_a, addr_b) = pair().await;
        roundtrip(BatchIo::new(a), BatchIo::new(b), addr_b).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn mmsg_send_single_recv() {
        // Cross-check the two implementations against each other.
        let (a, b, _addr_a, addr_b) = pair().await;
        roundtrip(BatchIo::new(a), BatchIo::new_single(b), addr_b).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn single_send_mmsg_recv() {
        let (a, b, _addr_a, addr_b) = pair().await;
        roundtrip(BatchIo::new_single(a), BatchIo::new(b), addr_b).await;
    }

    #[tokio::test]
    async fn send_batch_larger_than_max_batch() {
        let (a, b, _addr_a, addr_b) = pair().await;
        let tx = BatchIo::new(a);
        let rx = BatchIo::new(b);
        let payloads: Vec<Vec<u8>> = (0..150u16)
            .map(|i| i.to_le_bytes().repeat(20).to_vec())
            .collect();
        let msgs: Vec<(&[u8], SocketAddr)> =
            payloads.iter().map(|p| (p.as_slice(), addr_b)).collect();
        tx.send_batch(&msgs).await.unwrap();

        let mut slots: Vec<RecvSlot> = (0..MAX_BATCH).map(|_| RecvSlot::new(2048)).collect();
        let mut received = 0usize;
        while received < payloads.len() {
            let n = rx.recv_batch(&mut slots).await.unwrap();
            for slot in &slots[..n] {
                assert_eq!(slot.packet(), payloads[received].as_slice());
                received += 1;
            }
        }
    }
}
