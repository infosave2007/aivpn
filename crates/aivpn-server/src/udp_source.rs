//! Адрес ответа выбирается из локального адреса проверенного входящего пакета.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Weak};

use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::net::UdpSocket;

use crate::session::{Session, MAX_SESSIONS};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LocalEndpoint {
    pub ip: IpAddr,
    pub interface: u32,
}

struct Binding {
    owner: Weak<Mutex<Session>>,
    local: LocalEndpoint,
    needs_source: bool,
}

#[derive(Default)]
pub(crate) struct ReplySources(DashMap<SocketAddr, Binding>);

impl ReplySources {
    /// Вызывается только после AEAD и захвата replay-счетчика.
    pub fn record(
        &self,
        peer: SocketAddr,
        local: LocalEndpoint,
        owner: &Arc<Mutex<Session>>,
    ) -> bool {
        if local.ip.is_unspecified() || local.ip.is_multicast() {
            return false;
        }
        if self
            .0
            .get(&peer)
            .is_some_and(|entry| entry.local == local && entry.owner.ptr_eq(&Arc::downgrade(owner)))
        {
            return false;
        }
        if self.0.len() >= 2 * MAX_SESSIONS {
            // Не держим блокировку DashMap одновременно с блокировкой сессии.
            let bindings: Vec<_> = self
                .0
                .iter()
                .map(|entry| (*entry.key(), entry.owner.clone()))
                .collect();
            for (peer, binding) in bindings {
                let live = binding.upgrade().is_some_and(|owner| {
                    let session = owner.lock();
                    !session.is_removed() && session.client_addr == peer
                });
                if !live {
                    self.0
                        .remove_if(&peer, |_, current| current.owner.ptr_eq(&binding));
                }
            }
        }
        // Старые NAT-адреса живых сессий также удаляются при очистке выше.
        if self.0.len() >= 2 * MAX_SESSIONS && !self.0.contains_key(&peer) {
            return false;
        }
        let needs_source = std::net::UdpSocket::bind(if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .and_then(|socket| {
            socket.connect(peer)?;
            socket.local_addr()
        })
        .map_or(true, |selected| selected.ip() != local.ip);
        self.0.insert(
            peer,
            Binding {
                owner: Arc::downgrade(owner),
                local,
                needs_source,
            },
        );
        true
    }

    pub fn get(&self, peer: SocketAddr) -> Option<LocalEndpoint> {
        let (owner, local) = {
            let binding = self.0.get(&peer)?;
            (binding.owner.clone(), binding.local)
        };
        let owner = owner.upgrade()?;
        let session = owner.lock();
        (!session.is_removed() && session.client_addr == peer).then_some(local)
    }

    pub fn needs_source(&self, peer: SocketAddr) -> bool {
        self.0
            .get(&peer)
            .is_some_and(|binding| binding.needs_source)
    }
}

#[cfg(target_os = "linux")]
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub(crate) struct ControlBuffer(pub [u8; 128]);

#[cfg(target_os = "linux")]
pub(crate) fn enable(socket: &UdpSocket) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let (level, option) = if socket.local_addr()?.is_ipv4() {
        (libc::IPPROTO_IP, libc::IP_PKTINFO)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
    };
    let enabled: libc::c_int = 1;
    // Сокет принадлежит вызывающему коду; значение живет до возврата setsockopt.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as _,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn enable(_: &UdpSocket) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn received_local(message: &libc::msghdr) -> Option<LocalEndpoint> {
    // Буфер и длины заполняет recvmsg/recvmmsg, вызывающий код держит их живыми.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(message);
        while !header.is_null() {
            let info = &*header;
            if info.cmsg_level == libc::IPPROTO_IP
                && info.cmsg_type == libc::IP_PKTINFO
                && info.cmsg_len as usize
                    >= libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as _) as usize
            {
                let value =
                    std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::in_pktinfo>());
                return Some(LocalEndpoint {
                    ip: std::net::Ipv4Addr::from(value.ipi_addr.s_addr.to_ne_bytes()).into(),
                    interface: value.ipi_ifindex as u32,
                });
            }
            if info.cmsg_level == libc::IPPROTO_IPV6
                && info.cmsg_type == libc::IPV6_PKTINFO
                && info.cmsg_len as usize
                    >= libc::CMSG_LEN(std::mem::size_of::<libc::in6_pktinfo>() as _) as usize
            {
                let value =
                    std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::in6_pktinfo>());
                return Some(LocalEndpoint {
                    ip: std::net::Ipv6Addr::from(value.ipi6_addr.s6_addr).into(),
                    interface: value.ipi6_ifindex,
                });
            }
            header = libc::CMSG_NXTHDR(message, header);
        }
    }
    None
}

#[cfg(target_os = "linux")]
pub(crate) fn attach_source(
    message: &mut libc::msghdr,
    buffer: &mut ControlBuffer,
    source: Option<LocalEndpoint>,
) {
    let Some(source) = source else {
        return;
    };
    message.msg_control = buffer.0.as_mut_ptr().cast();
    // Выравнивание ControlBuffer подходит cmsghdr; места хватает для обоих семейств.
    unsafe {
        match source.ip {
            IpAddr::V4(ip) => {
                message.msg_controllen =
                    libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as _) as _;
                let header = libc::CMSG_FIRSTHDR(message);
                (*header).cmsg_level = libc::IPPROTO_IP;
                (*header).cmsg_type = libc::IP_PKTINFO;
                (*header).cmsg_len =
                    libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as _) as _;
                let mut value: libc::in_pktinfo = std::mem::zeroed();
                // Интерфейс выбирает маршрутизация; адрес остается тем, на который пришел запрос.
                value.ipi_spec_dst.s_addr = u32::from_ne_bytes(ip.octets());
                std::ptr::write(libc::CMSG_DATA(header).cast(), value);
            }
            IpAddr::V6(ip) => {
                message.msg_controllen =
                    libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as _) as _;
                let header = libc::CMSG_FIRSTHDR(message);
                (*header).cmsg_level = libc::IPPROTO_IPV6;
                (*header).cmsg_type = libc::IPV6_PKTINFO;
                (*header).cmsg_len =
                    libc::CMSG_LEN(std::mem::size_of::<libc::in6_pktinfo>() as _) as _;
                let mut value: libc::in6_pktinfo = std::mem::zeroed();
                value.ipi6_addr.s6_addr = ip.octets();
                if ip.is_unicast_link_local() {
                    value.ipi6_ifindex = source.interface;
                }
                std::ptr::write(libc::CMSG_DATA(header).cast(), value);
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) async fn recv_from(
    socket: &UdpSocket,
    buffer: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<LocalEndpoint>)> {
    use std::os::fd::AsRawFd;
    loop {
        socket.readable().await?;
        let result = socket.try_io(tokio::io::Interest::READABLE, || {
            let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut control = ControlBuffer([0; 128]);
            let mut iovec = libc::iovec {
                iov_base: buffer.as_mut_ptr().cast(),
                iov_len: buffer.len(),
            };
            let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
            header.msg_name = (&mut address as *mut libc::sockaddr_storage).cast();
            header.msg_namelen = std::mem::size_of_val(&address) as _;
            header.msg_control = control.0.as_mut_ptr().cast();
            header.msg_controllen = control.0.len() as _;
            header.msg_iov = &mut iovec;
            header.msg_iovlen = 1;
            // Сокет неблокирующий; адрес, данные и control остаются живыми до возврата.
            let received =
                unsafe { libc::recvmsg(socket.as_raw_fd(), &mut header, libc::MSG_DONTWAIT) };
            if received < 0 {
                return Err(io::Error::last_os_error());
            }
            let peer = unsafe { socket2::SockAddr::new(address, header.msg_namelen) }
                .as_socket()
                .ok_or_else(|| io::Error::other("Неизвестное семейство UDP"))?;
            Ok((received as usize, peer, received_local(&header)))
        });
        match result {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            other => return other,
        }
    }
}

/// Tests share mask socket helpers across platforms; without IP_PKTINFO
/// the local destination is unknown.
#[cfg(all(test, not(target_os = "linux")))]
pub(crate) async fn recv_from(
    socket: &UdpSocket,
    buffer: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<LocalEndpoint>)> {
    let (length, peer) = socket.recv_from(buffer).await?;
    Ok((length, peer, None))
}

pub(crate) async fn send_to(
    socket: &UdpSocket,
    sources: &ReplySources,
    packet: &[u8],
    peer: SocketAddr,
) -> io::Result<usize> {
    send_from(socket, packet, peer, sources.get(peer)).await
}

/// Ответ transport использует только локальный destination принятого Initial.
/// Глобальная привязка VPN меняется отдельно после AEAD и replay.
pub(crate) async fn send_from(
    socket: &UdpSocket,
    packet: &[u8],
    peer: SocketAddr,
    source: Option<LocalEndpoint>,
) -> io::Result<usize> {
    #[cfg(target_os = "linux")]
    if let Some(source) = source {
        use std::os::fd::AsRawFd;
        loop {
            socket.writable().await?;
            let result = socket.try_io(tokio::io::Interest::WRITABLE, || {
                let address = socket2::SockAddr::from(peer);
                let mut iovec = libc::iovec {
                    iov_base: packet.as_ptr() as *mut _,
                    iov_len: packet.len(),
                };
                let mut control = ControlBuffer([0; 128]);
                let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
                header.msg_name = address.as_ptr() as *mut _;
                header.msg_namelen = address.len();
                header.msg_iov = &mut iovec;
                header.msg_iovlen = 1;
                attach_source(&mut header, &mut control, Some(source));
                // Все указатели ведут в живые локальные значения; сокет неблокирующий.
                let sent =
                    unsafe { libc::sendmsg(socket.as_raw_fd(), &header, libc::MSG_DONTWAIT) };
                if sent < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(sent as usize)
                }
            });
            match result {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                other => return other,
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = source;
    socket.send_to(packet, peer).await
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::batch_io::{BatchIo, PacketBatchIo, RecvSlot};
    use aivpn_common::crypto;
    use std::time::Duration;

    async fn roundtrip(bind: &str, destination: IpAddr, single: bool) {
        let server = Arc::new(UdpSocket::bind(bind).await.unwrap());
        enable(&server).unwrap();
        let client = UdpSocket::bind(if destination.is_ipv4() {
            "127.0.0.1:0"
        } else {
            "[::1]:0"
        })
        .await
        .unwrap();
        client
            .connect(SocketAddr::new(
                destination,
                server.local_addr().unwrap().port(),
            ))
            .await
            .unwrap();
        client.send(b"probe").await.unwrap();
        let mut slots = vec![RecvSlot::new(2048)];
        let receive = if single {
            BatchIo::new_single(server.clone())
        } else {
            BatchIo::new(server.clone())
        };
        assert_eq!(receive.recv_batch(&mut slots).await.unwrap(), 1);
        let peer = slots[0].addr.unwrap();
        let local = slots[0].local.expect("Нет адреса назначения UDP");
        let mapped = match local.ip {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(local.ip),
            other => other,
        };
        assert_eq!(mapped, destination);
        let session = Arc::new(Mutex::new(Session::new(
            [1; 16],
            peer,
            crypto::derive_session_keys(&[7; 32], None, &[9; 32]),
            [3; 32],
        )));
        let sources = Arc::new(ReplySources::default());
        assert!(sources.record(peer, local, &session));
        assert!(!sources.record(peer, local, &session));
        let sender = BatchIo::with_sources(server.clone(), sources.clone());
        sender
            .send_batch(&[(b"batch-reply".as_slice(), peer)])
            .await
            .unwrap();
        let mut buffer = [0; 64];
        let length = tokio::time::timeout(Duration::from_secs(1), client.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..length], b"batch-reply");
        send_to(&server, &sources, b"actor-reply", peer)
            .await
            .unwrap();
        let length = tokio::time::timeout(Duration::from_secs(1), client.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..length], b"actor-reply");
        drop(session);
        assert!(
            sources.get(peer).is_none(),
            "Удаленная сессия не должна закреплять адрес ответа"
        );
    }

    #[tokio::test]
    async fn wildcard_ipv4_replies_from_the_received_destination() {
        roundtrip("0.0.0.0:0", "127.0.0.2".parse().unwrap(), false).await;
    }

    #[tokio::test]
    async fn single_receive_preserves_the_destination() {
        roundtrip("0.0.0.0:0", "127.0.0.2".parse().unwrap(), true).await;
    }

    #[tokio::test]
    async fn wildcard_ipv6_preserves_the_destination() {
        roundtrip("[::]:0", "::1".parse().unwrap(), false).await;
    }

    #[tokio::test]
    async fn dual_stack_socket_preserves_a_mapped_ipv4_destination() {
        roundtrip("[::]:0", "127.0.0.2".parse().unwrap(), false).await;
    }
}
