//! Запрос содержит endpoint, полученный из удержанного socket, а не PID/IP исключение.
use super::*;
use std::{
    net::SocketAddr,
    os::windows::io::{AsRawSocket, OwnedSocket},
};
use windows_sys::Win32::Networking::WinSock::*;

pub(crate) struct DnsEndpoint {
    pub endpoint: u64,
    pub protocol: u32,
    pub local: Option<SocketAddr>,
}

fn option(socket: usize, name: i32) -> io::Result<i32> {
    let mut value = 0i32;
    let mut size = std::mem::size_of_val(&value) as i32;
    if unsafe {
        getsockopt(
            socket,
            SOL_SOCKET,
            name,
            (&mut value as *mut i32).cast(),
            &mut size,
        )
    } == SOCKET_ERROR
    {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    if size != 4 {
        return Err(invalid());
    }
    Ok(value)
}

pub(crate) fn inspect_dns_socket(
    socket: &OwnedSocket,
    listener: bool,
    ipv4: Option<bool>,
) -> io::Result<DnsEndpoint> {
    let raw = socket.as_raw_socket() as usize;
    let protocol = match option(raw, SO_TYPE)? {
        SOCK_STREAM => 6,
        SOCK_DGRAM => 17,
        _ => return Err(invalid()),
    };
    let mut info: WSAPROTOCOL_INFOW = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&info) as i32;
    if unsafe {
        getsockopt(
            raw,
            SOL_SOCKET,
            SO_PROTOCOL_INFOW,
            (&mut info as *mut WSAPROTOCOL_INFOW).cast(),
            &mut size,
        )
    } == SOCKET_ERROR
    {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    if size as usize != std::mem::size_of_val(&info)
        || info.ProtocolChain.ChainLen != 1
        || ![AF_INET as i32, AF_INET6 as i32].contains(&info.iAddressFamily)
        || ipv4.is_some_and(|wanted| wanted != (info.iAddressFamily == AF_INET as i32))
        || info.iProtocol != protocol as i32
    {
        return Err(invalid());
    }
    let mut address: SOCKADDR_STORAGE = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&address) as i32;
    let connected = unsafe {
        getpeername(
            raw,
            (&mut address as *mut SOCKADDR_STORAGE).cast(),
            &mut length,
        )
    };
    if connected == 0 || unsafe { WSAGetLastError() } != WSAENOTCONN {
        return Err(invalid());
    }
    let local = if listener {
        if option(raw, SO_EXCLUSIVEADDRUSE)? == 0
            || option(raw, SO_REUSEADDR)? != 0
            || protocol == 6 && option(raw, SO_ACCEPTCONN)? == 0
        {
            return Err(invalid());
        }
        // Дубликат удерживается до удаления записи endpoint из ядра.
        let duplicate = socket.try_clone()?;
        let local = if protocol == 6 {
            let tcp: std::net::TcpListener = duplicate.into();
            tcp.local_addr()?
        } else {
            let udp: std::net::UdpSocket = duplicate.into();
            udp.local_addr()?
        };
        let expected: std::net::IpAddr = if info.iAddressFamily == AF_INET as i32 {
            "127.0.0.3".parse().unwrap()
        } else {
            "::1".parse().unwrap()
        };
        if local.ip() != expected || local.port() != 53 {
            return Err(invalid());
        }
        Some(local)
    } else {
        None
    };
    Ok(DnsEndpoint {
        endpoint: super::super::worker::endpoint(socket.as_raw_socket())?,
        protocol,
        local,
    })
}

impl DriverSession {
    pub(crate) fn begin_bootstrap_dns(&self, compartment: u32, epoch: u64) -> io::Result<()> {
        self.dns_request(6, compartment, 0, 0, epoch, None)
    }
    pub(crate) fn end_bootstrap_dns(&self, compartment: u32) -> io::Result<()> {
        self.dns_request(8, compartment, 0, 0, 0, None)
    }
    pub(crate) fn bootstrap_dns_endpoint(
        &self,
        compartment: u32,
        epoch: u64,
        endpoint: &DnsEndpoint,
        peer: SocketAddr,
    ) -> io::Result<()> {
        self.dns_request(7, compartment, 0, 0, epoch, Some((endpoint, peer)))
    }
    pub(crate) fn dns_guard(&self, compartment: u32, enable: bool) -> io::Result<()> {
        self.dns_request(if enable { 1 } else { 2 }, compartment, 0, 0, 0, None)
    }
    pub(crate) fn dns_route(
        &self,
        compartment: u32,
        profile: u32,
        generation: u64,
        epoch: u64,
    ) -> io::Result<()> {
        self.dns_request(3, compartment, profile, generation, epoch, None)
    }
    pub(crate) fn dns_endpoint(
        &self,
        compartment: u32,
        profile: u32,
        generation: u64,
        epoch: u64,
        endpoint: &DnsEndpoint,
        peer: SocketAddr,
        listener: bool,
    ) -> io::Result<()> {
        self.dns_request(
            if listener { 5 } else { 4 },
            compartment,
            profile,
            generation,
            epoch,
            Some((endpoint, peer)),
        )
    }
    fn dns_request(
        &self,
        operation: u32,
        compartment: u32,
        profile: u32,
        generation: u64,
        epoch: u64,
        socket: Option<(&DnsEndpoint, SocketAddr)>,
    ) -> io::Result<()> {
        let mut bytes = request(self.session.get(), 88);
        bytes[24..32].copy_from_slice(&generation.to_le_bytes());
        bytes[32..40].copy_from_slice(&epoch.to_le_bytes());
        bytes[48..52].copy_from_slice(&operation.to_le_bytes());
        bytes[52..56].copy_from_slice(&compartment.to_le_bytes());
        bytes[56..60].copy_from_slice(&profile.to_le_bytes());
        if let Some((socket, peer)) = socket {
            bytes[40..48].copy_from_slice(&socket.endpoint.to_le_bytes());
            bytes[64..68].copy_from_slice(&socket.protocol.to_le_bytes());
            bytes[68..70].copy_from_slice(&peer.port().to_le_bytes());
            match peer.ip() {
                std::net::IpAddr::V4(ip) => {
                    bytes[60..64].copy_from_slice(&4u32.to_le_bytes());
                    bytes[72..76].copy_from_slice(&ip.octets());
                }
                std::net::IpAddr::V6(ip) => {
                    bytes[60..64].copy_from_slice(&6u32.to_le_bytes());
                    bytes[72..88].copy_from_slice(&ip.octets());
                }
            }
        }
        self.exchange(QUERY + 48, &bytes).map(|_| ())
    }
}
