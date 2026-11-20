//! Служба создает UDP endpoint и передает его worker через WSADuplicateSocket.
use super::super::api::denied;
use std::{
    io,
    os::windows::io::{AsRawSocket, FromRawSocket, OwnedSocket, RawSocket},
    ptr,
};
use windows_sys::Win32::Networking::WinSock::*;

fn wsa(result: i32) -> io::Result<()> {
    if result == SOCKET_ERROR {
        Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
    } else {
        Ok(())
    }
}
pub fn endpoint(socket: RawSocket) -> io::Result<u64> {
    let mut endpoint = 0u64;
    let mut returned = 0;
    wsa(unsafe {
        WSAIoctl(
            socket as usize,
            SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE,
            ptr::null(),
            0,
            (&mut endpoint as *mut u64).cast(),
            8,
            &mut returned,
            ptr::null_mut(),
            None,
        )
    })?;
    if endpoint == 0 || returned != 8 {
        return Err(io::Error::other(format!(
            "Endpoint query: endpoint={endpoint}, bytes={returned}"
        )));
    }
    Ok(endpoint)
}
pub fn duplicate_transport(socket: RawSocket, service_pid: u32) -> io::Result<Vec<u8>> {
    if service_pid == 0 {
        return Err(denied());
    }
    let mut info: WSAPROTOCOL_INFOW = unsafe { std::mem::zeroed() };
    wsa(unsafe { WSADuplicateSocketW(socket as usize, service_pid, &mut info) })?;
    Ok(unsafe {
        std::slice::from_raw_parts(
            (&info as *const WSAPROTOCOL_INFOW).cast::<u8>(),
            std::mem::size_of_val(&info),
        )
    }
    .to_vec())
}
pub struct Winsock;
impl Winsock {
    pub fn start() -> io::Result<Self> {
        let mut data = unsafe { std::mem::zeroed() };
        let result = unsafe { WSAStartup(0x202, &mut data) };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        Ok(Self)
    }
}
impl Drop for Winsock {
    fn drop(&mut self) {
        unsafe {
            WSACleanup();
        }
    }
}

pub struct SharedTransport {
    // Сначала закрывается socket. До отзыва lease этот объект удерживает endpoint от reuse.
    socket: OwnedSocket,
    _winsock: Winsock,
    endpoint: u64,
    family: u16,
}
impl SharedTransport {
    pub fn create(ipv4: bool) -> io::Result<Self> {
        let winsock = Winsock::start()?;
        let family = if ipv4 { AF_INET } else { AF_INET6 };
        let raw = unsafe {
            WSASocketW(
                family as i32,
                SOCK_DGRAM,
                IPPROTO_UDP,
                ptr::null(),
                0,
                WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
            )
        };
        if raw == INVALID_SOCKET {
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
        Self::from_socket(
            unsafe { OwnedSocket::from_raw_socket(raw as RawSocket) },
            winsock,
            family,
        )
    }
    pub fn duplicate_for(&self, process: u32) -> io::Result<Vec<u8>> {
        duplicate_transport(self.socket.as_raw_socket(), process)
    }
    /// Вызывающий удерживает Winsock до закрытия возвращенного сокета.
    pub fn into_udp(self, _runtime: &Winsock) -> std::net::UdpSocket {
        self.socket.into()
    }
    pub fn from_protocol_info(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != std::mem::size_of::<WSAPROTOCOL_INFOW>() {
            return Err(io::Error::other(format!(
                "Protocol info length={}",
                bytes.len()
            )));
        }
        let info = unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<WSAPROTOCOL_INFOW>()) };
        if info.iSocketType != SOCK_DGRAM
            || info.iProtocol != IPPROTO_UDP
            || ![AF_INET as i32, AF_INET6 as i32].contains(&info.iAddressFamily)
            || info.ProtocolChain.ChainLen != 1
        {
            return Err(io::Error::other(format!(
                "Protocol info: type={}, protocol={}, family={}, chain={}",
                info.iSocketType, info.iProtocol, info.iAddressFamily, info.ProtocolChain.ChainLen
            )));
        }
        let winsock = Winsock::start()?;
        let raw = unsafe {
            WSASocketW(
                FROM_PROTOCOL_INFO,
                FROM_PROTOCOL_INFO,
                FROM_PROTOCOL_INFO,
                &info,
                0,
                WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
            )
        };
        if raw == INVALID_SOCKET {
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
        let socket = unsafe { OwnedSocket::from_raw_socket(raw as RawSocket) };
        Self::from_socket(socket, winsock, info.iAddressFamily as u16)
    }
    fn from_socket(socket: OwnedSocket, winsock: Winsock, family: u16) -> io::Result<Self> {
        let endpoint = endpoint(socket.as_raw_socket())?;
        let result = Self {
            socket,
            _winsock: winsock,
            endpoint,
            family,
        };
        result.verify_unused()?;
        Ok(result)
    }
    fn verify_unused(&self) -> io::Result<()> {
        let mut address: SOCKADDR_STORAGE = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&address) as i32;
        let raw = self.socket.as_raw_socket() as usize;
        let result = unsafe {
            getsockname(
                raw,
                (&mut address as *mut SOCKADDR_STORAGE).cast(),
                &mut length,
            )
        };
        if result == 0 {
            // У уже связанного сокета нет права на повторную регистрацию перед firstsend.
            return Err(io::Error::other("Transport уже связан с local address"));
        }
        if unsafe { WSAGetLastError() } != WSAEINVAL {
            return Err(io::Error::other(format!(
                "Transport local address: WSA={}",
                unsafe { WSAGetLastError() }
            )));
        }
        length = std::mem::size_of_val(&address) as i32;
        let result = unsafe {
            getpeername(
                raw,
                (&mut address as *mut SOCKADDR_STORAGE).cast(),
                &mut length,
            )
        };
        let error = unsafe { WSAGetLastError() };
        if result == 0 || error != WSAENOTCONN {
            return Err(io::Error::other(format!(
                "Transport peer: result={result}, WSA={error}"
            )));
        }
        Ok(())
    }
    pub fn endpoint(&self) -> u64 {
        self.endpoint
    }
    pub fn ipv4(&self) -> bool {
        self.family == AF_INET
    }
}
