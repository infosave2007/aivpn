//! Пакетный канал клиента. Настройка managed TUN остается у службы.

use aivpn_common::{error::Result, network_config::ClientNetworkConfig};
use tokio::io::AsyncReadExt;

#[cfg(any(target_os = "windows", test))]
mod framed;

#[cfg(target_os = "windows")]
#[path = "packet_endpoint/windows.rs"]
pub mod managed;

pub(crate) enum PacketEndpoint {
    Legacy(crate::tunnel::Tunnel),
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    Managed(managed::ManagedEndpoint),
}

pub(crate) enum PacketReader {
    Legacy(tun::DeviceReader),
    #[cfg(target_os = "linux")]
    Managed(std::sync::Arc<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>>),
    #[cfg(target_os = "windows")]
    Managed(managed::Reader),
}

impl PacketReader {
    pub async fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Legacy(reader) => reader.read(buffer).await,
            #[cfg(target_os = "linux")]
            Self::Managed(descriptor) => managed::read(descriptor, buffer).await,
            #[cfg(target_os = "windows")]
            Self::Managed(reader) => reader.read(buffer).await,
        }
    }
}

impl PacketEndpoint {
    pub fn is_managed(&self) -> bool {
        match self {
            Self::Legacy(_) => false,
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Managed(_) => true,
        }
    }

    pub fn legacy_mut(&mut self) -> Option<&mut crate::tunnel::Tunnel> {
        match self {
            Self::Legacy(tunnel) => Some(tunnel),
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Managed(_) => None,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Legacy(tunnel) => tunnel.name(),
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Managed(endpoint) => &endpoint.name,
        }
    }

    pub fn take_reader(&mut self) -> Option<PacketReader> {
        match self {
            Self::Legacy(tunnel) => tunnel.take_reader().map(PacketReader::Legacy),
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Managed(endpoint) => endpoint.reader.take().map(PacketReader::Managed),
        }
    }

    pub async fn write_packet_async(&mut self, packet: &[u8]) -> Result<usize> {
        match self {
            Self::Legacy(tunnel) => tunnel.write_packet_async(packet).await,
            #[cfg(target_os = "linux")]
            Self::Managed(endpoint) => Ok(managed::write(&endpoint.descriptor, packet).await?),
            #[cfg(target_os = "windows")]
            Self::Managed(endpoint) => Ok(endpoint.write(packet).await?),
        }
    }

    pub async fn apply_network_config(&mut self, config: ClientNetworkConfig) -> Result<()> {
        match self {
            Self::Legacy(tunnel) => tunnel.apply_network_config(config).await,
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Managed(endpoint) => {
                if endpoint.last_assignment.as_ref() != Some(&config) {
                    endpoint.assignment.confirmed_assignment(&config)?;
                    endpoint.last_assignment = Some(config);
                }
                Ok(())
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub mod managed {
    use super::*;
    use std::{
        io,
        os::fd::{AsRawFd, OwnedFd},
        sync::Arc,
    };
    use tokio::io::unix::AsyncFd;

    /// Ответ службы приходит только после применения и проверки назначения.
    pub trait ConfirmedAssignment: Send + Sync {
        fn confirmed_assignment(&self, config: &ClientNetworkConfig) -> Result<()>;
    }

    pub struct ManagedEndpoint {
        pub(super) name: String,
        pub(super) descriptor: Arc<AsyncFd<OwnedFd>>,
        pub(super) reader: Option<Arc<AsyncFd<OwnedFd>>>,
        pub(super) assignment: Arc<dyn ConfirmedAssignment>,
        pub(super) last_assignment: Option<ClientNetworkConfig>,
    }

    impl ManagedEndpoint {
        /// Принимает уже настроенный nonblocking FD, переданный доверенной службой.
        pub fn new(
            descriptor: OwnedFd,
            name: String,
            assignment: Arc<dyn ConfirmedAssignment>,
        ) -> io::Result<Self> {
            let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            if flags & libc::O_NONBLOCK == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Пакетный FD должен быть nonblocking",
                ));
            }
            // OwnedFd сохраняет номер и владение до Drop AsyncFd.
            let descriptor =
                Arc::new(unsafe { AsyncFd::register(descriptor) }.map_err(io::Error::from)?);
            Ok(Self {
                name,
                reader: Some(descriptor.clone()),
                descriptor,
                assignment,
                last_assignment: None,
            })
        }
    }

    pub(super) async fn read(
        descriptor: &AsyncFd<OwnedFd>,
        buffer: &mut [u8],
    ) -> io::Result<usize> {
        loop {
            let mut ready = descriptor.readable().await?;
            match ready.try_io(|fd| {
                syscall_result(unsafe {
                    libc::read(
                        fd.get_ref().as_raw_fd(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                    )
                })
            }) {
                Ok(result) => return result,
                Err(_) => continue,
            }
        }
    }

    pub(super) async fn write(descriptor: &AsyncFd<OwnedFd>, packet: &[u8]) -> io::Result<usize> {
        loop {
            let mut ready = descriptor.writable().await?;
            match ready.try_io(|fd| {
                syscall_result(unsafe {
                    libc::write(
                        fd.get_ref().as_raw_fd(),
                        packet.as_ptr().cast(),
                        packet.len(),
                    )
                })
            }) {
                Ok(Ok(size)) if size != packet.len() => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TUN принял неполный пакет",
                    ))
                }
                Ok(result) => return result,
                Err(_) => continue,
            }
        }
    }

    fn syscall_result(size: isize) -> io::Result<usize> {
        if size < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(size as usize)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            os::unix::net::UnixDatagram,
            sync::atomic::{AtomicUsize, Ordering},
        };

        struct Assignments(AtomicUsize);
        impl ConfirmedAssignment for Assignments {
            fn confirmed_assignment(&self, _: &ClientNetworkConfig) -> Result<()> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }

        #[tokio::test]
        async fn managed_endpoint_preserves_packet_boundaries_and_confirms_initial_assignment() {
            let (packet, peer) = UnixDatagram::pair().unwrap();
            packet.set_nonblocking(true).unwrap();
            let observer = Arc::new(Assignments(AtomicUsize::new(0)));
            let managed =
                ManagedEndpoint::new(packet.into(), "owned".into(), observer.clone()).unwrap();
            let mut endpoint = PacketEndpoint::Managed(managed);
            assert!(endpoint.legacy_mut().is_none());
            let mut reader = endpoint.take_reader().unwrap();
            assert!(endpoint.take_reader().is_none());
            peer.send(b"first packet").unwrap();
            peer.send(b"second packet").unwrap();
            let mut bytes = [0; 128];
            for packet in [b"first packet".as_slice(), b"second packet"] {
                let size = reader.read(&mut bytes).await.unwrap();
                assert_eq!(&bytes[..size], packet);
            }
            endpoint.write_packet_async(b"reply").await.unwrap();
            let size = peer.recv(&mut bytes).unwrap();
            assert_eq!(&bytes[..size], b"reply");
            let config = crate::tunnel::TunnelConfig::default()
                .client_network_config()
                .unwrap();
            endpoint.apply_network_config(config.clone()).await.unwrap();
            endpoint.apply_network_config(config).await.unwrap();
            assert_eq!(observer.0.load(Ordering::Relaxed), 1);
        }

        #[tokio::test]
        async fn blocking_descriptor_cannot_enter_the_reactor() {
            let (packet, _) = UnixDatagram::pair().unwrap();
            let observer = Arc::new(Assignments(AtomicUsize::new(0)));
            assert_eq!(
                ManagedEndpoint::new(packet.into(), "owned".into(), observer)
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}
