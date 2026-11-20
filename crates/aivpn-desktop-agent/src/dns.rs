//! DNS передает собственные сокеты единственному writer Control до отправки запроса.

use aivpn_desktop_policy::ProfileLease;
use std::{
    io,
    net::SocketAddr,
    sync::{mpsc, Arc},
};

type Wake = Arc<dyn Fn() -> io::Result<()> + Send + Sync>;
#[cfg(feature = "local-profile")]
pub(crate) mod bootstrap;
pub(crate) mod journal;

#[cfg(unix)]
pub type DnsSocket = std::os::fd::OwnedFd;
#[cfg(windows)]
pub type DnsSocket = std::os::windows::io::OwnedSocket;

const MAX_REQUESTS: usize = 256;

pub type BootstrapDnsRegistrar<'a> =
    Box<dyn Fn(DnsSocket, SocketAddr) -> io::Result<DnsSocketLease> + Send + Sync + 'a>;

/// Не сериализуется. Конкретный backend создает это право после проверки сокета и сеанса.
pub struct DnsSocketLease {
    _socket: DnsSocket,
}
impl DnsSocketLease {
    pub(crate) fn new(socket: DnsSocket) -> Self {
        Self { _socket: socket }
    }
}

pub(crate) struct Registration {
    pub socket: DnsSocket,
    pub lease: ProfileLease,
    pub assignment_generation: u64,
    pub resolver_epoch: u64,
    pub peer: SocketAddr,
    pub reply: Box<dyn FnOnce(io::Result<DnsSocketLease>) + Send>,
}

pub(crate) struct DnsRequests {
    sender: mpsc::SyncSender<Registration>,
    receiver: mpsc::Receiver<Registration>,
    wake: Option<Wake>,
}
impl DnsRequests {
    pub(crate) fn new() -> Self {
        let (sender, receiver) = mpsc::sync_channel(MAX_REQUESTS);
        Self {
            sender,
            receiver,
            wake: None,
        }
    }
    pub(crate) fn set_wake(&mut self, wake: Wake) {
        self.wake = Some(wake);
    }
    pub(crate) fn route(
        &self,
        lease: ProfileLease,
        assignment_generation: u64,
        resolver_epoch: u64,
        peer: SocketAddr,
    ) -> io::Result<DnsRoutePort> {
        if assignment_generation == 0
            || resolver_epoch == 0
            || peer.port() == 0
            || peer.ip().is_unspecified()
            || peer.ip().is_multicast()
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(DnsRoutePort {
            sender: self.sender.clone(),
            lease,
            assignment_generation,
            resolver_epoch,
            peer,
            process: std::process::id(),
            wake: self.wake.clone(),
        })
    }
    pub(crate) fn receive(&self) -> Result<Registration, mpsc::TryRecvError> {
        self.receiver.try_recv()
    }
}

/// Порт выдается текущим координатором для одного профиля и одного DNS upstream.
#[derive(Clone)]
pub struct DnsRoutePort {
    sender: mpsc::SyncSender<Registration>,
    lease: ProfileLease,
    assignment_generation: u64,
    resolver_epoch: u64,
    peer: SocketAddr,
    process: u32,
    wake: Option<Wake>,
}
impl DnsRoutePort {
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Callback только доставляет результат; он не меняет policy или журнал.
    pub fn register(
        &self,
        socket: DnsSocket,
        reply: impl FnOnce(io::Result<DnsSocketLease>) + Send + 'static,
    ) -> io::Result<()> {
        if self.process != std::process::id() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.sender
            .try_send(Registration {
                socket,
                lease: self.lease.clone(),
                assignment_generation: self.assignment_generation,
                resolver_epoch: self.resolver_epoch,
                peer: self.peer,
                reply: Box::new(reply),
            })
            .map_err(|error| -> io::Error {
                match error {
                    mpsc::TrySendError::Full(_) => io::ErrorKind::WouldBlock.into(),
                    mpsc::TrySendError::Disconnected(_) => io::ErrorKind::BrokenPipe.into(),
                }
            })?;
        if let Some(wake) = &self.wake {
            wake()?;
        }
        Ok(())
    }
}
