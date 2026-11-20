//! Windows entry общего клиента. Служба передает handles через точный allowlist.
use aivpn_client::{AivpnClient, ConfirmedAssignment, ManagedChannel, ManagedEndpoint};
use aivpn_common::{
    error::{Error, Result},
    network_config::ClientNetworkConfig,
    transport::SocketGuard,
};
use aivpn_desktop_agent::{
    windows::worker::{
        administration_handle, endpoint, verify_current_worker, SharedTransport, Winsock,
        WorkerChannel,
    },
    worker_protocol::{InterfaceAssignment, WorkerEvent},
};
use std::{
    io,
    net::SocketAddr,
    num::NonZeroU64,
    os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle, RawSocket},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::net::windows::named_pipe::NamedPipeClient;

struct ServiceChannel {
    stream: Arc<Mutex<WorkerChannel>>,
    generation: u64,
    peer: SocketAddr,
    winsock: Arc<Winsock>,
    endpoint: AtomicU64,
}
impl ServiceChannel {
    fn exchange(&self, event: WorkerEvent) -> Result<Vec<u8>> {
        let stream = self
            .stream
            .lock()
            .map_err(|_| io::Error::other("Канал службы поврежден"))?;
        stream.send(
            &serde_json::to_vec(&event).map_err(io::Error::other)?,
            Duration::from_secs(5),
        )?;
        Ok(stream.receive(event.response_timeout())?)
    }
    fn call(&self, event: WorkerEvent) -> Result<()> {
        if self.exchange(event)? != b"ACK" {
            return Err(Error::InvalidPacket("Нет подтверждения службы"));
        }
        Ok(())
    }
    fn reconnect(&self) -> Result<(u64, SocketAddr)> {
        let bytes = self.exchange(WorkerEvent::Reconnecting {
            generation: self.generation,
        })?;
        let reply: serde_json::Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        let next = reply["next_generation"]
            .as_u64()
            .ok_or(Error::InvalidPacket("Нет поколения службы"))?;
        if self.generation.checked_add(1) != Some(next) {
            return Err(Error::InvalidPacket("Чужое поколение службы"));
        }
        let peer = serde_json::from_value(reply["peer"].clone()).map_err(io::Error::other)?;
        Ok((next, peer))
    }
}
impl SocketGuard for ServiceChannel {
    fn allow_peer(&self, peer: SocketAddr) -> Result<()> {
        if peer != self.peer {
            return Err(Error::InvalidPacket("Чужой адрес транспорта"));
        }
        Ok(())
    }
    fn create_udp_socket(&self, peer: SocketAddr) -> Result<Option<std::net::UdpSocket>> {
        self.allow_peer(peer)?;
        if self.endpoint.load(Ordering::Acquire) != 0 {
            return Err(Error::InvalidPacket("Transport уже получен"));
        }
        let info = self.exchange(WorkerEvent::Transport {
            generation: self.generation,
            peer,
        })?;
        let transport = SharedTransport::from_protocol_info(&info)?;
        self.endpoint.store(transport.endpoint(), Ordering::Release);
        Ok(Some(transport.into_udp(&self.winsock)))
    }
    fn protect(&self, socket: RawSocket) -> Result<()> {
        let expected = self.endpoint.load(Ordering::Acquire);
        if expected == 0 || endpoint(socket)? != expected {
            return Err(Error::InvalidPacket("Чужой transport endpoint"));
        }
        Ok(())
    }
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> aivpn_common::transport::ResolveFuture<'a> {
        Box::pin(async move {
            let peer = SocketAddr::new(
                host.parse()
                    .map_err(|_| Error::InvalidPacket("Работник принимает numeric адрес"))?,
                port,
            );
            self.allow_peer(peer)?;
            Ok(vec![peer])
        })
    }
}
impl ConfirmedAssignment for ServiceChannel {
    fn confirmed_assignment(&self, config: &ClientNetworkConfig) -> Result<()> {
        let network = InterfaceAssignment::from_config(config)?;
        self.call(WorkerEvent::Assignment {
            generation: self.generation,
            network,
        })
    }
}
fn inherited(value: &str) -> io::Result<OwnedHandle> {
    let raw = value.parse::<usize>().map_err(io::Error::other)?;
    if raw == 0 || raw == usize::MAX {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(raw as _) };
    if unsafe {
        windows_sys::Win32::Foundation::SetHandleInformation(
            handle.as_raw_handle(),
            windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT,
            0,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(handle)
}
pub fn run() -> Result<()> {
    run_from(std::env::args_os().skip(1).collect())
}

pub fn run_from(arguments: Vec<std::ffi::OsString>) -> Result<()> {
    verify_current_worker()?;
    let raw = std::io::stderr().as_raw_handle();
    if raw.is_null() || raw == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error().into());
    }
    let handle =
        unsafe { std::os::windows::io::BorrowedHandle::borrow_raw(raw) }.try_clone_to_owned()?;
    let log = aivpn_desktop_agent::worker_log::WorkerLog::new(std::fs::File::from(handle))?;
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || log.clone())
        .init();
    let args = arguments
        .into_iter()
        .map(|value| {
            value
                .into_string()
                .map_err(|_| Error::InvalidPacket("Неверный унаследованный handle"))
        })
        .collect::<Result<Vec<_>>>()?;
    if args.len() != 4
        || args
            .iter()
            .enumerate()
            .any(|(i, value)| args[..i].contains(value))
    {
        return Err(Error::InvalidPacket("Нет унаследованных каналов"));
    }
    let event = inherited(&args[3])?;
    let wake: Arc<dyn Fn() -> io::Result<()> + Send + Sync> = Arc::new(move || {
        if unsafe { windows_sys::Win32::System::Threading::SetEvent(event.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    });
    let stream = WorkerChannel::from_owned(inherited(&args[0])?)?.with_wakeup(wake.clone());
    let packet = inherited(&args[1])?;
    let administration = administration_handle(inherited(&args[2])?, stream.server_pid()?)?;
    stream.send(b"RESTRICTED", Duration::from_secs(5))?;
    let mut profile: serde_json::Value =
        serde_json::from_slice(&stream.receive(Duration::from_secs(5))?)
            .map_err(io::Error::other)?;
    let name = profile["name"]
        .as_str()
        .ok_or(Error::InvalidPacket("Нет имени канала"))?
        .to_owned();
    let config = crate::managed_worker_config::client_config(&profile["connection"], name.clone())?;
    let peer = config.server_addr.parse().map_err(io::Error::other)?;
    let generation = profile["generation"]
        .as_u64()
        .filter(|v| *v != 0)
        .ok_or(Error::InvalidPacket("Нет поколения службы"))?;
    let mut channel = Arc::new(ServiceChannel {
        stream: Arc::new(Mutex::new(stream)),
        generation,
        peer,
        winsock: Arc::new(Winsock::start()?),
        endpoint: AtomicU64::new(0),
    });
    let shutdown = Arc::new(AtomicBool::new(false));
    let runtime = crate::managed_worker_config::runtime()?;
    runtime.block_on(async {
        use aivpn_client::reconnect::{
            should_reset_backoff, wait_reconnect_backoff, INITIAL_BACKOFF, MAX_BACKOFF,
        };
        let administration =
            unsafe { NamedPipeClient::from_raw_handle(administration.into_raw_handle()) }?;
        let administration =
            crate::managed_administration::AdministrationServer::start(administration);
        let packet = unsafe { NamedPipeClient::from_raw_handle(packet.into_raw_handle()) }?;
        let capacity = packet.info()?.in_buffer_size as usize;
        let packet = ManagedChannel::with_wakeup_capacity(packet, Some(wake), capacity);
        let mut backoff = INITIAL_BACKOFF;
        let mut reconnect = crate::managed_worker_config::ReconnectState::default();
        loop {
            let endpoint = ManagedEndpoint::new(
                packet.clone(),
                NonZeroU64::new(channel.generation)
                    .ok_or(Error::InvalidPacket("Нет поколения пакетного канала"))?,
                name.clone(),
                channel.clone(),
            );
            let config = reconnect.config(&profile["connection"], name.clone())?;
            let identity = crate::managed_worker_config::device_identity(&profile["connection"])?;
            let mut client = AivpnClient::new_managed_with_device_identity(
                config,
                endpoint,
                channel.clone(),
                identity,
            )?;
            crate::managed_worker_config::apply_runtime(&mut client, &profile["connection"])?;
            administration.bind(channel.generation, client.session_administration()?)?;
            let started = std::time::Instant::now();
            let result = client.run(shutdown.clone()).await;
            administration.clear();
            let retry = reconnect.record(client.ever_connected(), client.terminal_rejected());
            if let Err(error) = &result {
                tracing::warn!("Сеанс worker завершился: {error}");
            }
            client.disconnect().await;
            drop(client);
            if shutdown.load(Ordering::Acquire) || !retry {
                return result;
            }
            // ACK выдается после закрытия readiness, отзыва endpoint и новой lease.
            let (next, peer) = channel.reconnect()?;
            profile["connection"]["s"] = peer.to_string().into();
            channel = Arc::new(ServiceChannel {
                stream: channel.stream.clone(),
                generation: next,
                peer,
                winsock: channel.winsock.clone(),
                endpoint: AtomicU64::new(0),
            });
            if should_reset_backoff(started.elapsed()) {
                backoff = INITIAL_BACKOFF;
            }
            wait_reconnect_backoff(backoff, &shutdown).await;
            backoff = std::cmp::min(backoff * 2, MAX_BACKOFF);
        }
    })
}
