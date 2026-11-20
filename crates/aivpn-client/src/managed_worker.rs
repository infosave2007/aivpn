//! Единственный вход работника - унаследованный приватный канал службы.

use crate::managed_worker_config::client_config;
use aivpn_client::{AivpnClient, ConfirmedAssignment, ManagedEndpoint};
use aivpn_common::{
    error::{Error, Result},
    network_config::ClientNetworkConfig,
    transport::SocketGuard,
};
use aivpn_desktop_agent::{
    linux::{
        initialize_packet_worker,
        worker_protocol::{InterfaceAssignment, WorkerEvent},
    },
    unix::LocalStream,
};
use std::{
    io,
    net::SocketAddr,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

struct ServiceChannel {
    stream: Arc<Mutex<LocalStream>>,
    generation: u64,
    peer: SocketAddr,
}

impl ServiceChannel {
    fn exchange(&self, event: WorkerEvent, descriptor: Option<BorrowedFd<'_>>) -> Result<Vec<u8>> {
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| Error::Session("Канал службы поврежден".into()))?;
        stream.send(
            &serde_json::to_vec(&event).map_err(io::Error::other)?,
            &descriptor.into_iter().collect::<Vec<_>>(),
        )?;
        let response = stream.receive(Some(event.response_timeout()))?;
        if !response.descriptors.is_empty() {
            return Err(Error::Session(
                "Служба отказала в операции работника".into(),
            ));
        }
        Ok(response.payload)
    }
    fn call(&self, event: WorkerEvent, descriptor: Option<BorrowedFd<'_>>) -> Result<()> {
        if self.exchange(event, descriptor)? != b"ACK" {
            return Err(Error::InvalidPacket("Нет подтверждения службы"));
        }
        Ok(())
    }
    fn reconnect(&self) -> Result<(u64, SocketAddr)> {
        let bytes = self.exchange(
            WorkerEvent::Reconnecting {
                generation: self.generation,
            },
            None,
        )?;
        let reply: serde_json::Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        let next = reply["next_generation"]
            .as_u64()
            .ok_or(Error::InvalidPacket("Нет нового поколения службы"))?;
        if next
            != self
                .generation
                .checked_add(1)
                .ok_or(Error::InvalidPacket("Исчерпано поколение службы"))?
        {
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
    fn protect(&self, descriptor: i32) -> Result<()> {
        self.call(
            WorkerEvent::Transport {
                generation: self.generation,
                peer: self.peer,
            },
            Some(unsafe { BorrowedFd::borrow_raw(descriptor) }),
        )
    }
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> aivpn_common::transport::ResolveFuture<'a> {
        Box::pin(async move {
            let address = SocketAddr::new(
                host.parse()
                    .map_err(|_| Error::InvalidPacket("Работник принимает только numeric адрес"))?,
                port,
            );
            self.allow_peer(address)?;
            Ok(vec![address])
        })
    }
}

impl ConfirmedAssignment for ServiceChannel {
    fn confirmed_assignment(&self, config: &ClientNetworkConfig) -> Result<()> {
        let assignment = InterfaceAssignment::from_config(config)?;
        self.call(
            WorkerEvent::Assignment {
                generation: self.generation,
                network: assignment,
            },
            None,
        )
    }
}

pub fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr)
        .init();
    // Descriptor 3 имеет только один владелец. Exec/env/FD allowlist задает служба.
    // Без переданного канала владеть нечем: закрытие неоткрытого номера
    // нарушает IO safety и аварийно завершает отладочную сборку.
    if unsafe { libc::fcntl(3, libc::F_GETFD) } == -1 {
        return Err(Error::InvalidPacket("Работник запускается службой"));
    }
    let control = unsafe { OwnedFd::from_raw_fd(3) };
    if unsafe { libc::geteuid() } == 0
        && (unsafe { libc::setgroups(0, std::ptr::null()) } != 0
            || unsafe { libc::setresgid(65532, 65532, 65532) } != 0
            || unsafe { libc::setresuid(65532, 65532, 65532) } != 0)
    {
        return Err(io::Error::last_os_error().into());
    }
    if unsafe { libc::geteuid() } != 65532 {
        return Err(Error::InvalidPacket("Работник запускается службой"));
    }
    let runtime = initialize_packet_worker(control.as_fd(), crate::managed_worker_config::runtime)?;
    let monitor = control.try_clone()?;
    let mut stream = LocalStream::new(UnixStream::from(control));
    let service_pid = stream.peer_credentials()?.pid;
    stream.send(b"RESTRICTED", &[])?;
    let mut start = stream.receive(Some(Duration::from_secs(5)))?;
    if start.descriptors.len() != 2 {
        return Err(Error::InvalidPacket("Нет пакетного канала"));
    }
    let mut profile: serde_json::Value =
        serde_json::from_slice(&start.payload).map_err(io::Error::other)?;
    let name = profile["name"]
        .as_str()
        .ok_or_else(|| io::Error::other("Нет имени интерфейса"))?
        .to_owned();
    let config = client_config(&profile["connection"], name.clone())?;
    let peer = config
        .server_addr
        .parse()
        .map_err(|_| io::Error::other("Некорректный numeric peer"))?;
    let generation = profile["generation"]
        .as_u64()
        .filter(|n| *n != 0)
        .ok_or(Error::InvalidPacket("Нет поколения службы"))?;
    let mut channel = Arc::new(ServiceChannel {
        stream: Arc::new(Mutex::new(stream)),
        generation,
        peer,
    });
    let shutdown = Arc::new(AtomicBool::new(false));
    let end = shutdown.clone();
    let observer = std::thread::spawn(move || {
        while !end.load(Ordering::Acquire) {
            let mut descriptor = libc::pollfd {
                fd: monitor.as_raw_fd(),
                events: libc::POLLHUP | libc::POLLRDHUP,
                revents: 0,
            };
            if unsafe { libc::poll(&mut descriptor, 1, 100) } < 0 || descriptor.revents != 0 {
                end.store(true, Ordering::Release);
                break;
            }
        }
    });
    let result = runtime.block_on(async {
        use aivpn_client::reconnect::{
            should_reset_backoff, wait_reconnect_backoff, INITIAL_BACKOFF, MAX_BACKOFF,
        };
        let administration = start.descriptors.pop().unwrap();
        let administration = aivpn_desktop_agent::linux::administration_stream(
            administration,
            service_pid,
        )
        .inspect_err(
            |error| tracing::error!(%error, "Не удалось подготовить канал администрирования"),
        )?;
        let administration = crate::managed_administration::AdministrationServer::start(
            tokio::net::UnixStream::from_std(administration)?,
        );
        let descriptor = start.descriptors.remove(0);
        let mut backoff = INITIAL_BACKOFF;
        let mut reconnect = crate::managed_worker_config::ReconnectState::default();
        loop {
            let endpoint =
                ManagedEndpoint::new(descriptor.try_clone()?, name.clone(), channel.clone())?;
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
            client.disconnect().await;
            drop(client);
            if shutdown.load(Ordering::Acquire) || !retry {
                return result;
            }
            // ACK доказывает ready=0, отзыв cookie и новую service-owned lease.
            let (next, peer) = channel.reconnect()?;
            profile["connection"]["s"] = peer.to_string().into();
            channel = Arc::new(ServiceChannel {
                stream: channel.stream.clone(),
                generation: next,
                peer,
            });
            if should_reset_backoff(started.elapsed()) {
                backoff = INITIAL_BACKOFF;
            }
            wait_reconnect_backoff(backoff, &shutdown).await;
            if shutdown.load(Ordering::Acquire) {
                return Ok(());
            }
            backoff = std::cmp::min(backoff * 2, MAX_BACKOFF);
        }
    });
    shutdown.store(true, Ordering::Release);
    let _ = observer.join();
    let _ = channel.call(
        WorkerEvent::Disconnected {
            generation: channel.generation,
        },
        None,
    );
    result
}

#[cfg(test)]
mod assignment_tests {
    use super::*;
    use aivpn_common::network_config::VpnNetworkConfig;
    use aivpn_desktop_agent::linux::worker_protocol::WorkerEvent;

    #[test]
    fn assignment_waits_for_service_to_finish_a_slow_policy_installation() {
        let network = VpnNetworkConfig {
            server_vpn_ip: "10.77.0.1".parse().unwrap(),
            prefix_len: 24,
            mtu: 1280,
            ..Default::default()
        };
        let config = network.client_config("10.77.0.2".parse().unwrap()).unwrap();
        let (worker, service) = UnixStream::pair().unwrap();
        let reader = std::thread::spawn(move || {
            let mut service = LocalStream::new(service);
            let frame = service.receive(Some(Duration::from_secs(5))).unwrap();
            assert!(frame.descriptors.is_empty());
            assert!(matches!(
                serde_json::from_slice::<WorkerEvent>(&frame.payload).unwrap(),
                WorkerEvent::Assignment { generation: 7, .. }
            ));
            std::thread::sleep(Duration::from_secs(6));
            let _ = service.send(b"ACK", &[]);
        });
        let channel = ServiceChannel {
            stream: Arc::new(Mutex::new(LocalStream::new(worker))),
            generation: 7,
            peer: "192.0.2.1:443".parse().unwrap(),
        };
        let result = channel.confirmed_assignment(&config);
        reader.join().unwrap();
        assert!(
            result.is_ok(),
            "Подтвержденное назначение потеряно: {result:?}"
        );
    }

    fn round_trip(keepalive: Option<u8>) {
        let network = VpnNetworkConfig {
            server_vpn_ip: "10.77.0.1".parse().unwrap(),
            prefix_len: 24,
            mtu: 1280,
            ..Default::default()
        };
        let mut config = network.client_config("10.77.0.2".parse().unwrap()).unwrap();
        config.keepalive_secs = keepalive;
        config.validate().unwrap();
        let original = config.clone();
        let (worker, service) = UnixStream::pair().unwrap();
        let reader = std::thread::spawn(move || {
            let mut service = LocalStream::new(service);
            let frame = service.receive(Some(Duration::from_secs(5))).unwrap();
            assert!(frame.descriptors.is_empty());
            let event = serde_json::from_slice::<WorkerEvent>(&frame.payload);
            let value: serde_json::Value = serde_json::from_slice(&frame.payload).unwrap();
            let mut unknown_event = value.clone();
            unknown_event["not_allowed"] = true.into();
            assert!(serde_json::from_value::<WorkerEvent>(unknown_event).is_err());
            let mut unknown_assignment = value;
            unknown_assignment["network"]["not_allowed"] = true.into();
            assert!(serde_json::from_value::<WorkerEvent>(unknown_assignment).is_err());
            service
                .send(if event.is_ok() { b"ACK" } else { b"REJECT" }, &[])
                .unwrap();
            event.map_err(|error| error.to_string())
        });
        let channel = ServiceChannel {
            stream: Arc::new(Mutex::new(LocalStream::new(worker))),
            generation: 7,
            peer: "192.0.2.1:443".parse().unwrap(),
        };
        let result = channel.confirmed_assignment(&config);
        let event = reader.join().unwrap();
        assert!(
            event.is_ok(),
            "Служба отклонила настоящий assignment: {:?}",
            event.err()
        );
        let WorkerEvent::Assignment {
            generation,
            network,
        } = event.unwrap()
        else {
            panic!("Чужое событие");
        };
        assert!(result.is_ok());
        assert_eq!(generation, 7);
        assert_eq!(network.client_ip, config.client_ip);
        assert_eq!(network.server_vpn_ip, config.server_vpn_ip);
        assert_eq!(network.prefix_len, config.prefix_len);
        assert_eq!(network.mtu, config.mtu);
        assert_eq!(network.mdh_len, config.mdh_len);
        assert_eq!(config, original);
    }

    #[test]
    fn assignment_without_keepalive_crosses_service_codec() {
        round_trip(None);
    }

    #[test]
    fn assignment_with_keepalive_crosses_service_codec() {
        round_trip(Some(10));
    }
}
