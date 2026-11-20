//! Локальные слушатели общего DNS. Путь задает текущая capability, а не имя интерфейса.

use super::exchange::{self, udp_answer, DnsSocketRoute};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{watch, OwnedSemaphorePermit, Semaphore},
    task::{JoinHandle, JoinSet},
};

const MAX_WIRE: usize = u16::MAX as usize;
const MAX_IN_FLIGHT: usize = 256;
const MAX_CONNECTIONS: usize = 64;
const BYTE_BUDGET: usize = 32 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(5);

pub struct DnsRelayGate<R>(watch::Sender<Option<Arc<R>>>);
impl<R> Clone for DnsRelayGate<R> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<R> Default for DnsRelayGate<R> {
    fn default() -> Self {
        Self(watch::channel(None).0)
    }
}
impl<R> DnsRelayGate<R> {
    /// Каждый вызов создает новое поколение, даже при повторе того же маршрута.
    pub fn publish(&self, route: R) {
        self.0.send_replace(Some(Arc::new(route)));
    }
    pub fn close(&self) {
        self.0.send_replace(None);
    }
}

pub struct DnsRelayHandle {
    task: Option<JoinHandle<io::Result<()>>>,
    addresses: Vec<SocketAddr>,
    listeners: Listeners,
    stop: watch::Sender<bool>,
}
impl DnsRelayHandle {
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
    /// Служба регистрирует именно эти сокеты до изменения DNS ОС.
    #[cfg(unix)]
    pub fn duplicate_sockets(&self) -> io::Result<Vec<std::os::fd::OwnedFd>> {
        use std::os::fd::AsFd;
        self.listeners
            .iter()
            .try_fold(Vec::new(), |mut sockets, (tcp, udp)| {
                sockets.push(tcp.as_fd().try_clone_to_owned()?);
                sockets.push(udp.as_fd().try_clone_to_owned()?);
                Ok(sockets)
            })
    }
    #[cfg(windows)]
    pub fn duplicate_sockets(&self) -> io::Result<Vec<std::os::windows::io::OwnedSocket>> {
        use std::os::windows::io::AsSocket;
        self.listeners
            .iter()
            .try_fold(Vec::new(), |mut sockets, (tcp, udp)| {
                sockets.push(tcp.as_socket().try_clone_to_owned()?);
                sockets.push(udp.as_socket().try_clone_to_owned()?);
                Ok(sockets)
            })
    }
    pub fn is_finished(&self) -> bool {
        self.task.as_ref().is_none_or(JoinHandle::is_finished)
    }
    pub async fn wait(&mut self) -> io::Result<()> {
        let result = self.task.as_mut().ok_or(io::ErrorKind::NotConnected)?.await;
        self.task.take();
        match result {
            Ok(result) => result,
            Err(error) => Err(io::Error::other(error)),
        }
    }
    pub async fn shutdown(mut self) -> io::Result<()> {
        self.stop.send_replace(true);
        let Some(task) = self.task.take() else {
            return Ok(());
        };
        match task.await {
            Ok(result) => result,
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(io::Error::other(error)),
        }
    }
}
impl Drop for DnsRelayHandle {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}

/// Успешный bind подтверждает только слушатели. Готовность VPN подтверждает их владелец.
pub async fn bind<R: DnsSocketRoute + 'static>(
    addresses: &[SocketAddr],
    upstream: SocketAddr,
    gate: &DnsRelayGate<R>,
) -> io::Result<DnsRelayHandle> {
    bind_configured(addresses, upstream, gate, true).await
}

pub(super) async fn bind_configured<R: DnsSocketRoute + 'static>(
    addresses: &[SocketAddr],
    upstream: SocketAddr,
    gate: &DnsRelayGate<R>,
    local_only: bool,
) -> io::Result<DnsRelayHandle> {
    if addresses.is_empty()
        || addresses.len() > 2
        || (local_only && addresses.iter().any(|address| !address.ip().is_loopback()))
        || upstream.port() == 0
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut listeners = Vec::new();
    let mut bound = Vec::new();
    for address in addresses {
        let tcp = bind_tcp(*address).await?;
        let actual = tcp.local_addr()?;
        let udp = Arc::new(bind_udp(actual).await?);
        bound.push(actual);
        listeners.push((Arc::new(tcp), udp));
    }
    let ready = gate.0.subscribe();
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(serve(listeners.clone(), upstream, ready, stopped));
    Ok(DnsRelayHandle {
        task: Some(task),
        addresses: bound,
        listeners,
        stop,
    })
}

#[cfg(not(windows))]
async fn bind_tcp(address: SocketAddr) -> io::Result<TcpListener> {
    TcpListener::bind(address).await
}
#[cfg(not(windows))]
async fn bind_udp(address: SocketAddr) -> io::Result<UdpSocket> {
    UdpSocket::bind(address).await
}

#[cfg(windows)]
fn exclusive_socket(address: SocketAddr, tcp: bool) -> io::Result<socket2::Socket> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::*;
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(address),
        if tcp {
            socket2::Type::STREAM
        } else {
            socket2::Type::DGRAM
        },
        Some(if tcp {
            socket2::Protocol::TCP
        } else {
            socket2::Protocol::UDP
        }),
    )?;
    let enabled = 1i32;
    if unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&enabled as *const i32).cast(),
            std::mem::size_of_val(&enabled) as i32,
        )
    } == SOCKET_ERROR
    {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    if !tcp {
        disable_udp_peer_resets(&socket)?;
    }
    Ok(socket)
}
#[cfg(windows)]
fn disable_udp_peer_resets(socket: &socket2::Socket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        WSAGetLastError, WSAIoctl, SIO_UDP_CONNRESET, SOCKET_ERROR,
    };
    // ICMP от уже закрытого клиента относится к его ответу, а не к слушателю.
    let disabled = 0i32;
    let mut returned = 0;
    if unsafe {
        WSAIoctl(
            socket.as_raw_socket() as usize,
            SIO_UDP_CONNRESET,
            (&disabled as *const i32).cast(),
            std::mem::size_of_val(&disabled) as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            None,
        )
    } == SOCKET_ERROR
    {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(())
}
#[cfg(windows)]
async fn bind_tcp(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = exclusive_socket(address, true)?;
    socket.listen(128)?;
    TcpListener::from_std(socket.into())
}
#[cfg(windows)]
async fn bind_udp(address: SocketAddr) -> io::Result<UdpSocket> {
    UdpSocket::from_std(exclusive_socket(address, false)?.into())
}

type Listeners = Vec<(Arc<TcpListener>, Arc<UdpSocket>)>;
enum Job {
    Datagram(Arc<UdpSocket>, io::Result<(Vec<u8>, SocketAddr)>),
    Connection(Arc<TcpListener>, io::Result<TcpStream>),
    Finished,
}

fn receive_udp(jobs: &mut JoinSet<Job>, listener: Arc<UdpSocket>) {
    jobs.spawn(async move {
        let mut buffer = vec![0; MAX_WIRE];
        let received = listener
            .recv_from(&mut buffer)
            .await
            .map(|(size, peer)| (buffer[..size].to_vec(), peer));
        Job::Datagram(listener, received)
    });
}
fn accept_tcp(jobs: &mut JoinSet<Job>, listener: Arc<TcpListener>) {
    jobs.spawn(async move {
        let received = listener.accept().await.map(|(stream, _)| stream);
        Job::Connection(listener, received)
    });
}
fn receive(jobs: &mut JoinSet<Job>, listeners: &Listeners) {
    for (tcp, udp) in listeners {
        receive_udp(jobs, udp.clone());
        accept_tcp(jobs, tcp.clone());
    }
}
async fn drain(jobs: &mut JoinSet<Job>) {
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
}

async fn serve<R: DnsSocketRoute + 'static>(
    listeners: Listeners,
    upstream: SocketAddr,
    mut ready: watch::Receiver<Option<Arc<R>>>,
    mut stop: watch::Receiver<bool>,
) -> io::Result<()> {
    let budget = Arc::new(Budget::new());
    let mut jobs = JoinSet::new();
    receive(&mut jobs, &listeners);
    let result = loop {
        let job = tokio::select! {
            biased;
            _ = stop.changed() => break Ok(()),
            changed = ready.changed() => {
                drain(&mut jobs).await;
                if changed.is_err() { break Ok(()); }
                receive(&mut jobs, &listeners);
                continue;
            }
            job = jobs.join_next() => job,
        };
        match job {
            Some(Ok(Job::Datagram(listener, Ok((wire, peer))))) => {
                receive_udp(&mut jobs, listener.clone());
                let Some(route) = ready.borrow().clone() else {
                    continue;
                };
                if wire.len() < 12 {
                    continue;
                }
                let Some(permit) = budget.query(wire.len()) else {
                    continue;
                };
                let epoch = ready.clone();
                jobs.spawn(async move {
                    let _permit = permit;
                    let _ = tokio::time::timeout(
                        DEADLINE,
                        udp_query(listener, peer, wire, upstream, epoch, route),
                    )
                    .await;
                    Job::Finished
                });
            }
            Some(Ok(Job::Connection(listener, Ok(stream)))) => {
                accept_tcp(&mut jobs, listener);
                let Some(route) = ready.borrow().clone() else {
                    continue;
                };
                let Ok(permit) = budget.connections.clone().try_acquire_owned() else {
                    continue;
                };
                let budget = budget.clone();
                let epoch = ready.clone();
                jobs.spawn(async move {
                    let _permit = permit;
                    tcp_queries(stream, upstream, epoch, route, budget).await;
                    Job::Finished
                });
            }
            Some(Ok(Job::Datagram(_, Err(error)) | Job::Connection(_, Err(error)))) => {
                break Err(error)
            }
            Some(Ok(Job::Finished)) => (),
            Some(Err(error)) => break Err(io::Error::other(error)),
            None => break Err(io::Error::other("Остановлены слушатели DNS")),
        }
    };
    // Один набор задач удерживает все сокеты и leases до завершения их отмены.
    drain(&mut jobs).await;
    result
}

struct Budget {
    queries: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
    connections: Arc<Semaphore>,
}
impl Budget {
    fn new() -> Self {
        Self {
            queries: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            bytes: Arc::new(Semaphore::new(BYTE_BUDGET)),
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        }
    }
    fn query(&self, size: usize) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
        let query = self.queries.clone().try_acquire_owned().ok()?;
        let bytes = self
            .bytes
            .clone()
            .try_acquire_many_owned((size + 2 * MAX_WIRE + 2) as u32)
            .ok()?;
        Some((query, bytes))
    }
}

async fn udp_query<R: DnsSocketRoute>(
    output: Arc<UdpSocket>,
    peer: SocketAddr,
    wire: Vec<u8>,
    upstream: SocketAddr,
    epoch: watch::Receiver<Option<Arc<R>>>,
    route: Arc<R>,
) -> io::Result<()> {
    let answer = exchange::exchange(route.as_ref(), upstream, &wire).await?;
    let answer = udp_answer(&wire, answer)?;
    loop {
        output.writable().await?;
        let current = epoch.borrow();
        if !current
            .as_ref()
            .is_some_and(|value| Arc::ptr_eq(value, &route))
        {
            return Err(io::ErrorKind::Interrupted.into());
        }
        // Gate close ждет этот короткий синхронный send, без await под borrow.
        match output.try_send_to(&answer, peer) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            result => return result.map(|_| ()),
        }
    }
}

async fn tcp_queries<R: DnsSocketRoute>(
    mut stream: TcpStream,
    upstream: SocketAddr,
    epoch: watch::Receiver<Option<Arc<R>>>,
    route: Arc<R>,
    budget: Arc<Budget>,
) {
    for _ in 0..MAX_IN_FLIGHT {
        let result = tokio::time::timeout(DEADLINE, async {
            let size = stream.read_u16().await? as usize;
            if size < 12 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let _query = budget.query(size).ok_or(io::ErrorKind::WouldBlock)?;
            let mut wire = vec![0; size];
            stream.read_exact(&mut wire).await?;
            let answer = exchange::exchange_tcp(route.as_ref(), upstream, &wire).await?;
            write_tcp(&stream, &answer, &epoch, &route).await
        })
        .await;
        if !matches!(result, Ok(Ok(()))) {
            break;
        }
    }
}

async fn write_tcp<R>(
    stream: &TcpStream,
    answer: &[u8],
    epoch: &watch::Receiver<Option<Arc<R>>>,
    route: &Arc<R>,
) -> io::Result<()> {
    let mut frame = Vec::with_capacity(answer.len() + 2);
    frame.extend_from_slice(&(answer.len() as u16).to_be_bytes());
    frame.extend_from_slice(answer);
    let mut remaining = frame.as_slice();
    while !remaining.is_empty() {
        stream.writable().await?;
        let current = epoch.borrow();
        if !current
            .as_ref()
            .is_some_and(|value| Arc::ptr_eq(value, route))
        {
            return Err(io::ErrorKind::Interrupted.into());
        }
        match stream.try_write(remaining) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(size) => remaining = &remaining[size..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::exchange::RoutedSocket;
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::{io::AsyncWriteExt, net::TcpSocket, sync::oneshot};

    struct Lease(Arc<AtomicUsize>);
    impl Drop for Lease {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    struct LocalRoute {
        active: Arc<AtomicUsize>,
        opened: AtomicUsize,
    }
    impl LocalRoute {
        fn lease(&self, peer: SocketAddr) -> Lease {
            assert!(peer.ip().is_loopback());
            self.active.fetch_add(1, Ordering::SeqCst);
            self.opened.fetch_add(1, Ordering::SeqCst);
            Lease(self.active.clone())
        }
    }
    impl DnsSocketRoute for LocalRoute {
        type Lease = Lease;
        async fn udp(&self, peer: SocketAddr) -> io::Result<RoutedSocket<UdpSocket, Lease>> {
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            Ok(RoutedSocket {
                socket,
                lease: self.lease(peer),
            })
        }
        async fn tcp(&self, peer: SocketAddr) -> io::Result<RoutedSocket<TcpSocket, Lease>> {
            Ok(RoutedSocket {
                socket: TcpSocket::new_v4()?,
                lease: self.lease(peer),
            })
        }
    }

    fn query(id: u16) -> Vec<u8> {
        let mut query = vec![0x12, 0x34, 0x01, 0x10, 0, 1, 0, 0, 0, 0, 0, 1];
        query[..2].copy_from_slice(&id.to_be_bytes());
        query.extend_from_slice(b"\x04test\x03lab\x04test\0\0\x01\0\x01");
        query.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0]);
        query
    }

    #[tokio::test]
    async fn abandoned_udp_client_does_not_stop_other_dns_clients() {
        tokio::time::timeout(Duration::from_secs(4), async {
            let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let gate = DnsRelayGate::default();
            let mut relay = bind(
                &["127.0.0.1:0".parse().unwrap()],
                upstream.local_addr().unwrap(),
                &gate,
            )
            .await
            .unwrap();
            gate.publish(LocalRoute {
                active: Arc::new(AtomicUsize::new(0)),
                opened: AtomicUsize::new(0),
            });
            let abandoned = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            abandoned
                .send_to(&query(21), relay.addresses()[0])
                .await
                .unwrap();
            let mut bytes = [0; 2048];
            let (size, peer) = upstream.recv_from(&mut bytes).await.unwrap();
            drop(abandoned);
            bytes[2] |= 0x80;
            upstream.send_to(&bytes[..size], peer).await.unwrap();
            // Windows сообщает недоступность прежнего UDP peer следующему recv.
            tokio::time::sleep(Duration::from_millis(100)).await;
            if relay.is_finished() {
                let result = relay.wait().await;
                panic!("Закрытый UDP клиент остановил DNS listener: {result:?}");
            }
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client
                .send_to(&query(22), relay.addresses()[0])
                .await
                .unwrap();
            let (size, peer) = upstream.recv_from(&mut bytes).await.unwrap();
            bytes[2] |= 0x80;
            upstream.send_to(&bytes[..size], peer).await.unwrap();
            let size = client.recv(&mut bytes).await.unwrap();
            let mut expected = query(22);
            expected[2] |= 0x80;
            assert_eq!(&bytes[..size], expected);
            relay.shutdown().await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn udp_tcp_and_gate_close_keep_routes_and_listener_lifetimes_bounded() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let upstream = tcp.local_addr().unwrap();
            let udp = UdpSocket::bind(upstream).await.unwrap();
            let gate = DnsRelayGate::default();
            let relay = bind(&["127.0.0.1:0".parse().unwrap()], upstream, &gate)
                .await
                .unwrap();
            let address = relay.addresses()[0];
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client.send_to(&query(1), address).await.unwrap();
            let mut bytes = [0; 2048];
            assert!(
                tokio::time::timeout(Duration::from_millis(50), udp.recv_from(&mut bytes))
                    .await
                    .is_err()
            );
            let active = Arc::new(AtomicUsize::new(0));
            gate.publish(LocalRoute {
                active: active.clone(),
                opened: AtomicUsize::new(0),
            });
            let (held, observed) = oneshot::channel();
            let (send_old, wait_old) = oneshot::channel();
            let server = tokio::spawn(async move {
                let mut bytes = [0; 2048];
                let (size, peer) = udp.recv_from(&mut bytes).await.unwrap();
                assert_eq!(&bytes[..size], query(2));
                bytes[2] |= 0x80;
                udp.send_to(&bytes[..size], peer).await.unwrap();
                let (mut stream, _) = tcp.accept().await.unwrap();
                let size = stream.read_u16().await.unwrap() as usize;
                stream.read_exact(&mut bytes[..size]).await.unwrap();
                assert_eq!(&bytes[..size], query(3));
                bytes[2] |= 0x80;
                stream.write_u16(size as u16).await.unwrap();
                stream.write_all(&bytes[..size]).await.unwrap();
                let (size, peer) = udp.recv_from(&mut bytes).await.unwrap();
                assert_eq!(&bytes[..size], query(4));
                held.send(()).unwrap();
                wait_old.await.unwrap();
                bytes[2] |= 0x80;
                udp.send_to(&bytes[..size], peer).await.unwrap();
            });
            client.send_to(&query(2), address).await.unwrap();
            let size = client.recv(&mut bytes).await.unwrap();
            let mut answer = query(2);
            answer[2] |= 0x80;
            assert_eq!(&bytes[..size], answer);
            let mut stream = TcpStream::connect(address).await.unwrap();
            let wire = query(3);
            stream.write_u16(wire.len() as u16).await.unwrap();
            stream.write_all(&wire).await.unwrap();
            let size = stream.read_u16().await.unwrap() as usize;
            stream.read_exact(&mut bytes[..size]).await.unwrap();
            let mut answer = query(3);
            answer[2] |= 0x80;
            assert_eq!(&bytes[..size], answer);
            drop(stream);
            client.send_to(&query(4), address).await.unwrap();
            observed.await.unwrap();
            assert_eq!(active.load(Ordering::SeqCst), 1);
            gate.close();
            send_old.send(()).unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(50), client.recv(&mut bytes))
                    .await
                    .is_err()
            );
            relay.shutdown().await.unwrap();
            server.await.unwrap();
            assert_eq!(active.load(Ordering::SeqCst), 0);
            let _udp = UdpSocket::bind(address).await.unwrap();
            let _tcp = TcpListener::bind(address).await.unwrap();
        })
        .await
        .unwrap();
    }
}
