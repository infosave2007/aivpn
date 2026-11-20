//! Обмен DNS сохраняет исходный кадр и право на путь сокета до завершения запроса.

use hickory_proto::op::{Message, MessageType};
use std::{future::Future, io, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, UdpSocket},
};

const MAX_WIRE: usize = u16::MAX as usize;
const DEADLINE: Duration = Duration::from_secs(5);
const UDP_RETRY_INTERVAL: Duration = Duration::from_millis(500);

pub struct RoutedSocket<S, L> {
    pub socket: S,
    pub lease: L,
}

/// Реализация регистрирует конкретный сокет до connect и удерживает его право через lease.
pub trait DnsSocketRoute: Send + Sync {
    type Lease: Send;

    fn udp(
        &self,
        peer: SocketAddr,
    ) -> impl Future<Output = io::Result<RoutedSocket<UdpSocket, Self::Lease>>> + Send;

    fn tcp(
        &self,
        peer: SocketAddr,
    ) -> impl Future<Output = io::Result<RoutedSocket<TcpSocket, Self::Lease>>> + Send;
}

pub async fn exchange<R: DnsSocketRoute>(
    route: &R,
    peer: SocketAddr,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    tokio::time::timeout(DEADLINE, exchange_with_route(route, peer, query))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Истек срок запроса DNS"))?
}

pub async fn exchange_tcp<R: DnsSocketRoute>(
    route: &R,
    peer: SocketAddr,
    wire: &[u8],
) -> io::Result<Vec<u8>> {
    tokio::time::timeout(DEADLINE, async {
        let query = parse_query(wire)?;
        tcp_exchange(route, peer, wire, &query).await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Истек срок запроса DNS"))?
}

async fn exchange_with_route<R: DnsSocketRoute>(
    route: &R,
    peer: SocketAddr,
    wire: &[u8],
) -> io::Result<Vec<u8>> {
    let query = parse_query(wire)?;
    let mut response = vec![0; MAX_WIRE];
    let truncated = {
        let RoutedSocket {
            socket,
            lease: _lease,
        } = route.udp(peer).await?;
        socket.connect(peer).await?;
        // Повторяем тот же запрос через тот же разрешенный сокет в пределах общего срока.
        let size = loop {
            if socket.send(wire).await? != wire.len() {
                return Err(io::ErrorKind::WriteZero.into());
            }
            match tokio::time::timeout(UDP_RETRY_INTERVAL, socket.recv(&mut response)).await {
                Ok(received) => break received?,
                Err(_) => continue,
            }
        };
        response.truncate(size);
        validate_response(&response, &query)?
    };
    if !truncated {
        return Ok(response);
    }
    // Право UDP освобождено до нового сокета. Оба обмена используют один deadline.
    tcp_exchange(route, peer, wire, &query).await
}

async fn tcp_exchange<R: DnsSocketRoute>(
    route: &R,
    peer: SocketAddr,
    wire: &[u8],
    query: &Message,
) -> io::Result<Vec<u8>> {
    let RoutedSocket {
        socket,
        lease: _lease,
    } = route.tcp(peer).await?;
    let mut stream = socket.connect(peer).await?;
    stream.write_u16(wire.len() as u16).await?;
    stream.write_all(wire).await?;
    let size = stream.read_u16().await? as usize;
    if size < 12 {
        return Err(invalid("Некорректный размер ответа DNS по TCP"));
    }
    let mut response = vec![0; size];
    stream.read_exact(&mut response).await?;
    if validate_response(&response, &query)? {
        return Err(invalid("Усеченный ответ DNS по TCP"));
    }
    Ok(response)
}

fn parse_query(wire: &[u8]) -> io::Result<Message> {
    if !(12..=MAX_WIRE).contains(&wire.len()) {
        return Err(invalid("Некорректный размер запроса DNS"));
    }
    let query = Message::from_vec(wire).map_err(|_| invalid("Некорректный запрос DNS"))?;
    if query.metadata.message_type != MessageType::Query || query.queries.is_empty() {
        return Err(invalid("Ожидался запрос DNS с вопросом"));
    }
    Ok(query)
}

fn validate_response(wire: &[u8], query: &Message) -> io::Result<bool> {
    Ok(response(wire, query)?.metadata.truncation)
}

pub(crate) fn response(wire: &[u8], query: &Message) -> io::Result<Message> {
    let answer = Message::from_vec(wire).map_err(|_| invalid("Некорректный ответ DNS"))?;
    if answer.metadata.message_type != MessageType::Response
        || answer.metadata.id != query.metadata.id
        || answer.metadata.op_code != query.metadata.op_code
        || answer.queries != query.queries
    {
        return Err(invalid("Ответ DNS не соответствует запросу"));
    }
    Ok(answer)
}

pub fn udp_answer(query: &[u8], answer: Vec<u8>) -> io::Result<Vec<u8>> {
    let query = Message::from_vec(query).map_err(io::Error::other)?;
    if answer.len() <= query.max_payload() as usize {
        return Ok(answer);
    }
    let mut truncated = Message::from_vec(&answer)
        .map_err(io::Error::other)?
        .truncate();
    truncated.metadata.authentic_data = false;
    let wire = truncated.to_vec().map_err(io::Error::other)?;
    if wire.len() > query.max_payload() as usize {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(wire)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    pub(crate) struct Lease(Arc<AtomicUsize>);
    impl Drop for Lease {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    pub(crate) struct LocalRoute {
        pub(crate) active: Arc<AtomicUsize>,
        pub(crate) opened: AtomicUsize,
    }
    impl LocalRoute {
        fn lease(&self, peer: SocketAddr) -> Lease {
            assert!(peer.ip().is_loopback());
            self.active.fetch_add(1, Ordering::SeqCst);
            self.opened.fetch_add(1, Ordering::SeqCst);
            Lease(self.active.clone())
        }
    }

    #[tokio::test]
    async fn lost_udp_queries_retry_with_the_same_wire_peer_and_route_lease() {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = udp.local_addr().unwrap();
        let wire = query(0x7261);
        let mut expected = wire.clone();
        expected[2] |= 0x80;
        let query_wire = wire.clone();
        let answer = expected.clone();
        let route = LocalRoute {
            active: Arc::new(AtomicUsize::new(0)),
            opened: AtomicUsize::new(0),
        };
        let active = route.active.clone();
        let server = tokio::spawn(async move {
            let mut first_peer = None;
            let mut received = vec![0; MAX_WIRE];
            for attempt in 0..3 {
                let (size, source) = udp.recv_from(&mut received).await.unwrap();
                assert_eq!(&received[..size], query_wire.as_slice());
                assert_eq!(active.load(Ordering::SeqCst), 1);
                assert_eq!(*first_peer.get_or_insert(source), source);
                if attempt == 2 {
                    udp.send_to(&answer, source).await.unwrap();
                }
            }
        });
        let result =
            tokio::time::timeout(Duration::from_secs(2), exchange(&route, peer, &wire)).await;
        if result.is_err() {
            server.abort();
        }
        let server_result = server.await;
        assert!(
            result.is_ok(),
            "Потеря первых запросов сорвала разрешение DNS"
        );
        assert_eq!(result.unwrap().unwrap(), expected);
        server_result.unwrap();
        assert_eq!(route.opened.load(Ordering::SeqCst), 1);
        assert_eq!(route.active.load(Ordering::SeqCst), 0);
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

    pub(crate) fn query(id: u16) -> Vec<u8> {
        let mut query = vec![0x12, 0x34, 0x01, 0x10, 0, 1, 0, 0, 0, 0, 0, 1];
        query[..2].copy_from_slice(&id.to_be_bytes());
        query.extend_from_slice(b"\x04test\x03lab\x04test\0\0\x01\0\x01");
        query.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0]);
        query
    }

    #[tokio::test]
    async fn truncated_udp_uses_same_tcp_peer_preserves_wire_and_releases_routes() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(peer).await.unwrap();
        let query = query(0x1234);
        let mut expected = query.clone();
        expected[2] |= 0x80;
        expected[3] |= 0x20;
        let original = query.clone();
        let answer = expected.clone();
        let route = LocalRoute {
            active: Arc::new(AtomicUsize::new(0)),
            opened: AtomicUsize::new(0),
        };
        let active = route.active.clone();
        let server = tokio::spawn(async move {
            let mut bytes = [0; 65535];
            let (size, source) = udp.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..size], original);
            assert_eq!(active.load(Ordering::SeqCst), 1);
            let mut truncated = original.clone();
            truncated[2] |= 0x82;
            udp.send_to(&truncated, source).await.unwrap();
            let (mut stream, _) = tcp.accept().await.unwrap();
            let size = stream.read_u16().await.unwrap() as usize;
            let mut wire = vec![0; size];
            stream.read_exact(&mut wire).await.unwrap();
            assert_eq!(wire, original);
            assert_eq!(active.load(Ordering::SeqCst), 1);
            stream.write_u16(answer.len() as u16).await.unwrap();
            stream.write_all(&answer).await.unwrap();
        });
        let result = exchange(&route, peer, &query).await;
        assert!(result.is_ok(), "{}", result.unwrap_err());
        assert_eq!(result.unwrap(), expected);
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(route.opened.load(Ordering::SeqCst), 2);
        assert_eq!(route.active.load(Ordering::SeqCst), 0);
    }
}
