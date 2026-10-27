//! DNS для служебных соединений использует ту же защиту сокетов, что и транспорт.
use super::SocketGuard;
use crate::error::{Error, Result};
use hickory_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, UdpSocket},
};

pub(super) fn system_servers() -> Vec<SocketAddr> {
    if let Ok(value) = std::env::var("AIVPN_TRANSPORT_DNS") {
        return value
            .split([',', ' '])
            .filter_map(parse_server)
            .take(3)
            .collect();
    }
    let read = |path| {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                (fields.next() == Some("nameserver"))
                    .then(|| fields.next())
                    .flatten()
                    .and_then(parse_server)
            })
            .take(3)
            .collect::<Vec<_>>()
    };
    let configured = read("/etc/resolv.conf");
    if configured.iter().any(|address| address.ip().is_loopback()) {
        let physical = read("/run/systemd/resolve/resolv.conf");
        if !physical.is_empty() {
            return physical;
        }
    }
    configured
}

fn parse_server(value: &str) -> Option<SocketAddr> {
    value.parse().ok().or_else(|| {
        value
            .parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, 53))
    })
}

pub(super) async fn resolve(
    guard: &dyn SocketGuard,
    servers: &[SocketAddr],
    host: &str,
    port: u16,
) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.trim_matches(['[', ']']).parse() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    // Сохраняем локальные имена без обращения к сети.
    if let Ok(hosts) = std::fs::read_to_string("/etc/hosts") {
        let mut local = Vec::new();
        for line in hosts.lines() {
            let mut fields = line
                .split('#')
                .next()
                .unwrap_or_default()
                .split_whitespace();
            let ip = fields.next().and_then(|value| value.parse::<IpAddr>().ok());
            if fields.any(|value| value.eq_ignore_ascii_case(host.trim_end_matches('.'))) {
                if let Some(ip) = ip {
                    local.push(SocketAddr::new(ip, port));
                }
            }
        }
        if !local.is_empty() {
            return Ok(local);
        }
    }
    let mut name = Name::from_ascii(host).map_err(|_| Error::InvalidPacket("Неверное имя DNS"))?;
    name.set_fqdn(true);
    let (v4, v6) = tokio::join!(
        lookup(guard, servers, name.clone(), RecordType::A),
        lookup(guard, servers, name, RecordType::AAAA)
    );
    let mut result = Vec::new();
    let mut last_error = None;
    for answer in [v4, v6] {
        match answer {
            Ok(ips) => result.extend(ips.into_iter().map(|ip| SocketAddr::new(ip, port))),
            Err(error) => last_error = Some(error),
        }
    }
    result.sort();
    result.dedup();
    if result.is_empty() {
        return Err(last_error.unwrap_or(Error::InvalidPacket("DNS не вернул адресов")));
    }
    Ok(result)
}

async fn lookup(
    guard: &dyn SocketGuard,
    servers: &[SocketAddr],
    mut name: Name,
    kind: RecordType,
) -> Result<Vec<IpAddr>> {
    for _ in 0..8 {
        let mut query = Message::query();
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(name.clone(), kind));
        let mut response = None;
        let mut last_error = None;
        for server in servers {
            match tokio::time::timeout(Duration::from_secs(2), exchange(guard, *server, &query))
                .await
            {
                Ok(Ok(answer)) => {
                    response = Some(answer);
                    break;
                }
                Ok(Err(error)) => last_error = Some(error),
                Err(_) => last_error = Some(Error::Io(std::io::ErrorKind::TimedOut.into())),
            }
        }
        let answer = response.ok_or_else(|| {
            last_error.unwrap_or(Error::InvalidPacket("Не настроен служебный DNS"))
        })?;
        let mut next = None;
        for _ in 0..8 {
            let mut ips = Vec::new();
            for record in answer.answers.iter().filter(|record| record.name == name) {
                match &record.data {
                    RData::A(ip) if kind == RecordType::A => ips.push(IpAddr::V4(ip.0)),
                    RData::AAAA(ip) if kind == RecordType::AAAA => ips.push(IpAddr::V6(ip.0)),
                    RData::CNAME(alias) => next = Some(alias.0.clone()),
                    _ => {}
                }
            }
            if !ips.is_empty() {
                return Ok(ips);
            }
            match next.take() {
                Some(alias) if alias != name => {
                    name = alias;
                    next = Some(name.clone());
                }
                _ => break,
            }
            if !answer.answers.iter().any(|record| record.name == name) {
                break;
            }
        }
        if next.is_none() {
            return Ok(Vec::new());
        }
    }
    Err(Error::InvalidPacket("Слишком длинная цепочка DNS"))
}

fn validate(bytes: &[u8], query: &Message) -> Result<Message> {
    let answer =
        Message::from_vec(bytes).map_err(|_| Error::InvalidPacket("Неверный ответ DNS"))?;
    if answer.metadata.id != query.metadata.id
        || answer.metadata.message_type != MessageType::Response
        || answer.queries != query.queries
    {
        return Err(Error::InvalidPacket("Ответ DNS не соответствует запросу"));
    }
    if !matches!(
        answer.metadata.response_code,
        ResponseCode::NoError | ResponseCode::NXDomain
    ) {
        return Err(Error::InvalidPacket("Ошибка служебного DNS"));
    }
    Ok(answer)
}

async fn exchange(guard: &dyn SocketGuard, server: SocketAddr, query: &Message) -> Result<Message> {
    guard.allow_peer(server)?;
    let wire = query
        .to_vec()
        .map_err(|_| Error::InvalidPacket("Ошибка кодирования DNS"))?;
    let udp = UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        guard.protect(udp.as_raw_fd())?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        guard.protect(udp.as_raw_socket())?;
    }
    udp.connect(server).await?;
    udp.send(&wire).await?;
    let mut bytes = vec![0; u16::MAX as usize];
    let size = udp.recv(&mut bytes).await?;
    let answer = validate(&bytes[..size], query)?;
    if !answer.metadata.truncation {
        return Ok(answer);
    }
    let socket = if server.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        guard.protect(socket.as_raw_fd())?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        guard.protect(socket.as_raw_socket())?;
    }
    let mut tcp = socket.connect(server).await?;
    tcp.write_u16(wire.len() as u16).await?;
    tcp.write_all(&wire).await?;
    let size = tcp.read_u16().await? as usize;
    bytes.resize(size, 0);
    tcp.read_exact(&mut bytes).await?;
    let answer = validate(&bytes, query)?;
    if answer.metadata.truncation {
        return Err(Error::InvalidPacket("Обрезанный ответ DNS по TCP"));
    }
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{
        rdata::{A, CNAME},
        Record,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct Count(Arc<AtomicUsize>);
    impl SocketGuard for Count {
        #[cfg(unix)]
        fn protect(&self, _: std::os::fd::RawFd) -> Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        #[cfg(windows)]
        fn protect(&self, _: std::os::windows::io::RawSocket) -> Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }
    fn answer(query: &Message) -> Message {
        let mut answer = query.clone();
        answer.metadata.message_type = MessageType::Response;
        if query.queries[0].query_type() == RecordType::A {
            let name = query.queries[0].name().clone();
            let alias = Name::from_ascii("edge.test.").unwrap();
            answer.add_answer(Record::from_rdata(
                name,
                60,
                RData::CNAME(CNAME(alias.clone())),
            ));
            answer.add_answer(Record::from_rdata(
                alias,
                60,
                RData::A(A::new(192, 0, 2, 7)),
            ));
        }
        answer
    }

    #[tokio::test]
    async fn dns_protects_udp_and_tcp_and_follows_cname_without_system_lookup() {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = udp.local_addr().unwrap();
        let tcp = tokio::net::TcpListener::bind(address).await.unwrap();
        let udp_task = tokio::spawn(async move {
            let mut bytes = [0; 4096];
            for _ in 0..2 {
                let (size, peer) = udp.recv_from(&mut bytes).await.unwrap();
                let mut truncated = Message::from_vec(&bytes[..size]).unwrap();
                truncated.metadata.message_type = MessageType::Response;
                truncated.metadata.truncation = true;
                udp.send_to(&truncated.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        let tcp_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = tcp.accept().await.unwrap();
                let size = stream.read_u16().await.unwrap() as usize;
                let mut bytes = vec![0; size];
                stream.read_exact(&mut bytes).await.unwrap();
                let response = answer(&Message::from_vec(&bytes).unwrap())
                    .to_vec()
                    .unwrap();
                stream.write_u16(response.len() as u16).await.unwrap();
                stream.write_all(&response).await.unwrap();
            }
        });
        let calls = Arc::new(AtomicUsize::new(0));
        let result = resolve(&Count(calls.clone()), &[address], "carrier.invalid", 443)
            .await
            .unwrap();
        assert_eq!(result, vec!["192.0.2.7:443".parse().unwrap()]);
        assert_eq!(calls.load(Ordering::Relaxed), 4);
        udp_task.await.unwrap();
        tcp_task.await.unwrap();
    }

    #[test]
    fn mismatched_dns_response_is_rejected() {
        let mut query = Message::query();
        query.metadata.id = 17;
        query.add_query(Query::query(
            Name::from_ascii("carrier.invalid").unwrap(),
            RecordType::A,
        ));
        let mut response = answer(&query);
        response.metadata.id = 18;
        assert!(validate(&response.to_vec().unwrap(), &query).is_err());
        response.metadata.id = 17;
        response.queries.clear();
        assert!(validate(&response.to_vec().unwrap(), &query).is_err());
    }

    #[tokio::test]
    async fn literal_addresses_do_not_need_a_resolver() {
        assert_eq!(
            resolve(&super::super::NoSocketGuard, &[], "192.0.2.9", 443)
                .await
                .unwrap(),
            vec!["192.0.2.9:443".parse().unwrap()]
        );
    }
}
