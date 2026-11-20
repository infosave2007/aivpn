use super::*;
use std::sync::atomic::AtomicUsize;
use tokio::net::{TcpStream, UdpSocket};

struct UdpProxyPair {
    proxy: ProxyHandle,
    _control: TcpStream,
    socket: UdpSocket,
    relay: SocketAddr,
    dns_queries: Arc<AtomicUsize>,
    responder: tokio::task::JoinHandle<()>,
}

impl Drop for UdpProxyPair {
    fn drop(&mut self) {
        self.responder.abort();
    }
}

impl UdpProxyPair {
    async fn connected() -> Self {
        let (transport_tx, mut transport_rx) = mpsc::channel(128);
        let proxy = spawn_proxy(
            ProxyConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                vpn_ip: Ipv4Addr::new(10, 0, 0, 2),
                gateway_ip: Ipv4Addr::new(10, 0, 0, 1),
                prefix_len: 24,
                dns_servers: vec![Ipv4Addr::new(1, 1, 1, 1)],
            },
            transport_tx,
        )
        .await
        .unwrap();
        let incoming = proxy.rx_queue.clone();
        let wake = proxy.wake_tx.clone();
        let dns_queries = Arc::new(AtomicUsize::new(0));
        let observed_queries = dns_queries.clone();
        let responder = tokio::spawn(async move {
            while let Some(packet) = transport_rx.recv().await {
                if let Some(reply) = ipv4_udp_reply(&packet, &observed_queries) {
                    incoming.lock().unwrap().push_back(reply);
                    let _ = wake.try_send(());
                }
            }
        });
        let mut control = TcpStream::connect(proxy.listen_addr).await.unwrap();
        control.write_all(&[5, 1, 0]).await.unwrap();
        let mut greeting = [0; 2];
        tokio::time::timeout(Duration::from_secs(2), control.read_exact(&mut greeting))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(greeting, [5, 0]);
        control
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut reply = [0; 10];
        tokio::time::timeout(Duration::from_secs(2), control.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply[..4], &[5, REP_SUCCESS, 0, 1]);
        let relay = SocketAddr::from(([127, 0, 0, 1], u16::from_be_bytes([reply[8], reply[9]])));
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        Self {
            proxy,
            _control: control,
            socket,
            relay,
            dns_queries,
            responder,
        }
    }

    async fn exchange(&self, domain: Option<&str>, payload: &[u8]) {
        let mut packet = vec![0, 0, 0];
        if let Some(host) = domain {
            packet.extend_from_slice(&[3, host.len().try_into().unwrap()]);
            packet.extend_from_slice(host.as_bytes());
        } else {
            packet.extend_from_slice(&[1, 198, 18, 0, 1]);
        }
        packet.extend_from_slice(&9999u16.to_be_bytes());
        packet.extend_from_slice(payload);
        self.socket.send_to(&packet, self.relay).await.unwrap();
        let mut response = [0; 1024];
        let (len, sender) =
            tokio::time::timeout(Duration::from_secs(2), self.socket.recv_from(&mut response))
                .await
                .expect("Стек не вернул IPv4 UDP после запроса")
                .unwrap();
        assert_eq!(sender, self.relay);
        assert_eq!(&response[..10], &[0, 0, 0, 1, 198, 18, 0, 1, 0x27, 0x0f]);
        assert_eq!(&response[10..len], payload);
    }

    async fn send_ipv6(&self, address: &str, direct: bool) {
        let target = SocketAddr::new(address.parse().unwrap(), 443);
        if direct {
            self.proxy
                .network_tx
                .try_send(UdpStackCommand::SendPacket(UdpPacketCommand {
                    relay_port: self.relay.port(),
                    target: socket_addr_to_ip_endpoint(target),
                    payload: b"unsupported-family".to_vec(),
                }))
                .unwrap();
            self.proxy.wake_tx.try_send(()).unwrap();
        } else {
            let IpAddr::V6(ip) = target.ip() else {
                unreachable!()
            };
            let mut packet = vec![0, 0, 0, 4];
            packet.extend_from_slice(&ip.octets());
            packet.extend_from_slice(&443u16.to_be_bytes());
            packet.extend_from_slice(b"unsupported-family");
            self.socket.send_to(&packet, self.relay).await.unwrap();
        }
    }
}

// Вместо внешней сети отвечаем на реальные IP-пакеты стека: UDP echo и DNS A.
fn ipv4_udp_reply(packet: &[u8], dns_queries: &AtomicUsize) -> Option<Vec<u8>> {
    if packet.len() < 28 || packet[0] >> 4 != 4 || packet[9] != 17 {
        return None;
    }
    let header = usize::from(packet[0] & 15) * 4;
    let udp = packet.get(header..)?;
    let payload = udp.get(8..)?;
    let mut data = payload.to_vec();
    if udp[2..4] == 53u16.to_be_bytes() {
        let mut end = 12;
        while *payload.get(end)? != 0 {
            end += usize::from(payload[end]) + 1;
        }
        end += 5;
        if payload.get(end - 4..end - 2)? != [0, 1] {
            return None;
        }
        dns_queries.fetch_add(1, Ordering::Relaxed);
        data = payload.get(..end)?.to_vec();
        data[2..4].copy_from_slice(&[0x81, 0x80]);
        data[6..8].copy_from_slice(&1u16.to_be_bytes());
        data[8..12].fill(0);
        data.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 18, 0, 1]);
    }
    let mut reply = vec![0; 28 + data.len()];
    reply[0] = 0x45;
    reply[2..4].copy_from_slice(&((28 + data.len()) as u16).to_be_bytes());
    reply[8] = 64;
    reply[9] = 17;
    reply[12..16].copy_from_slice(&packet[16..20]);
    reply[16..20].copy_from_slice(&packet[12..16]);
    reply[20..22].copy_from_slice(&udp[2..4]);
    reply[22..24].copy_from_slice(&udp[..2]);
    reply[24..26].copy_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    reply[28..].copy_from_slice(&data);
    smoltcp::wire::Ipv4Packet::new_unchecked(reply.as_mut_slice()).fill_checksum();
    Some(reply)
}

async fn ipv6_does_not_interrupt_ipv4_or_dns(direct: bool) {
    let pair = UdpProxyPair::connected().await;
    pair.exchange(None, b"initial-ipv4").await;
    pair.exchange(Some("before.invalid"), b"initial-dns").await;
    assert_eq!(pair.dns_queries.load(Ordering::Relaxed), 1);
    for (index, address) in ["2001:db8::1", "fe80::1", "::1", "::ffff:192.0.2.1"]
        .iter()
        .enumerate()
    {
        pair.send_ipv6(address, direct).await;
        pair.exchange(None, b"ipv4-after-ipv6").await;
        // Новое имя исключает успех за счет кеша предыдущего DNS-ответа.
        pair.exchange(Some(&format!("after-{index}.invalid")), b"dns-after-ipv6")
            .await;
        assert_eq!(pair.dns_queries.load(Ordering::Relaxed), index + 2);
    }
}

#[tokio::test]
async fn socks_ipv6_udp_preserves_ipv4_and_fresh_dns() {
    ipv6_does_not_interrupt_ipv4_or_dns(false).await;
}

#[tokio::test]
async fn stack_ipv6_udp_preserves_ipv4_and_fresh_dns() {
    ipv6_does_not_interrupt_ipv4_or_dns(true).await;
}
