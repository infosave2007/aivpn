use super::{Tunnel, TunnelConfig};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::AsyncReadExt;
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::*;

#[tokio::test]
#[ignore = "Создает Wintun и маршруты только в отдельной Windows VM"]
async fn ipv6_split_include_installs_a_route_and_preserves_ipv4() {
    let mut tunnel = native_tunnel();
    basic_routes(&mut tunnel).await;
}

fn native_tunnel() -> Tunnel {
    require_stand();
    Tunnel::new(TunnelConfig {
        tun_name: format!("AivpnCidr-{}", std::process::id()),
        tun_addr: "198.18.41.2".into(),
        server_vpn_ip: "198.18.41.1".into(),
        ipv6: Some(("fd61:ff10::2".parse().unwrap(), 64)),
        include_routes: vec!["192.0.2.119/32".into(), "2001:db8:abf0::11/128".into()],
        ..TunnelConfig::default()
    })
}

async fn basic_routes(tunnel: &mut Tunnel) {
    tunnel.create().await.unwrap();
    let index: u32 = tunnel.wintun_if_index.as_ref().unwrap().parse().unwrap();
    assert!(!has_route("192.0.2.119".parse().unwrap(), index));
    assert!(!has_route("2001:db8:abf0::11".parse().unwrap(), index));
    tunnel.apply_split_routes().unwrap();
    assert!(has_route("192.0.2.119".parse().unwrap(), index));
    assert!(
        has_route("2001:db8:abf0::11".parse().unwrap(), index),
        "Успешная установка IPv6 include должна создавать настоящий маршрут"
    );
    let removed = find_route("2001:db8:abf0::11".parse().unwrap(), index).unwrap();
    assert_eq!(unsafe { DeleteIpForwardEntry2(&removed) }, 0);
    assert!(!has_route("2001:db8:abf0::11".parse().unwrap(), index));
    tunnel.apply_split_routes().unwrap();
    assert!(
        has_route("2001:db8:abf0::11".parse().unwrap(), index),
        "Повторная установка должна восстанавливать удаленный маршрут"
    );
    let mut reader = tunnel.take_reader().unwrap();
    echo_through_tun(tunnel, &mut reader, "198.18.41.2", "192.0.2.119").await;
    echo_through_tun(tunnel, &mut reader, "fd61:ff10::2", "2001:db8:abf0::11").await;
    drop(reader);
    tunnel.remove_split_routes();
    assert!(!has_route("192.0.2.119".parse().unwrap(), index));
    assert!(!has_route("2001:db8:abf0::11".parse().unwrap(), index));
}

#[tokio::test]
#[ignore = "Создает Wintun и маршруты только в отдельной Windows VM"]
async fn reconnect_and_network_assignment_keep_ipv4_ipv6_and_duplicate_prefixes() {
    for round in 0..4 {
        let mut tunnel = native_tunnel();
        tunnel.config.ipv6.as_mut().unwrap().1 = if round % 2 == 0 { 96 } else { 64 };
        tunnel
            .config
            .include_routes
            .push("2001:db8:abf0::11/128".into());
        tunnel.create().await.unwrap();
        let index: u32 = tunnel.wintun_if_index.as_ref().unwrap().parse().unwrap();
        tunnel.apply_split_routes().unwrap();
        let mut reader = tunnel.take_reader().unwrap();
        echo_through_tun(&mut tunnel, &mut reader, "198.18.41.2", "192.0.2.119").await;
        let mut network = tunnel.config.client_network_config().unwrap();
        network.client_ip = "198.18.42.2".parse().unwrap();
        network.server_vpn_ip = "198.18.42.1".parse().unwrap();
        network.ipv6_address = Some("fd61:ff11::2".into());
        network.ipv6_prefix_len = Some(96);
        tunnel.apply_network_config(network).await.unwrap();
        let route = find_route("192.0.2.119".parse().unwrap(), index).unwrap();
        let gateway =
            unsafe { Ipv4Addr::from(route.NextHop.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()) };
        assert_eq!(gateway, "198.18.42.1".parse::<Ipv4Addr>().unwrap());
        echo_with_source(
            &mut tunnel,
            &mut reader,
            "0.0.0.0",
            "192.0.2.119",
            "198.18.42.2",
        )
        .await;
        echo_with_source(
            &mut tunnel,
            &mut reader,
            "::",
            "2001:db8:abf0::11",
            "fd61:ff11::2",
        )
        .await;
        drop(reader);
        tunnel.remove_split_routes();
        assert!(!has_route("192.0.2.119".parse().unwrap(), index));
        assert!(!has_route("2001:db8:abf0::11".parse().unwrap(), index));
    }
}

#[tokio::test]
#[ignore = "Создает Wintun и маршруты только в отдельной Windows VM"]
async fn existing_foreign_route_and_old_configuration_survive_failed_apply() {
    let mut tunnel = native_tunnel();
    tunnel.create().await.unwrap();
    let index: u32 = tunnel.wintun_if_index.as_ref().unwrap().parse().unwrap();
    let mut foreign = ForeignRoute::create(index);
    tunnel.apply_split_routes().unwrap();
    tunnel
        .config
        .include_routes
        .extend(["198.51.100.77/32".into(), "203.0.113.77/32".into()]);
    assert!(tunnel.apply_split_routes().is_err());
    assert!(!has_route("198.51.100.77".parse().unwrap(), index));
    assert!(has_route("192.0.2.119".parse().unwrap(), index));
    assert!(has_route("2001:db8:abf0::11".parse().unwrap(), index));
    assert_eq!(
        find_route("203.0.113.77".parse().unwrap(), index)
            .unwrap()
            .Metric,
        73
    );
    tunnel.remove_split_routes();
    assert!(!has_route("192.0.2.119".parse().unwrap(), index));
    assert_eq!(
        find_route("203.0.113.77".parse().unwrap(), index)
            .unwrap()
            .Metric,
        73
    );
    foreign.release();
}

#[tokio::test]
#[ignore = "Создает Wintun и маршруты только в отдельной Windows VM"]
async fn externally_changed_route_is_preserved_until_restored() {
    let mut tunnel = native_tunnel();
    tunnel.create().await.unwrap();
    let index: u32 = tunnel.wintun_if_index.as_ref().unwrap().parse().unwrap();
    tunnel.apply_split_routes().unwrap();
    let mut changed = find_route("192.0.2.119".parse().unwrap(), index).unwrap();
    changed.Metric = 73;
    assert_eq!(unsafe { SetIpForwardEntry2(&changed) }, 0);
    assert!(tunnel.apply_split_routes().is_err());
    tunnel.remove_split_routes();
    assert_eq!(
        find_route("192.0.2.119".parse().unwrap(), index)
            .unwrap()
            .Metric,
        73
    );
    changed.Metric = 0;
    assert_eq!(unsafe { SetIpForwardEntry2(&changed) }, 0);
    tunnel.remove_split_routes();
    assert!(!has_route("192.0.2.119".parse().unwrap(), index));
}

#[tokio::test]
#[ignore = "Нужны отдельная Windows VM и локальный UDP echo endpoint обеих семей"]
async fn excludes_override_includes_and_return_to_system_ipv4_ipv6() {
    let port: u16 = std::env::var("AIVPN_NATIVE_CIDR_ECHO_PORT")
        .expect("Нужен порт локального стендового echo endpoint")
        .parse()
        .unwrap();
    let mut tunnel = native_tunnel();
    tunnel.config.include_routes = vec!["10.0.2.2/32".into(), "fec0::2/128".into()];
    tunnel.create().await.unwrap();
    let index: u32 = tunnel.wintun_if_index.as_ref().unwrap().parse().unwrap();
    tunnel.apply_split_routes().unwrap();
    let mut reader = tunnel.take_reader().unwrap();
    echo_through_tun(&mut tunnel, &mut reader, "198.18.41.2", "10.0.2.2").await;
    echo_through_tun(&mut tunnel, &mut reader, "fd61:ff10::2", "fec0::2").await;
    tunnel.config.exclude_routes = tunnel.config.include_routes.clone();
    tunnel.apply_split_routes().unwrap();
    assert!(!has_route("10.0.2.2".parse().unwrap(), index));
    assert!(!has_route("fec0::2".parse().unwrap(), index));
    for host in ["10.0.2.2", "fec0::2"] {
        let remote = std::net::SocketAddr::new(host.parse().unwrap(), port);
        let local = if remote.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = tokio::net::UdpSocket::bind(local).await.unwrap();
        let marker = b"aivpn-system-exclude-echo";
        socket.send_to(marker, remote).await.unwrap();
        let mut bytes = [0; 128];
        let (size, peer) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut bytes),
        )
        .await
        .expect("Исключение должно доставлять реальные UDP пакеты через обычную сеть")
        .unwrap();
        assert_eq!(&bytes[..size], marker);
        assert_eq!(peer.ip(), remote.ip());
        assert_eq!(peer.port(), port);
        assert_ne!(
            socket.local_addr().unwrap().ip(),
            tunnel.config.tun_addr.parse::<IpAddr>().unwrap()
        );
    }
    drop(reader);
    tunnel.remove_split_routes();
}

#[tokio::test]
#[ignore = "Меняет полный туннель только в отдельной Windows VM"]
async fn wide_exclusions_override_full_tunnel_halves_in_both_families() {
    let destinations = [
        "203.0.113.92".parse::<IpAddr>().unwrap(),
        "2001:db8:cd::92".parse().unwrap(),
    ];
    let original = destinations.map(best_interface);
    let mut tunnel = native_tunnel();
    tunnel.config.full_tunnel = true;
    tunnel.config.include_routes.clear();
    tunnel.create().await.unwrap();
    let index: u32 = tunnel.wintun_if_index.as_ref().unwrap().parse().unwrap();
    tunnel.enable_full_tunnel().unwrap();
    assert_eq!(destinations.map(best_interface), [index; 2]);
    for excluded in [
        vec!["0.0.0.0/0".into(), "::/0".into()],
        vec!["128.0.0.0/1".into(), "::/1".into()],
    ] {
        tunnel.config.exclude_routes = excluded;
        tunnel.apply_split_routes().unwrap();
        assert_eq!(
            destinations.map(best_interface),
            original,
            "Широкое исключение должно вернуть исходный системный интерфейс"
        );
    }
    tunnel.remove_split_routes();
    assert_eq!(destinations.map(best_interface), [index; 2]);
    drop(tunnel);
    assert_eq!(destinations.map(best_interface), original);
}

fn best_interface(destination: IpAddr) -> u32 {
    let mut address = SOCKADDR_INET::default();
    match destination {
        IpAddr::V4(ip) => {
            address.Ipv4.sin_family = AF_INET;
            address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
        }
        IpAddr::V6(ip) => {
            address.Ipv6.sin6_family = AF_INET6;
            address.Ipv6.sin6_addr.u.Byte = ip.octets();
        }
    }
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    assert_eq!(
        unsafe {
            GetBestRoute2(
                std::ptr::null(),
                0,
                std::ptr::null(),
                &address,
                0,
                &mut route,
                &mut source,
            )
        },
        0
    );
    route.InterfaceIndex
}

struct ForeignRoute(Option<MIB_IPFORWARD_ROW2>);
impl ForeignRoute {
    fn create(index: u32) -> Self {
        foreign_prefix(index, "203.0.113.77", 32, "198.18.41.1", 73)
    }

    fn release(&mut self) {
        assert_eq!(
            unsafe { DeleteIpForwardEntry2(self.0.as_ref().unwrap()) },
            0
        );
        self.0 = None;
    }
}
impl Drop for ForeignRoute {
    fn drop(&mut self) {
        if let Some(row) = self.0.as_ref() {
            let _ = unsafe { DeleteIpForwardEntry2(row) };
        }
    }
}

async fn echo_through_tun(
    tunnel: &mut Tunnel,
    reader: &mut tun::DeviceReader,
    local: &str,
    remote: &str,
) {
    echo_with_source(tunnel, reader, local, remote, local).await;
}

async fn echo_with_source(
    tunnel: &mut Tunnel,
    reader: &mut tun::DeviceReader,
    local: &str,
    remote: &str,
    expected_source: &str,
) {
    let remote = std::net::SocketAddr::new(remote.parse().unwrap(), 39217);
    let local = std::net::SocketAddr::new(local.parse().unwrap(), 0);
    let socket = tokio::net::UdpSocket::bind(local).await.unwrap();
    let marker = b"aivpn-native-cidr-payload";
    socket.send_to(marker, remote).await.unwrap();
    let mut packet = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let mut bytes = vec![0; 2048];
            let size = reader.read(&mut bytes).await.unwrap();
            bytes.truncate(size);
            if matches_packet(&bytes, remote.ip(), marker) {
                break bytes;
            }
        }
    })
    .await
    .expect("UDP должен выйти через настоящий Wintun");
    let (source, destination, width, udp) = if remote.is_ipv4() {
        (12, 16, 4, usize::from(packet[0] & 15) * 4)
    } else {
        (8, 24, 16, 40)
    };
    let actual_source = match width {
        4 => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(&packet[source..source + width]).unwrap(),
        )),
        _ => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[source..source + width]).unwrap(),
        )),
    };
    assert_eq!(
        actual_source,
        expected_source.parse::<IpAddr>().unwrap(),
        "Источник настоящего UDP кадра после назначения сервера"
    );
    // Перестановка адресов и портов сохраняет суммы IP и UDP, включая pseudoheader.
    for offset in 0..width {
        packet.swap(source + offset, destination + offset);
    }
    packet.swap(udp, udp + 2);
    packet.swap(udp + 1, udp + 3);
    tunnel.write_packet_async(&packet).await.unwrap();
    let mut response = [0; 128];
    let (size, peer) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        socket.recv_from(&mut response),
    )
    .await
    .expect("Ответ должен пройти из Wintun в исходный UDP socket")
    .unwrap();
    assert_eq!(&response[..size], marker);
    assert_eq!(peer.ip(), remote.ip());
    assert_eq!(peer.port(), remote.port());
}

fn matches_packet(packet: &[u8], remote: IpAddr, marker: &[u8]) -> bool {
    let destination = match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 28 && packet[9] == 17 => Some(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(&packet[16..20]).unwrap(),
        ))),
        Some(6) if packet.len() >= 48 && packet[6] == 17 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[24..40]).unwrap(),
        ))),
        _ => None,
    };
    packet.ends_with(marker) && destination == Some(remote)
}

fn has_route(address: IpAddr, index: u32) -> bool {
    find_route(address, index).is_some()
}

fn find_route(address: IpAddr, index: u32) -> Option<MIB_IPFORWARD_ROW2> {
    find_prefix(address, if address.is_ipv4() { 32 } else { 128 }, index)
}

#[tokio::test]
#[ignore = "Создает два собственных Wintun только в отдельной Windows VM"]
async fn exact_alias_does_not_select_or_reconfigure_suffix_adapter() {
    require_stand();
    let other_name = format!("AivpnCidr-{}-OtherAIVPN", std::process::id());
    let mut config = tun::Configuration::default();
    config
        .tun_name(&other_name)
        .address("198.19.81.2")
        .netmask("255.255.255.0")
        .up();
    config.platform_config(|platform| {
        platform.device_guid(0x917328bb81784cc69e8b000000000001);
    });
    let other = tun::create_as_async(&config).unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let other_index = alias_index(&other_name);
    let before = interface_addresses(other_index);
    let mut tunnel = native_tunnel();
    let created = tunnel.create().await;
    let expected = alias_index(&tunnel.config.tun_name);
    assert_ne!(expected, other_index);
    assert_eq!(
        tunnel
            .windows_interface_index()
            .unwrap()
            .parse::<u32>()
            .unwrap(),
        expected,
        "Индекс должен принадлежать точному alias, а не имени с таким суффиксом"
    );
    assert_eq!(
        interface_addresses(other_index),
        before,
        "Чужой alias нельзя перенастраивать"
    );
    created.unwrap();
    drop(other);
}

#[tokio::test]
#[ignore = "Меняет собственные маршруты только в отдельной Windows VM"]
async fn assignment_preserves_externally_changed_full_half() {
    let mut tunnel = native_tunnel();
    tunnel.config.full_tunnel = true;
    tunnel.create().await.unwrap();
    tunnel.enable_full_tunnel().unwrap();
    let index = alias_index(&tunnel.config.tun_name);
    let mut changed = find_prefix("0.0.0.0".parse().unwrap(), 1, index).unwrap();
    let original = changed.Metric;
    changed.Metric = 73;
    assert_eq!(unsafe { SetIpForwardEntry2(&changed) }, 0);
    let network = tunnel.config.client_network_config().unwrap();
    assert!(
        tunnel.apply_network_config(network).await.is_err(),
        "Внешнее изменение должно диагностироваться"
    );
    assert_eq!(
        find_prefix("0.0.0.0".parse().unwrap(), 1, index)
            .unwrap()
            .Metric,
        73
    );
    tunnel.disable_full_tunnel();
    assert_eq!(
        find_prefix("0.0.0.0".parse().unwrap(), 1, index)
            .unwrap()
            .Metric,
        73,
        "Очистка не должна удалять внешне измененную половину"
    );
    changed.Metric = original;
    assert_eq!(unsafe { SetIpForwardEntry2(&changed) }, 0);
}

#[tokio::test]
#[ignore = "Меняет собственные маршруты только в отдельной Windows VM"]
async fn failed_assignment_preserves_old_halves_and_foreign_conflict() {
    let mut tunnel = native_tunnel();
    tunnel.config.full_tunnel = true;
    tunnel.create().await.unwrap();
    tunnel.enable_full_tunnel().unwrap();
    let index = alias_index(&tunnel.config.tun_name);
    let old = find_prefix("0.0.0.0".parse().unwrap(), 1, index).unwrap();
    let mut conflict = old;
    conflict.NextHop.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes([198, 18, 41, 3]);
    conflict.Metric = 73;
    assert_eq!(unsafe { CreateIpForwardEntry2(&conflict) }, 0);
    let _foreign = ForeignRoute(Some(conflict));
    let mut network = tunnel.config.client_network_config().unwrap();
    network.server_vpn_ip = "198.18.41.3".parse().unwrap();
    assert!(
        tunnel.apply_network_config(network).await.is_err(),
        "Конфликт должен давать отказ создания"
    );
    let mut preserved = old;
    assert_eq!(
        unsafe { GetIpForwardEntry2(&mut preserved) },
        0,
        "Прежняя строка должна пережить отказ"
    );
    let mut preserved = conflict;
    assert_eq!(unsafe { GetIpForwardEntry2(&mut preserved) }, 0);
    assert_eq!(preserved.Metric, 73);
}

#[tokio::test]
#[ignore = "Меняет собственные маршруты только в отдельной Windows VM"]
async fn empty_lists_remove_previous_routes_in_both_families() {
    let mut tunnel = native_tunnel();
    tunnel.create().await.unwrap();
    let index = alias_index(&tunnel.config.tun_name);
    tunnel.apply_split_routes().unwrap();
    tunnel.config.include_routes.clear();
    tunnel.config.exclude_routes.clear();
    tunnel.apply_split_routes().unwrap();
    assert!(!has_route("192.0.2.119".parse().unwrap(), index));
    assert!(!has_route("2001:db8:abf0::11".parse().unwrap(), index));
}

fn alias_index(name: &str) -> u32 {
    let alias: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut luid = windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH::default();
    assert_eq!(
        unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) },
        0
    );
    let mut index = 0;
    assert_eq!(unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) }, 0);
    index
}

fn interface_addresses(index: u32) -> Vec<IpAddr> {
    let mut table = std::ptr::null_mut();
    assert_eq!(
        unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) },
        0
    );
    let mut addresses = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
            .iter()
            .filter(|row| row.InterfaceIndex == index)
            .map(|row| match row.Address.si_family {
                AF_INET => IpAddr::V4(Ipv4Addr::from(
                    row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
                )),
                _ => IpAddr::V6(Ipv6Addr::from(row.Address.Ipv6.sin6_addr.u.Byte)),
            })
            .collect::<Vec<_>>()
    };
    unsafe { FreeMibTable(table.cast()) };
    addresses.sort();
    addresses
}

fn find_prefix(address: IpAddr, bits: u8, index: u32) -> Option<MIB_IPFORWARD_ROW2> {
    let family = if address.is_ipv4() { AF_INET } else { AF_INET6 };
    let mut table = std::ptr::null_mut();
    assert_eq!(unsafe { GetIpForwardTable2(family, &mut table) }, 0);
    let found = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
            .iter()
            .find(|row| {
                row.InterfaceIndex == index
                    && row.DestinationPrefix.PrefixLength == bits
                    && match address {
                        IpAddr::V4(expected) => {
                            Ipv4Addr::from(
                                row.DestinationPrefix
                                    .Prefix
                                    .Ipv4
                                    .sin_addr
                                    .S_un
                                    .S_addr
                                    .to_ne_bytes(),
                            ) == expected
                        }
                        IpAddr::V6(expected) => {
                            Ipv6Addr::from(row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte)
                                == expected
                        }
                    }
            })
            .copied()
    };
    unsafe { FreeMibTable(table.cast()) };
    found
}

#[tokio::test]
#[ignore = "Создает второй собственный интерфейс как другой VPN только в Windows VM"]
async fn system_uses_other_vpn_prefix_metric_and_preserves_foreign_rows() {
    let mut tunnel = native_tunnel();
    tunnel.create().await.unwrap();
    let mut other = other_vpn();
    let index = alias_index(&other.config.tun_name);
    let mut reader = other.take_reader().unwrap();
    let mut routes = Vec::new();
    for (prefix, bits, hop, metric) in [
        ("192.0.2.0", 24, "198.19.82.1", 50),
        ("192.0.2.0", 24, "198.19.82.3", 10),
        ("192.0.2.0", 25, "198.19.82.4", 200),
        ("2001:db8:abf0::", 64, "fd61:ff12::1", 50),
        ("2001:db8:abf0::", 64, "fd61:ff12::3", 10),
        ("2001:db8:abf0::", 96, "fd61:ff12::4", 200),
    ] {
        routes.push(foreign_prefix(index, prefix, bits, hop, metric));
    }
    tunnel.config.exclude_routes = tunnel.config.include_routes.clone();
    for suffix in [4, 3] {
        tunnel.apply_split_routes().unwrap();
        for (remote, expected, hop) in [
            ("192.0.2.119", "198.19.82.2", format!("198.19.82.{suffix}")),
            (
                "2001:db8:abf0::11",
                "fd61:ff12::2",
                format!("fd61:ff12::{suffix}"),
            ),
        ] {
            let address = remote.parse::<IpAddr>().unwrap();
            let row = find_route(address, index).unwrap();
            assert_eq!(
                best_interface(address),
                index,
                "SYSTEM должен использовать отдельный другой VPN"
            );
            assert_eq!(
                row_hop(&row),
                hop.parse::<IpAddr>().unwrap(),
                "Выбор учитывает сначала префикс, затем метрику"
            );
            echo_with_source(
                &mut other,
                &mut reader,
                if address.is_ipv4() { "0.0.0.0" } else { "::" },
                remote,
                expected,
            )
            .await;
        }
        tunnel.remove_split_routes();
        for foreign in &routes {
            let expected = foreign.0.as_ref().unwrap();
            let mut current = *expected;
            assert_eq!(unsafe { GetIpForwardEntry2(&mut current) }, 0);
            assert_eq!(current.Metric, expected.Metric);
        }
        if suffix == 4 {
            routes.remove(5).release();
            routes.remove(2).release();
        }
    }
    drop(reader);
}

fn other_vpn() -> Tunnel {
    assert_eq!(std::env::var("AIVPN_NATIVE_CIDR_TEST").as_deref(), Ok("1"));
    let mut other = Tunnel::new(TunnelConfig {
        tun_name: format!("AivpnCidr-{}-OtherVPN", std::process::id()),
        tun_addr: "198.19.82.2".into(),
        server_vpn_ip: "198.19.82.1".into(),
        ipv6: Some(("fd61:ff12::2".parse().unwrap(), 64)),
        ..TunnelConfig::default()
    });
    let mut config = tun::Configuration::default();
    config
        .tun_name(&other.config.tun_name)
        .address(&other.config.tun_addr)
        .netmask(&other.config.tun_netmask)
        .up();
    config.platform_config(|platform| {
        platform.device_guid(0x917328bb81784cc69e8b000000000002);
    });
    let device = tun::create_as_async(&config).unwrap();
    let (writer, reader) = device.split().unwrap();
    other.writer = Some(writer);
    other.reader = Some(reader);
    other.wintun_if_index = Some(alias_index(&other.config.tun_name).to_string());
    other
        .owned_windows_ipv4_addresses
        .adopt_initial(
            alias_index(&other.config.tun_name),
            other.config.tun_addr.parse().unwrap(),
            24,
        )
        .unwrap();
    other.configure_windows().unwrap();
    other.configure_ipv6().unwrap();
    other
}

fn foreign_prefix(index: u32, prefix: &str, bits: u8, hop: &str, metric: u32) -> ForeignRoute {
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceIndex = index;
    row.DestinationPrefix.Prefix = test_socket(prefix.parse().unwrap());
    row.DestinationPrefix.PrefixLength = bits;
    row.NextHop = test_socket(hop.parse().unwrap());
    row.SitePrefixLength = 0;
    row.Metric = metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Loopback = false;
    row.AutoconfigureAddress = false;
    row.Publish = false;
    row.Immortal = false;
    assert_eq!(unsafe { CreateIpForwardEntry2(&row) }, 0);
    assert_eq!(unsafe { GetIpForwardEntry2(&mut row) }, 0);
    ForeignRoute(Some(row))
}

fn test_socket(address: IpAddr) -> SOCKADDR_INET {
    let mut value = SOCKADDR_INET::default();
    match address {
        IpAddr::V4(address) => {
            value.Ipv4.sin_family = AF_INET;
            value.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(address.octets());
        }
        IpAddr::V6(address) => {
            value.Ipv6.sin6_family = AF_INET6;
            value.Ipv6.sin6_addr.u.Byte = address.octets();
        }
    }
    value
}

fn row_hop(row: &MIB_IPFORWARD_ROW2) -> IpAddr {
    unsafe {
        match row.NextHop.si_family {
            AF_INET => Ipv4Addr::from(row.NextHop.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()).into(),
            _ => Ipv6Addr::from(row.NextHop.Ipv6.sin6_addr.u.Byte).into(),
        }
    }
}

#[tokio::test]
#[ignore = "Проверяет отказ нового назначения только в отдельной Windows VM"]
async fn failed_subnet_assignment_preserves_old_owned_route() {
    let mut tunnel = native_tunnel();
    tunnel.create().await.unwrap();
    let index = alias_index(&tunnel.config.tun_name);
    let old = find_prefix("198.18.41.0".parse().unwrap(), 24, index).unwrap();
    let foreign = foreign_prefix(index, "198.18.41.0", 24, "198.18.41.3", 73);
    let mut network = tunnel.config.client_network_config().unwrap();
    network.server_vpn_ip = "198.18.41.3".parse().unwrap();
    assert!(tunnel.apply_network_config(network).await.is_err());
    let mut current = old;
    assert_eq!(
        unsafe { GetIpForwardEntry2(&mut current) },
        0,
        "Отказ новой подсети сохраняет старую строку"
    );
    let mut current = *foreign.0.as_ref().unwrap();
    assert_eq!(unsafe { GetIpForwardEntry2(&mut current) }, 0);
    assert_eq!(current.Metric, 73);
}

fn require_stand() {
    assert_eq!(std::env::var("AIVPN_NATIVE_CIDR_TEST").as_deref(), Ok("1"));
    static INITIAL: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INITIAL.get_or_init(|| {
        let alias: Vec<u16> = "AIVPN".encode_utf16().chain(Some(0)).collect();
        let mut row = MIB_IF_ROW2::default();
        if unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut row.InterfaceLuid) } == 0 {
            assert!(
                unsafe { GetIfEntry2(&mut row) } != 0
                    || row.OperStatus
                        != windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp,
                "Нельзя запускать тест поверх действующего AIVPN"
            );
        }
    });
}

#[tokio::test]
#[ignore = "Проверяет собственные и внешние адреса только в отдельной Windows VM"]
async fn address_rollback_preserves_old_address_routes_and_foreign_address() {
    let mut tunnel = native_tunnel();
    tunnel.create().await.unwrap();
    let index = alias_index(&tunnel.config.tun_name);
    let mut address = MIB_UNICASTIPADDRESS_ROW::default();
    unsafe { InitializeUnicastIpAddressEntry(&mut address) };
    address.InterfaceIndex = index;
    address.Address = test_socket("198.18.41.77".parse().unwrap());
    address.OnLinkPrefixLength = 24;
    address.PrefixOrigin = IpPrefixOriginManual;
    address.SuffixOrigin = IpSuffixOriginManual;
    assert_eq!(unsafe { CreateUnicastIpAddressEntry(&address) }, 0);
    let _foreign_address = ForeignAddress(address);
    let foreign = foreign_prefix(index, "198.18.42.0", 24, "198.18.42.1", 73);
    let old = find_prefix("198.18.41.0".parse().unwrap(), 24, index).unwrap();
    let mut network = tunnel.config.client_network_config().unwrap();
    network.client_ip = "198.18.42.2".parse().unwrap();
    network.server_vpn_ip = "198.18.42.1".parse().unwrap();
    assert!(tunnel.apply_network_config(network).await.is_err());
    let addresses = interface_addresses(index);
    assert!(addresses.contains(&"198.18.41.2".parse().unwrap()));
    assert!(addresses.contains(&"198.18.41.77".parse().unwrap()));
    assert!(!addresses.contains(&"198.18.42.2".parse().unwrap()));
    let mut current = old;
    assert_eq!(unsafe { GetIpForwardEntry2(&mut current) }, 0);
    let mut current = *foreign.0.as_ref().unwrap();
    assert_eq!(unsafe { GetIpForwardEntry2(&mut current) }, 0);
    assert_eq!(current.Metric, 73);
    tunnel.owned_windows_ipv4_addresses.clear().unwrap();
    assert!(interface_addresses(index).contains(&"198.18.41.77".parse().unwrap()));
}

struct ForeignAddress(MIB_UNICASTIPADDRESS_ROW);
impl Drop for ForeignAddress {
    fn drop(&mut self) {
        unsafe { DeleteUnicastIpAddressEntry(&self.0) };
    }
}

#[tokio::test]
#[ignore = "Проверяет внешнюю смену атрибутов адреса только в отдельной Windows VM"]
async fn externally_changed_address_is_preserved() {
    let mut tunnel = native_tunnel();
    tunnel.create().await.unwrap();
    let index = alias_index(&tunnel.config.tun_name);
    let mut address = MIB_UNICASTIPADDRESS_ROW {
        InterfaceIndex: index,
        Address: test_socket("198.18.41.2".parse().unwrap()),
        ..Default::default()
    };
    assert_eq!(unsafe { GetUnicastIpAddressEntry(&mut address) }, 0);
    address.SkipAsSource = true;
    assert_eq!(unsafe { SetUnicastIpAddressEntry(&address) }, 0);
    assert!(tunnel.configure_windows().is_err());
    assert!(tunnel.owned_windows_ipv4_addresses.clear().is_err());
    assert_eq!(unsafe { GetUnicastIpAddressEntry(&mut address) }, 0);
    assert!(address.SkipAsSource);
    address.SkipAsSource = false;
    assert_eq!(unsafe { SetUnicastIpAddressEntry(&address) }, 0);
}

#[tokio::test]
#[ignore = "Меняет адреса и полный туннель только в отдельной Windows VM"]
async fn same_ipv4_prefix_change_preserves_routes_and_automatic_source() {
    let mut tunnel = native_tunnel();
    tunnel.config.full_tunnel = true;
    tunnel.create().await.unwrap();
    let index = alias_index(&tunnel.config.tun_name);
    tunnel.enable_full_tunnel().unwrap();
    tunnel.apply_split_routes().unwrap();
    let mut reader = tunnel.take_reader().unwrap();
    for (bits, gateway, subnet, old_subnet, old_bits, old_gateway) in [
        (
            23,
            "198.18.40.1",
            "198.18.40.0",
            "198.18.41.0",
            24,
            "198.18.41.1",
        ),
        (
            24,
            "198.18.41.1",
            "198.18.41.0",
            "198.18.40.0",
            23,
            "198.18.40.1",
        ),
    ] {
        let mut network = tunnel.config.client_network_config().unwrap();
        network.prefix_len = bits;
        network.server_vpn_ip = gateway.parse().unwrap();
        tunnel.apply_network_config(network).await.unwrap();
        let mut address = MIB_UNICASTIPADDRESS_ROW {
            InterfaceIndex: index,
            Address: test_socket("198.18.41.2".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(unsafe { GetUnicastIpAddressEntry(&mut address) }, 0);
        assert_eq!(address.OnLinkPrefixLength, bits);
        assert_eq!(address.DadState, IpDadStatePreferred);
        for (prefix, prefix_bits) in [
            (subnet, bits),
            ("0.0.0.0", 1),
            ("128.0.0.0", 1),
            ("192.0.2.119", 32),
        ] {
            assert_eq!(route_status(index, prefix, prefix_bits, gateway), 0);
        }
        assert_eq!(
            route_status(index, old_subnet, old_bits, old_gateway),
            windows_sys::Win32::Foundation::ERROR_NOT_FOUND
        );
        echo_with_source(
            &mut tunnel,
            &mut reader,
            "0.0.0.0",
            "192.0.2.119",
            "198.18.41.2",
        )
        .await;
        echo_with_source(
            &mut tunnel,
            &mut reader,
            "::",
            "2001:db8:abf0::11",
            "fd61:ff10::2",
        )
        .await;
    }
}

fn route_status(index: u32, prefix: &str, bits: u8, gateway: &str) -> u32 {
    let mut row = MIB_IPFORWARD_ROW2 {
        InterfaceIndex: index,
        DestinationPrefix: IP_ADDRESS_PREFIX {
            Prefix: test_socket(prefix.parse().unwrap()),
            PrefixLength: bits,
        },
        NextHop: test_socket(gateway.parse().unwrap()),
        ..Default::default()
    };
    unsafe { GetIpForwardEntry2(&mut row) }
}

#[tokio::test]
#[ignore = "Проверяет внешнее изменение Protocol только в отдельной Windows VM"]
async fn external_subnet_protocol_is_preserved_during_prefix_reassignment() {
    let mut tunnel = native_tunnel();
    tunnel.create().await.unwrap();
    tunnel.apply_split_routes().unwrap();
    let index = alias_index(&tunnel.config.tun_name);
    let mut changed = MIB_IPFORWARD_ROW2 {
        InterfaceIndex: index,
        DestinationPrefix: IP_ADDRESS_PREFIX {
            Prefix: test_socket("198.18.41.0".parse().unwrap()),
            PrefixLength: 24,
        },
        NextHop: test_socket("198.18.41.1".parse().unwrap()),
        ..Default::default()
    };
    assert_eq!(unsafe { GetIpForwardEntry2(&mut changed) }, 0);
    assert_eq!(changed.Protocol, MIB_IPPROTO_NETMGMT);
    changed.Protocol = MIB_IPPROTO_LOCAL;
    assert_eq!(unsafe { SetIpForwardEntry2(&changed) }, 0);
    let mut network = tunnel.config.client_network_config().unwrap();
    network.prefix_len = 23;
    network.server_vpn_ip = "198.18.40.1".parse().unwrap();
    assert!(tunnel.apply_network_config(network).await.is_err());
    assert_eq!(unsafe { GetIpForwardEntry2(&mut changed) }, 0);
    assert_eq!(
        changed.Protocol, MIB_IPPROTO_LOCAL,
        "Настоящее внешнее изменение нельзя перезаписывать"
    );
    let mut reader = tunnel.take_reader().unwrap();
    echo_with_source(
        &mut tunnel,
        &mut reader,
        "0.0.0.0",
        "192.0.2.119",
        "198.18.41.2",
    )
    .await;
    drop(reader);
    changed.Protocol = MIB_IPPROTO_NETMGMT;
    assert_eq!(unsafe { SetIpForwardEntry2(&changed) }, 0);
}
