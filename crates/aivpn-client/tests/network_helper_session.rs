#![cfg(target_os = "linux")]

use aivpn_client::network_session::{Reply, Request};
use aivpn_desktop_agent::unix::LocalStream;
use std::{
    io::{BufRead, BufReader},
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

fn exchange(
    channel: &mut LocalStream,
    request: Request,
    descriptors: &[std::os::fd::BorrowedFd<'_>],
) -> (Reply, Vec<OwnedFd>) {
    channel
        .send(&serde_json::to_vec(&request).unwrap(), descriptors)
        .unwrap();
    let frame = channel.receive(Some(Duration::from_secs(5))).unwrap();
    (
        serde_json::from_slice(&frame.payload).unwrap(),
        frame.descriptors,
    )
}

/// Запускается только внутри отдельной VM с собственным сетевым пространством.
#[test]
#[ignore]
fn same_image_helper_transfers_tun_marks_sockets_and_cleans_up() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert!(Path::new("/lab/.app-routing-guest").is_file());
    let image = std::env::var_os("AIVPN_TEST_IMAGE")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_aivpn-client").into());
    let mut child = Command::new(image)
        .args(["__network-helper", "--tun-session"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut path = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut path)
        .unwrap();
    let mut channel = LocalStream::new(UnixStream::connect(path.trim()).unwrap());
    assert_eq!(channel.peer_credentials().unwrap().pid.get(), child.id());
    assert_eq!(channel.peer_credentials().unwrap().uid, 0);
    let network = aivpn_common::network_config::ClientNetworkConfig::from_legacy_address(
        std::net::Ipv4Addr::from(u32::from(aivpn_common::network_config::LEGACY_SERVER_VPN_IP) + 1),
    );
    let (reply, mut fds) = exchange(
        &mut channel,
        Request::Create {
            name: "unified0".into(),
            network: network.clone(),
        },
        &[],
    );
    assert!(reply.error.is_none(), "{:?}", reply.error);
    assert_eq!(fds.len(), 1);
    let tun = fds.pop().unwrap();
    let (reply, _) = exchange(&mut channel, Request::Configure {}, &[]);
    assert!(reply.error.is_none(), "{:?}", reply.error);
    let output = Command::new("ip")
        .args(["-j", "addr", "show", "dev", "unified0"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains(&network.client_ip.to_string()));
    // Чужое устройство не присоединяется даже при верном имени сеанса.
    assert!(exchange(
        &mut channel,
        Request::Create {
            name: "unified0".into(),
            network
        },
        &[]
    )
    .0
    .error
    .is_some());
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    assert!(exchange(
        &mut channel,
        Request::MarkSocket {
            mark: aivpn_client::network_session::assigned_transport_mark(0).unwrap()
        },
        &[socket.as_fd()]
    )
    .0
    .error
    .is_none());
    let mut mark = 0u32;
    let mut length = std::mem::size_of_val(&mark) as libc::socklen_t;
    assert_eq!(
        unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                (&mut mark as *mut u32).cast(),
                &mut length,
            )
        },
        0
    );
    assert_eq!(
        mark,
        aivpn_client::network_session::assigned_transport_mark(0).unwrap()
    );
    assert!(exchange(
        &mut channel,
        Request::MarkSocket { mark: 1 },
        &[tun.as_fd()]
    )
    .0
    .error
    .is_some());
    // Весь batch отклоняется до первого изменения, а канал остается пригодным.
    assert!(exchange(
        &mut channel,
        Request::Ip {
            batch: "mtu\tlink_mtu\tunified0\t1300\ninvalid\texec\tsh".into()
        },
        &[]
    )
    .0
    .error
    .is_some());
    let mtu = std::fs::read_to_string("/sys/class/net/unified0/mtu").unwrap();
    assert_ne!(mtu.trim(), "1300");
    assert!(exchange(
        &mut channel,
        Request::Ip {
            batch: "mtu\tlink_mtu\tunified0\t1300".into()
        },
        &[]
    )
    .0
    .error
    .is_none());
    assert_eq!(
        std::fs::read_to_string("/sys/class/net/unified0/mtu")
            .unwrap()
            .trim(),
        "1300"
    );
    assert!(exchange(&mut channel, Request::Release {}, &[])
        .0
        .error
        .is_none());
    drop(tun);
    assert!(!Path::new("/sys/class/net/unified0").exists());
    let _ = exchange(&mut channel, Request::Stop {}, &[]);
    assert!(child.wait().unwrap().success());
    assert!(!Path::new(path.trim()).exists());
}

/// Проверяет реальный pkexec/Polkit, не подменяя помощник скриптом с setuid.
#[test]
#[ignore]
fn ordinary_user_gets_only_the_network_role_through_polkit() {
    assert_eq!(unsafe { libc::geteuid() }, 1000);
    assert!(Path::new("/lab/.app-routing-guest").is_file());
    assert!(aivpn_client::network_session::needed());
    let _owner = aivpn_client::network_session::keep_alive().unwrap();
    let network = aivpn_common::network_config::ClientNetworkConfig::from_legacy_address(
        std::net::Ipv4Addr::from(u32::from(aivpn_common::network_config::LEGACY_SERVER_VPN_IP) + 1),
    );
    let (descriptor, lease) =
        aivpn_client::network_session::create_tun("delegated0", network).unwrap();
    lease.configure().unwrap();
    assert!(Path::new("/sys/class/net/delegated0").exists());
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let guard = aivpn_client::network_session::delegated_guard(std::sync::Arc::new(
        aivpn_common::transport::MarkGuard::new(0x4149),
    ))
    .unwrap();
    guard.protect(socket.as_raw_fd()).unwrap();
    let mut mark = 0u32;
    let mut size = std::mem::size_of_val(&mark) as libc::socklen_t;
    assert_eq!(
        unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                (&mut mark as *mut u32).cast(),
                &mut size,
            )
        },
        0
    );
    assert_eq!(
        mark,
        aivpn_client::network_session::assigned_transport_mark(1000).unwrap()
    );
    // Тот же путь с другой первой ролью не получает разрешение помощника.
    let denied = Command::new("/usr/bin/pkexec")
        .args([
            "--disable-internal-agent",
            aivpn_client::network_session::IMAGE,
            "cli",
            "--version",
        ])
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(denied.stdout.is_empty());
    let conflict = Command::new("/usr/bin/pkexec")
        .args([
            "--disable-internal-agent",
            aivpn_client::network_session::IMAGE,
            "__network-helper",
            "cli",
            "--version",
        ])
        .output()
        .unwrap();
    assert_eq!(conflict.status.code(), Some(64));
    assert!(conflict.stdout.is_empty());
    drop(guard);
    drop(lease);
    drop(descriptor);
    assert!(!Path::new("/sys/class/net/delegated0").exists());
    let first = aivpn_client::network_session::current().unwrap();
    first.request(Request::Stop {}).unwrap();
    let second = aivpn_client::network_session::prepare().unwrap();
    assert!(!std::sync::Arc::ptr_eq(&first, &second));
    let (_, lease) = aivpn_client::network_session::create_tun(
        "restored0",
        aivpn_common::network_config::ClientNetworkConfig::from_legacy_address(
            std::net::Ipv4Addr::from(
                u32::from(aivpn_common::network_config::LEGACY_SERVER_VPN_IP) + 1,
            ),
        ),
    )
    .unwrap();
    lease.configure().unwrap();
    drop(lease);
}

/// Чужие интерфейсы и маршруты остаются прежними при корректном формате запроса.
#[test]
#[ignore]
fn network_role_preserves_foreign_objects_and_requires_owned_tun() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert!(Path::new("/lab/.app-routing-guest").is_file());
    let image = std::env::var_os("AIVPN_TEST_IMAGE")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_aivpn-client").into());
    let mut child = Command::new(image)
        .args(["__network-helper", "--tun-session"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut path = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut path)
        .unwrap();
    let mut channel = LocalStream::new(UnixStream::connect(path.trim()).unwrap());
    let old = std::fs::read_to_string("/sys/class/net/eth0/mtu").unwrap();
    let request = || Request::Ip {
        batch: "foreign\tlink_mtu\teth0\t1401".into(),
    };
    assert!(
        exchange(&mut channel, request(), &[]).0.error.is_some(),
        "Операция без собственного TUN принята"
    );
    let network = aivpn_common::network_config::ClientNetworkConfig::from_legacy_address(
        std::net::Ipv4Addr::from(u32::from(aivpn_common::network_config::LEGACY_SERVER_VPN_IP) + 1),
    );
    let (reply, fds) = exchange(
        &mut channel,
        Request::Create {
            name: "owner0".into(),
            network,
        },
        &[],
    );
    assert!(reply.error.is_none(), "{:?}", reply.error);
    assert!(
        exchange(&mut channel, request(), &[]).0.error.is_some(),
        "Изменение чужого интерфейса принято"
    );
    assert_eq!(
        std::fs::read_to_string("/sys/class/net/eth0/mtu").unwrap(),
        old
    );
    assert!(Command::new("ip")
        .args(["route", "add", "198.19.0.7/32", "dev", "eth0"])
        .status()
        .unwrap()
        .success());
    let (reply, _) = exchange(
        &mut channel,
        Request::Ip {
            batch: "foreign\troute_del\t198.19.0.7/32".into(),
        },
        &[],
    );
    assert!(reply.error.is_none(), "{:?}", reply.error);
    let row = Command::new("ip")
        .args(["route", "show", "exact", "198.19.0.7/32"])
        .output()
        .unwrap();
    assert!(!row.stdout.is_empty(), "Чужой маршрут удален");
    assert!(Command::new("ip")
        .args(["route", "del", "198.19.0.7/32"])
        .status()
        .unwrap()
        .success());
    drop(fds);
    let _ = exchange(&mut channel, Request::Stop {}, &[]);
    assert!(child.wait().unwrap().success());
}
