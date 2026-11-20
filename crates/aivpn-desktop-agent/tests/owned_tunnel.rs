#![cfg(target_os = "linux")]

use aivpn_desktop_agent::linux::OwnedTunnel;
use std::fs;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::Command;

fn isolated_root() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert!(fs::read_to_string("/proc/cmdline")
        .unwrap()
        .split_whitespace()
        .any(|word| word == "aivpn.app-routing-lab=1"));
    assert_eq!(
        fs::read("/lab/.app-routing-guest").unwrap(),
        b"aivpn-offline-routing-lab\n"
    );
}

fn ip(arguments: &[&str]) {
    let result = Command::new("ip").args(arguments).output().unwrap();
    assert!(result.status.success(), "{result:?}");
}

#[test]
#[ignore = "Изменяет сеть только в отдельной root VM"]
fn descriptor_lifetime_keeps_only_its_own_interface() {
    isolated_root();
    let first = OwnedTunnel::create().unwrap();
    let second = OwnedTunnel::create().unwrap();
    let first_identity = first.verify().unwrap();
    let second_identity = second.verify().unwrap();
    assert_ne!(first.name(), second.name());
    assert_ne!(first_identity.index, second_identity.index);
    assert_ne!(
        first_identity.device_identity,
        second_identity.device_identity
    );
    assert_ne!(first_identity.network_namespace.get(), 0);
    assert_eq!(
        first_identity.network_namespace,
        second_identity.network_namespace
    );
    let descriptor = first.duplicate_descriptor().unwrap();
    let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
    assert_ne!(flags & libc::FD_CLOEXEC, 0);
    let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFL) };
    assert_ne!(flags & libc::O_NONBLOCK, 0);
    let path = format!("/sys/class/net/{}", first.name());
    assert_eq!(
        fs::read_to_string(format!("{path}/owner")).unwrap().trim(),
        "-1"
    );
    assert_eq!(
        fs::read_to_string(format!("{path}/group")).unwrap().trim(),
        "-1"
    );
    drop(first);
    assert!(Path::new(&path).exists());
    assert_eq!(second.verify().unwrap(), second_identity);
    drop(descriptor);
    assert!(!Path::new(&path).exists());
    assert_eq!(second.verify().unwrap(), second_identity);
    let second_path = format!("/sys/class/net/{}", second.name());
    drop(second);
    assert!(!Path::new(&second_path).exists());
}

#[test]
#[ignore = "Изменяет сеть только в отдельной root VM"]
fn rename_and_same_index_replacement_cannot_satisfy_the_old_identity() {
    isolated_root();
    let tunnel = OwnedTunnel::create().unwrap();
    let identity = tunnel.verify().unwrap();
    let name = tunnel.name().to_owned();
    let renamed = "aivpn-test-old";
    ip(&["link", "set", "dev", &name, "name", renamed]);
    assert!(tunnel.verify().is_err());
    ip(&["link", "set", "dev", renamed, "name", &name]);
    assert_eq!(tunnel.verify().unwrap(), identity);
    ip(&["link", "delete", "dev", &name]);
    ip(&[
        "link",
        "add",
        "name",
        &name,
        "index",
        &identity.index.to_string(),
        "type",
        "dummy",
    ]);
    assert!(tunnel.verify().is_err());
    assert!(tunnel.duplicate_descriptor().is_err());
    drop(tunnel);
    assert!(Path::new(&format!("/sys/class/net/{name}")).exists());
    ip(&["link", "delete", "dev", &name]);
}

#[test]
#[ignore = "Изменяет сеть только в отдельной root VM"]
fn namespace_change_rejects_the_old_interface_until_restored() {
    isolated_root();
    let tunnel = OwnedTunnel::create().unwrap();
    let identity = tunnel.verify().unwrap();
    let namespace = fs::File::open("/proc/thread-self/ns/net").unwrap();
    assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
    ip(&["tuntap", "add", "dev", tunnel.name(), "mode", "tun"]);
    let rejected = tunnel.verify().is_err();
    assert_eq!(
        unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) },
        0
    );
    assert!(rejected);
    assert_eq!(tunnel.verify().unwrap(), identity);
}

#[test]
fn ordinary_user_cannot_create_a_service_tunnel() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    assert_eq!(
        OwnedTunnel::create().unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
}

#[test]
#[ignore = "Изменяет сеть только в отдельной root VM"]
fn changed_persistence_and_access_rights_are_rejected() {
    isolated_root();
    let tunnel = OwnedTunnel::create().unwrap();
    let descriptor = tunnel.duplicate_descriptor().unwrap();
    let identity = tunnel.verify().unwrap();
    assert_eq!(
        unsafe { libc::ioctl(descriptor.as_raw_fd(), libc::TUNSETPERSIST, 1) },
        0
    );
    let rejected = tunnel.verify().is_err();
    assert_eq!(
        unsafe { libc::ioctl(descriptor.as_raw_fd(), libc::TUNSETPERSIST, 0) },
        0
    );
    assert!(rejected);
    assert_eq!(tunnel.verify().unwrap(), identity);
    for operation in [libc::TUNSETOWNER, libc::TUNSETGROUP] {
        let tunnel = OwnedTunnel::create().unwrap();
        let descriptor = tunnel.duplicate_descriptor().unwrap();
        assert_eq!(
            unsafe { libc::ioctl(descriptor.as_raw_fd(), operation, 1000) },
            0
        );
        assert!(tunnel.verify().is_err());
        assert!(tunnel.duplicate_descriptor().is_err());
    }
}

#[path = "support/tunnel_packets.rs"]
mod tunnel_packets;
use tunnel_packets::reply;

#[test]
#[ignore = "Изменяет сеть только в отдельной root VM"]
fn duplicate_descriptor_carries_ipv4_and_ipv6_without_a_packet_info_header() {
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};
    isolated_root();
    let tunnel = OwnedTunnel::create().unwrap();
    let identity = tunnel.verify().unwrap();
    ip(&["link", "set", "dev", tunnel.name(), "up"]);
    ip(&["addr", "add", "10.66.0.1/30", "dev", tunnel.name()]);
    ip(&[
        "-6",
        "addr",
        "add",
        "fd66::1/64",
        "dev",
        tunnel.name(),
        "nodad",
    ]);
    let mut file = fs::File::from(tunnel.duplicate_descriptor().unwrap());
    for (ipv6, destination) in [(false, "10.66.0.2"), (true, "fd66::2")] {
        let mut ping = Command::new("ping")
            .args(["-n", "-c", "1", "-W", "3", "-I", tunnel.name(), destination])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut buffer = [0u8; 2048];
        let received = loop {
            match file.read(&mut buffer) {
                Ok(length) if length > 40 && buffer[0] >> 4 == if ipv6 { 6 } else { 4 } => {
                    if ipv6 && buffer[40] != 128 {
                        continue;
                    }
                    break length;
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("{error}"),
            }
            assert!(Instant::now() < deadline, "No outgoing echo packet");
            std::thread::sleep(Duration::from_millis(1));
        };
        let packet = &mut buffer[..received];
        reply(packet, ipv6);
        file.write_all(packet).unwrap();
        assert!(ping.wait().unwrap().success(), "{destination}");
        assert_eq!(tunnel.verify().unwrap(), identity);
    }
}

#[test]
#[ignore = "Изменяет сеть только в отдельной root VM"]
fn zero_socket_descriptor_remains_valid() {
    isolated_root();
    assert_eq!(unsafe { libc::unshare(libc::CLONE_FILES) }, 0);
    let tunnel = OwnedTunnel::create().unwrap();
    let identity = tunnel.verify().unwrap();
    assert_eq!(unsafe { libc::close(0) }, 0);
    assert_eq!(tunnel.verify().unwrap(), identity);
    assert!(tunnel.duplicate_descriptor().is_ok());
}

#[test]
#[ignore = "Изменяет сеть только в отдельной root VM"]
fn sysfs_from_another_network_namespace_cannot_identify_a_new_tunnel() {
    isolated_root();
    let original = OwnedTunnel::create().unwrap();
    let original_identity = original.verify().unwrap();
    let namespace = fs::File::open("/proc/thread-self/ns/net").unwrap();
    assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
    ip(&["link", "add", "name", "namespace-pad", "type", "dummy"]);
    let rejected = OwnedTunnel::create().is_err();
    assert_eq!(
        unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) },
        0
    );
    assert!(rejected);
    assert_eq!(original.verify().unwrap(), original_identity);
}

#[test]
#[ignore = "Изменяет сеть только в отдельной root VM"]
fn service_tunnels_cannot_be_created_outside_the_system_namespace() {
    isolated_root();
    let original = OwnedTunnel::create().unwrap();
    let namespace = fs::File::open("/proc/thread-self/ns/net").unwrap();
    assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
    let rejected = OwnedTunnel::create().is_err();
    assert_eq!(
        unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) },
        0
    );
    assert!(rejected);
    assert!(original.verify().is_ok());
}
