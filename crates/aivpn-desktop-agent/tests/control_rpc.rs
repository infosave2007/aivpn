#![cfg(target_os = "linux")]

use aivpn_desktop_agent::control::*;
use aivpn_desktop_agent::protocol::*;
use aivpn_desktop_agent::unix::{rpc::IncomingControl, LocalStream};
use aivpn_desktop_policy::*;
use std::io;
use std::num::NonZeroU64;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

#[path = "support/root_client.rs"]
mod root_client;
mod root_permissions;

#[path = "support/control_fixture.rs"]
mod fixture;
use fixture::{Backend, Memory};

#[test]
fn the_control_handler_uses_socket_credentials_and_preserves_request_identity() {
    let (client, server) = UnixStream::pair().unwrap();
    let uid = unsafe { libc::geteuid() };
    let thread = std::thread::spawn(move || {
        let mut service =
            Control::open(Platform::Linux, [3; 16], Memory::default(), Backend).unwrap();
        let incoming = IncomingControl::receive(server).unwrap();
        let outgoing = incoming.execute(&mut service);
        assert_eq!(service.state().serial(), 1);
        let profiles = service
            .state()
            .profiles()
            .list(&Authority {
                user: Owner::LinuxUser { uid },
                machine_admin: false,
            })
            .unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].owner, Owner::LinuxUser { uid });
        outgoing.send().unwrap();
    });
    let request = Request::new(
        NonZeroU64::new(75).unwrap(),
        Command::RegisterProfile {
            owner: Owner::LinuxUser { uid },
            registration_key: "local-profile".into(),
            consumers: vec![],
        },
    );
    let mut client = LocalStream::new(client);
    client.send(&request.to_json().unwrap(), &[]).unwrap();
    let frame = client
        .receive(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    assert!(frame.descriptors.is_empty());
    let response = Response::from_json(&frame.payload).unwrap();
    assert_eq!(response.id(), request.id());
    assert!(matches!(
        response.result(),
        Outcome::Ok {
            reply: Reply::Registered { .. }
        }
    ));
    thread.join().unwrap();
}

#[test]
fn unexpected_descriptors_and_forged_authority_are_rejected_before_dispatch() {
    for descriptor in [false, true] {
        let (client, server) = UnixStream::pair().unwrap();
        let thread = std::thread::spawn(move || {
            assert_eq!(
                IncomingControl::receive(server).err().unwrap().kind(),
                io::ErrorKind::InvalidData
            );
        });
        let mut client = LocalStream::new(client);
        if descriptor {
            let file = std::fs::File::open("/dev/null").unwrap();
            let request = Request::new(NonZeroU64::MIN, Command::Status {});
            client
                .send(&request.to_json().unwrap(), &[file.as_fd()])
                .unwrap();
        } else {
            client.send(br#"{"version":1,"id":1,"authority":{"machine_admin":true},"command":{"method":"status"}}"#, &[]).unwrap();
        }
        thread.join().unwrap();
        assert!(client
            .receive(Some(std::time::Duration::from_secs(1)))
            .is_err());
    }
}

#[test]
fn an_unprivileged_socket_cannot_register_a_profile_for_another_owner() {
    let uid = unsafe { libc::geteuid() };
    if uid == 0 {
        return;
    }
    let (client, server) = UnixStream::pair().unwrap();
    let thread = std::thread::spawn(move || {
        let mut service =
            Control::open(Platform::Linux, [4; 16], Memory::default(), Backend).unwrap();
        IncomingControl::receive(server)
            .unwrap()
            .execute(&mut service)
            .send()
            .unwrap();
        assert_eq!(service.state().serial(), 0);
    });
    let request = Request::new(
        NonZeroU64::MIN,
        Command::RegisterProfile {
            owner: Owner::LinuxUser { uid: 0 },
            registration_key: "foreign-profile".into(),
            consumers: vec![],
        },
    );
    let mut client = LocalStream::new(client);
    client.send(&request.to_json().unwrap(), &[]).unwrap();
    let response = Response::from_json(
        &client
            .receive(Some(std::time::Duration::from_secs(2)))
            .unwrap()
            .payload,
    )
    .unwrap();
    assert!(matches!(
        response.result(),
        Outcome::Error {
            code: ErrorCode::AccessDenied
        }
    ));
    thread.join().unwrap();
}
