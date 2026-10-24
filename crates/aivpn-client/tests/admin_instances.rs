#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

fn cli(runtime: &Path, addr: &str, command: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_aivpn-client"))
        .env("XDG_RUNTIME_DIR", runtime)
        .env("AIVPN_ADMIN_LISTEN", addr)
        .env_remove("AIVPN_CONNECTION_KEY")
        .env("RUST_LOG", "error")
        .args(command)
        .output()
        .unwrap()
}

#[test]
fn cli_selects_token_and_recording_status_for_each_instance() {
    let runtime =
        std::env::temp_dir().join(format!("aivpn-admin-cli-{:032x}", rand::random::<u128>()));
    let private = runtime.join("aivpn");
    std::fs::create_dir_all(&private).unwrap();
    let mut daemons = Vec::new();
    for role in [1, 2] {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = UdpSocket::bind(tcp.local_addr().unwrap()).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let addr = socket.local_addr().unwrap();
        let token = format!("test-instance-{role}");
        std::fs::write(private.join(format!("admin-{}.token", addr.port())), &token).unwrap();
        let status = private.join(format!("admin-{}.recording.status", addr.port()));
        let task = std::thread::spawn(move || {
            let (mut stream, _) = tcp.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut header = [0; 4];
            stream.read_exact(&mut header).unwrap();
            let size = u32::from_be_bytes(header) as usize;
            assert!(size < 2048);
            let mut raw = vec![0; size];
            stream.read_exact(&mut raw).unwrap();
            assert_eq!(raw, format!("{token}:role").as_bytes());
            let reply = role.to_string();
            stream
                .write_all(&(reply.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(reply.as_bytes()).unwrap();
            drop(stream);
            let mut buf = [0; 2048];
            let (len, _) = socket.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..len], format!("{token}:record_status").as_bytes());
            let snapshot = serde_json::json!({
                "can_record": true,
                "state": "recording",
                "service": format!("instance-{role}"),
                "message": null,
                "mask_id": null,
                "confidence": null,
                "updated_at_ms": 1
            });
            assert!(aivpn_client::secure_write::write_status_best_effort(
                &status,
                snapshot.to_string().as_bytes()
            ));
        });
        daemons.push((role, addr.to_string(), task));
    }
    for (role, addr, task) in daemons {
        let reply = cli(&runtime, &addr, &["role"]);
        assert!(reply.status.success());
        assert_eq!(
            String::from_utf8(reply.stdout).unwrap().trim(),
            role.to_string()
        );
        let reply = cli(&runtime, &addr, &["record", "status"]);
        assert!(reply.status.success());
        assert!(String::from_utf8(reply.stdout)
            .unwrap()
            .contains(&format!("instance-{role}")));
        task.join().unwrap();
    }
    assert!(!private.join("admin.token").exists());
    std::fs::remove_dir_all(runtime).unwrap();
}
