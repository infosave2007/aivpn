#![cfg(all(unix, not(feature = "production-secure")))]

use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use base64::Engine;

struct ClientProcess {
    child: Child,
    home: std::path::PathBuf,
}

impl Drop for ClientProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

#[test]
fn cli_reports_reconnecting_then_disconnected_on_sigterm() {
    let home =
        std::env::temp_dir().join(format!("aivpn-cli-status-{:032x}", rand::random::<u128>()));
    std::fs::create_dir(&home).unwrap();
    let admin = UdpSocket::bind("127.0.0.1:0").unwrap();
    let admin_addr = admin.local_addr().unwrap().to_string();
    drop(admin);
    // Нулевая X25519-точка дает ошибку DH до отправки первого пакета.
    // UDP send на порт 0 может успешно отправиться, и отказ проявится позже.
    let server_key = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
    let child = Command::new(env!("CARGO_BIN_EXE_aivpn-client"))
        .args([
            "--server",
            "127.0.0.1:0",
            "--server-key",
            &server_key,
            "--proxy-listen",
            "127.0.0.1:0",
            "--admin-listen",
            &admin_addr,
        ])
        .env("HOME", &home)
        .env("XDG_RUNTIME_DIR", &home)
        .env("XDG_CONFIG_HOME", &home)
        .env("AIVPN_DISABLE_NETCHANGE", "1")
        .env_remove("AIVPN_CONNECTION_KEY")
        .env_remove("AIVPN_TRANSPORT")
        .env("RUST_LOG", "error")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut process = ClientProcess { child, home };
    let stdout = process.child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let line = line.unwrap();
            if line.starts_with("AIVPN-STATUS ") {
                tx.send(line).unwrap();
            }
        }
    });

    assert_eq!(
        rx.recv_timeout(Duration::from_secs(10)).unwrap(),
        "AIVPN-STATUS reconnecting",
    );
    assert_eq!(
        unsafe { libc::kill(process.child.id() as i32, libc::SIGTERM) },
        0
    );
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(10)).unwrap(),
        "AIVPN-STATUS disconnected",
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = process.child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Клиент не завершился после SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    reader.join().unwrap();
    assert!(
        rx.try_recv().is_err(),
        "Лишнее событие при завершении клиента"
    );
}
