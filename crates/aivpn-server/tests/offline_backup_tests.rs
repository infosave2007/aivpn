#![cfg(unix)]

use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use aivpn_server::backup::{
    export_server, import_server_with_options, ExportOptions, ImportOptions,
};
use aivpn_server::ClientDatabase;

fn options(root: &Path) -> ImportOptions {
    ImportOptions {
        config_path: root.join("server.json"),
        clients_db: root.join("clients.json"),
        mask_dir: root.join("masks"),
    }
}

fn archive(root: &Path) -> PathBuf {
    let source = root.join("source");
    std::fs::create_dir(&source).unwrap();
    let config = source.join("server.json");
    let clients = source.join("clients.json");
    std::fs::write(&config, b"{}").unwrap();
    std::fs::write(&clients, b"{\"clients\":[]}").unwrap();
    let result = root.join("restore.tar.gz");
    export_server(
        &ExportOptions {
            include_config: true,
            include_clients: true,
            config_path: Some(config),
            clients_db: Some(clients),
            ..Default::default()
        },
        &result,
    )
    .unwrap();
    result
}

#[test]
fn restore_refuses_every_live_database_owner_until_last_drop() {
    let root = tempfile::tempdir().unwrap();
    let archive = archive(root.path());
    let opts = options(root.path());
    let first = ClientDatabase::load(&opts.clients_db, Default::default()).unwrap();
    first.add_client("live-fixture").unwrap();
    let before = std::fs::read(&opts.clients_db).unwrap();
    let second = ClientDatabase::load(&opts.clients_db, Default::default()).unwrap();
    assert!(
        import_server_with_options(&archive, &opts, false).is_err(),
        "Restore обошел живую базу"
    );
    assert_eq!(std::fs::read(&opts.clients_db).unwrap(), before);
    assert!(
        import_server_with_options(&archive, &opts, true).is_ok(),
        "Dry-run не должен менять базу или требовать offline"
    );
    drop(first);
    assert!(import_server_with_options(&archive, &opts, false).is_err());
    drop(second);
    import_server_with_options(&archive, &opts, false).unwrap();
    assert!(ClientDatabase::load(&opts.clients_db, Default::default())
        .unwrap()
        .list_clients()
        .is_empty());
}

struct FixtureProcess(Child);
impl Drop for FixtureProcess {
    fn drop(&mut self) {
        drop(self.0.stdin.take());
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn child(root: &Path, kind: &str) -> (FixtureProcess, std::sync::mpsc::Receiver<()>) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "offline_process_fixture", "--nocapture"])
        .env("AIVPN_OFFLINE_TEST_ROOT", root)
        .env("AIVPN_OFFLINE_TEST_KIND", kind)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            if line == "FIXTURE_READY" {
                let _ = send.send(());
                break;
            }
        }
    });
    (FixtureProcess(child), receive)
}

#[test]
fn offline_process_fixture() {
    let Ok(root) = std::env::var("AIVPN_OFFLINE_TEST_ROOT") else {
        return;
    };
    let path = Path::new(&root).join("clients.json");
    let database;
    if std::env::var("AIVPN_OFFLINE_TEST_KIND").unwrap() == "export" {
        export_server(
            &ExportOptions {
                include_clients: true,
                clients_db: Some(path),
                ..Default::default()
            },
            &Path::new(&root).join("export.tar.gz"),
        )
        .unwrap();
    } else {
        database = ClientDatabase::load(&path, Default::default()).unwrap();
        std::hint::black_box(&database);
    }
    println!("FIXTURE_READY");
    std::io::stdout().flush().unwrap();
    let mut byte = [0; 1];
    let _ = std::io::stdin().read(&mut byte);
}

#[test]
fn cli_refuses_another_process_and_restores_corrupt_files_only_offline() {
    let root = tempfile::tempdir().unwrap();
    let archive = archive(root.path());
    let opts = options(root.path());
    std::fs::write(&opts.config_path, b"{}").unwrap();
    std::fs::write(&opts.clients_db, b"{\"clients\":[]}").unwrap();
    let (process, ready) = child(root.path(), "live");
    ready.recv_timeout(Duration::from_secs(10)).unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_aivpn-server"))
            .arg("--import")
            .arg(&archive)
            .arg("--config")
            .arg(&opts.config_path)
            .arg("--clients-db")
            .arg(&opts.clients_db)
            .arg("--mask-dir")
            .arg(&opts.mask_dir)
            .env("PATH", "/nonexistent-aivpn-test-path")
            .output()
            .unwrap()
    };
    let refused = run();
    assert!(
        !refused.status.success(),
        "CLI восстановил файлы при живом другом процессе"
    );
    assert!(String::from_utf8_lossy(&refused.stderr).contains("offline"));
    assert!(!opts.mask_dir.exists());
    drop(process);
    std::fs::write(&opts.config_path, b"broken-json").unwrap();
    std::fs::write(&opts.clients_db, b"broken-json").unwrap();
    let restored = run();
    assert!(
        restored.status.success(),
        "CLI должен восстанавливать испорченные файлы: {}",
        String::from_utf8_lossy(&restored.stderr)
    );
    assert_eq!(std::fs::read(&opts.config_path).unwrap(), b"{}");
    assert_eq!(
        std::fs::read(&opts.clients_db).unwrap(),
        b"{\"clients\":[]}"
    );
}

#[test]
fn exclusive_restore_lock_blocks_load_and_export_in_other_processes() {
    use std::os::fd::AsRawFd;
    for kind in ["live", "export"] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("clients.json");
        std::fs::write(&path, b"{\"clients\":[]}").unwrap();
        let lock = std::fs::File::create(root.path().join("clients.json.live.lock")).unwrap();
        assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
        let (_process, ready) = child(root.path(), kind);
        assert!(
            ready.recv_timeout(Duration::from_millis(200)).is_err(),
            "{kind} обошел эксклюзивное offline-восстановление"
        );
        assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
        ready.recv_timeout(Duration::from_secs(10)).unwrap();
    }
}

#[test]
fn lifetime_lock_refuses_symlinks_without_touching_victim() {
    let root = tempfile::tempdir().unwrap();
    let opts = options(root.path());
    let victim = root.path().join("victim");
    std::fs::write(&victim, b"sentinel").unwrap();
    std::os::unix::fs::symlink(&victim, root.path().join("clients.json.live.lock")).unwrap();
    assert!(ClientDatabase::load(&opts.clients_db, Default::default()).is_err());
    assert_eq!(std::fs::read(victim).unwrap(), b"sentinel");
}

#[test]
fn cli_waits_for_restore_before_reading_config() {
    use std::os::fd::AsRawFd;
    let root = tempfile::tempdir().unwrap();
    let opts = options(root.path());
    std::fs::write(&opts.config_path, b"half-restored-config").unwrap();
    std::fs::write(&opts.clients_db, b"{\"clients\":[]}").unwrap();
    let lock = std::fs::File::create(root.path().join("clients.json.live.lock")).unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let mut process = FixtureProcess(
        Command::new(env!("CARGO_BIN_EXE_aivpn-server"))
            .arg("--list-clients")
            .arg("--config")
            .arg(&opts.config_path)
            .arg("--clients-db")
            .arg(&opts.clients_db)
            .env("PATH", "/nonexistent-aivpn-test-path")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        process.0.try_wait().unwrap().is_none(),
        "CLI прочитал незавершенный config до shared owner"
    );
    std::fs::write(&opts.config_path, b"{}").unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
    assert!(process.0.wait().unwrap().success());
}
