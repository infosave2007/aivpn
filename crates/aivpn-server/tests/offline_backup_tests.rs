#![cfg(unix)]

use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use aivpn_server::backup::{
    export_server, import_server_with_options, ExportOptions, ImportOptions,
};
use aivpn_server::ClientDatabase;

// fork в соседнем тесте временно наследует flock-дескрипторы до exec.
// Не совмещаем этот промежуток с проверкой освобождения последнего владельца.
static PROCESS_TEST_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn options(root: &Path) -> ImportOptions {
    ImportOptions {
        config_path: root.join("server.json"),
        clients_db: root.join("clients.json"),
        mask_dir: root.join("masks"),
    }
}

fn assert_restored_empty_config(opts: &ImportOptions) {
    let actual: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&opts.config_path).unwrap()).unwrap();
    assert_eq!(
        actual,
        serde_json::json!({"clients_db":opts.clients_db,"mask_dir":opts.mask_dir})
    );
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
    let _process_gate = PROCESS_TEST_GATE.lock().unwrap();
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
    let _process_gate = PROCESS_TEST_GATE.lock().unwrap();
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
    assert_restored_empty_config(&opts);
    assert_eq!(
        std::fs::read(&opts.clients_db).unwrap(),
        b"{\"clients\":[]}"
    );
}

#[test]
fn cli_import_uses_json_database_and_refuses_its_live_owner() {
    let _process_gate = PROCESS_TEST_GATE.lock().unwrap();
    let root = tempfile::tempdir().unwrap();
    let archive = archive(root.path());
    let opts = ImportOptions {
        config_path: root.path().join("server.json"),
        clients_db: root.path().join("custom-database/records.json"),
        mask_dir: root.path().join("custom-masks"),
    };
    let owner = ClientDatabase::load(&opts.clients_db, Default::default()).unwrap();
    owner.add_client("live-json-database").unwrap();
    let config = serde_json::to_vec(&serde_json::json!({
        "clients_db":opts.clients_db,
        "mask_dir":opts.mask_dir,
    }))
    .unwrap();
    std::fs::write(&opts.config_path, &config).unwrap();
    let database = std::fs::read(&opts.clients_db).unwrap();
    let run = |dry_run| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_aivpn-server"));
        command
            .env_clear()
            .env("PATH", "/nonexistent-aivpn-test-path")
            .arg("--import")
            .arg(&archive)
            .arg("--config")
            .arg(&opts.config_path);
        if dry_run {
            command.arg("--dry-run");
        }
        command.output().unwrap()
    };
    // Сначала проверяем выбор пути без записи. Ошибочный старый CLI не
    // должен даже пытаться создать настоящий default DB/lock вне fixture.
    let preview = run(true);
    assert!(preview.status.success());
    let stdout = String::from_utf8(preview.stdout).unwrap();
    assert!(
        stdout.contains(&format!("clients_db: {:?}", opts.clients_db)),
        "Import должен использовать JSON DB, а не другой default: {stdout}"
    );
    assert!(stdout.contains(&format!("mask_dir: {:?}", opts.mask_dir)));
    let refused = run(false);
    assert!(
        !refused.status.success(),
        "Import обошел живой JSON DB owner"
    );
    assert!(String::from_utf8_lossy(&refused.stderr).contains("offline"));
    assert_eq!(std::fs::read(&opts.config_path).unwrap(), config);
    assert_eq!(std::fs::read(&opts.clients_db).unwrap(), database);
    assert!(!opts.mask_dir.exists());
    drop(owner);
}

#[test]
fn successful_cli_restore_keeps_destinations_on_the_next_json_only_start() {
    let _process_gate = PROCESS_TEST_GATE.lock().unwrap();
    for empty_config in [false, true] {
        for selector in ["json", "env", "cli"] {
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("source");
            let target = root.path().join("target");
            std::fs::create_dir_all(&source).unwrap();
            std::fs::create_dir_all(&target).unwrap();
            let source_db = source.join("records.json");
            let source_masks = source.join("profiles");
            std::fs::create_dir(&source_masks).unwrap();
            let profile = aivpn_common::mask::preset_masks::quic_https_v2();
            let mask_name = format!("{}.json", profile.mask_id);
            std::fs::write(
                source_masks.join(&mask_name),
                serde_json::to_vec(&profile).unwrap(),
            )
            .unwrap();
            let signing = source.join("operator.key");
            std::fs::write(&signing, [18; 32]).unwrap();
            let config = if empty_config {
                serde_json::json!({})
            } else {
                serde_json::json!({
                    "clients_db":source_db,"mask_dir":source_masks,
                    "mask_signing_key":signing,"log_level":"warn",
                    "neural_enabled":false,"future_extension":{"keep":"fixture"},
                })
            };
            let source_config = source.join("server.json");
            std::fs::write(&source_config, serde_json::to_vec(&config).unwrap()).unwrap();
            let db = ClientDatabase::load(&source_db, Default::default()).unwrap();
            db.add_client("archived-only-client").unwrap();
            drop(db);
            let archive = root.path().join("relocated.tar.gz");
            export_server(
                &ExportOptions {
                    include_config: true,
                    include_clients: true,
                    include_masks: true,
                    config_path: Some(source_config),
                    clients_db: Some(source_db.clone()),
                    mask_dir: Some(source_masks),
                },
                &archive,
            )
            .unwrap();
            std::fs::write(&source_db, b"{\"clients\":[]}").unwrap();
            let db = ClientDatabase::load(&source_db, Default::default()).unwrap();
            db.add_client("source-after-export").unwrap();
            drop(db);
            std::fs::copy(
                source.join("backup_integrity.key"),
                target.join("backup_integrity.key"),
            )
            .unwrap();
            let opts = ImportOptions {
                config_path: target.join("server.json"),
                clients_db: target.join("selected/records.json"),
                mask_dir: target.join("selected/profiles"),
            };
            let old_db = target.join("previous/records.json");
            let old_masks = target.join("previous/profiles");
            let (json_db, json_masks) = if selector == "json" {
                (&opts.clients_db, &opts.mask_dir)
            } else {
                (&old_db, &old_masks)
            };
            let before = serde_json::to_vec(&serde_json::json!({
                "clients_db":json_db,"mask_dir":json_masks,
            }))
            .unwrap();
            std::fs::write(&opts.config_path, &before).unwrap();
            let preview = import_server_with_options(&archive, &opts, true).unwrap();
            assert!(preview.signed, "Проверяется исходный подписанный архив");
            assert_eq!(std::fs::read(&opts.config_path).unwrap(), before);
            let mut restore = Command::new(env!("CARGO_BIN_EXE_aivpn-server"));
            restore
                .env_clear()
                .env("PATH", "/nonexistent-aivpn-test-path")
                .arg("--import")
                .arg(&archive)
                .arg("--config")
                .arg(&opts.config_path);
            if selector == "env" {
                restore
                    .env("AIVPN_CLIENTS_DB", &opts.clients_db)
                    .env("AIVPN_MASK_DIR", &opts.mask_dir);
            } else if selector == "cli" {
                restore
                    .arg("--clients-db")
                    .arg(&opts.clients_db)
                    .arg("--mask-dir")
                    .arg(&opts.mask_dir);
            }
            let restored = restore.output().unwrap();
            assert!(
                restored.status.success(),
                "{}",
                String::from_utf8_lossy(&restored.stderr)
            );
            let actual: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&opts.config_path).unwrap()).unwrap();
            assert!(
                actual["clients_db"]
                    .as_str()
                    .is_some_and(|path| Path::new(path).starts_with(root.path())),
                "Fixture не должна открывать default DB вне temp-каталога"
            );
            let listed = Command::new(env!("CARGO_BIN_EXE_aivpn-server"))
                .env_clear()
                .env("PATH", "/nonexistent-aivpn-test-path")
                .env("AIVPN_MASK_SIGNING_KEY", &signing)
                .arg("--config")
                .arg(&opts.config_path)
                .arg("--list-clients")
                .output()
                .unwrap();
            assert!(
                listed.status.success(),
                "{}",
                String::from_utf8_lossy(&listed.stderr)
            );
            let stdout = String::from_utf8(listed.stdout).unwrap();
            assert!(
                stdout.contains("archived-only-client") && !stdout.contains("source-after-export"),
                "JSON-only запуск потерял восстановленную DB: {selector}, empty={empty_config}: {stdout}"
            );
            let mut expected = config;
            expected["clients_db"] = serde_json::to_value(&opts.clients_db).unwrap();
            expected["mask_dir"] = serde_json::to_value(&opts.mask_dir).unwrap();
            assert_eq!(actual, expected, "Меняются только два пути назначения");
            assert!(opts.mask_dir.join(mask_name).exists());
            assert_eq!(std::fs::read(&signing).unwrap(), [18; 32]);
        }
    }
}

#[test]
fn cli_import_corrupt_existing_config_needs_explicit_destinations() {
    let _process_gate = PROCESS_TEST_GATE.lock().unwrap();
    let root = tempfile::tempdir().unwrap();
    let archive = archive(root.path());
    let opts = options(root.path());
    std::fs::write(&opts.config_path, b"broken-json").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_aivpn-server"))
        .env_clear()
        .env("PATH", "/nonexistent-aivpn-test-path")
        .arg("--import")
        .arg(archive)
        .arg("--dry-run")
        .arg("--config")
        .arg(&opts.config_path)
        .output()
        .unwrap();
    assert!(
        !result.status.success(),
        "Поврежденный config не определяет DB, скрытый default недопустим"
    );
    assert_eq!(std::fs::read(opts.config_path).unwrap(), b"broken-json");
    assert!(!opts.clients_db.exists());
}

#[test]
fn cli_restore_null_and_empty_environment_paths_do_not_become_literal_targets() {
    let _process_gate = PROCESS_TEST_GATE.lock().unwrap();
    let root = tempfile::tempdir().unwrap();
    let archive = archive(root.path());
    let opts = options(root.path());
    let before = serde_json::to_vec(&serde_json::json!({
        "clients_db":opts.clients_db,"mask_dir":opts.mask_dir,
    }))
    .unwrap();
    std::fs::write(&opts.config_path, &before).unwrap();
    for value in ["null", "", "\"\"", "   "] {
        let result = Command::new(env!("CARGO_BIN_EXE_aivpn-server"))
            .env_clear()
            .env("PATH", "/nonexistent-aivpn-test-path")
            .env("AIVPN_CLIENTS_DB", value)
            .env("AIVPN_MASK_DIR", value)
            .arg("--import")
            .arg(&archive)
            .arg("--config")
            .arg(&opts.config_path)
            .arg("--dry-run")
            .output()
            .unwrap();
        if value == "null" {
            assert!(result.status.success());
            let stdout = String::from_utf8(result.stdout).unwrap();
            assert!(stdout.contains("clients_db: \"/etc/aivpn/clients.json\""));
            assert!(stdout.contains("mask_dir: \"/var/lib/aivpn/masks\""));
        } else {
            assert!(!result.status.success());
            assert!(String::from_utf8_lossy(&result.stderr).contains("пустой путь"));
        }
        assert_eq!(std::fs::read(&opts.config_path).unwrap(), before);
        assert!(!opts.clients_db.exists() && !opts.mask_dir.exists());
    }
}

#[test]
fn standalone_mask_signing_does_not_open_an_unrelated_database() {
    let _process_gate = PROCESS_TEST_GATE.lock().unwrap();
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("server.json");
    std::fs::write(&config, b"{}").unwrap();
    let unavailable_parent = root.path().join("not-a-directory");
    std::fs::write(&unavailable_parent, b"sentinel").unwrap();
    let masks = root.path().join("operator-masks");
    std::fs::create_dir(&masks).unwrap();
    let path = masks.join("quic_https_v2.json");
    let mut mask = aivpn_common::mask::preset_masks::quic_https_v2();
    mask.signature = [0; 64];
    std::fs::write(&path, serde_json::to_vec(&mask).unwrap()).unwrap();
    let key = root.path().join("operator.key");
    std::fs::write(&key, [7; 32]).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_aivpn-server"))
        .env_clear()
        .env("PATH", "/nonexistent-aivpn-test-path")
        .arg("--config")
        .arg(config)
        .arg("--clients-db")
        .arg(unavailable_parent.join("clients.json"))
        .arg("--sign-mask-dir")
        .arg(masks)
        .arg("--mask-signing-key")
        .arg(key)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Подпись не требует runtime DB: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let signed: aivpn_common::mask::MaskProfile =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_ne!(signed.signature, [0; 64]);
    assert!(signed
        .verify_signature(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .to_bytes()
        )
        .unwrap());
    assert_eq!(std::fs::read(unavailable_parent).unwrap(), b"sentinel");
}

#[test]
fn cli_restore_path_precedence_does_not_validate_unrelated_settings() {
    let _process_gate = PROCESS_TEST_GATE.lock().unwrap();
    let root = tempfile::tempdir().unwrap();
    let archive = archive(root.path());
    let config = root.path().join("server.json");
    let json_db = root.path().join("json-records.json");
    let json_masks = root.path().join("json-masks");
    std::fs::write(
        &config,
        serde_json::to_vec(&serde_json::json!({
            "clients_db":json_db,"mask_dir":json_masks,
            "listen_addr":false,"mask_signing_key":42,"neural_enabled":"broken",
        }))
        .unwrap(),
    )
    .unwrap();
    let env_db = root.path().join("env-records.json");
    let env_masks = root.path().join("env-masks");
    let cli_db = root.path().join("cli-records.json");
    let cli_masks = root.path().join("cli-masks");
    for use_cli in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_aivpn-server"));
        command
            .env_clear()
            .env("PATH", "/nonexistent-aivpn-test-path")
            .env("AIVPN_CLIENTS_DB", &env_db)
            .env("AIVPN_MASK_DIR", &env_masks)
            .arg("--import")
            .arg(&archive)
            .arg("--dry-run")
            .arg("--config")
            .arg(&config);
        let (expected_db, expected_masks) = if use_cli {
            command
                .arg("--clients-db")
                .arg(&cli_db)
                .arg("--mask-dir")
                .arg(&cli_masks);
            (&cli_db, &cli_masks)
        } else {
            (&env_db, &env_masks)
        };
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains(&format!("clients_db: {expected_db:?}")));
        assert!(stdout.contains(&format!("mask_dir: {expected_masks:?}")));
    }
    assert!(!env_db.exists() && !cli_db.exists() && !json_db.exists());
}

#[test]
fn cli_explicit_env_targets_recover_corrupt_files_and_fresh_config_has_defaults() {
    let _process_gate = PROCESS_TEST_GATE.lock().unwrap();
    let root = tempfile::tempdir().unwrap();
    let archive = archive(root.path());
    let opts = options(root.path());
    std::fs::write(&opts.config_path, b"broken-config").unwrap();
    std::fs::write(&opts.clients_db, b"broken-db").unwrap();
    let recovered = Command::new(env!("CARGO_BIN_EXE_aivpn-server"))
        .env_clear()
        .env("PATH", "/nonexistent-aivpn-test-path")
        .env("AIVPN_CONFIG", &opts.config_path)
        .env("AIVPN_CLIENTS_DB", &opts.clients_db)
        .env("AIVPN_MASK_DIR", &opts.mask_dir)
        .arg("--import")
        .arg(&archive)
        .output()
        .unwrap();
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_restored_empty_config(&opts);
    assert_eq!(
        std::fs::read(&opts.clients_db).unwrap(),
        b"{\"clients\":[]}"
    );
    let fresh = root.path().join("absent-server.json");
    let preview = Command::new(env!("CARGO_BIN_EXE_aivpn-server"))
        .env_clear()
        .env("PATH", "/nonexistent-aivpn-test-path")
        .arg("--import")
        .arg(&archive)
        .arg("--config")
        .arg(&fresh)
        .arg("--dry-run")
        .output()
        .unwrap();
    assert!(preview.status.success());
    let stdout = String::from_utf8(preview.stdout).unwrap();
    assert!(stdout.contains("clients_db: \"/etc/aivpn/clients.json\""));
    assert!(!fresh.exists());
}

#[test]
fn exclusive_restore_lock_blocks_load_and_export_in_other_processes() {
    let _process_gate = PROCESS_TEST_GATE.lock().unwrap();
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
    let _process_gate = PROCESS_TEST_GATE.lock().unwrap();
    use std::os::fd::AsRawFd;
    let root = tempfile::tempdir().unwrap();
    let opts = options(root.path());
    let signing = root.path().join("signing.key");
    std::fs::write(&signing, [18u8; 32]).unwrap();
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
            .env("AIVPN_MASK_SIGNING_KEY", &signing)
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

#[test]
fn cli_rereads_config_after_waiting_for_its_database_restore() {
    let _process_gate = PROCESS_TEST_GATE.lock().unwrap();
    use std::os::fd::AsRawFd;
    let root = tempfile::tempdir().unwrap();
    let opts = options(root.path());
    let signing = root.path().join("signing.key");
    std::fs::write(&signing, [18u8; 32]).unwrap();
    std::fs::write(
        &opts.config_path,
        serde_json::to_vec(&serde_json::json!({"clients_db":opts.clients_db})).unwrap(),
    )
    .unwrap();
    std::fs::write(&opts.clients_db, b"{\"clients\":[]}").unwrap();
    let restored_db = root.path().join("restored-clients.json");
    let fixture = ClientDatabase::load(&restored_db, Default::default()).unwrap();
    fixture.add_client("restored-db-client").unwrap();
    let lock = std::fs::File::create(root.path().join("clients.json.live.lock")).unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let mut process = FixtureProcess(
        Command::new(env!("CARGO_BIN_EXE_aivpn-server"))
            .arg("--list-clients")
            .arg("--config")
            .arg(&opts.config_path)
            .env_clear()
            .env("PATH", "/nonexistent-aivpn-test-path")
            .env("AIVPN_MASK_SIGNING_KEY", &signing)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        process.0.try_wait().unwrap().is_none(),
        "CLI обошел восстановление DB из config"
    );
    std::fs::write(
        &opts.config_path,
        serde_json::to_vec(&serde_json::json!({"clients_db":restored_db})).unwrap(),
    )
    .unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
    assert!(process.0.wait().unwrap().success());
    let mut stdout = String::new();
    process
        .0
        .stdout
        .as_mut()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    assert!(stdout.contains("restored-db-client"));
}
