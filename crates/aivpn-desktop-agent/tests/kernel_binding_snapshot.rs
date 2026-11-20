#![cfg(all(target_os = "linux", feature = "linux-kernel"))]
#[allow(dead_code)]
#[path = "support/retention_lab.rs"]
mod lab;
use aivpn_desktop_agent::{linux::kernel::KernelWriter, state::StateDirectory};
use aivpn_desktop_policy::*;
use std::{os::unix::fs::DirBuilderExt, path::Path};

#[test]
#[ignore = "Нужен собственный изолированный root-стенд"]
fn real_hardlinks_compile_into_a_frozen_snapshot() {
    lab::require_lab();
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert!(std::fs::read_to_string("/proc/cmdline")
        .unwrap()
        .split_ascii_whitespace()
        .any(|s| s == "aivpn.binding-snapshot=1"));
    lab::setup();
    let cleanup = lab::Cleanup;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(format!("{}/bindings", lab::ROOT))
        .unwrap();
    let mut writer = KernelWriter::install_new_snapshot(
        lab::NS,
        StateDirectory::open(Path::new(&format!("{}/state", lab::ROOT))).unwrap(),
    )
    .unwrap();
    writer
        .open_verified_bindings(
            StateDirectory::open(Path::new(&format!("{}/bindings", lab::ROOT))).unwrap(),
        )
        .unwrap();
    writer.recover_verified_bindings().unwrap();
    let (catalog, mut registry, authority) = lab::inputs(Path::new(lab::TARGET), lab::NS);
    let mut document = registry.policies().next().unwrap().document().clone();
    document.generation += 1;
    document.rules.push(RuleDocument {
        id: "alias".into(),
        application: Selector::Executable {
            path: lab::ALIAS.into(),
        },
        ..document.rules[0].clone()
    });
    let change = registry.prepare(document, &authority, Some(1)).unwrap();
    registry.commit(change).unwrap();
    let request = writer
        .selected_executables(&registry, &catalog, &authority, 1)
        .unwrap();
    let staged = unsafe {
        writer.stage_verified_bindings(
            &request,
            vec![
                lab::locate(Path::new(lab::TARGET)),
                lab::locate(Path::new(lab::ALIAS)),
            ],
        )
    }
    .unwrap();
    let snapshot = writer.prepare_binding_snapshot(&request, &staged);
    assert!(
        snapshot.is_ok(),
        "Настоящие A/H должны дать frozen artifact: {:?}",
        snapshot.as_ref().err()
    );
    let snapshot = snapshot.unwrap();
    assert_eq!(snapshot.record_count(), 12);
    use std::os::fd::{AsFd, AsRawFd};
    let fd = snapshot.as_fd().as_raw_fd();
    let root = lab::open(&lab::static_pins().join("maps/binding_root"));
    let zero = 0u32;
    let mut active = 0u32;
    for point in ["allocation", "fill", "readback", "freeze"] {
        std::env::set_var("AIVPN_SNAPSHOT_FAULT", point);
        assert!(
            writer.prepare_binding_snapshot(&request, &staged).is_err(),
            "fault {point}"
        );
        std::env::remove_var("AIVPN_SNAPSHOT_FAULT");
        assert_eq!(
            unsafe {
                lab::bpf_map_lookup_elem(
                    root.as_raw_fd(),
                    (&zero as *const u32).cast(),
                    (&mut active as *mut u32).cast(),
                )
            },
            -libc::ENOENT
        );
    }
    let key = [7u64, 0, 0, 0, 0];
    let value = [0u8; 64];
    assert_eq!(
        unsafe { lab::bpf_map_update_elem(fd, key.as_ptr().cast(), value.as_ptr().cast(), 0) },
        -libc::EPERM
    );
    drop(root);
    drop(snapshot);
    drop(writer);
    drop(cleanup);
    std::fs::remove_dir_all(
        "/sys/fs/bpf/aivpn_app_group_retainers/71717171717171717171717171717171",
    )
    .unwrap();
    drop(staged);
}

#[path = "support/linux_snapshot_fixture.rs"]
mod snapshot_fixture;
#[test]
#[ignore = "Нужен отдельный no-NIC root-стенд с BPF LSM"]
fn fixed_root_packet_matrix() {
    snapshot_fixture::require_guest();
    std::fs::write(
        "/lab/binding_probe.py",
        include_str!("support/linux_binding_probe.py"),
    )
    .unwrap();
    std::fs::write(
        "/lab/snapshot_probe.py",
        include_str!("support/linux_snapshot_probe.py"),
    )
    .unwrap();
    std::fs::write(
        "/lab/exec_probe.py",
        include_str!("support/linux_exec_probe.py"),
    )
    .unwrap();
    let status = std::process::Command::new("python3")
        .arg("/lab/snapshot_probe.py")
        .env("AIVPN_BINDING_FIXTURE", std::env::current_exe().unwrap())
        .status()
        .unwrap();
    assert!(status.success(), "Пакетный Snapshot consumer отказал");
}

#[test]
#[ignore = "Первый admission только в собственном no-NIC guest"]
fn snapshot_first_admission() {
    snapshot_fixture::require_guest();
    for (name, source) in [
        (
            "binding_probe.py",
            include_str!("support/linux_binding_probe.py"),
        ),
        (
            "admission_probe.py",
            include_str!("support/linux_admission_probe.py"),
        ),
    ] {
        std::fs::write(format!("/lab/{name}"), source).unwrap();
    }
    let status = std::process::Command::new("python3")
        .arg("/lab/admission_probe.py")
        .env("AIVPN_BINDING_FIXTURE", std::env::current_exe().unwrap())
        .status()
        .unwrap();
    assert!(status.success(), "Первый пакет не прошел admission oracle");
}
#[test]
#[ignore = "Дочерняя guarded fixture"]
fn snapshot_writer_child() {
    snapshot_fixture::require_guest();
    assert_eq!(std::env::var("AIVPN_SNAPSHOT_CHILD").as_deref(), Ok("1"));
    snapshot_fixture::run();
}

#[allow(dead_code)]
#[path = "support/linux_binding_fixture.rs"]
mod legacy_capture_fixture;
#[test]
#[ignore = "Дочерняя Legacy fixture только для capture regression в госте"]
fn legacy_capture_writer_child() {
    snapshot_fixture::require_guest();
    assert_eq!(std::env::var("CAPTURE_LEGACY").as_deref(), Ok("1"));
    legacy_capture_fixture::run();
}

#[path = "support/snapshot_modes.rs"]
mod snapshot_modes;
#[test]
#[ignore = "Собственный no-NIC guest: modes и metadata refusal без state lock"]
fn immutable_modes_and_metadata_refuse_without_changing_owned_state() {
    snapshot_modes::run();
}
