#![cfg(all(target_os = "linux", feature = "linux-kernel"))]

#[path = "support/linux_binding_fixture.rs"]
mod fixture;

#[test]
#[ignore = "Нужен отдельный no-NIC root-стенд с BPF LSM и свободным /dev/vda"]
fn known_inode_cannot_override_scoped_path_mismatch() {
    fixture::require_guest();
    let script = "/lab/binding_probe.py";
    std::fs::write(script, include_str!("support/linux_binding_probe.py")).unwrap();
    let status = std::process::Command::new("python3")
        .arg(script)
        .env("AIVPN_BINDING_FIXTURE", std::env::current_exe().unwrap())
        .status()
        .unwrap();
    assert!(
        status.success(),
        "Native binding regression завершился с ошибкой"
    );
}

#[test]
#[ignore = "Дочерний writer только для изолированного native-стенда"]
fn binding_writer_child() {
    fixture::require_guest();
    assert_eq!(std::env::var("AIVPN_BINDING_CHILD").as_deref(), Ok("1"));
    fixture::run();
}
