#[cfg(target_os = "linux")]
#[test]
fn tun_helper_requires_root_before_creating_a_listener() {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    if unsafe { geteuid() } == 0 {
        return;
    }
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_aivpn-client"))
        .args(["__network-helper", "--tun-session"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1), "{:?}", result);
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("root"));
}
