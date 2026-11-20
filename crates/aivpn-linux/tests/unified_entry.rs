use std::process::Command;

#[test]
fn headless_capabilities_do_not_initialize_gui_or_user_settings() {
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let scratch =
        Scratch(std::env::temp_dir().join(format!("aivpn-gui-entry-{}", std::process::id())));
    std::fs::create_dir(&scratch.0).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_aivpn-linux"))
        .arg("--capabilities")
        .env("HOME", &scratch.0)
        .env("XDG_CONFIG_HOME", scratch.0.join("config"))
        .env("XDG_DATA_HOME", scratch.0.join("data"))
        .env("XDG_RUNTIME_DIR", &scratch.0)
        .env("DISPLAY", "")
        .env_remove("WAYLAND_DISPLAY")
        .output()
        .unwrap();
    assert!(result.status.success(), "{:?}", result);
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains("\"readiness_checked\":false"), "{text}");
    assert!(!scratch.0.join("config/aivpn/settings.json").exists());
    assert!(!scratch.0.join("data/aivpn/keys.json").exists());
}
