use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

pub struct Fixture(pub PathBuf);

impl Fixture {
    pub fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "aivpn-state-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.0.exists() {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
}

pub fn icacls(path: &Path, arguments: &[&str]) {
    let output = Command::new("icacls.exe")
        .arg(path)
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "icacls: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}
