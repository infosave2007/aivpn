use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub(crate) fn read_failure(path: &Path, panicked: bool) -> Option<String> {
    const TAIL: u64 = 65536;
    let mut file = std::fs::File::open(path).ok()?;
    let length = file.seek(SeekFrom::End(0)).ok()?;
    file.seek(SeekFrom::Start(length.saturating_sub(TAIL)))
        .ok()?;
    let mut bytes = Vec::new();
    file.take(TAIL).read_to_end(&mut bytes).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    lines
        .clone()
        .rev()
        .find(|line| panicked && line.starts_with("AIVPN-PANIC "))
        .or_else(|| lines.last())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct Log(std::path::PathBuf);
    impl Log {
        fn new(text: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "aivpn-log-regression-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::write(&path, text).unwrap();
            Self(path)
        }
    }
    impl Drop for Log {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn panic_is_not_replaced_by_adapter_cleanup() {
        let log = Log::new("start\nAIVPN-PANIC tunnel.rs:42:7: test failure\n  0: frame\nINFO wintun_bindings::adapter: Successfully deleted Unmanaged sub_key: test\n");
        assert_eq!(
            read_failure(&log.0, true).as_deref(),
            Some("AIVPN-PANIC tunnel.rs:42:7: test failure")
        );
    }

    #[test]
    fn tail_start_inside_utf8_does_not_hide_error() {
        let log = Log::new(&format!("{}\nnetwork failure\n", "я".repeat(40000)));
        assert_eq!(
            read_failure(&log.0, true).as_deref(),
            Some("network failure")
        );
    }

    #[test]
    fn ordinary_exit_keeps_last_message() {
        let log = Log::new("start\nnetwork failure\n\n");
        assert_eq!(
            read_failure(&log.0, false).as_deref(),
            Some("network failure")
        );
    }

    #[test]
    fn later_connection_error_is_not_replaced_by_an_old_worker_panic() {
        let log = Log::new("AIVPN-PANIC task.rs:5:1: old background failure\nnetwork failure\n");
        assert_eq!(
            read_failure(&log.0, false).as_deref(),
            Some("network failure")
        );
    }
}
