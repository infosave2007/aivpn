//! Атомарная запись файлов состояния без перехода по символическим ссылкам.

use std::io::Write;
use std::path::Path;

/// Ошибка записи оставляет предыдущий снимок состояния доступным читателям.
pub fn write_status_best_effort(path: &Path, bytes: &[u8]) -> bool {
    let tmp_path = path.with_extension(format!("{:032x}.tmp", rand::random::<u128>()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let Ok(mut file) = options.open(&tmp_path) else {
        return false;
    };
    let result = file.write_all(bytes);
    drop(file);
    let success = result.is_ok() && std::fs::rename(&tmp_path, path).is_ok();
    if !success {
        let _ = std::fs::remove_file(&tmp_path);
    }
    success
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_writers_publish_complete_snapshots() {
        let dir =
            std::env::temp_dir().join(format!("aivpn-status-{:032x}", rand::random::<u128>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("status.json");
        let handles: Vec<_> = (0u8..8)
            .map(|value| {
                let path = path.clone();
                std::thread::spawn(move || {
                    for _ in 0..20 {
                        assert!(write_status_best_effort(&path, &[value; 4096]));
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        let snapshot = std::fs::read(&path).unwrap();
        assert_eq!(snapshot.len(), 4096);
        assert!(snapshot.iter().all(|byte| *byte == snapshot[0]));
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn writes_and_reads_back() {
        let dir =
            std::env::temp_dir().join(format!("aivpn-secure-write-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("status.json");
        write_status_best_effort(&path, b"{\"a\":1}");
        let data = std::fs::read(&path).unwrap();
        assert_eq!(data, b"{\"a\":1}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_to_follow_a_symlinked_target() {
        let dir = std::env::temp_dir().join(format!(
            "aivpn-secure-write-symlink-test-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let victim = dir.join("victim.txt");
        std::fs::write(&victim, b"original").unwrap();
        let path = dir.join("status.json");
        std::os::unix::fs::symlink(&victim, &path).unwrap();

        write_status_best_effort(&path, b"attacker-controlled");

        // The rename replaces the symlink itself; the victim file is untouched.
        let victim_contents = std::fs::read(&victim).unwrap();
        assert_eq!(victim_contents, b"original");
        // `path` is now a regular file with the new content.
        assert!(!std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        let path_contents = std::fs::read(&path).unwrap();
        assert_eq!(path_contents, b"attacker-controlled");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
