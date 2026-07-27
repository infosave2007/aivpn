//! Shared symlink-safe, best-effort atomic write helper for the small
//! status/IPC files this crate writes to predictable paths — often under
//! world-writable `/tmp` (or its Windows temp-dir equivalent) as a fallback
//! when a per-user runtime dir isn't available: recording status
//! (`record_cmd.rs`), the mask catalog (`mask_catalog.rs`), traffic stats and
//! the quality-score file (`client.rs`).
//!
//! Without hardening, a local attacker can pre-create any of these paths as a
//! symlink to a file the (possibly root — running as root is a documented
//! supported mode) client process can write; the next status write follows
//! the symlink and clobbers/corrupts the target. Mirrors the O_NOFOLLOW +
//! create_new + tmp-then-rename pattern already used by `kill_switch.rs`'s pf
//! anchor writer and the admin-token writer in `record_cmd.rs`.

use std::io::Write;
use std::path::Path;

/// Best-effort atomic, symlink-safe write of `bytes` to `path`.
///
/// Writes to a `.tmp` sibling via O_NOFOLLOW + O_EXCL (create_new) at mode
/// 0600 — so a pre-planted symlink or file at the temp path is rejected, not
/// followed or truncated-through — then renames onto the final path.
/// `rename(2)` never dereferences the final component of its destination: if
/// `path` itself is a pre-planted symlink, the rename detaches/replaces the
/// symlink itself rather than writing through it, so hardening only the temp
/// write (not the final path) is sufficient for both hops.
///
/// Returns `true` on success. Callers that don't need the fallback signal
/// (most status writers) can ignore the result; no-ops silently either way —
/// all call sites are best-effort status files whose absence is already
/// handled by readers (missing/stale data, not a hard error).
pub fn write_status_best_effort(path: &Path, bytes: &[u8]) -> bool {
    let tmp_path = path.with_extension("tmp");
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Best-effort unlink of any prior file at the tmp path (ours from a
        // previous run, or an attacker's pre-created symlink) before
        // creating fresh with O_EXCL, so the permission window never opens.
        // `remove_file` (unlink) never follows symlinks on the final
        // component either, so this can't be redirected to delete something
        // else.
        let _ = std::fs::remove_file(&tmp_path);
        let write_result = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp_path)
            .and_then(|mut f| f.write_all(bytes));
        if write_result.is_ok() {
            std::fs::rename(&tmp_path, path).is_ok()
        } else {
            let _ = std::fs::remove_file(&tmp_path);
            false
        }
    }
    #[cfg(not(unix))]
    {
        if std::fs::write(&tmp_path, bytes).is_ok() {
            std::fs::rename(&tmp_path, path).is_ok()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
