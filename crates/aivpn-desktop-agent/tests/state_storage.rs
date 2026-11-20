#![cfg(target_os = "linux")]

use aivpn_desktop_agent::state::{StateDirectory, StateFile, MAX_STATE_BYTES};
use std::fs::{self, File, Permissions};
use std::io;
use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::var_os("AIVPN_STATE_FIXTURE_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = parent.join(format!(
            "aivpn-desktop-state-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        fs::write(path.join(".aivpn-state-test"), b"aivpn-state-fixture-v1\n").unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn private_file(&self, name: &str, data: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, data).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        path
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn committed_state_and_pending_journal_survive_reopening() {
    let directory = Directory::new();
    {
        let mut store = StateDirectory::open(directory.path()).unwrap();
        assert_eq!(store.load(StateFile::Committed).unwrap(), None);
        assert_eq!(store.load(StateFile::Pending).unwrap(), None);
        store.replace(StateFile::Committed, b"old-state").unwrap();
        store
            .replace(StateFile::Pending, b"prepared-change")
            .unwrap();
    }
    let mut store = StateDirectory::open(directory.path()).unwrap();
    assert_eq!(
        store.load(StateFile::Committed).unwrap().unwrap(),
        b"old-state"
    );
    assert_eq!(
        store.load(StateFile::Pending).unwrap().unwrap(),
        b"prepared-change"
    );
    store.replace(StateFile::Committed, b"new-state").unwrap();
    store.clear_pending().unwrap();
    store.clear_pending().unwrap();
    assert_eq!(store.load(StateFile::Pending).unwrap(), None);
    store.replace(StateFile::Pending, b"").unwrap();
    assert_eq!(store.load(StateFile::Pending).unwrap(), Some(vec![]));
    store.clear_pending().unwrap();
    drop(store);
    let store = StateDirectory::open(directory.path()).unwrap();
    assert_eq!(
        store.load(StateFile::Committed).unwrap().unwrap(),
        b"new-state"
    );
    for name in ["state.json", ".lock"] {
        assert_eq!(
            fs::metadata(directory.0.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }
}

#[test]
fn a_second_writer_is_refused_until_the_first_store_closes() {
    let directory = Directory::new();
    let store = StateDirectory::open(directory.path()).unwrap();
    let error = StateDirectory::open(directory.path()).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    drop(store);
    assert!(StateDirectory::open(directory.path()).is_ok());
}

#[test]
fn a_forked_child_cannot_keep_the_closed_parent_store_locked() {
    use std::os::fd::{FromRawFd, OwnedFd};
    struct Child {
        pid: libc::pid_t,
        signal: Option<OwnedFd>,
    }
    impl Drop for Child {
        fn drop(&mut self) {
            self.signal.take();
            loop {
                if unsafe { libc::waitpid(self.pid, std::ptr::null_mut(), 0) } >= 0 {
                    break;
                }
                if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    break;
                }
            }
        }
    }
    let directory = Directory::new();
    let store = StateDirectory::open(directory.path()).unwrap();
    let mut pipe = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        // После fork ребенок вызывает только async-signal-safe функции до _exit.
        unsafe {
            libc::close(pipe[1]);
            libc::alarm(5);
            let mut byte = 0u8;
            libc::read(pipe[0], (&mut byte as *mut u8).cast(), 1);
            libc::_exit(0);
        }
    }
    let _child = Child {
        pid,
        signal: Some(unsafe { OwnedFd::from_raw_fd(pipe[1]) }),
    };
    drop(unsafe { OwnedFd::from_raw_fd(pipe[0]) });
    drop(store);
    assert!(StateDirectory::open(directory.path()).is_ok());
}

#[test]
fn public_or_symbolic_directories_are_refused() {
    let directory = Directory::new();
    fs::set_permissions(directory.path(), Permissions::from_mode(0o755)).unwrap();
    assert!(StateDirectory::open(directory.path()).is_err());
    fs::set_permissions(directory.path(), Permissions::from_mode(0o700)).unwrap();
    let outer = Directory::new();
    let alias = outer.0.join("alias");
    symlink(directory.path(), &alias).unwrap();
    assert!(StateDirectory::open(&alias).is_err());
    assert!(StateDirectory::open(&outer.0.join("missing")).is_err());
}

#[test]
fn unsafe_record_types_permissions_and_links_are_rejected_without_changing_targets() {
    for kind in ["symlink", "hardlink", "public", "directory", "fifo"] {
        let directory = Directory::new();
        let target = directory.private_file("victim", b"preserve");
        let path = directory.0.join("state.json");
        match kind {
            "symlink" => symlink(&target, &path).unwrap(),
            "hardlink" => fs::hard_link(&target, &path).unwrap(),
            "public" => {
                fs::write(&path, b"public").unwrap();
                fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
            }
            "directory" => fs::create_dir(&path).unwrap(),
            "fifo" => {
                use std::os::unix::ffi::OsStrExt;
                let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
            _ => unreachable!(),
        }
        let mut store = StateDirectory::open(directory.path()).unwrap();
        assert!(store.load(StateFile::Committed).is_err(), "{kind}");
        assert!(
            store.replace(StateFile::Committed, b"replacement").is_err(),
            "{kind}"
        );
        assert_eq!(fs::read(&target).unwrap(), b"preserve", "{kind}");
    }
}

#[test]
fn unsafe_lock_and_stale_temporary_files_are_preserved_and_refused() {
    for name in [".lock", ".new-state.json", ".new-pending.json"] {
        let directory = Directory::new();
        let victim = directory.private_file("victim", b"preserve");
        symlink(&victim, directory.0.join(name)).unwrap();
        assert!(StateDirectory::open(directory.path()).is_err(), "{name}");
        assert!(fs::symlink_metadata(directory.0.join(name))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&victim).unwrap(), b"preserve");
    }
}

#[test]
fn incomplete_temporary_writes_are_discarded_without_losing_the_committed_state() {
    let directory = Directory::new();
    directory.private_file("state.json", b"committed");
    for name in [".new-state.json", ".new-pending.json"] {
        directory.private_file(name, b"incomplete");
    }
    let store = StateDirectory::open(directory.path()).unwrap();
    assert_eq!(
        store.load(StateFile::Committed).unwrap().unwrap(),
        b"committed"
    );
    assert!(!directory.0.join(".new-state.json").exists());
    assert!(!directory.0.join(".new-pending.json").exists());
}

#[test]
fn oversized_files_and_writes_do_not_replace_the_last_valid_state() {
    assert_eq!(MAX_STATE_BYTES, 67_108_864);
    let directory = Directory::new();
    let mut store = StateDirectory::open(directory.path()).unwrap();
    store.replace(StateFile::Committed, b"preserve").unwrap();
    assert!(store
        .replace(StateFile::Committed, &vec![0; MAX_STATE_BYTES + 1])
        .is_err());
    assert_eq!(
        store.load(StateFile::Committed).unwrap().unwrap(),
        b"preserve"
    );
    let file = File::options()
        .write(true)
        .open(directory.0.join("state.json"))
        .unwrap();
    file.set_len(MAX_STATE_BYTES as u64 + 1).unwrap();
    assert!(store.load(StateFile::Committed).is_err());
    file.set_len(MAX_STATE_BYTES as u64).unwrap();
    let exact = store.load(StateFile::Committed).unwrap().unwrap();
    assert_eq!(exact.len(), MAX_STATE_BYTES);
    assert_eq!(exact.last(), Some(&0));
    store.replace(StateFile::Committed, &exact).unwrap();
    assert_eq!(store.load(StateFile::Committed).unwrap().unwrap(), exact);
}

#[test]
#[ignore = "Проверяется в отдельной root VM"]
fn root_rejects_foreign_ownership() {
    use std::os::unix::ffi::OsStrExt;
    assert_eq!(unsafe { libc::geteuid() }, 0);
    for name in ["", ".lock", "state.json", ".new-state.json"] {
        let directory = Directory::new();
        let path = if name.is_empty() {
            directory.0.clone()
        } else {
            directory.private_file(name, b"foreign")
        };
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(c_path.as_ptr(), 1001, 1001) }, 0);
        if name == "state.json" {
            let mut store = StateDirectory::open(directory.path()).unwrap();
            assert!(store.load(StateFile::Committed).is_err());
            assert!(store.replace(StateFile::Committed, b"replacement").is_err());
            assert_eq!(fs::read(&path).unwrap(), b"foreign");
        } else {
            assert!(StateDirectory::open(directory.path()).is_err(), "{name}");
        }
    }
}

#[test]
fn readers_only_observe_complete_atomic_snapshots() {
    let directory = Directory::new();
    let mut store = StateDirectory::open(directory.path()).unwrap();
    let first = vec![b'a'; 8192];
    let second = vec![b'b'; 16384];
    store.replace(StateFile::Committed, &first).unwrap();
    std::thread::scope(|scope| {
        let reader = scope.spawn(|| {
            for _ in 0..200 {
                let state = fs::read(directory.0.join("state.json")).unwrap();
                assert!(state == first || state == second);
            }
        });
        for _ in 0..30 {
            store.replace(StateFile::Committed, &second).unwrap();
            store.replace(StateFile::Committed, &first).unwrap();
        }
        reader.join().unwrap();
    });
}

#[cfg(target_env = "gnu")]
#[test]
fn native_file_faults_preserve_the_last_committed_snapshot() {
    let directory = Directory::new();
    fs::write(
        directory.0.join("faults.c"),
        include_str!("support/state_faults.c"),
    )
    .unwrap();
    let library = directory.0.join("faults.so");
    let output = std::process::Command::new("cc")
        .args(["-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(directory.0.join("faults.c"))
        .args(["-ldl", "-o"])
        .arg(&library)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for mode in [
        "open",
        "chmod",
        "lock",
        "sync-open",
        "unlink",
        "temporary-open",
        "write-error",
        "write-zero",
        "write-short",
        "sync-file",
        "rename",
        "sync-directory",
        "read-error",
        "read-short",
        "read-grow",
        "foreign-process",
        "descriptor-zero",
        "read-early-eof",
        "read-rewrite",
        "chmod-temporary",
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "state_fault_child",
                "--test-threads=1",
                "--nocapture",
            ])
            .env("LD_PRELOAD", &library)
            .env("AIVPN_STATE_FAULT", mode)
            .env("AIVPN_STATE_FIXTURE_ROOT", &directory.0)
            .output()
            .unwrap();
        assert!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "{mode}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(target_env = "gnu")]
#[test]
#[ignore]
fn state_fault_child() {
    let descriptors = || fs::read_dir("/proc/self/fd").unwrap().count();
    let before = descriptors();
    let mode = std::env::var("AIVPN_STATE_FAULT").unwrap();
    let directory = Directory::new();
    if matches!(
        mode.as_str(),
        "open" | "chmod" | "lock" | "sync-open" | "unlink"
    ) {
        if mode == "unlink" {
            directory.private_file(".new-state.json", b"incomplete");
        }
        std::env::set_var("AIVPN_STATE_ARMED", "1");
        assert!(StateDirectory::open(directory.path()).is_err());
        if mode == "chmod" {
            assert!(!directory.0.join(".lock").exists());
        }
        std::env::remove_var("AIVPN_STATE_ARMED");
        assert!(StateDirectory::open(directory.path()).is_ok());
        assert_eq!(descriptors(), before, "{mode}");
        return;
    }
    let mut store = StateDirectory::open(directory.path()).unwrap();
    store.replace(StateFile::Committed, b"preserve").unwrap();
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let saved_stdin = (mode == "descriptor-zero").then(|| {
        let fd = unsafe { libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 3) };
        assert!(fd >= 0);
        unsafe { OwnedFd::from_raw_fd(fd) }
    });
    std::env::set_var("AIVPN_STATE_ARMED", "1");
    if mode == "foreign-process" {
        assert!(store.load(StateFile::Committed).is_err());
        assert!(store
            .replace(StateFile::Committed, b"wrong-process")
            .is_err());
        assert!(store.clear_pending().is_err());
        drop(store);
        std::env::remove_var("AIVPN_STATE_ARMED");
        let store = StateDirectory::open(directory.path()).unwrap();
        assert_eq!(
            store.load(StateFile::Committed).unwrap().unwrap(),
            b"preserve"
        );
        drop(store);
        assert_eq!(descriptors(), before, "{mode}");
        return;
    }
    if mode.starts_with("read-") {
        let result = store.load(StateFile::Committed);
        if mode == "read-short" {
            assert_eq!(result.unwrap().unwrap(), b"preserve");
        } else {
            assert!(result.is_err());
        }
    } else {
        let result = store.replace(StateFile::Committed, b"replacement");
        std::env::remove_var("AIVPN_STATE_ARMED");
        let committed = store.load(StateFile::Committed).unwrap().unwrap();
        if matches!(mode.as_str(), "write-short" | "descriptor-zero") {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
        assert_eq!(
            committed,
            if matches!(
                mode.as_str(),
                "write-short" | "sync-directory" | "descriptor-zero"
            ) {
                b"replacement".as_slice()
            } else {
                b"preserve".as_slice()
            }
        );
        assert!(!directory.0.join(".new-state.json").exists());
        store.replace(StateFile::Committed, b"retry").unwrap();
        assert_eq!(store.load(StateFile::Committed).unwrap().unwrap(), b"retry");
    }
    std::env::remove_var("AIVPN_STATE_ARMED");
    drop(store);
    if let Some(input) = saved_stdin {
        assert_eq!(unsafe { libc::dup2(input.as_raw_fd(), 0) }, 0);
    }
    assert_eq!(descriptors(), before, "{mode}");
}
