#![cfg(target_os = "linux")]

use aivpn_desktop_agent::linux::ExecutableFile;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "aivpn-executable-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn write(&self, bytes: &[u8]) -> PathBuf {
        let path = self.0.join("program");
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn image() -> Vec<u8> {
    b"#!/bin/sh\nexit 0\n".to_vec()
}

#[test]
fn files_keep_their_identity_and_canonical_path() {
    let fixture = Fixture::new();
    let path = fixture.write(&image());
    let executable = ExecutableFile::open(&path).unwrap();
    executable.verify().unwrap();
    assert_eq!(executable.canonical_path(), path.canonicalize().unwrap());
    let executable = ExecutableFile::open(&std::env::current_exe().unwrap()).unwrap();
    executable.verify().unwrap();
}

#[test]
fn replacement_or_in_place_change_invalidates_the_prepared_file() {
    for replace in [false, true] {
        let fixture = Fixture::new();
        let path = fixture.write(&image());
        let executable = ExecutableFile::open(&path).unwrap();
        if replace {
            fs::rename(&path, fixture.0.join("old-program")).unwrap();
        }
        let mut modified = image();
        modified.push(0);
        fixture.write(&modified);
        assert!(executable.verify().is_err());
    }
}

#[test]
fn renaming_a_parent_cannot_leave_a_verified_path_pointing_at_another_inode() {
    let fixture = Fixture::new();
    let first = fixture.0.join("first");
    let moved = fixture.0.join("moved");
    fs::create_dir(&first).unwrap();
    let program = first.join("program");
    fs::write(&program, image()).unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
    let alias = fixture.0.join("alias");
    std::os::unix::fs::symlink(&first, &alias).unwrap();
    let source = alias.join("program");
    let executable = ExecutableFile::open(&source).unwrap();
    fs::rename(&first, &moved).unwrap();
    fs::create_dir(&first).unwrap();
    fs::write(&program, image()).unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink(&moved, &alias).unwrap();
    assert_ne!(executable.canonical_path(), source.canonicalize().unwrap());
    assert!(
        executable.verify().is_err(),
        "Исходный alias и FD еще совпадают, но сохраненный canonical указывает на другой файл"
    );
}

#[test]
fn symbolic_nonexecutable_special_and_relative_paths_are_refused() {
    let fixture = Fixture::new();
    let path = fixture.write(&image());
    let alias = fixture.0.join("alias");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert!(ExecutableFile::open(&alias).is_err());
    assert!(ExecutableFile::open(&fixture.0).is_err());
    assert!(ExecutableFile::open(std::path::Path::new("program")).is_err());
    assert!(ExecutableFile::open(std::path::Path::new("/dev/null")).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(ExecutableFile::open(&path).is_err());
}

#[test]
fn selected_symbolic_path_is_prepared_without_executing_the_target() {
    let fixture = Fixture::new();
    let target = fixture.write(&image());
    let alias = fixture.0.join("selected");
    std::os::unix::fs::symlink("program", &alias).unwrap();
    let selected = ExecutableFile::resolve_selected(&alias).unwrap();
    assert_eq!(selected.canonical_path(), target.canonicalize().unwrap());
    selected.verify().unwrap();
}

fn selected(path: &std::path::Path) -> ExecutableFile {
    ExecutableFile::resolve_selected(path).unwrap()
}

#[test]
fn selected_paths_follow_absolute_relative_parent_and_nested_links() {
    let fixture = Fixture::new();
    let target = fixture.write(&image());
    let absolute = fixture.0.join("absolute");
    let chain = fixture.0.join("chain");
    let parent = fixture.0.join("parent");
    std::os::unix::fs::symlink(&target, &absolute).unwrap();
    std::os::unix::fs::symlink("absolute", &chain).unwrap();
    std::os::unix::fs::symlink(&fixture.0, &parent).unwrap();
    for path in [&absolute, &chain, &parent.join("chain")] {
        let proof = selected(path);
        assert_eq!(proof.canonical_path(), target.canonicalize().unwrap());
        proof.verify().unwrap();
    }
}

#[test]
fn dotdot_is_resolved_after_symlinks_by_the_kernel() {
    let fixture = Fixture::new();
    let target = fixture.write(&image());
    fs::create_dir_all(fixture.0.join("deep/inside")).unwrap();
    std::os::unix::fs::symlink("deep/inside", fixture.0.join("parent")).unwrap();
    let source = fixture.0.join("parent/../../program");
    assert_eq!(selected(&source).canonical_path(), target);
    assert!(ExecutableFile::resolve_selected(&fixture.0.join("program/../program")).is_err());
    assert!(ExecutableFile::resolve_selected(&fixture.0.join("program/.")).is_err());
    assert!(ExecutableFile::resolve_selected(&fixture.0.join("program/")).is_err());
    std::os::unix::fs::symlink("parent/../../program", fixture.0.join("selected")).unwrap();
    selected(&fixture.0.join("selected")).verify().unwrap();
}

#[test]
fn unresolved_nonexecutable_and_special_selected_targets_are_refused() {
    let fixture = Fixture::new();
    let target = fixture.write(&image());
    for (name, link) in [
        ("broken", "missing"),
        ("loop", "loop"),
        ("special", "/dev/null"),
        ("directory", "."),
    ] {
        let source = fixture.0.join(name);
        std::os::unix::fs::symlink(link, &source).unwrap();
        assert!(ExecutableFile::resolve_selected(&source).is_err(), "{name}");
    }
    assert!(ExecutableFile::resolve_selected(std::path::Path::new("program")).is_err());
    std::os::unix::fs::symlink("program", fixture.0.join("selected")).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(ExecutableFile::resolve_selected(&fixture.0.join("selected")).is_err());
}

#[test]
fn magic_links_are_refused_in_final_intermediate_and_nested_components() {
    use std::os::fd::AsRawFd;
    let fixture = Fixture::new();
    let target = fixture.write(&image());
    let file = fs::File::open(&target).unwrap();
    let directory = fs::File::open(&fixture.0).unwrap();
    let paths = [
        PathBuf::from("/proc/self/exe"),
        PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())),
        PathBuf::from(format!("/proc/self/fd/{}/program", directory.as_raw_fd())),
        PathBuf::from(format!(
            "/proc/self/fd/{}/../{}/program",
            directory.as_raw_fd(),
            fixture.0.file_name().unwrap().to_str().unwrap()
        )),
    ];
    for (index, path) in paths.into_iter().enumerate() {
        assert!(ExecutableFile::resolve_selected(&path).is_err(), "{path:?}");
        let alias = fixture.0.join(format!("alias-{index}"));
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(ExecutableFile::resolve_selected(&alias).is_err());
    }
}

#[test]
fn replacing_a_link_even_with_the_same_target_invalidates_its_live_proof() {
    for same_target in [true, false] {
        let fixture = Fixture::new();
        fixture.write(&image());
        fs::copy(fixture.0.join("program"), fixture.0.join("other")).unwrap();
        let alias = fixture.0.join("selected");
        std::os::unix::fs::symlink("program", &alias).unwrap();
        let proof = selected(&alias);
        std::os::unix::fs::symlink(
            if same_target { "program" } else { "other" },
            fixture.0.join("new-link"),
        )
        .unwrap();
        fs::rename(fixture.0.join("new-link"), &alias).unwrap();
        assert!(proof.verify().is_err(), "same_target={same_target}");
        selected(&alias).verify().unwrap();
    }
}

#[test]
fn every_intermediate_link_is_retained_even_if_the_target_does_not_change() {
    for parent in [true, false] {
        let fixture = Fixture::new();
        fixture.write(&image());
        let middle = fixture.0.join("middle");
        let source = fixture.0.join("selected");
        let link_target = if parent { "." } else { "program" };
        std::os::unix::fs::symlink(link_target, &middle).unwrap();
        std::os::unix::fs::symlink(if parent { "middle/program" } else { "middle" }, &source)
            .unwrap();
        let proof = selected(&source);
        fs::remove_file(&middle).unwrap();
        std::os::unix::fs::symlink(link_target, &middle).unwrap();
        assert!(proof.verify().is_err());
    }
}

#[test]
fn selected_target_inode_and_bytes_are_reverified() {
    for replace in [true, false] {
        let fixture = Fixture::new();
        let target = fixture.write(&image());
        let alias = fixture.0.join("selected");
        std::os::unix::fs::symlink("program", &alias).unwrap();
        let proof = selected(&alias);
        if replace {
            fs::copy(&target, fixture.0.join("replacement")).unwrap();
            fs::rename(fixture.0.join("replacement"), &target).unwrap();
        } else {
            fs::write(&target, b"#!/bin/sh\nexit 1\n").unwrap();
        }
        assert!(proof.verify().is_err());
    }
}

#[test]
fn renamed_parent_is_refused_but_sibling_changes_are_allowed() {
    let fixture = Fixture::new();
    let parent = fixture.0.join("parent");
    fs::create_dir(&parent).unwrap();
    let target = fixture.write(&image());
    std::os::unix::fs::symlink(&target, parent.join("selected")).unwrap();
    let proof = selected(&parent.join("selected"));
    fs::write(parent.join("sibling"), b"changed").unwrap();
    proof.verify().unwrap();
    fs::rename(&parent, fixture.0.join("moved")).unwrap();
    fs::create_dir(&parent).unwrap();
    std::os::unix::fs::symlink(&target, parent.join("selected")).unwrap();
    assert!(proof.verify().is_err());
}

#[test]
fn link_traversals_and_component_work_have_finite_limits() {
    let fixture = Fixture::new();
    fixture.write(&image());
    let mut target = "program".to_string();
    for index in 1..=41 {
        let name = format!("link-{index}");
        std::os::unix::fs::symlink(target, fixture.0.join(&name)).unwrap();
        target = name;
    }
    selected(&fixture.0.join("link-40")).verify().unwrap();
    assert_eq!(
        ExecutableFile::resolve_selected(&fixture.0.join("link-41"))
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::ELOOP)
    );
    let base_steps = fixture.0.components().count() + 1;
    let boundary = format!(
        "{}/{}program",
        fixture.0.display(),
        "./".repeat(256 - base_steps)
    );
    selected(std::path::Path::new(&boundary)).verify().unwrap();
    let source = format!(
        "{}/{}program",
        fixture.0.display(),
        "./".repeat(257 - base_steps)
    );
    assert_eq!(
        ExecutableFile::resolve_selected(std::path::Path::new(&source))
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::ENAMETOOLONG)
    );
}

#[test]
fn repeated_success_and_failure_release_all_chain_descriptors() {
    if std::env::var_os("AIVPN_SELECTED_FD_CHILD").is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "repeated_success_and_failure_release_all_chain_descriptors",
                "--nocapture",
            ])
            .env("AIVPN_SELECTED_FD_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    let fixture = Fixture::new();
    fixture.write(&image());
    let mut target = "program".to_string();
    for index in 1..=40 {
        let name = format!("link-{index}");
        std::os::unix::fs::symlink(target, fixture.0.join(&name)).unwrap();
        target = name;
    }
    let count = || fs::read_dir("/proc/self/fd").unwrap().count();
    let baseline = count();
    for _ in 0..64 {
        let proof = selected(&fixture.0.join("link-40"));
        assert!(count() > baseline + 40);
        assert!(count() <= baseline + 256 + 1);
        proof.verify().unwrap();
        drop(proof);
        assert!(ExecutableFile::resolve_selected(&fixture.0.join("missing")).is_err());
        assert!(ExecutableFile::resolve_selected(std::path::Path::new("/proc/self/exe")).is_err());
        assert_eq!(count(), baseline);
    }
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    let restricted = libc::rlimit {
        rlim_cur: 64,
        rlim_max: limit.rlim_max,
    };
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &restricted) },
        0
    );
    for _ in 0..16 {
        assert_eq!(
            ExecutableFile::resolve_selected(&fixture.0.join("link-40"))
                .err()
                .unwrap()
                .raw_os_error(),
            Some(libc::EMFILE)
        );
        assert_eq!(count(), baseline);
    }
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
}

#[test]
fn unsupported_openat2_has_no_unsafe_fallback() {
    if std::env::var_os("AIVPN_SELECTED_SYSCALL_CHILD").is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "unsupported_openat2_has_no_unsafe_fallback",
                "--nocapture",
            ])
            .env("AIVPN_SELECTED_SYSCALL_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    let fixture = Fixture::new();
    let target = fixture.write(&image());
    let mut filter = [
        libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: libc::SYS_openat2 as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) },
        0
    );
    assert_eq!(
        ExecutableFile::resolve_selected(&target)
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::ENOSYS)
    );
    ExecutableFile::open(&target).unwrap().verify().unwrap();
}

#[test]
fn directory_binding_change_is_refused_even_when_target_and_path_stay_equal() {
    let fixture = Fixture::new();
    let target = fixture.write(&image());
    let first = fixture.0.join("first");
    let second = fixture.0.join("second");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();
    for directory in [&first, &second] {
        fs::hard_link(&target, directory.join("program")).unwrap();
    }
    let proof = selected(&first.join("program"));
    fs::rename(&first, fixture.0.join("moved")).unwrap();
    fs::rename(&second, &first).unwrap();
    assert_eq!(proof.canonical_path(), first.join("program"));
    assert!(proof.verify().is_err());
}

#[test]
fn content_verification_covers_direct_and_selected_files_without_moving_cursor() {
    use std::os::fd::{AsFd, AsRawFd};
    for resolve in [false, true] {
        let fixture = Fixture::new();
        let target = fixture.write(&image());
        let source = if resolve {
            let alias = fixture.0.join("selected");
            std::os::unix::fs::symlink("program", &alias).unwrap();
            alias
        } else {
            target.clone()
        };
        let proof = if resolve {
            selected(&source)
        } else {
            ExecutableFile::open(&source).unwrap()
        };
        assert_eq!(
            unsafe { libc::lseek(proof.as_fd().as_raw_fd(), 7, libc::SEEK_SET) },
            7
        );
        proof.verify().unwrap();
        assert_eq!(
            unsafe { libc::lseek(proof.as_fd().as_raw_fd(), 0, libc::SEEK_CUR) },
            7
        );
        fs::write(target, b"#!/bin/sh\nexit 1\n").unwrap();
        assert!(proof.verify().is_err());
    }
}

#[test]
fn oversized_content_is_rejected_before_reading_any_prefix() {
    let fixture = Fixture::new();
    let target = fixture.write(&image());
    fs::File::options()
        .write(true)
        .open(&target)
        .unwrap()
        .set_len(1024 * 1024 * 1024 + 1)
        .unwrap();
    let source = fixture.0.join("selected");
    std::os::unix::fs::symlink("program", &source).unwrap();
    assert_eq!(
        ExecutableFile::open(&target).err().unwrap().kind(),
        std::io::ErrorKind::Unsupported
    );
    assert_eq!(
        ExecutableFile::resolve_selected(&source)
            .err()
            .unwrap()
            .kind(),
        std::io::ErrorKind::Unsupported
    );
}

#[test]
fn changes_beyond_the_first_read_buffer_invalidate_content() {
    use std::os::unix::fs::FileExt;
    let fixture = Fixture::new();
    let target = fixture.write(&vec![1; 2 * 64 * 1024 + 1]);
    let proof = selected(&target);
    let writer = fs::File::options().write(true).open(&target).unwrap();
    writer.write_at(&[2], 2 * 64 * 1024).unwrap();
    assert!(proof.verify().is_err());
}

#[test]
#[ignore = "Нужен собственный стенд с ramfs и дискретными timestamps"]
fn unchanged_metadata_does_not_hide_content_rewrites() {
    use std::os::unix::fs::{FileExt, MetadataExt};
    assert!(fs::read_to_string("/proc/cmdline")
        .unwrap()
        .contains("aivpn.verified-bindings=1"));
    let stamp = |metadata: fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
            metadata.mode(),
        )
    };
    for resolve in [false, true] {
        for offset in [0, 15] {
            let fixture = Fixture::new();
            let target = fixture.write(&[1; 16]);
            let alias = fixture.0.join("selected");
            std::os::unix::fs::symlink("program", &alias).unwrap();
            let writer = fs::File::options().write(true).open(&target).unwrap();
            let mut reproduced = false;
            for _ in 0..256 {
                writer.write_at(&[1], offset).unwrap();
                let proof = if resolve {
                    selected(&alias)
                } else {
                    ExecutableFile::open(&target).unwrap()
                };
                let before = stamp(writer.metadata().unwrap());
                writer.write_at(&[2], offset).unwrap();
                let after = stamp(writer.metadata().unwrap());
                if before == after {
                    assert!(
                        proof.verify().is_err(),
                        "resolve={resolve}, offset={offset}, stamp={before:?}"
                    );
                    println!("SAME_STAMP_REWRITE_REFUSED resolve={resolve} offset={offset}");
                    reproduced = true;
                    break;
                }
            }
            assert!(
                reproduced,
                "Стенд не воспроизвел неизменный stamp, resolve={resolve}, offset={offset}"
            );
        }
    }
}

#[test]
#[ignore = "Нужен собственный root-стенд с ext4 для границы 1 GiB"]
fn content_limit_accepts_the_entire_one_gib_file() {
    use std::os::fd::{AsFd, AsRawFd};
    assert!(fs::read_to_string("/proc/cmdline")
        .unwrap()
        .contains("aivpn.verified-bindings=1"));
    let directory = PathBuf::from(format!(
        "/usr/bin/aivpn-content-limit-{}",
        std::process::id()
    ));
    fs::create_dir(&directory).unwrap();
    let fixture = Fixture(directory);
    let path = fixture.write(&image());
    fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(1024 * 1024 * 1024)
        .unwrap();
    let read_bytes = || {
        fs::read_to_string("/proc/self/io")
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("rchar: "))
            .unwrap()
            .parse::<u64>()
            .unwrap()
    };
    let bytes_before = read_bytes();
    let start = std::time::Instant::now();
    let proof = selected(&path);
    proof.verify().unwrap();
    assert_eq!(
        unsafe { libc::lseek(proof.as_fd().as_raw_fd(), 0, libc::SEEK_CUR) },
        0
    );
    let bytes_read = read_bytes() - bytes_before;
    assert!((3 * 1024 * 1024 * 1024..3 * 1024 * 1024 * 1024 + 1024 * 1024).contains(&bytes_read));
    println!("CONTENT_LIMIT_FULL_READ bytes_per_pass=1073741824 passes=3 buffer_bytes=65536 observed_rchar={bytes_read} elapsed_ms={}", start.elapsed().as_millis());
}
