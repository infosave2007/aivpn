#![cfg(target_os = "linux")]

use aivpn_desktop_agent::linux::{ExecutableFile, MountSnapshot};

#[test]
fn actual_executable_is_located_in_the_same_mount_namespace() {
    let path = std::env::current_exe().unwrap();
    let snapshot = MountSnapshot::read_current().unwrap();
    let located = snapshot
        .locate(ExecutableFile::resolve_selected(&path).unwrap())
        .unwrap();
    assert_eq!(located.canonical_path(), path.canonicalize().unwrap());
    assert!(located.filesystem_path().starts_with(b"/"));
    assert!(located.filesystem_path().len() < 4096);
    assert!(located.filesystem_device() <= u64::from(u32::MAX));
    located.verify().unwrap();
    drop(snapshot);
    located.verify().unwrap();
}

#[test]
#[ignore = "Требуется отдельный root-стенд с mount namespace"]
fn mount_changes_and_namespace_changes_invalidate_the_snapshot() {
    run_child("mount_namespace_child");
}

#[test]
#[ignore = "Требуется отдельный root-стенд с mount namespace"]
fn changing_root_through_a_bind_of_the_same_inode_invalidates_the_snapshot() {
    run_child("root_bind_child");
}

fn run_child(name: &str) {
    let directory =
        std::env::temp_dir().join(format!("aivpn-filesystem-{}-{name}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", name, "--nocapture"])
        .env("AIVPN_FILESYSTEM_TEST_CHILD", "1")
        .env("AIVPN_FILESYSTEM_TEST_DIRECTORY", &directory)
        .output()
        .unwrap();
    std::fs::remove_dir(directory).unwrap();
    assert!(
        result.status.success(),
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
#[ignore = "Вспомогательный процесс изолированного теста"]
fn mount_namespace_child() {
    if std::env::var_os("AIVPN_FILESYSTEM_TEST_CHILD").is_none() {
        return;
    }
    let path = std::env::current_exe().unwrap();
    let snapshot = MountSnapshot::read_current().unwrap();
    let located = snapshot
        .locate(ExecutableFile::resolve_selected(&path).unwrap())
        .unwrap();
    assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
    assert_eq!(
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        },
        0
    );
    assert!(located.verify().is_err());
    assert!(snapshot
        .locate(ExecutableFile::resolve_selected(&path).unwrap())
        .is_err());
    let snapshot = MountSnapshot::read_current().unwrap();
    let located = snapshot
        .locate(ExecutableFile::resolve_selected(&path).unwrap())
        .unwrap();
    let directory = std::env::temp_dir().join(format!("aivpn-mount-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(directory.as_os_str().as_bytes()).unwrap();
    assert_eq!(
        unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                name.as_ptr(),
                c"tmpfs".as_ptr(),
                0,
                std::ptr::null(),
            )
        },
        0
    );
    assert!(located.verify().is_err());
    assert!(
        located.verify().is_err(),
        "Событие poll не восстанавливает старый снимок"
    );
    assert!(snapshot
        .locate(ExecutableFile::resolve_selected(&path).unwrap())
        .is_err());
    let snapshot = MountSnapshot::read_current().unwrap();
    let located = snapshot
        .locate(ExecutableFile::resolve_selected(&path).unwrap())
        .unwrap();
    located.verify().unwrap();
    assert_eq!(unsafe { libc::umount2(name.as_ptr(), 0) }, 0);
    assert!(located.verify().is_err());
    std::fs::remove_dir(directory).unwrap();
}

#[test]
#[ignore = "Вспомогательный процесс изолированного теста"]
fn root_bind_child() {
    if std::env::var_os("AIVPN_FILESYSTEM_TEST_CHILD").is_none() {
        return;
    }
    assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
    assert_eq!(
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        },
        0
    );
    let directory =
        std::path::PathBuf::from(std::env::var_os("AIVPN_FILESYSTEM_TEST_DIRECTORY").unwrap());
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(directory.as_os_str().as_bytes()).unwrap();
    assert_eq!(
        unsafe {
            libc::mount(
                c"/".as_ptr(),
                name.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REC,
                std::ptr::null(),
            )
        },
        0
    );
    let snapshot = MountSnapshot::read_current().unwrap();
    let located = snapshot
        .locate(ExecutableFile::resolve_selected(&std::env::current_exe().unwrap()).unwrap())
        .unwrap();
    located.verify().unwrap();
    assert_eq!(unsafe { libc::chroot(name.as_ptr()) }, 0);
    std::env::set_current_dir("/").unwrap();
    assert!(
        located.verify().is_err(),
        "Одинаковый inode корня не подтверждает прежний mount root"
    );
    // Mounts исчезнут при выходе процесса. Каталог удаляет внешний тест.
}

#[test]
#[ignore = "Требуется отдельный root-стенд с mount namespace"]
fn selected_symlink_cross_mount_and_bind_mount_are_located() {
    run_child("selected_mount_child");
}

#[test]
#[ignore = "Вспомогательный процесс изолированного теста"]
fn selected_mount_child() {
    if std::env::var_os("AIVPN_FILESYSTEM_TEST_CHILD").is_none() {
        return;
    }
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
    assert_eq!(
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        },
        0
    );
    let directory =
        std::path::PathBuf::from(std::env::var_os("AIVPN_FILESYSTEM_TEST_DIRECTORY").unwrap());
    let mounted = directory.join("mounted");
    let bound = directory.join("bound");
    std::fs::create_dir(&mounted).unwrap();
    std::fs::create_dir(&bound).unwrap();
    let mounted_c = std::ffi::CString::new(mounted.as_os_str().as_bytes()).unwrap();
    let bound_c = std::ffi::CString::new(bound.as_os_str().as_bytes()).unwrap();
    assert_eq!(
        unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                mounted_c.as_ptr(),
                c"tmpfs".as_ptr(),
                0,
                std::ptr::null(),
            )
        },
        0
    );
    let target = mounted.join("program");
    std::fs::write(&target, b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        unsafe {
            libc::mount(
                mounted_c.as_ptr(),
                bound_c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        },
        0
    );
    let snapshot = MountSnapshot::read_current().unwrap();
    for (name, path) in [("cross", target), ("bind", bound.join("program"))] {
        let alias = directory.join(name);
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        let located = snapshot
            .locate(ExecutableFile::resolve_selected(&alias).unwrap())
            .unwrap();
        located.verify().unwrap();
        assert_eq!(located.canonical_path(), path);
        assert_eq!(located.filesystem_path(), b"/program");
        std::fs::remove_file(alias).unwrap();
    }
    assert_eq!(unsafe { libc::umount2(bound_c.as_ptr(), 0) }, 0);
    assert_eq!(unsafe { libc::umount2(mounted_c.as_ptr(), 0) }, 0);
    std::fs::remove_dir(bound).unwrap();
    std::fs::remove_dir(mounted).unwrap();
}
