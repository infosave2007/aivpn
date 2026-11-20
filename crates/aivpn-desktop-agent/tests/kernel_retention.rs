#![cfg(all(target_os = "linux", feature = "linux-kernel"))]

use aivpn_desktop_agent::linux::kernel::{KernelWriter, PinnedRetention};
use std::path::Path;
use std::process::{Command, Stdio};
#[path = "support/retention_lab.rs"]
mod lab;
use lab::*;

fn retain(writer: &mut KernelWriter, path: &Path) -> PinnedRetention {
    let (catalog, registry, authority) = inputs(path, NS);
    let plan = writer.prepare(&registry, &catalog, &authority).unwrap();
    let prepared = writer
        .prepare_executable(&plan, path.to_str().unwrap(), locate(path))
        .unwrap();
    // Стенд не отображает целевой файл в своем mm; запуск идет через новый exec.
    unsafe { writer.retain_executable(&plan, &prepared) }.unwrap()
}

#[test]
#[ignore = "Нужен изолированный root-стенд с bpffs и BPF LSM"]
fn pinned_retention_survives_sigkill_replacement_and_inode_eviction() {
    setup();
    let _cleanup = Cleanup;
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "retention_child", "--nocapture"])
        .env("RETENTION_CHILD", "create")
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    wait_ready(&mut child);
    let original = cookie(TARGET).unwrap();
    let control = cookie(CONTROL).unwrap();
    assert_ne!(original, control);
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
    evict();
    assert_eq!(cookie(ALIAS), Some(original));
    assert_eq!(cookie(CONTROL), None);
    let counter_before = file_counter();
    let mut writer = writer(false);
    let records = writer.recover_retentions().unwrap();
    assert_eq!(file_counter(), counter_before);
    assert_eq!(records.len(), 1);
    let link = records[0].link_id();
    drop(records);
    assert_eq!(writer.recover_retentions().unwrap()[0].link_id(), link);
    std::fs::copy(CONTROL, format!("{TARGET}.new")).unwrap();
    std::fs::rename(format!("{TARGET}.new"), TARGET).unwrap();
    execute(TARGET);
    assert_ne!(cookie(TARGET), Some(original));
    assert_eq!(cookie(ALIAS), Some(original));
    execute(ALIAS);
    assert_eq!(cookie(ALIAS), Some(original));
    let record = writer.recover_retentions().unwrap().pop().unwrap();
    writer.release_retention(record).unwrap();
    evict();
    assert_eq!(cookie(ALIAS), None);
    assert!(writer.recover_retentions().unwrap().is_empty());
}

fn wait_ready(child: &mut std::process::Child) {
    for _ in 0..200 {
        if Path::new(&format!("{ROOT}/ready")).exists() {
            return;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "helper exited before ready"
        );
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    child.kill().unwrap();
    panic!("helper timeout");
}

#[test]
#[ignore = "Вспомогательный процесс изолированного стенда"]
fn retention_child() {
    require_lab();
    match std::env::var("RETENTION_CHILD").unwrap().as_str() {
        "create" => {
            let mut writer = writer(true);
            execute(TARGET);
            execute(CONTROL);
            drop(retain(&mut writer, Path::new(TARGET)));
            std::fs::write(format!("{ROOT}/ready"), b"ready").unwrap();
            loop {
                std::thread::park();
            }
        }
        "attempt" => {
            let mut writer = writer(false);
            let (catalog, registry, authority) = inputs(Path::new(TARGET), NS);
            let plan = writer.prepare(&registry, &catalog, &authority).unwrap();
            let prepared = writer
                .prepare_executable(&plan, TARGET, locate(Path::new(TARGET)))
                .unwrap();
            assert!(unsafe { writer.retain_executable(&plan, &prepared) }.is_err());
            assert!(writer.recover_retentions().unwrap().is_empty());
        }
        "cut" => {
            let mut writer = writer(false);
            drop(retain(&mut writer, Path::new(TARGET)));
            panic!("cut did not occur");
        }
        "release" => {
            let mut writer = writer(false);
            let record = writer.recover_retentions().unwrap().pop().unwrap();
            writer.release_retention(record).unwrap();
            panic!("cut did not occur");
        }
        _ => panic!("unknown helper mode"),
    }
}

#[test]
#[ignore = "Нужен изолированный root-стенд с bpffs и BPF LSM"]
fn repeated_retain_recover_release_has_fd_and_pin_plateau() {
    setup();
    let _cleanup = Cleanup;
    let mut writer = writer(true);
    let before = fd_count();
    for _ in 0..24 {
        let retained = retain(&mut writer, Path::new(TARGET));
        let id = retained.link_id();
        drop(retained);
        let recovered = writer.recover_retentions().unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].link_id(), id);
        writer
            .release_retention(recovered.into_iter().next().unwrap())
            .unwrap();
        assert_eq!(std::fs::read_dir(dynamic_pins()).unwrap().count(), 0);
        assert_eq!(fd_count(), before);
    }
}

#[test]
#[ignore = "Нужен изолированный root-стенд с bpffs и BPF LSM"]
fn own_executable_shared_library_and_fork_are_refused_without_pins() {
    setup();
    let _cleanup = Cleanup;
    let mut writer = writer(true);
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let library = maps
        .lines()
        .filter_map(|line| line.split_ascii_whitespace().nth(5))
        .find(|path| path.contains("libc.so"))
        .unwrap();
    for path in [std::env::current_exe().unwrap(), library.into()] {
        let (catalog, registry, authority) = inputs(&path, NS);
        let plan = writer.prepare(&registry, &catalog, &authority).unwrap();
        let prepared = writer
            .prepare_executable(&plan, path.to_str().unwrap(), locate(&path))
            .unwrap();
        assert!(unsafe { writer.retain_executable(&plan, &prepared) }.is_err());
        assert!(writer.recover_retentions().unwrap().is_empty());
    }
    let (catalog, registry, authority) = inputs(Path::new(TARGET), NS);
    let plan = writer.prepare(&registry, &catalog, &authority).unwrap();
    let prepared = writer
        .prepare_executable(&plan, TARGET, locate(Path::new(TARGET)))
        .unwrap();
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        let refused = unsafe { writer.retain_executable(&plan, &prepared) }
            .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
            && writer
                .recover_retentions()
                .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied);
        unsafe { libc::_exit(if refused { 0 } else { 1 }) };
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert_eq!(status, 0);
    assert!(writer.recover_retentions().unwrap().is_empty());
}

#[test]
#[ignore = "Нужен изолированный root-стенд с bpffs и BPF LSM"]
fn damaged_metadata_wrong_namespace_and_unfrozen_records_are_preserved() {
    setup();
    let _cleanup = Cleanup;
    let mut writer = writer(true);
    let retained = retain(&mut writer, Path::new(TARGET));
    let directory = dynamic_pins().join(format!("link_{:08x}", retained.link_id()));
    drop(retained);
    let path = directory.join("record");
    let original = bytes(&open(&path));
    for offset in [0, 4, 20, 52, 56, 60, 64, 68, 104] {
        let mut damaged = original;
        damaged[offset] ^= 0x80;
        replace_record(&path, &damaged, true);
        assert!(writer.recover_retentions().is_err(), "offset {offset}");
        assert_eq!(bytes(&open(&path)), damaged);
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 3);
    }
    for offset in [4, 20, 52, 56, 60, 64] {
        let mut damaged = original;
        damaged[offset] ^= 0x80;
        resign(&mut damaged);
        replace_record(&path, &damaged, true);
        assert!(
            writer.recover_retentions().is_err(),
            "semantic field {offset}"
        );
    }
    let mut pid_zero = original;
    pid_zero[64..68].fill(0);
    replace_record(&path, &pid_zero, true);
    assert!(writer.recover_retentions().is_err());
    replace_record(&path, &original, false);
    assert!(writer.recover_retentions().is_err());
    replace_record(&path, &original, true);
    let retained = writer.recover_retentions().unwrap().pop().unwrap();
    writer.release_retention(retained).unwrap();
}

#[test]
#[ignore = "Нужен изолированный root-стенд с bpffs и BPF LSM"]
fn attach_rejects_pid_zero_foreign_pid_offset_count_and_flags() {
    setup();
    let _cleanup = Cleanup;
    drop(writer(true));
    for fault in ["pid0", "pid_other", "offset", "count", "flags", "pin-error"] {
        let output = helper("attempt")
            .env("RETENTION_FAULT", fault)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{fault}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(writer(false).recover_retentions().unwrap().is_empty());
    }
    std::fs::copy(CONTROL, format!("{TARGET}.new")).unwrap();
    let status = helper("attempt")
        .env("RETENTION_FAULT", "replace")
        .env("RETENTION_TARGET", TARGET)
        .env("RETENTION_REPLACEMENT", format!("{TARGET}.new"))
        .status()
        .unwrap();
    assert!(status.success());
    assert!(writer(false).recover_retentions().unwrap().is_empty());
}

fn helper(mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--ignored", "--exact", "retention_child", "--nocapture"])
        .env("RETENTION_CHILD", mode)
        .env("LD_PRELOAD", "/lab/kernel-retention-faults.so");
    command
}

#[test]
#[ignore = "Нужен изолированный root-стенд с bpffs и BPF LSM"]
fn crash_windows_preserve_incomplete_records_and_adopt_completed_rename() {
    setup();
    let _cleanup = Cleanup;
    drop(writer(true));
    let status = helper("cut")
        .env("RETENTION_FAULT", "reserve")
        .status()
        .unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert!(writer(false).recover_retentions().is_err());
    let pending = std::fs::read_dir(dynamic_pins())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(std::fs::read_dir(pending).unwrap().count(), 0);
    std::fs::remove_dir_all(dynamic_pins()).unwrap();
    for pin in ["/instance", "/record", "/link"] {
        let status = helper("cut")
            .env("RETENTION_PIN_CUT", pin)
            .status()
            .unwrap();

        assert_eq!(status.signal(), Some(libc::SIGKILL));
        let writer = writer(false);
        assert!(writer.recover_retentions().is_err());
        let paths = std::fs::read_dir(dynamic_pins())
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(paths.len(), 1);
        assert!(paths[0]
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("pending_"));
        let count = std::fs::read_dir(&paths[0]).unwrap().count();
        assert!((1..=3).contains(&count));
        assert!(writer.recover_retentions().is_err());
        assert_eq!(std::fs::read_dir(&paths[0]).unwrap().count(), count);
        drop(writer);
        std::fs::remove_dir_all(dynamic_pins()).unwrap();
    }
    let status = helper("cut")
        .env("RETENTION_FAULT", "commit")
        .status()
        .unwrap();

    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert_eq!(writer(false).recover_retentions().unwrap().len(), 1);
    let status = helper("release")
        .env("RETENTION_FAULT", "release")
        .status()
        .unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert!(writer(false).recover_retentions().is_err());
    let path = std::fs::read_dir(dynamic_pins())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("releasing_"));
    assert_eq!(std::fs::read_dir(path).unwrap().count(), 3);
    std::fs::remove_dir_all(dynamic_pins()).unwrap();
    for name in ["link", "record", "instance"] {
        {
            let mut current = writer(false);
            drop(retain(&mut current, Path::new(TARGET)));
        }
        let status = helper("release")
            .env("RETENTION_UNLINK_CUT", name)
            .status()
            .unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert!(writer(false).recover_retentions().is_err());
        let pending = std::fs::read_dir(dynamic_pins())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let count = std::fs::read_dir(&pending).unwrap().count();
        assert_eq!(
            count,
            match name {
                "link" => 2,
                "record" => 1,
                _ => 0,
            }
        );
        assert!(writer(false).recover_retentions().is_err());
        assert_eq!(std::fs::read_dir(&pending).unwrap().count(), count);
        std::fs::remove_dir_all(dynamic_pins()).unwrap();
    }
}

#[test]
#[ignore = "Нужен изолированный root-стенд с bpffs и BPF LSM"]
fn new_kernel_instance_cannot_adopt_or_release_old_retention() {
    setup();
    let _cleanup = Cleanup;
    let mut old = writer(true);
    let retained = retain(&mut old, Path::new(TARGET));
    drop(old);
    std::fs::remove_dir_all(static_pins()).unwrap();
    std::fs::remove_dir_all(format!("{ROOT}/state")).unwrap();
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(format!("{ROOT}/state"))
        .unwrap();
    let mut fresh = writer(true);
    assert!(fresh.recover_retentions().is_err());
    assert!(fresh.release_retention(retained).is_err());
    assert_eq!(std::fs::read_dir(dynamic_pins()).unwrap().count(), 1);
}

#[test]
#[ignore = "Нужен изолированный root-стенд с bpffs и BPF LSM"]
fn link_substitution_permissions_symlinks_and_bounded_inventory_are_refused() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    setup();
    let _cleanup = Cleanup;
    let mut writer = writer(true);
    let retained = retain(&mut writer, Path::new(TARGET));
    let other = retain(&mut writer, Path::new(CONTROL));
    let directory = dynamic_pins().join(format!("link_{:08x}", retained.link_id()));
    let link = directory.join("link");
    let held = open(&link);
    let foreign = open(&dynamic_pins().join(format!("link_{:08x}/link", other.link_id())));
    std::fs::remove_file(&link).unwrap();
    pin(&foreign, &link);
    assert!(writer.recover_retentions().is_err());
    std::fs::remove_file(&link).unwrap();
    pin(&held, &link);
    std::fs::set_permissions(&link, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(writer.recover_retentions().is_err());
    std::fs::set_permissions(&link, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::remove_file(&link).unwrap();
    symlink(directory.join("instance"), &link).unwrap();
    assert!(writer.recover_retentions().is_err());
    std::fs::remove_file(&link).unwrap();
    pin(&held, &link);
    let alias = Path::new("/sys/fs/bpf/retention-test-hardlink").to_path_buf();
    match std::fs::hard_link(&link, &alias) {
        Ok(()) => {
            println!("BPF_PIN_HARDLINK supported");
            assert!(writer.recover_retentions().is_err());
            std::fs::remove_file(alias).unwrap();
        }
        Err(error) => {
            println!("BPF_PIN_HARDLINK unsupported: {error}");
            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
        }
    }
    writer.release_retention(retained).unwrap();
    writer.release_retention(other).unwrap();
    for i in 0..4097 {
        std::fs::create_dir(dynamic_pins().join(format!("foreign_{i}"))).unwrap();
    }
    let error = writer.recover_retentions().err().unwrap();
    assert!(error.to_string().contains("Лимит"));
    assert_eq!(std::fs::read_dir(dynamic_pins()).unwrap().count(), 4097);
}

fn resign(bytes: &mut [u8; 128]) {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(&bytes[..104]);
    bytes[104..].copy_from_slice(&digest[..24]);
}

#[test]
#[ignore = "Нужен изолированный root-стенд с bpffs и BPF LSM"]
fn recovery_checks_native_link_type_program_count_offset_flags_and_filter() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    setup();
    let _cleanup = Cleanup;
    let mut writer = writer(true);
    let retained = retain(&mut writer, Path::new(TARGET));
    let original_name = dynamic_pins().join(format!("link_{:08x}", retained.link_id()));
    let original_link = open(&original_name.join("link"));
    let original_metadata = bytes(&open(&original_name.join("record")));
    let library =
        unsafe { libc::dlopen(c"/lab/kernel-retention-faults.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!library.is_null());
    let forge: unsafe extern "C" fn(i32, i32, i32) -> i32 =
        unsafe { std::mem::transmute(libc::dlsym(library, c"ar_retention_test_forge".as_ptr())) };
    let object_id: unsafe extern "C" fn(i32) -> i32 =
        unsafe { std::mem::transmute(libc::dlsym(library, c"ar_retention_test_id".as_ptr())) };
    let program = open(&static_pins().join("programs/retain_application_inode"));
    let file = std::fs::File::open(TARGET).unwrap();
    for fault in 1..=5 {
        let forged = if fault == 5 {
            open(&static_pins().join("links/root_00"))
        } else {
            let raw = unsafe { forge(program.as_raw_fd(), file.as_raw_fd(), fault) };
            assert!(raw >= 0, "forge {fault}: {raw}");
            unsafe { OwnedFd::from_raw_fd(raw) }
        };
        let id = unsafe { object_id(forged.as_raw_fd()) };
        assert!(id > 0);
        let mut metadata = original_metadata;
        metadata[60..64].copy_from_slice(&(id as u32).to_le_bytes());
        resign(&mut metadata);
        replace_record(&original_name.join("record"), &metadata, true);
        std::fs::remove_file(original_name.join("link")).unwrap();
        pin(&forged, &original_name.join("link"));
        let changed = dynamic_pins().join(format!("link_{id:08x}"));
        std::fs::rename(&original_name, &changed).unwrap();
        assert!(
            writer.recover_retentions().is_err(),
            "forged recovery {fault}"
        );
        std::fs::rename(&changed, &original_name).unwrap();
    }
    std::fs::remove_file(original_name.join("link")).unwrap();
    pin(&original_link, &original_name.join("link"));
    replace_record(&original_name.join("record"), &original_metadata, true);
    drop(retained);
    let current = writer.recover_retentions().unwrap().pop().unwrap();
    writer.release_retention(current).unwrap();
    unsafe {
        libc::dlclose(library);
    }
}

#[test]
#[ignore = "Нужен изолированный root-стенд с Btrfs subvolume и BPF LSM"]
fn btrfs_subvolume_mapped_hardlink_uses_kernel_device_not_fake_stat_device() {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    setup();
    let _cleanup = Cleanup;
    let mut writer = writer(true);
    let path = Path::new("/lab/btrfs/subvolume/application");
    std::fs::copy("/usr/bin/true", path).unwrap();
    let alias = path.with_file_name("alias");
    std::fs::hard_link(path, &alias).unwrap();
    let file = std::fs::File::open(&alias).unwrap();
    let stat = file.metadata().unwrap();
    let fake_device = ((libc::major(stat.dev()) as u64) << 20) | libc::minor(stat.dev()) as u64;
    let located = locate(path);
    let kernel_device = located.filesystem_device();
    assert_ne!(kernel_device, fake_device);
    let mapped = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    assert_ne!(mapped, libc::MAP_FAILED);
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let row = maps
        .lines()
        .find(|line| line.ends_with("/lab/btrfs/subvolume/alias"))
        .unwrap();
    let fields: Vec<_> = row.split_ascii_whitespace().collect();
    let (major, minor) = fields[3].split_once(':').unwrap();
    let map_device =
        (u64::from_str_radix(major, 16).unwrap() << 20) | u64::from_str_radix(minor, 16).unwrap();
    assert_eq!(map_device, kernel_device);
    assert_eq!(fields[4].parse::<u64>().unwrap(), stat.ino());
    println!("BTRFS_IDENTITY kernel_device={kernel_device} stat_device={fake_device} maps_device={map_device} inode={}",stat.ino());
    let (catalog, registry, authority) = inputs(path, NS);
    let plan = writer.prepare(&registry, &catalog, &authority).unwrap();
    let prepared = writer
        .prepare_executable(&plan, path.to_str().unwrap(), located)
        .unwrap();
    assert!(unsafe { writer.retain_executable(&plan, &prepared) }.is_err());
    assert!(writer.recover_retentions().unwrap().is_empty());
    assert_eq!(unsafe { libc::munmap(mapped, 4096) }, 0);
    let retained = unsafe { writer.retain_executable(&plan, &prepared) }.unwrap();
    writer.release_retention(retained).unwrap();
    std::fs::remove_file(alias).unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
#[ignore = "Нужен изолированный root-стенд с bpffs и BPF LSM"]
fn instance_pin_requires_map_operation_even_when_program_id_and_enum_match() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::MetadataExt;
    setup();
    let _cleanup = Cleanup;
    let library =
        unsafe { libc::dlopen(c"/lab/kernel-retention-faults.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!library.is_null());
    let reserve: unsafe extern "C" fn() -> i32 = unsafe {
        std::mem::transmute(libc::dlsym(
            library,
            c"ar_retention_test_reserve_map_ids".as_ptr(),
        ))
    };
    let foreign: unsafe extern "C" fn(i32, *mut u32) -> i32 = unsafe {
        std::mem::transmute(libc::dlsym(
            library,
            c"ar_retention_test_same_id_program".as_ptr(),
        ))
    };
    assert_eq!(unsafe { reserve() }, 0);
    let mut writer = writer(true);
    let retained = retain(&mut writer, Path::new(TARGET));
    let directory = dynamic_pins().join(format!("link_{:08x}", retained.link_id()));
    let instance = directory.join("instance");
    let correct = open(&instance);
    let original_record = bytes(&open(&directory.join("record")));
    let expected_id = u32::from_le_bytes(original_record[52..56].try_into().unwrap());
    let original_counter = file_counter();
    let mut identity = [0; 2];
    let raw = unsafe { foreign(correct.as_raw_fd(), identity.as_mut_ptr()) };
    assert!(raw >= 0, "Не создана программа с совпадающим ID: {raw}");
    let foreign = unsafe { OwnedFd::from_raw_fd(raw) };
    assert_eq!(identity, [2, expected_id]);
    std::fs::remove_file(&instance).unwrap();
    pin(&foreign, &instance);
    let before: Vec<_> = ["instance", "record", "link"]
        .iter()
        .map(|name| {
            let metadata = directory.join(name).symlink_metadata().unwrap();
            assert!(metadata.is_file());
            assert_eq!(
                (
                    metadata.uid(),
                    metadata.gid(),
                    metadata.mode() & 0o7777,
                    metadata.nlink()
                ),
                (0, 0, 0o600, 1)
            );
            (metadata.dev(), metadata.ino())
        })
        .collect();
    let recover_refused = writer.recover_retentions().is_err();
    let release_refused = writer.release_retention(retained).is_err();
    println!("INSTANCE_ID_COLLISION map_id={expected_id} program_id={} program_type={} recover_refused={recover_refused} release_refused={release_refused}", identity[1], identity[0]);
    assert!(
        recover_refused && release_refused,
        "Объект другого класса принят вместо карты instance"
    );
    let after: Vec<_> = ["instance", "record", "link"]
        .iter()
        .map(|name| {
            let metadata = directory.join(name).symlink_metadata().unwrap();
            (metadata.dev(), metadata.ino())
        })
        .collect();
    assert_eq!(before, after);
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 3);
    assert_eq!(bytes(&open(&directory.join("record"))), original_record);
    assert_eq!(file_counter(), original_counter);
    std::fs::remove_file(&instance).unwrap();
    pin(&correct, &instance);
    let adopted = writer.recover_retentions().unwrap();
    assert_eq!(adopted.len(), 1);
    assert_eq!(
        adopted[0].link_id(),
        u32::from_le_bytes(original_record[60..64].try_into().unwrap())
    );
    writer
        .release_retention(adopted.into_iter().next().unwrap())
        .unwrap();
    assert!(writer.recover_retentions().unwrap().is_empty());
    assert_eq!(file_counter(), original_counter);
    unsafe {
        libc::dlclose(library);
    }
}
