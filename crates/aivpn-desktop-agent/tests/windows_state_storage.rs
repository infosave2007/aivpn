#![cfg(target_os = "windows")]

#[path = "support/windows_state_fixture.rs"]
mod fixture;
use aivpn_desktop_agent::state::{StateDirectory, StateFile, MAX_STATE_BYTES};
use fixture::{icacls, Fixture};
use std::os::windows::fs::{symlink_dir, symlink_file, OpenOptionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};
use windows_sys::Win32::{
    Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE},
    System::Threading::{GetCurrentProcess, GetProcessHandleCount},
};

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn complete_snapshots_survive_reopen_and_only_one_writer_can_open() {
    let fixture = Fixture::new();
    let path = &fixture.0;
    let mut store = StateDirectory::open(path).unwrap();
    assert!(store.load(StateFile::Committed).unwrap().is_none());
    assert!(StateDirectory::open(path).is_err());
    store.replace(StateFile::Committed, b"old").unwrap();
    store
        .replace(StateFile::Committed, b"complete new")
        .unwrap();
    store.replace(StateFile::Pending, b"intent").unwrap();
    drop(store);
    let mut reopened = StateDirectory::open(path).unwrap();
    assert_eq!(
        reopened.load(StateFile::Committed).unwrap(),
        Some(b"complete new".to_vec())
    );
    assert_eq!(
        reopened.load(StateFile::Pending).unwrap(),
        Some(b"intent".to_vec())
    );
    reopened.clear_pending().unwrap();
    reopened.clear_pending().unwrap();
    assert_eq!(reopened.load(StateFile::Pending).unwrap(), None);
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn nested_stores_reuse_the_verified_volume_and_keep_independent_writer_locks() {
    let fixture = Fixture::new();
    let root = StateDirectory::open(&fixture.0).unwrap();
    let mut child = root.child(c"slots").unwrap();
    child.replace(StateFile::Committed, b"child").unwrap();
    assert!(root.child(c"slots").is_err());
    {
        let mut nested = child.child(c"bindings").unwrap();
        nested.replace(StateFile::Committed, b"nested").unwrap();
        assert_eq!(
            nested.load(StateFile::Committed).unwrap(),
            Some(b"nested".to_vec())
        );
    }
    assert!(root.child(c"..").is_err());
    drop(child);
    assert_eq!(
        root.child(c"slots")
            .unwrap()
            .load(StateFile::Committed)
            .unwrap(),
        Some(b"child".to_vec())
    );
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn separate_process_cannot_take_writer_lock_and_can_reopen_after_exit() {
    let fixture = Fixture::new();
    let store = StateDirectory::open(&fixture.0).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "child_writer", "--nocapture"])
        .env("AIVPN_STORAGE_CHILD_PATH", &fixture.0)
        .env("AIVPN_STORAGE_CHILD_BUSY", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    drop(store);
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "child_writer", "--nocapture"])
        .env("AIVPN_STORAGE_CHILD_PATH", &fixture.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let reopened = StateDirectory::open(&fixture.0).unwrap();
    assert_eq!(
        reopened.load(StateFile::Committed).unwrap(),
        Some(b"child snapshot".to_vec())
    );
}

#[test]
#[ignore = "Дочерний сценарий native Windows suite, окружение задает родитель"]
fn child_writer() {
    let path = std::env::var_os("AIVPN_STORAGE_CHILD_PATH")
        .expect("Дочерний сценарий запускает родитель с путем fixture");
    if std::env::var_os("AIVPN_STORAGE_CHILD_BUSY").is_some() {
        assert!(StateDirectory::open(std::path::Path::new(&path)).is_err());
    } else {
        StateDirectory::open(std::path::Path::new(&path))
            .unwrap()
            .replace(StateFile::Committed, b"child snapshot")
            .unwrap();
    }
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn exact_limit_empty_snapshot_and_oversized_existing_file() {
    let fixture = Fixture::new();
    let mut store = StateDirectory::open(&fixture.0).unwrap();
    let exact = vec![0x5a; MAX_STATE_BYTES];
    store.replace(StateFile::Committed, &exact).unwrap();
    assert_eq!(store.load(StateFile::Committed).unwrap(), Some(exact));
    assert!(store
        .replace(StateFile::Committed, &vec![0; MAX_STATE_BYTES + 1])
        .is_err());
    assert_eq!(
        store.load(StateFile::Committed).unwrap().unwrap().len(),
        MAX_STATE_BYTES
    );
    store.replace(StateFile::Committed, b"").unwrap();
    assert_eq!(store.load(StateFile::Committed).unwrap(), Some(Vec::new()));
    OpenOptions::new()
        .write(true)
        .open(fixture.0.join("state.json"))
        .unwrap()
        .set_len(MAX_STATE_BYTES as u64 + 1)
        .unwrap();
    assert!(store.load(StateFile::Committed).is_err());
    assert_eq!(
        fs::metadata(fixture.0.join("state.json")).unwrap().len(),
        MAX_STATE_BYTES as u64 + 1
    );
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn readers_observe_only_complete_snapshots_and_old_handles_stay_readable() {
    let fixture = Fixture::new();
    let mut store = StateDirectory::open(&fixture.0).unwrap();
    store
        .replace(StateFile::Committed, &vec![0x11; 128 * 1024])
        .unwrap();
    let mut old = File::open(fixture.0.join("state.json")).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(std::sync::Barrier::new(2));
    let reader_stop = stop.clone();
    let reader_ready = ready.clone();
    let path = fixture.0.join("state.json");
    let reader = thread::spawn(move || {
        reader_ready.wait();
        let mut count = 0;
        while !reader_stop.load(Ordering::Acquire) {
            let bytes = fs::read(&path).unwrap();
            assert_eq!(bytes.len(), 128 * 1024);
            assert!([0x11, 0x22].contains(&bytes[0]));
            assert!(bytes.iter().all(|byte| *byte == bytes[0]));
            count += 1;
        }
        count
    });
    ready.wait();
    for i in 0..32 {
        store
            .replace(
                StateFile::Committed,
                &vec![if i % 2 == 0 { 0x22 } else { 0x11 }; 128 * 1024],
            )
            .unwrap();
    }
    stop.store(true, Ordering::Release);
    assert!(reader.join().unwrap() > 0);
    let mut bytes = Vec::new();
    old.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, vec![0x11; 128 * 1024]);
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn clear_pending_removes_name_even_with_open_reader() {
    let fixture = Fixture::new();
    let mut store = StateDirectory::open(&fixture.0).unwrap();
    store.replace(StateFile::Pending, b"intent").unwrap();
    let mut reader = File::open(fixture.0.join("pending.json")).unwrap();
    store.clear_pending().unwrap();
    assert!(!fixture.0.join("pending.json").exists());
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"intent");
    drop(store);
    assert!(StateDirectory::open(&fixture.0)
        .unwrap()
        .load(StateFile::Pending)
        .unwrap()
        .is_none());
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn foreign_acl_directory_is_rejected_without_claiming_it() {
    let fixture = Fixture::new();
    fs::create_dir(&fixture.0).unwrap();
    fs::write(fixture.0.join("keep"), b"foreign").unwrap();
    icacls(&fixture.0, &["/grant", "*S-1-1-0:(OI)(CI)R"]);
    assert!(StateDirectory::open(&fixture.0).is_err());
    assert_eq!(fs::read(fixture.0.join("keep")).unwrap(), b"foreign");
    assert!(!fixture.0.join(".lock").exists());
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn foreign_owner_and_acl_records_are_rejected_and_preserved() {
    for owner in [false, true] {
        let fixture = Fixture::new();
        let mut store = StateDirectory::open(&fixture.0).unwrap();
        store.replace(StateFile::Committed, b"keep").unwrap();
        drop(store);
        let record = fixture.0.join("state.json");
        if owner {
            icacls(&record, &["/setowner", "*S-1-5-32-545"]);
        } else {
            icacls(&record, &["/grant", "*S-1-1-0:R"]);
        }
        assert!(StateDirectory::open(&fixture.0).is_err());
        assert_eq!(fs::read(&record).unwrap(), b"keep");
    }
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn unsafe_hard_links_records_and_temporary_files_are_not_removed() {
    for name in [
        "state.json",
        "pending.json",
        ".new-state.json",
        ".new-pending.json",
        ".lock",
    ] {
        let fixture = Fixture::new();
        let mut store = StateDirectory::open(&fixture.0).unwrap();
        store.replace(StateFile::Committed, b"keep").unwrap();
        drop(store);
        let source = fixture.0.join("source");
        fs::rename(fixture.0.join("state.json"), &source).unwrap();
        if name == ".lock" {
            fs::remove_file(fixture.0.join(".lock")).unwrap();
        }
        fs::hard_link(&source, fixture.0.join(name)).unwrap();
        assert!(StateDirectory::open(&fixture.0).is_err(), "{name}");
        assert_eq!(fs::read(fixture.0.join(name)).unwrap(), b"keep");
        assert_eq!(fs::read(source).unwrap(), b"keep");
    }
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn reparse_directories_ancestors_and_records_are_rejected() {
    let target = Fixture::new();
    let mut store = StateDirectory::open(&target.0).unwrap();
    store.replace(StateFile::Committed, b"keep").unwrap();
    drop(store);
    let link = Fixture::new();
    symlink_dir(&target.0, &link.0).unwrap();
    assert!(StateDirectory::open(&link.0).is_err());
    assert!(StateDirectory::open(&link.0.join("nested")).is_err());
    assert!(!target.0.join("nested").exists());
    fs::remove_dir(&link.0).unwrap();
    let record = target.0.join("pending.json");
    symlink_file(target.0.join("state.json"), &record).unwrap();
    assert!(StateDirectory::open(&target.0).is_err());
    assert!(fs::symlink_metadata(&record)
        .unwrap()
        .file_type()
        .is_symlink());
    fs::remove_file(record).unwrap();
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn owned_orphan_temporary_is_cleaned_but_foreign_temporary_is_preserved() {
    let fixture = Fixture::new();
    let mut store = StateDirectory::open(&fixture.0).unwrap();
    store.replace(StateFile::Committed, b"valid").unwrap();
    store.replace(StateFile::Pending, b"incomplete").unwrap();
    drop(store);
    fs::rename(
        fixture.0.join("pending.json"),
        fixture.0.join(".new-pending.json"),
    )
    .unwrap();
    let reopened = StateDirectory::open(&fixture.0).unwrap();
    assert_eq!(
        reopened.load(StateFile::Committed).unwrap(),
        Some(b"valid".to_vec())
    );
    assert!(!fixture.0.join(".new-pending.json").exists());
    drop(reopened);
    fs::write(fixture.0.join(".new-state.json"), b"foreign temporary").unwrap();
    icacls(
        &fixture.0.join(".new-state.json"),
        &["/grant", "*S-1-1-0:R"],
    );
    assert!(StateDirectory::open(&fixture.0).is_err());
    assert_eq!(
        fs::read(fixture.0.join(".new-state.json")).unwrap(),
        b"foreign temporary"
    );
    assert_eq!(fs::read(fixture.0.join("state.json")).unwrap(), b"valid");
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn ancestors_cannot_be_renamed_while_store_is_open() {
    let parent = Fixture::new();
    fs::create_dir(&parent.0).unwrap();
    let store = StateDirectory::open(&parent.0.join("state")).unwrap();
    let moved = parent.0.with_extension("moved");
    assert!(fs::rename(&parent.0, &moved).is_err());
    drop(store);
    fs::rename(&parent.0, &moved).unwrap();
    fs::rename(moved, &parent.0).unwrap();
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn conflicting_writer_handle_causes_error_without_overwriting_snapshot() {
    let fixture = Fixture::new();
    let mut store = StateDirectory::open(&fixture.0).unwrap();
    store.replace(StateFile::Committed, b"keep").unwrap();
    let mut writer = OpenOptions::new()
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(fixture.0.join("state.json"))
        .unwrap();
    assert!(store.load(StateFile::Committed).is_err());
    assert!(store.replace(StateFile::Committed, b"replacement").is_err());
    writer.write_all(b"keep").unwrap();
    drop(writer);
    assert_eq!(
        store.load(StateFile::Committed).unwrap(),
        Some(b"keep".to_vec())
    );
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn repeated_successful_and_failed_open_do_not_leak_handles() {
    if std::env::var_os("AIVPN_STORAGE_HANDLE_COUNT_CHILD").is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "repeated_successful_and_failed_open_do_not_leak_handles",
                "--nocapture",
            ])
            .env("AIVPN_STORAGE_HANDLE_COUNT_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        return;
    }
    let fixture = Fixture::new();
    drop(StateDirectory::open(&fixture.0).unwrap());
    let handles = || {
        let mut count = 0;
        assert_ne!(
            unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) },
            0
        );
        count
    };
    let before = handles();
    for _ in 0..24 {
        let store = StateDirectory::open(&fixture.0).unwrap();
        assert!(StateDirectory::open(&fixture.0).is_err());
        drop(store);
    }
    assert!(
        handles() <= before + 2,
        "before={before}, after={}",
        handles()
    );
}

#[test]
fn ambiguous_or_remote_paths_are_rejected() {
    for path in [
        r"relative",
        r"C:relative",
        r"\\server\share\state",
        r"C:\",
        r"C:\state:stream",
        r"C:\state.",
        r"C:\state ",
    ] {
        assert!(
            StateDirectory::open(std::path::Path::new(path)).is_err(),
            "{path}"
        );
    }
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn kernel_slots_keep_numbers_across_restart_and_reject_partial_records() {
    use aivpn_desktop_agent::slots::{KernelSlotStore, KernelState, SlotKey, SlotKind};
    use std::collections::BTreeSet;
    let fixture = Fixture::new();
    let key = SlotKey::new(SlotKind::Profile, "profile-a".into()).unwrap();
    let required = BTreeSet::from([key.clone()]);
    let mut slots = KernelSlotStore::open(
        StateDirectory::open(&fixture.0).unwrap(),
        [7; 16],
        KernelState::Fresh,
    )
    .unwrap();
    let assigned = slots.synchronize(&required).unwrap();
    drop(slots);
    let mut slots = KernelSlotStore::open(
        StateDirectory::open(&fixture.0).unwrap(),
        [7; 16],
        KernelState::Existing,
    )
    .unwrap();
    assert_eq!(slots.synchronize(&required).unwrap(), assigned);
    slots.synchronize(&BTreeSet::new()).unwrap();
    assert!(slots.synchronize(&required).unwrap()[&key] > assigned[&key]);
    drop(slots);
    let mut store = StateDirectory::open(&fixture.0).unwrap();
    store.replace(StateFile::Committed, b"{partial").unwrap();
    drop(store);
    assert!(KernelSlotStore::open(
        StateDirectory::open(&fixture.0).unwrap(),
        [7; 16],
        KernelState::Existing
    )
    .is_err());
    assert_eq!(fs::read(fixture.0.join("state.json")).unwrap(), b"{partial");
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn service_process_crash_releases_lock_and_leaves_complete_snapshot() {
    use std::io::BufRead;
    let fixture = Fixture::new();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "child_crash_writer", "--nocapture"])
        .env("AIVPN_STORAGE_CHILD_PATH", &fixture.0)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
    loop {
        let mut line = String::new();
        assert!(
            output.read_line(&mut line).unwrap() > 0,
            "Писатель не запустился"
        );
        if line.contains("WRITER_READY") {
            break;
        }
    }
    thread::sleep(std::time::Duration::from_millis(20));
    child.kill().unwrap();
    child.wait().unwrap();
    let store = StateDirectory::open(&fixture.0).unwrap();
    let bytes = store.load(StateFile::Committed).unwrap().unwrap();
    assert_eq!(bytes.len(), 128 * 1024);
    assert!(bytes.iter().all(|byte| *byte == bytes[0]));
    assert!(!fixture.0.join(".new-state.json").exists());
}

#[test]
#[ignore = "Дочерний сценарий native Windows suite, окружение задает родитель"]
fn child_crash_writer() {
    let path = std::env::var_os("AIVPN_STORAGE_CHILD_PATH")
        .expect("Дочерний сценарий запускает родитель с путем fixture");
    let mut store = StateDirectory::open(std::path::Path::new(&path)).unwrap();
    store
        .replace(StateFile::Committed, &vec![0; 128 * 1024])
        .unwrap();
    println!("WRITER_READY");
    std::io::stdout().flush().unwrap();
    for i in 0..10_000 {
        store
            .replace(StateFile::Committed, &vec![(i % 255) as u8; 128 * 1024])
            .unwrap();
    }
}

#[test]
#[ignore = "Отдельная проверка Windows VM reset с явно заданной фазой"]
fn vm_reset_fixture() {
    let phase = std::env::var_os("AIVPN_STORAGE_RESET_PHASE")
        .expect("Для VM reset нужна явно заданная фаза");
    assert!(
        phase == "write" || phase == "read",
        "Неизвестная фаза VM reset"
    );
    let path = std::path::Path::new(r"C:\AivpnLab\storage-reset-test");
    let mut store = StateDirectory::open(path).unwrap();
    if phase == "write" {
        store
            .replace(
                StateFile::Committed,
                b"durable complete snapshot before VM reset",
            )
            .unwrap();
        store
            .replace(StateFile::Pending, b"pending intent before VM reset")
            .unwrap();
    } else {
        assert_eq!(
            store.load(StateFile::Committed).unwrap().unwrap(),
            b"durable complete snapshot before VM reset"
        );
        assert_eq!(
            store.load(StateFile::Pending).unwrap().unwrap(),
            b"pending intent before VM reset"
        );
        drop(store);
        fs::remove_dir_all(path).unwrap();
    }
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn permissions_changed_after_open_are_rechecked_before_mutation() {
    let fixture = Fixture::new();
    let mut store = StateDirectory::open(&fixture.0).unwrap();
    store.replace(StateFile::Committed, b"keep").unwrap();
    icacls(&fixture.0, &["/grant", "*S-1-1-0:R"]);
    assert!(store.replace(StateFile::Committed, b"new").is_err());
    assert!(store.clear_pending().is_err());
    assert!(store.load(StateFile::Committed).is_err());
    assert_eq!(fs::read(fixture.0.join("state.json")).unwrap(), b"keep");
    assert!(!fixture.0.join(".new-state.json").exists());
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn kernel_rejects_readonly_replacement_and_original_is_preserved() {
    let fixture = Fixture::new();
    let mut store = StateDirectory::open(&fixture.0).unwrap();
    store.replace(StateFile::Committed, b"keep").unwrap();
    let path = fixture.0.join("state.json");
    let original_permissions = fs::metadata(&path).unwrap().permissions();
    let mut permissions = original_permissions.clone();
    permissions.set_readonly(true);
    fs::set_permissions(&path, permissions.clone()).unwrap();
    assert!(store.replace(StateFile::Committed, b"new").is_err());
    assert_eq!(
        store.load(StateFile::Committed).unwrap(),
        Some(b"keep".to_vec())
    );
    fs::set_permissions(path, original_permissions).unwrap();
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn worker_logs_bound_history_preserve_active_unknown_and_hardlinked_files() {
    use aivpn_desktop_agent::worker_log::{WorkerLog, WORKER_LOG_LIMIT};
    use std::collections::BTreeSet;
    let fixture = Fixture::new();
    let store = StateDirectory::open(&fixture.0).unwrap();
    let name = |n: usize| format!("worker-11111111-2222-3333-{n:016x}.log");
    for index in 0..80 {
        fs::write(fixture.0.join(name(index)), b"old completed worker").unwrap();
    }
    let unknown = fixture.0.join("manual-note.txt");
    fs::write(&unknown, b"foreign data").unwrap();
    let active_path = fixture.0.join(name(1000));
    let active = OpenOptions::new()
        .create_new(true)
        .write(true)
        .share_mode(FILE_SHARE_READ)
        .open(&active_path)
        .unwrap();
    let next = store.prepare_worker_log(&name(1001)).unwrap();
    let names = || {
        fs::read_dir(&fixture.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(
        names()
            .iter()
            .filter(|n| n.to_string_lossy().starts_with("worker-"))
            .count(),
        33
    );
    assert!(active_path.exists());
    assert_eq!(fs::read(&unknown).unwrap(), b"foreign data");
    // Права соответствуют унаследованному stdout работника: запись без чтения.
    let output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .share_mode(FILE_SHARE_READ)
        .open(&next)
        .unwrap();
    let mut log = WorkerLog::new(output).unwrap();
    log.write_all(&vec![b'x'; WORKER_LOG_LIMIT * 3]).unwrap();
    let mut clone = log.clone();
    clone.write_all(b"latest native worker failure\n").unwrap();
    clone.flush().unwrap();
    assert!(fs::metadata(&next).unwrap().len() <= WORKER_LOG_LIMIT as u64);
    let bytes = fs::read(&next).unwrap();
    assert!(bytes.ends_with(b"latest native worker failure\n"));
    let link = fixture.0.join(name(2000));
    fs::hard_link(&unknown, &link).unwrap();
    let before = names();
    assert!(store.prepare_worker_log(&name(1002)).is_err());
    assert_eq!(names(), before, "refused scan deleted a file");
    assert_eq!(fs::read(&unknown).unwrap(), b"foreign data");
    assert!(store.prepare_worker_log("../escape.log").is_err());
    drop(clone);
    drop(log);
    drop(active);
    drop(store);
}
