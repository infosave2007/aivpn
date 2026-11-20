use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);

fn location() -> PathBuf {
    std::env::temp_dir().join(format!(
        "aivpn-state-fault-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn operation_errors_are_returned_without_destroying_the_last_complete_snapshot() {
    for point in [
        Point::Create,
        Point::Write,
        Point::FileFlush,
        Point::Rename,
        Point::VolumeFlush,
    ] {
        let path = location();
        let mut store = StateDirectory::open(&path).unwrap();
        store
            .replace(StateFile::Committed, b"old snapshot")
            .unwrap();
        FAULT.with(|fault| fault.set(Some(point)));
        assert!(
            store
                .replace(StateFile::Committed, b"complete new snapshot")
                .is_err(),
            "{point:?}"
        );
        drop(store);
        let store = StateDirectory::open(&path).unwrap();
        let expected: &[u8] = if point == Point::VolumeFlush {
            b"complete new snapshot"
        } else {
            b"old snapshot"
        };
        assert_eq!(
            store.load(StateFile::Committed).unwrap().unwrap(),
            expected,
            "{point:?}"
        );
        assert!(!path.join(".new-state.json").exists());
        drop(store);
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn delete_and_post_delete_flush_errors_reach_the_caller() {
    for point in [Point::Delete, Point::VolumeFlush] {
        let path = location();
        let mut store = StateDirectory::open(&path).unwrap();
        store.replace(StateFile::Pending, b"intent").unwrap();
        FAULT.with(|fault| fault.set(Some(point)));
        assert!(store.clear_pending().is_err());
        let expected = if point == Point::Delete {
            Some(b"intent".to_vec())
        } else {
            None
        };
        assert_eq!(store.load(StateFile::Pending).unwrap(), expected);
        drop(store);
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn slot_store_is_poisoned_after_rename_succeeds_but_volume_flush_fails() {
    use crate::slots::{KernelSlotStore, KernelState, SlotKey, SlotKind};
    use std::collections::BTreeSet;
    let path = location();
    let mut slots = KernelSlotStore::open(
        StateDirectory::open(&path).unwrap(),
        [9; 16],
        KernelState::Fresh,
    )
    .unwrap();
    let required = BTreeSet::from([SlotKey::new(SlotKind::Profile, "new-profile".into()).unwrap()]);
    FAULT.with(|fault| fault.set(Some(Point::VolumeFlush)));
    assert!(slots.synchronize(&required).is_err());
    assert!(slots.synchronize(&required).is_err());
    drop(slots);
    let mut slots = KernelSlotStore::open(
        StateDirectory::open(&path).unwrap(),
        [9; 16],
        KernelState::Existing,
    )
    .unwrap();
    assert_eq!(
        slots
            .synchronize(&required)
            .unwrap()
            .values()
            .next()
            .unwrap()
            .get(),
        1
    );
    drop(slots);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
#[ignore = "Требуется изолированный Windows-стенд и право сброса буферов NTFS-тома"]
fn absent_pending_still_requires_a_successful_metadata_barrier() {
    let path = location();
    let mut store = StateDirectory::open(&path).unwrap();
    FAULT.with(|fault| fault.set(Some(Point::VolumeFlush)));
    assert!(store.clear_pending().is_err());
    store.clear_pending().unwrap();
    drop(store);
    std::fs::remove_dir_all(path).unwrap();
}
