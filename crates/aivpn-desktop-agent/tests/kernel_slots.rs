use aivpn_desktop_agent::slots::{KernelSlotStore, KernelState, SlotKey, SlotKind};
use std::collections::BTreeSet;

#[path = "support/kernel_slot_store.rs"]
mod storage;
use storage::Store;

fn key(name: &str) -> SlotKey {
    SlotKey::new(SlotKind::Executable, name.into()).unwrap()
}
fn required(names: &[&str]) -> BTreeSet<SlotKey> {
    names.iter().map(|name| key(name)).collect()
}

#[test]
fn numbers_survive_restart_and_identical_sync_does_not_write_again() {
    let store = Store::default();
    let mut slots = KernelSlotStore::open(store.clone(), [9; 16], KernelState::Fresh).unwrap();
    let first = slots
        .synchronize(&required(&["/usr/bin/a", "/usr/bin/b"]))
        .unwrap();
    let writes = store.0.borrow().writes;
    assert_eq!(
        slots
            .synchronize(&required(&["/usr/bin/b", "/usr/bin/a"]))
            .unwrap(),
        first
    );
    assert_eq!(store.0.borrow().writes, writes);
    drop(slots);
    let mut slots = KernelSlotStore::open(store, [9; 16], KernelState::Existing).unwrap();
    assert_eq!(
        slots
            .synchronize(&required(&["/usr/bin/a", "/usr/bin/b"]))
            .unwrap(),
        first
    );
}

#[test]
fn removing_and_recreating_a_key_never_reuses_its_old_number() {
    let store = Store::default();
    let mut slots = KernelSlotStore::open(store.clone(), [9; 16], KernelState::Fresh).unwrap();
    let first = slots.synchronize(&required(&["a", "b"])).unwrap();
    slots.synchronize(&required(&["b"])).unwrap();
    drop(slots);
    let mut slots = KernelSlotStore::open(store, [9; 16], KernelState::Existing).unwrap();
    let next = slots.synchronize(&required(&["a", "b"])).unwrap();
    assert_eq!(first[&key("b")], next[&key("b")]);
    assert!(next[&key("a")] > first[&key("a")]);
    assert_ne!(next[&key("a")], first[&key("b")]);
}

#[test]
fn a_failed_write_poisons_the_writer_and_reopening_observes_ambiguous_commit() {
    for committed in [false, true] {
        let store = Store::default();
        let mut slots = KernelSlotStore::open(store.clone(), [9; 16], KernelState::Fresh).unwrap();
        slots.synchronize(&required(&["a"])).unwrap();
        store.0.borrow_mut().fault = Some(committed);
        assert!(slots.synchronize(&required(&["a", "b"])).is_err());
        let writes = store.0.borrow().writes;
        assert!(slots.synchronize(&required(&["a"])).is_err());
        assert_eq!(store.0.borrow().writes, writes);
        drop(slots);
        let mut slots = KernelSlotStore::open(store, [9; 16], KernelState::Existing).unwrap();
        let bindings = slots.synchronize(&required(&["a", "c"])).unwrap();
        assert_eq!(bindings[&key("a")].get(), 1);
        assert_eq!(bindings[&key("c")].get(), if committed { 3 } else { 2 });
    }
}

#[test]
fn existing_kernel_state_cannot_start_again_with_an_empty_or_foreign_counter() {
    let store = Store::default();
    assert!(KernelSlotStore::open(store.clone(), [9; 16], KernelState::Existing).is_err());
    assert_eq!(store.0.borrow().writes, 0);
    drop(KernelSlotStore::open(store.clone(), [9; 16], KernelState::Fresh).unwrap());
    assert!(KernelSlotStore::open(store.clone(), [8; 16], KernelState::Existing).is_err());
    let before = store.0.borrow().committed.clone();
    store.0.borrow_mut().pending = Some(b"unrelated journal".to_vec());
    assert!(KernelSlotStore::open(store.clone(), [9; 16], KernelState::Existing).is_err());
    assert_eq!(store.0.borrow().committed, before);
}

#[test]
fn invalid_keys_and_capacity_overflow_do_not_change_the_committed_record() {
    for name in ["", "a\0b"] {
        assert!(SlotKey::new(SlotKind::Executable, name.into()).is_err());
    }
    assert!(SlotKey::new(SlotKind::Executable, "x".repeat(4097)).is_err());
    let store = Store::default();
    let mut slots = KernelSlotStore::open(store.clone(), [9; 16], KernelState::Fresh).unwrap();
    for (kind, capacity) in [
        (SlotKind::Profile, 256),
        (SlotKind::Owner, 256),
        (SlotKind::Package, 4096),
        (SlotKind::Executable, 4096),
    ] {
        let required = (0..=capacity)
            .map(|index| SlotKey::new(kind, index.to_string()).unwrap())
            .collect();
        let writes = store.0.borrow().writes;
        assert!(slots.synchronize(&required).is_err());
        assert_eq!(store.0.borrow().writes, writes);
    }
    assert_eq!(
        slots.synchronize(&required(&["after"])).unwrap()[&key("after")].get(),
        1
    );
}

#[test]
fn maximum_keys_and_kind_capacities_are_usable_together() {
    let store = Store::default();
    let mut slots = KernelSlotStore::open(store.clone(), [9; 16], KernelState::Fresh).unwrap();
    let initial: serde_json::Value =
        serde_json::from_slice(store.0.borrow().committed.as_ref().unwrap()).unwrap();
    assert_eq!(initial["next"], 1);
    let mut all = BTreeSet::new();
    for (kind, capacity) in [
        (SlotKind::Profile, 256),
        (SlotKind::Owner, 256),
        (SlotKind::Package, 4096),
        (SlotKind::Executable, 4096),
    ] {
        all.extend((0..capacity).map(|index| SlotKey::new(kind, index.to_string()).unwrap()));
    }
    // Максимальная длина - в байтах, без нормализации или усечения имени.
    all.remove(&key("0"));
    let longest = SlotKey::new(SlotKind::Executable, "я".repeat(2048)).unwrap();
    all.insert(longest.clone());
    let bindings = slots.synchronize(&all).unwrap();
    assert_eq!(bindings.len(), 8704);
    assert!(bindings.contains_key(&longest));
    drop(slots);
    let mut slots = KernelSlotStore::open(store, [9; 16], KernelState::Existing).unwrap();
    assert_eq!(slots.synchronize(&all).unwrap(), bindings);
}

#[test]
fn an_empty_record_still_requires_a_positive_next_number() {
    let store = Store::default();
    drop(KernelSlotStore::open(store.clone(), [9; 16], KernelState::Fresh).unwrap());
    mutate_record(&store, |record| record["next"] = 0.into());
    assert!(KernelSlotStore::open(store, [9; 16], KernelState::Existing).is_err());
}

fn mutate_record(store: &Store, mutate: impl FnOnce(&mut serde_json::Value)) {
    let bytes = store.0.borrow().committed.clone().unwrap();
    let mut record = serde_json::from_slice(&bytes).unwrap();
    mutate(&mut record);
    store.0.borrow_mut().committed = Some(serde_json::to_vec(&record).unwrap());
}

#[test]
fn exhausted_numbers_never_wrap_and_existing_bindings_can_still_be_removed() {
    let store = Store::default();
    drop(KernelSlotStore::open(store.clone(), [9; 16], KernelState::Fresh).unwrap());
    mutate_record(&store, |record| record["next"] = u32::MAX.into());
    let mut slots = KernelSlotStore::open(store.clone(), [9; 16], KernelState::Existing).unwrap();
    assert_eq!(
        slots.synchronize(&required(&["last"])).unwrap()[&key("last")].get(),
        u32::MAX
    );
    drop(slots);
    let mut slots = KernelSlotStore::open(store.clone(), [9; 16], KernelState::Existing).unwrap();
    let writes = store.0.borrow().writes;
    assert!(slots.synchronize(&required(&["last", "new"])).is_err());
    assert_eq!(store.0.borrow().writes, writes);
    assert_eq!(
        slots.synchronize(&required(&["last"])).unwrap()[&key("last")].get(),
        u32::MAX
    );
    slots.synchronize(&BTreeSet::new()).unwrap();
    assert!(slots.synchronize(&required(&["last"])).is_err());
}

#[test]
fn malformed_records_are_refused_without_resetting_or_overwriting() {
    for change in 0..12 {
        let store = Store::default();
        let mut slots = KernelSlotStore::open(store.clone(), [9; 16], KernelState::Fresh).unwrap();
        slots.synchronize(&required(&["a", "b"])).unwrap();
        drop(slots);
        mutate_record(&store, |record| match change {
            0 => record["kind"] = "other".into(),
            1 => record["version"] = 2.into(),
            2 => record["next"] = 0.into(),
            3 => record["next"] = (u64::from(u32::MAX) + 2).into(),
            4 => record["next"] = 2.into(),
            5 => record["bindings"][1]["number"] = 1.into(),
            6 => record["bindings"][1]["key"] = record["bindings"][0]["key"].clone(),
            7 => record["bindings"][0]["key"]["name"] = "".into(),
            8 => record["bindings"][0]["number"] = 0.into(),
            9 => record["unexpected"] = true.into(),
            10 => record["bindings"][0]["key"]["unexpected"] = true.into(),
            _ => record["bindings"][0]["unexpected"] = true.into(),
        });
        let bytes = store.0.borrow().committed.clone();
        let writes = store.0.borrow().writes;
        // Fresh также не дает права стереть существующий поврежденный счетчик.
        for state in [KernelState::Existing, KernelState::Fresh] {
            assert!(
                KernelSlotStore::open(store.clone(), [9; 16], state).is_err(),
                "case {change}"
            );
        }
        assert_eq!(store.0.borrow().committed, bytes);
        assert_eq!(store.0.borrow().writes, writes);
    }
}
