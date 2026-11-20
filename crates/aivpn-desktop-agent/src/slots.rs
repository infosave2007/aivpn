//! Сохраняемая нумерация объектов. Выданный номер не используется повторно.

use crate::control::ControlStore;
use crate::state::{StateFile, MAX_STATE_BYTES};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::num::NonZeroU32;

const FORMAT_VERSION: u32 = 1;
const RECORD_KIND: &str = "kernel-slots";
const FIRST_EXHAUSTED: u64 = u32::MAX as u64 + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotKind {
    Profile,
    Executable,
    Package,
    Owner,
    #[doc(hidden)]
    FileIdentity,
}

impl SlotKind {
    fn capacity(self) -> usize {
        match self {
            Self::Profile | Self::Owner => 256,
            Self::Executable | Self::Package | Self::FileIdentity => 4096,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotKey {
    pub(crate) kind: SlotKind,
    pub(crate) name: String,
}

impl SlotKey {
    pub fn new(kind: SlotKind, name: String) -> io::Result<Self> {
        if kind == SlotKind::FileIdentity {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let key = Self { kind, name };
        key.validate()?;
        Ok(key)
    }

    #[cfg(all(target_os = "linux", feature = "linux-kernel"))]
    pub(crate) fn file_identity(name: String) -> io::Result<Self> {
        let key = Self {
            kind: SlotKind::FileIdentity,
            name,
        };
        key.validate()?;
        Ok(key)
    }

    fn validate(&self) -> io::Result<()> {
        if self.name.is_empty() || self.name.len() > 4096 || self.name.contains('\0') {
            return Err(invalid_record());
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    key: SlotKey,
    number: NonZeroU32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    kind: String,
    version: u32,
    namespace: [u8; 16],
    next: u64,
    bindings: Vec<Binding>,
    #[serde(default)]
    grouped: bool,
}

impl Record {
    fn validate_header(&self, namespace: [u8; 16]) -> io::Result<()> {
        if self.kind != RECORD_KIND
            || self.version != FORMAT_VERSION
            || self.namespace != namespace
            || !(1..=FIRST_EXHAUSTED).contains(&self.next)
        {
            return Err(invalid_record());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum KernelState {
    Fresh,
    Existing,
}

pub struct KernelSlotStore<S> {
    store: S,
    namespace: [u8; 16],
    next: u64,
    bindings: BTreeMap<SlotKey, NonZeroU32>,
    poisoned: bool,
    grouped: bool,
}

impl<S: ControlStore> KernelSlotStore<S> {
    pub fn namespace(&self) -> [u8; 16] {
        self.namespace
    }
    #[cfg(all(target_os = "linux", feature = "linux-kernel"))]
    pub(crate) fn grouped_mode(&self) -> bool {
        self.grouped
    }

    #[cfg(all(target_os = "linux", feature = "linux-kernel"))]
    pub(crate) fn require_selector(&self, number: u32) -> io::Result<()> {
        self.ensure_available()?;
        if !self
            .bindings
            .iter()
            .any(|(key, value)| key.kind == SlotKind::Executable && value.get() == number)
        {
            return Err(invalid_record());
        }
        Ok(())
    }

    pub(crate) fn ensure_available(&self) -> io::Result<()> {
        require_unpoisoned(self.poisoned)
    }

    #[cfg(all(target_os = "linux", feature = "linux-kernel"))]
    pub(crate) fn require_binding(&self, key: &SlotKey, number: NonZeroU32) -> io::Result<()> {
        self.ensure_available()?;
        if self.bindings.get(key) != Some(&number) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(())
    }

    /// Хранилище принадлежит только нумерации и должно иметь единственного писателя.
    pub fn open(store: S, namespace: [u8; 16], state: KernelState) -> io::Result<Self> {
        if store.load(StateFile::Pending)?.is_some() {
            return Err(invalid_record());
        }
        let bytes = store.load(StateFile::Committed)?;
        let mut result = Self {
            store,
            namespace,
            next: 1,
            bindings: BTreeMap::new(),
            poisoned: false,
            grouped: false,
        };
        match bytes {
            Some(bytes) => result.restore(&bytes)?,
            None if matches!(state, KernelState::Fresh) => {
                result.persist(&BTreeMap::new(), 1)?;
            }
            None => return Err(invalid_record()),
        }
        Ok(result)
    }

    pub fn synchronize(
        &mut self,
        required: &BTreeSet<SlotKey>,
    ) -> io::Result<BTreeMap<SlotKey, NonZeroU32>> {
        self.ensure_available()?;
        if self.grouped
            || required
                .iter()
                .any(|key| key.kind == SlotKind::FileIdentity)
        {
            return Err(io::Error::other("Нужен планировщик групп inode"));
        }
        self.synchronize_exact(required)
    }

    #[cfg(any(
        target_os = "windows",
        all(target_os = "linux", feature = "linux-kernel")
    ))]
    pub(crate) fn synchronize_grouped(
        &mut self,
        required: &BTreeSet<SlotKey>,
    ) -> io::Result<BTreeMap<SlotKey, NonZeroU32>> {
        self.ensure_available()?;
        let mut union = required.clone();
        union.extend(self.bindings.keys().cloned());
        if !self.grouped {
            self.grouped = true;
            self.persist(&self.bindings.clone(), self.next)?;
        }
        self.synchronize_exact(&union)
    }

    #[cfg(all(target_os = "linux", feature = "linux-kernel"))]
    pub(crate) fn forget_group(&mut self, key: &SlotKey) -> io::Result<()> {
        self.ensure_available()?;
        if !self.grouped || key.kind != SlotKind::FileIdentity {
            return Err(invalid_record());
        }
        let mut bindings = self.bindings.clone();
        bindings.remove(key);
        self.persist(&bindings, self.next)?;
        self.bindings = bindings;
        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "linux-kernel"))]
    pub(crate) fn group_keys(&self) -> Vec<SlotKey> {
        self.bindings
            .keys()
            .filter(|key| key.kind == SlotKind::FileIdentity)
            .cloned()
            .collect()
    }

    fn synchronize_exact(
        &mut self,
        required: &BTreeSet<SlotKey>,
    ) -> io::Result<BTreeMap<SlotKey, NonZeroU32>> {
        validate_keys(required.iter())?;
        let mut next = self.next;
        let mut bindings = BTreeMap::new();
        for key in required {
            let number = match self.bindings.get(key) {
                Some(number) => *number,
                None => {
                    let number = u32::try_from(next)
                        .ok()
                        .and_then(NonZeroU32::new)
                        .ok_or_else(|| io::Error::other("Номера объектов исчерпаны"))?;
                    next += 1;
                    number
                }
            };
            bindings.insert(key.clone(), number);
        }
        if bindings != self.bindings {
            self.persist(&bindings, next)?;
            self.next = next;
            self.bindings = bindings;
        }
        Ok(self.bindings.clone())
    }

    fn restore(&mut self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > MAX_STATE_BYTES {
            return Err(invalid_record());
        }
        let record: Record = serde_json::from_slice(bytes).map_err(|_| invalid_record())?;
        record.validate_header(self.namespace)?;
        validate_keys(record.bindings.iter().map(|binding| &binding.key))?;
        let mut numbers = BTreeSet::new();
        for binding in record.bindings {
            if u64::from(binding.number.get()) >= record.next
                || !numbers.insert(binding.number)
                || self.bindings.insert(binding.key, binding.number).is_some()
            {
                return Err(invalid_record());
            }
        }
        self.next = record.next;
        self.grouped = record.grouped;
        self.validate_mode()
    }
    fn validate_mode(&self) -> io::Result<()> {
        if !self.grouped
            && self
                .bindings
                .keys()
                .any(|key| key.kind == SlotKind::FileIdentity)
        {
            return Err(invalid_record());
        }
        Ok(())
    }

    fn persist(&mut self, bindings: &BTreeMap<SlotKey, NonZeroU32>, next: u64) -> io::Result<()> {
        let record = Record {
            kind: RECORD_KIND.into(),
            version: FORMAT_VERSION,
            namespace: self.namespace,
            next,
            grouped: self.grouped,
            bindings: bindings
                .iter()
                .map(|(key, number)| Binding {
                    key: key.clone(),
                    number: *number,
                })
                .collect(),
        };
        let bytes = serde_json::to_vec(&record).map_err(io::Error::other)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(invalid_record());
        }
        // Ошибка после rename не позволяет узнать, какой счетчик попал на диск.
        if let Err(error) = self.store.replace(StateFile::Committed, &bytes) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }
}

pub(crate) fn require_unpoisoned(poisoned: bool) -> io::Result<()> {
    if poisoned {
        return Err(io::Error::other("Хранилище требует повторного открытия"));
    }
    Ok(())
}

fn validate_keys<'a>(keys: impl Iterator<Item = &'a SlotKey>) -> io::Result<()> {
    let mut counts = BTreeMap::<SlotKind, usize>::new();
    for key in keys {
        key.validate()?;
        let count = counts.entry(key.kind).or_default();
        *count += 1;
        if *count > key.kind.capacity() {
            return Err(invalid_record());
        }
    }
    Ok(())
}

fn invalid_record() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Повреждена нумерация объектов ядра",
    )
}

#[cfg(all(test, target_os = "linux", feature = "linux-kernel"))]
mod test_store {
    extern crate self as aivpn_desktop_agent;
    include!("../tests/support/kernel_slot_store.rs");
}
#[cfg(all(test, target_os = "linux", feature = "linux-kernel"))]
mod grouped_tests {
    use super::test_store::Store;
    use super::*;
    #[test]
    fn grouped_slots_share_counter_preserve_history_and_block_legacy_after_reopen() {
        let backing = Store::default();
        let mut slots =
            KernelSlotStore::open(backing.clone(), [4; 16], KernelState::Fresh).unwrap();
        let a = SlotKey::new(SlotKind::Executable, "/a".into()).unwrap();
        let h = SlotKey::new(SlotKind::Executable, "/h".into()).unwrap();
        let selected = slots
            .synchronize(&BTreeSet::from([a.clone(), h.clone()]))
            .unwrap();
        assert_ne!(selected[&a], selected[&h]);
        let identity = SlotKey::file_identity("instance/1".into()).unwrap();
        let grouped = slots
            .synchronize_grouped(&BTreeSet::from([identity.clone()]))
            .unwrap();
        assert!(grouped[&identity] > selected[&h]);
        assert_eq!(grouped[&a], selected[&a]);
        drop(slots);
        let mut slots = KernelSlotStore::open(backing, [4; 16], KernelState::Existing).unwrap();
        assert!(slots.synchronize(&BTreeSet::from([a])).is_err());
        assert_eq!(
            slots.synchronize_grouped(&BTreeSet::new()).unwrap()[&identity],
            grouped[&identity]
        );
    }
    #[test]
    fn modeled_4096_reuse_and_4097_refusal_preserve_numbers_and_burn_released_slots() {
        let mut slots =
            KernelSlotStore::open(Store::default(), [4; 16], KernelState::Fresh).unwrap();
        let keys = (0..4096)
            .map(|n| SlotKey::file_identity(format!("instance/{n}")).unwrap())
            .collect::<BTreeSet<_>>();
        let full = slots.synchronize_grouped(&keys).unwrap();
        let first = keys.first().unwrap().clone();
        assert_eq!(
            slots
                .synchronize_grouped(&BTreeSet::from([first.clone()]))
                .unwrap(),
            full
        );
        let extra = SlotKey::file_identity("instance/extra".into()).unwrap();
        assert!(slots
            .synchronize_grouped(&BTreeSet::from([extra.clone()]))
            .is_err());
        assert_eq!(slots.synchronize_grouped(&BTreeSet::new()).unwrap(), full);
        slots.forget_group(&first).unwrap();
        assert_eq!(
            slots
                .synchronize_grouped(&BTreeSet::from([extra.clone()]))
                .unwrap()[&extra]
                .get(),
            4097
        );
    }
    #[test]
    fn grouped_reservation_exhaustion_and_ambiguous_store_write_refuse() {
        let backing = Store::default();
        let mut slots =
            KernelSlotStore::open(backing.clone(), [4; 16], KernelState::Fresh).unwrap();
        slots.next = FIRST_EXHAUSTED;
        let key = SlotKey::file_identity("instance/1".into()).unwrap();
        assert!(slots
            .synchronize_grouped(&BTreeSet::from([key.clone()]))
            .is_err());
        slots.next = 1;
        backing.0.borrow_mut().fault = Some(true);
        assert!(slots
            .synchronize_grouped(&BTreeSet::from([key.clone()]))
            .is_err());
        assert!(slots.synchronize_grouped(&BTreeSet::new()).is_err());
        drop(slots);
        let slots = KernelSlotStore::open(backing, [4; 16], KernelState::Existing).unwrap();
        slots
            .require_binding(&key, NonZeroU32::new(1).unwrap())
            .unwrap();
    }
}
