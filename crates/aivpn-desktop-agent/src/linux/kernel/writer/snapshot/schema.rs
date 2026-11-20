use super::invalid;
use aivpn_desktop_policy::Owner;
use std::{collections::BTreeMap, io};

pub(in crate::linux::kernel::writer) const CAPACITY: u32 = 401408;
pub(in crate::linux::kernel::writer) const FLAGS: u32 = (1 << 7) | 1;
pub(in crate::linux::kernel::writer) const SHAPE: [u32; 5] = [1, 40, 64, CAPACITY, FLAGS];
pub(in crate::linux::kernel::writer) const HEADER: u64 = 1;
pub(in crate::linux::kernel::writer) const RULE: u64 = 2;
pub(in crate::linux::kernel::writer) const FILE: u64 = 3;
pub(in crate::linux::kernel::writer) const MEMBERSHIP: u64 = 4;
pub(in crate::linux::kernel::writer) const PHYSICAL: u64 = 5;
pub(in crate::linux::kernel::writer) const LOGICAL: u64 = 6;
pub(in crate::linux::kernel::writer) const META: u64 = 7;
pub(in crate::linux::kernel::writer) const IDENTITY: u64 = 8;
pub(in crate::linux::kernel::writer) const SOURCE_PHYSICAL: u64 = 9;
pub(in crate::linux::kernel::writer) const SOURCE_LOGICAL: u64 = 10;
pub(in crate::linux::kernel::writer) const SOURCE_META: u64 = 11;
pub(in crate::linux::kernel::writer) type Key = [u64; 5];
pub(in crate::linux::kernel::writer) type Value = [u8; 64];
pub(in crate::linux::kernel::writer) type Records = BTreeMap<Key, Value>;

pub(in crate::linux::kernel::writer) fn key(kind: u64, owner: u64, payload: [u64; 3]) -> Key {
    [kind, owner, payload[0], payload[1], payload[2]]
}
pub(in crate::linux::kernel::writer) fn scalar(value: u64) -> Value {
    let mut bytes = [0; 64];
    bytes[..8].copy_from_slice(&value.to_ne_bytes());
    bytes
}
pub(in crate::linux::kernel::writer) fn insert(
    records: &mut Records,
    key: Key,
    value: Value,
) -> io::Result<()> {
    if records.insert(key, value).is_some() {
        return Err(invalid());
    }
    Ok(())
}
pub(in crate::linux::kernel::writer) fn owner(owner: Owner) -> io::Result<u64> {
    match owner {
        Owner::Machine {} => Ok(3u64 << 32),
        Owner::LinuxUser { uid } => Ok((1u64 << 32) | u64::from(uid)),
        _ => Err(invalid()),
    }
}
pub(in crate::linux::kernel::writer) fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
pub(in crate::linux::kernel::writer) fn set_bit(value: &mut Value, index: usize) {
    let offset = (index / 64) * 8;
    let bits = u64::from_ne_bytes(value[offset..offset + 8].try_into().unwrap());
    value[offset..offset + 8].copy_from_slice(&(bits | (1 << (index % 64))).to_ne_bytes());
}
pub(in crate::linux::kernel::writer) fn bounded(count: usize, limit: usize) -> io::Result<()> {
    if count > limit {
        Err(invalid())
    } else {
        Ok(())
    }
}
