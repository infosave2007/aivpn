use super::{invalid, schema::*};
use crate::linux::kernel::{image::result, objects::ObjectInfo};
use std::{
    ffi::{c_int, c_void},
    io::{self, Read},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

unsafe extern "C" {
    fn aivpn_snapshot_create() -> c_int;
    fn bpf_map_update_elem(
        fd: c_int,
        key: *const c_void,
        value: *const c_void,
        flags: u64,
    ) -> c_int;
    fn bpf_map_lookup_elem(fd: c_int, key: *const c_void, value: *mut c_void) -> c_int;
    fn bpf_map_get_next_key(fd: c_int, key: *const c_void, next: *mut c_void) -> c_int;
    fn bpf_map_freeze(fd: c_int) -> c_int;
    fn bpf_map_get_fd_by_id(id: u32) -> c_int;
}

pub(in crate::linux::kernel::writer) fn prepare(records: &Records) -> io::Result<OwnedFd> {
    bounded(records.len(), 397826)?;
    let raw = unsafe { aivpn_snapshot_create() };
    if raw < 0 {
        return Err(io::Error::from_raw_os_error(-raw));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    if ObjectInfo::read(&fd)?.map_shape() != SHAPE {
        return Err(invalid());
    }
    for (key, value) in records {
        result(unsafe {
            bpf_map_update_elem(
                fd.as_raw_fd(),
                key.as_ptr().cast(),
                value.as_ptr().cast(),
                1,
            )
        })?;
    }
    readback(&fd, records)?;
    Ok(fd)
}
pub(in crate::linux::kernel::writer) fn freeze(fd: &OwnedFd, records: &Records) -> io::Result<()> {
    result(unsafe { bpf_map_freeze(fd.as_raw_fd()) })?;
    readback(fd, records)?;
    require_frozen(fd)
}
pub(in crate::linux::kernel::writer) fn require_frozen(fd: &OwnedFd) -> io::Result<()> {
    let mut info = String::new();
    std::fs::File::open(format!("/proc/thread-self/fdinfo/{}", fd.as_raw_fd()))?
        .take(4097)
        .read_to_string(&mut info)?;
    if info.len() > 4096 || !info.lines().any(|line| line == "frozen:\t1") {
        return Err(invalid());
    }
    Ok(())
}

pub(in crate::linux::kernel::writer) fn active(root: &OwnedFd) -> io::Result<OwnedFd> {
    if ObjectInfo::read(root)?.map_shape() != [12, 4, 4, 1, 0] {
        return Err(invalid());
    }
    let zero = 0u32;
    let mut id = 0u32;
    result(unsafe {
        bpf_map_lookup_elem(
            root.as_raw_fd(),
            (&zero as *const u32).cast(),
            (&mut id as *mut u32).cast(),
        )
    })?;
    if id == 0 {
        return Err(invalid());
    }
    let raw = unsafe { bpf_map_get_fd_by_id(id) };
    if raw < 0 {
        return Err(io::Error::from_raw_os_error(-raw));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    if ObjectInfo::read(&fd)?.words[1] != id || ObjectInfo::read(&fd)?.map_shape() != SHAPE {
        return Err(invalid());
    }
    require_frozen(&fd)?;
    Ok(fd)
}

pub(in crate::linux::kernel::writer) fn read_records(fd: &OwnedFd) -> io::Result<Records> {
    if ObjectInfo::read(fd)?.map_shape() != SHAPE {
        return Err(invalid());
    }
    let mut records = Records::new();
    let mut previous: Option<Key> = None;
    loop {
        let mut key = [0; 5];
        let pointer = previous
            .as_ref()
            .map_or(std::ptr::null(), |key| key.as_ptr().cast());
        let status =
            unsafe { bpf_map_get_next_key(fd.as_raw_fd(), pointer, key.as_mut_ptr().cast()) };
        if status == -libc::ENOENT {
            break;
        }
        result(status)?;
        bounded(records.len() + 1, 397826)?;
        let mut value = [0; 64];
        result(unsafe {
            bpf_map_lookup_elem(
                fd.as_raw_fd(),
                key.as_ptr().cast(),
                value.as_mut_ptr().cast(),
            )
        })?;
        if records.insert(key, value).is_some() {
            return Err(invalid());
        }
        previous = Some(key);
    }
    Ok(records)
}
fn readback(fd: &OwnedFd, records: &Records) -> io::Result<()> {
    let mut previous: Option<Key> = None;
    let mut seen = std::collections::BTreeSet::new();
    loop {
        let mut key = [0; 5];
        let pointer = previous
            .as_ref()
            .map_or(std::ptr::null(), |key| key.as_ptr().cast());
        let status =
            unsafe { bpf_map_get_next_key(fd.as_raw_fd(), pointer, key.as_mut_ptr().cast()) };
        if status == -libc::ENOENT {
            break;
        }
        result(status)?;
        if !seen.insert(key) {
            return Err(invalid());
        }
        let expected = records.get(&key).ok_or_else(invalid)?;
        let mut value = [0; 64];
        result(unsafe {
            bpf_map_lookup_elem(
                fd.as_raw_fd(),
                key.as_ptr().cast(),
                value.as_mut_ptr().cast(),
            )
        })?;
        if &value != expected {
            return Err(invalid());
        }
        previous = Some(key);
    }
    if seen.len() != records.len() {
        return Err(invalid());
    }
    Ok(())
}
