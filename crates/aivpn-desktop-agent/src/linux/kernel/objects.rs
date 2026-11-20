//! Чтение принадлежащих службе объектов без загрузки программ или изменения карт.

use super::image::result;
use super::invalid_object;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;

unsafe extern "C" {
    fn bpf_obj_get(path: *const c_char) -> c_int;
    fn bpf_obj_get_info_by_fd(fd: c_int, info: *mut c_void, size: *mut u32) -> c_int;
    fn bpf_map_lookup_elem(fd: c_int, key: *const c_void, value: *mut c_void) -> c_int;
}

#[repr(C, align(8))]
pub(super) struct ObjectInfo {
    pub words: [u32; 128],
}

impl ObjectInfo {
    pub fn read(fd: &impl AsRawFd) -> io::Result<Self> {
        let mut info = Self { words: [0; 128] };
        let mut size = std::mem::size_of::<Self>() as u32;
        result(unsafe {
            bpf_obj_get_info_by_fd(fd.as_raw_fd(), info.words.as_mut_ptr().cast(), &mut size)
        })?;
        if size < 8 || info.words[1] == 0 {
            return Err(invalid_object());
        }
        Ok(info)
    }

    pub fn map_shape(&self) -> [u32; 5] {
        [
            self.words[0],
            self.words[2],
            self.words[3],
            self.words[4],
            self.words[5],
        ]
    }

    pub(super) fn fingerprint(&self, name: &CStr) -> io::Result<Vec<u32>> {
        let group = name
            .to_bytes()
            .split(|byte| *byte == b'/')
            .next()
            .unwrap_or_default();
        match group {
            b"maps" => Ok(self.words[..6].to_vec()),
            b"programs" => Ok(self.words[..4].to_vec()),
            b"links" => {
                if self.words[0] == 1 {
                    // Указатель на имя tracepoint не входит в постоянную identity link.
                    let mut fields = self.words[..3].to_vec();
                    fields.extend_from_slice(&self.words[6..7]);
                    fields.extend_from_slice(&self.words[8..10]);
                    return Ok(fields);
                }
                if self.words[0] == 8 {
                    // Адрес буфера и счетчик missed не входят в постоянную identity link.
                    let mut fields = self.words[..3].to_vec();
                    fields.extend_from_slice(&self.words[6..8]);
                    return Ok(fields);
                }
                let end = match self.words[0] {
                    2 | 3 => 7,
                    10 => 8,
                    _ => return Err(invalid_object()),
                };
                let mut fields = self.words[..3].to_vec();
                fields.extend_from_slice(&self.words[4..end]);
                Ok(fields)
            }
            _ => Err(invalid_object()),
        }
    }
}

pub(super) fn open_pin(directory: &File, name: &CStr) -> io::Result<OwnedFd> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let node = unsafe { File::from_raw_fd(fd) };
    let metadata = node.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(invalid_object());
    }
    // O_PATH удерживает именно проверенный inode, даже если имя затем переименуют.
    let path = CString::new(format!("/proc/thread-self/fd/{}", node.as_raw_fd())).unwrap();
    let descriptor = unsafe { bpf_obj_get(path.as_ptr()) };
    if descriptor < 0 {
        return Err(io::Error::from_raw_os_error(-descriptor));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

pub(super) fn read_array<const N: usize>(fd: &OwnedFd) -> io::Result<[u8; N]> {
    // lookup копирует всю value: размер проверяется до передачи указателя на буфер.
    if ObjectInfo::read(fd)?.map_shape() != [2, 4, N as u32, 1, 0] {
        return Err(invalid_object());
    }
    let zero = 0u32;
    let mut bytes = [0u8; N];
    result(unsafe {
        bpf_map_lookup_elem(
            fd.as_raw_fd(),
            (&zero as *const u32).cast(),
            bytes.as_mut_ptr().cast(),
        )
    })?;
    Ok(bytes)
}

pub(super) fn inventory_digest(entries: &BTreeMap<CString, ObjectInfo>) -> io::Result<[u8; 32]> {
    let mut digest = Sha256::new();
    for (name, info) in entries {
        digest.update((name.to_bytes().len() as u32).to_le_bytes());
        digest.update(name.to_bytes());
        for value in info.fingerprint(name)? {
            digest.update(value.to_le_bytes());
        }
    }
    Ok(digest.finalize().into())
}
