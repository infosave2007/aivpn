//! Подключение capture minifilter подтверждается до запуска работников и публикации правил.
use super::{api::check, security::service_authority};
use std::{io, os::windows::ffi::OsStrExt, path::Path, ptr};
use windows_sys::Win32::{
    Foundation::*,
    Storage::{FileSystem::*, InstallableFileSystems::*},
};

const INSTANCE: &str = "Aivpn App Routing Instance";

pub struct ProvenanceVolume {
    instance: HFILTER_INSTANCE,
    filter: String,
}
impl Drop for ProvenanceVolume {
    fn drop(&mut self) {
        unsafe {
            FilterInstanceClose(self.instance);
        }
    }
}
impl ProvenanceVolume {
    /// Существующий экземпляр принимается только после открытия точного filter/volume/instance.
    /// Capture сохраняется при перезапуске службы; Drop не отключает minifilter.
    pub fn attach(filter: &str, mount: &Path) -> io::Result<Self> {
        service_authority()?;
        if filter.is_empty()
            || filter.len() > 128
            || !filter
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mount: Vec<u16> = mount.as_os_str().encode_wide().collect();
        if mount.is_empty() || mount.contains(&0) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mount: Vec<u16> = mount.into_iter().chain(Some(0)).collect();
        let mut volume = [0; 64];
        check(unsafe {
            GetVolumeNameForVolumeMountPointW(
                mount.as_ptr(),
                volume.as_mut_ptr(),
                volume.len() as u32,
            )
        })?;
        // GetVolumeName возвращает Win32 extended path, FltLib принимает NT GUID name.
        if volume[..4] != [b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16] {
            return Err(io::ErrorKind::InvalidData.into());
        }
        volume[1] = b'?' as u16;
        let mut filesystem = [0; 32];
        check(unsafe {
            GetVolumeInformationW(
                mount.as_ptr(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                filesystem.as_mut_ptr(),
                filesystem.len() as u32,
            )
        })?;
        let end = filesystem
            .iter()
            .position(|c| *c == 0)
            .ok_or(io::ErrorKind::InvalidData)?;
        if filesystem[..end] != "NTFS".encode_utf16().collect::<Vec<_>>() {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let name: Vec<u16> = filter.encode_utf16().chain(Some(0)).collect();
        let instance: Vec<u16> = INSTANCE.encode_utf16().chain(Some(0)).collect();
        let status = unsafe {
            FilterAttach(
                name.as_ptr(),
                volume.as_ptr(),
                instance.as_ptr(),
                0,
                ptr::null_mut(),
            )
        };
        if status < 0
            && status != ERROR_FLT_INSTANCE_ALTITUDE_COLLISION
            && status != ERROR_FLT_INSTANCE_NAME_COLLISION
        {
            return Err(hresult("подключение", status));
        }
        let mut handle = -1;
        let status = unsafe {
            FilterInstanceCreate(
                name.as_ptr(),
                volume.as_ptr(),
                instance.as_ptr(),
                &mut handle,
            )
        };
        if status < 0 {
            return Err(hresult("открытие экземпляра", status));
        }
        let value = Self {
            instance: handle,
            filter: filter.into(),
        };
        value.verify()?;
        Ok(value)
    }

    pub fn verify(&self) -> io::Result<()> {
        service_authority()?;
        let mut storage = vec![0u64; 2048];
        let mut length = 0;
        let status = unsafe {
            FilterInstanceGetInformation(
                self.instance,
                InstanceFullInformation,
                storage.as_mut_ptr().cast(),
                (storage.len() * 8) as u32,
                &mut length,
            )
        };
        if status < 0 {
            return Err(hresult("проверка экземпляра", status));
        }
        if length as usize > storage.len() * 8
            || (length as usize) < std::mem::size_of::<INSTANCE_FULL_INFORMATION>()
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let bytes =
            unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), length as usize) };
        let info = unsafe { &*storage.as_ptr().cast::<INSTANCE_FULL_INFORMATION>() };
        if info.NextEntryOffset != 0
            || !field(
                bytes,
                info.InstanceNameBufferOffset,
                info.InstanceNameLength,
            )?
            .eq_ignore_ascii_case(INSTANCE)
            || !field(bytes, info.FilterNameBufferOffset, info.FilterNameLength)?
                .eq_ignore_ascii_case(&self.filter)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
}
fn field(bytes: &[u8], offset: u16, length: u16) -> io::Result<String> {
    let start = offset as usize;
    let length = length as usize;
    if start < std::mem::size_of::<INSTANCE_FULL_INFORMATION>()
        || !start.is_multiple_of(2)
        || !length.is_multiple_of(2)
        || length == 0
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let data = bytes
        .get(start..start + length)
        .ok_or(io::ErrorKind::InvalidData)?;
    let text = data
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect::<Vec<_>>();
    if text.contains(&0) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    String::from_utf16(&text).map_err(|_| io::ErrorKind::InvalidData.into())
}
fn hresult(operation: &str, status: i32) -> io::Error {
    io::Error::other(format!(
        "Minifilter, {operation}: HRESULT {:#010x}",
        status as u32
    ))
}
