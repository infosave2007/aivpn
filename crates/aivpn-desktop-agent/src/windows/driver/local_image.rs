use super::*;
use windows_sys::Wdk::{
    Foundation::OBJECT_ATTRIBUTES,
    Storage::FileSystem::{
        NtCreateFile, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT,
    },
};

pub(super) fn open(path: &str) -> io::Result<Handle> {
    let mut path_units = path.encode_utf16().collect::<Vec<_>>();
    if path_units.is_empty() || path_units.len() > 4096 || path_units.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    if !local_volume(path)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Выбранный файл должен находиться на локальном томе",
        ));
    }
    let name = UNICODE_STRING {
        Length: (path_units.len() * 2) as u16,
        MaximumLength: (path_units.len() * 2) as u16,
        Buffer: path_units.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        ..Default::default()
    };
    let mut file = ptr::null_mut();
    let mut result = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtCreateFile(
            &mut file,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &attributes,
            &mut result,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ));
    }
    Handle::new(file)
}

struct VolumeSearch(HANDLE);
impl Drop for VolumeSearch {
    fn drop(&mut self) {
        unsafe { FindVolumeClose(self.0) };
    }
}

// Перечень томов не открывает пользовательский путь и не обращается к SMB.
fn local_volume(path: &str) -> io::Result<bool> {
    let mut volume = [0u16; 512];
    let search = unsafe { FindFirstVolumeW(volume.as_mut_ptr(), volume.len() as u32) };
    if search == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let search = VolumeSearch(search);
    let mut target = vec![0u16; 32768];
    for _ in 0..4096 {
        if let Some(name) = dos_volume_name(&volume) {
            let size =
                unsafe { QueryDosDeviceW(name.as_ptr(), target.as_mut_ptr(), target.len() as u32) }
                    as usize;
            if size > 0 && size <= target.len() && matches_volume(path, &target[..size]) {
                return Ok(true);
            }
        }
        if unsafe { FindNextVolumeW(search.0, volume.as_mut_ptr(), volume.len() as u32) } == 0 {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                Ok(false)
            } else {
                Err(error)
            };
        }
    }
    Err(io::ErrorKind::FileTooLarge.into())
}

fn dos_volume_name(volume: &[u16]) -> Option<Vec<u16>> {
    let end = volume.iter().position(|unit| *unit == 0)?;
    if end < 6 || volume[..4] != [92, 92, 63, 92] || volume[end - 1] != 92 {
        return None;
    }
    Some(volume[4..end - 1].iter().copied().chain([0]).collect())
}

fn matches_volume(path: &str, target: &[u16]) -> bool {
    let end = target
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(target.len());
    let Ok(volume) = String::from_utf16(&target[..end]) else {
        return false;
    };
    let volume = volume.to_lowercase();
    !volume.is_empty()
        && path
            .to_lowercase()
            .strip_prefix(&volume)
            .is_some_and(|suffix| suffix.starts_with('\\') && suffix.len() > 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::windows::io::AsRawHandle, path::PathBuf};

    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn local_volume_prefix_requires_a_complete_device_component() {
        let volume = "\\Device\\HarddiskVolume1\0"
            .encode_utf16()
            .collect::<Vec<_>>();
        assert!(matches_volume(
            "\\device\\harddiskvolume1\\app.exe",
            &volume
        ));
        for path in [
            "\\device\\harddiskvolume1",
            "\\device\\harddiskvolume1\\",
            "\\device\\harddiskvolume10\\app.exe",
            "\\device\\mup\\host\\share\\app.exe",
            "\\device\\namedpipe\\app.exe",
        ] {
            assert!(!matches_volume(path, &volume), "{path}");
        }
        assert!(!matches_volume("\\device\\mup\\host\\share", &[0]));
    }

    #[test]
    #[ignore = "Требуется нативный Windows с локальным NTFS"]
    fn remote_devices_are_rejected_before_opening_a_file() {
        for path in [
            "\\device\\mup\\127.0.0.1\\missing\\app.exe",
            "\\device\\namedpipe\\aivpn-local-image-test",
        ] {
            let error = match open(path) {
                Ok(_) => panic!("Принят путь вне локального тома"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(error.raw_os_error(), None);
        }
    }

    #[test]
    #[ignore = "Требуется нативный Windows с локальным NTFS"]
    fn selected_image_rejects_junction_and_keeps_rename_compatible() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = Fixture(std::env::temp_dir().join(format!("aivpn-local-image-{unique}")));
        fs::create_dir(&root.0).unwrap();
        let target = root.0.join("target");
        fs::create_dir(&target).unwrap();
        let image = target.join("selected.exe");
        fs::write(&image, b"local-selected-image").unwrap();
        let file = fs::File::open(&root.0)
            .or_else(|_| {
                use std::os::windows::fs::OpenOptionsExt;
                fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                    .open(&root.0)
            })
            .unwrap();
        let mut name = vec![0u16; 32768];
        let length = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                name.as_mut_ptr(),
                name.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_NT,
            )
        } as usize;
        assert!(length > 0 && length < name.len());
        let native = String::from_utf16(&name[..length]).unwrap().to_lowercase();
        drop(file);
        let held = open(&format!("{native}\\target\\selected.exe")).unwrap();
        fs::rename(&image, target.join("renamed.exe")).unwrap();
        drop(held);
        fs::rename(target.join("renamed.exe"), &image).unwrap();
        let junction = root.0.join("junction");
        assert!(std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&target)
            .output()
            .unwrap()
            .status
            .success());
        let redirected = format!("{native}\\junction\\selected.exe");
        // Контроль подтверждает существование цели через настоящий junction.
        let ordinary = fs::File::open(junction.join("selected.exe")).unwrap();
        drop(ordinary);
        assert!(
            open(&redirected).is_err(),
            "Перенаправленный путь принят службой"
        );
    }
}
