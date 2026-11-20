//! Сохраняются последние завершенные журналы; открытые работники не затрагиваются.
use super::*;
use windows_sys::Win32::Foundation::{ERROR_SHARING_VIOLATION, FILETIME};

const KEEP_CLOSED_LOGS: usize = 32;
const MAX_ENTRIES: usize = 65536;

pub(super) fn worker_log(path: &str) -> bool {
    path.strip_prefix("worker-")
        .and_then(|name| name.strip_suffix(".log"))
        .is_some_and(|name| {
            let parts: Vec<_> = name.split('-').collect();
            parts.len() == 4
                && parts.iter().zip([8, 4, 4, 16]).all(|(part, length)| {
                    part.len() == length && part.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
        })
}

fn timestamp(value: FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

impl StateDirectory {
    pub fn prepare_worker_log(&self, name: &str) -> io::Result<PathBuf> {
        self.validate_directory()?;
        if !worker_log(name) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut closed = Vec::new();
        // Предки удерживаются без FILE_SHARE_DELETE, каждый файл проверяется
        // через тот же handle, которым затем удаляется. Сначала полная проверка.
        for (index, entry) in std::fs::read_dir(&self.path)?.enumerate() {
            if index >= MAX_ENTRIES {
                return Err(oversized());
            }
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !worker_log(&name) {
                continue;
            }
            let file = match open(
                &self.path.join(&name),
                FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                OPEN_EXISTING,
                None,
                0,
            ) {
                Ok(file) => file,
                // У живого работника stdout не разрешает удаление, он остается на месте.
                Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) => {
                    continue
                }
                Err(error) => return Err(error),
            };
            let info = information(&file, false)?;
            image::protected_writer(&file)?;
            closed.push((timestamp(info.ftLastWriteTime), name, file));
        }
        closed.sort_by(|left, right| (right.0, &right.1).cmp(&(left.0, &left.1)));
        for (_, _, file) in closed.into_iter().skip(KEEP_CLOSED_LOGS) {
            let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
            checked(unsafe {
                SetFileInformationByHandle(
                    handle(&file),
                    FileDispositionInfo,
                    ptr::addr_of!(disposition).cast(),
                    std::mem::size_of_val(&disposition) as u32,
                )
            })?;
        }
        Ok(self.path.join(name))
    }
}
