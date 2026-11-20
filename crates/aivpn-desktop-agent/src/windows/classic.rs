//! Одноразовый канал обычного GUI и повышенного экземпляра того же образа.
use super::{
    api::{self, check, denied, Handle},
    security,
};
use aivpn_desktop_policy::Owner;
use std::{
    io,
    os::windows::ffi::OsStrExt,
    ptr,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{Pipes::*, Threading::*},
};

const LIMIT: usize = 64 * 1024;
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}
fn current_sid() -> io::Result<String> {
    match security::process_owner()? {
        Owner::WindowsUser { sid } => Ok(sid),
        _ => Err(denied()),
    }
}
fn pipe_name(context: &str) -> io::Result<Vec<u16>> {
    if context.len() != 32 || !context.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(denied());
    }
    Ok(wide(&format!(r"\\.\pipe\aivpn-classic-{context}")))
}

/// Тот же проверенный объект, который использует установка службы.
pub struct TrustedClassicImage(crate::state::TrustedImage);
impl TrustedClassicImage {
    pub fn open(path: &std::path::Path) -> io::Result<Self> {
        Ok(Self(crate::state::TrustedImage::open(path)?))
    }
    pub fn shell_path(&self) -> io::Result<std::path::PathBuf> {
        self.0.shell_path()
    }
}

/// Удержанные процесс и файл исключают переиспользование PID и замену образа.
pub struct ClassicPeer {
    process: Handle,
    _image: Handle,
}
impl ClassicPeer {
    fn verify(pid: u32) -> io::Result<Self> {
        let process = Handle::new(unsafe {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid)
        })?;
        if unsafe { WaitForSingleObject(process.raw(), 0) } != WAIT_TIMEOUT {
            return Err(denied());
        }
        let mut token = ptr::null_mut();
        check(unsafe { OpenProcessToken(process.raw(), TOKEN_QUERY, &mut token) })?;
        let token = Handle::new(token)?;
        if security::user_sid(token.raw())? != current_sid()? {
            return Err(denied());
        }
        let mut path = vec![0u16; 32768];
        let mut size = path.len() as u32;
        check(unsafe {
            QueryFullProcessImageNameW(process.raw(), 0, path.as_mut_ptr(), &mut size)
        })?;
        path.truncate(size as usize);
        path.push(0);
        let image = open_image(&path)?;
        let own = std::env::current_exe()?;
        let own = open_image(&own.as_os_str().encode_wide().chain([0]).collect::<Vec<_>>())?;
        if image_id(&image)? != image_id(&own)? && digest(&image)? != digest(&own)? {
            return Err(denied());
        }
        Ok(Self {
            process,
            _image: image,
        })
    }
    pub fn raw_process(&self) -> std::os::windows::io::RawHandle {
        self.process.raw()
    }
}
fn open_image(path: &[u16]) -> io::Result<Handle> {
    Handle::new(unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    })
}
fn image_id(image: &Handle) -> io::Result<(u32, u32, u32)> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    check(unsafe { GetFileInformationByHandle(image.raw(), &mut info) })?;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
        return Err(denied());
    }
    Ok((
        info.dwVolumeSerialNumber,
        info.nFileIndexHigh,
        info.nFileIndexLow,
    ))
}

/// Переносимая копия и установленный EXE могут иметь разные inode, но должны
/// содержать тот же образ. Оба файла закрыты для записи и rename до конца сеанса.
fn digest(handle: &Handle) -> io::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::from(handle.try_clone()?.into_owned());
    if file.metadata()?.len() > 512 * 1024 * 1024 {
        return Err(denied());
    }
    let mut hash = Sha256::new();
    let mut bytes = [0; 32768];
    loop {
        let size = file.read(&mut bytes)?;
        if size == 0 {
            break;
        }
        hash.update(&bytes[..size]);
    }
    Ok(hash.finalize().into())
}

pub struct ClassicListener {
    handle: Handle,
}
impl ClassicListener {
    pub fn bind(context: &str) -> io::Result<Self> {
        let name = pipe_name(context)?;
        let sid = current_sid()?;
        let text = wide(&format!(
            "O:{sid}G:{sid}D:P(A;;GA;;;{sid})(A;;GA;;;BA)(A;;GA;;;SY)"
        ));
        let mut raw = ptr::null_mut();
        check(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut raw,
                ptr::null_mut(),
            )
        })?;
        let descriptor = security::Descriptor(raw);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let handle = Handle::new(unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                LIMIT as u32,
                LIMIT as u32,
                0,
                &attributes,
            )
        })?;
        Ok(Self { handle })
    }
    pub fn accept(
        self,
        child: u32,
        timeout: Duration,
    ) -> io::Result<(ClassicChannel, ClassicPeer)> {
        let mut op = api::Operation::new(&self.handle)?;
        let result = unsafe { ConnectNamedPipe(self.handle.raw(), op.pointer()) };
        if result != 0 || unsafe { GetLastError() } != ERROR_PIPE_CONNECTED {
            op.started(result)?;
            op.finish(Instant::now() + timeout, &AtomicBool::new(false))?;
        }
        drop(op);
        let mut pid = 0;
        check(unsafe { GetNamedPipeClientProcessId(self.handle.raw(), &mut pid) })?;
        if pid != child {
            return Err(denied());
        }
        let peer = ClassicPeer::verify(pid)?;
        Ok((
            ClassicChannel {
                handle: self.handle,
            },
            peer,
        ))
    }
}

pub struct ClassicChannel {
    handle: Handle,
}
impl ClassicChannel {
    pub fn connect(context: &str, parent: u32) -> io::Result<(Self, ClassicPeer)> {
        if !security::is_admin()? {
            return Err(denied());
        }
        let peer = ClassicPeer::verify(parent)?;
        let name = pipe_name(context)?;
        let handle = Handle::new(unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        })?;
        let mut pid = 0;
        check(unsafe { GetNamedPipeServerProcessId(handle.raw(), &mut pid) })?;
        if pid != parent {
            return Err(denied());
        }
        Ok((Self { handle }, peer))
    }
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            handle: self.handle.try_clone()?,
        })
    }
    pub fn send(&self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > LIMIT {
            return Err(api::invalid());
        }
        api::send(
            &self.handle,
            payload,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
        )
    }
    pub fn receive(&self, timeout: Duration) -> io::Result<Vec<u8>> {
        let payload = api::receive(
            &self.handle,
            Instant::now() + timeout,
            &AtomicBool::new(false),
        )?;
        if payload.len() > LIMIT {
            return Err(api::invalid());
        }
        Ok(payload)
    }
    /// Нулевой расход CPU в простое; завершение владельца будит операцию ядра.
    pub fn receive_owned(&self, owner: &ClassicPeer) -> io::Result<Vec<u8>> {
        let mut first = [0u8];
        let mut op = api::Operation::new(&self.handle)?;
        let result = unsafe {
            ReadFile(
                self.handle.raw(),
                first.as_mut_ptr(),
                1,
                ptr::null_mut(),
                op.pointer(),
            )
        };
        op.started(result)?;
        if op.finish_idle(&owner.process)? != 1 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        drop(op);
        let deadline = Instant::now() + Duration::from_secs(5);
        let stop = AtomicBool::new(false);
        let mut length = [first[0], 0, 0, 0];
        api::read(&self.handle, &mut length[1..], deadline, &stop)?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > LIMIT {
            return Err(api::invalid());
        }
        let mut payload = vec![0; length];
        api::read(&self.handle, &mut payload, deadline, &stop)?;
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn context_cannot_select_another_pipe_or_remote_host() {
        assert!(pipe_name("0123456789abcdef0123456789abcdef").is_ok());
        for input in [
            "",
            r"\\server\pipe\test",
            "../aivpn",
            "0123456789abcdef0123456789abcdef00",
        ] {
            assert!(pipe_name(input).is_err());
        }
    }
}
