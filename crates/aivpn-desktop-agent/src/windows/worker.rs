//! Работник получает только заранее открытые каналы и ограниченный primary token.
mod administration;
mod desktop;
mod process;
mod token;
mod transport;
pub use process::{verify_current_worker, WorkerProcess};
pub use token::verify_worker_token;
pub use transport::{endpoint, SharedTransport, Winsock};

/// Канал передан по allowlist и должен вести к той же службе, что и control.
pub fn administration_handle(handle: OwnedHandle, service_pid: u32) -> io::Result<OwnedHandle> {
    let channel = WorkerChannel::from_owned(handle)?;
    if channel.server_pid()? != service_pid {
        return Err(denied());
    }
    Ok(channel.handle.into_owned())
}

use super::api::{self, check, denied, Handle};
use std::{
    io,
    os::windows::io::{AsRawHandle, IntoRawHandle, OwnedHandle},
    ptr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{Pipes::*, Threading::GetCurrentProcessId},
};

const FRAME_LIMIT: usize = 65536;
static NEXT_PIPE: AtomicU64 = AtomicU64::new(1);

pub struct WorkerChannel {
    handle: Handle,
    packet_frame: Vec<u8>,
    wake: Option<Arc<dyn Fn() -> io::Result<()> + Send + Sync>>,
}
impl WorkerChannel {
    /// Переданный handle уже является полномочием; повторного открытия по имени нет.
    pub fn from_owned(handle: OwnedHandle) -> io::Result<Self> {
        if unsafe { GetFileType(handle.as_raw_handle()) } != FILE_TYPE_PIPE {
            return Err(denied());
        }
        check(unsafe { SetHandleInformation(handle.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) })?;
        Ok(Self {
            handle: Handle::new(handle.into_raw_handle())?,
            packet_frame: Vec::new(),
            wake: None,
        })
    }
    pub fn with_wakeup(mut self, wake: Arc<dyn Fn() -> io::Result<()> + Send + Sync>) -> Self {
        self.wake = Some(wake);
        self
    }
    pub fn server_pid(&self) -> io::Result<u32> {
        let mut pid = 0;
        check(unsafe { GetNamedPipeServerProcessId(self.handle.raw(), &mut pid) })?;
        if pid == 0 {
            return Err(denied());
        }
        Ok(pid)
    }
    pub fn readable(&self) -> io::Result<bool> {
        let mut available = 0;
        check(unsafe {
            PeekNamedPipe(
                self.handle.raw(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut available,
                ptr::null_mut(),
            )
        })?;
        Ok(available != 0)
    }
    pub fn send(&self, bytes: &[u8], timeout: Duration) -> io::Result<()> {
        if bytes.is_empty() || bytes.len() > FRAME_LIMIT {
            return Err(api::invalid());
        }
        let deadline = Instant::now() + timeout;
        let stop = AtomicBool::new(false);
        api::write(
            &self.handle,
            &(bytes.len() as u32).to_be_bytes(),
            deadline,
            &stop,
        )?;
        if let Some(wake) = &self.wake {
            // Заголовок будит читателя до записи тела, которое может ждать свободного буфера.
            wake()?;
        }
        api::write(&self.handle, bytes, deadline, &stop)
    }
    pub fn receive(&self, timeout: Duration) -> io::Result<Vec<u8>> {
        let result = api::receive(
            &self.handle,
            Instant::now() + timeout,
            &AtomicBool::new(false),
        )?;
        if result.len() > FRAME_LIMIT {
            return Err(api::invalid());
        }
        Ok(result)
    }
    pub fn packet_send(&mut self, generation: u64, packet: &[u8]) -> io::Result<()> {
        if generation == 0 || !(20..=65535).contains(&packet.len()) {
            return Err(api::invalid());
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        let stop = AtomicBool::new(false);
        self.packet_frame.clear();
        self.packet_frame
            .extend_from_slice(&(packet.len() as u32).to_le_bytes());
        self.packet_frame
            .extend_from_slice(&generation.to_le_bytes());
        self.packet_frame.extend_from_slice(packet);
        api::write(&self.handle, &self.packet_frame, deadline, &stop)
    }
    pub fn packet_receive(
        &mut self,
        generation: u64,
        buffer: &mut [u8],
    ) -> io::Result<Option<usize>> {
        let deadline = Instant::now() + Duration::from_secs(2);
        let stop = AtomicBool::new(false);
        let mut header = [0; 12];
        let mut peeked = 0;
        let mut available = 0;
        check(unsafe {
            PeekNamedPipe(
                self.handle.raw(),
                header.as_mut_ptr().cast(),
                header.len() as u32,
                &mut peeked,
                &mut available,
                ptr::null_mut(),
            )
        })?;
        if peeked as usize == header.len() {
            let (size, current) = packet_header(&header, generation, buffer.len())?;
            if available as usize >= header.len() + size {
                // Один читатель забирает только готовый кадр, оставляя следующий в pipe.
                self.packet_frame.resize(header.len() + size, 0);
                api::read(&self.handle, &mut self.packet_frame, deadline, &stop)?;
                buffer[..size].copy_from_slice(&self.packet_frame[header.len()..]);
                return Ok(current.then_some(size));
            }
        }
        // Неполный кадр читается частями, чтобы большой writer не ждал полного буфера.
        api::read(&self.handle, &mut header, deadline, &stop)?;
        let (size, current) = packet_header(&header, generation, buffer.len())?;
        api::read(&self.handle, &mut buffer[..size], deadline, &stop)?;
        Ok(current.then_some(size))
    }
}

fn packet_header(header: &[u8; 12], generation: u64, capacity: usize) -> io::Result<(usize, bool)> {
    let size = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
    if !(20..=65535).contains(&size) || size > capacity {
        return Err(api::invalid());
    }
    let received = u64::from_le_bytes(header[4..].try_into().unwrap());
    if generation == 0 || received == 0 || received > generation {
        return Err(denied());
    }
    Ok((size, received == generation))
}

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn channel_pair() -> io::Result<(WorkerChannel, OwnedHandle)> {
    let serial = NEXT_PIPE
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
        .map_err(|_| denied())?;
    let name = process::wide(&format!(r"\\.\pipe\aivpn-worker-{}-{serial}", unsafe {
        GetCurrentProcessId()
    }));
    let sddl = process::wide("O:SYG:SYD:P(A;;GA;;;SY)");
    let mut raw = ptr::null_mut();
    check(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut raw,
            ptr::null_mut(),
        )
    })?;
    let descriptor = Descriptor(raw);
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let server = Handle::new(unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            131072,
            131072,
            0,
            &attributes,
        )
    })?;
    attributes.bInheritHandle = 1;
    let client = process::owned(unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            &attributes,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            ptr::null_mut(),
        )
    })?;
    // Client создается службой до spawn. Привязка к ребенку опирается на handle allowlist.
    let mut op = api::Operation::new(&server)?;
    let result = unsafe { ConnectNamedPipe(server.raw(), op.pointer()) };
    if result != 0 || unsafe { GetLastError() } != ERROR_PIPE_CONNECTED {
        op.started(result)?;
        op.finish(
            Instant::now() + Duration::from_secs(2),
            &AtomicBool::new(false),
        )?;
    }
    drop(op);
    Ok((
        WorkerChannel {
            handle: server,
            packet_frame: Vec::new(),
            wake: None,
        },
        client,
    ))
}
