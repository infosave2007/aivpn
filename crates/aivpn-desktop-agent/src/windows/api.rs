use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::*,
    System::{Threading::*, IO::*},
};

pub(super) struct Handle(OwnedHandle);
impl Handle {
    pub fn new(raw: HANDLE) -> io::Result<Self> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(unsafe { OwnedHandle::from_raw_handle(raw) }))
    }
    pub fn raw(&self) -> HANDLE {
        self.0.as_raw_handle()
    }
    pub fn try_clone(&self) -> io::Result<Self> {
        self.0.try_clone().map(Self)
    }
    pub fn into_owned(self) -> OwnedHandle {
        self.0
    }
}
pub(super) fn check(value: i32) -> io::Result<()> {
    if value == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
pub(super) fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Не подтверждены полномочия локального канала",
    )
}
pub(super) fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Некорректный кадр управления")
}
pub(super) fn stopped() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "Служба остановлена")
}
pub(super) fn remaining(deadline: Instant, stop: &AtomicBool) -> io::Result<u32> {
    if stop.load(Ordering::Acquire) {
        return Err(stopped());
    }
    let duration = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Истек срок локального запроса"))?;
    Ok(duration.as_millis().clamp(1, 20) as u32)
}

pub(super) struct Operation<'a> {
    pipe: &'a Handle,
    event: Handle,
    overlapped: Box<OVERLAPPED>,
    pending: bool,
}
impl<'a> Operation<'a> {
    pub fn new(pipe: &'a Handle) -> io::Result<Self> {
        let event = Handle::new(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) })?;
        let mut overlapped: Box<OVERLAPPED> = Box::new(unsafe { std::mem::zeroed() });
        overlapped.hEvent = event.raw();
        Ok(Self {
            pipe,
            event,
            overlapped,
            pending: false,
        })
    }
    pub fn pointer(&mut self) -> *mut OVERLAPPED {
        &mut *self.overlapped
    }
    pub fn started(&mut self, result: i32) -> io::Result<()> {
        if result == 0 && unsafe { GetLastError() } != ERROR_IO_PENDING {
            return Err(io::Error::last_os_error());
        }
        self.pending = true;
        Ok(())
    }
    pub fn ready(&self) -> io::Result<bool> {
        match unsafe { WaitForSingleObject(self.event.raw(), 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
    }
    pub fn event(&self) -> HANDLE {
        self.event.raw()
    }
    pub fn finish(&mut self, deadline: Instant, stop: &AtomicBool) -> io::Result<usize> {
        loop {
            let timeout = remaining(deadline, stop)?;
            match unsafe { WaitForSingleObject(self.event.raw(), timeout) } {
                WAIT_OBJECT_0 => break,
                WAIT_TIMEOUT => continue,
                _ => return Err(io::Error::last_os_error()),
            }
        }
        let mut count = 0;
        let result = unsafe { GetOverlappedResult(self.pipe.raw(), self.pointer(), &mut count, 0) };
        self.pending = false;
        check(result)?;
        Ok(count as usize)
    }
    pub fn finish_idle(&mut self, stop: &Handle) -> io::Result<usize> {
        let events = [self.event.raw(), stop.raw()];
        match unsafe { WaitForMultipleObjects(2, events.as_ptr(), 0, INFINITE) } {
            WAIT_OBJECT_0 => {
                let mut count = 0;
                let result =
                    unsafe { GetOverlappedResult(self.pipe.raw(), self.pointer(), &mut count, 0) };
                self.pending = false;
                check(result)?;
                Ok(count as usize)
            }
            value if value == WAIT_OBJECT_0 + 1 => Err(stopped()),
            _ => Err(io::Error::last_os_error()),
        }
    }
}
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        if self.pending {
            unsafe {
                CancelIoEx(self.pipe.raw(), self.pointer());
                let mut count = 0;
                // Буферы и OVERLAPPED остаются живы до подтверждения отмены ядром.
                GetOverlappedResult(self.pipe.raw(), self.pointer(), &mut count, 1);
            }
        }
    }
}

pub(super) fn read(
    pipe: &Handle,
    mut bytes: &mut [u8],
    deadline: Instant,
    stop: &AtomicBool,
) -> io::Result<()> {
    while !bytes.is_empty() {
        remaining(deadline, stop)?;
        let mut op = Operation::new(pipe)?;
        let result = unsafe {
            ReadFile(
                pipe.raw(),
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                ptr::null_mut(),
                op.pointer(),
            )
        };
        op.started(result)?;
        let count = op.finish(deadline, stop)?;
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        bytes = &mut bytes[count..];
    }
    Ok(())
}
pub(super) fn write(
    pipe: &Handle,
    mut bytes: &[u8],
    deadline: Instant,
    stop: &AtomicBool,
) -> io::Result<()> {
    while !bytes.is_empty() {
        remaining(deadline, stop)?;
        let mut op = Operation::new(pipe)?;
        let result = unsafe {
            WriteFile(
                pipe.raw(),
                bytes.as_ptr(),
                bytes.len() as u32,
                ptr::null_mut(),
                op.pointer(),
            )
        };
        op.started(result)?;
        let count = op.finish(deadline, stop)?;
        if count == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        bytes = &bytes[count..];
    }
    Ok(())
}
pub(super) fn receive(pipe: &Handle, deadline: Instant, stop: &AtomicBool) -> io::Result<Vec<u8>> {
    let mut length = [0; 4];
    read(pipe, &mut length[..1], deadline, stop)?;
    // Ожидание операции отдельно от времени передачи уже начатого кадра.
    let deadline = deadline.min(Instant::now() + Duration::from_secs(5));
    read(pipe, &mut length[1..], deadline, stop)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > crate::MAX_FRAME_BYTES {
        return Err(invalid());
    }
    let mut payload = vec![0; length];
    read(pipe, &mut payload, deadline, stop)?;
    Ok(payload)
}
pub(super) fn send(
    pipe: &Handle,
    payload: &[u8],
    deadline: Instant,
    stop: &AtomicBool,
) -> io::Result<()> {
    if payload.is_empty() || payload.len() > crate::MAX_FRAME_BYTES {
        return Err(invalid());
    }
    write(pipe, &(payload.len() as u32).to_be_bytes(), deadline, stop)?;
    write(pipe, payload, deadline, stop)
}
pub(super) const TIMEOUT: Duration = Duration::from_secs(2);
