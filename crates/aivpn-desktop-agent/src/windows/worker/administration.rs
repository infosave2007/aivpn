//! Приватный канал управления использует тот же codec, что и Linux-работник.
use super::{
    super::api::{self, check, Handle},
    channel_pair,
};
use crate::administration::{decode_payload, link::AdministrationLink, MAX_ADMIN_FRAME_BYTES};
use std::{
    io,
    os::windows::io::OwnedHandle,
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Storage::FileSystem::ReadFile,
    System::Threading::{CreateEventW, SetEvent},
};

pub(super) fn pair(generation: u64) -> io::Result<(AdministrationLink, OwnedHandle)> {
    let (channel, child) = channel_pair()?;
    let reader = channel.handle;
    let writer = reader.try_clone()?;
    let stopped = Arc::new(AtomicBool::new(false));
    let read_stop = stopped.clone();
    let write_stop = stopped.clone();
    let event = Handle::new(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) })?;
    let read_event = event.try_clone()?;
    let link = AdministrationLink::new(
        generation,
        move |bytes| {
            if bytes.is_empty() || bytes.len() > MAX_ADMIN_FRAME_BYTES {
                return Err(api::invalid());
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            api::write(
                &writer,
                &(bytes.len() as u32).to_be_bytes(),
                deadline,
                &write_stop,
            )?;
            api::write(&writer, bytes, deadline, &write_stop)
        },
        move || {
            if read_stop.load(Ordering::Acquire) {
                return Err(api::stopped());
            }
            let mut header = [0u8; 4];
            let mut operation = api::Operation::new(&reader)?;
            let started = unsafe {
                ReadFile(
                    reader.raw(),
                    header.as_mut_ptr(),
                    1,
                    ptr::null_mut(),
                    operation.pointer(),
                )
            };
            operation.started(started)?;
            if operation.finish_idle(&read_event)? != 1 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            drop(operation);
            let deadline = Instant::now() + Duration::from_secs(5);
            api::read(&reader, &mut header[1..], deadline, &read_stop)?;
            let length = u32::from_be_bytes(header) as usize;
            if length == 0 || length > MAX_ADMIN_FRAME_BYTES {
                return Err(api::invalid());
            }
            let mut bytes = vec![0; length];
            api::read(&reader, &mut bytes, deadline, &read_stop)?;
            decode_payload(&bytes)
        },
        move || {
            stopped.store(true, Ordering::Release);
            // Событие будит ожидающий I/O без периодического опроса простаивающего канала.
            let _ = check(unsafe { SetEvent(event.raw()) });
        },
    )?;
    Ok((link, child))
}
