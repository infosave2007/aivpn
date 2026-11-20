//! Дополнительный socketpair создается службой и передается после ограничения работника.
use super::{decode_payload, link::AdministrationLink, MAX_ADMIN_FRAME_BYTES};
use std::{
    io::{self, Read},
    net::Shutdown,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    time::{Duration, Instant},
};

pub(crate) fn pair(generation: u64) -> io::Result<(AdministrationLink, OwnedFd)> {
    let (root, worker) = UnixStream::pair()?;
    let writer = root.try_clone()?;
    let shutdown = root.try_clone()?;
    let mut reader = root;
    let link = AdministrationLink::new(
        generation,
        move |payload| {
            if payload.is_empty() || payload.len() > MAX_ADMIN_FRAME_BYTES {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            write_all(&writer, &(payload.len() as u32).to_be_bytes(), deadline)?;
            write_all(&writer, payload, deadline)
        },
        move || {
            // Не будим простаивающую службу. shutdown прерывает ожидание первого байта.
            reader.set_read_timeout(None)?;
            let mut header = [0; 4];
            reader.read_exact(&mut header[..1])?;
            let deadline = Instant::now() + Duration::from_secs(5);
            read_all(&mut reader, &mut header[1..], deadline)?;
            let length = u32::from_be_bytes(header) as usize;
            if length == 0 || length > MAX_ADMIN_FRAME_BYTES {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let mut payload = vec![0; length];
            read_all(&mut reader, &mut payload, deadline)?;
            decode_payload(&payload)
        },
        move || {
            let _ = shutdown.shutdown(Shutdown::Both);
        },
    )?;
    Ok((link, worker.into()))
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
}
fn write_all(stream: &UnixStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        let count = unsafe {
            libc::send(
                stream.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if count == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        bytes = &bytes[count as usize..];
    }
    Ok(())
}
fn read_all(stream: &mut UnixStream, mut bytes: &mut [u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
