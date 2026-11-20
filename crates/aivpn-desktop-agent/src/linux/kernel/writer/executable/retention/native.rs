use crate::linux::kernel::image::result;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

unsafe extern "C" {
    fn ar_retention_attach(program: i32, file: i32) -> i32;
    fn ar_retention_inspect(
        fd: i32,
        program: u32,
        link: u32,
        pid: u32,
        creating: i32,
        ids: *mut u32,
    ) -> i32;
    fn ar_retention_record(bytes: *const u8, length: u32) -> i32;
}

pub(super) fn attach(program: &OwnedFd, file: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    descriptor(unsafe { ar_retention_attach(program.as_raw_fd(), file.as_raw_fd()) })
}

pub(super) fn inspect(
    fd: &OwnedFd,
    program: u32,
    link: u32,
    pid: u32,
    creating: bool,
) -> io::Result<[u32; 3]> {
    let mut ids = [0; 3];
    result(unsafe {
        ar_retention_inspect(
            fd.as_raw_fd(),
            program,
            link,
            pid,
            creating.into(),
            ids.as_mut_ptr(),
        )
    })?;
    Ok(ids)
}

pub(super) fn record(bytes: &[u8]) -> io::Result<OwnedFd> {
    descriptor(unsafe { ar_retention_record(bytes.as_ptr(), bytes.len() as u32) })
}

fn descriptor(raw: i32) -> io::Result<OwnedFd> {
    if raw < 0 {
        return Err(io::Error::from_raw_os_error(-raw));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}
