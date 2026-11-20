use super::{invalid, record::id};
use crate::linux::kernel::objects::open_pin;
use crate::linux::kernel::pins::{bpffs_root, open_directory_at};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

pub(super) const LIMIT: usize = 4096;
unsafe extern "C" {
    fn bpf_obj_pin(fd: i32, path: *const libc::c_char) -> i32;
}

pub(super) fn base(namespace: [u8; 16], create: bool) -> io::Result<File> {
    named_base(namespace, c"aivpn_app_retainers", create)
}

pub(super) fn named_base(namespace: [u8; 16], name: &CStr, create: bool) -> io::Result<File> {
    let root = bpffs_root()?;
    let base = directory(&root, name, create)?;
    let name = CString::new(
        namespace
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
    .unwrap();
    directory(&base, &name, create)
}

pub(super) fn directory(parent: &File, name: &CStr, create: bool) -> io::Result<File> {
    if create && unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(error);
        }
    }
    let child = open_directory_at(parent, name)?;
    if parent.metadata()?.dev() != child.metadata()?.dev() {
        return Err(invalid());
    }
    Ok(child)
}

pub(super) fn names(directory: &File, limit: usize) -> io::Result<Vec<CString>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(format!("/proc/thread-self/fd/{}", directory.as_raw_fd()))? {
        if names.len() == limit {
            return Err(io::Error::other("Лимит удержаний исчерпан"));
        }
        names.push(CString::new(entry?.file_name().as_bytes()).map_err(|_| invalid())?);
    }
    names.sort();
    Ok(names)
}

pub(super) fn completed_name(link: u32) -> CString {
    CString::new(format!("link_{link:08x}")).unwrap()
}

pub(super) fn open_record(parent: &File, name: &CStr) -> io::Result<File> {
    let directory = directory(parent, name, false)?;
    if names(&directory, 3)?
        != [
            c"instance".to_owned(),
            c"link".to_owned(),
            c"record".to_owned(),
        ]
    {
        return Err(invalid());
    }
    Ok(directory)
}

pub(super) struct Creation<'a> {
    parent: &'a File,
    directory: File,
    name: CString,
    pins: Vec<(CString, u32)>,
    committed: bool,
}

impl<'a> Creation<'a> {
    pub fn new(parent: &'a File, link: u32) -> io::Result<Self> {
        let name = CString::new(format!("pending_{link:08x}")).unwrap();
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            parent,
            directory: directory(parent, &name, false)?,
            name,
            pins: Vec::new(),
            committed: false,
        })
    }
    pub fn pin(&mut self, name: &CStr, fd: &OwnedFd) -> io::Result<()> {
        let object_id = id(fd)?;
        let path = CString::new(format!(
            "/proc/thread-self/fd/{}/{}",
            self.directory.as_raw_fd(),
            name.to_str().unwrap()
        ))
        .unwrap();
        crate::linux::kernel::image::result(unsafe { bpf_obj_pin(fd.as_raw_fd(), path.as_ptr()) })?;
        self.pins.push((name.to_owned(), object_id));
        if unsafe { libc::fchmodat(self.directory.as_raw_fd(), name.as_ptr(), 0o600, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if id(&open_pin(&self.directory, name)?)? != object_id {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn commit(mut self, link: u32) -> io::Result<()> {
        rename(self.parent, &self.name, &completed_name(link))?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for Creation<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for (name, expected) in self.pins.iter().rev() {
            let _ = remove(&self.directory, name, *expected);
        }
        let _ = remove_directory(self.parent, &self.name, &self.directory);
    }
}

pub(super) fn remove(directory: &File, name: &CStr, expected: u32) -> io::Result<()> {
    if id(&open_pin(directory, name)?)? != expected {
        return Err(invalid());
    }
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn remove_directory(parent: &File, name: &CStr, held: &File) -> io::Result<()> {
    let current = directory(parent, name, false)?;
    if current.metadata()?.ino() != held.metadata()?.ino() {
        return Err(invalid());
    }
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn rename(parent: &File, from: &CStr, to: &CStr) -> io::Result<()> {
    if unsafe {
        libc::renameat2(
            parent.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
