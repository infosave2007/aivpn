use super::{invalid, KernelWriter};
use crate::linux::kernel::image::result;
use crate::linux::kernel::objects::read_array;
use crate::linux::LocatedExecutable;
use std::io;
use std::os::fd::{AsFd, AsRawFd};

unsafe extern "C" {
    fn bpf_map_lookup_elem(
        fd: i32,
        key: *const std::ffi::c_void,
        value: *mut std::ffi::c_void,
    ) -> i32;
    fn bpf_map_update_elem(
        fd: i32,
        key: *const std::ffi::c_void,
        value: *const std::ffi::c_void,
        flags: u64,
    ) -> i32;
    fn ar_allocate_file_cookie(program: i32) -> i32;
}

trait Storage {
    fn lookup(&self) -> io::Result<u64>;
    fn allocate(&self) -> io::Result<u64>;
    fn insert(&self, candidate: u64) -> io::Result<()>;
}

pub(super) fn acquire(writer: &KernelWriter, file: &LocatedExecutable) -> io::Result<u64> {
    file.verify()?;
    let storage = InodeStorage {
        writer,
        file: file.as_fd().as_raw_fd(),
    };
    let cookie = get_or_insert(&storage)?;
    file.verify()?;
    Ok(cookie)
}

fn nonzero(cookie: u64) -> io::Result<u64> {
    if cookie == 0 {
        return Err(invalid());
    }
    Ok(cookie)
}

fn get_or_insert(storage: &impl Storage) -> io::Result<u64> {
    if let Some(cookie) = existing(storage)? {
        return Ok(cookie);
    }
    let candidate = nonzero(storage.allocate()?)?;
    for _ in 0..4 {
        let inserted = insert_or_race(storage, candidate)?;
        if let Some(cookie) = readback(storage, candidate, inserted)? {
            return Ok(cookie);
        }
    }
    Err(io::Error::from_raw_os_error(libc::EAGAIN))
}
fn existing(storage: &impl Storage) -> io::Result<Option<u64>> {
    match storage.lookup() {
        Ok(cookie) => nonzero(cookie).map(Some),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(error) => Err(error),
    }
}
fn readback(storage: &impl Storage, candidate: u64, inserted: bool) -> io::Result<Option<u64>> {
    match storage.lookup() {
        Ok(cookie) if !inserted || cookie == candidate => nonzero(cookie).map(Some),
        Err(error) if !inserted && error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        _ => Err(invalid()),
    }
}

fn insert_or_race(storage: &impl Storage, candidate: u64) -> io::Result<bool> {
    match storage.insert(candidate) {
        Ok(()) => Ok(true),
        Err(error) if matches!(error.raw_os_error(), Some(libc::EEXIST | libc::EAGAIN)) => {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

struct InodeStorage<'a> {
    writer: &'a KernelWriter,
    file: i32,
}
impl Storage for InodeStorage<'_> {
    fn lookup(&self) -> io::Result<u64> {
        let mut value = 0;
        result(unsafe {
            bpf_map_lookup_elem(
                self.writer.kernel.map(c"inode_tokens")?.as_raw_fd(),
                (&self.file as *const i32).cast(),
                (&mut value as *mut u64).cast(),
            )
        })?;
        Ok(value)
    }
    fn allocate(&self) -> io::Result<u64> {
        result(unsafe {
            ar_allocate_file_cookie(
                self.writer
                    .kernel
                    .program(c"allocate_file_cookie")?
                    .as_raw_fd(),
            )
        })?;
        Ok(u64::from_ne_bytes(read_array::<8>(
            self.writer.kernel.map(c"file_result")?,
        )?))
    }
    fn insert(&self, candidate: u64) -> io::Result<()> {
        result(unsafe {
            bpf_map_update_elem(
                self.writer.kernel.map(c"inode_tokens")?.as_raw_fd(),
                (&self.file as *const i32).cast(),
                (&candidate as *const u64).cast(),
                1,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    struct Script {
        lookup: RefCell<VecDeque<Result<u64, i32>>>,
        insert: RefCell<VecDeque<Result<(), i32>>>,
        allocation: Result<u64, i32>,
        candidates: RefCell<Vec<u64>>,
    }
    impl Storage for Script {
        fn lookup(&self) -> io::Result<u64> {
            self.lookup
                .borrow_mut()
                .pop_front()
                .expect("лишний lookup")
                .map_err(io::Error::from_raw_os_error)
        }
        fn allocate(&self) -> io::Result<u64> {
            self.allocation.map_err(io::Error::from_raw_os_error)
        }
        fn insert(&self, candidate: u64) -> io::Result<()> {
            self.candidates.borrow_mut().push(candidate);
            self.insert
                .borrow_mut()
                .pop_front()
                .expect("лишний insert")
                .map_err(io::Error::from_raw_os_error)
        }
    }
    fn script(
        lookups: Vec<Result<u64, i32>>,
        inserts: Vec<Result<(), i32>>,
        allocation: Result<u64, i32>,
    ) -> Script {
        Script {
            lookup: RefCell::new(lookups.into()),
            insert: RefCell::new(inserts.into()),
            allocation,
            candidates: RefCell::new(Vec::new()),
        }
    }
    #[test]
    fn injected_cookie_winner_is_never_overwritten() {
        for race in [libc::EEXIST, libc::EAGAIN] {
            let storage = script(vec![Err(libc::ENOENT), Ok(73)], vec![Err(race)], Ok(72));
            assert_eq!(get_or_insert(&storage).unwrap(), 73);
            assert_eq!(*storage.candidates.borrow(), vec![72]);
        }
        let storage = script(vec![Ok(73)], vec![], Err(libc::ENOSPC));
        assert_eq!(get_or_insert(&storage).unwrap(), 73);
        assert!(storage.candidates.borrow().is_empty());
    }
    #[test]
    fn injected_cookie_errors_refuse_without_replacement_or_counter_rollback() {
        for allocation in [Ok(0), Err(libc::ENOSPC)] {
            let storage = script(vec![Err(libc::ENOENT)], vec![], allocation);
            assert!(get_or_insert(&storage).is_err());
            assert!(storage.candidates.borrow().is_empty());
        }
        for readback in [Ok(0), Ok(74), Err(libc::EIO)] {
            let storage = script(vec![Err(libc::ENOENT), readback], vec![Ok(())], Ok(72));
            assert!(get_or_insert(&storage).is_err());
        }
        let storage = script(vec![Ok(0)], vec![], Ok(72));
        assert!(get_or_insert(&storage).is_err());
        let storage = script(vec![Err(libc::ENOENT)], vec![Err(libc::ENOMEM)], Ok(72));
        assert_eq!(
            get_or_insert(&storage).unwrap_err().raw_os_error(),
            Some(libc::ENOMEM)
        );
    }
    #[test]
    fn injected_allocation_retry_is_bounded_and_burns_only_one_candidate() {
        let storage = script(
            vec![Err(libc::ENOENT); 5],
            vec![Err(libc::EAGAIN); 4],
            Ok(72),
        );
        assert_eq!(
            get_or_insert(&storage).unwrap_err().raw_os_error(),
            Some(libc::EAGAIN)
        );
        assert_eq!(*storage.candidates.borrow(), vec![72; 4]);
        let storage = script(
            vec![Err(libc::ENOENT), Err(libc::ENOENT), Ok(72)],
            vec![Err(libc::EAGAIN), Ok(())],
            Ok(72),
        );
        assert_eq!(get_or_insert(&storage).unwrap(), 72);
    }
}
