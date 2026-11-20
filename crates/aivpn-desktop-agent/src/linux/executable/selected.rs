use super::{invalid_executable, FileStamp};
use crate::linux::filesystem::mount_id;
use std::collections::VecDeque;
use std::ffi::CString;
use std::fs::{File, Metadata};
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const MAX_PATH: usize = 4095;
const MAX_STEPS: usize = 256;
const MAX_BYTES: usize = 64 * 1024;
const MAX_LINKS: usize = 40;

pub(super) struct ChainProof {
    steps: Vec<Step>,
    source_anchor: Option<(usize, Vec<u8>)>,
}

struct Step {
    descriptor: File,
    identity: Identity,
    link: Option<Link>,
}

#[derive(PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    mount: u64,
    kind: u32,
}

#[derive(PartialEq, Eq)]
struct Link {
    modified: (i64, i64),
    changed: (i64, i64),
    mode: u32,
    target: Vec<u8>,
}

struct Walk {
    proof: ChainProof,
    pending: VecDeque<Vec<u8>>,
    directory: usize,
    links: usize,
    bytes: usize,
}

impl ChainProof {
    pub(super) fn capture(source: &Path) -> io::Result<(Self, File)> {
        if !source.is_absolute() {
            return Err(invalid_executable());
        }
        let path = source.as_os_str().as_bytes();
        // Полный kernel lookup проверяет также trailing slash и общий лимит ссылок.
        let before = Target::open(path, libc::O_PATH)?;
        let proof = Walk::new(path)?.finish()?;
        before.verify(&proof.last()?.descriptor)?;
        let target = Target::open(path, libc::O_RDONLY | libc::O_NONBLOCK)?;
        before.verify(&target.descriptor)?;
        Ok((proof, target.descriptor))
    }

    fn last(&self) -> io::Result<&Step> {
        self.steps.last().ok_or_else(invalid_executable)
    }

    pub(super) fn verify(&self, source: &Path) -> io::Result<File> {
        let (current, descriptor) = Self::capture(source)?;
        if self.steps.len() != current.steps.len() || self.source_anchor != current.source_anchor {
            return Err(invalid_executable());
        }
        for (held, now) in self.steps.iter().zip(&current.steps) {
            held.verify()?;
            held.same_as(now)?;
        }
        Ok(descriptor)
    }

    #[cfg(feature = "linux-kernel")]
    pub(super) fn source_anchor(&self) -> io::Result<(File, Vec<u8>)> {
        let (index, suffix) = self.source_anchor.as_ref().ok_or_else(invalid_executable)?;
        let parent = self.steps.get(*index).ok_or_else(invalid_executable)?;
        parent.verify()?;
        Ok((parent.descriptor.try_clone()?, suffix.clone()))
    }
}

struct Target {
    descriptor: File,
    stamp: FileStamp,
    mount: u64,
}

impl Target {
    fn open(path: &[u8], flags: i32) -> io::Result<Self> {
        let descriptor = open_at(libc::AT_FDCWD, path, flags)?;
        Ok(Self {
            stamp: FileStamp::read(descriptor.metadata()?)?,
            mount: mount_id(descriptor.as_fd())?,
            descriptor,
        })
    }

    fn verify(&self, descriptor: &File) -> io::Result<()> {
        self.stamp.verify(descriptor.metadata())?;
        if mount_id(descriptor.as_fd())? != self.mount {
            return Err(invalid_executable());
        }
        Ok(())
    }
}

impl Walk {
    fn finish(mut self) -> io::Result<ChainProof> {
        while let Some(name) = self.pending.pop_front() {
            self.advance(&name)?;
        }
        Ok(self.proof)
    }

    fn new(path: &[u8]) -> io::Result<Self> {
        let root = Step::read(open_at(
            libc::AT_FDCWD,
            b"/",
            libc::O_PATH | libc::O_DIRECTORY,
        )?)?;
        let mut walk = Self {
            proof: ChainProof {
                steps: vec![root],
                source_anchor: None,
            },
            pending: VecDeque::new(),
            directory: 0,
            links: 0,
            bytes: 0,
        };
        walk.prepend(path)?;
        Ok(walk)
    }

    fn prepend(&mut self, path: &[u8]) -> io::Result<()> {
        self.bytes += path.len();
        if path.len() > MAX_PATH || self.bytes > MAX_BYTES {
            return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
        }
        // Не используем Path::components: точки и .. должен разрешать kernel.
        for name in path
            .rsplit(|byte| *byte == b'/')
            .filter(|name| !name.is_empty())
        {
            self.pending.push_front(name.to_vec());
        }
        if self.pending.len() + self.proof.steps.len() > MAX_STEPS {
            return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
        }
        Ok(())
    }

    fn advance(&mut self, name: &[u8]) -> io::Result<()> {
        if self.proof.steps.len() == MAX_STEPS {
            return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
        }
        let directory = self.proof.steps[self.directory].descriptor.as_raw_fd();
        let descriptor = open_at(directory, name, libc::O_PATH | libc::O_NOFOLLOW)?;
        let metadata = descriptor.metadata()?;
        if self.proof.source_anchor.is_none()
            && (metadata.file_type().is_symlink() || self.pending.is_empty())
        {
            let mut suffix = name.to_vec();
            for component in &self.pending {
                suffix.push(b'/');
                suffix.extend_from_slice(component);
            }
            if suffix.len() > MAX_PATH {
                return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
            }
            self.proof.source_anchor = Some((self.directory, suffix));
        }
        if metadata.file_type().is_symlink() {
            self.follow_link(directory, name, descriptor)?;
        } else {
            if !self.pending.is_empty() && !metadata.is_dir() {
                return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
            }
            self.directory = self.proof.steps.len();
            self.proof.steps.push(Step::read(descriptor)?);
        }
        Ok(())
    }

    fn follow_link(&mut self, directory: i32, name: &[u8], descriptor: File) -> io::Result<()> {
        self.links += 1;
        if self.links > MAX_LINKS {
            return Err(io::Error::from_raw_os_error(libc::ELOOP));
        }
        // O_PATH | O_NOFOLLOW допускает FD magic link. Отдельный lookup без
        // NOFOLLOW обязан успешно пройти тот же entry с NO_MAGICLINKS.
        let held = Step::read(descriptor)?;
        held.verify_entry(directory, name)?;
        let target = &held.link.as_ref().ok_or_else(invalid_executable)?.target;
        if target.starts_with(b"/") {
            self.directory = 0;
        }
        self.prepend(target)?;
        self.proof.steps.push(held);
        Ok(())
    }
}

impl Step {
    fn verify_entry(&self, directory: i32, name: &[u8]) -> io::Result<()> {
        open_at(directory, name, libc::O_PATH)?;
        let checked = Self::read(open_at(directory, name, libc::O_PATH | libc::O_NOFOLLOW)?)?;
        self.same_as(&checked)
    }

    fn same_as(&self, other: &Self) -> io::Result<()> {
        if self.identity != other.identity || self.link != other.link {
            return Err(invalid_executable());
        }
        Ok(())
    }

    fn read(descriptor: File) -> io::Result<Self> {
        let metadata = descriptor.metadata()?;
        let identity = Identity::read(&descriptor, &metadata)?;
        let link = Link::read(&descriptor, &metadata)?;
        Ok(Self {
            descriptor,
            identity,
            link,
        })
    }

    fn verify(&self) -> io::Result<()> {
        let metadata = self.descriptor.metadata()?;
        if self.identity != Identity::read(&self.descriptor, &metadata)?
            || self.link != Link::read(&self.descriptor, &metadata)?
        {
            return Err(invalid_executable());
        }
        Ok(())
    }
}

impl Identity {
    fn read(descriptor: &File, metadata: &Metadata) -> io::Result<Self> {
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mount: mount_id(descriptor.as_fd())?,
            kind: metadata.mode() & libc::S_IFMT,
        })
    }
}

impl Link {
    fn read(descriptor: &File, metadata: &Metadata) -> io::Result<Option<Self>> {
        if !metadata.file_type().is_symlink() {
            return Ok(None);
        }
        let mut target = vec![0; MAX_PATH + 1];
        let length = unsafe {
            libc::syscall(
                libc::SYS_readlinkat,
                descriptor.as_raw_fd(),
                c"".as_ptr(),
                target.as_mut_ptr(),
                target.len(),
            )
        };
        if length < 0 {
            return Err(io::Error::last_os_error());
        }
        if length as usize > MAX_PATH {
            return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
        }
        target.truncate(length as usize);
        Ok(Some(Self {
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
            mode: metadata.mode(),
            target,
        }))
    }
}

fn open_at(directory: i32, path: &[u8], flags: i32) -> io::Result<File> {
    if path.len() > MAX_PATH {
        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    let path = CString::new(path).map_err(|_| invalid_executable())?;
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (flags | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_NO_MAGICLINKS;
    let raw = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory,
            path.as_ptr(),
            &how,
            std::mem::size_of_val(&how),
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(raw as i32) })
}
