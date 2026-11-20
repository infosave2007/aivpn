//! Удерживаемый файл запуска. Привязка к картам ядра выполняется отдельно.

use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

mod selected;
use selected::ChainProof;
mod content;

pub struct ExecutableFile {
    descriptor: File,
    source: PathBuf,
    canonical: PathBuf,
    stamp: FileStamp,
    content: [u8; 32],
    source_proof: SourceProof,
}

enum SourceProof {
    Direct,
    Resolved(ChainProof),
}

#[derive(PartialEq, Eq)]
struct FileStamp {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    mode: u32,
}

impl FileStamp {
    fn verify(&self, metadata: io::Result<Metadata>) -> io::Result<()> {
        if Self::read(metadata?)? != *self {
            return Err(invalid_executable());
        }
        Ok(())
    }

    fn read(metadata: Metadata) -> io::Result<Self> {
        if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
            return Err(invalid_executable());
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
            mode: metadata.mode(),
        })
    }
}

impl ExecutableFile {
    pub fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(invalid_executable());
        }
        let descriptor = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        let stamp = FileStamp::read(descriptor.metadata()?)?;
        let prepared = Self {
            content: content::fingerprint(&descriptor, &stamp)?,
            descriptor,
            source: path.into(),
            canonical: path.canonicalize()?,
            stamp,
            source_proof: SourceProof::Direct,
        };
        prepared.verify()?;
        Ok(prepared)
    }

    /// Удерживает выбранный путь вместе со всеми пройденными ссылками.
    pub fn resolve_selected(path: &Path) -> io::Result<Self> {
        let (proof, descriptor) = ChainProof::capture(path)?;
        let stamp = FileStamp::read(descriptor.metadata()?)?;
        let prepared = Self {
            content: content::fingerprint(&descriptor, &stamp)?,
            stamp,
            descriptor,
            source: path.into(),
            canonical: path.canonicalize()?,
            source_proof: SourceProof::Resolved(proof),
        };
        prepared.verify()?;
        Ok(prepared)
    }

    pub fn canonical_path(&self) -> &Path {
        &self.canonical
    }

    #[cfg(feature = "linux-kernel")]
    pub(crate) fn source_path(&self) -> &Path {
        &self.source
    }

    #[cfg(feature = "linux-kernel")]
    pub(crate) fn source_anchor(&self) -> io::Result<(File, Vec<u8>)> {
        self.verify()?;
        match &self.source_proof {
            SourceProof::Resolved(proof) => proof.source_anchor(),
            SourceProof::Direct => {
                let (proof, descriptor) = ChainProof::capture(&self.source)?;
                self.stamp.verify(descriptor.metadata())?;
                proof.source_anchor()
            }
        }
    }

    /// Проверяется и удерживаемый inode, и текущее имя. Замена не становится
    /// доверенной только потому, что путь совпал с прежним.
    pub fn verify(&self) -> io::Result<()> {
        if self.source.canonicalize()? != self.canonical {
            return Err(invalid_executable());
        }
        self.stamp.verify(self.descriptor.metadata())?;
        self.verify_source()?;
        self.stamp.verify(self.canonical.symlink_metadata())?;
        if content::fingerprint(&self.descriptor, &self.stamp)? != self.content {
            return Err(invalid_executable());
        }
        Ok(())
    }

    fn verify_source(&self) -> io::Result<()> {
        match &self.source_proof {
            SourceProof::Direct => self.stamp.verify(self.source.symlink_metadata())?,
            SourceProof::Resolved(proof) => {
                let current = proof.verify(&self.source)?;
                self.stamp.verify(current.metadata())?;
            }
        }
        Ok(())
    }
}

impl AsFd for ExecutableFile {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

fn invalid_executable() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Исполняемый файл не прошел проверку",
    )
}
