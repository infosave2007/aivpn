//! Подготовленный файл не подтверждает установку привязки или готовность маршрута.

use super::super::objects::{read_array, ObjectInfo};
use super::KernelWriter;
use crate::bindings::BindingPlan;
use crate::linux::LocatedExecutable;
use std::io;
use std::num::NonZeroU32;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub(super) mod path_key;
use path_key::PathKey;

pub(super) mod retention;
pub use retention::PinnedRetention;

/// Удерживает проверенные файл и экземпляр карты. Перед установкой привязки
/// backend повторяет verify; сам объект не меняет правила ядра.
pub struct PreparedExecutable {
    file: VerifiedFile,
    application: NonZeroU32,
}

pub(super) struct VerifiedFile {
    pub(super) executable: LocatedExecutable,
    pub(super) instance: OwnedFd,
    keys: [PathKey; 2],
    source_keys: [PathKey; 2],
}

impl KernelWriter {
    pub fn prepare_executable(
        &self,
        plan: &BindingPlan,
        path: &str,
        executable: LocatedExecutable,
    ) -> io::Result<PreparedExecutable> {
        self.check_owner()?;
        let application = plan.executable_slot(&self.slots, path)?;
        if executable.source_path().as_os_str() != Path::new(path).as_os_str() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        executable.verify()?;
        let prepared = PreparedExecutable::new(self, executable, application)?;
        prepared.verify(self, plan)?;
        Ok(prepared)
    }
}

impl PreparedExecutable {
    fn new(
        writer: &KernelWriter,
        executable: LocatedExecutable,
        application: NonZeroU32,
    ) -> io::Result<Self> {
        Ok(Self {
            file: VerifiedFile::new(writer, executable)?,
            application,
        })
    }

    pub fn verify(&self, writer: &KernelWriter, plan: &BindingPlan) -> io::Result<()> {
        writer.check_owner()?;
        self.verify_binding(writer, plan)?;
        self.file.verify(writer)
    }

    fn verify_binding(&self, writer: &KernelWriter, plan: &BindingPlan) -> io::Result<()> {
        let path = self
            .file
            .executable
            .source_path()
            .to_str()
            .ok_or(io::ErrorKind::InvalidInput)?;
        let application = plan.executable_slot(&writer.slots, path)?;
        if application != self.application {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(())
    }
}

impl VerifiedFile {
    pub(super) fn new(writer: &KernelWriter, executable: LocatedExecutable) -> io::Result<Self> {
        executable.verify()?;
        let instance = writer
            .kernel
            .map(c"path_key")?
            .as_fd()
            .try_clone_to_owned()?;
        let seed = read_array::<16>(&instance)?;
        let keys = path_keys(seed, &executable)?;
        let source_keys = source_keys(seed, &executable)?;
        Ok(Self {
            executable,
            instance,
            keys,
            source_keys,
        })
    }

    pub(super) fn verify(&self, writer: &KernelWriter) -> io::Result<()> {
        writer.check_owner()?;
        self.verify_instance(writer)?;
        self.executable.verify()?;
        let seed = read_array::<16>(&self.instance)?;
        if self.keys != path_keys(seed, &self.executable)?
            || self.source_keys != source_keys(seed, &self.executable)?
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }

    fn verify_instance(&self, writer: &KernelWriter) -> io::Result<()> {
        if ObjectInfo::read(&self.instance)?.words[1]
            != ObjectInfo::read(writer.kernel.map(c"path_key")?)?.words[1]
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(())
    }
    pub(super) fn keys(&self) -> [[u64; 3]; 2] {
        [self.keys[0].words(), self.keys[1].words()]
    }
    pub(super) fn source_keys(&self) -> [[u64; 3]; 2] {
        [self.source_keys[0].words(), self.source_keys[1].words()]
    }
}

fn source_keys(seed: [u8; 16], executable: &LocatedExecutable) -> io::Result<[PathKey; 2]> {
    Ok([
        PathKey::new(
            seed,
            executable.source_filesystem_path(),
            executable.source_device(),
        )?,
        PathKey::new(
            seed,
            executable.source_path().as_os_str().as_bytes(),
            u64::MAX,
        )?,
    ])
}

fn path_keys(seed: [u8; 16], executable: &LocatedExecutable) -> io::Result<[PathKey; 2]> {
    Ok([
        PathKey::new(
            seed,
            executable.filesystem_path(),
            executable.filesystem_device(),
        )?,
        PathKey::new(
            seed,
            executable.canonical_path().as_os_str().as_bytes(),
            u64::MAX,
        )?,
    ])
}
