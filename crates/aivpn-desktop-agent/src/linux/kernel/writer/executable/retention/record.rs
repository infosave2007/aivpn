use super::{invalid, KernelWriter};
use crate::linux::kernel::objects::{read_array, ObjectInfo};
use sha2::{Digest, Sha256};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd};

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Record(pub [u8; 128]);

impl Record {
    pub fn new(
        writer: &KernelWriter,
        ids: [u32; 3],
        application: u32,
        device: u64,
        inode: u64,
    ) -> io::Result<Self> {
        let mut record = Self([0; 128]);
        record.0[..4].copy_from_slice(b"APR1");
        record.0[4..20].copy_from_slice(&writer.slots.namespace());
        record.0[20..52].copy_from_slice(&Sha256::digest(writer.kernel.mode().image()));
        for (index, value) in [
            id(writer.kernel.map(c"path_key")?)?,
            ids[1],
            ids[0],
            ids[2],
            application,
        ]
        .iter()
        .enumerate()
        {
            record.0[52 + index * 4..56 + index * 4].copy_from_slice(&value.to_le_bytes());
        }
        record.0[72..80].copy_from_slice(&device.to_le_bytes());
        record.0[80..88].copy_from_slice(&inode.to_le_bytes());
        record.0[88..104].copy_from_slice(&read_array::<16>(writer.kernel.map(c"path_key")?)?);
        let digest = Sha256::digest(&record.0[..104]);
        record.0[104..].copy_from_slice(&digest[..24]);
        Ok(record)
    }

    pub fn read(fd: &OwnedFd) -> io::Result<Self> {
        let record = Self(read_array(fd)?);
        let mut info = String::new();
        std::fs::File::open(format!("/proc/thread-self/fdinfo/{}", fd.as_raw_fd()))?
            .take(4097)
            .read_to_string(&mut info)?;
        if info.len() > 4096 || !info.lines().any(|line| line == "frozen:\t1") {
            return Err(invalid());
        }
        Ok(record)
    }

    pub fn verify(&self, writer: &KernelWriter, instance: &OwnedFd) -> io::Result<()> {
        let expected = Self::new(
            writer,
            [self.link(), self.program(), self.pid()],
            self.application(),
            self.device(),
            self.inode(),
        )?;
        if *self != expected {
            return Err(invalid());
        }
        self.verify_instance(instance)?;
        self.verify_values()?;
        if self.program() != id(writer.kernel.program(c"retain_application_inode")?)? {
            return Err(invalid());
        }
        Ok(())
    }

    fn verify_instance(&self, instance: &OwnedFd) -> io::Result<()> {
        // ID и номера enum разных классов BPF могут совпасть. Успешное чтение
        // массива подтверждает класс FD, форму карты и сохраненный seed.
        if id(instance)? != self.instance()
            || read_array::<16>(instance)?.as_slice() != &self.0[88..104]
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn verify_values(&self) -> io::Result<()> {
        if self.link() == 0
            || self.pid() == 0
            || self.pid() > i32::MAX as u32
            || self.application() == 0
            || self.inode() == 0
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn word(&self, offset: usize) -> u32 {
        u32::from_le_bytes(self.0[offset..offset + 4].try_into().unwrap())
    }
    pub fn instance(&self) -> u32 {
        self.word(52)
    }
    pub fn program(&self) -> u32 {
        self.word(56)
    }
    pub fn link(&self) -> u32 {
        self.word(60)
    }
    pub fn pid(&self) -> u32 {
        self.word(64)
    }
    pub fn application(&self) -> u32 {
        self.word(68)
    }
    pub fn device(&self) -> u64 {
        u64::from_le_bytes(self.0[72..80].try_into().unwrap())
    }
    pub fn inode(&self) -> u64 {
        u64::from_le_bytes(self.0[80..88].try_into().unwrap())
    }
}

pub(super) fn id(fd: &OwnedFd) -> io::Result<u32> {
    Ok(ObjectInfo::read(fd)?.words[1])
}
