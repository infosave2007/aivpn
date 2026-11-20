//! Очистка возможна только после durable подготовки и восстановления DNS.
use crate::{
    control::ControlState,
    policy::Platform,
    state::{StateDirectory, StateFile},
};
use sha2::{Digest, Sha256};
use std::io;

pub struct DecommissionProof<'a> {
    control: &'a StateDirectory,
    namespace: [u8; 16],
    serial: u64,
    bytes: Vec<u8>,
}

impl<'a> DecommissionProof<'a> {
    pub fn open(
        platform: Platform,
        namespace: [u8; 16],
        control: &'a StateDirectory,
    ) -> io::Result<Self> {
        let (serial, bytes) = ControlState::verify_decommissioned(platform, namespace, control)?;
        Ok(Self {
            control,
            namespace,
            serial,
            bytes,
        })
    }
    pub(crate) fn confirm(&self) -> io::Result<()> {
        if self.control.load(StateFile::Pending)?.is_some()
            || self.control.load(StateFile::Committed)?.as_ref() != Some(&self.bytes)
        {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        Ok(())
    }
    pub(crate) fn namespace(&self) -> [u8; 16] {
        self.namespace
    }
    pub(crate) fn serial(&self) -> u64 {
        self.serial
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.bytes).into()
    }
}
