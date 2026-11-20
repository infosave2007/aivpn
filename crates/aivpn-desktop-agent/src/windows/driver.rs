//! Доверенная сессия драйвера. Прием policy не включает WFP, routes или DNS.

use super::{api::Handle, security::service_authority};
use aivpn_desktop_policy::KernelPolicy;
use std::{io, num::NonZeroU64, ptr};
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*, System::IO::*};

mod dns;
mod identity;
mod local_image;
mod packet;
pub(crate) use dns::inspect_dns_socket;
mod runtime;
pub use identity::{DiagnosticAction, IdentityDiagnostic};
pub use packet::{PacketChannelConfig, PacketStatistics, TransportOwner, TransportReceipt};
pub(crate) use packet::{ProfilePacket, ProfileRoute};

const QUERY: u32 = (0x12 << 16) | (3 << 14) | (0x900 << 2);
const STAGE: u32 = QUERY + 4;
const HEADER_BYTES: usize = 24;
const STATUS_BYTES: usize = 48;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagedState {
    Empty,
    PolicyStaged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionStatus {
    pub session: NonZeroU64,
    pub generation: Option<NonZeroU64>,
    pub state: StagedState,
}

/// Handle не экспортируется и не наследуется. Все операции выполняет создавший процесс.
pub struct DriverSession {
    handle: Handle,
    session: NonZeroU64,
}

impl DriverSession {
    pub fn open() -> io::Result<Self> {
        service_authority()?;
        let name = "\\\\.\\AivpnAppRouting\0"
            .encode_utf16()
            .collect::<Vec<_>>();
        let handle = Handle::new(unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        })?;
        let status = exchange(&handle, QUERY, &request(0, HEADER_BYTES))?;
        Ok(Self {
            handle,
            session: status.session,
        })
    }

    pub fn status(&mut self) -> io::Result<SessionStatus> {
        self.exchange(QUERY, &request(self.session.get(), HEADER_BYTES))
    }

    /// Запоминает проверенную схему. Активация защиты этим API недоступна.
    pub fn stage(&mut self, policy: &KernelPolicy) -> io::Result<SessionStatus> {
        let policy = policy.to_native_bytes();
        self.stage_bytes(&policy)
    }
    pub(crate) fn stage_bytes(&mut self, policy: &[u8]) -> io::Result<SessionStatus> {
        let mut input = request(self.session.get(), HEADER_BYTES + policy.len());
        input[HEADER_BYTES..].copy_from_slice(&policy);
        self.exchange(STAGE, &input)
    }
    pub(crate) fn channel_id(&self) -> u64 {
        self.session.get()
    }

    fn exchange(&self, code: u32, input: &[u8]) -> io::Result<SessionStatus> {
        service_authority()?;
        let status = exchange(&self.handle, code, input)?;
        if status.session != self.session {
            return Err(invalid());
        }
        Ok(status)
    }
}

fn request(session: u64, size: usize) -> Vec<u8> {
    let mut bytes = vec![0; size];
    bytes[..4].copy_from_slice(&1u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&(size as u32).to_le_bytes());
    bytes[8..16].copy_from_slice(&session.to_le_bytes());
    bytes
}

fn exchange(handle: &Handle, code: u32, input: &[u8]) -> io::Result<SessionStatus> {
    let mut output = [0u8; STATUS_BYTES];
    exchange_bytes(handle, code, input, &mut output)?;
    decode_status(&output)
}

fn exchange_bytes(handle: &Handle, code: u32, input: &[u8], output: &mut [u8]) -> io::Result<()> {
    let mut size = 0;
    let result = unsafe {
        DeviceIoControl(
            handle.raw(),
            code,
            input.as_ptr().cast(),
            input.len() as u32,
            output.as_mut_ptr().cast(),
            output.len() as u32,
            &mut size,
            ptr::null_mut(),
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    if size as usize != output.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Длина ответа IOCTL {code:#x}: {size}, ожидалось {}",
                output.len()
            ),
        ));
    }
    Ok(())
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Несовместимый ответ драйвера")
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(
        bytes[at..at + 4]
            .try_into()
            .expect("Фиксированный размер ABI"),
    )
}

fn valid_status_header(bytes: &[u8; STATUS_BYTES]) -> bool {
    word(bytes, 0) == 1
        && word(bytes, 4) == STATUS_BYTES as u32
        && word(bytes, 16) == 0
        && word(bytes, 20) == 0
        && word(bytes, 36) == 1
        && word(bytes, 40) == 0
        && word(bytes, 44) == 0
}

fn decode_status(bytes: &[u8; STATUS_BYTES]) -> io::Result<SessionStatus> {
    if !valid_status_header(bytes) {
        return Err(invalid());
    }
    let session = NonZeroU64::new(u64::from_le_bytes(bytes[8..16].try_into().unwrap()))
        .ok_or_else(invalid)?;
    let generation = NonZeroU64::new(u64::from_le_bytes(bytes[24..32].try_into().unwrap()));
    let state = match (word(bytes, 32), generation) {
        (0, None) => StagedState::Empty,
        (1, Some(_)) => StagedState::PolicyStaged,
        _ => return Err(invalid()),
    };
    Ok(SessionStatus {
        session,
        generation,
        state,
    })
}

#[cfg(test)]
mod tests;
