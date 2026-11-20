//! Служба владеет CDO; работник получает только приватный пакетный pipe.
use super::*;
use std::{
    num::{NonZeroU32, NonZeroU64},
    os::windows::io::{AsRawHandle, OwnedHandle},
};

const CONFIG: u32 = (0x12 << 16) | (3 << 14) | (0x8a0 << 2);
const POP: u32 = (0x12 << 16) | (1 << 14) | (0x8a2 << 2) | 2;
const SEND: u32 = (0x12 << 16) | (2 << 14) | (0x8a3 << 2) | 1;
const POP_PROFILE: u32 = POP + (3 << 2);
const SEND_PROFILE: u32 = SEND + (3 << 2);

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct PacketStatistics {
    pub redirected4: u32,
    pub redirected6: u32,
    pub blocked: u32,
    pub last_status: i32,
    pub seen_out: u32,
    pub seen_in: u32,
    pub active_flows: u32,
    pub parse_failed: u32,
    pub completed: u32,
    pub maximum_batch: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProfileRoute {
    pub profile: NonZeroU32,
    pub generation: NonZeroU64,
}
impl ProfileRoute {
    pub fn new(profile: u32, generation: u64) -> io::Result<Self> {
        Ok(Self {
            profile: NonZeroU32::new(profile).ok_or_else(invalid)?,
            generation: NonZeroU64::new(generation).ok_or_else(invalid)?,
        })
    }
    fn bytes(self) -> [u8; 16] {
        let mut bytes = [0; 16];
        bytes[..4].copy_from_slice(&self.profile.get().to_le_bytes());
        bytes[8..].copy_from_slice(&self.generation.get().to_le_bytes());
        bytes
    }
}
#[derive(Debug, Clone, Copy)]
pub(crate) struct ProfilePacket {
    pub route: ProfileRoute,
    pub size: usize,
}

pub struct PacketChannelConfig {
    pub interface_index: u32,
    pub compartment: u32,
    pub mtu: u16,
    pub address: std::net::Ipv4Addr,
    pub ipv6: Option<std::net::Ipv6Addr>,
}
impl PacketChannelConfig {
    pub const MAX_MTU: u16 = 1500;
}
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub enum TransportOwner {
    Broker,
    Worker,
}
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct TransportReceipt {
    pub generation: u64,
    pub endpoint: u64,
    pub observed_owner: Option<TransportOwner>,
    pub socket_owner_pid: u64,
    pub worker_pid: u64,
}

impl DriverSession {
    #[cfg(feature = "windows-lab")]
    pub fn lab_counters(&self) -> io::Result<Vec<u32>> {
        let mut bytes = [0u8; 256];
        exchange_bytes(
            &self.handle,
            (0x12 << 16) | (3 << 14) | (0x9f1 << 2),
            &request(self.session.get(), HEADER_BYTES),
            &mut bytes,
        )?;
        Ok((0..64).map(|index| word(&bytes, index * 4)).collect())
    }
    #[cfg(feature = "windows-lab")]
    pub fn lab_injection_barrier(
        &self,
        started: &OwnedHandle,
        release: &OwnedHandle,
    ) -> io::Result<()> {
        let mut bytes = request(self.session.get(), 40);
        bytes[24..32].copy_from_slice(&(started.as_raw_handle() as usize as u64).to_le_bytes());
        bytes[32..40].copy_from_slice(&(release.as_raw_handle() as usize as u64).to_le_bytes());
        self.exchange((0x12 << 16) | (3 << 14) | (0x9f2 << 2), &bytes)
            .map(|_| ())
    }

    /// Существующий packet ABI: только числа, без повторной оценки identity.
    pub fn packet_statistics(&self) -> io::Result<PacketStatistics> {
        let mut bytes = [0u8; 44];
        let count = self.packet_io((0x12 << 16) | (1 << 14) | (0x8a1 << 2), &[], &mut bytes)?;
        if count != bytes.len() || word(&bytes, 0) != 1 {
            return Err(invalid());
        }
        Ok(PacketStatistics {
            redirected4: word(&bytes, 4),
            redirected6: word(&bytes, 8),
            blocked: word(&bytes, 12),
            last_status: word(&bytes, 16) as i32,
            seen_out: word(&bytes, 20),
            seen_in: word(&bytes, 24),
            active_flows: word(&bytes, 28),
            parse_failed: word(&bytes, 32),
            completed: word(&bytes, 36),
            maximum_batch: word(&bytes, 40),
        })
    }
    pub fn transport_receipt(&self) -> io::Result<TransportReceipt> {
        self.transport_receipt_for(None)
    }
    pub(crate) fn profile_transport_receipt(
        &self,
        profile: NonZeroU32,
    ) -> io::Result<TransportReceipt> {
        self.transport_receipt_for(Some(profile))
    }
    fn transport_receipt_for(&self, profile: Option<NonZeroU32>) -> io::Result<TransportReceipt> {
        let mut bytes = vec![0; if profile.is_some() { 64 } else { 56 }];
        let mut input = request(
            self.session.get(),
            if profile.is_some() { 32 } else { HEADER_BYTES },
        );
        if let Some(profile) = profile {
            input[24..28].copy_from_slice(&profile.get().to_le_bytes());
        }
        exchange_bytes(
            &self.handle,
            QUERY + if profile.is_some() { 56 } else { 24 },
            &input,
            &mut bytes,
        )?;
        let value = |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        if word(&bytes, 0) != if profile.is_some() { 2 } else { 1 }
            || word(&bytes, 4) as usize != bytes.len()
            || profile
                .is_some_and(|profile| word(&bytes, 56) != profile.get() || word(&bytes, 60) != 0)
            || value(8) != self.session.get()
            || word(&bytes, 36) != 0
        {
            return Err(invalid());
        }
        let observed_owner = match word(&bytes, 32) {
            0 => None,
            1 => Some(TransportOwner::Broker),
            2 => Some(TransportOwner::Worker),
            _ => return Err(invalid()),
        };
        Ok(TransportReceipt {
            generation: value(16),
            endpoint: value(24),
            observed_owner,
            socket_owner_pid: value(40),
            worker_pid: value(48),
        })
    }
    /// Вызов завершается до ResumeThread. Драйвер удерживает process object, а не PID.
    pub fn register_worker(
        &mut self,
        process: &OwnedHandle,
        image: &std::fs::File,
        generation: u64,
    ) -> io::Result<()> {
        self.transport_request(
            None,
            1,
            generation,
            process.as_raw_handle() as usize as u64,
            image.as_raw_handle() as usize as u64,
            0,
            None,
        )
    }
    pub fn register_transport(
        &mut self,
        generation: u64,
        transport: &super::super::worker::SharedTransport,
        peer: std::net::SocketAddr,
    ) -> io::Result<()> {
        if transport.ipv4() != peer.is_ipv4() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.transport_request(None, 2, generation, 0, 0, transport.endpoint(), Some(peer))
    }
    pub fn revoke_transport(&mut self, generation: u64) -> io::Result<()> {
        self.transport_request(None, 3, generation, 0, 0, 0, None)
    }
    pub(crate) fn register_profile_worker(
        &mut self,
        profile: NonZeroU32,
        generation: u64,
        process: &OwnedHandle,
        image: &std::fs::File,
    ) -> io::Result<()> {
        self.transport_request(
            Some(profile),
            1,
            generation,
            process.as_raw_handle() as usize as u64,
            image.as_raw_handle() as usize as u64,
            0,
            None,
        )
    }
    pub(crate) fn register_profile_transport(
        &mut self,
        route: ProfileRoute,
        transport: &super::super::worker::SharedTransport,
        peer: std::net::SocketAddr,
    ) -> io::Result<()> {
        if transport.ipv4() != peer.is_ipv4() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.transport_request(
            Some(route.profile),
            2,
            route.generation.get(),
            0,
            0,
            transport.endpoint(),
            Some(peer),
        )
    }
    pub(crate) fn revoke_profile_transport(&mut self, route: ProfileRoute) -> io::Result<()> {
        self.transport_request(
            Some(route.profile),
            3,
            route.generation.get(),
            0,
            0,
            0,
            None,
        )
    }
    fn transport_request(
        &self,
        profile: Option<NonZeroU32>,
        operation: u32,
        generation: u64,
        process: u64,
        image: u64,
        endpoint: u64,
        peer: Option<std::net::SocketAddr>,
    ) -> io::Result<()> {
        if generation == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut bytes = request(self.session.get(), if profile.is_some() { 96 } else { 88 });
        if let Some(profile) = profile {
            bytes[88..92].copy_from_slice(&profile.get().to_le_bytes());
        }
        bytes[80..88].copy_from_slice(&image.to_le_bytes());
        bytes[24..32].copy_from_slice(&generation.to_le_bytes());
        bytes[32..40].copy_from_slice(&process.to_le_bytes());
        bytes[40..48].copy_from_slice(&endpoint.to_le_bytes());
        bytes[48..52].copy_from_slice(&operation.to_le_bytes());
        if let Some(peer) = peer {
            bytes[56..58].copy_from_slice(&peer.port().to_le_bytes());
            match peer.ip() {
                std::net::IpAddr::V4(ip) => {
                    bytes[52] = 4;
                    bytes[60..64].copy_from_slice(&ip.octets());
                }
                std::net::IpAddr::V6(ip) => {
                    bytes[52] = 6;
                    bytes[60..76].copy_from_slice(&ip.octets());
                }
            }
        }
        self.exchange(QUERY + if profile.is_some() { 52 } else { 20 }, &bytes)
            .map(|_| ())
    }
    /// Ядро получает identity из удержанного process handle, решение не принимается из userspace.
    pub fn prepare_process(&mut self, process: &OwnedHandle) -> io::Result<()> {
        let mut input = request(self.session.get(), 56);
        input[24..32].copy_from_slice(&(process.as_raw_handle() as usize as u64).to_le_bytes());
        self.exchange(QUERY + 16, &input).map(|_| ())
    }

    pub fn configure_packet_channel(
        &mut self,
        config: PacketChannelConfig,
        event: &OwnedHandle,
    ) -> io::Result<()> {
        self.publish_packet_channel(config, event, true)
    }
    pub(crate) fn publish_packet_channel(
        &mut self,
        config: PacketChannelConfig,
        event: &OwnedHandle,
        ready: bool,
    ) -> io::Result<()> {
        self.publish_packet_config(config, event, ready, None)
    }
    pub(crate) fn publish_runtime_channel(
        &mut self,
        config: PacketChannelConfig,
        event: &OwnedHandle,
        ready: bool,
        profile: u32,
    ) -> io::Result<()> {
        self.publish_packet_config(config, event, ready, Some(profile))
    }
    fn publish_packet_config(
        &mut self,
        config: PacketChannelConfig,
        event: &OwnedHandle,
        ready: bool,
        profile: Option<u32>,
    ) -> io::Result<()> {
        let size = if profile.is_some() { 64 } else { 56 };
        let mut bytes = vec![0u8; size];
        for (index, word) in [
            if profile.is_some() { 2 } else { 1 },
            size as u32,
            u32::from(ready),
            u32::from(ready && config.ipv6.is_some()),
            config.interface_index,
            config.compartment,
            config.mtu as u32,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        bytes[28..32].copy_from_slice(&config.address.octets());
        if let Some(address) = config.ipv6 {
            bytes[32..48].copy_from_slice(&address.octets());
        }
        bytes[48..56].copy_from_slice(&(event.as_raw_handle() as usize as u64).to_le_bytes());
        if let Some(profile) = profile {
            bytes[56..60].copy_from_slice(&profile.to_le_bytes());
        }
        self.packet_io(CONFIG, &bytes, &mut []).map(|_| ())
    }
    pub fn block_packet_channel(&mut self) -> io::Result<()> {
        self.packet_io(CONFIG + 16, &[], &mut []).map(|_| ())
    }

    pub fn receive_packet(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        match self.packet_io(POP, &[], buffer) {
            Err(error) if error.raw_os_error() == Some(259) => Ok(None),
            Ok(size) if (20..=buffer.len()).contains(&size) => Ok(Some(size)),
            Ok(_) => Err(invalid()),
            Err(error) => Err(error),
        }
    }

    pub fn send_packet(&mut self, packet: &mut [u8]) -> io::Result<()> {
        if !(20..=65535).contains(&packet.len()) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        match self.packet_io(SEND, &[], packet) {
            // Закрытый поток и STATUS_DATA_ERROR валидатора пакетов не останавливают
            // другие соединения. Остальные ошибки IO по-прежнему возвращаются службе.
            Err(error) if matches!(error.raw_os_error(), Some(1168 | 23)) => Ok(()),
            result => result.map(|_| ()),
        }
    }

    pub(crate) fn block_profile_channel(&mut self, route: ProfileRoute) -> io::Result<()> {
        self.packet_io(CONFIG + 28, &route.bytes(), &mut [])
            .map(|_| ())
    }
    pub(crate) fn receive_profile_packet(
        &mut self,
        buffer: &mut [u8],
    ) -> io::Result<Option<ProfilePacket>> {
        if !(36..=65551).contains(&buffer.len()) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // Ядро режет исходящие пакеты до MTU. MDL не должен закреплять все 64 КБ.
        let capacity = buffer
            .len()
            .min(16 + usize::from(PacketChannelConfig::MAX_MTU));
        let buffer = &mut buffer[..capacity];
        let count = match self.packet_io(POP_PROFILE, &[], buffer) {
            Err(error) if error.raw_os_error() == Some(259) => return Ok(None),
            result => result?,
        };
        if !(36..=buffer.len()).contains(&count) || word(buffer, 4) != 0 {
            return Err(invalid());
        }
        let generation = u64::from_le_bytes(buffer[8..16].try_into().unwrap());
        Ok(Some(ProfilePacket {
            route: ProfileRoute::new(word(buffer, 0), generation)?,
            size: count - 16,
        }))
    }
    pub(crate) fn send_profile_packet(
        &mut self,
        route: ProfileRoute,
        packet: &mut [u8],
    ) -> io::Result<()> {
        if !(20..=65535).contains(&packet.len()) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        match self.packet_io(SEND_PROFILE, &route.bytes(), packet) {
            Err(error) if matches!(error.raw_os_error(), Some(1168 | 23)) => Ok(()),
            result => result.map(|_| ()),
        }
    }

    fn packet_io(&self, code: u32, input: &[u8], output: &mut [u8]) -> io::Result<usize> {
        // Драйвер проверяет токен, impersonation и владельца handle при каждом IOCTL.
        let mut count = 0;
        if unsafe {
            DeviceIoControl(
                self.handle.raw(),
                code,
                input.as_ptr().cast(),
                input.len() as u32,
                output.as_mut_ptr().cast(),
                output.len() as u32,
                &mut count,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(count as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_packet_io_keeps_the_kernel_access_and_transfer_contract() {
        for (code, function, access, method) in
            [(POP_PROFILE, 0x8a5, 1, 2), (SEND_PROFILE, 0x8a6, 2, 1)]
        {
            assert_eq!(code >> 16, 0x12);
            assert_eq!((code >> 2) & 0xfff, function);
            assert_eq!((code >> 14) & 3, access);
            assert_eq!(code & 3, method);
        }
    }
}
