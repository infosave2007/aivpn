//! Приватный протокол работника. Назначение содержит только настройки интерфейса.
use serde::{Deserialize, Serialize};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ipv6Assignment {
    pub address: Ipv6Addr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceAssignment {
    pub client_ip: Ipv4Addr,
    pub server_vpn_ip: Ipv4Addr,
    pub prefix_len: u8,
    pub mtu: u16,
    pub mdh_len: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<Ipv6Assignment>,
}

impl InterfaceAssignment {
    pub fn validate(&self) -> io::Result<()> {
        if self.prefix_len > 32
            || !(576..=9000).contains(&self.mtu)
            || self.mdh_len > self.mtu
            || [self.client_ip, self.server_vpn_ip].iter().any(|ip| {
                ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast()
            })
            || self.client_ip == self.server_vpn_ip
            || self.ipv6.is_some_and(|network| {
                !(1..=96).contains(&network.prefix_len)
                    || self.mtu < 1280
                    || network.address.is_unspecified()
                    || network.address.is_loopback()
                    || network.address.is_multicast()
                    || network.address.to_ipv4_mapped().is_some()
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Некорректное назначение сети работника",
            ));
        }
        Ok(())
    }

    #[cfg(feature = "local-profile")]
    pub fn from_config(
        config: &aivpn_common::network_config::ClientNetworkConfig,
    ) -> aivpn_common::error::Result<Self> {
        config.validate()?;
        let network = Self {
            client_ip: config.client_ip,
            server_vpn_ip: config.server_vpn_ip,
            prefix_len: config.prefix_len,
            mtu: config.mtu,
            mdh_len: config.mdh_len,
            ipv6: config
                .client_ipv6()?
                .map(|(address, prefix_len)| Ipv6Assignment {
                    address,
                    prefix_len,
                }),
        };
        network.validate()?;
        Ok(network)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerEvent {
    Transport {
        generation: u64,
        peer: SocketAddr,
    },
    Assignment {
        generation: u64,
        network: InterfaceAssignment,
    },
    Reconnecting {
        generation: u64,
    },
    Disconnected {
        generation: u64,
    },
}

impl WorkerEvent {
    /// Установка маршрутов и восстановление профиля требуют времени после приема кадра.
    pub fn response_timeout(&self) -> std::time::Duration {
        match self {
            Self::Transport { .. } => std::time::Duration::from_secs(5),
            Self::Assignment { .. } | Self::Reconnecting { .. } | Self::Disconnected { .. } => {
                std::time::Duration::from_secs(30)
            }
        }
    }
}

#[cfg(any(feature = "linux-kernel", target_os = "windows"))]
impl WorkerEvent {
    pub(crate) fn generation(&self) -> u64 {
        match self {
            Self::Transport { generation, .. }
            | Self::Assignment { generation, .. }
            | Self::Reconnecting { generation }
            | Self::Disconnected { generation } => *generation,
        }
    }
}
