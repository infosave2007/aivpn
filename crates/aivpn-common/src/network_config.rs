use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const DEFAULT_VPN_MTU: u16 = 1346;
pub const DEFAULT_KEEPALIVE_SECS: u8 = 8;
pub const LEGACY_VPN_PREFIX_LEN: u8 = 24;
pub const LEGACY_SERVER_VPN_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

fn default_server_vpn_ip() -> Ipv4Addr {
    LEGACY_SERVER_VPN_IP
}

fn default_prefix_len() -> u8 {
    LEGACY_VPN_PREFIX_LEN
}

fn default_mtu() -> u16 {
    DEFAULT_VPN_MTU
}

fn default_ipv6_prefix() -> String {
    "fd10:cafe::/48".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnNetworkConfig {
    #[serde(default = "default_server_vpn_ip")]
    pub server_vpn_ip: Ipv4Addr,
    #[serde(default = "default_prefix_len")]
    pub prefix_len: u8,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Keepalive interval pushed to clients in ServerHello. None = client uses its default (8s).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_secs: Option<u8>,
    /// Enable IPv6 dual-stack (NAT66). When true, the server will configure
    /// ip6tables/nftables masquerading and assign IPv6 addresses to clients.
    #[serde(default)]
    pub ipv6_enabled: bool,
    /// IPv6 ULA prefix allocated to VPN clients. Must be a /48.
    #[serde(default = "default_ipv6_prefix")]
    pub ipv6_prefix: String,
}

impl Default for VpnNetworkConfig {
    fn default() -> Self {
        Self {
            server_vpn_ip: default_server_vpn_ip(),
            prefix_len: default_prefix_len(),
            mtu: default_mtu(),
            keepalive_secs: None,
            ipv6_enabled: false,
            ipv6_prefix: default_ipv6_prefix(),
        }
    }
}

impl VpnNetworkConfig {
    pub fn validate(&self) -> Result<()> {
        if !(1..=30).contains(&self.prefix_len) {
            return Err(Error::InvalidPacket(
                "VPN prefix length must be in range 1..=30",
            ));
        }
        if self.server_vpn_ip == self.network_addr() || self.server_vpn_ip == self.broadcast_addr()
        {
            return Err(Error::InvalidPacket(
                "Server VPN IP must be a usable host address",
            ));
        }
        Ok(())
    }

    pub fn netmask(&self) -> Ipv4Addr {
        prefix_len_to_netmask(self.prefix_len)
    }

    pub fn network_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(ipv4_to_u32(self.server_vpn_ip) & self.mask_u32())
    }

    pub fn broadcast_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network_u32() | !self.mask_u32())
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        (ipv4_to_u32(ip) & self.mask_u32()) == self.network_u32()
    }

    pub fn cidr_string(&self) -> String {
        format!("{}/{}", self.network_addr(), self.prefix_len)
    }

    pub fn server_ip_string(&self) -> String {
        self.server_vpn_ip.to_string()
    }

    pub fn netmask_string(&self) -> String {
        self.netmask().to_string()
    }

    pub fn host_offset(&self, ip: Ipv4Addr) -> u32 {
        ipv4_to_u32(ip) & !self.mask_u32()
    }

    pub fn max_host_offset(&self) -> u32 {
        let host_mask = !self.mask_u32();
        host_mask.saturating_sub(1)
    }

    pub fn is_usable_host(&self, ip: Ipv4Addr) -> bool {
        self.contains(ip) && ip != self.network_addr() && ip != self.broadcast_addr()
    }

    pub fn ip_for_host_offset(&self, host_offset: u32) -> Option<Ipv4Addr> {
        if host_offset == 0 || host_offset > self.max_host_offset() {
            return None;
        }
        Some(Ipv4Addr::from(self.network_u32() | host_offset))
    }

    pub fn client_config(&self, client_ip: Ipv4Addr) -> Result<ClientNetworkConfig> {
        if !self.is_usable_host(client_ip) {
            return Err(Error::InvalidPacket(
                "Client VPN IP is outside configured VPN subnet",
            ));
        }
        if client_ip == self.server_vpn_ip {
            return Err(Error::InvalidPacket(
                "Client VPN IP cannot equal server VPN IP",
            ));
        }
        Ok(ClientNetworkConfig {
            client_ip,
            server_vpn_ip: self.server_vpn_ip,
            prefix_len: self.prefix_len,
            mtu: self.mtu,
            mdh_len: default_mdh_len(),
            keepalive_secs: self.keepalive_secs,
            ipv6_address: None,
        })
    }

    fn network_u32(&self) -> u32 {
        ipv4_to_u32(self.server_vpn_ip) & self.mask_u32()
    }

    fn mask_u32(&self) -> u32 {
        // Saturate defensively: `32 - prefix_len` underflows (and the shift
        // overflows) for prefix_len > 32, which a malformed config could carry.
        match self.prefix_len {
            0 => 0,
            p if p >= 32 => u32::MAX,
            p => u32::MAX << (32 - p),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientNetworkConfig {
    pub client_ip: Ipv4Addr,
    pub server_vpn_ip: Ipv4Addr,
    pub prefix_len: u8,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Mask-dependent header length in bytes.
    /// Clients MUST use this value for MDH generation and parsing.
    /// Defaults to 20 (STUN/WebRTC mask) for backward compatibility.
    #[serde(default = "default_mdh_len")]
    pub mdh_len: u16,
    /// Keepalive interval in seconds. None = use client default (8s).
    /// Sent by server in ServerHello to override per-network settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_secs: Option<u8>,
    /// Assigned IPv6 address for this client (e.g. "fd10:cafe::2").
    /// None when the server has IPv6 disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_address: Option<String>,
}

fn default_mdh_len() -> u16 {
    20
}

impl ClientNetworkConfig {
    pub const WIRE_SIZE: usize = 13;
    /// Wire-format / protocol-capability version.
    ///
    /// v2 (Variant A DPI fix) introduces **mask-defined tag offsets**: the 8-byte
    /// resonance tag may be embedded inside a real protocol header at a
    /// mask-specified byte offset instead of being a fixed prefix at packet
    /// offset 0. A v1 peer always assumes tag@0 and cannot parse packets built
    /// with a new-layout mask, so the version is bumped and `decode_wire`
    /// rejects mismatched versions — a v2 client refuses to negotiate with a v1
    /// server (and vice versa) rather than silently failing every packet.
    const WIRE_VERSION: u8 = 2;

    pub fn validate(&self) -> Result<()> {
        VpnNetworkConfig {
            server_vpn_ip: self.server_vpn_ip,
            prefix_len: self.prefix_len,
            mtu: self.mtu,
            keepalive_secs: None,
            ipv6_enabled: false,
            ipv6_prefix: default_ipv6_prefix(),
        }
        .client_config(self.client_ip)
        .map(|_| ())
    }

    pub fn netmask(&self) -> Ipv4Addr {
        prefix_len_to_netmask(self.prefix_len)
    }

    pub fn cidr_string(&self) -> String {
        format!("{}/{}", self.client_ip, self.prefix_len)
    }

    pub fn netmask_string(&self) -> String {
        self.netmask().to_string()
    }

    pub fn encode_wire(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0] = Self::WIRE_VERSION;
        buf[1] = self.prefix_len;
        buf[2..4].copy_from_slice(&self.mtu.to_le_bytes());
        buf[4..8].copy_from_slice(&self.server_vpn_ip.octets());
        buf[8..12].copy_from_slice(&self.client_ip.octets());
        buf[12] = self.keepalive_secs.unwrap_or(0);
        buf
    }

    pub fn decode_wire(data: &[u8]) -> Result<Self> {
        // Accept both old (12-byte) and new (13-byte) wire format
        if data.len() < 12 {
            return Err(Error::InvalidPacket(
                "Client network config has invalid wire length",
            ));
        }
        if data[0] != Self::WIRE_VERSION {
            return Err(Error::InvalidPacket(
                "Unsupported client network config wire version",
            ));
        }

        // Validate the prefix length BEFORE constructing/validating: a malicious
        // server could send prefix_len > 32, and the netmask shift helpers
        // (mask_u32 / prefix_len_to_netmask) compute `u32::MAX << (32 - prefix)`,
        // which underflows and panics for prefix_len > 32. Only /1../30 yield a
        // usable client subnet.
        if !(1..=30).contains(&data[1]) {
            return Err(Error::InvalidPacket(
                "Client network config prefix length out of range",
            ));
        }

        let keepalive_secs = if data.len() >= 13 && data[12] > 0 {
            Some(data[12])
        } else {
            None
        };

        let config = Self {
            prefix_len: data[1],
            mtu: u16::from_le_bytes([data[2], data[3]]),
            server_vpn_ip: Ipv4Addr::new(data[4], data[5], data[6], data[7]),
            client_ip: Ipv4Addr::new(data[8], data[9], data[10], data[11]),
            mdh_len: default_mdh_len(),
            keepalive_secs,
            ipv6_address: None,
        };
        config.validate()?;
        Ok(config)
    }
}

pub fn prefix_len_to_netmask(prefix_len: u8) -> Ipv4Addr {
    // Saturate: prefix_len > 32 would underflow `32 - prefix_len` and overflow
    // the shift. /32 is an all-ones mask.
    match prefix_len {
        0 => Ipv4Addr::new(0, 0, 0, 0),
        p if p >= 32 => Ipv4Addr::from(u32::MAX),
        p => Ipv4Addr::from(u32::MAX << (32 - p)),
    }
}

pub fn netmask_to_prefix_len(netmask: Ipv4Addr) -> Result<u8> {
    let mask = ipv4_to_u32(netmask);
    let prefix_len = mask.leading_ones() as u8;
    let expected = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    if mask != expected {
        return Err(Error::InvalidPacket("VPN netmask must be contiguous"));
    }
    Ok(prefix_len)
}

fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_roundtrip_preserves_client_network_config() {
        let config = ClientNetworkConfig {
            client_ip: Ipv4Addr::new(10, 150, 0, 2),
            server_vpn_ip: Ipv4Addr::new(10, 150, 0, 1),
            prefix_len: 24,
            mtu: 1346,
            mdh_len: 20,
            keepalive_secs: Some(4),
            ipv6_address: None,
        };

        let decoded = ClientNetworkConfig::decode_wire(&config.encode_wire()).unwrap();
        assert_eq!(decoded, config);
    }

    #[test]
    fn wire_decode_old_12_byte_format_backward_compat() {
        // Old 12-byte wire format must decode cleanly with keepalive_secs = None
        let old_wire: [u8; 12] = {
            let mut buf = [0u8; 12];
            buf[0] = ClientNetworkConfig::WIRE_VERSION; // current wire version
            buf[1] = 24; // prefix_len
            buf[2..4].copy_from_slice(&1346u16.to_le_bytes());
            buf[4..8].copy_from_slice(&Ipv4Addr::new(10, 150, 0, 1).octets());
            buf[8..12].copy_from_slice(&Ipv4Addr::new(10, 150, 0, 2).octets());
            buf
        };
        let decoded = ClientNetworkConfig::decode_wire(&old_wire).unwrap();
        assert_eq!(decoded.keepalive_secs, None);
        assert_eq!(decoded.mtu, 1346);
    }

    #[test]
    fn network_helpers_compute_addresses() {
        let config = VpnNetworkConfig {
            server_vpn_ip: Ipv4Addr::new(10, 150, 0, 1),
            prefix_len: 24,
            mtu: 1346,
            keepalive_secs: None,
            ipv6_enabled: false,
            ipv6_prefix: "fd10:cafe::/48".to_string(),
        };

        assert_eq!(config.network_addr(), Ipv4Addr::new(10, 150, 0, 0));
        assert_eq!(config.broadcast_addr(), Ipv4Addr::new(10, 150, 0, 255));
        assert_eq!(config.netmask(), Ipv4Addr::new(255, 255, 255, 0));
        assert!(config.is_usable_host(Ipv4Addr::new(10, 150, 0, 10)));
        assert!(!config.is_usable_host(Ipv4Addr::new(10, 150, 0, 0)));
    }
}
