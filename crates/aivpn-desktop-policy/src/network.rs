use crate::PolicyError;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub(crate) enum Network {
    V4 { address: u32, mask: u32 },
    V6 { address: u128, mask: u128 },
}

impl Network {
    pub(crate) fn parse(value: &str) -> Result<Self, PolicyError> {
        let (ip, prefix) = value
            .split_once('/')
            .ok_or(PolicyError::Invalid("нужна сеть с префиксом"))?;
        let ip: IpAddr = ip
            .parse()
            .map_err(|_| PolicyError::Invalid("неверный адрес сети"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| PolicyError::Invalid("неверный префикс сети"))?;
        match ip {
            IpAddr::V4(ip) => Self::v4(u32::from(ip), prefix),
            IpAddr::V6(ip) => match (ip.to_ipv4_mapped(), prefix.checked_sub(96)) {
                (Some(ip), Some(prefix)) => Self::v4(u32::from(ip), prefix),
                _ => Self::v6(u128::from(ip), prefix),
            },
        }
    }

    fn v4(address: u32, prefix: u8) -> Result<Self, PolicyError> {
        let mask = network_mask(u128::from(address), prefix, 32)? as u32;
        Ok(Self::V4 { address, mask })
    }

    fn v6(address: u128, prefix: u8) -> Result<Self, PolicyError> {
        let mask = network_mask(address, prefix, 128)?;
        Ok(Self::V6 { address, mask })
    }

    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4 { address, mask }, IpAddr::V4(ip)) => u32::from(ip) & mask == *address,
            (Self::V6 { address, mask }, IpAddr::V6(ip)) => u128::from(ip) & mask == *address,
            _ => false,
        }
    }
}

fn network_mask(address: u128, prefix: u8, width: u8) -> Result<u128, PolicyError> {
    if prefix > width {
        return Err(PolicyError::Invalid("префикс больше длины адреса"));
    }
    let mask = if prefix == 0 {
        0
    } else {
        (u128::MAX >> (128 - prefix)) << (width - prefix)
    };
    if address & mask != address {
        return Err(PolicyError::Invalid("в сети заданы биты хоста"));
    }
    Ok(mask)
}

pub(crate) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}
