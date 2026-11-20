use super::{Identity, Link, Snapshot, MAX_LINKS, MAX_NAME_UNITS};
use std::{io, ptr};
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, ERROR_NO_DATA, ERROR_SUCCESS},
        NetworkManagement::{IpHelper::*, Ndis::IfOperStatusUp},
        System::Registry::*,
    },
};

fn status(code: u32) -> io::Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

fn guid(identity: &Identity) -> GUID {
    GUID::from_u128(u128::from_be_bytes(identity.guid))
}

fn identity(row: &MIB_IF_ROW2) -> Identity {
    let id = row.InterfaceGuid;
    let value = (u128::from(id.data1) << 96)
        | (u128::from(id.data2) << 80)
        | (u128::from(id.data3) << 64)
        | u128::from(u64::from_be_bytes(id.data4));
    Identity {
        guid: value.to_be_bytes(),
        luid: unsafe { row.InterfaceLuid.Value },
        index: row.InterfaceIndex,
    }
}

struct Table(*mut MIB_IF_TABLE2);
impl Drop for Table {
    fn drop(&mut self) {
        unsafe { FreeMibTable(self.0.cast()) };
    }
}

pub(super) fn snapshot() -> io::Result<Snapshot> {
    let compartment = unsafe { GetCurrentThreadCompartmentId() };
    let eligible = ip_interfaces()?;
    let mut raw = ptr::null_mut();
    status(unsafe { GetIfTable2(&mut raw) })?;
    if raw.is_null() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let table = Table(raw);
    let count = unsafe { (*table.0).NumEntries } as usize;
    if count > 4096 {
        return Err(io::ErrorKind::FileTooLarge.into());
    }
    // Table - гибкий массив, его размер задается NumEntries, а память принадлежит API.
    let rows = unsafe {
        std::slice::from_raw_parts(ptr::addr_of!((*table.0).Table).cast::<MIB_IF_ROW2>(), count)
    };
    let mut links = Vec::new();
    for row in rows {
        // Снимок хранит настройки IP-адаптера и при отключенном линке.
        if row.Type == MIB_IF_TYPE_LOOPBACK
            || !eligible.contains(&unsafe { row.InterfaceLuid.Value })
        {
            continue;
        }
        if links.len() == MAX_LINKS {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        let id = identity(row);
        let servers = [configured(&id, false)?, configured(&id, true)?];
        verify_native(&id, &servers[0]).map_err(|e| {
            io::Error::new(e.kind(), format!("Чтение DNS интерфейса {}: {e}", id.index))
        })?;
        links.push(Link {
            identity: id,
            servers,
        });
    }
    links.sort_by(|a, b| a.identity.cmp(&b.identity));
    Ok(Snapshot { compartment, links })
}

fn ip_interfaces() -> io::Result<std::collections::BTreeSet<u64>> {
    adapters(false).map(|(interfaces, _)| interfaces)
}

pub(super) fn bootstrap_servers(before: &Snapshot) -> io::Result<Vec<std::net::SocketAddr>> {
    let (interfaces, servers) = adapters(true)?;
    let expected = before.links.iter().map(|link| link.identity.luid).collect();
    if interfaces != expected {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    Ok(servers)
}

fn adapters(
    collect_dns: bool,
) -> io::Result<(std::collections::BTreeSet<u64>, Vec<std::net::SocketAddr>)> {
    // Без INCLUDE_ALL_INTERFACES API возвращает адаптеры с включенным IP.
    // GetIfTable2 также содержит служебные NDIS интерфейсы без DNS-конфигурации.
    let mut flags = GAA_FLAG_SKIP_UNICAST
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_FRIENDLY_NAME;
    if !collect_dns {
        flags |= GAA_FLAG_SKIP_DNS_SERVER;
    }
    let mut bytes = 15 * 1024usize;
    for _ in 0..3 {
        if bytes > 1024 * 1024 {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        let mut buffer = vec![0u64; bytes.div_ceil(8)];
        let mut size = (buffer.len() * 8) as u32;
        let base = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let code = unsafe { GetAdaptersAddresses(0, flags, ptr::null(), base, &mut size) };
        if code == ERROR_BUFFER_OVERFLOW {
            bytes = size as usize;
            continue;
        }
        if code == ERROR_NO_DATA {
            return Ok(Default::default());
        }
        status(code)?;
        let start = base as usize;
        let end = start + buffer.len() * 8;
        let mut current = base;
        let mut result = std::collections::BTreeSet::new();
        let mut servers = Vec::new();
        for _ in 0..4096 {
            if current.is_null() {
                return Ok((result, servers));
            }
            let address = current as usize;
            if address < start
                || address % std::mem::align_of::<IP_ADAPTER_ADDRESSES_LH>() != 0
                || address
                    .checked_add(std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>())
                    .is_none_or(|v| v > end)
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let adapter = unsafe { &*current };
            if (unsafe { adapter.Anonymous1.Anonymous.Length } as usize)
                < std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>()
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if adapter.IfType != MIB_IF_TYPE_LOOPBACK {
                result.insert(unsafe { adapter.Luid.Value });
                if collect_dns && adapter.OperStatus == IfOperStatusUp {
                    for server in dns_servers(
                        start,
                        end,
                        adapter.FirstDnsServerAddress,
                        adapter.Ipv6IfIndex,
                    )? {
                        if !servers.contains(&server) {
                            servers.push(server);
                        }
                    }
                    if servers.len() > 32 {
                        return Err(io::ErrorKind::FileTooLarge.into());
                    }
                }
            }
            current = adapter.Next;
        }
        return Err(io::ErrorKind::FileTooLarge.into());
    }
    Err(io::ErrorKind::WouldBlock.into())
}

fn dns_servers(
    start: usize,
    end: usize,
    mut current: *const IP_ADAPTER_DNS_SERVER_ADDRESS_XP,
    ipv6_index: u32,
) -> io::Result<Vec<std::net::SocketAddr>> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
    };
    let check = |address: usize, length: usize, alignment: usize| -> io::Result<()> {
        if address < start
            || address % alignment != 0
            || address.checked_add(length).is_none_or(|value| value > end)
        {
            Err(io::ErrorKind::InvalidData.into())
        } else {
            Ok(())
        }
    };
    let mut result = Vec::new();
    for _ in 0..32 {
        if current.is_null() {
            return Ok(result);
        }
        check(
            current as usize,
            std::mem::size_of::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>(),
            std::mem::align_of::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>(),
        )?;
        let dns = unsafe { &*current };
        if (unsafe { dns.Anonymous.Anonymous.Length } as usize)
            < std::mem::size_of::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>()
            || dns.Address.iSockaddrLength < std::mem::size_of::<SOCKADDR>() as i32
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let address = dns.Address.lpSockaddr as usize;
        check(
            address,
            dns.Address.iSockaddrLength as usize,
            std::mem::align_of::<SOCKADDR>(),
        )?;
        let family = unsafe { (*dns.Address.lpSockaddr).sa_family };
        let server = match family {
            AF_INET => {
                check(
                    address,
                    std::mem::size_of::<SOCKADDR_IN>(),
                    std::mem::align_of::<SOCKADDR_IN>(),
                )?;
                let ip = unsafe { &*dns.Address.lpSockaddr.cast::<SOCKADDR_IN>() };
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(
                        unsafe { ip.sin_addr.S_un.S_addr }.to_ne_bytes(),
                    )),
                    53,
                )
            }
            AF_INET6 => {
                if (dns.Address.iSockaddrLength as usize) < std::mem::size_of::<SOCKADDR_IN6>() {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                check(
                    address,
                    std::mem::size_of::<SOCKADDR_IN6>(),
                    std::mem::align_of::<SOCKADDR_IN6>(),
                )?;
                let ip = unsafe { &*dns.Address.lpSockaddr.cast::<SOCKADDR_IN6>() };
                let address = Ipv6Addr::from(unsafe { ip.sin6_addr.u.Byte });
                let mut scope = unsafe { ip.Anonymous.sin6_scope_id };
                if address.is_unicast_link_local() && scope == 0 {
                    scope = ipv6_index;
                }
                SocketAddr::V6(SocketAddrV6::new(address, 53, 0, scope))
            }
            _ => return Err(io::ErrorKind::InvalidData.into()),
        };
        result.push(server);
        current = dns.Next;
    }
    if current.is_null() {
        Ok(result)
    } else {
        Err(io::ErrorKind::FileTooLarge.into())
    }
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

fn configured(id: &Identity, ipv6: bool) -> io::Result<String> {
    let g = guid(id);
    let service = if ipv6 { "Tcpip6" } else { "Tcpip" };
    let tail = u64::from_be_bytes(g.data4);
    let key_name = format!(
        "SYSTEM\\CurrentControlSet\\Services\\{service}\\Parameters\\Interfaces\\{{{:08x}-{:04x}-{:04x}-{:04x}-{:012x}}}\0",
        g.data1, g.data2, g.data3, tail >> 48, tail & 0x0000_ffff_ffff_ffff,
    ).encode_utf16().collect::<Vec<_>>();
    let mut raw = ptr::null_mut();
    let code = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key_name.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut raw,
        )
    };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(String::new());
    }
    status(code)?;
    let key = Key(raw);
    let name = "NameServer\0".encode_utf16().collect::<Vec<_>>();
    let mut value = vec![0u16; MAX_NAME_UNITS];
    let mut length = (value.len() * 2) as u32;
    let mut kind = 0;
    let code = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            ptr::null(),
            &mut kind,
            value.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(String::new());
    }
    status(code)?;
    if kind != REG_SZ || length % 2 != 0 || length as usize > value.len() * 2 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    value.truncate(length as usize / 2);
    if value.last() == Some(&0) {
        value.pop();
    }
    if value.contains(&0) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    String::from_utf16(&value).map_err(|_| io::ErrorKind::InvalidData.into())
}

struct Settings(DNS_INTERFACE_SETTINGS);
impl Drop for Settings {
    fn drop(&mut self) {
        unsafe { FreeInterfaceDnsSettings(&mut self.0) };
    }
}

fn native_string(raw: *const u16) -> io::Result<String> {
    if raw.is_null() {
        return Ok(String::new());
    }
    for length in 0..MAX_NAME_UNITS {
        if unsafe { *raw.add(length) } == 0 {
            let value = unsafe { std::slice::from_raw_parts(raw, length) };
            return String::from_utf16(value).map_err(|_| io::ErrorKind::InvalidData.into());
        }
    }
    Err(io::ErrorKind::FileTooLarge.into())
}

fn verify_native(id: &Identity, configured: &str) -> io::Result<()> {
    let mut settings = DNS_INTERFACE_SETTINGS {
        Version: 1,
        ..Default::default()
    };
    // Get требует Flags=0. Флаг IPV6 существует для Set, не для чтения.
    status(unsafe { GetInterfaceDnsSettings(guid(id), &mut settings) })?;
    let settings = Settings(settings);
    if native_string(settings.0.NameServer)? != configured {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    if !native_string(settings.0.ProfileNameServer)?.is_empty() {
        return Err(io::ErrorKind::Unsupported.into());
    }
    Ok(())
}

pub(super) fn set(id: &Identity, ipv6: bool, servers: &str) -> io::Result<()> {
    if servers.contains('\0') || servers.encode_utf16().count() >= MAX_NAME_UNITS {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut names: Vec<_> = servers.encode_utf16().chain(Some(0)).collect();
    let settings = DNS_INTERFACE_SETTINGS {
        Version: 1,
        Flags: u64::from(DNS_SETTING_NAMESERVER | if ipv6 { DNS_SETTING_IPV6 } else { 0 }),
        NameServer: names.as_mut_ptr(),
        ..Default::default()
    };
    // Даже Automatic передается непустым указателем на пустую строку.
    status(unsafe { SetInterfaceDnsSettings(guid(id), &settings) })
}
