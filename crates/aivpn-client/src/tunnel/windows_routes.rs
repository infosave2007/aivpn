//! Маршруты split tunnel обеих семей с учетом конкретного интерфейса.

use std::cmp::Reverse;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows_sys::Win32::Foundation::{ERROR_NOT_ENOUGH_MEMORY, ERROR_NOT_FOUND};
use windows_sys::Win32::NetworkManagement::{IpHelper::*, Ndis::NET_LUID_LH};
use windows_sys::Win32::Networking::WinSock::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Prefix {
    address: IpAddr,
    bits: u8,
}

impl Prefix {
    fn parse(text: &str) -> io::Result<Self> {
        let (address, bits) = text.split_once('/').ok_or_else(invalid_prefix)?;
        let address = address.parse::<IpAddr>().map_err(|_| invalid_prefix())?;
        let bits = bits.parse::<u8>().map_err(|_| invalid_prefix())?;
        Self::new(address, bits)
    }

    fn new(address: IpAddr, bits: u8) -> io::Result<Self> {
        let maximum = if address.is_ipv4() { 32 } else { 128 };
        if bits > maximum {
            return Err(invalid_prefix());
        }
        Ok(Self {
            address: masked(address, bits),
            bits,
        })
    }

    fn family(self) -> u16 {
        if self.address.is_ipv4() {
            AF_INET
        } else {
            AF_INET6
        }
    }

    fn covers(self, other: Self) -> bool {
        self.address.is_ipv4() == other.address.is_ipv4()
            && self.bits <= other.bits
            && masked(other.address, self.bits) == self.address
    }

    fn from_row(row: &MIB_IPFORWARD_ROW2) -> io::Result<Self> {
        Self::new(
            socket_address(&row.DestinationPrefix.Prefix)?.0,
            row.DestinationPrefix.PrefixLength,
        )
    }

    fn bypass_prefixes(self) -> Vec<Self> {
        if self.bits >= 2 {
            return vec![self];
        }
        // Полный туннель использует две половины /1. Более точные /2
        // сохраняют приоритет исключения независимо от метрик интерфейсов.
        (0..1u8 << (2 - self.bits))
            .map(|part| Self {
                address: match self.address {
                    IpAddr::V4(address) => {
                        Ipv4Addr::from(u32::from(address) + (u32::from(part) << 30)).into()
                    }
                    IpAddr::V6(address) => {
                        Ipv6Addr::from(u128::from(address) + (u128::from(part) << 126)).into()
                    }
                },
                bits: 2,
            })
            .collect()
    }
}

fn masked(address: IpAddr, bits: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let mask = u32::MAX.checked_shl(u32::from(32 - bits)).unwrap_or(0);
            Ipv4Addr::from(u32::from(address) & mask).into()
        }
        IpAddr::V6(address) => {
            let mask = u128::MAX.checked_shl(u32::from(128 - bits)).unwrap_or(0);
            Ipv6Addr::from(u128::from(address) & mask).into()
        }
    }
}

fn invalid_prefix() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "Некорректная подсеть split tunnel",
    )
}

fn status(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

fn socket(address: IpAddr, scope: u32) -> SOCKADDR_INET {
    let mut value = SOCKADDR_INET::default();
    match address {
        IpAddr::V4(address) => {
            value.Ipv4.sin_family = AF_INET;
            value.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(address.octets());
        }
        IpAddr::V6(address) => {
            value.Ipv6.sin6_family = AF_INET6;
            value.Ipv6.sin6_addr.u.Byte = address.octets();
            value.Ipv6.Anonymous.sin6_scope_id = scope;
        }
    }
    value
}

fn socket_address(value: &SOCKADDR_INET) -> io::Result<(IpAddr, u32)> {
    unsafe {
        match value.si_family {
            AF_INET => Ok((
                Ipv4Addr::from(value.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()).into(),
                0,
            )),
            AF_INET6 => Ok((
                Ipv6Addr::from(value.Ipv6.sin6_addr.u.Byte).into(),
                value.Ipv6.Anonymous.sin6_scope_id,
            )),
            _ => Err(invalid_prefix()),
        }
    }
}

pub(super) fn interface_index(name: &str) -> io::Result<u32> {
    let alias: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut luid = NET_LUID_LH::default();
    status(unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) })?;
    let mut index = 0;
    status(unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) })?;
    let mut reverse = [0u16; 257];
    status(unsafe { ConvertInterfaceLuidToAlias(&luid, reverse.as_mut_ptr(), reverse.len()) })?;
    let length = reverse
        .iter()
        .position(|part| *part == 0)
        .unwrap_or(reverse.len());
    if String::from_utf16_lossy(&reverse[..length]) != name || index == 0 {
        return Err(io::Error::other("Alias не принадлежит интерфейсу Wintun"));
    }
    Ok(index)
}

fn interface_luid(index: u32) -> io::Result<NET_LUID_LH> {
    let mut luid = NET_LUID_LH::default();
    status(unsafe { ConvertInterfaceIndexToLuid(index, &mut luid) })?;
    Ok(luid)
}

fn row(prefix: Prefix, luid: NET_LUID_LH, next_hop: SOCKADDR_INET) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid;
    row.DestinationPrefix.Prefix = socket(prefix.address, 0);
    row.DestinationPrefix.PrefixLength = prefix.bits;
    row.NextHop = next_hop;
    row.SitePrefixLength = 0;
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Loopback = false;
    row.AutoconfigureAddress = false;
    row.Publish = false;
    row.Immortal = false;
    row
}

fn route_table(family: u16) -> io::Result<Vec<MIB_IPFORWARD_ROW2>> {
    struct Table(*mut MIB_IPFORWARD_TABLE2);
    impl Drop for Table {
        fn drop(&mut self) {
            unsafe { FreeMibTable(self.0.cast()) }
        }
    }
    let mut table = std::ptr::null_mut();
    status(unsafe { GetIpForwardTable2(family, &mut table) })?;
    if table.is_null() {
        return Err(io::Error::other("Пустая таблица маршрутов Windows"));
    }
    let table = Table(table);
    let count = unsafe { (*table.0).NumEntries as usize };
    if count > 65_536 {
        return Err(io::Error::other(
            "Превышен размер таблицы маршрутов Windows",
        ));
    }
    Ok(unsafe { std::slice::from_raw_parts((*table.0).Table.as_ptr(), count) }.to_vec())
}

fn route_preference(row: &MIB_IPFORWARD_ROW2, family: u16) -> Option<(Reverse<u8>, u64, u32)> {
    let mut interface = MIB_IPINTERFACE_ROW::default();
    unsafe { InitializeIpInterfaceEntry(&mut interface) };
    interface.Family = family;
    interface.InterfaceLuid = row.InterfaceLuid;
    if unsafe { GetIpInterfaceEntry(&mut interface) } != 0 || !interface.Connected {
        return None;
    }
    Some((
        Reverse(row.DestinationPrefix.PrefixLength),
        u64::from(row.Metric) + u64::from(interface.Metric),
        row.InterfaceIndex,
    ))
}

fn bypass_row(
    prefix: Prefix,
    tunnel: NET_LUID_LH,
    owned: &[MIB_IPFORWARD_ROW2],
) -> io::Result<Option<MIB_IPFORWARD_ROW2>> {
    let rows = route_table(prefix.family())?;
    let best = rows
        .iter()
        .filter(|row| unsafe { row.InterfaceLuid.Value != tunnel.Value })
        .filter(|row| row.ValidLifetime != 0)
        .filter(|row| !owned.iter().any(|ours| same_route(ours, row)))
        .filter(|row| Prefix::from_row(row).is_ok_and(|candidate| candidate.covers(prefix)))
        .filter_map(|row| route_preference(row, prefix.family()).map(|rank| (rank, row)))
        .min_by_key(|(rank, _)| *rank)
        .map(|(_, row)| row)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NetworkUnreachable,
                "Нет исходного маршрута для исключения split tunnel",
            )
        })?;
    if Prefix::from_row(best)? == prefix {
        // Этот маршрут уже обеспечивает исключение, но служба не владеет им.
        return Ok(None);
    }
    Ok(Some(row(prefix, best.InterfaceLuid, best.NextHop)))
}

fn same_route(expected: &MIB_IPFORWARD_ROW2, current: &MIB_IPFORWARD_ROW2) -> bool {
    let key = route_key(expected);
    key.is_some()
        && key == route_key(current)
        && route_attributes(expected) == route_attributes(current)
}

fn route_key(row: &MIB_IPFORWARD_ROW2) -> Option<(u64, Prefix, (IpAddr, u32))> {
    Some((
        unsafe { row.InterfaceLuid.Value },
        Prefix::from_row(row).ok()?,
        socket_address(&row.NextHop).ok()?,
    ))
}

fn route_attributes(row: &MIB_IPFORWARD_ROW2) -> (u32, i32, u8, [bool; 4], u32, u32) {
    (
        row.Metric,
        row.Protocol,
        row.SitePrefixLength,
        [
            row.Loopback,
            row.AutoconfigureAddress,
            row.Publish,
            row.Immortal,
        ],
        row.ValidLifetime,
        row.PreferredLifetime,
    )
}

fn current_owned(row: &MIB_IPFORWARD_ROW2) -> io::Result<Option<MIB_IPFORWARD_ROW2>> {
    let mut current = *row;
    let code = unsafe { GetIpForwardEntry2(&mut current) };
    if code == ERROR_NOT_FOUND {
        return Ok(None);
    }
    status(code)?;
    if !same_route(row, &current) {
        return Err(io::Error::other("Маршрут изменен извне, удаление отменено"));
    }
    Ok(Some(current))
}

fn remove_owned(row: &MIB_IPFORWARD_ROW2) -> io::Result<()> {
    let Some(current) = current_owned(row)? else {
        return Ok(());
    };
    let code = unsafe { DeleteIpForwardEntry2(&current) };
    if code == ERROR_NOT_FOUND {
        return Ok(());
    }
    status(code)
}

fn require_owned(row: &MIB_IPFORWARD_ROW2) -> io::Result<()> {
    current_owned(row)?
        .ok_or_else(|| io::Error::other("Собственный маршрут исчез при смене адреса"))?;
    Ok(())
}

fn restore_protocol_after_address_update(row: &MIB_IPFORWARD_ROW2) -> io::Result<()> {
    let mut current = *row;
    status(unsafe { GetIpForwardEntry2(&mut current) })?;
    if same_route(row, &current) {
        return Ok(());
    }
    // SetUnicastIpAddressEntry меняет Protocol новой подсети на Local.
    // Другие атрибуты и ключ должны точно совпадать со снимком до вызова.
    let mut local = *row;
    local.Protocol = MIB_IPPROTO_LOCAL;
    let netmgmt = row.Protocol == MIB_IPPROTO_NETMGMT;
    let local_transition = same_route(&local, &current);
    if !netmgmt || !local_transition {
        return Err(io::Error::other(
            "Маршрут изменен извне, восстановление Protocol отменено",
        ));
    }
    status(unsafe { SetIpForwardEntry2(row) })?;
    require_owned(row)
}

#[derive(Default)]
pub(super) struct OwnedIpv4Addresses {
    rows: Vec<MIB_UNICASTIPADDRESS_ROW>,
}

pub(super) struct PreparedIpv4Address {
    row: MIB_UNICASTIPADDRESS_ROW,
    created: bool,
}

fn address_key(row: &MIB_UNICASTIPADDRESS_ROW) -> (u64, Option<(IpAddr, u32)>) {
    (
        unsafe { row.InterfaceLuid.Value },
        socket_address(&row.Address).ok(),
    )
}

fn address_attributes(row: &MIB_UNICASTIPADDRESS_ROW) -> (i32, i32, u32, u32, u8, bool) {
    (
        row.PrefixOrigin,
        row.SuffixOrigin,
        row.ValidLifetime,
        row.PreferredLifetime,
        row.OnLinkPrefixLength,
        row.SkipAsSource,
    )
}

fn current_address(row: &MIB_UNICASTIPADDRESS_ROW) -> io::Result<Option<MIB_UNICASTIPADDRESS_ROW>> {
    let mut current = *row;
    let code = unsafe { GetUnicastIpAddressEntry(&mut current) };
    if code == ERROR_NOT_FOUND {
        return Ok(None);
    }
    status(code)?;
    if address_key(row) != address_key(&current)
        || address_attributes(row) != address_attributes(&current)
    {
        return Err(io::Error::other("Адрес изменен извне, удаление отменено"));
    }
    Ok(Some(current))
}

impl OwnedIpv4Addresses {
    // Вызывать только сразу после назначения адреса при создании устройства tun.
    pub(super) fn adopt_initial(
        &mut self,
        index: u32,
        address: Ipv4Addr,
        bits: u8,
    ) -> io::Result<()> {
        let mut row = Self::desired(index, address, bits)?;
        status(unsafe { GetUnicastIpAddressEntry(&mut row) })?;
        if row.OnLinkPrefixLength != bits
            || row.PrefixOrigin != IpPrefixOriginManual
            || row.SuffixOrigin != IpSuffixOriginManual
        {
            return Err(io::Error::other(
                "Начальный адрес Wintun не соответствует назначению",
            ));
        }
        self.rows.push(row);
        Ok(())
    }

    fn desired(index: u32, address: Ipv4Addr, bits: u8) -> io::Result<MIB_UNICASTIPADDRESS_ROW> {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };
        row.InterfaceLuid = interface_luid(index)?;
        row.Address = socket(address.into(), 0);
        row.OnLinkPrefixLength = bits;
        row.PrefixOrigin = IpPrefixOriginManual;
        row.SuffixOrigin = IpSuffixOriginManual;
        row.SkipAsSource = false;
        row.DadState = IpDadStatePreferred;
        Ok(row)
    }

    pub(super) fn prepare(
        &mut self,
        index: u32,
        address: Ipv4Addr,
        bits: u8,
    ) -> io::Result<PreparedIpv4Address> {
        for row in &self.rows {
            current_address(row)?;
        }
        let row = Self::desired(index, address, bits)?;
        let mut current = row;
        let code = unsafe { GetUnicastIpAddressEntry(&mut current) };
        if code == 0 {
            if !self
                .rows
                .iter()
                .any(|owned| address_key(owned) == address_key(&current))
            {
                return Err(io::Error::other(
                    "Новый адрес уже принадлежит внешней конфигурации",
                ));
            }
            current.OnLinkPrefixLength = bits;
            return Ok(PreparedIpv4Address {
                row: current,
                created: false,
            });
        }
        if code != ERROR_NOT_FOUND {
            status(code)?;
        }
        status(unsafe { CreateUnicastIpAddressEntry(&row) })?;
        self.rows
            .retain(|owned| address_key(owned) != address_key(&row));
        self.rows.push(row);
        Ok(PreparedIpv4Address { row, created: true })
    }

    pub(super) fn wait_ready(&self, prepared: &PreparedIpv4Address) -> io::Result<()> {
        for _ in 0..50 {
            let mut current = prepared.row;
            status(unsafe { GetUnicastIpAddressEntry(&mut current) })?;
            if current.DadState == IpDadStatePreferred {
                return Ok(());
            }
            if current.DadState != IpDadStateTentative {
                return Err(io::Error::other("Назначенный адрес Wintun не готов"));
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Адрес Wintun остается tentative",
        ))
    }

    pub(super) fn finish(
        &mut self,
        prepared: &PreparedIpv4Address,
        routes: &OwnedSplitRoutes,
    ) -> io::Result<()> {
        let owned = self
            .rows
            .iter_mut()
            .find(|owned| address_key(owned) == address_key(&prepared.row))
            .ok_or_else(|| io::Error::other("Не найден собственный адрес Wintun"))?;
        current_address(owned)?;
        if address_attributes(owned) != address_attributes(&prepared.row) {
            let prefix = Prefix::new(
                socket_address(&prepared.row.Address)?.0,
                prepared.row.OnLinkPrefixLength,
            )?;
            routes.with_address_prefix_update(prefix, || {
                status(unsafe { SetUnicastIpAddressEntry(&prepared.row) })
            })?;
            *owned = prepared.row;
        }
        self.clear_matching(|owned| address_key(owned) != address_key(&prepared.row))
    }

    pub(super) fn rollback(&mut self, prepared: &PreparedIpv4Address) -> io::Result<()> {
        self.clear_matching(|owned| {
            prepared.created && address_key(owned) == address_key(&prepared.row)
        })
    }

    pub(super) fn clear(&mut self) -> io::Result<()> {
        self.clear_matching(|_| true)
    }

    fn clear_matching(
        &mut self,
        mut remove: impl FnMut(&MIB_UNICASTIPADDRESS_ROW) -> bool,
    ) -> io::Result<()> {
        let mut first_error = None;
        self.rows.retain(|row| {
            if !remove(row) {
                return true;
            }
            let result = current_address(row).and_then(|current| match current {
                Some(current) => status(unsafe { DeleteUnicastIpAddressEntry(&current) }),
                None => Ok(()),
            });
            match result {
                Ok(()) => false,
                Err(error) => {
                    first_error.get_or_insert(error);
                    true
                }
            }
        });
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[derive(Default)]
pub(super) struct OwnedSplitRoutes {
    rows: Vec<MIB_IPFORWARD_ROW2>,
    applied: bool,
}

impl OwnedSplitRoutes {
    pub(super) fn apply_ipv4(
        &mut self,
        index: u32,
        peer: Ipv4Addr,
        prefixes: &[String],
    ) -> io::Result<()> {
        let luid = interface_luid(index)?;
        let rows = prefixes
            .iter()
            .map(|text| {
                let mut route = include_row(Prefix::parse(text)?, luid, peer);
                route.Metric = 5;
                Ok(route)
            })
            .collect::<io::Result<Vec<_>>>()?;
        self.install(rows)
    }

    pub(super) fn apply(
        &mut self,
        index: u32,
        peer: Ipv4Addr,
        include: &[String],
        exclude: &[String],
    ) -> io::Result<()> {
        if include.len().saturating_add(exclude.len()) > 4096 {
            return Err(io::Error::other(
                "Превышено количество маршрутов split tunnel",
            ));
        }
        self.install(self.desired_rows(interface_luid(index)?, peer, include, exclude)?)
    }

    fn desired_rows(
        &self,
        tunnel: NET_LUID_LH,
        peer: Ipv4Addr,
        include: &[String],
        exclude: &[String],
    ) -> io::Result<Vec<MIB_IPFORWARD_ROW2>> {
        let excluded = exclude
            .iter()
            .map(|text| Prefix::parse(text))
            .collect::<io::Result<Vec<_>>>()?;
        let mut desired = Vec::new();
        for text in include {
            let prefix = Prefix::parse(text)?;
            if !excluded.iter().any(|excluded| excluded.covers(prefix)) {
                desired.push(include_row(prefix, tunnel, peer));
            }
        }
        for prefix in excluded.into_iter().flat_map(Prefix::bypass_prefixes) {
            if let Some(row) = bypass_row(prefix, tunnel, &self.rows)? {
                desired.push(row);
            }
        }
        if desired.len() > 4096 {
            return Err(io::Error::other(
                "Превышено количество развернутых маршрутов split tunnel",
            ));
        }
        Ok(desired)
    }

    fn install(&mut self, rows: Vec<MIB_IPFORWARD_ROW2>) -> io::Result<()> {
        let pending = self.pending_rows(&rows)?;
        self.rows
            .try_reserve(pending.len())
            .map_err(io::Error::other)?;
        self.create_rows(&pending)?;
        self.clear_matching(|owned| !rows.iter().any(|desired| same_route(owned, desired)))?;
        self.applied = true;
        Ok(())
    }

    fn pending_rows(&self, desired: &[MIB_IPFORWARD_ROW2]) -> io::Result<Vec<MIB_IPFORWARD_ROW2>> {
        let mut pending = Vec::new();
        for row in desired {
            if pending.iter().any(|queued| same_route(queued, row)) {
                continue;
            }
            let tracked = self.rows.iter().any(|owned| same_route(owned, row));
            if tracked && current_owned(row)?.is_some() {
                continue;
            }
            pending.push(*row);
        }
        Ok(pending)
    }

    fn create_rows(&mut self, rows: &[MIB_IPFORWARD_ROW2]) -> io::Result<()> {
        let mut created = Vec::new();
        created.try_reserve(rows.len()).map_err(io::Error::other)?;
        for row in rows {
            let tracked = self.rows.iter().any(|owned| same_route(owned, row));
            let code = if tracked || self.rows.len() < 8192 {
                unsafe { CreateIpForwardEntry2(row) }
            } else {
                ERROR_NOT_ENOUGH_MEMORY
            };
            if code != 0 {
                let rollback =
                    self.clear_matching(|owned| created.iter().any(|new| same_route(owned, new)));
                return Err(io::Error::other(format!(
                    "Не удалось добавить маршрут split tunnel: {}; откат: {:?}",
                    io::Error::from_raw_os_error(code as i32),
                    rollback.err()
                )));
            }
            if !tracked {
                self.rows.push(*row);
            }
            created.push(*row);
        }
        Ok(())
    }

    pub(super) fn clear_full_ipv4(&mut self) -> io::Result<()> {
        self.clear_matching(|row| {
            Prefix::from_row(row).is_ok_and(|prefix| prefix.family() == AF_INET && prefix.bits == 1)
        })
    }

    fn with_address_prefix_update(
        &self,
        prefix: Prefix,
        update: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        let affected = self
            .rows
            .iter()
            .filter(|row| Prefix::from_row(row).ok() == Some(prefix));
        for row in affected.clone() {
            require_owned(row)?;
        }
        update()?;
        for row in affected {
            restore_protocol_after_address_update(row)?;
        }
        Ok(())
    }

    pub(super) fn is_applied(&self) -> bool {
        self.applied
    }

    pub(super) fn clear(&mut self) -> io::Result<()> {
        self.clear_matching(|_| true)?;
        self.applied = false;
        Ok(())
    }

    fn clear_matching(
        &mut self,
        mut remove: impl FnMut(&MIB_IPFORWARD_ROW2) -> bool,
    ) -> io::Result<()> {
        let mut first_error = None;
        self.rows.retain(|row| {
            if !remove(row) {
                return true;
            }
            match remove_owned(row) {
                Ok(()) => false,
                Err(error) => {
                    first_error.get_or_insert(error);
                    true
                }
            }
        });
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

fn include_row(prefix: Prefix, tunnel: NET_LUID_LH, peer: Ipv4Addr) -> MIB_IPFORWARD_ROW2 {
    let hop = if prefix.address.is_ipv4() {
        peer.into()
    } else {
        Ipv6Addr::UNSPECIFIED.into()
    };
    row(prefix, tunnel, socket(hop, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_prefixes_accept_both_families_and_normalize_host_bits() {
        assert_eq!(
            Prefix::parse("192.0.2.119/24").unwrap(),
            Prefix {
                address: "192.0.2.0".parse().unwrap(),
                bits: 24
            }
        );
        assert_eq!(
            Prefix::parse("2001:db8::123/64").unwrap(),
            Prefix {
                address: "2001:db8::".parse().unwrap(),
                bits: 64
            }
        );
        for text in ["::/0", "0.0.0.0/0", "::1/128", "127.0.0.1/32"] {
            assert!(Prefix::parse(text).is_ok());
        }
        for text in [
            "::/129",
            "1.2.3.4/33",
            "::/-1",
            "::",
            "host/24",
            "::/1/2",
            "::/256",
        ] {
            assert!(Prefix::parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn a_bypass_candidate_must_cover_the_whole_requested_network() {
        let wide = Prefix::parse("2001:db8::/32").unwrap();
        let narrow = Prefix::parse("2001:db8:1::/48").unwrap();
        assert!(wide.covers(narrow));
        assert!(!narrow.covers(wide));
        assert!(!wide.covers(Prefix::parse("2001:db9::/32").unwrap()));
        assert!(!Prefix::parse("0.0.0.0/0").unwrap().covers(wide));
        for (text, count) in [
            ("0.0.0.0/0", 4),
            ("128.0.0.0/1", 2),
            ("::/0", 4),
            ("8000::/1", 2),
        ] {
            let original = Prefix::parse(text).unwrap();
            let expanded = original.bypass_prefixes();
            assert_eq!(expanded.len(), count);
            assert!(expanded
                .iter()
                .all(|prefix| prefix.bits == 2 && original.covers(*prefix)));
            assert!(expanded.windows(2).all(|pair| pair[0] != pair[1]));
        }
    }
}
