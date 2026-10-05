//! Правила WFP принадлежат приложению и не меняют политики других брандмауэров.

use std::io;
use std::net::IpAddr;
use std::ptr::{null, null_mut};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    FWP_E_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
};
use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceAliasToLuid;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

const SUBLAYER: GUID = GUID::from_u128(0x9e3f1a70_27d1_453c_9183_84061e7b0170);
const FILTER_BASE: u128 = 0x9e3f1a70_27d1_453c_9183_84061e7b0200;
const FILTERS_PER_LAYER: u8 = 8;
const LAYERS: [GUID; 2] = [
    FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
    FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
];

struct Engine(HANDLE);
impl Engine {
    fn open() -> io::Result<Self> {
        let mut handle = null_mut();
        check(unsafe { FwpmEngineOpen0(null(), 10, null(), null(), &mut handle) })?;
        Ok(Self(handle))
    }
    fn transaction(&self, operation: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        check(unsafe { FwpmTransactionBegin0(self.0, 0) })?;
        let result = operation().and_then(|()| check(unsafe { FwpmTransactionCommit0(self.0) }));
        if result.is_err() {
            unsafe {
                FwpmTransactionAbort0(self.0);
            }
        }
        result
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.0);
        }
    }
}
fn check(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}
fn delete_filters(engine: &Engine) -> io::Result<()> {
    for index in 0..LAYERS.len() * usize::from(FILTERS_PER_LAYER) {
        let key = GUID::from_u128(FILTER_BASE + index as u128);
        let code = unsafe { FwpmFilterDeleteByKey0(engine.0, &key) };
        if code != FWP_E_FILTER_NOT_FOUND as u32 {
            check(code)?;
        }
    }
    Ok(())
}

pub(super) fn activate(interface: &str, server: &str) -> io::Result<()> {
    restore_previous_backend()?;
    let server: IpAddr = server
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid VPN server address"))?;
    let alias: Vec<u16> = interface.encode_utf16().chain(Some(0)).collect();
    let mut luid = NET_LUID_LH::default();
    check(unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) })?;
    let mut luid_value = unsafe { luid.Value };
    let engine = Engine::open()?;
    engine.transaction(|| {
        let mut name: Vec<u16> = "AIVPN kill-switch".encode_utf16().chain(Some(0)).collect();
        let mut sublayer = FWPM_SUBLAYER0::default();
        sublayer.subLayerKey = SUBLAYER;
        sublayer.displayData.name = name.as_mut_ptr();
        sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
        sublayer.weight = u16::MAX;
        let result = unsafe { FwpmSubLayerAdd0(engine.0, &sublayer, null_mut()) };
        if result != FWP_E_ALREADY_EXISTS as u32 {
            check(result)?;
        }
        delete_filters(&engine)?;
        for (layer_index, layer) in LAYERS.iter().enumerate() {
            let mut add = |slot: u8,
                           weight: u64,
                           action,
                           conditions: &mut [FWPM_FILTER_CONDITION0]|
             -> io::Result<()> {
                let mut weight = weight;
                let mut filter = FWPM_FILTER0::default();
                filter.filterKey = GUID::from_u128(
                    FILTER_BASE
                        + layer_index as u128 * u128::from(FILTERS_PER_LAYER)
                        + u128::from(slot),
                );
                filter.displayData.name = name.as_mut_ptr();
                filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
                filter.layerKey = *layer;
                filter.subLayerKey = SUBLAYER;
                filter.weight.r#type = FWP_UINT64;
                filter.weight.Anonymous.uint64 = &mut weight;
                filter.action.r#type = action;
                filter.numFilterConditions = conditions.len() as u32;
                filter.filterCondition = conditions.as_mut_ptr();
                check(unsafe { FwpmFilterAdd0(engine.0, &filter, null_mut(), null_mut()) })
            };
            // Исключения имеют больший вес внутри собственного sublayer.
            // Остальные брандмауэры сохраняют право заблокировать пакет.
            let mut vpn = FWPM_FILTER_CONDITION0::default();
            vpn.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
            vpn.matchType = FWP_MATCH_EQUAL;
            vpn.conditionValue.r#type = FWP_UINT64;
            vpn.conditionValue.Anonymous.uint64 = &mut luid_value;
            add(0, 30, FWP_ACTION_PERMIT, &mut [vpn])?;
            let mut loopback = FWPM_FILTER_CONDITION0::default();
            loopback.fieldKey = FWPM_CONDITION_FLAGS;
            loopback.matchType = FWP_MATCH_FLAGS_ALL_SET;
            loopback.conditionValue.r#type = FWP_UINT32;
            loopback.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
            add(1, 20, FWP_ACTION_PERMIT, &mut [loopback])?;
            let mut remote = FWPM_FILTER_CONDITION0::default();
            remote.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
            remote.matchType = FWP_MATCH_EQUAL;
            let mut address6 = FWP_BYTE_ARRAY16::default();
            let matching_family = match server {
                IpAddr::V4(address) if layer_index == 0 => {
                    remote.conditionValue.r#type = FWP_UINT32;
                    remote.conditionValue.Anonymous.uint32 = u32::from(address);
                    true
                }
                IpAddr::V6(address) if layer_index == 1 => {
                    address6.byteArray16 = address.octets();
                    remote.conditionValue.r#type = FWP_BYTE_ARRAY16_TYPE;
                    remote.conditionValue.Anonymous.byteArray16 = &mut address6;
                    true
                }
                _ => false,
            };
            if matching_family {
                add(2, 10, FWP_ACTION_PERMIT, &mut [remote])?;
            }
            add(3, 1, FWP_ACTION_BLOCK, &mut [])?;
            let mut protocol = FWPM_FILTER_CONDITION0::default();
            protocol.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
            protocol.matchType = FWP_MATCH_EQUAL;
            protocol.conditionValue.r#type = FWP_UINT8;
            protocol.conditionValue.Anonymous.uint8 = 17;
            let mut local_port = FWPM_FILTER_CONDITION0::default();
            local_port.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
            local_port.matchType = FWP_MATCH_EQUAL;
            local_port.conditionValue.r#type = FWP_UINT16;
            local_port.conditionValue.Anonymous.uint16 = if layer_index == 0 { 68 } else { 546 };
            let mut remote_port = local_port;
            remote_port.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
            remote_port.conditionValue.Anonymous.uint16 = if layer_index == 0 { 67 } else { 547 };
            add(
                4,
                15,
                FWP_ACTION_PERMIT,
                &mut [protocol, local_port, remote_port],
            )?;
            if layer_index == 1 {
                // NDP нужен для доступности физического IPv6-шлюза.
                protocol.conditionValue.Anonymous.uint8 = 58;
                for (slot, prefix, length) in [(5, "fe80::", 10), (6, "ff02::", 16)] {
                    let mut range = FWP_V6_ADDR_AND_MASK::default();
                    range.addr = prefix
                        .parse::<std::net::Ipv6Addr>()
                        .expect("constant IPv6 prefix")
                        .octets();
                    range.prefixLength = length;
                    let mut destination = FWPM_FILTER_CONDITION0::default();
                    destination.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                    destination.matchType = FWP_MATCH_EQUAL;
                    destination.conditionValue.r#type = FWP_V6_ADDR_MASK;
                    destination.conditionValue.Anonymous.v6AddrMask = &mut range;
                    add(slot, 15, FWP_ACTION_PERMIT, &mut [protocol, destination])?;
                }
            }
        }
        Ok(())
    })
}

pub(super) fn clear() -> io::Result<()> {
    restore_previous_backend()?;
    let engine = Engine::open()?;
    engine.transaction(|| {
        delete_filters(&engine)?;
        let code = unsafe { FwpmSubLayerDeleteByKey0(engine.0, &SUBLAYER) };
        if code != FWP_E_SUBLAYER_NOT_FOUND as u32 {
            check(code)?;
        }
        Ok(())
    })
}

/// Старые выпуски меняли currentprofile через netsh. Восстанавливаем только
/// сохраненную ими политику; при повреждении файла ничего не угадываем.
fn restore_previous_backend() -> io::Result<()> {
    use std::process::Command;
    let path = std::path::PathBuf::from(
        std::env::var_os("SYSTEMROOT").ok_or_else(|| io::Error::other("SYSTEMROOT is missing"))?,
    )
    .join("Temp")
    .join("aivpn_ks_policy.txt");
    let mut file = match open_trusted_policy(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    use std::io::Read;
    let mut saved = String::new();
    (&mut file).take(16 * 1024).read_to_string(&mut saved)?;
    let policy = saved
        .lines()
        .filter_map(|line| {
            let value = line.rsplit(':').next()?.trim().to_ascii_lowercase();
            matches!(
                value.as_str(),
                "blockinbound,allowoutbound"
                    | "blockinbound,blockoutbound"
                    | "allowinbound,allowoutbound"
                    | "allowinbound,blockoutbound"
                    | "blockinboundalways,allowoutbound"
                    | "blockinboundalways,blockoutbound"
            )
            .then_some(value)
        })
        .next()
        .ok_or_else(|| io::Error::other("Invalid saved firewall policy"))?;
    let status = Command::new("netsh")
        .args([
            "advfirewall",
            "set",
            "currentprofile",
            "firewallpolicy",
            &policy,
        ])
        .status()?;
    if !status.success() {
        return Err(io::Error::other("Cannot restore previous firewall policy"));
    }
    let status = Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command",
        "$ErrorActionPreference='Stop'; Get-NetFirewallRule -Name AIVPN_KS_ALLOW_VPN,AIVPN_KS_ALLOW_SERVER,AIVPN_KS_ALLOW_LOCAL -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop"
    ]).status()?;
    if !status.success() {
        return Err(io::Error::other("Cannot remove previous firewall rules"));
    }
    drop(file);
    std::fs::remove_file(path)
}

// Файл старого backend находится в общем Temp. Проверяем владельца и ACL
// открытого дескриптора и запрещаем конкурентную замену до восстановления.
fn open_trusted_policy(path: &std::path::Path) -> io::Result<std::fs::File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::Storage::FileSystem::*;
    let denied = || {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Untrusted saved firewall policy",
        )
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.len() > 16 * 1024
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(denied());
    }
    let mut owner = null_mut();
    let mut dacl = null_mut();
    let mut descriptor = null_mut();
    check(unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    })?;
    let trusted = |sid: PSID| unsafe {
        !sid.is_null()
            && (IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
                || IsWellKnownSid(sid, WinLocalSystemSid) != 0)
    };
    let result = (|| {
        if !trusted(owner) || dacl.is_null() {
            return Err(denied());
        }
        for index in 0..unsafe { (*dacl).AceCount } {
            let mut ace = null_mut();
            if unsafe { GetAce(dacl, u32::from(index), &mut ace) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let header = unsafe { &*(ace as *const ACE_HEADER) };
            if header.AceFlags & INHERIT_ONLY_ACE as u8 != 0 {
                continue;
            }
            if header.AceType == 1 {
                continue;
            } // ACCESS_DENIED_ACE_TYPE
            if header.AceType != 0 {
                return Err(denied());
            } // Не угадываем смысл условных ACE.
            let allowed = unsafe { &*(ace as *const ACCESS_ALLOWED_ACE) };
            let writes = FILE_WRITE_DATA
                | FILE_APPEND_DATA
                | FILE_WRITE_EA
                | FILE_WRITE_ATTRIBUTES
                | DELETE
                | WRITE_DAC
                | WRITE_OWNER
                | 0x40000000
                | 0x10000000;
            let sid = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
            if allowed.Mask & writes != 0 && !trusted(sid) {
                return Err(denied());
            }
        }
        Ok(())
    })();
    unsafe {
        windows_sys::Win32::Foundation::LocalFree(descriptor);
    }
    result?;
    Ok(file)
}
