use super::*;
use aivpn_desktop_policy::KernelBindings;
use std::{
    net::IpAddr,
    os::windows::io::{AsRawHandle, OwnedHandle},
};
use windows_sys::Win32::Security::{Authorization::ConvertSidToStringSidW, *};

const BIND: u32 = QUERY + 8;
const DIAGNOSE: u32 = QUERY + 12;
const SID_BYTES: usize = 68;
const DIAGNOSTIC_BYTES: usize = 264;
const BIND_BYTES: usize = 8320;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticAction {
    System,
    Block,
    VpnNotReady,
    Vpn,
}

/// Снимок для проверки policy. Не подтверждает фильтрацию или допуск соединения.
#[derive(Debug, PartialEq, Eq)]
pub struct IdentityDiagnostic {
    pub action: DiagnosticAction,
    pub generation: NonZeroU64,
    pub rule: Option<u32>,
    pub depth: u32,
    pub unresolved: bool,
    pub owner_slot: u32,
    pub executable_slot: u32,
    pub package_slot: u32,
    pub os_image_available: bool,
    pub os_path_available: bool,
    pub policy_image_resolved: bool,
    pub parent_count: u32,
    pub created: u64,
    pub volume: u64,
    pub file_id: [u8; 16],
    /// FileID может быть недоступен после image cleanup; stream identity хранится отдельно.
    pub file_id_available: bool,
    pub user_sid: String,
    pub package_sid: Option<String>,
}

impl DriverSession {
    /// Файл открывает служба. Kernel handle удерживает объект при rename/delete; запись в прежний объект запрещена.
    pub fn bind_executable(&mut self, path: &str, bindings: &KernelBindings) -> io::Result<()> {
        let slot = bindings
            .executables
            .get(path)
            .ok_or(io::ErrorKind::NotFound)?;
        if !path.starts_with("\\device\\") || path.contains('\0') {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let selected: Vec<u16> = path.encode_utf16().collect();
        if selected.len() > 4096 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let file = super::local_image::open(path)?;
        self.bind(1, slot.get(), file.raw(), &[], &selected)
    }

    /// Token открывается службой; роли берутся из проверенного плана, SID - из ОС.
    pub fn bind_token(&mut self, token: &OwnedHandle, bindings: &KernelBindings) -> io::Result<()> {
        let owner = self.bind_selected_sid(token, TokenUser, 2, &bindings.windows_owners)?;
        let package = self.bind_selected_sid(token, TokenAppContainerSid, 3, &bindings.packages)?;
        if owner || package {
            Ok(())
        } else {
            Err(io::ErrorKind::NotFound.into())
        }
    }

    fn bind_selected_sid(
        &self,
        token: &OwnedHandle,
        class: TOKEN_INFORMATION_CLASS,
        kind: u32,
        selected: &std::collections::HashMap<String, std::num::NonZeroU32>,
    ) -> io::Result<bool> {
        let Some(sid) = token_sid(token, class)? else {
            return Ok(false);
        };
        let text = sid_text(&sid)?;
        let Some(slot) = selected.get(&text) else {
            return Ok(false);
        };
        self.bind(kind, slot.get(), token.as_raw_handle(), &sid, &[])?;
        Ok(true)
    }

    fn bind(
        &self,
        kind: u32,
        slot: u32,
        handle: HANDLE,
        sid: &[u8],
        path: &[u16],
    ) -> io::Result<()> {
        let mut input = request(self.session.get(), BIND_BYTES);
        input[24..28].copy_from_slice(&kind.to_le_bytes());
        input[28..32].copy_from_slice(&slot.to_le_bytes());
        input[32..40].copy_from_slice(&(handle as usize as u64).to_le_bytes());
        input[40..44].copy_from_slice(&(sid.len() as u32).to_le_bytes());
        input[48..48 + sid.len()].copy_from_slice(sid);
        input[120..124].copy_from_slice(&(path.len() as u32).to_le_bytes());
        for (index, unit) in path.iter().enumerate() {
            input[128 + index * 2..130 + index * 2].copy_from_slice(&unit.to_le_bytes());
        }
        self.exchange(BIND, &input).map(|_| ())
    }

    /// Process handle не назначает роль. Драйвер сопоставляет сохраненные объекты ОС.
    pub fn diagnose(
        &mut self,
        process: &OwnedHandle,
        destination: IpAddr,
    ) -> io::Result<IdentityDiagnostic> {
        service_authority()?;
        let mut input = request(self.session.get(), 56);
        input[24..32].copy_from_slice(&(process.as_raw_handle() as usize as u64).to_le_bytes());
        let destination = match destination {
            IpAddr::V6(address) => address
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(destination),
            _ => destination,
        };
        match destination {
            IpAddr::V4(address) => {
                input[32] = 4;
                input[40..44].copy_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                input[32] = 6;
                input[40..56].copy_from_slice(&address.octets());
            }
        }
        let mut output = [0; DIAGNOSTIC_BYTES];
        exchange_bytes(&self.handle, DIAGNOSE, &input, &mut output)?;
        decode_diagnostic(&output, self.session)
    }
}

fn token_sid(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> io::Result<Option<Vec<u8>>> {
    let mut length = 0;
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            ptr::null_mut(),
            0,
            &mut length,
        );
    }
    if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::last_os_error());
    }
    if length as usize > SID_BYTES + 32 {
        return Err(invalid());
    }
    let mut data = vec![0u64; (length as usize).div_ceil(8)];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            data.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let sid = if class == TokenUser {
        unsafe { (*data.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    } else {
        unsafe { (*data.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>()).TokenAppContainer }
    };
    if sid.is_null() {
        return Ok(None);
    }
    let length = unsafe { GetLengthSid(sid) } as usize;
    if length > SID_BYTES || unsafe { IsValidSid(sid) } == 0 {
        return Err(invalid());
    }
    Ok(Some(
        unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) }.to_vec(),
    ))
}

fn sid_text(bytes: &[u8]) -> io::Result<String> {
    if bytes.len() < 8
        || bytes.len() > SID_BYTES
        || bytes[0] != 1
        || bytes[1] > 15
        || 8 + 4 * bytes[1] as usize != bytes.len()
    {
        return Err(invalid());
    }
    // Win32 ожидает выровненный SID, ответ ABI содержит массив байтов.
    let mut aligned = [0u32; SID_BYTES / 4];
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), aligned.as_mut_ptr().cast(), bytes.len());
    }
    let mut text = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(aligned.as_ptr().cast_mut().cast(), &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let result = unsafe {
        let mut length = 0;
        while *text.add(length) != 0 {
            length += 1;
        }
        String::from_utf16(std::slice::from_raw_parts(text, length)).map_err(|_| invalid())
    };
    unsafe {
        LocalFree(text.cast());
    }
    result
}

fn diagnostic_sid(
    bytes: &[u8; DIAGNOSTIC_BYTES],
    start: usize,
    length: usize,
) -> io::Result<Option<String>> {
    if length > SID_BYTES
        || bytes[start + length..start + SID_BYTES]
            .iter()
            .any(|value| *value != 0)
    {
        return Err(invalid());
    }
    if length == 0 {
        return Ok(None);
    }
    sid_text(&bytes[start..start + length]).map(Some)
}

fn decode_diagnostic(
    bytes: &[u8; DIAGNOSTIC_BYTES],
    session: NonZeroU64,
) -> io::Result<IdentityDiagnostic> {
    let wide = |at| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    if !diagnostic_header(bytes, session) || !diagnostic_origin(bytes) {
        return Err(invalid());
    }
    Ok(IdentityDiagnostic {
        action: diagnostic_action(bytes)?,
        generation: NonZeroU64::new(wide(48)).ok_or_else(invalid)?,
        rule: diagnostic_rule(word(bytes, 32))?,
        depth: word(bytes, 36),
        unresolved: word(bytes, 40) != 0,
        owner_slot: word(bytes, 60),
        executable_slot: word(bytes, 64),
        package_slot: word(bytes, 68),
        os_image_available: word(bytes, 80) != 0,
        os_path_available: word(bytes, 84) != 0,
        policy_image_resolved: word(bytes, 72) != 0,
        parent_count: word(bytes, 76),
        created: wide(88),
        volume: wide(96),
        file_id: bytes[104..120].try_into().unwrap(),
        file_id_available: bytes[104..120] != [0; 16],
        user_sid: diagnostic_sid(bytes, 128, word(bytes, 120) as usize)?.ok_or_else(invalid)?,
        package_sid: diagnostic_sid(bytes, 196, word(bytes, 124) as usize)?,
    })
}

fn diagnostic_header(bytes: &[u8; DIAGNOSTIC_BYTES], session: NonZeroU64) -> bool {
    word(bytes, 0) == 1
        && word(bytes, 4) == DIAGNOSTIC_BYTES as u32
        && u64::from_le_bytes(bytes[8..16].try_into().unwrap()) == session.get()
        && [16, 20, 44].into_iter().all(|at| word(bytes, at) == 0)
}

fn diagnostic_origin(bytes: &[u8; DIAGNOSTIC_BYTES]) -> bool {
    word(bytes, 40) <= 1
        && word(bytes, 56) == 2
        && word(bytes, 72) <= 1
        && word(bytes, 76) <= 32
        && word(bytes, 36) <= word(bytes, 76)
        && bytes[88..96] != [0; 8]
        && diagnostic_image(bytes)
}

fn diagnostic_image(bytes: &[u8; DIAGNOSTIC_BYTES]) -> bool {
    word(bytes, 80) <= 1
        && word(bytes, 84) <= 1
        && word(bytes, 72) <= word(bytes, 80)
        && word(bytes, 72) <= word(bytes, 84)
}

fn diagnostic_action(bytes: &[u8; DIAGNOSTIC_BYTES]) -> io::Result<DiagnosticAction> {
    match (word(bytes, 24), word(bytes, 28)) {
        (0, 0) => Ok(DiagnosticAction::System),
        (1, 0) => Ok(DiagnosticAction::Block),
        (1, _) => Ok(DiagnosticAction::VpnNotReady),
        (2, profile) if profile != 0 => Ok(DiagnosticAction::Vpn),
        _ => Err(invalid()),
    }
}

fn diagnostic_rule(rule: u32) -> io::Result<Option<u32>> {
    match rule {
        u32::MAX => Ok(None),
        value if value < 256 => Ok(Some(value)),
        _ => Err(invalid()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response() -> [u8; DIAGNOSTIC_BYTES] {
        let mut bytes = [0; DIAGNOSTIC_BYTES];
        bytes[0] = 1;
        bytes[4..8].copy_from_slice(&(DIAGNOSTIC_BYTES as u32).to_le_bytes());
        bytes[8] = 9;
        bytes[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[48] = 1;
        bytes[56] = 2;
        bytes[88] = 1;
        bytes[120] = 12;
        bytes[128..140].copy_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
        bytes
    }
    #[test]
    fn missing_file_id_metadata_does_not_hide_retained_os_image() {
        let mut bytes = response();
        bytes[72] = 1;
        bytes[80] = 1;
        bytes[84] = 1;
        let session = NonZeroU64::new(9).unwrap();
        let result = decode_diagnostic(&bytes, session).unwrap();
        assert!(result.os_image_available && result.policy_image_resolved);
        assert!(!result.file_id_available);
        bytes[104] = 7;
        assert!(
            decode_diagnostic(&bytes, session)
                .unwrap()
                .file_id_available
        );
    }
    #[test]
    fn diagnostic_rejects_unsupported_actions_reserved_fields_and_invalid_identity() {
        let good = response();
        let session = NonZeroU64::new(9).unwrap();
        assert_eq!(
            decode_diagnostic(&good, session).unwrap().user_sid,
            "S-1-5-18"
        );
        for offset in [
            0, 4, 8, 16, 20, 24, 28, 32, 36, 40, 44, 48, 56, 72, 76, 80, 84, 88, 120, 124, 128,
            129, 195, 263,
        ] {
            let mut bad = good;
            bad[offset] = if [32, 48, 88].contains(&offset) {
                0
            } else {
                255
            };
            assert!(decode_diagnostic(&bad, session).is_err(), "offset={offset}");
        }
        let mut vpn = good;
        vpn[24] = 1;
        vpn[28] = 7;
        assert_eq!(
            decode_diagnostic(&vpn, session).unwrap().action,
            DiagnosticAction::VpnNotReady
        );
        vpn[24] = 2;
        assert_eq!(
            decode_diagnostic(&vpn, session).unwrap().action,
            DiagnosticAction::Vpn
        );
        vpn[28] = 0;
        assert!(decode_diagnostic(&vpn, session).is_err());
        vpn[24] = 3;
        assert!(decode_diagnostic(&vpn, session).is_err());
    }
}
