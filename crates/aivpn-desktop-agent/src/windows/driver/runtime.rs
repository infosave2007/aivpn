use super::*;
use windows_sys::Win32::Security::{
    Authorization::ConvertStringSidToSidW, GetLengthSid, IsValidSid,
};

const BEGIN: u32 = QUERY + 28;
const POLICY: u32 = QUERY + 32;
const SID: u32 = QUERY + 36;
const CLAIM: u32 = QUERY + 40;
const SEAL: u32 = QUERY + 44;

#[derive(Clone, Copy)]
pub(crate) struct RuntimeTransaction {
    pub epoch: u64,
    pub serial: u64,
}
struct Receipt {
    transaction: RuntimeTransaction,
    group: u32,
    claim: u64,
    carried: bool,
}

impl DriverSession {
    pub(crate) fn begin_runtime(
        &self,
        namespace: [u8; 16],
        serial: u64,
        policies: usize,
    ) -> io::Result<RuntimeTransaction> {
        if namespace == [0; 16] || serial == 0 || policies > 256 {
            return Err(invalid());
        }
        let mut bytes = request(self.session.get(), 56);
        bytes[24..40].copy_from_slice(&namespace);
        bytes[40..48].copy_from_slice(&serial.to_le_bytes());
        bytes[48..52].copy_from_slice(&(policies as u32).to_le_bytes());
        let receipt = self.runtime_call(BEGIN, &bytes, None)?;
        if receipt.transaction.serial != serial {
            return Err(invalid());
        }
        Ok(receipt.transaction)
    }

    /// Digest относится к документу из authenticated Control. Epoch выдает ядро.
    pub(crate) fn runtime_policy(
        &self,
        transaction: RuntimeTransaction,
        policy: &[u8],
        digest: [u8; 32],
    ) -> io::Result<bool> {
        if policy.len() != 14376 || digest == [0; 32] {
            return Err(invalid());
        }
        let mut bytes = request(self.session.get(), 14432);
        bytes[24..14400].copy_from_slice(policy);
        bytes[40..48].copy_from_slice(&transaction.epoch.to_le_bytes());
        bytes[14400..].copy_from_slice(&digest);
        Ok(self
            .runtime_call(POLICY, &bytes, Some(transaction))?
            .carried)
    }

    /// Роли берутся из доверенного policy store. Процесс приложения получает SID
    /// из собственного OS token; переданное клиентом имя не становится identity.
    pub(crate) fn runtime_sid(
        &self,
        transaction: RuntimeTransaction,
        kind: u32,
        slot: u32,
        text: &str,
    ) -> io::Result<()> {
        if !matches!(kind, 2 | 3) || slot == 0 || text.len() > 256 || text.contains('\0') {
            return Err(invalid());
        }
        let wide = text.encode_utf16().chain([0]).collect::<Vec<_>>();
        let mut sid = ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let result = (|| {
            let length = unsafe { GetLengthSid(sid) } as usize;
            if !(8..=68).contains(&length) || unsafe { IsValidSid(sid) } == 0 {
                return Err(invalid());
            }
            let mut bytes = request(self.session.get(), 120);
            bytes[24..28].copy_from_slice(&kind.to_le_bytes());
            bytes[28..32].copy_from_slice(&slot.to_le_bytes());
            bytes[32..36].copy_from_slice(&(length as u32).to_le_bytes());
            bytes[40..40 + length]
                .copy_from_slice(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) });
            bytes[112..120].copy_from_slice(&transaction.epoch.to_le_bytes());
            self.runtime_call(SID, &bytes, Some(transaction))
                .map(|_| ())
        })();
        unsafe {
            LocalFree(sid);
        }
        result
    }

    pub(crate) fn runtime_claim(
        &self,
        transaction: RuntimeTransaction,
        owner_kind: u32,
        owner: u32,
        selector: u32,
        path: &str,
    ) -> io::Result<(u32, u64)> {
        if !path.starts_with("\\device\\") || path.contains('\0') || selector == 0 {
            return Err(invalid());
        }
        let selected = path.encode_utf16().collect::<Vec<_>>();
        if selected.len() > 4096 {
            return Err(invalid());
        }
        let file = super::local_image::open(path)?;
        let mut bytes = request(self.session.get(), 8336);
        bytes[24..28].copy_from_slice(&1u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&selector.to_le_bytes());
        bytes[32..40].copy_from_slice(&(file.raw() as usize as u64).to_le_bytes());
        bytes[120..124].copy_from_slice(&(selected.len() as u32).to_le_bytes());
        for (index, value) in selected.into_iter().enumerate() {
            bytes[128 + index * 2..130 + index * 2].copy_from_slice(&value.to_le_bytes());
        }
        bytes[8320..8324].copy_from_slice(&owner_kind.to_le_bytes());
        bytes[8324..8328].copy_from_slice(&owner.to_le_bytes());
        bytes[8328..8336].copy_from_slice(&transaction.epoch.to_le_bytes());
        let receipt = self.runtime_call(CLAIM, &bytes, Some(transaction))?;
        Ok((receipt.group, receipt.claim))
    }

    pub(crate) fn seal_runtime(&self, transaction: RuntimeTransaction) -> io::Result<()> {
        let mut bytes = request(self.session.get(), 32);
        bytes[24..32].copy_from_slice(&transaction.epoch.to_le_bytes());
        self.runtime_call(SEAL, &bytes, Some(transaction))
            .map(|_| ())
    }

    fn runtime_call(
        &self,
        code: u32,
        input: &[u8],
        expected: Option<RuntimeTransaction>,
    ) -> io::Result<Receipt> {
        service_authority()?;
        let mut bytes = [0; 56];
        exchange_bytes(&self.handle, code, input, &mut bytes)?;
        let wide = |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        if word(&bytes, 0) != 1
            || word(&bytes, 4) != 56
            || wide(8) != self.session.get()
            || word(&bytes, 16) != 0
            || word(&bytes, 20) != 0
            || wide(24) == 0
            || wide(32) == 0
        {
            return Err(invalid());
        }
        let transaction = RuntimeTransaction {
            epoch: wide(24),
            serial: wide(32),
        };
        if expected.is_some_and(|value| {
            value.epoch != transaction.epoch || value.serial != transaction.serial
        }) {
            return Err(invalid());
        }
        let flags = word(&bytes, 44);
        if flags > 1 || (code != POLICY && flags != 0) {
            return Err(invalid());
        }
        let group = word(&bytes, 40);
        let claim = wide(48);
        if if code == CLAIM {
            group == 0 || claim == 0
        } else {
            group != 0 || claim != 0
        } {
            return Err(invalid());
        }
        Ok(Receipt {
            transaction,
            group,
            claim,
            carried: flags == 1,
        })
    }
}
