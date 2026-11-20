//! Собственные постоянные WFP filters. Существующие объекты проверяются без перезаписи.
use super::{
    api::{check, denied},
    security::service_authority,
};
use aivpn_desktop_policy::Owner;
use sha2::{Digest, Sha256};
use std::{io, path::Path, ptr};
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::*,
        NetworkManagement::WindowsFilteringPlatform::*,
        Security::{Authorization::*, *},
        System::Rpc::RPC_C_AUTHN_WINNT,
    },
};

mod retirement;
pub(super) use retirement::remove_owned;

const PROVIDER: GUID = GUID::from_u128(0x60ecfb00_24dc_47d9_b548_c50294d84a8c);
const SUBLAYER: GUID = GUID::from_u128(0x9bea0c00_ff59_46ec_ab91_8ff990ce4936);
const CONNECT4: GUID = GUID::from_u128(0xf3ac9bae_fd40_48e6_b621_270fed866b4e);
const CONNECT6: GUID = GUID::from_u128(0x5da18206_3ccd_436c_ba84_3916497c7996);
const AUTH4: GUID = GUID::from_u128(0xb92680f1_dc3f_436b_b358_034f5e03e62c);
const AUTH6: GUID = GUID::from_u128(0x7a24c87f_a8d4_4e54_ae47_6880830bd09e);
const CLOSE4: GUID = GUID::from_u128(0x1c9ef8d5_f54c_469a_a88f_96485732ddce);
const CLOSE6: GUID = GUID::from_u128(0x63ff2c51_eac9_483e_89ff_ab5cb71980ab);

const FLOW4: GUID = GUID::from_u128(0x0e2e4896_6945_4ccc_959e_39ca6df95784);
const FLOW6: GUID = GUID::from_u128(0xf665fca8_1d03_45a6_abca_e20f22214642);
const RELEASE4: GUID = GUID::from_u128(0x607e7036_044f_4b3d_a3f2_1c5e81fae28c);
const RELEASE6: GUID = GUID::from_u128(0x0be2cd09_b54b_437e_acc6_7bad448ceefa);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}
fn same(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}
fn code(status: u32) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}
fn provider(key: *const GUID) -> bool {
    !key.is_null() && same(unsafe { &*key }, &PROVIDER)
}
struct Engine(HANDLE);
impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            FwpmTransactionAbort0(self.0);
            FwpmEngineClose0(self.0);
        }
    }
}
struct Memory<T>(*mut T);
impl<T> Drop for Memory<T> {
    fn drop(&mut self) {
        unsafe {
            FwpmFreeMemory0((&mut self.0 as *mut *mut T).cast());
        }
    }
}
struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Installation {
    pub sublayer_weight: u16,
}

pub(super) fn ensure_system(previous: Option<Installation>) -> io::Result<Installation> {
    service_authority()?;
    let mut handle = ptr::null_mut();
    code(unsafe {
        FwpmEngineOpen0(
            ptr::null(),
            RPC_C_AUTHN_WINNT,
            ptr::null(),
            ptr::null(),
            &mut handle,
        )
    })?;
    let engine = Engine(handle);
    code(unsafe { FwpmTransactionBegin0(engine.0, 0) })?;
    ensure_provider(&engine).map_err(|e| io::Error::new(e.kind(), format!("Provider: {e}")))?;
    let sublayer_weight =
        ensure_sublayer(&engine).map_err(|e| io::Error::new(e.kind(), format!("Sublayer: {e}")))?;
    let installation = Installation { sublayer_weight };
    if previous.is_some_and(|value| value != installation) {
        return Err(io::Error::other(
            "Назначенный BFE вес sublayer изменился во время работы",
        ));
    }
    let mut sd = ptr::null_mut();
    let mut size = 0;
    check(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide("D:(A;;CC;;;SY)").as_ptr(),
            1,
            &mut sd,
            &mut size,
        )
    })?;
    let _sd = Descriptor(sd);
    let mut owner = FWP_BYTE_BLOB {
        size,
        data: sd.cast(),
    };
    for (layer, callout, scoped) in retirement::system_objects() {
        ensure_callout(&engine, &layer, &callout)
            .map_err(|e| io::Error::new(e.kind(), format!("Callout {:08x}: {e}", callout.data1)))?;
        ensure_filter(
            &engine,
            &layer,
            &callout,
            if scoped { Some(&mut owner) } else { None },
        )
        .map_err(|e| io::Error::new(e.kind(), format!("Filter {:08x}: {e}", callout.data1)))?;
    }
    code(unsafe { FwpmTransactionCommit0(engine.0) })?;
    Ok(installation)
}
pub(super) fn ensure_owner(namespace: [u8; 16], owner: &Owner) -> io::Result<()> {
    service_authority()?;
    let descriptor = match owner {
        Owner::Machine {} => None,
        Owner::WindowsUser { sid } => {
            if !sid.starts_with("S-")
                || sid
                    .bytes()
                    .any(|b| !b.is_ascii_digit() && b != b'S' && b != b'-')
            {
                return Err(denied());
            }
            let mut sd = ptr::null_mut();
            let mut size = 0;
            check(unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide(&format!("D:(A;;CC;;;{sid})")).as_ptr(),
                    1,
                    &mut sd,
                    &mut size,
                )
            })?;
            Some((Descriptor(sd), size))
        }
        _ => return Err(denied()),
    };
    let mut handle = ptr::null_mut();
    code(unsafe {
        FwpmEngineOpen0(
            ptr::null(),
            RPC_C_AUTHN_WINNT,
            ptr::null(),
            ptr::null(),
            &mut handle,
        )
    })?;
    let engine = Engine(handle);
    code(unsafe { FwpmTransactionBegin0(engine.0, 0) })?;
    let mut condition = FWPM_FILTER_CONDITION0::default();
    let mut blob = descriptor.as_ref().map(|(descriptor, size)| FWP_BYTE_BLOB {
        size: *size,
        data: descriptor.0.cast(),
    });
    if let Some(blob) = blob.as_mut() {
        condition.fieldKey = FWPM_CONDITION_ALE_USER_ID;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.r#type = FWP_SECURITY_DESCRIPTOR_TYPE;
        condition.conditionValue.Anonymous.sd = blob;
    }
    for (index, (layer, callout)) in [
        (FWPM_LAYER_ALE_AUTH_CONNECT_V4, AUTH4),
        (FWPM_LAYER_ALE_AUTH_CONNECT_V6, AUTH6),
        (FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4, CLOSE4),
        (FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6, CLOSE6),
    ]
    .into_iter()
    .enumerate()
    {
        let mut identity = namespace.to_vec();
        identity.extend(serde_json::to_vec(owner)?);
        let key = retirement::derived_key(b"aivpn-windows-owner-filter-v1", &identity, index);
        ensure_selected_filter(
            &engine,
            &layer,
            &callout,
            &key,
            if descriptor.is_some() {
                Some(&mut condition)
            } else {
                None
            },
        )?;
    }
    code(unsafe { FwpmTransactionCommit0(engine.0) })
}
fn ensure_provider(engine: &Engine) -> io::Result<()> {
    let name = wide("AIVPN guarded packet channel");
    let mut value = FWPM_PROVIDER0::default();
    value.providerKey = PROVIDER;
    value.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
    value.displayData.name = name.as_ptr().cast_mut();
    let result = unsafe { FwpmProviderAdd0(engine.0, &value, ptr::null_mut()) };
    if result != FWP_E_ALREADY_EXISTS as u32 {
        return code(result);
    }
    let mut existing = ptr::null_mut();
    code(unsafe { FwpmProviderGetByKey0(engine.0, &PROVIDER, &mut existing) })?;
    let memory = Memory(existing);
    let existing = unsafe { &*memory.0 };
    if existing.flags != FWPM_PROVIDER_FLAG_PERSISTENT
        || existing.providerData.size != 0
        || !existing.serviceName.is_null()
    {
        return Err(io::Error::other(format!(
            "Несовместимый объект: flags={}, data={}, service={}",
            existing.flags,
            existing.providerData.size,
            !existing.serviceName.is_null()
        )));
    }
    Ok(())
}
fn ensure_sublayer(engine: &Engine) -> io::Result<u16> {
    let name = wide("AIVPN guarded packet channel");
    let mut value = FWPM_SUBLAYER0::default();
    value.subLayerKey = SUBLAYER;
    value.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    value.weight = 0x7800;
    value.providerKey = (&PROVIDER as *const GUID).cast_mut();
    value.displayData.name = name.as_ptr().cast_mut();
    let result = unsafe { FwpmSubLayerAdd0(engine.0, &value, ptr::null_mut()) };
    if result != 0 && result != FWP_E_ALREADY_EXISTS as u32 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let mut existing = ptr::null_mut();
    code(unsafe { FwpmSubLayerGetByKey0(engine.0, &SUBLAYER, &mut existing) })?;
    let memory = Memory(existing);
    let existing = unsafe { &*memory.0 };
    if !provider(existing.providerKey)
        || existing.flags != value.flags
        || existing.providerData.size != 0
    {
        return Err(io::Error::other(format!(
            "Несовместимый sublayer: provider={}, flags={}, weight={}, data={}",
            provider(existing.providerKey),
            existing.flags,
            existing.weight,
            existing.providerData.size
        )));
    }
    // BFE назначает ближайший свободный вес. Все наши filters находятся в этом
    // sublayer; их взаимный порядок проверяется отдельно. Приоритет над чужими
    // sublayers не является условием допуска или разрешением обходить их блокировки.
    Ok(existing.weight)
}
fn ensure_callout(engine: &Engine, layer: &GUID, key: &GUID) -> io::Result<()> {
    let name = wide("AIVPN guarded packet channel");
    let mut value = FWPM_CALLOUT0::default();
    value.calloutKey = *key;
    value.applicableLayer = *layer;
    value.flags = FWPM_CALLOUT_FLAG_PERSISTENT;
    value.providerKey = (&PROVIDER as *const GUID).cast_mut();
    value.displayData.name = name.as_ptr().cast_mut();
    let result = unsafe { FwpmCalloutAdd0(engine.0, &value, ptr::null_mut(), ptr::null_mut()) };
    if result != 0 && result != FWP_E_ALREADY_EXISTS as u32 {
        return code(result);
    }
    let mut existing = ptr::null_mut();
    code(unsafe { FwpmCalloutGetByKey0(engine.0, key, &mut existing) })?;
    let memory = Memory(existing);
    let existing = unsafe { &*memory.0 };
    if !provider(existing.providerKey)
        || !same(&existing.applicableLayer, layer)
        || existing.providerData.size != 0
        || existing.flags != FWPM_CALLOUT_FLAG_PERSISTENT | FWPM_CALLOUT_FLAG_REGISTERED
    {
        return Err(io::Error::other(format!(
            "Несовместимый callout: flags={}, provider={}, layer={}, data={}",
            existing.flags,
            provider(existing.providerKey),
            same(&existing.applicableLayer, layer),
            existing.providerData.size
        )));
    }
    Ok(())
}
fn ensure_filter(
    engine: &Engine,
    layer: &GUID,
    key: &GUID,
    owner: Option<&mut FWP_BYTE_BLOB>,
) -> io::Result<()> {
    let mut condition = FWPM_FILTER_CONDITION0::default();
    condition.fieldKey = FWPM_CONDITION_ALE_USER_ID;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.r#type = FWP_SECURITY_DESCRIPTOR_TYPE;
    condition.conditionValue.Anonymous.sd = owner.map_or(ptr::null_mut(), |p| p);
    let condition = if unsafe { condition.conditionValue.Anonymous.sd }.is_null() {
        None
    } else {
        Some(&mut condition)
    };
    ensure_selected_filter(engine, layer, key, key, condition)
}
fn ensure_selected_filter(
    engine: &Engine,
    layer: &GUID,
    callout: &GUID,
    key: &GUID,
    mut condition: Option<&mut FWPM_FILTER_CONDITION0>,
) -> io::Result<()> {
    let name = wide("AIVPN scoped owner policy");
    let mut value = selected_filter_value(layer, callout, key, condition.as_deref_mut());
    value.displayData.name = name.as_ptr().cast_mut();
    let result = unsafe { FwpmFilterAdd0(engine.0, &value, ptr::null_mut(), ptr::null_mut()) };
    if result != 0 && result != FWP_E_ALREADY_EXISTS as u32 {
        return code(result);
    }
    let mut existing = ptr::null_mut();
    code(unsafe { FwpmFilterGetByKey0(engine.0, key, &mut existing) })?;
    let memory = Memory(existing);
    let existing = unsafe { &*memory.0 };
    verify_selected_filter(existing, &value, condition.as_deref())
}

fn selected_filter_value(
    layer: &GUID,
    callout: &GUID,
    key: &GUID,
    mut condition: Option<&mut FWPM_FILTER_CONDITION0>,
) -> FWPM_FILTER0 {
    let mut value = FWPM_FILTER0::default();
    value.filterKey = *key;
    value.flags = FWPM_FILTER_FLAG_PERSISTENT;
    // BFE индексирует APP_ID на AUTH_CONNECT. Запрашиваем этот документированный
    // флаг явно и проверяем полный результат, включая вновь созданный filter.
    if condition
        .as_ref()
        .is_some_and(|c| same(&c.fieldKey, &FWPM_CONDITION_ALE_APP_ID))
        && (same(layer, &FWPM_LAYER_ALE_AUTH_CONNECT_V4)
            || same(layer, &FWPM_LAYER_ALE_AUTH_CONNECT_V6))
    {
        value.flags |= FWPM_FILTER_FLAG_INDEXED;
    }
    value.providerKey = (&PROVIDER as *const GUID).cast_mut();
    value.layerKey = *layer;
    value.subLayerKey = SUBLAYER;
    value.weight.r#type = FWP_UINT8;
    value.weight.Anonymous.uint8 = 15;
    if let Some(condition) = condition.as_deref_mut() {
        value.numFilterConditions = 1;
        value.filterCondition = condition;
    }
    value.action.r#type = FWP_ACTION_CALLOUT_UNKNOWN;
    value.action.Anonymous.calloutKey = *callout;
    value
}

fn verify_selected_filter(
    existing: &FWPM_FILTER0,
    value: &FWPM_FILTER0,
    condition: Option<&FWPM_FILTER_CONDITION0>,
) -> io::Result<()> {
    if !provider(existing.providerKey)
        || !same(&existing.layerKey, &value.layerKey)
        || !same(&existing.subLayerKey, &SUBLAYER)
        || existing.flags != value.flags
        || existing.numFilterConditions != value.numFilterConditions
        || existing.action.r#type != value.action.r#type
        || !same(unsafe { &existing.action.Anonymous.calloutKey }, unsafe {
            &value.action.Anonymous.calloutKey
        })
        || existing.weight.r#type != FWP_UINT8
        || unsafe { existing.weight.Anonymous.uint8 } != 15
        || existing.providerData.size != 0
        || unsafe { existing.Anonymous.rawContext } != 0
    {
        return Err(io::Error::other(format!("Несовместимый filter: flags={}, provider={}, layer={}, sublayer={}, conditions={}, weight_type={}, action={}, context={}", existing.flags, provider(existing.providerKey), same(&existing.layerKey, &value.layerKey), same(&existing.subLayerKey, &SUBLAYER), existing.numFilterConditions, existing.weight.r#type, existing.action.r#type, unsafe { existing.Anonymous.rawContext })));
    }
    if value.numFilterConditions != 0 {
        if existing.filterCondition.is_null() {
            return Err(denied());
        }
        let actual = unsafe { &*existing.filterCondition };
        let condition = condition.ok_or_else(denied)?;
        if !same(&actual.fieldKey, &condition.fieldKey)
            || actual.matchType != condition.matchType
            || actual.conditionValue.r#type != condition.conditionValue.r#type
        {
            return Err(denied());
        }
        let (actual, expected) = if condition.conditionValue.r#type == FWP_SECURITY_DESCRIPTOR_TYPE
        {
            unsafe {
                (
                    actual.conditionValue.Anonymous.sd,
                    condition.conditionValue.Anonymous.sd,
                )
            }
        } else if condition.conditionValue.r#type == FWP_BYTE_BLOB_TYPE {
            unsafe {
                (
                    actual.conditionValue.Anonymous.byteBlob,
                    condition.conditionValue.Anonymous.byteBlob,
                )
            }
        } else {
            return Err(denied());
        };
        if actual.is_null()
            || unsafe { (*actual).size != (*expected).size || (*actual).data.is_null() }
        {
            return Err(denied());
        }
        if unsafe {
            std::slice::from_raw_parts((*actual).data, (*actual).size as usize)
                != std::slice::from_raw_parts((*expected).data, (*expected).size as usize)
        } {
            return Err(denied());
        }
    }
    Ok(())
}

/// AppId выбирает только обязательный вызов kernel guard. Он не дает worker
/// транспортного допуска: kernel требует удержанный process/lease/endpoint/peer.
pub(super) fn ensure_worker(path: &Path) -> io::Result<()> {
    service_authority()?;
    let mut app = ptr::null_mut();
    code(unsafe { FwpmGetAppIdFromFileName0(wide(&path.to_string_lossy()).as_ptr(), &mut app) })?;
    let app = Memory(app);
    let mut handle = ptr::null_mut();
    code(unsafe {
        FwpmEngineOpen0(
            ptr::null(),
            RPC_C_AUTHN_WINNT,
            ptr::null(),
            ptr::null(),
            &mut handle,
        )
    })?;
    let engine = Engine(handle);
    code(unsafe { FwpmTransactionBegin0(engine.0, 0) })?;
    let mut condition = FWPM_FILTER_CONDITION0::default();
    condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
    condition.conditionValue.Anonymous.byteBlob = app.0;
    let app_bytes = unsafe { std::slice::from_raw_parts((*app.0).data, (*app.0).size as usize) };
    for (index, (layer, callout)) in [
        (FWPM_LAYER_ALE_AUTH_CONNECT_V4, AUTH4),
        (FWPM_LAYER_ALE_AUTH_CONNECT_V6, AUTH6),
        (FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4, CLOSE4),
        (FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6, CLOSE6),
    ]
    .into_iter()
    .enumerate()
    {
        let key = retirement::derived_key(b"aivpn-worker-filter-v2", app_bytes, index);
        ensure_selected_filter(&engine, &layer, &callout, &key, Some(&mut condition))?;
    }
    code(unsafe { FwpmTransactionCommit0(engine.0) })
}
