//! BFE откатывает всю транзакцию, если хотя бы один объект не принадлежит установке.
use super::*;
use crate::maintenance::DecommissionProof;
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

pub(super) fn system_objects() -> [(GUID, GUID, bool); 10] {
    [
        (FWPM_LAYER_OUTBOUND_IPPACKET_V4, CONNECT4, false),
        (FWPM_LAYER_OUTBOUND_IPPACKET_V6, CONNECT6, false),
        (FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4, FLOW4, false),
        (FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6, FLOW6, false),
        (FWPM_LAYER_ALE_RESOURCE_RELEASE_V4, RELEASE4, false),
        (FWPM_LAYER_ALE_RESOURCE_RELEASE_V6, RELEASE6, false),
        (FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4, CLOSE4, true),
        (FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6, CLOSE6, true),
        (FWPM_LAYER_ALE_AUTH_CONNECT_V4, AUTH4, true),
        (FWPM_LAYER_ALE_AUTH_CONNECT_V6, AUTH6, true),
    ]
}

pub(super) fn derived_key(domain: &[u8], identity: &[u8], index: usize) -> GUID {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(identity);
    hash.update([index as u8]);
    let digest = hash.finalize();
    GUID::from_u128(u128::from_be_bytes(digest[..16].try_into().unwrap()))
}

fn blob_bytes(blob: *const FWP_BYTE_BLOB) -> io::Result<Vec<u8>> {
    // Дескрипторы получены от BFE и живут до освобождения Memory с результатом enum.
    let blob = unsafe { blob.as_ref() }.ok_or_else(denied)?;
    if blob.size == 0 || blob.size > 65536 || blob.data.is_null() {
        return Err(denied());
    }
    Ok(unsafe { std::slice::from_raw_parts(blob.data, blob.size as usize) }.to_vec())
}

fn descriptor_sid(blob: *const FWP_BYTE_BLOB) -> io::Result<String> {
    let bytes = blob_bytes(blob)?;
    let sd = bytes.as_ptr().cast_mut().cast();
    if bytes.len() < std::mem::size_of::<SECURITY_DESCRIPTOR_RELATIVE>()
        || unsafe { IsValidSecurityDescriptor(sd) } == 0
        || unsafe { GetSecurityDescriptorLength(sd) } as usize != bytes.len()
    {
        return Err(denied());
    }
    let mut control = 0;
    let mut revision = 0;
    check(unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) })?;
    if control & SE_SELF_RELATIVE == 0 {
        return Err(denied());
    }
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = ptr::null_mut();
    check(unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut acl, &mut defaulted) })?;
    if present == 0 || defaulted != 0 || acl.is_null() || unsafe { (*acl).AceCount } != 1 {
        return Err(denied());
    }
    let mut ace = ptr::null_mut();
    check(unsafe { GetAce(acl, 0, &mut ace) })?;
    let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
    let sid = (&ace.SidStart as *const u32).cast_mut().cast();
    if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8
        || ace.Header.AceFlags != 0
        || ace.Mask != 1
        || unsafe { IsValidSid(sid) } == 0
        || usize::from(ace.Header.AceSize) != 8 + unsafe { GetLengthSid(sid) } as usize
    {
        return Err(denied());
    }
    let mut text = ptr::null_mut();
    check(unsafe { ConvertSidToStringSidW(sid, &mut text) })?;
    let text_memory = Descriptor(text.cast());
    let mut length = 0;
    while length < 192 && unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    if length == 192 {
        return Err(denied());
    }
    let sid_text = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
        .map_err(|_| denied())?;
    drop(text_memory);
    let mut canonical = ptr::null_mut();
    let mut size = 0;
    check(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(&format!("D:(A;;CC;;;{sid_text})")).as_ptr(),
            1,
            &mut canonical,
            &mut size,
        )
    })?;
    let canonical = Descriptor(canonical);
    if bytes != unsafe { std::slice::from_raw_parts(canonical.0.cast::<u8>(), size as usize) } {
        return Err(denied());
    }
    Ok(sid_text)
}

fn condition(filter: &FWPM_FILTER0) -> io::Result<Option<&FWPM_FILTER_CONDITION0>> {
    match filter.numFilterConditions {
        0 => Ok(None),
        1 if !filter.filterCondition.is_null() => {
            let condition = unsafe { &*filter.filterCondition };
            if condition.matchType != FWP_MATCH_EQUAL {
                return Err(denied());
            }
            Ok(Some(condition))
        }
        _ => Err(denied()),
    }
}

fn verify_filter(filter: &FWPM_FILTER0, namespace: [u8; 16]) -> io::Result<()> {
    let selected = condition(filter)?;
    let sid = if let Some(condition) = selected {
        if same(&condition.fieldKey, &FWPM_CONDITION_ALE_USER_ID)
            && condition.conditionValue.r#type == FWP_SECURITY_DESCRIPTOR_TYPE
        {
            Some(descriptor_sid(unsafe {
                condition.conditionValue.Anonymous.sd
            })?)
        } else {
            None
        }
    } else {
        None
    };
    for (layer, key, scoped) in system_objects() {
        if same(&filter.filterKey, &key) {
            if scoped && sid.as_deref() != Some("S-1-5-18") || !scoped && selected.is_some() {
                return Err(denied());
            }
            let mut copy = selected.copied();
            let value = selected_filter_value(&layer, &key, &key, copy.as_mut());
            return verify_selected_filter(filter, &value, selected);
        }
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
        let key = if selected.is_none() || sid.is_some() {
            let owner = sid
                .as_ref()
                .map_or(Owner::Machine {}, |sid| Owner::WindowsUser {
                    sid: sid.clone(),
                });
            let mut identity = namespace.to_vec();
            identity.extend(serde_json::to_vec(&owner)?);
            derived_key(b"aivpn-windows-owner-filter-v1", &identity, index)
        } else {
            let condition = selected.ok_or_else(denied)?;
            if !same(&condition.fieldKey, &FWPM_CONDITION_ALE_APP_ID)
                || condition.conditionValue.r#type != FWP_BYTE_BLOB_TYPE
            {
                return Err(denied());
            }
            let bytes = blob_bytes(unsafe { condition.conditionValue.Anonymous.byteBlob })?;
            if bytes.len() % 2 != 0 {
                return Err(denied());
            }
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            if units.last() != Some(&0) || units[..units.len() - 1].contains(&0) {
                return Err(denied());
            }
            let path = String::from_utf16(&units[..units.len() - 1]).map_err(|_| denied())?;
            if !path.starts_with(r"\device\")
                || !(path.ends_with(r"\aivpn-packet-worker.exe") || path.ends_with(r"\aivpn.exe"))
            {
                return Err(denied());
            }
            derived_key(b"aivpn-worker-filter-v2", &bytes, index)
        };
        if same(&filter.filterKey, &key) {
            let mut copy = selected.copied();
            let value = selected_filter_value(&layer, &callout, &key, copy.as_mut());
            return verify_selected_filter(filter, &value, selected);
        }
    }
    Err(denied())
}

struct Enumeration<'a> {
    engine: &'a Engine,
    handle: HANDLE,
}
impl Drop for Enumeration<'_> {
    fn drop(&mut self) {
        unsafe {
            FwpmFilterDestroyEnumHandle0(self.engine.0, self.handle);
        }
    }
}

fn filter_ids(engine: &Engine, namespace: [u8; 16]) -> io::Result<Vec<u64>> {
    let mut handle = ptr::null_mut();
    // Нулевой template перечисляет все layers. GUID_NULL внутри template не является layer.
    code(unsafe { FwpmFilterCreateEnumHandle0(engine.0, ptr::null(), &mut handle) })?;
    let enumeration = Enumeration { engine, handle };
    let mut ids = Vec::new();
    let mut total = 0;
    loop {
        let mut entries = ptr::null_mut();
        let mut count = 0;
        code(unsafe {
            FwpmFilterEnum0(engine.0, enumeration.handle, 256, &mut entries, &mut count)
        })?;
        let entries = Memory(entries);
        if count == 0 {
            break;
        }
        total += count as usize;
        if count > 256 || entries.0.is_null() || total > 65536 {
            return Err(denied());
        }
        for filter in unsafe { std::slice::from_raw_parts(entries.0, count as usize) } {
            let filter = unsafe { filter.as_ref() }.ok_or_else(denied)?;
            if !provider(filter.providerKey) {
                continue;
            }
            verify_filter(filter, namespace).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "Принадлежность WFP filter {} не подтверждена: {error}",
                        filter.filterId
                    ),
                )
            })?;
            ids.push(filter.filterId);
        }
    }
    Ok(ids)
}

pub(in crate::windows) fn remove_owned(
    proof: &DecommissionProof<'_>,
    already_complete: bool,
) -> io::Result<()> {
    service_authority()?;
    proof.confirm()?;
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
    let mut provider_pointer = ptr::null_mut();
    let result = unsafe { FwpmProviderGetByKey0(engine.0, &PROVIDER, &mut provider_pointer) };
    let absent = result == FWP_E_PROVIDER_NOT_FOUND as u32;
    if !absent {
        code(result)?;
    }
    let provider_memory = Memory(provider_pointer);
    if !absent {
        let value = unsafe { &*provider_memory.0 };
        if already_complete
            || value.flags != FWPM_PROVIDER_FLAG_PERSISTENT
            || value.providerData.size != 0
            || !value.serviceName.is_null()
        {
            return Err(denied());
        }
    }
    let mut sublayer_pointer = ptr::null_mut();
    let result = unsafe { FwpmSubLayerGetByKey0(engine.0, &SUBLAYER, &mut sublayer_pointer) };
    let sublayer_absent = result == FWP_E_SUBLAYER_NOT_FOUND as u32;
    if !sublayer_absent {
        code(result)?;
    }
    let sublayer = Memory(sublayer_pointer);
    if sublayer_absent != absent {
        return Err(denied());
    }
    if !sublayer_absent {
        let value = unsafe { &*sublayer.0 };
        if !provider(value.providerKey)
            || value.flags != FWPM_SUBLAYER_FLAG_PERSISTENT
            || value.providerData.size != 0
        {
            return Err(denied());
        }
    }
    for (layer, key, _) in system_objects() {
        let mut pointer = ptr::null_mut();
        let result = unsafe { FwpmCalloutGetByKey0(engine.0, &key, &mut pointer) };
        if result == FWP_E_CALLOUT_NOT_FOUND as u32 {
            if !absent {
                return Err(denied());
            }
            continue;
        }
        code(result)?;
        let value = Memory(pointer);
        let value = unsafe { &*value.0 };
        if absent
            || !provider(value.providerKey)
            || !same(&value.applicableLayer, &layer)
            || value.providerData.size != 0
            || value.flags & !FWPM_CALLOUT_FLAG_REGISTERED != FWPM_CALLOUT_FLAG_PERSISTENT
        {
            return Err(denied());
        }
    }
    if absent {
        return Ok(());
    }
    let ids = filter_ids(&engine, proof.namespace())?;
    proof.confirm()?;
    for id in ids {
        code(unsafe { FwpmFilterDeleteById0(engine.0, id) })?;
    }
    for (_, key, _) in system_objects() {
        code(unsafe { FwpmCalloutDeleteByKey0(engine.0, &key) })?;
    }
    code(unsafe { FwpmSubLayerDeleteByKey0(engine.0, &SUBLAYER) })?;
    code(unsafe { FwpmProviderDeleteByKey0(engine.0, &PROVIDER) })?;
    proof.confirm()?;
    code(unsafe { FwpmTransactionCommit0(engine.0) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid_condition(sddl: &str) -> (Descriptor, FWP_BYTE_BLOB, FWPM_FILTER_CONDITION0) {
        let mut sd = ptr::null_mut();
        let mut size = 0;
        check(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                1,
                &mut sd,
                &mut size,
            )
        })
        .unwrap();
        let descriptor = Descriptor(sd);
        let blob = FWP_BYTE_BLOB {
            size,
            data: sd.cast(),
        };
        let mut condition = FWPM_FILTER_CONDITION0::default();
        condition.fieldKey = FWPM_CONDITION_ALE_USER_ID;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.r#type = FWP_SECURITY_DESCRIPTOR_TYPE;
        (descriptor, blob, condition)
    }

    #[test]
    fn retirement_verifies_system_and_owner_filters_without_widening_their_scope() {
        let namespace = [0x32; 16];
        let (_descriptor, mut blob, mut condition) = sid_condition("D:(A;;CC;;;SY)");
        condition.conditionValue.Anonymous.sd = &mut blob;
        for (layer, callout, scoped) in system_objects() {
            let value = selected_filter_value(
                &layer,
                &callout,
                &callout,
                if scoped { Some(&mut condition) } else { None },
            );
            verify_filter(&value, namespace).unwrap();
            let mut changed = value;
            changed.Anonymous.rawContext = 1;
            assert!(verify_filter(&changed, namespace).is_err());
            let mut changed = value;
            changed.flags |= FWPM_FILTER_FLAG_DISABLED;
            assert!(verify_filter(&changed, namespace).is_err());
        }
        for owner in [
            Owner::Machine {},
            Owner::WindowsUser {
                sid: "S-1-5-18".into(),
            },
        ] {
            let mut identity = namespace.to_vec();
            identity.extend(serde_json::to_vec(&owner).unwrap());
            let key = derived_key(b"aivpn-windows-owner-filter-v1", &identity, 0);
            let mut value = selected_filter_value(
                &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                &AUTH4,
                &key,
                if matches!(owner, Owner::Machine {}) {
                    None
                } else {
                    Some(&mut condition)
                },
            );
            verify_filter(&value, namespace).unwrap();
            assert!(verify_filter(&value, [0x33; 16]).is_err());
            value.weight.Anonymous.uint8 = 16;
            assert!(verify_filter(&value, namespace).is_err());
        }
    }

    #[test]
    fn retirement_rejects_added_acl_grants_and_unknown_filter_keys() {
        let namespace = [0x32; 16];
        let (_descriptor, mut blob, mut condition) = sid_condition("D:(A;;CC;;;SY)(A;;CC;;;BA)");
        condition.conditionValue.Anonymous.sd = &mut blob;
        let value = selected_filter_value(
            &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            &AUTH4,
            &AUTH4,
            Some(&mut condition),
        );
        assert!(verify_filter(&value, namespace).is_err());
        let unknown = selected_filter_value(
            &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            &AUTH4,
            &GUID::from_u128(0x1234),
            None,
        );
        assert!(verify_filter(&unknown, namespace).is_err());
    }

    #[test]
    fn retirement_accepts_worker_app_id_only_with_its_derived_key_and_exact_basename() {
        let namespace = [0x32; 16];
        let units = wide(r"\device\harddiskvolume3\aivpn\aivpn-packet-worker.exe");
        let mut bytes: Vec<u8> = units.into_iter().flat_map(u16::to_le_bytes).collect();
        let mut blob = FWP_BYTE_BLOB {
            size: bytes.len() as u32,
            data: bytes.as_mut_ptr(),
        };
        let mut condition = FWPM_FILTER_CONDITION0::default();
        condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
        condition.conditionValue.Anonymous.byteBlob = &mut blob;
        let key = derived_key(b"aivpn-worker-filter-v2", &bytes, 0);
        let mut value = selected_filter_value(
            &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            &AUTH4,
            &key,
            Some(&mut condition),
        );
        verify_filter(&value, namespace).unwrap();
        value.flags &= !FWPM_FILTER_FLAG_INDEXED;
        assert!(verify_filter(&value, namespace).is_err());
        let suffix_position = bytes.len() - 6;
        bytes[suffix_position] = b'X';
        let key = derived_key(b"aivpn-worker-filter-v2", &bytes, 0);
        value = selected_filter_value(
            &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            &AUTH4,
            &key,
            Some(&mut condition),
        );
        assert!(verify_filter(&value, namespace).is_err());
    }
}
