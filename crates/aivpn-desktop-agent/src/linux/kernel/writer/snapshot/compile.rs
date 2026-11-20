use super::{invalid, schema::*, SealedBindingManifest};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
};

unsafe extern "C" {
    fn aivpn_snapshot_policy_valid(bytes: *const u8, length: usize) -> i32;
}

pub(in crate::linux::kernel::writer) struct Bundle {
    pub records: Records,
    pub manifest_digest: [u8; 32],
    pub bundle_digest: [u8; 32],
}
type Rules = BTreeMap<(u64, u32), Vec<usize>>;

impl Bundle {
    pub fn compile(manifest: &SealedBindingManifest) -> io::Result<Self> {
        Self::compile_epoch(manifest, manifest.transaction().get())
    }
    pub(in crate::linux::kernel::writer) fn compile_epoch(
        manifest: &SealedBindingManifest,
        epoch: u64,
    ) -> io::Result<Self> {
        input_limits(manifest)?;
        let mut records = Records::new();
        let rules = policies(&mut records, manifest)?;
        let groups = groups(&mut records, manifest)?;
        let edges = memberships(&mut records, manifest, &rules, &groups)?;
        aliases(&mut records, manifest, &rules, &edges)?;
        let manifest_digest = manifest_digest(manifest)?;
        metadata(&mut records, manifest, manifest_digest, epoch)?;
        record_limits(&records)?;
        let bundle_digest = bundle_digest(&records);
        Ok(Self {
            records,
            manifest_digest,
            bundle_digest,
        })
    }
}
fn input_limits(manifest: &SealedBindingManifest) -> io::Result<()> {
    for (count, limit) in [
        (manifest.policies().len(), 256),
        (manifest.groups().len(), 4096),
        (manifest.aliases().len(), 65536),
        (manifest.memberships().len(), 65536),
    ] {
        bounded(count, limit)?;
    }
    Ok(())
}
fn record_limits(records: &Records) -> io::Result<()> {
    bounded(
        records
            .keys()
            .filter(|key| {
                matches!(
                    key[0],
                    PHYSICAL | LOGICAL | SOURCE_PHYSICAL | SOURCE_LOGICAL
                )
            })
            .count(),
        262144,
    )?;
    bounded(records.len(), 397826)
}
fn policies(records: &mut Records, manifest: &SealedBindingManifest) -> io::Result<Rules> {
    let mut rules = Rules::new();
    let mut total = 0usize;
    for policy in manifest.policies() {
        if unsafe { aivpn_snapshot_policy_valid(policy.as_ptr(), policy.len()) } != 1 {
            return Err(invalid());
        }
        let owner = (u64::from(word(policy, 4)) << 32) | u64::from(word(policy, 8));
        let count = word(policy, 12) as usize;
        total = total.checked_add(count).ok_or_else(invalid)?;
        bounded(total, 65536)?;
        let mut header = [0; 64];
        header[..40].copy_from_slice(&policy[..40]);
        insert(records, key(HEADER, owner, [0; 3]), header)?;
        for index in 0..count {
            let bytes = &policy[40 + index * 56..40 + (index + 1) * 56];
            let mut value = [0; 64];
            value[..56].copy_from_slice(bytes);
            insert(records, key(RULE, owner, [index as u64, 0, 0]), value)?;
            if word(bytes, 0) == 1 {
                rules
                    .entry((owner, word(bytes, 4)))
                    .or_default()
                    .push(index);
            }
        }
    }
    Ok(rules)
}
fn groups(records: &mut Records, manifest: &SealedBindingManifest) -> io::Result<BTreeSet<u32>> {
    let mut groups = BTreeSet::new();
    for group in manifest.groups() {
        if !groups.insert(group.id().get()) || group.cookie() == 0 {
            return Err(invalid());
        }
        insert(
            records,
            key(FILE, 0, [group.cookie(), 0, 0]),
            scalar(u64::from(group.id().get())),
        )?;
    }
    Ok(groups)
}
fn memberships(
    records: &mut Records,
    manifest: &SealedBindingManifest,
    rules: &Rules,
    groups: &BTreeSet<u32>,
) -> io::Result<BTreeSet<(u64, u32, u32)>> {
    let mut edges = BTreeSet::new();
    for edge in manifest.memberships() {
        let scope = owner(edge.owner())?;
        let selector = edge.selector().get();
        let group = edge.group().get();
        if !rules.contains_key(&(scope, selector)) || !groups.contains(&group) {
            return Err(invalid());
        }
        if edge
            .accepted_serial()
            .is_some_and(|serial| serial == 0 || serial > manifest.desired_serial())
        {
            return Err(invalid());
        }
        edges.insert((scope, selector, group));
        insert(
            records,
            key(
                MEMBERSHIP,
                scope,
                [u64::from(selector), u64::from(group), 0],
            ),
            scalar(1),
        )?;
    }
    Ok(edges)
}
fn aliases(
    records: &mut Records,
    manifest: &SealedBindingManifest,
    rules: &Rules,
    edges: &BTreeSet<(u64, u32, u32)>,
) -> io::Result<()> {
    let mut selected = BTreeSet::new();
    for alias in manifest.aliases() {
        let scope = owner(alias.owner())?;
        let selector = alias.selector().get();
        if !selected.insert((scope, selector))
            || !edges.contains(&(scope, selector, alias.group().get()))
        {
            return Err(invalid());
        }
        let indices = rules.get(&(scope, selector)).ok_or_else(invalid)?;
        for (kind, path) in [PHYSICAL, LOGICAL].into_iter().zip(alias.negative_keys()) {
            let bitmap = records.entry(key(kind, scope, path)).or_insert([0; 64]);
            for index in indices {
                set_bit(bitmap, *index);
            }
        }
        for (kind, path) in [SOURCE_PHYSICAL, SOURCE_LOGICAL]
            .into_iter()
            .zip(alias.source_keys())
        {
            let bitmap = records.entry(key(kind, scope, path)).or_insert([0; 64]);
            for index in indices {
                set_bit(bitmap, *index);
            }
        }
        let mut source_meta = [0; 64];
        for (index, word) in std::iter::once(1u64)
            .chain(alias.source_scope())
            .chain([256, 3, 0])
            .enumerate()
        {
            source_meta[index * 8..index * 8 + 8].copy_from_slice(&word.to_ne_bytes());
        }
        let meta_key = key(SOURCE_META, scope, [0; 3]);
        if let Some(previous) = records.insert(meta_key, source_meta) {
            if previous != source_meta {
                return Err(invalid());
            }
        }
    }
    if selected.len() != rules.len() {
        return Err(invalid());
    }
    Ok(())
}
fn metadata(
    records: &mut Records,
    manifest: &SealedBindingManifest,
    digest: [u8; 32],
    epoch: u64,
) -> io::Result<()> {
    let txn = manifest.transaction().get();
    if txn == 0 || epoch == 0 || manifest.desired_serial() == 0 {
        return Err(invalid());
    }
    let mut meta = [0; 64];
    meta[..4].copy_from_slice(&2u32.to_ne_bytes());
    for (offset, number) in [(8, epoch), (16, manifest.desired_serial()), (24, txn)] {
        meta[offset..offset + 8].copy_from_slice(&number.to_ne_bytes());
    }
    meta[32..].copy_from_slice(&manifest.desired_digest());
    insert(records, key(META, 0, [0; 3]), meta)?;
    let mut identity = [0; 64];
    identity[..32].copy_from_slice(&manifest.instance_digest());
    identity[32..].copy_from_slice(&digest);
    insert(records, key(IDENTITY, 0, [0; 3]), identity)
}
fn bundle_digest(records: &Records) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"linux-binding-bundle-v1");
    for field in SHAPE {
        digest.update(field.to_le_bytes());
    }
    digest.update((records.len() as u64).to_le_bytes());
    for (key, value) in records {
        for field in key {
            digest.update(field.to_le_bytes());
        }
        digest.update(value);
    }
    digest.finalize().into()
}
fn frame(digest: &mut Sha256, rows: &mut [Vec<u8>]) {
    rows.sort();
    digest.update((rows.len() as u64).to_le_bytes());
    for row in rows {
        digest.update((row.len() as u64).to_le_bytes());
        digest.update(row);
    }
}
fn manifest_digest(manifest: &SealedBindingManifest) -> io::Result<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(b"linux-binding-manifest-v2");
    digest.update(manifest.instance_digest());
    digest.update(manifest.desired_digest());
    digest.update(manifest.desired_serial().to_le_bytes());
    digest.update(manifest.transaction().get().to_le_bytes());
    frame(&mut digest, &mut manifest.policies().to_vec());
    frame(&mut digest, &mut alias_rows(manifest)?);
    frame(&mut digest, &mut group_rows(manifest));
    frame(&mut digest, &mut edge_rows(manifest)?);
    Ok(digest.finalize().into())
}
fn alias_rows(manifest: &SealedBindingManifest) -> io::Result<Vec<Vec<u8>>> {
    manifest
        .aliases()
        .iter()
        .map(|alias| {
            let mut row = owner(alias.owner())?.to_le_bytes().to_vec();
            row.extend(alias.selector().get().to_le_bytes());
            row.extend(alias.group().get().to_le_bytes());
            for field in alias.negative_keys().into_iter().flatten() {
                row.extend(field.to_le_bytes());
            }
            for field in alias
                .source_keys()
                .into_iter()
                .flatten()
                .chain(alias.source_scope())
            {
                row.extend(field.to_le_bytes());
            }
            row.extend((alias.path().len() as u64).to_le_bytes());
            row.extend(alias.path().as_bytes());
            Ok(row)
        })
        .collect()
}
fn group_rows(manifest: &SealedBindingManifest) -> Vec<Vec<u8>> {
    manifest
        .groups()
        .iter()
        .map(|group| {
            let mut row = group.id().get().to_le_bytes().to_vec();
            for field in [
                group.cookie(),
                group.device_inode().0,
                group.device_inode().1,
            ] {
                row.extend(field.to_le_bytes());
            }
            row.extend(group.link_id().to_le_bytes());
            row.extend(group.record_id().to_le_bytes());
            row.extend(group.record_digest());
            row
        })
        .collect()
}
fn edge_rows(manifest: &SealedBindingManifest) -> io::Result<Vec<Vec<u8>>> {
    manifest
        .memberships()
        .iter()
        .map(|edge| {
            let mut row = owner(edge.owner())?.to_le_bytes().to_vec();
            row.extend(edge.selector().get().to_le_bytes());
            row.extend(edge.group().get().to_le_bytes());
            row.push(u8::from(edge.accepted_serial().is_some()));
            row.extend(edge.accepted_serial().unwrap_or(0).to_le_bytes());
            Ok(row)
        })
        .collect()
}
