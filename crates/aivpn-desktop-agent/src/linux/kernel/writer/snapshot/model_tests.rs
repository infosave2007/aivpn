// Это модель compiler inputs, не native registry и не доказательство published history.
use super::*;
use crate::linux::kernel::writer::snapshot::compile::Bundle;

fn fixture(count: usize) -> SealedBindingManifest {
    let mut policy = vec![0u8; 14376];
    for (offset, value) in [
        (0, 1u32),
        (4, 1),
        (8, 1000),
        (12, count as u32),
        (16, 1),
        (32, 1),
    ] {
        policy[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }
    for index in 0..count.min(256) {
        let start = 40 + index * 56;
        for (offset, value) in [(0, 1u32), (4, 10), (12, 1), (16, 1)] {
            policy[start + offset..start + offset + 4].copy_from_slice(&value.to_ne_bytes());
        }
    }
    let evidence = GroupEvidence {
        slot: 20,
        cookie: 30,
        device: 1,
        inode: 2,
        link: 3,
        program: 4,
        pid: 5,
        record: 6,
        digest: [7; 32],
    };
    SealedBindingManifest {
        transaction: BindingTxnId {
            instance: [1; 32],
            number: 1,
        },
        serial: 1,
        digest: [2; 32],
        aliases: vec![VerifiedAlias {
            record: Alias {
                owner: (1 << 32) | 1000,
                path: "/model/a".into(),
                selector: 10,
                group: 20,
                keys: [[1, 2, 3], [4, 5, u64::MAX]],
                source_keys: [[1, 2, 3], [4, 5, u64::MAX]],
                source_scope: [1, 0, 1, 1],
            },
        }],
        groups: vec![VerifiedGroup { evidence }],
        memberships: vec![VerifiedMembership {
            owner: (1 << 32) | 1000,
            selector: SelectorId(NonZeroU32::new(10).unwrap()),
            group: FileGroupId(NonZeroU32::new(20).unwrap()),
            accepted_serial: None,
        }],
        policies: vec![policy],
    }
}
#[test]
fn all_256_rules_and_negative_bitmap_boundaries_are_preserved() {
    let manifest = fixture(256);
    let bundle = Bundle::compile(&manifest).unwrap();
    assert_eq!(bundle.records.len(), 266);
    let bitmap = bundle.records[&[5, (1 << 32) | 1000, 1, 2, 3]];
    for index in [0, 63, 64, 127, 128, 191, 192, 255] {
        let offset = index / 64 * 8;
        assert_ne!(
            u64::from_ne_bytes(bitmap[offset..offset + 8].try_into().unwrap())
                & (1u64 << (index % 64)),
            0
        );
        assert_eq!(
            &bundle.records[&[2, (1 << 32) | 1000, index as u64, 0, 0]][..56],
            &manifest.policies[0][40 + index * 56..40 + (index + 1) * 56]
        );
    }
    assert_eq!(&bitmap[..32], &[255; 32]);
    assert_eq!(&bitmap[32..], &[0; 32]);
}
#[test]
fn compiler_refuses_malformed_wire_and_dangling_references() {
    for offset in [0, 4, 12, 36, 40, 44, 48, 52, 56, 60, 64] {
        let mut m = fixture(2);
        m.policies[0][offset..offset + 4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(Bundle::compile(&m).is_err(), "accepted offset {offset}");
    }
    let mut m = fixture(2);
    m.groups.clear();
    assert!(Bundle::compile(&m).is_err());
    let mut m = fixture(2);
    m.memberships.clear();
    assert!(Bundle::compile(&m).is_err());
    let mut m = fixture(2);
    m.aliases.clear();
    assert!(Bundle::compile(&m).is_err());
    let mut m = fixture(2);
    m.memberships[0].owner = (1 << 32) | 1001;
    assert!(Bundle::compile(&m).is_err());
    let mut m = fixture(2);
    m.aliases.push(m.aliases[0].clone());
    assert!(Bundle::compile(&m).is_err());
    let mut m = fixture(2);
    m.groups.push(m.groups[0].clone());
    assert!(Bundle::compile(&m).is_err());
    let mut m = fixture(2);
    m.memberships.push(m.memberships[0].clone());
    assert!(Bundle::compile(&m).is_err());
    assert!(Bundle::compile(&fixture(257)).is_err());
}
#[test]
fn compiler_caps_refuse_count_plus_one_before_storage() {
    let mut m = fixture(1);
    m.policies = vec![m.policies[0].clone(); 257];
    assert!(Bundle::compile(&m).is_err());
    let mut m = fixture(1);
    m.groups = vec![m.groups[0].clone(); 4097];
    assert!(Bundle::compile(&m).is_err());
    let mut m = fixture(1);
    m.aliases = vec![m.aliases[0].clone(); 65537];
    assert!(Bundle::compile(&m).is_err());
    let mut m = fixture(1);
    m.memberships = vec![m.memberships[0].clone(); 65537];
    assert!(Bundle::compile(&m).is_err());
}
#[test]
fn canonical_digest_binds_retention_history_and_is_order_invariant() {
    let mut m = fixture(1);
    let first = Bundle::compile(&m).unwrap();
    m.groups[0].evidence.digest[0] ^= 1;
    let second = Bundle::compile(&m).unwrap();
    assert_ne!(first.manifest_digest, second.manifest_digest);
    assert_ne!(first.bundle_digest, second.bundle_digest);
    m.memberships[0].accepted_serial = Some(1);
    assert_ne!(
        second.manifest_digest,
        Bundle::compile(&m).unwrap().manifest_digest
    );
    let mut other = m.aliases[0].clone();
    other.record.path = "/model/h".into();
    other.record.selector = 11;
    m.aliases.push(other);
    m.policies[0][12..16].copy_from_slice(&2u32.to_ne_bytes());
    let rule = m.policies[0][40..96].to_vec();
    m.policies[0][96..152].copy_from_slice(&rule);
    m.policies[0][100..104].copy_from_slice(&11u32.to_ne_bytes());
    let mut edge = m.memberships[0].clone();
    edge.selector = SelectorId(NonZeroU32::new(11).unwrap());
    m.memberships.push(edge);
    let ordered = Bundle::compile(&m).unwrap();
    m.aliases.reverse();
    m.groups.reverse();
    m.memberships.reverse();
    let reversed = Bundle::compile(&m).unwrap();
    assert_eq!(ordered.manifest_digest, reversed.manifest_digest);
    assert_eq!(ordered.bundle_digest, reversed.bundle_digest);
    assert_eq!(ordered.records[&[5, (1 << 32) | 1000, 1, 2, 3]][0], 3);
}

fn capacity_model() -> SealedBindingManifest {
    let base = fixture(256);
    let mut model = fixture(256);
    model.policies.clear();
    model.aliases.clear();
    model.memberships.clear();
    model.groups.clear();
    for index in 0..4096u32 {
        let mut group = base.groups[0].clone();
        group.evidence.slot = index + 1;
        group.evidence.cookie = u64::from(index) + 1;
        group.evidence.inode = u64::from(index) + 1;
        group.evidence.link = index + 1;
        group.evidence.record = index + 1;
        model.groups.push(group);
    }
    for owner_index in 0..256u32 {
        let scope = (1u64 << 32) | u64::from(1000 + owner_index);
        let mut policy = base.policies[0].clone();
        policy[8..12].copy_from_slice(&(1000 + owner_index).to_ne_bytes());
        for index in 0..256u32 {
            let selector = owner_index * 256 + index + 1;
            let group = (selector - 1) % 4096 + 1;
            let offset = 40 + index as usize * 56 + 4;
            policy[offset..offset + 4].copy_from_slice(&selector.to_ne_bytes());
            model.aliases.push(VerifiedAlias {
                record: Alias {
                    owner: scope,
                    path: format!("/compiler-model/{selector}"),
                    selector,
                    group,
                    keys: [
                        [u64::from(selector), 1, 1],
                        [u64::from(selector), 2, u64::MAX],
                    ],
                    source_keys: [
                        [u64::from(selector), 3, 1],
                        [u64::from(selector), 4, u64::MAX],
                    ],
                    source_scope: [1, 0, 1, 1],
                },
            });
            model.memberships.push(VerifiedMembership {
                owner: scope,
                selector: SelectorId(NonZeroU32::new(selector).unwrap()),
                group: FileGroupId(NonZeroU32::new(group).unwrap()),
                accepted_serial: None,
            });
        }
        model.policies.push(policy);
    }
    model
}
#[test]
#[ignore = "Отдельный процесс для bounded userspace peak compiler model"]
fn compiler_capacity_process_peak_model() {
    // Только модель closed inputs: без kernel maps, реальных retentions и activation claims.
    let manifest = capacity_model();
    assert_eq!(
        (
            manifest.policies.len(),
            manifest.groups.len(),
            manifest.aliases.len(),
            manifest.memberships.len()
        ),
        (256, 4096, 65536, 65536)
    );
    let bundle = Bundle::compile(&manifest).unwrap();
    assert_eq!(bundle.records.len(), 266498);
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) }, 0);
    println!(
        "COMPILER_PROCESS_MODEL {}",
        serde_json::json!({"owners":256,"rules":65536,"groups":4096,"aliases":65536,"memberships":65536,"negative_records":131072,"records":bundle.records.len(),"maxrss_kib":usage.ru_maxrss,"bundle_digest":bundle.bundle_digest,"real_retentions":false,"kernel_maps":false})
    );
}
