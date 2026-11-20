use aivpn_desktop_policy::*;
use std::num::NonZeroU32;

fn inputs() -> (Policy, ProfileCatalog, Authority, KernelBindings) {
    let authority = Authority {
        user: Owner::LinuxUser { uid: 1000 },
        machine_admin: false,
    };
    let mut catalog = ProfileCatalog::new(Platform::Linux, [17; 16]);
    let id = catalog
        .register(&authority, authority.user.clone(), vec![])
        .unwrap();
    let policy = Policy::validate(
        PolicyDocument {
            split_enabled: true,
            version: 1,
            id: "apps".into(),
            generation: 1,
            platform: Platform::Linux,
            owner: authority.user.clone(),
            default_action: Action::System {},
            dns: DnsPolicy::SharedVpn {
                profile: id.clone(),
                acknowledge_outage: true,
            },
            rules: vec![RuleDocument {
                id: "browser".into(),
                application: Selector::Executable {
                    path: "/usr/bin/browser".into(),
                },
                destination: Some("203.0.113.0/24".into()),
                inherit_children: true,
                action: Action::Vpn {
                    profile: id.clone(),
                },
            }],
        },
        &authority,
    )
    .unwrap();
    catalog
        .set_global_dns(
            policy.document().dns.profile(),
            &Authority {
                machine_admin: true,
                ..authority.clone()
            },
        )
        .unwrap();
    let mut bindings = KernelBindings::default();
    bindings.profiles.insert(id, NonZeroU32::new(5).unwrap());
    bindings
        .executables
        .insert("/usr/bin/browser".into(), NonZeroU32::new(7).unwrap());
    (policy, catalog, authority, bindings)
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

#[test]
fn kernel_activation_revision_does_not_repeat_when_a_policy_is_recreated() {
    let (policy, catalog, authority, bindings) = inputs();
    let mut registry = PolicyRegistry::new(Platform::Linux);
    let initial = registry
        .prepare(policy.document().clone(), &authority, None)
        .unwrap();
    let first = KernelPolicy::compile_prepared(&initial, &catalog, &authority, &bindings)
        .unwrap()
        .to_native_bytes();
    registry.commit(initial).unwrap();
    let removal = registry
        .prepare_removal(authority.user.clone(), &authority, 1)
        .unwrap();
    assert_eq!(removal.owner(), &authority.user);
    assert_eq!(removal.revision(), 2);
    registry.commit_removal(removal).unwrap();
    let replacement = registry
        .prepare(policy.document().clone(), &authority, None)
        .unwrap();
    let next = KernelPolicy::compile_prepared(&replacement, &catalog, &authority, &bindings)
        .unwrap()
        .to_native_bytes();
    assert_eq!(u64::from_ne_bytes(first[16..24].try_into().unwrap()), 1);
    assert_eq!(u64::from_ne_bytes(next[16..24].try_into().unwrap()), 3);
    assert_eq!(policy.document().generation, 1);
    let foreign = Authority {
        user: Owner::LinuxUser { uid: 1001 },
        machine_admin: false,
    };
    assert!(KernelPolicy::compile_prepared(&replacement, &catalog, &foreign, &bindings).is_err());
}

#[test]
fn recovered_registry_compiles_with_activation_revision_and_keeps_access_checks() {
    let (policy, catalog, authority, bindings) = inputs();
    let mut registry = PolicyRegistry::new(Platform::Linux);
    assert!(KernelPolicy::compile_registered(
        &registry,
        &authority.user,
        &catalog,
        &authority,
        &bindings
    )
    .is_err());
    let initial = registry
        .prepare(policy.document().clone(), &authority, None)
        .unwrap();
    registry.commit(initial).unwrap();
    let removed = registry
        .prepare_removal(authority.user.clone(), &authority, 1)
        .unwrap();
    registry.commit_removal(removed).unwrap();
    let replacement = registry
        .prepare(policy.document().clone(), &authority, None)
        .unwrap();
    registry.commit(replacement).unwrap();
    let administrator = Authority {
        machine_admin: true,
        ..authority.clone()
    };
    let restored = PolicyRegistry::restore_metadata(
        Platform::Linux,
        &registry.store_metadata().unwrap(),
        &administrator,
    )
    .unwrap();
    let bytes = KernelPolicy::compile_registered(
        &restored,
        &authority.user,
        &catalog,
        &authority,
        &bindings,
    )
    .unwrap()
    .to_native_bytes();
    assert_eq!(u64::from_ne_bytes(bytes[16..24].try_into().unwrap()), 3);
    assert_eq!(
        restored.get(&authority.user).unwrap().document().generation,
        1
    );
    assert!(KernelPolicy::compile_registered(
        &restored,
        &authority.user,
        &catalog,
        &Authority {
            user: Owner::LinuxUser { uid: 1001 },
            machine_admin: false
        },
        &bindings
    )
    .is_err());
}

#[test]
fn native_layout_contains_only_bound_ids_and_network_bytes() {
    let (policy, catalog, authority, bindings) = inputs();
    let compiled = KernelPolicy::compile(&policy, &catalog, &authority, &bindings).unwrap();
    let bytes = compiled.to_native_bytes();
    assert_eq!(bytes.len(), 40 + 56 * 256);
    assert_eq!(
        [
            word(&bytes, 0),
            word(&bytes, 4),
            word(&bytes, 8),
            word(&bytes, 12)
        ],
        [1, 1, 1000, 1]
    );
    assert_eq!(u64::from_ne_bytes(bytes[16..24].try_into().unwrap()), 1);
    assert_eq!(
        [
            word(&bytes, 24),
            word(&bytes, 28),
            word(&bytes, 32),
            word(&bytes, 36)
        ],
        [0, 0, 5, 0]
    );
    assert_eq!(
        [
            word(&bytes, 40),
            word(&bytes, 44),
            word(&bytes, 48),
            word(&bytes, 52),
            word(&bytes, 56),
            word(&bytes, 60)
        ],
        [1, 7, 4, 1, 2, 5]
    );
    assert_eq!(&bytes[64..68], &[203, 0, 113, 0]);
    assert_eq!(&bytes[80..84], &[255, 255, 255, 0]);
    assert!(bytes[96..].iter().all(|byte| *byte == 0));
    assert!(!bytes.windows(7).any(|text| text == b"browser"));
}

#[test]
fn unresolved_bindings_cannot_silently_turn_into_system_route() {
    let (policy, catalog, authority, mut bindings) = inputs();
    bindings.executables.clear();
    assert!(KernelPolicy::compile(&policy, &catalog, &authority, &bindings).is_err());
    let (_, _, _, mut bindings) = inputs();
    bindings.profiles.clear();
    assert!(KernelPolicy::compile(&policy, &catalog, &authority, &bindings).is_err());
}

#[test]
fn missing_profile_permission_is_checked_before_compilation() {
    let (policy, catalog, _, bindings) = inputs();
    let wrong = Authority {
        user: Owner::LinuxUser { uid: 1001 },
        machine_admin: false,
    };
    assert!(KernelPolicy::compile(&policy, &catalog, &wrong, &bindings).is_err());
}

#[test]
fn windows_package_ipv6_and_default_vpn_keep_distinct_bindings() {
    let owner = Owner::WindowsUser {
        sid: "S-1-5-21-1-2-3-1000".into(),
    };
    let authority = Authority {
        user: owner.clone(),
        machine_admin: false,
    };
    let mut catalog = ProfileCatalog::new(Platform::Windows, [18; 16]);
    let id = catalog.register(&authority, owner.clone(), vec![]).unwrap();
    let policy = Policy::validate(
        PolicyDocument {
            split_enabled: true,
            version: 1,
            id: "win".into(),
            generation: u64::MAX,
            platform: Platform::Windows,
            owner,
            default_action: Action::Vpn {
                profile: id.clone(),
            },
            dns: DnsPolicy::SharedVpn {
                profile: id.clone(),
                acknowledge_outage: true,
            },
            rules: vec![RuleDocument {
                id: "package".into(),
                application: Selector::WindowsPackage {
                    sid: "S-1-15-2-42".into(),
                },
                destination: Some("2001:db8::/32".into()),
                inherit_children: false,
                action: Action::Block {},
            }],
        },
        &authority,
    )
    .unwrap();
    catalog
        .set_global_dns(
            policy.document().dns.profile(),
            &Authority {
                machine_admin: true,
                ..authority.clone()
            },
        )
        .unwrap();
    let mut bindings = KernelBindings::default();
    bindings.profiles.insert(id, NonZeroU32::new(9).unwrap());
    assert!(KernelPolicy::compile(&policy, &catalog, &authority, &bindings).is_err());
    bindings
        .windows_owners
        .insert("S-1-5-21-1-2-3-1000".into(), NonZeroU32::new(3).unwrap());
    assert!(KernelPolicy::compile(&policy, &catalog, &authority, &bindings).is_err());
    bindings
        .packages
        .insert("S-1-15-2-42".into(), NonZeroU32::new(11).unwrap());
    let bytes = KernelPolicy::compile(&policy, &catalog, &authority, &bindings)
        .unwrap()
        .to_native_bytes();
    assert_eq!(
        u64::from_ne_bytes(bytes[16..24].try_into().unwrap()),
        u64::MAX
    );
    assert_eq!(
        [
            word(&bytes, 4),
            word(&bytes, 8),
            word(&bytes, 24),
            word(&bytes, 28),
            word(&bytes, 32)
        ],
        [2, 3, 2, 9, 9]
    );
    assert_eq!(
        [
            word(&bytes, 40),
            word(&bytes, 44),
            word(&bytes, 48),
            word(&bytes, 52),
            word(&bytes, 56),
            word(&bytes, 60)
        ],
        [2, 11, 6, 0, 1, 0]
    );
    assert_eq!(
        &bytes[64..80],
        &"2001:db8::".parse::<std::net::Ipv6Addr>().unwrap().octets()
    );
    assert_eq!(&bytes[80..84], &[255; 4]);
    assert!(bytes[84..96].iter().all(|byte| *byte == 0));
}

#[test]
fn machine_policy_and_any_network_encode_without_an_application_binding() {
    let authority = Authority {
        user: Owner::LinuxUser { uid: 0 },
        machine_admin: true,
    };
    let mut catalog = ProfileCatalog::new(Platform::Linux, [19; 16]);
    let id = catalog
        .register(&authority, Owner::Machine {}, vec![])
        .unwrap();
    let policy = Policy::validate(
        PolicyDocument {
            split_enabled: true,
            version: 1,
            id: "machine".into(),
            generation: 1,
            platform: Platform::Linux,
            owner: Owner::Machine {},
            default_action: Action::Block {},
            dns: DnsPolicy::SharedVpn {
                profile: id.clone(),
                acknowledge_outage: true,
            },
            rules: vec![RuleDocument {
                id: "system".into(),
                application: Selector::Any {},
                destination: None,
                inherit_children: false,
                action: Action::System {},
            }],
        },
        &authority,
    )
    .unwrap();
    catalog
        .set_global_dns(
            policy.document().dns.profile(),
            &Authority {
                machine_admin: true,
                ..authority.clone()
            },
        )
        .unwrap();
    let mut bindings = KernelBindings::default();
    bindings.profiles.insert(id, NonZeroU32::new(1).unwrap());
    let bytes = KernelPolicy::compile(&policy, &catalog, &authority, &bindings)
        .unwrap()
        .to_native_bytes();
    assert_eq!(
        [
            word(&bytes, 4),
            word(&bytes, 8),
            word(&bytes, 12),
            word(&bytes, 24),
            word(&bytes, 28)
        ],
        [3, 0, 1, 1, 0]
    );
    assert!(bytes[40..].iter().all(|byte| *byte == 0));
}

#[test]
fn all_rule_slots_preserve_order_and_leave_no_stale_tail() {
    let (policy, catalog, authority, bindings) = inputs();
    let mut doc = policy.document().clone();
    doc.rules = (0..256)
        .map(|index| RuleDocument {
            id: format!("rule{index}"),
            destination: Some(format!("203.0.113.{index}/32")),
            ..doc.rules[0].clone()
        })
        .collect();
    let policy = Policy::validate(doc, &authority).unwrap();
    let bytes = KernelPolicy::compile(&policy, &catalog, &authority, &bindings)
        .unwrap()
        .to_native_bytes();
    assert_eq!(word(&bytes, 12), 256);
    for index in 0..256 {
        let start = 40 + 56 * index;
        assert_eq!(word(&bytes, start + 4), 7);
        assert_eq!(word(&bytes, start + 20), 5);
        assert_eq!(&bytes[start + 24..start + 28], &[203, 0, 113, index as u8]);
        assert_eq!(&bytes[start + 40..start + 44], &[255; 4]);
    }
}
