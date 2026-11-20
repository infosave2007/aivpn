use aivpn_desktop_agent::bindings::BindingPlan;
use aivpn_desktop_agent::slots::{KernelSlotStore, KernelState};
use aivpn_desktop_policy::*;
#[path = "support/kernel_slot_store.rs"]
mod storage;
use storage::Store;

fn inputs() -> (ProfileCatalog, PolicyRegistry, Authority, String) {
    let authority = Authority {
        user: Owner::LinuxUser { uid: 0 },
        machine_admin: true,
    };
    let mut catalog = ProfileCatalog::new(Platform::Linux, [9; 16]);
    let profile = catalog
        .register(
            &authority,
            Owner::LinuxUser { uid: 1000 },
            vec![Owner::LinuxUser { uid: 1001 }],
        )
        .unwrap();
    catalog.set_global_dns(&profile, &authority).unwrap();
    (
        catalog,
        PolicyRegistry::new(Platform::Linux),
        authority,
        profile,
    )
}
fn add_policy(
    registry: &mut PolicyRegistry,
    authority: &Authority,
    profile: &str,
    uid: u32,
    path: &str,
) {
    let doc = PolicyDocument {
        split_enabled: true,
        version: 1,
        id: format!("policy-{uid}"),
        generation: 1,
        platform: Platform::Linux,
        owner: Owner::LinuxUser { uid },
        default_action: Action::System {},
        dns: DnsPolicy::SharedVpn {
            profile: profile.into(),
            acknowledge_outage: true,
        },
        rules: vec![RuleDocument {
            id: "app".into(),
            application: Selector::Executable { path: path.into() },
            destination: None,
            inherit_children: true,
            action: Action::Vpn {
                profile: profile.into(),
            },
        }],
    };
    let prepared = registry.prepare(doc, authority, None).unwrap();
    registry.commit(prepared).unwrap();
}

#[test]
fn registered_policies_share_stable_app_numbers_and_preserve_activation_revision() {
    let (mut catalog, mut registry, authority, profile) = inputs();
    catalog
        .register(&authority, Owner::LinuxUser { uid: 1001 }, vec![])
        .unwrap();
    add_policy(
        &mut registry,
        &authority,
        &profile,
        1000,
        "/usr/bin/browser",
    );
    add_policy(
        &mut registry,
        &authority,
        &profile,
        1001,
        "/usr/bin/browser",
    );
    let store = Store::default();
    let mut slots = KernelSlotStore::open(store.clone(), [9; 16], KernelState::Fresh).unwrap();
    let plan = BindingPlan::prepare(&registry, &catalog, &authority, &mut slots).unwrap();
    assert_eq!(plan.bindings().profiles.len(), 2);
    assert_eq!(plan.bindings().executables.len(), 1);
    let app = plan.bindings().executables["/usr/bin/browser"];
    let vpn = plan.bindings().profiles[&profile];
    assert_ne!(app, vpn);
    let bytes = plan
        .policies()
        .iter()
        .map(KernelPolicy::to_native_bytes)
        .collect::<Vec<_>>();
    assert_eq!(bytes.len(), 2);
    for bytes in &bytes {
        assert_eq!(
            u64::from_ne_bytes(bytes[16..24].try_into().unwrap()),
            registry.revision()
        );
        assert_eq!(
            u32::from_ne_bytes(bytes[44..48].try_into().unwrap()),
            app.get()
        );
        assert_eq!(
            u32::from_ne_bytes(bytes[60..64].try_into().unwrap()),
            vpn.get()
        );
    }
    let writes = store.0.borrow().writes;
    drop(slots);
    let mut slots = KernelSlotStore::open(store.clone(), [9; 16], KernelState::Existing).unwrap();
    let next = BindingPlan::prepare(&registry, &catalog, &authority, &mut slots).unwrap();
    assert_eq!(
        next.policies()
            .iter()
            .map(KernelPolicy::to_native_bytes)
            .collect::<Vec<_>>(),
        bytes
    );
    assert_eq!(store.0.borrow().writes, writes);
}

#[test]
fn foreign_namespace_and_unprivileged_compilation_cannot_allocate_numbers() {
    let (catalog, registry, authority, _) = inputs();
    let store = Store::default();
    let mut slots = KernelSlotStore::open(store.clone(), [8; 16], KernelState::Fresh).unwrap();
    let writes = store.0.borrow().writes;
    assert!(BindingPlan::prepare(&registry, &catalog, &authority, &mut slots).is_err());
    assert_eq!(store.0.borrow().writes, writes);
    let user_store = Store::default();
    let mut slots = KernelSlotStore::open(user_store.clone(), [9; 16], KernelState::Fresh).unwrap();
    let writes = user_store.0.borrow().writes;
    let user = Authority {
        machine_admin: false,
        ..authority
    };
    assert!(BindingPlan::prepare(&registry, &catalog, &user, &mut slots).is_err());
    assert_eq!(user_store.0.borrow().writes, writes);
}

#[test]
fn storage_failure_prevents_any_compiled_plan_from_being_returned() {
    let (catalog, mut registry, authority, profile) = inputs();
    add_policy(
        &mut registry,
        &authority,
        &profile,
        1000,
        "/usr/bin/browser",
    );
    let store = Store::default();
    let mut slots = KernelSlotStore::open(store.clone(), [9; 16], KernelState::Fresh).unwrap();
    store.0.borrow_mut().fault = Some(false);
    assert!(BindingPlan::prepare(&registry, &catalog, &authority, &mut slots).is_err());
    assert!(BindingPlan::prepare(&registry, &catalog, &authority, &mut slots).is_err());
}

#[test]
fn admin_cannot_publish_a_profile_for_an_unlisted_policy_consumer() {
    let (catalog, mut registry, authority, profile) = inputs();
    add_policy(
        &mut registry,
        &authority,
        &profile,
        1002,
        "/usr/bin/browser",
    );
    let store = Store::default();
    let mut slots = KernelSlotStore::open(store.clone(), [9; 16], KernelState::Fresh).unwrap();
    let writes = store.0.borrow().writes;
    assert!(BindingPlan::prepare(&registry, &catalog, &authority, &mut slots).is_err());
    assert_eq!(store.0.borrow().writes, writes);
}

#[test]
fn windows_owner_package_and_executable_have_distinct_number_spaces() {
    let authority = Authority {
        user: Owner::WindowsUser {
            sid: "S-1-5-21-1000".into(),
        },
        machine_admin: true,
    };
    let mut catalog = ProfileCatalog::new(Platform::Windows, [9; 16]);
    let profile = catalog
        .register(&authority, authority.user.clone(), vec![])
        .unwrap();
    catalog.set_global_dns(&profile, &authority).unwrap();
    let mut registry = PolicyRegistry::new(Platform::Windows);
    let doc = PolicyDocument {
        split_enabled: true,
        version: 1,
        id: "windows".into(),
        generation: 1,
        platform: Platform::Windows,
        owner: authority.user.clone(),
        default_action: Action::System {},
        dns: DnsPolicy::SharedVpn {
            profile: profile.clone(),
            acknowledge_outage: true,
        },
        rules: vec![
            RuleDocument {
                id: "package".into(),
                application: Selector::WindowsPackage {
                    sid: "S-1-15-2-1000".into(),
                },
                destination: None,
                inherit_children: false,
                action: Action::Block {},
            },
            RuleDocument {
                id: "executable".into(),
                application: Selector::Executable {
                    path: "\\device\\harddiskvolume1\\browser.exe".into(),
                },
                destination: None,
                inherit_children: true,
                action: Action::Vpn {
                    profile: profile.clone(),
                },
            },
            RuleDocument {
                id: "all".into(),
                application: Selector::Any {},
                destination: None,
                inherit_children: false,
                action: Action::System {},
            },
        ],
    };
    let prepared = registry.prepare(doc, &authority, None).unwrap();
    registry.commit(prepared).unwrap();
    let mut slots = KernelSlotStore::open(Store::default(), [9; 16], KernelState::Fresh).unwrap();
    let plan = BindingPlan::prepare(&registry, &catalog, &authority, &mut slots).unwrap();
    let bindings = plan.bindings();
    let numbers = [
        bindings.profiles[&profile],
        bindings.windows_owners["S-1-5-21-1000"],
        bindings.packages["S-1-15-2-1000"],
        bindings.executables["\\device\\harddiskvolume1\\browser.exe"],
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(numbers.len(), 4);
    let bytes = plan.policies()[0].to_native_bytes();
    assert_eq!(u32::from_ne_bytes(bytes[4..8].try_into().unwrap()), 2);
    assert_eq!(
        u32::from_ne_bytes(bytes[8..12].try_into().unwrap()),
        bindings.windows_owners["S-1-5-21-1000"].get()
    );
}
