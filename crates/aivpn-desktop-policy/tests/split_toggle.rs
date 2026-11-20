use aivpn_desktop_policy::*;
use serde_json::{json, Value};
use std::num::NonZeroU32;

fn fixture(enabled: Option<bool>) -> (Policy, ProfileCatalog, Authority, String) {
    let authority = Authority {
        user: Owner::LinuxUser { uid: 1000 },
        machine_admin: false,
    };
    let mut catalog = ProfileCatalog::new(Platform::Linux, [17; 16]);
    let id = catalog
        .register(&authority, authority.user.clone(), vec![])
        .unwrap();
    catalog
        .set_global_dns(
            &id,
            &Authority {
                machine_admin: true,
                ..authority.clone()
            },
        )
        .unwrap();
    let mut doc = json!({"version":1,"id":"apps","generation":1,"platform":"linux",
        "owner":{"kind":"linux_user","uid":1000},"default_action":{"route":"system"},
        "dns":{"kind":"shared_vpn","profile":id,"acknowledge_outage":true},
        "rules":[{"id":"browser","application":{"kind":"executable","path":"/missing/browser"},
        "destination":"203.0.113.0/24","inherit_children":true,"action":{"route":"vpn","profile":id}}]});
    if let Some(enabled) = enabled {
        doc["split_enabled"] = enabled.into();
    }
    let policy = Policy::from_json(&doc.to_string(), &authority).unwrap();
    (policy, catalog, authority, id)
}

#[test]
fn missing_switch_preserves_legacy_split() {
    let (policy, _, _, _) = fixture(None);
    assert!(serde_json::to_value(policy.document())
        .unwrap()
        .get("split_enabled")
        .is_none());
    let process = ProcessIdentity {
        owner: Owner::LinuxUser { uid: 1000 },
        canonical_executable: "/other/app".into(),
        package_sid: None,
    };
    assert_eq!(
        policy
            .decide(&process, "198.51.100.1".parse().unwrap(), |_, _| true)
            .effective,
        Action::System {}
    );
}

#[test]
fn disabled_split_uses_full_vpn_but_keeps_rules_for_reenable() {
    let (policy, _, authority, id) = fixture(Some(false));
    let saved = serde_json::to_value(policy.document()).unwrap();
    assert_eq!(saved["rules"].as_array().unwrap().len(), 1);
    assert_eq!(saved["default_action"]["route"], "system");
    for address in ["203.0.113.1", "198.51.100.1", "2001:db8::1"] {
        let process = ProcessIdentity {
            owner: authority.user.clone(),
            canonical_executable: String::new(),
            package_sid: None,
        };
        assert_eq!(
            policy
                .decide(&process, address.parse().unwrap(), |_, _| true)
                .effective,
            Action::Vpn {
                profile: id.clone()
            }
        );
        assert_eq!(
            policy
                .decide(&process, address.parse().unwrap(), |_, _| false)
                .effective,
            Action::Block {}
        );
    }
    let process = ProcessIdentity {
        owner: authority.user.clone(),
        canonical_executable: String::new(),
        package_sid: None,
    };
    let ancestors = vec![process.clone(); 33];
    assert_eq!(
        policy
            .decide_with_ancestors(
                &process,
                &ancestors,
                "198.51.100.1".parse().unwrap(),
                |_, _| true
            )
            .effective,
        Action::Vpn {
            profile: id.clone()
        }
    );
    let mut restored: Value =
        serde_json::from_slice(&serde_json::to_vec(policy.document()).unwrap()).unwrap();
    restored["split_enabled"] = true.into();
    let enabled = Policy::from_json(&restored.to_string(), &authority).unwrap();
    let process = ProcessIdentity {
        owner: authority.user,
        canonical_executable: "/other/app".into(),
        package_sid: None,
    };
    assert_eq!(
        enabled
            .decide(&process, "198.51.100.1".parse().unwrap(), |_, _| true)
            .effective,
        Action::System {}
    );
    assert_eq!(
        serde_json::to_value(enabled.document()).unwrap()["rules"],
        saved["rules"]
    );
}

#[test]
fn disabled_kernel_policy_needs_no_saved_executable_binding() {
    let (policy, catalog, authority, id) = fixture(Some(false));
    let mut bindings = KernelBindings::default();
    bindings.profiles.insert(id, NonZeroU32::new(5).unwrap());
    let bytes = KernelPolicy::compile(&policy, &catalog, &authority, &bindings)
        .unwrap()
        .to_native_bytes();
    let word = |offset| u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
    assert_eq!(word(12), 0);
    assert_eq!(word(24), 2);
    assert_eq!(word(28), 5);
    assert!(bytes[40..].iter().all(|b| *b == 0));
}

#[test]
fn disabling_split_does_not_grant_another_users_dns_vpn() {
    let (policy, catalog, _, id) = fixture(Some(false));
    let authority = Authority {
        user: Owner::LinuxUser { uid: 1001 },
        machine_admin: false,
    };
    let mut saved = serde_json::to_value(policy.document()).unwrap();
    saved["owner"]["uid"] = 1001.into();
    saved["default_action"] = json!({"route":"system"});
    saved["rules"] = json!([]);
    let policy = Policy::from_json(&saved.to_string(), &authority).unwrap();
    let mut bindings = KernelBindings::default();
    bindings.profiles.insert(id, NonZeroU32::new(5).unwrap());
    assert!(matches!(
        KernelPolicy::compile(&policy, &catalog, &authority, &bindings),
        Err(CompileError::Profile(ProfileError::AccessDenied))
    ));
}
