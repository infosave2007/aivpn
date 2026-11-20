use aivpn_desktop_policy::*;
fn user(uid: u32) -> Authority {
    Authority {
        user: Owner::LinuxUser { uid },
        machine_admin: false,
    }
}
fn document(owner: &Authority, profile: &str) -> Policy {
    Policy::validate(
        PolicyDocument {
            split_enabled: true,
            version: 1,
            id: "apps".into(),
            generation: 1,
            platform: Platform::Linux,
            owner: owner.user.clone(),
            default_action: Action::System {},
            dns: DnsPolicy::SharedVpn {
                profile: profile.into(),
                acknowledge_outage: true,
            },
            rules: vec![],
        },
        owner,
    )
    .unwrap()
}
#[test]
fn outage_acknowledgement_does_not_authorize_global_dns_control() {
    let owner = user(1000);
    let mut catalog = ProfileCatalog::new(Platform::Linux, [31; 16]);
    let id = catalog
        .register(&owner, owner.user.clone(), vec![])
        .unwrap();
    assert!(catalog
        .authorize_policy(&document(&owner, &id), &owner)
        .is_err());
}

#[test]
fn only_machine_admin_can_select_or_clear_shared_dns() {
    let owner = user(1000);
    let admin = Authority {
        machine_admin: true,
        ..user(0)
    };
    let mut catalog = ProfileCatalog::new(Platform::Linux, [32; 16]);
    let id = catalog
        .register(&owner, owner.user.clone(), vec![])
        .unwrap();
    assert!(catalog.set_global_dns(&id, &owner).is_err());
    assert_eq!(catalog.global_dns_profile(), None);
    catalog.set_global_dns(&id, &admin).unwrap();
    assert_eq!(catalog.global_dns_profile(), Some(id.as_str()));
    assert!(catalog
        .authorize_policy(&document(&owner, &id), &owner)
        .is_ok());
    assert!(catalog.clear_global_dns(&owner).is_err());
    assert!(catalog.remove(&id, &owner).is_err());
    assert!(catalog.set_global_dns("missing", &admin).is_err());
    assert_eq!(catalog.global_dns_profile(), Some(id.as_str()));
    catalog.clear_global_dns(&admin).unwrap();
    catalog.remove(&id, &owner).unwrap();
}

#[test]
fn shared_dns_permission_does_not_grant_access_to_foreign_vpn_routes() {
    let owner = user(1000);
    let other = user(1001);
    let admin = Authority {
        machine_admin: true,
        ..user(0)
    };
    let mut catalog = ProfileCatalog::new(Platform::Linux, [33; 16]);
    let id = catalog
        .register(&other, other.user.clone(), vec![])
        .unwrap();
    catalog.set_global_dns(&id, &admin).unwrap();
    catalog
        .authorize_policy(&document(&owner, &id), &owner)
        .unwrap();
    let mut forbidden = document(&owner, &id).document().clone();
    forbidden.default_action = Action::Vpn { profile: id };
    assert!(catalog
        .authorize_policy(&Policy::validate(forbidden, &owner).unwrap(), &owner)
        .is_err());
}

#[test]
fn global_dns_selection_survives_restart_without_reactivating_a_session() {
    let owner = user(1000);
    let admin = Authority {
        machine_admin: true,
        ..user(0)
    };
    let mut catalog = ProfileCatalog::new(Platform::Linux, [34; 16]);
    let id = catalog
        .register(&owner, owner.user.clone(), vec![])
        .unwrap();
    catalog.set_global_dns(&id, &admin).unwrap();
    let data = catalog.store_metadata().unwrap();
    let restored = ProfileCatalog::restore_metadata(Platform::Linux, &data).unwrap();
    assert_eq!(restored.global_dns_profile(), Some(id.as_str()));
    assert!(!restored.available(&id, "203.0.113.8".parse().unwrap()));
    let mut corrupt: serde_json::Value = serde_json::from_slice(&data).unwrap();
    corrupt["global_dns"] = serde_json::json!("missing");
    assert!(ProfileCatalog::restore_metadata(
        Platform::Linux,
        &serde_json::to_vec(&corrupt).unwrap()
    )
    .is_err());
    corrupt.as_object_mut().unwrap().remove("global_dns");
    let old =
        ProfileCatalog::restore_metadata(Platform::Linux, &serde_json::to_vec(&corrupt).unwrap())
            .unwrap();
    assert_eq!(old.global_dns_profile(), None);
    assert!(old
        .authorize_policy(&document(&owner, &id), &owner)
        .is_err());
}

#[test]
fn a_user_cannot_replace_the_approved_dns_profile_through_a_policy_document() {
    let owner = user(1000);
    let admin = Authority {
        machine_admin: true,
        ..user(0)
    };
    let mut catalog = ProfileCatalog::new(Platform::Linux, [35; 16]);
    let first = catalog
        .register(&owner, owner.user.clone(), vec![])
        .unwrap();
    let second = catalog
        .register(&owner, owner.user.clone(), vec![])
        .unwrap();
    catalog.set_global_dns(&first, &admin).unwrap();
    assert!(catalog
        .authorize_policy(&document(&owner, &second), &owner)
        .is_err());
    catalog.set_global_dns(&second, &admin).unwrap();
    assert!(catalog
        .authorize_policy(&document(&owner, &first), &owner)
        .is_err());
    assert!(catalog
        .authorize_policy(&document(&owner, &second), &owner)
        .is_ok());
}

#[test]
fn administrative_scope_keeps_platform_identity_checks() {
    let admin = Authority {
        machine_admin: true,
        ..user(0)
    };
    let target = user(1001);
    assert!(Policy::validate(document(&target, "vpn").document().clone(), &admin).is_ok());
    let mut machine = document(&target, "vpn").document().clone();
    machine.owner = Owner::Machine {};
    let foreign_admin = Authority {
        user: Owner::WindowsUser {
            sid: "S-1-5-21-1-2-3-1000".into(),
        },
        machine_admin: true,
    };
    assert!(Policy::validate(machine, &foreign_admin).is_err());
    let mut catalog = ProfileCatalog::new(Platform::Linux, [36; 16]);
    assert!(catalog
        .register(&admin, target.user.clone(), vec![])
        .is_ok());
    assert!(catalog
        .register(&foreign_admin, Owner::Machine {}, vec![])
        .is_err());
}
