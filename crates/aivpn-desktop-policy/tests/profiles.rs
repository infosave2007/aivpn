use aivpn_desktop_policy::*;
use std::net::Ipv4Addr;

fn authority(uid: u32) -> Authority {
    Authority {
        user: Owner::LinuxUser { uid },
        machine_admin: false,
    }
}

fn assignment() -> ProfileAssignment {
    ProfileAssignment {
        interface_id: 42,
        ipv4: Ipv4Addr::new(10, 67, 0, 2),
        ipv6: None,
    }
}

fn policy(uid: u32, profile: &str) -> Policy {
    Policy::validate(
        PolicyDocument {
            split_enabled: true,
            version: 1,
            id: "apps".into(),
            generation: 1,
            platform: Platform::Linux,
            owner: authority(uid).user,
            default_action: Action::Vpn {
                profile: profile.into(),
            },
            dns: DnsPolicy::SharedVpn {
                profile: profile.into(),
                acknowledge_outage: true,
            },
            rules: vec![],
        },
        &authority(uid),
    )
    .unwrap()
}

fn ready(
    catalog: &mut ProfileCatalog,
    lease: &ProfileLease,
    assignment: ProfileAssignment,
) -> Result<u64, ProfileError> {
    let prepared = catalog.prepare_assignment(lease, assignment)?;
    let generation = prepared.generation();
    catalog.commit_ready(prepared)?;
    Ok(generation)
}

#[test]
fn private_profile_cannot_be_used_by_another_owner() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [1; 16]);
    assert!(catalog
        .register(&authority(1000), authority(1001).user, vec![])
        .is_err());
    let id = catalog
        .register(&authority(1000), authority(1000).user, vec![])
        .unwrap();
    catalog
        .set_global_dns(
            &id,
            &Authority {
                machine_admin: true,
                ..authority(0)
            },
        )
        .unwrap();
    assert!(catalog
        .authorize_policy(&policy(1000, &id), &authority(1000))
        .is_ok());
    assert!(catalog
        .authorize_policy(&policy(1001, &id), &authority(1001))
        .is_err());
    assert!(catalog
        .authorize_policy(&policy(1000, &id), &authority(1001))
        .is_err());
}

#[test]
fn shared_profile_requires_administrative_grant() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [2; 16]);
    assert!(catalog
        .register(
            &authority(1000),
            authority(1000).user,
            vec![authority(1001).user]
        )
        .is_err());
    let admin = Authority {
        machine_admin: true,
        ..authority(1000)
    };
    let id = catalog
        .register(&admin, admin.user.clone(), vec![authority(1001).user])
        .unwrap();
    catalog
        .set_global_dns(
            &id,
            &Authority {
                machine_admin: true,
                ..authority(0)
            },
        )
        .unwrap();
    assert!(catalog
        .authorize_policy(&policy(1001, &id), &authority(1001))
        .is_ok());
    assert!(catalog.begin_session(&id, &authority(1001)).is_err());
    assert!(catalog.begin_session(&id, &authority(1000)).is_ok());
}

#[test]
fn stale_or_foreign_lease_cannot_change_live_readiness() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [3; 16]);
    let mut other = ProfileCatalog::new(Platform::Linux, [3; 16]);
    let id = catalog
        .register(&authority(1000), authority(1000).user, vec![])
        .unwrap();
    let other_id = other
        .register(&authority(1000), authority(1000).user, vec![])
        .unwrap();
    assert_eq!(id, other_id);
    let stale = catalog.begin_session(&id, &authority(1000)).unwrap();
    let live = catalog.begin_session(&id, &authority(1000)).unwrap();
    let foreign = other.begin_session(&id, &authority(1000)).unwrap();
    assert!(ready(&mut catalog, &stale, assignment()).is_err());
    assert!(ready(&mut catalog, &foreign, assignment()).is_err());
    ready(&mut catalog, &live, assignment()).unwrap();
    assert!(catalog.disconnect(&stale).is_err());
    assert!(catalog.available(&id, "203.0.113.8".parse().unwrap()));
    assert!(!catalog.available(&id, "2001:db8::8".parse().unwrap()));
    catalog.disconnect(&live).unwrap();
    assert!(!catalog.available(&id, "203.0.113.8".parse().unwrap()));
}

#[test]
fn assignment_generation_is_stable_only_for_the_same_network() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [4; 16]);
    let id = catalog
        .register(&authority(1000), authority(1000).user, vec![])
        .unwrap();
    let lease = catalog.begin_session(&id, &authority(1000)).unwrap();
    assert_eq!(ready(&mut catalog, &lease, assignment()).unwrap(), 1);
    catalog.disconnect(&lease).unwrap();
    let lease = catalog.begin_session(&id, &authority(1000)).unwrap();
    assert_eq!(ready(&mut catalog, &lease, assignment()).unwrap(), 1);
    let mut changed = assignment();
    changed.interface_id += 1;
    assert_eq!(ready(&mut catalog, &lease, changed).unwrap(), 2);
    changed.ipv6 = Some("fd67:cafe::2".parse().unwrap());
    assert_eq!(ready(&mut catalog, &lease, changed).unwrap(), 3);
    assert!(catalog.available(&id, "2001:db8::8".parse().unwrap()));
    assert!(catalog.available(&id, "::ffff:203.0.113.8".parse().unwrap()));
}

#[test]
fn status_exposes_current_addresses_and_keeps_registration_lookup_with_controllers() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [8; 16]);
    let admin = Authority {
        machine_admin: true,
        ..authority(1000)
    };
    let id = catalog
        .register_stable(
            &admin,
            admin.user.clone(),
            "local-key",
            vec![authority(1001).user],
        )
        .unwrap();
    let initial = catalog.list(&authority(1000)).unwrap().remove(0);
    assert_eq!(initial.registration_key.as_deref(), Some("local-key"));
    assert_eq!(initial.ipv4, None);
    assert_eq!(
        catalog.list(&authority(1001)).unwrap()[0].registration_key,
        None
    );
    assert!(catalog.list(&authority(1002)).unwrap().is_empty());
    let lease = catalog.begin_session(&id, &authority(1000)).unwrap();
    let mut network = assignment();
    network.ipv6 = Some("fd67::2".parse().unwrap());
    ready(&mut catalog, &lease, network).unwrap();
    let active = catalog.list(&authority(1000)).unwrap().remove(0);
    assert_eq!(active.ipv4, Some(network.ipv4));
    assert_eq!(active.ipv6, network.ipv6);
    catalog.disconnect(&lease).unwrap();
    let stopped = catalog.list(&authority(1000)).unwrap().remove(0);
    assert_eq!(stopped.ipv4, None);
    assert_eq!(stopped.ipv6, None);
    assert_eq!(stopped.registration_key.as_deref(), Some("local-key"));
}

#[test]
fn invalid_assignment_closes_current_readiness() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [5; 16]);
    let id = catalog
        .register(&authority(1000), authority(1000).user, vec![])
        .unwrap();
    let lease = catalog.begin_session(&id, &authority(1000)).unwrap();
    let mut bad = assignment();
    bad.ipv4 = Ipv4Addr::UNSPECIFIED;
    ready(&mut catalog, &lease, assignment()).unwrap();
    assert!(ready(&mut catalog, &lease, bad).is_err());
    assert!(!catalog.available(&id, "203.0.113.8".parse().unwrap()));
    bad = assignment();
    bad.ipv6 = Some("::ffff:10.67.0.2".parse().unwrap());
    assert!(ready(&mut catalog, &lease, bad).is_err());
}

#[test]
fn removal_invalidates_leases_and_never_recycles_id() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [6; 16]);
    let id = catalog
        .register(&authority(1000), authority(1000).user, vec![])
        .unwrap();
    let lease = catalog.begin_session(&id, &authority(1000)).unwrap();
    assert!(catalog.remove(&id, &authority(1001)).is_err());
    catalog.remove(&id, &authority(1000)).unwrap();
    assert!(ready(&mut catalog, &lease, assignment()).is_err());
    assert!(!catalog.available(&id, "203.0.113.8".parse().unwrap()));
    let replacement = catalog
        .register(&authority(1000), authority(1000).user, vec![])
        .unwrap();
    assert_ne!(id, replacement);
}

#[test]
fn every_rule_and_dns_profile_is_authorized() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [7; 16]);
    let owned = catalog
        .register(&authority(1000), authority(1000).user, vec![])
        .unwrap();
    catalog
        .set_global_dns(
            &owned,
            &Authority {
                machine_admin: true,
                ..authority(0)
            },
        )
        .unwrap();
    let foreign = catalog
        .register(&authority(1001), authority(1001).user, vec![])
        .unwrap();
    let mut default_foreign = policy(1000, &owned).document().clone();
    default_foreign.default_action = Action::Vpn {
        profile: foreign.clone(),
    };
    assert!(catalog
        .authorize_policy(
            &Policy::validate(default_foreign, &authority(1000)).unwrap(),
            &authority(1000)
        )
        .is_err());
    let mut selected_only = policy(1000, &owned).document().clone();
    selected_only.default_action = Action::System {};
    selected_only.rules.push(RuleDocument {
        id: "block".into(),
        application: Selector::Any {},
        destination: None,
        inherit_children: false,
        action: Action::Block {},
    });
    assert!(catalog
        .authorize_policy(
            &Policy::validate(selected_only, &authority(1000)).unwrap(),
            &authority(1000)
        )
        .is_ok());
    let mut doc = policy(1000, &owned).document().clone();
    doc.rules.push(RuleDocument {
        id: "bypass".into(),
        application: Selector::Any {},
        destination: None,
        inherit_children: false,
        action: Action::Vpn {
            profile: foreign.clone(),
        },
    });
    assert!(catalog
        .authorize_policy(
            &Policy::validate(doc, &authority(1000)).unwrap(),
            &authority(1000)
        )
        .is_err());
    let mut doc = policy(1000, &owned).document().clone();
    doc.dns = DnsPolicy::SharedVpn {
        profile: foreign,
        acknowledge_outage: true,
    };
    assert!(catalog
        .authorize_policy(
            &Policy::validate(doc, &authority(1000)).unwrap(),
            &authority(1000)
        )
        .is_err());
}

#[test]
fn assignment_is_unavailable_until_committed_and_disconnect_invalidates_preparation() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [8; 16]);
    let id = catalog
        .register(&authority(1000), authority(1000).user, vec![])
        .unwrap();
    let lease = catalog.begin_session(&id, &authority(1000)).unwrap();
    let prepared = catalog.prepare_assignment(&lease, assignment()).unwrap();
    assert_eq!(prepared.assignment(), assignment());
    assert!(!catalog.available(&id, "203.0.113.8".parse().unwrap()));
    catalog.disconnect(&lease).unwrap();
    assert!(catalog.commit_ready(prepared).is_err());
    assert!(catalog.prepare_assignment(&lease, assignment()).is_err());
}

#[test]
fn only_latest_preparation_can_commit_even_when_network_generation_does_not_change() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [9; 16]);
    let id = catalog
        .register(&authority(1000), authority(1000).user, vec![])
        .unwrap();
    let lease = catalog.begin_session(&id, &authority(1000)).unwrap();
    ready(&mut catalog, &lease, assignment()).unwrap();
    let mut changed = assignment();
    changed.interface_id += 1;
    let stale = catalog.prepare_assignment(&lease, changed).unwrap();
    let live = catalog.prepare_assignment(&lease, assignment()).unwrap();
    assert_eq!(live.generation(), 1);
    catalog.commit_ready(live).unwrap();
    assert!(catalog.commit_ready(stale).is_err());
    assert!(catalog.available(&id, "203.0.113.8".parse().unwrap()));
    let pending = catalog.prepare_assignment(&lease, assignment()).unwrap();
    let mut invalid = assignment();
    invalid.interface_id = 0;
    assert!(catalog.prepare_assignment(&lease, invalid).is_err());
    assert!(catalog.commit_ready(pending).is_err());
    assert!(!catalog.available(&id, "203.0.113.8".parse().unwrap()));
}

#[test]
fn invalid_sources_and_interface_never_become_ready() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [10; 16]);
    let id = catalog
        .register(&authority(1000), authority(1000).user, vec![])
        .unwrap();
    let lease = catalog.begin_session(&id, &authority(1000)).unwrap();
    for source in ["0.1.2.3", "127.0.0.2", "224.0.0.1", "255.255.255.255"] {
        let mut bad = assignment();
        bad.ipv4 = source.parse().unwrap();
        assert!(ready(&mut catalog, &lease, bad).is_err());
    }
    for source in ["::", "::1", "ff02::1"] {
        let mut bad = assignment();
        bad.ipv6 = Some(source.parse().unwrap());
        assert!(ready(&mut catalog, &lease, bad).is_err());
    }
    let mut valid = assignment();
    valid.ipv4 = "223.255.255.254".parse().unwrap();
    assert!(ready(&mut catalog, &lease, valid).is_ok());
    assert!(catalog.available(&id, "::ffff:203.0.113.8".parse().unwrap()));
}

#[test]
fn catalog_capacity_and_grant_boundaries_preserve_existing_profiles() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [11; 16]);
    let admin = Authority {
        machine_admin: true,
        ..authority(1000)
    };
    let consumers = (1001..1129)
        .map(|uid| authority(uid).user)
        .collect::<Vec<_>>();
    let first = catalog
        .register(&admin, admin.user.clone(), consumers.clone())
        .unwrap();
    assert!(catalog
        .register(&admin, admin.user.clone(), vec![admin.user.clone()])
        .is_err());
    assert!(catalog
        .register(
            &admin,
            admin.user.clone(),
            vec![authority(1001).user, authority(1001).user]
        )
        .is_err());
    let mut excessive = consumers;
    excessive.push(authority(1129).user);
    assert!(catalog
        .register(&admin, admin.user.clone(), excessive)
        .is_err());
    for _ in 1..256 {
        catalog
            .register(&admin, admin.user.clone(), vec![])
            .unwrap();
    }
    assert!(catalog
        .register(&admin, admin.user.clone(), vec![])
        .is_err());
    catalog.remove(&first, &admin).unwrap();
    let replacement = catalog
        .register(&admin, admin.user.clone(), vec![])
        .unwrap();
    assert_ne!(replacement, first);
}

#[test]
fn windows_owner_and_platform_are_checked_before_registration() {
    let mut catalog = ProfileCatalog::new(Platform::Windows, [12; 16]);
    assert!(catalog
        .register(&authority(1000), authority(1000).user, vec![])
        .is_err());
    let owner = Owner::WindowsUser {
        sid: "S-1-5-21-1-2-3-1000".into(),
    };
    let auth = Authority {
        user: owner.clone(),
        machine_admin: false,
    };
    let id = catalog.register(&auth, owner, vec![]).unwrap();
    let lease = catalog.begin_session(&id, &auth).unwrap();
    ready(&mut catalog, &lease, assignment()).unwrap();
    assert!(catalog.available(&id, "203.0.113.8".parse().unwrap()));
    assert!(catalog
        .authorize_policy(&policy(1000, &id), &authority(1000))
        .is_err());
}

#[test]
fn machine_sharing_is_explicit_and_consumers_cannot_control_session() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [13; 16]);
    let admin = Authority {
        machine_admin: true,
        ..authority(0)
    };
    assert!(catalog
        .register(&authority(1000), Owner::Machine {}, vec![])
        .is_err());
    let id = catalog
        .register(&admin, Owner::Machine {}, vec![authority(1000).user])
        .unwrap();
    catalog
        .set_global_dns(
            &id,
            &Authority {
                machine_admin: true,
                ..authority(0)
            },
        )
        .unwrap();
    assert!(catalog
        .authorize_policy(&policy(1000, &id), &authority(1000))
        .is_ok());
    assert!(catalog.begin_session(&id, &authority(1000)).is_err());
    assert!(catalog.begin_session(&id, &admin).is_ok());
}

#[test]
fn starting_new_session_closes_previous_readiness_before_assignment() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [14; 16]);
    let id = catalog
        .register(&authority(1000), authority(1000).user, vec![])
        .unwrap();
    let old = catalog.begin_session(&id, &authority(1000)).unwrap();
    let before = ready(&mut catalog, &old, assignment()).unwrap();
    let old_id = catalog.list(&authority(1000)).unwrap()[0]
        .session_id
        .unwrap();
    assert_eq!(old_id, old.session_id());
    let new = catalog.begin_session(&id, &authority(1000)).unwrap();
    assert!(!catalog.available(&id, "203.0.113.8".parse().unwrap()));
    assert_eq!(ready(&mut catalog, &new, assignment()).unwrap(), before);
    let new_id = catalog.list(&authority(1000)).unwrap()[0]
        .session_id
        .unwrap();
    assert_eq!(new_id, new.session_id());
    assert_ne!(
        new_id, old_id,
        "Одинаковый адрес не должен связывать разные сеансы управления"
    );
    assert!(catalog.disconnect(&old).is_err());
    assert!(catalog.available(&id, "203.0.113.8".parse().unwrap()));
}

#[test]
fn session_identity_is_hidden_from_consumers_and_changes_after_catalog_restore() {
    let admin = Authority {
        machine_admin: true,
        ..authority(0)
    };
    let mut catalog = ProfileCatalog::new(Platform::Linux, [21; 16]);
    let id = catalog
        .register(&admin, authority(1000).user, vec![authority(1001).user])
        .unwrap();
    let lease = catalog.begin_session(&id, &authority(1000)).unwrap();
    ready(&mut catalog, &lease, assignment()).unwrap();
    let old = catalog.list(&authority(1000)).unwrap()[0]
        .session_id
        .unwrap();
    assert_eq!(catalog.list(&authority(1001)).unwrap()[0].session_id, None);
    let saved = catalog.store_metadata().unwrap();
    let mut restored = ProfileCatalog::restore_metadata(Platform::Linux, &saved).unwrap();
    assert_eq!(restored.list(&authority(1000)).unwrap()[0].session_id, None);
    let lease = restored.begin_session(&id, &authority(1000)).unwrap();
    ready(&mut restored, &lease, assignment()).unwrap();
    assert_ne!(
        restored.list(&authority(1000)).unwrap()[0]
            .session_id
            .unwrap(),
        old
    );
}
