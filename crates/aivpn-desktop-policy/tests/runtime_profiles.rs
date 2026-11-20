use aivpn_desktop_policy::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn user(uid: u32) -> Authority {
    Authority {
        user: Owner::LinuxUser { uid },
        machine_admin: false,
    }
}

fn administrator() -> Authority {
    Authority {
        machine_admin: true,
        ..user(0)
    }
}

fn assignment(interface_id: u64, ipv6: Option<Ipv6Addr>) -> ProfileAssignment {
    ProfileAssignment {
        interface_id,
        ipv4: Ipv4Addr::new(10, 67, 0, 2),
        ipv6,
    }
}

#[test]
fn runtime_snapshot_distinguishes_prepared_live_and_disconnected_assignments() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [71; 16]);
    let id = catalog
        .register(&user(1000), user(1000).user, vec![])
        .unwrap();
    let initial = catalog.runtime_profiles(&administrator()).unwrap();
    assert_eq!(initial.len(), 1);
    assert_eq!(initial[0].id, id);
    assert_eq!(initial[0].assignment, None);
    assert_eq!(initial[0].assignment_generation, 0);
    assert!(!initial[0].ready_ipv4);
    assert!(!initial[0].ready_ipv6);
    assert!(!catalog.has_recorded_assignments());

    let lease = catalog.begin_session(&id, &user(1000)).unwrap();
    let assigned = assignment(42, Some("fd67::2".parse().unwrap()));
    let prepared = catalog.prepare_assignment(&lease, assigned).unwrap();
    assert_eq!(catalog.runtime_profiles(&administrator()).unwrap(), initial);
    assert!(!catalog.has_recorded_assignments());
    let generation = prepared.generation();
    catalog.commit_ready(prepared).unwrap();
    let live = catalog.runtime_profiles(&administrator()).unwrap();
    assert_eq!(live[0].assignment, Some(assigned));
    assert_eq!(live[0].assignment_generation, generation);
    assert!(live[0].ready_ipv4);
    assert!(live[0].ready_ipv6);
    assert!(catalog.has_recorded_assignments());

    let restored =
        ProfileCatalog::restore_metadata(Platform::Linux, &catalog.store_metadata().unwrap())
            .unwrap();
    let restored = restored.runtime_profiles(&administrator()).unwrap();
    assert_eq!(restored[0].assignment, Some(assigned));
    assert_eq!(restored[0].assignment_generation, generation);
    assert!(!restored[0].ready_ipv4);
    assert!(!restored[0].ready_ipv6);

    catalog.disconnect(&lease).unwrap();
    let disconnected = catalog.runtime_profiles(&administrator()).unwrap();
    assert_eq!(disconnected[0].assignment, Some(assigned));
    assert_eq!(disconnected[0].assignment_generation, generation);
    assert!(!disconnected[0].ready_ipv4);
    assert!(!disconnected[0].ready_ipv6);
    assert!(catalog.has_recorded_assignments());
    assert!(live[0].ready_ipv4);

    let replacement = catalog.begin_session(&id, &user(1000)).unwrap();
    let prepared = catalog
        .prepare_assignment(&replacement, assignment(84, None))
        .unwrap();
    catalog.commit_ready(prepared).unwrap();
    let replaced = catalog.runtime_profiles(&administrator()).unwrap();
    assert_eq!(replaced[0].assignment.unwrap().interface_id, 84);
    assert!(replaced[0].assignment_generation > generation);
    assert!(replaced[0].ready_ipv4);
    assert!(!replaced[0].ready_ipv6);
    assert!(catalog.disconnect(&lease).is_err());
    assert_eq!(
        catalog.runtime_profiles(&administrator()).unwrap(),
        replaced
    );
    catalog.invalidate_sessions();
    let invalidated = catalog.runtime_profiles(&administrator()).unwrap();
    assert!(!invalidated[0].ready_ipv4);
    assert!(!invalidated[0].ready_ipv6);
    catalog.remove(&id, &user(1000)).unwrap();
    assert!(!catalog.has_recorded_assignments());
}

#[test]
fn runtime_snapshot_is_administrative_and_platform_checked() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [72; 16]);
    let id = catalog
        .register(&user(1000), user(1000).user, vec![])
        .unwrap();
    for authority in [
        user(1000),
        user(0),
        user(1001),
        Authority {
            user: Owner::Machine {},
            machine_admin: true,
        },
    ] {
        assert!(matches!(
            catalog.runtime_profiles(&authority),
            Err(ProfileError::AccessDenied)
        ));
    }
    let wrong_platform = Authority {
        user: Owner::WindowsUser {
            sid: "S-1-5-21-1000".into(),
        },
        machine_admin: true,
    };
    assert!(catalog.runtime_profiles(&wrong_platform).is_err());
    assert_eq!(
        catalog.runtime_profiles(&administrator()).unwrap()[0].id,
        id
    );
}

#[test]
fn runtime_snapshot_lists_all_profiles_in_stable_order_and_forgets_removed_entries() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [73; 16]);
    let first = catalog
        .register(&user(2000), user(2000).user, vec![])
        .unwrap();
    let second = catalog
        .register(&user(1000), user(1000).user, vec![])
        .unwrap();
    let mut expected = vec![first.clone(), second];
    expected.sort();
    assert_eq!(
        catalog
            .runtime_profiles(&administrator())
            .unwrap()
            .into_iter()
            .map(|profile| profile.id)
            .collect::<Vec<_>>(),
        expected
    );
    catalog.remove(&first, &user(2000)).unwrap();
    assert_eq!(catalog.runtime_profiles(&administrator()).unwrap().len(), 1);
    let empty = ProfileCatalog::new(Platform::Linux, [74; 16]);
    assert!(empty.runtime_profiles(&administrator()).unwrap().is_empty());
}

#[test]
fn windows_runtime_snapshot_requires_windows_administrative_authority() {
    let mut catalog = ProfileCatalog::new(Platform::Windows, [75; 16]);
    let owner = Authority {
        user: Owner::WindowsUser {
            sid: "S-1-5-21-1000".into(),
        },
        machine_admin: false,
    };
    let id = catalog
        .register(&owner, owner.user.clone(), vec![])
        .unwrap();
    let windows_admin = Authority {
        user: Owner::WindowsUser {
            sid: "S-1-5-18".into(),
        },
        machine_admin: true,
    };
    assert!(matches!(
        catalog.runtime_profiles(&owner),
        Err(ProfileError::AccessDenied)
    ));
    assert!(catalog.runtime_profiles(&administrator()).is_err());
    assert_eq!(catalog.runtime_profiles(&windows_admin).unwrap()[0].id, id);
}

#[test]
fn session_capability_reads_only_its_current_catalog_session() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [76; 16]);
    let id = catalog
        .register(&user(1000), user(1000).user, vec![])
        .unwrap();
    let lease = catalog.begin_session(&id, &user(1000)).unwrap();
    assert_eq!(catalog.session_profile(&lease).unwrap().id, id);
    assert!(!catalog.session_profile(&lease).unwrap().ready_ipv4);
    let prepared = catalog
        .prepare_assignment(&lease, assignment(42, None))
        .unwrap();
    catalog.commit_ready(prepared).unwrap();
    assert_eq!(
        catalog.session_profile(&lease).unwrap(),
        catalog.runtime_profiles(&administrator()).unwrap()[0]
    );

    let mut foreign = ProfileCatalog::new(Platform::Linux, [76; 16]);
    let foreign_id = foreign
        .register(&user(1000), user(1000).user, vec![])
        .unwrap();
    assert_eq!(foreign_id, id);
    let foreign_lease = foreign.begin_session(&foreign_id, &user(1000)).unwrap();
    assert!(matches!(
        catalog.session_profile(&foreign_lease),
        Err(ProfileError::StaleLease)
    ));
    let empty = ProfileCatalog::new(Platform::Linux, [76; 16]);
    assert!(matches!(
        empty.session_profile(&lease),
        Err(ProfileError::NotFound)
    ));

    let replacement = catalog.begin_session(&id, &user(1000)).unwrap();
    assert!(matches!(
        catalog.session_profile(&lease),
        Err(ProfileError::StaleLease)
    ));
    assert!(!catalog.session_profile(&replacement).unwrap().ready_ipv4);
    catalog.disconnect(&replacement).unwrap();
    assert!(matches!(
        catalog.session_profile(&replacement),
        Err(ProfileError::StaleLease)
    ));
}
