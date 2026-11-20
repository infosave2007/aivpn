use aivpn_desktop_policy::*;

fn user(uid: u32) -> Authority {
    Authority {
        user: Owner::LinuxUser { uid },
        machine_admin: uid == 0,
    }
}

#[test]
fn visible_profiles_do_not_grant_control_to_consumers() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [8; 16]);
    let private = catalog
        .register(&user(1000), user(1000).user, vec![])
        .unwrap();
    let shared = catalog
        .register(&user(0), user(1001).user, vec![user(1000).user])
        .unwrap();
    catalog
        .register(&user(1002), user(1002).user, vec![])
        .unwrap();
    let visible = catalog.list(&user(1000)).unwrap();
    assert_eq!(visible.len(), 2);
    assert_eq!(visible[0].id, private);
    assert!(visible[0].control_allowed);
    assert_eq!(visible[1].id, shared);
    assert!(!visible[1].control_allowed);
    assert_eq!(catalog.list(&user(0)).unwrap().len(), 3);
    assert!(catalog
        .list(&user(0))
        .unwrap()
        .iter()
        .all(|p| p.control_allowed));
    assert!(catalog.list(&user(1003)).unwrap().is_empty());
}

#[test]
fn view_reports_family_readiness_and_revokes_it_during_reassignment() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [9; 16]);
    let id = catalog
        .register(&user(1000), user(1000).user, vec![])
        .unwrap();
    let view = catalog.list(&user(1000)).unwrap().remove(0);
    assert!(!view.session_active && !view.ready_ipv4 && !view.ready_ipv6);
    assert_eq!(view.assignment_generation, 0);
    let lease = catalog.begin_session(&id, &user(1000)).unwrap();
    let assignment = ProfileAssignment {
        interface_id: 1,
        ipv4: "10.67.0.2".parse().unwrap(),
        ipv6: None,
    };
    let prepared = catalog.prepare_assignment(&lease, assignment).unwrap();
    let view = catalog.list(&user(1000)).unwrap().remove(0);
    assert!(view.session_active && !view.ready_ipv4 && !view.ready_ipv6);
    catalog.commit_ready(prepared).unwrap();
    let view = catalog.list(&user(1000)).unwrap().remove(0);
    assert!(view.session_active && view.ready_ipv4 && !view.ready_ipv6);
    assert_eq!(view.assignment_generation, 1);
    let dual = ProfileAssignment {
        ipv6: Some("fd67:cafe::2".parse().unwrap()),
        ..assignment
    };
    let prepared = catalog.prepare_assignment(&lease, dual).unwrap();
    assert!(!catalog.list(&user(1000)).unwrap()[0].ready_ipv4);
    catalog.commit_ready(prepared).unwrap();
    assert!(catalog.list(&user(1000)).unwrap()[0].ready_ipv6);
    catalog.disconnect(&lease).unwrap();
    let view = catalog.list(&user(1000)).unwrap().remove(0);
    assert!(!view.session_active && !view.ready_ipv4 && !view.ready_ipv6);
    assert_eq!(view.assignment_generation, 2);
}

#[test]
fn profile_listing_rejects_wrong_platform_authority() {
    let catalog = ProfileCatalog::new(Platform::Linux, [10; 16]);
    let wrong = Authority {
        user: Owner::WindowsUser {
            sid: "S-1-5-21-1".into(),
        },
        machine_admin: true,
    };
    assert!(catalog.list(&wrong).is_err());
    assert!(catalog
        .list(&Authority {
            user: Owner::Machine {},
            machine_admin: false
        })
        .is_err());
}

#[test]
fn backend_failure_revokes_live_leases_and_preparations_for_every_profile() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [11; 16]);
    let first = catalog
        .register(&user(1000), user(1000).user, vec![])
        .unwrap();
    let second = catalog
        .register(&user(1001), user(1001).user, vec![])
        .unwrap();
    let first_lease = catalog.begin_session(&first, &user(1000)).unwrap();
    let second_lease = catalog.begin_session(&second, &user(1001)).unwrap();
    let assignment = ProfileAssignment {
        interface_id: 2,
        ipv4: "10.67.0.2".parse().unwrap(),
        ipv6: None,
    };
    let ready = catalog
        .prepare_assignment(&first_lease, assignment)
        .unwrap();
    catalog.commit_ready(ready).unwrap();
    let pending = catalog
        .prepare_assignment(&second_lease, assignment)
        .unwrap();
    catalog.invalidate_sessions();
    assert!(catalog.commit_ready(pending).is_err());
    assert!(catalog
        .prepare_assignment(&first_lease, assignment)
        .is_err());
    assert!(catalog
        .list(&user(0))
        .unwrap()
        .iter()
        .all(|profile| !profile.session_active && !profile.ready_ipv4 && !profile.ready_ipv6));
    let new = catalog.begin_session(&first, &user(1000)).unwrap();
    let ready = catalog.prepare_assignment(&new, assignment).unwrap();
    assert_eq!(ready.generation(), 1);
    catalog.commit_ready(ready).unwrap();
}
