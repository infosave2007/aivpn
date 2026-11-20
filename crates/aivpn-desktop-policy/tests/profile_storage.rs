use aivpn_desktop_policy::*;
use std::net::IpAddr;

fn authority(uid: u32) -> Authority {
    Authority {
        user: Owner::LinuxUser { uid },
        machine_admin: false,
    }
}

fn ready(catalog: &mut ProfileCatalog, id: &str, owner: &Authority) -> ProfileLease {
    let lease = catalog.begin_session(id, owner).unwrap();
    let prepared = catalog
        .prepare_assignment(
            &lease,
            ProfileAssignment {
                interface_id: 17,
                ipv4: "10.67.0.2".parse().unwrap(),
                ipv6: None,
            },
        )
        .unwrap();
    catalog.commit_ready(prepared).unwrap();
    lease
}

#[test]
fn restart_preserves_ids_and_network_generation_but_never_readiness() {
    let owner = authority(1000);
    let mut catalog = ProfileCatalog::new(Platform::Linux, [17; 16]);
    let id = catalog
        .register(&owner, owner.user.clone(), vec![])
        .unwrap();
    let old_lease = ready(&mut catalog, &id, &owner);
    let data = catalog.store_metadata().unwrap();
    let mut restored = ProfileCatalog::restore_metadata(Platform::Linux, &data).unwrap();
    let destination: IpAddr = "203.0.113.8".parse().unwrap();
    assert!(!restored.available(&id, destination));
    assert!(restored.disconnect(&old_lease).is_err());
    let lease = restored.begin_session(&id, &owner).unwrap();
    let same = restored
        .prepare_assignment(
            &lease,
            ProfileAssignment {
                interface_id: 17,
                ipv4: "10.67.0.2".parse().unwrap(),
                ipv6: None,
            },
        )
        .unwrap();
    assert_eq!(same.generation(), 1);
    restored.commit_ready(same).unwrap();
    assert!(restored.available(&id, destination));
    let changed = restored
        .prepare_assignment(
            &lease,
            ProfileAssignment {
                interface_id: 18,
                ipv4: "10.67.0.3".parse().unwrap(),
                ipv6: None,
            },
        )
        .unwrap();
    assert_eq!(changed.generation(), 2);
}

#[test]
fn deleted_ids_remain_retired_after_restart() {
    let owner = authority(1000);
    let mut catalog = ProfileCatalog::new(Platform::Linux, [18; 16]);
    let id = catalog
        .register(&owner, owner.user.clone(), vec![])
        .unwrap();
    catalog.remove(&id, &owner).unwrap();
    let mut restored =
        ProfileCatalog::restore_metadata(Platform::Linux, &catalog.store_metadata().unwrap())
            .unwrap();
    let next = restored
        .register(&owner, owner.user.clone(), vec![])
        .unwrap();
    assert_ne!(id, next);
    assert_eq!(&id[..34], &next[..34]);
}

#[test]
fn deterministic_metadata_retains_access_grants() {
    let owner = Authority {
        machine_admin: true,
        ..authority(1000)
    };
    let mut catalog = ProfileCatalog::new(Platform::Linux, [19; 16]);
    let id = catalog
        .register(
            &owner,
            owner.user.clone(),
            vec![
                Owner::LinuxUser { uid: 1002 },
                Owner::LinuxUser { uid: 1001 },
            ],
        )
        .unwrap();
    catalog.set_global_dns(&id, &owner).unwrap();
    let data = catalog.store_metadata().unwrap();
    let mut restored = ProfileCatalog::restore_metadata(Platform::Linux, &data).unwrap();
    assert_eq!(data, restored.store_metadata().unwrap());
    assert!(restored.begin_session(&id, &authority(1001)).is_err());
    let policy = Policy::validate(
        PolicyDocument {
            split_enabled: true,
            version: 1,
            id: "shared".into(),
            generation: 1,
            platform: Platform::Linux,
            owner: Owner::LinuxUser { uid: 1001 },
            default_action: Action::System {},
            dns: DnsPolicy::SharedVpn {
                profile: id,
                acknowledge_outage: true,
            },
            rules: vec![],
        },
        &authority(1001),
    )
    .unwrap();
    restored
        .authorize_policy(&policy, &authority(1001))
        .unwrap();
    assert!(restored
        .authorize_policy(&policy, &authority(1003))
        .is_err());
}

#[test]
fn corrupted_metadata_is_rejected_instead_of_resetting_catalog() {
    let owner = authority(1000);
    let mut catalog = ProfileCatalog::new(Platform::Linux, [20; 16]);
    let id = catalog
        .register(&owner, owner.user.clone(), vec![])
        .unwrap();
    ready(&mut catalog, &id, &owner);
    let value: serde_json::Value =
        serde_json::from_slice(&catalog.store_metadata().unwrap()).unwrap();
    let mut cases = vec![];
    for (field, bad) in [
        ("version", serde_json::json!(2)),
        ("next_id", serde_json::json!("0000000000000000")),
        ("namespace", serde_json::json!("x")),
        ("platform", serde_json::json!("windows")),
    ] {
        let mut doc = value.clone();
        doc[field] = bad;
        cases.push(doc);
    }
    let mut duplicate = value.clone();
    duplicate["profiles"]
        .as_array_mut()
        .unwrap()
        .push(value["profiles"][0].clone());
    cases.push(duplicate);
    for (field, bad) in [
        ("id", serde_json::json!("pother")),
        ("assignment_generation", serde_json::json!(0)),
        ("assignment", serde_json::Value::Null),
        ("unexpected", serde_json::json!(true)),
        (
            "consumers",
            serde_json::json!([{"kind":"linux_user","uid":1000}]),
        ),
    ] {
        let mut doc = value.clone();
        doc["profiles"][0][field] = bad;
        cases.push(doc);
    }
    let mut reused = value.clone();
    reused["next_id"] = serde_json::json!("0000000000000001");
    cases.push(reused);
    let mut wrong_family = value;
    wrong_family["profiles"][0]["assignment"]["ipv4"] = serde_json::json!("127.0.0.1");
    cases.push(wrong_family);
    for doc in cases {
        assert!(
            ProfileCatalog::restore_metadata(Platform::Linux, &serde_json::to_vec(&doc).unwrap())
                .is_err(),
            "accepted {doc}"
        );
    }
    assert!(ProfileCatalog::restore_metadata(Platform::Linux, b"{}").is_err());
    assert!(
        ProfileCatalog::restore_metadata(Platform::Linux, &vec![b' '; 16 * 1024 * 1024 + 1])
            .is_err()
    );
}

#[test]
fn metadata_boundaries_and_canonical_numbers_are_enforced() {
    let owner = Authority {
        machine_admin: true,
        ..authority(1000)
    };
    let mut catalog = ProfileCatalog::new(Platform::Linux, [0xab; 16]);
    for index in 0..256 {
        catalog
            .register(
                &owner,
                owner.user.clone(),
                if index == 0 {
                    vec![
                        Owner::Machine {},
                        Owner::LinuxUser { uid: 1002 },
                        Owner::LinuxUser { uid: 1001 },
                    ]
                } else {
                    vec![]
                },
            )
            .unwrap();
    }
    let data = catalog.store_metadata().unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&data).unwrap();
    let ids = value["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
    let mut padded = data.clone();
    padded.resize(16 * 1024 * 1024, b' ');
    assert!(ProfileCatalog::restore_metadata(Platform::Linux, &padded).is_ok());
    padded.push(b' ');
    assert!(ProfileCatalog::restore_metadata(Platform::Linux, &padded).is_err());
    assert_eq!(
        data,
        ProfileCatalog::restore_metadata(Platform::Linux, &data)
            .unwrap()
            .store_metadata()
            .unwrap()
    );
    let extra = value["profiles"][0].clone();
    value["profiles"].as_array_mut().unwrap().push(extra);
    assert!(ProfileCatalog::restore_metadata(
        Platform::Linux,
        &serde_json::to_vec(&value).unwrap()
    )
    .is_err());
    let original: serde_json::Value = serde_json::from_slice(&data).unwrap();
    for (field, bad) in [
        (
            "namespace",
            serde_json::json!("ABABABABABABABABABABABABABABABAB"),
        ),
        ("next_id", serde_json::json!("101")),
        ("next_id", serde_json::json!("invalid")),
    ] {
        let mut doc = original.clone();
        doc[field] = bad;
        assert!(ProfileCatalog::restore_metadata(
            Platform::Linux,
            &serde_json::to_vec(&doc).unwrap()
        )
        .is_err());
    }
}

#[test]
fn windows_grants_survive_a_machine_catalog_restart() {
    let owner = Authority {
        user: Owner::WindowsUser {
            sid: "S-1-5-21-1-2-3-1000".into(),
        },
        machine_admin: true,
    };
    let mut catalog = ProfileCatalog::new(Platform::Windows, [21; 16]);
    let id = catalog
        .register(
            &owner,
            Owner::Machine {},
            vec![
                owner.user.clone(),
                Owner::WindowsUser {
                    sid: "S-1-5-21-1-2-3-1001".into(),
                },
            ],
        )
        .unwrap();
    catalog.set_global_dns(&id, &owner).unwrap();
    let data = catalog.store_metadata().unwrap();
    let restored = ProfileCatalog::restore_metadata(Platform::Windows, &data).unwrap();
    assert_eq!(data, restored.store_metadata().unwrap());
    let policy = Policy::validate(
        PolicyDocument {
            split_enabled: true,
            version: 1,
            id: "shared".into(),
            generation: 1,
            platform: Platform::Windows,
            owner: owner.user.clone(),
            default_action: Action::System {},
            dns: DnsPolicy::SharedVpn {
                profile: id,
                acknowledge_outage: true,
            },
            rules: vec![],
        },
        &owner,
    )
    .unwrap();
    restored.authorize_policy(&policy, &owner).unwrap();
}

#[test]
fn pending_assignment_is_durable_before_kernel_readiness_is_published() {
    let owner = authority(1000);
    let mut catalog = ProfileCatalog::new(Platform::Linux, [22; 16]);
    let id = catalog
        .register(&owner, owner.user.clone(), vec![])
        .unwrap();
    let lease = catalog.begin_session(&id, &owner).unwrap();
    let assignment = ProfileAssignment {
        interface_id: 19,
        ipv4: "10.67.0.4".parse().unwrap(),
        ipv6: None,
    };
    let first = catalog.prepare_assignment(&lease, assignment).unwrap();
    let pending = catalog.store_metadata_for_assignment(&first).unwrap();
    assert_ne!(pending, catalog.store_metadata().unwrap());
    assert!(!catalog.available(&id, "203.0.113.8".parse().unwrap()));
    let mut restarted = ProfileCatalog::restore_metadata(Platform::Linux, &pending).unwrap();
    assert!(!restarted.available(&id, "203.0.113.8".parse().unwrap()));
    let restarted_lease = restarted.begin_session(&id, &owner).unwrap();
    assert_eq!(
        restarted
            .prepare_assignment(&restarted_lease, assignment)
            .unwrap()
            .generation(),
        1
    );
    let latest = catalog.prepare_assignment(&lease, assignment).unwrap();
    assert!(catalog.store_metadata_for_assignment(&first).is_err());
    assert!(restarted.store_metadata_for_assignment(&latest).is_err());
    assert_eq!(
        pending,
        catalog.store_metadata_for_assignment(&latest).unwrap()
    );
    catalog.disconnect(&lease).unwrap();
    assert!(catalog.store_metadata_for_assignment(&latest).is_err());
}
