use aivpn_desktop_policy::*;

fn user(uid: u32) -> Authority {
    Authority {
        user: Owner::LinuxUser { uid },
        machine_admin: uid == 0,
    }
}

#[test]
fn retries_return_the_same_owned_profile_and_preserve_registration_across_restart() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [1; 16]);
    let key = "local-profile-1";
    let first = catalog
        .register_stable(&user(1000), user(1000).user, key, vec![])
        .unwrap();
    let lease = catalog.begin_session(&first, &user(1000)).unwrap();
    let assignment = ProfileAssignment {
        interface_id: 1,
        ipv4: "10.67.0.2".parse().unwrap(),
        ipv6: None,
    };
    let ready = catalog.prepare_assignment(&lease, assignment).unwrap();
    catalog.commit_ready(ready).unwrap();
    assert_eq!(
        catalog
            .register_stable(&user(1000), user(1000).user, key, vec![])
            .unwrap(),
        first
    );
    assert!(catalog.available(&first, "192.0.2.1".parse().unwrap()));
    let mut restored =
        ProfileCatalog::restore_metadata(Platform::Linux, &catalog.store_metadata().unwrap())
            .unwrap();
    assert_eq!(
        restored
            .register_stable(&user(1000), user(1000).user, key, vec![])
            .unwrap(),
        first
    );
    assert_eq!(restored.list(&user(1000)).unwrap().len(), 1);
    let other_owner = restored
        .register_stable(&user(1001), user(1001).user, key, vec![])
        .unwrap();
    let other_key = restored
        .register_stable(&user(1000), user(1000).user, "local-profile-2", vec![])
        .unwrap();
    assert_ne!(first, other_owner);
    assert_ne!(first, other_key);
    let mut restored =
        ProfileCatalog::restore_metadata(Platform::Linux, &restored.store_metadata().unwrap())
            .unwrap();
    assert_eq!(
        restored
            .register_stable(&user(1001), user(1001).user, key, vec![])
            .unwrap(),
        other_owner
    );
    assert_eq!(
        restored
            .register_stable(&user(1000), user(1000).user, "local-profile-2", vec![])
            .unwrap(),
        other_key
    );
    restored.remove(&first, &user(1000)).unwrap();
    let recreated = restored
        .register_stable(&user(1000), user(1000).user, key, vec![])
        .unwrap();
    assert_ne!(first, recreated);
}

#[test]
fn retries_cannot_change_access_grants_or_claim_foreign_profiles() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [2; 16]);
    let consumers = vec![user(1001).user, user(1002).user];
    let first = catalog
        .register_stable(&user(0), user(1000).user, "key", consumers.clone())
        .unwrap();
    assert_eq!(
        catalog
            .register_stable(
                &user(0),
                user(1000).user,
                "key",
                consumers.into_iter().rev().collect()
            )
            .unwrap(),
        first
    );
    assert!(matches!(
        catalog.register_stable(&user(1000), user(1000).user, "key", vec![]),
        Err(ProfileError::RegistrationConflict)
    ));
    assert!(catalog
        .register_stable(&user(1001), user(1000).user, "key", vec![])
        .is_err());
    assert!(catalog
        .register_stable(&user(1001), user(1001).user, "other", vec![user(1002).user])
        .is_err());
    assert_eq!(catalog.list(&user(0)).unwrap().len(), 1);
}

#[test]
fn registration_keys_are_bounded_and_duplicate_stored_keys_are_rejected() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [3; 16]);
    for key in ["", "a/b", "a\0b", "имя", &"a".repeat(65)] {
        assert!(catalog
            .register_stable(&user(1000), user(1000).user, key, vec![])
            .is_err());
    }
    catalog
        .register_stable(&user(1000), user(1000).user, &"a".repeat(64), vec![])
        .unwrap();
    catalog
        .register_stable(&user(1000), user(1000).user, "other", vec![])
        .unwrap();
    let bytes = catalog.store_metadata().unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["profiles"][1]["registration_key"] = value["profiles"][0]["registration_key"].clone();
    assert!(ProfileCatalog::restore_metadata(
        Platform::Linux,
        &serde_json::to_vec(&value).unwrap()
    )
    .is_err());
    for key in [serde_json::json!(""), serde_json::json!("a/b")] {
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["profiles"][0]["registration_key"] = key;
        assert!(ProfileCatalog::restore_metadata(
            Platform::Linux,
            &serde_json::to_vec(&value).unwrap()
        )
        .is_err());
    }
}

#[test]
fn an_existing_registration_remains_usable_when_the_catalog_is_full() {
    let mut catalog = ProfileCatalog::new(Platform::Linux, [4; 16]);
    let first = catalog
        .register_stable(&user(1000), user(1000).user, "first", vec![])
        .unwrap();
    for _ in 1..256 {
        catalog
            .register(&user(1000), user(1000).user, vec![])
            .unwrap();
    }
    assert!(matches!(
        catalog.register_stable(&user(1000), user(1000).user, "new", vec![]),
        Err(ProfileError::Capacity)
    ));
    assert_eq!(
        catalog
            .register_stable(&user(1000), user(1000).user, "first", vec![])
            .unwrap(),
        first
    );
}
