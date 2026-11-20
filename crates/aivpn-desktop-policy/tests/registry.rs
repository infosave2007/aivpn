use aivpn_desktop_policy::*;

fn draft(uid: u32, generation: u64) -> PolicyDocument {
    PolicyDocument {
        split_enabled: true,
        version: 1,
        id: format!("user-{uid}"),
        generation,
        platform: Platform::Linux,
        owner: Owner::LinuxUser { uid },
        default_action: Action::System {},
        dns: DnsPolicy::SharedVpn {
            profile: "personal".into(),
            acknowledge_outage: true,
        },
        rules: Vec::new(),
    }
}

fn auth(uid: u32) -> Authority {
    Authority {
        user: Owner::LinuxUser { uid },
        machine_admin: false,
    }
}

fn admin() -> Authority {
    Authority {
        machine_admin: true,
        ..auth(0)
    }
}

#[test]
fn persisted_policy_revisions_are_restored_without_replaying_history() {
    let mut registry = PolicyRegistry::new(Platform::Linux);
    for generation in 1..=3 {
        let update = registry
            .prepare(
                draft(1000, generation),
                &auth(1000),
                (generation > 1).then_some(generation - 1),
            )
            .unwrap();
        let prepared = registry.store_metadata_for_policy(&update).unwrap();
        assert_eq!(registry.revision(), generation - 1);
        let preview =
            PolicyRegistry::restore_metadata(Platform::Linux, &prepared, &admin()).unwrap();
        assert_eq!(preview.revision(), generation);
        assert_eq!(
            preview.get(&auth(1000).user).unwrap().document().generation,
            generation
        );
        registry.commit(update).unwrap();
    }
    let bytes = registry.store_metadata().unwrap();
    assert!(PolicyRegistry::restore_metadata(Platform::Linux, &bytes, &auth(1000)).is_err());
    assert!(PolicyRegistry::restore_metadata(Platform::Windows, &bytes, &admin()).is_err());
    let restored = PolicyRegistry::restore_metadata(Platform::Linux, &bytes, &admin()).unwrap();
    assert_eq!(restored.store_metadata().unwrap(), bytes);
    assert!(restored
        .prepare(draft(1000, 4), &auth(1000), Some(3))
        .is_ok());
}

#[test]
fn removing_a_policy_is_authorized_prepared_and_committed_by_revision() {
    let mut registry = PolicyRegistry::new(Platform::Linux);
    let owner = auth(1000).user;
    let initial = registry.prepare(draft(1000, 1), &auth(1000), None).unwrap();
    registry.commit(initial).unwrap();
    let old = registry.get(&owner).unwrap();
    assert!(registry
        .prepare_removal(owner.clone(), &auth(1001), 1)
        .is_err());
    assert!(registry
        .prepare_removal(owner.clone(), &auth(1000), 2)
        .is_err());
    let removal = registry
        .prepare_removal(owner.clone(), &auth(1000), 1)
        .unwrap();
    let bytes = registry.store_metadata_for_removal(&removal).unwrap();
    assert_eq!(registry.revision(), 1);
    assert!(registry.get(&owner).is_some());
    let restored = PolicyRegistry::restore_metadata(Platform::Linux, &bytes, &admin()).unwrap();
    assert_eq!(restored.revision(), 2);
    assert!(restored.get(&owner).is_none());
    registry.commit_removal(removal).unwrap();
    assert!(registry.get(&owner).is_none());
    assert_eq!(registry.revision(), 2);
    assert_eq!(old.document().generation, 1);
    assert!(registry.prepare_removal(owner, &auth(1000), 1).is_err());
}

#[test]
fn a_removed_and_recreated_slot_cannot_accept_a_stale_prepared_update() {
    let mut registry = PolicyRegistry::new(Platform::Linux);
    let delayed_initial = registry.prepare(draft(1000, 1), &auth(1000), None).unwrap();
    let initial = registry.prepare(draft(1000, 1), &auth(1000), None).unwrap();
    registry.commit(initial).unwrap();
    let delayed_update = registry
        .prepare(draft(1000, 2), &auth(1000), Some(1))
        .unwrap();
    let delayed_removal = registry
        .prepare_removal(auth(1000).user, &auth(1000), 1)
        .unwrap();
    let removal = registry
        .prepare_removal(auth(1000).user, &auth(1000), 1)
        .unwrap();
    registry.commit_removal(removal).unwrap();
    assert!(registry
        .store_metadata_for_policy(&delayed_initial)
        .is_err());
    assert!(registry.commit(delayed_initial).is_err());
    let replacement = registry.prepare(draft(1000, 1), &auth(1000), None).unwrap();
    assert_eq!(replacement.revision(), 3);
    registry.commit(replacement).unwrap();
    assert!(registry.store_metadata_for_policy(&delayed_update).is_err());
    assert!(registry.commit(delayed_update).is_err());
    assert!(registry
        .store_metadata_for_removal(&delayed_removal)
        .is_err());
    assert!(registry.commit_removal(delayed_removal).is_err());
    assert_eq!(
        registry
            .get(&auth(1000).user)
            .unwrap()
            .document()
            .generation,
        1
    );
}

#[test]
fn removal_preparations_cannot_cross_registry_instances() {
    let mut first = PolicyRegistry::new(Platform::Linux);
    let mut second = PolicyRegistry::new(Platform::Linux);
    for registry in [&mut first, &mut second] {
        let update = registry.prepare(draft(1000, 1), &auth(1000), None).unwrap();
        registry.commit(update).unwrap();
    }
    let removal = first
        .prepare_removal(auth(1000).user, &auth(1000), 1)
        .unwrap();
    assert!(second.store_metadata_for_removal(&removal).is_err());
    assert!(second.commit_removal(removal).is_err());
    assert!(second.get(&auth(1000).user).is_some());
    let update = first.prepare(draft(1000, 2), &auth(1000), Some(1)).unwrap();
    assert!(second.store_metadata_for_policy(&update).is_err());
}

#[test]
fn restored_metadata_is_validated_instead_of_trusting_its_owner_label() {
    let mut registry = PolicyRegistry::new(Platform::Linux);
    let initial = registry.prepare(draft(1000, 1), &auth(1000), None).unwrap();
    registry.commit(initial).unwrap();
    let raw: serde_json::Value =
        serde_json::from_slice(&registry.store_metadata().unwrap()).unwrap();
    for (field, value) in [
        ("version", serde_json::json!(2)),
        ("platform", serde_json::json!("windows")),
        ("revision", serde_json::json!(0)),
        ("extra", serde_json::json!(true)),
    ] {
        let mut corrupt = raw.clone();
        corrupt[field] = value;
        assert!(
            PolicyRegistry::restore_metadata(
                Platform::Linux,
                &serde_json::to_vec(&corrupt).unwrap(),
                &admin()
            )
            .is_err(),
            "{field}"
        );
    }
    let mut duplicate = raw.clone();
    duplicate["policies"]
        .as_array_mut()
        .unwrap()
        .push(raw["policies"][0].clone());
    assert!(PolicyRegistry::restore_metadata(
        Platform::Linux,
        &serde_json::to_vec(&duplicate).unwrap(),
        &admin()
    )
    .is_err());
    let mut excessive = raw.clone();
    excessive["policies"] = serde_json::json!(vec![raw["policies"][0].clone(); 257]);
    assert!(PolicyRegistry::restore_metadata(
        Platform::Linux,
        &serde_json::to_vec(&excessive).unwrap(),
        &admin()
    )
    .is_err());
    let mut machine = raw.clone();
    machine["revision"] = serde_json::json!(2);
    let mut other = raw["policies"][0].clone();
    other["owner"] = serde_json::json!({"kind":"machine"});
    machine["policies"].as_array_mut().unwrap().push(other);
    assert!(PolicyRegistry::restore_metadata(
        Platform::Linux,
        &serde_json::to_vec(&machine).unwrap(),
        &admin()
    )
    .is_err());
    let mut invalid = raw;
    invalid["policies"][0]["generation"] = serde_json::json!(0);
    assert!(PolicyRegistry::restore_metadata(
        Platform::Linux,
        &serde_json::to_vec(&invalid).unwrap(),
        &admin()
    )
    .is_err());
    let mut exact = registry.store_metadata().unwrap();
    exact.resize(36 * 1024 * 1024, b' ');
    assert!(PolicyRegistry::restore_metadata(Platform::Linux, &exact, &admin()).is_ok());
    let oversized = vec![b' '; 36 * 1024 * 1024 + 1];
    assert!(PolicyRegistry::restore_metadata(Platform::Linux, &oversized, &admin()).is_err());
}

#[test]
fn snapshots_are_canonical_and_revision_overflow_is_rejected() {
    let mut snapshots = Vec::new();
    for order in [[1000, 1001], [1001, 1000]] {
        let mut registry = PolicyRegistry::new(Platform::Linux);
        for uid in order {
            let update = registry.prepare(draft(uid, 1), &auth(uid), None).unwrap();
            registry.commit(update).unwrap();
        }
        snapshots.push(registry.store_metadata().unwrap());
    }
    assert_eq!(snapshots[0], snapshots[1]);
    let mut raw: serde_json::Value = serde_json::from_slice(&snapshots[0]).unwrap();
    raw["revision"] = serde_json::json!(u64::MAX);
    let terminal = PolicyRegistry::restore_metadata(
        Platform::Linux,
        &serde_json::to_vec(&raw).unwrap(),
        &admin(),
    )
    .unwrap();
    assert!(terminal
        .prepare(draft(1000, 2), &auth(1000), Some(1))
        .is_err());
    assert!(terminal
        .prepare_removal(auth(1000).user, &auth(1000), 1)
        .is_err());
    let empty = PolicyRegistry::new(Platform::Linux)
        .store_metadata()
        .unwrap();
    let restored = PolicyRegistry::restore_metadata(Platform::Linux, &empty, &admin()).unwrap();
    assert_eq!(restored.revision(), 0);
    assert_eq!(restored.store_metadata().unwrap(), empty);
}

#[test]
fn update_is_not_visible_until_committed() {
    let mut registry = PolicyRegistry::new(Platform::Linux);
    let update = registry.prepare(draft(1000, 1), &auth(1000), None).unwrap();
    assert!(registry.get(&auth(1000).user).is_none());
    assert_eq!(update.policy().document().generation, 1);
    registry.commit(update).unwrap();
    assert_eq!(
        registry
            .get(&auth(1000).user)
            .unwrap()
            .document()
            .generation,
        1
    );
}

#[test]
fn competing_updates_cannot_overwrite_each_other() {
    let mut registry = PolicyRegistry::new(Platform::Linux);
    let first = registry.prepare(draft(1000, 1), &auth(1000), None).unwrap();
    let second = registry.prepare(draft(1000, 1), &auth(1000), None).unwrap();
    registry.commit(first).unwrap();
    assert!(registry.commit(second).is_err());
    assert!(registry.prepare(draft(1000, 2), &auth(1000), None).is_err());
    assert!(registry
        .prepare(draft(1000, 3), &auth(1000), Some(1))
        .is_err());
    assert!(registry
        .prepare(draft(1000, 2), &auth(1000), Some(1))
        .is_ok());
}

#[test]
fn old_flow_snapshot_keeps_its_policy_generation() {
    let mut registry = PolicyRegistry::new(Platform::Linux);
    let first = registry.prepare(draft(1000, 1), &auth(1000), None).unwrap();
    registry.commit(first).unwrap();
    let old = registry.get(&auth(1000).user).unwrap();
    let mut next = draft(1000, 2);
    next.default_action = Action::Block {};
    let update = registry.prepare(next, &auth(1000), Some(1)).unwrap();
    registry.commit(update).unwrap();
    let new = registry.get(&auth(1000).user).unwrap();
    let app = ProcessIdentity {
        owner: auth(1000).user,
        canonical_executable: "/usr/bin/example".into(),
        package_sid: None,
    };
    let ip = "203.0.113.8".parse().unwrap();
    assert_eq!(
        old.decide(&app, ip, |_, _| false).effective,
        Action::System {}
    );
    assert_eq!(
        new.decide(&app, ip, |_, _| false).effective,
        Action::Block {}
    );
    assert_eq!(old.document().generation, 1);
    assert_eq!(new.document().generation, 2);
}

#[test]
fn machine_and_user_policies_cannot_overlap_implicitly() {
    let mut registry = PolicyRegistry::new(Platform::Linux);
    let mut machine = draft(1000, 1);
    machine.owner = Owner::Machine {};
    let admin = Authority {
        machine_admin: true,
        ..auth(1000)
    };
    let machine_update = registry.prepare(machine, &admin, None).unwrap();
    let user_update = registry.prepare(draft(1000, 1), &auth(1000), None).unwrap();
    registry.commit(user_update).unwrap();
    assert!(registry.commit(machine_update).is_err());
}

#[test]
fn registry_rejects_wrong_platform_and_unexpected_initial_generation() {
    let registry = PolicyRegistry::new(Platform::Windows);
    assert!(registry.prepare(draft(1000, 1), &auth(1000), None).is_err());
    let registry = PolicyRegistry::new(Platform::Linux);
    assert!(registry.prepare(draft(1000, 2), &auth(1000), None).is_err());
}

#[test]
fn capacity_is_rechecked_after_preparation() {
    let mut registry = PolicyRegistry::new(Platform::Linux);
    for uid in 1..256 {
        let update = registry.prepare(draft(uid, 1), &auth(uid), None).unwrap();
        registry.commit(update).unwrap();
    }
    let first = registry.prepare(draft(256, 1), &auth(256), None).unwrap();
    let second = registry.prepare(draft(257, 1), &auth(257), None).unwrap();
    registry.commit(first).unwrap();
    assert!(registry.commit(second).is_err());
    assert!(registry.prepare(draft(257, 1), &auth(257), None).is_err());
    let metadata = registry.store_metadata().unwrap();
    let restored = PolicyRegistry::restore_metadata(Platform::Linux, &metadata, &admin()).unwrap();
    assert!(restored.get(&auth(256).user).is_some());
    assert_eq!(restored.store_metadata().unwrap(), metadata);
}

#[test]
fn prepared_update_cannot_be_committed_to_another_registry() {
    let first = PolicyRegistry::new(Platform::Linux);
    let mut second = PolicyRegistry::new(Platform::Linux);
    let update = first.prepare(draft(1000, 1), &auth(1000), None).unwrap();
    assert!(second.commit(update).is_err());
    assert!(second.get(&auth(1000).user).is_none());
}

#[test]
fn conflicting_shared_dns_profiles_are_rejected() {
    let mut registry = PolicyRegistry::new(Platform::Linux);
    let first = registry.prepare(draft(1000, 1), &auth(1000), None).unwrap();
    let mut second = draft(1001, 1);
    second.dns = DnsPolicy::SharedVpn {
        profile: "different-dns".into(),
        acknowledge_outage: true,
    };
    let pending = registry.prepare(second.clone(), &auth(1001), None).unwrap();
    registry.commit(first).unwrap();
    assert!(registry.commit(pending).is_err());
    assert!(registry.prepare(second, &auth(1001), None).is_err());
    assert!(registry.get(&auth(1001).user).is_none());
}
