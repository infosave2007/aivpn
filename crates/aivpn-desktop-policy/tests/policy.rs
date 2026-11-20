use aivpn_desktop_policy::*;
use std::net::IpAddr;

fn document() -> PolicyDocument {
    PolicyDocument {
        split_enabled: true,
        version: 1,
        id: "work".into(),
        generation: 1,
        platform: Platform::Linux,
        owner: Owner::LinuxUser { uid: 1000 },
        default_action: Action::System {},
        dns: DnsPolicy::SharedVpn {
            profile: "personal".into(),
            acknowledge_outage: true,
        },
        rules: vec![RuleDocument {
            id: "browser".into(),
            application: Selector::Executable {
                path: "/usr/bin/browser".into(),
            },
            destination: None,
            inherit_children: true,
            action: Action::Vpn {
                profile: "personal".into(),
            },
        }],
    }
}

fn authority() -> Authority {
    Authority {
        user: Owner::LinuxUser { uid: 1000 },
        machine_admin: false,
    }
}

fn process(path: &str, uid: u32) -> ProcessIdentity {
    ProcessIdentity {
        owner: Owner::LinuxUser { uid },
        canonical_executable: path.into(),
        package_sid: None,
    }
}

fn target() -> IpAddr {
    "203.0.113.8".parse().unwrap()
}

#[test]
fn local_vpn_destinations_stay_local_without_requiring_a_ready_profile() {
    for destination in ["127.0.0.1", "127.99.8.7", "::1", "::ffff:127.0.0.1"] {
        for default in [false, true] {
            let mut document = document();
            if default {
                document.default_action = document.rules.remove(0).action;
            }
            let policy = Policy::validate(document, &authority()).unwrap();
            let decision = policy.decide(
                &process("/usr/bin/browser", 1000),
                destination.parse().unwrap(),
                |_, _| panic!("local traffic must not consult VPN readiness"),
            );
            assert_eq!(decision.effective, Action::System {});
            assert!(matches!(decision.requested, Action::Vpn { .. }));
            assert_eq!(decision.reason, DecisionReason::LocalDestination);
            assert_eq!(decision.rule_id.is_none(), default);
        }
    }
}

#[test]
fn explicit_block_also_blocks_loopback_and_nearby_addresses_are_not_local() {
    let mut blocked = document();
    blocked.rules[0].action = Action::Block {};
    let blocked = Policy::validate(blocked, &authority()).unwrap();
    let vpn = Policy::validate(document(), &authority()).unwrap();
    for destination in ["127.0.0.1", "::1"] {
        let decision = blocked.decide(
            &process("/usr/bin/browser", 1000),
            destination.parse().unwrap(),
            |_, _| true,
        );
        assert_eq!(decision.effective, Action::Block {});
        assert_eq!(decision.reason, DecisionReason::MatchedRule);
    }
    for destination in ["126.255.255.255", "128.0.0.0", "::", "::2", "fe80::1"] {
        let decision = vpn.decide(
            &process("/usr/bin/browser", 1000),
            destination.parse().unwrap(),
            |_, _| false,
        );
        assert_eq!(decision.effective, Action::Block {});
        assert_eq!(decision.reason, DecisionReason::VpnUnavailable);
    }
}

#[test]
fn selected_application_uses_vpn_and_others_keep_system_path() {
    let policy = Policy::validate(document(), &authority()).unwrap();
    let selected = policy.decide(&process("/usr/bin/browser", 1000), target(), |_, _| true);
    assert_eq!(
        selected.effective,
        Action::Vpn {
            profile: "personal".into()
        }
    );
    assert_eq!(selected.rule_id.as_deref(), Some("browser"));
    assert_eq!(
        policy
            .decide(&process("/usr/bin/updater", 1000), target(), |_, _| true)
            .effective,
        Action::System {}
    );
    assert_eq!(
        policy
            .decide(&process("/usr/bin/browser", 1001), target(), |_, _| true)
            .effective,
        Action::System {}
    );
}

#[test]
fn unavailable_profile_blocks_selected_application_without_system_fallback() {
    let policy = Policy::validate(document(), &authority()).unwrap();
    let result = policy.decide(&process("/usr/bin/browser", 1000), target(), |_, _| false);
    assert_eq!(result.effective, Action::Block {});
    assert_eq!(
        result.requested,
        Action::Vpn {
            profile: "personal".into()
        }
    );
    assert_eq!(result.reason, DecisionReason::VpnUnavailable);
    assert_eq!(
        policy
            .decide(&process("/usr/bin/updater", 1000), target(), |_, _| false)
            .effective,
        Action::System {}
    );
}

#[test]
fn all_except_selected_only_applies_to_the_policy_owner() {
    let mut doc = document();
    doc.default_action = Action::Vpn {
        profile: "personal".into(),
    };
    doc.rules[0].action = Action::System {};
    let policy = Policy::validate(doc, &authority()).unwrap();
    assert_eq!(
        policy
            .decide(&process("/usr/bin/browser", 1000), target(), |_, _| true)
            .effective,
        Action::System {}
    );
    assert!(matches!(
        policy
            .decide(&process("/usr/bin/updater", 1000), target(), |_, _| true)
            .effective,
        Action::Vpn { .. }
    ));
    assert_eq!(
        policy
            .decide(&process("/usr/bin/updater", 0), target(), |_, _| true)
            .effective,
        Action::System {}
    );
}

#[test]
fn combined_rules_match_application_and_network_in_explicit_order() {
    let mut doc = document();
    doc.rules[0].destination = Some("10.8.0.0/16".into());
    doc.rules.insert(
        0,
        RuleDocument {
            id: "blocked-lan".into(),
            application: Selector::Any {},
            destination: Some("10.8.1.0/24".into()),
            inherit_children: true,
            action: Action::Block {},
        },
    );
    let policy = Policy::validate(doc, &authority()).unwrap();
    let app = process("/usr/bin/browser", 1000);
    assert_eq!(
        policy
            .decide(&app, "10.8.1.9".parse().unwrap(), |_, _| true)
            .effective,
        Action::Block {}
    );
    assert!(matches!(
        policy
            .decide(&app, "10.8.2.9".parse().unwrap(), |_, _| true)
            .effective,
        Action::Vpn { .. }
    ));
    assert_eq!(
        policy
            .decide(&app, "10.9.2.9".parse().unwrap(), |_, _| true)
            .effective,
        Action::System {}
    );
    assert_eq!(
        policy
            .decide(
                &process("/usr/bin/updater", 1000),
                "10.8.2.9".parse().unwrap(),
                |_, _| true
            )
            .effective,
        Action::System {}
    );
}

#[test]
fn ipv6_rules_do_not_match_ipv4_and_do_match_network_boundaries() {
    let mut doc = document();
    doc.rules[0].destination = Some("2001:db8::/32".into());
    let policy = Policy::validate(doc, &authority()).unwrap();
    let app = process("/usr/bin/browser", 1000);
    for ip in ["2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"] {
        assert!(matches!(
            policy
                .decide(&app, ip.parse().unwrap(), |_, _| true)
                .effective,
            Action::Vpn { .. }
        ));
    }
    for ip in ["2001:db9::", "203.0.113.8"] {
        assert_eq!(
            policy
                .decide(&app, ip.parse().unwrap(), |_, _| true)
                .effective,
            Action::System {}
        );
    }
}

#[test]
fn invalid_networks_and_duplicate_rule_ids_are_rejected() {
    for cidr in [
        "10.8.1.1/24",
        "0.0.0.0/33",
        "::/129",
        "bad",
        "2001:db8::1/32",
    ] {
        let mut doc = document();
        doc.rules[0].destination = Some(cidr.into());
        assert!(
            Policy::validate(doc, &authority()).is_err(),
            "accepted {cidr}"
        );
    }
    let mut doc = document();
    doc.rules.push(doc.rules[0].clone());
    assert!(Policy::validate(doc, &authority()).is_err());
}

#[test]
fn machine_policy_and_another_user_require_verified_authority() {
    let mut doc = document();
    doc.owner = Owner::Machine {};
    assert!(Policy::validate(doc.clone(), &authority()).is_err());
    assert!(Policy::validate(
        doc,
        &Authority {
            machine_admin: true,
            ..authority()
        }
    )
    .is_ok());
    let mut doc = document();
    doc.owner = Owner::LinuxUser { uid: 1001 };
    assert!(Policy::validate(doc, &authority()).is_err());
}

#[test]
fn windows_requires_explicit_acknowledgement_of_shared_dns_outage() {
    let mut doc = document();
    doc.platform = Platform::Windows;
    doc.owner = Owner::WindowsUser {
        sid: "S-1-5-21-1-2-3-1001".into(),
    };
    doc.rules[0].application = Selector::Executable {
        path: r"\device\harddiskvolume3\apps\browser.exe".into(),
    };
    let auth = Authority {
        user: doc.owner.clone(),
        machine_admin: false,
    };
    let mut unsupported = serde_json::to_value(doc.clone()).unwrap();
    unsupported["dns"] = serde_json::json!({"kind": "per_application"});
    assert!(Policy::from_json(&unsupported.to_string(), &auth).is_err());
    doc.dns = DnsPolicy::SharedVpn {
        profile: "personal".into(),
        acknowledge_outage: false,
    };
    assert!(Policy::validate(doc.clone(), &auth).is_err());
    doc.dns = DnsPolicy::SharedVpn {
        profile: "personal".into(),
        acknowledge_outage: true,
    };
    assert!(Policy::validate(doc, &auth).is_ok());
}

#[test]
fn serialized_policies_enforce_version_limits_and_unknown_fields() {
    let json = serde_json::to_string(&document()).unwrap();
    let policy = Policy::from_json(&json, &authority()).unwrap();
    assert_eq!(policy.document().generation, 1);
    let mut value = serde_json::to_value(document()).unwrap();
    value["version"] = 2.into();
    assert!(Policy::from_json(&value.to_string(), &authority()).is_err());
    value["version"] = 1.into();
    value["unexpected"] = true.into();
    assert!(Policy::from_json(&value.to_string(), &authority()).is_err());
    assert!(Policy::from_json(&" ".repeat(128 * 1024 + 1), &authority()).is_err());
}

#[test]
fn ipv4_and_ipv6_zero_and_host_prefixes_are_safe() {
    for (cidr, inside, outside) in [
        ("0.0.0.0/0", "255.255.255.255", "::1"),
        (
            "::/0",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "127.0.0.1",
        ),
        ("203.0.113.8/32", "203.0.113.8", "203.0.113.9"),
        ("2001:db8::1/128", "2001:db8::1", "2001:db8::2"),
    ] {
        let mut doc = document();
        doc.rules[0].destination = Some(cidr.into());
        let policy = Policy::validate(doc, &authority()).unwrap();
        let app = process("/usr/bin/browser", 1000);
        assert!(matches!(
            policy
                .decide(&app, inside.parse().unwrap(), |_, _| true)
                .effective,
            Action::Vpn { .. }
        ));
        assert_eq!(
            policy
                .decide(&app, outside.parse().unwrap(), |_, _| true)
                .effective,
            Action::System {}
        );
    }
}

#[test]
fn rule_limit_generation_and_canonical_paths_are_enforced() {
    let mut doc = document();
    doc.generation = 0;
    assert!(Policy::validate(doc, &authority()).is_err());
    let mut doc = document();
    doc.rules = (0..257)
        .map(|index| RuleDocument {
            id: format!("r{index}"),
            ..document().rules.remove(0)
        })
        .collect();
    assert!(Policy::validate(doc, &authority()).is_err());
    for path in [
        "browser",
        "/usr/../bin/browser",
        "/usr//bin/browser",
        "/usr/bin/browser/",
        "/usr/bin/br\0owser",
    ] {
        let mut doc = document();
        doc.rules[0].application = Selector::Executable { path: path.into() };
        assert!(
            Policy::validate(doc, &authority()).is_err(),
            "accepted {path:?}"
        );
    }
}

#[test]
fn windows_package_rules_use_the_exact_package_identity() {
    let sid = "S-1-5-21-1-2-3-1001";
    let package = "S-1-15-2-10-20-30-40-50-60-70";
    let mut doc = document();
    doc.platform = Platform::Windows;
    doc.owner = Owner::WindowsUser { sid: sid.into() };
    doc.dns = DnsPolicy::SharedVpn {
        profile: "personal".into(),
        acknowledge_outage: true,
    };
    doc.rules[0].application = Selector::WindowsPackage {
        sid: package.into(),
    };
    let auth = Authority {
        user: doc.owner.clone(),
        machine_admin: false,
    };
    let app = ProcessIdentity {
        owner: doc.owner.clone(),
        canonical_executable: String::new(),
        package_sid: Some(package.into()),
    };
    let policy = Policy::validate(doc.clone(), &auth).unwrap();
    assert!(matches!(
        policy.decide(&app, target(), |_, _| true).effective,
        Action::Vpn { .. }
    ));
    let other = ProcessIdentity {
        canonical_executable: "\\device\\harddiskvolume3\\apps\\other.exe".into(),
        package_sid: None,
        ..app
    };
    assert_eq!(
        policy.decide(&other, target(), |_, _| true).effective,
        Action::System {}
    );
    for invalid in ["S-1-15-2-+10", "S-1-15-2-010", "S-1-15-2-4294967296"] {
        doc.rules[0].application = Selector::WindowsPackage {
            sid: invalid.into(),
        };
        assert!(Policy::validate(doc.clone(), &auth).is_err());
    }
}

#[test]
fn unknown_process_identity_never_receives_an_unprotected_default() {
    let policy = Policy::validate(document(), &authority()).unwrap();
    let unknown = process("", 1000);
    let decision = policy.decide(&unknown, target(), |_, _| true);
    assert_eq!(decision.effective, Action::Block {});
    assert_eq!(decision.reason, DecisionReason::UnresolvedIdentity);
}

#[test]
fn missing_vpn_address_family_never_falls_back_to_system() {
    let policy = Policy::validate(document(), &authority()).unwrap();
    let app = process("/usr/bin/browser", 1000);
    let ipv6 = policy.decide(&app, "2001:db8::1".parse().unwrap(), |_, ip| ip.is_ipv4());
    assert_eq!(ipv6.effective, Action::Block {});
    assert_eq!(ipv6.reason, DecisionReason::VpnUnavailable);
    let ipv4 = policy.decide(&app, target(), |_, ip| ip.is_ipv4());
    assert!(matches!(ipv4.effective, Action::Vpn { .. }));
}

#[test]
fn ipv4_mapped_destination_uses_ipv4_policy_and_readiness() {
    let mut doc = document();
    doc.rules[0].destination = Some("203.0.113.0/24".into());
    let policy = Policy::validate(doc, &authority()).unwrap();
    let result = policy.decide(
        &process("/usr/bin/browser", 1000),
        "::ffff:203.0.113.8".parse().unwrap(),
        |_, ip| ip.is_ipv4(),
    );
    assert_eq!(
        result.effective,
        Action::Vpn {
            profile: "personal".into()
        }
    );
    let mut doc = document();
    doc.rules[0].destination = Some("::ffff:203.0.113.0/120".into());
    let policy = Policy::validate(doc, &authority()).unwrap();
    assert!(matches!(
        policy
            .decide(&process("/usr/bin/browser", 1000), target(), |_, ip| ip
                .is_ipv4())
            .effective,
        Action::Vpn { .. }
    ));
}

#[test]
fn child_inherits_parent_rules_but_its_explicit_rule_has_priority() {
    let mut doc = document();
    let mut child_rule = doc.rules[0].clone();
    child_rule.id = "child".into();
    child_rule.application = Selector::Executable {
        path: "/usr/bin/helper".into(),
    };
    child_rule.action = Action::Block {};
    child_rule.destination = Some("10.8.0.0/16".into());
    doc.rules.push(child_rule);
    let policy = Policy::validate(doc, &authority()).unwrap();
    let child = process("/usr/bin/helper", 1000);
    let ancestors = [process("/usr/bin/browser", 1000)];
    assert!(matches!(
        policy
            .decide_with_ancestors(&child, &ancestors, target(), |_, _| true)
            .effective,
        Action::Vpn { .. }
    ));
    assert_eq!(
        policy
            .decide_with_ancestors(&child, &ancestors, "10.8.1.1".parse().unwrap(), |_, _| true)
            .effective,
        Action::Block {}
    );
}

#[test]
fn inheritance_does_not_override_global_rules_or_cross_user_boundaries() {
    let mut doc = document();
    doc.rules.insert(
        0,
        RuleDocument {
            id: "global".into(),
            application: Selector::Any {},
            destination: Some("203.0.113.0/24".into()),
            inherit_children: true,
            action: Action::Block {},
        },
    );
    let policy = Policy::validate(doc, &authority()).unwrap();
    let child = process("/usr/bin/helper", 1000);
    let global = policy.decide_with_ancestors(
        &child,
        &[process("/usr/bin/browser", 1000)],
        target(),
        |_, _| true,
    );
    assert_eq!(global.effective, Action::Block {});
    assert_eq!(global.inherited_depth, None);
    let policy = Policy::validate(document(), &authority()).unwrap();
    assert_eq!(
        policy
            .decide_with_ancestors(
                &child,
                &[process("/usr/bin/browser", 0)],
                target(),
                |_, _| true
            )
            .effective,
        Action::System {}
    );
    let mut doc = document();
    doc.rules[0].inherit_children = false;
    let policy = Policy::validate(doc, &authority()).unwrap();
    assert_eq!(
        policy
            .decide_with_ancestors(
                &child,
                &[process("/usr/bin/browser", 1000)],
                target(),
                |_, _| true
            )
            .effective,
        Action::System {}
    );
}

#[test]
fn omitted_inheritance_flag_keeps_children_protected_and_depth_is_bounded() {
    let mut json = serde_json::to_value(document()).unwrap();
    json["rules"][0]
        .as_object_mut()
        .unwrap()
        .remove("inherit_children");
    let policy = Policy::from_json(&json.to_string(), &authority()).unwrap();
    let child = process("/usr/bin/helper", 1000);
    let parent = process("/usr/bin/browser", 1000);
    let decision =
        policy.decide_with_ancestors(&child, std::slice::from_ref(&parent), target(), |_, _| true);
    assert_eq!(decision.inherited_depth, Some(1));
    assert!(matches!(decision.effective, Action::Vpn { .. }));
    let mut ancestors = vec![process("/usr/bin/helper", 1000); 32];
    ancestors[31] = parent.clone();
    let at_limit = policy.decide_with_ancestors(&child, &ancestors, target(), |_, _| true);
    assert_eq!(at_limit.inherited_depth, Some(32));
    assert!(matches!(at_limit.effective, Action::Vpn { .. }));
    let decision = policy.decide_with_ancestors(&child, &vec![parent; 33], target(), |_, _| true);
    assert_eq!(decision.reason, DecisionReason::UnresolvedAncestry);
    assert_eq!(decision.effective, Action::Block {});
}

#[test]
fn a_global_catch_all_does_not_erase_an_earlier_inherited_rule() {
    let mut doc = document();
    doc.rules.push(RuleDocument {
        id: "catch-all".into(),
        application: Selector::Any {},
        destination: None,
        inherit_children: true,
        action: Action::System {},
    });
    let policy = Policy::validate(doc, &authority()).unwrap();
    let child = process("/usr/bin/helper", 1000);
    let decision = policy.decide_with_ancestors(
        &child,
        &[process("/usr/bin/browser", 1000)],
        target(),
        |_, _| true,
    );
    assert_eq!(decision.rule_id.as_deref(), Some("browser"));
    assert_eq!(decision.inherited_depth, Some(1));
    assert!(matches!(decision.effective, Action::Vpn { .. }));
}

#[test]
fn nearest_matching_parent_precedes_an_earlier_grandparent_rule() {
    let mut doc = document();
    doc.rules.push(RuleDocument {
        id: "launcher".into(),
        application: Selector::Executable {
            path: "/usr/bin/launcher".into(),
        },
        destination: None,
        inherit_children: true,
        action: Action::Block {},
    });
    let policy = Policy::validate(doc, &authority()).unwrap();
    let child = process("/usr/bin/helper", 1000);
    let ancestors = [
        process("/usr/bin/launcher", 1000),
        process("/usr/bin/browser", 1000),
    ];
    let decision = policy.decide_with_ancestors(&child, &ancestors, target(), |_, _| true);
    assert_eq!(decision.rule_id.as_deref(), Some("launcher"));
    assert_eq!(decision.inherited_depth, Some(1));
    assert_eq!(decision.effective, Action::Block {});
}

#[test]
fn unresolved_parent_cannot_remove_inherited_protection() {
    let authority = Authority {
        user: Owner::LinuxUser { uid: 1000 },
        machine_admin: false,
    };
    let policy = Policy::validate(
        PolicyDocument {
            split_enabled: true,
            version: 1,
            id: "parents".into(),
            generation: 1,
            platform: Platform::Linux,
            owner: authority.user.clone(),
            default_action: Action::System {},
            dns: DnsPolicy::SharedVpn {
                profile: "vpn".into(),
                acknowledge_outage: true,
            },
            rules: vec![RuleDocument {
                id: "parent".into(),
                application: Selector::Executable {
                    path: "/usr/bin/protected".into(),
                },
                destination: None,
                inherit_children: true,
                action: Action::Vpn {
                    profile: "vpn".into(),
                },
            }],
        },
        &authority,
    )
    .unwrap();
    let child = ProcessIdentity {
        owner: authority.user.clone(),
        canonical_executable: "/usr/bin/child".into(),
        package_sid: None,
    };
    let unknown = ProcessIdentity {
        owner: authority.user,
        canonical_executable: String::new(),
        package_sid: None,
    };
    let result = policy.decide_with_ancestors(
        &child,
        &[unknown],
        "203.0.113.8".parse().unwrap(),
        |_, _| true,
    );
    assert_eq!(result.effective, Action::Block {});
    assert_eq!(result.reason, DecisionReason::UnresolvedAncestry);
}

#[test]
fn explicit_child_rule_does_not_require_unresolved_parent_identity() {
    let policy = Policy::validate(document(), &authority()).unwrap();
    let result = policy.decide_with_ancestors(
        &process("/usr/bin/browser", 1000),
        &[process("", 1000)],
        target(),
        |_, _| true,
    );
    assert!(matches!(result.effective, Action::Vpn { .. }));
    assert_eq!(result.inherited_depth, None);
}

#[test]
fn unresolved_parents_only_block_relevant_inherited_rules() {
    let mut doc = document();
    doc.rules[0].destination = Some("10.8.0.0/16".into());
    let child = process("/usr/bin/helper", 1000);
    let unknown = process("", 1000);
    let policy = Policy::validate(doc.clone(), &authority()).unwrap();
    let outside =
        policy.decide_with_ancestors(&child, std::slice::from_ref(&unknown), target(), |_, _| {
            true
        });
    assert_eq!(outside.effective, Action::System {});
    let inside = "10.8.1.9".parse().unwrap();
    let blocked =
        policy.decide_with_ancestors(&child, std::slice::from_ref(&unknown), inside, |_, _| true);
    assert_eq!(blocked.effective, Action::Block {});
    doc.rules[0].inherit_children = false;
    let policy = Policy::validate(doc, &authority()).unwrap();
    assert_eq!(
        policy
            .decide_with_ancestors(&child, &[unknown], inside, |_, _| true,)
            .effective,
        Action::System {}
    );
    let policy = Policy::validate(document(), &authority()).unwrap();
    assert_eq!(
        policy
            .decide_with_ancestors(&child, &[process("", 1001)], target(), |_, _| true,)
            .effective,
        Action::System {}
    );
}
