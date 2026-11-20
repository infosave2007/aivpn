use aivpn_desktop_policy::*;

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
        rules: Vec::new(),
    }
}

fn validate(doc: PolicyDocument) -> Result<Policy, PolicyError> {
    let authority = Authority {
        user: doc.owner.clone(),
        machine_admin: false,
    };
    Policy::validate(doc, &authority)
}

fn rule(id: String, path: String) -> RuleDocument {
    RuleDocument {
        id,
        application: Selector::Executable { path },
        destination: None,
        inherit_children: false,
        action: Action::Block {},
    }
}

#[test]
fn parameterless_variants_reject_hidden_owner_route_and_selector_fields() {
    let authority = Authority {
        user: Owner::LinuxUser { uid: 0 },
        machine_admin: true,
    };
    let valid = serde_json::to_value(document()).unwrap();
    let mut invalid = vec![];
    let mut doc = valid.clone();
    doc["owner"] = serde_json::json!({"kind":"machine","uid":1000});
    invalid.push(doc);
    for route in ["system", "block"] {
        let mut doc = valid.clone();
        doc["default_action"] = serde_json::json!({"route":route,"profile":"hidden"});
        invalid.push(doc);
    }
    let mut doc = valid;
    doc["rules"] = serde_json::json!([{"id":"all","application":{"kind":"any","path":"/usr/bin/hidden"},"destination":null,"action":{"route":"system"}}]);
    invalid.push(doc);
    for doc in invalid {
        assert!(
            Policy::from_json(&doc.to_string(), &authority).is_err(),
            "{doc}"
        );
    }
}

#[test]
fn maximum_rules_identifier_and_path_lengths_are_accepted() {
    let mut doc = document();
    doc.id = "a".repeat(64);
    doc.rules = (0..256)
        .map(|index| rule(format!("r{index}"), "/usr/bin/example".into()))
        .collect();
    validate(doc).unwrap();
    let mut doc = document();
    doc.rules
        .push(rule("long".into(), format!("/{}", "a".repeat(4095))));
    validate(doc.clone()).unwrap();
    if let Selector::Executable { path } = &mut doc.rules[0].application {
        path.push('a');
    }
    assert!(validate(doc).is_err());
    for id in ["", ".hidden", "a/b", "имя", "a\0b", &"a".repeat(65)] {
        let mut doc = document();
        doc.id = id.into();
        assert!(validate(doc).is_err(), "accepted ID {id:?}");
    }
    for path in ["", "/usr/bi\0n/example"] {
        let mut doc = document();
        doc.rules.push(rule("bad".into(), path.into()));
        assert!(validate(doc).is_err());
    }
}

#[test]
fn serialized_document_limit_accepts_the_boundary_and_rejects_one_extra_byte() {
    let mut doc = document();
    for index in 0..32 {
        doc.rules
            .push(rule(format!("r{index}"), format!("/{}", "a".repeat(4095))));
    }
    let length = serde_json::to_vec(&doc).unwrap().len();
    assert!(length > 128 * 1024);
    let mut excess = length - 128 * 1024;
    for rule in doc.rules.iter_mut().rev() {
        if let Selector::Executable { path } = &mut rule.application {
            let removed = excess.min(path.len() - 2);
            path.truncate(path.len() - removed);
            excess -= removed;
        }
    }
    assert_eq!(excess, 0);
    assert_eq!(serde_json::to_vec(&doc).unwrap().len(), 128 * 1024);
    validate(doc.clone()).unwrap();
    if let Selector::Executable { path } = &mut doc.rules.last_mut().unwrap().application {
        path.push('a');
    }
    assert!(validate(doc).is_err());

    let text = serde_json::to_string(&document()).unwrap();
    let authority = Authority {
        user: document().owner,
        machine_admin: false,
    };
    let at_limit = format!("{text}{}", " ".repeat(128 * 1024 - text.len()));
    Policy::from_json(&at_limit, &authority).unwrap();
    assert!(Policy::from_json(&(at_limit + " "), &authority).is_err());
}

#[test]
fn malformed_windows_owner_sids_are_rejected_without_panicking() {
    let max_sid = format!("S-1-281474976710655-{}", vec!["4294967295"; 15].join("-"));
    assert_eq!(max_sid.len(), 184);
    let mut doc = document();
    doc.platform = Platform::Windows;
    doc.owner = Owner::WindowsUser { sid: max_sid };
    validate(doc.clone()).unwrap();
    for sid in [
        "",
        "S",
        "S-1",
        "S-1-5",
        "S-2-5-1",
        "X-1-5-1",
        "S-1-281474976710656-1",
        &"x".repeat(185),
    ] {
        doc.owner = Owner::WindowsUser { sid: sid.into() };
        assert!(validate(doc.clone()).is_err(), "accepted SID {sid:?}");
    }
}

#[test]
fn rules_without_inheritance_apply_to_the_executable_itself() {
    let mut doc = document();
    doc.rules
        .push(rule("selected".into(), "/usr/bin/example".into()));
    let process = ProcessIdentity {
        owner: doc.owner.clone(),
        canonical_executable: "/usr/bin/example".into(),
        package_sid: None,
    };
    let policy = validate(doc).unwrap();
    let decision = policy.decide(&process, "203.0.113.1".parse().unwrap(), |_, _| true);
    assert_eq!(decision.effective, Action::Block {});
    assert_eq!(decision.rule_id.as_deref(), Some("selected"));
    assert_eq!(decision.inherited_depth, None);
}

#[test]
fn unknown_identity_does_not_block_unrelated_networks_or_global_rules() {
    let mut doc = document();
    doc.rules
        .push(rule("selected".into(), "/usr/bin/example".into()));
    doc.rules[0].destination = Some("10.0.0.0/8".into());
    let process = ProcessIdentity {
        owner: doc.owner.clone(),
        canonical_executable: String::new(),
        package_sid: None,
    };
    let policy = validate(doc).unwrap();
    assert_eq!(
        policy
            .decide(&process, "203.0.113.1".parse().unwrap(), |_, _| true)
            .effective,
        Action::System {}
    );
    let mut doc = document();
    doc.rules.push(RuleDocument {
        application: Selector::Any {},
        action: Action::System {},
        ..rule("global".into(), "/usr/bin/example".into())
    });
    let policy = validate(doc).unwrap();
    let decision = policy.decide(&process, "203.0.113.1".parse().unwrap(), |_, _| true);
    assert_eq!(decision.rule_id.as_deref(), Some("global"));
    assert_eq!(decision.effective, Action::System {});
}

#[test]
fn matching_any_before_app_rule_does_not_need_unknown_self_or_parent() {
    for action in [
        Action::System {},
        Action::Block {},
        Action::Vpn {
            profile: "personal".into(),
        },
    ] {
        let mut doc = document();
        doc.rules = vec![
            RuleDocument {
                id: "early-any".into(),
                application: Selector::Any {},
                destination: Some("192.0.2.0/24".into()),
                inherit_children: false,
                action: action.clone(),
            },
            RuleDocument {
                inherit_children: true,
                action: Action::Vpn {
                    profile: "personal".into(),
                },
                ..rule("selected".into(), "/usr/bin/example".into())
            },
        ];
        let owner = doc.owner.clone();
        let policy = validate(doc).unwrap();
        let unknown = ProcessIdentity {
            owner,
            canonical_executable: String::new(),
            package_sid: None,
        };
        for inherited in [false, true] {
            let mut process = unknown.clone();
            let ancestors = if inherited {
                process.canonical_executable = "/usr/bin/ordinary".into();
                vec![unknown.clone()]
            } else {
                vec![]
            };
            let decision = policy.decide_with_ancestors(
                &process,
                &ancestors,
                "192.0.2.1".parse().unwrap(),
                |_, _| true,
            );
            assert_eq!(decision.effective, action);
            assert_eq!(decision.rule_id.as_deref(), Some("early-any"));
            let outside = policy.decide_with_ancestors(
                &process,
                &ancestors,
                "198.18.0.53".parse().unwrap(),
                |_, _| true,
            );
            assert_eq!(outside.effective, Action::Block {});
            assert!(matches!(
                outside.reason,
                DecisionReason::UnresolvedIdentity | DecisionReason::UnresolvedAncestry
            ));
        }
    }
}

#[test]
fn self_only_rule_needs_self_identity_but_not_parent_identity() {
    let mut doc = document();
    doc.rules
        .push(rule("self-only".into(), "/usr/bin/example".into()));
    let unknown = ProcessIdentity {
        owner: doc.owner.clone(),
        canonical_executable: String::new(),
        package_sid: None,
    };
    let ordinary = ProcessIdentity {
        canonical_executable: "/usr/bin/ordinary".into(),
        ..unknown.clone()
    };
    let policy = validate(doc).unwrap();
    let destination = "203.0.113.1".parse().unwrap();
    let self_unknown = policy.decide(&unknown, destination, |_, _| true);
    assert_eq!(self_unknown.effective, Action::Block {});
    assert_eq!(self_unknown.reason, DecisionReason::UnresolvedIdentity);
    let parent_unknown =
        policy.decide_with_ancestors(&ordinary, &[unknown], destination, |_, _| true);
    assert_eq!(parent_unknown.effective, Action::System {});
    assert_ne!(parent_unknown.reason, DecisionReason::UnresolvedAncestry);
}
