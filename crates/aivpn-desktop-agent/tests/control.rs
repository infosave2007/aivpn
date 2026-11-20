use aivpn_desktop_agent::control::*;
use aivpn_desktop_agent::protocol::*;
use aivpn_desktop_agent::state::StateFile;
use aivpn_desktop_policy::*;
use std::cell::RefCell;
use std::io;
use std::num::NonZeroU64;
use std::rc::Rc;

#[derive(Default)]
struct Records {
    committed: Option<Vec<u8>>,
    pending: Option<Vec<u8>>,
    dns: Option<Vec<u8>>,
    fault: Option<&'static str>,
    events: Vec<String>,
}

#[derive(Clone, Default)]
struct Store(Rc<RefCell<Records>>);

fn key() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!("local-profile-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

#[test]
fn machine_decommission_is_authorized_durable_and_terminal_for_all_users() {
    let store = Store::default();
    let mut service = open(store.clone(), true);
    let reply = call(
        &mut service,
        0,
        Command::RegisterProfile {
            owner: user(1000).user,
            registration_key: key(),
            consumers: vec![user(1001).user],
        },
    );
    let profile = match reply.into_result() {
        Outcome::Ok {
            reply: Reply::Registered { profile },
        } => profile,
        other => panic!("{other:?}"),
    };
    assert!(matches!(
        call(
            &mut service,
            0,
            Command::SetGlobalDns {
                profile: profile.clone(),
                acknowledge_outage: true,
            }
        )
        .result(),
        Outcome::Ok { .. }
    ));
    for uid in [1000, 1001] {
        assert!(matches!(
            call(
                &mut service,
                uid,
                Command::ApplyPolicy {
                    document: policy(uid, &profile),
                    expected_generation: None,
                }
            )
            .result(),
            Outcome::Ok { .. }
        ));
    }
    let decommission = || {
        Request::from_json(br#"{"version":1,"id":1,"command":{"method":"decommission"}}"#).unwrap()
    };
    let before = store.0.borrow().committed.clone();
    assert!(
        !serde_json::from_slice::<serde_json::Value>(before.as_ref().unwrap())
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("decommissioned")
    );
    let serial = service.state().serial();
    store.0.borrow_mut().events.clear();
    expect_error(
        service.handle(&user(1000), decommission()),
        ErrorCode::AccessDenied,
    );
    assert_eq!(service.state().serial(), serial);
    assert_eq!(store.0.borrow().committed, before);
    assert!(store.0.borrow().events.is_empty());
    assert!(matches!(
        service.handle(&user(0), decommission()).result(),
        Outcome::Ok {
            reply: Reply::Done {}
        }
    ));
    assert!(service.state().policies().policies().next().is_none());
    assert!(service
        .state()
        .profiles()
        .list(&user(0))
        .unwrap()
        .is_empty());
    assert_eq!(service.state().profiles().global_dns_profile(), None);
    let serial = service.state().serial();
    store.0.borrow_mut().events.clear();
    assert!(matches!(
        service.handle(&user(0), decommission()).result(),
        Outcome::Ok { .. }
    ));
    assert_eq!(service.state().serial(), serial);
    assert!(store.0.borrow().events.is_empty());
    drop(service);
    let mut service = open(store.clone(), true);
    let forbidden = Command::RegisterProfile {
        owner: user(1001).user,
        registration_key: key(),
        consumers: vec![],
    };
    expect_error(call(&mut service, 1001, forbidden), ErrorCode::Conflict);
    let committed = store.0.borrow().committed.clone().unwrap();
    let value: serde_json::Value = serde_json::from_slice(&committed).unwrap();
    assert_eq!(value["decommissioned"], true);
}

#[test]
fn decommission_cannot_skip_a_live_session_or_claim_success_after_a_storage_fault() {
    let decommission = || {
        Request::from_json(br#"{"version":1,"id":1,"command":{"method":"decommission"}}"#).unwrap()
    };
    let store = Store::default();
    let mut service = open(store.clone(), true);
    let profile = registered(&mut service, 1000);
    let lease = service
        .begin_profile_session(&profile, &user(1000))
        .unwrap();
    let serial = service.state().serial();
    expect_error(
        service.handle(&user(0), decommission()),
        ErrorCode::Conflict,
    );
    assert_eq!(service.state().serial(), serial);
    service.disconnect_profile_session(&lease).unwrap();
    store.0.borrow_mut().fault = Some("committed");
    expect_error(service.handle(&user(0), decommission()), ErrorCode::Storage);
    assert!(store
        .0
        .borrow()
        .events
        .last()
        .is_some_and(|event| event == "block"));
    drop(service);
    store.0.borrow_mut().fault = None;
    let mut recovered = open(store.clone(), true);
    assert!(matches!(
        recovered.handle(&user(0), decommission()).result(),
        Outcome::Ok { .. }
    ));
    assert!(recovered
        .state()
        .profiles()
        .list(&user(0))
        .unwrap()
        .is_empty());
}

#[test]
fn decommission_marker_cannot_hide_remaining_profiles() {
    let store = Store::default();
    let mut service = open(store.clone(), true);
    registered(&mut service, 1000);
    drop(service);
    let mut value: serde_json::Value =
        serde_json::from_slice(store.0.borrow().committed.as_ref().unwrap()).unwrap();
    value["decommissioned"] = serde_json::json!(true);
    store.0.borrow_mut().committed = Some(serde_json::to_vec(&value).unwrap());
    store.0.borrow_mut().events.clear();
    assert!(Control::open(
        Platform::Linux,
        [2; 16],
        store.clone(),
        Backend {
            records: store.clone(),
            fail: Rc::default(),
            supported: true,
        }
    )
    .is_err());
    assert_eq!(store.0.borrow().events, ["block"]);
}

#[test]
fn retrying_registration_does_not_create_another_profile_or_reinstall_the_backend() {
    let store = Store::default();
    let mut service = open(store.clone(), true);
    let request = || {
        Request::new(
            NonZeroU64::MIN,
            Command::RegisterProfile {
                owner: user(1000).user,
                registration_key: "profile-with-lost-reply".into(),
                consumers: vec![],
            },
        )
    };
    let first = service.handle(&user(1000), request()).to_json().unwrap();
    let serial = service.state().serial();
    store.0.borrow_mut().events.clear();
    let second = service.handle(&user(1000), request()).to_json().unwrap();
    assert_eq!(first, second);
    assert_eq!(service.state().serial(), serial);
    assert!(store.0.borrow().events.is_empty());
    drop(service);
    let mut service = open(store.clone(), true);
    store.0.borrow_mut().events.clear();
    assert_eq!(
        service.handle(&user(1000), request()).to_json().unwrap(),
        first
    );
    assert!(store.0.borrow().events.is_empty());
    assert_eq!(
        service.state().profiles().list(&user(1000)).unwrap().len(),
        1
    );
}

#[test]
fn dns_without_application_rules_still_requires_a_guard_when_backend_support_is_lost() {
    let store = Store::default();
    let mut service = open(store.clone(), true);
    let profile = registered(&mut service, 1000);
    call(
        &mut service,
        0,
        Command::SetGlobalDns {
            profile,
            acknowledge_outage: true,
        },
    );
    drop(service);
    store.0.borrow_mut().events.clear();
    let service = open(store.clone(), false);
    assert_eq!(service.backend_state(), BackendState::Recovering);
    assert_eq!(store.0.borrow().events, ["block"]);
}

#[test]
fn only_referenced_profiles_are_protected_against_deletion() {
    let store = Store::default();
    let mut service = open(store, true);
    let dns = registered(&mut service, 1000);
    let traffic = registered(&mut service, 1000);
    let unused = registered(&mut service, 1000);
    call(
        &mut service,
        0,
        Command::SetGlobalDns {
            profile: dns.clone(),
            acknowledge_outage: true,
        },
    );
    let mut document = policy(1000, &dns);
    document.default_action = Action::Vpn {
        profile: traffic.clone(),
    };
    let response = call(
        &mut service,
        1000,
        Command::ApplyPolicy {
            document: document.clone(),
            expected_generation: None,
        },
    );
    assert!(matches!(response.result(), Outcome::Ok { .. }));
    expect_error(
        call(
            &mut service,
            1000,
            Command::DeleteProfile {
                profile: traffic.clone(),
            },
        ),
        ErrorCode::Conflict,
    );
    assert!(matches!(
        call(
            &mut service,
            1000,
            Command::DeleteProfile { profile: unused }
        )
        .result(),
        Outcome::Ok { .. }
    ));
    document.generation = 2;
    document.default_action = Action::System {};
    document.rules.push(RuleDocument {
        id: "all".into(),
        application: Selector::Any {},
        destination: None,
        inherit_children: true,
        action: Action::Vpn {
            profile: traffic.clone(),
        },
    });
    let response = call(
        &mut service,
        1000,
        Command::ApplyPolicy {
            document,
            expected_generation: Some(1),
        },
    );
    assert!(matches!(response.result(), Outcome::Ok { .. }));
    expect_error(
        call(
            &mut service,
            1000,
            Command::DeleteProfile {
                profile: traffic.clone(),
            },
        ),
        ErrorCode::Conflict,
    );
    call(
        &mut service,
        1000,
        Command::RemovePolicy {
            owner: user(1000).user,
            expected_generation: 2,
        },
    );
    assert!(matches!(
        call(
            &mut service,
            1000,
            Command::DeleteProfile { profile: traffic }
        )
        .result(),
        Outcome::Ok { .. }
    ));
}

#[test]
fn exact_snapshot_limit_is_readable_and_one_extra_byte_is_rejected() {
    let store = Store::default();
    let mut service = open(store.clone(), true);
    registered(&mut service, 1000);
    drop(service);
    store
        .0
        .borrow_mut()
        .committed
        .as_mut()
        .unwrap()
        .resize(aivpn_desktop_agent::state::MAX_STATE_BYTES, b' ');
    let service = open(store.clone(), true);
    assert_eq!(
        service.state().profiles().list(&user(1000)).unwrap().len(),
        1
    );
    drop(service);
    store.0.borrow_mut().committed.as_mut().unwrap().push(b' ');
    let backend = Backend {
        records: store.clone(),
        fail: Rc::default(),
        supported: true,
    };
    assert!(Control::open(Platform::Linux, [2; 16], store, backend).is_err());
}

impl ControlStore for Store {
    fn load(&self, file: StateFile) -> io::Result<Option<Vec<u8>>> {
        let state = self.0.borrow();
        Ok(match file {
            StateFile::Committed => &state.committed,
            StateFile::Pending => &state.pending,
            StateFile::DnsJournal => &state.dns,
        }
        .clone())
    }
    fn replace(&mut self, file: StateFile, bytes: &[u8]) -> io::Result<()> {
        let mut state = self.0.borrow_mut();
        let name = match file {
            StateFile::Committed => "committed",
            StateFile::Pending => "pending",
            StateFile::DnsJournal => "dns",
        };
        state.events.push(name.into());
        if state.fault == Some("before_pending") && name == "pending" {
            return Err(io::Error::other("fault before write"));
        }
        match file {
            StateFile::Committed => state.committed = Some(bytes.into()),
            StateFile::Pending => state.pending = Some(bytes.into()),
            StateFile::DnsJournal => state.dns = Some(bytes.into()),
        }
        if state.fault == Some(name) {
            return Err(io::Error::other("fault after rename"));
        }
        Ok(())
    }
    fn clear_pending(&mut self) -> io::Result<()> {
        let mut state = self.0.borrow_mut();
        state.events.push("clear".into());
        if state.fault == Some("clear") {
            return Err(io::Error::other("clear fault"));
        }
        state.pending = None;
        Ok(())
    }
}

#[test]
fn failure_before_the_journal_write_cannot_create_a_profile_on_restart() {
    let store = Store::default();
    let mut service = open(store.clone(), true);
    let original = registered(&mut service, 1000);
    store.0.borrow_mut().fault = Some("before_pending");
    expect_error(
        call(
            &mut service,
            1000,
            Command::RegisterProfile {
                registration_key: key(),
                owner: user(1000).user,
                consumers: vec![],
            },
        ),
        ErrorCode::Storage,
    );
    drop(service);
    store.0.borrow_mut().fault = None;
    let service = open(store, true);
    let profiles = service.state().profiles().list(&user(1000)).unwrap();
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].id, original);
}

#[test]
fn recovery_refuses_metadata_conflicts_and_invalid_catalog_policy_links() {
    let store = Store::default();
    let mut service = open(store.clone(), true);
    let profile = registered(&mut service, 1000);
    call(
        &mut service,
        0,
        Command::SetGlobalDns {
            profile: profile.clone(),
            acknowledge_outage: true,
        },
    );
    call(
        &mut service,
        1000,
        Command::ApplyPolicy {
            document: policy(1000, &profile),
            expected_generation: None,
        },
    );
    let valid: serde_json::Value =
        serde_json::from_slice(store.0.borrow().committed.as_ref().unwrap()).unwrap();
    drop(service);
    let mut invalid = vec![];
    for (field, value) in [
        ("version", serde_json::json!(2)),
        ("platform", serde_json::json!("windows")),
        ("serial", serde_json::json!(0)),
    ] {
        let mut snapshot = valid.clone();
        snapshot[field] = value;
        invalid.push(snapshot);
    }
    let mut snapshot = valid.clone();
    snapshot["profiles"]["global_dns"] = serde_json::Value::Null;
    invalid.push(snapshot);
    let mut snapshot = valid.clone();
    snapshot["profiles"]["profiles"][0]["owner"] =
        serde_json::json!({"kind":"linux_user","uid":1001});
    invalid.push(snapshot);
    let mut snapshot = valid.clone();
    snapshot["profiles"]["profiles"][0]["assignment_generation"] = serde_json::json!(1);
    invalid.push(snapshot);
    let mut snapshot = valid.clone();
    snapshot["policies"]["version"] = serde_json::json!(2);
    invalid.push(snapshot);
    for snapshot in invalid {
        let store = Store::default();
        store.0.borrow_mut().committed = Some(serde_json::to_vec(&snapshot).unwrap());
        let backend = Backend {
            records: store.clone(),
            fail: Rc::default(),
            supported: true,
        };
        assert!(
            Control::open(Platform::Linux, [2; 16], store.clone(), backend).is_err(),
            "{snapshot}"
        );
        assert_eq!(store.0.borrow().events, ["block"]);
    }
    let mut changed = valid.clone();
    changed["profiles"]["profiles"][0]["consumers"] =
        serde_json::json!([{"kind":"linux_user","uid":1001}]);
    let encoded = serde_json::to_string(&valid).unwrap();
    let other_namespace: serde_json::Value =
        serde_json::from_str(&encoded.replace(&"02".repeat(16), &"03".repeat(16))).unwrap();
    for (committed, pending) in [
        (None, valid.clone()),
        (Some(valid.clone()), changed),
        (Some(valid.clone()), other_namespace),
    ] {
        let store = Store::default();
        store.0.borrow_mut().committed = committed.map(|value| serde_json::to_vec(&value).unwrap());
        store.0.borrow_mut().pending = Some(serde_json::to_vec(&pending).unwrap());
        let backend = Backend {
            records: store.clone(),
            fail: Rc::default(),
            supported: true,
        };
        assert!(Control::open(Platform::Linux, [2; 16], store, backend).is_err());
    }
}

#[test]
fn missing_backend_retains_pending_intent_and_startup_failure_is_visible() {
    let store = Store::default();
    let mut service = open(store.clone(), true);
    registered(&mut service, 1000);
    let committed = store.0.borrow().committed.clone();
    store.0.borrow_mut().pending = committed;
    drop(service);
    let mut service = open(store.clone(), false);
    assert_eq!(service.backend_state(), BackendState::Recovering);
    expect_error(
        call(
            &mut service,
            1000,
            Command::DeleteProfile {
                profile: "missing".into(),
            },
        ),
        ErrorCode::RecoveryRequired,
    );
    assert!(store.0.borrow().pending.is_some());
    drop(service);
    let backend = Backend {
        records: store.clone(),
        fail: Rc::new(RefCell::new(true)),
        supported: true,
    };
    let service = Control::open(Platform::Linux, [2; 16], store.clone(), backend).unwrap();
    assert_eq!(service.backend_state(), BackendState::Recovering);
    assert!(store.0.borrow().pending.is_some());
}

#[test]
fn windows_metadata_recovery_keeps_sid_ownership_and_policy_revision() {
    let store = Store::default();
    let backend = Backend {
        records: store.clone(),
        fail: Rc::default(),
        supported: true,
    };
    let mut service = Control::open(Platform::Windows, [3; 16], store.clone(), backend).unwrap();
    let user = Authority {
        user: Owner::WindowsUser {
            sid: "S-1-5-21-1000".into(),
        },
        machine_admin: false,
    };
    let admin = Authority {
        user: Owner::WindowsUser {
            sid: "S-1-5-18".into(),
        },
        machine_admin: true,
    };
    let response = service.handle(
        &user,
        Request::new(
            NonZeroU64::MIN,
            Command::RegisterProfile {
                registration_key: key(),
                owner: user.user.clone(),
                consumers: vec![],
            },
        ),
    );
    let profile = match response.result() {
        Outcome::Ok {
            reply: Reply::Registered { profile },
        } => profile.clone(),
        other => panic!("{other:?}"),
    };
    let response = service.handle(
        &admin,
        Request::new(
            NonZeroU64::MIN,
            Command::SetGlobalDns {
                profile: profile.clone(),
                acknowledge_outage: true,
            },
        ),
    );
    assert!(matches!(response.result(), Outcome::Ok { .. }));
    let mut document = policy(1000, &profile);
    document.platform = Platform::Windows;
    document.owner = user.user.clone();
    let response = service.handle(
        &user,
        Request::new(
            NonZeroU64::MIN,
            Command::ApplyPolicy {
                document,
                expected_generation: None,
            },
        ),
    );
    assert!(matches!(
        response.result(),
        Outcome::Ok {
            reply: Reply::Applied { revision: 1 }
        }
    ));
    drop(service);
    let backend = Backend {
        records: store.clone(),
        fail: Rc::default(),
        supported: true,
    };
    let service = Control::open(Platform::Windows, [3; 16], store, backend).unwrap();
    assert_eq!(
        service.state().profiles().list(&user).unwrap()[0].owner,
        user.user
    );
    assert_eq!(
        service
            .state()
            .policies()
            .get(&user.user)
            .unwrap()
            .document()
            .generation,
        1
    );
}

#[derive(Clone)]
struct Backend {
    records: Store,
    fail: Rc<RefCell<bool>>,
    supported: bool,
}

impl<S: aivpn_desktop_agent::control::ControlStore> RoutingBackend<S> for Backend {
    fn installed_state(&self) -> aivpn_desktop_agent::control::InstalledState {
        aivpn_desktop_agent::control::InstalledState::Active
    }
    fn supported(&self) -> bool {
        self.supported
    }
    fn install(
        &mut self,
        _store: &mut S,
        desired: &ControlState,
        _live_profiles: &ProfileCatalog,
    ) -> io::Result<()> {
        self.records
            .0
            .borrow_mut()
            .events
            .push(format!("install:{}", desired.serial()));
        if *self.fail.borrow() {
            return Err(io::Error::other("backend fault"));
        }
        Ok(())
    }
    fn block(&mut self) -> io::Result<()> {
        self.records.0.borrow_mut().events.push("block".into());
        if self.records.0.borrow().fault == Some("block") {
            return Err(io::Error::other("block fault"));
        }
        Ok(())
    }
}

#[test]
fn failed_guard_is_reported_as_unverified_and_cannot_accept_more_changes() {
    let store = Store::default();
    let fail = Rc::new(RefCell::new(false));
    let backend = Backend {
        records: store.clone(),
        fail: fail.clone(),
        supported: true,
    };
    let mut service = Control::open(Platform::Linux, [2; 16], store.clone(), backend).unwrap();
    *fail.borrow_mut() = true;
    store.0.borrow_mut().fault = Some("block");
    expect_error(
        call(
            &mut service,
            1000,
            Command::RegisterProfile {
                registration_key: key(),
                owner: user(1000).user,
                consumers: vec![],
            },
        ),
        ErrorCode::BackendUnavailable,
    );
    assert_eq!(service.backend_state(), BackendState::ProtectionUnverified);
    expect_error(
        call(
            &mut service,
            1000,
            Command::RegisterProfile {
                registration_key: key(),
                owner: user(1000).user,
                consumers: vec![],
            },
        ),
        ErrorCode::RecoveryRequired,
    );
    assert!(matches!(
        call(&mut service, 1000, Command::Status {}).result(),
        Outcome::Ok {
            reply: Reply::Status {
                backend: BackendState::ProtectionUnverified,
                ..
            }
        }
    ));
    drop(service);
    store.0.borrow_mut().committed = Some(b"garbage".to_vec());
    let backend = Backend {
        records: store.clone(),
        fail,
        supported: true,
    };
    let error = Control::open(Platform::Linux, [2; 16], store, backend)
        .err()
        .unwrap();
    assert!(error.to_string().contains("не подтверждена"));
}

#[test]
fn read_and_validate_leave_both_journal_and_live_policy_unchanged() {
    let store = Store::default();
    let mut service = open(store.clone(), true);
    let profile = registered(&mut service, 1000);
    call(
        &mut service,
        0,
        Command::SetGlobalDns {
            profile: profile.clone(),
            acknowledge_outage: true,
        },
    );
    store.0.borrow_mut().events.clear();
    assert!(matches!(
        call(
            &mut service,
            1000,
            Command::ValidatePolicy {
                document: policy(1000, &profile),
                expected_generation: None
            }
        )
        .result(),
        Outcome::Ok {
            reply: Reply::Validated { revision: 1 }
        }
    ));
    assert!(matches!(
        call(
            &mut service,
            1000,
            Command::GetPolicy {
                owner: user(1000).user
            }
        )
        .result(),
        Outcome::Ok {
            reply: Reply::Policy { document: None }
        }
    ));
    assert!(
        matches!(call(&mut service, 1000, Command::ListProfiles {}).result(), Outcome::Ok { reply: Reply::Profiles { profiles } } if profiles.len() == 1)
    );
    expect_error(
        call(
            &mut service,
            1000,
            Command::RegisterProfile {
                registration_key: key(),
                owner: user(1001).user,
                consumers: vec![],
            },
        ),
        ErrorCode::AccessDenied,
    );
    assert_eq!(service.state().policies().revision(), 0);
    assert_eq!(service.state().serial(), 2);
    assert!(store.0.borrow().events.is_empty());
    let wrong = Authority {
        user: Owner::WindowsUser {
            sid: "S-1-5-18".into(),
        },
        machine_admin: true,
    };
    let response = service.handle(&wrong, Request::new(NonZeroU64::MIN, Command::Status {}));
    assert!(matches!(
        response.result(),
        Outcome::Error {
            code: ErrorCode::InvalidRequest
        }
    ));
}

#[test]
fn policy_compare_and_swap_and_profile_acl_are_checked_before_kernel_changes() {
    let store = Store::default();
    let mut service = open(store.clone(), true);
    let profile = registered(&mut service, 1000);
    call(
        &mut service,
        0,
        Command::SetGlobalDns {
            profile: profile.clone(),
            acknowledge_outage: true,
        },
    );
    call(
        &mut service,
        1000,
        Command::ApplyPolicy {
            document: policy(1000, &profile),
            expected_generation: None,
        },
    );
    store.0.borrow_mut().events.clear();
    expect_error(
        call(
            &mut service,
            1000,
            Command::ApplyPolicy {
                document: policy(1000, &profile),
                expected_generation: None,
            },
        ),
        ErrorCode::Conflict,
    );
    expect_error(
        call(
            &mut service,
            1001,
            Command::ApplyPolicy {
                document: policy(1001, &profile),
                expected_generation: None,
            },
        ),
        ErrorCode::AccessDenied,
    );
    expect_error(
        call(
            &mut service,
            1000,
            Command::RemovePolicy {
                owner: user(1000).user,
                expected_generation: 2,
            },
        ),
        ErrorCode::Conflict,
    );
    assert!(store.0.borrow().events.is_empty());
    let mut next = policy(1000, &profile);
    next.generation = 2;
    assert!(matches!(
        call(
            &mut service,
            1000,
            Command::ApplyPolicy {
                document: next,
                expected_generation: Some(1)
            }
        )
        .result(),
        Outcome::Ok {
            reply: Reply::Applied { revision: 2 }
        }
    ));
    let response = call(
        &mut service,
        1000,
        Command::GetPolicy {
            owner: user(1000).user,
        },
    );
    assert!(
        matches!(response.result(), Outcome::Ok { reply: Reply::Policy { document: Some(document) } } if document.generation == 2)
    );
}

#[test]
fn shared_consumers_can_see_the_profile_without_deleting_it() {
    let store = Store::default();
    let mut service = open(store, true);
    let response = call(
        &mut service,
        0,
        Command::RegisterProfile {
            registration_key: key(),
            owner: user(1000).user,
            consumers: vec![user(1001).user],
        },
    );
    let profile = match response.result() {
        Outcome::Ok {
            reply: Reply::Registered { profile },
        } => profile.clone(),
        other => panic!("{other:?}"),
    };
    expect_error(
        call(
            &mut service,
            1001,
            Command::DeleteProfile {
                profile: profile.clone(),
            },
        ),
        ErrorCode::AccessDenied,
    );
    assert!(matches!(
        call(&mut service, 1000, Command::DeleteProfile { profile }).result(),
        Outcome::Ok {
            reply: Reply::Done {}
        }
    ));
}

fn user(uid: u32) -> Authority {
    Authority {
        user: Owner::LinuxUser { uid },
        machine_admin: uid == 0,
    }
}

fn open(store: Store, supported: bool) -> Control<Store, Backend> {
    let backend = Backend {
        records: store.clone(),
        fail: Rc::default(),
        supported,
    };
    Control::open(Platform::Linux, [2; 16], store, backend).unwrap()
}

fn call(service: &mut Control<Store, Backend>, uid: u32, command: Command) -> Response {
    service.handle(&user(uid), Request::new(NonZeroU64::MIN, command))
}

fn registered(service: &mut Control<Store, Backend>, uid: u32) -> String {
    match call(
        service,
        uid,
        Command::RegisterProfile {
            registration_key: key(),
            owner: user(uid).user,
            consumers: vec![],
        },
    )
    .result()
    {
        Outcome::Ok {
            reply: Reply::Registered { profile },
        } => profile.clone(),
        other => panic!("{other:?}"),
    }
}

fn policy(uid: u32, profile: &str) -> PolicyDocument {
    PolicyDocument {
        split_enabled: true,
        version: 1,
        id: "apps".into(),
        generation: 1,
        platform: Platform::Linux,
        owner: user(uid).user,
        default_action: Action::Vpn {
            profile: profile.into(),
        },
        dns: DnsPolicy::SharedVpn {
            profile: profile.into(),
            acknowledge_outage: true,
        },
        rules: vec![],
    }
}

fn expect_error(response: Response, expected: ErrorCode) {
    assert!(
        matches!(response.result(), Outcome::Error { code } if *code == expected),
        "{response:?}"
    );
}

#[test]
fn profile_and_policy_transaction_survive_restart_with_no_ready_vpn() {
    let store = Store::default();
    let mut service = open(store.clone(), true);
    let profile = registered(&mut service, 1000);
    expect_error(
        call(
            &mut service,
            1000,
            Command::SetGlobalDns {
                profile: profile.clone(),
                acknowledge_outage: true,
            },
        ),
        ErrorCode::AccessDenied,
    );
    assert!(matches!(
        call(
            &mut service,
            0,
            Command::SetGlobalDns {
                profile: profile.clone(),
                acknowledge_outage: true
            }
        )
        .result(),
        Outcome::Ok { .. }
    ));
    let response = call(
        &mut service,
        1000,
        Command::ApplyPolicy {
            document: policy(1000, &profile),
            expected_generation: None,
        },
    );
    assert!(matches!(
        response.result(),
        Outcome::Ok {
            reply: Reply::Applied { revision: 1 }
        }
    ));
    assert_eq!(service.state().serial(), 3);
    assert!(store.0.borrow().pending.is_none());
    drop(service);
    let mut service = open(store, true);
    assert_eq!(service.state().policies().revision(), 1);
    let profiles = service.state().profiles().list(&user(1000)).unwrap();
    assert_eq!(profiles[0].id, profile);
    assert!(!profiles[0].session_active && !profiles[0].ready_ipv4 && !profiles[0].ready_ipv6);
    expect_error(
        call(&mut service, 1000, Command::DeleteProfile { profile }),
        ErrorCode::Conflict,
    );
    expect_error(
        call(&mut service, 0, Command::ClearGlobalDns {}),
        ErrorCode::Conflict,
    );
    assert!(matches!(
        call(
            &mut service,
            1000,
            Command::RemovePolicy {
                owner: user(1000).user,
                expected_generation: 1
            }
        )
        .result(),
        Outcome::Ok { .. }
    ));
    assert!(matches!(
        call(&mut service, 0, Command::ClearGlobalDns {}).result(),
        Outcome::Ok { .. }
    ));
}

#[test]
fn journal_precedes_kernel_and_commit_precedes_live_publication() {
    let store = Store::default();
    let mut service = open(store.clone(), true);
    store.0.borrow_mut().events.clear();
    registered(&mut service, 1000);
    assert_eq!(
        store.0.borrow().events,
        ["pending", "install:1", "committed", "clear"]
    );
}

#[test]
fn each_failed_transaction_enters_recovery_and_is_finished_on_restart() {
    for phase in ["pending", "backend", "committed", "clear"] {
        let store = Store::default();
        let fail = Rc::new(RefCell::new(false));
        let backend = Backend {
            records: store.clone(),
            fail: fail.clone(),
            supported: true,
        };
        let mut service = Control::open(Platform::Linux, [2; 16], store.clone(), backend).unwrap();
        if phase == "backend" {
            *fail.borrow_mut() = true;
        } else {
            store.0.borrow_mut().fault = Some(phase);
        }
        expect_error(
            call(
                &mut service,
                1000,
                Command::RegisterProfile {
                    registration_key: key(),
                    owner: user(1000).user,
                    consumers: vec![],
                },
            ),
            if phase == "backend" {
                ErrorCode::BackendUnavailable
            } else {
                ErrorCode::Storage
            },
        );
        assert_eq!(service.backend_state(), BackendState::Recovering);
        assert!(service
            .state()
            .profiles()
            .list(&user(1000))
            .unwrap()
            .is_empty());
        assert_eq!(store.0.borrow().events.last().unwrap(), "block");
        expect_error(
            call(
                &mut service,
                1000,
                Command::RegisterProfile {
                    registration_key: key(),
                    owner: user(1000).user,
                    consumers: vec![],
                },
            ),
            ErrorCode::RecoveryRequired,
        );
        drop(service);
        store.0.borrow_mut().fault = None;
        let service = open(store.clone(), true);
        assert_eq!(
            service.state().profiles().list(&user(1000)).unwrap().len(),
            1
        );
        assert_eq!(service.state().serial(), 1);
        assert!(store.0.borrow().pending.is_none());
    }
}

#[test]
fn authorization_and_validation_do_not_write_or_install_anything() {
    let store = Store::default();
    let mut service = open(store.clone(), true);
    let profile = registered(&mut service, 1000);
    store.0.borrow_mut().events.clear();
    expect_error(
        call(
            &mut service,
            1001,
            Command::DeleteProfile {
                profile: profile.clone(),
            },
        ),
        ErrorCode::NotFound,
    );
    expect_error(
        call(
            &mut service,
            1001,
            Command::GetPolicy {
                owner: user(1000).user,
            },
        ),
        ErrorCode::AccessDenied,
    );
    expect_error(
        call(
            &mut service,
            0,
            Command::SetGlobalDns {
                profile,
                acknowledge_outage: false,
            },
        ),
        ErrorCode::InvalidRequest,
    );
    assert!(store.0.borrow().events.is_empty());
}

#[test]
fn unavailable_backend_never_claims_activation_or_modifies_metadata() {
    let store = Store::default();
    let mut service = open(store.clone(), false);
    assert_eq!(service.backend_state(), BackendState::Unavailable);
    expect_error(
        call(
            &mut service,
            1000,
            Command::RegisterProfile {
                registration_key: key(),
                owner: user(1000).user,
                consumers: vec![],
            },
        ),
        ErrorCode::BackendUnavailable,
    );
    assert!(store.0.borrow().events.is_empty());
}

#[test]
fn broken_or_unrelated_metadata_is_rejected_without_reset() {
    for corrupt in [b"{}".as_slice(), b"garbage"] {
        let store = Store::default();
        store.0.borrow_mut().committed = Some(corrupt.into());
        let backend = Backend {
            records: store.clone(),
            fail: Rc::default(),
            supported: true,
        };
        assert!(Control::open(Platform::Linux, [2; 16], store.clone(), backend).is_err());
        assert_eq!(store.0.borrow().events, ["block"]);
    }
    let store = Store::default();
    let mut service = open(store.clone(), true);
    registered(&mut service, 1000);
    let snapshot = store.0.borrow().committed.clone().unwrap();
    drop(service);
    let mut changed: serde_json::Value = serde_json::from_slice(&snapshot).unwrap();
    changed["serial"] = serde_json::json!(77);
    store.0.borrow_mut().pending = Some(serde_json::to_vec(&changed).unwrap());
    let backend = Backend {
        records: store.clone(),
        fail: Rc::default(),
        supported: true,
    };
    assert!(Control::open(Platform::Linux, [2; 16], store, backend).is_err());
}

#[test]
fn split_switch_survives_service_reload_without_losing_saved_rules() {
    let store = Store::default();
    let mut service = open(store.clone(), true);
    let profile = match call(
        &mut service,
        1000,
        Command::RegisterProfile {
            owner: user(1000).user,
            registration_key: key(),
            consumers: vec![],
        },
    )
    .into_result()
    {
        Outcome::Ok {
            reply: Reply::Registered { profile },
        } => profile,
        other => panic!("{other:?}"),
    };
    assert!(matches!(
        call(
            &mut service,
            0,
            Command::SetGlobalDns {
                profile: profile.clone(),
                acknowledge_outage: true
            }
        )
        .result(),
        Outcome::Ok { .. }
    ));
    let original = policy(1000, &profile);
    let mut doc = original.clone();
    for (generation, enabled) in [(1, true), (2, false), (3, true)] {
        doc.generation = generation;
        doc.split_enabled = enabled;
        assert!(matches!(
            call(
                &mut service,
                1000,
                Command::ApplyPolicy {
                    document: doc.clone(),
                    expected_generation: (generation > 1).then_some(generation - 1)
                }
            )
            .result(),
            Outcome::Ok { .. }
        ));
        drop(service);
        service = open(store.clone(), true);
        match call(
            &mut service,
            1000,
            Command::GetPolicy {
                owner: user(1000).user,
            },
        )
        .into_result()
        {
            Outcome::Ok {
                reply:
                    Reply::Policy {
                        document: Some(restored),
                    },
            } => {
                assert_eq!(restored.split_enabled, enabled);
                assert_eq!(restored.rules, original.rules);
                assert_eq!(restored.default_action, original.default_action);
            }
            other => panic!("{other:?}"),
        }
        let restored = service.state().policies().get(&user(1000).user).unwrap();
        if !enabled {
            assert!(restored.effective_document().rules.is_empty());
            assert_eq!(
                restored.effective_document().default_action,
                Action::Vpn {
                    profile: profile.clone()
                }
            );
        }
    }
}
