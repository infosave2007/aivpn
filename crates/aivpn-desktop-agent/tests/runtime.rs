use aivpn_desktop_agent::control::{Control, ControlState, ControlStore, RoutingBackend};
use aivpn_desktop_agent::protocol::{BackendState, Command, ErrorCode, Outcome, Reply, Request};
use aivpn_desktop_agent::state::StateFile;
use aivpn_desktop_policy::{Authority, Owner, Platform, ProfileAssignment, ProfileCatalog};
use std::cell::RefCell;
use std::io;
use std::num::NonZeroU64;
use std::rc::Rc;

#[derive(Default)]
struct Records {
    committed: Option<Vec<u8>>,
    pending: Option<Vec<u8>>,
    dns: Option<Vec<u8>>,
    events: Vec<&'static str>,
    fault: Option<&'static str>,
    block_fault: bool,
}

#[derive(Clone, Default)]
struct Store(Rc<RefCell<Records>>);

impl ControlStore for Store {
    fn load(&self, file: StateFile) -> io::Result<Option<Vec<u8>>> {
        let records = self.0.borrow();
        Ok(match file {
            StateFile::Committed => &records.committed,
            StateFile::Pending => &records.pending,
            StateFile::DnsJournal => &records.dns,
        }
        .clone())
    }

    fn replace(&mut self, file: StateFile, bytes: &[u8]) -> io::Result<()> {
        let mut records = self.0.borrow_mut();
        let name = match file {
            StateFile::Pending => "pending",
            StateFile::DnsJournal => "dns",
            StateFile::Committed => "committed",
        };
        records.events.push(name);
        if records.fault == Some(name) {
            return Err(io::Error::other("storage fault"));
        }
        *match file {
            StateFile::Pending => &mut records.pending,
            StateFile::DnsJournal => &mut records.dns,
            StateFile::Committed => &mut records.committed,
        } = Some(bytes.to_vec());
        Ok(())
    }

    fn clear_pending(&mut self) -> io::Result<()> {
        let mut records = self.0.borrow_mut();
        records.events.push("clear");
        if records.fault == Some("clear") {
            return Err(io::Error::other("clear fault"));
        }
        records.pending = None;
        Ok(())
    }
}

struct Backend {
    records: Store,
    supported: bool,
    platform: Platform,
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
        live: &ProfileCatalog,
    ) -> io::Result<()> {
        let profiles = live
            .runtime_profiles(&administrator_for(self.platform))
            .unwrap();
        let ready = profiles.iter().any(|profile| profile.ready_ipv4);
        let phase = if ready {
            "install_ready"
        } else {
            "install_offline"
        };
        let mut records = self.records.0.borrow_mut();
        records.events.push(phase);
        if let (true, Some(pending)) = (ready, records.pending.as_ref()) {
            let stored: serde_json::Value = serde_json::from_slice(pending).unwrap();
            let stored = ProfileCatalog::restore_metadata(
                self.platform,
                &serde_json::to_vec(&stored["profiles"]).unwrap(),
            )
            .unwrap();
            let expected = desired
                .profiles()
                .runtime_profiles(&administrator_for(self.platform))
                .unwrap();
            assert_eq!(
                stored
                    .runtime_profiles(&administrator_for(self.platform))
                    .unwrap(),
                expected
            );
            for profile in profiles.iter().filter(|profile| profile.ready_ipv4) {
                let planned = expected
                    .iter()
                    .find(|planned| planned.id == profile.id)
                    .unwrap();
                assert_eq!(planned.assignment, profile.assignment);
                assert_eq!(planned.assignment_generation, profile.assignment_generation);
            }
        }
        if records.fault == Some(phase) {
            return Err(io::Error::other("backend fault"));
        }
        Ok(())
    }

    fn block(&mut self) -> io::Result<()> {
        let mut records = self.records.0.borrow_mut();
        records.events.push("block");
        if records.block_fault {
            Err(io::Error::other("block fault"))
        } else {
            Ok(())
        }
    }
}

fn user(uid: u32) -> Authority {
    Authority {
        user: Owner::LinuxUser { uid },
        machine_admin: false,
    }
}

fn administrator() -> Authority {
    administrator_for(Platform::Linux)
}

fn administrator_for(platform: Platform) -> Authority {
    Authority {
        machine_admin: true,
        user: match platform {
            Platform::Linux => user(0).user,
            Platform::Windows => Owner::WindowsUser {
                sid: "S-1-5-18".into(),
            },
        },
    }
}

fn open(store: Store) -> Control<Store, Backend> {
    open_for(store, Platform::Linux)
}

fn open_for(store: Store, platform: Platform) -> Control<Store, Backend> {
    Control::open(
        platform,
        [81; 16],
        store.clone(),
        Backend {
            records: store,
            supported: true,
            platform,
        },
    )
    .unwrap()
}

fn setup() -> (Control<Store, Backend>, Store, String) {
    let store = Store::default();
    let mut service = open(store.clone());
    let response = service.handle(
        &user(1000),
        Request::new(
            NonZeroU64::MIN,
            Command::RegisterProfile {
                owner: user(1000).user,
                registration_key: "runtime-profile".into(),
                consumers: vec![],
            },
        ),
    );
    let id = match response.result() {
        Outcome::Ok {
            reply: Reply::Registered { profile },
        } => profile.clone(),
        other => panic!("{other:?}"),
    };
    store.0.borrow_mut().events.clear();
    (service, store, id)
}

fn assignment() -> ProfileAssignment {
    ProfileAssignment {
        interface_id: 41,
        ipv4: "10.67.0.2".parse().unwrap(),
        ipv6: Some("fd67::2".parse().unwrap()),
    }
}

#[test]
fn assignment_is_journaled_before_readiness_and_exact_retry_does_not_flap() {
    let (mut service, store, id) = setup();
    let lease = service.begin_profile_session(&id, &user(1000)).unwrap();
    assert_eq!(store.0.borrow().events, ["install_offline"]);
    store.0.borrow_mut().events.clear();
    let generation = service.assign_profile(&lease, assignment()).unwrap();
    assert_eq!(
        store.0.borrow().events,
        [
            "install_offline",
            "pending",
            "install_offline",
            "committed",
            "clear",
            "install_ready"
        ]
    );
    let profile = service.state().profiles().session_profile(&lease).unwrap();
    assert_eq!(profile.assignment, Some(assignment()));
    assert_eq!(profile.assignment_generation, generation);
    assert!(profile.ready_ipv4 && profile.ready_ipv6);
    let response = service.handle(
        &user(2000),
        Request::new(
            NonZeroU64::MIN,
            Command::RegisterProfile {
                owner: user(2000).user,
                registration_key: "other-runtime-profile".into(),
                consumers: vec![],
            },
        ),
    );
    assert!(matches!(response.result(), Outcome::Ok { .. }));
    assert!(
        service
            .state()
            .profiles()
            .session_profile(&lease)
            .unwrap()
            .ready_ipv4
    );
    let serial = service.state().serial();
    store.0.borrow_mut().events.clear();
    assert_eq!(
        service.assign_profile(&lease, assignment()).unwrap(),
        generation
    );
    assert_eq!(service.state().serial(), serial);
    assert_eq!(store.0.borrow().events, ["install_ready"]);
    service.disconnect_profile_session(&lease).unwrap();
    assert!(!service.state().profiles().list(&administrator()).unwrap()[0].ready_ipv4);
    drop(service);
    let recovered = open(store.clone());
    let profile = &recovered
        .state()
        .profiles()
        .runtime_profiles(&administrator())
        .unwrap()[0];
    assert_eq!(profile.assignment, Some(assignment()));
    assert_eq!(profile.assignment_generation, generation);
    assert!(!profile.ready_ipv4 && !profile.ready_ipv6);
    assert!(recovered
        .state()
        .profiles()
        .session_profile(&lease)
        .is_err());
}

#[test]
fn foreign_and_stale_sessions_cannot_disrupt_a_new_ready_session() {
    let (mut service, store, id) = setup();
    assert!(matches!(
        service.begin_profile_session(&id, &user(1001)),
        Err(ErrorCode::AccessDenied)
    ));
    assert!(store.0.borrow().events.is_empty());
    assert!(matches!(
        service.begin_profile_session(
            &id,
            &Authority {
                user: Owner::Machine {},
                machine_admin: true
            }
        ),
        Err(ErrorCode::AccessDenied)
    ));
    assert!(store.0.borrow().events.is_empty());
    let old = service.begin_profile_session(&id, &user(1000)).unwrap();
    service.assign_profile(&old, assignment()).unwrap();
    let new = service.begin_profile_session(&id, &user(1000)).unwrap();
    service.assign_profile(&new, assignment()).unwrap();
    store.0.borrow_mut().events.clear();
    assert_eq!(
        service.assign_profile(&old, assignment()),
        Err(ErrorCode::Conflict)
    );
    assert_eq!(
        service.disconnect_profile_session(&old),
        Err(ErrorCode::Conflict)
    );
    assert!(store.0.borrow().events.is_empty());
    assert!(
        service
            .state()
            .profiles()
            .session_profile(&new)
            .unwrap()
            .ready_ipv4
    );
}

#[test]
fn invalid_assignment_closes_old_readiness_before_reporting_the_error() {
    let (mut service, store, id) = setup();
    let lease = service.begin_profile_session(&id, &user(1000)).unwrap();
    service.assign_profile(&lease, assignment()).unwrap();
    store.0.borrow_mut().events.clear();
    let invalid = ProfileAssignment {
        interface_id: 0,
        ..assignment()
    };
    assert_eq!(
        service.assign_profile(&lease, invalid),
        Err(ErrorCode::InvalidRequest)
    );
    assert_eq!(store.0.borrow().events, ["install_offline"]);
    assert!(
        !service
            .state()
            .profiles()
            .session_profile(&lease)
            .unwrap()
            .ready_ipv4
    );
    assert_eq!(service.backend_state(), BackendState::Active);
}

#[test]
fn faults_revoke_leases_and_recovery_never_restores_readiness() {
    for fault in [
        "install_offline",
        "pending",
        "install_ready",
        "committed",
        "clear",
    ] {
        let (mut service, store, id) = setup();
        let lease = service.begin_profile_session(&id, &user(1000)).unwrap();
        store.0.borrow_mut().fault = Some(fault);
        assert!(
            service.assign_profile(&lease, assignment()).is_err(),
            "{fault}"
        );
        assert_eq!(service.backend_state(), BackendState::Recovering, "{fault}");
        assert!(
            service.state().profiles().session_profile(&lease).is_err(),
            "{fault}"
        );
        assert_eq!(store.0.borrow().events.last(), Some(&"block"), "{fault}");
        drop(service);
        store.0.borrow_mut().fault = None;
        let recovered = open(store.clone());
        let profiles = recovered
            .state()
            .profiles()
            .runtime_profiles(&administrator())
            .unwrap();
        let expected = if matches!(fault, "install_offline" | "pending") {
            None
        } else {
            Some(assignment())
        };
        assert_eq!(profiles[0].assignment, expected, "{fault}");
        assert!(
            recovered
                .state()
                .profiles()
                .runtime_profiles(&administrator())
                .unwrap()
                .iter()
                .all(|profile| !profile.ready_ipv4 && !profile.ready_ipv6),
            "{fault}"
        );
        assert!(store.0.borrow().pending.is_none());
    }
}

#[test]
fn failed_block_is_reported_as_unverified_protection() {
    let (mut service, store, id) = setup();
    let lease = service.begin_profile_session(&id, &user(1000)).unwrap();
    let mut records = store.0.borrow_mut();
    records.fault = Some("install_ready");
    records.block_fault = true;
    drop(records);
    assert!(service.assign_profile(&lease, assignment()).is_err());
    assert_eq!(service.backend_state(), BackendState::ProtectionUnverified);
    store.0.borrow_mut().events.clear();
    assert!(matches!(
        service.begin_profile_session(&id, &user(1000)),
        Err(ErrorCode::RecoveryRequired)
    ));
    assert_eq!(
        service.assign_profile(&lease, assignment()),
        Err(ErrorCode::RecoveryRequired)
    );
    assert_eq!(
        service.disconnect_profile_session(&lease),
        Err(ErrorCode::RecoveryRequired)
    );
    assert!(store.0.borrow().events.is_empty());
}

#[test]
fn session_start_and_disconnect_faults_block_before_returning() {
    for replacing in [false, true] {
        let (mut service, store, id) = setup();
        let lease = service.begin_profile_session(&id, &user(1000)).unwrap();
        service.assign_profile(&lease, assignment()).unwrap();
        let committed = store.0.borrow().committed.clone();
        let mut records = store.0.borrow_mut();
        records.events.clear();
        records.fault = Some("install_offline");
        drop(records);
        let result = if replacing {
            service.begin_profile_session(&id, &user(1000)).map(|_| ())
        } else {
            service.disconnect_profile_session(&lease)
        };
        assert_eq!(result, Err(ErrorCode::BackendUnavailable));
        assert_eq!(service.backend_state(), BackendState::Recovering);
        assert_eq!(store.0.borrow().events, ["install_offline", "block"]);
        assert_eq!(store.0.borrow().committed, committed);
        assert!(store.0.borrow().pending.is_none());
        assert!(service.state().profiles().session_profile(&lease).is_err());
    }
}

#[test]
fn exact_retry_failure_revokes_readiness_without_rewriting_the_journal() {
    let (mut service, store, id) = setup();
    let lease = service.begin_profile_session(&id, &user(1000)).unwrap();
    service.assign_profile(&lease, assignment()).unwrap();
    let committed = store.0.borrow().committed.clone();
    let mut records = store.0.borrow_mut();
    records.events.clear();
    records.fault = Some("install_ready");
    drop(records);
    assert_eq!(
        service.assign_profile(&lease, assignment()),
        Err(ErrorCode::BackendUnavailable)
    );
    assert_eq!(service.backend_state(), BackendState::Recovering);
    assert_eq!(store.0.borrow().events, ["install_ready", "block"]);
    assert_eq!(store.0.borrow().committed, committed);
    assert!(store.0.borrow().pending.is_none());
    assert!(service.state().profiles().session_profile(&lease).is_err());
}

#[test]
fn exhausted_serial_closes_the_profile_without_overflow_or_partial_commit() {
    let (service, store, id) = setup();
    drop(service);
    let mut snapshot: serde_json::Value =
        serde_json::from_slice(store.0.borrow().committed.as_ref().unwrap()).unwrap();
    snapshot["serial"] = u64::MAX.into();
    store.0.borrow_mut().committed = Some(serde_json::to_vec(&snapshot).unwrap());
    let mut service = open(store.clone());
    let lease = service.begin_profile_session(&id, &user(1000)).unwrap();
    store.0.borrow_mut().events.clear();
    assert_eq!(
        service.assign_profile(&lease, assignment()),
        Err(ErrorCode::Capacity)
    );
    assert_eq!(service.state().serial(), u64::MAX);
    assert!(
        !service
            .state()
            .profiles()
            .session_profile(&lease)
            .unwrap()
            .ready_ipv4
    );
    assert_eq!(store.0.borrow().events, ["install_offline"]);
    assert!(store.0.borrow().pending.is_none());
}

#[test]
fn invalid_assignment_does_not_disconnect_another_profile_session() {
    let (mut service, store, first) = setup();
    let response = service.handle(
        &user(2000),
        Request::new(
            NonZeroU64::MIN,
            Command::RegisterProfile {
                owner: user(2000).user,
                registration_key: "parallel-profile".into(),
                consumers: vec![],
            },
        ),
    );
    let second = match response.result() {
        Outcome::Ok {
            reply: Reply::Registered { profile },
        } => profile.clone(),
        other => panic!("{other:?}"),
    };
    let first = service.begin_profile_session(&first, &user(1000)).unwrap();
    service.assign_profile(&first, assignment()).unwrap();
    let second = service.begin_profile_session(&second, &user(2000)).unwrap();
    service
        .assign_profile(
            &second,
            ProfileAssignment {
                interface_id: 84,
                ..assignment()
            },
        )
        .unwrap();
    let committed = store.0.borrow().committed.clone();
    assert_eq!(
        service.assign_profile(
            &first,
            ProfileAssignment {
                interface_id: 0,
                ..assignment()
            }
        ),
        Err(ErrorCode::InvalidRequest)
    );
    assert!(
        !service
            .state()
            .profiles()
            .session_profile(&first)
            .unwrap()
            .ready_ipv4
    );
    assert!(
        service
            .state()
            .profiles()
            .session_profile(&second)
            .unwrap()
            .ready_ipv4
    );
    assert_eq!(service.backend_state(), BackendState::Active);
    assert_eq!(store.0.borrow().committed, committed);
    service.disconnect_profile_session(&first).unwrap();
    assert!(
        service
            .state()
            .profiles()
            .session_profile(&second)
            .unwrap()
            .ready_ipv4
    );
}

#[test]
fn windows_session_uses_sid_authority_and_restores_offline_metadata() {
    let store = Store::default();
    let mut service = open_for(store.clone(), Platform::Windows);
    let owner = Authority {
        user: Owner::WindowsUser {
            sid: "S-1-5-21-1000".into(),
        },
        machine_admin: false,
    };
    let response = service.handle(
        &owner,
        Request::new(
            NonZeroU64::MIN,
            Command::RegisterProfile {
                owner: owner.user.clone(),
                registration_key: "windows-runtime".into(),
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
    let lease = service.begin_profile_session(&profile, &owner).unwrap();
    let generation = service.assign_profile(&lease, assignment()).unwrap();
    assert!(
        service
            .state()
            .profiles()
            .session_profile(&lease)
            .unwrap()
            .ready_ipv6
    );
    let serial = service.state().serial();
    assert_eq!(
        service.assign_profile(&lease, assignment()).unwrap(),
        generation
    );
    assert_eq!(service.state().serial(), serial);
    drop(service);
    let recovered = open_for(store, Platform::Windows);
    let profiles = recovered
        .state()
        .profiles()
        .runtime_profiles(&administrator_for(Platform::Windows))
        .unwrap();
    assert_eq!(profiles[0].assignment, Some(assignment()));
    assert_eq!(profiles[0].assignment_generation, generation);
    assert!(!profiles[0].ready_ipv4 && !profiles[0].ready_ipv6);
    assert!(recovered
        .state()
        .profiles()
        .session_profile(&lease)
        .is_err());
}

#[test]
fn unsupported_backend_still_closes_protection_for_recorded_runtime_assignments() {
    let (mut service, store, id) = setup();
    let lease = service.begin_profile_session(&id, &user(1000)).unwrap();
    service.assign_profile(&lease, assignment()).unwrap();
    drop(service);
    store.0.borrow_mut().events.clear();
    let mut recovered = Control::open(
        Platform::Linux,
        [81; 16],
        store.clone(),
        Backend {
            records: store.clone(),
            supported: false,
            platform: Platform::Linux,
        },
    )
    .unwrap();
    assert_eq!(recovered.backend_state(), BackendState::Recovering);
    assert_eq!(store.0.borrow().events, ["block"]);
    assert!(
        !recovered
            .state()
            .profiles()
            .runtime_profiles(&administrator())
            .unwrap()[0]
            .ready_ipv4
    );
    store.0.borrow_mut().events.clear();
    assert!(matches!(
        recovered.begin_profile_session(&id, &user(1000)),
        Err(ErrorCode::RecoveryRequired)
    ));
    assert_eq!(
        recovered.assign_profile(&lease, assignment()),
        Err(ErrorCode::RecoveryRequired)
    );
    assert_eq!(
        recovered.disconnect_profile_session(&lease),
        Err(ErrorCode::RecoveryRequired)
    );
    assert!(store.0.borrow().events.is_empty());
}

#[test]
fn unassigned_profiles_do_not_claim_protection_on_an_unsupported_backend() {
    let (mut service, store, id) = setup();
    let lease = service.begin_profile_session(&id, &user(1000)).unwrap();
    drop(service);
    store.0.borrow_mut().events.clear();
    let mut service = Control::open(
        Platform::Linux,
        [81; 16],
        store.clone(),
        Backend {
            records: store.clone(),
            supported: false,
            platform: Platform::Linux,
        },
    )
    .unwrap();
    assert_eq!(service.backend_state(), BackendState::Unavailable);
    assert!(matches!(
        service.begin_profile_session(&id, &user(1000)),
        Err(ErrorCode::BackendUnavailable)
    ));
    assert_eq!(
        service.assign_profile(&lease, assignment()),
        Err(ErrorCode::BackendUnavailable)
    );
    assert_eq!(
        service.disconnect_profile_session(&lease),
        Err(ErrorCode::BackendUnavailable)
    );
    assert!(store.0.borrow().events.is_empty());
}

#[test]
fn mutation_after_assignment_recovers_the_next_journal_transaction() {
    let (mut service, store, id) = setup();
    let lease = service.begin_profile_session(&id, &user(1000)).unwrap();
    service.assign_profile(&lease, assignment()).unwrap();
    store.0.borrow_mut().fault = Some("committed");
    let response = service.handle(
        &user(2000),
        Request::new(
            NonZeroU64::MIN,
            Command::RegisterProfile {
                owner: user(2000).user,
                registration_key: "registered-after-assignment".into(),
                consumers: vec![],
            },
        ),
    );
    assert!(matches!(
        response.result(),
        Outcome::Error {
            code: ErrorCode::Storage
        }
    ));
    drop(service);
    store.0.borrow_mut().fault = None;
    let recovered = open(store.clone());
    assert_eq!(recovered.backend_state(), BackendState::Active);
    let profiles = recovered
        .state()
        .profiles()
        .runtime_profiles(&administrator())
        .unwrap();
    assert_eq!(profiles.len(), 2);
    let assigned = profiles.iter().find(|profile| profile.id == id).unwrap();
    assert_eq!(assigned.assignment, Some(assignment()));
    assert!(profiles.iter().all(|profile| !profile.ready_ipv4));
    assert!(store.0.borrow().pending.is_none());
}
