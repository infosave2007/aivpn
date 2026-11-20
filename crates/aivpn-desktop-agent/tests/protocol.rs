use aivpn_desktop_agent::protocol::*;
use aivpn_desktop_policy::{Owner, Platform, ProfileStatus};
use std::num::NonZeroU64;

#[test]
fn worker_start_has_its_own_deadline_without_extending_ordinary_queries() {
    let connection =
        aivpn_desktop_agent::connection::ConnectionDocument::from_json(br#"{"s":"192.0.2.1:443"}"#)
            .unwrap();
    let start = Request::new(
        NonZeroU64::MIN,
        Command::StartProfile {
            profile: "selected".into(),
            connection,
        },
    );
    assert_eq!(start.response_timeout(), std::time::Duration::from_secs(30));
    let status = Request::new(NonZeroU64::MIN, Command::Status {});
    assert_eq!(status.response_timeout(), std::time::Duration::from_secs(5));
}

#[test]
fn request_roundtrip_has_a_single_version_and_nonzero_id() {
    let request = Request::new(NonZeroU64::new(42).unwrap(), Command::ListProfiles {});
    let bytes = request.to_json().unwrap();
    let parsed = Request::from_json(&bytes).unwrap();
    assert_eq!(parsed.id(), request.id());
    assert!(matches!(parsed.command(), Command::ListProfiles {}));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["version"],
        1
    );
}

#[test]
fn request_boundary_rejects_authority_injection_and_ambiguous_messages() {
    for value in [
        r#"{"version":2,"id":1,"command":{"method":"status"}}"#,
        r#"{"version":1,"id":0,"command":{"method":"status"}}"#,
        r#"{"version":1,"id":-1,"command":{"method":"status"}}"#,
        r#"{"version":1,"id":1,"id":2,"command":{"method":"status"}}"#,
        r#"{"version":1,"id":1,"authority":{"machine_admin":true},"command":{"method":"status"}}"#,
        r#"{"version":1,"id":1,"command":{"method":"status","uid":0}}"#,
        r#"{"version":1,"id":1,"command":{"method":"list_profiles","uid":0}}"#,
        r#"{"version":1,"id":1,"command":{"method":"clear_global_dns","uid":0}}"#,
        r#"{"version":1,"id":1,"command":{"method":"shell","command":"id"}}"#,
        r#"{"version":1,"id":1,"command":{"method":"delete_profile","profile":"x","pid":1}}"#,
        r#"{"version":1,"id":1,"command":{"method":"status"}}{}"#,
    ] {
        assert!(Request::from_json(value.as_bytes()).is_err(), "{value}");
    }
    assert!(Request::from_json(&vec![b' '; aivpn_desktop_agent::MAX_FRAME_BYTES + 1]).is_err());
}

#[test]
fn responses_are_correlated_and_reject_unknown_fields() {
    let id = NonZeroU64::new(u64::MAX).unwrap();
    let response = Response::success(
        id,
        Reply::Status {
            platform: Platform::Linux,
            backend: BackendState::Unavailable,
            revision: 0,
            global_dns_profile: None,
        },
    );
    let bytes = response.to_json().unwrap();
    assert_eq!(Response::from_json(&bytes).unwrap().id(), id);
    let response = Response::failure(id, ErrorCode::AccessDenied);
    let mut value: serde_json::Value =
        serde_json::from_slice(&response.to_json().unwrap()).unwrap();
    assert_eq!(value["result"]["code"], "access_denied");
    value["result"]["authority"] = serde_json::json!({"machine_admin":true});
    assert!(Response::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn serialization_obeys_transport_limits_in_both_directions() {
    let id = NonZeroU64::MIN;
    let large = "x".repeat(aivpn_desktop_agent::MAX_FRAME_BYTES);
    let request = Request::new(
        id,
        Command::DeleteProfile {
            profile: large.clone(),
        },
    );
    assert!(request.to_json().is_err());
    let response = Response::success(id, Reply::Registered { profile: large });
    assert!(response.to_json().is_err());
    assert!(Response::from_json(&vec![b' '; aivpn_desktop_agent::MAX_FRAME_BYTES + 1]).is_err());
    assert!(Response::from_json(
        br#"{"version":3,"id":1,"result":{"outcome":"error","code":"invalid_request"}}"#
    )
    .is_err());
}

#[test]
fn control_messages_do_not_need_process_ids_or_secret_configuration() {
    let request = Request::new(
        NonZeroU64::MIN,
        Command::RegisterProfile {
            registration_key: "protocol-profile".into(),
            owner: Owner::LinuxUser { uid: 1000 },
            consumers: vec![],
        },
    );
    let parsed = Request::from_json(&request.to_json().unwrap()).unwrap();
    assert!(matches!(parsed.command(), Command::RegisterProfile { .. }));
}

#[test]
fn start_profile_does_not_expose_secrets_or_accept_a_server_side_file_path() {
    use aivpn_desktop_agent::connection::{ConnectionDocument, WorkerConfiguration};
    let connection =
        ConnectionDocument::from_json(br#"{"s":"192.0.2.1:443","p":"private-regression-key"}"#)
            .unwrap();
    let request = Request::new(
        NonZeroU64::MIN,
        Command::StartProfile {
            profile: "one".into(),
            connection,
        },
    );
    assert!(!format!("{request:?}").contains("private-regression-key"));
    let parsed = Request::from_json(&request.to_json().unwrap()).unwrap();
    let Command::StartProfile { connection, .. } = parsed.command() else {
        panic!("Неверная команда")
    };
    assert!(WorkerConfiguration::from_document(connection).is_ok());
    assert!(Request::from_json(br#"{"version":1,"id":1,"command":{"method":"start_profile","profile":"one","connection":{},"file":"/etc/shadow"}}"#).is_err());
}

#[test]
fn profile_readiness_is_returned_without_worker_authority_or_secrets() {
    let profile = ProfileStatus {
        id: "profile".into(),
        owner: Owner::LinuxUser { uid: 1000 },
        control_allowed: false,
        session_active: true,
        ready_ipv4: true,
        ready_ipv6: false,
        assignment_generation: 7,
        session_id: None,
        registration_key: None,
        ipv4: Some("10.67.0.2".parse().unwrap()),
        ipv6: None,
    };
    let response = Response::success(
        NonZeroU64::MIN,
        Reply::Profiles {
            profiles: vec![profile.clone()],
        },
    );
    let parsed = Response::from_json(&response.to_json().unwrap()).unwrap();
    assert!(
        matches!(parsed.result(), Outcome::Ok { reply: Reply::Profiles { profiles } } if profiles == &[profile])
    );
    assert!(Response::from_json(
        br#"{"version":1,"id":1,"result":{"outcome":"ok","reply":{"kind":"done","uid":0}}}"#
    )
    .is_err());
}

#[test]
fn desktop_management_preserves_the_existing_maximum_management_body() {
    use aivpn_desktop_agent::administration::{CommandText, ReplyText, SessionQuery};
    use base64::Engine;
    let body = base64::engine::general_purpose::STANDARD.encode(vec![7; 512 * 1024]);
    let line = format!("mgmt:1:/api/v1/fixture:{body}");
    let request = Request::new(
        NonZeroU64::MIN,
        Command::SessionAdmin {
            profile: "selected".into(),
            assignment_generation: NonZeroU64::MIN,
            session_id: [1; 16],
            query: SessionQuery::Execute {
                command: CommandText::new(line.clone()).unwrap(),
            },
        },
    );
    let encoded = request
        .to_json()
        .expect("Полный объем управления должен проходить через службу");
    let decoded = Request::from_json(&encoded).unwrap();
    let Command::SessionAdmin {
        query: SessionQuery::Execute { command },
        ..
    } = decoded.command()
    else {
        panic!("Неверная команда")
    };
    assert_eq!(command.as_str(), line);
    assert!(!format!("{request:?}").contains("mgmt:1:/api/v1/fixture:"));
    let response = Response::success(
        request.id(),
        Reply::SessionReply {
            output: ReplyText::new(format!("200:{body}")).unwrap(),
        },
    );
    let decoded = Response::from_json(&response.to_json().unwrap()).unwrap();
    assert!(
        matches!(decoded.result(), Outcome::Ok { reply: Reply::SessionReply { output } } if output.as_str() == format!("200:{body}"))
    );
    assert!(!format!("{response:?}").contains("200:"));
}

#[test]
fn a_maximum_size_policy_fits_inside_its_control_envelope() {
    use aivpn_desktop_policy::*;
    let authority = Authority {
        user: Owner::LinuxUser { uid: 1000 },
        machine_admin: false,
    };
    let mut document = PolicyDocument {
        split_enabled: true,
        version: 1,
        id: "maximum".into(),
        generation: 1,
        platform: Platform::Linux,
        owner: authority.user.clone(),
        default_action: Action::System {},
        dns: DnsPolicy::SharedVpn {
            profile: "profile".into(),
            acknowledge_outage: true,
        },
        rules: (0..32)
            .map(|index| RuleDocument {
                id: format!("r{index}"),
                application: Selector::Executable {
                    path: format!("/{}", "a".repeat(4095)),
                },
                destination: None,
                inherit_children: true,
                action: Action::Block {},
            })
            .collect(),
    };
    let mut excess = serde_json::to_vec(&document).unwrap().len() - 128 * 1024;
    for rule in document.rules.iter_mut().rev() {
        if let Selector::Executable { path } = &mut rule.application {
            let removed = excess.min(path.len() - 2);
            path.truncate(path.len() - removed);
            excess -= removed;
        }
    }
    assert_eq!(excess, 0);
    assert_eq!(serde_json::to_vec(&document).unwrap().len(), 128 * 1024);
    Policy::validate(document.clone(), &authority).unwrap();
    let request = Request::new(
        NonZeroU64::MIN,
        Command::ApplyPolicy {
            document,
            expected_generation: None,
        },
    );
    let bytes = request.to_json().unwrap();
    assert!(bytes.len() > 128 * 1024);
    assert!(matches!(
        Request::from_json(&bytes).unwrap().command(),
        Command::ApplyPolicy { .. }
    ));
}

#[test]
fn exact_transport_boundary_accepts_a_complete_json_message() {
    let request = Request::new(NonZeroU64::MIN, Command::Status {});
    let mut bytes = request.to_json().unwrap();
    bytes.resize(aivpn_desktop_agent::MAX_FRAME_BYTES, b' ');
    assert!(matches!(
        Request::from_json(&bytes).unwrap().command(),
        Command::Status {}
    ));
    let overhead = Request::new(
        NonZeroU64::MIN,
        Command::DeleteProfile {
            profile: String::new(),
        },
    )
    .to_json()
    .unwrap()
    .len();
    let request = Request::new(
        NonZeroU64::MIN,
        Command::DeleteProfile {
            profile: "x".repeat(aivpn_desktop_agent::MAX_FRAME_BYTES - overhead),
        },
    );
    assert_eq!(
        request.to_json().unwrap().len(),
        aivpn_desktop_agent::MAX_FRAME_BYTES
    );
}
