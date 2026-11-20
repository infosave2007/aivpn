use aivpn_desktop_agent::worker_protocol::WorkerEvent;

#[test]
fn authenticated_dual_stack_assignment_survives_the_private_worker_channel() {
    let value = serde_json::json!({
        "event": "assignment", "generation": 7,
        "network": {
            "client_ip": "10.67.0.2", "server_vpn_ip": "10.67.0.1",
            "prefix_len": 24, "mtu": 1280, "mdh_len": 24,
            "ipv6": {"address": "fd00:67::2", "prefix_len": 64}
        }
    });
    let event: WorkerEvent = serde_json::from_value(value.clone())
        .expect("Подтвержденный сервером IPv6 должен доходить до desktop-службы");
    assert_eq!(serde_json::to_value(event).unwrap(), value);
}

#[test]
fn ipv4_only_workers_keep_the_existing_private_assignment() {
    let value = serde_json::json!({
        "client_ip": "10.67.0.2", "server_vpn_ip": "10.67.0.1",
        "prefix_len": 24, "mtu": 1280, "mdh_len": 24
    });
    let assignment: aivpn_desktop_agent::worker_protocol::InterfaceAssignment =
        serde_json::from_value(value.clone()).unwrap();
    assignment.validate().unwrap();
    assert_eq!(serde_json::to_value(assignment).unwrap(), value);
}

#[cfg(feature = "local-profile")]
#[test]
fn confirmed_network_preserves_ipv6_and_rejects_invalid_family_metadata() {
    use aivpn_common::network_config::ClientNetworkConfig;
    use aivpn_desktop_agent::worker_protocol::InterfaceAssignment;
    let mut config = ClientNetworkConfig::from_legacy_address("10.0.0.2".parse().unwrap());
    config.ipv6_address = Some("fd00:67::2".into());
    config.ipv6_prefix_len = Some(64);
    let assignment = InterfaceAssignment::from_config(&config).unwrap();
    assert_eq!(assignment.ipv6.unwrap().address.to_string(), "fd00:67::2");
    for address in ["::", "::1", "ff02::1", "::ffff:192.0.2.2"] {
        config.ipv6_address = Some(address.into());
        assert!(
            InterfaceAssignment::from_config(&config).is_err(),
            "{address}"
        );
    }
    config.ipv6_address = Some("fd00:67::2".into());
    for prefix in [None, Some(0), Some(97), Some(128)] {
        config.ipv6_prefix_len = prefix;
        assert!(
            InterfaceAssignment::from_config(&config).is_err(),
            "{prefix:?}"
        );
    }
    let mut malformed = assignment;
    malformed.ipv6.as_mut().unwrap().prefix_len = 0;
    assert!(malformed.validate().is_err());
    malformed = assignment;
    malformed.mtu = 1279;
    assert!(malformed.validate().is_err());
}
