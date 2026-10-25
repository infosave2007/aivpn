use crate::key_storage::ConnectionKey;
use crate::vpn_manager::ConnectionState;

pub fn can_edit_network(state: ConnectionState) -> bool {
    state == ConnectionState::Disconnected
}

pub struct RouteDraft {
    pub index: usize,
    key_identity: String,
    pub full_tunnel: bool,
    pub proxy: bool,
    pub proxy_addr: String,
    pub include: String,
    pub exclude: String,
    pub dns: String,
}

impl RouteDraft {
    pub fn new(index: usize, key: &ConnectionKey, dns: &str) -> Self {
        Self {
            index,
            key_identity: key.key.clone(),
            full_tunnel: key.full_tunnel,
            proxy: key.proxy_listen.is_some(),
            proxy_addr: key
                .proxy_listen
                .clone()
                .unwrap_or_else(|| "127.0.0.1:1080".into()),
            include: key.include_routes.join("\n"),
            exclude: key.exclude_routes.join("\n"),
            dns: dns.into(),
        }
    }

    pub fn matches(&self, index: usize, key: &ConnectionKey) -> bool {
        self.index == index && self.key_identity == key.key
    }
}

pub fn route_lines(value: &str) -> Vec<String> {
    value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn key(server: &str) -> ConnectionKey {
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!(r#"{{"s":"{server}"}}"#));
        ConnectionKey::from_key_string("Пример", &raw).unwrap()
    }

    #[test]
    fn cannot_write_network_or_profiles_during_any_live_transition() {
        assert!(can_edit_network(ConnectionState::Disconnected));
        for state in [
            ConnectionState::Connecting,
            ConnectionState::Connected,
            ConnectionState::Disconnecting,
        ] {
            assert!(!can_edit_network(state), "{state:?}");
        }
    }

    #[test]
    fn stale_route_form_cannot_apply_to_replaced_profile_at_same_index() {
        let first = key("first.example.invalid:443");
        let other = key("other.example.invalid:443");
        let draft = RouteDraft::new(1, &first, "127.0.0.1:5353");
        assert!(draft.matches(1, &first));
        assert!(!draft.matches(0, &first));
        assert!(!draft.matches(1, &other));
    }

    #[test]
    fn route_draft_keeps_profile_routes_separate_from_global_dns() {
        let mut profile = key("example.invalid:443");
        profile.full_tunnel = true;
        profile.include_routes = vec!["10.20.0.0/16".into()];
        profile.exclude_routes = vec!["192.168.0.0/16".into()];
        let draft = RouteDraft::new(0, &profile, "127.0.0.1:5353");
        assert_eq!(draft.include, "10.20.0.0/16");
        assert_eq!(draft.exclude, "192.168.0.0/16");
        assert!(draft.full_tunnel && !draft.proxy);
        assert_eq!(draft.dns, "127.0.0.1:5353");
        assert_eq!(
            route_lines(" \n 10.0.0.0/8 \r\n\n ::/0 "),
            vec!["10.0.0.0/8", "::/0"]
        );
    }
}
