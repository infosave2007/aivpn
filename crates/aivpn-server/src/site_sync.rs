//! Площадки site-to-site поверх masked PoolDialer.
//!
//! Здесь конфиг, разбор RouteSync, допуск источника по `remote_subnets` и
//! установка маршрутов. Исходящий SitePeer, счетчики nonce и синтетические
//! сессии сняты: живой канал это handshake dialer, site keypair и PSK.
//! Решения allowlist и advert принимают конфиг аргументом. `SITE_CONFIG`
//! нужен только рантайму после `init_config_only`.

use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;

use serde::Deserialize;
use tracing::{info, warn};

const MAX_SUBNETS_JSON_BYTES: usize = 4096;
const MAX_SUBNETS_PER_MSG: usize = 64;

/// Конфиг площадок на время процесса. Тесты его не заполняют.
static SITE_CONFIG: OnceLock<SiteToSiteConfig> = OnceLock::new();
static SITE_TUN: OnceLock<String> = OnceLock::new();

/// Один сосед площадки.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SitePeerConfig {
    pub name: String,
    /// `host:port` VPN соседа.
    pub endpoint: String,
    /// 32 байта BLAKE3, base64. Должен совпасть с конфигом соседа.
    pub sync_key: String,
    /// Подсети, которые сосед имеет право анонсировать и с которых может слать SiteData.
    #[serde(default)]
    pub remote_subnets: Vec<String>,
    /// `node_id`, которым сосед представляется в masked RouteSync.
    /// Пусто: сравнение идет по `name`.
    #[serde(default)]
    pub node_id: Option<String>,
}

/// Блок `"site_to_site"` в server.json.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SiteToSiteConfig {
    /// Имя этой площадки. Dialer берет его как node_id, если у пула id нет.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_name: Option<String>,
    /// Локальные подсети, которые dialer анонсирует соседям.
    #[serde(default)]
    pub local_subnets: Vec<String>,
    #[serde(default)]
    pub peers: Vec<SitePeerConfig>,
}

/// Запомнить конфиг, не запуская транспорт.
pub fn init_config_only(config: &SiteToSiteConfig, tun_name: &str) -> Result<(), String> {
    if !private_iface_name(tun_name) {
        return Err("Invalid site TUN interface".into());
    }
    SITE_TUN
        .set(tun_name.to_string())
        .map_err(|_| "Site routing already initialized")?;
    SITE_CONFIG
        .set(config.clone())
        .map_err(|_| "Site configuration already initialized".into())
}

/// Куда отдать внутренний пакет площадки.
pub(crate) enum SiteDestination {
    Peer(String),
    Ambiguous,
}

enum PrefixClass {
    Miss,
    Unique(u8),
    Tie(u8),
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// CIDR без лишних символов. Длина префикса в диапазоне семьи адреса.
fn parse_cidr(cidr: &str) -> Option<(IpAddr, u8)> {
    let (addr_str, prefix_str) = cidr.split_once('/')?;
    if addr_str.is_empty()
        || prefix_str.is_empty()
        || !prefix_str.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    if prefix_str.len() > 1 && prefix_str.starts_with('0') {
        return None;
    }
    let prefix: u8 = prefix_str.parse().ok()?;
    let addr: IpAddr = addr_str.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if u32::from(prefix) > max {
        return None;
    }
    Some((addr, prefix))
}

fn contains(network: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (network, ip) {
        (IpAddr::V4(net), IpAddr::V4(host)) => {
            let mask = v4_mask(prefix);
            u32::from(net) & mask == u32::from(host) & mask
        }
        (IpAddr::V6(net), IpAddr::V6(host)) => {
            let mask = v6_mask(prefix);
            u128::from(net) & mask == u128::from(host) & mask
        }
        _ => false,
    }
}

fn host_bits_clear(addr: IpAddr, prefix: u8) -> bool {
    match addr {
        IpAddr::V4(v4) => u32::from(v4) & !v4_mask(prefix) == 0,
        IpAddr::V6(v6) => u128::from(v6) & !v6_mask(prefix) == 0,
    }
}

fn matching_prefix_len(cidr: &str, ip: IpAddr) -> Option<u8> {
    let (network, prefix) = parse_cidr(cidr)?;
    contains(network, prefix, ip).then_some(prefix)
}

/// Самый длинный префикс. Два совпадения одной длины: отказ.
fn classify_prefixes(subnets: &[String], ip: IpAddr) -> PrefixClass {
    let mut best: Option<u8> = None;
    let mut tie = false;
    for subnet in subnets {
        let Some(len) = matching_prefix_len(subnet, ip) else {
            continue;
        };
        match best {
            None => best = Some(len),
            Some(current) if len > current => {
                best = Some(len);
                tie = false;
            }
            Some(current) if len == current => tie = true,
            _ => {}
        }
    }
    match best {
        Some(len) if tie => PrefixClass::Tie(len),
        Some(len) => PrefixClass::Unique(len),
        None => PrefixClass::Miss,
    }
}

/// Источник входит в список, если выигрывает ровно один самый длинный префикс.
/// IPv4 и IPv6 не пересекаются. Равные префиксы закрывают допуск.
pub(crate) fn source_in_subnets(subnets: &[String], source: impl Into<IpAddr>) -> bool {
    matches!(
        classify_prefixes(subnets, source.into()),
        PrefixClass::Unique(_)
    )
}

fn single_peer(
    peers: &[SitePeerConfig],
    mut pred: impl FnMut(&SitePeerConfig) -> bool,
) -> Option<&SitePeerConfig> {
    let mut found = None;
    for peer in peers {
        if pred(peer) {
            if found.is_some() {
                return None;
            }
            found = Some(peer);
        }
    }
    found
}

fn peer_matches_node(peer: &SitePeerConfig, node_id: &str) -> bool {
    let node_id = node_id.trim();
    if node_id.is_empty() {
        return false;
    }
    match peer
        .node_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
    {
        Some(configured) => configured == node_id,
        None => peer.name == node_id,
    }
}

fn source_allowed_for_node_in(
    config: &SiteToSiteConfig,
    node_id: Option<&str>,
    source: impl Into<IpAddr>,
) -> bool {
    let Some(node_id) = node_id.map(str::trim).filter(|id| !id.is_empty()) else {
        return false;
    };
    let Some(peer) = single_peer(&config.peers, |peer| peer_matches_node(peer, node_id)) else {
        return false;
    };
    source_in_subnets(&peer.remote_subnets, source)
}

fn source_allowed_for_endpoint_in(
    config: &SiteToSiteConfig,
    endpoint: &str,
    source: impl Into<IpAddr>,
) -> bool {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return false;
    }
    let Some(peer) = single_peer(&config.peers, |peer| peer.endpoint.trim() == endpoint) else {
        return false;
    };
    source_in_subnets(&peer.remote_subnets, source)
}

/// Источник разрешен только подсетям одной площадки с этим node_id.
/// Чужой, пустой или повторенный id: отказ.
pub(crate) fn source_allowed_for_node(node_id: Option<&str>, source: impl Into<IpAddr>) -> bool {
    let Some(config) = SITE_CONFIG.get() else {
        return false;
    };
    source_allowed_for_node_in(config, node_id, source)
}

/// То же правило, ключ: endpoint конкретной dial-сессии.
pub(crate) fn source_allowed_for_endpoint(endpoint: &str, source: impl Into<IpAddr>) -> bool {
    let Some(config) = SITE_CONFIG.get() else {
        return false;
    };
    source_allowed_for_endpoint_in(config, endpoint, source)
}

fn site_destination_in(
    peers: &[SitePeerConfig],
    dst: impl Into<IpAddr>,
) -> Option<SiteDestination> {
    let ip = dst.into();
    let mut best: Option<u8> = None;
    let mut endpoint: Option<&str> = None;
    let mut ambiguous = false;
    for peer in peers {
        let (len, unique) = match classify_prefixes(&peer.remote_subnets, ip) {
            PrefixClass::Miss => continue,
            PrefixClass::Unique(len) => (len, Some(peer.endpoint.as_str())),
            PrefixClass::Tie(len) => (len, None),
        };
        match best {
            Some(current) if len < current => {}
            Some(current) if len == current => {
                ambiguous = true;
                endpoint = None;
            }
            _ => {
                best = Some(len);
                ambiguous = unique.is_none();
                endpoint = unique;
            }
        }
    }
    best?;
    if ambiguous {
        return Some(SiteDestination::Ambiguous);
    }
    endpoint.map(|value| SiteDestination::Peer(value.to_string()))
}

/// Ровно одна площадка с самым длинным префиксом. Равная длина: `Ambiguous`.
pub(crate) fn site_destination_for(dst: impl Into<IpAddr>) -> Option<SiteDestination> {
    let config = SITE_CONFIG.get()?;
    site_destination_in(&config.peers, dst)
}

enum RouteSyncPayload {
    Masked {
        node_id: String,
        subnets: Vec<String>,
    },
}

enum Advertiser {
    NodeId(String),
}

/// RouteSync всегда содержит node_id. Старый массив не доказывает личность.
fn parse_route_sync_payload(subnets_json: &[u8]) -> Option<RouteSyncPayload> {
    #[derive(Deserialize)]
    struct MaskedForm {
        #[serde(default)]
        node_id: String,
        #[serde(default)]
        subnets: Vec<String>,
    }

    let value: serde_json::Value = serde_json::from_slice(subnets_json).ok()?;
    match value {
        serde_json::Value::Object(_) => {
            let parsed: MaskedForm = serde_json::from_value(value).ok()?;
            if parsed.node_id.is_empty() {
                return None;
            }
            Some(RouteSyncPayload::Masked {
                node_id: parsed.node_id,
                subnets: parsed.subnets,
            })
        }
        _ => None,
    }
}

fn authorized_subnets_for<'a>(
    config: &'a SiteToSiteConfig,
    advertiser: &Advertiser,
    advertised: &[String],
) -> Option<(&'a SitePeerConfig, Vec<String>)> {
    let peer = match advertiser {
        Advertiser::NodeId(node_id) => {
            single_peer(&config.peers, |peer| peer_matches_node(peer, node_id))?
        }
    };
    let authorized: Vec<String> = advertised
        .iter()
        .filter(|subnet| peer.remote_subnets.iter().any(|own| own == *subnet))
        .cloned()
        .collect();
    Some((peer, authorized))
}

/// Подсети, которые можно ставить в ядро. Глобальный конфиг не читается.
fn plan_route_installs(
    config: &SiteToSiteConfig,
    subnets_json: &[u8],
    from_addr: &str,
    verified_node_id: Option<&str>,
) -> Vec<String> {
    let _from_socket: SocketAddr = match from_addr.parse() {
        Ok(addr) => addr,
        Err(_) => {
            warn!("site_sync: адрес отправителя {from_addr} не разобран, advert отброшен");
            return Vec::new();
        }
    };
    if subnets_json.len() > MAX_SUBNETS_JSON_BYTES {
        warn!(
            "site_sync: RouteSync {} байт от {} больше лимита, advert отброшен",
            subnets_json.len(),
            from_addr
        );
        return Vec::new();
    }
    let payload = match parse_route_sync_payload(subnets_json) {
        Some(payload) => payload,
        None => {
            warn!("site_sync: RouteSync от {from_addr} не разобран, advert отброшен");
            return Vec::new();
        }
    };
    let (advertiser, advertised) = match payload {
        RouteSyncPayload::Masked {
            node_id: claimed,
            subnets,
        } => {
            let node = match verified_node_id.map(str::trim).filter(|id| !id.is_empty()) {
                Some(verified) => {
                    if claimed != verified {
                        warn!(
                            "site_sync: RouteSync от {from_addr} проверен как {verified}, \
                             в теле заявлен {claimed}, берется проверенный id"
                        );
                    }
                    verified.to_string()
                }
                None => {
                    warn!(
                        "site_sync: RouteSync от {from_addr} без проверенного id, \
                         берется самозаявленный {claimed}"
                    );
                    claimed
                }
            };
            (Advertiser::NodeId(node), subnets)
        }
    };
    if advertised.len() > MAX_SUBNETS_PER_MSG {
        warn!(
            "site_sync: RouteSync от {from_addr} содержит {} подсетей, лимит {MAX_SUBNETS_PER_MSG}",
            advertised.len()
        );
        return Vec::new();
    }
    let Some((peer, authorized)) = authorized_subnets_for(config, &advertiser, &advertised) else {
        warn!("site_sync: RouteSync от {from_addr} не совпал ни с одной площадкой, отказ");
        return Vec::new();
    };
    let mut install = Vec::new();
    for subnet in &advertised {
        if !authorized.iter().any(|own| own == subnet) {
            warn!(
                "site_sync: подсеть {subnet} вне allowlist площадки {}, пропуск",
                peer.name
            );
            continue;
        }
        if !subnet_installable(subnet) {
            warn!(
                "site_sync: подсеть {subnet} площадки {} не проходит проверку CIDR, пропуск",
                peer.name
            );
            continue;
        }
        if !install.iter().any(|have: &String| have == subnet) {
            install.push(subnet.clone());
        }
    }
    install
}

/// Входящий RouteSync. Сессия уже проверена вызывающим кодом.
pub fn handle_route_sync(subnets_json: &[u8], from_addr: &str, verified_node_id: Option<&str>) {
    let Some(config) = SITE_CONFIG.get() else {
        warn!("site_sync: RouteSync получен, site-to-site не задан, пакет отброшен");
        return;
    };
    let Some(tun_name) = SITE_TUN.get() else {
        return;
    };
    for subnet in plan_route_installs(config, subnets_json, from_addr, verified_node_id) {
        // Внешний endpoint не является шлюзом внутренней подсети: сначала шифруем в TUN.
        info!("site_sync: установка маршрута {subnet} через {tun_name}");
        install_route(&subnet, tun_name);
    }
}

fn is_safe_subnet(cidr: &str) -> bool {
    let Some((addr, prefix)) = parse_cidr(cidr) else {
        return false;
    };
    if prefix == 0 || addr.is_loopback() {
        return false;
    }
    match addr {
        IpAddr::V4(v4) => prefix >= 8 && !v4.is_link_local(),
        IpAddr::V6(v6) => prefix >= 16 && (v6.segments()[0] & 0xffc0) != 0xfe80,
    }
}

fn subnet_installable(cidr: &str) -> bool {
    let Some((addr, prefix)) = parse_cidr(cidr) else {
        return false;
    };
    host_bits_clear(addr, prefix) && is_safe_subnet(cidr)
}

/// Имя интерфейса: `^[a-z][a-z0-9_-]{0,14}$`. Так отсекаются чужие строки в `ip`.
fn private_iface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name.starts_with(|ch: char| ch.is_ascii_lowercase())
        && name
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-')
}

fn route_gateway_host(via: &str) -> &str {
    let via = via.trim();
    if let Some(rest) = via.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
    }
    if via.parse::<IpAddr>().is_ok() {
        return via;
    }
    if let Some((host, port)) = via.rsplit_once(':') {
        if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) {
            return host;
        }
    }
    via
}

enum NextHop {
    Gateway(IpAddr),
    Device(String),
}

fn route_next_hop(via: &str, want_v6: bool) -> Option<NextHop> {
    let host = route_gateway_host(via);
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_unspecified() || ip.is_ipv6() != want_v6 {
            return None;
        }
        return Some(NextHop::Gateway(ip));
    }
    if private_iface_name(host) {
        return Some(NextHop::Device(host.to_string()));
    }
    None
}

/// Аргументы `ip` без имени программы. IPv6 allowlist идет как `ip -6 route`.
fn route_ip_args(subnet: &str, via: &str) -> Option<Vec<String>> {
    if !subnet_installable(subnet) {
        return None;
    }
    let (addr, _) = parse_cidr(subnet)?;
    let hop = route_next_hop(via, addr.is_ipv6())?;
    let mut args = vec![
        if addr.is_ipv6() { "-6" } else { "-4" }.to_string(),
        "route".to_string(),
        "add".to_string(),
        subnet.to_string(),
    ];
    match hop {
        NextHop::Gateway(ip) => {
            args.push("via".to_string());
            args.push(ip.to_string());
        }
        NextHop::Device(name) => {
            args.push("dev".to_string());
            args.push(name);
        }
    }
    Some(args)
}

fn install_route(subnet: &str, via: &str) {
    let Some(args) = route_ip_args(subnet, via) else {
        warn!("site_sync: маршрут {subnet} через {via} не установлен, проверка не пройдена");
        return;
    };
    let shown = args.join(" ");
    match std::process::Command::new("ip").args(&args).status() {
        Ok(status) if status.success() => info!("site_sync: ip {shown} выполнен"),
        Ok(status) => warn!("site_sync: ip {shown} завершился с {status}"),
        Err(err) => warn!("site_sync: ip {shown} не запущен: {err}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn test_sync_key_b64() -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [7u8; 32])
    }

    fn peer(name: &str, endpoint: &str, node_id: Option<&str>, subnets: &[&str]) -> SitePeerConfig {
        SitePeerConfig {
            name: name.to_string(),
            endpoint: endpoint.to_string(),
            sync_key: test_sync_key_b64(),
            remote_subnets: subnets.iter().map(|item| (*item).to_string()).collect(),
            node_id: node_id.map(str::to_string),
        }
    }

    fn two_peer_config() -> SiteToSiteConfig {
        SiteToSiteConfig {
            local_name: Some("hq".to_string()),
            local_subnets: vec!["192.168.1.0/24".to_string()],
            peers: vec![
                peer(
                    "office-b",
                    "203.0.113.10:443",
                    Some("office-b-node"),
                    &["192.168.2.0/24"],
                ),
                peer("office-c", "203.0.113.20:443", None, &["10.10.0.0/24"]),
            ],
        }
    }

    fn dualstack_config() -> SiteToSiteConfig {
        SiteToSiteConfig {
            local_name: Some("hq".to_string()),
            local_subnets: vec!["192.168.1.0/24".to_string(), "fd00:1::/64".to_string()],
            peers: vec![
                peer(
                    "office-b",
                    "198.51.100.10:443",
                    Some("office-b-node"),
                    &["10.0.0.0/8", "10.1.0.0/16", "fd00::/32", "fd00:0:1::/48"],
                ),
                peer(
                    "office-c",
                    "198.51.100.11:443",
                    Some("office-c-node"),
                    &["192.168.2.0/24", "fd10::/64"],
                ),
            ],
        }
    }

    #[test]
    fn ipv6_site_routes_are_admitted_over_ipv4_transport() {
        let config = dualstack_config();
        let json = br#"{"node_id":"office-b-node","subnets":["fd00::/32"]}"#;
        assert_eq!(
            plan_route_installs(&config, json, "198.51.100.10:443", Some("office-b-node")),
            vec!["fd00::/32"]
        );
    }

    #[test]
    fn site_sources_are_limited_to_configured_subnets() {
        let subnets = vec!["192.168.2.0/24".to_string(), "invalid/999".to_string()];
        assert!(source_in_subnets(&subnets, ip("192.168.2.10")));
        assert!(!source_in_subnets(&subnets, ip("192.168.3.10")));
        assert!(!source_in_subnets(&subnets, ip("1.2.3.4")));
        assert!(!source_in_subnets(&[], ip("10.0.0.2")));
        assert!(!source_in_subnets(&subnets, ip("fd00::1")));
    }

    #[test]
    fn dualstack_source_allowlist_uses_longest_prefix_and_fails_closed() {
        let config = dualstack_config();
        let broad = &config.peers[0].remote_subnets;
        assert!(source_in_subnets(broad, ip("10.1.2.3")));
        assert!(source_in_subnets(broad, ip("10.2.0.1")));
        assert!(source_in_subnets(broad, ip("fd00:0:1::5")));
        // fd00::/32 покрывает fd00:0::/32. fd00:2::1 уже вне этого префикса.
        assert!(source_in_subnets(broad, ip("fd00:0:2::1")));
        assert!(!source_in_subnets(broad, ip("fd00:2::1")));
        assert!(!source_in_subnets(broad, ip("192.168.2.10")));
        assert!(!source_in_subnets(broad, ip("fd10::1")));
        assert!(!source_in_subnets(broad, ip("2001:db8::1")));

        let tied_v4 = vec!["192.168.2.0/24".to_string(), "192.168.2.0/24".to_string()];
        let tied_v6 = vec!["fd00:2::/64".to_string(), "fd00:2::/64".to_string()];
        assert!(!source_in_subnets(&tied_v4, ip("192.168.2.10")));
        assert!(!source_in_subnets(&tied_v6, ip("fd00:2::10")));

        assert!(source_allowed_for_node_in(
            &config,
            Some("office-b-node"),
            ip("10.1.2.3")
        ));
        assert!(source_allowed_for_node_in(
            &config,
            Some("office-b-node"),
            ip("fd00:0:1::9")
        ));
        assert!(!source_allowed_for_node_in(
            &config,
            Some("office-b-node"),
            ip("192.168.2.10")
        ));
        assert!(!source_allowed_for_node_in(
            &config,
            Some("office-b-node"),
            ip("fd10::1")
        ));
        assert!(!source_allowed_for_node_in(
            &config,
            Some("foreign-node"),
            ip("10.1.2.3")
        ));
        assert!(!source_allowed_for_node_in(
            &config,
            Some("foreign-node"),
            ip("fd00:0:1::9")
        ));
        assert!(!source_allowed_for_node_in(&config, None, ip("10.1.2.3")));
        assert!(!source_allowed_for_endpoint_in(
            &config,
            "198.51.100.10:443",
            ip("fd10::1")
        ));
        assert!(source_allowed_for_endpoint_in(
            &config,
            "198.51.100.11:443",
            ip("fd10::1")
        ));
        assert!(!source_allowed_for_endpoint_in(
            &config,
            "198.51.100.11:443",
            ip("10.1.2.3")
        ));
        assert!(!source_allowed_for_endpoint_in(
            &config,
            "203.0.113.9:443",
            ip("192.168.2.10")
        ));

        let mut duplicated = config.clone();
        duplicated.peers.push(peer(
            "office-b-copy",
            "198.51.100.12:443",
            Some("office-b-node"),
            &["10.1.0.0/16"],
        ));
        assert!(!source_allowed_for_node_in(
            &duplicated,
            Some("office-b-node"),
            ip("10.1.2.3")
        ));
    }

    #[test]
    fn destination_prefers_longest_prefix_and_rejects_equal_prefixes() {
        let peers = vec![
            peer(
                "office-b",
                "198.51.100.10:443",
                Some("office-b-node"),
                &["10.0.0.0/8", "fd00::/32"],
            ),
            peer(
                "office-c",
                "198.51.100.11:443",
                Some("office-c-node"),
                &["10.1.0.0/16", "fd00:0:1::/48", "192.168.2.0/24"],
            ),
            peer(
                "office-d",
                "198.51.100.12:443",
                Some("office-d-node"),
                &["192.168.2.0/24"],
            ),
        ];
        assert!(matches!(
            site_destination_in(&peers, ip("10.1.2.3")),
            Some(SiteDestination::Peer(endpoint)) if endpoint == "198.51.100.11:443"
        ));
        assert!(matches!(
            site_destination_in(&peers, ip("fd00:0:1::5")),
            Some(SiteDestination::Peer(endpoint)) if endpoint == "198.51.100.11:443"
        ));
        assert!(matches!(
            site_destination_in(&peers, ip("10.2.0.1")),
            Some(SiteDestination::Peer(endpoint)) if endpoint == "198.51.100.10:443"
        ));
        assert!(matches!(
            site_destination_in(&peers, ip("192.168.2.10")),
            Some(SiteDestination::Ambiguous)
        ));
        assert!(site_destination_in(&peers, ip("192.0.2.1")).is_none());
        assert!(site_destination_in(&peers, ip("fd10::1")).is_none());
    }

    #[test]
    fn route_gateway_host_parses_all_via_forms() {
        assert_eq!(route_gateway_host("1.2.3.4:443"), "1.2.3.4");
        assert_eq!(route_gateway_host("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(route_gateway_host("2001:db8::1"), "2001:db8::1");
        assert_eq!(route_gateway_host("1.2.3.4"), "1.2.3.4");
        assert_eq!(
            route_gateway_host("peer.example.com:443"),
            "peer.example.com"
        );
    }

    fn arg_text(subnet: &str, via: &str) -> Option<Vec<String>> {
        route_ip_args(subnet, via)
    }

    #[test]
    fn route_args_cover_ipv4_ipv6_and_private_iface_only() {
        assert_eq!(
            arg_text("192.168.2.0/24", "1.2.3.4:443"),
            Some(vec![
                "-4".into(),
                "route".into(),
                "add".into(),
                "192.168.2.0/24".into(),
                "via".into(),
                "1.2.3.4".into()
            ])
        );
        assert_eq!(
            arg_text("fd00:2::/64", "[2001:db8::1]:443"),
            Some(vec![
                "-6".into(),
                "route".into(),
                "add".into(),
                "fd00:2::/64".into(),
                "via".into(),
                "2001:db8::1".into()
            ])
        );
        assert_eq!(
            arg_text("fd00:2::/64", "aivpn0"),
            Some(vec![
                "-6".into(),
                "route".into(),
                "add".into(),
                "fd00:2::/64".into(),
                "dev".into(),
                "aivpn0".into()
            ])
        );
        assert_eq!(
            arg_text("10.8.0.0/16", "tun0"),
            Some(vec![
                "-4".into(),
                "route".into(),
                "add".into(),
                "10.8.0.0/16".into(),
                "dev".into(),
                "tun0".into()
            ])
        );
        assert!(route_ip_args("192.168.2.5/24", "1.2.3.4").is_none());
        assert!(route_ip_args("0.0.0.0/0", "1.2.3.4").is_none());
        assert!(route_ip_args("::/0", "2001:db8::1").is_none());
        assert!(route_ip_args("127.0.0.0/8", "1.2.3.4").is_none());
        assert!(route_ip_args("fe80::/64", "2001:db8::1").is_none());
        assert!(route_ip_args("fd00:2::/64", "203.0.113.10").is_none());
        assert!(route_ip_args("192.168.2.0/24", "2001:db8::1").is_none());
        assert!(route_ip_args("fd00:2::/64", "peer.example.com").is_none());
        assert!(route_ip_args("fd00:2::/64", "BadIface").is_none());
        assert!(route_ip_args("fd00:2::/64", "aivpn0;rm").is_none());
        assert!(route_ip_args("fd00:2::/64", "-6").is_none());
        assert!(source_in_subnets(
            &["192.168.2.5/24".to_string()],
            ip("192.168.2.10")
        ));
    }

    #[test]
    fn masked_advert_known_node_id_authorizes_only_its_own_subnets() {
        let config = two_peer_config();
        let advertiser = Advertiser::NodeId("office-b-node".to_string());
        let advertised = vec!["192.168.2.0/24".to_string()];
        let (peer, authorized) =
            authorized_subnets_for(&config, &advertiser, &advertised).expect("площадка найдена");
        assert_eq!(peer.name, "office-b");
        assert_eq!(authorized, vec!["192.168.2.0/24".to_string()]);
    }

    #[test]
    fn masked_advert_unknown_node_id_fails_closed() {
        let config = two_peer_config();
        let advertiser = Advertiser::NodeId("some-random-attacker-node".to_string());
        let advertised = vec!["192.168.2.0/24".to_string()];
        assert!(authorized_subnets_for(&config, &advertiser, &advertised).is_none());
    }

    #[test]
    fn masked_advert_cannot_claim_another_peers_subnet() {
        let config = two_peer_config();
        let advertiser = Advertiser::NodeId("office-b-node".to_string());
        let advertised = vec!["192.168.2.0/24".to_string(), "10.10.0.0/24".to_string()];
        let (peer, authorized) =
            authorized_subnets_for(&config, &advertiser, &advertised).expect("площадка найдена");
        assert_eq!(peer.name, "office-b");
        assert_eq!(authorized, vec!["192.168.2.0/24".to_string()]);
    }

    #[test]
    fn masked_advert_falls_back_to_name_when_peer_has_no_node_id() {
        let config = two_peer_config();
        let advertiser = Advertiser::NodeId("office-c".to_string());
        let advertised = vec!["10.10.0.0/24".to_string()];
        let (peer, authorized) =
            authorized_subnets_for(&config, &advertiser, &advertised).expect("площадка найдена");
        assert_eq!(peer.name, "office-c");
        assert_eq!(authorized, vec!["10.10.0.0/24".to_string()]);
    }

    #[test]
    fn duplicate_node_id_fails_closed() {
        let mut config = two_peer_config();
        config.peers[1].node_id = Some("office-b-node".to_string());
        let advertiser = Advertiser::NodeId("office-b-node".to_string());
        assert!(
            authorized_subnets_for(&config, &advertiser, &["192.168.2.0/24".to_string()]).is_none()
        );
    }

    #[test]
    fn parse_masked_object_payload() {
        let json = br#"{"node_id":"office-b-node","subnets":["192.168.2.0/24"]}"#;
        match parse_route_sync_payload(json).expect("разбор") {
            RouteSyncPayload::Masked { node_id, subnets } => {
                assert_eq!(node_id, "office-b-node");
                assert_eq!(subnets, vec!["192.168.2.0/24".to_string()]);
            }
        }
    }

    #[test]
    fn route_array_without_identity_is_rejected() {
        assert!(parse_route_sync_payload(br#"["192.168.1.0/24"]"#).is_none());
    }

    #[test]
    fn parse_masked_object_with_empty_node_id_is_unparseable() {
        let json = br#"{"node_id":"","subnets":["192.168.2.0/24"]}"#;
        assert!(parse_route_sync_payload(json).is_none());
    }

    #[test]
    fn handle_route_sync_end_to_end_masked_path_uses_own_allowlist_only() {
        let config = two_peer_config();
        let payload = br#"{"node_id":"office-b-node","subnets":["192.168.2.0/24"]}"#;
        assert_eq!(
            plan_route_installs(&config, payload, "198.51.100.99:54321", None),
            vec!["192.168.2.0/24".to_string()]
        );
        let hijack = br#"{"node_id":"unknown-attacker","subnets":["192.168.2.0/24"]}"#;
        assert!(plan_route_installs(&config, hijack, "198.51.100.99:54321", None).is_empty());
    }

    #[test]
    fn verified_node_id_overrides_self_asserted_node_id_in_masked_payload() {
        let config = two_peer_config();
        let advertiser = Advertiser::NodeId("office-b-node".to_string());
        let advertised = vec!["10.10.0.0/24".to_string(), "192.168.2.0/24".to_string()];
        let (peer, authorized) =
            authorized_subnets_for(&config, &advertiser, &advertised).expect("площадка найдена");
        assert_eq!(peer.name, "office-b");
        assert_eq!(authorized, vec!["192.168.2.0/24".to_string()]);
        assert_ne!("office-c-node", "office-b-node");
    }

    #[test]
    fn handle_route_sync_end_to_end_trusts_verified_node_id_over_payload() {
        let config = two_peer_config();
        let payload = br#"{"node_id":"office-c-node","subnets":["10.10.0.0/24","192.168.2.0/24"]}"#;
        assert_eq!(
            plan_route_installs(
                &config,
                payload,
                "198.51.100.99:54322",
                Some("office-b-node")
            ),
            vec!["192.168.2.0/24".to_string()]
        );
    }

    #[test]
    fn foreign_node_route_advert_installs_nothing() {
        let config = dualstack_config();
        let stolen = br#"{"node_id":"office-c-node","subnets":["192.168.2.0/24","fd10::/64"]}"#;
        assert!(
            plan_route_installs(&config, stolen, "198.51.100.99:9", Some("office-b-node"))
                .is_empty()
        );
        let stranger = br#"{"node_id":"office-b-node","subnets":["10.1.0.0/16","fd00:0:1::/48"]}"#;
        assert!(
            plan_route_installs(&config, stranger, "198.51.100.99:9", Some("foreign-node"))
                .is_empty()
        );
        let claimed = br#"{"node_id":"stranger","subnets":["10.1.0.0/16","fd10::/64"]}"#;
        assert!(plan_route_installs(&config, claimed, "198.51.100.99:9", None).is_empty());
        let own_v4 = br#"{"node_id":"office-c-node","subnets":["192.168.2.0/24","10.1.0.0/16"]}"#;
        assert_eq!(
            plan_route_installs(&config, own_v4, "198.51.100.11:443", Some("office-c-node")),
            vec!["192.168.2.0/24".to_string()]
        );
        let own_v6 = br#"{"node_id":"office-c-node","subnets":["fd10::/64","fd00:0:1::/48"]}"#;
        assert_eq!(
            plan_route_installs(&config, own_v6, "[2001:db8::11]:443", Some("office-c-node")),
            vec!["fd10::/64".to_string()]
        );
    }

    #[tokio::test]
    async fn udp_allowlist_rejects_foreign_source_then_accepts_own() {
        let subnets = vec!["192.168.2.0/24".to_string(), "fd00:2::/64".to_string()];
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let mut packet = [0u8; 20];
        packet[0] = 0x45;
        packet[2] = 0;
        packet[3] = 20;
        packet[12] = 10;
        packet[13] = 9;
        packet[14] = 9;
        packet[15] = 9;
        sender.send_to(&packet, dest).await.unwrap();
        let mut buf = [0u8; 64];
        let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
        let parsed = aivpn_common::ip_packet::IpPacket::parse(&buf[..n]).unwrap();
        assert!(!source_in_subnets(&subnets, parsed.source));

        packet[12] = 192;
        packet[13] = 168;
        packet[14] = 2;
        packet[15] = 10;
        sender.send_to(&packet, dest).await.unwrap();
        let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
        let parsed = aivpn_common::ip_packet::IpPacket::parse(&buf[..n]).unwrap();
        assert!(source_in_subnets(&subnets, parsed.source));

        let mut v6 = vec![0u8; 48];
        v6[0] = 0x60;
        v6[4..6].copy_from_slice(&8u16.to_be_bytes());
        v6[6] = 59;
        let foreign: Ipv6Addr = "fd10::1".parse().unwrap();
        let own: Ipv6Addr = "fd00:2::10".parse().unwrap();
        v6[8..24].copy_from_slice(&foreign.octets());
        let parsed = aivpn_common::ip_packet::IpPacket::parse(&v6).unwrap();
        assert!(!source_in_subnets(&subnets, parsed.source));
        v6[8..24].copy_from_slice(&own.octets());
        let parsed = aivpn_common::ip_packet::IpPacket::parse(&v6).unwrap();
        assert!(source_in_subnets(&subnets, parsed.source));
        assert!(!source_in_subnets(
            &["192.168.2.0/24".to_string()],
            IpAddr::V6(own)
        ));
    }
}
