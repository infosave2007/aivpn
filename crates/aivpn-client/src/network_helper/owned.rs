//! Помощник изменяет собственные маршруты, сохраняя существующие записи ядра.
use super::batch::ParsedCommand;
use std::{collections::BTreeMap, io, net::IpAddr};

const PROTOCOL: &str = "244";
const METRIC_BASE: u32 = 0xa17e0000;

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Операция не принадлежит сетевому сеансу",
    )
}
fn query(family: &str, args: &[&str]) -> io::Result<Vec<serde_json::Value>> {
    let output = crate::Tunnel::system_ip()?
        .args(["-j", family, "route"])
        .args(args)
        .output()?;
    if !output.status.success() || output.stdout.len() > 1024 * 1024 {
        return Err(denied());
    }
    serde_json::from_slice(&output.stdout).map_err(io::Error::other)
}
fn ip(args: &[String]) -> io::Result<i32> {
    Ok(crate::Tunnel::net_admin_command("ip")
        .args(args)
        .status()?
        .code()
        .unwrap_or(-1))
}
fn field<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    args.windows(2).find(|p| p[0] == key).map(|p| p[1].as_str())
}
fn family(ip: IpAddr) -> &'static str {
    if ip.is_ipv6() {
        "-6"
    } else {
        "-4"
    }
}
#[derive(Clone)]
struct Peer {
    address: IpAddr,
    device: String,
    gateway: Option<String>,
}
#[derive(Clone)]
struct Route {
    family: String,
    prefix: String,
    body: Vec<String>,
}
impl Route {
    fn command(&self, action: &str, metric: u32) -> Vec<String> {
        let mut args = vec![self.family.clone(), "route".into(), action.into()];
        args.extend(self.body.clone());
        args.extend([
            "proto".into(),
            PROTOCOL.into(),
            "metric".into(),
            metric.to_string(),
        ]);
        args
    }
}
enum Plan {
    Command(Vec<String>),
    Put(Route),
    Delete(String, String),
    Ignore,
}

pub(super) struct OwnedIp {
    metric: u32,
    peer: Option<Peer>,
    routes: BTreeMap<(String, String), Route>,
}
impl OwnedIp {
    pub(super) fn new() -> Self {
        Self {
            metric: METRIC_BASE | rand::random::<u16>() as u32,
            peer: None,
            routes: BTreeMap::new(),
        }
    }
    pub(super) fn set_peer(&mut self, address: IpAddr) -> io::Result<()> {
        if self.peer.as_ref().is_some_and(|p| p.address == address) {
            return Ok(());
        }
        if !self.routes.is_empty() {
            return Err(denied());
        }
        let rows = query(family(address), &["get", &address.to_string()])?;
        let row = rows.first().ok_or_else(denied)?;
        self.peer = Some(Peer {
            address,
            device: row["dev"].as_str().ok_or_else(denied)?.into(),
            gateway: row["gateway"].as_str().map(str::to_owned),
        });
        Ok(())
    }
    fn plan(&self, argv: &[String], tun: &str) -> io::Result<Plan> {
        let (family, args) = if argv.first().is_some_and(|v| v == "-6") {
            ("-6", &argv[1..])
        } else {
            ("-4", argv)
        };
        if args.first().is_some_and(|v| v == "link" || v == "addr") {
            if field(args, "dev") != Some(tun) {
                return Err(denied());
            }
            return Ok(Plan::Command(argv.to_vec()));
        }
        if args.len() < 3 || args[0] != "route" {
            return Err(denied());
        }
        let blackhole = args[2] == "blackhole";
        let prefix = args
            .get(if blackhole { 3 } else { 2 })
            .ok_or_else(denied)?
            .clone();
        if prefix == "default" {
            return Err(denied());
        }
        if args[1] == "del" {
            return Ok(Plan::Delete(family.into(), prefix));
        }
        if args[1] != "add" && args[1] != "replace" {
            return Err(denied());
        }
        let mut body = args[2..].to_vec();
        // Исходные proto/metric клиента не дают прав на удаление маршрута.
        for key in ["proto", "metric"] {
            if let Some(index) = body.iter().position(|v| v == key) {
                body.drain(index..index + 2);
            }
        }
        let own_tun = field(args, "dev") == Some(tun);
        let block = blackhole && family == "-6" && matches!(prefix.as_str(), "::/1" | "8000::/1");
        if !own_tun && !block {
            let peer = self.peer.as_ref().ok_or_else(denied)?;
            let host = prefix
                .split('/')
                .next()
                .and_then(|v| v.parse::<IpAddr>().ok());
            let host_prefix = if peer.address.is_ipv6() { 128 } else { 32 };
            let exact = prefix
                .split_once('/')
                .is_none_or(|(_, p)| p.parse::<u8>() == Ok(host_prefix));
            if host == Some(peer.address) && exact {
                body = vec![prefix.clone()];
                if let Some(gateway) = &peer.gateway {
                    body.extend(["via".into(), gateway.clone()]);
                }
                body.extend(["dev".into(), peer.device.clone()]);
                if peer.gateway.is_some() {
                    body.push("onlink".into());
                }
            } else if field(args, "scope") == Some("link") {
                // Старый fallback добавлял host route шлюза даже после успеха bypass.
                let rows = query(family, &["show", "default"])?;
                if rows.iter().any(|r| {
                    r["gateway"].as_str() == Some(prefix.as_str())
                        && r["dev"].as_str() == field(args, "dev")
                }) {
                    return Ok(Plan::Ignore);
                }
                return Err(denied());
            } else if field(args, "proto") == Some("242") {
                let rows = query(family, &["show", "default"])?;
                if !rows.iter().any(|r| {
                    r["dev"].as_str() == field(args, "dev")
                        && r["gateway"].as_str() == field(args, "via")
                }) {
                    return Err(denied());
                }
            } else {
                return Err(denied());
            }
        }
        Ok(Plan::Put(Route {
            family: family.into(),
            prefix,
            body,
        }))
    }
    fn is_ours(&self, row: &serde_json::Value, key: &(String, String)) -> bool {
        let Some(route) = self.routes.get(key) else {
            return false;
        };
        let kind = if route.body.first().map(String::as_str) == Some("blackhole") {
            "blackhole"
        } else {
            "unicast"
        };
        if row["type"].as_str().unwrap_or("unicast") != kind {
            return false;
        }
        if row["dev"].as_str() != field(&route.body, "dev")
            || row["gateway"].as_str() != field(&route.body, "via")
        {
            return false;
        }
        (row["protocol"].as_str() == Some(PROTOCOL) || row["protocol"].as_u64() == Some(244))
            && row["metric"].as_u64() == Some(self.metric as u64)
    }
    fn remove(&mut self, key: &(String, String)) -> io::Result<()> {
        if let Some(route) = self.routes.get(key) {
            let rows = query(&route.family, &["show", "exact", &route.prefix])?;
            if rows.iter().any(|r| self.is_ours(r, key))
                && ip(&route.command("del", self.metric))? != 0
            {
                return Err(denied());
            }
        }
        self.routes.remove(key);
        Ok(())
    }
    fn put(&mut self, route: Route, tun: &str) -> io::Result<i32> {
        let key = (route.family.clone(), route.prefix.clone());
        if self.routes.len() >= 65536 && !self.routes.contains_key(&key) {
            return Err(io::Error::other("Превышен размер журнала маршрутов"));
        }
        let rows = query(&route.family, &["show", "exact", &route.prefix])?;
        let foreign: Vec<_> = rows.iter().filter(|r| !self.is_ours(r, &key)).collect();
        if !foreign.is_empty() {
            // Уже существующий собственный connected route или подходящий обход
            // сохраняется. Он не попадает в журнал и не удаляется при отключении.
            let compatible = foreign.iter().all(|r| {
                if route.body.first().map(String::as_str) == Some("blackhole") {
                    return matches!(
                        r["type"].as_str(),
                        Some("blackhole" | "unreachable" | "prohibit")
                    );
                }
                r["dev"].as_str() == Some(tun)
                    || (r["dev"].as_str() == field(&route.body, "dev")
                        && r["gateway"].as_str() == field(&route.body, "via"))
            });
            return if compatible { Ok(0) } else { Err(denied()) };
        }
        if self.routes.get(&key).is_some_and(|r| r.body == route.body)
            && rows.iter().any(|r| self.is_ours(r, &key))
        {
            return Ok(0);
        }
        self.remove(&key)?;
        // Запись до вызова позволяет убрать остаток при обычном отказе команды.
        self.routes.insert(key.clone(), route.clone());
        let code = ip(&route.command("add", self.metric))?;
        if code != 0 {
            self.routes.remove(&key);
        }
        Ok(code)
    }
    pub(super) fn apply(
        &mut self,
        commands: Vec<ParsedCommand>,
        tun: &str,
    ) -> io::Result<Vec<(String, i32)>> {
        let plans = commands
            .iter()
            .map(|c| self.plan(&c.argv, tun))
            .collect::<io::Result<Vec<_>>>()?;
        let mut statuses = Vec::new();
        for (command, plan) in commands.into_iter().zip(plans) {
            let code = match plan {
                Plan::Command(argv) => ip(&argv)?,
                Plan::Put(route) => self.put(route, tun)?,
                Plan::Delete(family, prefix) => {
                    self.remove(&(family, prefix))?;
                    0
                }
                Plan::Ignore => 0,
            };
            statuses.push((command.name, code));
        }
        Ok(statuses)
    }
    pub(super) fn clear(&mut self) -> io::Result<()> {
        for key in self.routes.keys().cloned().collect::<Vec<_>>() {
            self.remove(&key)?;
        }
        self.peer = None;
        Ok(())
    }
}
impl Drop for OwnedIp {
    fn drop(&mut self) {
        let keys = self
            .routes
            .iter()
            .filter(|(_, r)| r.body.first().map(String::as_str) != Some("blackhole"))
            .map(|(k, _)| k.clone())
            .collect::<Vec<_>>();
        for key in keys {
            let _ = self.remove(&key);
        }
    }
}

/// Только явное административное восстановление, вне кешируемой роли.
pub(super) fn clear_stale() -> io::Result<()> {
    for family in ["-4", "-6"] {
        for row in query(family, &["show", "proto", PROTOCOL])? {
            let Some(metric) = row["metric"]
                .as_u64()
                .filter(|m| *m <= u32::MAX as u64 && (*m as u32 & 0xffff0000) == METRIC_BASE)
            else {
                continue;
            };
            let Some(prefix) = row["dst"].as_str() else {
                continue;
            };
            let mut body = Vec::new();
            if row["type"].as_str() == Some("blackhole") {
                body.push("blackhole".into());
            }
            body.push(prefix.into());
            if ip(&Route {
                family: family.into(),
                prefix: prefix.into(),
                body,
            }
            .command("del", metric as u32))?
                != 0
            {
                return Err(denied());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(value: &str) -> Vec<String> {
        value.split_whitespace().map(str::to_owned).collect()
    }
    #[test]
    fn denies_foreign_interface_and_unbound_bypass() {
        let owner = OwnedIp::new();
        for command in [
            "link set dev eth0 mtu 9000",
            "addr replace 10.0.0.2/24 dev eth0",
            "route replace 10.0.0.0/8 dev eth0",
            "route replace 1.1.1.1 via 192.0.2.1 dev eth0",
        ] {
            assert!(owner.plan(&args(command), "tun0").is_err(), "{command}");
        }
        assert!(owner
            .plan(&args("link set dev tun0 mtu 1280"), "tun0")
            .is_ok());
    }
    #[test]
    fn derives_peer_route_from_kernel_snapshot() {
        let mut owner = OwnedIp::new();
        owner.peer = Some(Peer {
            address: "192.0.2.1".parse().unwrap(),
            device: "wan0".into(),
            gateway: None,
        });
        let Plan::Put(route) = owner
            .plan(
                &args("route replace 192.0.2.1 via 10.0.2.2 dev eth0"),
                "tun0",
            )
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(route.body, args("192.0.2.1 dev wan0"));
        assert!(owner
            .plan(
                &args("route replace 192.0.2.0/24 via 10.0.2.2 dev eth0"),
                "tun0"
            )
            .is_err());
    }
}
