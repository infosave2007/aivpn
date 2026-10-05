//! Отдельная таблица исходных маршрутов для помеченных сокетов транспорта.
use crate::tunnel::Tunnel;
use std::{io, process::Command};

pub(crate) struct TransportRoutes {
    table: u32,
    mark: u32,
    families: Vec<&'static str>,
}

fn ip(args: &[String]) -> io::Result<()> {
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    if Tunnel::run_ip_privileged(&borrowed)? != 0 {
        return Err(io::Error::other("не удалось настроить обход туннеля"));
    }
    Ok(())
}

fn route_args(family: &str, table: u32, line: &str) -> Option<Vec<String>> {
    let words: Vec<&str> = line.split_whitespace().collect();
    if words.first() != Some(&"default") {
        return None;
    }
    let device = words.windows(2).find(|pair| pair[0] == "dev")?[1];
    if device.len() > 15
        || !device
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-:".contains(&c))
    {
        return None;
    }
    let mut args = vec![
        family.into(),
        "route".into(),
        "add".into(),
        "table".into(),
        table.to_string(),
        "default".into(),
    ];
    if let Some(pair) = words.windows(2).find(|pair| pair[0] == "via") {
        pair[1].parse::<std::net::IpAddr>().ok()?;
        args.extend(["via".into(), pair[1].into()]);
    }
    args.extend(["dev".into(), device.into()]);
    if words.iter().any(|word| *word == "via") {
        args.push("onlink".into());
    }
    Some(args)
}

impl TransportRoutes {
    pub(crate) fn install(mark: u32) -> io::Result<Self> {
        if mark == 0 {
            return Err(io::Error::other("нулевая метка транспорта"));
        }
        let table = (0..64)
            .find_map(|_| {
                let candidate = 10000 + rand::random::<u32>() % 20000;
                for family in ["-4", "-6"] {
                    for query in [
                        vec![family, "rule", "show", "pref"],
                        vec![family, "route", "show", "table"],
                    ] {
                        let output = Command::new("ip")
                            .args(query)
                            .arg(candidate.to_string())
                            .output()
                            .ok()?;
                        if !output.stdout.is_empty() {
                            return None;
                        }
                    }
                }
                Some(candidate)
            })
            .ok_or_else(|| io::Error::other("нет свободной таблицы маршрутов"))?;
        let mut result = Self {
            table,
            mark,
            families: Vec::new(),
        };
        for family in ["-4", "-6"] {
            let output = Command::new("ip")
                .args([family, "route", "show", "default"])
                .output()?;
            if !output.status.success() {
                return Err(io::Error::other("не удалось прочитать исходный маршрут"));
            }
            let text = String::from_utf8_lossy(&output.stdout);
            let Some(args) = text
                .lines()
                .find_map(|line| route_args(family, table, line))
            else {
                continue;
            };
            result.families.push(family);
            ip(&args)?;
            ip(&[
                family.into(),
                "rule".into(),
                "add".into(),
                "pref".into(),
                table.to_string(),
                "fwmark".into(),
                mark.to_string(),
                "lookup".into(),
                table.to_string(),
            ])?;
        }
        if result.families.is_empty() {
            return Err(io::Error::other("нет исходного маршрута для транспорта"));
        }
        Ok(result)
    }
}
impl Drop for TransportRoutes {
    fn drop(&mut self) {
        for family in &self.families {
            let _ = ip(&[
                (*family).into(),
                "rule".into(),
                "del".into(),
                "pref".into(),
                self.table.to_string(),
                "fwmark".into(),
                self.mark.to_string(),
                "lookup".into(),
                self.table.to_string(),
            ]);
            let _ = ip(&[
                (*family).into(),
                "route".into(),
                "flush".into(),
                "table".into(),
                self.table.to_string(),
            ]);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn copies_physical_default_for_both_families() {
        let a = route_args(
            "-4",
            17000,
            "default via 192.0.2.1 dev eth0 proto dhcp metric 100",
        )
        .unwrap();
        assert!(a.windows(2).any(|w| w == ["via", "192.0.2.1"]));
        assert_eq!(a.last().unwrap(), "onlink");
        let b = route_args("-6", 17000, "default via fe80::1 dev wlan0 metric 600").unwrap();
        assert_eq!(b[0], "-6");
        assert!(route_args("-4", 17000, "default dev ppp0").is_some());
        assert!(route_args("-4", 17000, "0.0.0.0/1 dev tun0").is_none());
        assert!(route_args("-4", 17000, "default via invalid dev eth0").is_none());
    }
    #[test]
    fn marked_packets_bypass_tun_and_cleanup_in_private_namespace() {
        const CHILD: &str = "AIVPN_ROUTE_TEST_PARENT_NS";
        let namespace = std::fs::read_link("/proc/self/ns/net").unwrap();
        if let Ok(parent) = std::env::var(CHILD) {
            assert_ne!(
                namespace.to_string_lossy(),
                parent,
                "тест не должен менять сеть хоста"
            );
            let run = |args: &[&str]| {
                let output = Command::new("ip").args(args).output().unwrap();
                assert!(
                    output.status.success(),
                    "ip {args:?}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                String::from_utf8(output.stdout).unwrap()
            };
            run(&["tuntap", "add", "dev", "compat0", "mode", "tun"]);
            run(&["link", "set", "compat0", "up"]);
            run(&["addr", "add", "192.0.2.2/24", "dev", "compat0"]);
            run(&[
                "-6",
                "addr",
                "add",
                "2001:db8:1::2/64",
                "dev",
                "compat0",
                "nodad",
            ]);
            run(&[
                "route",
                "add",
                "default",
                "via",
                "192.0.2.1",
                "dev",
                "compat0",
            ]);
            run(&[
                "-6",
                "route",
                "add",
                "default",
                "via",
                "2001:db8:1::1",
                "dev",
                "compat0",
            ]);
            let routes = TransportRoutes::install(0x4149).unwrap();
            run(&["tuntap", "add", "dev", "compatvpn", "mode", "tun"]);
            run(&["link", "set", "compatvpn", "up"]);
            for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
                run(&["route", "add", prefix, "dev", "compatvpn"]);
            }
            for prefix in ["::/1", "8000::/1"] {
                run(&["-6", "route", "add", prefix, "dev", "compatvpn"]);
            }
            for (family, address) in [("-4", "1.1.1.1"), ("-6", "2001:db8:2::1")] {
                assert!(run(&[family, "route", "get", address, "mark", "16713"])
                    .contains("dev compat0"));
                assert!(run(&[family, "route", "get", address]).contains("dev compatvpn"));
            }
            drop(routes);
            assert!(!run(&["rule", "show"]).contains("0x4149"));
            assert!(!run(&["-6", "rule", "show"]).contains("0x4149"));
            return;
        }
        let output=Command::new("unshare").args(["-Urn"]).arg(std::env::current_exe().unwrap())
            .args(["--exact","transport_routes::tests::marked_packets_bypass_tun_and_cleanup_in_private_namespace","--nocapture"])
            .env(CHILD,namespace).output();
        let output = match output {
            Ok(output) => output,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                eprintln!("unshare недоступен: проверка пространства имен не выполнена");
                return;
            }
            Err(e) => panic!("{e}"),
        };
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() && stderr.contains("unshare failed: Operation not permitted") {
            eprintln!("пространства имен запрещены: сетевая проверка не выполнена");
            return;
        }
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            stderr
        );
    }
}
