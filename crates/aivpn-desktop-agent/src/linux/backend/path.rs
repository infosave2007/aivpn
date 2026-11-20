use super::*;
use crate::linux::kernel::PROFILE_MARK_MASK;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    os::fd::OwnedFd,
    process::Stdio,
    time::{Duration, Instant},
};

mod collection;
pub(super) use collection::DataPaths;
pub(in crate::linux) mod retirement;

#[derive(Clone)]
struct OwnedRule {
    priority: u32,
    table: u32,
    mark: u32,
}
impl OwnedRule {
    fn matches(&self, rule: &Value) -> bool {
        number(&rule["priority"]) == Some(u64::from(self.priority))
            && number(&rule["table"]) == Some(u64::from(self.table))
            && number(&rule["fwmark"]) == Some(u64::from(self.mark))
            && number(&rule["fwmask"]) == Some(u64::from(PROFILE_MARK_MASK))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[derive(Clone)]
struct TunnelRecord {
    name: String,
    index: u32,
    netns: u64,
    device: u64,
    tcx: u32,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[derive(Clone)]
struct Record {
    matcher: u32,
    tunnel_intent: u64,
    tunnel: Option<TunnelRecord>,
    version: u32,
    namespace: [u8; 16],
    boot: String,
    profile: Option<String>,
    slot: u32,
    table: u32,
    priority: u32,
    mark: u32,
    zone: u32,
    chain: String,
    nft: String,
    phase: String,
    nft_state: Option<Value>,
    filter_state: Vec<String>,
}
pub(super) struct DataPath {
    store: StateDirectory,
    record: Record,
    tunnel: Option<OwnedTunnel>,
    matcher: Option<OwnedFd>,
    tcx: Option<OwnedFd>,
    network: Option<InterfaceAssignment>,
    poisoned: bool,
}

impl DataPath {
    pub(super) fn slot(&self) -> u32 {
        self.record.slot
    }
    pub(super) fn open(namespace: [u8; 16], store: StateDirectory) -> io::Result<Self> {
        Self::open_number(namespace, store, 1)
    }
    pub(super) fn open_number(
        namespace: [u8; 16],
        store: StateDirectory,
        number: u16,
    ) -> io::Result<Self> {
        if !(1..=256).contains(&number) {
            return Err(invalid());
        }
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let record = match store.load(StateFile::Committed)? {
            Some(bytes) => {
                let record: Record = serde_json::from_slice(&bytes)?;
                if record.version != 2 || record.namespace != namespace || record.boot != boot {
                    return Err(invalid());
                }
                let mut suffix: String =
                    namespace[..8].iter().map(|b| format!("{b:02x}")).collect();
                if number != 1 {
                    suffix.push_str(&format!("_{number}"));
                }
                if record.table != 42000 + u32::from(number)
                    || record.zone != record.table
                    || record.mark != (0xa100 + u32::from(number)) << 16
                    || record.priority != 100
                    || record.chain != format!("AIVPN_{suffix}")
                    || record.nft != format!("aivpn_{suffix}")
                {
                    return Err(invalid());
                }
                record
            }
            None => {
                let mut suffix: String =
                    namespace[..8].iter().map(|b| format!("{b:02x}")).collect();
                if number != 1 {
                    suffix.push_str(&format!("_{number}"));
                }
                Record {
                    matcher: 0,
                    tunnel_intent: 0,
                    tunnel: None,
                    version: 2,
                    namespace,
                    boot,
                    profile: None,
                    slot: 0,
                    table: 42000 + u32::from(number),
                    priority: 100,
                    mark: (0xa100 + u32::from(number)) << 16,
                    zone: 42000 + u32::from(number),
                    chain: format!("AIVPN_{suffix}"),
                    nft: format!("aivpn_{suffix}"),
                    phase: "new".into(),
                    nft_state: None,
                    filter_state: Vec::new(),
                }
            }
        };
        let path = Self {
            store,
            record,
            tunnel: None,
            matcher: None,
            tcx: None,
            network: None,
            poisoned: false,
        };
        if path.record.phase != "new" {
            path.verify_persistent()?;
        }
        Ok(path)
    }
    fn persist(&mut self) -> io::Result<()> {
        if self.poisoned {
            return Err(invalid());
        }
        if let Err(error) = self
            .store
            .replace(StateFile::Committed, &serde_json::to_vec(&self.record)?)
        {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }
    fn begin(
        &mut self,
        writer: &KernelWriter,
        profile: &str,
        slot: u32,
        matcher: OwnedFd,
        peers: &[OwnedRule],
    ) -> io::Result<&OwnedTunnel> {
        if self.poisoned
            || self
                .record
                .profile
                .as_ref()
                .is_some_and(|old| old != profile)
        {
            return Err(io::Error::other(
                "Этот экземпляр допускает один активный профиль",
            ));
        }
        if self.record.phase == "new" {
            self.preflight(peers)?;
            self.record.profile = Some(profile.into());
            self.record.slot = slot;
            self.record.matcher = writer.object_id(&matcher)?;
            self.record.phase = "reserved".into();
            self.persist()?;
            if let Err(error) = self.install_guard(writer, &matcher) {
                self.poisoned = true;
                return Err(error);
            }
            self.remember_guard()?;
            self.record.phase = "guarded".into();
            self.persist()?;
        } else {
            self.verify_persistent()?;
            self.verify_kernel(writer)?;
            if self.record.slot != slot {
                return Err(invalid());
            }
        }
        self.tcx = None;
        self.tunnel = None;
        self.record.tunnel = None;
        self.record.tunnel_intent = self
            .record
            .tunnel_intent
            .checked_add(1)
            .ok_or_else(invalid)?;
        self.persist()?;
        self.tunnel = Some(OwnedTunnel::create()?);
        self.tcx = Some(writer.attach_related_icmp(self.tunnel()?)?);
        let identity = self.tunnel()?.verify()?;
        self.record.tunnel = Some(TunnelRecord {
            name: self.tunnel()?.name().into(),
            index: identity.index.get(),
            netns: identity.network_namespace.get(),
            device: identity.device_identity.get(),
            tcx: writer.object_id(self.tcx.as_ref().ok_or_else(invalid)?)?,
        });
        self.persist()?;
        self.matcher = Some(matcher);
        self.network = None;
        self.tunnel()
    }
    pub(super) fn verify_kernel(&self, writer: &KernelWriter) -> io::Result<()> {
        if self.record.phase != "new" {
            writer.verify_profile_matcher(self.record.slot, self.record.matcher)?;
        }
        if let Some(tunnel) = &self.tunnel {
            let identity = tunnel.verify()?;
            let saved = self.record.tunnel.as_ref().ok_or_else(invalid)?;
            if saved.name != tunnel.name()
                || saved.index != identity.index.get()
                || saved.netns != identity.network_namespace.get()
                || saved.device != identity.device_identity.get()
                || saved.tcx != writer.object_id(self.tcx.as_ref().ok_or_else(invalid)?)?
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub(super) fn tunnel(&self) -> io::Result<&OwnedTunnel> {
        self.tunnel
            .as_ref()
            .ok_or_else(|| io::ErrorKind::NotConnected.into())
    }
    fn end(&mut self) -> io::Result<()> {
        self.network = None;
        self.tcx = None;
        self.tunnel = None;
        self.record.tunnel = None;
        self.persist()
    }
    pub(super) fn stage_network(&mut self, network: InterfaceAssignment) -> io::Result<()> {
        network.validate()?;
        self.network = Some(network);
        Ok(())
    }
    pub(super) fn prepare(
        &mut self,
        desired: &ControlState,
        live: &ProfileCatalog,
        authority: &Authority,
    ) -> io::Result<()> {
        if self.record.phase == "new" {
            return Ok(());
        }
        self.verify_persistent()?;
        let Some(network) = self.network else {
            return Ok(());
        };
        let profile = desired
            .profiles()
            .runtime_profiles(authority)
            .map_err(io::Error::other)?
            .into_iter()
            .find(|p| Some(&p.id) == self.record.profile.as_ref())
            .ok_or_else(invalid)?;
        let Some(assignment) = profile.assignment else {
            return Ok(());
        };
        let tunnel = self.tunnel()?;
        let identity = tunnel.verify()?;
        let current = live
            .runtime_profiles(authority)
            .map_err(io::Error::other)?
            .into_iter()
            .find(|p| p.id == profile.id)
            .ok_or_else(invalid)?;
        if assignment.interface_id != identity.device_identity.get()
            || assignment.ipv4 != network.client_ip
            || assignment.ipv6 != network.ipv6.map(|network| network.address)
        {
            // Первое ready=0 после reconnect еще содержит прежнее durable назначение.
            if !current.ready_ipv4
                && !current.ready_ipv6
                && profile.assignment == current.assignment
                && profile.assignment_generation == current.assignment_generation
            {
                return Ok(());
            }
            return Err(io::Error::other(
                "Назначение отличается от принадлежащего службе TUN",
            ));
        }
        if current.ready_ipv4 {
            return self.verify_assignment(network);
        }
        let name = tunnel.name().to_owned();
        self.record.phase = "assigning".into();
        self.persist()?;
        let outcome = (|| {
            run(
                "ip",
                &[
                    "link",
                    "set",
                    "dev",
                    &name,
                    "mtu",
                    &network.mtu.to_string(),
                    "up",
                ],
                None,
            )?;
            run(
                "ip",
                &["-4", "addr", "flush", "dev", &name, "scope", "global"],
                None,
            )?;
            run(
                "ip",
                &[
                    "-4",
                    "addr",
                    "replace",
                    &format!("{}/{}", network.client_ip, network.prefix_len),
                    "dev",
                    &name,
                    "noprefixroute",
                ],
                None,
            )?;
            run(
                "ip",
                &[
                    "-4",
                    "route",
                    "replace",
                    "default",
                    "dev",
                    &name,
                    "table",
                    &self.record.table.to_string(),
                    "metric",
                    "1",
                ],
                None,
            )?;
            run(
                "ip",
                &["-6", "addr", "flush", "dev", &name, "scope", "global"],
                None,
            )?;
            // Terminal unreachable остается в таблице при удалении прежнего IPv6 пути.
            run(
                "ip",
                &[
                    "-6",
                    "route",
                    "flush",
                    "table",
                    &self.record.table.to_string(),
                    "type",
                    "unicast",
                ],
                None,
            )?;
            if let Some(ipv6) = network.ipv6 {
                run(
                    "ip",
                    &[
                        "-6",
                        "addr",
                        "replace",
                        &format!("{}/{}", ipv6.address, ipv6.prefix_len),
                        "dev",
                        &name,
                        "noprefixroute",
                        "nodad",
                    ],
                    None,
                )?;
                run(
                    "ip",
                    &[
                        "-6",
                        "route",
                        "replace",
                        "default",
                        "dev",
                        &name,
                        "table",
                        &self.record.table.to_string(),
                        "metric",
                        "1",
                    ],
                    None,
                )?;
            }
            let mut script=format!("flush chain inet {} ingress\nadd rule inet {} ingress iifname \"{}\" ct zone set {}\nflush chain inet {} post\nadd rule inet {} post meta mark & 0x{:x} == 0x{:x} oifname \"{}\" snat ip to {}\n",self.record.nft,self.record.nft,name,self.record.zone,self.record.nft,self.record.nft,PROFILE_MARK_MASK,self.record.mark,name,network.client_ip);
            if let Some(ipv6) = network.ipv6 {
                script.push_str(&format!("add rule inet {} post meta mark & 0x{:x} == 0x{:x} oifname \"{}\" snat ip6 to {}\n", self.record.nft, PROFILE_MARK_MASK, self.record.mark, name, ipv6.address));
            }
            run("nft", &["-f", "-"], Some(script.as_bytes()))?;
            self.verify_assignment(network)?;
            self.remember_guard()?;
            self.record.phase = "guarded".into();
            self.persist()
        })();
        if outcome.is_err() {
            self.poisoned = true;
        }
        outcome
    }
    pub(super) fn ready_profile(
        &self,
        desired: &ControlState,
        live: &ProfileCatalog,
        authority: &Authority,
    ) -> io::Result<Option<(aivpn_desktop_policy::RuntimeProfile, ProfilePath)>> {
        let Some(id) = &self.record.profile else {
            return Ok(None);
        };
        let Some(tunnel) = &self.tunnel else {
            return Ok(None);
        };
        let identity = tunnel.verify()?;
        let mut profile = live
            .runtime_profiles(authority)
            .map_err(io::Error::other)?
            .into_iter()
            .find(|p| &p.id == id)
            .ok_or_else(invalid)?;
        if profile.ready_ipv4 || profile.ready_ipv6 {
            let expected = desired
                .profiles()
                .runtime_profiles(authority)
                .map_err(io::Error::other)?
                .into_iter()
                .find(|p| &p.id == id)
                .ok_or_else(invalid)?;
            if expected.assignment != profile.assignment
                || expected.assignment_generation != profile.assignment_generation
            {
                return Err(io::Error::other(
                    "Готовность ссылается на другое назначение",
                ));
            }
            self.verify_assignment(
                self.network
                    .ok_or_else(|| io::Error::other("Нет сети готового профиля"))?,
            )?;
        } else if profile
            .assignment
            .is_some_and(|assignment| assignment.interface_id != identity.device_identity.get())
        {
            profile.assignment = None;
        }
        Ok(Some((
            profile,
            ProfilePath {
                slot: self.record.slot,
                mark: self.record.mark,
                zone: self.record.zone,
                identity,
            },
        )))
    }
    fn preflight(&self, peers: &[OwnedRule]) -> io::Result<()> {
        for family in ["-4", "-6"] {
            let rules = json("ip", &[family, "-j", "rule", "show"])?;
            for rule in rules.as_array().ok_or_else(invalid)? {
                if peers.iter().any(|peer| peer.matches(rule)) {
                    continue;
                }
                let priority = number(&rule["priority"]).ok_or_else(invalid)?;
                if priority > 0 && priority <= self.record.priority as u64
                    || number(&rule["table"]) == Some(self.record.table as u64)
                    || mark_overlap(rule, self.record.mark)?
                {
                    return Err(io::Error::other("Зарезервированные правила заняты"));
                }
            }
            if let Ok(routes) = json(
                "ip",
                &[
                    family,
                    "-j",
                    "route",
                    "show",
                    "table",
                    &self.record.table.to_string(),
                ],
            ) {
                if routes.as_array().is_none_or(|rows| !rows.is_empty()) {
                    return Err(invalid());
                }
            }
        }
        if run("nft", &["list", "table", "inet", &self.record.nft], None).is_ok() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        Ok(())
    }
    fn install_guard(&self, writer: &KernelWriter, matcher: &OwnedFd) -> io::Result<()> {
        for family in ["-4", "-6"] {
            run(
                "ip",
                &[
                    family,
                    "route",
                    "add",
                    "unreachable",
                    "default",
                    "table",
                    &self.record.table.to_string(),
                    "metric",
                    "32767",
                ],
                None,
            )?;
            run(
                "ip",
                &[
                    family,
                    "rule",
                    "add",
                    "priority",
                    &self.record.priority.to_string(),
                    "fwmark",
                    &format!("0x{:x}/0x{:x}", self.record.mark, PROFILE_MARK_MASK),
                    "lookup",
                    &self.record.table.to_string(),
                ],
                None,
            )?;
        }
        let pins = format!(
            "/sys/fs/bpf/aivpn_app_routes/{}/programs/match_block",
            self.record
                .namespace
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let matcher_path = writer.pin_profile_matcher(self.record.slot, matcher)?;
        for executable in ["iptables-nft", "ip6tables-nft"] {
            for table in ["raw", "mangle"] {
                run(executable, &["-t", table, "-N", &self.record.chain], None)?;
                run(
                    executable,
                    &["-t", table, "-I", "OUTPUT", "1", "-j", &self.record.chain],
                    None,
                )?;
            }
            run(
                executable,
                &[
                    "-t",
                    "raw",
                    "-A",
                    &self.record.chain,
                    "-m",
                    "bpf",
                    "--object-pinned",
                    &matcher_path,
                    "-j",
                    "CT",
                    "--zone",
                    &self.record.zone.to_string(),
                ],
                None,
            )?;
            run(
                executable,
                &[
                    "-t",
                    "mangle",
                    "-A",
                    &self.record.chain,
                    "-m",
                    "bpf",
                    "--object-pinned",
                    &pins,
                    "-j",
                    "DROP",
                ],
                None,
            )?;
            run(
                executable,
                &[
                    "-t",
                    "mangle",
                    "-A",
                    &self.record.chain,
                    "-m",
                    "bpf",
                    "--object-pinned",
                    &matcher_path,
                    "-j",
                    "MARK",
                    "--set-xmark",
                    &format!("0x{:x}/0x{:x}", self.record.mark, PROFILE_MARK_MASK),
                ],
                None,
            )?;
        }
        let script=format!("add table inet {}\nadd chain inet {} ingress {{ type filter hook prerouting priority raw; policy accept; }}\nadd chain inet {} post {{ type nat hook postrouting priority srcnat; policy accept; }}\n",self.record.nft,self.record.nft,self.record.nft);
        run("nft", &["-f", "-"], Some(script.as_bytes()))?;
        Ok(())
    }
    fn filter_state(&self) -> io::Result<Vec<String>> {
        let mut state = Vec::new();
        for executable in ["iptables-nft", "ip6tables-nft"] {
            for table in ["raw", "mangle"] {
                state.push(
                    String::from_utf8(run(
                        executable,
                        &["-t", table, "-S", &self.record.chain],
                        None,
                    )?)
                    .map_err(io::Error::other)?,
                );
                run(
                    executable,
                    &["-t", table, "-C", "OUTPUT", "-j", &self.record.chain],
                    None,
                )?;
            }
        }
        Ok(state)
    }
    fn remember_guard(&mut self) -> io::Result<()> {
        self.record.filter_state = self.filter_state()?;
        self.record.nft_state = Some(json(
            "nft",
            &["-j", "list", "table", "inet", &self.record.nft],
        )?);
        Ok(())
    }
    fn verify_persistent(&self) -> io::Result<()> {
        if self.poisoned || self.record.phase != "guarded" {
            return Err(io::Error::other("Журнал сетевого пути не в guarded"));
        }
        if self.record.filter_state != self.filter_state()? {
            return Err(io::Error::other("Изменена собственная цепочка OUTPUT"));
        }
        if self.record.nft_state.as_ref()
            != Some(&json(
                "nft",
                &["-j", "list", "table", "inet", &self.record.nft],
            )?)
        {
            return Err(io::Error::other("Изменена собственная таблица nft"));
        }
        for family in ["-4", "-6"] {
            let routes = json(
                "ip",
                &[
                    family,
                    "-j",
                    "route",
                    "show",
                    "table",
                    &self.record.table.to_string(),
                ],
            )?;
            if !routes.as_array().ok_or_else(invalid)?.iter().any(|r| {
                r["type"] == "unreachable" && r["dst"] == "default" && r["metric"] == 32767
            }) {
                return Err(io::Error::other(format!(
                    "Нет terminal route {family}: {routes}"
                )));
            }
            for route in routes.as_array().ok_or_else(invalid)? {
                if route["type"] == "unreachable"
                    && route["dst"] == "default"
                    && route["metric"] == 32767
                {
                    continue;
                }
                let saved = self.record.tunnel.as_ref().ok_or_else(invalid)?;
                use std::os::unix::fs::MetadataExt;
                if route["dst"] != "default"
                    || route["metric"] != 1
                    || route["dev"] != saved.name
                    || !route["gateway"].is_null()
                    || fs::metadata(format!("/sys/class/net/{}", saved.name))?.ino() != saved.device
                {
                    return Err(invalid());
                }
            }
            let rules = json("ip", &[family, "-j", "rule", "show"])?;
            let protected = rules
                .as_array()
                .ok_or_else(invalid)?
                .iter()
                .filter(|r| number(&r["table"]) == Some(self.record.table as u64))
                .count();
            if protected != 1 {
                return Err(invalid());
            }
            if !rules.as_array().ok_or_else(invalid)?.iter().any(|r| {
                r["priority"] == self.record.priority
                    && number(&r["table"]) == Some(self.record.table as u64)
                    && r["fwmark"] == format!("0x{:x}", self.record.mark)
                    && r["fwmask"] == format!("0x{:x}", PROFILE_MARK_MASK)
            }) {
                return Err(io::Error::other(format!(
                    "Нет собственного fwmark rule {family}: {rules}"
                )));
            }
        }
        Ok(())
    }
    fn verify_assignment(&self, network: InterfaceAssignment) -> io::Result<()> {
        let tunnel = self.tunnel()?;
        tunnel.verify()?;
        let links = json("ip", &["-j", "addr", "show", "dev", tunnel.name()])?;
        let link = &links[0];
        let ipv4: Vec<_> = link["addr_info"]
            .as_array()
            .ok_or_else(invalid)?
            .iter()
            .filter(|addr| addr["family"] == "inet")
            .collect();
        if link["mtu"] != network.mtu
            || !link["flags"]
                .as_array()
                .ok_or_else(invalid)?
                .iter()
                .any(|flag| flag == "UP")
            || ipv4.len() != 1
            || ipv4[0]["local"] != network.client_ip.to_string()
            || ipv4[0]["prefixlen"] != network.prefix_len
        {
            return Err(invalid());
        }
        let ipv6: Vec<_> = link["addr_info"]
            .as_array()
            .ok_or_else(invalid)?
            .iter()
            .filter(|addr| addr["family"] == "inet6" && addr["scope"] == "global")
            .collect();
        match network.ipv6 {
            Some(expected)
                if ipv6.len() == 1
                    && ipv6[0]["local"] == expected.address.to_string()
                    && ipv6[0]["prefixlen"] == expected.prefix_len =>
            {
                ()
            }
            None if ipv6.is_empty() => (),
            _ => return Err(invalid()),
        }
        for family in ["-4", "-6"] {
            let routes = json(
                "ip",
                &[
                    family,
                    "-j",
                    "route",
                    "show",
                    "table",
                    &self.record.table.to_string(),
                ],
            )?;
            let active: Vec<_> = routes
                .as_array()
                .ok_or_else(invalid)?
                .iter()
                .filter(|route| route["type"] != "unreachable")
                .collect();
            let expected = family == "-4" || network.ipv6.is_some();
            if expected {
                if active.len() != 1
                    || active[0]["dst"] != "default"
                    || active[0]["dev"] != tunnel.name()
                    || active[0]["metric"] != 1
                    || !active[0]["gateway"].is_null()
                {
                    return Err(invalid());
                }
            } else if !active.is_empty() {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
fn invalid() -> io::Error {
    io::Error::other("Принадлежность или готовность сетевого пути не подтверждена")
}
fn json(program: &str, args: &[&str]) -> io::Result<Value> {
    serde_json::from_slice(&run(program, args, None)?).map_err(io::Error::other)
}
pub(crate) fn run(program: &str, args: &[&str], input: Option<&[u8]>) -> io::Result<Vec<u8>> {
    if !["ip", "nft", "iptables-nft", "ip6tables-nft"].contains(&program) {
        return Err(invalid());
    }
    let mut child = crate::linux::system_network_command(program)?
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input)?;
    }
    let stdout = child.stdout.take().unwrap();
    std::thread::scope(|scope| {
        let output = scope.spawn(move || {
            let mut bytes = Vec::new();
            stdout.take(2 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
            Ok::<_, io::Error>(bytes)
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::ErrorKind::TimedOut.into());
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let bytes = output.join().map_err(|_| invalid())??;
        if !status.success() || bytes.len() > 2 * 1024 * 1024 {
            return Err(io::Error::other(format!(
                "Не выполнена фиксированная операция {program}"
            )));
        }
        Ok(bytes)
    })
}

fn number(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        let text = value.as_str()?;
        match text.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).ok(),
            None => text.parse().ok(),
        }
    })
}

fn mark_overlap(rule: &Value, mark: u32) -> io::Result<bool> {
    if rule["fwmark"].is_null() {
        return Ok(false);
    }
    let parse = |value: &Value| -> io::Result<u32> {
        if let Some(number) = value.as_u64() {
            return u32::try_from(number).map_err(io::Error::other);
        }
        let text = value.as_str().ok_or_else(invalid)?;
        u32::from_str_radix(
            text.strip_prefix("0x").unwrap_or(text),
            if text.starts_with("0x") { 16 } else { 10 },
        )
        .map_err(io::Error::other)
    };
    let foreign = parse(&rule["fwmark"])?;
    let mask = if rule["fwmask"].is_null() {
        u32::MAX
    } else {
        parse(&rule["fwmask"])?
    };
    let shared = mask & PROFILE_MARK_MASK;
    Ok(shared != 0 && (mark ^ foreign) & shared == 0)
}
