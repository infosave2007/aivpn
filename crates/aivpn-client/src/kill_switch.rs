//! Kill-switch and leak-protection for all platforms.
//!
//! When active, all outbound traffic is blocked except:
//!   - traffic on the VPN TUN interface
//!   - traffic to the physical VPN server IP (so the tunnel stays alive)
//!   - loopback traffic
//!
//! Rules are intentionally NOT removed on unexpected process death (SIGKILL),
//! keeping the user protected until they explicitly run `kill-switch clear`.

use aivpn_common::error::{Error, Result};

#[cfg(any(target_os = "macos", test))]
mod macos_pf;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(not(target_os = "windows"))]
use std::io;
use tracing::info;
#[allow(unused_imports)]
use tracing::warn;

pub struct KillSwitch {
    tun_name: String,
    server_ip: String,
    /// Firewall mark whose traffic is let out alongside the tunnel.
    ///
    /// The server-address bypass below only covers a session that talks to the
    /// server directly. A transport that reaches the server by some other route
    /// opens sockets to addresses this struct does not know and cannot
    /// enumerate — so with only the address bypass, switching the kill-switch
    /// on would block the very transport carrying the tunnel, and "leak
    /// protection" would read to the user as "the VPN stopped working".
    ///
    /// Marked traffic is therefore accepted as a class. It is the same mark the
    /// socket guard stamps, so exactly the sockets that were deliberately kept
    /// out of the tunnel are the ones allowed out here — nothing broader.
    mark: Option<u32>,
    #[cfg(any(target_os = "macos", windows))]
    guard: Option<aivpn_common::transport::SharedGuard>,
    active: bool,
    /// Даже прерванная настройка может оставить защитные правила до явного выхода.
    cleanup_needed: bool,
}

impl KillSwitch {
    pub fn new(tun_name: String, server_ip: String) -> Self {
        Self {
            tun_name,
            server_ip,
            mark: None,
            #[cfg(any(target_os = "macos", windows))]
            guard: None,
            active: false,
            cleanup_needed: false,
        }
    }

    /// Подключить исключения транспорта и к защите, оставшейся после перезапуска.
    #[cfg(any(target_os = "macos", windows))]
    pub(crate) fn prepare_transport_guard(
        guard: &aivpn_common::transport::SharedGuard,
    ) -> Result<()> {
        #[cfg(windows)]
        guard.set_firewall_peer_handler(Some(std::sync::Arc::new(|peer| {
            windows::allow_transport_peer(peer).map_err(Error::Io)
        })))?;
        #[cfg(target_os = "macos")]
        {
            let rules = std::process::Command::new("/sbin/pfctl")
                .args(["-a", "aivpn_ks", "-s", "rules"])
                .output()?;
            if rules.status.success() && !rules.stdout.is_empty() {
                guard.set_firewall(true)?;
            }
        }
        Ok(())
    }

    /// Also let out traffic carrying `mark` (see the field's documentation).
    /// Must be set before `activate()`; changing it afterwards has no effect
    /// until the next activation.
    pub fn with_mark(mut self, mark: u32) -> Self {
        self.mark = Some(mark);
        self
    }

    #[cfg(any(target_os = "macos", windows))]
    pub fn with_guard(mut self, guard: aivpn_common::transport::SharedGuard) -> Self {
        self.guard = Some(guard);
        self
    }

    /// Address family for the server-bypass nft rule: `ip6` when the server
    /// address is IPv6, `ip` otherwise.
    ///
    /// This used to be hard-coded to `ip`. With an IPv6 server the rule then
    /// matched no packet at all, so switching the kill-switch on blocked the
    /// client's own traffic to its server — which reads to a user as "the VPN
    /// stopped working", not as "leak protection engaged".
    ///
    /// A bare `:` test is enough: `server_ip` is an address, never a
    /// host:port pair (the port lives separately in the connection key), so
    /// the only colons that can appear are an IPv6 separator.
    #[cfg(any(target_os = "linux", test))]
    fn nft_family(&self) -> &'static str {
        if self.server_ip.contains(':') {
            "ip6"
        } else {
            "ip"
        }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Activate kill-switch: block all traffic except VPN tunnel + server bypass.
    pub fn activate(&mut self) -> Result<()> {
        if self.active {
            return Ok(());
        }
        self.cleanup_needed = true;
        self.activate_impl()?;
        self.active = true;
        info!("Kill-switch activated — non-VPN traffic blocked");
        Ok(())
    }

    /// Remove kill-switch rules (called on graceful disconnect).
    pub fn deactivate(&mut self) {
        if !self.active && !self.cleanup_needed {
            return;
        }
        self.deactivate_impl();
        self.active = false;
        self.cleanup_needed = false;
        info!("Kill-switch deactivated");
    }

    /// Remove any stale rules left by a previous session (e.g. after SIGKILL).
    /// Safe to call when no rules are present.
    pub fn clear_stale() -> Result<()> {
        #[cfg(target_os = "windows")]
        windows::clear().map_err(Error::Io)?;
        #[cfg(not(target_os = "windows"))]
        Self::clear_stale_impl();
        info!("Kill-switch stale rules cleared");
        Ok(())
    }

    // ──────────────────── Linux ────────────────────

    #[cfg(target_os = "linux")]
    fn activate_impl(&self) -> Result<()> {
        use std::process::Command;

        // Try nftables first
        if Command::new("nft")
            .arg("--version")
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            let ok = Command::new("nft")
                .args(["add", "table", "inet", "aivpn_ks"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !ok {
                return Err(Error::Io(io::Error::other(
                    "kill-switch: nft failed to create aivpn_ks table",
                )));
            }
            let chain_spec = "{ type filter hook output priority 0 ; policy drop ; }";
            let chain_ok = Command::new("nft")
                .args(["add", "chain", "inet", "aivpn_ks", "output", chain_spec])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !chain_ok {
                // Не удаляем прежнюю защиту при неудачном reconnect.
                return Err(Error::Io(io::Error::other(
                    "kill-switch: nft failed to create drop-policy chain",
                )));
            }
            // Flush stale accept rules from a previous activation. `add table` /
            // `add chain` are idempotent and do NOT clear existing rules, so
            // without this every reconnect (new random TUN name) or pool failover
            // (new server IP) would APPEND another `oifname <old-tun> accept` /
            // `ip daddr <old-server-ip> accept` rule that survives for the life of
            // the process. The stale `daddr` rules are a real bypass — any host
            // process could still reach the old server IP unblocked. The drop
            // policy set above is preserved by flushing only the chain's rules
            // (mirrors the iptables path's `-F AIVPN_KS`).
            let flushed = Command::new("nft")
                .args(["flush", "chain", "inet", "aivpn_ks", "output"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !flushed {
                return Err(Error::Io(io::Error::other(
                    "kill-switch: cannot clear stale nft rules",
                )));
            }
            let ip_family = self.nft_family();
            let mut rules: Vec<Vec<String>> = vec![
                vec![
                    "add", "rule", "inet", "aivpn_ks", "output", "oifname", "lo", "accept",
                ]
                .into_iter()
                .map(String::from)
                .collect(),
                vec![
                    "add",
                    "rule",
                    "inet",
                    "aivpn_ks",
                    "output",
                    "oifname",
                    self.tun_name.as_str(),
                    "accept",
                ]
                .into_iter()
                .map(String::from)
                .collect(),
                // Server IP bypass — use ip/ip6 family based on address type
                vec![
                    "add",
                    "rule",
                    "inet",
                    "aivpn_ks",
                    "output",
                    ip_family,
                    "daddr",
                    self.server_ip.as_str(),
                    "accept",
                ]
                .into_iter()
                .map(String::from)
                .collect(),
            ];
            // Marked traffic — the transport's own sockets (see `mark`).
            if let Some(m) = self.mark {
                rules.push(
                    vec![
                        "add",
                        "rule",
                        "inet",
                        "aivpn_ks",
                        "output",
                        "meta",
                        "mark",
                        &format!("0x{m:x}"),
                        "accept",
                    ]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                );
            }
            for rule in &rules {
                let rule_ok = Command::new("nft")
                    .args(rule.as_slice())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                if !rule_ok {
                    // DROP policy остается до следующей попытки или явного выхода.
                    return Err(Error::Io(io::Error::other(
                        "kill-switch: nft failed to add accept rule (tunnel would be blocked)",
                    )));
                }
            }
            return Ok(());
        }

        self.activate_iptables(&mut |program, args| {
            Command::new(program)
                .args(args)
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        })
    }

    #[cfg(target_os = "linux")]
    fn activate_iptables(&self, run: &mut impl FnMut(&str, &[&str]) -> bool) -> Result<()> {
        let tun = self.tun_name.as_str();
        let sip = self.server_ip.as_str();
        let server_family = if self.server_ip.contains(':') {
            "ip6tables"
        } else {
            "iptables"
        };
        for ipt in ["iptables", "ip6tables"] {
            // Guard остается после прерванной перестройки и не дублируется.
            let exists = run(
                ipt,
                &[
                    "-C",
                    "OUTPUT",
                    "-m",
                    "comment",
                    "--comment",
                    "AIVPN_KS_UPDATE",
                    "-j",
                    "DROP",
                ],
            );
            if !exists
                && !run(
                    ipt,
                    &[
                        "-I",
                        "OUTPUT",
                        "1",
                        "-m",
                        "comment",
                        "--comment",
                        "AIVPN_KS_UPDATE",
                        "-j",
                        "DROP",
                    ],
                )
            {
                return Err(Error::Io(io::Error::other(
                    "kill-switch: cannot protect rule update",
                )));
            }
        }
        for ipt in ["iptables", "ip6tables"] {
            run(ipt, &["-N", "AIVPN_KS"]);
            if !run(ipt, &["-F", "AIVPN_KS"]) {
                return Err(Error::Io(io::Error::other(
                    "kill-switch: cannot clear stale iptables rules",
                )));
            }
            // -D may legitimately fail (no pre-existing jump rule); ignore its result.
            run(ipt, &["-D", "OUTPUT", "-j", "AIVPN_KS"]);
            let mark_arg = self.mark.map(|m| format!("0x{m:x}"));
            let mut cmds: Vec<Vec<&str>> = vec![
                vec![ipt, "-A", "AIVPN_KS", "-o", "lo", "-j", "ACCEPT"],
                vec![ipt, "-A", "AIVPN_KS", "-o", tun, "-j", "ACCEPT"],
            ];
            if ipt == server_family {
                cmds.push(vec![ipt, "-A", "AIVPN_KS", "-d", sip, "-j", "ACCEPT"]);
            }
            // Marked traffic — the transport's own sockets (see `mark`). Must be
            // appended before the DROP that terminates the chain.
            if let Some(m) = mark_arg.as_deref() {
                cmds.push(vec![
                    ipt, "-A", "AIVPN_KS", "-m", "mark", "--mark", m, "-j", "ACCEPT",
                ]);
            }
            cmds.push(vec![ipt, "-A", "AIVPN_KS", "-j", "DROP"]);
            cmds.push(vec![ipt, "-I", "OUTPUT", "1", "-j", "AIVPN_KS"]);
            for cmd in &cmds {
                let ok = run(cmd[0], &cmd[1..]);
                if !ok {
                    return Err(Error::Io(io::Error::other(format!(
                        "kill-switch: {ipt} rule setup failed; drop protection retained"
                    ))));
                }
            }
            if !run(
                ipt,
                &[
                    "-D",
                    "OUTPUT",
                    "-m",
                    "comment",
                    "--comment",
                    "AIVPN_KS_UPDATE",
                    "-j",
                    "DROP",
                ],
            ) {
                return Err(Error::Io(io::Error::other(
                    "kill-switch: cannot release update guard",
                )));
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn clear_iptables(run: &mut impl FnMut(&str, &[&str]) -> bool) {
        for program in ["iptables", "ip6tables"] {
            run(program, &["-D", "OUTPUT", "-j", "AIVPN_KS"]);
            run(program, &["-F", "AIVPN_KS"]);
            run(program, &["-X", "AIVPN_KS"]);
            run(
                program,
                &[
                    "-D",
                    "OUTPUT",
                    "-m",
                    "comment",
                    "--comment",
                    "AIVPN_KS_UPDATE",
                    "-j",
                    "DROP",
                ],
            );
        }
    }

    #[cfg(target_os = "linux")]
    fn deactivate_impl(&self) {
        Self::clear_stale_impl();
    }

    #[cfg(target_os = "linux")]
    fn clear_stale_impl() {
        use std::process::Command;
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", "aivpn_ks"])
            .status();
        Self::clear_iptables(&mut |program, args| {
            Command::new(program)
                .args(args)
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        });
    }

    // ──────────────────── macOS ────────────────────

    #[cfg(target_os = "macos")]
    fn activate_impl(&self) -> Result<()> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        use std::process::Command;

        let mut rules = format!(
            "block out all\npass out on lo0 all\npass out on {tun} all\npass out proto {{tcp,udp}} from any to {sip}\n",
            tun = self.tun_name,
            sip = self.server_ip,
        );
        if self
            .guard
            .as_ref()
            .is_some_and(|guard| guard.uses_firewall_table())
        {
            rules = format!("table <aivpn_transport> persist\n{rules}pass out proto {{tcp,udp}} from any to <aivpn_transport>\n");
        }

        // Write anchor rules to a root-only directory, not world-writable /tmp.
        // O_NOFOLLOW ensures we fail if the path is a symlink (symlink attack prevention).
        let run_dir = "/var/run/aivpn";
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(run_dir)
            .map_err(|e| {
                Error::Io(io::Error::new(
                    io::ErrorKind::Other,
                    format!("kill-switch: failed to create {}: {}", run_dir, e),
                ))
            })?;

        let anchor_file = "/var/run/aivpn/aivpn_ks.conf";
        let _ = std::fs::remove_file(anchor_file); // remove stale file; ignore error
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(anchor_file)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(rules.as_bytes())
            })
            .map_err(|e| {
                Error::Io(io::Error::new(
                    io::ErrorKind::Other,
                    format!("kill-switch: failed to write pf rules: {}", e),
                ))
            })?;

        let load = Command::new("pfctl")
            .args(["-a", "aivpn_ks", "-f", anchor_file])
            .status()
            .map_err(Error::Io)?;
        if !load.success() {
            let _ = std::fs::remove_file(anchor_file);
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::Other,
                "kill-switch: pfctl failed to load anchor",
            )));
        }

        // Уже включенный PF может вернуть ошибку на повторный -e.
        let _ = Command::new("pfctl").args(["-e"]).status();
        let status = Command::new("pfctl").args(["-s", "info"]).output()?;
        if !status.status.success()
            || !String::from_utf8_lossy(&status.stdout)
                .lines()
                .any(|line| line.starts_with("Status: Enabled"))
        {
            return Err(io::Error::other("kill-switch: PF не включен").into());
        }

        // Inject anchor reference into running pf config if not present
        let root_rules = Command::new("pfctl").args(["-s", "rules"]).output()?;
        if !root_rules.status.success() {
            return Err(io::Error::other("kill-switch: правила PF недоступны").into());
        }
        let already = macos_pf::anchor_is_first(&String::from_utf8_lossy(&root_rules.stdout));
        if !already {
            let existing = std::fs::read_to_string("/etc/pf.conf")?;
            let with_anchor = macos_pf::with_first_anchor(&existing);
            let ref_file = "/var/run/aivpn/aivpn_ks_ref.conf";
            let _ = std::fs::remove_file(ref_file);
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(ref_file)
                .and_then(|mut f| {
                    use std::io::Write;
                    f.write_all(with_anchor.as_bytes())
                })?;
            if !Command::new("pfctl")
                .args(["-f", ref_file])
                .status()?
                .success()
            {
                return Err(
                    io::Error::other("kill-switch: не удалось подключить anchor PF").into(),
                );
            }
        }

        if let Some(guard) = &self.guard {
            guard.set_firewall(true)?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn deactivate_impl(&self) {
        if let Some(guard) = &self.guard {
            let _ = guard.set_firewall(false);
        }
        use std::process::Command;
        let _ = Command::new("pfctl")
            .args(["-a", "aivpn_ks", "-F", "rules"])
            .status();
        let _ = std::fs::remove_file("/var/run/aivpn/aivpn_ks.conf");
        let _ = std::fs::remove_file("/var/run/aivpn/aivpn_ks_ref.conf");
    }

    #[cfg(target_os = "macos")]
    fn clear_stale_impl() {
        use std::process::Command;
        let _ = Command::new("pfctl")
            .args(["-a", "aivpn_ks", "-F", "rules"])
            .status();
        let _ = std::fs::remove_file("/var/run/aivpn/aivpn_ks.conf");
        let _ = std::fs::remove_file("/var/run/aivpn/aivpn_ks_ref.conf");
    }

    // ──────────────────── Windows ────────────────────

    #[cfg(target_os = "windows")]
    fn activate_impl(&self) -> Result<()> {
        windows::activate(&self.tun_name, &self.server_ip).map_err(Error::Io)?;
        if let Some(guard) = &self.guard {
            guard.set_firewall_peer_handler(Some(std::sync::Arc::new(|peer| {
                windows::allow_transport_peer(peer).map_err(Error::Io)
            })))?;
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn deactivate_impl(&self) {
        if let Some(guard) = &self.guard {
            let _ = guard.set_firewall_peer_handler(None);
        }
        if let Err(error) = windows::clear() {
            warn!("kill-switch cleanup failed: {error}");
        }
    }

    // ──────────────────── Unsupported platforms ────────────────────

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    fn activate_impl(&self) -> Result<()> {
        warn!("Kill-switch not supported on this platform");
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    fn deactivate_impl(&self) {}

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    fn clear_stale_impl() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn stale_accept_rules_cannot_survive_failed_flush() {
        let ks = KillSwitch::new("tun0".into(), "192.0.2.1".into());
        assert!(ks
            .activate_iptables(&mut |_program, args| args != ["-F", "AIVPN_KS"])
            .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reconnect_guard_precedes_flush_and_leaves_after_jump() {
        let ks = KillSwitch::new("tun0".into(), "192.0.2.1".into());
        let mut commands = Vec::new();
        ks.activate_iptables(&mut |program, args| {
            commands.push(format!("{} {}", program, args.join(" ")));
            args.first() != Some(&"-C")
        })
        .unwrap();
        for family in ["iptables", "ip6tables"] {
            let guard = commands
                .iter()
                .position(|c| {
                    c == &format!(
                        "{family} -I OUTPUT 1 -m comment --comment AIVPN_KS_UPDATE -j DROP"
                    )
                })
                .unwrap();
            let flush = commands
                .iter()
                .position(|c| c == &format!("{family} -F AIVPN_KS"))
                .unwrap();
            let jump = commands
                .iter()
                .position(|c| c == &format!("{family} -I OUTPUT 1 -j AIVPN_KS"))
                .unwrap();
            let release = commands
                .iter()
                .position(|c| {
                    c == &format!("{family} -D OUTPUT -m comment --comment AIVPN_KS_UPDATE -j DROP")
                })
                .unwrap();
            assert!(guard < flush && flush < jump && jump < release);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fallback_blocks_both_families_and_bypasses_only_server_family() {
        for server in ["192.0.2.1", "2001:db8::1"] {
            let ks = KillSwitch::new("tun0".into(), server.into()).with_mark(0x4149);
            let mut commands = Vec::new();
            ks.activate_iptables(&mut |program, args| {
                commands.push(format!("{} {}", program, args.join(" ")));
                true
            })
            .unwrap();
            for family in ["iptables", "ip6tables"] {
                assert!(commands.contains(&format!("{family} -A AIVPN_KS -j DROP")));
                assert!(commands.contains(&format!("{family} -I OUTPUT 1 -j AIVPN_KS")));
            }
            assert_eq!(commands.iter().filter(|c| c.contains(" -d ")).count(), 1);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fallback_partial_failure_preserves_drop_guards() {
        let ks = KillSwitch::new("tun0".into(), "192.0.2.1".into());
        let mut commands = Vec::new();
        assert!(ks
            .activate_iptables(&mut |program, args| {
                commands.push(format!("{} {}", program, args.join(" ")));
                !(program == "ip6tables" && args == ["-A", "AIVPN_KS", "-j", "DROP"])
            })
            .is_err());
        for family in ["iptables", "ip6tables"] {
            assert!(!commands.contains(&format!("{family} -X AIVPN_KS")));
        }
        assert!(
            !commands.contains(
                &"ip6tables -D OUTPUT -m comment --comment AIVPN_KS_UPDATE -j DROP".to_owned()
            ),
            "Ошибка настройки не должна снимать DROP guard неготовой семьи"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nft_failure_fixture() {
        let Ok(kind) = std::env::var("AIVPN_KS_FIXTURE_KIND") else {
            return;
        };
        let log = std::env::var("AIVPN_KS_FIXTURE_LOG").unwrap();
        let mut ks = if kind == "tunnel" {
            let mut config = crate::tunnel::TunnelConfig::default();
            config.kill_switch = true;
            let mut tunnel = crate::tunnel::Tunnel::new(config);
            assert!(tunnel.activate_kill_switch().is_err());
            tunnel
                .take_kill_switch()
                .expect("Неудачная активация тоже владеет очисткой правил")
        } else {
            let mut ks = KillSwitch::new("tun0".into(), "192.0.2.1".into());
            assert!(ks.activate().is_err());
            assert!(!ks.is_active());
            ks
        };
        use std::io::Write;
        writeln!(
            std::fs::OpenOptions::new().append(true).open(log).unwrap(),
            "BEFORE_INTENTIONAL_EXIT"
        )
        .unwrap();
        ks.deactivate();
    }

    #[cfg(target_os = "linux")]
    fn nft_failure_log(kind: &str) -> String {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root =
            std::env::temp_dir().join(format!("aivpn-ks-test-{:032x}", rand::random::<u128>()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let _cleanup = Cleanup(root.clone());
        let nft = root.join("nft");
        std::fs::write(&nft, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$AIVPN_KS_FIXTURE_LOG\"\nif [ \"$1 $2\" = 'add rule' ]; then exit 1; fi\n").unwrap();
        std::fs::set_permissions(&nft, std::fs::Permissions::from_mode(0o700)).unwrap();
        let log = root.join("commands");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "kill_switch::tests::nft_failure_fixture",
                "--nocapture",
            ])
            .env("PATH", &root)
            .env("AIVPN_KS_FIXTURE_KIND", kind)
            .env("AIVPN_KS_FIXTURE_LOG", &log)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        std::fs::read_to_string(log).unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nft_partial_failure_stays_closed_until_intentional_exit() {
        let log = nft_failure_log("direct");
        let (before, after) = log.split_once("BEFORE_INTENTIONAL_EXIT").unwrap();
        assert!(
            !before.contains("delete table"),
            "Неудачная настройка сняла DROP policy"
        );
        assert!(
            after.contains("delete table"),
            "Intentional exit должен очистить частичную настройку"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tunnel_keeps_failed_activation_owner_for_intentional_cleanup() {
        let log = nft_failure_log("tunnel");
        assert!(log
            .split_once("BEFORE_INTENTIONAL_EXIT")
            .unwrap()
            .1
            .contains("delete table"));
    }

    /// No mark by default: a session that talks to the server directly needs
    /// only the address bypass, and accepting an unset mark would widen the
    /// hole for nothing.
    #[test]
    fn no_mark_bypass_unless_asked() {
        let ks = KillSwitch::new("tun0".to_string(), "1.2.3.4".to_string());
        assert_eq!(ks.mark, None);
    }

    /// The mark survives onto the struct that builds the firewall rules — if it
    /// did not, switching the kill-switch on would block the transport carrying
    /// the tunnel, and the failure would look like a network fault rather than
    /// a policy decision.
    #[test]
    fn mark_bypass_is_stored() {
        let ks = KillSwitch::new("tun0".to_string(), "1.2.3.4".to_string()).with_mark(0x4149);
        assert_eq!(ks.mark, Some(0x4149));
        assert!(!ks.is_active(), "with_mark must not activate anything");
    }

    /// IPv6 server addresses must select the ip6 family. See `nft_family`:
    /// with `ip` hard-coded the bypass rule matched nothing and the
    /// kill-switch blocked the tunnel's own traffic.
    #[test]
    fn ipv6_server_selects_ip6_family() {
        let ks = KillSwitch::new("tun0".to_string(), "2001:db8::1".to_string());
        assert_eq!(ks.nft_family(), "ip6");
    }

    #[test]
    fn ipv4_server_selects_ip_family() {
        let ks = KillSwitch::new("tun0".to_string(), "203.0.113.1".to_string());
        assert_eq!(ks.nft_family(), "ip");
    }

    /// The compressed all-zeros form is still IPv6 and still has colons —
    /// guarding the detection against a "looks too short to be v6" rewrite.
    #[test]
    fn compressed_ipv6_still_selects_ip6() {
        let ks = KillSwitch::new("tun0".to_string(), "::1".to_string());
        assert_eq!(ks.nft_family(), "ip6");
    }

    #[test]
    fn test_new_not_active() {
        let ks = KillSwitch::new("tun0".to_string(), "1.2.3.4".to_string());
        assert!(!ks.is_active());
    }

    #[test]
    fn test_deactivate_when_not_active_is_noop() {
        let mut ks = KillSwitch::new("tun0".to_string(), "1.2.3.4".to_string());
        ks.deactivate();
        assert!(!ks.is_active());
    }

    #[test]
    fn test_fields_stored() {
        let ks = KillSwitch::new("utun5".to_string(), "198.51.100.1".to_string());
        assert_eq!(ks.server_ip, "198.51.100.1");
        assert_eq!(ks.tun_name, "utun5");
        assert!(!ks.is_active());
    }

    #[test]
    fn test_double_activate_skips_second() {
        // Verify the guard condition: second activate() on an already-active
        // KillSwitch returns Ok without re-running the platform commands.
        // We simulate by setting active = true manually via a helper method.
        let mut ks = KillSwitch::new("tun9".to_string(), "10.0.0.1".to_string());
        ks.active = true; // pretend it's already on
                          // Should not panic or fail
        let result = ks.activate();
        assert!(result.is_ok());
    }
}
