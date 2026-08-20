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
    active: bool,
}

impl KillSwitch {
    pub fn new(tun_name: String, server_ip: String) -> Self {
        Self {
            tun_name,
            server_ip,
            mark: None,
            active: false,
        }
    }

    /// Also let out traffic carrying `mark` (see the field's documentation).
    /// Must be set before `activate()`; changing it afterwards has no effect
    /// until the next activation.
    pub fn with_mark(mut self, mark: u32) -> Self {
        self.mark = Some(mark);
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
        self.activate_impl()?;
        self.active = true;
        info!("Kill-switch activated — non-VPN traffic blocked");
        Ok(())
    }

    /// Remove kill-switch rules (called on graceful disconnect).
    pub fn deactivate(&mut self) {
        if !self.active {
            return;
        }
        self.deactivate_impl();
        self.active = false;
        info!("Kill-switch deactivated");
    }

    /// Remove any stale rules left by a previous session (e.g. after SIGKILL).
    /// Safe to call when no rules are present.
    pub fn clear_stale() {
        Self::clear_stale_impl();
        info!("Kill-switch stale rules cleared");
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
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::Other,
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
                // Roll back the table so we don't leave a policy-less table behind,
                // then fail loud instead of reporting "active" with nothing blocked.
                let _ = Command::new("nft")
                    .args(["delete", "table", "inet", "aivpn_ks"])
                    .status();
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::Other,
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
            let _ = Command::new("nft")
                .args(["flush", "chain", "inet", "aivpn_ks", "output"])
                .status();
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
                    let _ = Command::new("nft")
                        .args(["delete", "table", "inet", "aivpn_ks"])
                        .status();
                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::Other,
                        "kill-switch: nft failed to add accept rule (tunnel would be blocked)",
                    )));
                }
            }
            return Ok(());
        }

        // Fallback: iptables / ip6tables
        let tun = self.tun_name.as_str();
        let sip = self.server_ip.as_str();
        // Use ip6tables for IPv6 server addresses
        let ipt = if self.server_ip.contains(':') {
            "ip6tables"
        } else {
            "iptables"
        };
        for cmd in &[vec![ipt, "-N", "AIVPN_KS"], vec![ipt, "-F", "AIVPN_KS"]] {
            let _ = Command::new(cmd[0]).args(&cmd[1..]).status();
        }
        // -D may legitimately fail (no pre-existing jump rule); ignore its result.
        let _ = Command::new(ipt)
            .args(["-D", "OUTPUT", "-j", "AIVPN_KS"])
            .status();
        let mark_arg = self.mark.map(|m| format!("0x{m:x}"));
        let mut cmds: Vec<Vec<&str>> = vec![
            vec![ipt, "-I", "OUTPUT", "1", "-j", "AIVPN_KS"],
            vec![ipt, "-A", "AIVPN_KS", "-o", "lo", "-j", "ACCEPT"],
            vec![ipt, "-A", "AIVPN_KS", "-o", tun, "-j", "ACCEPT"],
            vec![ipt, "-A", "AIVPN_KS", "-d", sip, "-j", "ACCEPT"],
        ];
        // Marked traffic — the transport's own sockets (see `mark`). Must be
        // appended before the DROP that terminates the chain.
        if let Some(m) = mark_arg.as_deref() {
            cmds.push(vec![
                ipt, "-A", "AIVPN_KS", "-m", "mark", "--mark", m, "-j", "ACCEPT",
            ]);
        }
        cmds.push(vec![ipt, "-A", "AIVPN_KS", "-j", "DROP"]);
        for cmd in &cmds {
            let ok = Command::new(cmd[0])
                .args(&cmd[1..])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !ok {
                let _ = Command::new(ipt)
                    .args(["-D", "OUTPUT", "-j", "AIVPN_KS"])
                    .status();
                let _ = Command::new(ipt).args(["-F", "AIVPN_KS"]).status();
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::Other,
                    format!("kill-switch: {ipt} rule setup failed (nothing is blocked)"),
                )));
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn deactivate_impl(&self) {
        use std::process::Command;
        // Try nftables
        if Command::new("sh")
            .args(["-c", "nft list table inet aivpn_ks 2>/dev/null"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            let _ = Command::new("nft")
                .args(["delete", "table", "inet", "aivpn_ks"])
                .status();
            return;
        }
        // Fallback: iptables
        let _ = Command::new("iptables")
            .args(["-D", "OUTPUT", "-j", "AIVPN_KS"])
            .status();
        let _ = Command::new("iptables").args(["-F", "AIVPN_KS"]).status();
        let _ = Command::new("iptables").args(["-X", "AIVPN_KS"]).status();
    }

    #[cfg(target_os = "linux")]
    fn clear_stale_impl() {
        use std::process::Command;
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", "aivpn_ks"])
            .status();
        let _ = Command::new("iptables")
            .args(["-D", "OUTPUT", "-j", "AIVPN_KS"])
            .status();
        let _ = Command::new("iptables").args(["-F", "AIVPN_KS"]).status();
        let _ = Command::new("iptables").args(["-X", "AIVPN_KS"]).status();
    }

    // ──────────────────── macOS ────────────────────

    #[cfg(target_os = "macos")]
    fn activate_impl(&self) -> Result<()> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        use std::process::Command;

        let rules = format!(
            "block out all\npass out on lo0 all\npass out on {tun} all\npass out proto {{tcp,udp}} from any to {sip}\n",
            tun = self.tun_name,
            sip = self.server_ip,
        );

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

        // Enable pf if not already running (best-effort)
        let _ = Command::new("pfctl").args(["-e"]).status();

        // Inject anchor reference into running pf config if not present
        let already = Command::new("sh")
            .args(["-c", "pfctl -s all 2>/dev/null | grep -q aivpn_ks"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !already {
            let existing = std::fs::read_to_string("/etc/pf.conf").unwrap_or_default();
            let with_anchor = format!("{}\nanchor \"aivpn_ks\"\n", existing);
            let ref_file = "/var/run/aivpn/aivpn_ks_ref.conf";
            let _ = std::fs::remove_file(ref_file);
            let wrote = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(ref_file)
                .and_then(|mut f| {
                    use std::io::Write;
                    f.write_all(with_anchor.as_bytes())
                })
                .is_ok();
            if wrote {
                let _ = Command::new("pfctl").args(["-f", ref_file]).status();
            }
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn deactivate_impl(&self) {
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
    fn policy_save_path() -> std::path::PathBuf {
        std::path::PathBuf::from(
            std::env::var("SYSTEMROOT").unwrap_or_else(|_| "C:\\Windows".to_string()),
        )
        .join("Temp")
        .join("aivpn_ks_policy.txt")
    }

    #[cfg(target_os = "windows")]
    fn activate_impl(&self) -> Result<()> {
        use std::process::Command;

        // Save the current firewall policy so we can restore it on deactivate —
        // but ONLY on the first activation of this process. `tunnel.rs` builds a
        // brand-new `KillSwitch` (and `main.rs`'s reconnect loop a brand-new
        // `AivpnClient`) on every reconnect iteration, and kill-switch state is
        // intentionally left active across reconnect backoffs (deactivate only
        // runs on clean shutdown). If we re-query+overwrite the save file on
        // every activation, the second reconnect captures the ALREADY-BLOCKED
        // "allowinbound,blockoutbound" state as the "restore to" target — so
        // eventual deactivate() "restores" into a permanently blocked policy
        // with no allow rules, locking the user off the network. Only write
        // the save file if one doesn't already exist so the true pre-VPN
        // policy captured by the first activation always wins.
        let save_path = Self::policy_save_path();
        if !save_path.exists() {
            if let Ok(out) = Command::new("netsh")
                .args(["advfirewall", "show", "currentprofile", "firewallpolicy"])
                .output()
            {
                if let Some(p) = save_path.parent() {
                    let _ = std::fs::create_dir_all(p);
                }
                let _ = std::fs::write(&save_path, &out.stdout);
            }
        }

        // Set default outbound to block — allow rules below override this for
        // specific interfaces/IPs, so VPN traffic still flows.
        let status = Command::new("netsh")
            .args([
                "advfirewall",
                "set",
                "currentprofile",
                "firewallpolicy",
                "allowinbound,blockoutbound",
            ])
            .status()
            .map_err(Error::Io)?;
        if !status.success() {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::Other,
                "kill-switch: failed to set outbound block policy — Windows Firewall may be disabled, nothing is blocked",
            )));
        }

        // Add allow rules that override the default block for VPN traffic.
        // The block policy above is already live, so a failure here means
        // outbound traffic — including to the VPN server itself — stays
        // fully blocked with no way to reconnect. Fail loud and roll back
        // to the pre-activation policy instead of reporting "active".
        //
        // Delete any pre-existing rule of the same name first: every reconnect
        // picks a fresh random tun name (main.rs) and can select a different
        // pool server, so without this an `add rule` across reconnects leaves
        // every previous tun-name/server-IP allow rule in place — unbounded
        // firewall-table growth plus a widening allow-list for the process
        // lifetime. `delete rule` is a no-op (best-effort) when nothing matches.
        for (name, extra) in &[
            ("AIVPN_KS_ALLOW_VPN", format!("interface={}", self.tun_name)),
            (
                "AIVPN_KS_ALLOW_SERVER",
                format!("remoteip={}", self.server_ip),
            ),
            ("AIVPN_KS_ALLOW_LOCAL", "remoteip=127.0.0.0/8".to_string()),
        ] {
            let _ = Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={}", name),
                ])
                .status();
            let ok = Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={}", name),
                    "dir=out",
                    "action=allow",
                    extra.as_str(),
                ])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !ok {
                self.deactivate_impl();
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "kill-switch: failed to add allow rule '{name}' — rolled back \
                         (outbound was fully blocked with no allow rules, which would \
                         have locked out the VPN server itself)"
                    ),
                )));
            }
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn deactivate_impl(&self) {
        use std::process::Command;

        // Remove allow rules
        for name in &[
            "AIVPN_KS_ALLOW_VPN",
            "AIVPN_KS_ALLOW_SERVER",
            "AIVPN_KS_ALLOW_LOCAL",
        ] {
            let _ = Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={}", name),
                ])
                .status();
        }

        // Restore saved policy, or fall back to allow
        let save_path = Self::policy_save_path();
        let restored = if save_path.exists() {
            if let Ok(saved) = std::fs::read_to_string(&save_path) {
                // The policy label is locale-specific ("Firewall Policy" in EN,
                // "Firewallrichtlinie" in DE, "Политика брандмауэра" in RU, …) but
                // the VALUE is always English: "(Block|Allow)Inbound,(Block|Allow)Outbound".
                // Match by value shape, not by label, so any Windows locale works.
                saved.lines().find_map(|l| {
                    let v = l.split(':').last().unwrap_or(l).trim().to_lowercase();
                    if (v.starts_with("allowinbound") || v.starts_with("blockinbound"))
                        && (v.ends_with("allowoutbound") || v.ends_with("blockoutbound"))
                    {
                        Some(v)
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        } else {
            None
        };

        let policy = restored.as_deref().unwrap_or("allowinbound,allowoutbound");
        let _ = Command::new("netsh")
            .args([
                "advfirewall",
                "set",
                "currentprofile",
                "firewallpolicy",
                policy,
            ])
            .status();
        let _ = std::fs::remove_file(&save_path);
    }

    #[cfg(target_os = "windows")]
    fn clear_stale_impl() {
        // Reuse deactivate_impl logic via a temporary instance
        let ks = KillSwitch {
            tun_name: String::new(),
            server_ip: String::new(),
            active: true,
        };
        ks.deactivate_impl();
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
