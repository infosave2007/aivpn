//! NAT Forwarder Module
//!
//! Handles TUN device creation, packet forwarding, and NAT masquerading.
//! Detects nftables vs iptables at runtime; manages rules idempotently so
//! that server restarts never accumulate duplicate firewall entries.

use std::io;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
#[cfg(target_os = "linux")]
use tracing::warn;
use tracing::{debug, info};

use aivpn_common::error::{Error, Result};
use aivpn_common::network_config::VpnNetworkConfig;

/// Default server TUN MTU.  Aligned with DEFAULT_VPN_MTU (1346) so the server→client
/// outer UDP datagram stays ≤ 1424 bytes on the wire (inner 1346 + ~50 aivpn overhead
/// + 28 outer IP/UDP).  This safely clears LTE/GTP-U paths (≈1464 effective MTU) and
/// CGNAT carriers such as Megafon/MTS.  Higher values like 1420 produce ≥1498-byte
/// datagrams that fragment on cellular paths — CGNAT drops fragments → RX=0.
pub const DEFAULT_TUN_MTU: u16 = 1346;

// ── Firewall backend ───────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FwBackend {
    Nftables,
    Iptables,
}

/// Detect which firewall backend is available. Prefers nftables.
#[cfg(target_os = "linux")]
fn detect_fw_backend() -> FwBackend {
    use std::process::Command;
    let ok = Command::new("nft")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if ok {
        FwBackend::Nftables
    } else {
        FwBackend::Iptables
    }
}

/// Chain to hang the compatibility accepts on, and whether they are needed.
///
/// netfilter runs the legacy iptables FORWARD hook independently of our nft
/// table, so a forwarded packet must be accepted by BOTH. Docker sets
/// `-P FORWARD DROP` on the host, which means an nft-only ruleset silently
/// drops every client packet: the traffic reaches the server's tun and nothing
/// ever leaves it. Prefer `DOCKER-USER` (Docker never flushes it, so the rules
/// survive a Docker reload); fall back to `FORWARD` when that chain is absent.
#[cfg(target_os = "linux")]
fn iptables_forward_compat_chain() -> Option<&'static str> {
    use std::process::Command;
    let policy_is_drop = Command::new("iptables")
        .args(["-S", "FORWARD"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("-P FORWARD DROP"))
        .unwrap_or(false);
    if !policy_is_drop {
        return None;
    }
    let has_docker_user = Command::new("iptables")
        .args(["-S", "DOCKER-USER"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    Some(if has_docker_user {
        "DOCKER-USER"
    } else {
        "FORWARD"
    })
}

/// Add an iptables rule only if an identical rule does not already exist.
#[cfg(target_os = "linux")]
fn ipt_ensure(table: &str, chain: &str, rule: &[&str]) {
    use std::process::Command;
    let mut check: Vec<&str> = vec!["-t", table, "-C", chain];
    check.extend_from_slice(rule);
    let exists = Command::new("iptables")
        .args(&check)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !exists {
        let mut add: Vec<&str> = vec!["-t", table, "-A", chain];
        add.extend_from_slice(rule);
        if let Ok(out) = Command::new("iptables").args(&add).output() {
            if !out.status.success() {
                warn!(
                    "iptables add failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
    }
}

/// Delete an iptables rule (best-effort; silently ignores "not found").
#[cfg(target_os = "linux")]
fn ipt_delete(table: &str, chain: &str, rule: &[&str]) {
    use std::process::Command;
    let mut del: Vec<&str> = vec!["-t", table, "-D", chain];
    del.extend_from_slice(rule);
    let _ = Command::new("iptables").args(&del).output();
}

// ── IPv6 NAT66 helpers ────────────────────────────────────────────────────

/// Assign an IPv6 address to a TUN interface.
///
/// Equivalent to: `ip -6 addr add <addr>/<prefix_len> dev <tun_name>`
#[cfg(target_os = "linux")]
pub fn assign_ipv6_to_tun(
    tun_name: &str,
    addr: &str,
    prefix_len: u8,
) -> std::result::Result<(), String> {
    use std::process::Command;
    let cidr = format!("{}/{}", addr, prefix_len);
    let out = Command::new("ip")
        .args(["-6", "addr", "add", &cidr, "dev", tun_name])
        .output()
        .map_err(|e| format!("ip addr add ipv6 spawn: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // "RTNETLINK answers: File exists" means the address is already set — treat as OK.
        if stderr.contains("File exists") {
            return Ok(());
        }
        Err(format!("ip -6 addr add failed: {stderr}"))
    }
}

#[cfg(not(target_os = "linux"))]
pub fn assign_ipv6_to_tun(
    _tun_name: &str,
    _addr: &str,
    _prefix_len: u8,
) -> std::result::Result<(), String> {
    Err("assign_ipv6_to_tun is only supported on Linux".to_string())
}

/// Install NAT66 masquerading rules for the given ULA prefix.
///
/// Uses the same nftables/iptables auto-detection as the IPv4 path.
/// The nftables table is named `aivpn6`; ip6tables rules carry the `aivpn`
/// comment tag for easy identification/removal.
#[cfg(target_os = "linux")]
pub fn setup_nat66(tun_name: &str, prefix: &str) -> std::result::Result<(), String> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    // Enable IPv6 forwarding (idempotent).
    let fwd = std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding").unwrap_or_default();
    if fwd.trim() != "1" {
        let _ = std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1");
    }

    let use_nft = Command::new("nft")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if use_nft {
        // Remove stale table from a previous run.
        let _ = Command::new("nft")
            .args(["delete", "table", "ip6", "aivpn6"])
            .output();

        let ruleset = format!(
            "table ip6 aivpn6 {{\n\
             \tchain nat_out {{\n\
             \t\ttype nat hook postrouting priority srcnat;\n\
             \t\tip6 saddr {prefix} masquerade\n\
             \t}}\n\
             \tchain forward {{\n\
             \t\ttype filter hook forward priority filter;\n\
             \t\tiifname \"{tun_name}\" accept\n\
             \t\toifname \"{tun_name}\" ct state related,established accept\n\
             \t}}\n\
             }}\n"
        );

        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("nft spawn (nat66): {e}"))?;

        if let Some(stdin) = child.stdin.as_mut() {
            let _ = stdin.write_all(ruleset.as_bytes());
        }
        let out = child
            .wait_with_output()
            .map_err(|e| format!("nft wait (nat66): {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "nftables nat66 setup failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        info!("nftables: aivpn6 table installed (NAT66 + forward)");
    } else {
        // ip6tables fallback.
        let c = "aivpn";
        ip6t_ensure(
            "nat",
            "POSTROUTING",
            &[
                "-s",
                prefix,
                "-m",
                "comment",
                "--comment",
                c,
                "-j",
                "MASQUERADE",
            ],
        );
        ip6t_ensure(
            "filter",
            "FORWARD",
            &[
                "-i",
                tun_name,
                "-m",
                "comment",
                "--comment",
                c,
                "-j",
                "ACCEPT",
            ],
        );
        ip6t_ensure(
            "filter",
            "FORWARD",
            &[
                "-o",
                tun_name,
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-m",
                "comment",
                "--comment",
                c,
                "-j",
                "ACCEPT",
            ],
        );
        info!("ip6tables: aivpn NAT66 + forward rules installed");
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn setup_nat66(_tun_name: &str, _prefix: &str) -> std::result::Result<(), String> {
    Err("setup_nat66 is only supported on Linux".to_string())
}

/// Remove NAT66 masquerading rules installed by [`setup_nat66`].
#[cfg(target_os = "linux")]
pub fn teardown_nat66(tun_name: &str, prefix: &str) -> std::result::Result<(), String> {
    use std::process::Command;

    let use_nft = Command::new("nft")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if use_nft {
        let _ = Command::new("nft")
            .args(["delete", "table", "ip6", "aivpn6"])
            .output();
        info!("nftables: aivpn6 table removed");
    } else {
        let c = "aivpn";
        ip6t_delete(
            "nat",
            "POSTROUTING",
            &[
                "-s",
                prefix,
                "-m",
                "comment",
                "--comment",
                c,
                "-j",
                "MASQUERADE",
            ],
        );
        ip6t_delete(
            "filter",
            "FORWARD",
            &[
                "-i",
                tun_name,
                "-m",
                "comment",
                "--comment",
                c,
                "-j",
                "ACCEPT",
            ],
        );
        ip6t_delete(
            "filter",
            "FORWARD",
            &[
                "-o",
                tun_name,
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-m",
                "comment",
                "--comment",
                c,
                "-j",
                "ACCEPT",
            ],
        );
        info!("ip6tables: aivpn NAT66 rules removed");
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn teardown_nat66(_tun_name: &str, _prefix: &str) -> std::result::Result<(), String> {
    Err("teardown_nat66 is only supported on Linux".to_string())
}

/// Add an ip6tables rule only if an identical rule does not already exist.
#[cfg(target_os = "linux")]
fn ip6t_ensure(table: &str, chain: &str, rule: &[&str]) {
    use std::process::Command;
    let mut check: Vec<&str> = vec!["-t", table, "-C", chain];
    check.extend_from_slice(rule);
    let exists = Command::new("ip6tables")
        .args(&check)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !exists {
        let mut add: Vec<&str> = vec!["-t", table, "-A", chain];
        add.extend_from_slice(rule);
        if let Ok(out) = Command::new("ip6tables").args(&add).output() {
            if !out.status.success() {
                warn!(
                    "ip6tables add failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
    }
}

/// Delete an ip6tables rule (best-effort; silently ignores "not found").
#[cfg(target_os = "linux")]
fn ip6t_delete(table: &str, chain: &str, rule: &[&str]) {
    use std::process::Command;
    let mut del: Vec<&str> = vec!["-t", table, "-D", chain];
    del.extend_from_slice(rule);
    let _ = Command::new("ip6tables").args(&del).output();
}

// ── NatForwarder ───────────────────────────────────────────────────────────

/// NAT Forwarder for routing VPN client traffic to the internet.
pub struct NatForwarder {
    tun_name: String,
    tun_addr: String,
    tun_netmask: String,
    tun_mtu: u16,
    network_config: VpnNetworkConfig,
    writer_taken: Option<Mutex<Option<tun::DeviceWriter>>>,
    reader: Option<Mutex<Option<tun::DeviceReader>>>,
    #[cfg(target_os = "linux")]
    fw_backend: Option<FwBackend>,
}

impl NatForwarder {
    pub fn new(
        tun_name: &str,
        tun_addr: &str,
        tun_netmask: &str,
        tun_mtu: u16,
        network_config: VpnNetworkConfig,
    ) -> Result<Self> {
        Ok(Self {
            tun_name: tun_name.to_string(),
            tun_addr: tun_addr.to_string(),
            tun_netmask: tun_netmask.to_string(),
            tun_mtu,
            network_config,
            writer_taken: None,
            reader: None,
            #[cfg(target_os = "linux")]
            fw_backend: None,
        })
    }

    /// Create TUN device and install firewall rules.
    pub fn create(&mut self) -> Result<()> {
        // H-S-3: reject tun_name that could inject into nftables/iptables format strings.
        Self::validate_tun_name(&self.tun_name)?;

        let mut config = tun::Configuration::default();

        config
            .tun_name(&self.tun_name)
            .address(&self.tun_addr)
            .netmask(&self.tun_netmask)
            .mtu(self.tun_mtu)
            .up();

        #[cfg(target_os = "linux")]
        config.platform_config(|config| {
            config.ensure_root_privileges(true);
        });

        let dev = tun::create_as_async(&config)
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;

        let (writer, reader) = dev
            .split()
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
        self.writer_taken = Some(Mutex::new(Some(writer)));
        self.reader = Some(Mutex::new(Some(reader)));

        info!(
            "Created NAT TUN device: {} ({}/{}, subnet {}, mtu {})",
            self.tun_name,
            self.tun_addr,
            self.tun_netmask,
            self.network_config.cidr_string(),
            self.tun_mtu,
        );

        #[cfg(target_os = "linux")]
        {
            self.enable_ip_forwarding()?;
            let backend = detect_fw_backend();
            info!("Firewall backend: {:?}", backend);
            match backend {
                FwBackend::Nftables => {
                    match self.setup_nftables() {
                        Ok(()) => {
                            // See `iptables_forward_compat_chain`: on a host where Docker
                            // set `-P FORWARD DROP`, nft accepts alone are not enough.
                            if let Some(chain) = iptables_forward_compat_chain() {
                                let tun = self.tun_name.clone();
                                ipt_ensure("filter", chain, &["-i", &tun, "-j", "ACCEPT"]);
                                ipt_ensure(
                                    "filter",
                                    chain,
                                    &[
                                        "-o",
                                        &tun,
                                        "-m",
                                        "conntrack",
                                        "--ctstate",
                                        "ESTABLISHED,RELATED",
                                        "-j",
                                        "ACCEPT",
                                    ],
                                );
                                info!(
                                    "iptables: FORWARD policy is DROP — added {chain} accepts for {tun} \
                                     so nftables-forwarded client traffic is not dropped by the legacy hook"
                                );
                            }
                            self.fw_backend = Some(FwBackend::Nftables);
                        }
                        Err(e) => {
                            // The nft binary exists but the ruleset did not apply
                            // (no CAP_NET_ADMIN, kernel without nf_tables, seccomp).
                            // detect_fw_backend() only probes the binary, so without
                            // this fallback the server would start with NO masquerade/
                            // forward rules at all and every client would be offline.
                            // `nft -f -` is atomic, so a failed apply leaves no
                            // partial `aivpn` table behind for the iptables path to
                            // conflict with.
                            warn!("nftables setup failed ({}) — falling back to iptables", e);
                            self.setup_iptables().map_err(|ipt_e| {
                                Error::Io(io::Error::new(
                                    io::ErrorKind::Other,
                                    format!(
                                        "firewall setup failed on both backends: nftables: {}; iptables: {}",
                                        e, ipt_e
                                    ),
                                ))
                            })?;
                            self.fw_backend = Some(FwBackend::Iptables);
                        }
                    }
                }
                FwBackend::Iptables => {
                    self.setup_iptables()?;
                    self.fw_backend = Some(FwBackend::Iptables);
                }
            }
        }

        Ok(())
    }

    /// Enable IPv4 forwarding (idempotent — checks before writing).
    #[cfg(target_os = "linux")]
    fn enable_ip_forwarding(&self) -> Result<()> {
        use std::fs::{read_to_string, write};

        if let Ok(val) = read_to_string("/proc/sys/net/ipv4/ip_forward") {
            if val.trim() == "1" {
                info!("IPv4 forwarding already enabled");
                return Ok(());
            }
        }
        write("/proc/sys/net/ipv4/ip_forward", "1").map_err(|e| {
            Error::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("Failed to enable IP forwarding: {e}"),
            ))
        })?;
        info!("Enabled IPv4 forwarding");
        Ok(())
    }

    /// Validate that tun_name is safe to interpolate into nftables/iptables
    /// format strings (H-S-3). Accepts names matching ^[a-z][a-z0-9_-]{0,14}$.
    fn validate_tun_name(name: &str) -> Result<()> {
        let ok = !name.is_empty()
            && name.len() <= 15
            && name.starts_with(|c: char| c.is_ascii_lowercase())
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
        if ok {
            Ok(())
        } else {
            Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "tun_name '{}' is invalid: must match ^[a-z][a-z0-9_-]{{0,14}}$",
                    name
                ),
            )))
        }
    }

    /// Install nftables rules inside a dedicated `aivpn` table.
    ///
    /// The table is deleted first (if it exists from a previous run) and then
    /// recreated atomically so there are never duplicate rules.
    #[cfg(target_os = "linux")]
    fn setup_nftables(&self) -> Result<()> {
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        let cidr = self.network_config.cidr_string();
        let tun = &self.tun_name;

        // Remove stale table from a previous server run (idempotent).
        let _ = Command::new("nft")
            .args(["delete", "table", "ip", "aivpn"])
            .output();

        // Build and apply the full ruleset atomically via `nft -f -`.
        let ruleset = format!(
            "table ip aivpn {{\n\
             \tchain nat_out {{\n\
             \t\ttype nat hook postrouting priority srcnat;\n\
             \t\tip saddr {cidr} masquerade\n\
             \t}}\n\
             \tchain forward {{\n\
             \t\ttype filter hook forward priority filter;\n\
             \t\tiifname \"{tun}\" accept\n\
             \t\toifname \"{tun}\" ct state related,established accept\n\
             \t\toifname \"{tun}\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu\n\
             \t\tiifname \"{tun}\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu\n\
             \t}}\n\
             }}\n"
        );

        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                Error::Io(io::Error::new(
                    io::ErrorKind::Other,
                    format!("nft spawn: {e}"),
                ))
            })?;

        if let Some(stdin) = child.stdin.as_mut() {
            let _ = stdin.write_all(ruleset.as_bytes());
        }

        let out = child.wait_with_output().map_err(|e| {
            Error::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("nft wait: {e}"),
            ))
        })?;

        if out.status.success() {
            info!("nftables: aivpn table installed (NAT + forward + MSS clamp)");
            Ok(())
        } else {
            // stderr alone can be empty (e.g. nft killed by a seccomp SIGSYS in
            // a container) — always include the exit status and stdout so the
            // failure is diagnosable from the log. Returning Err (instead of
            // swallowing the failure) lets create() fall back to iptables —
            // mirroring setup_nat66, which already fails hard here.
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            Err(Error::Io(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "nftables setup failed (status: {}): {}{}",
                    out.status,
                    if stderr.trim().is_empty() {
                        "<no stderr>"
                    } else {
                        stderr.trim()
                    },
                    if stdout.trim().is_empty() {
                        String::new()
                    } else {
                        format!(" | stdout: {}", stdout.trim())
                    }
                ),
            )))
        }
    }

    /// Install iptables rules with check-before-add idempotency.
    ///
    /// Each rule is tagged with `-m comment --comment aivpn` so that Drop
    /// can remove only our rules without touching any pre-existing ones.
    #[cfg(target_os = "linux")]
    fn setup_iptables(&self) -> Result<()> {
        let cidr = self.network_config.cidr_string();
        let tun = &self.tun_name;
        let c = "aivpn";

        ipt_ensure(
            "nat",
            "POSTROUTING",
            &[
                "-s",
                &cidr,
                "-m",
                "comment",
                "--comment",
                c,
                "-j",
                "MASQUERADE",
            ],
        );
        ipt_ensure(
            "filter",
            "FORWARD",
            &["-i", tun, "-m", "comment", "--comment", c, "-j", "ACCEPT"],
        );
        ipt_ensure(
            "filter",
            "FORWARD",
            &[
                "-o",
                tun,
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-m",
                "comment",
                "--comment",
                c,
                "-j",
                "ACCEPT",
            ],
        );
        ipt_ensure(
            "mangle",
            "FORWARD",
            &[
                "-o",
                tun,
                "-p",
                "tcp",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
                "-m",
                "comment",
                "--comment",
                c,
                "-j",
                "TCPMSS",
                "--clamp-mss-to-pmtu",
            ],
        );
        ipt_ensure(
            "mangle",
            "FORWARD",
            &[
                "-i",
                tun,
                "-p",
                "tcp",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
                "-m",
                "comment",
                "--comment",
                c,
                "-j",
                "TCPMSS",
                "--clamp-mss-to-pmtu",
            ],
        );

        info!("iptables: aivpn NAT + forward + MSS clamp rules installed");
        Ok(())
    }

    /// Forward a packet to the TUN interface (write path, fallback when writer task not spawned).
    pub async fn forward_packet(&self, packet: &[u8]) -> Result<()> {
        let taken = self.writer_taken.as_ref().ok_or_else(|| {
            Error::Io(io::Error::new(
                io::ErrorKind::NotConnected,
                "TUN device not created",
            ))
        })?;
        let mut guard = taken.lock().await;
        let writer = guard.as_mut().ok_or_else(|| {
            Error::Io(io::Error::new(
                io::ErrorKind::NotConnected,
                "TUN writer already taken by writer task",
            ))
        })?;
        writer.write_all(packet).await?;
        debug!("Forwarded {} bytes to TUN", packet.len());
        Ok(())
    }

    /// Take ownership of the TUN writer (for use in a dedicated writer task).
    pub async fn take_writer(&self) -> Option<tun::DeviceWriter> {
        if let Some(ref lock) = self.writer_taken {
            lock.lock().await.take()
        } else {
            None
        }
    }

    /// Take ownership of the TUN reader (for use in a spawned reader task).
    pub async fn take_reader(&self) -> Option<tun::DeviceReader> {
        if let Some(reader_lock) = &self.reader {
            reader_lock.lock().await.take()
        } else {
            None
        }
    }

    /// Return the TUN device name.
    pub fn tun_name(&self) -> &str {
        &self.tun_name
    }
}

impl Drop for NatForwarder {
    fn drop(&mut self) {
        if self.writer_taken.is_some() {
            info!("Closing NAT TUN device: {}", self.tun_name);
        }

        #[cfg(target_os = "linux")]
        {
            // Tear down the IPv6 NAT66 rules installed by setup_nat66 when IPv6 was
            // enabled — the IPv4 cleanup below only removes the `aivpn` table, so
            // without this the `aivpn6` table / ip6tables MASQUERADE+FORWARD rules
            // leaked on the host after shutdown.
            if self.network_config.ipv6_enabled {
                let _ = teardown_nat66(&self.tun_name, &self.network_config.ipv6_prefix);
            }
            match self.fw_backend {
                Some(FwBackend::Nftables) => {
                    use std::process::Command;
                    let _ = Command::new("nft")
                        .args(["delete", "table", "ip", "aivpn"])
                        .output();
                    info!("nftables: aivpn table removed");
                    // Symmetric cleanup of the legacy-hook compatibility accepts.
                    if let Some(chain) = iptables_forward_compat_chain() {
                        let tun = self.tun_name.clone();
                        ipt_delete("filter", chain, &["-i", &tun, "-j", "ACCEPT"]);
                        ipt_delete(
                            "filter",
                            chain,
                            &[
                                "-o",
                                &tun,
                                "-m",
                                "conntrack",
                                "--ctstate",
                                "ESTABLISHED,RELATED",
                                "-j",
                                "ACCEPT",
                            ],
                        );
                    }
                }
                Some(FwBackend::Iptables) => {
                    let cidr = self.network_config.cidr_string();
                    let tun = &self.tun_name;
                    let c = "aivpn";

                    ipt_delete(
                        "nat",
                        "POSTROUTING",
                        &[
                            "-s",
                            &cidr,
                            "-m",
                            "comment",
                            "--comment",
                            c,
                            "-j",
                            "MASQUERADE",
                        ],
                    );
                    ipt_delete(
                        "filter",
                        "FORWARD",
                        &["-i", tun, "-m", "comment", "--comment", c, "-j", "ACCEPT"],
                    );
                    ipt_delete(
                        "filter",
                        "FORWARD",
                        &[
                            "-o",
                            tun,
                            "-m",
                            "conntrack",
                            "--ctstate",
                            "RELATED,ESTABLISHED",
                            "-m",
                            "comment",
                            "--comment",
                            c,
                            "-j",
                            "ACCEPT",
                        ],
                    );
                    ipt_delete(
                        "mangle",
                        "FORWARD",
                        &[
                            "-o",
                            tun,
                            "-p",
                            "tcp",
                            "--tcp-flags",
                            "SYN,RST",
                            "SYN",
                            "-m",
                            "comment",
                            "--comment",
                            c,
                            "-j",
                            "TCPMSS",
                            "--clamp-mss-to-pmtu",
                        ],
                    );
                    ipt_delete(
                        "mangle",
                        "FORWARD",
                        &[
                            "-i",
                            tun,
                            "-p",
                            "tcp",
                            "--tcp-flags",
                            "SYN,RST",
                            "SYN",
                            "-m",
                            "comment",
                            "--comment",
                            c,
                            "-j",
                            "TCPMSS",
                            "--clamp-mss-to-pmtu",
                        ],
                    );
                    info!("iptables: aivpn rules removed");
                }
                None => {}
            }
        }
    }
}
