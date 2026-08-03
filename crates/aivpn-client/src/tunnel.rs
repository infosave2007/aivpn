//! Tunnel Module - Cross-platform TUN Device Integration
//!
//! Supports Linux, macOS and Windows.
//! Handles TUN device creation, packet capture, and routing.

use std::io;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info, warn};

use crate::kill_switch::KillSwitch;
use aivpn_common::error::{Error, Result};
use aivpn_common::network_config::{ClientNetworkConfig, VpnNetworkConfig, LEGACY_SERVER_VPN_IP};

// Real worst-case outer overhead per packet:
//   TAG(8) + MDH(varies, default 20) + pad_len(2) + inner_hdr(4) + random_padding(≤24) + Poly1305(16) ≈ 74 bytes.
// Masks with MDH > ~40 bytes require a lower negotiated client MTU via ServerHello network_config.
const WAN_SAFE_TUN_MTU: u16 = 1346;

/// Whether the current process has an elevated (Administrator) token.
/// Creating a Wintun adapter always requires this on Windows — there is no
/// capability-based model like Linux's CAP_NET_ADMIN to scope it down to.
/// Checked before attempting adapter creation so a non-admin run fails with
/// a clear, actionable message instead of the underlying `tun` crate's raw
/// `WintunCreateAdapter failed "No inner logs"` (the OS often doesn't give
/// the driver a more specific reason for this particular failure mode).
#[cfg(target_os = "windows")]
fn is_elevated() -> bool {
    use std::mem;
    use std::ptr;
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
    use winapi::um::securitybaseapi::GetTokenInformation;
    use winapi::um::winnt::{TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};

    unsafe {
        let mut token = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            // Can't even query — assume not elevated rather than risk a
            // false "you're fine" that masks the real WintunCreateAdapter
            // error later.
            return false;
        }

        let mut elevation: TOKEN_ELEVATION = mem::zeroed();
        let mut ret_size: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut winapi::ctypes::c_void,
            mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_size,
        );
        winapi::um::handleapi::CloseHandle(token);

        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// Tunnel configuration
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub tun_name: String,
    pub tun_addr: String,
    pub server_vpn_ip: String,
    pub tun_netmask: String,
    pub prefix_len: u8,
    pub mtu: u16,
    /// Route all traffic through VPN (full tunnel mode)
    pub full_tunnel: bool,
    /// MDH (mask-defined header) byte count for the initial mask.
    /// Must match the server's active mask to avoid packet decode failures on connect.
    pub mdh_len: u16,
    /// CIDRs to route through VPN in split mode (e.g. "10.0.0.0/8,192.168.1.0/24")
    pub include_routes: Vec<String>,
    /// CIDRs to bypass the VPN even in full-tunnel mode
    pub exclude_routes: Vec<String>,
    /// Block all non-VPN traffic while the tunnel is up (kill-switch)
    pub kill_switch: bool,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        use rand::Rng;
        Self {
            tun_name: format!("tun{:04x}", rand::thread_rng().gen::<u16>()),
            tun_addr: "10.0.0.2".to_string(),
            server_vpn_ip: LEGACY_SERVER_VPN_IP.to_string(),
            tun_netmask: "255.255.255.0".to_string(),
            prefix_len: 24,
            mtu: WAN_SAFE_TUN_MTU,
            full_tunnel: false,
            mdh_len: 20u16,
            include_routes: Vec::new(),
            exclude_routes: Vec::new(),
            kill_switch: false,
        }
    }
}

impl TunnelConfig {
    pub fn from_network_config(
        tun_name: String,
        network_config: ClientNetworkConfig,
        full_tunnel: bool,
    ) -> Self {
        // Clamp to MAX_PACKET_SIZE (1500): client.rs's FecEncoder is
        // hardcoded to a 1500-byte parity buffer
        // (`FecEncoder::new(fec_n, 1500)`), and `FecEncoder::feed()` silently
        // truncates anything longer — bytes beyond 1500 never get XORed into
        // repair parity, so any lost packet in a group containing an
        // oversized member gets "recovered" corrupted/truncated instead of
        // failing loudly. `network_config.mtu` is server-controlled (pushed
        // in `apply_server_network_override`) as well as
        // config-file/bootstrap-controlled here at startup, up to u16::MAX —
        // this is the single choke point both paths route through before a
        // `TunnelConfig` (and the MTU actually applied to the TUN device) is
        // produced.
        let mtu = network_config
            .mtu
            .min(aivpn_common::protocol::MAX_PACKET_SIZE as u16);
        Self {
            tun_name,
            tun_addr: network_config.client_ip.to_string(),
            server_vpn_ip: network_config.server_vpn_ip.to_string(),
            tun_netmask: network_config.netmask_string(),
            prefix_len: network_config.prefix_len,
            mtu,
            full_tunnel,
            mdh_len: network_config.mdh_len,
            include_routes: Vec::new(),
            exclude_routes: Vec::new(),
            kill_switch: false,
        }
    }

    pub fn client_network_config(&self) -> Result<ClientNetworkConfig> {
        let client_ip = self.configured_client_ip()?;
        let server_vpn_ip = self.configured_server_vpn_ip()?;
        let network_config = ClientNetworkConfig {
            client_ip,
            server_vpn_ip,
            prefix_len: self.prefix_len,
            mtu: self.mtu,
            mdh_len: self.mdh_len,
            keepalive_secs: None,
            ipv6_address: None,
        };
        network_config.validate()?;
        Ok(network_config)
    }

    fn configured_client_ip(&self) -> Result<std::net::Ipv4Addr> {
        self.tun_addr.parse().map_err(|e| {
            Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid configured client IP {}: {}", self.tun_addr, e),
            ))
        })
    }

    fn configured_server_vpn_ip(&self) -> Result<std::net::Ipv4Addr> {
        self.server_vpn_ip.parse().map_err(|e| {
            Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Invalid configured server VPN IP {}: {}",
                    self.server_vpn_ip, e
                ),
            ))
        })
    }

    fn vpn_network_config(&self) -> Result<VpnNetworkConfig> {
        let network_config = VpnNetworkConfig {
            server_vpn_ip: self.configured_server_vpn_ip()?,
            prefix_len: self.prefix_len,
            mtu: self.mtu,
            keepalive_secs: None,
            ipv6_enabled: false,
            ipv6_prefix: "fd10:cafe::/48".to_string(),
        };
        network_config.validate()?;
        Ok(network_config)
    }
}

/// TUN Tunnel for packet capture
pub struct Tunnel {
    config: TunnelConfig,
    reader: Option<tun::DeviceReader>,
    writer: Option<tun::DeviceWriter>,
    /// Saved default gateway for full-tunnel restore
    saved_default_gw: Option<String>,
    /// Saved default device for full-tunnel restore on Linux (e.g. "eth0").
    /// Stored alongside saved_default_gw; used in disable_full_tunnel().
    saved_default_dev: Option<String>,
    /// Server IP for bypass route cleanup
    server_ip: Option<String>,
    /// Active IPv6 interface name saved before we add the blackhole route.
    /// Used to restore the route on disconnect instead of guessing (e.g. hard-coding en0).
    /// Only read in the macOS restore_ipv6 path; allow(dead_code) silences Linux build warnings.
    #[allow(dead_code)]
    saved_ipv6_iface: Option<String>,
    /// Windows: wintun adapter interface index for explicit route binding.
    /// Without this, `route add` may bind VPN routes to the physical NIC.
    /// Only read in Windows-gated code paths; allow(dead_code) silences Linux/macOS build warnings.
    #[allow(dead_code)]
    wintun_if_index: Option<String>,
    /// CIDRs added by apply_split_routes — removed on Drop.
    split_routes_applied: Vec<String>,
    /// Active kill-switch instance; deactivated on graceful Drop.
    kill_switch_state: Option<KillSwitch>,
}

/// PID of a currently in-flight `pkexec` child spawned by
/// `Tunnel::run_via_pkexec_stdin`, if any (0 = none). Tracked so the client
/// can attempt to kill it from its own shutdown/Drop path —
/// `Tunnel::drop()` calls `kill_orphaned_pkexec_child()` — instead of
/// leaving it reparented to init (and the polkit auth dialog still showing)
/// if this process is killed/crashes while the dialog is up.
///
/// This is necessarily a best-effort, PARTIAL mitigation, not a full fix:
/// `pkexec` is normally installed setuid-root, so it runs with euid 0 from
/// the instant of its own `exec()` — before the auth dialog even appears.
/// An unprivileged client cannot `kill()` a process it doesn't own (EPERM);
/// the same setuid-exec rule is also why `PR_SET_PDEATHSIG` doesn't help
/// here (the kernel clears it on any setuid/capability-bearing exec). So
/// this fully closes the orphan window only when the client itself runs as
/// root (a supported/documented mode — see vpn_manager.rs); for an
/// unprivileged client it's a harmless no-op attempt, no worse than the
/// prior status quo, and still covers the actual reachable case of a clean
/// disconnect/reconnect/panic-unwind racing an open auth dialog (Drop runs
/// on all of those, just not on SIGKILL of this process).
#[cfg(target_os = "linux")]
static ACTIVE_PKEXEC_PID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Best-effort kill of a tracked in-flight `pkexec` child. See
/// `ACTIVE_PKEXEC_PID` for why this can't be a complete fix.
#[cfg(target_os = "linux")]
fn kill_orphaned_pkexec_child() {
    let pid = ACTIVE_PKEXEC_PID.swap(0, std::sync::atomic::Ordering::SeqCst);
    if pid != 0 {
        // SAFETY: FFI call to kill(2) with a pid we obtained from our own
        // Child::id() and an integer signal constant — no pointers involved.
        // A permission failure (pid already root-owned) or a stale pid
        // (process already exited) both just return an ignored errno; this
        // is best-effort cleanup, not a correctness-critical path.
        unsafe {
            libc::kill(pid as i32, libc::SIGKILL);
        }
    }
}

impl Tunnel {
    pub fn new(config: TunnelConfig) -> Self {
        Self {
            config,
            reader: None,
            writer: None,
            saved_default_gw: None,
            saved_default_dev: None,
            server_ip: None,
            saved_ipv6_iface: None,
            wintun_if_index: None,
            split_routes_applied: Vec::new(),
            kill_switch_state: None,
        }
    }

    #[cfg(target_os = "windows")]
    fn windows_command_output(output: &std::process::Output) -> String {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

        match (stdout.is_empty(), stderr.is_empty()) {
            (false, false) => format!("{} | {}", stdout, stderr),
            (false, true) => stdout,
            (true, false) => stderr,
            (true, true) => format!("route exited with status {}", output.status),
        }
    }

    #[cfg(target_os = "windows")]
    fn run_windows_route(args: &[&str], context: &str) -> Result<std::process::Output> {
        std::process::Command::new("route")
            .args(args)
            .output()
            .map_err(|e| {
                Error::Io(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to run route for {}: {}", context, e),
                ))
            })
    }

    #[cfg(target_os = "windows")]
    fn add_windows_route_with_retry(
        &self,
        add_args: &[&str],
        delete_args: &[&str],
        success_message: &str,
        context: &str,
    ) -> Result<()> {
        let first_attempt = Self::run_windows_route(add_args, context)?;
        if first_attempt.status.success() {
            info!("{}", success_message);
            return Ok(());
        }

        let first_error = Self::windows_command_output(&first_attempt);
        debug!("Initial route add failed for {}: {}", context, first_error);

        let delete_attempt = Self::run_windows_route(delete_args, context)?;
        if !delete_attempt.status.success() {
            debug!(
                "Route delete before retry failed for {}: {}",
                context,
                Self::windows_command_output(&delete_attempt)
            );
        }

        let retry_attempt = Self::run_windows_route(add_args, context)?;
        if retry_attempt.status.success() {
            info!("{}", success_message);
            return Ok(());
        }

        Err(Error::Io(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Failed to configure {} after retry: {}",
                context,
                Self::windows_command_output(&retry_attempt)
            ),
        )))
    }

    /// Create TUN device (works on Linux, macOS, Windows)
    pub async fn create(&mut self) -> Result<()> {
        let mut config_builder = tun::Configuration::default();

        config_builder
            .address(&self.config.tun_addr)
            .netmask(&self.config.tun_netmask)
            .up();

        // Windows: skip MTU via tun config — SetIpInterfaceEntry called by the tun crate
        // immediately after adapter creation races with Windows IP stack initialization and
        // returns ERROR_INVALID_PARAMETER (os error 87). MTU is set via netsh in configure_windows().
        #[cfg(not(target_os = "windows"))]
        config_builder.mtu(self.config.mtu);

        #[cfg(target_os = "macos")]
        {
            // Disable tun crate's automatic routing — it generates invalid CIDR
            // notation (e.g. "route -n add -net 10.0.0.4/24") which macOS route(8)
            // does not support.  We handle routing ourselves in configure_macos()
            // using the correct "-netmask" syntax.
            config_builder.platform_config(|config| {
                config.enable_routing(false);
            });
        }

        #[cfg(target_os = "linux")]
        {
            config_builder.tun_name(&self.config.tun_name);
            config_builder.platform_config(|config| {
                config.ensure_root_privileges(true);
            });
        }

        #[cfg(target_os = "windows")]
        {
            // Stable adapter name so reconnects reuse the existing adapter via WintunOpenAdapter
            // instead of recreating it, which avoids a race where the Windows IP stack hasn't
            // finished initializing the new adapter when we call GetIpInterfaceEntry.
            config_builder.tun_name("AIVPN");
            config_builder.platform_config(|config| {
                config.device_guid(9099482345783245345u128);
            });
        }

        #[cfg(target_os = "windows")]
        if !is_elevated() {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Creating the network adapter requires Administrator rights on Windows \
                 (there is no scoped-down capability model like Linux's CAP_NET_ADMIN — \
                 it's all-or-nothing). Restart AIVPN as Administrator, or use \
                 --proxy-listen for a SOCKS5-proxy mode that doesn't need a TUN device \
                 at all.",
            )));
        }

        let dev = tun::create_as_async(&config_builder).map_err(|e| {
            let msg = e.to_string();
            #[cfg(target_os = "windows")]
            {
                // is_elevated() above already covers the common case; this
                // is a fallback for whatever WintunCreateAdapter failure
                // mode doesn't hinge on elevation (a stale adapter left by
                // an earlier crashed run, a conflicting GUID, the Wintun
                // driver itself not installed/loaded, etc.) — still worth
                // pointing at, since none of that is obvious from the raw
                // "WintunCreateAdapter failed" text alone.
                return Error::Io(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "{msg} (if this persists even when running as Administrator, try \
                         removing any stale AIVPN adapter in Device Manager, or reinstalling \
                         the Wintun driver)"
                    ),
                ));
            }
            #[cfg(not(target_os = "windows"))]
            Error::Io(io::Error::new(io::ErrorKind::Other, msg))
        })?;

        // Get actual device name before split (on macOS, name is assigned by kernel as utunN)
        if let Ok(actual_name) = tun::AbstractDevice::tun_name(&*dev) {
            self.config.tun_name = actual_name;
        }

        // Split into independent reader/writer — no Mutex needed for concurrent I/O
        let (writer, reader) = dev.split().map_err(Error::Io)?;
        self.reader = Some(reader);
        self.writer = Some(writer);

        info!(
            "Created TUN device: {} ({}/{})",
            self.config.tun_name, self.config.tun_addr, self.config.tun_netmask
        );

        // Claim this device with the native network-change listener BEFORE any
        // configuration below touches it. Everything `configure_linux()` and
        // the later `apply_network_config()` do emits netlink LINK/IFADDR
        // events on exactly this interface; without the claim the listener
        // reports them as "the network moved" and the session is torn down
        // moments after it establishes. Registering first closes the window in
        // which our own setup events could still be misread.
        //
        // Resolution failure is non-fatal: index 0 means "nothing registered",
        // so the listener falls back to reporting every event — the pre-filter
        // behavior — rather than going silent.
        //
        // Linux-only: `if_nametoindex` is not part of the Windows libc surface,
        // and Linux is the only platform whose listener consumes the index (see
        // `net_change::set_own_tun_ifindex`).
        #[cfg(target_os = "linux")]
        {
            let ifindex = std::ffi::CString::new(self.config.tun_name.as_str())
                .map(|c| unsafe { libc::if_nametoindex(c.as_ptr()) })
                .unwrap_or(0);
            if ifindex == 0 {
                debug!(
                    "net_change: could not resolve ifindex for {} — network-change \
                     events will not be filtered for this session",
                    self.config.tun_name
                );
            }
            crate::net_change::set_own_tun_ifindex(ifindex);
        }

        // Platform-specific post-creation configuration
        #[cfg(target_os = "macos")]
        self.configure_macos().await?;

        #[cfg(target_os = "linux")]
        self.configure_linux()?;

        #[cfg(target_os = "windows")]
        {
            // The Windows IP stack can take a moment to finish initializing a
            // freshly-created adapter, so `netsh interface ipv4 show interfaces`
            // may not list it yet on the first attempt — retry briefly instead
            // of failing the whole connection on a transient race.
            self.wintun_if_index = self.find_wintun_interface_index();
            for _ in 0..4 {
                if self.wintun_if_index.is_some() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                self.wintun_if_index = self.find_wintun_interface_index();
            }
            if let Some(ref idx) = self.wintun_if_index {
                info!("Wintun interface index: {}", idx);
            } else {
                // Without the interface index, configure_windows() would add VPN routes
                // bound to the default gateway NIC instead of the wintun adapter, silently
                // routing all traffic outside the tunnel. Fail hard so the user sees a
                // clear error rather than a "connected" tunnel that leaks all traffic.
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    "Could not determine wintun interface index — cannot add routes safely. \
                     Ensure Wintun is installed and the adapter name matches the config.",
                )));
            }
            self.configure_windows()?;
        }

        Ok(())
    }

    pub async fn apply_network_config(
        &mut self,
        mut network_config: ClientNetworkConfig,
    ) -> Result<()> {
        network_config.validate()?;
        // Clamp to MAX_PACKET_SIZE — see the matching comment in
        // `TunnelConfig::from_network_config`. This is the live path that
        // sets the TUN device's actual MTU on a server-pushed
        // (ServerHello/mid-session) network-config override, so it must be
        // clamped independently of that other choke point, not just rely on
        // it.
        network_config.mtu = network_config
            .mtu
            .min(aivpn_common::protocol::MAX_PACKET_SIZE as u16);
        // Remember the address the device carried BEFORE this override: on
        // Linux `ip addr replace <new>` with a different IP ADDS it as a
        // secondary address, the old one stays primary and keeps winning
        // source selection — so the server's anti-spoof check would still see
        // the stale IP and drop every data packet. The old CIDR must be
        // deleted explicitly.
        #[cfg(target_os = "linux")]
        let stale_cidr = self
            .config
            .client_network_config()
            .ok()
            .map(|c| c.cidr_string());
        self.config.tun_addr = network_config.client_ip.to_string();
        self.config.server_vpn_ip = network_config.server_vpn_ip.to_string();
        self.config.tun_netmask = network_config.netmask_string();
        self.config.prefix_len = network_config.prefix_len;
        self.config.mtu = network_config.mtu;

        if self.reader.is_none() && self.writer.is_none() {
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        {
            self.configure_macos().await?;
            // configure_macos() only installs the VPN subnet route.  If full-tunnel
            // mode was already active (saved_default_gw is set), the 0/1 + 128/1
            // default-route overrides were wiped by the ifconfig/route cleanup above.
            // Re-install them so internet traffic keeps flowing through the tunnel
            // after a server-pushed network-config update (ServerHello override).
            if self.config.full_tunnel && self.saved_default_gw.is_some() {
                self.enable_full_tunnel()?;
            }
        }

        #[cfg(target_os = "linux")]
        {
            self.configure_linux()?;
            let new_cidr = self.config.client_network_config()?.cidr_string();
            if let Some(stale) = stale_cidr.filter(|old| *old != new_cidr) {
                self.remove_stale_linux_addr(&stale);
            }
        }

        #[cfg(target_os = "windows")]
        self.configure_windows()?;

        Ok(())
    }

    /// Delete a stale IPv4 address left on the TUN device after a
    /// server-pushed network override changed the client IP (see
    /// `apply_network_config`). Best-effort: the new address is already
    /// installed, so a failure here only risks the kernel still preferring
    /// the old source IP.
    #[cfg(target_os = "linux")]
    fn remove_stale_linux_addr(&self, stale_cidr: &str) {
        let tun_name = &self.config.tun_name;
        match Self::run_ip_batch_privileged(&[(
            "addr_del",
            &["addr", "del", stale_cidr, "dev", tun_name],
        )]) {
            Ok(results)
                if results
                    .iter()
                    .any(|(name, s)| name == "addr_del" && s.success()) =>
            {
                info!("Removed stale tunnel address {}", stale_cidr);
            }
            Ok(_) => warn!(
                "Could not remove stale tunnel address {} — outgoing packets may keep \
                 the old source IP until reconnect",
                stale_cidr
            ),
            Err(e) => warn!("Stale address cleanup failed: {}", e),
        }
    }

    // ──────────────────── macOS ────────────────────

    /// Configure TUN device on macOS (ifconfig + route)
    #[cfg(target_os = "macos")]
    async fn configure_macos(&mut self) -> Result<()> {
        use std::process::Command;

        let tun_name = &self.config.tun_name;
        let tun_addr = &self.config.tun_addr;
        let peer_addr = &self.config.server_vpn_ip;
        let vpn_network = self.config.vpn_network_config()?;
        let vpn_network_addr = vpn_network.network_addr().to_string();
        let tun_netmask = self.config.tun_netmask.clone();

        // Set point-to-point addresses with explicit netmask
        let status = Command::new("/sbin/ifconfig")
            .args([
                tun_name,
                "inet",
                tun_addr,
                peer_addr,
                "netmask",
                &tun_netmask,
                "mtu",
                &self.config.mtu.to_string(),
                "up",
            ])
            .status()
            .map_err(|e| {
                Error::Io(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to run ifconfig: {}", e),
                ))
            })?;

        if !status.success() {
            error!("ifconfig failed with status: {}", status);
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("ifconfig failed: {}", status),
            )));
        } else {
            info!(
                "Configured {} with {} -> {} (netmask {})",
                tun_name, tun_addr, peer_addr, tun_netmask
            );
        }

        // Delete any stale routes to prevent conflicts
        info!("Cleaning up stale routes...");
        let _ = Command::new("/sbin/route")
            .args(["-n", "delete", "-host", peer_addr])
            .status();
        let _ = Command::new("/sbin/route")
            .args([
                "-n",
                "delete",
                "-net",
                &vpn_network_addr,
                "-netmask",
                &tun_netmask,
            ])
            .status();

        // Yield for 100 ms to let macOS finish tearing down stale routes before
        // re-adding them. Using tokio::time::sleep avoids blocking the async executor.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Add host route for the peer (10.0.0.1) - REQUIRED for point-to-point
        info!("Adding host route for peer {} via {}", peer_addr, tun_name);
        let status = Command::new("/sbin/route")
            .args(["-n", "add", "-host", peer_addr, "-interface", tun_name])
            .status()
            .map_err(|e| {
                Error::Io(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to add host route: {}", e),
                ))
            })?;

        if !status.success() {
            error!(
                "route add -host {} failed with status: {}",
                peer_addr, status
            );
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to add host route: {}", status),
            )));
        } else {
            info!("✓ Added host route {} via {}", peer_addr, tun_name);
        }

        // Add subnet route for 10.0.0.0/24
        // Must use -interface <tun_name> on a P2P TUN; passing the client IP as
        // a gateway produces "not in table" / silent failure on macOS because the
        // kernel has no ARP resolution path for a TUN peer address.
        info!(
            "Adding subnet route {}/{} via interface {}",
            vpn_network_addr, self.config.prefix_len, tun_name
        );
        let status = Command::new("/sbin/route")
            .args([
                "-n",
                "add",
                "-net",
                &vpn_network_addr,
                "-netmask",
                &tun_netmask,
                "-interface",
                tun_name,
            ])
            .status()
            .map_err(|e| {
                Error::Io(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to add subnet route: {}", e),
                ))
            })?;

        if !status.success() {
            error!(
                "route add -net {}/{} failed with status: {}",
                vpn_network_addr, self.config.prefix_len, status
            );
            // Don't fail completely - host route is more important
            debug!("Subnet route may already exist or not be needed");
        } else {
            info!(
                "Added subnet route {}/{} via interface {}",
                vpn_network_addr, self.config.prefix_len, tun_name
            );
        }

        // Block IPv6 to prevent traffic leaks (IPv6 bypasses the IPv4-only VPN tunnel).
        // First, discover and save the current IPv6 default interface so we can restore
        // it precisely on disconnect — avoids the "hardcode en0" problem.
        info!("Blocking IPv6 to prevent traffic leak...");
        let ipv6_iface = Command::new("/sbin/route")
            .args(["-n", "get", "-inet6", "default"])
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .and_then(|text| {
                text.lines()
                    .find(|l| l.trim().starts_with("interface:"))
                    .and_then(|l| l.split(':').nth(1))
                    .map(|s| s.trim().to_string())
            });
        if let Some(ref iface) = ipv6_iface {
            info!(
                "Saving IPv6 default interface: {} (will restore on disconnect)",
                iface
            );
        } else {
            info!("No IPv6 default route found — nothing to restore on disconnect");
        }
        self.saved_ipv6_iface = ipv6_iface;

        // Add a blackhole for ::/0 — any IPv6 packet hits a dead end inside the OS.
        let _ = Command::new("/sbin/route")
            .args(["-n", "delete", "-inet6", "default"])
            .status();
        let _ = Command::new("/sbin/route")
            .args(["-n", "add", "-inet6", "-net", "::/0", "-blackhole"])
            .status();
        info!("IPv6 blocked — all v6 traffic goes to blackhole (no leak possible)");

        // Verify routes — diagnostic-only (just logs which routes are
        // present). Best-effort: this must never fail the whole connect
        // attempt just because `netstat` couldn't exec (missing from PATH,
        // sandboxed environment, transient ENOMEM/EMFILE) — that would abort
        // an otherwise fully working `configure_macos()` → `create()` →
        // `connect()` over a logging command.
        info!("Verifying routes...");
        if let Ok(output) = Command::new("netstat").args(["-rn", "-f", "inet"]).output() {
            let routes = String::from_utf8_lossy(&output.stdout);
            if routes.contains(&vpn_network_addr) {
                info!("Routes verified:");
                for line in routes.lines().filter(|l| l.contains(&vpn_network_addr)) {
                    debug!("  {}", line.trim());
                }
            }
        } else {
            warn!("Failed to run netstat for route verification (diagnostic-only, continuing)");
        }

        Ok(())
    }

    // ──────────────────── Linux ────────────────────

    /// Run `ip <args>`, falling back to `pkexec ip <args>` if the direct
    /// invocation is rejected by the kernel with a permission error.
    ///
    /// Background: aivpn-linux grants CAP_NET_ADMIN to both the client
    /// binary and every `ip` binary it finds as a *file capability* (see
    /// `ensure_capable_binary` in `aivpn-linux/src/app.rs`). File
    /// capabilities are silently voided at exec time if the calling process
    /// (or any ancestor) has the `no_new_privs` bit set: per `capabilities(7)`
    /// and `Documentation/userspace-api/no_new_privs.rst`, "execve() promises
    /// not to grant the privilege to do anything that could not have been
    /// done without the execve call ... file capabilities will not add to
    /// the permitted set." `getcap` only inspects the on-disk xattr, so it
    /// keeps reporting the capability as present even when the kernel
    /// refuses to grant it at exec time — exactly the "verified via getcap,
    /// yet RTNETLINK EPERM at runtime" symptom seen in the field. Rather
    /// than trying to pin down *why* `no_new_privs` ended up set somewhere
    /// in the process ancestry (login shell, desktop launcher, a
    /// `systemd --user` unit with `NoNewPrivileges=yes`, AppImage/Flatpak
    /// integration, etc.), recover unconditionally by asking pkexec for
    /// one-shot root privilege instead of relying on the file capability.
    #[cfg(target_os = "linux")]
    fn run_ip_privileged(args: &[&str]) -> io::Result<std::process::ExitStatus> {
        Ok(Self::run_ip_batch_privileged(&[("cmd", args)])?
            .into_iter()
            .next()
            .expect("run_ip_batch_privileged returns one entry per input command")
            .1)
    }

    /// Shell-quote a single argument for safe interpolation into a script
    /// string (wraps in single quotes, escaping any embedded single quote).
    /// Every `ip` argument that flows into `run_ip_batch_privileged`'s
    /// generated script goes through this — required since the whole batch
    /// is executed as one `sh -c "..."`/`pkexec sh -c "..."` invocation, and
    /// several call sites interpolate values sourced from `ip route show
    /// default`'s own output (gateway/device names).
    #[cfg(target_os = "linux")]
    fn shell_quote(s: &str) -> String {
        format!("'{}'", s.replace('\'', r"'\''"))
    }

    /// Fixed, system-wide path of the privileged network helper installed
    /// by aivpn-linux's one-time setup (see `ensure_capable_binary` in
    /// `crates/aivpn-linux/src/app.rs`), together with a polkit `.policy`
    /// action binding `pkexec <this-exact-path>` to `auth_admin_keep`.
    ///
    /// This is a FIXED system path — `/usr/local/libexec/aivpn/`, root-owned
    /// — rather than anything under the invoking user's home directory.
    /// That matters for two reasons: (1) it lets the polkit action's
    /// `org.freedesktop.policykit.exec.path` annotation be a hardcoded
    /// string shared by every user on the machine, with no per-user
    /// template substitution; and (2) unlike a per-user path, whose parent
    /// directory is necessarily writable by that same user (making the
    /// installed file swappable even though the file itself is root-owned
    /// — directory write permission governs unlink/replace, not file
    /// ownership), this path's entire directory chain is root-owned and
    /// not group/other-writable, so no unprivileged process can plant a
    /// substitute file here.
    ///
    /// Also works correctly when aivpn-client runs standalone (no GUI setup
    /// ever ran): the path just won't exist, and the caller falls back to
    /// `pkexec sh -c "..."` (see `run_ip_batch_privileged`).
    #[cfg(target_os = "linux")]
    fn ip_helper_path() -> std::path::PathBuf {
        std::path::PathBuf::from("/usr/local/libexec/aivpn/aivpn-ip-helper")
    }

    /// Refuse to treat a file at the helper path as trustworthy unless it's
    /// root-owned and not group/other-writable. Belt-and-suspenders: pkexec
    /// itself doesn't care who owns the program it's asked to run (that's
    /// not what makes root grant privilege — the polkit authorization is),
    /// but if this ever finds something other than the aivpn-linux-installed
    /// helper, we'd rather fall back to the known-safe `pkexec sh -c "..."`
    /// path than hand root a script via an unverified binary.
    #[cfg(target_os = "linux")]
    fn is_trusted_root_binary(path: &std::path::Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(path) {
            Ok(meta) => meta.uid() == 0 && (meta.mode() & 0o022) == 0,
            Err(_) => false,
        }
    }

    /// Translate one `(name, ip-args)` pair — exactly the shapes already
    /// constructed by `configure_linux` / `enable_full_tunnel` /
    /// `apply_split_routes` below — into a single line of the
    /// `aivpn-ip-helper` wire protocol:
    ///
    /// ```text
    /// <name>\t<verb>\t<field>\t<field>...
    /// ```
    ///
    /// Returns `None` for any args shape that isn't one of the helper's
    /// whitelisted verbs (see `crates/aivpn-client/src/bin/aivpn-ip-helper.rs`)
    /// — callers treat that as "can't use the helper for this batch, fall
    /// back to `pkexec sh -c \"...\"`" rather than silently dropping a
    /// command. Also rejects (returns `None` for) any field containing a
    /// tab or newline, since those are the wire protocol's own field/line
    /// separators — defense in depth on top of the `ip route show
    /// default`-sourced values already being whitespace-split tokens that
    /// can't contain either.
    #[cfg(target_os = "linux")]
    fn helper_line_for(name: &str, args: &[&str]) -> Option<String> {
        if name.is_empty()
            || name.contains(':')
            || name.contains('\t')
            || name.contains('\n')
            || args
                .iter()
                .any(|a| a.is_empty() || a.contains('\t') || a.contains('\n'))
        {
            return None;
        }
        match args {
            ["route", "replace", "0.0.0.0/1", "dev", iface] => {
                Some(format!("{name}\troute_replace_fulltunnel_lower\t{iface}"))
            }
            ["route", "replace", "128.0.0.0/1", "dev", iface] => {
                Some(format!("{name}\troute_replace_fulltunnel_upper\t{iface}"))
            }
            ["-6", "route", "replace", "blackhole", "default"] => {
                Some(format!("{name}\troute_replace_ipv6_blackhole"))
            }
            ["addr", "replace", cidr, "dev", iface] => {
                Some(format!("{name}\taddr_replace\t{cidr}\t{iface}"))
            }
            ["addr", "del", cidr, "dev", iface] => {
                Some(format!("{name}\taddr_del\t{cidr}\t{iface}"))
            }
            ["route", "replace", cidr, "dev", iface] => {
                Some(format!("{name}\troute_replace_dev\t{cidr}\t{iface}"))
            }
            ["route", "replace", ip, "via", gw, "dev", iface, "onlink"] => Some(format!(
                "{name}\troute_replace_via_dev_onlink\t{ip}\t{gw}\t{iface}"
            )),
            ["route", "replace", ip, "via", gw, "dev", iface] => Some(format!(
                "{name}\troute_replace_via_dev\t{ip}\t{gw}\t{iface}"
            )),
            ["route", "replace", gw, "dev", iface, "scope", "link"] => {
                Some(format!("{name}\troute_replace_gw_link\t{gw}\t{iface}"))
            }
            ["route", "replace", cidr, "via", gw] => {
                Some(format!("{name}\troute_replace_via\t{cidr}\t{gw}"))
            }
            _ => None,
        }
    }

    /// Build the full `aivpn-ip-helper` wire-protocol payload for a whole
    /// batch, or `None` if any command in it doesn't map to one of the
    /// helper's whitelisted verbs (in which case the caller falls back to
    /// `pkexec sh -c "..."` for the entire batch — no partial helper use).
    #[cfg(target_os = "linux")]
    fn build_helper_wire(commands: &[(&str, &[&str])]) -> Option<String> {
        let mut lines = Vec::with_capacity(commands.len());
        for (name, args) in commands {
            lines.push(Self::helper_line_for(name, args)?);
        }
        Some(lines.join("\n"))
    }

    /// Parse `aivpn-ip-helper`'s `<name>:<exit_code>` output lines — the
    /// shell-free equivalent of `parse_marker_statuses`'s
    /// `__AIVPN_STATUS:<name>:<code>` markers used by the `pkexec sh -c
    /// "..."` fallback path.
    #[cfg(target_os = "linux")]
    fn parse_helper_statuses(stdout: &[u8]) -> Vec<(String, std::process::ExitStatus)> {
        use std::os::unix::process::ExitStatusExt;
        String::from_utf8_lossy(stdout)
            .lines()
            .filter_map(|line| {
                let (name, code) = line.rsplit_once(':')?;
                let code: i32 = code.trim().parse().ok()?;
                Some((name.to_string(), std::process::ExitStatus::from_raw(code)))
            })
            .collect()
    }

    /// Run `pkexec <program>`, feeding `input` to the program's stdin and
    /// closing it, then collecting output the same way `Command::output()`
    /// would. Used for the `aivpn-ip-helper` path: the helper reads its
    /// whole command batch from stdin (rather than argv) so the batch text
    /// — which can embed VPN gateway/interface names sourced from `ip
    /// route show default` — never shows up in `ps` output.
    #[cfg(target_os = "linux")]
    fn run_via_pkexec_stdin(
        program: &std::path::Path,
        input: &str,
    ) -> io::Result<std::process::Output> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let mut child = Command::new("pkexec")
            .arg(program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        ACTIVE_PKEXEC_PID.store(child.id(), std::sync::atomic::Ordering::SeqCst);
        // Guard clears the tracked PID on every exit path (normal return,
        // `?`-early-return doesn't apply here, but future edits might add
        // one) so a completed/reaped child is never mistakenly signaled by
        // `kill_orphaned_pkexec_child()` later.
        struct ClearPidOnDrop;
        impl Drop for ClearPidOnDrop {
            fn drop(&mut self) {
                ACTIVE_PKEXEC_PID.store(0, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let _clear_guard = ClearPidOnDrop;

        if let Some(mut stdin) = child.stdin.take() {
            // Best-effort: if the helper (or pkexec itself) exits early —
            // e.g. the user cancels the auth dialog — the write can fail
            // with EPIPE. That's not a new failure mode of ours; the
            // eventual wait_with_output() below still reports the real
            // process outcome either way.
            let _ = stdin.write_all(input.as_bytes());
        }

        child.wait_with_output()
    }

    /// Run a batch of named `ip <args>` invocations as ONE shell script,
    /// falling back to a SINGLE `pkexec sh -c ...` prompt for the whole
    /// batch if (and only if) any of them hits what looks like a permission
    /// error when tried directly first.
    ///
    /// Before this, each `ip` call that needed escalation triggered its own
    /// separate `pkexec` invocation — with file capabilities not reliably
    /// taking effect on some systems (see `run_ip_privileged`'s doc comment;
    /// root cause still unconfirmed, `NoNewPrivs=0` was observed on one
    /// affected machine, ruling out that theory too), a single connection
    /// attempt could need address, route, bypass-route, and full-tunnel-trick
    /// escalation all in the same attempt — up to 7 separate polkit password
    /// prompts for one `Connect` click, live-reported as unusable UX. Each
    /// command's actual exit status is captured via an echoed marker in the
    /// script (`__AIVPN_STATUS:<name>:<code>`) rather than relying on the
    /// combined script's own exit code, so callers get the exact same
    /// per-command success/failure information as before — this is a pure
    /// prompt-count optimization, not a change in what counts as success.
    #[cfg(target_os = "linux")]
    fn run_ip_batch_privileged(
        commands: &[(&str, &[&str])],
    ) -> io::Result<Vec<(String, std::process::ExitStatus)>> {
        use std::os::unix::process::ExitStatusExt;
        use std::process::Command;

        let script: String = commands
            .iter()
            .map(|(name, args)| {
                let mut parts = vec!["ip".to_string()];
                parts.extend(args.iter().map(|a| Self::shell_quote(a)));
                format!("{}; echo \"__AIVPN_STATUS:{}:$?\"", parts.join(" "), name)
            })
            .collect::<Vec<_>>()
            .join("\n");

        let parse_marker_statuses = |stdout: &[u8]| -> Vec<(String, std::process::ExitStatus)> {
            String::from_utf8_lossy(stdout)
                .lines()
                .filter_map(|line| line.strip_prefix("__AIVPN_STATUS:"))
                .filter_map(|rest| {
                    let (name, code) = rest.rsplit_once(':')?;
                    let code: i32 = code.trim().parse().ok()?;
                    Some((name.to_string(), std::process::ExitStatus::from_raw(code)))
                })
                .collect()
        };

        let output = Command::new("sh").arg("-c").arg(&script).output()?;
        let direct_results = parse_marker_statuses(&output.stdout);
        // Every command must have produced a marker line, and every one of
        // those must itself have succeeded, for the batch to count as fully
        // resolved without escalation.
        if direct_results.len() == commands.len() && direct_results.iter().all(|(_, s)| s.success())
        {
            return Ok(direct_results);
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        eprint!("{}", stderr);

        let looks_like_permission_denied = stderr.contains("Operation not permitted");
        if !looks_like_permission_denied {
            // Some non-permission failure (e.g. "File exists" for a route
            // that's already there) — return what we have; pkexec would
            // just fail the same way and cost the user a prompt for nothing.
            return Ok(direct_results);
        }

        error!(
            "ip batch [{}] failed with a permission error despite file capabilities being \
             granted (getcap only checks the on-disk xattr, not whether no_new_privs blocks \
             it at exec time — see capabilities(7)). Falling back to a single pkexec prompt \
             for the whole batch instead of one per command.",
            commands
                .iter()
                .map(|(name, _)| *name)
                .collect::<Vec<_>>()
                .join(", ")
        );

        // Prefer `pkexec <aivpn-ip-helper>` over `pkexec sh -c "..."` when
        // aivpn-linux's one-time setup has installed the helper at its
        // fixed system path (see `ip_helper_path`) AND it passes the trust
        // check: pkexec resolves the program's exact path and, since a
        // polkit action annotates that exact path via
        // org.freedesktop.policykit.exec.path (see
        // platforms/linux/polkit/com.aivpn.client.policy), uses that
        // action's auth level instead of the generic
        // org.freedesktop.policykit.exec one. That action grants
        // auth_admin_keep, so a disconnect→reconnect within the polkit
        // session's cache window (~5 min by default) needs no further
        // prompt. This is a single up-front decision (helper installed +
        // trusted + every command maps to a whitelisted verb), not a
        // try-then-retry — so a cancelled/failed helper auth never costs a
        // second prompt via the sh -c fallback below.
        let helper_path = Self::ip_helper_path();
        if Self::is_trusted_root_binary(&helper_path) {
            if let Some(wire) = Self::build_helper_wire(commands) {
                let output = Self::run_via_pkexec_stdin(&helper_path, &wire)?;
                return Ok(Self::parse_helper_statuses(&output.stdout));
            }
        }

        let output = Command::new("pkexec")
            .arg("sh")
            .arg("-c")
            .arg(&script)
            .output()?;
        Ok(parse_marker_statuses(&output.stdout))
    }

    /// Configure TUN device on Linux (ip route). Both the address and route
    /// mutation run in a single privileged batch (at most one pkexec prompt
    /// for this whole function, not one per `ip` call — see
    /// `run_ip_batch_privileged`).
    #[cfg(target_os = "linux")]
    fn configure_linux(&self) -> Result<()> {
        let tun_name = &self.config.tun_name;
        let cidr = self.config.client_network_config()?.cidr_string();
        let vpn_cidr = self.config.vpn_network_config()?.cidr_string();

        let results = Self::run_ip_batch_privileged(&[
            ("addr", &["addr", "replace", &cidr, "dev", tun_name]),
            ("route", &["route", "replace", &vpn_cidr, "dev", tun_name]),
        ])
        .map_err(|e| {
            Error::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to configure tunnel: {}", e),
            ))
        })?;

        let addr_ok = results
            .iter()
            .find(|(name, _)| name == "addr")
            .is_some_and(|(_, s)| s.success());
        if !addr_ok {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Failed to configure tunnel address {} on {}",
                    cidr, tun_name
                ),
            )));
        }

        let route_ok = results
            .iter()
            .find(|(name, _)| name == "route")
            .is_some_and(|(_, s)| s.success());
        if route_ok {
            info!("Added route {} via {}", vpn_cidr, tun_name);
        } else {
            debug!("ip route add {} failed (may already exist)", vpn_cidr);
        }

        Ok(())
    }

    // ──────────────────── Windows ────────────────────

    /// Discover the wintun adapter's interface index via `netsh`.
    /// Used to pass `IF <index>` to `route add` so Windows binds the route
    /// to wintun rather than the physical NIC with the best next-hop metric.
    #[cfg(target_os = "windows")]
    fn find_wintun_interface_index(&self) -> Option<String> {
        let output = std::process::Command::new("netsh")
            .args(["interface", "ipv4", "show", "interfaces"])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let tun_lower = self.config.tun_name.to_lowercase();
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.to_lowercase().ends_with(&tun_lower) {
                if let Some(idx) = trimmed.split_whitespace().next() {
                    if idx.parse::<u32>().is_ok() {
                        return Some(idx.to_string());
                    }
                }
            }
        }
        None
    }

    /// Configure TUN device on Windows (netsh / route add)
    #[cfg(target_os = "windows")]
    fn configure_windows(&self) -> Result<()> {
        let peer_addr = &self.config.server_vpn_ip;
        let vpn_network = self.config.vpn_network_config()?;
        let network_addr = vpn_network.network_addr().to_string();
        let tun_netmask = self.config.tun_netmask.clone();

        // Explicitly bind the VPN subnet route to the wintun interface.
        // Without IF, Windows may attach it to the physical NIC.
        let (add_args, delete_args): (Vec<&str>, Vec<&str>) =
            if let Some(ref idx) = self.wintun_if_index {
                (
                    vec![
                        "add",
                        network_addr.as_str(),
                        "mask",
                        tun_netmask.as_str(),
                        peer_addr,
                        "IF",
                        idx.as_str(),
                    ],
                    vec![
                        "delete",
                        network_addr.as_str(),
                        "mask",
                        tun_netmask.as_str(),
                        "IF",
                        idx.as_str(),
                    ],
                )
            } else {
                (
                    vec![
                        "add",
                        network_addr.as_str(),
                        "mask",
                        tun_netmask.as_str(),
                        peer_addr,
                    ],
                    vec![
                        "delete",
                        network_addr.as_str(),
                        "mask",
                        tun_netmask.as_str(),
                    ],
                )
            };

        self.add_windows_route_with_retry(
            &add_args,
            &delete_args,
            &format!(
                "Added route {}/{} via {} IF {} (Windows)",
                network_addr,
                self.config.prefix_len,
                peer_addr,
                self.wintun_if_index.as_deref().unwrap_or("auto")
            ),
            &format!(
                "VPN subnet route {}/{}",
                network_addr, self.config.prefix_len
            ),
        )?;

        // Set MTU via netsh (SetIpInterfaceEntry is skipped in config_builder for Windows
        // due to a race with the IP stack; this runs after the session is established).
        if let Some(ref idx) = self.wintun_if_index {
            let mtu_str = self.config.mtu.to_string();
            let _ = std::process::Command::new("netsh")
                .args([
                    "interface",
                    "ipv4",
                    "set",
                    "subinterface",
                    idx.as_str(),
                    &format!("mtu={}", mtu_str),
                    "store=persistent",
                ])
                .status();
        }

        Ok(())
    }

    /// Set VPN server IP (call before enable_full_tunnel)
    pub fn set_server_ip(&mut self, server_ip: String) {
        self.server_ip = Some(server_ip);
    }

    /// Enable full-tunnel mode: route all traffic through VPN
    #[cfg(target_os = "macos")]
    pub fn enable_full_tunnel(&mut self) -> Result<()> {
        use std::process::Command;

        let tun_name = &self.config.tun_name;

        // 1. Get current default gateway
        let output = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .map_err(|e| {
                Error::Io(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to get default route: {}", e),
                ))
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let default_gw = stdout
            .lines()
            .find(|l| l.trim().starts_with("gateway:"))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string());

        let gw = match default_gw {
            Some(g) => g,
            None => {
                error!("Could not determine default gateway");
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::Other,
                    "Could not determine default gateway",
                )));
            }
        };

        info!("Current default gateway: {}", gw);
        self.saved_default_gw = Some(gw.clone());

        // 2. Add bypass route for VPN server IP via original gateway
        if let Some(ref server_ip) = self.server_ip {
            let _ = Command::new("route")
                .args(["-n", "delete", "-host", server_ip])
                .status();
            let status = Command::new("route")
                .args(["-n", "add", "-host", server_ip, &gw])
                .status()
                .map_err(|e| {
                    Error::Io(io::Error::new(
                        io::ErrorKind::Other,
                        format!("Failed to add server bypass route: {}", e),
                    ))
                })?;
            if status.success() {
                info!("Added bypass route: {} via {}", server_ip, gw);
            } else {
                error!("Failed to add bypass route for {}", server_ip);
            }
        }

        // 3. Route all traffic through TUN using 0/1 + 128/1 trick
        for net in ["0.0.0.0/1", "128.0.0.0/1"] {
            let _ = Command::new("route")
                .args(["-n", "delete", "-net", net])
                .status();
            let status = Command::new("route")
                .args(["-n", "add", "-net", net, "-interface", tun_name])
                .status()
                .map_err(|e| {
                    Error::Io(io::Error::new(
                        io::ErrorKind::Other,
                        format!("Failed to add full-tunnel route {}: {}", net, e),
                    ))
                })?;
            if status.success() {
                info!("Added full-tunnel route: {} via {}", net, tun_name);
            } else {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "route add -net {} -interface {} failed (exit {:?})",
                        net,
                        tun_name,
                        status.code()
                    ),
                )));
            }
        }

        info!("Full tunnel mode enabled — all traffic routed through VPN");
        Ok(())
    }

    /// Enable full-tunnel mode on Linux
    #[cfg(target_os = "linux")]
    pub fn enable_full_tunnel(&mut self) -> Result<()> {
        use std::process::Command;

        let tun_name = &self.config.tun_name;

        // 1. Get current default gateway
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .map_err(|e| {
                Error::Io(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to get default route: {}", e),
                ))
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let route_fields: Vec<&str> = stdout.split_whitespace().collect();
        let default_gw = route_fields
            .windows(2)
            .find(|window| window[0] == "via")
            .map(|window| window[1].to_string());
        let default_dev = route_fields
            .windows(2)
            .find(|window| window[0] == "dev")
            .map(|window| window[1].to_string());
        let default_onlink = route_fields.iter().any(|field| *field == "onlink");

        let (gw, default_dev) = match (default_gw, default_dev) {
            (Some(gw), Some(default_dev)) => (gw, default_dev),
            _ => {
                error!("Could not determine default gateway/interface");
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::Other,
                    "Could not determine default gateway/interface",
                )));
            }
        };

        info!(
            "Current default gateway: {} via {}{}",
            gw,
            default_dev,
            if default_onlink { " onlink" } else { "" }
        );
        self.saved_default_gw = Some(gw.clone());
        self.saved_default_dev = Some(default_dev.clone());

        // 2 & 3. Bypass route for the VPN server IP + the 0/1+128/1
        // full-tunnel trick, all issued as ONE privileged batch (at most one
        // pkexec prompt for this whole function). All the bypass-route
        // variants are safe to attempt unconditionally in the same batch:
        // `ip route replace` only touches the routing table on success, so
        // an invalid variant for this network topology (e.g. non-onlink when
        // the gateway needs onlink) just fails without disturbing whatever
        // the valid variant already installed — order doesn't matter, only
        // "did at least one succeed".
        let mut batch: Vec<(&str, Vec<&str>)> = Vec::new();
        if let Some(ref server_ip) = self.server_ip {
            if default_onlink {
                batch.push((
                    "bypass_onlink",
                    vec![
                        "route",
                        "replace",
                        server_ip.as_str(),
                        "via",
                        gw.as_str(),
                        "dev",
                        default_dev.as_str(),
                        "onlink",
                    ],
                ));
            }
            batch.push((
                "bypass_plain",
                vec![
                    "route",
                    "replace",
                    server_ip.as_str(),
                    "via",
                    gw.as_str(),
                    "dev",
                    default_dev.as_str(),
                ],
            ));
            if !default_onlink {
                batch.push((
                    "bypass_onlink",
                    vec![
                        "route",
                        "replace",
                        server_ip.as_str(),
                        "via",
                        gw.as_str(),
                        "dev",
                        default_dev.as_str(),
                        "onlink",
                    ],
                ));
            }
            // Fallback path: a host route for the gateway itself (harmless
            // to add even if a bypass variant above already succeeded), then
            // one more bypass attempt that can now rely on it.
            batch.push((
                "gw_link",
                vec![
                    "route",
                    "replace",
                    gw.as_str(),
                    "dev",
                    default_dev.as_str(),
                    "scope",
                    "link",
                ],
            ));
            batch.push((
                "bypass_after_gw_link",
                vec![
                    "route",
                    "replace",
                    server_ip.as_str(),
                    "via",
                    gw.as_str(),
                    "dev",
                    default_dev.as_str(),
                ],
            ));
        }
        batch.push((
            "ft_0",
            vec!["route", "replace", "0.0.0.0/1", "dev", tun_name],
        ));
        batch.push((
            "ft_1",
            vec!["route", "replace", "128.0.0.0/1", "dev", tun_name],
        ));
        // Blackhole IPv6. Unlike macOS (configure_macos), the Linux full-tunnel
        // path only rerouted IPv4 (0/1 + 128/1), so on a dual-stack host every
        // IPv6 packet — including IPv6 DNS and dual-stack sites — leaked outside
        // the tunnel whenever full-tunnel was used without the kill-switch (the
        // nft inet table only blocks v6 when the kill-switch is on). Send the v6
        // default to a blackhole; restore_ipv6 removes it on teardown. Best
        // effort — on an IPv4-only host this simply fails harmlessly, so success
        // is not gated on it.
        batch.push((
            "ipv6_blackhole",
            vec!["-6", "route", "replace", "blackhole", "default"],
        ));

        let named_args: Vec<(&str, &[&str])> = batch
            .iter()
            .map(|(name, args)| (*name, args.as_slice()))
            .collect();
        let results = Self::run_ip_batch_privileged(&named_args).map_err(|e| {
            Error::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to configure full-tunnel routes: {}", e),
            ))
        })?;

        let succeeded = |name: &str| results.iter().any(|(n, s)| n == name && s.success());

        if self.server_ip.is_some() {
            let bypass_added = succeeded("bypass_onlink")
                || succeeded("bypass_plain")
                || succeeded("bypass_after_gw_link");
            if !bypass_added {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "Failed to add bypass route for {} via {} dev {}",
                        self.server_ip.as_deref().unwrap_or(""),
                        gw,
                        default_dev
                    ),
                )));
            }
            info!(
                "Added bypass route: {} via {} dev {}",
                self.server_ip.as_deref().unwrap_or(""),
                gw,
                default_dev
            );
        }

        if !succeeded("ft_0") || !succeeded("ft_1") {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::Other,
                "Failed to add full-tunnel 0.0.0.0/1 + 128.0.0.0/1 routes",
            )));
        }
        info!(
            "Added full-tunnel routes: 0.0.0.0/1 + 128.0.0.0/1 via {}",
            tun_name
        );

        info!("Full tunnel mode enabled — all traffic routed through VPN");
        Ok(())
    }

    /// Enable full-tunnel mode on Windows
    #[cfg(target_os = "windows")]
    pub fn enable_full_tunnel(&mut self) -> Result<()> {
        use std::process::Command;

        let peer_addr = self.config.server_vpn_ip.clone();

        // 1. Get current default gateway via powershell
        let output = Command::new("powershell")
            .args([
                "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop",
            ])
            .output()
            .map_err(|e| {
                Error::Io(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to get default route: {}", e),
                ))
            })?;

        let gw = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if gw.is_empty() {
            error!("Could not determine default gateway");
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::Other,
                "Could not determine default gateway",
            )));
        }

        info!("Current default gateway: {}", gw);
        self.saved_default_gw = Some(gw.clone());

        // 2. Add bypass route for VPN server IP via original gateway
        if let Some(ref server_ip) = self.server_ip {
            let success_message = format!("Added bypass route: {} via {}", server_ip, gw);
            let add_args = [
                "add",
                server_ip.as_str(),
                "mask",
                "255.255.255.255",
                gw.as_str(),
            ];
            let delete_args = ["delete", server_ip.as_str(), "mask", "255.255.255.255"];
            self.add_windows_route_with_retry(
                &add_args,
                &delete_args,
                &success_message,
                &format!("server bypass route {}", server_ip),
            )?;
        }

        // 3. Route all traffic through TUN via 0/1 + 128/1 trick
        //    Explicitly bind to wintun IF to prevent Windows from attaching
        //    these routes to the physical NIC.
        for net in [("0.0.0.0", "128.0.0.0"), ("128.0.0.0", "128.0.0.0")] {
            let if_suffix = self.wintun_if_index.as_deref().unwrap_or("auto");
            let success_message = format!(
                "Added full-tunnel route: {}/1 via {} IF {}",
                net.0, peer_addr, if_suffix
            );
            let (add_args, delete_args): (Vec<&str>, Vec<&str>) =
                if let Some(ref idx) = self.wintun_if_index {
                    (
                        vec![
                            "add",
                            net.0,
                            "mask",
                            net.1,
                            peer_addr.as_str(),
                            "metric",
                            "5",
                            "IF",
                            idx.as_str(),
                        ],
                        vec!["delete", net.0, "mask", net.1],
                    )
                } else {
                    (
                        vec![
                            "add",
                            net.0,
                            "mask",
                            net.1,
                            peer_addr.as_str(),
                            "metric",
                            "5",
                        ],
                        vec!["delete", net.0, "mask", net.1],
                    )
                };
            self.add_windows_route_with_retry(
                &add_args,
                &delete_args,
                &success_message,
                &format!("full-tunnel route {}/{}", net.0, net.1),
            )?;
        }

        // IPv4 is now fully routed through the TUN via the 0/1+128/1 trick, but
        // that leaves the OS's pre-existing IPv6 default route untouched — on
        // any dual-stack network (most residential/mobile ISPs) IPv6-capable
        // destinations reach the physical NIC directly, fully bypassing the
        // VPN, while the user believes "full tunnel" protects them. Windows
        // has no direct equivalent of macOS/Linux's "route ::/0 to a
        // blackhole" (route.exe doesn't do IPv6; a netsh blackhole route needs
        // a real interface). `Disable-NetAdapterBinding -ComponentID
        // ms_tcpip6` is the standard, no-reboot way to pull IPv6 off every
        // adapter for the session; `disable_full_tunnel` re-enables it.
        // Best-effort: a failure here (e.g. no admin rights on the binding
        // call, which differs from the route-add rights already required
        // above) must not abort an otherwise fully working IPv4 tunnel.
        let ipv6_disabled = Command::new("powershell")
            .args([
                "-Command",
                "Disable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6",
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ipv6_disabled {
            info!("IPv6 disabled on all adapters for the session — no v6 leak around full-tunnel");
        } else {
            warn!(
                "Failed to disable IPv6 bindings — full-tunnel mode may not protect IPv6 traffic \
                 on this dual-stack network"
            );
        }

        info!("Full tunnel mode enabled — all traffic routed through VPN");
        Ok(())
    }

    /// Disable full-tunnel mode: restore original routing
    #[cfg(target_os = "macos")]
    fn disable_full_tunnel(&mut self) {
        use std::process::Command;

        for net in ["0.0.0.0/1", "128.0.0.0/1"] {
            let _ = Command::new("route")
                .args(["-n", "delete", "-net", net])
                .status();
        }
        if let Some(ref server_ip) = self.server_ip {
            let _ = Command::new("route")
                .args(["-n", "delete", "-host", server_ip])
                .status();
        }
        info!("Full tunnel routes removed");
    }

    /// Disable full-tunnel mode on Linux
    #[cfg(target_os = "linux")]
    fn disable_full_tunnel(&mut self) {
        use std::process::Command;

        for net in ["0.0.0.0/1", "128.0.0.0/1"] {
            let _ = Command::new("ip").args(["route", "del", net]).status();
        }
        if let Some(ref server_ip) = self.server_ip {
            let _ = Command::new("ip")
                .args(["route", "del", server_ip])
                .status();
        }
        // Restore default gateway
        if let Some(ref gw) = self.saved_default_gw {
            let mut args = vec!["route", "add", "default", "via", gw.as_str()];
            let dev_owned;
            if let Some(ref dev) = self.saved_default_dev {
                dev_owned = dev.clone();
                args.extend_from_slice(&["dev", dev_owned.as_str()]);
            }
            let _ = Command::new("ip").args(&args).status();
        }
        // Remove the IPv6 blackhole added by enable_full_tunnel so v6 works
        // again after disconnect.
        self.restore_ipv6();
        info!("Full tunnel routes removed");
    }

    /// Disable full-tunnel mode on Windows
    #[cfg(target_os = "windows")]
    fn disable_full_tunnel(&mut self) {
        use std::process::Command;

        for net in [("0.0.0.0", "128.0.0.0"), ("128.0.0.0", "128.0.0.0")] {
            let _ = Command::new("route")
                .args(["delete", net.0, "mask", net.1])
                .status();
        }
        if let Some(ref server_ip) = self.server_ip {
            let _ = Command::new("route").args(["delete", server_ip]).status();
        }
        // Symmetric restore for the IPv6 binding disabled in enable_full_tunnel.
        let _ = Command::new("powershell")
            .args([
                "-Command",
                "Enable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6",
            ])
            .status();
        info!("Full tunnel routes removed");
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    pub fn enable_full_tunnel(&mut self) -> Result<()> {
        Ok(())
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    fn disable_full_tunnel(&mut self) {}

    // ──────────────────── Split-tunnel ────────────────────

    /// Parse "a.b.c.d/n" → (net_addr, netmask) for Windows route commands.
    #[cfg(target_os = "windows")]
    fn cidr_to_net_mask(cidr: &str) -> Option<(String, String)> {
        let (net, prefix) = cidr.split_once('/')?;
        let prefix: u8 = prefix.parse().ok()?;
        let _: std::net::Ipv4Addr = net.parse().ok()?;
        let mask = if prefix == 0 {
            0u32
        } else {
            u32::MAX.wrapping_shl(32 - prefix as u32)
        };
        Some((net.to_string(), std::net::Ipv4Addr::from(mask).to_string()))
    }

    /// Apply include/exclude routes for split-tunnel mode.
    /// Call after enable_full_tunnel (if in full-tunnel mode) and after TUN is up.
    #[cfg(target_os = "linux")]
    pub fn apply_split_routes(&mut self) -> Result<()> {
        use std::process::Command;
        let tun = self.config.tun_name.clone();

        for cidr in self.config.include_routes.clone() {
            let ok = Self::run_ip_privileged(&["route", "replace", &cidr, "dev", &tun])
                .map(|s| s.success())
                .unwrap_or(false);
            if ok {
                info!("Split-tunnel include: {} via {}", cidr, tun);
                self.split_routes_applied.push(cidr);
            } else {
                error!("Split-tunnel: failed to add include route {}", cidr);
            }
        }

        let gw_opt = self.saved_default_gw.clone().or_else(|| {
            Command::new("ip")
                .args(["route", "show", "default"])
                .output()
                .ok()
                .and_then(|o| {
                    let s = String::from_utf8_lossy(&o.stdout).to_string();
                    let fields: Vec<&str> = s.split_whitespace().collect();
                    fields
                        .windows(2)
                        .find(|w| w[0] == "via")
                        .map(|w| w[1].to_string())
                })
        });

        if let Some(gw) = gw_opt {
            for cidr in self.config.exclude_routes.clone() {
                let ok = Self::run_ip_privileged(&["route", "replace", &cidr, "via", &gw])
                    .map(|s| s.success())
                    .unwrap_or(false);
                if ok {
                    info!("Split-tunnel exclude: {} via {} (bypass VPN)", cidr, gw);
                    self.split_routes_applied.push(cidr);
                } else {
                    error!("Split-tunnel: failed to exclude route {}", cidr);
                }
            }
        } else if !self.config.exclude_routes.is_empty() {
            error!("Split-tunnel: no default gateway found for exclude_routes");
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn remove_split_routes(&mut self) {
        use std::process::Command;
        for cidr in self.split_routes_applied.drain(..) {
            let _ = Command::new("ip").args(["route", "del", &cidr]).status();
        }
        if !self.config.include_routes.is_empty() || !self.config.exclude_routes.is_empty() {
            info!("Split-tunnel routes removed");
        }
    }

    #[cfg(target_os = "macos")]
    pub fn apply_split_routes(&mut self) -> Result<()> {
        use std::process::Command;
        let tun = self.config.tun_name.clone();

        for cidr in self.config.include_routes.clone() {
            let ok = Command::new("/sbin/route")
                .args(["-n", "add", "-net", &cidr, "-interface", &tun])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if ok {
                info!("Split-tunnel include: {} via {}", cidr, tun);
                self.split_routes_applied.push(cidr);
            } else {
                error!("Split-tunnel: failed to add include route {}", cidr);
            }
        }

        let gw_opt = self.saved_default_gw.clone().or_else(|| {
            Command::new("/sbin/route")
                .args(["-n", "get", "default"])
                .output()
                .ok()
                .and_then(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .find(|l| l.trim().starts_with("gateway:"))
                        .and_then(|l| l.split(':').nth(1))
                        .map(|s| s.trim().to_string())
                })
        });

        if let Some(gw) = gw_opt {
            for cidr in self.config.exclude_routes.clone() {
                let ok = Command::new("/sbin/route")
                    .args(["-n", "add", "-net", &cidr, &gw])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                if ok {
                    info!("Split-tunnel exclude: {} via {} (bypass VPN)", cidr, gw);
                    self.split_routes_applied.push(cidr);
                } else {
                    error!("Split-tunnel: failed to exclude route {}", cidr);
                }
            }
        } else if !self.config.exclude_routes.is_empty() {
            error!("Split-tunnel: no default gateway found for exclude_routes");
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn remove_split_routes(&mut self) {
        use std::process::Command;
        for cidr in self.split_routes_applied.drain(..) {
            let _ = Command::new("/sbin/route")
                .args(["-n", "delete", "-net", &cidr])
                .status();
        }
        if !self.config.include_routes.is_empty() || !self.config.exclude_routes.is_empty() {
            info!("Split-tunnel routes removed");
        }
    }

    #[cfg(target_os = "windows")]
    pub fn apply_split_routes(&mut self) -> Result<()> {
        use std::process::Command;
        let peer = self.config.server_vpn_ip.clone();

        for cidr in self.config.include_routes.clone() {
            if let Some((net, mask)) = Self::cidr_to_net_mask(&cidr) {
                let ok = if let Some(ref idx) = self.wintun_if_index.clone() {
                    Command::new("route")
                        .args(["add", &net, "mask", &mask, &peer, "IF", idx])
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false)
                } else {
                    Command::new("route")
                        .args(["add", &net, "mask", &mask, &peer])
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false)
                };
                if ok {
                    info!("Split-tunnel include: {} via {}", cidr, peer);
                    self.split_routes_applied.push(cidr);
                } else {
                    error!("Split-tunnel: failed to add include route {}", cidr);
                }
            }
        }

        let gw_opt = self.saved_default_gw.clone().or_else(|| {
            Command::new("powershell")
                .args([
                    "-Command",
                    "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop",
                ])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .filter(|s| !s.is_empty())
        });

        if let Some(gw) = gw_opt {
            for cidr in self.config.exclude_routes.clone() {
                if let Some((net, mask)) = Self::cidr_to_net_mask(&cidr) {
                    let ok = Command::new("route")
                        .args(["add", &net, "mask", &mask, &gw])
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false);
                    if ok {
                        info!("Split-tunnel exclude: {} via {} (bypass VPN)", cidr, gw);
                        self.split_routes_applied.push(cidr);
                    } else {
                        error!("Split-tunnel: failed to exclude route {}", cidr);
                    }
                }
            }
        } else if !self.config.exclude_routes.is_empty() {
            error!("Split-tunnel: no default gateway found for exclude_routes");
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn remove_split_routes(&mut self) {
        use std::process::Command;
        for cidr in self.split_routes_applied.drain(..) {
            if let Some((net, mask)) = Self::cidr_to_net_mask(&cidr) {
                let _ = Command::new("route")
                    .args(["delete", &net, "mask", &mask])
                    .status();
            }
        }
        if !self.config.include_routes.is_empty() || !self.config.exclude_routes.is_empty() {
            info!("Split-tunnel routes removed");
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub fn apply_split_routes(&mut self) -> Result<()> {
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    fn remove_split_routes(&mut self) {}

    // ──────────────────── Kill-switch ────────────────────

    /// Activate the kill-switch if configured. Call after full-tunnel and split-routes setup.
    pub fn activate_kill_switch(&mut self) -> Result<()> {
        if !self.config.kill_switch {
            return Ok(());
        }
        let server_ip = self
            .server_ip
            .clone()
            .unwrap_or_else(|| self.config.server_vpn_ip.clone());
        let mut ks = KillSwitch::new(self.config.tun_name.clone(), server_ip);
        ks.activate()?;
        self.kill_switch_state = Some(ks);
        Ok(())
    }

    /// Explicitly deactivate the kill-switch. Call this on intentional disconnect,
    /// NOT from Drop — the kill-switch must persist across reconnect backoffs.
    pub fn deactivate_kill_switch(&mut self) {
        if let Some(ref mut ks) = self.kill_switch_state {
            ks.deactivate();
        }
        self.kill_switch_state = None;
    }

    /// Restore IPv6 on macOS when disconnecting
    #[cfg(target_os = "macos")]
    fn restore_ipv6(&self) {
        use std::process::Command;

        info!("Restoring IPv6...");
        // Remove the blackhole.  If we saved the interface before blocking,
        // restore the default route through it.  If not — the macOS network
        // stack will re-discover the gateway via ND/SLAAC automatically.
        let _ = Command::new("/sbin/route")
            .args(["-n", "delete", "-inet6", "-net", "::/0", "-blackhole"])
            .status();

        if let Some(ref iface) = self.saved_ipv6_iface {
            let status = Command::new("/sbin/route")
                .args(["-n", "add", "-inet6", "default", "-interface", iface])
                .status();
            match status {
                Ok(s) if s.success() => info!("IPv6 default route restored via {}", iface),
                _ => info!(
                    "IPv6 blackhole removed — macOS will auto-restore via ND (iface {})",
                    iface
                ),
            }
        } else {
            info!("IPv6 blackhole removed — macOS will auto-restore via ND");
        }
    }

    /// Restore IPv6 on Linux
    #[cfg(target_os = "linux")]
    fn restore_ipv6(&self) {
        use std::process::Command;

        info!("Restoring IPv6...");
        // Remove the blackhole (if any).  Let the kernel re-discover the gateway.
        let _ = Command::new("ip")
            .args(["-6", "route", "del", "blackhole", "default"])
            .status();
        let _ = Command::new("ip")
            .args(["-6", "route", "del", "::/0"])
            .status();
        info!("IPv6 blackhole removed — kernel will auto-restore via ND/RA");
    }

    /// Take the TUN reader (moves ownership to caller, e.g. spawned task)
    pub fn take_reader(&mut self) -> Option<tun::DeviceReader> {
        self.reader.take()
    }

    /// Write packet to TUN asynchronously
    pub async fn write_packet_async(&mut self, packet: &[u8]) -> Result<usize> {
        let writer = self.writer.as_mut().ok_or_else(|| {
            Error::Io(io::Error::new(
                io::ErrorKind::NotConnected,
                "TUN writer not available",
            ))
        })?;

        // macOS utun devices require a 4-byte address-family prefix before every packet
        // (AF_INET = 2, AF_INET6 = 30, both as big-endian u32). The read path strips this
        // prefix; we must re-add it symmetrically on the write path.
        #[cfg(target_os = "macos")]
        let to_write: std::borrow::Cow<[u8]> = {
            let af: u32 = if !packet.is_empty() && (packet[0] >> 4) == 6 {
                30
            } else {
                2
            };
            let mut framed = Vec::with_capacity(4 + packet.len());
            framed.extend_from_slice(&af.to_be_bytes());
            framed.extend_from_slice(packet);
            std::borrow::Cow::Owned(framed)
        };
        #[cfg(not(target_os = "macos"))]
        let to_write: std::borrow::Cow<[u8]> = std::borrow::Cow::Borrowed(packet);

        writer.write_all(&to_write).await?;
        writer.flush().await?;

        debug!("Wrote {} bytes to TUN", packet.len());
        Ok(packet.len())
    }

    /// Get TUN device name
    pub fn name(&self) -> &str {
        &self.config.tun_name
    }

    /// Get TUN config
    pub fn config(&self) -> &TunnelConfig {
        &self.config
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        // Kill-switch is NOT deactivated on drop to persist across reconnects.
        // Call deactivate_kill_switch() explicitly on intentional exit.

        // Best-effort cleanup of an in-flight pkexec child (see
        // ACTIVE_PKEXEC_PID's doc comment for what this does and doesn't
        // cover) — runs on every normal disconnect/reconnect-loop iteration
        // and on unwinding panics, just not on SIGKILL of this process.
        #[cfg(target_os = "linux")]
        kill_orphaned_pkexec_child();

        self.remove_split_routes();

        if self.config.full_tunnel && self.saved_default_gw.is_some() {
            self.disable_full_tunnel();
        }

        // Restore IPv6 blackhole route removed during full-tunnel setup.
        // Must run on both macOS (saves/restores via saved_ipv6_iface) and Linux
        // (removes the blackhole default route added in disable_ipv6).
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        self.restore_ipv6();

        if self.writer.is_some() || self.reader.is_some() {
            info!("Closing TUN device: {}", self.config.tun_name);
        }

        // Release the claim: the next connect creates a TUN under a fresh
        // random name and index, and a stale index left registered here could
        // suppress a genuine event on whatever device the kernel later assigns
        // that index to.
        crate::net_change::set_own_tun_ifindex(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_config() {
        let config = TunnelConfig::default();
        assert!(
            config.tun_name.starts_with("tun"),
            "TUN name should start with 'tun'"
        );
        assert_eq!(config.tun_addr, "10.0.0.2");
        assert_eq!(config.server_vpn_ip, "10.0.0.1");
        assert_eq!(config.mtu, WAN_SAFE_TUN_MTU);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_shell_quote_neutralizes_injection_attempts() {
        // run_ip_batch_privileged interpolates values sourced from `ip route
        // show default`'s own output (gateway/device names) into a shell
        // script executed via `sh -c` / `pkexec sh -c`. Confirm shell_quote
        // actually neutralizes metacharacters rather than just wrapping them.
        let cases = [
            ("eth0", "'eth0'"),
            ("10.0.0.1", "'10.0.0.1'"),
            ("a'; rm -rf /; echo '", r"'a'\''; rm -rf /; echo '\'''"),
            ("$(reboot)", "'$(reboot)'"),
            ("`whoami`", "'`whoami`'"),
        ];
        for (input, expected) in cases {
            assert_eq!(Tunnel::shell_quote(input), expected, "input: {input}");
        }

        // Actually round-trip the malicious case through a real shell to
        // prove it's inert, not just eyeballing the escaped string.
        let malicious = "a'; touch /tmp/aivpn_shell_quote_pwned; echo '";
        let quoted = Tunnel::shell_quote(malicious);
        let script = format!("printf '%s' {quoted}", quoted = quoted);
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(&script)
            .output()
            .expect("sh must be available to run this test");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            malicious,
            "quoted value must round-trip through the shell as literal text, \
             not be interpreted"
        );
        assert!(
            !std::path::Path::new("/tmp/aivpn_shell_quote_pwned").exists(),
            "shell_quote failed to neutralize an embedded command substitution/terminator"
        );
    }
}
