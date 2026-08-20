//! AIVPN Client Binary - Full Implementation

use aivpn_client::adaptive::{AdaptiveConfig, AdaptiveMonitor};
use aivpn_client::bench::run_bench;
use aivpn_client::bootstrap_cache;
use aivpn_client::bootstrap_loader::{self, BootstrapConfig};
use aivpn_client::client::{base_mask_family, handshake_reject_message, ClientConfig};
use aivpn_client::mask_feedback_log::{MaskFeedbackLog, RegionalHintsStore};
use aivpn_client::server_pool::{PoolMode, ServerEntry, ServerPool};
use aivpn_client::tunnel::TunnelConfig;
use aivpn_client::AivpnClient;
use aivpn_common::mask::preset_masks;
#[cfg(not(feature = "production-secure"))]
use aivpn_common::mask::preset_masks::bootstrap_default;
use aivpn_common::mask::BootstrapDescriptor;
use aivpn_common::network_config::{ClientNetworkConfig, DEFAULT_VPN_MTU, LEGACY_SERVER_VPN_IP};
use aivpn_common::quality::AdaptiveLevel;
use base64::Engine;
use clap::Parser;
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

/// AIVPN Client - Censorship-resistant VPN client
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct ClientArgs {
    /// Server address (e.g., 1.2.3.4:443)
    #[arg(short, long)]
    pub server: Option<String>,

    /// Server public key (base64, 32 bytes)
    #[arg(long)]
    pub server_key: Option<String>,

    /// Server signing public key (base64, 32 bytes)
    #[arg(long)]
    pub server_signing_key: Option<String>,

    /// Operator mask-verifying public key (base64, 32 bytes) — verifies the
    /// embedded operator signature of masks pushed via MaskUpdate (R2 Phase B).
    /// Also sourced from the config file or the `mop` field of the connection key.
    #[arg(long)]
    pub mask_operator_pubkey: Option<String>,

    /// Mask artifact verification mode: off | warn | enforce (default: warn).
    /// warn logs failures but accepts; enforce rejects unsigned/badly-signed masks.
    #[arg(long)]
    pub mask_verify_mode: Option<String>,

    /// Connection key (aivpn://...) — contains server, key, PSK, VPN IP
    #[arg(short = 'k', long)]
    pub connection_key: Option<String>,

    /// TUN device name (random if not specified)
    #[arg(long)]
    pub tun_name: Option<String>,

    /// TUN device address
    #[arg(long, default_value = "10.0.0.2")]
    pub tun_addr: String,

    /// Route all traffic through VPN tunnel
    #[arg(long, default_value_t = false)]
    pub full_tunnel: bool,

    /// Config file path (JSON)
    #[arg(long)]
    pub config: Option<String>,

    /// Passive bootstrap descriptor URL (may be repeated)
    #[arg(long)]
    pub bootstrap_descriptor_url: Vec<String>,

    /// CDN bootstrap URL (multi-channel distribution)
    #[arg(long)]
    pub bootstrap_cdn_url: Option<String>,

    /// Telegram bot token for bootstrap distribution (authenticated Bot API —
    /// required for the server's actual publish path, sendDocument, to be
    /// retrievable at all). Prefer the env var over the flag: a CLI arg is
    /// visible in /proc/<pid>/cmdline to every local user.
    #[arg(long, env = "AIVPN_BOOTSTRAP_TELEGRAM_TOKEN")]
    pub bootstrap_telegram_token: Option<String>,

    /// Telegram chat/channel ID to filter updates to (optional; if the bot
    /// is only used for bootstrap distribution, omitting this works fine)
    #[arg(long)]
    pub bootstrap_telegram_chat: Option<String>,

    /// GitHub repo for bootstrap distribution (e.g., infosave2007/aivpn)
    #[arg(long)]
    pub bootstrap_github: Option<String>,

    /// Disable built-in bootstrap fallback (production secure mode)
    #[arg(long, default_value_t = false)]
    pub no_fallback: bool,

    /// Run as SOCKS5 proxy on this address instead of a TUN device (no root required).
    /// Example: --proxy-listen 127.0.0.1:1080
    #[arg(long, value_name = "HOST:PORT")]
    pub proxy_listen: Option<String>,

    /// Path to a 104-byte mTLS client certificate (raw binary or base64-encoded).
    /// Required when the server has `mtls.required = true`.
    #[arg(long, value_name = "FILE")]
    pub mtls_cert: Option<std::path::PathBuf>,

    /// Route only these CIDRs through the VPN (comma-separated, split-tunnel mode).
    /// Example: --include-routes 10.0.0.0/8,192.168.1.0/24
    #[arg(
        long,
        value_name = "CIDR,...",
        use_value_delimiter = true,
        value_delimiter = ','
    )]
    pub include_routes: Vec<String>,

    /// Bypass the VPN for these CIDRs (comma-separated). Use with --full-tunnel to exclude subnets.
    /// Example: --exclude-routes 192.168.0.0/16,172.16.0.0/12
    #[arg(
        long,
        value_name = "CIDR,...",
        use_value_delimiter = true,
        value_delimiter = ','
    )]
    pub exclude_routes: Vec<String>,

    /// Block all non-VPN traffic while connected (kill-switch / leak protection).
    /// Rules persist after unexpected process death; run `kill-switch clear` to recover.
    #[arg(long, default_value_t = false)]
    pub kill_switch: bool,

    /// Enable adaptive mode — automatically adjusts MTU and keepalive on packet loss.
    #[arg(long, default_value_t = false)]
    pub adaptive: bool,

    /// Adaptive mode level: 0=Off, 1=Light (6s), 2=Aggressive (4s), 3=Satellite (15s).
    /// Overrides --adaptive when set. Passed by GUI clients.
    #[arg(long, value_name = "N")]
    pub adaptive_level: Option<u8>,

    /// Start a local DNS proxy on this address to prevent DNS leaks (e.g. 127.0.0.1:5300).
    /// Point /etc/resolv.conf at this address after connecting.
    #[arg(long, value_name = "HOST:PORT")]
    pub dns_proxy: Option<String>,

    /// Upstream DNS resolver used by --dns-proxy (default: 1.1.1.1:53).
    #[arg(long, value_name = "HOST:PORT", default_value = "1.1.1.1:53")]
    pub dns_upstream: String,

    /// Preferred mask profile name (e.g. webrtc_zoom_v3, quic_https_v2).
    /// When set, overrides the bootstrap-selected mask with the named built-in preset.
    /// Has no effect if the name is not a known preset.
    #[arg(long, value_name = "NAME")]
    pub preferred_mask: Option<String>,

    /// Request a polymorphic (per-session perturbed) variant of the named base mask
    /// (e.g. webrtc_zoom_v3). The server derives the variant deterministically from
    /// the session's PRNG seed and pushes it back via the normal MaskUpdate channel.
    /// Has no effect if the name is not a known preset.
    #[arg(long, value_name = "MASK_ID")]
    pub polymorphic_base: Option<String>,

    /// Opt in to sharing crowdsourced mask-blocking feedback with the server
    /// (which masks worked/failed, aggregated by coarse region). Off by default.
    #[arg(long, default_value_t = false)]
    pub share_mask_feedback: bool,

    /// Opt in to receiving server-provided "masks currently working in your
    /// region" hints. Off by default.
    #[arg(long, default_value_t = false)]
    pub receive_mask_hints: bool,

    /// Coarse region (ISO 3166-1 alpha-2, e.g. "DE") used only for crowdsourced
    /// mask feedback. No finer-grained location ever leaves the client.
    #[arg(long, value_name = "CC")]
    pub country_code: Option<String>,

    #[command(subcommand)]
    pub command: Option<ClientCommand>,
}

#[derive(clap::Subcommand, Debug)]
pub enum ClientCommand {
    /// Recording CLI commands
    Record {
        #[command(subcommand)]
        action: RecordAction,
    },
    /// Kill-switch management
    #[command(name = "kill-switch")]
    KillSwitch {
        #[command(subcommand)]
        action: KillSwitchAction,
    },
    /// Run connection diagnostics (latency, packet loss, quality score)
    Bench {
        /// Duration of the benchmark in seconds
        #[arg(short, long, default_value_t = 10)]
        duration: u64,
        /// Output as JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// P2.3-desktop: issue an in-tunnel management API call against the
    /// running client daemon, bridged over its local admin socket. This is
    /// the surface the Windows egui / Linux iced GUIs (which shell out to
    /// this binary rather than embedding the crate) use to drive in-tunnel
    /// admin/pool management. Prints the numeric HTTP-style status to
    /// stderr and the raw response body to stdout, so it composes cleanly
    /// with `jq`/pipelines.
    Mgmt {
        /// HTTP-style method the server-side management API expects.
        #[arg(long, value_enum)]
        method: MgmtMethod,
        /// Curated REST-shaped API path, e.g. /api/v1/clients
        #[arg(long)]
        path: String,
        /// File containing the raw request body (JSON, typically). Omit for
        /// an empty body.
        #[arg(long, value_name = "FILE")]
        body_file: Option<std::path::PathBuf>,
        /// Admin-socket auth token. Defaults to reading the token the
        /// running daemon wrote for this OS user (same file `record`
        /// commands use).
        #[arg(long)]
        token: Option<String>,
        /// Admin-socket address of the running client daemon.
        #[arg(long, default_value = "127.0.0.1:44301")]
        socket: String,
    },
    /// P2.3-desktop: report the server-assigned role (0=User, 1=Viewer,
    /// 2=Admin) cached by the running client daemon.
    Role {
        /// Admin-socket auth token (see `mgmt --token`).
        #[arg(long)]
        token: Option<String>,
        /// Admin-socket address of the running client daemon.
        #[arg(long, default_value = "127.0.0.1:44301")]
        socket: String,
    },
    /// Wave C2b-CLI: desktop bridge to the server SSH-installer
    /// (`aivpn_common::ssh_install`, re-exported as `aivpn_client::ssh_install`).
    /// Lets a GUI (or a human) drive a remote `aivpn-server` install over
    /// SSH by spawning this subcommand as a subprocess and reading its
    /// stdout — see `aivpn_client::ssh_install_cmd`'s module doc comment for
    /// the exact streaming contract. Gated behind the `ssh-install` feature
    /// so the default build never links `russh`/`russh-sftp`.
    #[cfg(feature = "ssh-install")]
    #[command(name = "ssh-install")]
    SshInstall {
        #[command(subcommand)]
        action: aivpn_client::ssh_install_cmd::SshInstallAction,
    },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
#[value(rename_all = "UPPER")]
pub enum MgmtMethod {
    Get,
    Post,
    Patch,
    Delete,
    Put,
}

impl MgmtMethod {
    /// Wire encoding used by `ControlPayload::MgmtRequest` / the admin-socket
    /// `mgmt:` command: 0=GET, 1=POST, 2=PATCH, 3=DELETE, 4=PUT.
    fn as_u8(self) -> u8 {
        match self {
            MgmtMethod::Get => 0,
            MgmtMethod::Post => 1,
            MgmtMethod::Patch => 2,
            MgmtMethod::Delete => 3,
            MgmtMethod::Put => 4,
        }
    }
}

/// Send a `"{token}:{command}"` datagram to the running daemon's admin
/// socket and wait (bounded) for a reply datagram. Shared by the `mgmt` and
/// `role` CLI subcommands, which — unlike the pre-existing `record`
/// subcommand (fire-and-forget, polls a status file) — need the daemon's
/// direct reply.
fn send_admin_request(socket_addr: &str, line: &str) -> Option<String> {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").ok()?;
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok()?;
    socket.send_to(line.as_bytes(), socket_addr).ok()?;
    let mut buf = [0u8; 65536];
    let (len, _addr) = socket.recv_from(&mut buf).ok()?;
    std::str::from_utf8(&buf[..len]).ok().map(|s| s.to_string())
}

#[derive(clap::Subcommand, Debug)]
pub enum KillSwitchAction {
    /// Remove stale kill-switch firewall rules left by a previous session
    Clear,
}

#[derive(clap::Subcommand, Debug)]
pub enum RecordAction {
    /// Start a new traffic recording session
    Start {
        #[arg(short, long)]
        service: String,
    },
    /// Stop the current recording and generate a mask
    Stop,
    /// Show the last known recording capability/state from the running client daemon
    Status,
}

// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Default, Deserialize)]
struct ClientFileConfig {
    server_addr: Option<String>,
    server_public_key: Option<String>,
    server_signing_public_key: Option<String>,
    mask_operator_pubkey: Option<String>,
    mask_verify_mode: Option<String>,
    preshared_key: Option<String>,
    tun_name: Option<String>,
    tun_addr: Option<String>,
    full_tunnel: Option<bool>,
    network_config: Option<ClientNetworkConfig>,
    bootstrap_descriptor_urls: Option<Vec<String>>,
    bootstrap_descriptors: Option<Vec<BootstrapDescriptor>>,
    include_routes: Option<Vec<String>>,
    exclude_routes: Option<Vec<String>>,
    kill_switch: Option<bool>,
}

fn load_client_file_config(path: Option<&str>) -> Option<ClientFileConfig> {
    let resolved = path?;
    std::fs::read_to_string(&resolved)
        .ok()
        .and_then(|json| serde_json::from_str::<ClientFileConfig>(&json).ok())
}

fn decode_base64_key(label: &str, encoded: &str) -> [u8; 32] {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap_or_else(|e| {
            error!("Invalid {}: {}", label, e);
            std::process::exit(1);
        });
    if decoded.len() != 32 {
        error!("{} must be 32 bytes, got {}", label, decoded.len());
        std::process::exit(1);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    out
}

// In development mode, derive a deterministic bootstrap mask from the PSK when no cached descriptors are available.
fn bootstrap_mask_for_psk(psk: &[u8; 32]) -> aivpn_common::mask::MaskProfile {
    use blake3;
    let presets = preset_masks::all();
    let hash = blake3::derive_key("aivpn-bootstrap-mask-v1", psk);
    let idx = hash[0] as usize % presets.len();
    presets[idx].clone()
}

#[tokio::main]
async fn main() {
    // On Windows, stderr inheritance via Stdio::from(File) is unreliable for
    // cross-compiled (MinGW) binaries with CREATE_NO_WINDOW. Write the log
    // directly to %LOCALAPPDATA%\AIVPN\client.log instead.
    #[cfg(target_os = "windows")]
    let _log_guard = {
        let args: Vec<String> = std::env::args().collect();
        // Only write to the persistent log file for the main VPN connection mode.
        // Subcommands (record, kill-switch, bench, mgmt, role, ssh-install) are
        // short-lived one-off CLI invocations that must not truncate the VPN
        // connection log. Must match the real `ClientCommand` variants exactly:
        // `Record`("record"),
        // `KillSwitch`("kill-switch" — clap's `#[command(name = "kill-switch")]`),
        // `Bench`("bench"), `Mgmt`("mgmt"), `Role`("role"),
        // `SshInstall`("ssh-install"). The P2.3-desktop bridge commands matter
        // most here: the Windows GUI shells out `aivpn-client.exe mgmt ...`
        // repeatedly WHILE the VPN daemon is running — before they were listed,
        // every such call fell into the main-mode branch below and truncated
        // %LOCALAPPDATA%\AIVPN\client.log mid-session. There is no top-level "status"/"key" subcommand, so
        // those never matched anything; "kill-switch" was missing entirely,
        // which meant e.g. `aivpn-client.exe kill-switch clear` — a genuine
        // one-off admin action — fell through to the main-mode branch below and
        // truncated %LOCALAPPDATA%\AIVPN\client.log, destroying diagnostic
        // history from the last real VPN session.
        let is_subcommand = args.iter().skip(1).any(|a| {
            matches!(
                a.as_str(),
                "record" | "kill-switch" | "bench" | "mgmt" | "role" | "ssh-install"
            )
        });

        let log_path = if is_subcommand {
            None
        } else {
            std::env::var_os("LOCALAPPDATA")
                .map(|p| std::path::PathBuf::from(p).join("AIVPN").join("client.log"))
        };

        if let Some(ref path) = log_path {
            let _ = std::fs::create_dir_all(path.parent().unwrap());
            // Redact the connection key before logging: the value of
            // --connection-key/-k (or any bare aivpn:// token) embeds the PSK
            // and server keys — a reusable secret that must never land in a
            // persistent plaintext log.
            let redacted_args: Vec<String> = {
                let mut out = Vec::with_capacity(args.len());
                let mut redact_next = false;
                for a in &args {
                    if redact_next {
                        redact_next = false;
                        out.push("<redacted>".to_string());
                    } else if a == "--connection-key" || a == "-k" {
                        redact_next = true;
                        out.push(a.clone());
                    } else if a.starts_with("--connection-key=") {
                        out.push("--connection-key=<redacted>".to_string());
                    } else if a.contains("aivpn://") {
                        out.push("<redacted>".to_string());
                    } else {
                        out.push(a.clone());
                    }
                }
                out
            };
            // Truncate and write startup header so each connect starts fresh.
            let _ = std::fs::write(
                path,
                format!(
                    "=== aivpn-client started ===\nargs: {:?}\nfull_tunnel: {}\n",
                    redacted_args,
                    args.contains(&"--full-tunnel".to_string())
                ),
            );
        }

        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

        let file = log_path.as_ref().and_then(|p| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .ok()
        });

        if let Some(f) = file {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::sync::Mutex::new(f))
                .with_ansi(false)
                .init();
        } else {
            // No log file (every subcommand — `log_path` is `None` for
            // `is_subcommand` above — and the daemon when `%LOCALAPPDATA%`
            // is unset): write to STDERR, never STDOUT. `mgmt`/`role`/
            // `ssh-install` print their machine-readable reply (mgmt JSON
            // body, role integer, `##AIVPN` markers) on STDOUT, and the
            // egui GUI parses it; a default-`info` tracing line on STDOUT
            // would corrupt that. Mirrors the non-Windows branch below.
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .init();
        }
        log_path // keep in scope so the subscriber lives for the whole process
    };

    #[cfg(not(target_os = "windows"))]
    // Initialize logging — default to INFO level when RUST_LOG is not set.
    // Writes to stderr, not stdout: `bench --json`/other structured-output
    // subcommands print their result via `println!` to stdout, and mixing
    // log lines into that stream corrupts the JSON a caller (e.g. the Linux
    // GUI's diagnostics button) tries to parse — the GUI would then silently
    // show no result at all, since serde_json::from_slice on the combined
    // buffer just fails.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    // Diagnostic for the "getcap says the capability is granted, but `ip`
    // still gets RTNETLINK EPERM" failure mode: if this process (or an
    // ancestor) has the kernel's no_new_privs bit set, file capabilities
    // granted via setcap to this binary and to `ip` are silently ignored at
    // exec time (capabilities(7); Documentation/userspace-api/no_new_privs.rst).
    // `getcap` only inspects the on-disk xattr, so it can't detect this.
    #[cfg(target_os = "linux")]
    {
        let no_new_privs = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("NoNewPrivs:"))
                    .map(|l| l.trim().to_string())
            })
            .unwrap_or_else(|| "NoNewPrivs: <unavailable>".to_string());
        info!("{no_new_privs} (1 = file capabilities granted via setcap to this binary or to `ip` are silently voided at exec time)");
    }

    // Setup Ctrl+C handler in a separate task
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {}
            Err(e) => warn!("Ctrl+C handler error: {e}"),
        }
        info!("Received Ctrl+C, shutting down...");
        shutdown_clone.store(true, Ordering::SeqCst);
        SHUTDOWN.store(true, Ordering::SeqCst);
    });

    // Handle SIGTERM (sent by systemd, docker stop, kill) so the tunnel routes
    // and kill-switch firewall rules are cleaned up on graceful service stop.
    #[cfg(unix)]
    {
        let shutdown_sigterm = shutdown.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            match signal(SignalKind::terminate()) {
                Ok(mut sig) => {
                    sig.recv().await;
                    info!("Received SIGTERM, shutting down...");
                }
                Err(e) => {
                    warn!("SIGTERM handler setup failed: {e}");
                    return;
                }
            }
            shutdown_sigterm.store(true, Ordering::SeqCst);
            SHUTDOWN.store(true, Ordering::SeqCst);
        });
    }

    // Parse arguments
    let mut args = ClientArgs::parse();
    if args.connection_key.is_none() {
        if let Ok(val) = std::env::var("AIVPN_CONNECTION_KEY") {
            args.connection_key = Some(val);
        }
    }
    std::env::remove_var("AIVPN_CONNECTION_KEY");

    // Handle subcommands
    if let Some(command) = args.command {
        match command {
            ClientCommand::KillSwitch { action } => match action {
                KillSwitchAction::Clear => {
                    aivpn_client::kill_switch::KillSwitch::clear_stale();
                    println!("Kill-switch stale rules cleared.");
                    return;
                }
            },
            ClientCommand::Bench { duration, json } => {
                let server_addr = args
                    .server
                    .clone()
                    .or_else(|| {
                        args.connection_key.as_deref().and_then(|ck| {
                            let payload = ck.trim().strip_prefix("aivpn://").unwrap_or(ck.trim());
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(payload)
                                .ok()
                                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                                .and_then(|v| v["s"].as_str().map(|s| s.to_string()))
                        })
                    })
                    .unwrap_or_else(|| {
                        error!("--server or --connection-key required for bench");
                        std::process::exit(1);
                    });

                let addr = server_addr.parse().unwrap_or_else(|e| {
                    error!("Invalid server address '{}': {}", server_addr, e);
                    std::process::exit(1);
                });
                let result = run_bench(addr, Duration::from_secs(duration)).await;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&result).unwrap_or_default()
                    );
                } else {
                    println!("═══ AIVPN Diagnostics ═══");
                    println!("Server:      {}", server_addr);
                    println!("Samples:     {}", result.samples);
                    println!("Latency P50: {:.1} ms", result.latency_p50_ms);
                    println!("Latency P95: {:.1} ms", result.latency_p95_ms);
                    println!("Latency P99: {:.1} ms", result.latency_p99_ms);
                    println!("Packet loss: {:.1}%", result.packet_loss_pct);
                    println!("Throughput:  {:.0} kbps est.", result.throughput_up_kbps);
                    println!(
                        "Quality:     {} ({})",
                        result.quality_score, result.quality_label
                    );
                }
                return;
            }
            ClientCommand::Mgmt {
                method,
                path,
                body_file,
                token,
                socket,
            } => {
                let body = match body_file {
                    Some(f) => std::fs::read(&f).unwrap_or_else(|e| {
                        eprintln!("Failed to read --body-file {}: {e}", f.display());
                        std::process::exit(1);
                    }),
                    None => Vec::new(),
                };
                let token = token
                    .or_else(aivpn_client::record_cmd::read_admin_token)
                    .unwrap_or_default();
                let body_b64 = aivpn_client::record_cmd::encode_body_b64(&body);
                let line = format!("{token}:mgmt:{}:{path}:{body_b64}", method.as_u8());
                match send_admin_request(&socket, &line) {
                    Some(reply) => match aivpn_client::record_cmd::parse_mgmt_reply(&reply) {
                        Some((status, resp_body)) => {
                            eprintln!("{status}");
                            use std::io::Write;
                            let _ = std::io::stdout().write_all(&resp_body);
                            if status == 0 {
                                std::process::exit(1);
                            }
                        }
                        None => {
                            eprintln!("Malformed reply from daemon: {reply}");
                            std::process::exit(1);
                        }
                    },
                    None => {
                        eprintln!("No reply from daemon at {socket} (is aivpn-client running?)");
                        std::process::exit(1);
                    }
                }
                return;
            }
            ClientCommand::Role { token, socket } => {
                let token = token
                    .or_else(aivpn_client::record_cmd::read_admin_token)
                    .unwrap_or_default();
                let line = format!("{token}:role");
                match send_admin_request(&socket, &line) {
                    Some(reply) => println!("{reply}"),
                    None => {
                        eprintln!("No reply from daemon at {socket} (is aivpn-client running?)");
                        std::process::exit(1);
                    }
                }
                return;
            }
            #[cfg(feature = "ssh-install")]
            ClientCommand::SshInstall { action } => {
                let code = aivpn_client::ssh_install_cmd::run(action).await;
                std::process::exit(code);
            }
            ClientCommand::Record { action } => {
                match action {
                    RecordAction::Start { service } => {
                        aivpn_client::record_cmd::handle_recording_status(true, Some(&service));
                        let token =
                            aivpn_client::record_cmd::read_admin_token().unwrap_or_default();
                        match std::net::UdpSocket::bind("127.0.0.1:0").and_then(|s| {
                            s.send_to(
                                format!("{token}:record_start:{service}").as_bytes(),
                                "127.0.0.1:44301",
                            )
                            .map(|_| s)
                        }) {
                            Ok(_) => {
                                println!("Recording start requested for '{service}'.");
                                println!("Run 'aivpn-client record status' to inspect progress.");
                            }
                            Err(e) => eprintln!("Failed to send record command: {e}"),
                        }
                    }
                    RecordAction::Stop => {
                        let prior = aivpn_client::record_cmd::read_local_status();
                        aivpn_client::record_cmd::mark_recording_stop_requested(
                            prior.as_ref().and_then(|status| status.service.as_deref()),
                        );
                        let token =
                            aivpn_client::record_cmd::read_admin_token().unwrap_or_default();
                        match std::net::UdpSocket::bind("127.0.0.1:0").and_then(|s| {
                            s.send_to(format!("{token}:record_stop").as_bytes(), "127.0.0.1:44301")
                                .map(|_| s)
                        }) {
                            Ok(_) => {}
                            Err(e) => eprintln!("Failed to send record command: {e}"),
                        }
                        println!("Recording stop requested.");
                        println!("Run 'aivpn-client record status' to inspect progress.");
                    }
                    RecordAction::Status => {
                        let before = aivpn_client::record_cmd::read_local_status()
                            .map(|status| status.updated_at_ms)
                            .unwrap_or(0);
                        let token =
                            aivpn_client::record_cmd::read_admin_token().unwrap_or_default();
                        if let Ok(socket) = std::net::UdpSocket::bind("127.0.0.1:0") {
                            let _ = socket.send_to(
                                format!("{token}:record_status").as_bytes(),
                                "127.0.0.1:44301",
                            );
                        }
                        let start = std::time::Instant::now();
                        let mut latest = None;
                        while start.elapsed() < std::time::Duration::from_secs(2) {
                            if let Some(status) = aivpn_client::record_cmd::read_local_status() {
                                if status.updated_at_ms >= before {
                                    latest = Some(status);
                                    break;
                                }
                            }
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        }
                        if let Some(status) =
                            latest.or_else(aivpn_client::record_cmd::read_local_status)
                        {
                            aivpn_client::record_cmd::print_local_status(&status);
                        } else {
                            println!("No recording status is available yet.");
                        }
                    }
                }
                return;
            }
        }
    }

    let file_config = load_client_file_config(args.config.as_deref());

    // Parse connection key or individual args
    let (
        server_addr,
        server_key_b64,
        psk_bytes,
        network_config,
        inline_descriptors,
        bootstrap_descriptor_urls,
        tun_name_fixed,
        full_tunnel,
    ) = if let Some(ref conn_key) = args.connection_key {
        let payload = conn_key
            .trim()
            .strip_prefix("aivpn://")
            .unwrap_or(conn_key.trim());
        let json_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap_or_else(|e| {
                error!("Invalid connection key: {}", e);
                std::process::exit(1);
            });
        let json: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap_or_else(|e| {
            error!("Malformed connection key JSON: {}", e);
            std::process::exit(1);
        });
        let s = json["s"]
            .as_str()
            .unwrap_or_else(|| {
                error!("Connection key missing server address (\"s\")");
                std::process::exit(1);
            })
            .to_string();
        let k = json["k"]
            .as_str()
            .unwrap_or_else(|| {
                error!("Connection key missing server key (\"k\")");
                std::process::exit(1);
            })
            .to_string();
        let psk: Option<Vec<u8>> = json["p"]
            .as_str()
            .and_then(|p| base64::engine::general_purpose::STANDARD.decode(p).ok());
        let network_config = json
            .get("n")
            .cloned()
            .and_then(|value| serde_json::from_value::<ClientNetworkConfig>(value).ok())
            .or_else(|| {
                json["i"].as_str().and_then(|ip| {
                    ip.parse::<Ipv4Addr>()
                        .ok()
                        .map(|client_ip| ClientNetworkConfig {
                            client_ip,
                            server_vpn_ip: LEGACY_SERVER_VPN_IP,
                            prefix_len: 24,
                            mtu: DEFAULT_VPN_MTU,
                            mdh_len: 20,
                            keepalive_secs: None,
                            ipv6_address: None,
                        })
                })
            })
            .unwrap_or_else(|| fallback_network_config(&args.tun_addr));
        let inline_descriptors = json
            .get("bd")
            .cloned()
            .and_then(|value| serde_json::from_value::<Vec<BootstrapDescriptor>>(value).ok())
            .unwrap_or_default();
        let bootstrap_descriptor_urls = json
            .get("bu")
            .cloned()
            .and_then(|value| serde_json::from_value::<Vec<String>>(value).ok())
            .unwrap_or_default();
        (
            s,
            k,
            psk,
            network_config,
            inline_descriptors,
            bootstrap_descriptor_urls,
            args.tun_name.clone(),
            args.full_tunnel,
        )
    } else {
        let server = args
            .server
            .clone()
            .or_else(|| {
                file_config
                    .as_ref()
                    .and_then(|config| config.server_addr.clone())
            })
            .unwrap_or_else(|| {
                error!("Either --connection-key or --server + --server-key required");
                std::process::exit(1);
            });
        let key = args
            .server_key
            .clone()
            .or_else(|| {
                file_config
                    .as_ref()
                    .and_then(|config| config.server_public_key.clone())
            })
            .unwrap_or_else(|| {
                error!("Either --connection-key or --server + --server-key required");
                std::process::exit(1);
            });
        let psk = file_config
            .as_ref()
            .and_then(|config| config.preshared_key.as_ref())
            .and_then(|value| base64::engine::general_purpose::STANDARD.decode(value).ok());
        let network_config = file_config
            .as_ref()
            .and_then(|config| config.network_config.clone())
            .unwrap_or_else(|| {
                fallback_network_config(
                    file_config
                        .as_ref()
                        .and_then(|config| config.tun_addr.as_deref())
                        .unwrap_or(&args.tun_addr),
                )
            });
        let mut urls = file_config
            .as_ref()
            .and_then(|config| config.bootstrap_descriptor_urls.clone())
            .unwrap_or_default();
        urls.extend(args.bootstrap_descriptor_url.clone());
        (
            server,
            key,
            psk,
            network_config,
            file_config
                .as_ref()
                .and_then(|config| config.bootstrap_descriptors.clone())
                .unwrap_or_default(),
            urls,
            args.tun_name.clone().or_else(|| {
                file_config
                    .as_ref()
                    .and_then(|config| config.tun_name.clone())
            }),
            args.full_tunnel
                || file_config
                    .as_ref()
                    .and_then(|config| config.full_tunnel)
                    .unwrap_or(false),
        )
    };

    // Build server pool from optional "pool" array in the connection key.
    // Hostname endpoints are resolved here (async) via the system resolver —
    // the sync ServerPool::new would silently drop every non-"IP:port" entry,
    // leaving a hostname pool with zero nodes and failover quietly dead.
    let pool_peers = args.connection_key.as_deref().and_then(|ck| {
        let payload = ck.trim().strip_prefix("aivpn://").unwrap_or(ck.trim());
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .ok()?;
        let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        let peers: Vec<ServerEntry> = serde_json::from_value(json.get("pool")?.clone()).ok()?;
        if peers.is_empty() {
            return None;
        }
        Some(peers)
    });
    let server_pool = match pool_peers {
        Some(peers) => {
            Some(ServerPool::resolve_and_new(&server_addr, peers, PoolMode::Failover).await)
        }
        None => None,
    };
    if let Some(ref pool) = server_pool {
        info!("Server pool active: {} node(s)", pool.node_count());
    }

    // Resolve effective adaptive level: --adaptive-level N overrides bool --adaptive.
    // N is honored as the client's starting AdaptiveLevel (keepalive interval + FEC),
    // not just a hint for MTU shrinkage — the quality tracker can still raise/lower it
    // automatically from there based on observed RTT/jitter/loss.
    let initial_adaptive_level = AdaptiveLevel::from_u8(
        args.adaptive_level
            .unwrap_or(if args.adaptive { 1 } else { 0 }),
    );
    let adaptive_on = initial_adaptive_level != AdaptiveLevel::Off;

    // Adaptive mode monitor
    let adaptive_monitor = AdaptiveMonitor::new(AdaptiveConfig {
        enabled: adaptive_on,
        ..AdaptiveConfig::default()
    });
    if adaptive_on {
        info!(
            "Adaptive mode enabled at level {:?} (keepalive {}s, FEC 1/{})",
            initial_adaptive_level,
            initial_adaptive_level.keepalive_secs(),
            initial_adaptive_level.fec_n()
        );
    }
    // Lower initial MTU for restrictive mobile networks (MTS, Megafon) when adaptive is on.
    let network_config = if adaptive_on {
        aivpn_common::network_config::ClientNetworkConfig {
            mtu: network_config.mtu.min(1200),
            ..network_config
        }
    } else {
        network_config
    };
    // NOTE: the loss-triggered live MTU step-down was removed as a never-wired
    // dead path — the TUN device's MTU is fixed at creation (tunnel.rs) and nothing
    // fed real packet loss into it. Loss resilience today comes from AdaptiveLevel's
    // score-driven keepalive + FEC redundancy instead (see quality.rs / client.rs).
    let _ = adaptive_monitor;

    info!("AIVPN Client v{}", env!("CARGO_PKG_VERSION"));
    info!("Connecting to server: {}", server_addr);

    let server_public_key = decode_base64_key("server key", &server_key_b64);

    // Optional ed25519 signing key for ServerHello/MaskUpdate/BootstrapDescriptor
    // verification. Sourced (in precedence order) from --server-signing-key, the
    // config file, or the `sk` field embedded in the aivpn:// connection key — the
    // last is the default onboarding path, so verification is now active out of
    // the box for anyone who pastes a key from a server that embeds it.
    let conn_signing_key_b64: Option<String> = args.connection_key.as_deref().and_then(|ck| {
        parse_connection_key(ck)
            .ok()
            .and_then(|j| j.get("sk").and_then(|v| v.as_str().map(String::from)))
    });
    let server_signing_b64: Option<String> = args
        .server_signing_key
        .clone()
        .or_else(|| {
            file_config
                .as_ref()
                .and_then(|c| c.server_signing_public_key.clone())
        })
        .or(conn_signing_key_b64);
    let server_signing_key: Option<[u8; 32]> =
        server_signing_b64.map(|b64| decode_base64_key("server signing key", &b64));

    // R2 Phase B: operator mask-verifying public key for artifact-level mask
    // signature verification. Sourced (in precedence order) from
    // --mask-operator-pubkey, the config file, or the `mop` field embedded in
    // the aivpn:// connection key — mirroring the `sk` transport key above.
    let conn_mop_b64: Option<String> = args.connection_key.as_deref().and_then(|ck| {
        parse_connection_key(ck)
            .ok()
            .and_then(|j| j.get("mop").and_then(|v| v.as_str().map(String::from)))
    });
    let mask_operator_pubkey: Option<[u8; 32]> = args
        .mask_operator_pubkey
        .clone()
        .or_else(|| {
            file_config
                .as_ref()
                .and_then(|c| c.mask_operator_pubkey.clone())
        })
        .or(conn_mop_b64)
        .map(|b64| decode_base64_key("mask operator pubkey", &b64));
    let mask_verify_mode: aivpn_common::mask::MaskVerifyMode =
        match args.mask_verify_mode.clone().or_else(|| {
            file_config
                .as_ref()
                .and_then(|c| c.mask_verify_mode.clone())
        }) {
            None => aivpn_common::mask::MaskVerifyMode::default(),
            Some(s) => s.parse().unwrap_or_else(|e| {
                error!("{}", e);
                std::process::exit(1);
            }),
        };

    // Parse PSK
    let preshared_key: Option<[u8; 32]> = psk_bytes.and_then(|v| {
        if v.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v);
            Some(arr)
        } else {
            None
        }
    });

    let network_config = network_config;

    if server_signing_key.is_none() {
        warn!("No --server-signing-key provided; bootstrap descriptors accepted without signature verification");
    }
    for descriptor in inline_descriptors {
        if let Err(e) =
            bootstrap_cache::store_verified_descriptor(descriptor, server_signing_key.as_ref())
        {
            warn!(
                "Failed to store bootstrap descriptor from config/key: {}",
                e
            );
        }
    }
    let fetched =
        bootstrap_cache::refresh_from_urls(&bootstrap_descriptor_urls, server_signing_key.as_ref())
            .await;
    if fetched > 0 {
        info!(
            "Fetched {} bootstrap descriptor(s) from passive URLs",
            fetched
        );
    }

    // Build multi-channel bootstrap configuration if any channels are specified
    let mut bootstrap_config = BootstrapConfig::default();
    if let Some(cdn_url) = &args.bootstrap_cdn_url {
        bootstrap_config = bootstrap_config.with_cdn(cdn_url, "custom");
    }
    if let Some(telegram_token) = &args.bootstrap_telegram_token {
        bootstrap_config =
            bootstrap_config.with_telegram(telegram_token, args.bootstrap_telegram_chat.clone());
    }
    if let Some(github_repo) = &args.bootstrap_github {
        bootstrap_config = bootstrap_config.with_github(github_repo, "bootstrap-");
    }

    // Load from multi-channel if configured
    if !bootstrap_config.channels.is_empty() {
        info!(
            "Loading bootstrap descriptors from {} channels",
            bootstrap_config.channels.len()
        );
        let stats = bootstrap_loader::load_multi_channel(&bootstrap_config).await;
        info!(
            "Multi-channel bootstrap: {}/{} succeeded, {} descriptors loaded in {}ms",
            stats.successful_channels,
            stats.total_channels,
            stats.total_descriptors,
            stats.elapsed_ms
        );
    }

    let no_fallback = args.no_fallback || !bootstrap_config.channels.is_empty();
    let proxy_listen = args.proxy_listen.as_ref().map(|s| {
        let addr = s.parse::<std::net::SocketAddr>().unwrap_or_else(|e| {
            error!("Invalid --proxy-listen '{}': {}", s, e);
            std::process::exit(1);
        });
        if !addr.ip().is_loopback() {
            warn!(
                "--proxy-listen {} binds to a non-loopback address; the SOCKS5 proxy has no \
                 authentication, so anyone reachable on that interface can relay traffic \
                 through the VPN tunnel",
                addr
            );
        }
        addr
    });
    let mtls_cert: Option<Vec<u8>> = args.mtls_cert.as_ref().map(|path| {
        let raw = std::fs::read(path).unwrap_or_else(|e| {
            error!("Cannot read --mtls-cert '{}': {}", path.display(), e);
            std::process::exit(1);
        });
        // Accept raw 104-byte binary or base64-encoded text.
        if raw.len() == 104 {
            raw
        } else {
            let s = String::from_utf8_lossy(&raw);
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(s.trim())
                .unwrap_or_else(|e| {
                    error!(
                        "--mtls-cert is neither 104-byte binary nor valid base64: {}",
                        e
                    );
                    std::process::exit(1);
                })
        }
    });
    let mut backoff = INITIAL_BACKOFF;
    let max_backoff = MAX_BACKOFF;

    // §2 crowdsourced blocking feedback — parse the coarse region once (shared
    // by every reconnect iteration). Invalid codes are dropped with a warning.
    let country_code: Option<[u8; 2]> = args.country_code.as_deref().and_then(|s| {
        let b = s.trim().as_bytes();
        if b.len() == 2 && b[0].is_ascii_alphabetic() && b[1].is_ascii_alphabetic() {
            Some([b[0].to_ascii_uppercase(), b[1].to_ascii_uppercase()])
        } else {
            warn!(
                "--country-code '{}' is not a 2-letter ISO 3166-1 code; ignoring it (mask feedback will omit region)",
                s
            );
            None
        }
    });
    // §2 L2 failure attribution — consecutive failed-attempt counts per base
    // mask family, carried across reconnect iterations. A family is only
    // recorded as a FAILURE once it has failed `report_failure_threshold`
    // consecutive times (the server-pushed noise gate), then the counter
    // resets. A successful connection clears the family's counter.
    let mut consecutive_fails: std::collections::HashMap<String, u8> =
        std::collections::HashMap::new();
    // Resilience against an unmatchable cached bootstrap descriptor: count
    // consecutive attempts that NEVER reached a connected state. A cached
    // descriptor signed by a server whose key was rotated (or an epoch the
    // current server no longer retains) yields a polymorphic handshake mask the
    // server cannot reproduce → every handshake fails with a tag mismatch and
    // the client loops forever. After this many dead handshakes we drop the
    // descriptor-derived mask for the built-in default preset, which every
    // server matches via its builtin candidate set. Reset on any real connect.
    const HANDSHAKE_FALLBACK_THRESHOLD: u32 = 3;
    let mut handshake_fail_streak: u32 = 0;
    // 3b: native OS network-change listener, spawned ONCE for the whole
    // process lifetime (see net_change.rs) — best-effort, `None` when
    // unsupported/unavailable, in which case the client falls back to the
    // existing poll-based watchdogs unchanged. The same `Arc<Notify>` handle
    // is threaded into every reconnect iteration's `ClientConfig` below so a
    // single OS registration serves every `AivpnClient::run()` call.
    // An alternative transport can generate its own link/address churn (a
    // WebRTC-style engine opens sockets and runs ICE) that the OS network-change
    // listener cannot distinguish from a real network change, tearing the
    // session down mid-session. When such a transport is configured, or when the
    // operator sets AIVPN_DISABLE_NETCHANGE, skip the native listener and rely
    // on the poll-based watchdogs, which key off actual RX silence rather than
    // interface events.
    let disable_netchange = std::env::var("AIVPN_DISABLE_NETCHANGE").is_ok()
        || std::env::var("AIVPN_TRANSPORT")
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
    let network_change_notify = if disable_netchange {
        None
    } else {
        aivpn_client::net_change::spawn()
    };
    // Whether the user opted in to sharing outcome data (failures + successes).
    // Recording a failure additionally requires a country code (the server
    // aggregates per region and drops feedback without one).
    let feedback_share_enabled = args.share_mask_feedback && country_code.is_some();

    // Start DNS proxy once before the reconnect loop so it stays alive across
    // tunnel restarts. If created inside the loop, the handle is dropped at the
    // end of each iteration and the proxy is killed during the backoff sleep —
    // creating a DNS leak window on every reconnect.
    let _dns_proxy_handle = args.dns_proxy.as_deref().and_then(|bind_str| {
        // Unlike every other malformed-input path in this file
        // (--server-key, --proxy-listen, --mtls-cert, --mask-verify-mode,
        // --tun-addr all log+exit on bad input), a typo'd
        // --dns-proxy/--dns-upstream used to fail via `.ok()?` with zero
        // logging — the user's requested DNS leak protection silently never
        // starts, with nothing in the log to say why. Warn loudly instead so
        // this is at least visible, without hard-exiting the whole client
        // over a proxy that's opt-in.
        let bind_addr = match bind_str.parse::<std::net::SocketAddr>() {
            Ok(a) => a,
            Err(e) => {
                error!(
                    "--dns-proxy '{}' is not a valid address:port — DNS leak protection NOT started: {}",
                    bind_str, e
                );
                return None;
            }
        };
        let upstream_addr = match args.dns_upstream.parse::<std::net::SocketAddr>() {
            Ok(a) => a,
            Err(e) => {
                error!(
                    "--dns-upstream '{}' is not a valid address:port — DNS leak protection NOT started: {}",
                    args.dns_upstream, e
                );
                return None;
            }
        };
        Some(aivpn_client::dns_proxy::spawn_dns_proxy(
            aivpn_client::dns_proxy::DnsProxyConfig {
                listen_addr: bind_addr,
                upstream_addr,
            },
        ))
    });

    loop {
        if shutdown.load(Ordering::SeqCst) {
            info!("Shutdown requested, stopping client loop");
            break;
        }

        // Use stable TUN name when user asked for it; otherwise generate fresh.
        // Fresh name avoids rare conflicts when previous TUN wasn't fully torn down yet.
        let tun_name = tun_name_fixed.clone().unwrap_or_else(|| {
            use rand::Rng;
            format!("tun{:04x}", rand::thread_rng().gen::<u16>())
        });

        // Select initial mask from cached descriptors
        // In production secure mode (no_fallback), fail if no valid descriptors are available
        let initial_mask = bootstrap_cache::select_initial_mask(preshared_key.as_ref());

        // FIX (Jul 15): sticky last-known-good mask. In AUTO mode (no explicit
        // --preferred-mask / --polymorphic-base), once a mask has carried real
        // data this process, reuse it across reconnects instead of re-deriving
        // from the churning descriptor set — which otherwise hops masks on every
        // data-watchdog reconnect and never lets the data plane settle. Yields to
        // the handshake-fallback threshold (handled below) so a no-longer-
        // matchable sticky mask cannot wedge the client. Mirrors the mobile cores.
        let initial_mask = if args.preferred_mask.is_none()
            && args.polymorphic_base.is_none()
            && handshake_fail_streak < HANDSHAKE_FALLBACK_THRESHOLD
        {
            bootstrap_cache::LAST_GOOD_MASK
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
                .or(initial_mask)
        } else {
            initial_mask
        };

        let initial_mask = if no_fallback {
            match initial_mask {
                Some(mask) => mask,
                None => {
                    error!(
                        "No valid bootstrap descriptors available and fallback disabled. \
                         Ensure multi-channel bootstrap is configured or descriptors are cached."
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(backoff * 2, max_backoff);
                    continue;
                }
            }
        } else {
            // Development mode: fall back to built-in mask if no cached descriptors
            #[cfg(feature = "production-secure")]
            {
                match initial_mask {
                    Some(mask) => mask,
                    None => {
                        error!("No valid bootstrap descriptors available");
                        tokio::time::sleep(backoff).await;
                        backoff = std::cmp::min(backoff * 2, max_backoff);
                        continue;
                    }
                }
            }
            #[cfg(not(feature = "production-secure"))]
            {
                // psk-based fallback provides a stable development experience without requiring descriptor management, while still allowing testing of the full mask selection and rotation logic.
                match initial_mask {
                    Some(mask) => mask,
                    None => match &preshared_key {
                        Some(psk_bytes) => bootstrap_mask_for_psk(psk_bytes),
                        None => bootstrap_default(),
                    },
                }
            }
        };

        // 3c: whether THIS iteration's initial_mask came from the resilience
        // fallback below rather than normal bootstrap selection. Threaded
        // into ClientConfig so the client can surface it to file-polling
        // GUIs (Windows traffic.stats `fallback:` key); the stdout
        // AIVPN-STATUS line right below covers stdout-reading GUIs (Linux)
        // and the CLI. Declared unconditionally (defaults false) so
        // production-secure builds — which never take the branch below —
        // still have a value to put in ClientConfig. `mut` is unused (and
        // allowed) specifically in production-secure builds, where the
        // fallback branch that mutates it is compiled out entirely.
        #[allow(unused_mut)]
        let mut is_bootstrap_fallback = false;

        // Resilience net (F1): after repeated handshakes that never connected,
        // abandon the descriptor-derived mask for the built-in default preset,
        // which every server matches. Only in builds that permit the built-in
        // fallback bootstrap — a production-secure client must stay on signed
        // descriptors even at the cost of availability. An explicit
        // --preferred-mask / --polymorphic-base below still takes precedence.
        #[cfg(not(feature = "production-secure"))]
        let initial_mask = if !no_fallback && handshake_fail_streak >= HANDSHAKE_FALLBACK_THRESHOLD
        {
            warn!(
                "{} consecutive handshakes never connected — falling back to the built-in default mask (a cached bootstrap descriptor may be unmatchable by this server, e.g. after a server-key change)",
                handshake_fail_streak
            );
            // 3c: machine-readable status line (mirrors "AIVPN-STATUS
            // connected <ip>") so the CLI and stdout-reading GUIs (Linux)
            // can show a "using built-in mask (fallback)" indicator.
            println!("AIVPN-STATUS bootstrap-fallback");
            is_bootstrap_fallback = true;
            bootstrap_default()
        } else {
            initial_mask
        };

        // production-secure companion to the fallback above: never drop to an
        // unsigned builtin mask, but still recover from a cached descriptor the
        // server can no longer match (rotated signing/session key, expired
        // epoch) — otherwise `select_initial_mask()` deterministically re-picks
        // the same newest-`created_at` descriptor every reconnect and the
        // client is stuck until the descriptor's own (possibly hours/days-long)
        // `expires_at` passes. Exclude the specific failing descriptor id from
        // this run's selection (not delete it from disk) so selection advances
        // to the next-newest still-valid SIGNED descriptor, and kick an
        // immediate re-fetch in case the operator has since published a fresh
        // one. Resets the fail streak so the newly-selected descriptor gets its
        // own full threshold before being excluded in turn.
        #[cfg(feature = "production-secure")]
        let initial_mask = if handshake_fail_streak >= HANDSHAKE_FALLBACK_THRESHOLD {
            let descriptor_id = initial_mask
                .mask_id
                .strip_prefix("bootstrap:")
                .and_then(|rest| rest.split(':').next())
                .map(|s| s.to_string());
            if let Some(id) = &descriptor_id {
                warn!(
                    "{} consecutive handshakes never connected on descriptor '{}' — excluding it \
                     from selection and forcing a bootstrap re-fetch (production-secure: no unsigned fallback)",
                    handshake_fail_streak, id
                );
                bootstrap_cache::exclude_descriptor(id);
                handshake_fail_streak = 0;
            }
            let refetched = bootstrap_cache::refresh_from_urls(
                &bootstrap_descriptor_urls,
                server_signing_key.as_ref(),
            )
            .await;
            if refetched > 0 {
                info!(
                    "Re-fetched {} bootstrap descriptor(s) after a stuck descriptor",
                    refetched
                );
            }
            bootstrap_cache::select_initial_mask(preshared_key.as_ref()).unwrap_or(initial_mask)
        } else {
            initial_mask
        };

        // Honor --preferred-mask: override with a named built-in preset when
        // available. In polymorphic mode we deliberately leave the initial mask
        // as the bootstrap fallback (matching every GUI) so the opening burst
        // isn't a fingerprintable named preset — the server pushes the
        // per-session variant via MaskUpdate one RTT later. So --polymorphic-base
        // takes precedence and suppresses --preferred-mask.
        let initial_mask = if args.polymorphic_base.is_some() {
            if args.preferred_mask.is_some() {
                warn!("--polymorphic-base set; ignoring --preferred-mask for the initial mask");
            }
            initial_mask
        } else if let Some(ref name) = args.preferred_mask {
            match aivpn_common::mask::preset_masks::by_id(name.as_str()) {
                Some(m) => {
                    info!("Using preferred mask '{}'", name);
                    m
                }
                None => {
                    warn!(
                        "Preferred mask '{}' not found in built-in presets, using bootstrap selection",
                        name
                    );
                    initial_mask
                }
            }
        } else {
            initial_mask
        };

        // §2 L3 — soft regional-hint bias. When the user opts in to hints and a
        // country is set, and there is NO explicit --preferred-mask /
        // --polymorphic-base override, softly steer the initial mask toward the
        // preset that the server reported working best in this region. Rules
        // that keep this SOFT and safe:
        //   - Never overrides an explicit --preferred-mask/--polymorphic-base
        //     (those branches above already produced a mask; this only runs in
        //     the plain fallthrough case).
        //   - Never runs in `no_fallback`/production-secure mode, where the
        //     opening mask MUST be a valid signed bootstrap descriptor — biasing
        //     it to a named preset would break bootstrap security.
        //   - Only applies when a hinted mask is a KNOWN built-in preset with a
        //     success score at or above `HINT_BIAS_MIN_SCORE`; otherwise the
        //     bootstrap-selected mask is kept unchanged.
        let initial_mask = if args.receive_mask_hints
            && !no_fallback
            && args.preferred_mask.is_none()
            && args.polymorphic_base.is_none()
        {
            if let Some(cc) = country_code {
                let hints = RegionalHintsStore::load_default().for_region(cc);
                let biased = hints.into_iter().find_map(|(mask_id, score)| {
                    if score < HINT_BIAS_MIN_SCORE {
                        return None;
                    }
                    aivpn_common::mask::preset_masks::by_id(&mask_id).map(|m| (mask_id, score, m))
                });
                match biased {
                    Some((mask_id, score, mask)) => {
                        info!(
                            "Regional hint bias: using mask '{}' (score {:.2}) for region {}{}",
                            mask_id, score, cc[0] as char, cc[1] as char
                        );
                        mask
                    }
                    None => initial_mask,
                }
            } else {
                initial_mask
            }
        } else {
            initial_mask
        };
        // Capture the attempt's base mask family for §2 failure attribution
        // before `initial_mask` is moved into ClientConfig below.
        //
        // In polymorphic mode the initial mask is deliberately the
        // bootstrap-fallback family (so the opening burst isn't a named preset),
        // but the mask the session actually runs is the server-pushed per-session
        // variant of `--polymorphic-base`. Attributing a failed attempt to the
        // fallback family would silently blame the wrong family for every §3
        // session, defeating §2. So prefer the configured polymorphic base when
        // set; otherwise fall back to the bootstrap/initial mask family. Kept
        // consistent with the success path in `client.rs`.
        let attempt_mask_family = match args.polymorphic_base.as_deref() {
            Some(base) => base_mask_family(base),
            None => base_mask_family(&initial_mask.mask_id),
        };

        let mut include_routes: Vec<String> = if !args.include_routes.is_empty() {
            args.include_routes.clone()
        } else {
            file_config
                .as_ref()
                .and_then(|c| c.include_routes.clone())
                .unwrap_or_default()
        };
        // DNS proxy forwards queries from a fresh OS socket bound to 0.0.0.0, so
        // without an explicit route the upstream resolver is only reachable via the
        // tunnel when --full-tunnel is set — split-tunnel users would silently leak
        // every DNS query out the physical interface. Add a host route for the
        // upstream resolver so --dns-proxy actually tunnels regardless of mode.
        if args.dns_proxy.is_some() {
            if let Ok(upstream) = args.dns_upstream.parse::<std::net::SocketAddr>() {
                let cidr = match upstream.ip() {
                    std::net::IpAddr::V4(ip) => format!("{ip}/32"),
                    std::net::IpAddr::V6(ip) => format!("{ip}/128"),
                };
                if !include_routes.iter().any(|r| r == &cidr) {
                    include_routes.push(cidr);
                }
            }
        }
        let exclude_routes: Vec<String> = if !args.exclude_routes.is_empty() {
            args.exclude_routes.clone()
        } else {
            file_config
                .as_ref()
                .and_then(|c| c.exclude_routes.clone())
                .unwrap_or_default()
        };
        let mut tun_config = TunnelConfig::from_network_config(
            tun_name.clone(),
            network_config.clone(),
            full_tunnel,
        );
        tun_config.include_routes = include_routes;
        tun_config.exclude_routes = exclude_routes;
        tun_config.kill_switch = args.kill_switch
            || file_config
                .as_ref()
                .and_then(|c| c.kill_switch)
                .unwrap_or(false);

        // Failover: pick next healthy node from pool, or fall back to primary
        let active_server_addr: Option<std::net::SocketAddr> =
            server_pool.as_ref().and_then(|p| p.next_server());
        let active_server = active_server_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| server_addr.clone());

        let config = ClientConfig {
            server_addr: active_server,
            server_public_key,
            server_signing_key,
            preshared_key,
            initial_mask,
            tun_config,
            proxy_listen,
            mtls_cert: mtls_cert.clone(),
            initial_adaptive_level,
            polymorphic_base: args.polymorphic_base.clone(),
            // §2 crowdsourced blocking feedback — opt-in, OFF unless the user
            // explicitly enables it via CLI flags (or a GUI that passes them).
            share_mask_feedback: args.share_mask_feedback,
            receive_mask_hints: args.receive_mask_hints,
            country_code,
            mask_operator_pubkey,
            mask_verify_mode,
            network_change_notify: network_change_notify.clone(),
            is_bootstrap_fallback,
            control_only: false,
            inbound_control_tap: None,
            node_identity: None,
            pool_node_id: None,
            transport: transport_config(),
        };

        match AivpnClient::new(config) {
            Ok(mut client) => {
                client.set_transport_registry(
                    std::sync::Arc::new(transport_registry()),
                    platform_socket_guard(),
                );
                info!("Client initialized successfully (TUN: {})", tun_name);

                // Write initial stats file (platform-appropriate paths)
                #[cfg(target_os = "windows")]
                {
                    if let Some(local_app) = std::env::var_os("LOCALAPPDATA") {
                        let dir = std::path::PathBuf::from(local_app).join("AIVPN");
                        let _ = std::fs::create_dir_all(&dir);
                        let _ = std::fs::write(dir.join("traffic.stats"), "sent:0,received:0");
                    }
                    let _ = std::fs::write(
                        std::env::temp_dir().join("aivpn-traffic.stats"),
                        "sent:0,received:0",
                    );
                }
                #[cfg(not(target_os = "windows"))]
                {
                    let _ = std::fs::write("/var/run/aivpn/traffic.stats", "sent:0,received:0");
                    let _ = std::fs::write("/tmp/aivpn-traffic.stats", "sent:0,received:0");
                }
                aivpn_client::record_cmd::reset_local_status();

                let connect_started = std::time::Instant::now();
                let run_result = client.run(shutdown.clone()).await;

                // §2 L2 failure attribution — did this attempt ever reach a
                // connected state? An attempt that never connected is evidence
                // the mask may be blocked; record it (subject to the consecutive
                // threshold) so the next successful connection reports it. A
                // successful connection clears the family's failure streak.
                // F1 resilience streak — independent of feedback opt-in. A real
                // connection clears it; a dead handshake grows it until the
                // built-in-mask fallback above kicks in.
                if client.ever_connected() {
                    handshake_fail_streak = 0;
                } else {
                    handshake_fail_streak = handshake_fail_streak.saturating_add(1);
                }

                // Wire the pool's health tracking to the real connection outcome —
                // without this, `NodeState::is_healthy()` never sees a failure and
                // `next_server()` (Failover mode) retries the same dead primary
                // forever instead of advancing to a peer.
                if let (Some(pool), Some(addr)) = (server_pool.as_ref(), active_server_addr) {
                    if client.ever_connected() {
                        pool.report_success(addr);
                        let rtt = client.last_rtt_ms();
                        if rtt > 0 {
                            pool.update_rtt(addr, rtt as f64);
                        }
                    } else {
                        pool.report_failure(addr);
                    }
                }

                if feedback_share_enabled {
                    if client.ever_connected() {
                        consecutive_fails.remove(&attempt_mask_family);
                    } else {
                        let mut log = MaskFeedbackLog::load_default();
                        let threshold = log.failure_threshold().max(1);
                        let count = consecutive_fails
                            .entry(attempt_mask_family.clone())
                            .or_insert(0);
                        *count = count.saturating_add(1);
                        if *count >= threshold {
                            log.append(attempt_mask_family.clone(), false);
                            info!(
                                "§2 recorded mask FAILURE for family '{}' ({} consecutive failed attempts)",
                                attempt_mask_family, count
                            );
                            *count = 0;
                        }
                    }
                }

                match run_result {
                    Ok(()) => {
                        // Clean shutdown — deactivate kill-switch before exiting
                        client.deactivate_kill_switch();
                        break;
                    }
                    Err(e) => {
                        // 3f: an authenticated HandshakeReject is a terminal,
                        // PSK-proven refusal (one-time key already used /
                        // expired / disabled) — retrying would only hammer
                        // the server with a request it will refuse forever.
                        // Stop the reconnect loop instead of backing off and
                        // trying again, mirroring the clean-shutdown Ok(())
                        // arm above (kill-switch deactivated, process exits).
                        if client.terminal_rejected() {
                            error!(
                                "Handshake rejected by server: {} — not retrying",
                                handshake_reject_message(client.reject_reason())
                            );
                            client.deactivate_kill_switch();
                            break;
                        }
                        // A connection that stayed up beyond the healthy threshold is
                        // treated as a genuinely established session, so its backoff
                        // resets to the initial value. Without this, a transient drop
                        // after hours of healthy uptime would inherit the grown backoff
                        // from earlier failures (up to max_backoff) and stall the first
                        // reconnect attempt for up to a full minute.
                        let uptime = connect_started.elapsed();
                        if should_reset_backoff(uptime) {
                            backoff = INITIAL_BACKOFF;
                        }
                        warn!(
                            "Client run failed after {}s: {}. Reconnecting in {}s",
                            uptime.as_secs(),
                            e,
                            backoff.as_secs()
                        );
                    }
                }
            }
            Err(e) => {
                error!(
                    "Failed to create client: {}. Reconnecting in {}s",
                    e,
                    backoff.as_secs()
                );
            }
        }

        if shutdown.load(Ordering::SeqCst) {
            info!("Shutdown requested after failure");
            break;
        }

        tokio::time::sleep(backoff).await;
        backoff = std::cmp::min(backoff * 2, max_backoff);
    }
}

/// Parse an `aivpn://` connection key and return the decoded JSON value.
///
/// Accepts both the full `aivpn://...` URI form and a bare base64url payload.
/// Returns an error string on any parse failure so callers can surface a
/// human-readable message without calling `std::process::exit`.
fn parse_connection_key(conn_key: &str) -> Result<serde_json::Value, String> {
    let payload = conn_key
        .trim()
        .strip_prefix("aivpn://")
        .unwrap_or(conn_key.trim());
    let json_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| format!("Invalid connection key base64: {}", e))?;
    serde_json::from_slice(&json_bytes).map_err(|e| format!("Malformed connection key JSON: {}", e))
}

/// §2 L3 — minimum server-reported success score for a regional hint to be
/// allowed to bias initial mask selection. Below this the bootstrap-selected
/// mask is kept, so a weak/noisy hint never displaces the default choice.
const HINT_BIAS_MIN_SCORE: f32 = 0.5;

/// Initial reconnect backoff, also the value a healthy session resets to.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
/// Upper bound on the reconnect backoff.
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// A session that stayed connected at least this long is considered healthy;
/// its reconnect backoff resets to `INITIAL_BACKOFF` instead of continuing to
/// grow. The threshold comfortably exceeds normal handshake time so that only
/// genuinely established sessions (well past connect) trigger a reset.
const HEALTHY_CONNECTION_THRESHOLD: Duration = Duration::from_secs(30);

/// Whether a session with the given uptime should reset the reconnect backoff.
fn should_reset_backoff(uptime: Duration) -> bool {
    uptime >= HEALTHY_CONNECTION_THRESHOLD
}

fn fallback_network_config(tun_addr: &str) -> ClientNetworkConfig {
    let client_ip = tun_addr.parse::<Ipv4Addr>().unwrap_or_else(|_| {
        error!("Invalid TUN address '{}': expected IPv4 address", tun_addr);
        std::process::exit(1);
    });

    ClientNetworkConfig {
        client_ip,
        server_vpn_ip: LEGACY_SERVER_VPN_IP,
        prefix_len: 24,
        mtu: DEFAULT_VPN_MTU,
        mdh_len: 20,
        keepalive_secs: None,
        ipv6_address: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid aivpn:// connection key from a JSON object literal.
    fn make_conn_key(json: &str) -> String {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes());
        format!("aivpn://{}", encoded)
    }

    // ── valid key round-trip ──────────────────────────────────────────────────

    #[test]
    fn test_parse_connection_key_valid_full() {
        // A realistic key contains server address (s), server public key (k), and PSK (p).
        let json = r#"{"s":"1.2.3.4:443","k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","p":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#;
        let key = make_conn_key(json);
        let val = parse_connection_key(&key).expect("must parse");
        assert_eq!(val["s"].as_str().unwrap(), "1.2.3.4:443");
        assert!(val["k"].as_str().is_some());
        assert!(val["p"].as_str().is_some());
    }

    #[test]
    fn test_parse_connection_key_bare_payload_without_prefix() {
        // Bare base64url (no "aivpn://" prefix) must also be accepted.
        let json = r#"{"s":"10.0.0.1:1194","k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#;
        let bare = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes());
        let val = parse_connection_key(&bare).expect("must parse bare payload");
        assert_eq!(val["s"].as_str().unwrap(), "10.0.0.1:1194");
    }

    #[test]
    fn test_parse_connection_key_optional_network_config() {
        // The "n" field carries a ClientNetworkConfig block.
        let json = r#"{"s":"1.2.3.4:443","k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","n":{"client_ip":"10.8.0.2","server_vpn_ip":"10.8.0.1","prefix_len":24,"mtu":1400,"mdh_len":20}}"#;
        let key = make_conn_key(json);
        let val = parse_connection_key(&key).expect("must parse");
        assert!(
            val.get("n").is_some(),
            "network config block must survive round-trip"
        );
    }

    #[test]
    fn test_parse_connection_key_with_server_pool() {
        // The "pool" field carries a Vec<ServerEntry>.
        let json = r#"{"s":"node1.example.com:443","k":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","pool":[{"addr":"node2.example.com:443"},{"addr":"node3.example.com:443"}]}"#;
        let key = make_conn_key(json);
        let val = parse_connection_key(&key).expect("must parse");
        let pool = val["pool"].as_array().expect("pool must be an array");
        assert_eq!(pool.len(), 2);
    }

    // ── invalid / malformed keys ──────────────────────────────────────────────

    #[test]
    fn test_parse_connection_key_rejects_invalid_base64() {
        let err = parse_connection_key("aivpn://this is not valid base64!!!");
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("Invalid connection key"));
    }

    #[test]
    fn test_parse_connection_key_rejects_non_json_payload() {
        // Valid base64 but the decoded content is not JSON.
        let bad = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not json");
        let err = parse_connection_key(&format!("aivpn://{}", bad));
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("Malformed connection key"));
    }

    #[test]
    fn test_parse_connection_key_empty_object_is_valid_json() {
        // An empty JSON object parses without error (missing fields are caught
        // later by the caller — that's not the parser's job).
        let key = make_conn_key("{}");
        assert!(parse_connection_key(&key).is_ok());
    }

    // ── fallback_network_config ───────────────────────────────────────────────

    #[test]
    fn test_fallback_network_config_parses_valid_ipv4() {
        let cfg = fallback_network_config("10.0.0.5");
        assert_eq!(cfg.client_ip.to_string(), "10.0.0.5");
        assert_eq!(cfg.prefix_len, 24);
        assert_eq!(cfg.mtu, DEFAULT_VPN_MTU);
        assert_eq!(cfg.mdh_len, 20);
        assert!(cfg.keepalive_secs.is_none());
    }

    // ── decode_base64_key ────────────────────────────────────────────────────

    #[test]
    fn test_should_reset_backoff_healthy_session() {
        // A session that lasted past the healthy threshold resets the backoff.
        assert!(should_reset_backoff(HEALTHY_CONNECTION_THRESHOLD));
        assert!(should_reset_backoff(Duration::from_secs(3600)));
    }

    #[test]
    fn test_should_reset_backoff_short_session() {
        // A session that dropped quickly (e.g. failed handshake) keeps growing
        // the backoff instead of resetting it.
        assert!(!should_reset_backoff(Duration::from_secs(0)));
        assert!(!should_reset_backoff(Duration::from_secs(1)));
        assert!(!should_reset_backoff(
            HEALTHY_CONNECTION_THRESHOLD - Duration::from_millis(1)
        ));
    }

    #[test]
    fn test_decode_base64_key_valid_32_bytes() {
        // 32 zero bytes encoded in standard base64.
        let b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let key = decode_base64_key("test key", &b64);
        assert_eq!(key, [0u8; 32]);
    }
}

/// Which datagram transport this run should open, if configuration names one.
///
/// Deliberately configuration-only: there is no command-line flag and no UI
/// control for this, so the choice cannot be made accidentally and does not
/// have to be represented anywhere a user can see. `AIVPN_TRANSPORT` names the
/// transport; `AIVPN_TRANSPORT_PARAMS` carries base64 parameters that are
/// passed through without being parsed here — what they mean is entirely the
/// business of whichever factory claimed the name.
///
/// `None` — the case in a build that registers nothing — is the direct UDP
/// socket the client has always used.
fn transport_config() -> Option<aivpn_common::transport::TransportConfig> {
    let name = std::env::var("AIVPN_TRANSPORT")
        .ok()
        .filter(|s| !s.trim().is_empty())?;
    let params = std::env::var("AIVPN_TRANSPORT_PARAMS")
        .ok()
        .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
        .unwrap_or_default();
    Some(aivpn_common::transport::TransportConfig::new(
        name.trim(),
        params,
    ))
}

/// The transports this binary can open.
///
/// This function is the extension point: a build that plugs in additional
/// datagram transports registers them here, and nothing else in the client
/// changes — it resolves whatever `transport_config()` asks for against this
/// registry and otherwise knows nothing about what is in it. The default build
/// registers none, so the only path is the direct UDP socket.
fn transport_registry() -> aivpn_common::transport::TransportRegistry {
    #[allow(unused_mut)]
    let mut registry = aivpn_common::transport::TransportRegistry::new();
    registry
}

/// Platform hook that keeps a transport's own sockets out of this tunnel.
///
/// The direct UDP socket does not need one — it is kept out by the host route
/// installed for the server address — so the default build supplies a guard
/// that protects nothing. A transport that opens sockets of its own to
/// addresses this client does not route around needs a real implementation
/// here (SO_MARK on Linux, `VpnService.protect` on Android).
fn platform_socket_guard() -> aivpn_common::transport::SharedGuard {
    aivpn_common::transport::no_socket_guard()
}
