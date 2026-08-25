use std::path::PathBuf;

/// Recording state snapshot parsed from the client's status file.
#[derive(Debug, Clone, Default)]
pub struct RecordingSnapshot {
    pub state: String, // "idle"|"recording"|"stopping"|"analyzing"|"success"|"failed"
    pub service: String,
    pub mask_id: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VpnStatus {
    Disconnected,
    Connecting,
    Connected { vpn_ip: String },
    Error(String),
}

#[derive(Debug, Clone, Default)]
pub struct TrafficStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub quality_score: u8,
    pub server_adaptive_level: u8,
    /// Session epoch (unix ms) stamped by the client's stats writer once per
    /// session (`since:` key). Changes on a silent in-process reconnect, so a
    /// reader can detect a session restart (counters reset together with the
    /// timer). None when the file predates the field (old client binary) or
    /// was a pre-session zero-write.
    pub connected_since: Option<u64>,
}

/// Locate a binary named `name` either next to the currently-running
/// `aivpn-linux` executable (the AppImage/release-tarball layout, where all
/// bundled binaries sit side by side in `usr/bin/`) or on `PATH`.
fn find_sibling_binary(name: &str) -> Result<PathBuf, String> {
    // Resolve ONLY next to the running executable (an absolute, canonicalized
    // path). The PATH fallback was removed deliberately: `aivpn-ip-helper` is
    // copied to a root-owned system path and run as root, and aivpn-client is
    // launched for privileged networking, so accepting a binary from an
    // attacker-writable PATH entry (or a bare relative name) is a
    // binary-planting → privilege-escalation vector. Release layouts always
    // co-locate these binaries next to the GUI.
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate own exe: {e}"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| "own exe has no parent dir".to_string())?;
    let candidate = dir.join(name);
    // Canonicalize so the returned path is absolute and symlink-resolved.
    match candidate.canonicalize() {
        Ok(p) if p.is_file() => Ok(p),
        _ => Err(format!(
            "'{name}' not found next to the aivpn-linux binary ({})",
            candidate.display()
        )),
    }
}

pub fn find_client_binary() -> Result<PathBuf, String> {
    find_sibling_binary("aivpn-client")
}

/// Locate the `aivpn-ip-helper` binary built alongside `aivpn-client` (see
/// the `[[bin]]` entry in `crates/aivpn-client/Cargo.toml`) — used by
/// `ensure_capable_binary` in `app.rs` to install it to its fixed system
/// path (`/usr/local/libexec/aivpn/aivpn-ip-helper`) during the one-time
/// privileged setup.
pub fn find_ip_helper_binary() -> Result<PathBuf, String> {
    find_sibling_binary("aivpn-ip-helper")
}

/// Only trust status files owned by us or by root. Some fallback paths live
/// in world-writable /tmp, where any local user can pre-create the fixed
/// filename and spoof the displayed counters / quality / recording state.
/// The client runs either as our own uid (setcap'd copy) or as root
/// (pkexec / root GUI), and an attacker can't forge root ownership in
/// sticky-bit /tmp, so uid == euid || uid == 0 covers all legitimate writers.
///
/// Opened with O_NOFOLLOW (the final path component must not be a symlink)
/// and ownership is checked with fstat on the open fd, then the content is
/// read from that same fd — so a symlink swapped in /tmp between check and
/// read (TOCTOU) can neither pass the check nor redirect the read.
/// Returns (mtime, content) so callers can rank candidates by freshness
/// using the same fd's stat.
fn read_trusted_stats_file(path: &std::path::Path) -> Option<(std::time::SystemTime, String)> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?; // fstat — same inode as the read below
    if meta.uid() != unsafe { libc::geteuid() } && meta.uid() != 0 {
        return None;
    }
    let mtime = meta.modified().ok()?;
    let mut content = String::new();
    file.read_to_string(&mut content).ok()?;
    Some((mtime, content))
}

pub fn read_traffic_stats() -> TrafficStats {
    let candidates: Vec<PathBuf> = vec![
        dirs::cache_dir()
            .map(|d| d.join("aivpn").join("traffic.stats"))
            .unwrap_or_default(),
        PathBuf::from("/tmp/aivpn-traffic.stats"),
        PathBuf::from("/tmp/traffic.stats"),
    ];
    let mut stats = TrafficStats::default();
    // Rank candidates by mtime (exactly like quality.json below): with a
    // fixed first-parse-wins order, a stale file left at an earlier path by
    // a previous run shadows the live one being updated at a later path.
    let mut traffic_by_freshness: Vec<_> = candidates
        .iter()
        .filter_map(|p| read_trusted_stats_file(p))
        .collect();
    traffic_by_freshness.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, content) in traffic_by_freshness {
        if let Some(s) = parse_traffic_stats(&content) {
            stats.bytes_sent = s.bytes_sent;
            stats.bytes_received = s.bytes_received;
            stats.connected_since = s.connected_since;
            break;
        }
    }
    // The client writes quality.json to /var/run/aivpn/ when it can (root /
    // full-tunnel runs) and only falls back to /tmp when that fails, so the
    // GUI must check both locations or a root-launched client shows quality 0.
    // A previous run may have left a file at the other location — read the
    // freshest one instead of the first that parses.
    let quality_candidates: Vec<PathBuf> = vec![
        dirs::cache_dir()
            .map(|d| d.join("aivpn").join("quality.json"))
            .unwrap_or_default(),
        PathBuf::from("/var/run/aivpn/quality.json"),
        PathBuf::from("/tmp/aivpn-quality.json"),
    ];
    let mut by_freshness: Vec<_> = quality_candidates
        .iter()
        .filter_map(|p| read_trusted_stats_file(p))
        .collect();
    by_freshness.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, content) in by_freshness {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
            stats.quality_score = v.get("quality").and_then(|x| x.as_u64()).unwrap_or(0) as u8;
            stats.server_adaptive_level =
                v.get("adaptive").and_then(|x| x.as_u64()).unwrap_or(0) as u8;
            break;
        }
    }
    stats
}

fn parse_traffic_stats(content: &str) -> Option<TrafficStats> {
    let mut sent = None;
    let mut received = None;
    let mut since = None;
    for part in content.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("sent:") {
            sent = v.trim().parse().ok();
        } else if let Some(v) = part.strip_prefix("received:") {
            received = v.trim().parse().ok();
        } else if let Some(v) = part.strip_prefix("since:") {
            since = v.trim().parse().ok();
        }
    }
    Some(TrafficStats {
        bytes_sent: sent?,
        bytes_received: received?,
        connected_since: since,
        ..Default::default()
    })
}

/// Read the recording status file written by `aivpn-client record status`.
/// Returns None if the file is missing or unparseable.
pub fn read_recording_status() -> Option<RecordingSnapshot> {
    let candidates: Vec<PathBuf> = vec![
        dirs::cache_dir()
            .map(|d| d.join("aivpn").join("recording.status"))
            .unwrap_or_default(),
        PathBuf::from("/tmp/aivpn-recording.status"),
    ];
    for path in &candidates {
        if let Some((_, content)) = read_trusted_stats_file(path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
                return Some(RecordingSnapshot {
                    state: v["state"].as_str().unwrap_or("idle").to_string(),
                    service: v["service"].as_str().unwrap_or("").to_string(),
                    mask_id: v["mask_id"].as_str().map(|s| s.to_string()),
                    message: v["message"].as_str().map(|s| s.to_string()),
                });
            }
        }
    }
    None
}

/// Extract the server address from an `aivpn://` connection key.
/// The JSON payload's "s" field contains the full address (host:port or [IPv6]:port).
/// Returns it verbatim — no naive colon-splitting — so IPv6 like [::1]:443 is preserved.
pub fn extract_server_addr(key: &str) -> Option<String> {
    use base64::Engine;
    let b64 = key.strip_prefix("aivpn://")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(b64))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(b64))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(b64))
        .ok()?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    json["s"].as_str().map(|s| s.to_string())
}

/// Parameters needed to build the `aivpn-client` child process command line,
/// mirrored 1:1 out of `App::subscription`'s worker stream (moved here for
/// parity with the Windows GUI, whose equivalent argv-building lives as a
/// named function/method in this same module rather than inlined in the
/// event loop — see `aivpn-windows/src/vpn_manager.rs::connect`).
pub struct ClientLaunchParams {
    pub full_tunnel: bool,
    pub mtls_cert: Option<String>,
    pub kill_switch: bool,
    pub adaptive_level: u8,
    pub dns_proxy: String,
    pub exclude_routes: Vec<String>,
    pub include_routes: Vec<String>,
    pub socks5_enabled: bool,
    pub socks5_addr: String,
    pub preferred_mask: String,
    pub polymorphic_mask: bool,
    pub share_mask_feedback: bool,
    pub receive_mask_hints: bool,
    pub country_code: String,
    pub bootstrap_cdn_url: String,
    pub bootstrap_telegram_token: String,
    pub bootstrap_telegram_chat: String,
    pub bootstrap_github: String,
    pub server_signing_key: String,
}

/// Build the `aivpn-client` launch command. Pure move of the inline
/// construction previously done directly inside `App::subscription`'s
/// worker stream closure — same flags, same env-vs-argv choices (the
/// connection key and the bootstrap Telegram token go via env, never argv,
/// since `/proc/<pid>/cmdline` is world-readable on Linux), same order.
pub fn build_client_command(
    binary: &std::path::Path,
    key: &str,
    params: &ClientLaunchParams,
) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(binary);
    // Ensure the VPN client is killed if this GUI process exits
    // (e.g. Quit from the tray). Without this, dropping the Child
    // on shutdown leaves aivpn-client orphaned with the tunnel up.
    cmd.kill_on_drop(true);
    // Pass the connection key (which embeds the PSK) via the
    // environment, NOT argv: /proc/<pid>/cmdline is world-readable
    // on Linux, so a CLI arg would expose the PSK to every local
    // user. /proc/<pid>/environ is owner/root-only, and the client
    // reads AIVPN_CONNECTION_KEY then immediately removes it from
    // its own environment. Matches the Windows GUI.
    cmd.env("AIVPN_CONNECTION_KEY", key);
    if params.full_tunnel {
        cmd.arg("--full-tunnel");
    }
    if let Some(ref cert) = params.mtls_cert {
        if !cert.is_empty() {
            cmd.args(["--mtls-cert", cert]);
        }
    }
    if params.kill_switch {
        cmd.arg("--kill-switch");
    }
    if params.adaptive_level > 0 {
        cmd.args(["--adaptive-level", &params.adaptive_level.to_string()]);
    }
    if !params.dns_proxy.is_empty() {
        cmd.args(["--dns-proxy", &params.dns_proxy]);
    }
    for route in &params.exclude_routes {
        cmd.args(["--exclude-routes", route]);
    }
    for route in &params.include_routes {
        cmd.args(["--include-routes", route]);
    }
    if params.socks5_enabled && !params.socks5_addr.is_empty() {
        cmd.args(["--proxy-listen", &params.socks5_addr]);
    }
    let has_concrete_mask = !params.preferred_mask.is_empty() && params.preferred_mask != "auto";
    if params.polymorphic_mask && has_concrete_mask {
        // Polymorphic mode takes precedence: request a per-session
        // unique variant of the chosen base mask instead of the
        // fixed preset.
        cmd.args(["--polymorphic-base", &params.preferred_mask]);
    } else if has_concrete_mask {
        cmd.args(["--preferred-mask", &params.preferred_mask]);
    }
    if params.share_mask_feedback {
        cmd.arg("--share-mask-feedback");
    }
    if params.receive_mask_hints {
        cmd.arg("--receive-mask-hints");
    }
    if !params.country_code.is_empty() {
        cmd.args(["--country-code", &params.country_code]);
    }
    if !params.bootstrap_cdn_url.is_empty() {
        cmd.args(["--bootstrap-cdn-url", &params.bootstrap_cdn_url]);
    }
    if !params.bootstrap_telegram_token.is_empty() {
        // Via env, not argv — the token is a real credential and
        // /proc/<pid>/cmdline is world-readable on Linux.
        cmd.env(
            "AIVPN_BOOTSTRAP_TELEGRAM_TOKEN",
            &params.bootstrap_telegram_token,
        );
    }
    if !params.bootstrap_telegram_chat.is_empty() {
        cmd.args(["--bootstrap-telegram-chat", &params.bootstrap_telegram_chat]);
    }
    if !params.bootstrap_github.is_empty() {
        cmd.args(["--bootstrap-github", &params.bootstrap_github]);
    }
    if !params.server_signing_key.is_empty() {
        cmd.args(["--server-signing-key", &params.server_signing_key]);
    }
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    cmd
}

/// Parse one line of the client's machine-readable stdout status protocol:
/// "AIVPN-STATUS connected <vpn_ip>" / "AIVPN-STATUS reconnecting" /
/// "AIVPN-STATUS disconnected" / "AIVPN-STATUS rejected <reason>". Pure move
/// out of `App::subscription`'s worker stream closure (was a zero-capture
/// local closure there already, so hoisting it out is behavior-identical).
pub fn parse_status_line(l: &str) -> Option<VpnStatus> {
    let mut it = l.trim().strip_prefix("AIVPN-STATUS ")?.split_whitespace();
    match it.next()? {
        "connected" => Some(VpnStatus::Connected {
            vpn_ip: it.next().unwrap_or_default().to_string(),
        }),
        "reconnecting" => Some(VpnStatus::Connecting),
        "disconnected" => Some(VpnStatus::Disconnected),
        // 3f: authenticated terminal handshake refusal —
        // surfaced as an Error status (same red/urgent UI
        // treatment as any other fatal client-side
        // error). Mapped from the client's ASCII token
        // (see handshake_reject_token in client.rs) so
        // this doesn't depend on its English log wording.
        "rejected" => {
            let token = it.next().unwrap_or("unspecified");
            let msg = match token {
                "one_time_used" => "server: one-time key already used",
                "expired" => "server: client expired",
                "disabled" => "server: client disabled",
                _ => "server: connection refused",
            };
            Some(VpnStatus::Error(msg.to_string()))
        }
        _ => None,
    }
}

pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else {
        format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
    }
}
