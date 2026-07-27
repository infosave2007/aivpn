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
