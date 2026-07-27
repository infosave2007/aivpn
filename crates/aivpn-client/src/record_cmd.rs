//! Recording CLI Commands — Client-side recording controls
//!
//! Handles `aivpn record start/stop/status` and `aivpn masks list/delete/retrain`
//! by sending appropriate ControlPayload messages to the server.

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Returns platform-appropriate paths for recording status files.
pub fn recording_status_paths() -> Vec<std::path::PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let mut paths = Vec::new();
        if let Some(local_app) = std::env::var_os("LOCALAPPDATA") {
            let dir = std::path::PathBuf::from(local_app).join("AIVPN");
            let _ = std::fs::create_dir_all(&dir);
            paths.push(dir.join("recording.status"));
        }
        paths.push(std::env::temp_dir().join("aivpn-recording.status"));
        paths
    }
    #[cfg(not(target_os = "windows"))]
    {
        vec![
            std::path::PathBuf::from("/var/run/aivpn/recording.status"),
            std::path::PathBuf::from("/tmp/aivpn-recording.status"),
        ]
    }
}

/// Per-user path for the local admin-socket auth token. The admin UDP socket
/// (127.0.0.1:44301) accepts recording start/stop/status commands from any
/// local process; on a shared/multi-user host that meant any other local
/// user could start, stop, or read another user's recording session. The
/// token scopes commands to whoever can read this 0600 file — i.e. the same
/// OS user the daemon is running as.
fn admin_token_path() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Some(local_app) = std::env::var_os("LOCALAPPDATA") {
            return std::path::PathBuf::from(local_app)
                .join("AIVPN")
                .join("admin.token");
        }
        std::env::temp_dir().join("aivpn-admin.token")
    }
    #[cfg(not(target_os = "windows"))]
    {
        #[cfg(unix)]
        let uid = unsafe { libc::getuid() };
        #[cfg(not(unix))]
        let uid = 0u32;
        // Prefer XDG_RUNTIME_DIR (tmpfs, mode 0700, per-user, auto-cleaned on
        // logout) over the world-writable /tmp namespace, which invites
        // symlink/pre-create attacks on a predictable shared path.
        if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
            return std::path::PathBuf::from(runtime_dir)
                .join("aivpn")
                .join("admin.token");
        }
        // Per-uid SUBDIRECTORY under /tmp, never a bare file in /tmp:
        // ensure_admin_token() chmods the token's PARENT to 0700, so the parent
        // must be our own `/tmp/aivpn-{uid}` dir. A bare `/tmp/aivpn-admin-{uid}.token`
        // makes the parent `/tmp` itself and flips /tmp to 0700, breaking the
        // whole system's temp dir (this process usually runs as root for TUN).
        std::path::PathBuf::from(format!("/tmp/aivpn-{uid}")).join("admin.token")
    }
}

/// Generate a fresh admin-socket auth token and persist it for this run.
/// Called once by the daemon at startup; invalidates any token from a prior
/// run (each connection gets its own).
pub fn ensure_admin_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let token: String = (0..32)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect();

    let path = admin_token_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    // Best-effort unlink of any prior file (ours from a previous run, or an
    // attacker's pre-created symlink/file) before creating fresh with O_EXCL
    // so the permission window never opens and symlinks aren't followed.
    let _ = std::fs::remove_file(&path);
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut f| f.write_all(token.as_bytes()))
        {
            Ok(()) => {}
            Err(e) => warn!("Failed to write admin token to {}: {e}", path.display()),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::write(&path, &token);
    }
    token
}

/// Read the admin-socket auth token written by the running daemon. Used by
/// `aivpn-client record start/stop/status` before sending a command.
pub fn read_admin_token() -> Option<String> {
    std::fs::read_to_string(admin_token_path())
        .ok()
        .map(|s| s.trim().to_string())
}

/// Constant-time token comparison to avoid leaking match-length via timing.
/// Always walks a fixed-size window regardless of input length, instead of
/// early-returning on a length mismatch, so the comparison takes the same
/// time whether the candidate is the right length or not.
pub fn tokens_match(a: &str, b: &str) -> bool {
    const WINDOW: usize = 64; // generous over our fixed 32-char token length
    let a = a.as_bytes();
    let b = b.as_bytes();
    let mut diff = (a.len() != b.len()) as u8;
    for i in 0..WINDOW {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingLocalStatus {
    pub can_record: Option<bool>,
    pub state: String,
    pub service: Option<String>,
    pub message: Option<String>,
    pub mask_id: Option<String>,
    pub confidence: Option<f32>,
    pub updated_at_ms: u64,
}

impl Default for RecordingLocalStatus {
    fn default() -> Self {
        Self {
            can_record: None,
            state: "idle".into(),
            service: None,
            message: Some("Recording access not checked yet".into()),
            mask_id: None,
            confidence: None,
            updated_at_ms: current_timestamp_ms(),
        }
    }
}

fn current_timestamp_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn write_status(status: &RecordingLocalStatus) {
    if let Ok(json) = serde_json::to_vec(status) {
        for path in recording_status_paths() {
            // Atomic temp+rename (not plain std::fs::write, which
            // open+truncate+writes in place) so a CLI `record status` poll
            // landing mid-write never sees a 0-byte/partial file — and
            // O_NOFOLLOW/create_new-hardened, since this can fall back to a
            // predictable world-writable /tmp path (see secure_write.rs).
            crate::secure_write::write_status_best_effort(&path, &json);
        }
    }
}

pub fn reset_local_status() {
    write_status(&RecordingLocalStatus::default());
}

pub fn read_local_status() -> Option<RecordingLocalStatus> {
    recording_status_paths().iter().find_map(|path| {
        let data = std::fs::read(path).ok()?;
        serde_json::from_slice::<RecordingLocalStatus>(&data).ok()
    })
}

pub fn print_local_status(status: &RecordingLocalStatus) {
    let headline = match status.state.as_str() {
        "recording" => "Recording is active",
        "stopping" => "Recording stop requested",
        "analyzing" => "Server is analyzing the recording",
        "success" => "Mask recorded successfully",
        "failed" => "Recording failed",
        _ => {
            if status.can_record == Some(true) {
                "Recording is available"
            } else if status.can_record == Some(false) {
                "Current key cannot record masks"
            } else {
                "Recording status is not available yet"
            }
        }
    };

    println!("{}", headline);
    if let Some(service) = &status.service {
        println!("Service: {}", service);
    }
    if let Some(mask_id) = &status.mask_id {
        println!("Mask ID: {}", mask_id);
    }
    if let Some(confidence) = status.confidence {
        println!("Confidence: {:.2}", confidence);
    }
    if let Some(message) = &status.message {
        println!("Status: {}", message);
    }
}

pub fn handle_recording_status(can_record: bool, active_service: Option<&str>) {
    let message = if can_record {
        if let Some(service) = active_service {
            format!("Recording is active for '{}'", service)
        } else {
            "Recording is available for this key".to_string()
        }
    } else {
        "This key is not allowed to record masks".to_string()
    };
    write_status(&RecordingLocalStatus {
        can_record: Some(can_record),
        state: if active_service.is_some() {
            "recording".into()
        } else {
            "idle".into()
        },
        service: active_service.map(|value| value.to_string()),
        message: Some(message),
        mask_id: None,
        confidence: None,
        updated_at_ms: current_timestamp_ms(),
    });
}

pub fn mark_recording_stop_requested(service: Option<&str>) {
    write_status(&RecordingLocalStatus {
        can_record: Some(true),
        state: "stopping".into(),
        service: service.map(|value| value.to_string()),
        message: Some("Recording stop requested".into()),
        mask_id: None,
        confidence: None,
        updated_at_ms: current_timestamp_ms(),
    });
}

/// Display recording acknowledgment from server
pub fn handle_recording_ack(session_id: &[u8; 16], status: &str) {
    let sid_hex = session_id
        .iter()
        .take(4)
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    match status {
        "started" => {
            info!("📹 Recording started (session: {}...)", sid_hex);
            write_status(&RecordingLocalStatus {
                can_record: Some(true),
                state: "recording".into(),
                service: read_local_status().and_then(|status| status.service),
                message: Some("Recording started. Use the service normally.".into()),
                mask_id: None,
                confidence: None,
                updated_at_ms: current_timestamp_ms(),
            });
            println!("Recording started. Use the service normally.");
            println!("No manual stop needed — recording will finish automatically.");
            println!("It will analyze the capture once enough traffic is collected or the session goes idle.");
        }
        "analyzing" => {
            info!("🔍 Recording finished, server analyzing...");
            let service = read_local_status().and_then(|status| status.service);
            write_status(&RecordingLocalStatus {
                can_record: Some(true),
                state: "analyzing".into(),
                service,
                message: Some("Recording finished. Server is analyzing traffic.".into()),
                mask_id: None,
                confidence: None,
                updated_at_ms: current_timestamp_ms(),
            });
            println!("Recording finished. Server is analyzing traffic...");
        }
        other => {
            info!("Recording status: {}", other);
            println!("Recording status: {}", other);
        }
    }
}

/// Display recording completion
pub fn handle_recording_complete(service: &str, mask_id: &str, confidence: f32) {
    info!("✅ Mask generated for '{}'", service);
    write_status(&RecordingLocalStatus {
        can_record: Some(true),
        state: "success".into(),
        service: Some(service.to_string()),
        message: Some("Mask generated and tested".into()),
        mask_id: Some(mask_id.to_string()),
        confidence: Some(confidence),
        updated_at_ms: current_timestamp_ms(),
    });
    println!();
    println!("✅ Mask generated and tested!");
    println!();
    println!("   Mask ID:     {}", mask_id);
    println!("   Service:     {}", service);
    println!("   Confidence:  {:.2}", confidence);
    println!();
    println!("   Broadcasting to all clients...");
}

/// Display recording failure
pub fn handle_recording_failed(reason: &str) {
    info!("❌ Recording failed: {}", reason);
    let can_record = if reason.to_lowercase().contains("recording-admin") {
        Some(false)
    } else {
        read_local_status().and_then(|status| status.can_record)
    };
    write_status(&RecordingLocalStatus {
        can_record,
        state: "failed".into(),
        service: read_local_status().and_then(|status| status.service),
        message: Some(reason.to_string()),
        mask_id: None,
        confidence: None,
        updated_at_ms: current_timestamp_ms(),
    });
    println!();
    println!("❌ Recording failed!");
    println!("   Reason: {}", reason);
    println!();
    println!("   Tips:");
    println!("   - Use the service for at least 1 minute");
    println!("   - Ensure active traffic (not idle)");
    println!("   - Need at least 500 packets captured");
}
