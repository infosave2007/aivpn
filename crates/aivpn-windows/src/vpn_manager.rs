//! VPN Manager — subprocess control for aivpn-client.exe
//!
//! Launches the Rust client binary in the background (no console window),
//! monitors its process state, reads traffic stats and recording status from file.
//!
//! SECURITY NOTE: The device public key (X25519) must NEVER be shown in the UI.
//! Exposing it would allow correlation attacks linking the user's device to VPN sessions.

use base64::Engine as _;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
}

pub struct TrafficStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub quality_score: u8,
    pub server_adaptive_level: u8,
    /// Client's currently-effective VPN IP, from the `ip:` key the client's
    /// stats writer adds to traffic.stats. Unlike the connection key's own
    /// (static, one-time-parsed) `vpn_ip`, this reflects a server-assigned IP
    /// after a pool re-home. `None` before the first stats write with an
    /// `ip:` field arrives, or if that field failed to parse as an IPv4
    /// address (e.g. a torn read of the non-atomic stats write).
    pub vpn_ip: Option<String>,
    /// 3c: true when the client's `fallback:1` key in traffic.stats says
    /// this session is running on the built-in default mask (bootstrap
    /// resilience fallback after repeated dead handshakes) rather than a
    /// normal bootstrap-derived one. Unlike Linux (which also gets the
    /// "AIVPN-STATUS bootstrap-fallback" stdout line), this GUI's child
    /// stdout is piped to `Stdio::null()` (see `connect()`), so the stats
    /// file is the only channel — same reason `vpn_ip` above exists.
    pub fallback: bool,
}

// ── Recording ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum RecordingState {
    Idle,
    Starting(String),
    Recording(String),
    Stopping(String),
    Analyzing(String),
    Success(String, Option<String>), // service, mask_id
    Failed(String, String),          // service, reason
}

#[derive(Debug, Clone)]
pub struct RecordingResult {
    pub succeeded: bool,
    pub details: String,
}

/// Benchmark result parsed from `aivpn-client bench --json` output.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct BenchResult {
    pub latency_p50_ms: f64,
    pub latency_p95_ms: f64,
    pub latency_p99_ms: f64,
    pub packet_loss_pct: f64,
    pub quality_score: u8,
}

/// True for a well-formed mask id. Bounded length, ASCII alphanumerics plus
/// `_ : . -`  — a superset of both the server's own on-disk filename guard
/// (`mask_store::safe_mask_path`: alnum + `_` + `-`) and the macOS helper's
/// `isAcceptableMaskId` (`^[a-z0-9_]{1,64}$`), so it accepts every id either
/// component can legitimately emit while still rejecting anything that could
/// smuggle a second argv token, a shell metacharacter, or a path-traversal
/// sequence: no whitespace, quotes, slashes, backslashes, or control chars.
/// mask_id values are server-sourced (pushed via mask_catalog.json) and reach
/// this process's argv for a connection that may run UAC-elevated
/// (full-tunnel mode) — this is the last line of defense before Command::arg.
pub fn is_acceptable_mask_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id != "."
        && id != ".."
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '.' | '-'))
}

pub struct VpnManager {
    state: ConnectionState,
    child: Option<Child>,
    stats: TrafficStats,
    last_poll: Option<Instant>,
    pub client_binary: PathBuf,
    /// Server address extracted from the connection key at connect time.
    pub server_addr: Option<String>,
    // Recording
    pub recording_state: RecordingState,
    pub can_record_masks: bool,
    pub recording_capability_known: bool,
    pub last_recording_result: Option<RecordingResult>,
    minimum_recording_ts: u64,
    last_recording_poll: Option<Instant>,
    pub last_error: Option<String>,
    recording_refresh_in_flight: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Timestamp when we entered Connected state — used to detect a stalled tunnel
    /// (process alive but Wintun failing in its reconnect loop).
    connected_since: Option<Instant>,
    /// Session epoch (unix ms) from the stats file's `since:` key — stamped by
    /// the client child once per session. A CHANGE here means the child
    /// silently reconnected (new session): counters legitimately reset to
    /// lower values and the displayed uptime must restart with them. None
    /// until a session's first stats write arrives (or with an old-format
    /// client binary that writes no `since`).
    session_since_ms: Option<u64>,
    /// Whether the current session was started with --kill-switch. Used to run
    /// `kill-switch clear` after TerminateProcess so firewall rules don't stay active.
    kill_switch_active: bool,
    /// Windows Job Object handle (stored as usize) created with
    /// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. The client child is assigned to it so the OS
    /// force-terminates the tunnel process if the GUI dies without running Drop (crash,
    /// abort, or Task Manager kill), preventing an orphaned client and a duplicate client
    /// on the next launch. Best-effort: None means fall back to unmanaged child spawning.
    #[cfg(windows)]
    job_handle: Option<usize>,
    /// Per-session child supervision thread (HIGH-2): watches the client PID
    /// from a background thread so a child crash is detected — and the
    /// kill-switch cleared — even while SW_HIDE has paused the egui update
    /// loop (poll_status() only runs inside update()).
    #[cfg(windows)]
    supervisor: Option<SupervisorHandle>,
    /// Wakes the egui event loop (ctx.request_repaint) from background
    /// threads. Set once by the GUI right after startup, before any connect.
    wake_cb: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

/// Shared state between VpnManager (UI thread) and its per-session child
/// supervision thread.
#[cfg(windows)]
struct SupervisorHandle {
    /// Set by the UI thread before an INTENTIONAL kill (disconnect/Drop) so
    /// the supervisor doesn't misread it as a crash.
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// swap(true) before running `kill-switch clear` — whichever side
    /// (supervisor or UI-thread poll) gets there first runs it exactly once.
    cleared_kill_switch: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for VpnManager {
    fn drop(&mut self) {
        // Intentional teardown — stop the supervisor before killing the child
        // so it doesn't treat the kill as a crash.
        #[cfg(windows)]
        if let Some(s) = self.supervisor.as_ref() {
            s.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        if let Some(ref mut c) = self.child {
            let _ = c.kill();
            let _ = c.wait();
        }
        if self.kill_switch_active {
            self.clear_kill_switch_once();
        }
    }
}

impl VpnManager {
    pub fn new() -> Self {
        let client_binary = Self::find_client_binary();
        // MEDIUM-1: a GUI crash skips every kill-switch cleanup path (Drop,
        // disconnect, poll) and leaves the block-all firewall rules active
        // with no process that remembers them — detect that via the marker
        // file the previous session left behind and clear the rules now.
        #[cfg(windows)]
        Self::clear_orphaned_kill_switch(&client_binary);
        Self {
            state: ConnectionState::Disconnected,
            child: None,
            stats: TrafficStats {
                bytes_sent: 0,
                bytes_received: 0,
                quality_score: 0,
                server_adaptive_level: 0,
                // Pre-existing field (`vpn_ip`) was missing from this
                // literal in the working tree before this change — a latent
                // compile error this crate can't be built to catch on a
                // non-Windows host. Filled in here alongside the new
                // `fallback` field (3c) since both are being touched.
                vpn_ip: None,
                fallback: false,
            },
            last_poll: None,
            client_binary,
            server_addr: None,
            recording_state: RecordingState::Idle,
            can_record_masks: false,
            recording_capability_known: false,
            last_recording_result: None,
            minimum_recording_ts: 0,
            last_recording_poll: None,
            last_error: None,
            recording_refresh_in_flight: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                false,
            )),
            connected_since: None,
            session_since_ms: None,
            kill_switch_active: false,
            #[cfg(windows)]
            job_handle: create_kill_on_close_job(),
            #[cfg(windows)]
            supervisor: None,
            wake_cb: None,
        }
    }

    /// Register the callback that wakes the egui event loop
    /// (`ctx.request_repaint()`). Called once by the GUI at startup, before
    /// any connect, so every session's supervision thread can poke the UI.
    pub fn set_wake_callback(&mut self, cb: impl Fn() + Send + Sync + 'static) {
        self.wake_cb = Some(std::sync::Arc::new(cb));
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn stats(&self) -> &TrafficStats {
        &self.stats
    }

    pub fn is_connected(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    pub fn is_busy(&self) -> bool {
        matches!(
            self.state,
            ConnectionState::Connecting | ConnectionState::Disconnecting
        )
    }

    /// Connect using a connection key
    pub fn connect(
        &mut self,
        connection_key: &str,
        full_tunnel: bool,
        proxy_listen: Option<&str>,
        mtls_cert_path: Option<&str>,
        exclude_routes: &[String],
        include_routes: &[String],
        kill_switch: bool,
        adaptive_level: u8,
        dns_proxy: Option<&str>,
        preferred_mask: Option<&str>,
        bootstrap_cdn_url: Option<&str>,
        bootstrap_telegram_token: Option<&str>,
        bootstrap_telegram_chat: Option<&str>,
        bootstrap_github: Option<&str>,
        server_signing_key: Option<&str>,
        polymorphic_base: Option<&str>,
        share_mask_feedback: bool,
        receive_mask_hints: bool,
        country_code: Option<&str>,
        transport: Option<&aivpn_common::transport::TransportConfig>,
    ) -> Result<(), String> {
        if self.child.is_some() {
            return Err("Already running".to_string());
        }

        if !self.client_binary.exists() {
            return Err(format!(
                "Client binary not found: {}",
                self.client_binary.display()
            ));
        }

        // Validate dns_proxy before any state mutations so a bad address doesn't silently
        // wipe last_error and delete stats files when no connection is actually attempted.
        if let Some(addr) = dns_proxy {
            if !addr.is_empty() && addr.parse::<std::net::SocketAddr>().is_err() {
                return Err(format!("Invalid dns-proxy address: {addr}"));
            }
        }

        // HIGH: mask_id is server-sourced — it arrives via the client-written
        // mask_catalog.json (populated from the server's mask catalog push) and
        // the UI only offers ids read straight out of that file. Both
        // preferred_mask and polymorphic_base ultimately flow into this
        // process's argv (`--preferred-mask` / `--polymorphic-base` below), and
        // when full_tunnel is set that argv belongs to a process launched via
        // the UAC-elevated --elevated-connect hop. A hostile/MITM server could
        // otherwise hide an attacker-controlled token behind a benign-looking
        // catalog label and have it land in an elevated child's command line.
        // Reject anything outside a strict charset before it ever reaches
        // Command::arg — mirrors isAcceptableMaskId() in the macOS helper
        // (platforms/macos/aivpn-helper/main.swift), which guards the same
        // data at the same boundary. "auto"/empty are the sentinel values that
        // never reach argv at all (see the branch below), so they're exempt.
        if let Some(mask) = preferred_mask {
            if !mask.is_empty() && mask != "auto" && !is_acceptable_mask_id(mask) {
                return Err(format!("Invalid mask profile id: {mask}"));
            }
        }
        if let Some(base) = polymorphic_base {
            if !base.is_empty() && base != "auto" && !is_acceptable_mask_id(base) {
                return Err(format!("Invalid polymorphic mask base: {base}"));
            }
        }

        self.state = ConnectionState::Connecting;
        self.server_addr = extract_server_addr(connection_key);
        // Reset all per-session state on new connection
        self.last_error = None;
        self.recording_state = RecordingState::Idle;
        self.can_record_masks = false;
        self.recording_capability_known = false;
        self.last_recording_result = None;
        self.minimum_recording_ts = current_timestamp_ms();
        // Delete stale stats files so the first Connected poll reads zeros
        let _ = std::fs::remove_file(Self::stats_file_path());
        let _ = std::fs::remove_file(std::env::temp_dir().join("aivpn-traffic.stats"));
        // LOW-3: aivpn-quality.json is also per-session — a stale one from the
        // previous session would show its quality/FEC badge as current.
        let _ = std::fs::remove_file(std::env::temp_dir().join("aivpn-quality.json"));

        let mut cmd = Command::new(&self.client_binary);
        cmd.env("AIVPN_CONNECTION_KEY", connection_key);
        // An extension may have selected an alternative transport. Pass it
        // neutrally: a name plus a base64 blob the client forwards to the
        // factory unparsed. Absent → direct UDP.
        if let Some(cfg) = transport {
            use base64::Engine as _;
            cmd.env("AIVPN_TRANSPORT", cfg.name());
            cmd.env(
                "AIVPN_TRANSPORT_PARAMS",
                base64::engine::general_purpose::STANDARD.encode(cfg.params()),
            );
        }

        if full_tunnel {
            cmd.arg("--full-tunnel");
        }

        if let Some(addr) = proxy_listen {
            cmd.arg("--proxy-listen").arg(addr);
        }

        if let Some(cert) = mtls_cert_path {
            cmd.arg("--mtls-cert").arg(cert);
        }

        for route in exclude_routes {
            if !route.trim().is_empty() {
                cmd.arg("--exclude-routes").arg(route.trim());
            }
        }

        for route in include_routes {
            if !route.trim().is_empty() {
                cmd.arg("--include-routes").arg(route.trim());
            }
        }

        if kill_switch {
            cmd.arg("--kill-switch");
        }

        if adaptive_level > 0 {
            cmd.arg("--adaptive-level").arg(adaptive_level.to_string());
        }

        if let Some(addr) = dns_proxy {
            if !addr.is_empty() {
                cmd.arg("--dns-proxy").arg(addr);
            }
        }

        // Polymorphic per-session mask variant takes precedence over the plain
        // preferred-mask selection: when a concrete preset is chosen and the
        // polymorphic toggle is on, request a per-session perturbed variant of
        // it instead of the static preset.
        let polymorphic_active = polymorphic_base
            .map(|m| !m.is_empty() && m != "auto")
            .unwrap_or(false);
        if polymorphic_active {
            cmd.arg("--polymorphic-base").arg(polymorphic_base.unwrap());
        } else if let Some(mask) = preferred_mask {
            if !mask.is_empty() && mask != "auto" {
                cmd.arg("--preferred-mask").arg(mask);
            }
        }

        // §2 crowdsourced mask feedback opt-ins
        if share_mask_feedback {
            cmd.arg("--share-mask-feedback");
        }
        if receive_mask_hints {
            cmd.arg("--receive-mask-hints");
        }
        if let Some(cc) = country_code {
            if !cc.is_empty() {
                cmd.arg("--country-code").arg(cc);
            }
        }

        if let Some(url) = bootstrap_cdn_url {
            if !url.is_empty() {
                cmd.arg("--bootstrap-cdn-url").arg(url);
            }
        }

        if let Some(token) = bootstrap_telegram_token {
            if !token.is_empty() {
                // Via env, not argv — the token is a real credential and the
                // command line is visible to other users (Process Explorer /
                // Task Manager "Command line" column). Matches the connection-key.
                cmd.env("AIVPN_BOOTSTRAP_TELEGRAM_TOKEN", token);
            }
        }

        if let Some(chat) = bootstrap_telegram_chat {
            if !chat.is_empty() {
                cmd.arg("--bootstrap-telegram-chat").arg(chat);
            }
        }

        if let Some(repo) = bootstrap_github {
            if !repo.is_empty() {
                cmd.arg("--bootstrap-github").arg(repo);
            }
        }

        if let Some(key) = server_signing_key {
            if !key.is_empty() {
                cmd.arg("--server-signing-key").arg(key);
            }
        }

        // Run from the directory containing the client binary so wintun.dll is found
        // via the default relative path ("wintun.dll") used by the tun crate.
        if let Some(dir) = self.client_binary.parent() {
            if dir != std::path::Path::new("") {
                cmd.current_dir(dir);
            }
        }

        // The client binary writes its log directly to %LOCALAPPDATA%\AIVPN\client.log
        // (tracing_subscriber opened from inside the process). Stderr redirect via
        // Stdio::from(File) is unreliable for MinGW cross-compiled binaries with
        // CREATE_NO_WINDOW — we no longer rely on it.
        cmd.env("RUST_LOG", "info");
        cmd.stderr(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::null());

        // Hide console window on Windows
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        match cmd.spawn() {
            Ok(child) => {
                let child_pid = child.id();
                // Assign the client to the kill-on-close Job Object so it dies with the
                // GUI even on an abnormal exit that skips Drop. Best-effort — on failure
                // the child still runs, just without the crash-cleanup guarantee.
                #[cfg(windows)]
                if let Some(job) = self.job_handle {
                    use std::os::windows::io::AsRawHandle;
                    use winapi::um::jobapi2::AssignProcessToJobObject;
                    let h = child.as_raw_handle();
                    if unsafe { AssignProcessToJobObject(job as _, h as _) } == 0 {
                        gui_log(
                            "job: AssignProcessToJobObject failed; client will not be \
                             auto-killed if the GUI crashes",
                        );
                    }
                }
                self.child = Some(child);
                self.kill_switch_active = kill_switch;
                if kill_switch {
                    // MEDIUM-1: persist a marker (contents: child PID) so a
                    // GUI crash that skips every cleanup path is detected on
                    // the next launch and the orphaned rules cleared. Deleted
                    // whenever `kill-switch clear` is actually spawned.
                    let marker = Self::kill_switch_marker_path();
                    if let Some(dir) = marker.parent() {
                        let _ = std::fs::create_dir_all(dir);
                    }
                    let _ = std::fs::write(&marker, child_pid.to_string());
                }
                #[cfg(windows)]
                self.spawn_child_supervisor(child_pid, kill_switch);
                // Stay in Connecting — poll_status() transitions to Connected once
                // the process survives its first liveness check, preventing the UI
                // from briefly showing Connected before the TUN device is up.
                self.stats.bytes_sent = 0;
                self.stats.bytes_received = 0;
                self.stats.vpn_ip = None;
                self.stats.fallback = false;
                self.session_since_ms = None;
                // Request initial recording status
                self.request_recording_status_refresh();
                Ok(())
            }
            Err(e) => {
                self.state = ConnectionState::Disconnected;
                Err(format!("Failed to start client: {}", e))
            }
        }
    }

    /// Spawn `aivpn-client kill-switch clear` to remove firewall rules left by
    /// TerminateProcess (child.kill() on Windows bypasses the graceful shutdown cleanup path).
    ///
    /// Fire-and-forget: callers (disconnect(), poll_status(), Drop) all run on the egui
    /// render/update thread, so blocking on `.status()` would freeze the whole window for
    /// as long as the child takes — indefinitely if it hangs. `spawn()` is quick and
    /// synchronous, so it also still works from Drop during app exit; dropping the Child
    /// handle detaches the process, which keeps running until the rules are cleared.
    fn run_kill_switch_clear(binary: &std::path::Path) {
        let mut cmd = std::process::Command::new(binary);
        cmd.args(["kill-switch", "clear"]);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        match cmd.spawn() {
            Ok(_) => {
                // Rules are being cleared — the crash-recovery marker no
                // longer applies (kept on spawn failure so the next launch
                // retries via clear_orphaned_kill_switch()).
                let _ = std::fs::remove_file(Self::kill_switch_marker_path());
            }
            Err(e) => gui_log(&format!("kill-switch clear: spawn failed: {e}")),
        }
    }

    /// Run `kill-switch clear` at most once per session: the supervision
    /// thread and the UI-thread paths (disconnect/poll/Drop) race to the
    /// shared `cleared_kill_switch` flag; whoever swaps it first clears.
    fn clear_kill_switch_once(&mut self) {
        #[cfg(windows)]
        let already = self
            .supervisor
            .as_ref()
            .map(|s| {
                s.cleared_kill_switch
                    .swap(true, std::sync::atomic::Ordering::SeqCst)
            })
            .unwrap_or(false);
        #[cfg(not(windows))]
        let already = false;
        if !already {
            Self::run_kill_switch_clear(&self.client_binary);
        }
        self.kill_switch_active = false;
    }

    /// Marker recording that a client session was started with --kill-switch
    /// (contents: the child PID). Deleted whenever `kill-switch clear` is
    /// spawned; its survival across a GUI crash triggers the startup cleanup
    /// in `clear_orphaned_kill_switch()`.
    fn kill_switch_marker_path() -> PathBuf {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("AIVPN")
            .join("kill-switch.active")
    }

    /// Startup recovery (MEDIUM-1): if a previous session's kill-switch
    /// marker survived (GUI crashed with rules active) and its client is no
    /// longer running, clear the rules. Blocking on purpose — a fire-and-
    /// forget clear could race a connect_on_startup session started
    /// milliseconds later and wipe the NEW session's freshly-added rules.
    #[cfg(windows)]
    fn clear_orphaned_kill_switch(binary: &std::path::Path) {
        let marker = Self::kill_switch_marker_path();
        let Ok(content) = std::fs::read_to_string(&marker) else {
            return;
        };
        if let Ok(pid) = content.trim().parse::<u32>() {
            if pid != 0 && process_is_aivpn_client(pid) {
                // A client from a previous session is still alive and owns
                // the rules — leave both it and the marker alone.
                return;
            }
        }
        gui_log("kill-switch: stale marker from a previous session — clearing orphaned rules");
        let mut cmd = Command::new(binary);
        cmd.args(["kill-switch", "clear"]);
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        match cmd.status() {
            Ok(_) => {
                let _ = std::fs::remove_file(&marker);
            }
            Err(e) => gui_log(&format!("kill-switch clear (startup): spawn failed: {e}")),
        }
    }

    /// HIGH-2: per-session supervision thread. poll_status() only runs inside
    /// egui's update(), which SW_HIDE pauses — so while the window is hidden
    /// a client crash would go undetected and, with kill-switch on, leave the
    /// user without internet indefinitely. This thread watches the child PID
    /// independently, clears the kill-switch the moment the child dies, and
    /// pokes the event loop so poll_status() reconciles the UI state.
    #[cfg(windows)]
    fn spawn_child_supervisor(&mut self, pid: u32, kill_switch: bool) {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        // connect() rejects while a child exists, so any previous supervisor
        // is already gone — belt and braces.
        if let Some(prev) = self.supervisor.take() {
            prev.shutdown.store(true, Ordering::SeqCst);
        }
        let shutdown = Arc::new(AtomicBool::new(false));
        let cleared = Arc::new(AtomicBool::new(false));
        self.supervisor = Some(SupervisorHandle {
            shutdown: Arc::clone(&shutdown),
            cleared_kill_switch: Arc::clone(&cleared),
        });
        let binary = self.client_binary.clone();
        let wake = self.wake_cb.clone();
        std::thread::spawn(move || {
            use winapi::shared::winerror::WAIT_TIMEOUT;
            use winapi::um::handleapi::CloseHandle;
            use winapi::um::processthreadsapi::OpenProcess;
            use winapi::um::synchapi::WaitForSingleObject;
            use winapi::um::winbase::WAIT_OBJECT_0;
            use winapi::um::winnt::SYNCHRONIZE;
            let handle = unsafe { OpenProcess(SYNCHRONIZE, 0, pid) };
            if handle.is_null() {
                gui_log(
                    "supervisor: OpenProcess failed — hidden-window crash detection \
                     disabled for this session",
                );
                return;
            }
            loop {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                let r = unsafe { WaitForSingleObject(handle, 1000) };
                if r == WAIT_TIMEOUT {
                    continue;
                }
                if r == WAIT_OBJECT_0 && !shutdown.load(Ordering::SeqCst) {
                    // Child died while the update loop may be paused: clear
                    // the kill-switch NOW (dedup'd against the UI thread via
                    // the shared flag) instead of waiting for the user to
                    // reopen the window, then wake the UI to reconcile.
                    if kill_switch && !cleared.swap(true, Ordering::SeqCst) {
                        gui_log("supervisor: client exited — clearing kill-switch");
                        Self::run_kill_switch_clear(&binary);
                    }
                    if let Some(w) = &wake {
                        w();
                    }
                }
                break;
            }
            unsafe { CloseHandle(handle) };
        });
    }

    /// Disconnect — kill the client process
    pub fn disconnect(&mut self) {
        self.state = ConnectionState::Disconnecting;

        // Intentional kill — signal the supervision thread BEFORE killing so
        // it doesn't misread the exit as a crash and double-handle it.
        #[cfg(windows)]
        if let Some(s) = self.supervisor.as_ref() {
            s.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
        }

        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;

        // child.kill() on Windows calls TerminateProcess which bypasses KillSwitch::deactivate()
        // in the client. Run `kill-switch clear` explicitly so the user is not left without
        // internet access after clicking Disconnect while kill-switch was enabled.
        if self.kill_switch_active {
            self.clear_kill_switch_once();
        }
        #[cfg(windows)]
        {
            self.supervisor = None;
        }

        self.state = ConnectionState::Disconnected;
        self.stats.bytes_sent = 0;
        self.stats.bytes_received = 0;
        self.stats.vpn_ip = None;
        self.stats.fallback = false;
        self.session_since_ms = None;
        self.connected_since = None;
        self.last_error = None;
        // Reset recording
        self.recording_state = RecordingState::Idle;
        self.can_record_masks = false;
        self.recording_capability_known = false;
        self.last_recording_result = None;
        self.minimum_recording_ts = 0;
    }

    /// Run a benchmark against the server using `aivpn-client bench --json`.
    /// Blocks until the bench completes (call from a background thread).
    pub fn run_bench_blocking(binary: &PathBuf, server_addr: &str) -> Option<BenchResult> {
        if server_addr.is_empty() {
            return None;
        }
        let mut cmd = Command::new(binary);
        cmd.args(["bench", "--server", server_addr, "--json"]);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let out = match cmd.output() {
            Ok(o) => o,
            Err(e) => {
                gui_log(&format!("bench: spawn failed: {e}"));
                return None;
            }
        };
        if !out.status.success() {
            gui_log(&format!("bench: exit {}", out.status));
            return None;
        }
        match serde_json::from_slice(&out.stdout) {
            Ok(r) => Some(r),
            Err(e) => {
                gui_log(&format!("bench: JSON parse error: {e}"));
                None
            }
        }
    }

    /// Return the current server address (set when connect() was called).
    pub fn server_addr(&self) -> Option<&str> {
        self.server_addr.as_deref()
    }

    /// Poll process status and read traffic stats
    pub fn poll_status(&mut self) {
        // Only poll every 500ms
        if let Some(last) = self.last_poll {
            if last.elapsed() < std::time::Duration::from_millis(500) {
                return;
            }
        }
        self.last_poll = Some(Instant::now());

        // Check if process is still alive
        if let Some(ref mut child) = self.child {
            match child.try_wait() {
                Ok(Some(status)) => {
                    // All exits seen by poll_status() are unexpected — intentional disconnects
                    // go through disconnect() which kills and waits before returning, so child
                    // is already None by the time poll_status() runs.
                    let detail = Self::read_last_log_line()
                        .map(|l| format!(": {l}"))
                        .unwrap_or_default();
                    if status.success() {
                        self.last_error =
                            Some(format!("Client disconnected unexpectedly{}", detail));
                    } else {
                        self.last_error = Some(format!("Client exited ({}){}", status, detail));
                    }
                    self.child = None;
                    if self.kill_switch_active {
                        self.clear_kill_switch_once();
                    }
                    #[cfg(windows)]
                    if let Some(s) = self.supervisor.take() {
                        s.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                    self.state = ConnectionState::Disconnected;
                    self.connected_since = None;
                    self.stats.bytes_sent = 0;
                    self.stats.bytes_received = 0;
                    self.stats.vpn_ip = None;
                    self.stats.fallback = false;
                    self.session_since_ms = None;
                    return;
                }
                Ok(None) => {
                    // Still running
                    if self.state == ConnectionState::Connecting {
                        self.state = ConnectionState::Connected;
                        self.connected_since = Some(Instant::now());
                    }
                }
                Err(e) => {
                    self.last_error = Some(format!("Connection lost (OS error): {e}"));
                    self.child = None;
                    if self.kill_switch_active {
                        self.clear_kill_switch_once();
                    }
                    #[cfg(windows)]
                    if let Some(s) = self.supervisor.take() {
                        s.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                    self.state = ConnectionState::Disconnected;
                    self.connected_since = None;
                    // LOW-4: mirror the Ok(Some) reset — otherwise stale
                    // counters and a stale session epoch survive into the
                    // next session's display.
                    self.stats.bytes_sent = 0;
                    self.stats.bytes_received = 0;
                    self.stats.vpn_ip = None;
                    self.stats.fallback = false;
                    self.session_since_ms = None;
                    return;
                }
            }
        }

        // Read traffic stats from file
        if self.state == ConnectionState::Connected {
            self.read_traffic_stats();
            self.poll_recording_status();

            // Once traffic is flowing, a previous stall error is no longer relevant.
            if self.stats.bytes_sent > 0 || self.stats.bytes_received > 0 {
                self.last_error = None;
            }

            // If the tunnel has been "Connected" for >2s but traffic is still zero,
            // the client process is alive but stuck in its Wintun reconnect loop.
            // Surface the last log line unconditionally (no keyword filter) so the user
            // sees the real cause (e.g. "WintunCreateAdapter failed: Access Denied")
            // even when the log line doesn't contain "warn"/"error"/"failed".
            if self.last_error.is_none()
                && self.stats.bytes_sent == 0
                && self.stats.bytes_received == 0
            {
                let stalled = self
                    .connected_since
                    .map(|t| t.elapsed().as_secs() >= 2)
                    .unwrap_or(false);
                if stalled {
                    if let Some(line) = Self::read_last_log_line() {
                        self.last_error = Some(line);
                    } else {
                        self.last_error = Some("No tunnel traffic after 2s".to_string());
                    }
                }
            }
        }
    }

    // ── Recording ───────────────────────────────────────────────────────

    /// Start mask recording for a given service name
    pub fn start_recording(&mut self, service_name: &str) {
        let service = service_name.trim().to_string();
        if service.is_empty() {
            return;
        }
        self.minimum_recording_ts = current_timestamp_ms();
        self.last_recording_result = None;
        self.recording_state = RecordingState::Starting(service.clone());

        // Run: aivpn-client record start --service <name>
        self.run_client_subcommand(&["record", "start", "--service", &service]);
    }

    /// Stop current mask recording
    pub fn stop_recording(&mut self) {
        let current_service = match &self.recording_state {
            RecordingState::Recording(s) | RecordingState::Starting(s) => s.clone(),
            _ => return,
        };
        self.minimum_recording_ts = current_timestamp_ms();
        self.recording_state = RecordingState::Stopping(current_service);

        // Run: aivpn-client record stop
        self.run_client_subcommand(&["record", "stop"]);
    }

    /// Clear the result banner
    pub fn clear_recording_result(&mut self) {
        self.last_recording_result = None;
    }

    /// Whether the record button should be disabled
    pub fn recording_button_disabled(&self) -> bool {
        matches!(
            self.recording_state,
            RecordingState::Stopping(_) | RecordingState::Analyzing(_)
        )
    }

    /// Whether we're actively recording or starting
    pub fn is_recording(&self) -> bool {
        matches!(
            self.recording_state,
            RecordingState::Recording(_) | RecordingState::Starting(_)
        )
    }

    /// Run a subcommand via the client binary in the background
    fn run_client_subcommand(&self, args: &[&str]) {
        let binary = self.client_binary.clone();
        let args_owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        std::thread::spawn(move || {
            let mut cmd = Command::new(&binary);
            for arg in &args_owned {
                cmd.arg(arg);
            }
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                cmd.creation_flags(CREATE_NO_WINDOW);
            }
            match cmd.output() {
                Ok(out) if !out.status.success() => {
                    gui_log(&format!(
                        "record subcommand failed (exit {}): {}",
                        out.status,
                        String::from_utf8_lossy(&out.stderr)
                    ));
                }
                Err(e) => {
                    gui_log(&format!("record subcommand spawn error: {e}"));
                }
                _ => {}
            }
        });
    }

    /// Ask the client to refresh the recording status file (at most one subprocess at a time)
    fn request_recording_status_refresh(&self) {
        use std::sync::atomic::Ordering;
        if self
            .recording_refresh_in_flight
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return; // previous refresh still running
        }
        let flag = std::sync::Arc::clone(&self.recording_refresh_in_flight);
        let binary = self.client_binary.clone();
        std::thread::spawn(move || {
            let mut cmd = std::process::Command::new(&binary);
            cmd.args(["record", "status"]);
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                cmd.creation_flags(CREATE_NO_WINDOW);
            }
            let _ = cmd.output();
            flag.store(false, Ordering::Release);
        });
    }

    /// Poll recording status from the status file on disk
    fn poll_recording_status(&mut self) {
        // Only poll every 2 seconds
        if let Some(last) = self.last_recording_poll {
            if last.elapsed() < std::time::Duration::from_secs(2) {
                return;
            }
        }
        self.last_recording_poll = Some(Instant::now());

        if let Some(snapshot) = self.load_recording_status() {
            let applied = self.apply_recording_info(&snapshot);
            if !applied || snapshot.can_record.is_none() {
                self.request_recording_status_refresh();
            }
        } else {
            self.request_recording_status_refresh();
        }
    }

    fn recording_status_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(local_app) = dirs::data_local_dir() {
            paths.push(local_app.join("AIVPN").join("recording.status"));
        }
        paths.push(std::env::temp_dir().join("aivpn-recording.status"));
        paths
    }

    fn load_recording_status(&self) -> Option<RecordingSnapshot> {
        for path in Self::recording_status_paths() {
            if let Ok(data) = std::fs::read(&path) {
                if let Ok(snapshot) = serde_json::from_slice::<RecordingSnapshot>(&data) {
                    return Some(snapshot);
                }
            }
        }
        None
    }

    fn apply_recording_info(&mut self, snapshot: &RecordingSnapshot) -> bool {
        if snapshot.updated_at_ms < self.minimum_recording_ts {
            return false;
        }

        self.minimum_recording_ts = snapshot.updated_at_ms;
        self.recording_capability_known = snapshot.can_record.is_some();
        self.can_record_masks = snapshot.can_record.unwrap_or(false);

        let service = snapshot
            .service
            .clone()
            .unwrap_or_else(|| "mask".to_string());
        match snapshot.state.as_str() {
            "recording" => {
                self.recording_state = RecordingState::Recording(service);
            }
            "stopping" => {
                self.recording_state = RecordingState::Stopping(service);
            }
            "analyzing" => {
                self.recording_state = RecordingState::Analyzing(service);
            }
            "success" => {
                self.recording_state = RecordingState::Success(service, snapshot.mask_id.clone());
                let details = if let Some(ref mask_id) = snapshot.mask_id {
                    format!("Mask saved. ID: {}", mask_id)
                } else {
                    "Mask saved successfully.".to_string()
                };
                self.last_recording_result = Some(RecordingResult {
                    succeeded: true,
                    details,
                });
            }
            "failed" => {
                let reason = snapshot
                    .message
                    .clone()
                    .unwrap_or_else(|| "Recording failed".to_string());
                self.recording_state = RecordingState::Failed(service, reason.clone());
                self.last_recording_result = Some(RecordingResult {
                    succeeded: false,
                    details: reason,
                });
            }
            _ => {
                self.recording_state = RecordingState::Idle;
            }
        }

        true
    }

    // ── Traffic stats ───────────────────────────────────────────────────

    fn read_traffic_stats(&mut self) {
        // Try standard path first, then fallback
        let paths = [
            Self::stats_file_path(),
            std::env::temp_dir().join("aivpn-traffic.stats"),
        ];

        for path in &paths {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Some((sent, recv, since, ip, fallback)) = Self::parse_stats(&content) {
                    // 3c: direct overwrite, no monotonic/plausibility gate —
                    // this is a live boolean flag (like `ip` above), not a
                    // counter; a rare torn-read misfire self-corrects within
                    // one more 500ms poll tick. Absent key (old client
                    // binary, or a not-currently-falling-back session) reads
                    // as `false`.
                    self.stats.fallback = fallback;
                    // Plausibility gate (torn-read hardening, mirrors the
                    // `since` gate below): only accept an `ip` that parses as
                    // IPv4 — a partial/interleaved read of the non-atomic
                    // stats write could otherwise surface truncated garbage.
                    // Never clear a previously-good value on a bad read; the
                    // 4 explicit reset sites (connect/disconnect/exit) own
                    // clearing it back to None.
                    if let Some(ip) = ip.filter(|s| s.parse::<std::net::Ipv4Addr>().is_ok()) {
                        self.stats.vpn_ip = Some(ip);
                    }
                    // Plausibility gate (MEDIUM-2, torn-read hardening): the
                    // client's stats write is not atomic, so a partial read
                    // can yield a truncated/garbage `since` that would fake a
                    // session change — flashing an absurd uptime and
                    // re-arming the stall window. Accept the epoch only if
                    // it is a sane wall-clock value: after ~Sep 2020
                    // (1.6e12 ms) and at most 60 s in the future.
                    let since = since.filter(|&s| {
                        s > 1_600_000_000_000 && s <= current_timestamp_ms().saturating_add(60_000)
                    });
                    match since {
                        Some(s) if self.session_since_ms != Some(s) => {
                            // The `since` epoch appeared or changed: the client
                            // child started a NEW session (silent in-process
                            // reconnect). Accept the lower counters — the old
                            // monotonic guard would freeze the display at the
                            // previous session's totals, masking a dead tunnel
                            // from the 2 s stall heuristic in poll_status().
                            self.session_since_ms = Some(s);
                            self.stats.bytes_sent = sent;
                            self.stats.bytes_received = recv;
                            // Re-arm the stall heuristic: the new session's
                            // counters start at zero, which must not count as
                            // "stalled since the ORIGINAL connect" — give the
                            // fresh tunnel its own 2 s window.
                            if self.state == ConnectionState::Connected {
                                self.connected_since = Some(Instant::now());
                            }
                        }
                        _ => {
                            // Same session — or an old-format file with no
                            // `since` (backward compat): keep the monotonic
                            // guard so a stale/partial read can't jump the
                            // display down.
                            if sent >= self.stats.bytes_sent || self.stats.bytes_sent == 0 {
                                self.stats.bytes_sent = sent;
                            }
                            if recv >= self.stats.bytes_received || self.stats.bytes_received == 0 {
                                self.stats.bytes_received = recv;
                            }
                        }
                    }
                    let (qs, sal) = Self::read_quality_json();
                    self.stats.quality_score = qs;
                    self.stats.server_adaptive_level = sal;
                    return;
                }
            }
        }
    }

    /// Session epoch (unix ms) of the client child's CURRENT session, parsed
    /// from the stats file. The GUI derives displayed uptime from this
    /// (wall-clock now − since) so the timer resets together with the
    /// per-session counters on a silent reconnect.
    pub fn session_since_ms(&self) -> Option<u64> {
        self.session_since_ms
    }

    fn read_quality_json() -> (u8, u8) {
        let path = std::env::temp_dir().join("aivpn-quality.json");
        let content = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (0, 0),
            Err(e) => {
                gui_log(&format!("read_quality_json: {e}"));
                return (0, 0);
            }
        };
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
            let quality = v["quality"].as_u64().unwrap_or(0) as u8;
            let adaptive = v["adaptive"].as_u64().unwrap_or(0) as u8;
            return (quality, adaptive);
        }
        (0, 0)
    }

    fn parse_stats(content: &str) -> Option<(u64, u64, Option<u64>, Option<String>, bool)> {
        // Format: "sent:12345,received:67890[,since:<unix-ms>][,ip:<vpn-ip>][,fallback:0|1]"
        // — `since` is the session epoch, absent in pre-session zero-writes
        // and in files from old client binaries. `ip` is the client's
        // currently-effective VPN IP (HIGH #2, client parity): absent in the
        // same cases as `since`, and re-written on every tick so a pool
        // re-home to a different server-assigned IP shows up here even
        // though the GUI's own child stdout is piped to Stdio::null(). `fallback`
        // (3c) is 1 while this session is running on the built-in default
        // mask (bootstrap resilience fallback); absent/anything-but-"1"
        // reads as not-falling-back — same absent-key backward compat as
        // `since`/`ip`.
        let content = content.trim();
        let mut sent = None;
        let mut recv = None;
        let mut since = None;
        let mut ip = None;
        let mut fallback = false;

        for part in content.split(',') {
            let mut kv = part.splitn(2, ':');
            match (kv.next(), kv.next()) {
                (Some("sent"), Some(v)) => sent = v.trim().parse().ok(),
                (Some("received"), Some(v)) => recv = v.trim().parse().ok(),
                (Some("since"), Some(v)) => since = v.trim().parse().ok(),
                (Some("ip"), Some(v)) => ip = Some(v.trim().to_string()),
                (Some("fallback"), Some(v)) => fallback = v.trim() == "1",
                _ => {}
            }
        }

        match (sent, recv) {
            (Some(s), Some(r)) => Some((s, r, since, ip, fallback)),
            _ => None,
        }
    }

    fn client_log_path() -> PathBuf {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("AIVPN")
            .join("client.log")
    }

    /// Read the last non-empty line of the client log (for error surfacing).
    fn read_last_log_line() -> Option<String> {
        use std::io::{Read, Seek, SeekFrom};
        const TAIL: u64 = 65536;
        let mut f = std::fs::File::open(Self::client_log_path()).ok()?;
        let len = f.seek(SeekFrom::End(0)).ok()?;
        f.seek(SeekFrom::Start(len.saturating_sub(TAIL))).ok()?;
        let mut buf = String::new();
        f.read_to_string(&mut buf).ok()?;
        buf.lines()
            .filter(|l| !l.trim().is_empty())
            .last()
            .map(|l| l.trim().to_string())
    }

    fn stats_file_path() -> PathBuf {
        if cfg!(windows) {
            dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("AIVPN")
                .join("traffic.stats")
        } else {
            PathBuf::from("/var/run/aivpn/traffic.stats")
        }
    }

    fn find_client_binary() -> PathBuf {
        // 1. Next to this executable
        if let Ok(exe) = std::env::current_exe() {
            let dir = exe.parent().unwrap_or(std::path::Path::new("."));
            let candidate = dir.join("aivpn-client.exe");
            if candidate.exists() {
                return candidate;
            }
            // Also check without .exe for non-windows dev
            let candidate = dir.join("aivpn-client");
            if candidate.exists() {
                return candidate;
            }
        }

        // 2. Program Files
        if cfg!(windows) {
            let pf = PathBuf::from(r"C:\Program Files\AIVPN\aivpn-client.exe");
            if pf.exists() {
                return pf;
            }
        }

        // 3. Fallback — a TRUSTED ABSOLUTE path, never a bare relative name.
        // The GUI runs elevated (requireAdministrator manifest); returning
        // "aivpn-client.exe" would let Windows search the current directory and
        // PATH, so an attacker-planted binary in an writable CWD/PATH entry
        // would run as admin (binary planting → EoP). An absolute path that
        // doesn't exist simply fails to spawn — safe.
        if cfg!(windows) {
            PathBuf::from(r"C:\Program Files\AIVPN\aivpn-client.exe")
        } else {
            // Dev/non-windows: resolve next to our own exe, absolute, or a
            // clearly-invalid absolute path (never a bare relative name).
            std::env::current_exe()
                .ok()
                .and_then(|e| e.parent().map(|d| d.join("aivpn-client")))
                .unwrap_or_else(|| PathBuf::from("/nonexistent/aivpn-client"))
        }
    }
}

// ── Recording status file format (matches aivpn-client record_cmd.rs) ───

#[derive(Debug, serde::Deserialize)]
struct RecordingSnapshot {
    can_record: Option<bool>,
    state: String,
    service: Option<String>,
    message: Option<String>,
    mask_id: Option<String>,
    #[allow(dead_code)]
    confidence: Option<f32>,
    updated_at_ms: u64,
}

/// Extract the server address from an `aivpn://` connection key.
/// Connection key format: `aivpn://` + base64url(JSON) where JSON["s"] = "host:port".
fn extract_server_addr(key: &str) -> Option<String> {
    let b64 = key.strip_prefix("aivpn://")?;
    // Try multiple Base64 formats just in case padding or standard charset is used
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(b64))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(b64))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(b64))
        .ok()?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    json["s"].as_str().map(|s| s.to_string())
}

/// Create a Windows Job Object configured to terminate all assigned processes when the
/// job handle closes. The GUI process holds this handle for its whole lifetime, so if it
/// exits for any reason (including a crash that skips Drop) the OS closes the handle and
/// kills the assigned client. Returns None on any failure (caller falls back gracefully).
#[cfg(windows)]
fn create_kill_on_close_job() -> Option<usize> {
    use std::{mem, ptr};
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::jobapi2::{CreateJobObjectW, SetInformationJobObject};
    use winapi::um::winnt::{
        JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    unsafe {
        let job = CreateJobObjectW(ptr::null_mut(), ptr::null());
        if job.is_null() {
            return None;
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = mem::zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ok = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &mut info as *mut _ as *mut _,
            mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        if ok == 0 {
            CloseHandle(job);
            return None;
        }
        Some(job as usize)
    }
}

/// Whether `pid` is a live process whose image is aivpn-client.exe. Used by
/// the MEDIUM-1 startup recovery to distinguish "previous session's client
/// still running" from "stale marker after a crash" (a bare liveness check
/// would false-positive on PID reuse and strand the user behind orphaned
/// block-all rules).
#[cfg(windows)]
fn process_is_aivpn_client(pid: u32) -> bool {
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::winbase::QueryFullProcessImageNameW;
    use winapi::um::winnt::PROCESS_QUERY_LIMITED_INFORMATION;
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        if ok == 0 {
            return false;
        }
        String::from_utf16_lossy(&buf[..len as usize])
            .to_ascii_lowercase()
            .ends_with("aivpn-client.exe")
    }
}

/// Log a GUI-side diagnostic line (LOW-5). `eprintln!` alone is invisible
/// under `windows_subsystem = "windows"` (there is no console), so every
/// message is also appended to %LOCALAPPDATA%\AIVPN\gui.log where it can
/// actually be read. Truncates the log when it grows past ~1 MB.
pub fn gui_log(msg: &str) {
    eprintln!("{msg}");
    if let Some(dir) = dirs::data_local_dir() {
        use std::io::Write;
        let dir = dir.join("AIVPN");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("gui.log");
        let too_big = std::fs::metadata(&path)
            .map(|m| m.len() > 1_000_000)
            .unwrap_or(false);
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true);
        if too_big {
            opts.write(true).truncate(true);
        } else {
            opts.append(true);
        }
        if let Ok(mut f) = opts.open(&path) {
            let _ = writeln!(f, "{msg}");
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

/// Format byte count for display
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
