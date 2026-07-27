#![cfg_attr(windows, windows_subsystem = "windows")]

mod admin;
#[cfg(windows)]
mod admin_ops;
#[cfg(windows)]
mod app_update;
#[cfg(windows)]
mod assets;
mod install_wizard;
mod key_storage;
mod localization;
#[cfg(windows)]
mod platform_win;
#[cfg(windows)]
mod views;
mod vpn_manager;

#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
fn main() {
    use eframe::egui;
    use localization::AppSettings;

    // LOW-2: single-instance guard. The --elevated-connect hop must ignore
    // the "already running" answer — its non-elevated parent is still alive
    // for a moment during the handoff — but it still claims a mutex handle so
    // the guard stays armed after the parent exits.
    let is_elevated_hop = std::env::args().any(|a| a == "--elevated-connect");
    if claim_single_instance_mutex() && !is_elevated_hop {
        focus_existing_instance();
        return;
    }

    let settings = AppSettings::load();
    let dark = settings.dark_mode;

    let vp = egui::ViewportBuilder::default()
        .with_title("AIVPN")
        .with_inner_size([380.0, 560.0])
        .with_min_inner_size([340.0, 420.0])
        .with_resizable(true)
        .with_icon(app_icon());

    let options = eframe::NativeOptions {
        viewport: vp,
        ..Default::default()
    };

    // Write startup marker before run_native so panics inside it also leave a trace
    let startup_log = dirs::data_local_dir().map(|d| d.join("AIVPN").join("startup.log"));
    if let Some(ref p) = startup_log {
        let _ = std::fs::create_dir_all(p.parent().unwrap_or(p));
        let _ = std::fs::write(p, "=== AIVPN starting ===\n");
    }

    if let Err(e) = eframe::run_native(
        "AIVPN",
        options,
        Box::new(move |cc| {
            let ctx = &cc.egui_ctx;
            let mut fonts = egui::FontDefinitions::default();
            fonts.font_data.insert(
                "Inter".to_owned(),
                egui::FontData::from_static(include_bytes!("../assets/Inter-Regular.ttf")).into(),
            );
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .insert(0, "Inter".to_owned());
            ctx.set_fonts(fonts);
            apply_theme_to_ctx(ctx, dark);
            let mut app = AivpnApp::new(settings, ctx);
            app.init_tray();
            if app.settings.connect_on_startup {
                // HIGH-1: must NOT be do_connect() — that toggles, and on an
                // --elevated-connect hop new() has already started the
                // connection, so a toggle here would immediately tear it down.
                app.startup_auto_connect();
            }
            Ok(Box::new(app))
        }),
    ) {
        if let Some(p) = startup_log {
            let _ = std::fs::write(p, format!("startup error: {e}\n"));
        }
    }
}

// ── Tray handles ───────────────────────────────────────────────────────────

#[cfg(windows)]
struct TrayHandles {
    _icon: tray_icon::TrayIcon,
    connect_item: tray_icon::menu::MenuItem,
    show_item: tray_icon::menu::MenuItem,
    quit_item: tray_icon::menu::MenuItem,
}

// ── App struct ─────────────────────────────────────────────────────────────

#[cfg(windows)]
use admin::{AdminRequest, AdminResponse};
#[cfg(windows)]
use assets::{app_icon, apply_theme_to_ctx, make_tray_icon};
#[cfg(windows)]
use key_storage::KeyStorage;
#[cfg(windows)]
use localization::{t, AppSettings, Lang};
#[cfg(windows)]
use platform_win::{
    bring_window_to_front, claim_single_instance_mutex, focus_existing_instance, is_elevated,
    relaunch_elevated,
};
#[cfg(windows)]
use std::time::Instant;
#[cfg(windows)]
use vpn_manager::{
    format_bytes, gui_log, BenchResult, ConnectionState, RecordingState, VpnManager,
};

#[cfg(windows)]
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// G-A3: mirrors the server's `pending_config::PENDING_CONFIG_TIMEOUT`
/// (~120s) — duplicated client-side purely for the UI's own countdown
/// display. This clock is cosmetic-only: the server's own sweep task is
/// what actually rolls a change back, on its own clock, regardless of
/// what this local countdown shows (a client/server clock skew or a
/// delayed frame only affects when the LOCAL banner disappears).
#[cfg(windows)]
const ADMIN_SETTINGS_CONFIRM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

#[cfg(windows)]
struct AivpnApp {
    settings: AppSettings,
    vpn: VpnManager,
    keys: KeyStorage,

    connected_since: Option<Instant>,
    last_conn_state: ConnectionState,

    error_msg: Option<String>,
    error_at: Option<Instant>,
    dirty_at: Option<Instant>,

    // Add/Edit dialog
    show_dialog: bool,
    editing_idx: Option<usize>,
    dlg_name: String,
    dlg_key: String,
    dlg_full_tunnel: bool,
    dlg_proxy: bool,
    dlg_proxy_addr: String,
    dlg_error: Option<String>,
    dlg_exclude_routes: String,
    dlg_include_routes: String,
    dlg_mtls_cert: String,

    // Diagnostics / benchmark
    bench_result: Option<BenchResult>,
    bench_running: bool,
    bench_rx: Option<std::sync::mpsc::Receiver<Option<BenchResult>>>,

    recording_service: String,

    window_visible: bool,
    quitting: bool,
    /// True when this instance was launched via --elevated-connect (the
    /// self-relaunch-elevated hop): new() already started the connection, so
    /// the connect_on_startup hook must not fire on top of it (HIGH-1).
    elevated_connect_hop: bool,
    tray_connected: Option<bool>,
    tray: Option<TrayHandles>,
    tray_show_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    quit_requested: std::sync::Arc<std::sync::atomic::AtomicBool>,
    connect_requested: std::sync::Arc<std::sync::atomic::AtomicBool>,
    tray_thread_shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,

    // ── Admin panel (P3.4) — in-tunnel client management ────────────────
    admin_tx: std::sync::mpsc::Sender<AdminResponse>,
    admin_rx: std::sync::mpsc::Receiver<AdminResponse>,
    /// Server-assigned role cached for the CURRENT session (0/1/2). `None`
    /// until the `role` query answers; the panel only ever shows once this
    /// is `Some(1)` (Viewer) or `Some(2)` (Admin) — fails closed (never
    /// shown) on a query error or plain `User` role.
    ///
    /// G-A1: Viewer and Admin now reach the SAME panel — every subsection
    /// (clients/pool/audit) is visible to both; `draw_admin_clients_section`
    /// takes a `can_mutate` flag (`admin_role == Some(2)`) that hides every
    /// mutating control (add/edit/enable-disable/reset-device/revoke) for
    /// a Viewer, leaving only reads the server's `authorize()` already
    /// permits that role (every curated route is GET-only for Viewer).
    admin_role: Option<u8>,
    admin_clients_loaded: bool,
    admin_clients: Vec<admin::AdminClient>,
    admin_clients_loading: bool,
    admin_clients_error: Option<String>,
    /// Client ids with an operation (delete/revoke/reset-device) in flight —
    /// disables that row's buttons so a slow ~5s mgmt round-trip can't be
    /// double-clicked into two concurrent operations on the same client.
    admin_busy_ids: std::collections::HashSet<String>,
    admin_status: Option<admin::AdminStatus>,
    // ── G-A2: audit-log panel (Viewer + Admin, GET-only) ────────────────
    admin_audit_loaded: bool,
    admin_audit: Vec<admin::AuditEntry>,
    /// Hash-chain verification result for `admin_audit` (from the server's
    /// `?verify=1` response) — `None` until the first load, or if the
    /// server answered with the plain bare-array shape (see
    /// `admin::parse_audit_log`'s doc comment).
    admin_audit_verified: Option<bool>,
    /// Tail-window index (0-based, oldest-first) of the first broken link,
    /// present only when `admin_audit_verified == Some(false)`.
    admin_audit_broken_at: Option<usize>,
    admin_audit_loading: bool,
    admin_audit_error: Option<String>,

    admin_show_add: bool,
    admin_add_name: String,
    admin_add_one_time: bool,
    admin_add_expiry: String,
    /// B3: `host:port`, empty = use the server's global default.
    admin_add_exit_node: String,
    /// G-B1: `true` once the user has explicitly picked "custom" in the
    /// exit-node `ComboBox` — keeps the free-text box shown even if the
    /// typed value happens to match "(default)" or a known pool-node
    /// address (`admin::classify_exit_node` would otherwise reclassify it
    /// away from Custom on the very next frame).
    admin_add_exit_custom_mode: bool,
    admin_add_error: Option<String>,
    admin_add_busy: bool,

    admin_edit_id: Option<String>,
    admin_edit_name: String,
    admin_edit_enabled: bool,
    admin_edit_expiry: String,
    /// B3: `host:port`, empty = clear the per-client override.
    admin_edit_exit_node: String,
    /// G-B1: same rationale as `admin_add_exit_custom_mode`, for the edit
    /// form.
    admin_edit_exit_custom_mode: bool,
    admin_edit_error: Option<String>,
    admin_edit_busy: bool,

    // ── Pool topology view (B3) — Viewer + Admin ────────────────────────
    /// `true` once the pool nodes/health have been kicked off for the
    /// current session (mirrors `admin_clients_loaded`'s one-shot gate).
    admin_pool_loaded: bool,
    admin_pool_nodes: Vec<admin::PoolNode>,
    admin_pool_nodes_loading: bool,
    admin_pool_nodes_error: Option<String>,
    admin_pool_health: Option<admin::PoolHealth>,

    // Connection-key / QR viewer window
    admin_key_id: Option<String>,
    admin_key_name: String,
    admin_key_value: Option<String>,
    admin_key_loading: bool,
    admin_key_error: Option<String>,
    admin_key_saved_msg: Option<String>,
    admin_qr_png: Option<Vec<u8>>,
    admin_qr_texture: Option<eframe::egui::TextureHandle>,
    admin_qr_loading: bool,
    admin_qr_error: Option<String>,
    admin_qr_saved_msg: Option<String>,

    // Revoke confirmation modal
    admin_revoke_id: Option<String>,
    admin_revoke_name: String,

    // ── G-A3: Server Settings (Admin only) — apply-with-rollback ────────
    // for the active mask (per-client) and the global default exit node.
    // Both share the SAME apply -> pending-token -> confirm/timeout flow,
    // but are tracked in independent field sets (mirrors the server's
    // `PendingConfigManager`, which keys entries by target file, so a mask
    // apply and an exit-node apply can both be pending at once without
    // colliding).
    /// Free-text client id/name the "Active mask" apply targets — picked
    /// via a `ComboBox` over the already-loaded `admin_clients` list, not
    /// re-fetched here.
    admin_settings_mask_client: String,
    admin_settings_mask_id: String,
    admin_settings_mask_busy: bool,
    admin_settings_mask_error: Option<String>,
    admin_settings_mask_token: Option<String>,
    admin_settings_mask_deadline: Option<Instant>,
    admin_settings_mask_confirm_busy: bool,
    /// Set for one "apply" cycle when the pending token's deadline passed
    /// locally without a confirm — cleared the next time this setting's
    /// Apply is clicked. Purely informational: the server's own sweep
    /// task already performed the real rollback by the time this fires.
    admin_settings_mask_rolled_back: bool,

    /// `host:port`, empty = clear the global default (`None`).
    admin_settings_exit_node: String,
    /// Same rationale as `admin_add_exit_custom_mode` — G-B1's picker
    /// convention reused here via `Self::draw_exit_node_picker`.
    admin_settings_exit_custom_mode: bool,
    admin_settings_exit_busy: bool,
    admin_settings_exit_error: Option<String>,
    admin_settings_exit_token: Option<String>,
    admin_settings_exit_deadline: Option<Instant>,
    admin_settings_exit_confirm_busy: bool,
    admin_settings_exit_rolled_back: bool,

    // ── SSH server-install wizard (C3) — shells out to `aivpn-client
    // ssh-install {script,probe,run}`, see `install_wizard.rs`'s module
    // doc. GAP-G2: entry point is a top-level, always-visible button on the
    // main screen (see `update()`'s header area) — reachable with no
    // connection and no admin role, since installing a brand-new server is
    // the base "first server from scratch" scenario, not a management
    // action against an already-running one. ─────────────────────────────
    ssh_wizard_open: bool,
    ssh_wizard_stage: SshWizardStage,
    ssh_host: String,
    ssh_port: String,
    ssh_user: String,
    /// `false` = password auth, `true` = private-key file auth.
    ssh_auth_key_mode: bool,
    ssh_password: String,
    ssh_key_path: String,
    ssh_key_passphrase: String,
    ssh_mode_docker: bool,
    ssh_server_ip: String,
    ssh_server_port: String,
    ssh_bind_device: bool,

    ssh_probe_busy: bool,
    ssh_probe_error: Option<String>,
    ssh_probe_rx: Option<std::sync::mpsc::Receiver<Result<String, String>>>,
    /// TOFU fingerprint returned by `ssh-install probe`, shown to the user
    /// for confirmation before `ssh_trusted` is set.
    ssh_fingerprint: Option<String>,
    ssh_trusted: bool,

    ssh_show_script: bool,
    ssh_script_loading: bool,
    ssh_script_rx: Option<std::sync::mpsc::Receiver<Result<(String, String), String>>>,
    ssh_script_text: Option<String>,
    ssh_script_sha256: Option<String>,
    ssh_script_error: Option<String>,

    /// Fresh per install run (see `start_ssh_install`), not created once in
    /// `new()` — so closing the wizard mid-install (`close_ssh_wizard`) can
    /// drop the receiver and stop this session from consuming a still-
    /// running background thread's output/markers, which would otherwise
    /// bleed into a later, unrelated install run sharing the same channel.
    ssh_install_rx: Option<std::sync::mpsc::Receiver<install_wizard::InstallLine>>,
    ssh_install_running: bool,
    ssh_install_log: Vec<install_wizard::InstallLine>,
    ssh_install_connection_key: Option<String>,
    /// `Some(true)` once a terminal ok marker (the synthetic `gui_process`
    /// exit-status marker `install_wizard::spawn_install` always sends) has
    /// been seen; `Some(false)` on a terminal error; `None` while running.
    ssh_install_done_ok: Option<bool>,
    /// Set once `import_ssh_install_key` has successfully added the
    /// finished install's connection key to `keys`.
    ssh_import_done: bool,

    // ── GAP-G3: server binary source — default GitHub Releases / custom
    // URL / local file upload, mirrors `ssh_install_cmd.rs`'s RunArgs
    // --binary-file/--binary-url flags via `install_wizard::BinarySource`.
    ssh_binary_source_choice: SshBinarySourceChoice,
    ssh_binary_url: String,
    ssh_binary_file_path: String,
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SshWizardStage {
    /// Target host/auth/options form, not yet probed.
    Form,
    /// Fingerprint confirmed ("I trust this host") — ready to install.
    Confirmed,
    /// `spawn_install` running, streaming `ssh_install_log`.
    Installing,
    /// Terminal state reached (`ssh_install_done_ok` is `Some`).
    Done,
}

/// GAP-G3: which `aivpn-server` binary the wizard tells the remote script to
/// use — UI-facing mirror of `install_wizard::BinarySource`, kept separate
/// so the URL/file text fields can stay populated even while `Default` is
/// selected (matches the existing `ssh_auth_key_mode` pattern for auth).
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum SshBinarySourceChoice {
    #[default]
    Default,
    Url,
    LocalFile,
}

#[cfg(windows)]
impl AivpnApp {
    fn new(settings: AppSettings, ctx: &eframe::egui::Context) -> Self {
        let (admin_tx, admin_rx) = std::sync::mpsc::channel();
        let mut app = Self {
            settings,
            vpn: VpnManager::new(),
            keys: KeyStorage::load(),
            admin_tx,
            admin_rx,
            admin_role: None,
            admin_clients_loaded: false,
            admin_clients: Vec::new(),
            admin_clients_loading: false,
            admin_clients_error: None,
            admin_busy_ids: std::collections::HashSet::new(),
            admin_status: None,
            admin_audit_loaded: false,
            admin_audit: Vec::new(),
            admin_audit_verified: None,
            admin_audit_broken_at: None,
            admin_audit_loading: false,
            admin_audit_error: None,
            admin_show_add: false,
            admin_add_name: String::new(),
            admin_add_one_time: false,
            admin_add_expiry: String::new(),
            admin_add_exit_node: String::new(),
            admin_add_exit_custom_mode: false,
            admin_add_error: None,
            admin_add_busy: false,
            admin_edit_id: None,
            admin_edit_name: String::new(),
            admin_edit_enabled: true,
            admin_edit_expiry: String::new(),
            admin_edit_exit_node: String::new(),
            admin_edit_exit_custom_mode: false,
            admin_edit_error: None,
            admin_edit_busy: false,
            admin_pool_loaded: false,
            admin_pool_nodes: Vec::new(),
            admin_pool_nodes_loading: false,
            admin_pool_nodes_error: None,
            admin_pool_health: None,
            admin_key_id: None,
            admin_key_name: String::new(),
            admin_key_value: None,
            admin_key_loading: false,
            admin_key_error: None,
            admin_key_saved_msg: None,
            admin_qr_png: None,
            admin_qr_texture: None,
            admin_qr_loading: false,
            admin_qr_error: None,
            admin_qr_saved_msg: None,
            admin_revoke_id: None,
            admin_revoke_name: String::new(),
            admin_settings_mask_client: String::new(),
            admin_settings_mask_id: String::new(),
            admin_settings_mask_busy: false,
            admin_settings_mask_error: None,
            admin_settings_mask_token: None,
            admin_settings_mask_deadline: None,
            admin_settings_mask_confirm_busy: false,
            admin_settings_mask_rolled_back: false,
            admin_settings_exit_node: String::new(),
            admin_settings_exit_custom_mode: false,
            admin_settings_exit_busy: false,
            admin_settings_exit_error: None,
            admin_settings_exit_token: None,
            admin_settings_exit_deadline: None,
            admin_settings_exit_confirm_busy: false,
            admin_settings_exit_rolled_back: false,
            ssh_wizard_open: false,
            ssh_wizard_stage: SshWizardStage::Form,
            ssh_host: String::new(),
            ssh_port: "22".to_string(),
            ssh_user: "root".to_string(),
            ssh_auth_key_mode: false,
            ssh_password: String::new(),
            ssh_key_path: String::new(),
            ssh_key_passphrase: String::new(),
            ssh_mode_docker: false,
            ssh_server_ip: String::new(),
            ssh_server_port: String::new(),
            ssh_bind_device: true,
            ssh_probe_busy: false,
            ssh_probe_error: None,
            ssh_probe_rx: None,
            ssh_fingerprint: None,
            ssh_trusted: false,
            ssh_show_script: false,
            ssh_script_loading: false,
            ssh_script_rx: None,
            ssh_script_text: None,
            ssh_script_sha256: None,
            ssh_script_error: None,
            ssh_install_rx: None,
            ssh_install_running: false,
            ssh_install_log: Vec::new(),
            ssh_install_connection_key: None,
            ssh_install_done_ok: None,
            ssh_import_done: false,
            ssh_binary_source_choice: SshBinarySourceChoice::default(),
            ssh_binary_url: String::new(),
            ssh_binary_file_path: String::new(),
            connected_since: None,
            last_conn_state: ConnectionState::Disconnected,
            error_msg: None,
            error_at: None,
            dirty_at: None,
            show_dialog: false,
            editing_idx: None,
            dlg_name: String::new(),
            dlg_key: String::new(),
            dlg_full_tunnel: false,
            dlg_proxy: false,
            dlg_proxy_addr: String::new(),
            dlg_error: None,
            dlg_exclude_routes: String::new(),
            dlg_include_routes: String::new(),
            dlg_mtls_cert: String::new(),
            bench_result: None,
            bench_running: false,
            bench_rx: None,
            recording_service: String::new(),
            window_visible: true,
            quitting: false,
            elevated_connect_hop: false,
            tray_connected: None,
            tray: None,
            tray_show_flag: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            quit_requested: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            connect_requested: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            tray_thread_shutdown: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        // HIGH-2: let the background supervision thread wake the egui event
        // loop when the client child dies while the window is hidden. Must be
        // registered BEFORE any connect (including the --elevated-connect one
        // just below) so every session's supervisor gets it.
        let repaint_ctx = ctx.clone();
        app.vpn
            .set_wake_callback(move || repaint_ctx.request_repaint());

        // Continuation of a self-relaunch-elevated hop (see relaunch_elevated
        // in do_connect()): this instance IS the elevated one now, launched
        // solely to complete the full-tunnel connect the non-elevated
        // instance couldn't. Select the same key by index and connect
        // immediately — no user interaction needed, the original click
        // already happened in the process that's now exited.
        let args: Vec<String> = std::env::args().collect();
        if let Some(pos) = args.iter().position(|a| a == "--elevated-connect") {
            app.elevated_connect_hop = true;
            if let Some(idx) = args.get(pos + 1).and_then(|s| s.parse::<usize>().ok()) {
                if idx < app.keys.keys.len() {
                    app.keys.selected = Some(idx);
                    app.do_connect();
                }
            }
        }

        app
    }

    /// `connect_on_startup` entry point — connects only when idle, unlike
    /// do_connect() whose toggle semantics would DISCONNECT a session that is
    /// already connecting (HIGH-1: the --elevated-connect session started in
    /// new() is in exactly that state when the startup hook runs).
    fn startup_auto_connect(&mut self) {
        if self.elevated_connect_hop {
            return;
        }
        if !self.vpn.is_connected() && !self.vpn.is_busy() {
            self.do_connect();
        }
    }

    fn init_tray(&mut self) {
        use tray_icon::{
            menu::{Menu, MenuItem, PredefinedMenuItem},
            TrayIconBuilder,
        };

        let lang = self.settings.lang;
        let menu = Menu::new();
        let connect_item = MenuItem::new(t(lang, "connect"), true, None);
        let show_item = MenuItem::new(t(lang, "show"), true, None);
        let quit_item = MenuItem::new(t(lang, "quit"), true, None);
        let _ = menu.append_items(&[
            &connect_item,
            &PredefinedMenuItem::separator(),
            &show_item,
            &PredefinedMenuItem::separator(),
            &quit_item,
        ]);
        let mut builder = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("AIVPN — Disconnected");
        if let Some(icon) = make_tray_icon(false) {
            builder = builder.with_icon(icon);
        }
        match builder.build() {
            Ok(icon) => {
                // Clone IDs before moving items into TrayHandles
                let quit_id = quit_item.id().clone();
                let show_id = show_item.id().clone();
                let connect_id = connect_item.id().clone();
                self.tray = Some(TrayHandles {
                    _icon: icon,
                    connect_item,
                    show_item,
                    quit_item,
                });
                // Background thread: poll TrayIconEvent + MenuEvent and restore the window
                // via Win32. Must run in bg thread so Quit/Connect/Show work even when
                // eframe's update() loop is paused by SW_HIDE.
                let flag = std::sync::Arc::clone(&self.tray_show_flag);
                let quit_flag = std::sync::Arc::clone(&self.quit_requested);
                let connect_flag = std::sync::Arc::clone(&self.connect_requested);
                let shutdown = std::sync::Arc::clone(&self.tray_thread_shutdown);
                std::thread::spawn(move || {
                    use std::sync::atomic::Ordering::Relaxed;
                    use tray_icon::{MouseButton, MouseButtonState, TrayIconEvent};
                    loop {
                        if shutdown.load(Relaxed) {
                            break;
                        }
                        // Icon left-click / double-click → show window
                        while let Ok(ev) = TrayIconEvent::receiver().try_recv() {
                            let show = matches!(
                                ev,
                                TrayIconEvent::Click {
                                    button: MouseButton::Left,
                                    button_state: MouseButtonState::Up,
                                    ..
                                } | TrayIconEvent::DoubleClick { .. }
                            );
                            if show {
                                flag.store(true, Relaxed);
                                bring_window_to_front();
                            }
                        }
                        // Menu events — processed here so Quit/Show/Connect work while hidden
                        while let Ok(ev) = tray_icon::menu::MenuEvent::receiver().try_recv() {
                            if ev.id() == &quit_id {
                                // Wake eframe then signal quit via the flag
                                bring_window_to_front();
                                flag.store(true, Relaxed);
                                quit_flag.store(true, Relaxed);
                            } else if ev.id() == &show_id {
                                bring_window_to_front();
                                flag.store(true, Relaxed);
                            } else if ev.id() == &connect_id {
                                bring_window_to_front();
                                flag.store(true, Relaxed);
                                connect_flag.store(true, Relaxed);
                            }
                        }
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                });
            }
            Err(e) => gui_log(&format!("tray init: {e}")),
        }
    }

    fn show_error(&mut self, msg: String) {
        self.error_msg = Some(msg);
        self.error_at = Some(Instant::now());
    }

    fn tick(&mut self) {
        self.vpn.poll_status();

        // Poll benchmark result channel
        if self.bench_running {
            if let Some(rx) = &self.bench_rx {
                match rx.try_recv() {
                    Ok(result) => {
                        self.bench_result = result;
                        self.bench_running = false;
                        self.bench_rx = None;
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        // Thread panicked — unblock the button
                        self.bench_running = false;
                        self.bench_rx = None;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                }
            }
        }

        let cur = self.vpn.state();
        if cur != self.last_conn_state {
            if cur == ConnectionState::Connected {
                self.connected_since = Some(Instant::now());
                // P3.4: query the server-assigned role once per new
                // session — the admin panel only appears once this comes
                // back Some(2). Reset first so a stale role from a PREVIOUS
                // session's Admin client can't leak into a new session
                // against a non-admin one while the query is in flight.
                self.admin_role = None;
                self.admin_clients_loaded = false;
                admin::spawn(
                    self.vpn.client_binary.clone(),
                    AdminRequest::Role,
                    self.admin_tx.clone(),
                );
            } else if self.last_conn_state == ConnectionState::Connected {
                self.connected_since = None;
                self.reset_admin_state();
            }
            self.last_conn_state = cur;
        }
        self.poll_admin();
        // G-A3: local auto-rollback countdown — purely cosmetic (see
        // `ADMIN_SETTINGS_CONFIRM_TIMEOUT`'s doc comment); runs AFTER
        // `poll_admin` drains this frame's responses so a `ConfigConfirmed`
        // that arrived in the same frame the deadline passed already
        // cleared the deadline field and wins the race (a genuine confirm
        // success is always more authoritative than this local clock).
        if let Some(deadline) = self.admin_settings_mask_deadline {
            if Instant::now() >= deadline {
                self.admin_settings_mask_token = None;
                self.admin_settings_mask_deadline = None;
                self.admin_settings_mask_rolled_back = true;
            }
        }
        if let Some(deadline) = self.admin_settings_exit_deadline {
            if Instant::now() >= deadline {
                self.admin_settings_exit_token = None;
                self.admin_settings_exit_deadline = None;
                self.admin_settings_exit_rolled_back = true;
            }
        }
        self.poll_ssh_install();
        if let Some(at) = self.error_at {
            if at.elapsed().as_secs() > 8 {
                self.error_msg = None;
                self.error_at = None;
            }
        }
        if let Some(at) = self.dirty_at {
            if at.elapsed().as_secs() >= 2 {
                self.settings.save();
                self.dirty_at = None;
            }
        }
    }

    fn do_connect(&mut self) {
        if self.vpn.is_connected() || self.vpn.is_busy() {
            self.vpn.disconnect();
            return;
        }
        let lang = self.settings.lang;
        let Some(ck) = self.keys.selected_key() else {
            self.show_error(t(lang, "no_key_selected").to_string());
            return;
        };
        let key = ck.key.clone();
        let full_tunnel = ck.full_tunnel;

        #[cfg(windows)]
        if full_tunnel && !is_elevated() {
            let Some(idx) = self.keys.selected else {
                self.show_error(t(lang, "no_key_selected").to_string());
                return;
            };
            match relaunch_elevated(idx) {
                Ok(()) => {
                    // Hand off entirely to the elevated instance — save
                    // settings first since this process is about to exit
                    // and never reach its normal on-exit save path.
                    self.settings.save();
                    std::process::exit(0);
                }
                Err(e) => {
                    self.show_error(e);
                    return;
                }
            }
        }

        let proxy_listen = ck.proxy_listen.clone();
        let mtls_cert_path = ck.mtls_cert_path.clone();
        let exclude_routes = ck.exclude_routes.clone();
        let include_routes = ck.include_routes.clone();
        let kill_switch = self.settings.kill_switch;
        let adaptive_level = self.settings.adaptive_level;
        let dns = self.settings.dns_proxy.clone();
        let dns_opt: Option<&str> = if dns.is_empty() { None } else { Some(&dns) };
        let preferred_mask = self.settings.preferred_mask.clone();
        let bootstrap_cdn_url = self.settings.bootstrap_cdn_url.clone();
        let bootstrap_telegram_token = self.settings.bootstrap_telegram_token.clone();
        let bootstrap_telegram_chat = self.settings.bootstrap_telegram_chat.clone();
        let bootstrap_github = self.settings.bootstrap_github.clone();
        let server_signing_key = self.settings.server_signing_key.clone();
        let polymorphic_base = if self.settings.polymorphic_mask {
            preferred_mask.clone()
        } else {
            String::new()
        };
        let share_mask_feedback = self.settings.share_mask_feedback;
        let receive_mask_hints = self.settings.receive_mask_hints;
        let country_code = self.settings.country_code.clone();
        if let Err(e) = self.vpn.connect(
            &key,
            full_tunnel,
            proxy_listen.as_deref(),
            mtls_cert_path.as_deref(),
            &exclude_routes,
            &include_routes,
            kill_switch,
            adaptive_level,
            dns_opt,
            Some(preferred_mask.as_str()),
            Some(bootstrap_cdn_url.as_str()),
            Some(bootstrap_telegram_token.as_str()),
            Some(bootstrap_telegram_chat.as_str()),
            Some(bootstrap_github.as_str()),
            Some(server_signing_key.as_str()),
            Some(polymorphic_base.as_str()),
            share_mask_feedback,
            receive_mask_hints,
            Some(country_code.as_str()),
        ) {
            self.show_error(e);
        }
    }

    fn update_tray(&mut self) {
        let Some(tray) = &self.tray else { return };
        let lang = self.settings.lang;
        let is_connected = self.vpn.is_connected();
        let is_busy = self.vpn.is_busy();
        let _ = tray.connect_item.set_text(if is_connected || is_busy {
            t(lang, "disconnect")
        } else {
            t(lang, "connect")
        });
        let _ = tray.connect_item.set_enabled(!is_busy);
        let tooltip = if is_connected {
            let s = self.vpn.stats();
            format!(
                "AIVPN ↓ {} ↑ {}",
                format_bytes(s.bytes_received),
                format_bytes(s.bytes_sent)
            )
        } else {
            "AIVPN — Disconnected".to_string()
        };
        let _ = tray._icon.set_tooltip(Some(&tooltip));
        if Some(is_connected) != self.tray_connected {
            self.tray_connected = Some(is_connected);
            if let Some(icon) = make_tray_icon(is_connected) {
                let _ = tray._icon.set_icon(Some(icon));
            }
        }
    }

    fn show_window_win32(&self) {
        bring_window_to_front();
    }
}
