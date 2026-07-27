#![cfg_attr(windows, windows_subsystem = "windows")]

mod admin;
mod install_wizard;
mod key_storage;
mod localization;
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

// ── Theme / visuals ────────────────────────────────────────────────────────

#[cfg(windows)]
fn apply_theme_to_ctx(ctx: &eframe::egui::Context, dark: bool) {
    use eframe::egui::{self, FontFamily, FontId, TextStyle};

    if dark {
        ctx.set_visuals(egui::Visuals::dark());
    } else {
        ctx.set_visuals(egui::Visuals::light());
    }

    let mut style = (*ctx.style()).clone();
    style.text_styles = [
        (
            TextStyle::Heading,
            FontId::new(16.0, FontFamily::Proportional),
        ),
        (TextStyle::Body, FontId::new(14.0, FontFamily::Proportional)),
        (
            TextStyle::Button,
            FontId::new(14.0, FontFamily::Proportional),
        ),
        (
            TextStyle::Small,
            FontId::new(12.0, FontFamily::Proportional),
        ),
        (
            TextStyle::Monospace,
            FontId::new(13.0, FontFamily::Monospace),
        ),
    ]
    .into();
    style.spacing.button_padding = egui::vec2(10.0, 6.0);
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.visuals.window_corner_radius = egui::CornerRadius::same(6);
    style.visuals.widgets.noninteractive.corner_radius = egui::CornerRadius::same(4);
    style.visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(4);
    style.visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(4);
    style.visuals.widgets.active.corner_radius = egui::CornerRadius::same(4);

    if dark {
        style.visuals.panel_fill = egui::Color32::from_rgb(0x1E, 0x1E, 0x1E);
        style.visuals.window_fill = egui::Color32::from_rgb(0x25, 0x25, 0x25);
        style.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(0x2D, 0x2D, 0x2D);
        style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(0x3A, 0x3A, 0x3A);
        style.visuals.extreme_bg_color = egui::Color32::from_rgb(0x15, 0x15, 0x15);
    } else {
        style.visuals.panel_fill = egui::Color32::from_rgb(0xF5, 0xF5, 0xF5);
        style.visuals.window_fill = egui::Color32::WHITE;
        style.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(0xE8, 0xE8, 0xE8);
        style.visuals.extreme_bg_color = egui::Color32::WHITE;
    }
    ctx.set_style(style);
}

// ── Programmatic icons ─────────────────────────────────────────────────────

/// Brandbook assets (see assets/brand/BRANDBOOK.md) — main app icon
/// (512x512, full resonance-ring design) and the dedicated tray asset
/// (64x64, simplified for small-size legibility). Both embedded at compile
/// time; decoded once and cached, since `app_icon()` is called once at
/// startup but `make_tray_icon()` is called on every connection-state
/// change (see the "recreated every frame" note this was already fixed
/// for elsewhere — this cache avoids re-decoding the PNG on each call).
static APP_ICON_PNG: &[u8] = include_bytes!("../../../assets/brand/icon-512.png");
static TRAY_ICON_PNG: &[u8] = include_bytes!("../../../assets/brand/tray-dark.png");

#[derive(serde::Deserialize)]
struct MaskCatalogEntry {
    mask_id: String,
    label: String,
    generated: bool,
}

/// Localized suffix appended to auto-generated masks in the picker (Variant A).
fn auto_mask_suffix(lang: localization::Lang) -> &'static str {
    match lang {
        localization::Lang::Ru => " (авто)",
        localization::Lang::En => " (auto)",
    }
}

/// Candidate paths where `aivpn-client.exe` writes the server-pushed mask
/// catalog (mirrors the client's `mask_catalog_paths`).
fn mask_catalog_paths() -> Vec<std::path::PathBuf> {
    let mut v = Vec::new();
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        v.push(
            std::path::PathBuf::from(local)
                .join("AIVPN")
                .join("mask_catalog.json"),
        );
    }
    v.push(std::env::temp_dir().join("aivpn-mask-catalog.json"));
    v
}

/// (id, display) mask choices from the server catalog, marking auto-generated
/// masks with the localized "(авто)" suffix. `None` until a catalog has been
/// received, so the caller falls back to the built-in preset list.
fn mask_choices_from_catalog(lang: localization::Lang) -> Option<Vec<(String, String)>> {
    for path in mask_catalog_paths() {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(entries) = serde_json::from_slice::<Vec<MaskCatalogEntry>>(&bytes) else {
            continue;
        };
        let mut out = vec![("auto".to_string(), "auto".to_string())];
        for e in entries {
            if e.mask_id == "auto" {
                continue;
            }
            // HIGH: mask_catalog.json is written by aivpn-client from a
            // server-pushed catalog — an id that fails the same strict
            // charset vpn_manager::connect() enforces before argv would be
            // rejected there anyway, but skip it here too so it never even
            // becomes a clickable option (defense in depth, see
            // vpn_manager::is_acceptable_mask_id for the full rationale).
            if !vpn_manager::is_acceptable_mask_id(&e.mask_id) {
                vpn_manager::gui_log(&format!(
                    "mask catalog: skipping entry with invalid mask_id {:?}",
                    e.mask_id
                ));
                continue;
            }
            let display = if e.generated {
                format!("{}{}", e.label, auto_mask_suffix(lang))
            } else {
                e.label
            };
            out.push((e.mask_id, display));
        }
        return Some(out);
    }
    None
}

/// Decode a PNG into (rgba_bytes, width, height). Panics on decode failure
/// — both callers pass a bundled, known-good asset, so a failure here means
/// the build is broken, not a runtime condition to recover from.
///
/// `png`/`eframe` are `cfg(windows)`-only dependencies (see Cargo.toml), so
/// this — and `app_icon` below — must stay gated the same way for the crate
/// to remain host-buildable on Linux (`cargo test -p aivpn-windows`), same
/// as every other egui-touching item in this file.
#[cfg(windows)]
fn decode_png_rgba(bytes: &[u8]) -> (Vec<u8>, u32, u32) {
    let decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    let mut reader = decoder.read_info().expect("bundled brand PNG must decode");
    let mut rgba = vec![
        0u8;
        reader
            .output_buffer_size()
            .expect("bundled brand PNG must have a known buffer size")
    ];
    let info = reader
        .next_frame(&mut rgba)
        .expect("bundled brand PNG must decode");
    rgba.truncate(info.buffer_size());
    (rgba, info.width, info.height)
}

#[cfg(windows)]
fn app_icon() -> std::sync::Arc<eframe::egui::IconData> {
    let (rgba, width, height) = decode_png_rgba(APP_ICON_PNG);
    std::sync::Arc::new(eframe::egui::IconData {
        rgba,
        width,
        height,
    })
}

/// Coarse "Xs/Xm/Xh/Xd" relative-age string for a `last_seen_unix` field
/// from `GET /api/v1/pool/nodes` — the pool section (B3) has no on-disk
/// clock skew guard, so a slightly-negative delta (peer clock ahead of
/// ours) is just clamped to zero rather than shown as "-Ns".
#[cfg(windows)]
fn format_unix_ago(ts: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let secs = (now - ts).max(0);
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

#[cfg(windows)]
fn tray_icon_base() -> &'static (Vec<u8>, u32, u32) {
    static BASE: std::sync::OnceLock<(Vec<u8>, u32, u32)> = std::sync::OnceLock::new();
    BASE.get_or_init(|| decode_png_rgba(TRAY_ICON_PNG))
}

#[cfg(windows)]
fn make_tray_icon(connected: bool) -> Option<tray_icon::Icon> {
    let (base, width, height) = tray_icon_base();
    let mut rgba = base.clone();

    // Small status-colour dot composited in the bottom-right corner, on top
    // of the branded icon — keeps the connected/disconnected signal at a
    // glance (the whole point of the original solid-colour-circle icon)
    // without abandoning brand consistency the way a plain green/grey
    // circle did.
    let (r, g, b) = if connected {
        (0x4C, 0xAF, 0x50u8)
    } else {
        (0x78, 0x78, 0x78u8)
    };
    let radius = (*width as f32) * 0.22;
    let cx = *width as f32 - radius - 1.0;
    let cy = *height as f32 - radius - 1.0;
    for y in 0..*height {
        for x in 0..*width {
            let dx = x as f32 - cx;
            let dy = y as f32 - cy;
            if (dx * dx + dy * dy).sqrt() < radius {
                let i = ((y * width + x) * 4) as usize;
                rgba[i] = r;
                rgba[i + 1] = g;
                rgba[i + 2] = b;
                rgba[i + 3] = 0xFF;
            }
        }
    }

    match tray_icon::Icon::from_rgba(rgba, *width, *height) {
        Ok(icon) => Some(icon),
        Err(e) => {
            vpn_manager::gui_log(&format!("tray: failed to build icon: {e}"));
            None
        }
    }
}

// ── On-demand UAC elevation for full-tunnel mode ────────────────────────────
//
// aivpn-windows.exe itself launches without any elevation manifest — the
// user can run it as a normal user, and proxy-mode connections never need
// admin rights at all (Wintun is the only thing that does). Only when the
// user selects a full-tunnel key and the process isn't already elevated do
// we self-relaunch elevated, rather than forcing UAC at every launch.
//
// ShellExecuteEx (the API that actually shows the UAC consent prompt) has
// no equivalent of CreateProcess's lpEnvironment — there is no way to pass
// environment variables to the child it launches. The connection key is
// deliberately passed via an env var today (AIVPN_CONNECTION_KEY), not a
// CLI arg, specifically so it never appears in Task Manager's command-line
// column. Relaunching aivpn-client.exe directly through ShellExecuteEx with
// the key in its command line would reintroduce exactly that exposure.
//
// Instead, this relaunches aivpn-windows.exe ITSELF elevated, passing only
// a non-secret key index via --elevated-connect. The freshly-elevated GUI
// instance decrypts its own copy of the connection key from KeyStorage
// (DPAPI, CurrentUser scope — decryptable by any process running as this
// same user, elevated or not) and spawns aivpn-client.exe the normal way
// (Command::spawn + env, unchanged from the existing proxy-mode path). The
// original, non-elevated instance exits once the elevated one is launched.

#[cfg(windows)]
fn is_elevated() -> bool {
    use std::mem;
    use std::ptr;
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
    use winapi::um::securitybaseapi::GetTokenInformation;
    use winapi::um::winnt::{TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};

    unsafe {
        let mut token = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
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

/// Relaunch this exe elevated via ShellExecuteEx's "runas" verb (the API
/// that shows the native UAC consent dialog), passing only the non-secret
/// key index. Returns Err if the user cancels the prompt or ShellExecuteEx
/// itself fails; never returns Ok (the caller is expected to exit the
/// current process immediately after a successful launch, so there is
/// nothing meaningful to return to).
#[cfg(windows)]
fn relaunch_elevated(key_index: usize) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use winapi::um::shellapi::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use winapi::um::winuser::SW_SHOWNORMAL;

    let exe = std::env::current_exe()
        .map_err(|e| format!("Could not determine current executable path: {e}"))?;

    let wide = |s: &OsStr| -> Vec<u16> { s.encode_wide().chain(std::iter::once(0)).collect() };
    let verb = wide(OsStr::new("runas"));
    let file = wide(exe.as_os_str());
    let params_str = format!("--elevated-connect {key_index}");
    let params = wide(OsStr::new(&params_str));
    let dir = exe.parent().map(|d| wide(d.as_os_str()));

    let mut sei: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    sei.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = verb.as_ptr();
    sei.lpFile = file.as_ptr();
    sei.lpParameters = params.as_ptr();
    sei.lpDirectory = dir.as_ref().map(|d| d.as_ptr()).unwrap_or(std::ptr::null());
    sei.nShow = SW_SHOWNORMAL;

    let ok = unsafe { ShellExecuteExW(&mut sei) };
    if ok == 0 || sei.hProcess.is_null() {
        return Err(
            "Elevation was cancelled or failed. Full-tunnel mode requires Administrator \
             rights on Windows to create the network adapter — either allow the elevation \
             prompt, or switch this key to proxy mode (no admin rights needed)."
                .to_string(),
        );
    }
    // We don't need the handle — the elevated instance is now fully
    // independent and manages its own lifecycle.
    unsafe { winapi::um::handleapi::CloseHandle(sei.hProcess) };
    Ok(())
}

// ── Win32 helpers ──────────────────────────────────────────────────────────

/// Claim (and intentionally leak, for the process lifetime) the named
/// single-instance mutex. Returns true when another AIVPN GUI already holds
/// it; false also when the mutex could not be created at all — an
/// undiagnosable failure must not block launching the app.
#[cfg(windows)]
fn claim_single_instance_mutex() -> bool {
    use winapi::shared::winerror::ERROR_ALREADY_EXISTS;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::synchapi::CreateMutexW;
    let name: Vec<u16> = "AIVPN_GUI_SingleInstance\0".encode_utf16().collect();
    unsafe {
        let h = CreateMutexW(std::ptr::null_mut(), 0, name.as_ptr());
        if h.is_null() {
            return false;
        }
        // Handle deliberately not closed: the mutex must stay held for the
        // whole process lifetime; the OS releases it at process exit.
        GetLastError() == ERROR_ALREADY_EXISTS
    }
}

/// Bring the ALREADY-RUNNING instance's window to the foreground before this
/// duplicate process exits. This is the one place a cross-process
/// FindWindowW is the point (contrast find_own_aivpn_hwnd()) — any window
/// titled "AIVPN" here belongs to the other instance, not to us.
#[cfg(windows)]
fn focus_existing_instance() {
    unsafe {
        use winapi::um::winuser::{FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE};
        let title: Vec<u16> = "AIVPN\0".encode_utf16().collect();
        let hwnd = FindWindowW(std::ptr::null(), title.as_ptr());
        if !hwnd.is_null() {
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
        }
    }
}

/// Locate THIS process's main window (LOW-1). A bare FindWindowW(null,
/// "AIVPN") matches any top-level window with that title from any process —
/// so walk all title matches and keep the one owned by our PID.
#[cfg(windows)]
fn find_own_aivpn_hwnd() -> winapi::shared::windef::HWND {
    use winapi::um::processthreadsapi::GetCurrentProcessId;
    use winapi::um::winuser::{FindWindowExW, GetWindowThreadProcessId};
    let title: Vec<u16> = "AIVPN\0".encode_utf16().collect();
    unsafe {
        let my_pid = GetCurrentProcessId();
        let mut hwnd = FindWindowExW(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            title.as_ptr(),
        );
        while !hwnd.is_null() {
            let mut pid: u32 = 0;
            GetWindowThreadProcessId(hwnd, &mut pid);
            if pid == my_pid {
                return hwnd;
            }
            hwnd = FindWindowExW(std::ptr::null_mut(), hwnd, std::ptr::null(), title.as_ptr());
        }
        std::ptr::null_mut()
    }
}

/// Restore + focus the AIVPN window, bypassing SetForegroundWindow restrictions via
/// AttachThreadInput. Uses SW_RESTORE so a minimized window is un-minimized.
#[cfg(windows)]
fn bring_window_to_front() {
    unsafe {
        use winapi::um::processthreadsapi::GetCurrentThreadId;
        use winapi::um::winuser::{
            AttachThreadInput, BringWindowToTop, GetForegroundWindow, GetWindowThreadProcessId,
            SetForegroundWindow, ShowWindow, SW_RESTORE,
        };
        let hwnd = find_own_aivpn_hwnd();
        if hwnd.is_null() {
            return;
        }
        let fg_hwnd = GetForegroundWindow();
        let fg_thread = GetWindowThreadProcessId(fg_hwnd, std::ptr::null_mut());
        let my_thread = GetCurrentThreadId();
        if fg_thread != 0 && fg_thread != my_thread {
            AttachThreadInput(fg_thread, my_thread, 1);
        }
        ShowWindow(hwnd, SW_RESTORE);
        BringWindowToTop(hwnd);
        SetForegroundWindow(hwnd);
        if fg_thread != 0 && fg_thread != my_thread {
            AttachThreadInput(fg_thread, my_thread, 0);
        }
    }
}

#[cfg(not(windows))]
fn bring_window_to_front() {}

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
use key_storage::KeyStorage;
#[cfg(windows)]
use localization::{t, AppSettings, Lang};
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

    // ── Admin panel (P3.4) ──────────────────────────────────────────────

    /// Drain every pending `AdminResponse` and apply it to UI state. Called
    /// once per `tick()`.
    fn poll_admin(&mut self) {
        while let Ok(msg) = self.admin_rx.try_recv() {
            match msg {
                AdminResponse::Role(r) => match r {
                    Ok(role) => {
                        self.admin_role = Some(role);
                        // G-A1: the client list is a plain GET the server's
                        // `authorize()` already permits a Viewer — only the
                        // mutating controls inside `draw_admin_clients_
                        // section` stay Admin-only, gated by `can_mutate`.
                        if role >= 1 && !self.admin_clients_loaded {
                            self.admin_clients_loaded = true;
                            self.refresh_admin_clients();
                        }
                        // B3: pool topology is Viewer(1)+Admin(2) readable —
                        // see `mgmt_service.rs`'s `authorize`.
                        if role >= 1 && !self.admin_pool_loaded {
                            self.admin_pool_loaded = true;
                            self.refresh_admin_pool();
                        }
                        // G-A2: audit log is likewise Viewer(1)+Admin(2)
                        // GET-only readable.
                        if role >= 1 && !self.admin_audit_loaded {
                            self.admin_audit_loaded = true;
                            self.refresh_admin_audit();
                        }
                    }
                    Err(_) => {
                        // Fails closed: an unreadable/unknown role never
                        // shows the panel, same as an explicit User role.
                        self.admin_role = Some(0);
                    }
                },
                AdminResponse::Clients(r) => {
                    self.admin_clients_loading = false;
                    match r {
                        Ok(list) => {
                            self.admin_clients = list;
                            self.admin_clients_error = None;
                        }
                        Err(e) => self.admin_clients_error = Some(e),
                    }
                }
                // `editing` comes from the ORIGINATING request, not from
                // "is the edit form open right now" — see the variant's doc
                // comment in admin.rs (BUG FIX: overlapping add/edit used to
                // misroute errors and close the wrong form).
                AdminResponse::ClientSaved { editing, result } => {
                    if editing {
                        self.admin_edit_busy = false;
                    } else {
                        self.admin_add_busy = false;
                    }
                    match result {
                        Ok(_) => {
                            if editing {
                                self.admin_edit_id = None;
                                self.admin_edit_error = None;
                            } else {
                                self.admin_show_add = false;
                                self.admin_add_error = None;
                            }
                            self.refresh_admin_clients();
                        }
                        Err(e) => {
                            if editing {
                                self.admin_edit_error = Some(e);
                            } else {
                                self.admin_add_error = Some(e);
                            }
                        }
                    }
                }
                AdminResponse::ClientDeleted { id, result } => {
                    self.admin_busy_ids.remove(&id);
                    match result {
                        Ok(()) => self.refresh_admin_clients(),
                        Err(e) => self.show_error(e),
                    }
                }
                AdminResponse::ClientRevoked { id, result } => {
                    self.admin_busy_ids.remove(&id);
                    if self.admin_revoke_id.as_deref() == Some(id.as_str()) {
                        self.admin_revoke_id = None;
                    }
                    match result {
                        Ok(()) => self.refresh_admin_clients(),
                        Err(e) => self.show_error(e),
                    }
                }
                AdminResponse::DeviceReset { id, result } => {
                    self.admin_busy_ids.remove(&id);
                    match result {
                        Ok(()) => self.refresh_admin_clients(),
                        Err(e) => self.show_error(e),
                    }
                }
                AdminResponse::ConnectionKey { id, result } => {
                    // Only touch UI state if this answers the client the
                    // viewer window CURRENTLY shows — a stale response for a
                    // previously-viewed client must not clear the loading
                    // spinner of the request still in flight for the current
                    // one (BUG FIX, review: `loading = false` used to run
                    // before this id check).
                    if self.admin_key_id.as_deref() == Some(id.as_str()) {
                        self.admin_key_loading = false;
                        match result {
                            Ok(key) => {
                                self.admin_key_value = Some(key);
                                self.admin_key_error = None;
                            }
                            Err(e) => self.admin_key_error = Some(e),
                        }
                    }
                }
                AdminResponse::Qr { id, result } => {
                    // Same stale-response guard as ConnectionKey above.
                    if self.admin_key_id.as_deref() == Some(id.as_str()) {
                        self.admin_qr_loading = false;
                        match result {
                            Ok(png) => {
                                self.admin_qr_png = Some(png);
                                self.admin_qr_texture = None; // rebuilt lazily on next draw
                                self.admin_qr_error = None;
                            }
                            Err(e) => self.admin_qr_error = Some(e),
                        }
                    }
                }
                AdminResponse::Status(r) => {
                    if let Ok(s) = r {
                        self.admin_status = Some(s);
                    }
                }
                AdminResponse::AuditLog(r) => {
                    self.admin_audit_loading = false;
                    match r {
                        Ok(view) => {
                            self.admin_audit = view.entries;
                            self.admin_audit_verified = view.verified;
                            self.admin_audit_broken_at = view.broken_at;
                            self.admin_audit_error = None;
                        }
                        Err(e) => self.admin_audit_error = Some(e),
                    }
                }
                AdminResponse::PoolNodes(r) => {
                    self.admin_pool_nodes_loading = false;
                    match r {
                        Ok(list) => {
                            self.admin_pool_nodes = list;
                            self.admin_pool_nodes_error = None;
                        }
                        Err(e) => self.admin_pool_nodes_error = Some(e),
                    }
                }
                AdminResponse::PoolHealth(r) => {
                    // Best-effort: a failed health fetch leaves the last
                    // known summary on screen rather than blanking it —
                    // `admin_pool_nodes_error` above already surfaces a
                    // pool-unreachable condition from the paired call.
                    if let Ok(h) = r {
                        self.admin_pool_health = Some(h);
                    }
                }
                AdminResponse::ConfigApplied { setting, result } => {
                    match setting {
                        admin::ConfigSetting::ActiveMask => self.admin_settings_mask_busy = false,
                        admin::ConfigSetting::ExitNode => self.admin_settings_exit_busy = false,
                    }
                    match result {
                        Ok(applied) => {
                            let deadline = Some(Instant::now() + ADMIN_SETTINGS_CONFIRM_TIMEOUT);
                            match setting {
                                admin::ConfigSetting::ActiveMask => {
                                    self.admin_settings_mask_token = Some(applied.token);
                                    self.admin_settings_mask_deadline = deadline;
                                    self.admin_settings_mask_error = None;
                                    self.admin_settings_mask_rolled_back = false;
                                }
                                admin::ConfigSetting::ExitNode => {
                                    self.admin_settings_exit_token = Some(applied.token);
                                    self.admin_settings_exit_deadline = deadline;
                                    self.admin_settings_exit_error = None;
                                    self.admin_settings_exit_rolled_back = false;
                                }
                            }
                        }
                        Err(e) => match setting {
                            admin::ConfigSetting::ActiveMask => {
                                self.admin_settings_mask_error = Some(e)
                            }
                            admin::ConfigSetting::ExitNode => {
                                self.admin_settings_exit_error = Some(e)
                            }
                        },
                    }
                }
                AdminResponse::ConfigConfirmed { setting, result } => {
                    match setting {
                        admin::ConfigSetting::ActiveMask => {
                            self.admin_settings_mask_confirm_busy = false
                        }
                        admin::ConfigSetting::ExitNode => {
                            self.admin_settings_exit_confirm_busy = false
                        }
                    }
                    match result {
                        Ok(()) => match setting {
                            admin::ConfigSetting::ActiveMask => {
                                self.admin_settings_mask_token = None;
                                self.admin_settings_mask_deadline = None;
                                self.admin_settings_mask_rolled_back = false;
                            }
                            admin::ConfigSetting::ExitNode => {
                                self.admin_settings_exit_token = None;
                                self.admin_settings_exit_deadline = None;
                                self.admin_settings_exit_rolled_back = false;
                            }
                        },
                        // Deliberately leaves token/deadline intact on a
                        // confirm error: it might be transient (the token
                        // itself may still be valid server-side), so the
                        // user gets another shot at Confirm before the
                        // LOCAL countdown (see `tick()`) times it out on
                        // its own. Only that local timeout — not a failed
                        // confirm call — ever sets `*_rolled_back`.
                        Err(e) => self.show_error(e),
                    }
                }
            }
        }
    }

    // ── SSH server-install wizard (C3) ──────────────────────────────────

    /// Drain every pending streamed `InstallLine` plus the one-shot probe/
    /// script results, and apply them to wizard UI state. Called once per
    /// `tick()`, mirroring `poll_admin`.
    fn poll_ssh_install(&mut self) {
        // BUG FIX (review): `ssh_install_rx` is a fresh channel per install
        // run (see `start_ssh_install`), not a single app-lifetime pair —
        // that was the original bug. A single shared Sender/Receiver never
        // dropped for the app's whole lifetime meant closing the wizard
        // mid-install (the window's native ✕, handled by `close_ssh_wizard`)
        // left the background `spawn_install` thread still writing into the
        // same channel; if the user then reopened the wizard and started a
        // SECOND install, both threads' lines/markers interleaved into one
        // `ssh_install_log`, and whichever thread's `gui_process` terminal
        // marker arrived first could silently end the WRONG run's progress
        // display. Recreating the channel per run, and dropping it in
        // `close_ssh_wizard`, isolates each run: an abandoned thread's
        // `tx.send` starts failing (it already handles that — see
        // `spawn_install`'s doc comment) instead of polluting a later run.
        let mut rx_disconnected = false;
        // G-C1: set inside the `rx`-borrowing loop below, acted on after it
        // ends — `import_ssh_install_key` takes `&mut self`, which the
        // borrow checker can't reconcile with the outstanding `&self.
        // ssh_install_rx` borrow `rx` holds for the loop's duration (unlike
        // the direct field writes below, a `&mut self` method call is
        // opaque to it and would conflict).
        let mut auto_import_key = false;
        if let Some(rx) = &self.ssh_install_rx {
            loop {
                match rx.try_recv() {
                    Ok(line) => {
                        if let install_wizard::InstallLine::Marker {
                            step,
                            status,
                            connection_key,
                            ..
                        } = &line
                        {
                            if let Some(key) = connection_key {
                                self.ssh_install_connection_key = Some(key.clone());
                                // G-C1: auto-import the moment the terminal
                                // success marker's key shows up — no more
                                // waiting on a manual "Import profile"
                                // click. `should_auto_import` also guards
                                // against double-importing if this marker
                                // is somehow observed twice in one run.
                                if install_wizard::should_auto_import(
                                    status,
                                    connection_key,
                                    self.ssh_import_done,
                                ) {
                                    auto_import_key = true;
                                }
                            }
                            // `gui_process` is spawn_install's own synthetic
                            // marker, always sent exactly once when the
                            // child exits (see install_wizard.rs's doc
                            // comment) — the one reliable "the subprocess is
                            // done" signal, regardless of whether the remote
                            // script/CLI got far enough to emit its own
                            // `done`/`client_done` markers.
                            if step == "gui_process" {
                                self.ssh_install_running = false;
                                self.ssh_install_done_ok = Some(status == "ok");
                                self.ssh_wizard_stage = SshWizardStage::Done;
                            }
                        }
                        self.ssh_install_log.push(line);
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        rx_disconnected = true;
                        break;
                    }
                }
            }
        }
        // G-C1: now that `rx`'s borrow of `self.ssh_install_rx` has ended,
        // it's safe to call the `&mut self` import path.
        if auto_import_key {
            self.import_ssh_install_key();
        }
        if rx_disconnected {
            self.ssh_install_rx = None;
            // The sender thread is gone without ever sending its terminal
            // `gui_process` marker (e.g. it panicked) — don't leave the UI
            // stuck showing "Installing…" forever.
            if self.ssh_install_running {
                self.ssh_install_running = false;
                self.ssh_install_done_ok = Some(false);
                self.ssh_wizard_stage = SshWizardStage::Done;
            }
        }

        if let Some(rx) = &self.ssh_probe_rx {
            match rx.try_recv() {
                Ok(Ok(fingerprint)) => {
                    self.ssh_fingerprint = Some(fingerprint);
                    self.ssh_probe_busy = false;
                    self.ssh_probe_error = None;
                    self.ssh_probe_rx = None;
                }
                Ok(Err(e)) => {
                    self.ssh_probe_error = Some(e);
                    self.ssh_probe_busy = false;
                    self.ssh_probe_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.ssh_probe_busy = false;
                    self.ssh_probe_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }

        if let Some(rx) = &self.ssh_script_rx {
            match rx.try_recv() {
                Ok(Ok((sha256, script))) => {
                    self.ssh_script_sha256 = Some(sha256);
                    self.ssh_script_text = Some(script);
                    self.ssh_script_loading = false;
                    self.ssh_script_error = None;
                    self.ssh_script_rx = None;
                }
                Ok(Err(e)) => {
                    self.ssh_script_error = Some(e);
                    self.ssh_script_loading = false;
                    self.ssh_script_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.ssh_script_loading = false;
                    self.ssh_script_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
    }

    /// `ssh-install probe` (TOFU step 1) on a background thread — see
    /// `install_wizard::probe`'s doc comment.
    fn start_ssh_probe(&mut self) {
        let host = self.ssh_host.trim().to_string();
        if host.is_empty() {
            self.ssh_probe_error = Some("Host is required".to_string());
            return;
        }
        let port: u16 = match self.ssh_port.trim().parse() {
            Ok(p) => p,
            Err(_) => {
                self.ssh_probe_error = Some("Invalid port".to_string());
                return;
            }
        };
        let user = if self.ssh_user.trim().is_empty() {
            "root".to_string()
        } else {
            self.ssh_user.trim().to_string()
        };

        self.ssh_probe_busy = true;
        self.ssh_probe_error = None;
        self.ssh_fingerprint = None;
        self.ssh_trusted = false;

        let client_binary = self.vpn.client_binary.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        self.ssh_probe_rx = Some(rx);
        std::thread::spawn(move || {
            let result = install_wizard::probe(&client_binary, &host, port, &user);
            let _ = tx.send(result);
        });
    }

    /// `ssh-install script` + `--sha256-only` (paranoid-mode review) on a
    /// background thread — see `install_wizard::fetch_script`'s doc
    /// comment.
    fn start_fetch_script(&mut self) {
        if self.ssh_script_loading {
            return;
        }
        self.ssh_script_loading = true;
        self.ssh_script_error = None;
        let client_binary = self.vpn.client_binary.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        self.ssh_script_rx = Some(rx);
        std::thread::spawn(move || {
            let result = install_wizard::fetch_script(&client_binary);
            let _ = tx.send(result);
        });
    }

    /// Builds an `InstallTarget` from the wizard's form fields and starts
    /// `install_wizard::spawn_install` streaming into `ssh_install_rx`.
    /// Requires [`Self::ssh_fingerprint`] to already be `Some` (TOFU step 1
    /// must have completed) — the caller-side "Install" button is disabled
    /// otherwise, so this is an invariant, not a user-facing error path.
    fn start_ssh_install(&mut self) {
        let fingerprint = match &self.ssh_fingerprint {
            Some(f) => f.clone(),
            None => return,
        };
        let port: u16 = self.ssh_port.trim().parse().unwrap_or(22);
        let user = if self.ssh_user.trim().is_empty() {
            "root".to_string()
        } else {
            self.ssh_user.trim().to_string()
        };

        let (auth, secret) = if self.ssh_auth_key_mode {
            let has_passphrase = !self.ssh_key_passphrase.is_empty();
            (
                install_wizard::InstallAuth::KeyFile {
                    path: std::path::PathBuf::from(self.ssh_key_path.trim()),
                    has_passphrase,
                },
                has_passphrase.then(|| self.ssh_key_passphrase.clone()),
            )
        } else {
            (
                install_wizard::InstallAuth::Password,
                Some(self.ssh_password.clone()),
            )
        };

        // GAP-G3: default/URL/local-file — see `SshBinarySourceChoice`'s doc
        // comment. A blank URL/path silently falls back to `Default`
        // (`install_wizard::build_run_args` already trims+skips a blank
        // URL; a blank file path is passed through as-is, same as every
        // other path field in this wizard — `ssh-install run` itself is the
        // one that will reject an empty/missing `--binary-file`).
        let binary_source = match self.ssh_binary_source_choice {
            SshBinarySourceChoice::Default => install_wizard::BinarySource::Default,
            SshBinarySourceChoice::Url => {
                install_wizard::BinarySource::Url(self.ssh_binary_url.trim().to_string())
            }
            SshBinarySourceChoice::LocalFile => install_wizard::BinarySource::LocalFile(
                std::path::PathBuf::from(self.ssh_binary_file_path.trim()),
            ),
        };

        let target = install_wizard::InstallTarget {
            host: self.ssh_host.trim().to_string(),
            port,
            user,
            fingerprint,
            auth,
            mode: if self.ssh_mode_docker {
                install_wizard::InstallModeChoice::Docker
            } else {
                install_wizard::InstallModeChoice::Systemd
            },
            binary_source,
            server_ip: (!self.ssh_server_ip.trim().is_empty())
                .then(|| self.ssh_server_ip.trim().to_string()),
            server_port: self.ssh_server_port.trim().parse().ok(),
            bind_device: self.ssh_bind_device,
        };

        self.ssh_install_running = true;
        self.ssh_install_log.clear();
        self.ssh_install_connection_key = None;
        self.ssh_install_done_ok = None;
        self.ssh_import_done = false;
        self.ssh_wizard_stage = SshWizardStage::Installing;

        // Fresh channel per run — see `ssh_install_rx`'s doc comment (review
        // bug fix) for why this must not be a single app-lifetime pair.
        let (tx, rx) = std::sync::mpsc::channel();
        self.ssh_install_rx = Some(rx);
        install_wizard::spawn_install(self.vpn.client_binary.clone(), target, secret, tx);
    }

    /// Adds the finished install's `connection_key` to `keys` under an
    /// auto-generated name, same validation path as the manual "Add key"
    /// dialog (`KeyStorage::add_key`).
    fn import_ssh_install_key(&mut self) {
        let Some(key) = self.ssh_install_connection_key.clone() else {
            return;
        };
        let name = if self.ssh_host.trim().is_empty() {
            "SSH install".to_string()
        } else {
            format!("SSH install ({})", self.ssh_host.trim())
        };
        match self
            .keys
            .add_key(&name, &key, false, None, None, Vec::new(), Vec::new())
        {
            Ok(()) => self.ssh_import_done = true,
            Err(e) => self.show_error(format!("Failed to import profile: {e}")),
        }
    }

    /// Closes the wizard and clears every per-run field (but not the
    /// host/port/user/mode/options form fields — left in place so
    /// reopening after a finished/failed run doesn't force retyping them).
    fn close_ssh_wizard(&mut self) {
        self.ssh_wizard_open = false;
        self.ssh_wizard_stage = SshWizardStage::Form;
        self.ssh_password.clear();
        self.ssh_key_passphrase.clear();
        self.ssh_probe_busy = false;
        self.ssh_probe_error = None;
        self.ssh_probe_rx = None;
        self.ssh_fingerprint = None;
        self.ssh_trusted = false;
        self.ssh_show_script = false;
        self.ssh_script_loading = false;
        self.ssh_script_rx = None;
        self.ssh_script_text = None;
        self.ssh_script_sha256 = None;
        self.ssh_script_error = None;
        self.ssh_install_running = false;
        self.ssh_install_log.clear();
        self.ssh_install_connection_key = None;
        self.ssh_install_done_ok = None;
        self.ssh_import_done = false;
        // Review bug fix: drop the receiver so a still-running background
        // install thread's `tx.send` starts failing (it already handles
        // that gracefully) instead of continuing to feed a NEW run's state
        // if the user reopens the wizard and starts another install before
        // this one's remote script has finished — see `ssh_install_rx`'s
        // and `poll_ssh_install`'s doc comments.
        self.ssh_install_rx = None;
    }

    fn refresh_admin_pool(&mut self) {
        self.admin_pool_nodes_loading = true;
        self.admin_pool_nodes_error = None;
        admin::spawn(
            self.vpn.client_binary.clone(),
            AdminRequest::PoolNodes,
            self.admin_tx.clone(),
        );
        admin::spawn(
            self.vpn.client_binary.clone(),
            AdminRequest::PoolHealth,
            self.admin_tx.clone(),
        );
    }

    fn refresh_admin_clients(&mut self) {
        self.admin_clients_loading = true;
        self.admin_clients_error = None;
        admin::spawn(
            self.vpn.client_binary.clone(),
            AdminRequest::ListClients,
            self.admin_tx.clone(),
        );
    }

    /// G-A2: refresh the audit-log panel — Viewer(1)+Admin(2), same as
    /// `refresh_admin_pool`.
    fn refresh_admin_audit(&mut self) {
        self.admin_audit_loading = true;
        self.admin_audit_error = None;
        admin::spawn(
            self.vpn.client_binary.clone(),
            AdminRequest::AuditLog,
            self.admin_tx.clone(),
        );
    }

    /// Clear every admin-panel field back to its pre-session default.
    /// Called when the session leaves the Connected state — the panel
    /// (and its cached role/clients/dialogs) belongs to that one session
    /// only, never carries over to the next connect.
    fn reset_admin_state(&mut self) {
        self.admin_role = None;
        self.admin_clients_loaded = false;
        self.admin_clients.clear();
        self.admin_clients_loading = false;
        self.admin_clients_error = None;
        self.admin_busy_ids.clear();
        self.admin_status = None;
        self.admin_audit_loaded = false;
        self.admin_audit.clear();
        self.admin_audit_verified = None;
        self.admin_audit_broken_at = None;
        self.admin_audit_loading = false;
        self.admin_audit_error = None;
        self.admin_show_add = false;
        self.admin_add_error = None;
        self.admin_add_busy = false;
        self.admin_add_exit_node.clear();
        self.admin_add_exit_custom_mode = false;
        self.admin_edit_id = None;
        self.admin_edit_error = None;
        self.admin_edit_busy = false;
        self.admin_edit_exit_node.clear();
        self.admin_edit_exit_custom_mode = false;
        self.admin_pool_loaded = false;
        self.admin_pool_nodes.clear();
        self.admin_pool_nodes_loading = false;
        self.admin_pool_nodes_error = None;
        self.admin_pool_health = None;
        self.admin_key_id = None;
        self.admin_key_value = None;
        self.admin_key_loading = false;
        self.admin_key_error = None;
        self.admin_key_saved_msg = None;
        self.admin_qr_png = None;
        self.admin_qr_texture = None;
        self.admin_qr_loading = false;
        self.admin_qr_error = None;
        self.admin_qr_saved_msg = None;
        self.admin_revoke_id = None;
        self.admin_settings_mask_client.clear();
        self.admin_settings_mask_id.clear();
        self.admin_settings_mask_busy = false;
        self.admin_settings_mask_error = None;
        self.admin_settings_mask_token = None;
        self.admin_settings_mask_deadline = None;
        self.admin_settings_mask_confirm_busy = false;
        self.admin_settings_mask_rolled_back = false;
        self.admin_settings_exit_node.clear();
        self.admin_settings_exit_custom_mode = false;
        self.admin_settings_exit_busy = false;
        self.admin_settings_exit_error = None;
        self.admin_settings_exit_token = None;
        self.admin_settings_exit_deadline = None;
        self.admin_settings_exit_confirm_busy = false;
        self.admin_settings_exit_rolled_back = false;
    }

    /// Save the currently-displayed connection key to a `.txt` file next to
    /// the user's Downloads (falling back to their home directory). No file
    /// dialog is bundled here — this crate is kept dependency-light and
    /// already ships no `rfd`/similar — so the destination is fixed rather
    /// than user-chosen; the resulting path is shown back in the UI.
    fn save_admin_key_to_file(&mut self, key: &str) {
        let dir = dirs::download_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let path = dir.join(format!("aivpn-key-{}.txt", self.sanitized_admin_key_name()));
        match std::fs::write(&path, key) {
            Ok(()) => self.admin_key_saved_msg = Some(path.display().to_string()),
            Err(e) => self.admin_key_error = Some(format!("Failed to save key: {e}")),
        }
    }

    /// Save the currently-displayed QR PNG next to the user's Downloads
    /// (same rationale/fallback as `save_admin_key_to_file`).
    fn save_admin_qr_to_file(&mut self, png: &[u8]) {
        let dir = dirs::download_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let path = dir.join(format!("aivpn-key-{}.png", self.sanitized_admin_key_name()));
        match std::fs::write(&path, png) {
            Ok(()) => self.admin_qr_saved_msg = Some(path.display().to_string()),
            Err(e) => self.admin_qr_error = Some(format!("Failed to save QR: {e}")),
        }
    }

    /// Filesystem-safe stem derived from the client name currently shown in
    /// the key/QR viewer — falls back to "client" if the name has no
    /// alphanumeric characters at all (e.g. emoji-only names).
    fn sanitized_admin_key_name(&self) -> String {
        let safe: String = self
            .admin_key_name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .collect();
        if safe.is_empty() {
            "client".to_string()
        } else {
            safe
        }
    }

    /// G-B1: exit-node picker shared by the add/edit forms — a `ComboBox`
    /// listing "(default)", every known pool-node address
    /// (`admin::exit_node_addresses`), and "custom", instead of a bare
    /// free-text field. `value` is the form's existing `host:port` string
    /// (unchanged wire representation — still empty for default, still
    /// free text for a manual entry), `custom_mode` is the form's
    /// `admin_*_exit_custom_mode` flag (see its doc comment for why the
    /// UI needs it in addition to `admin::classify_exit_node`). No `&self`
    /// param: called as `Self::draw_exit_node_picker(...)` from both forms
    /// so the caller can pass either the add- or edit-form's fields
    /// without a disjoint-field-borrow conflict against `self`.
    fn draw_exit_node_picker(
        ui: &mut eframe::egui::Ui,
        lang: Lang,
        id_salt: &str,
        value: &mut String,
        custom_mode: &mut bool,
        known_addresses: &[String],
    ) {
        use eframe::egui;

        let choice = if *custom_mode {
            admin::ExitNodeChoice::Custom
        } else {
            admin::classify_exit_node(value, known_addresses)
        };
        let default_label = t(lang, "admin_exit_node_default");
        let custom_label = t(lang, "admin_exit_node_custom");
        let selected_text = match &choice {
            admin::ExitNodeChoice::Default => default_label.to_string(),
            admin::ExitNodeChoice::Node(addr) => addr.clone(),
            admin::ExitNodeChoice::Custom => custom_label.to_string(),
        };

        egui::ComboBox::from_id_salt(id_salt)
            .selected_text(selected_text)
            .width(230.0)
            .show_ui(ui, |ui| {
                if ui
                    .selectable_label(choice == admin::ExitNodeChoice::Default, default_label)
                    .clicked()
                {
                    value.clear();
                    *custom_mode = false;
                }
                for addr in known_addresses {
                    let is_selected =
                        matches!(&choice, admin::ExitNodeChoice::Node(a) if a == addr);
                    if ui.selectable_label(is_selected, addr).clicked() {
                        *value = addr.clone();
                        *custom_mode = false;
                    }
                }
                if ui
                    .selectable_label(choice == admin::ExitNodeChoice::Custom, custom_label)
                    .clicked()
                {
                    *custom_mode = true;
                }
            })
            .response
            .on_hover_text(t(lang, "admin_exit_node_live_hint"));

        if matches!(choice, admin::ExitNodeChoice::Custom) {
            ui.add(
                egui::TextEdit::singleline(value)
                    .desired_width(f32::INFINITY)
                    .hint_text("exit.example.com:51820"),
            );
        }
    }

    /// Client-list + add/edit forms + pool topology + audit log — drawn
    /// inline inside the main scroll area (see call site in `update()`),
    /// following the same pattern as the Recording/Diagnostics sections
    /// above it. Only ever called for `admin_role == Some(1)` (Viewer) or
    /// `Some(2)` (Admin) — see the call site's `matches!` guard — so every
    /// subsection below is reachable by both roles; `can_mutate`
    /// (`is_admin`) is threaded down to `draw_admin_clients_section` to
    /// hide the mutating controls (add/edit/enable-disable/reset-device/
    /// revoke) for a Viewer, leaving read-only access to clients/pool/audit
    /// (G-A1) — the same GET-only allowlist the server's `authorize()`
    /// already grants that role.
    fn draw_admin_panel(&mut self, ui: &mut eframe::egui::Ui, lang: Lang) {
        let is_admin = self.admin_role == Some(2);

        // GAP-G2/G1: the SSH-install wizard's entry point moved to the main
        // screen (always visible, no connection/admin role required — see
        // `update()`'s header area); the migration wizard was removed
        // entirely (web-only per GAP-G1). Nothing wizard-related belongs
        // here anymore.
        self.draw_admin_clients_section(ui, lang, is_admin);

        // ── Pool topology (B3) — Viewer + Admin ─────────────────────────
        self.draw_admin_pool_section(ui, lang);

        // ── Audit log (G-A2) — Viewer + Admin, GET-only ──────────────────
        self.draw_audit_panel(ui, lang);

        // ── Server Settings (G-A3) — Admin ONLY, unlike every section ────
        // above: this mutates server-wide/per-client heavy config, so it
        // gets no Viewer read-only rendering at all (contrast
        // `draw_admin_clients_section`'s `can_mutate` split, which still
        // shows a Viewer the client list itself, just without the mutating
        // controls).
        if is_admin {
            self.draw_admin_server_settings_section(ui, lang);
        }
    }

    /// Client list + add/edit forms + server status — visible to both
    /// Viewer and Admin (G-A1); `can_mutate` (`true` only for a confirmed
    /// Admin) gates every mutating control inside — the "+ add" button,
    /// the add/edit forms, and each row's Edit/Reset-device/Revoke
    /// buttons. "Key / QR" stays available to both: it's a plain GET the
    /// server's `authorize()` already permits a Viewer (`connection-key`
    /// is a curated GET route; QR rendering never touches the mgmt API at
    /// all — it's the client daemon's own admin-socket protocol,
    /// independent of the server-assigned role).
    fn draw_admin_clients_section(
        &mut self,
        ui: &mut eframe::egui::Ui,
        lang: Lang,
        can_mutate: bool,
    ) {
        use eframe::egui;

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(t(lang, "admin_panel")).strong());
            if !can_mutate {
                ui.label(
                    egui::RichText::new(t(lang, "admin_view_only"))
                        .size(11.0)
                        .weak(),
                );
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button(t(lang, "admin_refresh")).clicked() {
                    self.refresh_admin_clients();
                }
                if can_mutate && ui.small_button("  +  ").clicked() {
                    self.admin_show_add = true;
                    self.admin_edit_id = None;
                    self.admin_add_name.clear();
                    self.admin_add_one_time = false;
                    self.admin_add_expiry.clear();
                    self.admin_add_exit_node.clear();
                    self.admin_add_exit_custom_mode = false;
                    self.admin_add_error = None;
                }
            });
        });

        if self.admin_clients_loading {
            ui.weak(t(lang, "admin_loading"));
        }
        if let Some(err) = &self.admin_clients_error {
            ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
        }

        let frame = egui::Frame::group(ui.style())
            .inner_margin(egui::Margin::same(4i8))
            .corner_radius(egui::CornerRadius::same(4));
        frame.show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            egui::ScrollArea::vertical()
                .id_salt("admin_clients")
                .max_height(200.0)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    if self.admin_clients.is_empty() && !self.admin_clients_loading {
                        ui.weak(t(lang, "admin_no_clients"));
                    }
                    // Snapshot first: the per-row buttons below mutate
                    // `self` (busy set, dialog state), so nothing here may
                    // hold a borrow of `self.admin_clients` while that runs.
                    let clients = self.admin_clients.clone();
                    for c in &clients {
                        let busy = self.admin_busy_ids.contains(&c.id);
                        ui.group(|ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                let status_color = if c.enabled {
                                    egui::Color32::from_rgb(0x4C, 0xAF, 0x50)
                                } else {
                                    egui::Color32::from_rgb(0x78, 0x78, 0x78)
                                };
                                ui.colored_label(status_color, "●");
                                ui.label(egui::RichText::new(&c.name).strong());
                                ui.label(
                                    egui::RichText::new(format!("({})", c.role))
                                        .size(11.0)
                                        .weak(),
                                );
                                if c.one_time {
                                    ui.label(
                                        egui::RichText::new(t(lang, "admin_one_time_badge"))
                                            .size(10.0)
                                            .weak(),
                                    );
                                }
                            });
                            ui.label(egui::RichText::new(&c.vpn_ip).size(11.0).weak());
                            if let Some(exp) = &c.expires_at {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "{}: {exp}",
                                        t(lang, "admin_expires")
                                    ))
                                    .size(10.0)
                                    .weak(),
                                );
                            }
                            if let Some(exit) = &c.exit_node {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "{}: {exit}",
                                        t(lang, "admin_exit_node")
                                    ))
                                    .size(10.0)
                                    .weak(),
                                );
                            }
                            ui.horizontal(|ui| {
                                if ui
                                    .add_enabled(!busy, egui::Button::new(t(lang, "admin_key_qr")))
                                    .clicked()
                                {
                                    self.admin_key_id = Some(c.id.clone());
                                    self.admin_key_name = c.name.clone();
                                    self.admin_key_value = None;
                                    self.admin_key_error = None;
                                    self.admin_key_saved_msg = None;
                                    self.admin_key_loading = true;
                                    self.admin_qr_png = None;
                                    self.admin_qr_texture = None;
                                    self.admin_qr_error = None;
                                    self.admin_qr_saved_msg = None;
                                    admin::spawn(
                                        self.vpn.client_binary.clone(),
                                        AdminRequest::ConnectionKey { id: c.id.clone() },
                                        self.admin_tx.clone(),
                                    );
                                }
                                // G-A1: Edit/Reset-device/Revoke all mutate
                                // server state — hidden entirely for a
                                // Viewer rather than shown-disabled, same
                                // treatment as the "+ add" button above.
                                if can_mutate {
                                    if ui
                                        .add_enabled(!busy, egui::Button::new(t(lang, "edit")))
                                        .clicked()
                                    {
                                        self.admin_show_add = false;
                                        self.admin_edit_id = Some(c.id.clone());
                                        self.admin_edit_name = c.name.clone();
                                        self.admin_edit_enabled = c.enabled;
                                        self.admin_edit_expiry =
                                            c.expires_at.clone().unwrap_or_default();
                                        self.admin_edit_exit_node =
                                            c.exit_node.clone().unwrap_or_default();
                                        self.admin_edit_exit_custom_mode = false;
                                        self.admin_edit_error = None;
                                    }
                                    if ui
                                        .add_enabled(
                                            !busy,
                                            egui::Button::new(t(lang, "admin_reset_device")),
                                        )
                                        .clicked()
                                    {
                                        self.admin_busy_ids.insert(c.id.clone());
                                        admin::spawn(
                                            self.vpn.client_binary.clone(),
                                            AdminRequest::ResetDevice { id: c.id.clone() },
                                            self.admin_tx.clone(),
                                        );
                                    }
                                    let revoke_btn = egui::Button::new(
                                        egui::RichText::new(t(lang, "admin_revoke"))
                                            .color(egui::Color32::WHITE),
                                    )
                                    .fill(egui::Color32::from_rgb(0xC6, 0x28, 0x28));
                                    if ui.add_enabled(!busy, revoke_btn).clicked() {
                                        self.admin_revoke_id = Some(c.id.clone());
                                        self.admin_revoke_name = c.name.clone();
                                    }
                                }
                            });
                        });
                    }
                });
        });

        // ── Add-client form (Admin only — a mutating control) ────────────
        if can_mutate && self.admin_show_add {
            ui.add_space(4.0);
            ui.label(egui::RichText::new(t(lang, "admin_add_client")).strong());
            ui.add(
                egui::TextEdit::singleline(&mut self.admin_add_name)
                    .desired_width(f32::INFINITY)
                    .hint_text(t(lang, "key_name")),
            );
            ui.checkbox(&mut self.admin_add_one_time, t(lang, "admin_one_time"));
            ui.label(t(lang, "admin_expiry_hint"));
            ui.add(
                egui::TextEdit::singleline(&mut self.admin_add_expiry)
                    .desired_width(f32::INFINITY)
                    .hint_text("2026-08-01T00:00:00Z"),
            );
            ui.label(t(lang, "admin_exit_node"));
            Self::draw_exit_node_picker(
                ui,
                lang,
                "admin_add_exit_node_combo",
                &mut self.admin_add_exit_node,
                &mut self.admin_add_exit_custom_mode,
                &admin::exit_node_addresses(&self.admin_pool_nodes),
            );
            if let Some(err) = &self.admin_add_error {
                ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
            }
            ui.horizontal(|ui| {
                let can_save = !self.admin_add_name.trim().is_empty() && !self.admin_add_busy;
                if ui
                    .add_enabled(can_save, egui::Button::new(t(lang, "save")))
                    .clicked()
                {
                    self.admin_add_busy = true;
                    self.admin_add_error = None;
                    let form = admin::NewClientForm {
                        name: self.admin_add_name.trim().to_string(),
                        one_time: self.admin_add_one_time,
                        expires_at: self.admin_add_expiry.trim().to_string(),
                        exit_node: self.admin_add_exit_node.trim().to_string(),
                    };
                    admin::spawn(
                        self.vpn.client_binary.clone(),
                        AdminRequest::AddClient(form),
                        self.admin_tx.clone(),
                    );
                }
                if ui
                    .add_enabled(!self.admin_add_busy, egui::Button::new(t(lang, "cancel")))
                    .clicked()
                {
                    self.admin_show_add = false;
                    self.admin_add_error = None;
                }
            });
        }

        // ── Edit-client form (Admin only). `can_mutate &&` here is
        // defense-in-depth, not the primary gate — `admin_edit_id` can only
        // ever be set via the Edit button above, which is itself hidden
        // for a Viewer (e.g. guards against a role downgrade landing
        // mid-interaction).
        if can_mutate {
            if let Some(id) = self.admin_edit_id.clone() {
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(format!("{}: {}", t(lang, "edit"), self.admin_edit_name))
                        .strong(),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut self.admin_edit_name)
                        .desired_width(f32::INFINITY)
                        .hint_text(t(lang, "key_name")),
                );
                ui.checkbox(&mut self.admin_edit_enabled, t(lang, "admin_enabled"));
                ui.label(t(lang, "admin_expiry_hint"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.admin_edit_expiry)
                        .desired_width(f32::INFINITY)
                        .hint_text("2026-08-01T00:00:00Z"),
                );
                ui.label(t(lang, "admin_exit_node"));
                Self::draw_exit_node_picker(
                    ui,
                    lang,
                    "admin_edit_exit_node_combo",
                    &mut self.admin_edit_exit_node,
                    &mut self.admin_edit_exit_custom_mode,
                    &admin::exit_node_addresses(&self.admin_pool_nodes),
                );
                if let Some(err) = &self.admin_edit_error {
                    ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
                }
                ui.horizontal(|ui| {
                    let can_save = !self.admin_edit_name.trim().is_empty() && !self.admin_edit_busy;
                    if ui
                        .add_enabled(can_save, egui::Button::new(t(lang, "save")))
                        .clicked()
                    {
                        self.admin_edit_busy = true;
                        self.admin_edit_error = None;
                        let form = admin::EditClientForm {
                            id: id.clone(),
                            name: self.admin_edit_name.trim().to_string(),
                            enabled: self.admin_edit_enabled,
                            expires_at: self.admin_edit_expiry.trim().to_string(),
                            exit_node: self.admin_edit_exit_node.trim().to_string(),
                        };
                        admin::spawn(
                            self.vpn.client_binary.clone(),
                            AdminRequest::EditClient(form),
                            self.admin_tx.clone(),
                        );
                    }
                    if ui
                        .add_enabled(!self.admin_edit_busy, egui::Button::new(t(lang, "cancel")))
                        .clicked()
                    {
                        self.admin_edit_id = None;
                        self.admin_edit_error = None;
                    }
                });
            }
        }

        // ── Server status (read-only) — Viewer + Admin ───────────────────
        // A plain GET (`GET /api/v1/status`), same as the client list
        // above; nothing here mutates, so it's shown to both roles
        // unconditionally (no `can_mutate` check needed).
        egui::CollapsingHeader::new(t(lang, "admin_status_header")).show(ui, |ui| {
            if ui.button(t(lang, "admin_refresh")).clicked() {
                admin::spawn(
                    self.vpn.client_binary.clone(),
                    AdminRequest::Status,
                    self.admin_tx.clone(),
                );
            }
            if let Some(s) = &self.admin_status {
                ui.label(format!(
                    "{}: {}/{}   {}: {}",
                    t(lang, "admin_status_clients"),
                    s.clients_enabled,
                    s.clients_total,
                    t(lang, "admin_status_kernel"),
                    if s.kernel_module { "✓" } else { "✗" }
                ));
            }
        });
    }

    /// G-A2: audit-log panel — hash-chain-verified tail of the server's
    /// append-only admin audit log (`GET /api/v1/audit-log?verify=1`,
    /// `mgmt_service::audit_verify`). Only ever called from
    /// `draw_admin_panel`, itself gated on `admin_role == Some(1)` (Viewer)
    /// or `Some(2)` (Admin) — GET-only in the server's curated allowlist
    /// regardless of role, so unlike `draw_admin_clients_section` there is
    /// no `can_mutate` split here at all: nothing in this panel ever
    /// mutates anything.
    fn draw_audit_panel(&mut self, ui: &mut eframe::egui::Ui, lang: Lang) {
        use eframe::egui;

        egui::CollapsingHeader::new(t(lang, "admin_audit_panel"))
            .default_open(false)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if ui.small_button(t(lang, "admin_refresh")).clicked() {
                        self.refresh_admin_audit();
                    }
                });

                if self.admin_audit_loading {
                    ui.weak(t(lang, "admin_loading"));
                }
                if let Some(err) = &self.admin_audit_error {
                    ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
                }

                // Hash-chain verification badge — `None` (no info, e.g. an
                // older server that ignored `?verify=1`) renders nothing
                // rather than defaulting to either color.
                match self.admin_audit_verified {
                    Some(true) => {
                        ui.colored_label(
                            egui::Color32::from_rgb(0x4C, 0xAF, 0x50),
                            t(lang, "admin_audit_chain_verified"),
                        );
                    }
                    Some(false) => {
                        let idx = self
                            .admin_audit_broken_at
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "?".to_string());
                        ui.colored_label(
                            egui::Color32::from_rgb(0xEF, 0x53, 0x50),
                            format!("{} ({idx})", t(lang, "admin_audit_chain_broken")),
                        );
                    }
                    None => {}
                }

                if self.admin_audit.is_empty() && !self.admin_audit_loading {
                    ui.weak(t(lang, "admin_audit_no_entries"));
                }

                let frame = egui::Frame::group(ui.style())
                    .inner_margin(egui::Margin::same(4i8))
                    .corner_radius(egui::CornerRadius::same(4));
                frame.show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    egui::ScrollArea::vertical()
                        .id_salt("admin_audit")
                        .max_height(180.0)
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            // Oldest-first from the server; show newest-first
                            // so the most recent action is always visible
                            // without scrolling.
                            for e in self.admin_audit.iter().rev() {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "[{}] {} {} {} — {}",
                                        e.ts, e.actor, e.action, e.target, e.result
                                    ))
                                    .size(10.0)
                                    .weak(),
                                );
                            }
                        });
                });
            });
    }

    /// Pool topology view (B3) — node list + health summary, read-only.
    /// Viewer(1)+Admin(2) both reach this (see `draw_admin_panel`'s doc
    /// comment); it never issues a mutating call, matching the server's
    /// `authorize()` treating `pool/*` as GET-only for every role that can
    /// reach it at all.
    fn draw_admin_pool_section(&mut self, ui: &mut eframe::egui::Ui, lang: Lang) {
        use eframe::egui;

        egui::CollapsingHeader::new(t(lang, "admin_pool_section"))
            .default_open(false)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if ui.small_button(t(lang, "admin_refresh")).clicked() {
                        self.refresh_admin_pool();
                    }
                });

                if self.admin_pool_nodes_loading {
                    ui.weak(t(lang, "admin_loading"));
                }
                if let Some(err) = &self.admin_pool_nodes_error {
                    ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
                }

                if let Some(h) = &self.admin_pool_health {
                    ui.label(format!(
                        "{}: {}   {}: {}/{}   {}: {}/{}",
                        t(lang, "admin_pool_transport"),
                        h.transport,
                        t(lang, "admin_pool_connected"),
                        h.connected_peers,
                        h.total_nodes,
                        t(lang, "admin_pool_converged"),
                        h.converged_peers,
                        h.total_nodes,
                    ));
                    if h.partition_conflict {
                        ui.colored_label(
                            egui::Color32::from_rgb(0xFF, 0xA7, 0x26),
                            t(lang, "admin_pool_partition_conflict"),
                        );
                    }
                    if h.subnet_mismatch {
                        ui.colored_label(
                            egui::Color32::from_rgb(0xFF, 0xA7, 0x26),
                            t(lang, "admin_pool_subnet_mismatch"),
                        );
                    }
                }

                let frame = egui::Frame::group(ui.style())
                    .inner_margin(egui::Margin::same(4i8))
                    .corner_radius(egui::CornerRadius::same(4));
                frame.show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    egui::ScrollArea::vertical()
                        .id_salt("admin_pool_nodes")
                        .max_height(180.0)
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            if self.admin_pool_nodes.is_empty() && !self.admin_pool_nodes_loading {
                                ui.weak(t(lang, "admin_pool_no_nodes"));
                            }
                            for n in &self.admin_pool_nodes {
                                ui.group(|ui| {
                                    ui.set_width(ui.available_width());
                                    ui.horizontal(|ui| {
                                        let status_color = if n.connected {
                                            egui::Color32::from_rgb(0x4C, 0xAF, 0x50)
                                        } else {
                                            egui::Color32::from_rgb(0x78, 0x78, 0x78)
                                        };
                                        ui.colored_label(status_color, "●");
                                        ui.label(egui::RichText::new(&n.node_id).strong());
                                        if n.revoked {
                                            ui.colored_label(
                                                egui::Color32::from_rgb(0xEF, 0x53, 0x50),
                                                t(lang, "admin_pool_revoked"),
                                            );
                                        } else if n.verified {
                                            ui.label(
                                                egui::RichText::new(t(lang, "admin_pool_verified"))
                                                    .size(10.0)
                                                    .weak(),
                                            );
                                        }
                                    });
                                    if let Some(addr) = &n.address {
                                        ui.label(egui::RichText::new(addr).size(11.0).weak());
                                    }
                                    if let Some(ts) = n.last_seen_unix {
                                        ui.label(
                                            egui::RichText::new(format!(
                                                "{}: {}",
                                                t(lang, "admin_pool_last_seen"),
                                                format_unix_ago(ts)
                                            ))
                                            .size(10.0)
                                            .weak(),
                                        );
                                    }
                                });
                            }
                        });
                });
            });
    }

    /// G-A3: Server Settings — Admin-only apply-with-rollback for the
    /// active mask (per client — see `admin.rs`'s module-doc note on why
    /// there is no server-WIDE default mask here) and the global default
    /// exit node. Only ever called for `is_admin` (see `draw_admin_panel`'s
    /// call site) — unlike every other admin subsection, there is no
    /// Viewer-visible read-only rendering at all.
    fn draw_admin_server_settings_section(&mut self, ui: &mut eframe::egui::Ui, lang: Lang) {
        use eframe::egui;

        egui::CollapsingHeader::new(t(lang, "admin_settings_panel"))
            .default_open(false)
            .show(ui, |ui| {
                // ── Active mask (per client) ─────────────────────────────
                ui.label(egui::RichText::new(t(lang, "admin_settings_mask_section")).strong());
                if self.admin_clients.is_empty() {
                    ui.weak(t(lang, "admin_settings_mask_no_clients"));
                } else {
                    ui.horizontal(|ui| {
                        ui.label(t(lang, "admin_settings_mask_client_label"));
                        let selected_label = self
                            .admin_clients
                            .iter()
                            .find(|c| c.id == self.admin_settings_mask_client)
                            .map(|c| c.name.clone())
                            .unwrap_or_default();
                        egui::ComboBox::from_id_salt("admin_settings_mask_client_combo")
                            .selected_text(selected_label)
                            .show_ui(ui, |ui| {
                                for c in &self.admin_clients {
                                    let is_selected = self.admin_settings_mask_client == c.id;
                                    if ui.selectable_label(is_selected, &c.name).clicked() {
                                        self.admin_settings_mask_client = c.id.clone();
                                    }
                                }
                            });
                    });
                    ui.label(t(lang, "admin_settings_mask_id_label"));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.admin_settings_mask_id)
                            .desired_width(f32::INFINITY)
                            .hint_text(t(lang, "admin_settings_mask_id_hint")),
                    );
                    if let Some(err) = &self.admin_settings_mask_error {
                        ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
                    }
                    if self.admin_settings_mask_rolled_back {
                        ui.colored_label(
                            egui::Color32::from_rgb(0xFF, 0xA7, 0x26),
                            t(lang, "admin_settings_rolled_back"),
                        );
                    }
                    if let Some(token) = self.admin_settings_mask_token.clone() {
                        let confirm_clicked = Self::draw_pending_config_banner(
                            ui,
                            lang,
                            self.admin_settings_mask_deadline,
                            self.admin_settings_mask_confirm_busy,
                        );
                        if confirm_clicked {
                            self.admin_settings_mask_confirm_busy = true;
                            admin::spawn(
                                self.vpn.client_binary.clone(),
                                AdminRequest::ConfirmConfig {
                                    setting: admin::ConfigSetting::ActiveMask,
                                    token,
                                },
                                self.admin_tx.clone(),
                            );
                        }
                    } else {
                        let can_apply = !self.admin_settings_mask_client.is_empty()
                            && admin::mask_id_looks_valid(self.admin_settings_mask_id.trim())
                            && !self.admin_settings_mask_busy;
                        if ui
                            .add_enabled(
                                can_apply,
                                egui::Button::new(t(lang, "admin_settings_apply")),
                            )
                            .clicked()
                        {
                            self.admin_settings_mask_busy = true;
                            self.admin_settings_mask_error = None;
                            self.admin_settings_mask_rolled_back = false;
                            admin::spawn(
                                self.vpn.client_binary.clone(),
                                AdminRequest::ApplyActiveMask {
                                    client_id: self.admin_settings_mask_client.clone(),
                                    mask: self.admin_settings_mask_id.trim().to_string(),
                                },
                                self.admin_tx.clone(),
                            );
                        }
                    }
                }

                ui.separator();

                // ── Global default exit node (pool.exit_node) ────────────
                ui.label(egui::RichText::new(t(lang, "admin_settings_exit_section")).strong());
                ui.label(
                    egui::RichText::new(t(lang, "admin_settings_exit_restart_hint"))
                        .size(10.0)
                        .weak(),
                );
                Self::draw_global_exit_node_picker(
                    ui,
                    lang,
                    &mut self.admin_settings_exit_node,
                    &mut self.admin_settings_exit_custom_mode,
                    &admin::exit_node_addresses(&self.admin_pool_nodes),
                );
                if let Some(err) = &self.admin_settings_exit_error {
                    ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
                }
                if self.admin_settings_exit_rolled_back {
                    ui.colored_label(
                        egui::Color32::from_rgb(0xFF, 0xA7, 0x26),
                        t(lang, "admin_settings_rolled_back"),
                    );
                }
                if let Some(token) = self.admin_settings_exit_token.clone() {
                    let confirm_clicked = Self::draw_pending_config_banner(
                        ui,
                        lang,
                        self.admin_settings_exit_deadline,
                        self.admin_settings_exit_confirm_busy,
                    );
                    if confirm_clicked {
                        self.admin_settings_exit_confirm_busy = true;
                        admin::spawn(
                            self.vpn.client_binary.clone(),
                            AdminRequest::ConfirmConfig {
                                setting: admin::ConfigSetting::ExitNode,
                                token,
                            },
                            self.admin_tx.clone(),
                        );
                    }
                } else if ui
                    .add_enabled(
                        !self.admin_settings_exit_busy,
                        egui::Button::new(t(lang, "admin_settings_apply")),
                    )
                    .clicked()
                {
                    self.admin_settings_exit_busy = true;
                    self.admin_settings_exit_error = None;
                    self.admin_settings_exit_rolled_back = false;
                    let trimmed = self.admin_settings_exit_node.trim();
                    let addr = if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    };
                    admin::spawn(
                        self.vpn.client_binary.clone(),
                        AdminRequest::ApplyExitNode { addr },
                        self.admin_tx.clone(),
                    );
                }
            });
    }

    /// G-A3: shared "pending confirmation" banner — the countdown text plus
    /// the Confirm button, used identically by both the active-mask and
    /// exit-node blocks in `draw_admin_server_settings_section`. Returns
    /// `true` if Confirm was clicked this frame; no `&self`/`&mut self`
    /// param (same rationale as `draw_exit_node_picker`) so it can be
    /// called from either block without a disjoint-field-borrow conflict —
    /// the caller does the actual `admin::spawn` since which busy flag to
    /// set and which `ConfigSetting` to send differs per call site.
    fn draw_pending_config_banner(
        ui: &mut eframe::egui::Ui,
        lang: Lang,
        deadline: Option<Instant>,
        confirm_busy: bool,
    ) -> bool {
        use eframe::egui;

        // Frame-time based, not a separate timer: `update()` already runs
        // continuously while a session is Connected (egui repaints on
        // every VPN status poll), so this recomputes fresh each draw.
        let secs_left = deadline
            .map(|d| d.saturating_duration_since(Instant::now()).as_secs())
            .unwrap_or(0);
        ui.colored_label(
            egui::Color32::from_rgb(0xFF, 0xA7, 0x26),
            format!(
                "{} ({secs_left}s)",
                t(lang, "admin_settings_pending_banner")
            ),
        );
        ui.add_enabled(
            !confirm_busy,
            egui::Button::new(t(lang, "admin_settings_confirm")),
        )
        .clicked()
    }

    /// G-A3: exit-node picker for the GLOBAL default (`pool.exit_node`) —
    /// same `ComboBox`-over-known-pool-addresses-plus-custom shape as
    /// `draw_exit_node_picker`, but with its own "no override" label
    /// ("(none)" rather than "(default)" — there IS no higher-level
    /// default to fall back to for this one, clearing it disables global
    /// exit routing entirely) and no live-apply hover hint (the restart
    /// caveat is already shown as a persistent label above the picker in
    /// `draw_admin_server_settings_section`, unlike the per-client picker
    /// which has no equivalent always-visible caption).
    fn draw_global_exit_node_picker(
        ui: &mut eframe::egui::Ui,
        lang: Lang,
        value: &mut String,
        custom_mode: &mut bool,
        known_addresses: &[String],
    ) {
        use eframe::egui;

        let choice = if *custom_mode {
            admin::ExitNodeChoice::Custom
        } else {
            admin::classify_exit_node(value, known_addresses)
        };
        let none_label = t(lang, "admin_settings_exit_none");
        let custom_label = t(lang, "admin_exit_node_custom");
        let selected_text = match &choice {
            admin::ExitNodeChoice::Default => none_label.to_string(),
            admin::ExitNodeChoice::Node(addr) => addr.clone(),
            admin::ExitNodeChoice::Custom => custom_label.to_string(),
        };

        egui::ComboBox::from_id_salt("admin_settings_exit_node_combo")
            .selected_text(selected_text)
            .width(230.0)
            .show_ui(ui, |ui| {
                if ui
                    .selectable_label(choice == admin::ExitNodeChoice::Default, none_label)
                    .clicked()
                {
                    value.clear();
                    *custom_mode = false;
                }
                for addr in known_addresses {
                    let is_selected =
                        matches!(&choice, admin::ExitNodeChoice::Node(a) if a == addr);
                    if ui.selectable_label(is_selected, addr).clicked() {
                        *value = addr.clone();
                        *custom_mode = false;
                    }
                }
                if ui
                    .selectable_label(choice == admin::ExitNodeChoice::Custom, custom_label)
                    .clicked()
                {
                    *custom_mode = true;
                }
            });

        if matches!(choice, admin::ExitNodeChoice::Custom) {
            ui.add(
                egui::TextEdit::singleline(value)
                    .desired_width(f32::INFINITY)
                    .hint_text("exit.example.com:51820"),
            );
        }
    }

    /// Connection-key / QR viewer window and the revoke-confirmation modal —
    /// both are separate top-level egui containers, so they're drawn once
    /// per frame from `update()` alongside the existing key add/edit
    /// viewport dialog, rather than nested inside `draw_admin_panel`'s
    /// `CentralPanel` closure.
    fn draw_admin_extras(&mut self, ctx: &eframe::egui::Context, lang: Lang) {
        use eframe::egui;

        if self.admin_key_id.is_some() {
            let mut open = true;
            let title = format!("{}: {}", t(lang, "admin_key_qr"), self.admin_key_name);
            egui::Window::new(title)
                .id(egui::Id::new("admin_key_window"))
                .collapsible(false)
                .resizable(true)
                .open(&mut open)
                .show(ctx, |ui| {
                    if self.admin_key_loading {
                        ui.weak(t(lang, "admin_loading"));
                    }
                    if let Some(err) = &self.admin_key_error {
                        ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
                    }
                    if let Some(key) = self.admin_key_value.clone() {
                        let mut display_key = key.clone();
                        ui.add(
                            egui::TextEdit::multiline(&mut display_key)
                                .desired_width(360.0)
                                .desired_rows(3)
                                .font(egui::TextStyle::Monospace)
                                .interactive(false),
                        );
                        ui.horizontal(|ui| {
                            if ui.button(t(lang, "copy")).clicked() {
                                ctx.copy_text(key.clone());
                            }
                            if ui.button(t(lang, "admin_save_key_file")).clicked() {
                                self.save_admin_key_to_file(&key);
                            }
                            if !self.admin_qr_loading && self.admin_qr_png.is_none() {
                                if ui.button(t(lang, "admin_show_qr")).clicked() {
                                    self.admin_qr_loading = true;
                                    self.admin_qr_error = None;
                                    let id = self.admin_key_id.clone().unwrap_or_default();
                                    admin::spawn(
                                        self.vpn.client_binary.clone(),
                                        AdminRequest::Qr {
                                            id,
                                            text: key.clone(),
                                        },
                                        self.admin_tx.clone(),
                                    );
                                }
                            }
                        });
                        if let Some(saved) = &self.admin_key_saved_msg {
                            ui.label(
                                egui::RichText::new(format!(
                                    "{}: {saved}",
                                    t(lang, "admin_saved_to")
                                ))
                                .size(11.0)
                                .weak(),
                            );
                        }
                    }
                    if self.admin_qr_loading {
                        ui.weak(t(lang, "admin_loading"));
                    }
                    if let Some(err) = &self.admin_qr_error {
                        ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
                    }
                    if let Some(png) = self.admin_qr_png.clone() {
                        let texture = self.admin_qr_texture.get_or_insert_with(|| {
                            let (rgba, w, h) = decode_png_rgba(&png);
                            ctx.load_texture(
                                "admin-qr",
                                egui::ColorImage::from_rgba_unmultiplied(
                                    [w as usize, h as usize],
                                    &rgba,
                                ),
                                egui::TextureOptions::default(),
                            )
                        });
                        ui.image((texture.id(), texture.size_vec2()));
                        if ui.button(t(lang, "admin_save_qr_file")).clicked() {
                            self.save_admin_qr_to_file(&png);
                        }
                        if let Some(saved) = &self.admin_qr_saved_msg {
                            ui.label(
                                egui::RichText::new(format!(
                                    "{}: {saved}",
                                    t(lang, "admin_saved_to")
                                ))
                                .size(11.0)
                                .weak(),
                            );
                        }
                    }
                });
            if !open {
                self.admin_key_id = None;
                self.admin_key_value = None;
                self.admin_qr_png = None;
                self.admin_qr_texture = None;
            }
        }

        if let Some(id) = self.admin_revoke_id.clone() {
            let name = self.admin_revoke_name.clone();
            let busy = self.admin_busy_ids.contains(&id);
            let resp = egui::Modal::new(egui::Id::new("admin_revoke_modal")).show(ctx, |ui| {
                ui.set_width(300.0);
                ui.label(egui::RichText::new(t(lang, "admin_revoke_confirm_title")).strong());
                ui.label(format!(
                    "{} \u{201c}{name}\u{201d}?",
                    t(lang, "admin_revoke_confirm_body")
                ));
                ui.label(
                    egui::RichText::new(t(lang, "admin_revoke_confirm_warn"))
                        .size(11.0)
                        .weak(),
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(!busy, egui::Button::new(t(lang, "cancel")))
                        .clicked()
                    {
                        self.admin_revoke_id = None;
                    }
                    let revoke_btn = egui::Button::new(
                        egui::RichText::new(t(lang, "admin_revoke")).color(egui::Color32::WHITE),
                    )
                    .fill(egui::Color32::from_rgb(0xC6, 0x28, 0x28));
                    if ui.add_enabled(!busy, revoke_btn).clicked() {
                        self.admin_busy_ids.insert(id.clone());
                        admin::spawn(
                            self.vpn.client_binary.clone(),
                            AdminRequest::RevokeClient { id: id.clone() },
                            self.admin_tx.clone(),
                        );
                    }
                });
            });
            if resp.should_close() {
                self.admin_revoke_id = None;
            }
        }
    }

    // ── SSH server-install wizard (C3) — separate top-level window, same
    // rationale as `draw_admin_extras`'s viewport dialogs. ────────────────

    fn draw_ssh_install_window(&mut self, ctx: &eframe::egui::Context, lang: Lang) {
        use eframe::egui;

        if !self.ssh_wizard_open {
            return;
        }
        let mut open = true;
        egui::Window::new(t(lang, "ssh_wizard_title"))
            .id(egui::Id::new("ssh_install_wizard"))
            .collapsible(false)
            .resizable(true)
            .default_width(440.0)
            .open(&mut open)
            .show(ctx, |ui| match self.ssh_wizard_stage {
                SshWizardStage::Form | SshWizardStage::Confirmed => {
                    self.draw_ssh_wizard_form(ui, lang)
                }
                SshWizardStage::Installing | SshWizardStage::Done => {
                    self.draw_ssh_wizard_progress(ui, lang)
                }
            });
        if !open {
            self.close_ssh_wizard();
        }

        if self.ssh_show_script {
            self.draw_ssh_script_window(ctx, lang);
        }
    }

    fn draw_ssh_wizard_form(&mut self, ui: &mut eframe::egui::Ui, lang: Lang) {
        use eframe::egui;

        egui::Grid::new("ssh_wizard_target_grid")
            .num_columns(2)
            .spacing([8.0, 4.0])
            .show(ui, |ui| {
                ui.label(t(lang, "ssh_host"));
                ui.text_edit_singleline(&mut self.ssh_host);
                ui.end_row();
                ui.label(t(lang, "ssh_port"));
                ui.text_edit_singleline(&mut self.ssh_port);
                ui.end_row();
                ui.label(t(lang, "ssh_user"));
                ui.text_edit_singleline(&mut self.ssh_user);
                ui.end_row();
            });

        ui.separator();
        ui.horizontal(|ui| {
            ui.radio_value(
                &mut self.ssh_auth_key_mode,
                false,
                t(lang, "ssh_auth_password"),
            );
            ui.radio_value(&mut self.ssh_auth_key_mode, true, t(lang, "ssh_auth_key"));
        });
        if self.ssh_auth_key_mode {
            ui.horizontal(|ui| {
                ui.label(t(lang, "ssh_key_path"));
                ui.text_edit_singleline(&mut self.ssh_key_path);
            });
            ui.horizontal(|ui| {
                ui.label(t(lang, "ssh_key_passphrase"));
                ui.add(egui::TextEdit::singleline(&mut self.ssh_key_passphrase).password(true));
            });
        } else {
            ui.horizontal(|ui| {
                ui.label(t(lang, "ssh_password"));
                ui.add(egui::TextEdit::singleline(&mut self.ssh_password).password(true));
            });
        }

        // GAP-G3: server binary source — default(GitHub Releases)/URL/local
        // file, mirrors ssh_install_cmd.rs's RunArgs --binary-file/
        // --binary-url flags via install_wizard::BinarySource (see
        // start_ssh_install's mapping).
        ui.separator();
        ui.label(egui::RichText::new(t(lang, "ssh_binary_source_label")).strong());
        ui.horizontal(|ui| {
            ui.radio_value(
                &mut self.ssh_binary_source_choice,
                SshBinarySourceChoice::Default,
                t(lang, "ssh_binary_source_default"),
            );
            ui.radio_value(
                &mut self.ssh_binary_source_choice,
                SshBinarySourceChoice::Url,
                t(lang, "ssh_binary_source_url"),
            );
            ui.radio_value(
                &mut self.ssh_binary_source_choice,
                SshBinarySourceChoice::LocalFile,
                t(lang, "ssh_binary_source_file"),
            );
        });
        match self.ssh_binary_source_choice {
            SshBinarySourceChoice::Default => {}
            SshBinarySourceChoice::Url => {
                ui.horizontal(|ui| {
                    ui.label(t(lang, "ssh_binary_url_label"));
                    ui.text_edit_singleline(&mut self.ssh_binary_url);
                });
            }
            SshBinarySourceChoice::LocalFile => {
                ui.horizontal(|ui| {
                    ui.label(t(lang, "ssh_binary_file_label"));
                    ui.text_edit_singleline(&mut self.ssh_binary_file_path);
                });
            }
        }

        ui.separator();
        ui.checkbox(&mut self.ssh_mode_docker, t(lang, "ssh_mode_docker"));
        ui.horizontal(|ui| {
            ui.label(t(lang, "ssh_server_ip"));
            ui.text_edit_singleline(&mut self.ssh_server_ip);
        });
        ui.horizontal(|ui| {
            ui.label(t(lang, "ssh_server_port"));
            ui.text_edit_singleline(&mut self.ssh_server_port);
        });
        ui.checkbox(&mut self.ssh_bind_device, t(lang, "ssh_bind_device"));

        ui.separator();
        ui.horizontal(|ui| {
            if ui.button(t(lang, "ssh_show_script_btn")).clicked() {
                self.ssh_show_script = true;
                if self.ssh_script_text.is_none() && !self.ssh_script_loading {
                    self.start_fetch_script();
                }
            }
            let probe_enabled = !self.ssh_probe_busy && !self.ssh_host.trim().is_empty();
            if ui
                .add_enabled(probe_enabled, egui::Button::new(t(lang, "ssh_probe_btn")))
                .clicked()
            {
                self.start_ssh_probe();
            }
        });
        if self.ssh_probe_busy {
            ui.weak(t(lang, "admin_loading"));
        }
        if let Some(err) = &self.ssh_probe_error {
            ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
        }

        if let Some(fp) = self.ssh_fingerprint.clone() {
            ui.separator();
            ui.label(egui::RichText::new(t(lang, "ssh_fingerprint_label")).strong());
            ui.label(egui::RichText::new(&fp).font(egui::TextStyle::Monospace));
            ui.checkbox(&mut self.ssh_trusted, t(lang, "ssh_trust_checkbox"));

            let auth_ready = if self.ssh_auth_key_mode {
                !self.ssh_key_path.trim().is_empty()
            } else {
                !self.ssh_password.is_empty()
            };
            let install_enabled = self.ssh_trusted && auth_ready;
            if ui
                .add_enabled(
                    install_enabled,
                    egui::Button::new(t(lang, "ssh_install_btn")),
                )
                .clicked()
            {
                self.start_ssh_install();
            }
        }
    }

    fn draw_ssh_wizard_progress(&mut self, ui: &mut eframe::egui::Ui, lang: Lang) {
        use eframe::egui;

        if self.ssh_install_running {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(t(lang, "ssh_installing"));
            });
        }

        egui::Frame::group(ui.style())
            .inner_margin(egui::Margin::same(4i8))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                egui::ScrollArea::vertical()
                    .id_salt("ssh_install_log")
                    .max_height(260.0)
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        for line in &self.ssh_install_log {
                            match line {
                                install_wizard::InstallLine::Raw(s) => {
                                    ui.label(
                                        egui::RichText::new(s)
                                            .font(egui::TextStyle::Monospace)
                                            .size(11.0),
                                    );
                                }
                                install_wizard::InstallLine::Marker {
                                    step,
                                    status,
                                    code,
                                    msg,
                                    ..
                                } => {
                                    // Internal-only synthetic marker — see
                                    // gui_process_exit_line's doc comment in
                                    // install_wizard.rs; never shown raw.
                                    if step == "gui_process" {
                                        continue;
                                    }
                                    let color = match status.as_str() {
                                        "ok" => egui::Color32::from_rgb(0x4C, 0xAF, 0x50),
                                        "error" => egui::Color32::from_rgb(0xEF, 0x53, 0x50),
                                        _ => egui::Color32::from_rgb(0xFF, 0xA7, 0x26),
                                    };
                                    let mut text = format!("[{step}] {status}");
                                    if let Some(c) = code {
                                        text.push_str(&format!(" ({c})"));
                                    }
                                    if let Some(m) = msg {
                                        text.push_str(&format!(": {m}"));
                                    }
                                    ui.colored_label(color, egui::RichText::new(text).size(11.0));
                                }
                            }
                        }
                    });
            });

        if let Some(ok) = self.ssh_install_done_ok {
            ui.separator();
            if ok {
                ui.colored_label(
                    egui::Color32::from_rgb(0x4C, 0xAF, 0x50),
                    t(lang, "ssh_install_done_ok"),
                );
            } else {
                ui.colored_label(
                    egui::Color32::from_rgb(0xEF, 0x53, 0x50),
                    t(lang, "ssh_install_done_error"),
                );
            }
            // G-C1: the profile is now imported automatically the moment
            // the terminal marker's key arrives (`poll_ssh_install`) —
            // no manual click required. This just confirms it happened
            // and shows the key, mirroring the admin panel's read-only
            // key viewer (`admin_key_value` above). `!ssh_import_done`
            // only remains reachable if the auto-import itself failed
            // (e.g. `KeyStorage::add_key` rejected it) — that path keeps
            // the old manual button as a retry rather than stranding the
            // key with no way to add it.
            if let Some(key) = self.ssh_install_connection_key.clone() {
                ui.separator();
                if self.ssh_import_done {
                    ui.colored_label(
                        egui::Color32::from_rgb(0x4C, 0xAF, 0x50),
                        t(lang, "ssh_import_profile_done"),
                    );
                    let mut display_key = key.clone();
                    ui.add(
                        egui::TextEdit::multiline(&mut display_key)
                            .desired_width(360.0)
                            .desired_rows(3)
                            .font(egui::TextStyle::Monospace)
                            .interactive(false),
                    );
                    if ui.button(t(lang, "copy")).clicked() {
                        ui.ctx().copy_text(key);
                    }
                } else {
                    ui.colored_label(
                        egui::Color32::from_rgb(0xEF, 0x53, 0x50),
                        t(lang, "ssh_import_profile_retry_hint"),
                    );
                    if ui.button(t(lang, "ssh_import_profile_btn")).clicked() {
                        self.import_ssh_install_key();
                    }
                }
            }
            if ui.button(t(lang, "ssh_wizard_close_btn")).clicked() {
                self.close_ssh_wizard();
            }
        }
    }

    /// "Show script" review window — text + sha256, independent of the
    /// main wizard window's open/close state so it can stay open while the
    /// form behind it is edited.
    fn draw_ssh_script_window(&mut self, ctx: &eframe::egui::Context, lang: Lang) {
        use eframe::egui;

        let mut open = true;
        egui::Window::new(t(lang, "ssh_script_title"))
            .id(egui::Id::new("ssh_install_script_window"))
            .collapsible(false)
            .resizable(true)
            .default_width(560.0)
            .default_height(420.0)
            .open(&mut open)
            .show(ctx, |ui| {
                if self.ssh_script_loading {
                    ui.weak(t(lang, "admin_loading"));
                }
                if let Some(err) = &self.ssh_script_error {
                    ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), err);
                }
                if let Some(sha256) = &self.ssh_script_sha256 {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(t(lang, "ssh_script_sha256")).strong());
                        ui.label(egui::RichText::new(sha256).font(egui::TextStyle::Monospace));
                        if ui.small_button(t(lang, "copy")).clicked() {
                            ctx.copy_text(sha256.clone());
                        }
                    });
                }
                if let Some(script) = self.ssh_script_text.clone() {
                    let mut display = script;
                    egui::ScrollArea::vertical()
                        .id_salt("ssh_script_text")
                        .max_height(320.0)
                        .show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut display)
                                    .desired_width(f32::INFINITY)
                                    .font(egui::TextStyle::Monospace)
                                    .interactive(false),
                            );
                        });
                }
            });
        if !open {
            self.ssh_show_script = false;
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

// ── Autostart (Windows registry) ───────────────────────────────────────────

#[cfg(windows)]
fn set_autostart(enable: bool) {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_path = r"Software\Microsoft\Windows\CurrentVersion\Run";
    if let Ok((run, _)) = hkcu.create_subkey(run_path) {
        if enable {
            if let Ok(exe) = std::env::current_exe() {
                // LOW-6: write the path as an OsString (winreg encodes it to
                // UTF-16 losslessly) — to_string_lossy would corrupt a path
                // containing unpaired surrogates and register a broken
                // autostart command.
                let mut quoted = std::ffi::OsString::from("\"");
                quoted.push(exe.as_os_str());
                quoted.push("\"");
                let _ = run.set_value("AIVPN", &quoted);
            }
        } else {
            let _ = run.delete_value("AIVPN");
        }
    }
}

#[cfg(not(windows))]
fn set_autostart(_enable: bool) {}

#[cfg(windows)]
impl eframe::App for AivpnApp {
    fn update(&mut self, ctx: &eframe::egui::Context, _frame: &mut eframe::Frame) {
        use eframe::egui;
        use std::sync::atomic::Ordering::Relaxed;

        self.tick();

        // Sync window_visible from background tray thread (tray_show_flag set by bg thread
        // so window restore works even when SW_HIDE pauses the eframe update loop).
        if self.tray_show_flag.swap(false, Relaxed) {
            self.window_visible = true;
        }

        // Handle tray menu actions signalled from the background thread.
        // MenuEvent is drained in init_tray() bg thread so it works even when window is hidden.
        if self.quit_requested.swap(false, Relaxed) {
            self.tray_thread_shutdown.store(true, Relaxed);
            self.tray = None;
            self.vpn.disconnect();
            self.settings.save();
            self.quitting = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        if self.connect_requested.swap(false, Relaxed) {
            self.window_visible = true;
            self.do_connect();
        }

        self.update_tray();

        let lang = self.settings.lang;
        let is_connected = self.vpn.is_connected();
        let is_busy = self.vpn.is_busy();
        let conn_state = self.vpn.state();
        let bytes_rx = self.vpn.stats().bytes_received;
        let bytes_tx = self.vpn.stats().bytes_sent;
        let quality = self.vpn.stats().quality_score;
        // HIGH #2 (client parity): the live, possibly server-re-homed VPN IP
        // from traffic.stats (`ip:` key) takes priority over the connection
        // key's static, one-time-parsed IP — falls back to the latter only
        // before the client's first stats write of the session arrives.
        let vpn_ip_display: Option<String> = self.vpn.stats().vpn_ip.clone().or_else(|| {
            self.keys
                .selected_key()
                .map(|k| k.vpn_ip.clone())
                .filter(|s| !s.is_empty())
        });
        // Uptime comes from the client's session epoch (`since:` in the stats
        // file, wall-clock now − since): on a silent in-child reconnect the
        // epoch changes and the stopwatch resets together with the per-session
        // counters. The GUI-local Instant is only a fallback for old-format
        // clients that don't write `since` (and the pre-first-write window).
        let uptime = self
            .vpn
            .session_since_ms()
            .map(|since_ms| {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                now_ms.saturating_sub(since_ms) / 1000
            })
            .or_else(|| self.connected_since.map(|t| t.elapsed().as_secs()))
            .unwrap_or(0);

        let status_text = match conn_state {
            ConnectionState::Disconnected => t(lang, "disconnected").to_string(),
            ConnectionState::Connecting => t(lang, "connecting").to_string(),
            ConnectionState::Connected => {
                let h = uptime / 3600;
                let m = (uptime % 3600) / 60;
                let s = uptime % 60;
                if h > 0 {
                    format!("{} {}:{:02}:{:02}", t(lang, "connected"), h, m, s)
                } else {
                    format!("{} {}:{:02}", t(lang, "connected"), m, s)
                }
            }
            ConnectionState::Disconnecting => t(lang, "disconnecting").to_string(),
        };

        let no_traffic_warn = is_connected && uptime > 30 && bytes_rx == 0 && bytes_tx == 0;
        // last_error (specific cause from stall detection) takes precedence over the generic
        // no_traffic_warn so the user sees "WintunCreateAdapter failed" not "No traffic detected".
        let error_display: Option<String> = if let Some(e) = &self.error_msg {
            Some(e.clone())
        } else if let Some(e) = self.vpn.last_error.clone().filter(|e| !e.is_empty()) {
            Some(e)
        } else if no_traffic_warn {
            Some(t(lang, "no_traffic_warn").to_string())
        } else {
            None
        };

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    // ── Header ─────────────────────────────────────────────────────
                    ui.horizontal(|ui| {
                        let dot_color = match conn_state {
                            ConnectionState::Connected => egui::Color32::from_rgb(0x4C, 0xAF, 0x50),
                            ConnectionState::Connecting | ConnectionState::Disconnecting => {
                                egui::Color32::from_rgb(0xFF, 0xA7, 0x26)
                            }
                            ConnectionState::Disconnected => {
                                egui::Color32::from_rgb(0x78, 0x78, 0x78)
                            }
                        };
                        let (dot_rect, _) =
                            ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
                        ui.painter()
                            .circle_filled(dot_rect.center(), 5.0, dot_color);
                        ui.label(egui::RichText::new("AIVPN").size(17.0).strong());

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button(lang.label()).clicked() {
                                self.settings.lang = match self.settings.lang {
                                    Lang::En => Lang::Ru,
                                    Lang::Ru => Lang::En,
                                };
                                self.dirty_at.get_or_insert(Instant::now());
                            }
                            let theme_lbl = if self.settings.dark_mode {
                                "☀"
                            } else {
                                "🌙"
                            };
                            if ui.small_button(theme_lbl).clicked() {
                                self.settings.dark_mode = !self.settings.dark_mode;
                                self.dirty_at.get_or_insert(Instant::now());
                                apply_theme_to_ctx(ctx, self.settings.dark_mode);
                            }
                            ui.label(
                                egui::RichText::new(format!("v{APP_VERSION}"))
                                    .size(11.0)
                                    .weak(),
                            );
                        });
                    });

                    ui.separator();

                    // ── Status + Connect card ─────────────────────────────────────
                    let status_color = match conn_state {
                        ConnectionState::Connected => egui::Color32::from_rgb(0x4C, 0xAF, 0x50),
                        ConnectionState::Connecting | ConnectionState::Disconnecting => {
                            egui::Color32::from_rgb(0xFF, 0xA7, 0x26)
                        }
                        ConnectionState::Disconnected => ui.visuals().text_color(),
                    };
                    let btn_text = if is_connected || is_busy {
                        t(lang, "disconnect")
                    } else {
                        t(lang, "connect")
                    };
                    let btn_color = if is_connected || is_busy {
                        egui::Color32::from_rgb(0xC6, 0x28, 0x28)
                    } else {
                        egui::Color32::from_rgb(0x19, 0x76, 0xD2)
                    };
                    let card_bg = if self.settings.dark_mode {
                        egui::Color32::from_rgb(0x26, 0x26, 0x30)
                    } else {
                        egui::Color32::from_rgb(0xEA, 0xEA, 0xF4)
                    };
                    egui::Frame::new()
                        .fill(card_bg)
                        .corner_radius(egui::CornerRadius::same(10))
                        .inner_margin(egui::Margin::symmetric(12i8, 10i8))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(&status_text)
                                        .color(status_color)
                                        .size(15.0),
                                );
                                if is_connected {
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "↑ {}",
                                                    format_bytes(bytes_tx)
                                                ))
                                                .size(11.0)
                                                .weak(),
                                            );
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "↓ {}",
                                                    format_bytes(bytes_rx)
                                                ))
                                                .size(11.0)
                                                .weak(),
                                            );
                                        },
                                    );
                                }
                            });
                            // Show which profile will be connected
                            if let Some(name) = self.keys.selected_key().map(|k| k.name.clone()) {
                                ui.label(
                                    egui::RichText::new(format!("→ {name}")).size(11.0).weak(),
                                );
                            }
                            // HIGH #2 (client parity): show the assigned VPN
                            // IP once connected, live-updated across a pool
                            // re-home (see vpn_ip_display above).
                            if is_connected {
                                if let Some(ip) = &vpn_ip_display {
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "{}: {ip}",
                                            t(lang, "vpn_ip_label")
                                        ))
                                        .size(11.0)
                                        .weak(),
                                    );
                                }
                            }
                            // 3c: bootstrap-fallback indicator — live value
                            // from traffic.stats `fallback:` key (this GUI's
                            // child stdout is Stdio::null(), so the stats
                            // file is the only channel; see TrafficStats::fallback).
                            if (is_connected || is_busy) && self.vpn.stats().fallback {
                                ui.label(
                                    egui::RichText::new(t(lang, "bootstrap_fallback_label"))
                                        .size(11.0)
                                        .color(egui::Color32::from_rgb(0xFF, 0xA7, 0x26)),
                                );
                            }
                            // Warn when disconnected and no key is available/selected
                            if !is_connected && !is_busy {
                                let warn_color = egui::Color32::from_rgb(0xFF, 0xA7, 0x26);
                                if self.keys.keys.is_empty() {
                                    ui.label(
                                        egui::RichText::new(t(lang, "no_keys"))
                                            .color(warn_color)
                                            .size(11.0),
                                    );
                                } else if self.keys.selected_key().is_none() {
                                    ui.label(
                                        egui::RichText::new(t(lang, "no_key_selected"))
                                            .color(warn_color)
                                            .size(11.0),
                                    );
                                }
                            }
                            ui.add_space(4.0);
                            let can_connect = is_connected || self.keys.selected_key().is_some();
                            let btn = egui::Button::new(
                                egui::RichText::new(btn_text)
                                    .color(egui::Color32::WHITE)
                                    .size(15.0)
                                    .strong(),
                            )
                            .fill(btn_color)
                            .min_size(egui::vec2(ui.available_width(), 38.0));
                            if ui.add_enabled(!is_busy && can_connect, btn).clicked() {
                                self.do_connect();
                            }
                        });

                    ui.add_space(4.0);
                    ui.separator();

                    // ── GAP-G2: SSH server-install wizard entry point ────────────────
                    // Always visible on the main screen — no connection and no admin
                    // role required, since installing a brand-new server ("first
                    // server from scratch") is a base scenario, not a management
                    // action on an already-running one (that flow, e.g. client
                    // management, stays gated behind draw_admin_panel/is_admin).
                    ui.horizontal(|ui| {
                        if ui.small_button(t(lang, "ssh_wizard_open_btn")).clicked() {
                            self.ssh_wizard_open = true;
                        }
                    });

                    ui.add_space(4.0);
                    ui.separator();

                    // ── Connection keys ────────────────────────────────────────────
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(t(lang, "keys")).strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("  +  ").clicked() {
                                self.dlg_name.clear();
                                self.dlg_key.clear();
                                self.dlg_full_tunnel = false;
                                self.dlg_proxy = false;
                                self.dlg_proxy_addr.clear();
                                self.dlg_exclude_routes.clear();
                                self.dlg_include_routes.clear();
                                self.dlg_mtls_cert.clear();
                                self.dlg_error = None;
                                self.editing_idx = None;
                                self.show_dialog = true;
                            }
                        });
                    });

                    let frame = egui::Frame::group(ui.style())
                        .inner_margin(egui::Margin::same(4i8))
                        .corner_radius(egui::CornerRadius::same(4));
                    frame.show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        egui::ScrollArea::vertical()
                            .id_salt("keys")
                            .max_height(90.0)
                            .show(ui, |ui: &mut egui::Ui| {
                                ui.set_width(ui.available_width());
                                // Defer deletion until after the loop: calling remove_key mid-loop
                                // shrinks the Vec while `for i in 0..len` keeps the original end,
                                // so a later iteration indexes out of bounds and panics (triggered
                                // by deleting any non-last key via the right-click menu).
                                let mut delete_idx: Option<usize> = None;
                                if self.keys.keys.is_empty() {
                                    ui.weak(t(lang, "no_keys"));
                                } else {
                                    for i in 0..self.keys.keys.len() {
                                        let name = self.keys.keys[i].name.clone();
                                        let selected = self.keys.selected == Some(i);
                                        let resp = ui.selectable_label(selected, &name);
                                        if resp.clicked() {
                                            self.keys.selected = Some(i);
                                        }
                                        resp.context_menu(|ui| {
                                            if ui.button(t(lang, "edit")).clicked() {
                                                let ck = &self.keys.keys[i];
                                                self.dlg_name = ck.name.clone();
                                                self.dlg_key = ck.key.clone();
                                                self.dlg_full_tunnel = ck.full_tunnel;
                                                self.dlg_proxy = ck.proxy_listen.is_some();
                                                self.dlg_proxy_addr =
                                                    ck.proxy_listen.clone().unwrap_or_default();
                                                self.dlg_exclude_routes =
                                                    ck.exclude_routes.join("\n");
                                                self.dlg_include_routes =
                                                    ck.include_routes.join("\n");
                                                self.dlg_mtls_cert =
                                                    ck.mtls_cert_path.clone().unwrap_or_default();
                                                self.dlg_error = None;
                                                self.editing_idx = Some(i);
                                                self.show_dialog = true;
                                                ui.close_menu();
                                            }
                                            ui.add_enabled_ui(!is_connected, |ui| {
                                                if ui.button(t(lang, "delete")).clicked() {
                                                    delete_idx = Some(i);
                                                    ui.close_menu();
                                                }
                                            });
                                        });
                                    }
                                }
                                if let Some(i) = delete_idx {
                                    self.keys.remove_key(i);
                                }
                            });
                    });

                    ui.horizontal(|ui| {
                        let sel = self.keys.selected;
                        if ui
                            .add_enabled(sel.is_some(), egui::Button::new(t(lang, "edit")))
                            .clicked()
                        {
                            if let Some(idx) = sel {
                                let ck = &self.keys.keys[idx];
                                self.dlg_name = ck.name.clone();
                                self.dlg_key = ck.key.clone();
                                self.dlg_full_tunnel = ck.full_tunnel;
                                self.dlg_proxy = ck.proxy_listen.is_some();
                                self.dlg_proxy_addr = ck.proxy_listen.clone().unwrap_or_default();
                                self.dlg_exclude_routes = ck.exclude_routes.join("\n");
                                self.dlg_include_routes = ck.include_routes.join("\n");
                                self.dlg_mtls_cert = ck.mtls_cert_path.clone().unwrap_or_default();
                                self.dlg_error = None;
                                self.editing_idx = Some(idx);
                                self.show_dialog = true;
                            }
                        }
                        if ui
                            .add_enabled(
                                sel.is_some() && !is_connected,
                                egui::Button::new(t(lang, "delete")),
                            )
                            .clicked()
                        {
                            if let Some(idx) = sel {
                                self.keys.remove_key(idx);
                            }
                        }
                    });

                    ui.separator();

                    // ── Traffic indicators (quality / FEC / uptime) ────────────────
                    ui.horizontal(|ui| {
                        if is_connected && quality > 0 {
                            let qc = if quality >= 70 {
                                egui::Color32::from_rgb(0x4C, 0xAF, 0x50)
                            } else if quality >= 40 {
                                egui::Color32::from_rgb(0xFF, 0xA7, 0x26)
                            } else {
                                egui::Color32::from_rgb(0xEF, 0x53, 0x50)
                            };
                            ui.label(
                                egui::RichText::new(format!("Q:{quality}%"))
                                    .color(qc)
                                    .size(13.0),
                            );
                        }
                        let sal = self.vpn.stats().server_adaptive_level;
                        if is_connected && (sal >= 2 || self.settings.adaptive_level >= 2) {
                            ui.label(
                                egui::RichText::new("FEC")
                                    .color(egui::Color32::from_rgb(0x42, 0xA5, 0xF5))
                                    .size(13.0)
                                    .strong(),
                            );
                        }
                    });

                    ui.separator();

                    // ── Recording (only when server reports capability) ────────────
                    if is_connected
                        && self.vpn.recording_capability_known
                        && self.vpn.can_record_masks
                    {
                        let is_rec = self.vpn.is_recording();
                        let rec_busy = self.vpn.recording_button_disabled();
                        let rec_status: Option<&'static str> = match &self.vpn.recording_state {
                            RecordingState::Starting(_) => Some(t(lang, "recording_starting")),
                            RecordingState::Recording(_) => Some(t(lang, "recording_active")),
                            RecordingState::Stopping(_) => Some(t(lang, "recording_stopping")),
                            RecordingState::Analyzing(_) => Some(t(lang, "recording_analyzing")),
                            RecordingState::Success(_, _) => Some(t(lang, "recording_success")),
                            RecordingState::Failed(_, _) => Some(t(lang, "recording_failed")),
                            RecordingState::Idle => None,
                        };
                        let rec_result = self.vpn.last_recording_result.clone();
                        ui.horizontal(|ui| {
                            if is_rec {
                                let stop_btn = egui::Button::new(
                                    egui::RichText::new(t(lang, "stop_recording"))
                                        .color(egui::Color32::WHITE),
                                )
                                .fill(egui::Color32::from_rgb(0xE5, 0x39, 0x35));
                                if ui.add_enabled(!rec_busy, stop_btn).clicked() {
                                    self.vpn.stop_recording();
                                }
                            } else {
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.recording_service)
                                        .desired_width(130.0)
                                        .hint_text(t(lang, "record_service_name")),
                                );
                                let svc = {
                                    let s = self.recording_service.trim().to_string();
                                    if s.is_empty() {
                                        "custom".to_string()
                                    } else {
                                        s
                                    }
                                };
                                if ui
                                    .add_enabled(
                                        !rec_busy,
                                        egui::Button::new(t(lang, "record_new_mask")),
                                    )
                                    .clicked()
                                {
                                    self.vpn.start_recording(&svc);
                                }
                            }
                            if let Some(s) = rec_status {
                                ui.label(egui::RichText::new(s).size(11.0).weak());
                            }
                        });
                        if let Some(result) = rec_result {
                            let color = if result.succeeded {
                                egui::Color32::from_rgb(0x4C, 0xAF, 0x50)
                            } else {
                                egui::Color32::from_rgb(0xEF, 0x53, 0x50)
                            };
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(&result.details).color(color).size(11.0),
                                );
                                if ui.small_button(t(lang, "dismiss")).clicked() {
                                    self.vpn.clear_recording_result();
                                }
                            });
                        }

                        // ── Diagnostics / Benchmark ───────────────────────────────
                        ui.horizontal(|ui| {
                            let bench_lbl = if self.bench_running {
                                t(lang, "bench_running")
                            } else {
                                t(lang, "run_benchmark")
                            };
                            if ui
                                .add_enabled(!self.bench_running, egui::Button::new(bench_lbl))
                                .clicked()
                            {
                                let binary = self.vpn.client_binary.clone();
                                let server = self.vpn.server_addr().unwrap_or("").to_string();
                                if server.is_empty() {
                                    self.show_error(
                                        "No server address — reconnect first".to_string(),
                                    );
                                } else {
                                    self.bench_running = true;
                                    self.bench_result = None;
                                    let (tx, rx) = std::sync::mpsc::channel();
                                    self.bench_rx = Some(rx);
                                    std::thread::spawn(move || {
                                        let result =
                                            VpnManager::run_bench_blocking(&binary, &server);
                                        let _ = tx.send(result);
                                    });
                                }
                            }
                            if let Some(ref r) = self.bench_result {
                                let qc = if r.quality_score >= 70 {
                                    egui::Color32::from_rgb(0x4C, 0xAF, 0x50)
                                } else if r.quality_score >= 40 {
                                    egui::Color32::from_rgb(0xFF, 0xA7, 0x26)
                                } else {
                                    egui::Color32::from_rgb(0xEF, 0x53, 0x50)
                                };
                                ui.label(
                                    egui::RichText::new(format!(
                                        "P50: {:.0}ms  Q:{}/100",
                                        r.latency_p50_ms, r.quality_score
                                    ))
                                    .color(qc)
                                    .size(12.0),
                                );
                            }
                        });

                        ui.separator();
                    }

                    // ── Admin panel (P3.4) — Viewer(1) and Admin(2) both get ────────
                    // ── clients/pool/audit (G-A1/G-A2); Viewer read-only ─────────────
                    if is_connected && matches!(self.admin_role, Some(1) | Some(2)) {
                        self.draw_admin_panel(ui, lang);
                        ui.separator();
                    }

                    // ── Settings ───────────────────────────────────────────────────
                    let mut ks = self.settings.kill_switch;
                    if ui
                        .add_enabled(
                            !is_connected && !is_busy,
                            egui::Checkbox::new(&mut ks, t(lang, "kill_switch")),
                        )
                        .changed()
                    {
                        self.settings.kill_switch = ks;
                        self.dirty_at.get_or_insert(Instant::now());
                    }

                    // Grid ensures both labels share the same column width → comboboxes align
                    egui::Grid::new("settings_controls")
                        .num_columns(2)
                        .spacing([8.0, 4.0])
                        .show(ui, |ui| {
                            ui.label(t(lang, "adaptive_mode"));
                            const ADM_DESCS: &[&str] = &[
                                "Server picks the best profile automatically",
                                "Basic traffic mimicry. Keepalive every 15 s.",
                                "HTTPS/QUIC mimicry. Keepalive every 8 s.",
                                "Max mimicry. Optimized for high latency (>300 ms).",
                            ];
                            let labels = ["Auto", "Light", "Aggressive", "Satellite"];
                            let mut adp = self.settings.adaptive_level as usize;
                            egui::ComboBox::from_id_salt("adp")
                                .selected_text(labels[adp.min(3)])
                                .width(150.0)
                                .show_ui(ui, |ui| {
                                    for (i, lbl) in labels.iter().enumerate() {
                                        if ui
                                            .selectable_value(&mut adp, i, *lbl)
                                            .on_hover_text(ADM_DESCS[i])
                                            .changed()
                                        {
                                            self.settings.adaptive_level = adp as u8;
                                            self.dirty_at.get_or_insert(Instant::now());
                                        }
                                    }
                                });
                            ui.end_row();

                            ui.label(t(lang, "mask_profile"));
                            // Prefer the server-pushed catalog (auto masks marked
                            // "(авто)"); fall back to the built-in presets until a
                            // catalog has been received.
                            let mask_choices: Vec<(String, String)> = mask_choices_from_catalog(
                                self.settings.lang,
                            )
                            .unwrap_or_else(|| {
                                [
                                    "auto",
                                    "webrtc_zoom_v3",
                                    "quic_https_v2",
                                    "webrtc_yandex_telemost_v1",
                                    "webrtc_vk_teams_v1",
                                    "webrtc_sberjazz_v1",
                                ]
                                .iter()
                                .map(|s| (s.to_string(), s.to_string()))
                                .collect()
                            });
                            let cur = self.settings.preferred_mask.clone();
                            let cur_label = mask_choices
                                .iter()
                                .find(|(id, _)| id == &cur)
                                .map(|(_, d)| d.clone())
                                .unwrap_or_else(|| "auto".to_string());
                            egui::ComboBox::from_id_salt("mask_profile")
                                .selected_text(cur_label)
                                .width(150.0)
                                .show_ui(ui, |ui| {
                                    for (id, display) in &mask_choices {
                                        if ui
                                            .selectable_value(
                                                &mut self.settings.preferred_mask,
                                                id.clone(),
                                                display,
                                            )
                                            .changed()
                                        {
                                            if self.settings.preferred_mask == "auto" {
                                                // "Auto" has no concrete base mask to
                                                // polymorph from — leaving the toggle
                                                // checked would be inert (disabled in
                                                // the UI, but the stored value stays
                                                // true and could still be persisted).
                                                self.settings.polymorphic_mask = false;
                                            }
                                            self.dirty_at.get_or_insert(Instant::now());
                                        }
                                    }
                                });
                            ui.end_row();
                        });

                    let cur_mask_is_preset = self.settings.preferred_mask != "auto"
                        && !self.settings.preferred_mask.is_empty();
                    let mut polymorphic = self.settings.polymorphic_mask;
                    if ui
                        .add_enabled(
                            cur_mask_is_preset,
                            egui::Checkbox::new(&mut polymorphic, t(lang, "polymorphic_mask")),
                        )
                        .on_hover_text(t(lang, "polymorphic_mask_hint"))
                        .changed()
                    {
                        self.settings.polymorphic_mask = polymorphic;
                        self.dirty_at.get_or_insert(Instant::now());
                    }

                    ui.label(t(lang, "dns_proxy"));
                    let dns_r = ui.add(
                        egui::TextEdit::singleline(&mut self.settings.dns_proxy)
                            .desired_width(f32::INFINITY)
                            .hint_text("127.0.0.1:5353"),
                    );
                    if dns_r.changed() {
                        self.dirty_at.get_or_insert(Instant::now());
                    }

                    egui::CollapsingHeader::new(t(lang, "mask_feedback_section")).show(ui, |ui| {
                        ui.label(t(lang, "mask_feedback_hint"));

                        let mut share_fb = self.settings.share_mask_feedback;
                        if ui
                            .checkbox(&mut share_fb, t(lang, "share_mask_feedback"))
                            .changed()
                        {
                            self.settings.share_mask_feedback = share_fb;
                            self.dirty_at.get_or_insert(Instant::now());
                        }

                        let mut receive_hints = self.settings.receive_mask_hints;
                        if ui
                            .checkbox(&mut receive_hints, t(lang, "receive_mask_hints"))
                            .changed()
                        {
                            self.settings.receive_mask_hints = receive_hints;
                            self.dirty_at.get_or_insert(Instant::now());
                        }

                        ui.label(t(lang, "country_code"));
                        let cc_r = ui.add(
                            egui::TextEdit::singleline(&mut self.settings.country_code)
                                .desired_width(60.0)
                                .char_limit(2)
                                .hint_text("DE"),
                        );
                        if cc_r.changed() {
                            // Filter to ASCII letters only (drop digits/punctuation), matching
                            // the Linux/macOS/iOS country-code inputs.
                            self.settings.country_code = self
                                .settings
                                .country_code
                                .chars()
                                .filter(|c| c.is_ascii_alphabetic())
                                .take(2)
                                .collect::<String>()
                                .to_uppercase();
                            self.dirty_at.get_or_insert(Instant::now());
                        }
                    });

                    egui::CollapsingHeader::new(t(lang, "bootstrap_section")).show(ui, |ui| {
                        ui.label(t(lang, "bootstrap_hint"));

                        ui.label(t(lang, "bootstrap_cdn_url"));
                        if ui
                            .add(
                                egui::TextEdit::singleline(&mut self.settings.bootstrap_cdn_url)
                                    .desired_width(f32::INFINITY),
                            )
                            .changed()
                        {
                            self.dirty_at.get_or_insert(Instant::now());
                        }

                        ui.label(t(lang, "bootstrap_telegram_token"));
                        if ui
                            .add(
                                egui::TextEdit::singleline(
                                    &mut self.settings.bootstrap_telegram_token,
                                )
                                .desired_width(f32::INFINITY),
                            )
                            .changed()
                        {
                            self.dirty_at.get_or_insert(Instant::now());
                        }

                        ui.label(t(lang, "bootstrap_telegram_chat"));
                        if ui
                            .add(
                                egui::TextEdit::singleline(
                                    &mut self.settings.bootstrap_telegram_chat,
                                )
                                .desired_width(f32::INFINITY),
                            )
                            .changed()
                        {
                            self.dirty_at.get_or_insert(Instant::now());
                        }

                        ui.label(t(lang, "bootstrap_github"));
                        if ui
                            .add(
                                egui::TextEdit::singleline(&mut self.settings.bootstrap_github)
                                    .desired_width(f32::INFINITY),
                            )
                            .changed()
                        {
                            self.dirty_at.get_or_insert(Instant::now());
                        }

                        ui.label(t(lang, "server_signing_key"));
                        if ui
                            .add(
                                egui::TextEdit::singleline(&mut self.settings.server_signing_key)
                                    .desired_width(f32::INFINITY),
                            )
                            .changed()
                        {
                            self.dirty_at.get_or_insert(Instant::now());
                        }
                    });

                    let mut startup = self.settings.connect_on_startup;
                    if ui
                        .checkbox(&mut startup, t(lang, "connect_on_startup"))
                        .changed()
                    {
                        self.settings.connect_on_startup = startup;
                        set_autostart(startup);
                        // Save immediately — registry and settings.json must stay in sync
                        self.settings.save();
                        self.dirty_at = None;
                    }
                    // ── Error / warning ────────────────────────────────────────────
                    if let Some(err) = &error_display {
                        ui.separator();
                        let err_color = if no_traffic_warn {
                            egui::Color32::from_rgb(0xFF, 0xA7, 0x26)
                        } else {
                            egui::Color32::from_rgb(0xEF, 0x53, 0x50)
                        };
                        let is_persistent_vpn_err = self.error_msg.is_none()
                            && self
                                .vpn
                                .last_error
                                .as_deref()
                                .is_some_and(|e| !e.is_empty());
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(err).color(err_color).size(12.0),
                                )
                                .wrap(),
                            );
                            if is_persistent_vpn_err {
                                if ui.small_button("✕").clicked() {
                                    self.vpn.last_error = None;
                                }
                            }
                        });
                    }
                });
        });

        // P3.4: connection-key/QR viewer window + revoke-confirmation modal —
        // separate top-level containers, drawn once per frame regardless of
        // whether draw_admin_panel() ran this frame (admin_key_id/
        // admin_revoke_id can still be Some right after the panel itself
        // stops being drawn, e.g. a disconnect mid-dialog — reset_admin_state()
        // clears both, but only on the NEXT tick(), not synchronously here).
        self.draw_admin_extras(ctx, lang);

        // C3: SSH install wizard window — same "always drawn, independent
        // of draw_admin_panel this frame" rationale as draw_admin_extras
        // above (its own `ssh_wizard_open` flag gates visibility). GAP-G1:
        // the migration wizard (export/import via the tunnel mgmt bridge)
        // was removed — migration is a web-panel-only feature.
        self.draw_ssh_install_window(ctx, lang);

        // ── Add / Edit dialog — separate OS window (can go outside main window) ──
        if self.show_dialog {
            let title = if self.editing_idx.is_some() {
                t(lang, "edit")
            } else {
                t(lang, "add_key")
            };
            // Split-borrow individual fields so the FnMut closure can mutate them
            // while `ctx` (a separate parameter, not part of self) drives the call.
            let show_dialog = &mut self.show_dialog;
            let editing_idx = &mut self.editing_idx;
            let dlg_name = &mut self.dlg_name;
            let dlg_key = &mut self.dlg_key;
            let dlg_full_tunnel = &mut self.dlg_full_tunnel;
            let dlg_proxy = &mut self.dlg_proxy;
            let dlg_proxy_addr = &mut self.dlg_proxy_addr;
            let dlg_exclude_routes = &mut self.dlg_exclude_routes;
            let dlg_include_routes = &mut self.dlg_include_routes;
            let dlg_mtls_cert = &mut self.dlg_mtls_cert;
            let dlg_error = &mut self.dlg_error;
            let keys = &mut self.keys;
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of("key_dialog"),
                egui::ViewportBuilder::default()
                    .with_title(title)
                    .with_inner_size([370.0, 470.0])
                    .with_resizable(true),
                |ctx, _| {
                    if ctx.input(|i| i.viewport().close_requested()) {
                        *show_dialog = false;
                        *dlg_error = None;
                    }
                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.label(t(lang, "key_name"));
                        ui.add(egui::TextEdit::singleline(dlg_name).desired_width(f32::INFINITY));
                        ui.add_space(4.0);
                        ui.label(t(lang, "key_value"));
                        ui.add(
                            egui::TextEdit::singleline(dlg_key)
                                .desired_width(f32::INFINITY)
                                .hint_text("aivpn://…")
                                // LOW/MEDIUM: this field carries the PSK-bearing
                                // aivpn:// connection key — mask it like a password
                                // field so it isn't rendered in clear text on screen
                                // (shoulder-surf / screenshot exposure). Verified
                                // against the vendored egui 0.31.1 source
                                // (widgets/text_edit/builder.rs): `password(bool)` is
                                // a real TextEdit builder method in this version.
                                .password(true),
                        );
                        ui.add_space(4.0);
                        ui.checkbox(dlg_full_tunnel, t(lang, "full_tunnel"));
                        ui.checkbox(dlg_proxy, t(lang, "proxy_mode"));
                        if *dlg_proxy {
                            ui.add(
                                egui::TextEdit::singleline(dlg_proxy_addr)
                                    .desired_width(f32::INFINITY)
                                    .hint_text("127.0.0.1:1080"),
                            );
                        }
                        ui.add_space(4.0);
                        ui.label(t(lang, "exclude_routes"));
                        ui.add(
                            egui::TextEdit::multiline(dlg_exclude_routes)
                                .desired_width(f32::INFINITY)
                                .desired_rows(3)
                                .hint_text(t(lang, "exclude_routes_hint")),
                        );
                        ui.add_space(4.0);
                        ui.label(t(lang, "include_routes"));
                        ui.add(
                            egui::TextEdit::multiline(dlg_include_routes)
                                .desired_width(f32::INFINITY)
                                .desired_rows(3)
                                .hint_text(t(lang, "include_routes_hint")),
                        );
                        ui.add_space(4.0);
                        ui.label(t(lang, "mtls_cert_path"));
                        ui.add(
                            egui::TextEdit::singleline(dlg_mtls_cert)
                                .desired_width(f32::INFINITY)
                                .hint_text(t(lang, "mtls_cert_hint")),
                        );
                        if let Some(e) = dlg_error.as_deref() {
                            ui.colored_label(egui::Color32::from_rgb(0xEF, 0x53, 0x50), e);
                        }
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            let can_save =
                                !dlg_name.trim().is_empty() && !dlg_key.trim().is_empty();
                            if ui
                                .add_enabled(can_save, egui::Button::new(t(lang, "save")))
                                .clicked()
                            {
                                let proxy = if *dlg_proxy && !dlg_proxy_addr.is_empty() {
                                    Some(dlg_proxy_addr.clone())
                                } else {
                                    None
                                };
                                let exclude_routes: Vec<String> = dlg_exclude_routes
                                    .lines()
                                    .map(|l| l.trim().to_string())
                                    .filter(|s| !s.is_empty())
                                    .collect();
                                let include_routes: Vec<String> = dlg_include_routes
                                    .lines()
                                    .map(|l| l.trim().to_string())
                                    .filter(|s| !s.is_empty())
                                    .collect();
                                let mtls = if dlg_mtls_cert.trim().is_empty() {
                                    None
                                } else {
                                    Some(dlg_mtls_cert.trim().to_string())
                                };
                                let result = if let Some(idx) = *editing_idx {
                                    keys.update_key(
                                        idx,
                                        dlg_name,
                                        dlg_key,
                                        *dlg_full_tunnel,
                                        proxy,
                                        mtls,
                                        exclude_routes,
                                        include_routes,
                                    )
                                } else {
                                    keys.add_key(
                                        dlg_name,
                                        dlg_key,
                                        *dlg_full_tunnel,
                                        proxy,
                                        mtls,
                                        exclude_routes,
                                        include_routes,
                                    )
                                };
                                match result {
                                    Ok(()) => {
                                        *show_dialog = false;
                                        *dlg_error = None;
                                    }
                                    Err(e) => *dlg_error = Some(e),
                                }
                            }
                            if ui.button(t(lang, "cancel")).clicked() {
                                *show_dialog = false;
                                *dlg_error = None;
                            }
                        });
                    });
                },
            );
        }

        // Minimize → hide to tray (fix: minimize was going to taskbar, not tray)
        if ctx.input(|i| i.viewport().minimized.unwrap_or(false)) && !self.quitting {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            #[cfg(windows)]
            unsafe {
                use winapi::um::winuser::{ShowWindow, SW_HIDE};
                let hwnd = find_own_aivpn_hwnd();
                if !hwnd.is_null() {
                    ShowWindow(hwnd, SW_HIDE);
                }
            }
            self.window_visible = false;
        }

        // Close button → hide to tray instead of quitting (skip when quit was requested)
        if ctx.input(|i| i.viewport().close_requested()) && !self.quitting {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            #[cfg(windows)]
            unsafe {
                use winapi::um::winuser::{ShowWindow, SW_HIDE};
                let hwnd = find_own_aivpn_hwnd();
                if !hwnd.is_null() {
                    ShowWindow(hwnd, SW_HIDE);
                }
            }
            self.window_visible = false;
        }

        // Repaint every second for live uptime/traffic display
        ctx.request_repaint_after(std::time::Duration::from_secs(1));
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if !self.quitting {
            self.vpn.disconnect();
            let _ = self.settings.save();
        }
    }
}
