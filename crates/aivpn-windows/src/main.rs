#![cfg_attr(windows, windows_subsystem = "windows")]

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

fn app_icon() -> std::sync::Arc<eframe::egui::IconData> {
    let (rgba, width, height) = decode_png_rgba(APP_ICON_PNG);
    std::sync::Arc::new(eframe::egui::IconData {
        rgba,
        width,
        height,
    })
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
}

#[cfg(windows)]
impl AivpnApp {
    fn new(settings: AppSettings, ctx: &eframe::egui::Context) -> Self {
        let mut app = Self {
            settings,
            vpn: VpnManager::new(),
            keys: KeyStorage::load(),
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
            } else if self.last_conn_state == ConnectionState::Connected {
                self.connected_since = None;
            }
            self.last_conn_state = cur;
        }
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
