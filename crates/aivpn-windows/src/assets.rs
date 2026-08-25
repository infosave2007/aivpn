use crate::localization;
use crate::vpn_manager;

// ── Theme / visuals ────────────────────────────────────────────────────────

#[cfg(windows)]
pub(crate) fn apply_theme_to_ctx(ctx: &eframe::egui::Context, dark: bool) {
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
pub(crate) fn mask_choices_from_catalog(lang: localization::Lang) -> Option<Vec<(String, String)>> {
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
pub(crate) fn decode_png_rgba(bytes: &[u8]) -> (Vec<u8>, u32, u32) {
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
pub(crate) fn app_icon() -> std::sync::Arc<eframe::egui::IconData> {
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
pub(crate) fn format_unix_ago(ts: i64) -> String {
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
pub(crate) fn make_tray_icon(connected: bool) -> Option<tray_icon::Icon> {
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
