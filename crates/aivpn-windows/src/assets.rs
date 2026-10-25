use crate::localization;
use crate::vpn_manager;

// ── Theme / visuals ────────────────────────────────────────────────────────

#[cfg(windows)]
pub(crate) fn install_fonts(ctx: &eframe::egui::Context) {
    use eframe::egui;
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "Inter".into(),
        egui::FontData::from_static(include_bytes!("../assets/Inter-Regular.ttf")).into(),
    );
    let mut names = vec!["Inter".to_owned()];
    if let Some(dir) = std::env::var_os("WINDIR") {
        for name in ["SegoeUI-VF.ttf", "segoeui.ttf"] {
            if let Ok(bytes) = std::fs::read(std::path::Path::new(&dir).join("Fonts").join(name)) {
                fonts
                    .font_data
                    .insert("Segoe UI".into(), egui::FontData::from_owned(bytes).into());
                names.insert(0, "Segoe UI".into());
                break;
            }
        }
    }
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .splice(0..0, names);
    ctx.set_fonts(fonts);
}

#[cfg(windows)]
pub(crate) struct FluentColors {
    pub background: eframe::egui::Color32,
    pub surface: eframe::egui::Color32,
    pub border: eframe::egui::Color32,
    pub accent: eframe::egui::Color32,
    pub on_accent: eframe::egui::Color32,
    pub success: eframe::egui::Color32,
}

#[cfg(windows)]
pub(crate) fn fluent_colors(dark: bool) -> FluentColors {
    use eframe::egui::Color32 as C;
    if dark {
        FluentColors {
            background: C::from_rgb(32, 32, 32),
            surface: C::from_rgb(45, 45, 45),
            border: C::from_rgb(69, 69, 69),
            accent: C::from_rgb(96, 205, 255),
            on_accent: C::from_rgb(0, 51, 77),
            success: C::from_rgb(108, 203, 154),
        }
    } else {
        FluentColors {
            background: C::from_rgb(243, 243, 243),
            surface: C::WHITE,
            border: C::from_rgb(222, 222, 222),
            accent: C::from_rgb(0, 103, 192),
            on_accent: C::WHITE,
            success: C::from_rgb(15, 108, 54),
        }
    }
}

#[cfg(windows)]
pub(crate) fn apply_theme_to_ctx(ctx: &eframe::egui::Context, dark: bool) {
    use eframe::egui::{self, Color32 as C, FontFamily, FontId, TextStyle};
    let colors = fluent_colors(dark);
    let mut visuals = if dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    let ink = if dark {
        C::from_rgb(245, 245, 245)
    } else {
        C::from_rgb(26, 26, 26)
    };
    let selection = if dark {
        C::from_rgb(38, 59, 72)
    } else {
        C::from_rgb(232, 240, 247)
    };
    visuals.panel_fill = if dark {
        C::from_rgb(39, 39, 39)
    } else {
        C::from_rgb(250, 250, 250)
    };
    visuals.window_fill = colors.surface;
    visuals.extreme_bg_color = colors.surface;
    visuals.faint_bg_color = selection;
    visuals.override_text_color = Some(ink);
    visuals.hyperlink_color = colors.accent;
    visuals.selection.bg_fill = selection;
    visuals.selection.stroke = egui::Stroke::new(1.0_f32, colors.accent);
    visuals.warn_fg_color = if dark {
        C::from_rgb(249, 211, 125)
    } else {
        C::from_rgb(128, 89, 0)
    };
    visuals.error_fg_color = if dark {
        C::from_rgb(255, 180, 171)
    } else {
        C::from_rgb(179, 35, 37)
    };
    for widget in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        widget.corner_radius = egui::CornerRadius::same(4);
        widget.fg_stroke.color = ink;
        widget.bg_stroke = egui::Stroke::new(1.0_f32, colors.border);
    }
    // egui смешивает слабый текст с этой поверхностью пополам.
    visuals.widgets.noninteractive.weak_bg_fill = if dark {
        C::from_rgb(147, 147, 147)
    } else {
        C::from_rgb(160, 160, 160)
    };
    visuals.widgets.inactive.bg_fill = colors.surface;
    visuals.widgets.inactive.weak_bg_fill = colors.surface;
    visuals.widgets.hovered.bg_fill = selection;
    visuals.widgets.hovered.weak_bg_fill = selection;
    visuals.widgets.active.bg_fill = selection;
    visuals.widgets.active.weak_bg_fill = selection;
    visuals.window_corner_radius = egui::CornerRadius::same(8);
    ctx.set_visuals(visuals);
    let mut style = (*ctx.style()).clone();
    style.text_styles = [
        (
            TextStyle::Heading,
            FontId::new(18.0, FontFamily::Proportional),
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
    style.spacing.button_padding = egui::vec2(13.0, 8.0);
    style.spacing.interact_size = egui::vec2(34.0, 34.0);
    style.spacing.item_spacing = egui::vec2(8.0, 10.0);
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

/// Декодирует встроенный ресурс, проверенный при сборке.
#[cfg(windows)]
pub(crate) fn decode_png_rgba(bytes: &[u8]) -> (Vec<u8>, u32, u32) {
    try_decode_png_rgba(bytes).expect("bundled brand PNG must decode")
}

/// Проверяет полученное изображение и приводит все поддержанные цвета к RGBA8.
#[cfg(any(windows, test))]
pub(crate) fn try_decode_png_rgba(bytes: &[u8]) -> Result<(Vec<u8>, u32, u32), String> {
    let mut decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    decoder.set_limits(png::Limits {
        bytes: 16 * 1024 * 1024,
    });
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().map_err(|error| error.to_string())?;
    let size = reader
        .output_buffer_size()
        .filter(|size| *size <= 16 * 1024 * 1024)
        .ok_or("PNG слишком большой")?;
    let mut pixels = vec![0; size];
    let info = reader
        .next_frame(&mut pixels)
        .map_err(|error| error.to_string())?;
    pixels.truncate(info.buffer_size());
    let count = (info.width as usize)
        .checked_mul(info.height as usize)
        .filter(|count| *count <= 4 * 1024 * 1024)
        .ok_or("PNG слишком большой")?;
    let mut rgba = Vec::with_capacity(count * 4);
    match info.color_type {
        png::ColorType::Grayscale => {
            for value in pixels {
                rgba.extend_from_slice(&[value, value, value, 255]);
            }
        }
        png::ColorType::GrayscaleAlpha => {
            for pixel in pixels.chunks_exact(2) {
                rgba.extend_from_slice(&[pixel[0], pixel[0], pixel[0], pixel[1]]);
            }
        }
        png::ColorType::Rgb => {
            for pixel in pixels.chunks_exact(3) {
                rgba.extend_from_slice(&[pixel[0], pixel[1], pixel[2], 255]);
            }
        }
        png::ColorType::Rgba => rgba = pixels,
        _ => return Err("Неподдерживаемый цвет PNG".into()),
    }
    if rgba.len() != count * 4 {
        return Err("Неверная длина PNG".into());
    }
    Ok((rgba, info.width, info.height))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_png_accepts_gray_rgb_and_alpha_without_panicking() {
        for (color, pixels, expected) in [
            (
                png::ColorType::Grayscale,
                vec![0, 255],
                vec![0, 0, 0, 255, 255, 255, 255, 255],
            ),
            (
                png::ColorType::GrayscaleAlpha,
                vec![0, 17, 255, 19],
                vec![0, 0, 0, 17, 255, 255, 255, 19],
            ),
            (
                png::ColorType::Rgb,
                vec![1, 2, 3, 4, 5, 6],
                vec![1, 2, 3, 255, 4, 5, 6, 255],
            ),
        ] {
            let mut encoded = Vec::new();
            {
                let mut encoder = png::Encoder::new(&mut encoded, 2, 1);
                encoder.set_color(color);
                encoder.set_depth(png::BitDepth::Eight);
                encoder
                    .write_header()
                    .unwrap()
                    .write_image_data(&pixels)
                    .unwrap();
            }
            let (rgba, width, height) = try_decode_png_rgba(&encoded).unwrap();
            assert_eq!((width, height), (2, 1));
            assert_eq!(rgba, expected);
        }
        assert!(try_decode_png_rgba(b"invalid PNG").is_err());
    }
}
