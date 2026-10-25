use super::*;
use crate::localization::Lang;
use appearance::{ColorScheme, Page, UiLayout};
use eframe::egui;

fn app(ctx: &egui::Context) -> AivpnApp {
    let settings: AppSettings =
        serde_json::from_str(r#"{"lang":"ru","color_scheme":"light"}"#).unwrap();
    AivpnApp::new(settings, ctx)
}

#[test]
fn layout_and_theme_switch_keep_session_counters_and_unsaved_forms() {
    let ctx = egui::Context::default();
    let mut app = app(&ctx);
    app.vpn = VpnManager::connected_ui_fixture();
    app.connected_since = Some(Instant::now() - std::time::Duration::from_secs(1458));
    app.page = Page::Routes;
    app.dlg_name = "Несохраненный профиль".into();
    app.dlg_key = "несохраненный ввод".into();
    app.admin_add_name = "Новый клиент".into();
    let since = app.connected_since;
    let vpn_since = app.vpn.session_since_ms();
    let stats = (app.vpn.stats().bytes_received, app.vpn.stats().bytes_sent);
    for layout in [
        UiLayout::Compact,
        UiLayout::FluentDesktop,
        UiLayout::Compact,
    ] {
        app.set_ui_layout(&ctx, layout);
        assert_eq!(app.settings.ui_layout, layout);
        app.settings.color_scheme = Some(ColorScheme::Dark);
        app.sync_appearance(&ctx);
        assert_eq!(app.vpn.state(), ConnectionState::Connected);
        assert_eq!(app.connected_since, since);
        assert_eq!(app.vpn.session_since_ms(), vpn_since);
        assert_eq!(
            (app.vpn.stats().bytes_received, app.vpn.stats().bytes_sent),
            stats
        );
        assert_eq!(app.page, Page::Routes);
        assert_eq!(app.dlg_name, "Несохраненный профиль");
        assert_eq!(app.dlg_key, "несохраненный ввод");
        assert_eq!(app.admin_add_name, "Новый клиент");
    }
}

#[test]
fn fluent_secondary_text_remains_readable_on_its_surfaces() {
    fn luminance(color: egui::Color32) -> f64 {
        let [r, g, b, _] = color.to_array();
        let linear = |c: u8| {
            let c = c as f64 / 255.0;
            if c <= 0.04045 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b)
    }
    let ctx = egui::Context::default();
    for dark in [false, true] {
        assets::apply_theme_to_ctx(&ctx, dark);
        let visuals = ctx.style().visuals.clone();
        let foreground = luminance(visuals.weak_text_color());
        for background in [
            visuals.panel_fill,
            visuals.window_fill,
            assets::fluent_colors(dark).background,
        ] {
            let bg = luminance(background);
            let contrast = (foreground.max(bg) + 0.05) / (foreground.min(bg) + 0.05);
            assert!(contrast >= 4.5, "dark={dark}, contrast={contrast}");
        }
    }
}

#[test]
fn profile_write_and_global_shortcuts_cannot_escape_an_active_modal() {
    let ctx = egui::Context::default();
    let mut app = app(&ctx);
    app.vpn = VpnManager::connected_ui_fixture();
    app.open_profile(None);
    assert!(!app.show_dialog);
    app.vpn = VpnManager::new();
    app.open_profile(None);
    assert!(app.show_dialog);
    app.page = Page::Profiles;
    let _ = ctx.run(
        egui::RawInput {
            events: vec![egui::Event::Key {
                key: egui::Key::Comma,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::CTRL,
            }],
            ..Default::default()
        },
        |ctx| app.handle_shortcuts(ctx),
    );
    assert_eq!(app.page, Page::Profiles);
    assert!(app.show_dialog);
}

fn example_key(server: &str) -> key_storage::ConnectionKey {
    use base64::Engine;
    let value =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!(r#"{{"s":"{server}"}}"#));
    key_storage::ConnectionKey::from_key_string("Пример", &value).unwrap()
}

#[test]
fn proxy_session_never_claims_firewall_protection() {
    let ctx = egui::Context::default();
    let mut app = app(&ctx);
    app.vpn = VpnManager::connected_ui_fixture();
    app.vpn.set_ui_test_kill_switch(true);
    let mut key = example_key("proxy.example.invalid:443");
    key.proxy_listen = Some("127.0.0.1:1080".into());
    app.keys = key_storage::KeyStorage {
        keys: vec![key],
        selected: Some(0),
    };
    let mut drawn = String::new();
    fn collect(shape: &egui::Shape, out: &mut String) {
        match shape {
            egui::Shape::Text(text) => {
                out.push_str(&text.galley.job.text);
                out.push('\n');
            }
            egui::Shape::Vec(shapes) => {
                for s in shapes {
                    collect(s, out);
                }
            }
            _ => {}
        }
    }
    for _ in 0..2 {
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(960.0, 680.0),
                )),
                ..Default::default()
            },
            |ctx| {
                app.sync_appearance(ctx);
                app.draw_shell(ctx);
            },
        );
        drawn.clear();
        for shape in output.shapes {
            collect(&shape.shape, &mut drawn);
        }
    }
    app.vpn.set_ui_test_kill_switch(false);
    assert!(!drawn.contains("Включена для этого сеанса"));
    assert!(drawn.contains("не применяется"));
}

#[test]
fn settings_write_failure_leaves_profile_and_dns_unchanged() {
    let ctx = egui::Context::default();
    let mut app = app(&ctx);
    app.settings.dns_proxy = "127.0.0.1:5353".into();
    let key = example_key("routes.example.invalid:443");
    app.keys = key_storage::KeyStorage {
        keys: vec![key.clone()],
        selected: Some(0),
    };
    app.keys.save().unwrap();
    let mut draft = ui_model::RouteDraft::new(0, &key, "127.0.0.1:5354");
    draft.include = "10.20.0.0/16".into();
    app.route_draft = Some(draft);
    let path = dirs::data_local_dir().unwrap().join("AIVPN/settings.json");
    let backup = std::fs::read(&path).ok();
    let _ = std::fs::remove_file(&path);
    std::fs::create_dir(&path).unwrap();
    app.save_routes();
    std::fs::remove_dir(&path).unwrap();
    if let Some(bytes) = backup {
        std::fs::write(&path, bytes).unwrap();
    }
    assert!(app.routes_error.is_some());
    assert_eq!(app.settings.dns_proxy, "127.0.0.1:5353");
    assert!(app.keys.keys[0].include_routes.is_empty());
    assert!(key_storage::KeyStorage::load().keys[0]
        .include_routes
        .is_empty());
}

#[test]
fn ssh_wizard_stays_inside_compact_minimum_window() {
    let ctx = egui::Context::default();
    let mut app = app(&ctx);
    app.ssh_wizard_open = true;
    let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(380.0, 520.0));
    for _ in 0..3 {
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(screen),
                ..Default::default()
            },
            |ctx| {
                app.sync_appearance(ctx);
                app.draw_ssh_install_window(ctx, Lang::Ru);
            },
        );
    }
    let rect = ctx
        .memory(|m| m.area_rect(egui::Id::new("ssh_install_wizard")))
        .unwrap();
    assert!(screen.contains_rect(rect), "{rect:?}");
}

#[test]
fn ssh_import_appends_without_replacing_the_active_profile_or_session() {
    let ctx = egui::Context::default();
    let mut app = app(&ctx);
    app.keys = key_storage::KeyStorage {
        keys: vec![example_key("active.example.invalid:443")],
        selected: Some(0),
    };
    app.vpn = VpnManager::connected_ui_fixture();
    app.ssh_install_connection_key = Some(example_key("new.example.invalid:443").key);
    app.import_ssh_install_key();
    assert!(app.ssh_import_done);
    assert_eq!(app.keys.keys.len(), 2);
    assert_eq!(app.keys.selected, Some(0));
    assert_eq!(app.vpn.state(), ConnectionState::Connected);
    assert_eq!(app.vpn.stats().bytes_received, 12_345_678);
}

#[test]
fn profile_validation_error_is_fully_visible_at_minimum_size() {
    let ctx = egui::Context::default();
    let mut app = app(&ctx);
    app.open_profile(None);
    let message = "Проверьте ключ подключения AIVPN.";
    app.dlg_error = Some(message.into());
    let mut visible = false;
    for _ in 0..3 {
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(380.0, 520.0),
                )),
                ..Default::default()
            },
            |ctx| {
                app.sync_appearance(ctx);
                app.draw_profile_dialog(ctx);
            },
        );
        for shape in output.shapes {
            if let egui::Shape::Text(ref label) = shape.shape {
                if label.galley.job.text == message {
                    visible = shape
                        .clip_rect
                        .contains_rect(shape.shape.visual_bounding_rect());
                }
            }
        }
    }
    assert!(visible);
}

#[test]
fn profile_write_failure_restores_the_previously_saved_dns() {
    let ctx = egui::Context::default();
    let mut app = app(&ctx);
    app.settings.dns_proxy = "127.0.0.1:5353".into();
    app.settings.save().unwrap();
    let key = example_key("readonly.example.invalid:443");
    app.keys = key_storage::KeyStorage {
        keys: vec![key.clone()],
        selected: Some(0),
    };
    app.keys.save().unwrap();
    let path = dirs::data_local_dir().unwrap().join("AIVPN/keys.json");
    let backup = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let mut draft = ui_model::RouteDraft::new(0, &key, "127.0.0.1:5354");
    draft.include = "10.20.0.0/16".into();
    app.route_draft = Some(draft);
    app.save_routes();
    std::fs::remove_dir(&path).unwrap();
    std::fs::write(&path, backup).unwrap();
    assert!(app.routes_error.is_some());
    assert_eq!(app.settings.dns_proxy, "127.0.0.1:5353");
    assert_eq!(AppSettings::load().dns_proxy, "127.0.0.1:5353");
    assert!(app.keys.keys[0].include_routes.is_empty());
}

#[test]
fn live_masks_page_does_not_normalize_or_save_network_preferences() {
    let ctx = egui::Context::default();
    let mut app = app(&ctx);
    app.vpn = VpnManager::connected_ui_fixture();
    app.page = Page::Masks;
    app.settings.preferred_mask = "auto".into();
    app.settings.polymorphic_mask = true;
    let before = serde_json::to_value(&app.settings).unwrap();
    let _ = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(960.0, 680.0),
            )),
            ..Default::default()
        },
        |ctx| {
            app.sync_appearance(ctx);
            app.draw_shell(ctx);
        },
    );
    assert_eq!(serde_json::to_value(&app.settings).unwrap(), before);
    assert!(app.dirty_at.is_none());
}
