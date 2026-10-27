use super::*;

impl App {
    pub(super) fn is_dark(&self) -> bool {
        match self.settings.color_scheme {
            Some(ColorScheme::Light) => false,
            Some(ColorScheme::Dark) => true,
            Some(ColorScheme::System) => match self.system_theme {
                iced::theme::Mode::Light => false,
                iced::theme::Mode::Dark => true,
                iced::theme::Mode::None => self.settings.dark_mode,
            },
            None => self.settings.dark_mode,
        }
    }

    pub(super) fn profiles_locked(&self) -> bool {
        self.pending_connect
            || self.adopted_reap_in_flight
            || matches!(
                self.status,
                VpnStatus::Connecting | VpnStatus::Connected { .. }
            )
    }

    pub(super) fn set_layout(&mut self, layout: UiLayout) {
        self.settings.ui_layout = layout;
    }

    pub(super) fn kill_switch_value(&self) -> Option<bool> {
        if matches!(self.status, VpnStatus::Connected { .. }) && self.adopted_client.is_some() {
            return None;
        }
        Some(if matches!(self.status, VpnStatus::Connected { .. }) {
            self.launched_kill_switch
        } else {
            self.settings.kill_switch
        })
    }

    pub(super) fn appearance_theme(&self) -> Theme {
        let material = self.settings.ui_layout == UiLayout::Material;
        let dark = self.is_dark();
        let (background, foreground, primary) = match (material, dark) {
            (true, false) => (0xFCF9FF, 0x211F26, 0x675087),
            (true, true) => (0x161319, 0xE9E0EC, 0xD1B7F4),
            (false, false) => (0xEFF0F1, 0x232629, 0x1676A3),
            (false, true) => (0x2A2E32, 0xEFF0F1, 0x3DAEE9),
        };
        Theme::custom_with_fn(
            "AIVPN".to_string(),
            iced::theme::Palette {
                background: rgb(background),
                text: rgb(foreground),
                primary: rgb(primary),
                success: rgb(if dark { 0xA8D4AF } else { 0x386A43 }),
                warning: rgb(if dark { 0xE8C477 } else { 0x785A13 }),
                danger: rgb(if dark { 0xFFB4AB } else { 0xA52A26 }),
            },
            |palette| {
                use iced::theme::palette::{Extended, Pair};
                let mut extended = Extended::generate(palette);
                let (surface, border, muted, selected) = match (material, dark) {
                    (true, false) => (0xF0EBF4, 0xCAC4D0, 0x625D69, 0xEADDFF),
                    (true, true) => (0x242028, 0x49434F, 0xCAC2CF, 0x4D3B63),
                    (false, false) => (0xFCFCFC, 0xB8BDC1, 0x545B61, 0xD6EBF5),
                    (false, true) => (0x232629, 0x64696D, 0xB8BDC1, 0x254D63),
                };
                extended.background.weak = Pair::new(rgb(surface), palette.text);
                extended.background.strong = Pair::new(rgb(border), rgb(muted));
                extended.secondary.base = Pair::new(rgb(surface), palette.text);
                extended.secondary.weak = Pair::new(rgb(surface), palette.text);
                extended.primary.weak = Pair::new(rgb(selected), palette.text);
                extended
            },
        )
    }
}

pub(super) fn rgb(hex: u32) -> Color {
    Color::from_rgb8((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

pub(super) fn input_style(
    theme: &Theme,
    status: iced::widget::text_input::Status,
) -> iced::widget::text_input::Style {
    let mut style = iced::widget::text_input::default(theme, status);
    style.placeholder = Color {
        a: 0.7,
        ..theme.palette().text
    };
    if status == iced::widget::text_input::Status::Disabled {
        style.value = style.placeholder;
    }
    style
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        App::from_state(AppSettings::default(), KeyStorage::default(), None).0
    }

    #[test]
    fn switching_layout_keeps_session_and_forms() {
        let mut app = app();
        app.status = VpnStatus::Connected {
            vpn_ip: "10.8.0.2".into(),
        };
        app.connection_key = Some("test-session".into());
        app.stats.bytes_received = 12000;
        app.stats.connected_since = Some(12345);
        app.admin_role = Some(2);
        app.admin_generation = 19;
        app.launched_kill_switch = true;
        app.dlg_name = "Черновик".into();
        app.server_settings_exit_node = "node.test:443".into();
        app.page = UiPage::Service;
        let child = app.child_handle.clone();
        for layout in [UiLayout::Material, UiLayout::Breeze] {
            app.set_layout(layout);
            assert_eq!(app.settings.ui_layout, layout);
            assert!(Arc::ptr_eq(&child, &app.child_handle));
            assert_eq!(app.connection_key.as_deref(), Some("test-session"));
            assert_eq!(app.stats.bytes_received, 12000);
            assert_eq!(app.stats.connected_since, Some(12345));
            assert_eq!(app.admin_generation, 19);
            assert_eq!(app.admin_role, Some(2));
            assert!(app.launched_kill_switch);
            assert_eq!(app.page, UiPage::Service);
            assert_eq!(app.dlg_name, "Черновик");
            assert_eq!(app.server_settings_exit_node, "node.test:443");
            let _ = app.view();
        }
    }

    #[test]
    fn active_session_rejects_profile_writes_even_from_stale_messages() {
        let mut app = app();
        app.storage.keys = vec![ConnectionKey::default(), ConnectionKey::default()];
        app.storage.selected = Some(0);
        app.status = VpnStatus::Connecting;
        for message in [
            Message::SelectProfile(1),
            Message::ShowAddDialog,
            Message::ShowEditDialog(0),
            Message::RemoveProfile(0),
            Message::DlgSave,
        ] {
            let _ = app.update(message);
            assert_eq!(app.storage.selected, Some(0));
            assert_eq!(app.storage.keys.len(), 2);
            assert_eq!(app.dialog, DialogMode::None);
        }
    }

    #[test]
    fn delete_requires_explicit_confirmation() {
        let mut app = app();
        app.storage.keys = vec![ConnectionKey::default()];
        let _ = app.update(Message::RemoveProfile(0));
        assert_eq!(app.storage.keys.len(), 1);
        assert_eq!(app.pending_remove, Some(0));
    }

    #[test]
    fn system_theme_uses_legacy_fallback_until_reported() {
        let mut app = app();
        assert!(app.is_dark());
        app.system_theme = iced::theme::Mode::Light;
        assert!(!app.is_dark());
        app.settings.color_scheme = None;
        assert!(app.is_dark());
    }
    #[test]
    fn full_tunnel_summary_does_not_claim_allowlist_only() {
        let mut app = app();
        app.storage.keys = vec![ConnectionKey {
            full_tunnel: true,
            ..Default::default()
        }];
        app.storage.selected = Some(0);
        app.settings.include_routes = "10.0.0.0/8".into();
        assert_eq!(app.route_summary(), "All traffic through VPN");
    }

    #[test]
    fn busy_session_rejects_network_preference_messages() {
        let mut app = app();
        app.status = VpnStatus::Connected {
            vpn_ip: "10.8.0.2".into(),
        };
        let before = serde_json::to_value(&app.settings).unwrap();
        for message in [
            Message::ToggleKillSwitch(true),
            Message::DnsProxyChanged("1.2.3.4:53".into()),
            Message::MaskOptionChanged("youtube".into()),
            Message::IncludeRoutesChanged("10.0.0.0/8".into()),
            Message::ToggleSocks5(true),
        ] {
            let task = app.update(message);
            assert_eq!(task.units(), 0);
            assert_eq!(serde_json::to_value(&app.settings).unwrap(), before);
        }
    }
    #[test]
    fn adopted_session_does_not_invent_kill_switch_state() {
        let mut app = app();
        app.status = VpnStatus::Connected {
            vpn_ip: "recovered".into(),
        };
        app.adopted_client = Some((1, 1));
        assert_eq!(app.kill_switch_value(), None);
    }
    #[test]
    fn input_placeholders_remain_readable_in_all_palettes() {
        fn luminance(color: Color) -> f32 {
            let linear = |v: f32| {
                if v <= 0.04045 {
                    v / 12.92
                } else {
                    ((v + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * linear(color.r) + 0.7152 * linear(color.g) + 0.0722 * linear(color.b)
        }
        let mut app = app();
        for layout in [UiLayout::Breeze, UiLayout::Material] {
            app.set_layout(layout);
            for scheme in [ColorScheme::Light, ColorScheme::Dark] {
                app.settings.color_scheme = Some(scheme);
                let theme = app.theme();
                let style = input_style(&theme, iced::widget::text_input::Status::Active);
                let background = theme.palette().background;
                let foreground = Color {
                    r: style.placeholder.r * style.placeholder.a
                        + background.r * (1.0 - style.placeholder.a),
                    g: style.placeholder.g * style.placeholder.a
                        + background.g * (1.0 - style.placeholder.a),
                    b: style.placeholder.b * style.placeholder.a
                        + background.b * (1.0 - style.placeholder.a),
                    a: 1.0,
                };
                let (a, b) = (luminance(foreground), luminance(background));
                assert!(
                    (a.max(b) + 0.05) / (a.min(b) + 0.05) >= 4.5,
                    "{:?} {:?}",
                    layout,
                    scheme
                );
            }
        }
    }
}
