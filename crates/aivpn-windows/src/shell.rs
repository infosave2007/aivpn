use crate::appearance::{text, ColorScheme, Page, UiLayout};
use crate::assets::{apply_theme_to_ctx, fluent_colors, mask_choices_from_catalog};
use crate::key_storage::ConnectionKey;
use crate::localization::{t, Lang};
use crate::ui_model::can_edit_network;
use crate::vpn_manager::{format_bytes, ConnectionState};
use eframe::egui::{self, RichText};
use std::time::Instant;

impl crate::AivpnApp {
    pub(crate) fn sync_appearance(&mut self, ctx: &egui::Context) {
        let scheme = self.settings.effective_color_scheme();
        let system = ctx.system_theme().map(|theme| theme == egui::Theme::Dark);
        let dark = scheme.is_dark(system, self.settings.dark_mode);
        if self.applied_dark != Some(dark) {
            ctx.set_theme(match scheme {
                ColorScheme::System => egui::ThemePreference::System,
                ColorScheme::Light => egui::ThemePreference::Light,
                ColorScheme::Dark => egui::ThemePreference::Dark,
            });
            apply_theme_to_ctx(ctx, dark);
            ctx.send_viewport_cmd(egui::ViewportCommand::SetTheme(if dark {
                egui::SystemTheme::Dark
            } else {
                egui::SystemTheme::Light
            }));
            self.applied_dark = Some(dark);
        }
    }

    pub(crate) fn set_ui_layout(&mut self, ctx: &egui::Context, layout: UiLayout) {
        if self.settings.ui_layout == layout {
            return;
        }
        self.settings.ui_layout = layout;
        ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(
            layout.min_size().into(),
        ));
        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(
            layout.initial_size().into(),
        ));
        self.save_preferences();
    }

    fn save_preferences(&mut self) {
        if let Err(error) = self.settings.save() {
            self.show_error(error);
        }
        self.dirty_at = None;
    }

    pub(crate) fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        if self.show_dialog
            || self.delete_profile.is_some()
            || self.ssh_wizard_open
            || self.admin_key_id.is_some()
            || self.admin_revoke_id.is_some()
            || ctx.memory(|m| m.any_popup_open())
        {
            return;
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::N)) {
            self.open_profile(None);
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::Comma)) {
            self.page = Page::Settings;
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::L)) {
            self.page = Page::Service;
            self.logs_open = true;
            self.refresh_log();
        }
    }

    fn connection_label(&self) -> &'static str {
        let lang = self.settings.lang;
        match self.vpn.state() {
            ConnectionState::Connected => text(lang, "В сети", "Connected"),
            ConnectionState::Connecting => t(lang, "connecting"),
            ConnectionState::Disconnecting => t(lang, "disconnecting"),
            ConnectionState::Disconnected => text(lang, "Не подключено", "Disconnected"),
        }
    }

    fn uptime(&self) -> u64 {
        self.vpn
            .session_since_ms()
            .map(|since| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                now.saturating_sub(since) / 1000
            })
            .or_else(|| self.connected_since.map(|since| since.elapsed().as_secs()))
            .unwrap_or(0)
    }

    pub(crate) fn draw_shell(&mut self, ctx: &egui::Context) {
        let lang = self.settings.lang;
        let palette = fluent_colors(ctx.style().visuals.dark_mode);
        egui::TopBottomPanel::bottom("connection_footer")
            .frame(
                egui::Frame::new()
                    .fill(palette.background)
                    .inner_margin(egui::Margin::symmetric(16, 6)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    self.status_dot(ui);
                    ui.small(self.connection_label());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button(text(lang, "Журнал", "Log")).clicked() {
                            self.page = Page::Service;
                            self.logs_open = true;
                            self.refresh_log();
                        }
                        ui.weak(format!("v{}", crate::APP_VERSION));
                    });
                });
            });
        if self.settings.ui_layout == UiLayout::FluentDesktop {
            egui::SidePanel::left("desktop_navigation")
                .exact_width(184.0)
                .resizable(false)
                .frame(
                    egui::Frame::new()
                        .fill(palette.background)
                        .inner_margin(egui::Margin::symmetric(8, 18)),
                )
                .show(ctx, |ui| {
                    for page in Page::ALL.into_iter().filter(|p| *p != Page::Settings) {
                        self.nav_button(ui, page);
                    }
                    ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                        self.nav_button(ui, Page::Settings);
                    });
                });
        } else {
            egui::TopBottomPanel::top("compact_navigation")
                .frame(
                    egui::Frame::new()
                        .fill(palette.background)
                        .inner_margin(egui::Margin::symmetric(16, 12)),
                )
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.weak(text(lang, "Раздел", "Section"));
                        egui::ComboBox::from_id_salt("compact_page")
                            .width((ui.available_width() - 10.0).max(100.0))
                            .selected_text(self.page.label(lang))
                            .show_ui(ui, |ui| {
                                for page in Page::ALL {
                                    ui.selectable_value(&mut self.page, page, page.label(lang));
                                }
                            });
                    });
                });
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::central_panel(&ctx.style()).inner_margin(
                if self.settings.ui_layout == UiLayout::Compact {
                    18
                } else {
                    28
                },
            ))
            .show(ctx, |ui| {
                ui.label(RichText::new(self.page.label(lang)).size(27.0));
                ui.add_space(12.0);
                egui::ScrollArea::vertical()
                    .id_salt(("page", self.page as u8))
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        match self.page {
                            Page::Home => self.draw_connection(ui),
                            Page::Profiles => self.draw_profiles(ui),
                            Page::Routes => self.draw_routes(ui),
                            Page::Masks => self.draw_masks(ui),
                            Page::Service => self.draw_service(ui),
                            Page::Settings => self.draw_preferences(ui),
                        }
                        self.draw_error(ui);
                    });
            });
    }

    fn nav_button(&mut self, ui: &mut egui::Ui, page: Page) {
        let selected = self.page == page;
        let response = ui
            .allocate_ui_with_layout(
                egui::vec2(ui.available_width(), 40.0),
                egui::Layout::top_down(egui::Align::Min).with_cross_justify(true),
                |ui| {
                    ui.spacing_mut().interact_size.y = 40.0;
                    ui.selectable_label(selected, page.label(self.settings.lang))
                },
            )
            .inner;
        if selected {
            let color = fluent_colors(ui.visuals().dark_mode).accent;
            let rect = egui::Rect::from_min_size(
                response.rect.left_center() - egui::vec2(0.0, 9.0),
                egui::vec2(3.0, 18.0),
            );
            ui.painter().rect_filled(rect, 2.0, color);
        }
        if response.clicked() {
            self.page = page;
        }
    }

    fn status_dot(&self, ui: &mut egui::Ui) {
        let color = match self.vpn.state() {
            ConnectionState::Connected => fluent_colors(ui.visuals().dark_mode).success,
            ConnectionState::Connecting | ConnectionState::Disconnecting => {
                ui.visuals().warn_fg_color
            }
            ConnectionState::Disconnected => ui.visuals().weak_text_color(),
        };
        let (rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 12.0), egui::Sense::hover());
        ui.painter().circle_filled(rect.center(), 3.5, color);
    }

    pub(crate) fn profile_route_summary(key: &ConnectionKey, lang: Lang) -> String {
        if let Some(proxy) = &key.proxy_listen {
            return format!("SOCKS5: {proxy}");
        }
        let mode = if key.full_tunnel {
            text(lang, "Весь трафик через VPN", "All traffic through VPN")
        } else if key.include_routes.is_empty() {
            text(lang, "Маршруты сервера", "Server routes")
        } else {
            text(
                lang,
                "Сети профиля и маршруты сервера",
                "Profile networks and server routes",
            )
        };
        if key.exclude_routes.is_empty() {
            mode.into()
        } else {
            format!(
                "{} {}",
                mode,
                text(lang, "с исключениями", "with exclusions")
            )
        }
    }

    fn draw_connection(&mut self, ui: &mut egui::Ui) {
        let lang = self.settings.lang;
        let connected = self.vpn.is_connected();
        let busy = self.vpn.is_busy();
        let palette = fluent_colors(ui.visuals().dark_mode);
        if self.keys.keys.is_empty() {
            ui.label(
                RichText::new(text(
                    lang,
                    "Добавьте ключ подключения",
                    "Add a connection key",
                ))
                .size(20.0),
            );
            ui.label(text(
                lang,
                "Получите готовый ключ у владельца сервера или установите свой сервер.",
                "Get a key from the server owner or install your own server.",
            ));
            ui.horizontal_wrapped(|ui| {
                if ui.button(text(lang, "Добавить ключ", "Add key")).clicked() {
                    self.open_profile(None);
                }
                if ui.button(t(lang, "ssh_wizard_open_btn")).clicked() {
                    self.ssh_wizard_open = true;
                }
            });
            return;
        }
        let name = self
            .keys
            .selected_key()
            .map(|k| k.name.clone())
            .unwrap_or_else(|| t(lang, "no_key_selected").into());
        let server = self
            .keys
            .selected_key()
            .map(|k| k.server_addr.clone())
            .unwrap_or_default();
        egui::Frame::new()
            .fill(palette.surface)
            .stroke(egui::Stroke::new(1.0_f32, palette.border))
            .corner_radius(8)
            .inner_margin(20)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal_wrapped(|ui| {
                    ui.vertical(|ui| {
                        ui.set_width((ui.available_width() - 125.0).max(130.0));
                        ui.add(egui::Label::new(RichText::new(name).size(20.0)).wrap());
                        ui.add(egui::Label::new(RichText::new(server).small().weak()).wrap());
                    });
                    let label = if connected {
                        t(lang, "disconnect")
                    } else if busy {
                        text(lang, "Отменить", "Cancel")
                    } else {
                        t(lang, "connect")
                    };
                    let enabled = self.vpn.state() != ConnectionState::Disconnecting
                        && (connected || busy || self.keys.selected_key().is_some());
                    if ui
                        .add_enabled(
                            enabled,
                            egui::Button::new(RichText::new(label).color(palette.on_accent))
                                .fill(palette.accent)
                                .min_size(egui::vec2(108.0, 38.0)),
                        )
                        .clicked()
                    {
                        self.do_connect();
                    }
                });
                ui.add_space(18.0);
                ui.columns(3, |cols| {
                    cols[0].small(format!(
                        "↓ {}",
                        format_bytes(self.vpn.stats().bytes_received)
                    ));
                    cols[1].with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
                        let status = if connected {
                            let seconds = self.uptime();
                            format!(
                                "{} {:02}:{:02}:{:02}",
                                self.connection_label(),
                                seconds / 3600,
                                seconds % 3600 / 60,
                                seconds % 60
                            )
                        } else {
                            self.connection_label().to_owned()
                        };
                        ui.add(egui::Label::new(RichText::new(status).small()).wrap());
                    });
                    cols[2].with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                        ui.small(format!("↑ {}", format_bytes(self.vpn.stats().bytes_sent)));
                    });
                });
            });
        ui.add_space(12.0);
        if (connected || busy) && self.vpn.stats().fallback {
            ui.colored_label(
                ui.visuals().warn_fg_color,
                t(lang, "bootstrap_fallback_label"),
            );
        }
        let route = self
            .keys
            .selected_key()
            .map(|key| Self::profile_route_summary(key, lang))
            .unwrap_or_default();
        ui.label(text(lang, "Маршрутизация", "Routing"));
        ui.weak(route);
        if ui
            .small_button(text(lang, "Изменить маршруты", "Change routes"))
            .clicked()
        {
            self.page = Page::Routes;
        }
        ui.separator();
        ui.label(text(
            lang,
            "Блокировка вне VPN",
            "Traffic blocking outside VPN",
        ));
        if connected
            && self
                .keys
                .selected_key()
                .is_some_and(|key| key.proxy_listen.is_some())
        {
            ui.weak(text(
                lang,
                "В режиме SOCKS5 блокировка остального трафика не применяется.",
                "SOCKS5 mode does not block traffic outside the proxy.",
            ));
        } else if connected {
            ui.weak(if self.vpn.kill_switch_enabled() {
                text(
                    lang,
                    "Включена для этого сеанса",
                    "Enabled for this session",
                )
            } else {
                text(
                    lang,
                    "Выключена для этого сеанса",
                    "Disabled for this session",
                )
            });
        } else {
            ui.weak(if self.settings.kill_switch {
                text(
                    lang,
                    "Включится при следующем подключении",
                    "Will be enabled on next connection",
                )
            } else {
                text(lang, "Выключена", "Disabled")
            });
        }
        ui.separator();
        if connected {
            let ip = self
                .vpn
                .stats()
                .vpn_ip
                .as_deref()
                .or_else(|| self.keys.selected_key().map(|k| k.vpn_ip.as_str()))
                .unwrap_or("");
            ui.label(t(lang, "vpn_ip_label"));
            ui.weak(ip);
            let quality = self.vpn.stats().quality_score;
            if quality > 0 {
                ui.small(format!(
                    "{}: {quality}%{}",
                    text(lang, "Качество канала", "Channel quality"),
                    if self.vpn.stats().server_adaptive_level >= 2 {
                        " · FEC"
                    } else {
                        ""
                    }
                ));
            } else {
                ui.weak(text(
                    lang,
                    "Качество канала пока неизвестно",
                    "Channel quality is not yet known",
                ));
            }
        } else {
            ui.weak(text(
                lang,
                "В полном туннеле Windows может запросить разрешение на подключение.",
                "Windows may ask for permission to connect in full tunnel mode.",
            ));
        }
        ui.add_space(10.0);
        ui.weak(text(
            lang,
            "Диагностика, установка сервера и журнал находятся в разделе «Сервис».",
            "Diagnostics, server installation and logs are on the Service page.",
        ));
    }

    fn draw_preferences(&mut self, ui: &mut egui::Ui) {
        let lang = self.settings.lang;
        ui.label(RichText::new(text(lang, "Оформление", "Appearance")).size(18.0));
        ui.label(text(lang, "Компоновка", "Layout"));
        let mut layout = self.settings.ui_layout;
        egui::ComboBox::from_id_salt("ui_layout")
            .width(ui.available_width().min(350.0))
            .selected_text(layout.label(lang))
            .show_ui(ui, |ui| {
                for value in [UiLayout::FluentDesktop, UiLayout::Compact] {
                    ui.selectable_value(&mut layout, value, value.label(lang));
                }
            });
        if layout != self.settings.ui_layout {
            self.set_ui_layout(ui.ctx(), layout);
        }
        ui.label(text(lang, "Цветовая тема", "Color theme"));
        let mut scheme = self.settings.effective_color_scheme();
        egui::ComboBox::from_id_salt("color_scheme")
            .width(ui.available_width().min(350.0))
            .selected_text(scheme.label(lang))
            .show_ui(ui, |ui| {
                for value in [ColorScheme::System, ColorScheme::Light, ColorScheme::Dark] {
                    ui.selectable_value(&mut scheme, value, value.label(lang));
                }
            });
        if scheme != self.settings.effective_color_scheme() {
            self.settings.color_scheme = Some(scheme);
            self.applied_dark = None;
            self.sync_appearance(ui.ctx());
            self.save_preferences();
        }
        ui.weak(text(
            lang,
            "Оформление меняется сразу. VPN и время сеанса сохраняются.",
            "Appearance changes immediately. VPN and session time are preserved.",
        ));
        ui.add_space(8.0);
        ui.separator();
        ui.label(text(lang, "Язык приложения", "Application language"));
        let mut language = self.settings.lang;
        egui::ComboBox::from_id_salt("language")
            .selected_text(language.label())
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut language, Lang::Ru, "Русский");
                ui.selectable_value(&mut language, Lang::En, "English");
            });
        if language != self.settings.lang {
            self.settings.lang = language;
            self.save_preferences();
        }
        ui.separator();
        ui.label(
            RichText::new(text(
                lang,
                "При входе в Windows",
                "When signing in to Windows",
            ))
            .size(18.0),
        );
        let mut startup = self.settings.connect_on_startup;
        if ui
            .checkbox(
                &mut startup,
                text(
                    lang,
                    "Запускать приложение и подключать VPN",
                    "Start the app and connect VPN",
                ),
            )
            .changed()
        {
            self.settings.connect_on_startup = startup;
            crate::platform_win::set_autostart(startup);
            self.save_preferences();
        }
        ui.separator();
        ui.label(
            RichText::new(text(lang, "Защита соединения", "Connection protection")).size(18.0),
        );
        if ui
            .add_enabled(
                can_edit_network(self.vpn.state()),
                egui::Checkbox::new(&mut self.settings.kill_switch, t(lang, "kill_switch")),
            )
            .changed()
        {
            self.dirty_at.get_or_insert(Instant::now());
        }
        ui.weak(text(
            lang,
            "Сетевые параметры применяются при следующем подключении.",
            "Network settings apply on the next connection.",
        ));
    }

    fn draw_masks(&mut self, ui: &mut egui::Ui) {
        let lang = self.settings.lang;
        let editable = can_edit_network(self.vpn.state());
        ui.weak(if editable {
            text(
                lang,
                "Общие параметры клиента. Применяются при следующем подключении.",
                "Shared client settings. Applied on next connection.",
            )
        } else {
            text(
                lang,
                "Для изменения параметров отключите VPN.",
                "Disconnect VPN to change these settings.",
            )
        });
        ui.add_enabled_ui(editable, |ui| {
            let before = (
                self.settings.preferred_mask.clone(),
                self.settings.adaptive_level,
                self.settings.polymorphic_mask,
                self.settings.share_mask_feedback,
                self.settings.receive_mask_hints,
                self.settings.country_code.clone(),
            );
            ui.label(t(lang, "mask_profile"));
            let choices = mask_choices_from_catalog(lang).unwrap_or_else(|| {
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
            let current = choices
                .iter()
                .find(|(id, _)| id == &self.settings.preferred_mask)
                .map(|(_, label)| label.as_str())
                .unwrap_or(&self.settings.preferred_mask);
            egui::ComboBox::from_id_salt("mask_profile")
                .width(ui.available_width().min(420.0))
                .selected_text(current)
                .show_ui(ui, |ui| {
                    for (id, label) in &choices {
                        ui.selectable_value(&mut self.settings.preferred_mask, id.clone(), label);
                    }
                });
            ui.label(t(lang, "adaptive_mode"));
            let levels = [
                text(lang, "Авто", "Auto"),
                text(lang, "Умеренный", "Light"),
                text(lang, "Агрессивный", "Aggressive"),
                text(lang, "Спутниковый", "Satellite"),
            ];
            egui::ComboBox::from_id_salt("adaptive_level")
                .width(ui.available_width().min(420.0))
                .selected_text(levels[(self.settings.adaptive_level as usize).min(3)])
                .show_ui(ui, |ui| {
                    for (i, label) in levels.iter().enumerate() {
                        ui.selectable_value(&mut self.settings.adaptive_level, i as u8, *label);
                    }
                });
            let preset =
                !self.settings.preferred_mask.is_empty() && self.settings.preferred_mask != "auto";
            if editable && !preset {
                self.settings.polymorphic_mask = false;
            }
            ui.add_enabled(
                preset,
                egui::Checkbox::new(
                    &mut self.settings.polymorphic_mask,
                    t(lang, "polymorphic_mask"),
                ),
            )
            .on_hover_text(t(lang, "polymorphic_mask_hint"));
            ui.separator();
            ui.label(RichText::new(t(lang, "mask_feedback_section")).size(18.0));
            ui.weak(t(lang, "mask_feedback_hint"));
            ui.checkbox(
                &mut self.settings.share_mask_feedback,
                t(lang, "share_mask_feedback"),
            );
            ui.checkbox(
                &mut self.settings.receive_mask_hints,
                t(lang, "receive_mask_hints"),
            );
            ui.label(t(lang, "country_code"));
            if ui
                .add(
                    egui::TextEdit::singleline(&mut self.settings.country_code)
                        .char_limit(2)
                        .desired_width(70.0),
                )
                .changed()
            {
                self.settings.country_code = self
                    .settings
                    .country_code
                    .chars()
                    .filter(char::is_ascii_alphabetic)
                    .take(2)
                    .collect::<String>()
                    .to_uppercase();
            }
            let after = (
                self.settings.preferred_mask.clone(),
                self.settings.adaptive_level,
                self.settings.polymorphic_mask,
                self.settings.share_mask_feedback,
                self.settings.receive_mask_hints,
                self.settings.country_code.clone(),
            );
            if before != after {
                self.dirty_at.get_or_insert(Instant::now());
            }
        });
    }

    fn draw_service(&mut self, ui: &mut egui::Ui) {
        let lang = self.settings.lang;
        ui.label(RichText::new(text(lang, "Установка сервера", "Server installation")).size(18.0));
        if ui.button(t(lang, "ssh_wizard_open_btn")).clicked() {
            self.ssh_wizard_open = true;
        }
        ui.separator();
        self.draw_service_tools(ui, lang);
        ui.add_enabled_ui(can_edit_network(self.vpn.state()), |ui| {
            egui::CollapsingHeader::new(t(lang, "bootstrap_section")).show(ui, |ui| {
                ui.weak(t(lang, "bootstrap_hint"));
                let mut changed = false;
                for (label, value, password) in [
                    (
                        t(lang, "bootstrap_cdn_url"),
                        &mut self.settings.bootstrap_cdn_url,
                        false,
                    ),
                    (
                        t(lang, "bootstrap_telegram_token"),
                        &mut self.settings.bootstrap_telegram_token,
                        true,
                    ),
                    (
                        t(lang, "bootstrap_telegram_chat"),
                        &mut self.settings.bootstrap_telegram_chat,
                        false,
                    ),
                    (
                        t(lang, "bootstrap_github"),
                        &mut self.settings.bootstrap_github,
                        false,
                    ),
                    (
                        t(lang, "server_signing_key"),
                        &mut self.settings.server_signing_key,
                        false,
                    ),
                ] {
                    ui.label(label);
                    changed |= ui
                        .add(
                            egui::TextEdit::singleline(value)
                                .password(password)
                                .desired_width(f32::INFINITY),
                        )
                        .changed();
                }
                if changed {
                    self.dirty_at.get_or_insert(Instant::now());
                }
            });
            self.draw_ext_section(ui, lang);
        });
        ui.separator();
        if ui
            .selectable_label(
                self.logs_open,
                text(lang, "Журнал подключения", "Connection log"),
            )
            .clicked()
        {
            self.logs_open = !self.logs_open;
            if self.logs_open {
                self.refresh_log();
            }
        }
        if self.logs_open {
            ui.horizontal_wrapped(|ui| {
                if ui.button(text(lang, "Обновить", "Refresh")).clicked() {
                    self.refresh_log();
                }
                if ui
                    .button(text(lang, "Сохранить журнал...", "Save log..."))
                    .clicked()
                {
                    if let Some(path) = crate::platform_win::choose_log_path(lang) {
                        if let Err(error) = std::fs::write(path, &self.log_text) {
                            self.show_error(error.to_string());
                        }
                    }
                }
            });
            if self.log_text.is_empty() {
                ui.weak(text(
                    lang,
                    "В журнале пока нет событий.",
                    "No log events yet.",
                ));
            } else {
                ui.add(
                    egui::TextEdit::multiline(&mut self.log_text)
                        .interactive(false)
                        .desired_rows(12)
                        .desired_width(f32::INFINITY),
                );
            }
        }
    }

    fn refresh_log(&mut self) {
        use std::io::{Read, Seek, SeekFrom};
        let mut output = String::new();
        if let Some(dir) = dirs::data_local_dir() {
            for name in ["client.log", "gui.log"] {
                if let Ok(mut file) = std::fs::File::open(dir.join("AIVPN").join(name)) {
                    if let Ok(len) = file.seek(SeekFrom::End(0)) {
                        let _ = file.seek(SeekFrom::Start(len.saturating_sub(65536)));
                    }
                    let mut bytes = Vec::new();
                    let _ = file.take(65536).read_to_end(&mut bytes);
                    output.push_str(name);
                    output.push('\n');
                    for line in String::from_utf8_lossy(&bytes).lines() {
                        let lower = line.to_ascii_lowercase();
                        if ![
                            "aivpn://",
                            "token",
                            "private",
                            "psk",
                            "device.key",
                            "public_key",
                            "pubkey",
                        ]
                        .iter()
                        .any(|word| lower.contains(word))
                        {
                            output.push_str(line);
                            output.push('\n');
                        }
                    }
                }
            }
        }
        self.log_text = output;
    }

    fn draw_error(&mut self, ui: &mut egui::Ui) {
        let error = self
            .error_msg
            .clone()
            .or_else(|| self.vpn.last_error.clone())
            .or_else(|| {
                (self.vpn.is_connected()
                    && self.uptime() > 30
                    && self.vpn.stats().bytes_received == 0
                    && self.vpn.stats().bytes_sent == 0)
                    .then(|| t(self.settings.lang, "no_traffic_warn").to_string())
            });
        if let Some(error) = error.filter(|e| !e.is_empty()) {
            ui.separator();
            ui.add(
                egui::Label::new(RichText::new(error).color(ui.visuals().error_fg_color)).wrap(),
            );
            if ui
                .small_button(text(self.settings.lang, "Скрыть сообщение", "Dismiss"))
                .clicked()
            {
                self.error_msg = None;
                self.vpn.last_error = None;
            }
        }
    }
}
