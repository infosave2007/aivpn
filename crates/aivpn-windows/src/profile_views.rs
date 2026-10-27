use crate::appearance::{text, Page};
use crate::localization::t;
use crate::ui_model::{can_edit_network, route_lines, RouteDraft};
use eframe::egui::{self, RichText};

impl crate::AivpnApp {
    pub(crate) fn open_profile(&mut self, index: Option<usize>) {
        if !can_edit_network(self.vpn.state()) {
            return;
        }
        self.editing_idx = index;
        self.dlg_reveal = false;
        self.dlg_error = None;
        if let Some(profile) = index.and_then(|i| self.keys.keys.get(i)) {
            self.dlg_name = profile.name.clone();
            self.dlg_key = profile.key.clone();
            self.dlg_full_tunnel = profile.full_tunnel;
            self.dlg_proxy = profile.proxy_listen.is_some();
            self.dlg_proxy_addr = profile
                .proxy_listen
                .clone()
                .unwrap_or_else(|| "127.0.0.1:1080".into());
            self.dlg_exclude_routes = profile.exclude_routes.join("\n");
            self.dlg_include_routes = profile.include_routes.join("\n");
            self.dlg_mtls_cert = profile.mtls_cert_path.clone().unwrap_or_default();
        } else {
            self.dlg_name.clear();
            self.dlg_key.clear();
            self.dlg_mtls_cert.clear();
            self.dlg_exclude_routes.clear();
            self.dlg_include_routes.clear();
            self.dlg_full_tunnel = true;
            self.dlg_proxy = false;
            self.dlg_proxy_addr = "127.0.0.1:1080".into();
        }
        self.show_dialog = true;
    }

    pub(crate) fn draw_profiles(&mut self, ui: &mut egui::Ui) {
        let lang = self.settings.lang;
        let editable = can_edit_network(self.vpn.state());
        if ui
            .add_enabled(
                editable,
                egui::Button::new(text(lang, "Добавить профиль", "Add profile")),
            )
            .clicked()
        {
            self.open_profile(None);
        }
        if !editable {
            ui.weak(text(
                lang,
                "Отключите VPN для выбора или изменения профиля.",
                "Disconnect VPN to select or change a profile.",
            ));
        }
        if self.keys.keys.is_empty() {
            ui.add_space(12.0);
            ui.label(t(lang, "no_keys"));
        }
        for i in 0..self.keys.keys.len() {
            let profile = &self.keys.keys[i];
            let selected = self.keys.selected == Some(i);
            let name = profile.name.clone();
            let server = profile.server_addr.clone();
            let summary = Self::profile_route_summary(profile, lang);
            let colors = crate::assets::fluent_colors(ui.visuals().dark_mode);
            egui::Frame::new()
                .fill(colors.surface)
                .stroke(egui::Stroke::new(
                    1.0_f32,
                    if selected {
                        colors.accent
                    } else {
                        colors.border
                    },
                ))
                .corner_radius(6)
                .inner_margin(16)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(name).size(18.0));
                    ui.add(egui::Label::new(RichText::new(server).small().weak()).wrap());
                    ui.weak(summary);
                    ui.horizontal_wrapped(|ui| {
                        if ui
                            .add_enabled(
                                editable && !selected,
                                egui::Button::new(if selected {
                                    text(lang, "Выбран", "Selected")
                                } else {
                                    text(lang, "Выбрать", "Select")
                                }),
                            )
                            .clicked()
                        {
                            let previous = self.keys.selected;
                            self.keys.selected = Some(i);
                            if let Err(error) = self.keys.save() {
                                self.keys.selected = previous;
                                self.show_error(error);
                            } else {
                                self.route_draft = None;
                                self.routes_saved = false;
                                self.routes_error = None;
                            }
                        }
                        if ui
                            .add_enabled(editable, egui::Button::new(t(lang, "edit")))
                            .clicked()
                        {
                            self.open_profile(Some(i));
                        }
                        if ui
                            .add_enabled(
                                editable,
                                egui::Button::new(
                                    RichText::new(t(lang, "delete"))
                                        .color(ui.visuals().error_fg_color),
                                ),
                            )
                            .clicked()
                        {
                            self.delete_profile = Some(i);
                        }
                    });
                });
            ui.add_space(4.0);
        }
    }

    fn save_profile(&mut self) {
        if !can_edit_network(self.vpn.state()) {
            return;
        }
        if self.dlg_name.trim().is_empty() || self.dlg_key.trim().is_empty() {
            self.dlg_error = Some(
                text(
                    self.settings.lang,
                    "Укажите название и ключ подключения.",
                    "Enter a name and connection key.",
                )
                .into(),
            );
            return;
        }
        let proxy = self
            .dlg_proxy
            .then(|| self.dlg_proxy_addr.trim().to_owned());
        if proxy.as_ref().is_some_and(String::is_empty) {
            self.dlg_error = Some(
                text(
                    self.settings.lang,
                    "Укажите адрес SOCKS5.",
                    "Enter the SOCKS5 address.",
                )
                .into(),
            );
            return;
        }
        let mtls =
            (!self.dlg_mtls_cert.trim().is_empty()).then(|| self.dlg_mtls_cert.trim().to_owned());
        let args = (
            route_lines(&self.dlg_exclude_routes),
            route_lines(&self.dlg_include_routes),
        );
        let result = if let Some(index) = self.editing_idx {
            self.keys.update_key(
                index,
                self.dlg_name.trim(),
                &self.dlg_key,
                self.dlg_full_tunnel,
                proxy,
                mtls,
                args.0,
                args.1,
            )
        } else {
            self.keys.add_key(
                self.dlg_name.trim(),
                &self.dlg_key,
                self.dlg_full_tunnel,
                proxy,
                mtls,
                args.0,
                args.1,
            )
        };
        match result {
            Ok(()) => {
                self.show_dialog = false;
                self.dlg_error = None;
                self.route_draft = None;
                self.routes_saved = false;
                self.page = Page::Profiles;
                self.dlg_key.clear();
                self.dlg_reveal = false;
            }
            Err(error) => {
                self.dlg_error = Some(match error.as_str() {
                    "Invalid connection key format" => text(
                        self.settings.lang,
                        "Проверьте ключ подключения AIVPN.",
                        "Check the AIVPN connection key.",
                    )
                    .into(),
                    "This key already exists" => text(
                        self.settings.lang,
                        "Такой ключ уже есть в списке профилей.",
                        "This key is already in the profile list.",
                    )
                    .into(),
                    _ => error,
                })
            }
        }
    }

    pub(crate) fn draw_profile_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_dialog {
            return;
        }
        let lang = self.settings.lang;
        let editable = can_edit_network(self.vpn.state());
        let mut save = false;
        let mut cancel = false;
        egui::Modal::new(egui::Id::new("profile_dialog"))
            .frame(egui::Frame::popup(&ctx.style()).inner_margin(24))
            .show(ctx, |ui| {
                ui.set_width((ctx.screen_rect().width() - 80.0).clamp(250.0, 440.0));
                ui.label(
                    RichText::new(if self.editing_idx.is_some() {
                        text(lang, "Изменить профиль", "Edit profile")
                    } else {
                        text(lang, "Добавить профиль", "Add profile")
                    })
                    .size(22.0),
                );
                ui.add_space(8.0);
                egui::ScrollArea::vertical()
                    .id_salt("profile_fields")
                    .max_height(
                        (ctx.screen_rect().height()
                            - if self.dlg_error.is_some() {
                                240.0
                            } else {
                                200.0
                            })
                        .max(140.0),
                    )
                    .show(ui, |ui| {
                        ui.add_enabled_ui(editable, |ui| {
                            ui.label(t(lang, "key_name"));
                            ui.add(
                                egui::TextEdit::singleline(&mut self.dlg_name)
                                    .desired_width(f32::INFINITY),
                            );
                            ui.label(t(lang, "key_value"));
                            ui.horizontal(|ui| {
                                let width = (ui.available_width() - 95.0).max(100.0);
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.dlg_key)
                                        .password(!self.dlg_reveal)
                                        .desired_width(width)
                                        .hint_text("aivpn://"),
                                );
                                if ui
                                    .button(if self.dlg_reveal {
                                        text(lang, "Скрыть", "Hide")
                                    } else {
                                        text(lang, "Показать", "Show")
                                    })
                                    .clicked()
                                {
                                    self.dlg_reveal = !self.dlg_reveal;
                                }
                            });
                            let mut mode = if self.dlg_proxy {
                                2
                            } else {
                                usize::from(!self.dlg_full_tunnel)
                            };
                            Self::draw_route_mode(ui, lang, &mut mode);
                            self.dlg_full_tunnel = mode == 0;
                            self.dlg_proxy = mode == 2;
                            if self.dlg_proxy {
                                ui.label(text(lang, "Адрес SOCKS5", "SOCKS5 address"));
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.dlg_proxy_addr)
                                        .desired_width(f32::INFINITY),
                                );
                            }
                            ui.label(t(lang, "mtls_cert_path"));
                            ui.horizontal(|ui| {
                                let width = (ui.available_width() - 95.0).max(100.0);
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.dlg_mtls_cert)
                                        .desired_width(width),
                                );
                                if ui.button(text(lang, "Обзор...", "Browse...")).clicked() {
                                    if let Some(path) = crate::platform_win::choose_mtls_file(lang)
                                    {
                                        self.dlg_mtls_cert = path;
                                    }
                                }
                            });
                            ui.weak(text(
                                lang,
                                "Включаемые и исключаемые сети находятся в разделе «Маршруты».",
                                "Included and excluded networks are on the Routes page.",
                            ));
                        });
                        if !editable {
                            ui.weak(text(
                                lang,
                                "Отключите VPN для сохранения профиля.",
                                "Disconnect VPN to save the profile.",
                            ));
                        }
                    });
                if let Some(error) = &self.dlg_error {
                    ui.add(
                        egui::Label::new(RichText::new(error).color(ui.visuals().error_fg_color))
                            .wrap(),
                    );
                }
                ui.add_space(12.0);
                ui.horizontal_wrapped(|ui| {
                    cancel = ui.button(t(lang, "cancel")).clicked();
                    save = ui
                        .add_enabled(editable, egui::Button::new(t(lang, "save")))
                        .clicked();
                });
                let popup_open = ctx.memory(|m| m.any_popup_open());
                if !popup_open {
                    cancel |=
                        ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape));
                    save |=
                        ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Enter));
                }
            });
        if cancel {
            self.show_dialog = false;
            self.dlg_error = None;
            self.dlg_key.clear();
            self.dlg_reveal = false;
        } else if save {
            self.save_profile();
        }
    }

    pub(crate) fn draw_delete_dialog(&mut self, ctx: &egui::Context) {
        let Some(index) = self.delete_profile else {
            return;
        };
        let Some(profile) = self.keys.keys.get(index) else {
            self.delete_profile = None;
            return;
        };
        let name = profile.name.clone();
        let lang = self.settings.lang;
        let mut remove = false;
        let mut cancel = false;
        egui::Modal::new(egui::Id::new("delete_profile")).show(ctx, |ui| {
            ui.set_width((ctx.screen_rect().width() - 80.0).clamp(250.0, 400.0));
            ui.label(RichText::new(text(lang, "Удалить профиль?", "Delete profile?")).size(22.0));
            ui.add(egui::Label::new(name).wrap());
            ui.weak(text(
                lang,
                "Ключ будет удален только из этого приложения.",
                "The key will only be removed from this app.",
            ));
            ui.horizontal(|ui| {
                cancel = ui.button(t(lang, "cancel")).clicked();
                remove = ui
                    .add_enabled(
                        can_edit_network(self.vpn.state()),
                        egui::Button::new(t(lang, "delete")),
                    )
                    .clicked();
            });
            cancel |= ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape));
        });
        if remove && can_edit_network(self.vpn.state()) {
            let previous = self.keys.keys.len();
            self.keys.remove_key(index);
            if self.keys.keys.len() == previous {
                self.show_error(
                    text(
                        lang,
                        "Не удалось удалить профиль. Проверьте доступ к файлу настроек.",
                        "Could not delete the profile. Check settings file access.",
                    )
                    .into(),
                );
            } else {
                self.route_draft = None;
                self.routes_saved = false;
                self.routes_error = None;
            }
        }
        if remove || cancel {
            self.delete_profile = None;
        }
    }

    fn draw_route_mode(ui: &mut egui::Ui, lang: crate::localization::Lang, mode: &mut usize) {
        let labels = [
            text(lang, "Весь трафик через VPN", "All traffic through VPN"),
            text(
                lang,
                "Сети профиля и сервера",
                "Profile and server networks",
            ),
            "SOCKS5",
        ];
        ui.label(text(lang, "Режим подключения", "Connection mode"));
        egui::ComboBox::from_id_salt("route_mode")
            .width(ui.available_width().min(420.0))
            .selected_text(labels[(*mode).min(2)])
            .show_ui(ui, |ui| {
                for (i, label) in labels.iter().enumerate() {
                    ui.selectable_value(mode, i, *label);
                }
            });
    }

    pub(crate) fn draw_routes(&mut self, ui: &mut egui::Ui) {
        let lang = self.settings.lang;
        let Some(index) = self.keys.selected else {
            ui.label(t(lang, "no_key_selected"));
            return;
        };
        let Some(key) = self.keys.keys.get(index) else {
            return;
        };
        if !self
            .route_draft
            .as_ref()
            .is_some_and(|d| d.matches(index, key))
        {
            self.route_draft = Some(RouteDraft::new(index, key, &self.settings.dns_proxy));
            self.routes_error = None;
            self.routes_saved = false;
        }
        ui.label(format!(
            "{}: {}",
            text(lang, "Профиль", "Profile"),
            key.name
        ));
        let editable = can_edit_network(self.vpn.state());
        ui.weak(if editable {
            text(
                lang,
                "Изменения применятся при следующем подключении.",
                "Changes apply on the next connection.",
            )
        } else {
            text(
                lang,
                "Параметры доступны для чтения. Для изменения отключите VPN.",
                "Settings are read-only. Disconnect VPN to change them.",
            )
        });
        let draft = self.route_draft.as_mut().unwrap();
        ui.add_enabled_ui(editable, |ui| {
            let mut mode = if draft.proxy {
                2
            } else {
                usize::from(!draft.full_tunnel)
            };
            Self::draw_route_mode(ui, lang, &mut mode);
            draft.full_tunnel = mode == 0;
            draft.proxy = mode == 2;
            if draft.proxy {
                ui.label(text(lang, "Адрес SOCKS5", "SOCKS5 address"));
                ui.add(
                    egui::TextEdit::singleline(&mut draft.proxy_addr).desired_width(f32::INFINITY),
                );
            } else {
                ui.label(text(
                    lang,
                    "Дополнительно направить через VPN",
                    "Additionally route through VPN",
                ));
                ui.add(
                    egui::TextEdit::multiline(&mut draft.include)
                        .desired_rows(3)
                        .desired_width(f32::INFINITY)
                        .hint_text("10.20.0.0/16"),
                );
                ui.label(t(lang, "exclude_routes"));
                ui.add(
                    egui::TextEdit::multiline(&mut draft.exclude)
                        .desired_rows(3)
                        .desired_width(f32::INFINITY)
                        .hint_text("192.168.0.0/16"),
                );
            }
            ui.separator();
            ui.label(text(
                lang,
                "DNS-прокси - общий параметр клиента",
                "DNS proxy - shared client setting",
            ));
            ui.add(
                egui::TextEdit::singleline(&mut draft.dns)
                    .desired_width(f32::INFINITY)
                    .hint_text("127.0.0.1:5353"),
            );
        });
        let save = ui
            .add_enabled(editable, egui::Button::new(t(lang, "save")))
            .clicked();
        if let Some(error) = &self.routes_error {
            ui.colored_label(ui.visuals().error_fg_color, error);
        }
        if self.routes_saved {
            ui.weak(text(
                lang,
                "Параметры сохранены для следующего подключения.",
                "Settings saved for the next connection.",
            ));
        }
        if save {
            self.save_routes();
        }
    }

    pub(crate) fn save_routes(&mut self) {
        if !can_edit_network(self.vpn.state()) {
            return;
        }
        let Some(draft) = self.route_draft.as_ref() else {
            return;
        };
        let Some(key) = self
            .keys
            .keys
            .get(draft.index)
            .filter(|key| draft.matches(draft.index, key))
        else {
            return;
        };
        if self.keys.selected != Some(draft.index) {
            return;
        }
        let dns = draft.dns.trim().to_owned();
        let proxy = draft.proxy.then(|| draft.proxy_addr.trim().to_owned());
        if proxy.as_ref().is_some_and(String::is_empty) {
            self.routes_error = Some(
                text(
                    self.settings.lang,
                    "Укажите адрес SOCKS5.",
                    "Enter the SOCKS5 address.",
                )
                .into(),
            );
            return;
        }
        let old_dns = self.settings.dns_proxy.clone();
        self.settings.dns_proxy = dns;
        self.routes_saved = false;
        if let Err(error) = self.settings.save() {
            self.settings.dns_proxy = old_dns;
            self.routes_error = Some(error);
            return;
        }
        let result = self.keys.update_key(
            draft.index,
            &key.name.clone(),
            &key.key.clone(),
            draft.full_tunnel,
            proxy,
            key.mtls_cert_path.clone(),
            route_lines(&draft.exclude),
            route_lines(&draft.include),
        );
        match result {
            Ok(()) => {
                self.routes_error = None;
                self.routes_saved = true;
            }
            Err(error) => {
                self.settings.dns_proxy = old_dns;
                self.routes_error = Some(match self.settings.save() {
                    Ok(()) => error,
                    Err(rollback) => format!(
                        "{}: {error}. {}: {rollback}",
                        text(
                            self.settings.lang,
                            "Не удалось сохранить профиль",
                            "Could not save profile"
                        ),
                        text(
                            self.settings.lang,
                            "Не удалось восстановить прежний DNS на диске",
                            "Could not restore previous DNS on disk"
                        )
                    ),
                });
            }
        }
    }
}
