use super::appearance::rgb;
use super::*;
use iced::widget::{column, opaque, row, stack, Button};

impl App {
    pub(super) fn tr<'a>(&self, ru: &'a str, en: &'a str) -> &'a str {
        if self.settings.lang == "ru" {
            ru
        } else {
            en
        }
    }

    fn material(&self) -> bool {
        self.settings.ui_layout == UiLayout::Material
    }

    fn surface(&self) -> Color {
        match (self.material(), self.is_dark()) {
            (true, true) => rgb(0x242028),
            (true, false) => rgb(0xF0EBF4),
            (false, true) => rgb(0x232629),
            (false, false) => rgb(0xFCFCFC),
        }
    }

    fn panel<'a>(
        &self,
        content: impl Into<Element<'a, Message>>,
    ) -> iced::widget::Container<'a, Message> {
        let surface = self.surface();
        let radius = if self.material() { 18.0 } else { 5.0 };
        container(content)
            .padding(if self.material() { 20 } else { 16 })
            .width(Length::Fill)
            .style(move |theme: &Theme| container::Style {
                background: Some(surface.into()),
                border: Border {
                    radius: radius.into(),
                    width: if radius < 10.0 { 1.0 } else { 0.0 },
                    color: theme.extended_palette().background.strong.color,
                },
                ..Default::default()
            })
    }

    fn action<'a>(
        &self,
        label: impl Into<String>,
        message: Option<Message>,
        primary: bool,
    ) -> Button<'a, Message> {
        let material = self.material();
        button(text(label.into()).size(14))
            .padding([9, 14])
            .on_press_maybe(message)
            .style(move |theme, status| {
                let mut style = if primary {
                    button::primary(theme, status)
                } else {
                    button::secondary(theme, status)
                };
                if !primary {
                    style.border.width = 1.0;
                    style.border.color = theme.extended_palette().background.strong.color;
                }
                style.border.radius = if material { 16.0.into() } else { 4.0.into() };
                style
            })
    }

    fn nav_button(&self, page: UiPage, label: &str) -> Element<'_, Message> {
        let selected = self.page == page;
        let material = self.material();
        button(text(label.to_string()).size(14))
            .on_press(Message::PageSelected(page))
            .padding([11, 14])
            .width(Length::Fill)
            .style(move |theme, status| {
                let mut style = if selected {
                    button::secondary(theme, status)
                } else {
                    button::text(theme, status)
                };
                if selected {
                    style.background = Some(theme.extended_palette().primary.weak.color.into());
                }
                style.border.radius = if material { 18.0.into() } else { 4.0.into() };
                style
            })
            .into()
    }

    pub(super) fn section_title<'a>(&self, title: &'a str) -> Element<'a, Message> {
        text(title)
            .size(if self.material() { 26 } else { 22 })
            .into()
    }

    fn page_content(&self) -> Element<'_, Message> {
        match self.page {
            UiPage::Overview => self.view_overview(),
            UiPage::Profiles => self.view_profiles(),
            page => self.view_sections(page),
        }
    }

    pub(super) fn view_main(&self) -> Element<'_, Message> {
        let brand = row![
            image(image::Handle::from_bytes(
                include_bytes!("../../../../assets/brand/tray-dark.png").as_slice()
            ))
            .width(24)
            .height(24),
            text("AIVPN").size(20),
            text(concat!("v", env!("CARGO_PKG_VERSION"))).size(12),
            Space::new().width(Length::Fill),
            button(self.tr("EN", "RU"))
                .on_press(Message::ToggleLang)
                .style(button::text),
        ]
        .spacing(10)
        .align_y(Alignment::Center);
        let body: Element<Message> = if self.material() {
            let nav = column![
                self.nav_button(UiPage::Overview, "VPN"),
                self.nav_button(UiPage::Profiles, self.tr("Профили", "Profiles")),
                self.nav_button(UiPage::Routes, self.tr("Маршруты", "Routes")),
                self.nav_button(UiPage::Masks, self.tr("Маски", "Masks")),
                self.nav_button(UiPage::Settings, self.tr("Настройки", "Settings")),
                self.nav_button(UiPage::Service, self.tr("Сервис", "Service")),
            ]
            .spacing(6)
            .padding([20, 8])
            .width(160);
            row![
                nav,
                scrollable(
                    container(self.page_content())
                        .padding(24)
                        .width(Length::Fill)
                )
                .height(Length::Fill)
            ]
            .height(Length::Fill)
            .into()
        } else {
            let toolbar = row![
                self.connect_button(),
                self.edit_profile_button(),
                self.action(
                    self.tr("Удалить", "Delete"),
                    self.storage
                        .selected
                        .filter(|_| !self.profiles_locked())
                        .map(Message::RemoveProfile),
                    false
                ),
                Space::new().width(Length::Fill),
                self.action(
                    self.tr("Настройки", "Settings"),
                    Some(Message::PageSelected(UiPage::Settings)),
                    false
                ),
                self.action(
                    self.tr("Сервис", "Service"),
                    Some(Message::PageSelected(UiPage::Service)),
                    false
                ),
            ]
            .spacing(8)
            .align_y(Alignment::Center);
            let tabs = row![
                self.nav_button(UiPage::Overview, self.tr("Обзор", "Overview")),
                self.nav_button(UiPage::Routes, self.tr("Маршруты", "Routes")),
                self.nav_button(UiPage::Masks, self.tr("Маски", "Masks")),
            ]
            .spacing(4);
            let details = column![
                tabs,
                rule::horizontal(1),
                scrollable(
                    container(self.page_content())
                        .padding(18)
                        .width(Length::Fill)
                )
                .height(Length::Fill)
            ]
            .spacing(8)
            .width(Length::Fill)
            .height(Length::Fill);
            column![
                toolbar,
                rule::horizontal(1),
                row![self.profile_sidebar(), details]
                    .spacing(12)
                    .height(Length::Fill)
            ]
            .padding([8, 12])
            .spacing(10)
            .height(Length::Fill)
            .into()
        };
        let footer = row![
            text(self.status_label()).size(12),
            Space::new().width(Length::Fill),
            button(text(self.tr("Журнал", "Log")).size(12))
                .on_press(Message::Keyboard(
                    iced::keyboard::Key::Character("l".into()),
                    iced::keyboard::Modifiers::CTRL
                ))
                .style(button::text),
        ]
        .align_y(Alignment::Center)
        .padding([4, 16]);
        container(column![
            container(brand).padding([12, 20]),
            rule::horizontal(1),
            body,
            rule::horizontal(1),
            footer
        ])
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }

    fn connect_button(&self) -> Element<'_, Message> {
        let (label, message) = match self.status {
            VpnStatus::Connecting => (self.tr("Отменить", "Cancel"), Some(Message::Disconnect)),
            VpnStatus::Connected { .. } => (
                self.tr("Отключить", "Disconnect"),
                Some(Message::Disconnect),
            ),
            _ => (
                self.tr("Подключить", "Connect"),
                self.storage
                    .selected_key()
                    .is_some()
                    .then_some(Message::Connect),
            ),
        };
        self.action(label, message, true).into()
    }

    pub(super) fn edit_profile_button(&self) -> Element<'_, Message> {
        self.action(
            self.tr("Изменить", "Edit"),
            self.storage
                .selected
                .filter(|_| !self.profiles_locked())
                .map(Message::ShowEditDialog),
            false,
        )
        .into()
    }

    fn profile_sidebar(&self) -> Element<'_, Message> {
        let mut items = column![text(self.tr("ПОДКЛЮЧЕНИЯ", "CONNECTIONS")).size(12)].spacing(8);
        for (i, key) in self.storage.keys.iter().enumerate() {
            let selected = self.storage.selected == Some(i);
            let content =
                column![text(&key.name).size(14), text(&key.server_addr).size(12)].spacing(4);
            items = items.push(
                button(content)
                    .on_press_maybe((!self.profiles_locked()).then_some(Message::SelectProfile(i)))
                    .width(Length::Fill)
                    .padding(10)
                    .style(move |theme: &Theme, status| {
                        let mut style = button::text(theme, status);
                        if selected {
                            style.background =
                                Some(theme.extended_palette().primary.weak.color.into());
                            style.text_color = theme.extended_palette().primary.weak.text;
                        }
                        style.border.radius = 4.0.into();
                        style
                    }),
            );
        }
        if self.storage.keys.is_empty() {
            items = items.push(
                text(self.tr("Добавьте ключ для подключения", "Add a connection key")).size(13),
            );
        }
        let hint: Element<Message> = if self.profiles_locked() {
            text(self.tr(
                "Профили доступны после отключения",
                "Disconnect to change profiles",
            ))
            .size(12)
            .into()
        } else {
            Space::new().into()
        };
        column![
            scrollable(items).height(Length::Fill),
            hint,
            self.action(
                self.tr("Добавить", "Add"),
                (!self.profiles_locked()).then_some(Message::ShowAddDialog),
                false
            )
            .width(Length::Fill),
        ]
        .spacing(10)
        .width(180)
        .height(Length::Fill)
        .into()
    }

    fn status_label(&self) -> &str {
        match self.status {
            VpnStatus::Connecting => self.tr("Подключение...", "Connecting..."),
            VpnStatus::Connected { .. } => self.tr("В сети", "Connected"),
            VpnStatus::Error(_) => self.tr("Ошибка подключения", "Connection error"),
            VpnStatus::Disconnected => self.tr("Не подключено", "Disconnected"),
        }
    }

    fn elapsed(&self) -> String {
        if !matches!(self.status, VpnStatus::Connected { .. }) {
            return "00:00".into();
        }
        self.stats
            .connected_since
            .map(|since| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(since);
                let secs = now.saturating_sub(since) / 1000;
                format!(
                    "{:02}:{:02}:{:02}",
                    secs / 3600,
                    (secs % 3600) / 60,
                    secs % 60
                )
            })
            .unwrap_or_else(|| {
                self.tr("Время пока неизвестно", "Uptime unavailable")
                    .into()
            })
    }

    pub(super) fn route_summary(&self) -> String {
        let full = self.storage.selected_key().is_some_and(|k| k.full_tunnel);
        let includes = !self.settings.include_routes.trim().is_empty();
        let excludes = !self.settings.exclude_routes.trim().is_empty();
        let base = if full {
            self.tr("Весь трафик через VPN", "All traffic through VPN")
        } else if includes {
            self.tr(
                "Указанные сети и маршруты сервера",
                "Included networks and server routes",
            )
        } else {
            self.tr("Маршруты сервера", "Server routes")
        };
        if excludes {
            format!(
                "{}{}",
                base,
                self.tr(", с исключениями", ", with exclusions")
            )
        } else {
            base.into()
        }
    }

    fn view_overview(&self) -> Element<'_, Message> {
        let theme = self.theme();
        let muted = theme.extended_palette().background.strong.text;
        let status_color = match self.status {
            VpnStatus::Connected { .. } => theme.palette().success,
            VpnStatus::Connecting => theme.palette().warning,
            VpnStatus::Error(_) => theme.palette().danger,
            _ => theme.palette().text,
        };
        let mut content =
            column![self.section_title(self.tr("Подключение", "Connection"))].spacing(20);
        if self.storage.keys.is_empty() {
            return content
                .push(
                    self.panel(
                        column![
                            text(
                                self.tr("Ваш VPN начинается с ключа", "Your VPN starts with a key")
                            )
                            .size(22),
                            text(self.tr(
                                "Добавьте готовый профиль или установите свой сервер.",
                                "Add a profile or install your own server."
                            ))
                            .size(14),
                            self.action(
                                self.tr("Добавить ключ", "Add key"),
                                Some(Message::ShowAddDialog),
                                true
                            ),
                            self.action(
                                self.tr("Установить сервер", "Install server"),
                                Some(Message::PageSelected(UiPage::Service)),
                                false
                            ),
                        ]
                        .spacing(18),
                    ),
                )
                .into();
        }
        let profile_name = self
            .storage
            .selected_key()
            .map(|k| k.name.as_str())
            .unwrap_or(self.tr("Выберите профиль", "Select a profile"));
        let status = column![
            text(self.status_label()).size(24).color(status_color),
            text(profile_name).size(14)
        ]
        .spacing(8)
        .width(Length::Fill);
        let summary: Element<Message> = if self.material() {
            row![status, self.connect_button()]
                .spacing(12)
                .align_y(Alignment::Center)
                .into()
        } else {
            status.into()
        };
        let connected = matches!(self.status, VpnStatus::Connected { .. });
        let rx = if connected {
            self.stats.bytes_received
        } else {
            0
        };
        let tx = if connected { self.stats.bytes_sent } else { 0 };
        content = content.push(
            self.panel(
                column![
                    summary,
                    row![
                        text(format!("↓ {}", format_bytes(rx))).size(13),
                        Space::new().width(Length::Fill),
                        text(self.elapsed()).size(13),
                        Space::new().width(Length::Fill),
                        text(format!("↑ {}", format_bytes(tx))).size(13)
                    ]
                    .spacing(8),
                ]
                .spacing(20),
            ),
        );
        if let VpnStatus::Error(error) = &self.status {
            content = content.push(text(error).size(14).color(status_color));
        }
        if self.bootstrap_fallback && self.profiles_locked() {
            content = content.push(
                text(t(&self.settings.lang, "Using built-in mask (fallback)"))
                    .size(13)
                    .color(theme.palette().warning),
            );
        }
        if let Some(key) = self.storage.selected_key() {
            let kill_switch = self.kill_switch_value();
            let kill_label = if connected {
                self.tr("Блокировка без VPN в сеансе", "Session kill switch")
            } else {
                self.tr(
                    "Блокировка без VPN при подключении",
                    "Kill switch on next connection",
                )
            };
            let mut details = column![
                text(self.tr("Параметры подключения", "Connection details")).size(17),
                self.detail(self.tr("Сервер", "Server"), &key.server_addr),
                self.detail(self.tr("Маршруты", "Routes"), &self.route_summary()),
                self.detail(
                    kill_label,
                    match kill_switch {
                        Some(true) => self.tr("Включена", "Enabled"),
                        Some(false) => self.tr("Выключена", "Disabled"),
                        None => self.tr(
                            "Неизвестно для восстановленного сеанса",
                            "Unknown for recovered session"
                        ),
                    }
                ),
            ]
            .spacing(16);
            if let VpnStatus::Connected { vpn_ip } = &self.status {
                details = details.push(self.detail(self.tr("Адрес VPN", "VPN address"), vpn_ip));
            }
            if connected && self.stats.quality_score > 0 {
                details = details.push(self.detail(
                    self.tr("Качество канала", "Link quality"),
                    &format!("{}%", self.stats.quality_score),
                ));
            }
            content = content.push(self.panel(details));
        }
        content
            .push(
                text(self.tr(
                    "Управление сервером и диагностика находятся в разделе «Сервис».",
                    "Server management and diagnostics are in Service.",
                ))
                .size(12)
                .color(muted),
            )
            .into()
    }

    fn detail<'a>(&self, label: &str, value: &str) -> Element<'a, Message> {
        column![
            text(label.to_owned()).size(12),
            text(value.to_owned()).size(14)
        ]
        .spacing(4)
        .into()
    }

    fn view_profiles(&self) -> Element<'_, Message> {
        let mut content = column![row![
            self.section_title(self.tr("Профили", "Profiles")),
            Space::new().width(Length::Fill),
            self.action(
                self.tr("Добавить", "Add"),
                (!self.profiles_locked()).then_some(Message::ShowAddDialog),
                true
            )
        ]
        .align_y(Alignment::Center)]
        .spacing(16);
        if self.profiles_locked() {
            content = content.push(
                text(self.tr(
                    "Отключите VPN для изменения профилей.",
                    "Disconnect VPN to edit profiles.",
                ))
                .size(13),
            );
        }
        for (i, key) in self.storage.keys.iter().enumerate() {
            let selected = self.storage.selected == Some(i);
            content = content.push(
                self.panel(
                    column![
                        text(&key.name).size(18),
                        text(&key.server_addr).size(13),
                        row![
                            self.action(
                                if selected {
                                    self.tr("Выбран", "Selected")
                                } else {
                                    self.tr("Выбрать", "Select")
                                },
                                (!self.profiles_locked() && !selected)
                                    .then_some(Message::SelectProfile(i)),
                                selected
                            ),
                            self.action(
                                self.tr("Изменить", "Edit"),
                                (!self.profiles_locked()).then_some(Message::ShowEditDialog(i)),
                                false
                            ),
                            self.action(
                                self.tr("Удалить", "Delete"),
                                (!self.profiles_locked()).then_some(Message::RemoveProfile(i)),
                                false
                            ),
                        ]
                        .spacing(8)
                    ]
                    .spacing(12),
                ),
            );
        }
        if self.storage.keys.is_empty() {
            content = content.push(
                text(self.tr(
                    "Профилей пока нет. Добавьте ключ подключения.",
                    "No profiles yet. Add a connection key.",
                ))
                .size(14),
            );
        }
        content.into()
    }

    pub(super) fn view_appearance_settings(&self) -> Element<'_, Message> {
        let selected_scheme = self
            .settings
            .color_scheme
            .unwrap_or(if self.settings.dark_mode {
                ColorScheme::Dark
            } else {
                ColorScheme::Light
            });
        let mut schemes = row![].spacing(8);
        for (scheme, ru, en) in [
            (ColorScheme::System, "Системная", "System"),
            (ColorScheme::Light, "Светлая", "Light"),
            (ColorScheme::Dark, "Темная", "Dark"),
        ] {
            schemes = schemes.push(self.action(
                self.tr(ru, en),
                Some(Message::ColorSchemeChanged(scheme)),
                selected_scheme == scheme,
            ));
        }
        column![
            text(self.tr("Компоновка", "Layout")).size(16),
            row![
                self.action(
                    "Material",
                    Some(Message::LayoutChanged(UiLayout::Material)),
                    self.material()
                ),
                self.action(
                    "KDE / Breeze",
                    Some(Message::LayoutChanged(UiLayout::Breeze)),
                    !self.material()
                ),
            ]
            .spacing(8),
            text(self.tr(
                "Меняется сразу. Соединение и открытые формы сохраняются.",
                "Applies immediately. Keeps your connection and open forms."
            ))
            .size(12),
            text(self.tr("Цветовая тема", "Color scheme")).size(16),
            schemes,
        ]
        .spacing(14)
        .into()
    }

    pub(super) fn dialog_overlay<'a>(
        &self,
        base: Element<'a, Message>,
        dialog: Element<'a, Message>,
    ) -> Element<'a, Message> {
        stack![
            base,
            opaque(
                container(dialog)
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .style(|_| container::Style {
                        background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.45).into()),
                        ..Default::default()
                    })
            )
        ]
        .into()
    }

    pub(super) fn view_delete_confirmation(&self) -> Element<'_, Message> {
        let name = self
            .pending_remove
            .and_then(|i| self.storage.keys.get(i))
            .map(|k| k.name.as_str())
            .unwrap_or("");
        let dialog = self
            .panel(
                column![
                    text(self.tr("Удалить профиль?", "Delete profile?")).size(22),
                    text(name).size(16),
                    text(self.tr(
                        "Ключ будет удален только из этого приложения.",
                        "The key will be removed from this app."
                    ))
                    .size(14),
                    row![
                        self.action(
                            self.tr("Отмена", "Cancel"),
                            Some(Message::CancelRemoveProfile),
                            false
                        ),
                        self.action(
                            self.tr("Удалить", "Delete"),
                            Some(Message::ConfirmRemoveProfile),
                            true
                        )
                    ]
                    .spacing(8),
                ]
                .spacing(18),
            )
            .max_width(440);
        container(dialog).center(Length::Fill).padding(24).into()
    }
}
