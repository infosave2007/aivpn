use super::*;
use aivpn_desktop_agent::{
    client::editor::{Completion, Editor, Operation, Route},
    connection::ConnectionDocument,
    policy::Selector,
};
use iced::widget::{column, row};

pub(super) type Panel = Editor;

#[derive(Debug, Clone)]
pub enum Event {
    Install,
    Run(Operation),
    Finished(Result<Completion, String>),
    Register,
    Start,
    Stop,
    DeleteProfile,
    SelectProfile(String),
    Acknowledge(bool),
    UseDns,
    SetDns,
    Path(String),
    Browse,
    Chosen(Option<std::path::PathBuf>),
    NewRoute(Route),
    Add,
    DefaultRoute(Route),
    SplitEnabled(bool),
    RuleRoute(usize, Route),
    Destination(usize, String),
    Inherit(usize, bool),
    Move(usize, bool),
    DeleteRule(usize),
    Validate,
    Apply,
    Remove,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivpn_desktop_agent::{
        client::editor::Snapshot,
        policy::{Action, Owner},
        protocol::BackendState,
    };

    #[test]
    fn editor_keeps_app_rules_when_service_readiness_changes() {
        let (mut app, _) = App::from_state(AppSettings::default(), KeyStorage::default(), None);
        let snapshot = Snapshot {
            owner: Owner::LinuxUser { uid: 1000 },
            backend: BackendState::Guarded,
            global_dns_profile: Some("vpn".into()),
            profiles: Vec::new(),
            policy: None,
        };
        let _ = app.update_app_routing(Event::Finished(Ok(Completion {
            snapshot: snapshot.clone(),
            selected_profile: None,
            replace_draft: true,
            message: String::new(),
        })));
        let _ = app.update_app_routing(Event::SelectProfile("vpn".into()));
        let _ = app.update_app_routing(Event::Path("/usr/bin/true".into()));
        let _ = app.update_app_routing(Event::NewRoute(Route::Vpn));
        let _ = app.update_app_routing(Event::Add);
        assert!(matches!(
            app.app_routing.draft.as_ref().unwrap().document.rules[0].action,
            Action::Vpn { .. }
        ));
        let _ = app.update_app_routing(Event::Destination(0, "203.0.113.0/24".into()));
        let _ = app.update_app_routing(Event::Inherit(0, false));
        let _ = app.update_app_routing(Event::Finished(Ok(Completion {
            snapshot,
            selected_profile: None,
            replace_draft: false,
            message: "Готовность обновлена".into(),
        })));
        let rule = &app.app_routing.draft.as_ref().unwrap().document.rules[0];
        assert_eq!(rule.destination.as_deref(), Some("203.0.113.0/24"));
        assert!(!rule.inherit_children);
        app.app_routing.busy = true;
        app.app_routing.inspecting = true;
        let _ = app.update_app_routing(Event::Path("/usr/bin/false".into()));
        assert_eq!(app.app_routing.new_path, "/usr/bin/false");
        app.app_routing.inspecting = false;
        let _ = app.update_app_routing(Event::Path("/usr/bin/changed".into()));
        assert_eq!(app.app_routing.new_path, "/usr/bin/false");
        app.app_routing.busy = false;
        for layout in [UiLayout::Material, UiLayout::Breeze] {
            app.set_layout(layout);
            let _ = app.view_app_routing();
        }
        let _ = app.update_app_routing(Event::DeleteRule(0));
        assert!(app
            .app_routing
            .draft
            .as_ref()
            .unwrap()
            .document
            .rules
            .is_empty());
    }
}

impl App {
    pub(super) fn update_app_routing(&mut self, event: Event) -> Task<Message> {
        if let Event::Finished(result) = event {
            self.app_routing.complete(result);
            return Task::none();
        }
        if self.app_routing.busy && !self.app_routing.inspecting {
            return Task::none();
        }
        if matches!(event, Event::Install) {
            self.app_routing.busy = true;
            self.app_routing.error = None;
            return Task::perform(
                async {
                    tokio::task::spawn_blocking(|| {
                        aivpn_client::installer::run(vec!["install".into()], true)
                            .map_err(|error| error.to_string())?;
                        Operation::Refresh.execute()
                    })
                    .await
                    .map_err(|error| error.to_string())?
                },
                |result| Message::AppRouting(Event::Finished(result)),
            );
        }
        if matches!(event, Event::Browse) {
            return Task::perform(
                async {
                    rfd::AsyncFileDialog::new()
                        .pick_file()
                        .await
                        .map(|file| file.path().to_path_buf())
                },
                |path| Message::AppRouting(Event::Chosen(path)),
            );
        }
        let result = (|| -> Result<Option<Operation>, String> {
            let options = self.desktop_client_options();
            let panel = &mut self.app_routing;
            let operation = match event {
                Event::Run(operation) => {
                    if matches!(operation, Operation::Launch(_)) && !panel.can_launch() {
                        return Err(
                            "Сначала примените черновик правил и дождитесь ответа службы".into(),
                        );
                    }
                    operation
                }
                Event::Install | Event::Finished(_) => unreachable!(),
                Event::Register | Event::Start => {
                    let key = self
                        .storage
                        .selected_key()
                        .ok_or("Выберите локальный ключ подключения")?;
                    let connection =
                        ConnectionDocument::from_key(&key.key).map_err(|e| e.to_string())?;
                    if matches!(event, Event::Register) {
                        Operation::Register(connection)
                    } else {
                        Operation::StartConfigured {
                            profile: panel.selected().map_err(|e| e.to_string())?,
                            connection,
                            options,
                            certificate_file: key
                                .mtls_cert
                                .as_deref()
                                .filter(|path| !path.is_empty())
                                .map(std::path::PathBuf::from),
                        }
                    }
                }
                Event::Stop => Operation::Stop(panel.selected().map_err(|e| e.to_string())?),
                Event::DeleteProfile => {
                    Operation::Delete(panel.selected().map_err(|e| e.to_string())?)
                }
                Event::SetDns => Operation::SetDns {
                    profile: panel.selected().map_err(|e| e.to_string())?,
                    acknowledge_outage: panel.acknowledge_outage,
                },
                Event::Validate => Operation::Validate(
                    panel
                        .draft
                        .clone()
                        .ok_or("Сначала прочитайте состояние службы")?,
                ),
                Event::Apply => Operation::Apply(
                    panel
                        .draft
                        .clone()
                        .ok_or("Сначала прочитайте состояние службы")?,
                ),
                Event::Remove => Operation::Remove(
                    panel
                        .draft
                        .clone()
                        .ok_or("Сначала прочитайте состояние службы")?,
                ),
                Event::SelectProfile(profile) => {
                    panel.selected_profile = Some(profile);
                    return Ok(None);
                }
                Event::Acknowledge(value) => {
                    panel.acknowledge_outage = value;
                    return Ok(None);
                }
                Event::UseDns => {
                    panel.use_dns_profile().map_err(|e| e.to_string())?;
                    return Ok(None);
                }
                Event::Path(value) => {
                    panel.new_path = value;
                    return Ok(None);
                }
                Event::NewRoute(route) => {
                    panel.new_route = route;
                    return Ok(None);
                }
                Event::Add => {
                    panel.add_application().map_err(|e| e.to_string())?;
                    return Ok(None);
                }
                Event::Chosen(path) => {
                    if let Some(path) = path {
                        panel.new_path = path.to_str().ok_or("Путь должен быть в UTF-8")?.into();
                    }
                    return Ok(None);
                }
                Event::Browse => return Ok(None),
                edit => {
                    let draft = panel
                        .draft
                        .as_mut()
                        .ok_or("Сначала прочитайте состояние службы")?;
                    match edit {
                        Event::SplitEnabled(value) => {
                            draft.document.split_enabled = value;
                        }
                        Event::DefaultRoute(route) => {
                            draft.document.default_action = route
                                .action(panel.selected_profile.as_deref())
                                .map_err(|e| e.to_string())?
                        }
                        Event::RuleRoute(index, route) => {
                            let rule = draft
                                .document
                                .rules
                                .get_mut(index)
                                .ok_or("Правило уже удалено")?;
                            rule.action = route
                                .action(panel.selected_profile.as_deref())
                                .map_err(|e| e.to_string())?;
                        }
                        Event::Destination(index, value) => {
                            let rule = draft
                                .document
                                .rules
                                .get_mut(index)
                                .ok_or("Правило уже удалено")?;
                            rule.destination = if value.trim().is_empty() {
                                None
                            } else {
                                Some(value)
                            };
                        }
                        Event::Inherit(index, value) => {
                            draft
                                .document
                                .rules
                                .get_mut(index)
                                .ok_or("Правило уже удалено")?
                                .inherit_children = value
                        }
                        Event::Move(index, up) => {
                            let next = if up {
                                index.checked_sub(1)
                            } else {
                                index.checked_add(1)
                            };
                            if let Some(next) =
                                next.filter(|next| *next < draft.document.rules.len())
                            {
                                if index < draft.document.rules.len() {
                                    draft.document.rules.swap(index, next);
                                }
                            }
                        }
                        Event::DeleteRule(index) => {
                            if index < draft.document.rules.len() {
                                draft.document.rules.remove(index);
                            }
                        }
                        _ => unreachable!(),
                    }
                    return Ok(None);
                }
            };
            Ok(Some(operation))
        })();
        match result {
            Ok(Some(operation)) => {
                if self.app_routing.busy {
                    return Task::none();
                }
                self.app_routing.busy = true;
                self.app_routing.inspecting = matches!(operation, Operation::Inspect);
                self.app_routing.error = None;
                Task::perform(execute(operation), |result| {
                    Message::AppRouting(Event::Finished(result))
                })
            }
            Err(error) => {
                self.app_routing.error = Some(error);
                Task::none()
            }
            Ok(None) => Task::none(),
        }
    }

    pub(super) fn view_app_routing(&self) -> Element<'_, Message> {
        if !cfg!(feature = "app-routing") {
            return text(if self.settings.lang == "ru" {
                "Split по приложениям не включен в эту сборку"
            } else {
                "Application routing is not compiled into this build"
            })
            .into();
        }
        let panel = &self.app_routing;
        let action = |label, event| {
            let button = button(text(label));
            if panel.busy {
                button
            } else {
                button.on_press(Message::AppRouting(event))
            }
        };
        let mut body = column![
            self.section_title(self.tr("Маршрутизация приложений", "Application routing")),
            action(
                self.tr(
                    "Установить или обновить компоненты",
                    "Install or update components"
                ),
                Event::Install
            ),
            text(self.tr(
                aivpn_desktop_agent::client::editor::SHARED_DNS_NOTICE,
                aivpn_desktop_agent::client::editor::SHARED_DNS_NOTICE_EN
            )),
            action(
                self.tr("Перечитать и сбросить правки", "Reload and discard edits"),
                Event::Run(Operation::Refresh)
            ),
        ]
        .spacing(12);
        if let Some(snapshot) = &panel.snapshot {
            body = body.push(text(format!(
                "Backend: {:?}; DNS: {}",
                snapshot.backend,
                snapshot.global_dns_profile.as_deref().unwrap_or("SYSTEM")
            )));
            let profiles = snapshot
                .profiles
                .iter()
                .map(|profile| profile.id.clone())
                .collect::<Vec<_>>();
            body = body.push(pick_list(
                profiles,
                panel.selected_profile.clone(),
                |profile| Message::AppRouting(Event::SelectProfile(profile)),
            ));
            if let Some(profile) = snapshot
                .profiles
                .iter()
                .find(|profile| Some(&profile.id) == panel.selected_profile.as_ref())
            {
                body = body.push(text(format!(
                    "Session: {}; IPv4: {}; IPv6: {}",
                    profile.session_active, profile.ready_ipv4, profile.ready_ipv6
                )));
            }
            body = body.push(text(format!(
                "{}: {}",
                self.tr("Локальный ключ", "Local key"),
                self.storage
                    .selected_key()
                    .map(|key| key.name.as_str())
                    .unwrap_or("-")
            )));
            body = body.push(
                row![
                    action(
                        self.tr("Зарегистрировать ключ", "Register key"),
                        Event::Register
                    ),
                    action(self.tr("Запустить", "Start"), Event::Start),
                    action(self.tr("Остановить", "Stop"), Event::Stop),
                    action(
                        self.tr("Удалить профиль", "Delete profile"),
                        Event::DeleteProfile
                    )
                ]
                .spacing(6),
            );
            body = body.push(
                checkbox(panel.acknowledge_outage)
                    .label(self.tr(
                        "Понимаю ограничение общего DNS при разрыве VPN",
                        "I understand the shared DNS outage limitation",
                    ))
                    .on_toggle(|value| Message::AppRouting(Event::Acknowledge(value))),
            );
            body = body.push(
                row![
                    action(self.tr("DNS в черновик", "Use DNS in draft"), Event::UseDns),
                    action(
                        self.tr("Включить общий DNS", "Enable shared DNS"),
                        Event::SetDns
                    ),
                    action(
                        self.tr("Восстановить DNS", "Restore DNS"),
                        Event::Run(Operation::ClearDns)
                    )
                ]
                .spacing(6),
            );
        }
        if let Some(draft) = &panel.draft {
            body = body.push(
                checkbox(draft.document.split_enabled)
                    .label(self.tr("Split по приложениям", "Application split tunneling"))
                    .on_toggle(|value| Message::AppRouting(Event::SplitEnabled(value))),
            );
            body = body.push(text(self.tr(
                "Выключено: весь трафик через профиль DNS. Нажмите Применить; списки сохраняются.",
                "Off: all traffic uses the DNS profile. Click Apply; saved rules are retained.",
            )));
            body = body.push(text(self.tr(
                aivpn_desktop_agent::client::launch::NOTICE,
                aivpn_desktop_agent::client::launch::NOTICE_EN,
            )));
            body = body.push(text(self.tr("По умолчанию (SYSTEM: только выбранные приложения в VPN; VPN: выбранные приложения в обход)", "Default (SYSTEM: selected apps use VPN; VPN: selected apps bypass VPN)")));
            body = body.push(pick_list(
                Route::ALL,
                Some(Route::of(&draft.document.default_action)),
                |route| Message::AppRouting(Event::DefaultRoute(route)),
            ));
            body = body.push(
                row![
                    text_input(
                        self.tr("Абсолютный путь приложения", "Absolute application path"),
                        &panel.new_path
                    )
                    .on_input(|value| Message::AppRouting(Event::Path(value))),
                    action(self.tr("Выбрать", "Browse"), Event::Browse),
                    pick_list(Route::ALL, Some(panel.new_route), |route| {
                        Message::AppRouting(Event::NewRoute(route))
                    }),
                    action(self.tr("Добавить", "Add"), Event::Add)
                ]
                .spacing(6),
            );
            for (index, rule) in draft.document.rules.iter().enumerate() {
                if let Selector::Executable { path } = &rule.application {
                    let launch =
                        button(text(self.tr("Запустить приложение", "Launch application")));
                    body = body.push(if panel.can_launch() {
                        launch.on_press(Message::AppRouting(Event::Run(Operation::Launch(
                            std::path::PathBuf::from(path),
                        ))))
                    } else {
                        launch
                    });
                }
                let name = match &rule.application {
                    Selector::Any {} => "*",
                    Selector::Executable { path } => path,
                    Selector::WindowsPackage { sid } => sid,
                };
                body = body.push(
                    column![
                        text(format!("{}. {}", index + 1, name)),
                        row![
                            pick_list(Route::ALL, Some(Route::of(&rule.action)), move |route| {
                                Message::AppRouting(Event::RuleRoute(index, route))
                            }),
                            text_input("CIDR", rule.destination.as_deref().unwrap_or("")).on_input(
                                move |value| Message::AppRouting(Event::Destination(index, value))
                            ),
                            action("↑", Event::Move(index, true)),
                            action("↓", Event::Move(index, false)),
                            action(self.tr("Удалить", "Delete"), Event::DeleteRule(index))
                        ]
                        .spacing(6),
                        checkbox(rule.inherit_children)
                            .label(self.tr("Включая дочерние процессы", "Include child processes"))
                            .on_toggle(move |value| Message::AppRouting(Event::Inherit(
                                index, value
                            ))),
                    ]
                    .spacing(4),
                );
            }
            body = body.push(
                row![
                    action(self.tr("Проверить", "Validate"), Event::Validate),
                    action(self.tr("Применить", "Apply"), Event::Apply),
                    action(self.tr("Удалить правила", "Remove rules"), Event::Remove)
                ]
                .spacing(6),
            );
        }
        if panel.busy {
            body = body.push(text(
                self.tr("Ожидание службы...", "Waiting for service..."),
            ));
        }
        if !panel.message.is_empty() {
            body = body.push(text(&panel.message));
        }
        if let Some(error) = &panel.error {
            body = body.push(text(error).color(Color::from_rgb(0.9, 0.2, 0.1)));
        }
        body.into()
    }
}

async fn execute(operation: Operation) -> Result<Completion, String> {
    use aivpn_desktop_agent::{client::ClientError, protocol::ErrorCode};
    let dns = match &operation {
        Operation::SetDns {
            profile,
            acknowledge_outage,
        } => Some((Some(profile.clone()), *acknowledge_outage)),
        Operation::ClearDns => Some((None, true)),
        _ => None,
    };
    let reply = tokio::task::spawn_blocking(move || operation.execute_checked())
        .await
        .map_err(|error| format!("Запрос службы прерван: {error}"))?;
    match reply {
        Ok(completion) => Ok(completion),
        Err(ClientError::Rejected(ErrorCode::AccessDenied)) if dns.is_some() => {
            let (profile, acknowledged) = dns.unwrap();
            privilege::set_shared_dns(profile.as_deref(), acknowledged).await?;
            tokio::task::spawn_blocking(move || {
                Completion::confirm_dns(profile.as_deref()).map_err(|error| error.to_string())
            })
            .await
            .map_err(|error| format!("Повторное чтение состояния прервано: {error}"))?
        }
        Err(error) => Err(error.to_string()),
    }
}
