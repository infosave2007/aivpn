use crate::{appearance::text, localization::Lang};
use aivpn_desktop_agent::{
    client::editor::{Completion, Editor, Operation, Route},
    connection::ConnectionDocument,
    policy::Selector,
};
use std::sync::mpsc::{self, Receiver, TryRecvError};

#[derive(Default)]
pub(crate) struct Panel {
    editor: Editor,
    pending: Option<Receiver<Result<Completion, String>>>,
    last_request: Option<std::time::Instant>,
}
impl Panel {
    pub(crate) fn split_enabled(&self) -> bool {
        self.editor
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.policy.as_ref())
            .is_none_or(|policy| policy.split_enabled)
    }
    pub(crate) fn policy_was_seen(&self) -> bool {
        self.editor
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.policy.is_some())
    }
    pub(crate) fn complete_home(&mut self, completion: Completion) {
        self.editor.observe(completion.snapshot);
    }
    pub(crate) fn poll(&mut self) {
        let result = match self.pending.as_ref().map(Receiver::try_recv) {
            Some(Ok(result)) => Some(result),
            Some(Err(TryRecvError::Disconnected)) => Some(Err("Запрос к службе прерван".into())),
            _ => None,
        };
        if let Some(result) = result {
            self.pending = None;
            self.editor.complete(result);
        }
    }
    fn submit(&mut self, operation: Operation, context: egui::Context) {
        let inspecting = matches!(operation, Operation::Inspect);
        self.submit_with(move || execute(operation), inspecting, context);
    }
    fn submit_with(
        &mut self,
        operation: impl FnOnce() -> Result<Completion, String> + Send + 'static,
        inspecting: bool,
        context: egui::Context,
    ) {
        if self.editor.busy {
            return;
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        self.editor.busy = true;
        self.editor.inspecting = inspecting;
        self.editor.error = None;
        self.last_request = Some(std::time::Instant::now());
        let spawned = std::thread::Builder::new()
            .name("aivpn-control".into())
            .spawn(move || {
                let _ = sender.send(operation());
                context.request_repaint();
            });
        match spawned {
            Ok(_) => self.pending = Some(receiver),
            Err(error) => self.editor.complete(Err(error.to_string())),
        }
    }
    fn draw(
        &mut self,
        ui: &mut egui::Ui,
        lang: Lang,
        key: Option<&crate::key_storage::ConnectionKey>,
        options: aivpn_desktop_agent::connection::DesktopClientOptions,
    ) {
        if !cfg!(feature = "app-routing") {
            ui.label(text(
                lang,
                "Split по приложениям не включен в эту сборку",
                "Application routing is not compiled into this build",
            ));
            return;
        }
        if ui
            .add_enabled(
                !self.editor.busy,
                egui::Button::new(text(
                    lang,
                    "Установить или обновить компоненты",
                    "Install or update components",
                )),
            )
            .clicked()
        {
            self.submit_with(
                || {
                    let code = aivpn_client::installer::run(vec!["install".into()], true)
                        .map_err(|error| error.to_string())?;
                    let mut completion = Operation::Refresh.execute()?;
                    if code != std::process::ExitCode::SUCCESS {
                        completion.message =
                            "Для завершения установки нужна перезагрузка Windows".into();
                    }
                    Ok(completion)
                },
                false,
                ui.ctx().clone(),
            );
            return;
        }
        let mut operation = None;
        if !self.editor.busy
            && self.editor.error.is_none()
            && self
                .last_request
                .is_none_or(|last| last.elapsed() >= std::time::Duration::from_secs(2))
        {
            operation = Some(if self.editor.snapshot.is_none() {
                Operation::Refresh
            } else {
                Operation::Inspect
            });
        }
        let panel = &mut self.editor;
        ui.label(text(
            lang,
            aivpn_desktop_agent::client::editor::SHARED_DNS_NOTICE,
            aivpn_desktop_agent::client::editor::SHARED_DNS_NOTICE_EN,
        ));
        ui.add_enabled_ui(!panel.busy || panel.inspecting, |ui| {
            if ui.add_enabled(!panel.busy, egui::Button::new(text(lang, "Перечитать и сбросить правки", "Reload and discard edits"))).clicked() { operation = Some(Operation::Refresh); }
            if let Some(snapshot) = &panel.snapshot {
                ui.label(format!("Backend: {:?}; DNS: {}", snapshot.backend, snapshot.global_dns_profile.as_deref().unwrap_or("SYSTEM")));
                egui::ComboBox::from_id_salt("routing-profile").selected_text(panel.selected_profile.as_deref().unwrap_or("VPN profile")).show_ui(ui, |ui| {
                    for profile in &snapshot.profiles {
                        ui.selectable_value(&mut panel.selected_profile, Some(profile.id.clone()), &profile.id);
                    }
                });
                if let Some(profile) = snapshot.profiles.iter().find(|profile| Some(&profile.id) == panel.selected_profile.as_ref()) {
                    ui.label(format!("Session: {}; IPv4: {}; IPv6: {}", profile.session_active, profile.ready_ipv4, profile.ready_ipv6));
                }
                ui.label(format!("{}: {}", text(lang, "Локальный ключ", "Local key"), key.map(|key| key.name.as_str()).unwrap_or("-")));
                ui.horizontal_wrapped(|ui| {
                    for (label, register) in [(text(lang, "Зарегистрировать ключ", "Register key"), true), (text(lang, "Запустить", "Start"), false)] {
                        if ui.add_enabled(!panel.busy, egui::Button::new(label)).clicked() {
                            let next = key.ok_or_else(|| "Выберите локальный ключ подключения".to_string()).and_then(|key| ConnectionDocument::from_key(&key.key).map_err(|e| e.to_string())).and_then(|connection| {
                                if register { Ok(Operation::Register(connection)) } else { Ok(Operation::StartConfigured { profile: panel.selected().map_err(|e| e.to_string())?, connection, options: options.clone(), certificate_file: key.and_then(|key| key.mtls_cert_path.as_deref()).filter(|path| !path.is_empty()).map(std::path::PathBuf::from) }) }
                            });
                            match next { Ok(next) => operation = Some(next), Err(error) => panel.error = Some(error) }
                        }
                    }
                    if ui.add_enabled(!panel.busy, egui::Button::new(text(lang, "Остановить", "Stop"))).clicked() {
                        match panel.selected() { Ok(profile) => operation = Some(Operation::Stop(profile)), Err(e) => panel.error = Some(e.to_string()) }
                    }
                    if ui.add_enabled(!panel.busy, egui::Button::new(text(lang, "Удалить профиль", "Delete profile"))).clicked() {
                        match panel.selected() { Ok(profile) => operation = Some(Operation::Delete(profile)), Err(e) => panel.error = Some(e.to_string()) }
                    }
                });
                ui.checkbox(&mut panel.acknowledge_outage, text(lang, "Понимаю ограничение общего DNS при разрыве VPN", "I understand the shared DNS outage limitation"));
                ui.horizontal_wrapped(|ui| {
                    if ui.add_enabled(!panel.busy, egui::Button::new(text(lang, "DNS в черновик", "Use DNS in draft"))).clicked() {
                        if let Err(e) = panel.use_dns_profile() { panel.error = Some(e.to_string()); }
                    }
                    if ui.add_enabled(!panel.busy, egui::Button::new(text(lang, "Включить общий DNS", "Enable shared DNS"))).clicked() {
                        match panel.selected() { Ok(profile) => operation = Some(Operation::SetDns { profile, acknowledge_outage: panel.acknowledge_outage }), Err(e) => panel.error = Some(e.to_string()) }
                    }
                    if ui.add_enabled(!panel.busy, egui::Button::new(text(lang, "Восстановить DNS", "Restore DNS"))).clicked() { operation = Some(Operation::ClearDns); }
                });
            }
            if panel.draft.is_some() {
                ui.checkbox(&mut panel.draft.as_mut().unwrap().document.split_enabled, text(lang, "Split по приложениям", "Application split tunneling"));
                ui.weak(text(lang, "Выключено: весь трафик через профиль DNS. Нажмите Применить; списки сохраняются.", "Off: all traffic uses the DNS profile. Click Apply; saved rules are retained."));
                ui.label(text(lang, aivpn_desktop_agent::client::launch::NOTICE,
                    aivpn_desktop_agent::client::launch::NOTICE_EN));
                let mut default_route = Route::of(&panel.draft.as_ref().unwrap().document.default_action);
                ui.label(text(lang, "По умолчанию (SYSTEM: только выбранные приложения в VPN; VPN: выбранные приложения в обход)", "Default (SYSTEM: selected apps use VPN; VPN: selected apps bypass VPN)"));
                if route_picker(ui, "routing-default", &mut default_route) {
                    match default_route.action(panel.selected_profile.as_deref()) { Ok(action) => panel.draft.as_mut().unwrap().document.default_action = action, Err(e) => panel.error = Some(e.to_string()) }
                }
                ui.horizontal_wrapped(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut panel.new_path).hint_text(text(lang, "Абсолютный путь приложения", "Absolute application path")));
                    if ui.button(text(lang, "Выбрать", "Browse")).clicked() {
                        if let Some(path) = crate::platform_win::choose_application(lang) { panel.new_path = path; }
                    }
                    route_picker(ui, "routing-new", &mut panel.new_route);
                    if ui.add_enabled(!panel.busy, egui::Button::new(text(lang, "Добавить", "Add"))).clicked() {
                        if let Err(e) = panel.add_application() { panel.error = Some(e.to_string()); }
                    }
                });
                let launch_ready = panel.can_launch();
                let draft = panel.draft.as_mut().unwrap();
                let mut remove = None;
                let mut shift = None;
                for (index, rule) in draft.document.rules.iter_mut().enumerate() {
                    ui.push_id(&rule.id, |ui| {
                        ui.separator();
                        let name = match &rule.application { Selector::Any {} => "*", Selector::Executable { path } => path, Selector::WindowsPackage { sid } => sid };
                        ui.label(format!("{}. {}", index+1, name));
                        ui.horizontal_wrapped(|ui| {
                            if let Selector::Executable { path } = &rule.application {
                                if ui.add_enabled(launch_ready, egui::Button::new(text(lang, "Запустить приложение", "Launch application"))).clicked() {
                                    operation = Some(Operation::Launch(std::path::PathBuf::from(path)));
                                }
                            }
                            let mut route = Route::of(&rule.action);
                            if route_picker(ui, "route", &mut route) {
                                match route.action(panel.selected_profile.as_deref()) { Ok(action) => rule.action = action, Err(e) => panel.error = Some(e.to_string()) }
                            }
                            let mut destination = rule.destination.clone().unwrap_or_default();
                            if ui.add(egui::TextEdit::singleline(&mut destination).hint_text("CIDR")).changed() { rule.destination = if destination.trim().is_empty() { None } else { Some(destination) }; }
                            if ui.button("↑").clicked() { shift = Some((index, true)); }
                            if ui.button("↓").clicked() { shift = Some((index, false)); }
                            if ui.add_enabled(!panel.busy, egui::Button::new(text(lang, "Удалить", "Delete"))).clicked() { remove = Some(index); }
                        });
                        ui.checkbox(&mut rule.inherit_children, text(lang, "Включая дочерние процессы", "Include child processes"));
                    });
                }
                if let Some(index) = remove { draft.document.rules.remove(index); }
                else if let Some((index, up)) = shift {
                    let next = if up { index.checked_sub(1) } else { index.checked_add(1) };
                    if let Some(next) = next.filter(|next| *next < draft.document.rules.len()) { draft.document.rules.swap(index, next); }
                }
                ui.horizontal_wrapped(|ui| {
                    if ui.add_enabled(!panel.busy, egui::Button::new(text(lang, "Проверить", "Validate"))).clicked() { operation = Some(Operation::Validate(draft.clone())); }
                    if ui.add_enabled(!panel.busy, egui::Button::new(text(lang, "Применить", "Apply"))).clicked() { operation = Some(Operation::Apply(draft.clone())); }
                    if ui.add_enabled(!panel.busy, egui::Button::new(text(lang, "Удалить правила", "Remove rules"))).clicked() { operation = Some(Operation::Remove(draft.clone())); }
                });
            }
        });
        if panel.busy {
            ui.spinner();
        }
        if !panel.message.is_empty() {
            ui.label(&panel.message);
        }
        if let Some(error) = &panel.error {
            ui.colored_label(egui::Color32::RED, error);
        }
        if let Some(operation) = operation {
            if matches!(operation, Operation::Launch(_)) && !self.editor.can_launch() {
                self.editor.error =
                    Some("Сначала примените черновик правил и дождитесь ответа службы".into());
            } else {
                self.submit(operation, ui.ctx().clone());
            }
        }
    }
}

fn execute(operation: Operation) -> Result<Completion, String> {
    use aivpn_desktop_agent::{client::ClientError, protocol::ErrorCode};
    let dns = match &operation {
        Operation::SetDns {
            profile,
            acknowledge_outage,
        } => Some((Some(profile.clone()), *acknowledge_outage)),
        Operation::ClearDns => Some((None, true)),
        _ => None,
    };
    match operation.execute_checked() {
        Ok(completion) => Ok(completion),
        Err(ClientError::Rejected(ErrorCode::AccessDenied)) if dns.is_some() => {
            let (profile, acknowledged) = dns.unwrap();
            aivpn_desktop_agent::client::elevation::set_shared_dns(
                profile.as_deref(),
                acknowledged,
            )
            .map_err(|error| format!("Не удалось подтвердить изменение общего DNS: {error}"))?;
            Completion::confirm_dns(profile.as_deref()).map_err(|error| error.to_string())
        }
        Err(error) => Err(error.to_string()),
    }
}

fn route_picker(ui: &mut egui::Ui, id: &str, route: &mut Route) -> bool {
    let mut selected = false;
    egui::ComboBox::from_id_salt(id)
        .selected_text(route.to_string())
        .show_ui(ui, |ui| {
            for choice in Route::ALL {
                selected |= ui
                    .selectable_value(route, choice, choice.to_string())
                    .clicked();
            }
        });
    selected
}

impl super::AivpnApp {
    pub(crate) fn draw_app_routing(&mut self, ui: &mut egui::Ui) {
        let options = self.desktop_client_options();
        self.app_routing
            .draw(ui, self.settings.lang, self.keys.selected_key(), options);
    }
}
