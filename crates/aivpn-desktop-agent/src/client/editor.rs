//! Общая модель редактора правил. Интерфейсы не подменяют ответ службы своим статусом.
use super::{call, current_owner, ClientError};
use crate::{
    policy::{
        Action, DnsPolicy, Owner, Platform, PolicyDocument, ProfileStatus, RuleDocument, Selector,
    },
    protocol::{BackendState, Command, Reply},
};
use std::{io, path::Path};

pub const SHARED_DNS_NOTICE: &str = "Правила относятся к этому пользователю. DNS общий для всей системы: при разрыве VPN разрешение имен может перестать работать во всех приложениях. Пока общий DNS включен, mDNS и LLMNR не выходят в физическую сеть, поэтому поиск локальных имен может быть недоступен.";
pub const SHARED_DNS_NOTICE_EN: &str = "Rules apply to this user. DNS is shared system-wide: if the VPN fails, name resolution may stop for every application. While shared DNS is enabled, network mDNS and LLMNR discovery is restricted, so local names may be unavailable.";

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub owner: Owner,
    pub backend: BackendState,
    pub global_dns_profile: Option<String>,
    pub profiles: Vec<ProfileStatus>,
    pub policy: Option<PolicyDocument>,
}
impl Snapshot {
    pub fn load() -> Result<Self, ClientError> {
        Self::load_with(call)
    }
    pub(super) fn load_with(
        mut send: impl FnMut(Command) -> Result<Reply, ClientError>,
    ) -> Result<Self, ClientError> {
        let owner = current_owner()?;
        let Reply::Status {
            backend,
            global_dns_profile,
            ..
        } = send(Command::Status {})?
        else {
            return Err(invalid_reply());
        };
        let Reply::Profiles { profiles } = send(Command::ListProfiles {})? else {
            return Err(invalid_reply());
        };
        let Reply::Policy { document } = send(Command::GetPolicy {
            owner: owner.clone(),
        })?
        else {
            return Err(invalid_reply());
        };
        Ok(Self {
            owner,
            backend,
            global_dns_profile,
            profiles,
            policy: document,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Draft {
    pub document: PolicyDocument,
    pub expected_generation: Option<u64>,
}
impl Draft {
    pub fn from_snapshot(snapshot: &Snapshot) -> Self {
        if let Some(document) = &snapshot.policy {
            return Self {
                document: document.clone(),
                expected_generation: Some(document.generation),
            };
        }
        Self {
            document: PolicyDocument {
                split_enabled: true,
                version: 1,
                id: "desktop-app-routing".into(),
                generation: 1,
                platform: if cfg!(target_os = "windows") {
                    Platform::Windows
                } else {
                    Platform::Linux
                },
                owner: snapshot.owner.clone(),
                default_action: Action::System {},
                dns: DnsPolicy::SharedVpn {
                    profile: snapshot.global_dns_profile.clone().unwrap_or_default(),
                    acknowledge_outage: snapshot.global_dns_profile.is_some(),
                },
                rules: Vec::new(),
            },
            expected_generation: None,
        }
    }
    pub fn add_executable(&mut self, path: String, action: Action) -> io::Result<()> {
        if self.document.rules.len() >= 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Допускается не более 256 правил",
            ));
        }
        let index = (1..=257)
            .find(|index| {
                !self
                    .document
                    .rules
                    .iter()
                    .any(|rule| rule.id == format!("app-{index}"))
            })
            .ok_or(io::ErrorKind::InvalidInput)?;
        self.document.rules.push(RuleDocument {
            id: format!("app-{index}"),
            application: Selector::Executable { path },
            destination: None,
            inherit_children: true,
            action,
        });
        Ok(())
    }
    fn command(&self, validate: bool) -> io::Result<Command> {
        let mut document = self.document.clone();
        document.generation = match self.expected_generation {
            Some(old) => old.checked_add(1).ok_or(io::ErrorKind::InvalidInput)?,
            None => 1,
        };
        Ok(if validate {
            Command::ValidatePolicy {
                document,
                expected_generation: self.expected_generation,
            }
        } else {
            Command::ApplyPolicy {
                document,
                expected_generation: self.expected_generation,
            }
        })
    }
    pub fn validate(&self) -> Result<(), ClientError> {
        if matches!(call(self.command(true)?)?, Reply::Validated { .. }) {
            Ok(())
        } else {
            Err(invalid_reply())
        }
    }
    pub fn apply(&self) -> Result<(), ClientError> {
        if matches!(call(self.command(false)?)?, Reply::Applied { .. }) {
            Ok(())
        } else {
            Err(invalid_reply())
        }
    }
    pub fn remove(&self) -> Result<(), ClientError> {
        let expected_generation = self
            .expected_generation
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        expect_applied(call(Command::RemovePolicy {
            owner: self.document.owner.clone(),
            expected_generation,
        })?)
    }
}

/// Linux сохраняет выбранный путь для проверки symlink/mount контекста backend.
/// Windows получает открытое NT-имя, без повторного поиска буквы диска в службе.
pub fn application_path(path: &Path) -> io::Result<String> {
    if !path.is_absolute() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    #[cfg(target_os = "linux")]
    {
        path.to_str().map(str::to_owned).ok_or(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Путь приложения должен быть в UTF-8",
        ))
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFinalPathNameByHandleW, FILE_NAME_OPENED, VOLUME_NAME_NT,
        };
        let file = std::fs::File::open(path)?;
        let mut buffer = vec![0; 32768];
        let count = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                FILE_NAME_OPENED | VOLUME_NAME_NT,
            )
        };
        if count == 0 {
            return Err(io::Error::last_os_error());
        }
        if count as usize >= buffer.len() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let path = String::from_utf16(&buffer[..count as usize])
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        nt_application_path(&path)
    }
}
fn invalid_reply() -> ClientError {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Неожиданный ответ службы маршрутизации",
    )
    .into()
}

#[cfg(any(test, target_os = "windows"))]
fn nt_application_path(path: &str) -> io::Result<String> {
    let suffix = path
        .strip_prefix("\\Device\\")
        .or_else(|| path.strip_prefix("\\device\\"))
        .ok_or(io::ErrorKind::InvalidInput)?;
    Ok(format!("\\device\\{suffix}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Route {
    System,
    #[default]
    Vpn,
    Block,
}
impl Route {
    pub const ALL: [Self; 3] = [Self::System, Self::Vpn, Self::Block];
    pub fn action(self, profile: Option<&str>) -> io::Result<Action> {
        Ok(match self {
            Self::System => Action::System {},
            Self::Block => Action::Block {},
            Self::Vpn => Action::Vpn {
                profile: profile
                    .filter(|p| !p.is_empty())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "Выберите профиль VPN")
                    })?
                    .into(),
            },
        })
    }
    pub fn of(action: &Action) -> Self {
        match action {
            Action::System {} => Self::System,
            Action::Vpn { .. } => Self::Vpn,
            Action::Block {} => Self::Block,
        }
    }
}
impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::System => "SYSTEM",
            Self::Vpn => "VPN",
            Self::Block => "BLOCK",
        })
    }
}

#[derive(Debug, Clone)]
pub enum Operation {
    Launch(std::path::PathBuf),
    Refresh,
    Inspect,
    Register(crate::connection::ConnectionDocument),
    Validate(Draft),
    Apply(Draft),
    Remove(Draft),
    SetDns {
        profile: String,
        acknowledge_outage: bool,
    },
    ClearDns,
    Start {
        profile: String,
        connection: crate::connection::ConnectionDocument,
    },
    StartConfigured {
        profile: String,
        connection: crate::connection::ConnectionDocument,
        options: crate::connection::DesktopClientOptions,
        certificate_file: Option<std::path::PathBuf>,
    },
    Stop(String),
    Delete(String),
}

#[derive(Debug, Clone)]
pub struct Completion {
    pub snapshot: Snapshot,
    pub selected_profile: Option<String>,
    pub replace_draft: bool,
    pub message: String,
}

impl Completion {
    /// После отдельного административного процесса проверяем фактический выбор DNS.
    pub fn confirm_dns(profile: Option<&str>) -> Result<Self, ClientError> {
        let mut completion = Operation::Inspect.execute_checked()?;
        if completion.snapshot.global_dns_profile.as_deref() != profile {
            return Err(io::Error::other(
                "Выбор общего DNS изменился или не подтвержден. Перечитайте состояние службы",
            )
            .into());
        }
        completion.message = if profile.is_some() {
            "Общий DNS закреплен за профилем"
        } else {
            "Прежний системный DNS восстановлен"
        }
        .into();
        Ok(completion)
    }
}

impl Operation {
    /// Блокирующий IPC выполняется вне потока интерфейса. Повторов записи здесь нет.
    pub fn execute(self) -> Result<Completion, String> {
        self.execute_checked().map_err(|e| e.to_string())
    }
    pub fn execute_checked(self) -> Result<Completion, ClientError> {
        let mut selected_profile = None;
        let read_only = matches!(self, Self::Refresh | Self::Inspect);
        let replace_draft = matches!(self, Self::Refresh | Self::Apply(_) | Self::Remove(_));
        let message = match self {
            Self::Launch(program) => {
                super::launch::spawn(&program, &[])?;
                "Приложение запущено. Ранее открытые соединения сохраняют прежний маршрут"
            }
            Self::Refresh | Self::Inspect => "Состояние службы обновлено",
            Self::Register(connection) => {
                let reply = call(Command::RegisterProfile {
                    owner: current_owner()?,
                    registration_key: connection.registration_key()?,
                    consumers: Vec::new(),
                })?;
                let Reply::Registered { profile } = reply else {
                    return Err(invalid_reply());
                };
                selected_profile = Some(profile);
                "Профиль зарегистрирован"
            }
            Self::Validate(draft) => {
                draft.validate()?;
                "Правила проверены, изменения еще не применены"
            }
            Self::Apply(draft) => {
                draft.apply()?;
                "Правила применены"
            }
            Self::Remove(draft) => {
                draft.remove()?;
                "Правила удалены"
            }
            Self::SetDns {
                profile,
                acknowledge_outage,
            } => {
                expect_done(call(Command::SetGlobalDns {
                    profile,
                    acknowledge_outage,
                })?)?;
                "Общий DNS закреплен за профилем"
            }
            Self::ClearDns => {
                expect_done(call(Command::ClearGlobalDns {})?)?;
                "Прежний системный DNS восстановлен"
            }
            Self::Start {
                profile,
                connection,
            } => {
                expect_done(call(Command::StartProfile {
                    profile,
                    connection,
                })?)?;
                "Запуск запрошен. Готовность показывает служба"
            }
            Self::StartConfigured {
                profile,
                connection,
                mut options,
                certificate_file,
            } => {
                if let Some(path) = certificate_file {
                    options.mtls_certificate = Some(read_certificate(&path)?);
                }
                let connection = connection.with_client_options(&options)?;
                #[cfg(feature = "local-profile")]
                let connection = connection.with_local_identity()?;
                expect_done(call(Command::StartProfile {
                    profile,
                    connection,
                })?)?;
                "Запуск запрошен. Готовность показывает служба"
            }
            Self::Stop(profile) => {
                expect_done(call(Command::StopProfile { profile })?)?;
                "Остановка запрошена"
            }
            Self::Delete(profile) => {
                expect_done(call(Command::DeleteProfile { profile })?)?;
                "Профиль удален"
            }
        };
        let snapshot = match Snapshot::load() {
            Ok(snapshot) => snapshot,
            Err(error) if read_only => return Err(error),
            Err(error) => {
                return Err(io::Error::other(format!(
                    "{message}. Повторное чтение состояния не удалось: {error}"
                ))
                .into())
            }
        };
        Ok(Completion {
            snapshot,
            selected_profile,
            replace_draft,
            message: message.into(),
        })
    }
}
fn expect_done(reply: Reply) -> Result<(), ClientError> {
    if matches!(reply, Reply::Done {}) {
        Ok(())
    } else {
        Err(invalid_reply())
    }
}

/// Файл читает интерфейс с правами пользователя, а служба получает только содержимое.
fn read_certificate(path: &Path) -> io::Result<String> {
    use base64::Engine;
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err(io::Error::other("Некорректный файл сертификата mTLS"));
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() != 104 {
        let encoded = std::str::from_utf8(&bytes)
            .map_err(|_| io::Error::other("Некорректный сертификат mTLS"))?;
        bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .map_err(|_| io::Error::other("Некорректный сертификат mTLS"))?;
    }
    if bytes.len() != 104 {
        return Err(io::Error::other("Некорректный размер сертификата mTLS"));
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

fn expect_applied(reply: Reply) -> Result<(), ClientError> {
    if matches!(reply, Reply::Applied { .. }) {
        Ok(())
    } else {
        Err(invalid_reply())
    }
}

#[derive(Debug, Default)]
pub struct Editor {
    pub snapshot: Option<Snapshot>,
    pub draft: Option<Draft>,
    pub selected_profile: Option<String>,
    pub acknowledge_outage: bool,
    pub new_path: String,
    pub new_route: Route,
    pub busy: bool,
    pub inspecting: bool,
    pub message: String,
    pub error: Option<String>,
}
impl Editor {
    pub fn can_launch(&self) -> bool {
        !self.busy
            && self.snapshot.as_ref().is_some_and(|snapshot| {
                matches!(
                    snapshot.backend,
                    BackendState::Guarded | BackendState::Active
                ) && snapshot
                    .policy
                    .as_ref()
                    .zip(self.draft.as_ref())
                    .is_some_and(|(policy, draft)| *policy == draft.document)
            })
    }

    /// Фоновый опрос главного окна не завершает запрос редактора и не стирает черновик.
    pub fn observe(&mut self, snapshot: Snapshot) {
        if self.draft.is_none() {
            self.draft = Some(Draft::from_snapshot(&snapshot));
        }
        if self.selected_profile.as_ref().is_some_and(|selected| {
            !snapshot
                .profiles
                .iter()
                .any(|profile| profile.id == *selected)
        }) {
            self.selected_profile = None;
        }
        self.snapshot = Some(snapshot);
    }

    pub fn complete(&mut self, result: Result<Completion, String>) {
        self.busy = false;
        self.inspecting = false;
        match result {
            Err(error) => self.error = Some(error),
            Ok(completion) => {
                self.error = None;
                self.message = completion.message;
                if completion.replace_draft || self.draft.is_none() {
                    self.draft = Some(Draft::from_snapshot(&completion.snapshot));
                }
                if let Some(profile) = completion.selected_profile {
                    self.selected_profile = Some(profile);
                }
                if self.selected_profile.as_ref().is_some_and(|selected| {
                    !completion
                        .snapshot
                        .profiles
                        .iter()
                        .any(|p| p.id == *selected)
                }) {
                    self.selected_profile = None;
                }
                self.snapshot = Some(completion.snapshot);
            }
        }
    }
    pub fn selected(&self) -> io::Result<String> {
        self.selected_profile
            .clone()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Выберите профиль VPN"))
    }
    pub fn use_dns_profile(&mut self) -> io::Result<()> {
        if !self.acknowledge_outage {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Подтвердите ограничение общего DNS",
            ));
        }
        let profile = self.selected()?;
        self.draft
            .as_mut()
            .ok_or(io::ErrorKind::NotConnected)?
            .document
            .dns = DnsPolicy::SharedVpn {
            profile,
            acknowledge_outage: true,
        };
        Ok(())
    }
    pub fn add_application(&mut self) -> io::Result<()> {
        let path = application_path(Path::new(&self.new_path))?;
        let action = self.new_route.action(self.selected_profile.as_deref())?;
        self.draft
            .as_mut()
            .ok_or(io::ErrorKind::NotConnected)?
            .add_executable(path, action)?;
        self.new_path.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Authority, Policy, ProcessIdentity};
    fn snapshot() -> Snapshot {
        Snapshot {
            owner: Owner::LinuxUser { uid: 1000 },
            backend: BackendState::Guarded,
            global_dns_profile: Some("vpn".into()),
            profiles: Vec::new(),
            policy: None,
        }
    }
    #[test]
    fn both_templates_preserve_system_and_vpn_choices() {
        let mut draft = Draft::from_snapshot(&snapshot());
        draft.document.platform = Platform::Linux;
        let authority = Authority {
            user: draft.document.owner.clone(),
            machine_admin: false,
        };
        let selected = ProcessIdentity {
            owner: authority.user.clone(),
            canonical_executable: "/usr/bin/browser".into(),
            package_sid: None,
        };
        draft
            .add_executable(
                selected.canonical_executable.clone(),
                Action::Vpn {
                    profile: "vpn".into(),
                },
            )
            .unwrap();
        let policy = Policy::validate(draft.document.clone(), &authority).unwrap();
        assert!(matches!(
            policy
                .decide(&selected, "203.0.113.1".parse().unwrap(), |_, _| true)
                .effective,
            Action::Vpn { .. }
        ));
        draft.document.default_action = Action::Vpn {
            profile: "vpn".into(),
        };
        draft.document.rules[0].action = Action::System {};
        let policy = Policy::validate(draft.document, &authority).unwrap();
        assert_eq!(
            policy
                .decide(&selected, "203.0.113.1".parse().unwrap(), |_, _| true)
                .effective,
            Action::System {}
        );
    }
    #[test]
    fn an_unapplied_or_replaced_draft_cannot_launch_an_application() {
        let mut state = snapshot();
        state.policy = Some(Draft::from_snapshot(&state).document);
        let mut editor = Editor {
            draft: Some(Draft::from_snapshot(&state)),
            snapshot: Some(state),
            ..Default::default()
        };
        assert!(editor.can_launch());
        editor.draft.as_mut().unwrap().document.default_action = Action::Block {};
        assert!(!editor.can_launch());
        editor.draft = Some(Draft::from_snapshot(editor.snapshot.as_ref().unwrap()));
        editor
            .snapshot
            .as_mut()
            .unwrap()
            .policy
            .as_mut()
            .unwrap()
            .generation += 1;
        assert!(!editor.can_launch());
    }
    #[test]
    fn editing_keeps_the_expected_generation_for_conflict_detection() {
        let mut state = snapshot();
        let mut initial = Draft::from_snapshot(&state).document;
        initial.generation = 7;
        state.policy = Some(initial);
        let draft = Draft::from_snapshot(&state);
        assert!(
            matches!(draft.command(false).unwrap(), Command::ApplyPolicy { expected_generation: Some(7), document } if document.generation==8)
        );
    }

    #[test]
    fn client_reads_raw_and_encoded_certificates_with_a_fixed_size_bound() {
        struct Temporary(std::path::PathBuf);
        impl Drop for Temporary {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        use base64::Engine;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = Temporary(
            std::env::temp_dir().join(format!("aivpn-cert-test-{}-{nonce}", std::process::id())),
        );
        let raw = [7u8; 104];
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path.0)
            .unwrap();
        use std::io::Write;
        file.write_all(&raw).unwrap();
        drop(file);
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
        assert_eq!(read_certificate(&path.0).unwrap(), encoded);
        std::fs::write(&path.0, format!("{encoded}\n")).unwrap();
        assert_eq!(read_certificate(&path.0).unwrap(), encoded);
        std::fs::write(&path.0, [0; 4097]).unwrap();
        assert!(read_certificate(&path.0).is_err());
        let options = crate::connection::DesktopClientOptions {
            mtls_certificate: Some("private-test-certificate".into()),
            ..Default::default()
        };
        assert!(!format!("{options:?}").contains("private-test-certificate"));
    }

    #[test]
    fn windows_opened_path_uses_policy_prefix_without_folding_file_names() {
        use crate::policy::{Authority, Policy};
        let path =
            nt_application_path("\\Device\\HarddiskVolume3\\Users\\Test\\Browser.EXE").unwrap();
        assert_eq!(path, "\\device\\HarddiskVolume3\\Users\\Test\\Browser.EXE");
        let owner = Owner::WindowsUser {
            sid: "S-1-5-21-1-2-3-1000".into(),
        };
        let state = Snapshot {
            owner: owner.clone(),
            ..snapshot()
        };
        let mut draft = Draft::from_snapshot(&state);
        draft.document.platform = Platform::Windows;
        draft
            .add_executable(
                path,
                Action::Vpn {
                    profile: "vpn".into(),
                },
            )
            .unwrap();
        assert!(Policy::validate(
            draft.document,
            &Authority {
                user: owner,
                machine_admin: false
            }
        )
        .is_ok());
        assert!(expect_applied(Reply::Applied { revision: 7 }).is_ok());
        assert!(expect_applied(Reply::Done {}).is_err());
    }

    #[test]
    fn polling_preserves_edits_and_only_service_readiness_marks_ready() {
        let state = snapshot();
        let mut editor = Editor::default();
        editor.complete(Ok(Completion {
            snapshot: state.clone(),
            selected_profile: None,
            replace_draft: true,
            message: String::new(),
        }));
        editor.draft.as_mut().unwrap().document.default_action = Action::Block {};
        let mut updated = state.clone();
        updated.profiles.push(ProfileStatus {
            id: "vpn".into(),
            owner: state.owner.clone(),
            control_allowed: true,
            session_active: true,
            ready_ipv4: false,
            ready_ipv6: false,
            assignment_generation: 0,
            session_id: None,
            registration_key: None,
            ipv4: None,
            ipv6: None,
        });
        editor.complete(Ok(Completion {
            snapshot: updated,
            selected_profile: Some("vpn".into()),
            replace_draft: false,
            message: "Запуск запрошен".into(),
        }));
        assert_eq!(
            editor.draft.as_ref().unwrap().document.default_action,
            Action::Block {}
        );
        assert!(!editor.snapshot.as_ref().unwrap().profiles[0].ready_ipv4);
        editor.busy = true;
        editor.error = Some("Предыдущая ошибка редактора".into());
        editor.observe(state.clone());
        assert!(editor.busy);
        assert_eq!(editor.error.as_deref(), Some("Предыдущая ошибка редактора"));
        assert_eq!(
            editor.draft.as_ref().unwrap().document.default_action,
            Action::Block {}
        );
        editor.complete(Err("Служба недоступна".into()));
        assert!(!editor.busy);
        assert_eq!(
            editor.draft.as_ref().unwrap().document.default_action,
            Action::Block {}
        );
        assert_eq!(editor.error.as_deref(), Some("Служба недоступна"));
    }

    #[test]
    fn dns_requires_explicit_outage_acknowledgement() {
        let mut editor = Editor {
            selected_profile: Some("vpn".into()),
            draft: Some(Draft::from_snapshot(&snapshot())),
            ..Editor::default()
        };
        assert!(editor.use_dns_profile().is_err());
        editor.acknowledge_outage = true;
        editor.use_dns_profile().unwrap();
        assert_eq!(editor.draft.unwrap().document.dns.profile(), "vpn");
    }
}
