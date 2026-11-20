//! Запуск остается у пользователя. Первый сокет классифицирует уже установленный backend.
use super::{editor::Snapshot, ClientError};
use crate::protocol::BackendState;
use std::{
    ffi::OsString,
    fs::File,
    io,
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(target_os = "linux")]
pub mod desktop;
#[cfg(target_os = "linux")]
mod reaper;

pub const NOTICE: &str = "После первой установки службы перезагрузите компьютер: правила с наследованием требуют истории процессов с начала сеанса. Запуск не переносит уже открытые соединения. Если приложение передает запрос существующему экземпляру, нужен отдельный экземпляр или его перезапуск.";
pub const NOTICE_EN: &str = "Restart the computer after first installing the service: inherited rules need process history from the start of the session. Launching does not move existing connections. An application that delegates to an existing instance needs a separate instance or a restart.";

pub fn command(program: &Path, arguments: &[OsString]) -> Result<Command, ClientError> {
    let snapshot = Snapshot::load()?;
    require_policy(&snapshot)?;
    let program = program_path(program)?;
    let file = File::open(&program)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Выберите исполняемый файл приложения",
        )
        .into());
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o111 == 0 || mode & 0o6000 != 0 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "Для запуска нужен исполняемый файл без setuid/setgid: смена владельца меняет применяемую политику").into());
        }
    }
    let mut command = Command::new(program);
    command.args(arguments);
    Ok(command)
}

pub fn spawn(program: &Path, arguments: &[OsString]) -> Result<u32, ClientError> {
    let mut command = command(program, arguments)?;
    #[cfg(target_os = "linux")]
    {
        Ok(reaper::spawn(&mut command)?)
    }
    #[cfg(target_os = "windows")]
    {
        // Закрытие process handle не завершает приложение и не оставляет zombie в Windows.
        Ok(command.spawn()?.id())
    }
}

fn require_policy(snapshot: &Snapshot) -> io::Result<()> {
    if !matches!(
        snapshot.backend,
        BackendState::Guarded | BackendState::Active
    ) {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "Служба не подтвердила установку защиты приложений",
        ));
    }
    if !snapshot
        .policy
        .as_ref()
        .is_some_and(|policy| policy.owner == snapshot.owner)
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Сначала примените правила приложений текущего пользователя",
        ));
    }
    Ok(())
}

fn program_path(program: &Path) -> io::Result<PathBuf> {
    #[cfg(target_os = "windows")]
    if let Some(path) = program.to_str().and_then(windows_native_path) {
        return Ok(path.into());
    }
    if !program.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Нужен абсолютный путь приложения",
        ));
    }
    Ok(program.to_owned())
}

#[cfg(any(test, target_os = "windows"))]
fn windows_native_path(path: &str) -> Option<String> {
    let suffix = path
        .strip_prefix("\\device\\")
        .or_else(|| path.strip_prefix("\\Device\\"))?;
    (!suffix.is_empty()).then(|| format!("\\\\?\\GLOBALROOT\\Device\\{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::editor::Draft;
    use crate::policy::Owner;

    #[test]
    fn launch_requires_installed_protection_and_the_callers_policy() {
        let mut snapshot = Snapshot {
            owner: Owner::LinuxUser { uid: 1000 },
            backend: BackendState::Guarded,
            global_dns_profile: None,
            profiles: Vec::new(),
            policy: None,
        };
        assert!(require_policy(&snapshot).is_err());
        snapshot.policy = Some(Draft::from_snapshot(&snapshot).document);
        require_policy(&snapshot).unwrap();
        for backend in [
            BackendState::Unavailable,
            BackendState::Recovering,
            BackendState::ProtectionUnverified,
        ] {
            snapshot.backend = backend;
            assert!(require_policy(&snapshot).is_err());
        }
        snapshot.backend = BackendState::Active;
        snapshot.owner = Owner::LinuxUser { uid: 1001 };
        assert!(require_policy(&snapshot).is_err());
    }

    #[test]
    fn stored_windows_native_name_keeps_its_namespace_and_file_case() {
        assert_eq!(
            windows_native_path("\\device\\HarddiskVolume3\\Apps\\Browser.EXE").as_deref(),
            Some("\\\\?\\GLOBALROOT\\Device\\HarddiskVolume3\\Apps\\Browser.EXE")
        );
        assert!(windows_native_path("C:\\Apps\\Browser.EXE").is_none());
        assert!(windows_native_path("\\device\\").is_none());
    }
}
