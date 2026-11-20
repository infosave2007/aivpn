//! Установка единого образа и ограниченное повышение прав через Polkit.

use super::Message;

/// Refuse to grant CAP_NET_ADMIN to anything that isn't a root-owned,
/// non-group/other-writable file. Without this, a writable directory ahead
/// of /usr/bin in PATH (or an attacker-planted binary) could get a
/// standing, unprompted capability grant the next time the user clicks
/// through the one pkexec dialog they have a legitimate reason to trust.
#[cfg(unix)]
fn is_trusted_system_binary(path: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(canonical) = std::fs::canonicalize(path) else {
        return false;
    };
    let Ok(file) = std::fs::metadata(&canonical) else {
        return false;
    };
    file.is_file()
        && canonical.ancestors().all(|ancestor| {
            std::fs::symlink_metadata(ancestor).is_ok_and(|meta| {
                meta.uid() == 0 && meta.mode() & 0o022 == 0 && !meta.file_type().is_symlink()
            })
        })
}

/// Общий DNS меняет администратор. Передаем только аргументы CLI, без оболочки.
pub(super) async fn set_shared_dns(
    profile: Option<&str>,
    acknowledge_outage: bool,
) -> Result<(), String> {
    let control = std::path::Path::new(aivpn_client::network_session::IMAGE);
    if !is_trusted_system_binary(control) {
        return Err("Для общего DNS нужен установленный системный клиент AIVPN".into());
    }
    let pkexec = std::path::Path::new("/usr/bin/pkexec");
    if !is_trusted_system_binary(pkexec) {
        return Err("Не найден системный запрос административных прав pkexec".into());
    }
    let mut command = tokio::process::Command::new(pkexec);
    command.kill_on_drop(true);
    command.arg(control).args(["app-routing", "dns"]);
    match profile {
        Some(profile) if acknowledge_outage => {
            command.arg("set").arg(profile).arg("--acknowledge-outage");
        }
        Some(_) => return Err("Подтвердите ограничение общего DNS".into()),
        None => {
            command.arg("clear");
        }
    }
    let result = tokio::time::timeout(std::time::Duration::from_secs(120), command.output())
        .await
        .map_err(|_| {
            "Ожидание авторизации или ответа службы истекло. Перечитайте состояние общего DNS."
                .to_string()
        })?
        .map_err(|error| format!("Не удалось запросить права администратора: {error}"))?;
    if !result.status.success() {
        return Err("Не удалось подтвердить изменение общего DNS. Перечитайте состояние службы: авторизация могла быть отменена или запрос отклонен.".into());
    }
    Ok(())
}
#[cfg(not(unix))]
fn is_trusted_system_binary(_path: &std::path::Path) -> bool {
    false
}

/// Базовая установка одинакова для GUI, CLI и AppImage.
pub(super) async fn ensure_installed_image(
    source: &std::path::Path,
    _lang: &str,
    _sender: &mut iced::futures::channel::mpsc::Sender<Message>,
) -> Result<std::path::PathBuf, String> {
    let source = source.to_owned();
    tokio::task::spawn_blocking(move || aivpn_client::installer::ensure_basic(&source))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}
