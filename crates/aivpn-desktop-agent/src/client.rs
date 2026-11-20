//! Общий клиент управления для CLI и интерфейсов desktop.

use crate::protocol::{Command, ErrorCode, Outcome, Reply, Request};
use aivpn_desktop_policy::Owner;
use std::{io, num::NonZeroU64};
use thiserror::Error;
pub mod editor;
pub mod launch;
pub mod session;
pub use session::SessionTarget;
#[cfg(any(target_os = "windows", test))]
pub mod elevation;

pub const WINDOWS_CONTROL_NAME: &str = "aivpn-app-routing";
pub const LINUX_CONTROL_PATH: &str = "/run/aivpn-app-routing/control.sock";

pub fn session_administration(
    profile: &str,
    query: crate::administration::SessionQuery,
) -> Result<crate::administration::ReplyText, ClientError> {
    SessionTarget::current(profile)?.query(query)
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("Нет ответа проверенной службы маршрутизации: {0}")]
    Transport(#[from] io::Error),
    #[error("Служба отклонила запрос: {0:?}")]
    Rejected(ErrorCode),
}

/// Владелец текущего процесса. Полномочия служба независимо проверяет по IPC.
pub fn current_owner() -> io::Result<Owner> {
    #[cfg(target_os = "linux")]
    {
        Ok(Owner::LinuxUser {
            uid: unsafe { libc::geteuid() },
        })
    }
    #[cfg(target_os = "windows")]
    {
        crate::windows::current_owner()
    }
}

/// Один запрос без автоматического повтора изменяющих операций.
pub fn call(command: Command) -> Result<Reply, ClientError> {
    if !cfg!(feature = "routing-control")
        && !matches!(
            command,
            Command::Status {} | Command::ListProfiles {} | Command::GetPolicy { .. }
        )
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Управление правилами приложений не включено в эту сборку",
        )
        .into());
    }
    let request = Request::new(NonZeroU64::MIN, command);
    #[cfg(target_os = "linux")]
    let response =
        crate::unix::connect_root_control(std::path::Path::new(LINUX_CONTROL_PATH), &request)?;
    #[cfg(target_os = "windows")]
    let response = crate::windows::ControlClient::call(WINDOWS_CONTROL_NAME, &request)?;
    response_result(response.into_result())
}

fn response_result(result: Outcome) -> Result<Reply, ClientError> {
    match result {
        Outcome::Ok { reply } => Ok(reply),
        Outcome::Error { code } => Err(ClientError::Rejected(code)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_failure_is_not_reported_as_success() {
        assert!(matches!(
            response_result(Outcome::Error {
                code: ErrorCode::RecoveryRequired
            }),
            Err(ClientError::Rejected(ErrorCode::RecoveryRequired))
        ));
        assert!(matches!(
            response_result(Outcome::Ok {
                reply: Reply::Done {}
            }),
            Ok(Reply::Done {})
        ));
    }

    #[test]
    fn current_owner_matches_the_operating_system() {
        let owner = current_owner().unwrap();
        #[cfg(target_os = "linux")]
        assert_eq!(
            owner,
            Owner::LinuxUser {
                uid: unsafe { libc::geteuid() }
            }
        );
        #[cfg(target_os = "windows")]
        assert!(
            matches!(owner, Owner::WindowsUser { sid } if sid.starts_with("S-1-") && sid.len() < 185)
        );
    }
}
