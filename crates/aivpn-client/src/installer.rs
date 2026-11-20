//! Встроенная установка использует только ресурсы выбранного образа.
use std::{ffi::OsString, io, path::PathBuf, process::ExitCode};

pub fn run(arguments: Vec<OsString>, routing: bool) -> io::Result<ExitCode> {
    if arguments == [OsString::from("--help")] || arguments == [OsString::from("-h")] {
        println!("Установка: setup install | uninstall; split по приложениям: app-routing install | uninstall");
        return Ok(ExitCode::SUCCESS);
    }
    if arguments.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Использование: setup install | uninstall",
        ));
    }
    let action = arguments[0]
        .to_str()
        .filter(|v| matches!(*v, "install" | "uninstall"))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Неизвестное действие установки",
            )
        })?;
    #[cfg(target_os = "linux")]
    {
        linux::install(&std::env::current_exe()?, action, routing)?;
        Ok(ExitCode::SUCCESS)
    }
    #[cfg(windows)]
    {
        windows::install(action, routing, None)
    }
}

#[cfg(target_os = "linux")]
pub fn ensure_basic(source: &std::path::Path) -> io::Result<PathBuf> {
    linux::ensure(source)
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::path::Path;
    use std::{
        io::{Read, Write},
        process::{Command, Stdio},
    };
    const BASIC: &str = include_str!("../../../deploy/install-client-image.sh");
    const ROUTING: &str = include_str!("../../../deploy/install-app-routing.sh");
    const SERVICE: &str = include_str!("../../../deploy/systemd/aivpn-app-routing.service");
    const SOCKET: &str = include_str!("../../../deploy/systemd/aivpn-app-routing.socket");
    const POLICY: &str = include_str!("../../../platforms/linux/polkit/com.aivpn.client.policy");
    const POLICY_PATH: &str = "/usr/share/polkit-1/actions/com.aivpn.client.policy";
    const APP_RECEIPT: &str = "/var/lib/aivpn-app-routing-install/manifest";
    const MAX_IMAGE: u64 = 512 * 1024 * 1024;
    pub fn ensure(source: &Path) -> io::Result<PathBuf> {
        let installed = Path::new(crate::network_session::IMAGE);
        let bytes = snapshot(source)?;
        if crate::network_session::validate_image(installed, false).is_ok()
            && std::fs::read(installed).is_ok_and(|other| other == bytes)
            && std::fs::read(POLICY_PATH).is_ok_and(|other| other == POLICY.as_bytes())
        {
            return Ok(installed.into());
        }
        install_snapshot(bytes, "install", false)?;
        crate::network_session::validate_image(installed, false)?;
        Ok(installed.into())
    }
    fn snapshot(source: &Path) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        std::fs::File::open(source)?
            .take(MAX_IMAGE + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_IMAGE || !bytes.starts_with(b"\x7fELF") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Недопустимый образ клиента",
            ));
        }
        Ok(bytes)
    }
    pub(super) fn install(source: &Path, action: &str, routing: bool) -> io::Result<()> {
        install_snapshot(snapshot(source)?, action, routing)
    }
    fn install_snapshot(image: Vec<u8>, action: &str, routing: bool) -> io::Result<()> {
        if routing && !cfg!(feature = "desktop-service") {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Для этой установки нужна сборка с app-routing",
            ));
        }
        crate::network_session::validate_image(Path::new("/usr/bin/bash"), false)?;
        let resources = [
            ("aivpn", image.as_slice()),
            ("com.aivpn.client.policy", POLICY.as_bytes()),
            ("aivpn-app-routing.service", SERVICE.as_bytes()),
            ("aivpn-app-routing.socket", SOCKET.as_bytes()),
        ];
        let mut script=format!("set -euo pipefail\numask 077\nexport AIVPN_COMPILED_ROUTING={}\nexport AIVPN_SETUP_CALLER={}\nbundle=$(mktemp -d /var/tmp/aivpn-setup.XXXXXXXX)\ntrap 'rm -rf -- \"$bundle\"' EXIT\n",cfg!(feature="desktop-service"),std::process::id());
        for (name, bytes) in resources {
            script.push_str(&format!(
                "head -c {} > \"$bundle/{name}\"\ntest \"$(wc -c < \"$bundle/{name}\")\" -eq {}\n",
                bytes.len(),
                bytes.len()
            ));
        }
        // Receipt закрыт от обычного пользователя. Выбор транзакции делает root.
        script.push_str(&format!(
            "if [[ {routing} == true || ( {action} == install && -f {APP_RECEIPT} ) ]]; then\n"
        ));
        script.push_str("[[ $AIVPN_COMPILED_ROUTING == true ]] || { printf '%s\\n' 'Для этой установки нужна сборка с app-routing' >&2; exit 1; }\n");
        script.push_str(&format!("( set -- {action} \"$bundle\"\n{ROUTING}\n)\n"));
        if action == "install" {
            script.push_str(&format!("( set -- install \"$bundle\"\n{BASIC}\n)\n"));
        }
        script.push_str(&format!(
            "else\n( set -- {action} \"$bundle\"\n{BASIC}\n)\nfi\n"
        ));
        let mut command = if unsafe { libc::geteuid() } == 0 {
            Command::new("/usr/bin/bash")
        } else {
            crate::network_session::validate_image(Path::new("/usr/bin/pkexec"), true)?;
            let mut c = Command::new("/usr/bin/pkexec");
            c.args(["--disable-internal-agent", "/usr/bin/bash"]);
            c
        };
        let mut child = command
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .args(["-c", &script])
            .stdin(Stdio::piped())
            .spawn()?;
        let mut input = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("Нет канала установщика"))?;
        let write = (|| {
            for (_, bytes) in resources {
                input.write_all(bytes)?;
            }
            io::Result::Ok(())
        })();
        drop(input);
        let result = child.wait()?;
        write?;
        if !result.success() {
            return Err(io::Error::other(format!(
                "Установка отменена или завершилась с ошибкой: {result}"
            )));
        }
        Ok(())
    }
}

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub fn run_internal(arguments: Vec<OsString>) -> io::Result<ExitCode> {
    windows::run_internal(arguments)
}

#[cfg(windows)]
pub fn ensure_basic_windows() -> io::Result<PathBuf> {
    windows::ensure()
}

#[cfg(windows)]
pub fn windows_resources() -> (bool, bool) {
    windows::resources()
}

#[cfg(windows)]
pub(crate) fn windows_environment() -> io::Result<Vec<(OsString, OsString)>> {
    windows::environment()
}
