//! Выбор режима общего образа до запуска интерфейса и async runtime.

use std::{ffi::OsString, io::Write, process::ExitCode};

#[derive(Clone, Copy)]
pub enum DefaultMode {
    Cli,
    Gui,
}

enum Role {
    Cli,
    Routing,
    Service,
    Worker,
    NetworkHelper,
    Classic,
    Setup,
    InternalSetup,
    Capabilities,
}

/// None оставляет управление графическому входу. Скрытые режимы не попадают в GUI.
pub fn dispatch(default: DefaultMode) -> Option<ExitCode> {
    #[cfg(all(windows, target_env = "gnu"))]
    {
        unsafe extern "C" {
            static _load_config_used: u8;
        }
        std::hint::black_box(&raw const _load_config_used);
    }
    let mut arguments: Vec<OsString> = std::env::args_os().collect();
    let first = arguments.get(1).map(OsString::as_os_str);
    let role = match first.and_then(|value| value.to_str()) {
        Some("cli") => Role::Cli,
        Some("app-routing") => Role::Routing,
        Some("setup") => Role::Setup,
        Some("__setup") => Role::InternalSetup,
        Some("__routing-service") => Role::Service,
        Some("__packet-worker") => Role::Worker,
        Some("__network-helper") => Role::NetworkHelper,
        Some("__classic-client") => Role::Classic,
        Some("--capabilities") => Role::Capabilities,
        Some(value) if value.starts_with("__") => {
            eprintln!("Неизвестный внутренний режим клиента");
            return Some(ExitCode::from(64));
        }
        _ => {
            let name = arguments
                .first()
                .and_then(|value| std::path::Path::new(value).file_name());
            if name == Some(std::ffi::OsStr::new("aivpn-app-control")) {
                return Some(run_routing(arguments));
            }
            let cli_alias = name == Some(std::ffi::OsStr::new("aivpn-client"));
            let help = first.is_some_and(|value| {
                matches!(value.to_str(), Some("--help" | "-h" | "--version" | "-V"))
            });
            return match default {
                DefaultMode::Cli => Some(run_client(arguments)),
                DefaultMode::Gui if cli_alias || help => Some(run_client(arguments)),
                DefaultMode::Gui => None,
            };
        }
    };
    #[cfg(windows)]
    if matches!(
        &role,
        Role::Cli | Role::Routing | Role::Setup | Role::Capabilities
    ) {
        attach_cli_console();
    }
    arguments.remove(1);
    Some(match role {
        Role::Cli => run_client(arguments),
        Role::Routing => run_routing(arguments),
        Role::Service => run_service(arguments),
        Role::Worker => run_worker(arguments),
        Role::NetworkHelper => run_helper(arguments),
        Role::InternalSetup => {
            #[cfg(windows)]
            {
                match crate::installer::run_internal(arguments.into_iter().skip(1).collect()) {
                    Ok(code) => code,
                    Err(error) => failed(error),
                }
            }
            #[cfg(not(windows))]
            {
                let _ = arguments;
                ExitCode::from(69)
            }
        }
        Role::Setup => run_setup(arguments, false),
        Role::Classic => {
            #[cfg(windows)]
            {
                match crate::classic_windows::run(arguments.into_iter().skip(1).collect()) {
                    Ok(code) => code,
                    Err(error) => failed(error),
                }
            }
            #[cfg(not(windows))]
            {
                let _ = arguments;
                eprintln!("Этот внутренний режим доступен только в Windows");
                ExitCode::from(69)
            }
        }
        Role::Capabilities => capabilities(&arguments),
    })
}

fn run_client(arguments: Vec<OsString>) -> ExitCode {
    #[cfg(windows)]
    attach_cli_console();
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => {
            runtime.block_on(crate::run::run_with_args(
                Vec::new(),
                aivpn_common::transport::no_socket_guard(),
                arguments,
            ));
            ExitCode::SUCCESS
        }
        Err(error) => failed(error),
    }
}

#[cfg(not(all(feature = "desktop-service", target_os = "linux")))]
fn unavailable() -> ExitCode {
    eprintln!("Этот режим не включен в сборку клиента для данной платформы");
    ExitCode::from(69)
}

fn failed(error: impl std::fmt::Display) -> ExitCode {
    eprintln!("Клиент завершил режим с ошибкой: {error}");
    ExitCode::FAILURE
}

fn run_setup(arguments: Vec<OsString>, routing: bool) -> ExitCode {
    #[cfg(any(target_os = "linux", windows))]
    return match crate::installer::run(arguments.into_iter().skip(1).collect(), routing) {
        Ok(code) => code,
        Err(error) => failed(error),
    };
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (arguments, routing);
        unavailable()
    }
}

fn run_routing(arguments: Vec<OsString>) -> ExitCode {
    if arguments
        .get(1)
        .and_then(|value| value.to_str())
        .is_some_and(|value| matches!(value, "install" | "uninstall"))
    {
        return run_setup(arguments, true);
    }
    #[cfg(all(
        feature = "desktop-service",
        any(target_os = "linux", target_os = "windows")
    ))]
    return aivpn_desktop_agent::app_control::run_from(arguments);
    #[cfg(not(all(
        feature = "desktop-service",
        any(target_os = "linux", target_os = "windows")
    )))]
    {
        let _ = arguments;
        unavailable()
    }
}

fn run_service(arguments: Vec<OsString>) -> ExitCode {
    #[cfg(all(
        feature = "desktop-service",
        any(target_os = "linux", target_os = "windows")
    ))]
    return match crate::routing_service::run_from(arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => failed(error),
    };
    #[cfg(not(all(
        feature = "desktop-service",
        any(target_os = "linux", target_os = "windows")
    )))]
    {
        let _ = arguments;
        unavailable()
    }
}

fn run_worker(arguments: Vec<OsString>) -> ExitCode {
    #[cfg(all(feature = "desktop-worker", target_os = "linux"))]
    return if arguments.len() != 1 {
        ExitCode::from(64)
    } else {
        match crate::managed_worker::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => failed(error),
        }
    };
    #[cfg(all(feature = "desktop-worker", target_os = "windows"))]
    return match crate::managed_worker::run_from(arguments.into_iter().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => failed(error),
    };
    #[cfg(not(all(
        feature = "desktop-worker",
        any(target_os = "linux", target_os = "windows")
    )))]
    {
        let _ = arguments;
        unavailable()
    }
}

fn run_helper(arguments: Vec<OsString>) -> ExitCode {
    #[cfg(target_os = "linux")]
    return crate::network_helper::run(arguments.into_iter().skip(1));
    #[cfg(not(target_os = "linux"))]
    {
        let _ = arguments;
        unavailable()
    }
}

fn capabilities(arguments: &[OsString]) -> ExitCode {
    if arguments.len() != 1 {
        return ExitCode::from(64);
    }
    #[cfg(windows)]
    let (wintun, driver) = crate::installer::windows_resources();
    #[cfg(not(windows))]
    let (wintun, driver) = (false, false);
    let value = serde_json::json!({
        "resources": { "wintun_dll": wintun, "routing_driver": driver },
        "version": env!("CARGO_PKG_VERSION"),
        "platform": std::env::consts::OS,
        "app_routing": {
            "compiled": cfg!(all(feature = "desktop-service", any(target_os = "linux", target_os = "windows"))),
            "os_supported": cfg!(any(target_os = "linux", target_os = "windows")),
            "readiness_checked": false,
            "readiness_command": ["app-routing", "status"],
            "readiness_reason": "status_required",
        },
    });
    let mut output = std::io::stdout().lock();
    match serde_json::to_writer(&mut output, &value)
        .map_err(std::io::Error::other)
        .and_then(|()| output.write_all(b"\n"))
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => failed(error),
    }
}

/// Унаследованные pipe и перенаправления имеют приоритет перед консолью родителя.
#[cfg(windows)]
fn attach_cli_console() {
    use windows_sys::Win32::{Foundation::INVALID_HANDLE_VALUE, System::Console::*};
    let valid = |handle: windows_sys::Win32::Foundation::HANDLE| {
        !handle.is_null() && handle != INVALID_HANDLE_VALUE
    };
    unsafe {
        if !valid(GetStdHandle(STD_OUTPUT_HANDLE)) && !valid(GetStdHandle(STD_ERROR_HANDLE)) {
            AttachConsole(ATTACH_PARENT_PROCESS);
        }
    }
}

#[cfg(all(test, windows))]
mod loader_tests {
    #[test]
    fn static_windows_dependencies_use_system_directory() {
        std::hint::black_box(
            super::dispatch as fn(super::DefaultMode) -> Option<std::process::ExitCode>,
        );
        let image = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let word = |at: usize| u16::from_le_bytes(image[at..at + 2].try_into().unwrap());
        let dword = |at: usize| u32::from_le_bytes(image[at..at + 4].try_into().unwrap()) as usize;
        let pe = dword(0x3c);
        let optional = pe + 24;
        let is_64 = word(optional) == 0x20b;
        let directory = optional + if is_64 { 112 } else { 96 };
        let rva = dword(directory + 10 * 8);
        assert_ne!(rva, 0, "Нет PE load configuration");
        let table = optional + word(pe + 20) as usize;
        let section = (0..word(pe + 6) as usize)
            .map(|n| table + n * 40)
            .find(|at| rva >= dword(at + 12) && rva < dword(at + 12) + dword(at + 16))
            .unwrap();
        let offset = dword(section + 20) + rva - dword(section + 12);
        assert_ne!(
            word(offset + if is_64 { 78 } else { 54 }) & 0x800,
            0,
            "Начальный поиск DLL не ограничен System32"
        );
    }
}
