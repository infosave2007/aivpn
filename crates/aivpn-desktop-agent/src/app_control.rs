use crate::{
    client,
    protocol::{Command, Reply},
};
use aivpn_desktop_policy::{Owner, PolicyDocument};
use clap::{Parser, Subcommand};
use std::{
    ffi::OsString,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    process::ExitCode,
};

const MAX_POLICY_BYTES: u64 = 128 * 1024;

#[derive(Parser)]
#[command(
    version,
    about = "Управление split по приложениям через локальную службу"
)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Отдельный пользовательский пункт меню, без изменения исходных desktop entry.
    #[cfg(target_os = "linux")]
    InstallDesktop {
        #[arg(long)]
        name: String,
        executable: PathBuf,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        arguments: Vec<OsString>,
    },
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    RunStored { encoded: String },
    /// Запуск с правами пользователя. Действуют уже примененные правила, без shell.
    Run {
        #[arg(value_name = "APPLICATION")]
        executable: PathBuf,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        arguments: Vec<OsString>,
    },
    /// Фактическое состояние службы, защиты и общего DNS.
    Status,
    /// Включить или выключить split, сохранив документ правил.
    Split {
        #[arg(value_parser = ["on", "off"])]
        state: String,
        #[arg(long)]
        machine: bool,
    },
    /// Подготовка удаления службы: остановить VPN и снять политики всех пользователей.
    Decommission {
        #[arg(long, required = true)]
        all_users: bool,
    },
    /// Доступные профили и готовность их VPN-сеансов.
    Profiles,
    /// Статистика и команды текущего VPN-сеанса через проверенную службу.
    Session {
        profile: String,
        #[command(subcommand)]
        action: SessionAction,
    },
    /// Стабильная регистрация профиля текущего пользователя.
    Register { key: String },
    /// Удаление своего профиля без действующих сеансов и правил.
    Delete { profile: String },
    /// Запуск своего профиля; файл читает CLI, а не привилегированная служба.
    Start {
        profile: String,
        #[arg(long)]
        connection_file: PathBuf,
    },
    /// Остановка своего профиля с сохранением действующей защиты правил.
    Stop { profile: String },
    /// Политика текущего пользователя.
    Get {
        #[arg(long)]
        machine: bool,
    },
    /// Проверка документа службой без изменения правил.
    Check {
        file: PathBuf,
        #[arg(long)]
        expected_generation: Option<u64>,
    },
    /// Применение документа с проверкой предыдущего поколения.
    Apply {
        file: PathBuf,
        #[arg(long)]
        expected_generation: Option<u64>,
    },
    /// Удаление своей политики с проверкой поколения.
    Remove {
        #[arg(long)]
        generation: u64,
        #[arg(long)]
        machine: bool,
    },
    /// Выбор общего DNS. При разрыве VPN имена перестанут разрешаться для всех приложений.
    Dns {
        #[command(subcommand)]
        action: DnsAction,
    },
}

#[derive(Subcommand)]
enum DnsAction {
    Set {
        profile: String,
        #[arg(long, required = true)]
        acknowledge_outage: bool,
    },
    Clear,
}

#[derive(Subcommand)]
enum SessionAction {
    Statistics,
    /// Текст команды читается с правами пользователя. '-' означает stdin.
    Request {
        file: PathBuf,
    },
}

pub fn run() -> ExitCode {
    run_from(std::env::args_os().collect())
}

pub fn run_from(arguments: Vec<OsString>) -> ExitCode {
    let args = Args::parse_from(arguments);
    match execute(args.action) {
        Ok(Execution::Application(mut command)) => {
            eprintln!("{}", client::launch::NOTICE);
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::process::CommandExt;
                eprintln!("Не удалось запустить приложение: {}", command.exec());
                ExitCode::FAILURE
            }
            #[cfg(target_os = "windows")]
            match command.status() {
                Ok(status) => std::process::exit(status.code().unwrap_or(1)),
                Err(error) => {
                    eprintln!("Не удалось запустить приложение: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Ok(Execution::Reply(reply)) => emit_json(&reply),
        #[cfg(target_os = "linux")]
        Ok(Execution::Desktop(path)) => emit_json(&serde_json::json!({"desktop_entry":path})),
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn emit_json(value: &impl serde::Serialize) -> ExitCode {
    match serde_json::to_writer_pretty(std::io::stdout().lock(), value) {
        Ok(()) => {
            println!();
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Не удалось вывести результат: {error}");
            ExitCode::FAILURE
        }
    }
}

enum Execution {
    Reply(Reply),
    Application(std::process::Command),
    #[cfg(target_os = "linux")]
    Desktop(PathBuf),
}

fn execute(action: Action) -> Result<Execution, Box<dyn std::error::Error>> {
    let owner = |machine| {
        if machine {
            Ok(Owner::Machine {})
        } else {
            client::current_owner()
        }
    };
    let command = match action {
        #[cfg(target_os = "linux")]
        Action::InstallDesktop {
            name,
            executable,
            arguments,
        } => {
            return Ok(Execution::Desktop(client::launch::desktop::install(
                &executable,
                &arguments,
                &name,
            )?));
        }
        #[cfg(target_os = "linux")]
        Action::RunStored { encoded } => {
            return Ok(Execution::Application(
                client::launch::desktop::stored_command(&encoded)?,
            ));
        }
        Action::Run {
            executable,
            arguments,
        } => {
            return Ok(Execution::Application(client::launch::command(
                &executable,
                &arguments,
            )?));
        }
        Action::Status => Command::Status {},
        Action::Split { state, machine } => {
            let Reply::Policy {
                document: Some(mut document),
            } = client::call(Command::GetPolicy {
                owner: owner(machine)?,
            })?
            else {
                return Err("Политика еще не создана".into());
            };
            let expected_generation = Some(document.generation);
            document.generation = document
                .generation
                .checked_add(1)
                .ok_or("Поколение исчерпано")?;
            document.split_enabled = state == "on";
            Command::ApplyPolicy {
                document,
                expected_generation,
            }
        }
        Action::Decommission { all_users: true } => Command::Decommission {},
        Action::Decommission { all_users: false } => {
            return Err("Требуется явный параметр --all-users".into());
        }
        Action::Profiles => Command::ListProfiles {},
        Action::Session { profile, action } => {
            use crate::administration::{CommandText, SessionQuery, MAX_ADMIN_FRAME_BYTES};
            let query = match action {
                SessionAction::Statistics => SessionQuery::Statistics {},
                SessionAction::Request { file } => {
                    let input: Box<dyn Read> = if file.as_os_str() == "-" {
                        Box::new(io::stdin())
                    } else {
                        Box::new(File::open(file)?)
                    };
                    let mut bytes = Vec::new();
                    input
                        .take(MAX_ADMIN_FRAME_BYTES as u64 + 1)
                        .read_to_end(&mut bytes)?;
                    let command = CommandText::new(
                        String::from_utf8(bytes)?
                            .trim_end_matches(['\n', '\r'])
                            .to_owned(),
                    )?;
                    SessionQuery::Execute { command }
                }
            };
            client::SessionTarget::current(&profile)?.command(query)
        }
        Action::Register { key } => Command::RegisterProfile {
            owner: client::current_owner()?,
            registration_key: key,
            consumers: Vec::new(),
        },
        Action::Delete { profile } => Command::DeleteProfile { profile },
        Action::Start {
            profile,
            connection_file,
        } => Command::StartProfile {
            profile,
            connection: read_connection(&connection_file)?,
        },
        Action::Stop { profile } => Command::StopProfile { profile },
        Action::Get { machine } => Command::GetPolicy {
            owner: owner(machine)?,
        },
        Action::Check {
            file,
            expected_generation,
        } => Command::ValidatePolicy {
            document: read_policy(&file)?,
            expected_generation,
        },
        Action::Apply {
            file,
            expected_generation,
        } => Command::ApplyPolicy {
            document: read_policy(&file)?,
            expected_generation,
        },
        Action::Remove {
            generation,
            machine,
        } => Command::RemovePolicy {
            owner: owner(machine)?,
            expected_generation: generation,
        },
        Action::Dns {
            action:
                DnsAction::Set {
                    profile,
                    acknowledge_outage,
                },
        } => Command::SetGlobalDns {
            profile,
            acknowledge_outage,
        },
        Action::Dns {
            action: DnsAction::Clear,
        } => Command::ClearGlobalDns {},
    };
    Ok(Execution::Reply(client::call(command)?))
}

fn read_connection(path: &Path) -> io::Result<crate::connection::ConnectionDocument> {
    use crate::connection::{ConnectionDocument, MAX_CONNECTION_BYTES};
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONNECTION_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ConnectionDocument::from_json(&bytes)?.with_local_identity()
}

fn read_policy(path: &Path) -> io::Result<PolicyDocument> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    decode_policy(file)
}

fn decode_policy(reader: impl Read) -> io::Result<PolicyDocument> {
    let mut bytes = Vec::new();
    reader.take(MAX_POLICY_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_POLICY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Документ политики больше 128 КиБ",
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Некорректный документ политики"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_outage_requires_an_explicit_acknowledgement() {
        assert!(Args::try_parse_from(["ctl", "dns", "set", "profile"]).is_err());
        assert!(
            Args::try_parse_from(["ctl", "dns", "set", "profile", "--acknowledge-outage"]).is_ok()
        );
    }

    #[test]
    fn policy_read_is_bounded_even_when_a_reader_never_ends() {
        assert_eq!(
            decode_policy(io::repeat(b' ')).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn policy_parser_rejects_unknown_authority_and_trailing_documents() {
        let document = serde_json::json!({
            "version":1,"id":"test","generation":1,"platform":"linux","owner":{"kind":"linux_user","uid":1000},
            "default_action":{"route":"system"},"dns":{"kind":"shared_vpn","profile":"one","acknowledge_outage":true},"rules":[]
        });
        let bytes = serde_json::to_vec(&document).unwrap();
        assert_eq!(decode_policy(&bytes[..]).unwrap().id, "test");
        let mut invalid = document;
        invalid["machine_admin"] = true.into();
        assert!(decode_policy(&serde_json::to_vec(&invalid).unwrap()[..]).is_err());
        assert!(decode_policy(&[bytes, b"{}".to_vec()].concat()[..]).is_err());
    }
}
