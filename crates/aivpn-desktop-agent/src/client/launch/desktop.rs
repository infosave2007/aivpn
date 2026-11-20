//! Отдельный пользовательский ярлык. Исходные desktop entry не изменяются.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
};

const MAX_STORED_BYTES: usize = 64 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u32,
    executable: String,
    arguments: Vec<String>,
}

pub fn stored_command(encoded: &str) -> Result<Command, ClientError> {
    if encoded.len() > MAX_STORED_BYTES * 4 / 3 + 4 {
        return Err(invalid("Ярлык превышает допустимый размер").into());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| invalid("Некорректный ярлык"))?;
    if bytes.len() > MAX_STORED_BYTES {
        return Err(invalid("Ярлык превышает допустимый размер").into());
    }
    let stored: Stored =
        serde_json::from_slice(&bytes).map_err(|_| invalid("Некорректный ярлык"))?;
    if stored.version != 1 {
        return Err(invalid("Неизвестная версия ярлыка").into());
    }
    let arguments = stored
        .arguments
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    command(Path::new(&stored.executable), &arguments)
}

pub fn install(program: &Path, arguments: &[OsString], name: &str) -> Result<PathBuf, ClientError> {
    // Проверяем текущую службу и политику, сам процесс пока не создаем.
    drop(command(program, arguments)?);
    if name.trim().is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
        return Err(invalid("Укажите непустое имя ярлыка без управляющих символов").into());
    }
    let text = |value: &std::ffi::OsStr| {
        value
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| invalid("Ярлык поддерживает пути и аргументы UTF-8"))
    };
    let stored = Stored {
        version: 1,
        executable: text(program.as_os_str())?,
        arguments: arguments
            .iter()
            .map(|a| text(a))
            .collect::<io::Result<Vec<_>>>()?,
    };
    let bytes = serde_json::to_vec(&stored).map_err(io::Error::other)?;
    if bytes.len() > MAX_STORED_BYTES {
        return Err(invalid("Ярлык превышает допустимый размер").into());
    }
    let encoded = URL_SAFE_NO_PAD.encode(&bytes);
    let helper = std::env::current_exe()?;
    let helper = text(helper.as_os_str())?;
    if helper.contains('=') || helper.chars().any(char::is_control) {
        return Err(invalid("Путь клиента нельзя записать в desktop entry").into());
    }
    let mut quoted = String::from("\"");
    for character in helper.chars() {
        if matches!(character, '"' | '`' | '$' | '\\') {
            quoted.push_str("\\\\");
        }
        if character == '\\' {
            quoted.push_str("\\\\");
        } else if character == '%' {
            quoted.push_str("%%");
        } else {
            quoted.push(character);
        }
    }
    quoted.push('"');
    // Только ASCII descriptor попадает в Exec. Unicode, %, кавычки и shell-символы
    // приложения проходят как данные, без field-code expansion и без shell.
    let contents = format!("[Desktop Entry]\nType=Application\nVersion=1.0\nName=AIVPN: {}\nExec={} app-routing run-stored {}\nTerminal=false\nIcon=application-x-executable\nCategories=Utility;\nX-AIVPN-Managed=true\n", name.replace('\\', "\\\\"), quoted, encoded);
    let home = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .map(|p| p.join(".local/share"))
        })
        .ok_or_else(|| invalid("Не найден пользовательский каталог приложений"))?;
    let directory = home.join("applications");
    fs::create_dir_all(&directory)?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let target = directory.join(format!("aivpn-app-{digest}.desktop"));
    if target.try_exists()? {
        return same_entry(&target, contents.as_bytes()).map_err(Into::into);
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let temporary = directory.join(format!(".aivpn-{}-{nonce}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let outcome = (|| {
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        match fs::hard_link(&temporary, &target) {
            Ok(()) => Ok(target.clone()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                same_entry(&target, contents.as_bytes())
            }
            Err(error) => Err(error),
        }
    })();
    let _ = fs::remove_file(&temporary);
    Ok(outcome?)
}

fn same_entry(path: &Path, expected: &[u8]) -> io::Result<PathBuf> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("Ярлык уже существует и не является обычным файлом"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes != expected {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Ярлык изменен пользователем и не будет перезаписан",
        ));
    }
    Ok(path.to_owned())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
