//! Локальная политика процесса. Читается из общего JSON и не входит в профиль.
//!
//! Неизвестный ключ в файле игнорируется: здесь только поля, которые общий
//! код умеет применить. Содержимое файла в текст ошибки не попадает.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Error, Result};

const MAX_CONFIG_BYTES: u64 = 64 * 1024;

fn traffic_adaptation_default() -> bool {
    true
}

/// Глобальные локальные настройки. Поле адаптации по умолчанию включено.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default = "traffic_adaptation_default")]
    pub traffic_adaptation: bool,
    /// Паузы отправки данных; настройка локальная, из ключа подключения не берется.
    #[serde(default)]
    pub upload_shaping: crate::pacing::PacingMode,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            traffic_adaptation: true,
            upload_shaping: crate::pacing::PacingMode::default(),
        }
    }
}

impl RuntimeConfig {
    /// Только отсутствие стандартного файла дает значения по умолчанию.
    /// Сломанная ссылка и другие ошибки не отменяют локальный запрет.
    pub fn load_default_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        match std::fs::symlink_metadata(path) {
            Ok(_) => Self::load_file(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error.into()),
        }
    }

    /// Прочитать файл. Больше 64 КиБ или неверный JSON - ошибка без тела файла.
    ///
    /// Отсутствующий файл сюда не подставляется: вызывающий сам решает, что
    /// отсутствие стандартного пути означает значения по умолчанию.
    pub fn load_file(path: impl AsRef<Path>) -> Result<Self> {
        read_local_config(path)
    }
}

/// Ограниченное чтение локального JSON без вывода значений в ошибке.
pub fn read_local_config<T: serde::de::DeserializeOwned>(path: impl AsRef<Path>) -> Result<T> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut file = options.open(path.as_ref())?;
    if !file.metadata()?.is_file() {
        return Err(Error::Serialization(
            "конфигурация должна быть обычным файлом".into(),
        ));
    }
    let mut buf = Vec::new();
    file.by_ref()
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_CONFIG_BYTES {
        return Err(Error::Serialization(
            "файл конфигурации больше 64 КиБ".into(),
        ));
    }
    serde_json::from_slice(&buf)
        .map_err(|_| Error::Serialization("файл конфигурации содержит неверный JSON".into()))
}

#[derive(Clone, Copy)]
#[cfg_attr(not(test), allow(dead_code))]
enum HostKind {
    Linux,
    Macos,
    Windows,
}

fn non_empty(value: Option<&std::ffi::OsStr>) -> Option<&std::ffi::OsStr> {
    value.filter(|item| !item.is_empty())
}

fn path_for(
    kind: HostKind,
    xdg: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
    appdata: Option<&std::ffi::OsStr>,
) -> PathBuf {
    match kind {
        HostKind::Windows => match non_empty(appdata) {
            Some(dir) => PathBuf::from(dir).join("aivpn").join("config.json"),
            None => PathBuf::from(r"C:\ProgramData\aivpn\config.json"),
        },
        HostKind::Macos => match non_empty(home) {
            Some(dir) => PathBuf::from(dir)
                .join("Library")
                .join("Application Support")
                .join("aivpn")
                .join("config.json"),
            None => PathBuf::from("/Library/Application Support/aivpn/config.json"),
        },
        HostKind::Linux => {
            if let Some(dir) = non_empty(xdg).filter(|dir| Path::new(dir).is_absolute()) {
                return PathBuf::from(dir).join("aivpn").join("config.json");
            }
            match non_empty(home) {
                Some(dir) => PathBuf::from(dir)
                    .join(".config")
                    .join("aivpn")
                    .join("config.json"),
                None => PathBuf::from("/etc/aivpn/config.json"),
            }
        }
    }
}

/// Стандартный путь общего файла. Android этот путь не использует: каталог
/// приложения приходит отдельно, из `filesDir`.
pub fn default_config_path() -> PathBuf {
    #[cfg(windows)]
    {
        path_for(
            HostKind::Windows,
            None,
            None,
            std::env::var_os("APPDATA").as_deref(),
        )
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        path_for(
            HostKind::Macos,
            None,
            std::env::var_os("HOME").as_deref(),
            None,
        )
    }
    #[cfg(all(unix, not(any(target_os = "macos", target_os = "ios"))))]
    {
        path_for(
            HostKind::Linux,
            std::env::var_os("XDG_CONFIG_HOME").as_deref(),
            std::env::var_os("HOME").as_deref(),
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(name: &str, bytes: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "aivpn-runtime-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn upload_shaping_is_local_explicit_and_validated() {
        use crate::pacing::PacingMode;
        assert_eq!(
            serde_json::from_str::<RuntimeConfig>("{}")
                .unwrap()
                .upload_shaping,
            PacingMode::Adaptive
        );
        for (value, expected) in [
            ("adaptive", PacingMode::Adaptive),
            ("full", PacingMode::Full),
            ("off", PacingMode::Off),
        ] {
            let json = format!(r#"{{"upload_shaping":"{value}"}}"#);
            assert_eq!(
                serde_json::from_str::<RuntimeConfig>(&json)
                    .unwrap()
                    .upload_shaping,
                expected
            );
        }
        assert!(serde_json::from_str::<RuntimeConfig>(r#"{"upload_shaping":"invalid"}"#).is_err());
    }

    #[test]
    fn default_is_true_and_json_false_wins() {
        assert!(RuntimeConfig::default().traffic_adaptation);
        let parsed: RuntimeConfig = serde_json::from_str("{}").unwrap();
        assert!(parsed.traffic_adaptation);
        let path = write_temp(
            "false.json",
            br#"{"traffic_adaptation":false,"unrelated":1}"#,
        );
        let loaded = RuntimeConfig::load_file(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(!loaded.traffic_adaptation);
    }

    #[test]
    fn type_error_does_not_become_true() {
        let path = write_temp("bad.json", br#"{"traffic_adaptation":"no"}"#);
        let error = RuntimeConfig::load_file(&path).unwrap_err();
        let _ = std::fs::remove_file(&path);
        let text = error.to_string();
        assert!(text.contains("неверный JSON"));
        assert!(!text.contains("no"));
    }

    #[test]
    fn oversize_is_rejected_without_body() {
        let mut bytes = vec![b' '; (MAX_CONFIG_BYTES as usize) + 8];
        bytes[0] = b'{';
        bytes[1] = b'}';
        let path = write_temp("big.json", &bytes);
        let error = RuntimeConfig::load_file(&path).unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(error.to_string().contains("64"));
    }

    #[test]
    fn missing_file_is_not_a_silent_default() {
        let path = std::env::temp_dir().join(format!(
            "aivpn-runtime-missing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        assert!(matches!(
            RuntimeConfig::load_file(&path),
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound
        ));
    }

    #[cfg(unix)]
    #[test]
    fn broken_link_does_not_silently_enable_adaptation() {
        let path = write_temp("link", b"");
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(path.with_extension("missing"), &path).unwrap();
        let result = RuntimeConfig::load_default_file(&path);
        std::fs::remove_file(&path).unwrap();
        assert!(result.is_err());
        assert!(
            RuntimeConfig::load_default_file(&path)
                .unwrap()
                .traffic_adaptation
        );
    }

    #[test]
    fn room_params_do_not_override_runtime_false() {
        let runtime = RuntimeConfig {
            traffic_adaptation: false,
            ..Default::default()
        };
        let params = br#"{"room":"alpha","traffic_adaptation":true}"#.to_vec();
        let cfg = crate::transport::TransportConfig::new("local", params.clone())
            .with_runtime_config(runtime);
        assert!(!cfg.runtime_config().traffic_adaptation);
        assert_eq!(cfg.params(), params.as_slice());
        assert!(
            crate::transport::TransportConfig::default()
                .runtime_config()
                .traffic_adaptation
        );
    }

    #[test]
    fn transport_debug_does_not_print_opaque_credentials() {
        let config = crate::transport::TransportConfig::new("sample", vec![234, 187, 13, 77]);
        let rendered = format!("{config:?}");
        assert!(rendered.contains("params_len: 4"));
        assert!(!rendered.contains("234"));
        assert!(!rendered.contains("187"));
    }

    #[test]
    fn relative_xdg_and_missing_home_do_not_select_working_directory() {
        assert_eq!(
            path_for(
                HostKind::Linux,
                Some(std::ffi::OsStr::new("relative")),
                Some(std::ffi::OsStr::new("/home/user")),
                None
            ),
            PathBuf::from("/home/user/.config/aivpn/config.json")
        );
        assert_eq!(
            path_for(HostKind::Linux, None, None, None),
            PathBuf::from("/etc/aivpn/config.json")
        );
    }

    #[cfg(unix)]
    #[test]
    fn fifo_is_rejected_without_waiting_for_a_writer() {
        use std::os::unix::ffi::OsStrExt;
        let path = write_temp("pipe", b"");
        std::fs::remove_file(&path).unwrap();
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let result = RuntimeConfig::load_file(&path);
        std::fs::remove_file(&path).unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn windows_service_uses_programdata_without_appdata() {
        assert_eq!(
            path_for(HostKind::Windows, None, None, None),
            PathBuf::from(r"C:\ProgramData\aivpn\config.json"),
        );
    }

    #[test]
    fn paths_follow_the_host_convention() {
        let linux = path_for(
            HostKind::Linux,
            Some(std::ffi::OsStr::new("/xdg")),
            Some(std::ffi::OsStr::new("/home/user")),
            None,
        );
        assert_eq!(linux, PathBuf::from("/xdg/aivpn/config.json"));
        let fallback = path_for(
            HostKind::Linux,
            Some(std::ffi::OsStr::new("")),
            Some(std::ffi::OsStr::new("/home/user")),
            None,
        );
        assert_eq!(
            fallback,
            PathBuf::from("/home/user/.config/aivpn/config.json")
        );
        let mac = path_for(
            HostKind::Macos,
            Some(std::ffi::OsStr::new("/xdg")),
            Some(std::ffi::OsStr::new("/Users/user")),
            None,
        );
        assert_eq!(
            mac,
            PathBuf::from("/Users/user/Library/Application Support/aivpn/config.json")
        );
        let windows = path_for(
            HostKind::Windows,
            None,
            None,
            Some(std::ffi::OsStr::new(r"C:\Users\user\AppData\Roaming")),
        );
        assert_eq!(
            windows,
            PathBuf::from(r"C:\Users\user\AppData\Roaming")
                .join("aivpn")
                .join("config.json")
        );
    }
}
