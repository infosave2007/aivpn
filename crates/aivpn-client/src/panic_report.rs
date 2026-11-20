use std::fs::File;
use std::io::Write;

pub(crate) fn install(file: File) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
            .unwrap_or("Panic без текстового сообщения");
        let message = if message.contains("aivpn://") {
            "Содержимое panic с ключом подключения скрыто".to_owned()
        } else {
            message
                .chars()
                .take(2048)
                .collect::<String>()
                .replace('\n', "\\n")
                .replace('\r', "\\r")
        };
        let location = info.location().map(ToString::to_string).unwrap_or_default();
        // Отдельный дескриптор сохраняет причину до очистки TUN, даже без stderr.
        let mut writer = &file;
        let _ = writeln!(
            writer,
            "AIVPN-PANIC {location}: {message}\nBacktrace:\n{}",
            std::backtrace::Backtrace::force_capture()
        );
        let _ = writer.flush();
        previous(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};

    #[test]
    fn panic_is_saved_when_stderr_is_discarded() {
        let path =
            std::env::temp_dir().join(format!("aivpn-panic-regression-{}.log", std::process::id()));
        std::fs::write(&path, "start\n").unwrap();
        let result = Command::new(std::env::current_exe().unwrap())
            .args(["panic_child", "--ignored", "--test-threads=1"])
            .env("AIVPN_PANIC_TEST_LOG", &path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(path);
        assert!(!result.success());
        assert!(text.contains("AIVPN-PANIC"), "{text}");
        assert!(text.contains("test driver failure"), "{text}");
        assert!(text.contains("panic_report.rs:"), "{text}");
        assert!(text.contains("Backtrace:"), "{text}");
        assert!(text.ends_with("INFO adapter cleanup\n"), "{text}");
    }

    #[test]
    fn panic_does_not_persist_connection_key() {
        let path =
            std::env::temp_dir().join(format!("aivpn-panic-secret-{}.log", std::process::id()));
        std::fs::write(&path, "start\n").unwrap();
        let result = Command::new(std::env::current_exe().unwrap())
            .args(["panic_child", "--ignored", "--test-threads=1"])
            .env("AIVPN_PANIC_TEST_LOG", &path)
            .env("AIVPN_PANIC_TEST_SECRET", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(path);
        assert!(!result.success());
        assert!(text.contains("AIVPN-PANIC"));
        assert!(!text.contains("aivpn://"), "{text}");
        assert!(!text.contains("test-secret-value"), "{text}");
    }

    #[test]
    #[ignore = "Выполняется отдельным процессом для проверки глобального panic hook"]
    fn panic_child() {
        let path = std::env::var_os("AIVPN_PANIC_TEST_LOG").unwrap();
        let file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        struct Cleanup(File);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = writeln!(self.0, "INFO adapter cleanup");
            }
        }
        let _cleanup = Cleanup(file.try_clone().unwrap());
        install(file);
        if std::env::var_os("AIVPN_PANIC_TEST_SECRET").is_some() {
            panic!("Invalid connection: aivpn://test-secret-value");
        }
        panic!("test driver failure");
    }
}
