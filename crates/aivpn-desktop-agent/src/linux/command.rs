//! Системные сетевые утилиты выбираются без пользовательского PATH.
use std::{
    fs, io,
    os::unix::{fs::MetadataExt, process::CommandExt},
    path::Path,
    process::Command,
};

pub fn system_network_command(program: &str) -> io::Result<Command> {
    if !["ip", "nft", "iptables-nft", "ip6tables-nft"].contains(&program) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let owner = fs::metadata("/")?.uid();
    for directory in ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
        let Ok(path) = Path::new(directory).join(program).canonicalize() else {
            continue;
        };
        if !path
            .metadata()
            .is_ok_and(|meta| meta.is_file() && meta.mode() & 0o111 != 0)
            || !path.ancestors().all(|part| {
                fs::symlink_metadata(part)
                    .is_ok_and(|meta| meta.uid() == owner && meta.mode() & 0o022 == 0)
            })
        {
            continue;
        }
        let mut command = Command::new(path);
        // Multicall сохраняет выбранное имя, даже если путь ведет на busybox/xtables.
        command.arg0(program);
        return Ok(command);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("Не найдена доверенная системная команда {program}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arbitrary_programs_are_rejected_before_lookup() {
        for program in ["sh", "../ip", "/usr/bin/ip", "ip;id", ""] {
            assert_eq!(
                system_network_command(program).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }
    #[test]
    fn system_ip_uses_an_absolute_trusted_image_and_keeps_the_applet_name() {
        let mut command = system_network_command("ip").unwrap();
        assert!(Path::new(command.get_program()).is_absolute());
        // Проверяем реальный запрос, а не только выбранную строку пути.
        let output = command.args(["-j", "link", "show", "lo"]).output().unwrap();
        assert!(output.status.success(), "{:?}", output);
        let rows: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(rows[0]["ifname"], "lo");
    }
}
