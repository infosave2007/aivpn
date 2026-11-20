//! Общий DNS через собственную запись openresolv; записи подключений не заменяются.
mod command;
use crate::dns::journal::Provider;
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::{self, Read},
    net::SocketAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

const RELAY: &str = "127.0.0.3";
const MAX_FILE: usize = 65536;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    content: Vec<String>,
    exclusive: bool,
    effective: bool,
    private: bool,
    nosearch: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    resolvconf_key: String,
    program: command::Identity,
    boot: String,
    namespace: u64,
    entry: Option<Entry>,
    bootstrap: Vec<SocketAddr>,
    settings: Vec<String>,
}
impl PartialEq for Snapshot {
    fn eq(&self, other: &Self) -> bool {
        // DHCP остается динамическим после удаления нашей записи.
        // При установке before дополнительно сверяется непосредственно перед записью.
        self.resolvconf_key == other.resolvconf_key
            && self.program == other.program
            && self.boot == other.boot
            && self.namespace == other.namespace
            && self.entry == other.entry
    }
}
impl Eq for Snapshot {}

impl Snapshot {
    fn expired_by(&self, current: &Self) -> io::Result<bool> {
        if self.resolvconf_key != current.resolvconf_key {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if self.boot == current.boot {
            return Ok(false);
        }
        if self.entry.is_some() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        // Запись openresolv хранится в /run. Новая загрузка не дает права удалять новую запись.
        if current.entry.is_some() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        Ok(true)
    }
}

pub(crate) struct Resolvconf {
    program: command::Program,
    key: String,
}
impl Resolvconf {
    pub(crate) fn manages_resolv_conf() -> io::Result<bool> {
        match effective() {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::Unsupported => Ok(false),
            Err(error) => Err(error),
        }
    }
    pub(crate) fn open(namespace: [u8; 16]) -> io::Result<Self> {
        effective()?;
        let program = command::Program::open()?;
        let version = program.run(&["--version"], None)?;
        if !version.starts_with(b"openresolv ") {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let key = format!(
            "tun.aivpn-{}",
            namespace
                .iter()
                .map(|v| format!("{v:02x}"))
                .collect::<String>()
        );
        Ok(Self { program, key })
    }
    fn list(&self, args: &[&str]) -> io::Result<Vec<String>> {
        let bytes = self.program.run(args, None)?;
        let value = std::str::from_utf8(&bytes).map_err(|_| io::ErrorKind::InvalidData)?;
        let keys = value
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if keys.len() > 256 || keys.iter().any(|key| key.len() > 255) {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        Ok(keys)
    }
    fn read(&self) -> io::Result<Snapshot> {
        let keys = self.list(&["-i"])?;
        let (bootstrap, settings) = effective()?;
        let entry = if keys.contains(&self.key) {
            let content = lines(&self.program.run(&["-l", &self.key], None)?)?;
            Some(Entry {
                content,
                exclusive: self.list(&["-x", &self.key])?.contains(&self.key),
                effective: self.list(&["-L", "-i"])? == [self.key.clone()],
                private: self.list(&["-p", &self.key])?.contains(&self.key),
                nosearch: self.list(&["-p", "-p", &self.key])?.contains(&self.key),
            })
        } else {
            None
        };
        if let Some(entry) = &entry {
            let expected_settings = entry
                .content
                .iter()
                .filter(|line| !line.starts_with("nameserver "))
                .cloned()
                .collect::<Vec<_>>();
            if bootstrap != [SocketAddr::new(RELAY.parse().unwrap(), 53)]
                || settings != expected_settings
            {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
        }
        Ok(Snapshot {
            resolvconf_key: self.key.clone(),
            program: self.program.identity().clone(),
            boot: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?,
            namespace: std::fs::metadata("/proc/thread-self/ns/net")?.ino(),
            entry,
            bootstrap,
            settings,
        })
    }
}
impl Provider for Resolvconf {
    type Snapshot = Snapshot;
    fn runtime_expired(&mut self, before: &Snapshot) -> io::Result<bool> {
        before.expired_by(&self.read()?)
    }
    fn snapshot(&mut self) -> io::Result<Snapshot> {
        self.read()
    }
    fn bootstrap_servers(&mut self, before: &Snapshot) -> io::Result<Vec<SocketAddr>> {
        let current = self.read()?;
        if current != *before
            || current.bootstrap != before.bootstrap
            || current.settings != before.settings
        {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        crate::dns::journal::validate_bootstrap_servers(&before.bootstrap)?;
        Ok(before.bootstrap.clone())
    }
    fn plan_vpn(&mut self, before: &Snapshot) -> io::Result<Snapshot> {
        if before.entry.is_some() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let mut planned = before.clone();
        let mut content = before.settings.clone();
        content.push(format!("nameserver {RELAY}"));
        if content.iter().map(|line| line.len() + 1).sum::<usize>() > 4096 {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        planned.entry = Some(Entry {
            content,
            exclusive: true,
            effective: true,
            private: false,
            nosearch: false,
        });
        Ok(planned)
    }
    fn plan_restore(&mut self, _: &Snapshot, original: &Snapshot) -> io::Result<Snapshot> {
        if original.entry.is_some() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(original.clone())
    }
    fn apply(&mut self, expected: &Snapshot, planned: &Snapshot) -> io::Result<()> {
        let current = self.read()?;
        if current == *planned {
            return Ok(());
        }
        if current != *expected
            || (expected.entry.is_none()
                && (current.bootstrap != expected.bootstrap
                    || current.settings != expected.settings))
        {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        match &planned.entry {
            Some(entry)
                if entry.exclusive && entry.effective && !entry.private && !entry.nosearch =>
            {
                let content = entry.content.join("\n") + "\n";
                self.program.run(
                    &["-m", "0", "-x", "-a", &self.key],
                    Some(content.as_bytes()),
                )?;
            }
            None => {
                self.program.run(&["-d", &self.key], None)?;
            }
            _ => return Err(io::ErrorKind::InvalidData.into()),
        }
        if self.read()? != *planned {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        Ok(())
    }
}

fn lines(bytes: &[u8]) -> io::Result<Vec<String>> {
    if bytes.len() > MAX_FILE {
        return Err(io::ErrorKind::FileTooLarge.into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| io::ErrorKind::InvalidData)?;
    let mut result = Vec::new();
    for line in text.lines() {
        let line = line
            .split('#')
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .collect::<Vec<_>>();
        if line.is_empty() {
            continue;
        }
        if !matches!(
            line[0],
            "nameserver" | "search" | "domain" | "options" | "sortlist"
        ) {
            return Err(io::ErrorKind::Unsupported.into());
        }
        result.push(line.join(" "));
    }
    Ok(result)
}
fn effective() -> io::Result<(Vec<SocketAddr>, Vec<String>)> {
    let path = Path::new("/etc/resolv.conf").canonicalize()?;
    for parent in path.parent().ok_or(io::ErrorKind::InvalidData)?.ancestors() {
        let m = std::fs::symlink_metadata(parent)?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 || m.len() > MAX_FILE as u64 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_FILE as u64 + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if (
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    ) != (
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    if bytes.split(|byte| *byte == b'\n').next() != Some(b"# Generated by resolvconf".as_slice()) {
        return Err(io::ErrorKind::Unsupported.into());
    }
    let mut servers = Vec::new();
    let mut settings = Vec::new();
    for line in lines(&bytes)? {
        if let Some(value) = line.strip_prefix("nameserver ") {
            let ip = value.parse().map_err(|_| io::ErrorKind::InvalidData)?;
            servers.push(SocketAddr::new(ip, 53));
        } else {
            settings.push(line);
        }
    }
    if servers.len() > 32 {
        return Err(io::ErrorKind::FileTooLarge.into());
    }
    Ok((servers, settings))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(boot: &str) -> Snapshot {
        Snapshot {
            resolvconf_key: "tun.aivpn-owned".into(),
            program: serde_json::from_value(serde_json::json!({
                "device": 1, "inode": 2, "ctime": 3, "ctime_nsec": 4
            }))
            .unwrap(),
            boot: boot.into(),
            namespace: 1,
            entry: None,
            bootstrap: vec!["198.18.0.53:53".parse().unwrap()],
            settings: vec!["search lab.test".into()],
        }
    }

    #[test]
    fn new_boot_accepts_expired_record_without_restoring_old_network() {
        let before = snapshot("old");
        let mut current = snapshot("new");
        current.bootstrap = vec!["198.18.0.54:53".parse().unwrap()];
        current.namespace = 2;
        current.settings = vec!["search new.lab.test".into()];
        let observed = current.clone();
        assert!(before.expired_by(&current).unwrap());
        assert_eq!(current.bootstrap, observed.bootstrap);
        assert_eq!(current.settings, observed.settings);
    }

    #[test]
    fn same_boot_missing_entry_is_not_an_expired_record() {
        let before = snapshot("same");
        let mut current = before.clone();
        current.namespace = 2;
        assert!(!before.expired_by(&current).unwrap());
    }

    #[test]
    fn new_boot_existing_entry_is_not_ours_to_replace() {
        let before = snapshot("old");
        let mut current = snapshot("new");
        current.entry = Some(Entry {
            content: vec!["nameserver 127.0.0.3".into()],
            exclusive: true,
            effective: true,
            private: false,
            nosearch: false,
        });
        assert_eq!(
            before.expired_by(&current).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
    }

    #[test]
    fn new_boot_cannot_expire_another_namespaces_record() {
        let before = snapshot("old");
        let mut current = snapshot("new");
        current.resolvconf_key = "tun.aivpn-other".into();
        assert_eq!(
            before.expired_by(&current).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
