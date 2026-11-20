//! Обычный resolv.conf. Файлы, принадлежащие менеджеру сети, выбирает другой адаптер.
use crate::dns::journal::Provider;
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

const MAX_FILE: usize = 65536;
const MAX_ATTRIBUTES: usize = 128 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Value {
    parent_device: u64,
    parent_inode: u64,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    mtime: i64,
    mtime_nsec: i64,
    bytes: Vec<u8>,
    attributes: Vec<(Vec<u8>, Vec<u8>)>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    value: Value,
    stage: Option<String>,
}
impl PartialEq for Snapshot {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}
impl Eq for Snapshot {}

pub(crate) struct FileProvider {
    directory: File,
    parent: PathBuf,
    identity: (u64, u64),
    staging: super::staging::Staging,
}
impl FileProvider {
    pub(crate) fn open(parent: &Path, namespace: [u8; 16]) -> io::Result<Self> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent)?;
        let metadata = directory.metadata()?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(Self {
            directory,
            parent: parent.into(),
            identity: (metadata.dev(), metadata.ino()),
            staging: super::staging::Staging::new("dns", namespace),
        })
    }
    fn check_parent(&self) -> io::Result<()> {
        let m = std::fs::symlink_metadata(&self.parent)?;
        if !m.is_dir()
            || (m.dev(), m.ino()) != self.identity
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o022 != 0
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }
    fn open_file(&self, name: &CString, flags: i32) -> io::Result<File> {
        self.check_parent()?;
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn read(&self, mut file: File, stage: Option<String>) -> io::Result<Snapshot> {
        let m = file.metadata()?;
        if !m.is_file()
            || m.nlink() != 1
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o022 != 0
            || m.len() > MAX_FILE as u64
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_FILE as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_FILE {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        let attributes = attributes(&file)?;
        let after = file.metadata()?;
        if (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        ) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(Snapshot {
            value: Value {
                parent_device: self.identity.0,
                parent_inode: self.identity.1,
                device: m.dev(),
                inode: m.ino(),
                uid: m.uid(),
                gid: m.gid(),
                mode: m.mode() & 0o7777,
                mtime: m.mtime(),
                mtime_nsec: m.mtime_nsec(),
                bytes,
                attributes,
            },
            stage,
        })
    }
    fn prepare(
        &mut self,
        original: &Snapshot,
        bytes: Vec<u8>,
        restore_time: bool,
    ) -> io::Result<Snapshot> {
        self.check_parent()?;
        let native = self.staging.prepare_name(&self.directory)?;
        let name = native
            .to_str()
            .map_err(|_| io::ErrorKind::InvalidData)?
            .to_owned();
        let mut file = self.open_file(&native, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL)?;
        let result = (|| {
            file.write_all(&bytes)?;
            if unsafe { libc::fchown(file.as_raw_fd(), original.value.uid, original.value.gid) } < 0
            {
                return Err(io::Error::last_os_error());
            }
            for (key, value) in &original.value.attributes {
                let key = CString::new(key.as_slice()).map_err(|_| io::ErrorKind::InvalidData)?;
                if unsafe {
                    libc::fsetxattr(
                        file.as_raw_fd(),
                        key.as_ptr(),
                        value.as_ptr().cast(),
                        value.len(),
                        0,
                    )
                } < 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            if unsafe { libc::fchmod(file.as_raw_fd(), original.value.mode) } < 0 {
                return Err(io::Error::last_os_error());
            }
            if restore_time {
                let times = [
                    libc::timespec {
                        tv_sec: 0,
                        tv_nsec: libc::UTIME_OMIT,
                    },
                    libc::timespec {
                        tv_sec: original.value.mtime,
                        tv_nsec: original.value.mtime_nsec,
                    },
                ];
                if unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) } < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            file.sync_all()?;
            // Снимок читается с начала, независимо от позиции после write_all.
            use std::io::Seek;
            file.rewind()?;
            let snapshot = self.read(file.try_clone()?, Some(name))?;
            if snapshot.value.bytes != bytes
                || snapshot.value.mode != original.value.mode
                || snapshot.value.uid != original.value.uid
                || snapshot.value.gid != original.value.gid
                || snapshot.value.attributes != original.value.attributes
            {
                return Err(io::ErrorKind::Unsupported.into());
            }
            self.directory.sync_all()?;
            Ok(snapshot)
        })();
        if result.is_err() {
            unsafe { libc::unlinkat(self.directory.as_raw_fd(), native.as_ptr(), 0) };
        }
        result
    }
}
impl Provider for FileProvider {
    type Snapshot = Snapshot;
    fn cleanup_restored(&mut self) -> io::Result<()> {
        self.check_parent()?;
        self.staging.clear(&self.directory)
    }
    fn bootstrap_servers(&mut self, before: &Snapshot) -> io::Result<Vec<std::net::SocketAddr>> {
        let content =
            std::str::from_utf8(&before.value.bytes).map_err(|_| io::ErrorKind::InvalidData)?;
        let mut servers = Vec::new();
        for line in content.lines() {
            let mut fields = line
                .split('#')
                .next()
                .unwrap_or_default()
                .split_whitespace();
            if fields.next() == Some("nameserver") {
                let server = crate::dns::journal::bootstrap_server(
                    fields.next().ok_or(io::ErrorKind::InvalidData)?,
                    None,
                )?;
                if !servers.contains(&server) {
                    servers.push(server);
                }
            }
        }
        crate::dns::journal::validate_bootstrap_servers(&servers)?;
        Ok(servers)
    }
    fn snapshot(&mut self) -> io::Result<Snapshot> {
        self.read(
            self.open_file(&CString::new("resolv.conf").unwrap(), libc::O_RDONLY)?,
            None,
        )
    }
    fn plan_vpn(&mut self, before: &Snapshot) -> io::Result<Snapshot> {
        let mut bytes = Vec::new();
        for line in before.value.bytes.split_inclusive(|b| *b == b'\n') {
            let text = line.trim_ascii_start();
            if text.starts_with(b"nameserver") && text.get(10).is_none_or(u8::is_ascii_whitespace) {
                continue;
            }
            bytes.extend_from_slice(line);
        }
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            bytes.push(b'\n');
        }
        bytes.extend_from_slice(b"nameserver 127.0.0.3\n");
        if bytes.len() > MAX_FILE {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        self.prepare(before, bytes, false)
    }
    fn plan_restore(&mut self, current: &Snapshot, original: &Snapshot) -> io::Result<Snapshot> {
        if current == original {
            return Ok(current.clone());
        }
        self.prepare(original, original.value.bytes.clone(), true)
    }
    fn apply(&mut self, expected: &Snapshot, planned: &Snapshot) -> io::Result<()> {
        if self.snapshot()? != *expected {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        if planned == expected {
            return Ok(());
        }
        if (planned.value.parent_device, planned.value.parent_inode) != self.identity {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let name = planned.stage.as_ref().ok_or(io::ErrorKind::InvalidData)?;
        if !self.staging.accepts(name) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let name = CString::new(name.as_str()).map_err(|_| io::ErrorKind::InvalidData)?;
        if self.read(
            self.open_file(&name, libc::O_RDONLY)?,
            planned.stage.clone(),
        )? != *planned
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if self.snapshot()? != *expected {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        if unsafe {
            libc::renameat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                self.directory.as_raw_fd(),
                c"resolv.conf".as_ptr(),
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        self.directory.sync_all()?;
        if self.snapshot()? != *planned {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
}

fn attributes(file: &File) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let fd = file.as_raw_fd();
    let length = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize > 65536 {
        return Err(io::ErrorKind::FileTooLarge.into());
    }
    let mut names = vec![0u8; length as usize];
    if unsafe { libc::flistxattr(fd, names.as_mut_ptr().cast(), names.len()) } != length {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    let mut result = Vec::new();
    let mut total = 0;
    for name in names.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        let native = CString::new(name).map_err(|_| io::ErrorKind::InvalidData)?;
        let length = unsafe { libc::fgetxattr(fd, native.as_ptr(), std::ptr::null_mut(), 0) };
        if length < 0 {
            return Err(io::Error::last_os_error());
        }
        total += length as usize;
        if total > MAX_ATTRIBUTES || result.len() >= 64 {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        let mut value = vec![0u8; length as usize];
        if unsafe { libc::fgetxattr(fd, native.as_ptr(), value.as_mut_ptr().cast(), value.len()) }
            != length
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        result.push((name.into(), value));
    }
    result.sort();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path =
                std::env::temp_dir().join(format!("aivpn-resolv-{}-{nonce}", std::process::id()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn abandoned_plan_is_removed_before_preparing_the_next_change() {
        let fixture = Fixture::new();
        let path = fixture.0.join("resolv.conf");
        std::fs::write(&path, b"nameserver 9.9.9.9\n").unwrap();
        let mut provider = FileProvider::open(&fixture.0, [7; 16]).unwrap();
        let original = provider.snapshot().unwrap();
        provider.plan_vpn(&original).unwrap();
        drop(provider);

        let mut provider = FileProvider::open(&fixture.0, [7; 16]).unwrap();
        let planned = provider.plan_vpn(&original).unwrap();
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 2);
        assert_eq!(provider.snapshot().unwrap(), original);
        provider.apply(&original, &planned).unwrap();
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
    }
    #[test]
    fn disabling_dns_after_an_unrecorded_plan_cleans_the_temporary_file() {
        use crate::{control::ControlStore, dns::journal, state::StateFile};
        struct Store {
            journal: Option<Vec<u8>>,
            writes: usize,
            fail: bool,
        }
        impl ControlStore for Store {
            fn load(&self, file: StateFile) -> io::Result<Option<Vec<u8>>> {
                assert!(matches!(file, StateFile::DnsJournal));
                Ok(self.journal.clone())
            }
            fn replace(&mut self, file: StateFile, bytes: &[u8]) -> io::Result<()> {
                assert!(matches!(file, StateFile::DnsJournal));
                self.writes += 1;
                if self.fail && self.writes == 3 {
                    return Err(io::Error::other("Не удалось сохранить подготовленный план"));
                }
                self.journal = Some(bytes.to_vec());
                Ok(())
            }
            fn clear_pending(&mut self) -> io::Result<()> {
                unreachable!()
            }
        }
        struct Guard(bool);
        impl journal::Guard for Guard {
            fn enable(&mut self) -> io::Result<()> {
                self.0 = true;
                Ok(())
            }
            fn disable(&mut self) -> io::Result<()> {
                self.0 = false;
                Ok(())
            }
        }
        let fixture = Fixture::new();
        let path = fixture.0.join("resolv.conf");
        std::fs::write(&path, b"nameserver 9.9.9.9\n").unwrap();
        let mut provider = FileProvider::open(&fixture.0, [7; 16]).unwrap();
        let before = provider.snapshot().unwrap();
        let mut store = Store {
            journal: None,
            writes: 0,
            fail: true,
        };
        let mut guard = Guard(false);
        let scope = journal::DnsScope {
            namespace: [7; 16],
            control_serial: 1,
            control_digest: [1; 32],
            profile: "test".into(),
        };
        assert!(journal::activate(&mut store, scope, &mut provider, &mut guard).is_err());
        assert!(guard.0);
        assert_eq!(provider.snapshot().unwrap(), before);
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 2);
        drop(provider);
        let mut provider = FileProvider::open(&fixture.0, [7; 16]).unwrap();
        store.fail = false;
        journal::restore(&mut store, [7; 16], &mut provider, &mut guard).unwrap();
        assert!(!guard.0);
        assert_eq!(provider.snapshot().unwrap(), before);
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
        journal::restore(&mut store, [7; 16], &mut provider, &mut guard).unwrap();
        assert!(!guard.0);
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
    }
    #[test]
    fn preparing_a_plan_keeps_other_namespaces_and_unscoped_files() {
        let fixture = Fixture::new();
        std::fs::write(fixture.0.join("resolv.conf"), b"nameserver 9.9.9.9\n").unwrap();
        let mut other = FileProvider::open(&fixture.0, [8; 16]).unwrap();
        let original = other.snapshot().unwrap();
        let other_plan = other.plan_vpn(&original).unwrap();
        let other_path = fixture.0.join(other_plan.stage.as_ref().unwrap());
        let legacy = fixture
            .0
            .join(".aivpn-dns-11111111111111111111111111111111.new");
        std::fs::write(&legacy, b"unattributed").unwrap();
        let mut provider = FileProvider::open(&fixture.0, [7; 16]).unwrap();
        provider.plan_vpn(&original).unwrap();
        let planned = provider.plan_vpn(&original).unwrap();
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 4);
        assert!(other_path.is_file());
        assert_eq!(std::fs::read(legacy).unwrap(), b"unattributed");
        assert!(provider.apply(&original, &other_plan).is_err());
        provider.apply(&original, &planned).unwrap();
    }
    #[test]
    fn unsafe_temporary_file_is_preserved_and_stops_cleanup() {
        let fixture = Fixture::new();
        let original_path = fixture.0.join("resolv.conf");
        std::fs::write(&original_path, b"nameserver 9.9.9.9\n").unwrap();
        let mut provider = FileProvider::open(&fixture.0, [7; 16]).unwrap();
        let original = provider.snapshot().unwrap();
        let planned = provider.plan_vpn(&original).unwrap();
        let staged = fixture.0.join(planned.stage.as_ref().unwrap());
        std::fs::remove_file(&staged).unwrap();
        std::os::unix::fs::symlink("resolv.conf", &staged).unwrap();
        assert_eq!(
            provider.plan_vpn(&original).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(std::fs::symlink_metadata(&staged).unwrap().is_symlink());
        assert_eq!(provider.snapshot().unwrap(), original);
        std::fs::remove_file(&staged).unwrap();
        std::fs::hard_link(&original_path, &staged).unwrap();
        assert_eq!(
            provider
                .staging
                .prepare_name(&provider.directory)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(std::fs::read(&staged).unwrap(), original.value.bytes);
    }
    #[test]
    fn real_file_roundtrip_preserves_options_metadata_and_attributes() {
        let fixture = Fixture::new();
        let path = fixture.0.join("resolv.conf");
        let bytes=b"# local resolver\nsearch lab.test\n nameserver 9.9.9.9\noptions timeout:1 attempts:1\n";
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let f = File::open(&path).unwrap();
        assert_eq!(
            unsafe {
                libc::fsetxattr(
                    f.as_raw_fd(),
                    c"user.aivpn-test".as_ptr(),
                    b"metadata".as_ptr().cast(),
                    8,
                    0,
                )
            },
            0
        );
        drop(f);
        let mut provider = FileProvider::open(&fixture.0, [7; 16]).unwrap();
        let before = provider.snapshot().unwrap();
        assert_eq!(
            provider.bootstrap_servers(&before).unwrap(),
            ["9.9.9.9:53".parse().unwrap()]
        );
        let planned = provider.plan_vpn(&before).unwrap();
        assert_eq!(provider.snapshot().unwrap(), before);
        let encoded = serde_json::to_vec(&planned).unwrap();
        drop(provider);
        let mut provider = FileProvider::open(&fixture.0, [7; 16]).unwrap();
        let planned = serde_json::from_slice(&encoded).unwrap();
        provider.apply(&before, &planned).unwrap();
        assert_eq!(provider.snapshot().unwrap(), planned);
        assert_eq!(std::fs::read(&path).unwrap(),b"# local resolver\nsearch lab.test\noptions timeout:1 attempts:1\nnameserver 127.0.0.3\n");
        let restored = provider.plan_restore(&planned, &before).unwrap();
        provider.apply(&planned, &restored).unwrap();
        let actual = provider.snapshot().unwrap();
        assert_eq!(actual.value.bytes, bytes);
        assert_eq!(actual.value.mode, before.value.mode);
        assert_eq!(actual.value.attributes, before.value.attributes);
        assert_eq!(actual.value.mtime, before.value.mtime);
        assert_eq!(actual.value.mtime_nsec, before.value.mtime_nsec);
        // Восстановление заменяет файл, а не переписывает его на месте. Номер
        // inode исходного файла освобожден первой заменой, и файловая система
        // вправе выдать его снова, поэтому сравнивается файл, который
        // существовал до восстановления.
        assert_ne!(actual.value.inode, planned.value.inode);
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
    }
    #[test]
    fn foreign_replacement_is_preserved_even_with_identical_contents() {
        let fixture = Fixture::new();
        let path = fixture.0.join("resolv.conf");
        std::fs::write(&path, b"nameserver 9.9.9.9\n").unwrap();
        let mut provider = FileProvider::open(&fixture.0, [7; 16]).unwrap();
        let before = provider.snapshot().unwrap();
        let planned = provider.plan_vpn(&before).unwrap();
        let foreign = fixture.0.join("foreign");
        std::fs::write(&foreign, &before.value.bytes).unwrap();
        std::fs::rename(foreign, &path).unwrap();
        assert_eq!(
            provider.apply(&before, &planned).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&path).unwrap(), before.value.bytes);
    }
    #[test]
    fn symlink_is_not_converted_to_a_regular_file() {
        let fixture = Fixture::new();
        let target = fixture.0.join("managed");
        std::fs::write(&target, b"nameserver 9.9.9.9\n").unwrap();
        std::os::unix::fs::symlink("managed", fixture.0.join("resolv.conf")).unwrap();
        let mut provider = FileProvider::open(&fixture.0, [7; 16]).unwrap();
        assert!(provider.snapshot().is_err());
        assert!(std::fs::symlink_metadata(fixture.0.join("resolv.conf"))
            .unwrap()
            .is_symlink());
        assert_eq!(std::fs::read(target).unwrap(), b"nameserver 9.9.9.9\n");
    }
}
