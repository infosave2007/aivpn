//! Постоянный секрет из 32 байт. Ошибка чтения не разрешает замену идентичности.

use rand::RngCore;
#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

fn read_key(path: &Path) -> io::Result<[u8; 32]> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000);
    }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Некорректный файл ключа устройства",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Ключ устройства не может быть ссылкой",
            ));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    file.read_exact(&mut *bytes)?;
    Ok(*bytes)
}

pub fn load_or_create_secret(path: &Path) -> io::Result<[u8; 32]> {
    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    match read_key(path) {
        Ok(key) => return Ok(key),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    fs::create_dir_all(dir)?;
    if fs::symlink_metadata(dir)?.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Каталог ключа устройства не может быть ссылкой",
        ));
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng
        .try_fill_bytes(&mut *bytes)
        .map_err(io::Error::other)?;
    let temporary = dir.join(format!(".device-{:032x}.tmp", rand::random::<u128>()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&temporary)?;
    let result = (|| {
        file.write_all(&*bytes)?;
        file.sync_all()?;
        // hard_link публикует готовый файл без перезаписи ключа другого процесса.
        match fs::hard_link(&temporary, path) {
            Ok(()) => {
                #[cfg(unix)]
                File::open(dir)?.sync_all()?;
                Ok(*bytes)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => read_key(path),
            Err(error) => Err(error),
        }
    })();
    drop(file);
    let _ = fs::remove_file(&temporary);
    result
}
