//! Постоянная идентичность клиента хранится в закрытом каталоге.

use aivpn_common::crypto::KeyPair;
use std::fs;
use std::io;
use std::path::Path;

pub(super) fn load_or_create(dir: &Path) -> io::Result<KeyPair> {
    fs::create_dir_all(dir)?;
    if fs::symlink_metadata(dir)?.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Каталог ключа устройства не может быть ссылкой",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    aivpn_common::identity_file::load_or_create_secret(&dir.join("device.key"))
        .map(KeyPair::from_private_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("aivpn-device-{:032x}", rand::random::<u128>()))
    }

    #[test]
    fn concurrent_creation_keeps_one_identity() {
        let dir = test_dir();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let dir = dir.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    load_or_create(&dir).unwrap().export_private_key()
                })
            })
            .collect();
        let keys: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert!(keys.iter().all(|key| key == &keys[0]));
        assert_eq!(load_or_create(&dir).unwrap().export_private_key(), keys[0]);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(dir.join("device.key"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn malformed_existing_key_is_not_replaced() {
        let dir = test_dir();
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("device.key"), b"broken").unwrap();
        assert!(load_or_create(&dir).is_err());
        assert_eq!(fs::read(dir.join("device.key")).unwrap(), b"broken");
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_is_not_followed() {
        let dir = test_dir();
        fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("other.key");
        fs::write(&victim, [4u8; 32]).unwrap();
        std::os::unix::fs::symlink(&victim, dir.join("device.key")).unwrap();
        assert!(load_or_create(&dir).is_err());
        assert_eq!(fs::read(victim).unwrap(), [4u8; 32]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_creation_does_not_return_volatile_key() {
        let path = test_dir();
        fs::write(&path, b"not a directory").unwrap();
        assert!(load_or_create(&path).is_err());
        fs::remove_file(path).unwrap();
    }
}
