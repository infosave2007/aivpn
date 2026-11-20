//! Настройки работника передаются по проверенному IPC, без пути к пользовательскому файлу.

use serde::{Deserialize, Serialize};
use std::{fmt, io, net::SocketAddr};

mod options;
#[cfg(feature = "local-profile")]
mod pool;
pub use options::{DesktopClientOptions, CLIENT_OPTIONS_FIELD};

pub const MAX_CONNECTION_BYTES: usize = 48 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConnectionDocument(serde_json::Value);

impl fmt::Debug for ConnectionDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConnectionDocument([скрыто])")
    }
}

impl ConnectionDocument {
    /// Вызывается только интерфейсом или CLI до передачи документа службе.
    #[cfg(feature = "local-profile")]
    pub fn with_local_identity(self) -> io::Result<Self> {
        let runtime = aivpn_common::transport::RuntimeConfig::load_default_file(
            aivpn_common::transport::default_config_path(),
        )
        .map_err(io::Error::other)?;
        #[cfg(windows)]
        let variable = "USERPROFILE";
        #[cfg(not(windows))]
        let variable = "HOME";
        let directory = std::env::var_os(variable)
            .map(|home| std::path::PathBuf::from(home).join(".config").join("aivpn"));
        let document = self.with_identity_directory(directory.as_deref())?;
        let mut options = DesktopClientOptions::from_profile(&document.0)?;
        options.runtime = runtime;
        document.with_client_options(&options)
    }

    #[cfg(feature = "local-profile")]
    fn with_identity_directory(self, directory: Option<&std::path::Path>) -> io::Result<Self> {
        use base64::Engine;
        if !self.0.is_object() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut options = DesktopClientOptions::from_profile(&self.0)?;
        if options.device_private_key.is_none() {
            let directory = directory.ok_or_else(|| {
                io::Error::other("Не определен домашний каталог для ключа устройства")
            })?;
            let key = aivpn_common::identity_file::load_or_create_device_secret(directory)?;
            options.device_private_key =
                Some(base64::engine::general_purpose::STANDARD.encode(key));
        }
        options.device_secret()?;
        self.with_client_options(&options)
    }
    pub fn with_client_options(mut self, options: &DesktopClientOptions) -> io::Result<Self> {
        let object = self.0.as_object_mut().ok_or(io::ErrorKind::InvalidInput)?;
        object.insert(CLIENT_OPTIONS_FIELD.into(), serde_json::to_value(options)?);
        if serde_json::to_vec(&self)?.len() > MAX_CONNECTION_BYTES {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(self)
    }
    pub fn from_key(key: &str) -> io::Result<Self> {
        use base64::{engine::general_purpose, Engine};
        let key = key.trim().strip_prefix("aivpn://").unwrap_or(key.trim());
        if key.len() > MAX_CONNECTION_BYTES * 2 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let bytes = [
            general_purpose::URL_SAFE_NO_PAD,
            general_purpose::URL_SAFE,
            general_purpose::STANDARD_NO_PAD,
            general_purpose::STANDARD,
        ]
        .iter()
        .find_map(|engine| engine.decode(key).ok())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Некорректный ключ подключения")
        })?;
        Self::from_json(&bytes)
    }
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub fn registration_key(&self) -> io::Result<String> {
        use sha2::{Digest, Sha256};
        fn ordered(value: &serde_json::Value) -> serde_json::Value {
            match value {
                serde_json::Value::Object(map) => {
                    let mut entries = map.iter().collect::<Vec<_>>();
                    entries.sort_by_key(|(key, _)| *key);
                    serde_json::Value::Object(
                        entries
                            .into_iter()
                            .map(|(key, value)| (key.clone(), ordered(value)))
                            .collect(),
                    )
                }
                serde_json::Value::Array(values) => {
                    serde_json::Value::Array(values.iter().map(ordered).collect())
                }
                value => value.clone(),
            }
        }
        let mut hash = Sha256::new();
        hash.update(b"aivpn-desktop-profile-v1");
        let mut identity = self.0.clone();
        if let Some(object) = identity.as_object_mut() {
            object.remove(CLIENT_OPTIONS_FIELD);
        }
        hash.update(serde_json::to_vec(&ordered(&identity))?);
        Ok(format!("{:x}", hash.finalize()))
    }
    pub fn from_json(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > MAX_CONNECTION_BYTES {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        serde_json::from_slice(bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Некорректные настройки подключения",
            )
        })
    }
}

#[derive(Clone)]
pub struct WorkerConfiguration {
    pub(crate) connection: serde_json::Value,
    pub(crate) peer: Option<SocketAddr>,
    pub(crate) hostname: Option<(String, u16)>,
    #[cfg(feature = "local-profile")]
    pool: Option<pool::Selection>,
}

impl WorkerConfiguration {
    pub fn validate_identity(&self) -> io::Result<()> {
        DesktopClientOptions::from_profile(&self.connection)?
            .device_secret()
            .map(|_| ())
    }
    /// Для самостоятельных стендов, запущенных оператором. Служба этот метод не вызывает.
    #[cfg(feature = "local-profile")]
    pub fn with_local_identity(self) -> io::Result<Self> {
        Self::from_document(&ConnectionDocument(self.connection).with_local_identity()?)
    }
    pub fn from_document(document: &ConnectionDocument) -> io::Result<Self> {
        if !document.0.is_object() || serde_json::to_vec(document)?.len() > MAX_CONNECTION_BYTES {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let address = document.0["s"]
            .as_str()
            .ok_or(io::ErrorKind::InvalidInput)?;
        let (peer, hostname) = parse_endpoint(address)?;
        #[cfg(feature = "local-profile")]
        let pool = pool::Selection::from_profile(&document.0)?;
        Ok(Self {
            connection: document.0.clone(),
            peer,
            hostname,
            #[cfg(feature = "local-profile")]
            pool,
        })
    }

    #[cfg(feature = "local-profile")]
    pub(crate) fn next_attempt(&mut self, excluded: &[String]) -> io::Result<Self> {
        let Some(selection) = &mut self.pool else {
            if self.connection["s"]
                .as_str()
                .is_some_and(|endpoint| excluded.iter().any(|value| value == endpoint))
            {
                return Err(io::ErrorKind::NotConnected.into());
            }
            return Ok(self.clone());
        };
        let endpoint = selection.next(excluded)?;
        let (peer, hostname) = parse_endpoint(&endpoint)?;
        let mut selected = self.clone();
        selected.connection["s"] = endpoint.into();
        selected.peer = peer;
        selected.hostname = hostname;
        Ok(selected)
    }
    pub(crate) fn connected(&mut self) {
        #[cfg(feature = "local-profile")]
        if let Some(pool) = &mut self.pool {
            pool.connected();
        }
    }
    pub(crate) fn finish_attempt(&mut self) {
        #[cfg(feature = "local-profile")]
        if let Some(pool) = &mut self.pool {
            pool.finish();
        }
    }
    pub(crate) fn numeric_peer(&self) -> io::Result<SocketAddr> {
        self.peer
            .ok_or_else(|| io::Error::other("Имя сервера еще не разрешено службой"))
    }
    pub(crate) fn resolved(&self, peer: SocketAddr) -> io::Result<Self> {
        if self
            .hostname
            .as_ref()
            .is_none_or(|(_, port)| *port != peer.port())
            || peer.ip().is_unspecified()
            || peer.ip().is_multicast()
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut resolved = self.clone();
        resolved.connection["s"] = peer.to_string().into();
        resolved.peer = Some(peer);
        resolved.hostname = None;
        Ok(resolved)
    }

    #[cfg(target_os = "linux")]
    pub fn open(path: &std::path::Path) -> io::Result<Self> {
        use std::{
            fs::OpenOptions,
            io::Read,
            os::unix::fs::{MetadataExt, OpenOptionsExt},
        };
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() > MAX_CONNECTION_BYTES as u64
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_CONNECTION_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        Self::from_document(&ConnectionDocument::from_json(&bytes)?)
    }

    #[cfg(target_os = "windows")]
    pub fn open(store: &crate::state::StateDirectory) -> io::Result<Self> {
        let bytes = store
            .load(crate::state::StateFile::Committed)?
            .ok_or(io::ErrorKind::NotFound)?;
        Self::from_document(&ConnectionDocument::from_json(&bytes)?)
    }
}

fn parse_endpoint(address: &str) -> io::Result<(Option<SocketAddr>, Option<(String, u16)>)> {
    Ok(match address.parse::<SocketAddr>() {
        Ok(peer) => {
            if peer.port() == 0 || peer.ip().is_unspecified() || peer.ip().is_multicast() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            (Some(peer), None)
        }
        Err(_) => {
            let (host, port) = address
                .rsplit_once(':')
                .ok_or(io::ErrorKind::InvalidInput)?;
            let port: u16 = port.parse().map_err(|_| io::ErrorKind::InvalidInput)?;
            if port == 0
                || host.len() > 253
                || host.trim_end_matches('.').split('.').any(|label| {
                    label.is_empty()
                        || label.len() > 63
                        || !label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
                })
            {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            (None, Some((host.into(), port)))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_debug_never_prints_profile_secrets() {
        let document =
            ConnectionDocument::from_json(br#"{"s":"192.0.2.1:443","p":"private-test-key"}"#)
                .unwrap();
        assert!(!format!("{document:?}").contains("private-test-key"));
        assert!(WorkerConfiguration::from_document(&document).is_ok());
    }

    #[test]
    fn imported_key_identity_ignores_json_key_order_and_uri_prefix() {
        use base64::{engine::general_purpose, Engine};
        let first = br#"{"s":"192.0.2.1:443","p":"test","n":{"mtu":1280,"prefix":24}}"#;
        let second = br#"{"n":{"prefix":24,"mtu":1280},"p":"test","s":"192.0.2.1:443"}"#;
        let one = ConnectionDocument::from_key(&format!(
            " aivpn://{} ",
            general_purpose::URL_SAFE_NO_PAD.encode(first)
        ))
        .unwrap();
        let two = ConnectionDocument::from_key(&general_purpose::STANDARD.encode(second)).unwrap();
        assert_eq!(
            one.registration_key().unwrap(),
            two.registration_key().unwrap()
        );
        assert!(ConnectionDocument::from_key("not a key").is_err());
        assert!(ConnectionDocument::from_key(&"a".repeat(MAX_CONNECTION_BYTES * 2 + 1)).is_err());
    }

    #[test]
    fn worker_transport_requires_a_bounded_unicast_endpoint() {
        for peer in [
            "0.0.0.0:443",
            "[::]:443",
            "224.0.0.1:443",
            "[ff02::1]:443",
            "192.0.2.1:0",
            "bad host:443",
            "bad..host:443",
            "host:0",
            "host:70000",
            "https://host:443",
        ] {
            let document = ConnectionDocument(serde_json::json!({"s":peer}));
            assert!(
                WorkerConfiguration::from_document(&document).is_err(),
                "{peer}"
            );
        }
        let oversized = ConnectionDocument(
            serde_json::json!({"s":"192.0.2.1:443","p":"x".repeat(MAX_CONNECTION_BYTES)}),
        );
        assert!(WorkerConfiguration::from_document(&oversized).is_err());
        assert!(ConnectionDocument::from_json(&vec![b' '; MAX_CONNECTION_BYTES + 1]).is_err());
    }

    #[test]
    fn hostname_is_resolved_only_in_a_copy_and_keeps_the_server_port() {
        let document = ConnectionDocument(serde_json::json!({"s":"vpn.example.test:443"}));
        let source = WorkerConfiguration::from_document(&document).unwrap();
        assert!(source.numeric_peer().is_err());
        assert_eq!(source.hostname, Some(("vpn.example.test".into(), 443)));
        assert!(source.resolved("192.0.2.1:53".parse().unwrap()).is_err());
        let ready = source.resolved("192.0.2.1:443".parse().unwrap()).unwrap();
        assert_eq!(
            ready.numeric_peer().unwrap(),
            "192.0.2.1:443".parse().unwrap()
        );
        assert_eq!(source.connection["s"], "vpn.example.test:443");
        assert_eq!(document.0["s"], "vpn.example.test:443");
        assert_eq!(ready.connection["s"], "192.0.2.1:443");
    }

    #[test]
    fn changing_local_settings_does_not_register_a_second_vpn_profile() {
        let first = ConnectionDocument(serde_json::json!({"s":"192.0.2.1:443","p":"test"}));
        let options = DesktopClientOptions {
            preferred_mask: Some("quic_https_v2".into()),
            adaptive_level: 2,
            ..Default::default()
        };
        let second = first.clone().with_client_options(&options).unwrap();
        assert_eq!(
            first.registration_key().unwrap(),
            second.registration_key().unwrap()
        );
        assert!(first.0.get(CLIENT_OPTIONS_FIELD).is_none());
        let worker = WorkerConfiguration::from_document(&second).unwrap();
        let actual = DesktopClientOptions::from_profile(&worker.connection).unwrap();
        assert_eq!(actual.preferred_mask, options.preferred_mask);
        assert_eq!(actual.adaptive_level, 2);
    }

    #[test]
    #[cfg(feature = "local-profile")]
    fn frontend_identity_reuses_the_legacy_device_file_and_rejects_corruption() {
        struct Temporary(std::path::PathBuf);
        impl Drop for Temporary {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = Temporary(std::env::temp_dir().join(format!(
            "aivpn-local-identity-{}-{nonce}",
            std::process::id()
        )));
        let old = aivpn_common::identity_file::load_or_create_device_secret(&directory.0).unwrap();
        let document = ConnectionDocument(serde_json::json!({"s":"192.0.2.1:443","p":"test"}));
        let first = document
            .clone()
            .with_identity_directory(Some(&directory.0))
            .unwrap();
        let second = document
            .clone()
            .with_identity_directory(Some(&directory.0))
            .unwrap();
        let one = DesktopClientOptions::from_profile(&first.0).unwrap();
        let two = DesktopClientOptions::from_profile(&second.0).unwrap();
        use base64::Engine;
        let expected = base64::engine::general_purpose::STANDARD.encode(old);
        assert!(one.device_private_key.as_deref() == Some(expected.as_str()));
        assert!(one.device_private_key == two.device_private_key);
        assert!(document.0.get(CLIENT_OPTIONS_FIELD).is_none());
        assert!(first.clone().with_identity_directory(None).is_ok());
        assert_eq!(
            document.registration_key().unwrap(),
            first.registration_key().unwrap()
        );
        std::fs::write(directory.0.join("device.key"), b"broken").unwrap();
        assert!(document
            .with_identity_directory(Some(&directory.0))
            .is_err());
        assert!(std::fs::read(directory.0.join("device.key")).unwrap() == b"broken");
    }

    #[test]
    fn desktop_registration_key_is_accepted_and_idempotent_in_real_catalog() {
        use crate::policy::{Authority, Owner, Platform, ProfileCatalog};
        let document = ConnectionDocument(serde_json::json!({"s":"192.0.2.1:443","p":"test"}));
        let key = document.registration_key().unwrap();
        let authority = Authority {
            user: Owner::LinuxUser { uid: 1000 },
            machine_admin: false,
        };
        let mut catalog = ProfileCatalog::new(Platform::Linux, [1; 16]);
        let first = catalog
            .register_stable(&authority, authority.user.clone(), &key, Vec::new())
            .unwrap();
        let second = catalog
            .register_stable(&authority, authority.user.clone(), &key, Vec::new())
            .unwrap();
        assert_eq!(first, second);
    }
}
