use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// On-disk format — wraps keys + selected index.
/// Loading falls back to the legacy bare-array format for compatibility.
#[derive(Debug, Serialize, Deserialize)]
struct StoredData {
    keys: Vec<ConnectionKey>,
    #[serde(default)]
    selected: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConnectionKey {
    pub name: String,
    pub key: String,
    pub server_addr: String,
    pub vpn_ip: String,
    pub full_tunnel: bool,
    pub proxy_listen: Option<String>,
    /// Path to a client mTLS certificate file (raw binary or base64-encoded).
    /// Passed to the client subprocess via --mtls-cert PATH.
    #[serde(default)]
    pub mtls_cert: Option<String>,
    pub exclude_routes: Vec<String>,
}

impl ConnectionKey {
    pub fn from_key_string(
        name: impl Into<String>,
        key: impl Into<String>,
    ) -> Result<Self, String> {
        let key = key.into();
        let stripped = key.trim_start_matches("aivpn://");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(stripped)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(stripped))
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(stripped))
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(stripped))
            .map_err(|e| format!("Base64 decode error: {e}"))?;
        let json: serde_json::Value =
            serde_json::from_slice(&decoded).map_err(|e| format!("JSON parse error: {e}"))?;
        // json["s"] is stored verbatim — no port splitting — so IPv6 addresses
        // like "[::1]:443" are preserved correctly.
        let server_addr = json
            .get("s")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let vpn_ip = json
            .get("i")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        Ok(ConnectionKey {
            name: name.into(),
            key,
            server_addr,
            vpn_ip,
            full_tunnel: false,
            proxy_listen: None,
            mtls_cert: None,
            exclude_routes: Vec::new(),
        })
    }
}

#[derive(Debug, Default)]
pub struct KeyStorage {
    pub keys: Vec<ConnectionKey>,
    pub selected: Option<usize>,
    path: PathBuf,
}

impl KeyStorage {
    pub fn load() -> Self {
        let path = storage_path();
        let (keys, selected) = if path.exists() {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| {
                    // Try new envelope format first; fall back to legacy bare array.
                    serde_json::from_str::<StoredData>(&s)
                        .map(|d| {
                            // Validate saved selected index.
                            let sel = d.selected.filter(|&i| i < d.keys.len());
                            (d.keys, sel)
                        })
                        .or_else(|_| {
                            serde_json::from_str::<Vec<ConnectionKey>>(&s).map(|keys| {
                                let sel = if keys.is_empty() { None } else { Some(0) };
                                (keys, sel)
                            })
                        })
                        .ok()
                })
                .unwrap_or_default()
        } else {
            (Vec::new(), None)
        };
        KeyStorage {
            keys,
            selected,
            path,
        }
    }

    pub fn save(&self) {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
            // The keys file holds the full aivpn:// connection key (incl. the
            // PSK) in plaintext; keep the directory owner-only too.
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
        let data = StoredData {
            keys: self.keys.clone(),
            selected: self.selected,
        };
        let Ok(json) = serde_json::to_string_pretty(&data) else {
            return;
        };

        // Write 0600 to a temp file then atomically rename, so a crash mid-write
        // can't corrupt the existing keys and the PSK is never world-readable.
        let tmp = self.path.with_extension("json.tmp");
        let write_result = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .and_then(|mut f| f.write_all(json.as_bytes()).and_then(|_| f.sync_all()));
        match write_result {
            Ok(()) => {
                if let Err(e) = std::fs::rename(&tmp, &self.path) {
                    eprintln!("aivpn: failed to persist keys: {e}");
                    let _ = std::fs::remove_file(&tmp);
                }
            }
            Err(e) => {
                eprintln!("aivpn: failed to write keys temp file: {e}");
                let _ = std::fs::remove_file(&tmp);
            }
        }
    }

    pub fn add(&mut self, key: ConnectionKey) -> Result<(), String> {
        if self.keys.iter().any(|k| k.key == key.key) {
            return Err("Key already exists".to_string());
        }
        let first = self.keys.is_empty();
        self.keys.push(key);
        if first {
            self.selected = Some(0);
        }
        self.save();
        Ok(())
    }

    pub fn remove(&mut self, idx: usize) {
        if idx >= self.keys.len() {
            return;
        }
        self.keys.remove(idx);
        // Keep the selection pointing at the SAME profile: indices above the
        // removed slot shift down by one; removing the selected profile
        // falls back to the nearest remaining one.
        self.selected = match self.selected {
            Some(s) if s > idx => Some(s - 1),
            Some(s) if s == idx && self.keys.is_empty() => None,
            Some(s) if s == idx => Some(s.min(self.keys.len() - 1)),
            keep => keep,
        };
        self.save();
    }

    pub fn update(&mut self, idx: usize, key: ConnectionKey) {
        if idx < self.keys.len() {
            self.keys[idx] = key;
            self.save();
        }
    }

    pub fn selected_key(&self) -> Option<&ConnectionKey> {
        self.selected.and_then(|i| self.keys.get(i))
    }
}

fn storage_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("aivpn")
        .join("keys.json")
}
