//! Connection key storage
//!
//! Stores keys encrypted at rest via Windows DPAPI (CryptProtectData /
//! CryptUnprotectData).  The encrypted blob is base64-encoded before being
//! written to %LOCALAPPDATA%/AIVPN/keys.json so the file remains valid JSON.
//! Encryption is tied to the current Windows user account — other users
//! (and offline attackers) cannot decrypt the stored connection keys.

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ── DPAPI helpers (Windows-only) ─────────────────────────────────────────────

#[cfg(windows)]
mod dpapi {
    use std::ptr;
    use winapi::um::dpapi::{CryptProtectData, CryptUnprotectData};
    use winapi::um::winbase::LocalFree;
    use winapi::um::wincrypt::DATA_BLOB;

    pub fn encrypt(plaintext: &[u8]) -> Option<Vec<u8>> {
        let mut input = DATA_BLOB {
            cbData: plaintext.len() as u32,
            pbData: plaintext.as_ptr() as *mut u8,
        };
        let mut output = DATA_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };
        let ok = unsafe {
            CryptProtectData(
                &mut input,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                &mut output,
            )
        };
        if ok == 0 || output.pbData.is_null() {
            return None;
        }
        let bytes =
            unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe { LocalFree(output.pbData as _) };
        Some(bytes)
    }

    pub fn decrypt(ciphertext: &[u8]) -> Option<Vec<u8>> {
        let mut input = DATA_BLOB {
            cbData: ciphertext.len() as u32,
            pbData: ciphertext.as_ptr() as *mut u8,
        };
        let mut output = DATA_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };
        let ok = unsafe {
            CryptUnprotectData(
                &mut input,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                &mut output,
            )
        };
        if ok == 0 || output.pbData.is_null() {
            return None;
        }
        let bytes =
            unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe { LocalFree(output.pbData as _) };
        Some(bytes)
    }
}

/// Encrypt a connection-key string for storage.
/// On Windows uses DPAPI; returns Err if DPAPI is unavailable so callers never
/// silently write a plaintext PSK to disk. Non-Windows builds (cargo check only)
/// return the value unchanged.
///
/// `pub(crate)` so `localization.rs` can reuse the same DPAPI-backed
/// protection for the Telegram bootstrap bot token (a real credential that
/// was previously stored in plaintext in settings.json, unlike this key).
pub(crate) fn protect_key(key: &str) -> Result<String, String> {
    #[cfg(windows)]
    {
        return dpapi::encrypt(key.as_bytes())
            .map(|blob| base64::engine::general_purpose::STANDARD.encode(&blob))
            .ok_or_else(|| "DPAPI encryption failed — key not saved".to_string());
    }
    #[cfg(not(windows))]
    Ok(key.to_string())
}

/// Decrypt a stored connection-key string.
/// Returns Ok(plaintext) on DPAPI success, Ok(stored) for legacy plaintext —
/// either a value that never was base64, or a base64-looking plaintext key
/// whose DPAPI decryption failed (old versions stored the bare key payload,
/// which can decode as STANDARD base64 when it contains no '-'/'_'; that must
/// NOT be mistaken for a DPAPI blob and dropped). Err only when the value is
/// neither decryptable nor a parseable connection key — truly corrupt or
/// encrypted under a different user/machine.
///
/// `pub(crate)` — see `protect_key` above.
pub(crate) fn unprotect_key(stored: &str) -> Result<String, String> {
    #[cfg(windows)]
    {
        if let Ok(blob) = base64::engine::general_purpose::STANDARD.decode(stored) {
            // It decoded as base64 → probably a DPAPI blob; on success we're
            // done. A failure does NOT condemn the value (see fn doc) — fall
            // through to the plaintext validation below.
            if let Some(pt) = dpapi::decrypt(&blob).and_then(|pt| String::from_utf8(pt).ok()) {
                return Ok(pt);
            }
        }
    }
    // Legacy plaintext candidate: accept it only if it still parses as a
    // connection key. A genuine DPAPI blob that failed decryption is binary
    // garbage under base64, not key JSON, so it stays Err here and the caller
    // drops it as before.
    if ConnectionKey::from_key_string("", stored).is_some() {
        Ok(stored.to_string())
    } else {
        Err("unreadable stored key (corrupt or from a different user/machine)".to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionKey {
    pub name: String,
    pub key: String,
    #[serde(default)]
    pub server_addr: String,
    #[serde(default)]
    pub vpn_ip: String,
    #[serde(default)]
    pub full_tunnel: bool,
    #[serde(default)]
    pub proxy_listen: Option<String>,
    /// Path to client mTLS cert file. Stored plaintext — only `key` is DPAPI-encrypted.
    #[serde(default)]
    pub mtls_cert_path: Option<String>,
    /// CIDRs to exclude from the VPN tunnel (split-tunnel bypass list).
    #[serde(default)]
    pub exclude_routes: Vec<String>,
    /// CIDRs to route exclusively through the VPN tunnel (split-tunnel allowlist).
    #[serde(default)]
    pub include_routes: Vec<String>,
}

impl ConnectionKey {
    pub fn from_key_string(name: &str, key: &str) -> Option<Self> {
        let payload = key.trim().strip_prefix("aivpn://").unwrap_or(key.trim());
        let json_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload))
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(payload))
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(payload))
            .ok()?;
        let json: serde_json::Value = serde_json::from_slice(&json_bytes).ok()?;
        let server_addr = json["s"].as_str().unwrap_or("").to_string();
        let vpn_ip = json["i"].as_str().unwrap_or("").to_string();

        Some(Self {
            name: name.to_string(),
            key: key.trim().to_string(),
            server_addr,
            vpn_ip,
            full_tunnel: false,
            proxy_listen: None,
            mtls_cert_path: None,
            exclude_routes: Vec::new(),
            include_routes: Vec::new(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyStorage {
    pub keys: Vec<ConnectionKey>,
    #[serde(default)]
    pub selected: Option<usize>,
}

impl KeyStorage {
    pub fn load() -> Self {
        let path = Self::storage_path();
        if path.exists() {
            if let Ok(data) = std::fs::read_to_string(&path) {
                if let Ok(mut storage) = serde_json::from_str::<KeyStorage>(&data) {
                    // Decrypt keys from disk (transparent migration of legacy plaintext).
                    // Track whether any key was stored in plaintext so we can re-encrypt now.
                    let mut needs_save = false;
                    let mut bad_keys: Vec<usize> = Vec::new();
                    for (i, k) in storage.keys.iter_mut().enumerate() {
                        match unprotect_key(&k.key) {
                            Ok(decrypted) => {
                                if decrypted == k.key {
                                    // Legacy plaintext — mark for immediate re-encryption.
                                    needs_save = true;
                                }
                                k.key = decrypted;
                            }
                            Err(e) => {
                                // DPAPI decryption failed — key is corrupted or from a
                                // different user/machine. Skip it to avoid treating the
                                // ciphertext blob as a plaintext connection key.
                                crate::vpn_manager::gui_log(&format!(
                                    "aivpn: skipping corrupt key {:?}: {}",
                                    k.name, e
                                ));
                                bad_keys.push(i);
                            }
                        }
                    }
                    // Remove corrupt keys in reverse order to preserve indices.
                    for i in bad_keys.into_iter().rev() {
                        storage.keys.remove(i);
                        needs_save = true;
                    }
                    // Validate selected index
                    if let Some(idx) = storage.selected {
                        if idx >= storage.keys.len() {
                            storage.selected = None;
                        }
                    }
                    if needs_save {
                        let _ = storage.save();
                    }
                    return storage;
                }
            }
        }
        Self {
            keys: Vec::new(),
            selected: None,
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = Self::storage_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create directory {:?}: {}", parent, e))?;
        }
        let mut encrypted_keys = Vec::with_capacity(self.keys.len());
        for k in &self.keys {
            let mut k2 = k.clone();
            k2.key = protect_key(&k.key)?;
            encrypted_keys.push(k2);
        }
        let on_disk = KeyStorage {
            keys: encrypted_keys,
            selected: self.selected,
        };
        let json = serde_json::to_string_pretty(&on_disk)
            .map_err(|e| format!("Serialization error: {}", e))?;
        // Atomic write: tmp file + rename to avoid corrupt keys.json on crash
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &json).map_err(|e| format!("Cannot write {:?}: {}", tmp, e))?;
        std::fs::rename(&tmp, &path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("Cannot rename {:?} → {:?}: {}", tmp, path, e)
        })
    }

    pub fn add_key(
        &mut self,
        name: &str,
        key: &str,
        full_tunnel: bool,
        proxy_listen: Option<String>,
        mtls_cert_path: Option<String>,
        exclude_routes: Vec<String>,
        include_routes: Vec<String>,
    ) -> Result<(), String> {
        // Validate key format
        let mut ck = ConnectionKey::from_key_string(name, key)
            .ok_or_else(|| "Invalid connection key format".to_string())?;
        ck.full_tunnel = full_tunnel;
        ck.proxy_listen = proxy_listen;
        ck.mtls_cert_path = mtls_cert_path;
        ck.exclude_routes = exclude_routes;
        ck.include_routes = include_routes;

        // Check for duplicates
        if self.keys.iter().any(|k| k.key == ck.key) {
            return Err("This key already exists".to_string());
        }

        let prev_selected = self.selected;
        self.keys.push(ck);
        if self.selected.is_none() {
            self.selected = Some(self.keys.len() - 1);
        }
        if let Err(e) = self.save() {
            // Rollback: disk write failed, undo the in-memory mutation
            self.keys.pop();
            self.selected = prev_selected;
            return Err(e);
        }
        Ok(())
    }

    pub fn update_key(
        &mut self,
        idx: usize,
        name: &str,
        key: &str,
        full_tunnel: bool,
        proxy_listen: Option<String>,
        mtls_cert_path: Option<String>,
        exclude_routes: Vec<String>,
        include_routes: Vec<String>,
    ) -> Result<(), String> {
        if idx >= self.keys.len() {
            return Err("Invalid key index".to_string());
        }
        let mut ck = ConnectionKey::from_key_string(name, key)
            .ok_or_else(|| "Invalid connection key format".to_string())?;
        ck.full_tunnel = full_tunnel;
        ck.proxy_listen = proxy_listen;
        ck.mtls_cert_path = mtls_cert_path;
        ck.exclude_routes = exclude_routes;
        ck.include_routes = include_routes;

        // Reject if the new key string duplicates a different existing profile.
        if self
            .keys
            .iter()
            .enumerate()
            .any(|(i, k)| i != idx && k.key == ck.key)
        {
            return Err("This key already exists".to_string());
        }

        let old = std::mem::replace(&mut self.keys[idx], ck);
        if let Err(e) = self.save() {
            // Rollback: restore old key on disk write failure
            self.keys[idx] = old;
            return Err(e);
        }
        Ok(())
    }

    pub fn remove_key(&mut self, idx: usize) {
        if idx < self.keys.len() {
            let removed = self.keys.remove(idx);
            let old_selected = self.selected;
            match self.selected {
                Some(sel) if sel == idx => {
                    self.selected = if self.keys.is_empty() {
                        None
                    } else {
                        Some(sel.min(self.keys.len() - 1))
                    };
                }
                Some(sel) if sel > idx => {
                    self.selected = Some(sel - 1);
                }
                _ => {}
            }
            if self.save().is_err() {
                // Rollback: restore the key so it doesn't silently reappear on next load
                self.keys.insert(idx, removed);
                self.selected = old_selected;
            }
        }
    }

    pub fn selected_key(&self) -> Option<&ConnectionKey> {
        self.selected.and_then(|idx| self.keys.get(idx))
    }

    fn storage_path() -> PathBuf {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("AIVPN")
            .join("keys.json")
    }
}
