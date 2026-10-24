use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub dark_mode: bool,
    pub kill_switch: bool,
    pub adaptive_level: u8,
    pub dns_proxy: String,
    /// Start AIVPN automatically at login via XDG autostart entry.
    #[serde(default)]
    pub autostart: bool,
    /// Preferred mask profile passed via --preferred-mask. "auto" means let the server choose.
    #[serde(default = "default_mask")]
    pub preferred_mask: String,
    /// Comma-separated CIDRs to exclude from the VPN tunnel (split tunnel).
    #[serde(default)]
    pub exclude_routes: String,
    /// Comma-separated CIDRs to route exclusively through the VPN tunnel (split tunnel allowlist).
    #[serde(default)]
    pub include_routes: String,
    /// Enable SOCKS5 proxy mode.
    #[serde(default)]
    pub socks5_enabled: bool,
    /// Address for the SOCKS5 listener (e.g. "127.0.0.1:1080").
    #[serde(default = "default_socks5_addr")]
    pub socks5_addr: String,
    /// UI language: "en" or "ru".
    #[serde(default = "default_lang")]
    pub lang: String,
    /// Advanced/operator: CDN URL for bootstrap descriptor discovery (--bootstrap-cdn-url). Empty means unset.
    #[serde(default = "default_bootstrap_field")]
    pub bootstrap_cdn_url: String,
    /// Advanced/operator: Telegram bot token for bootstrap discovery, authenticated Bot API
    /// (--bootstrap-telegram-token). Empty means unset.
    #[serde(default = "default_bootstrap_field")]
    pub bootstrap_telegram_token: String,
    /// Advanced/operator: Telegram chat/channel ID to filter updates to, optional
    /// (--bootstrap-telegram-chat). Empty means unset (scans all recent updates).
    #[serde(default = "default_bootstrap_field")]
    pub bootstrap_telegram_chat: String,
    /// Advanced/operator: GitHub repo for bootstrap discovery (--bootstrap-github). Empty means unset.
    #[serde(default = "default_bootstrap_field")]
    pub bootstrap_github: String,
    /// Advanced/operator: server signing public key (base64) to verify bootstrap descriptors (--server-signing-key). Empty means unset.
    #[serde(default = "default_bootstrap_field")]
    pub server_signing_key: String,
    /// Request a per-session polymorphic variant of the selected preferred_mask
    /// (--polymorphic-base). Ignored when preferred_mask is "auto".
    #[serde(default)]
    pub polymorphic_mask: bool,
    /// Opt in to sharing blocked-mask feedback with the server (--share-mask-feedback).
    #[serde(default)]
    pub share_mask_feedback: bool,
    /// Opt in to receiving mask hints for the configured region (--receive-mask-hints).
    #[serde(default)]
    pub receive_mask_hints: bool,
    /// ISO 3166-1 alpha-2 region code used for mask hints (--country-code). Empty means unset.
    #[serde(default)]
    pub country_code: String,
}

fn default_lang() -> String {
    "en".to_string()
}

fn default_mask() -> String {
    "auto".to_string()
}

fn default_socks5_addr() -> String {
    "127.0.0.1:1080".to_string()
}

fn default_bootstrap_field() -> String {
    String::new()
}

impl Default for AppSettings {
    fn default() -> Self {
        AppSettings {
            dark_mode: true,
            kill_switch: false,
            adaptive_level: 0,
            dns_proxy: String::new(),
            autostart: false,
            preferred_mask: "auto".to_string(),
            exclude_routes: String::new(),
            include_routes: String::new(),
            socks5_enabled: false,
            socks5_addr: "127.0.0.1:1080".to_string(),
            lang: "en".to_string(),
            bootstrap_cdn_url: String::new(),
            bootstrap_telegram_token: String::new(),
            bootstrap_telegram_chat: String::new(),
            bootstrap_github: String::new(),
            server_signing_key: String::new(),
            polymorphic_mask: false,
            share_mask_feedback: false,
            receive_mask_hints: false,
            country_code: String::new(),
        }
    }
}

impl AppSettings {
    pub fn load() -> Self {
        let path = settings_path();
        if path.exists() {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            Self::default()
        }
    }

    pub fn save(&self) {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let path = settings_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
            // settings.json can hold a real credential (the bootstrap
            // Telegram bot token), so keep the directory owner-only here
            // too — don't rely on key_storage::save() having run first.
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
        let Ok(json) = serde_json::to_string_pretty(self) else {
            return;
        };

        // Write 0600 to a temp file then atomically rename (same pattern as
        // key_storage.rs): a crash mid-write can't corrupt the existing
        // settings and the Telegram token is never world-readable.
        let tmp = path.with_extension("json.tmp");
        let write_result = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .and_then(|mut f| f.write_all(json.as_bytes()).and_then(|_| f.sync_all()));
        match write_result {
            Ok(()) => {
                if let Err(e) = std::fs::rename(&tmp, &path) {
                    eprintln!("aivpn: failed to persist settings: {e}");
                    let _ = std::fs::remove_file(&tmp);
                }
            }
            Err(e) => {
                eprintln!("aivpn: failed to write settings temp file: {e}");
                let _ = std::fs::remove_file(&tmp);
            }
        }
    }
}

fn settings_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("aivpn")
        .join("settings.json")
}

fn autostart_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("autostart").join("aivpn.desktop"))
}

fn desktop_exec_argument(path: &str) -> String {
    let mut quoted = String::from("\"");
    for character in path.chars() {
        match character {
            '\\' | '"' | '$' | '`' => {
                quoted.push('\\');
                quoted.push(character);
            }
            '%' => quoted.push_str("%%"),
            _ => quoted.push(character),
        }
    }
    quoted.push('"');
    quoted
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Write an XDG autostart .desktop entry so AIVPN launches at login.
pub fn write_autostart_entry() {
    let path = match autostart_path() {
        Some(p) => p,
        None => return,
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // When running as an AppImage, current_exe() points inside the ephemeral
    // /tmp/.mount-* squashfs that vanishes on quit, so an autostart entry
    // referencing it would break on the next login. $APPIMAGE holds the
    // stable path to the .AppImage file itself; prefer it when set.
    let exe = std::env::var("APPIMAGE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            std::env::current_exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "aivpn-linux".to_string())
        });
    let exe = desktop_exec_argument(&exe);
    let content = format!(
        "[Desktop Entry]\nType=Application\nExec={exe}\nName=AIVPN\nX-GNOME-Autostart-enabled=true\n"
    );
    let _ = std::fs::write(&path, content);
}

/// Remove the XDG autostart .desktop entry.
pub fn remove_autostart_entry() {
    if let Some(path) = autostart_path() {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autostart_escapes_paths_and_field_codes() {
        assert_eq!(
            desktop_exec_argument("/home/a b/AIVPN.AppImage"),
            "\"/home/a b/AIVPN.AppImage\""
        );
        assert_eq!(
            desktop_exec_argument("/home/50%/AIVPN"),
            "\"/home/50%%/AIVPN\""
        );
        assert_eq!(desktop_exec_argument("a\\b\"$`"), r#""a\\\\b\\"\\$\\`""#);
        assert!(!desktop_exec_argument("a\nb").contains('\n'));
    }
}
