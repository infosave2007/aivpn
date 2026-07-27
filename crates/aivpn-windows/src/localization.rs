//! Localization — English/Russian
//!
//! App settings (language + theme) are persisted together in
//! %LOCALAPPDATA%\AIVPN\settings.json. Legacy lang.txt is migrated on first load.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    En,
    Ru,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    #[serde(default = "default_lang")]
    pub lang: Lang,
    #[serde(default = "default_dark")]
    pub dark_mode: bool,
    #[serde(default)]
    pub kill_switch: bool,
    #[serde(default)]
    pub adaptive_level: u8,
    #[serde(default)]
    pub dns_proxy: String,
    #[serde(default = "default_preferred_mask")]
    pub preferred_mask: String,
    #[serde(default)]
    pub connect_on_startup: bool,
    // Advanced/operator bootstrap discovery — lets a client with no working
    // aivpn:// key yet discover a server/mask via signed multi-channel fallback.
    #[serde(default)]
    pub bootstrap_cdn_url: String,
    #[serde(default)]
    pub bootstrap_telegram_token: String,
    #[serde(default)]
    pub bootstrap_telegram_chat: String,
    #[serde(default)]
    pub bootstrap_github: String,
    #[serde(default)]
    pub server_signing_key: String,
    // Polymorphic per-session mask variant (§3). Takes precedence over
    // preferred_mask when enabled and preferred_mask is a concrete preset.
    #[serde(default)]
    pub polymorphic_mask: bool,
    // Crowdsourced mask feedback opt-ins (§2).
    #[serde(default)]
    pub share_mask_feedback: bool,
    #[serde(default)]
    pub receive_mask_hints: bool,
    #[serde(default)]
    pub country_code: String,
}

fn default_lang() -> Lang {
    Lang::En
}
fn default_dark() -> bool {
    true
}
fn default_preferred_mask() -> String {
    "auto".to_string()
}

fn settings_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_default()
        .join("AIVPN")
        .join("settings.json")
}

impl AppSettings {
    pub fn load() -> Self {
        let path = settings_path();
        if path.exists() {
            if let Ok(data) = std::fs::read_to_string(&path) {
                if let Ok(mut s) = serde_json::from_str::<AppSettings>(&data) {
                    // MEDIUM: the Telegram bootstrap bot token is a real credential
                    // (grants control of the bootstrap-distribution bot) that used to
                    // be stored in plaintext here, unlike the connection key — which
                    // is DPAPI-encrypted in keys.json. Decrypt it the same way,
                    // transparently migrating any legacy-plaintext value (mirrors
                    // KeyStorage::load()'s handling of legacy plaintext keys below).
                    let mut needs_save = false;
                    if !s.bootstrap_telegram_token.is_empty() {
                        match crate::key_storage::unprotect_key(&s.bootstrap_telegram_token) {
                            Ok(decrypted) => {
                                if decrypted == s.bootstrap_telegram_token {
                                    // Didn't change → base64 decode failed → legacy
                                    // plaintext. Re-encrypt on the immediate save below.
                                    needs_save = true;
                                } else {
                                    s.bootstrap_telegram_token = decrypted;
                                }
                            }
                            Err(e) => {
                                // Corrupted or from a different user/machine — drop it
                                // rather than risk treating ciphertext as a live token,
                                // same treatment KeyStorage gives an undecryptable key.
                                crate::vpn_manager::gui_log(&format!(
                                    "aivpn: dropping corrupt bootstrap_telegram_token: {e}"
                                ));
                                s.bootstrap_telegram_token = String::new();
                                needs_save = true;
                            }
                        }
                    }
                    if needs_save {
                        s.save();
                    }
                    return s;
                }
            }
        }
        // Migrate from legacy lang.txt
        let lang_txt = dirs::data_local_dir()
            .unwrap_or_default()
            .join("AIVPN")
            .join("lang.txt");
        let lang = if let Ok(v) = std::fs::read_to_string(lang_txt) {
            match v.trim() {
                "ru" => Lang::Ru,
                _ => Lang::En,
            }
        } else {
            Lang::En
        };
        AppSettings {
            lang,
            dark_mode: true,
            kill_switch: false,
            adaptive_level: 0,
            dns_proxy: String::new(),
            preferred_mask: "auto".to_string(),
            connect_on_startup: false,
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

    pub fn save(&self) {
        let path = settings_path();
        if let Some(p) = path.parent() {
            let _ = std::fs::create_dir_all(p);
        }
        // Encrypt the Telegram bootstrap token before it touches disk — build a
        // disk-only copy rather than mutating `self`, so the in-memory value the
        // rest of the app uses (e.g. passed to aivpn-client.exe via env var)
        // stays plaintext. Best-effort: if DPAPI is ever unavailable, fall back
        // to writing it in plaintext (this field's pre-existing behavior) rather
        // than losing every other setting sharing this file.
        let mut on_disk = self.clone();
        if !on_disk.bootstrap_telegram_token.is_empty() {
            match crate::key_storage::protect_key(&on_disk.bootstrap_telegram_token) {
                Ok(encrypted) => on_disk.bootstrap_telegram_token = encrypted,
                Err(e) => {
                    crate::vpn_manager::gui_log(&format!(
                        "aivpn: bootstrap_telegram_token DPAPI encryption failed, saving plaintext: {e}"
                    ));
                }
            }
        }
        let Ok(json) = serde_json::to_string_pretty(&on_disk) else {
            return;
        };
        // Atomic write: write to .tmp then rename to prevent corrupt settings.json on crash
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, &json).is_ok() {
            if let Err(e) = std::fs::rename(&tmp, &path) {
                crate::vpn_manager::gui_log(&format!(
                    "AppSettings::save rename {tmp:?} → {path:?}: {e}"
                ));
                let _ = std::fs::remove_file(&tmp);
            }
        }
    }
}

/// Load theme preference (defaults to dark).
pub fn load_theme() -> bool {
    AppSettings::load().dark_mode
}

/// Persist theme preference alongside language setting.
pub fn save_theme(dark: bool) {
    let mut s = AppSettings::load();
    s.dark_mode = dark;
    s.save();
}

impl Lang {
    pub fn load() -> Self {
        AppSettings::load().lang
    }

    pub fn save(&self) {
        let mut s = AppSettings::load();
        s.lang = *self;
        s.save();
    }

    pub fn toggle(&mut self) {
        *self = match self {
            Lang::En => Lang::Ru,
            Lang::Ru => Lang::En,
        };
        self.save();
    }

    pub fn label(&self) -> &'static str {
        match self {
            Lang::En => "EN",
            Lang::Ru => "RU",
        }
    }
}

/// Translate a key to current language
pub fn t(lang: Lang, key: &str) -> &'static str {
    match (lang, key) {
        // Status
        (Lang::En, "status") => "Status",
        (Lang::Ru, "status") => "Статус",
        (Lang::En, "connected") => "Connected",
        (Lang::Ru, "connected") => "Подключено",
        (Lang::En, "disconnected") => "Disconnected",
        (Lang::Ru, "disconnected") => "Отключено",
        (Lang::En, "connecting") => "Connecting...",
        (Lang::Ru, "connecting") => "Подключение...",
        (Lang::En, "disconnecting") => "Disconnecting...",
        (Lang::Ru, "disconnecting") => "Отключение...",

        // Buttons
        (Lang::En, "connect") => "Connect",
        (Lang::Ru, "connect") => "Подключить",
        (Lang::En, "disconnect") => "Disconnect",
        (Lang::Ru, "disconnect") => "Отключить",

        // Keys
        (Lang::En, "keys") => "Connection Keys",
        (Lang::Ru, "keys") => "Ключи подключения",
        (Lang::En, "copy") => "Copy",
        (Lang::Ru, "copy") => "Копировать",
        (Lang::En, "add_key") => "Add Key",
        (Lang::Ru, "add_key") => "Добавить ключ",
        (Lang::En, "key_name") => "Name",
        (Lang::Ru, "key_name") => "Название",
        (Lang::En, "key_value") => "Key (aivpn://...)",
        (Lang::Ru, "key_value") => "Ключ (aivpn://...)",
        (Lang::En, "save") => "Save",
        (Lang::Ru, "save") => "Сохранить",
        (Lang::En, "cancel") => "Cancel",
        (Lang::Ru, "cancel") => "Отмена",
        (Lang::En, "delete") => "Delete",
        (Lang::Ru, "delete") => "Удалить",
        (Lang::En, "edit") => "Edit",
        (Lang::Ru, "edit") => "Изм.",
        (Lang::En, "no_keys") => "No keys added",
        (Lang::Ru, "no_keys") => "Ключи не добавлены",

        // Traffic
        (Lang::En, "traffic") => "Traffic",
        (Lang::Ru, "traffic") => "Трафик",
        (Lang::En, "downloaded") => "Downloaded",
        (Lang::Ru, "downloaded") => "Получено",
        (Lang::En, "uploaded") => "Uploaded",
        (Lang::Ru, "uploaded") => "Отправлено",

        // Options
        (Lang::En, "full_tunnel") => "Route all traffic through VPN",
        (Lang::Ru, "full_tunnel") => "Весь трафик через VPN",
        (Lang::En, "proxy_mode") => "Proxy mode (no admin rights)",
        (Lang::Ru, "proxy_mode") => "Прокси-режим (без прав адм.)",
        (Lang::En, "proxy_addr") => "Listen address",
        (Lang::Ru, "proxy_addr") => "Адрес прослушивания",
        (Lang::En, "exclude_routes") => "Exclude routes (one CIDR per line)",
        (Lang::Ru, "exclude_routes") => "Исключить маршруты (по одному CIDR)",
        (Lang::En, "exclude_routes_hint") => "e.g. 192.168.1.0/24",
        (Lang::Ru, "exclude_routes_hint") => "напр. 192.168.1.0/24",
        (Lang::En, "include_routes") => "Include routes only (one CIDR per line)",
        (Lang::Ru, "include_routes") => "Только эти маршруты (по одному CIDR)",
        (Lang::En, "include_routes_hint") => "e.g. 10.0.0.0/8 — leave empty to route everything",
        (Lang::Ru, "include_routes_hint") => "напр. 10.0.0.0/8 — оставьте пустым, чтобы маршрутизировать всё",

        // Misc
        (Lang::En, "show") => "Show",
        (Lang::Ru, "show") => "Показать",
        (Lang::En, "quit") => "Quit",
        (Lang::Ru, "quit") => "Выход",
        (Lang::En, "version") => "Version",
        (Lang::Ru, "version") => "Версия",
        (Lang::En, "no_key_selected") => "Select a key first",
        (Lang::Ru, "no_key_selected") => "Сначала выберите ключ",
        (Lang::En, "client_not_found") => "Client binary not found",
        (Lang::Ru, "client_not_found") => "Клиент не найден",

        // Recording
        (Lang::En, "record_new_mask") => "Record New Mask",
        (Lang::Ru, "record_new_mask") => "Записать новую маску",
        (Lang::En, "record_service_name") => "Service name",
        (Lang::Ru, "record_service_name") => "Имя сервиса",
        (Lang::En, "stop_recording") => "Stop Recording",
        (Lang::Ru, "stop_recording") => "Остановить запись",
        (Lang::En, "recording_ready") => "Ready to record",
        (Lang::Ru, "recording_ready") => "Готово к записи",
        (Lang::En, "recording_starting") => "Starting recording...",
        (Lang::Ru, "recording_starting") => "Запуск записи...",
        (Lang::En, "recording_active") => "Recording in progress — use the service normally",
        (Lang::Ru, "recording_active") => "Запись идёт — используйте сервис",
        (Lang::En, "recording_stopping") => "Stopping recording...",
        (Lang::Ru, "recording_stopping") => "Остановка записи...",
        (Lang::En, "recording_analyzing") => "Server analyzing traffic...",
        (Lang::Ru, "recording_analyzing") => "Сервер анализирует трафик...",
        (Lang::En, "recording_success") => "Mask recorded",
        (Lang::Ru, "recording_success") => "Маска записана",
        (Lang::En, "recording_failed") => "Recording failed",
        (Lang::Ru, "recording_failed") => "Запись не удалась",
        (Lang::En, "recording_self_test_failed") => "Self-test failed",
        (Lang::Ru, "recording_self_test_failed") => "Самотест не пройден",
        (Lang::En, "dismiss") => "Dismiss",
        (Lang::Ru, "dismiss") => "Закрыть",

        // Kill-switch
        (Lang::En, "kill_switch") => "Kill Switch (block traffic if VPN drops)",
        (Lang::Ru, "kill_switch") => "Kill Switch (блок трафика при разрыве VPN)",

        // DNS proxy
        (Lang::En, "dns_proxy") => "DNS Proxy (leave empty to disable)",
        (Lang::Ru, "dns_proxy") => "DNS-прокси (пусто — отключено)",

        // Adaptive / diagnostics
        (Lang::En, "adaptive_mode") => "Adaptive Mode",
        (Lang::Ru, "adaptive_mode") => "Адаптивный режим",
        (Lang::En, "adaptive_hint") => "Auto: server picks best. Light: basic mimicry, 15s keepalive. Aggressive: HTTPS/QUIC mimicry, 8s keepalive. Satellite: max mimicry, high-latency optimized.",
        (Lang::Ru, "adaptive_hint") => "Auto: сервер выбирает. Light: базовая маскировка, 15с. Aggressive: HTTPS/QUIC, 8с. Satellite: максимум, для высоких задержек.",
        (Lang::En, "mask_hint") => "Traffic camouflage — auto picks the best profile",
        (Lang::Ru, "mask_hint") => "Маскировка трафика — auto выбирает лучший профиль",
        (Lang::En, "dns_hint") => "Route DNS through the tunnel to prevent leaks",
        (Lang::Ru, "dns_hint") => "Направить DNS через туннель для защиты от утечек",
        (Lang::En, "startup_hint") => "Launch VPN automatically when Windows starts",
        (Lang::Ru, "startup_hint") => "Автозапуск VPN при старте Windows",

        // No-traffic warning
        (Lang::En, "no_traffic_warn") => {
            "Tunnel up, no traffic. Check aivpn-client.exe and server."
        }
        (Lang::Ru, "no_traffic_warn") => {
            "Туннель активен, трафика нет. Проверьте aivpn-client.exe и сервер."
        }

        // Assigned VPN IP (HIGH #2, client parity): live value from the
        // client's traffic.stats `ip:` field, updated on a server pool
        // re-home — not the connection key's static one-time-parsed IP.
        (Lang::En, "vpn_ip_label") => "IP",
        (Lang::Ru, "vpn_ip_label") => "IP",

        // 3c: bootstrap-fallback indicator — live value from the client's
        // traffic.stats `fallback:` key (this GUI's child stdout is piped to
        // Stdio::null(), so unlike Linux it can't read the client's
        // "AIVPN-STATUS bootstrap-fallback" stdout line directly).
        (Lang::En, "bootstrap_fallback_label") => "Using built-in mask (fallback)",
        (Lang::Ru, "bootstrap_fallback_label") => "Встроенная маска (аварийный режим)",

        // Tray connect/disconnect
        (Lang::En, "tray_connect") => "Connect",
        (Lang::Ru, "tray_connect") => "Подключить",
        (Lang::En, "tray_disconnect") => "Disconnect",
        (Lang::Ru, "tray_disconnect") => "Отключить",

        // Mask profile
        (Lang::En, "mask_profile") => "Mask Profile",
        (Lang::Ru, "mask_profile") => "Профиль маски",

        // Autostart
        (Lang::En, "connect_on_startup") => "Connect on Windows startup",
        (Lang::Ru, "connect_on_startup") => "Запускать при старте Windows",

        // mTLS certificate
        (Lang::En, "mtls_cert_path") => "mTLS Certificate path (optional)",
        (Lang::Ru, "mtls_cert_path") => "Путь к mTLS-сертификату (необязательно)",
        (Lang::En, "mtls_cert_hint") => "C:\\path\\to\\cert.pem",
        (Lang::Ru, "mtls_cert_hint") => "C:\\путь\\к\\cert.pem",

        // Diagnostics / benchmark
        (Lang::En, "run_benchmark") => "Run Benchmark",
        (Lang::Ru, "run_benchmark") => "Тест скорости",
        (Lang::En, "bench_running") => "Running...",
        (Lang::Ru, "bench_running") => "Выполняется...",

        // Bootstrap descriptor discovery (advanced/operator use)
        (Lang::En, "bootstrap_section") => "Bootstrap discovery (advanced)",
        (Lang::Ru, "bootstrap_section") => "Обнаружение сервера (доп.)",
        (Lang::En, "bootstrap_hint") => "For operators only. Finds a server/mask via signed CDN/Telegram/GitHub channels when you don't have a working aivpn:// key yet.",
        (Lang::Ru, "bootstrap_hint") => "Только для операторов. Поиск сервера/маски через подписанные каналы CDN/Telegram/GitHub, если рабочего ключа aivpn:// ещё нет.",
        (Lang::En, "bootstrap_cdn_url") => "CDN bootstrap URL",
        (Lang::Ru, "bootstrap_cdn_url") => "CDN URL для bootstrap",
        (Lang::En, "bootstrap_telegram_token") => "Telegram bootstrap bot token",
        (Lang::Ru, "bootstrap_telegram_token") => "Токен Telegram-бота для bootstrap",
        (Lang::En, "bootstrap_telegram_chat") => "Telegram bootstrap chat/channel ID (optional)",
        (Lang::Ru, "bootstrap_telegram_chat") => "ID чата/канала Telegram для bootstrap (необязательно)",
        (Lang::En, "bootstrap_github") => "GitHub bootstrap repo (owner/repo)",
        (Lang::Ru, "bootstrap_github") => "GitHub-репозиторий для bootstrap (owner/repo)",
        (Lang::En, "server_signing_key") => "Server signing public key (base64)",
        (Lang::Ru, "server_signing_key") => "Публичный ключ подписи сервера (base64)",

        // Polymorphic per-session mask variant
        (Lang::En, "polymorphic_mask") => "Polymorphic (per-session unique)",
        (Lang::Ru, "polymorphic_mask") => "Полиморфная (уникальна для сессии)",
        (Lang::En, "polymorphic_mask_hint") => {
            "Requests a unique per-session variant of the selected mask preset"
        }
        (Lang::Ru, "polymorphic_mask_hint") => {
            "Запрашивает уникальный для сессии вариант выбранного профиля маски"
        }

        // Crowdsourced mask feedback (opt-in)
        (Lang::En, "mask_feedback_section") => "Crowdsourced mask feedback (optional)",
        (Lang::Ru, "mask_feedback_section") => "Общая статистика по маскам (необязательно)",
        (Lang::En, "mask_feedback_hint") => {
            "Helps everyone pick working masks faster. No fine-grained location ever leaves the client."
        }
        (Lang::Ru, "mask_feedback_hint") => {
            "Помогает всем быстрее находить рабочие маски. Точное местоположение никогда не покидает клиент."
        }
        (Lang::En, "share_mask_feedback") => "Share blocked-mask feedback",
        (Lang::Ru, "share_mask_feedback") => "Делиться данными о заблокированных масках",
        (Lang::En, "receive_mask_hints") => "Receive mask hints for my region",
        (Lang::Ru, "receive_mask_hints") => "Получать подсказки по маскам для моего региона",
        (Lang::En, "country_code") => "Country code (ISO 3166-1 alpha-2, e.g. DE)",
        (Lang::Ru, "country_code") => "Код страны (ISO 3166-1 alpha-2, напр. DE)",

        // Admin panel (P3.4) — in-tunnel client management, Admin role only
        (Lang::En, "admin_panel") => "Admin — Clients",
        (Lang::Ru, "admin_panel") => "Админ — Клиенты",
        (Lang::En, "admin_refresh") => "Refresh",
        (Lang::Ru, "admin_refresh") => "Обновить",
        (Lang::En, "admin_loading") => "Loading…",
        (Lang::Ru, "admin_loading") => "Загрузка…",
        (Lang::En, "admin_no_clients") => "No clients registered",
        (Lang::Ru, "admin_no_clients") => "Клиенты не зарегистрированы",
        (Lang::En, "admin_one_time_badge") => "one-time",
        (Lang::Ru, "admin_one_time_badge") => "разовый",
        (Lang::En, "admin_expires") => "Expires",
        (Lang::Ru, "admin_expires") => "Истекает",
        (Lang::En, "admin_key_qr") => "Key / QR",
        (Lang::Ru, "admin_key_qr") => "Ключ / QR",
        (Lang::En, "admin_reset_device") => "Reset device",
        (Lang::Ru, "admin_reset_device") => "Сбросить устройство",
        (Lang::En, "admin_revoke") => "Revoke",
        (Lang::Ru, "admin_revoke") => "Отозвать",
        (Lang::En, "admin_add_client") => "Add client",
        (Lang::Ru, "admin_add_client") => "Добавить клиента",
        (Lang::En, "admin_one_time") => "One-time enrollment (bind first connecting device)",
        (Lang::Ru, "admin_one_time") => {
            "Разовая привязка (первое подключённое устройство)"
        }
        (Lang::En, "admin_expiry_hint") => "Expiry (RFC3339, optional)",
        (Lang::Ru, "admin_expiry_hint") => "Срок действия (RFC3339, необязательно)",
        (Lang::En, "admin_enabled") => "Enabled",
        (Lang::Ru, "admin_enabled") => "Включён",
        (Lang::En, "admin_status_audit") => "Server status & audit log",
        (Lang::Ru, "admin_status_audit") => "Статус сервера и журнал аудита",
        (Lang::En, "admin_status_clients") => "Clients enabled/total",
        (Lang::Ru, "admin_status_clients") => "Клиентов включено/всего",
        (Lang::En, "admin_status_kernel") => "Kernel module",
        (Lang::Ru, "admin_status_kernel") => "Kernel-модуль",
        (Lang::En, "admin_save_key_file") => "Save key to file",
        (Lang::Ru, "admin_save_key_file") => "Сохранить ключ в файл",
        (Lang::En, "admin_show_qr") => "Show QR",
        (Lang::Ru, "admin_show_qr") => "Показать QR",
        (Lang::En, "admin_save_qr_file") => "Save QR to file",
        (Lang::Ru, "admin_save_qr_file") => "Сохранить QR в файл",
        (Lang::En, "admin_saved_to") => "Saved to",
        (Lang::Ru, "admin_saved_to") => "Сохранено в",
        (Lang::En, "admin_revoke_confirm_title") => "Revoke client?",
        (Lang::Ru, "admin_revoke_confirm_title") => "Отозвать клиента?",
        (Lang::En, "admin_revoke_confirm_body") => "Permanently revoke and disconnect",
        (Lang::Ru, "admin_revoke_confirm_body") => "Безвозвратно отозвать и отключить",
        (Lang::En, "admin_revoke_confirm_warn") => {
            "This cannot be undone. The client's key stops working immediately."
        }
        (Lang::Ru, "admin_revoke_confirm_warn") => {
            "Это необратимо. Ключ клиента перестанет работать немедленно."
        }

        // Per-client exit node (B3) — Admin edit, shown to Viewer read-only
        (Lang::En, "admin_exit_node") => "Exit node",
        (Lang::Ru, "admin_exit_node") => "Узел выхода",
        (Lang::En, "admin_exit_node_hint") => "Exit node (optional, host:port — empty = global default)",
        (Lang::Ru, "admin_exit_node_hint") => {
            "Узел выхода (необязательно, host:port — пусто = глобальный по умолчанию)"
        }

        // Pool topology view (B3) — Viewer + Admin
        (Lang::En, "admin_pool_section") => "Pool topology",
        (Lang::Ru, "admin_pool_section") => "Топология пула",
        (Lang::En, "admin_pool_transport") => "Transport",
        (Lang::Ru, "admin_pool_transport") => "Транспорт",
        (Lang::En, "admin_pool_connected") => "Connected",
        (Lang::Ru, "admin_pool_connected") => "Подключено",
        (Lang::En, "admin_pool_converged") => "Converged",
        (Lang::Ru, "admin_pool_converged") => "Синхронизировано",
        (Lang::En, "admin_pool_no_nodes") => "No pool nodes",
        (Lang::Ru, "admin_pool_no_nodes") => "Узлы пула отсутствуют",
        (Lang::En, "admin_pool_verified") => "verified",
        (Lang::Ru, "admin_pool_verified") => "подтверждён",
        (Lang::En, "admin_pool_revoked") => "revoked",
        (Lang::Ru, "admin_pool_revoked") => "отозван",
        (Lang::En, "admin_pool_last_seen") => "Last seen",
        (Lang::Ru, "admin_pool_last_seen") => "Последний раз в сети",
        (Lang::En, "admin_pool_partition_conflict") => {
            "⚠ Partition conflict: a peer claims the same VPN-IP partition as this node"
        }
        (Lang::Ru, "admin_pool_partition_conflict") => {
            "⚠ Конфликт партиции: пир заявляет ту же партицию VPN-IP, что и этот узел"
        }
        (Lang::En, "admin_pool_subnet_mismatch") => {
            "⚠ Subnet mismatch: a peer disagrees on the VPN subnet"
        }
        (Lang::Ru, "admin_pool_subnet_mismatch") => {
            "⚠ Несовпадение подсети: пир не согласен с VPN-подсетью"
        }

        // Default fallback
        (_, _) => "???",
    }
}
