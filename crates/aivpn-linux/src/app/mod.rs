mod i18n;
mod messages;
mod privilege;
mod views;

use i18n::t;
use iced::futures::SinkExt;
use iced::widget::{
    button, checkbox, container, horizontal_rule, image, pick_list, scrollable, text, text_input,
    Space,
};
use iced::{Alignment, Background, Border, Color, Element, Length, Subscription, Task, Theme};
pub use messages::Message;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::admin::{
    self, AuditLogView, ClientRecord, ConfigSetting, EditClientArgs, NewClientArgs, PoolHealth,
    PoolNode,
};
use crate::install_wizard::{
    self, BinarySourceOpt, InstallAuth, InstallLine, InstallModeOpt, InstallTarget,
};
use crate::key_storage::{ConnectionKey, KeyStorage};
use crate::settings::{remove_autostart_entry, write_autostart_entry, AppSettings};
use crate::vpn_manager::{
    self, extract_server_addr, find_client_binary, format_bytes, read_recording_status,
    read_traffic_stats, RecordingSnapshot, TrafficStats, VpnStatus,
};
#[allow(unused_imports)]
use notify_rust;

const MAX_LOG_LINES: usize = 200;

/// G-A3: client-side estimate of the server's `PENDING_CONFIG_TIMEOUT`
/// (`pending_config.rs`, ~120s) — the countdown shown next to the "Confirm"
/// button in Server Settings. Deliberately approximate: this GUI never
/// learns the server's real deadline over the wire (`config/apply`'s
/// response carries only the token), so a `Confirm` sent right as this
/// client-side timer hits 0 may still occasionally race an
/// already-rolled-back server — surfaced as a normal `confirm_config`
/// error, not a hang, since the server is the sole source of truth for the
/// actual expiry.
const SERVER_SETTINGS_CONFIRM_WINDOW_SECS: u32 = 120;

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.as_str().starts_with('[') {
                chars.next();
                for ch in chars.by_ref() {
                    // CSI sequences are terminated by any final byte in
                    // 0x40-0x7E, not just letters (e.g. `~` ends cursor/key
                    // sequences, `@` is ICH).
                    if ('\x40'..='\x7e').contains(&ch) {
                        break;
                    }
                }
            } else {
                chars.next();
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Best-effort path to a client binary able to run `kill-switch clear`
/// without prompting: prefer the persisted CAP_NET_ADMIN copy installed by
/// `ensure_capable_binary()`, falling back to the sibling build output.
fn capable_client_binary() -> Option<std::path::PathBuf> {
    if let Some(persisted) = dirs::data_local_dir().map(|d| d.join("aivpn").join("aivpn-client")) {
        if persisted.is_file() {
            return Some(persisted);
        }
    }
    find_client_binary().ok()
}

/// Spawn `aivpn-client kill-switch clear` detached (never waited on by the
/// UI thread). Used when the client had to be SIGKILLed while the kill-switch
/// was active: SIGKILL bypasses the client's own firewall cleanup, which
/// would otherwise leave the user with all non-VPN traffic blocked. Matches
/// the Windows GUI's run_kill_switch_clear-after-TerminateProcess behavior.
fn spawn_kill_switch_clear() {
    if let Some(binary) = capable_client_binary() {
        let _ = std::process::Command::new(binary)
            .args(["kill-switch", "clear"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
}

/// Gracefully terminate the aivpn-client child: SIGTERM first so the
/// client's signal handler deactivates the kill-switch and restores routes
/// (the client does NOT clear firewall rules on SIGKILL — it can't, SIGKILL
/// is uncatchable), then SIGKILL only if it is still alive after a grace
/// period.
///
/// `clear_inline` selects how a needed `kill-switch clear` runs after a
/// forced SIGKILL: `false` (Disconnect / app teardown) spawns it detached so
/// the GUI never waits on it; `true` (reconnect) runs it to completion
/// *inside* this future, so by the time the caller proceeds to spawn a NEW
/// client no stray detached clear can fire seconds later and silently wipe
/// the new session's firewall rules (fail-open while the UI shows protected).
async fn terminate_child_wait(
    mut child: tokio::process::Child,
    kill_switch_active: bool,
    clear_inline: bool,
) {
    if let Some(pid) = child.id() {
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
    }
    if tokio::time::timeout(std::time::Duration::from_secs(3), child.wait())
        .await
        .is_err()
    {
        // Still alive after the grace period — force-kill, reap, and
        // clear any firewall rules the client never got to remove.
        let _ = child.start_kill();
        let _ = child.wait().await;
        if kill_switch_active {
            if clear_inline {
                // kill_on_drop: if the clear itself hangs past the timeout it
                // is killed, not left running where it could later remove the
                // NEW session's rules.
                if let Some(binary) = capable_client_binary() {
                    let mut cmd = tokio::process::Command::new(binary);
                    cmd.args(["kill-switch", "clear"])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .kill_on_drop(true);
                    if let Ok(mut clear) = cmd.spawn() {
                        let _ =
                            tokio::time::timeout(std::time::Duration::from_secs(5), clear.wait())
                                .await;
                    }
                }
            } else {
                spawn_kill_switch_clear();
            }
        }
    }
    remove_client_pidfile();
}

/// Detached variant for Disconnect / teardown paths: the reap happens on a
/// background task so the UI never blocks.
fn terminate_child_graceful(child: tokio::process::Child, kill_switch_active: bool) {
    tokio::spawn(terminate_child_wait(child, kill_switch_active, false));
}

fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(2))
        .and_then(|u| u.parse::<u32>().ok())
        .map(|uid| uid == 0)
        .unwrap_or(false)
}

/// Per-user runtime dir for GUI bookkeeping (single-instance lock, client
/// pidfile). XDG_RUNTIME_DIR is per-user and mode 0700; fall back to the
/// (also owner-only) cache dir rather than shared /tmp, where another user
/// could pre-plant the fixed filenames.
fn aivpn_runtime_dir() -> std::path::PathBuf {
    dirs::runtime_dir()
        .or_else(dirs::cache_dir)
        .unwrap_or_else(std::env::temp_dir)
        .join("aivpn")
}

/// starttime (clock ticks since boot, /proc/<pid>/stat field 22) — together
/// with the pid this uniquely identifies one process incarnation, so a
/// recycled pid can never be mistaken for our client.
fn proc_starttime(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm (field 2) may itself contain spaces/parens; the fixed-format
    // fields resume after the LAST ')'. starttime is field 22 overall, i.e.
    // the 20th whitespace token after `state`.
    let rest = stat.rsplit_once(')')?.1;
    rest.split_whitespace().nth(19)?.parse().ok()
}

fn client_pidfile_path() -> std::path::PathBuf {
    aivpn_runtime_dir().join("client.pid")
}

/// Record the freshly spawned client as "<pid> <starttime>" so a GUI that
/// crashes and restarts can find and re-adopt it (see the recovery in
/// `App::new`). Removed again at every reap site.
fn write_client_pidfile(pid: u32) {
    if let Some(starttime) = proc_starttime(pid) {
        let path = client_pidfile_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(path, format!("{pid} {starttime}"));
    }
}

fn remove_client_pidfile() {
    let _ = std::fs::remove_file(client_pidfile_path());
}

/// Startup recovery: if the pidfile left by a previous (crashed) GUI run
/// still names a live process with the same starttime AND comm
/// "aivpn-client", return it for adoption; otherwise clean up the stale file.
fn recover_orphaned_client() -> Option<(u32, u64)> {
    let content = std::fs::read_to_string(client_pidfile_path()).ok()?;
    let parsed = (|| -> Option<(u32, u64)> {
        let mut it = content.split_whitespace();
        let pid: u32 = it.next()?.parse().ok()?;
        let starttime: u64 = it.next()?.parse().ok()?;
        if proc_starttime(pid) != Some(starttime) {
            return None;
        }
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
        (comm.trim() == "aivpn-client").then_some((pid, starttime))
    })();
    if parsed.is_none() {
        remove_client_pidfile();
    }
    parsed
}

/// Single-GUI-instance guard. `Ok(guard)` — lock acquired; keep the guard
/// alive for the whole process (`None` inside means the lock file could not
/// even be created, in which case we start anyway rather than lock the user
/// out of their own VPN). `Err(())` — another aivpn-linux already holds it.
pub fn acquire_single_instance_lock() -> Result<Option<std::fs::File>, ()> {
    use std::os::unix::io::AsRawFd;
    let dir = aivpn_runtime_dir();
    let _ = std::fs::create_dir_all(&dir);
    let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(dir.join("gui.lock"))
    else {
        return Ok(None);
    };
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Ok(Some(file))
    } else {
        Err(())
    }
}

/// SIGTERM an ADOPTED (recovered from a previous GUI run — not our child, so
/// it cannot be wait()ed) client and poll for its exit; after the grace
/// period SIGKILL it and clear any firewall rules its kill-switch may have
/// left. The recovered session's launch flags are unknown, so the clear is
/// unconditional — a spurious clear is harmless.
async fn terminate_adopted_wait(pid: u32, starttime: u64) {
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while proc_starttime(pid) == Some(starttime) {
        if std::time::Instant::now() >= deadline {
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
            spawn_kill_switch_clear();
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    remove_client_pidfile();
}

#[derive(Debug, Clone, PartialEq)]
pub enum RecordingState {
    Idle,
    Active(String), // service name
    Stopping,
    Done { succeeded: bool, details: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdaptiveOption {
    Auto,
    Low,
    Medium,
    High,
}

impl AdaptiveOption {
    pub fn all() -> &'static [AdaptiveOption] {
        &[
            AdaptiveOption::Auto,
            AdaptiveOption::Low,
            AdaptiveOption::Medium,
            AdaptiveOption::High,
        ]
    }

    pub fn from_level(level: u8) -> Self {
        match level {
            1 => AdaptiveOption::Low,
            2 => AdaptiveOption::Medium,
            3 => AdaptiveOption::High,
            _ => AdaptiveOption::Auto,
        }
    }

    pub fn to_level(&self) -> u8 {
        match self {
            AdaptiveOption::Auto => 0,
            AdaptiveOption::Low => 1,
            AdaptiveOption::Medium => 2,
            AdaptiveOption::High => 3,
        }
    }
}

impl AdaptiveOption {
    fn desc(&self, lang: &str) -> &'static str {
        if lang == "ru" {
            match self {
                AdaptiveOption::Auto => "Только шифрование. Без маскировки трафика.",
                AdaptiveOption::Low => "Базовая маскировка. Keepalive каждые 15 с.",
                AdaptiveOption::Medium => "Имитация HTTPS/QUIC. Keepalive каждые 8 с.",
                AdaptiveOption::High => {
                    "Оптимизация для высокой задержки (>300 мс). Максимальная маскировка."
                }
            }
        } else {
            match self {
                AdaptiveOption::Auto => "Encryption only. No traffic mimicry.",
                AdaptiveOption::Low => "Basic mimicry. Keepalive every 15 s.",
                AdaptiveOption::Medium => "HTTPS/QUIC mimicry. Keepalive every 8 s.",
                AdaptiveOption::High => "Optimized for high latency (>300 ms). Maximum mimicry.",
            }
        }
    }
}

/// Muted hint text shown under the "Bootstrap (advanced)" section header.
/// Bootstrap descriptors are an operator/advanced feature for discovering a
/// working server/mask via signed multi-channel fallback when the user has
/// no working `aivpn://` connection key yet — not needed for normal use.
fn bootstrap_desc(lang: &str) -> &'static str {
    if lang == "ru" {
        "Для опытных пользователей/операторов: поиск рабочего сервера и маски без готового ключа подключения через подписанные дескрипторы (CDN/Telegram/GitHub). Не требуется для обычного подключения по одному ключу."
    } else {
        "Advanced/operator use: discover a working server and mask without a working connection key yet, via signed multi-channel descriptors (CDN/Telegram/GitHub). Not needed for normal single-key connections."
    }
}

impl std::fmt::Display for AdaptiveOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AdaptiveOption::Auto => "Off",
            AdaptiveOption::Low => "Light (keepalive 15s)",
            AdaptiveOption::Medium => "Aggressive (keepalive 8s)",
            AdaptiveOption::High => "Satellite (high latency)",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaskOption {
    Auto,
    WebrtcZoomV3,
    QuicHttpsV2,
    WebrtcYandexTelemostV1,
    WebrtcVkTeamsV1,
    WebrtcSberjazzV1,
}

impl MaskOption {
    pub fn all() -> &'static [MaskOption] {
        &[
            MaskOption::Auto,
            MaskOption::WebrtcZoomV3,
            MaskOption::QuicHttpsV2,
            MaskOption::WebrtcYandexTelemostV1,
            MaskOption::WebrtcVkTeamsV1,
            MaskOption::WebrtcSberjazzV1,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MaskOption::Auto => "auto",
            MaskOption::WebrtcZoomV3 => "webrtc_zoom_v3",
            MaskOption::QuicHttpsV2 => "quic_https_v2",
            MaskOption::WebrtcYandexTelemostV1 => "webrtc_yandex_telemost_v1",
            MaskOption::WebrtcVkTeamsV1 => "webrtc_vk_teams_v1",
            MaskOption::WebrtcSberjazzV1 => "webrtc_sberjazz_v1",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "webrtc_zoom_v3" => MaskOption::WebrtcZoomV3,
            "quic_https_v2" => MaskOption::QuicHttpsV2,
            "webrtc_yandex_telemost_v1" => MaskOption::WebrtcYandexTelemostV1,
            "webrtc_vk_teams_v1" => MaskOption::WebrtcVkTeamsV1,
            "webrtc_sberjazz_v1" => MaskOption::WebrtcSberjazzV1,
            _ => MaskOption::Auto,
        }
    }
}

impl MaskOption {
    fn label(&self) -> &'static str {
        match self {
            MaskOption::Auto => "Auto (server default)",
            MaskOption::WebrtcZoomV3 => "Zoom WebRTC v3",
            MaskOption::QuicHttpsV2 => "QUIC / HTTPS v2",
            MaskOption::WebrtcYandexTelemostV1 => "Yandex Telemost",
            MaskOption::WebrtcVkTeamsV1 => "VK Teams",
            MaskOption::WebrtcSberjazzV1 => "SberJazz",
        }
    }

    fn desc(&self, lang: &str) -> &'static str {
        if lang == "ru" {
            match self {
                MaskOption::Auto => "Сервер выбирает оптимальную маску автоматически.",
                MaskOption::WebrtcZoomV3 => "Имитация трафика Zoom WebRTC видеоконференций.",
                MaskOption::QuicHttpsV2 => "Имитация QUIC/HTTPS браузерного трафика.",
                MaskOption::WebrtcYandexTelemostV1 => "Имитация Yandex Telemost видеозвонков.",
                MaskOption::WebrtcVkTeamsV1 => "Имитация VK Teams корпоративного мессенджера.",
                MaskOption::WebrtcSberjazzV1 => "Имитация трафика SberJazz конференций.",
            }
        } else {
            match self {
                MaskOption::Auto => "Server selects the best mask automatically.",
                MaskOption::WebrtcZoomV3 => "Mimics Zoom WebRTC video conferencing traffic.",
                MaskOption::QuicHttpsV2 => "Mimics QUIC/HTTPS browser traffic.",
                MaskOption::WebrtcYandexTelemostV1 => "Mimics Yandex Telemost video calls.",
                MaskOption::WebrtcVkTeamsV1 => "Mimics VK Teams corporate messenger traffic.",
                MaskOption::WebrtcSberjazzV1 => "Mimics SberJazz conference traffic.",
            }
        }
    }
}

impl std::fmt::Display for MaskOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// C3: which `install_wizard::BinarySourceOpt` variant the install wizard's
/// binary-source picker currently has selected. Kept separate from
/// `BinarySourceOpt` itself (rather than storing that enum directly in
/// `App`) so switching the picker back and forth doesn't discard whatever
/// the user already typed into the URL/path fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallBinarySourceKind {
    Default,
    Url,
    LocalFile,
}

impl InstallBinarySourceKind {
    fn all() -> &'static [InstallBinarySourceKind] {
        &[
            InstallBinarySourceKind::Default,
            InstallBinarySourceKind::Url,
            InstallBinarySourceKind::LocalFile,
        ]
    }
}

impl std::fmt::Display for InstallBinarySourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            InstallBinarySourceKind::Default => "Server default (GitHub Releases)",
            InstallBinarySourceKind::Url => "Custom URL",
            InstallBinarySourceKind::LocalFile => "Local file",
        };
        write!(f, "{s}")
    }
}

/// Localized suffix appended to auto-generated masks in the picker (Variant A).
fn auto_mask_suffix(lang: &str) -> &'static str {
    match lang {
        "ru" => " (авто)",
        "zh" => " (自动)",
        _ => " (auto)",
    }
}

/// One entry in the mask picker: the wire `id` plus the human `display` string
/// (which already carries the "(авто)" suffix for auto-generated masks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskChoice {
    pub id: String,
    pub display: String,
}

impl std::fmt::Display for MaskChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display)
    }
}

/// G-B1: what picking a given `ExitNodeChoice` in the exit-node `pick_list`
/// does to the free-text `admin_new_exit_node`/`admin_edit_exit_node` field
/// it sits beside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitNodeSelection {
    /// Clears the field — empty means "fall back to the pool's global
    /// default" server-side (`exit_node: None`/`null`).
    Default,
    /// Fills the field with this pool node's `host:port` verbatim (from
    /// `GET /api/v1/pool/nodes`'s `address`).
    Node(String),
    /// Leaves the field exactly as the user last typed it — the free-text
    /// path (`text_input` beside the picker) is unchanged/unremoved by G-B1,
    /// this is just the dropdown's "I'm typing something not in the list"
    /// entry so it can still show *something* selected.
    Custom,
}

/// One entry in the exit-node `pick_list` — mirrors `MaskChoice`'s
/// id+display shape (`selection` drives the on-pick side effect above,
/// `display` is what's rendered/what `PartialEq`-matches the currently
/// selected row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitNodeChoice {
    pub selection: ExitNodeSelection,
    pub display: String,
}

impl std::fmt::Display for ExitNodeChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display)
    }
}

/// Builds the exit-node picker's option list: "(default)" first, then every
/// pool node with a non-empty `address` (verified/unverified/offline all
/// included — the picker doesn't second-guess reachability, same as the
/// existing free-text path never did), then "Custom..." last.
fn exit_node_choices(lang: &str, pool_nodes: &[PoolNode]) -> Vec<ExitNodeChoice> {
    let mut choices = vec![ExitNodeChoice {
        selection: ExitNodeSelection::Default,
        display: t(lang, "(default)").to_string(),
    }];
    for n in pool_nodes {
        if let Some(addr) = n.address.as_ref().filter(|a| !a.trim().is_empty()) {
            choices.push(ExitNodeChoice {
                selection: ExitNodeSelection::Node(addr.clone()),
                display: addr.clone(),
            });
        }
    }
    choices.push(ExitNodeChoice {
        selection: ExitNodeSelection::Custom,
        display: t(lang, "Custom...").to_string(),
    });
    choices
}

/// Which `exit_node_choices()` entry currently matches `text` (the live
/// content of the free-text field), so the picker highlights the right row
/// instead of going blank the moment the user picks a preset. Falls back to
/// the list's "Custom..." entry for anything that isn't empty and isn't a
/// known pool-node address — i.e. manually-typed `host:port` values keep
/// working exactly as before, just shown as "Custom..." in the dropdown.
fn exit_node_selected(text: &str, choices: &[ExitNodeChoice]) -> Option<ExitNodeChoice> {
    if text.is_empty() {
        return choices
            .iter()
            .find(|c| c.selection == ExitNodeSelection::Default)
            .cloned();
    }
    choices
        .iter()
        .find(|c| matches!(&c.selection, ExitNodeSelection::Node(addr) if addr == text))
        .or_else(|| {
            choices
                .iter()
                .find(|c| c.selection == ExitNodeSelection::Custom)
        })
        .cloned()
}

/// G-A3: which of the two `HeavySetting`s (`admin::ConfigSetting`) a
/// `server_settings_pending` token belongs to — drives the pending banner's
/// "applies live" vs "applies on restart" caption in
/// `view_server_settings_section`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerSettingsPendingKind {
    ActiveMask,
    ExitNode,
}

/// G-A3: one entry in the Server Settings "target client" `pick_list` for
/// the active-mask-override setting — mirrors `MaskChoice`/`ExitNodeChoice`'s
/// id+display shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminClientChoice {
    pub id: String,
    pub display: String,
}

impl std::fmt::Display for AdminClientChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display)
    }
}

/// Builds the Server Settings client picker's option list from
/// `self.admin_clients` (the same list `view_admin_section` already fetches
/// on panel open — no separate network round trip here).
fn admin_client_choices(clients: &[ClientRecord]) -> Vec<AdminClientChoice> {
    clients
        .iter()
        .map(|c| AdminClientChoice {
            id: c.id.clone(),
            display: if c.name.is_empty() {
                c.id.clone()
            } else {
                format!("{} ({})", c.name, c.id)
            },
        })
        .collect()
}

#[derive(serde::Deserialize)]
struct CatalogEntryRaw {
    mask_id: String,
    label: String,
    generated: bool,
}

/// Candidate paths where `aivpn-client` writes the server-pushed mask catalog
/// (mirrors `aivpn_client::mask_catalog::mask_catalog_paths`, kept local so the
/// GUI needs no heavy dependency on the client crate).
fn mask_catalog_file_paths() -> Vec<std::path::PathBuf> {
    let mut v = Vec::new();
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
        v.push(
            std::path::PathBuf::from(rt)
                .join("aivpn")
                .join("mask_catalog.json"),
        );
    }
    v.push(std::path::PathBuf::from("/var/run/aivpn/mask_catalog.json"));
    v.push(std::path::PathBuf::from("/tmp/aivpn-mask-catalog.json"));
    v
}

/// Build picker choices from the server's mask catalog, appending the localized
/// "(авто)" suffix to auto-generated masks. Returns `None` when no catalog has
/// been received yet (the caller then falls back to the built-in presets).
/// Called from `view()` on every render, so the parsed result is cached and
/// the file is only re-read when its mtime (or path, or language) changes.
fn mask_choices_from_catalog(lang: &str) -> Option<Vec<MaskChoice>> {
    type CatalogCache = (
        std::path::PathBuf,
        std::time::SystemTime,
        String,
        Vec<MaskChoice>,
    );
    static CACHE: Mutex<Option<CatalogCache>> = Mutex::new(None);
    for path in mask_catalog_file_paths() {
        let Ok(mtime) = std::fs::metadata(&path).and_then(|m| m.modified()) else {
            continue;
        };
        {
            let cache = match CACHE.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            if let Some((cp, cm, cl, choices)) = cache.as_ref() {
                if *cp == path && *cm == mtime && cl == lang {
                    return Some(choices.clone());
                }
            }
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(entries) = serde_json::from_slice::<Vec<CatalogEntryRaw>>(&bytes) else {
            continue;
        };
        let mut choices = vec![MaskChoice {
            id: "auto".to_string(),
            display: MaskOption::Auto.label().to_string(),
        }];
        for e in entries {
            if e.mask_id == "auto" {
                continue;
            }
            let display = if e.generated {
                format!("{}{}", e.label, auto_mask_suffix(lang))
            } else {
                e.label
            };
            choices.push(MaskChoice {
                id: e.mask_id,
                display,
            });
        }
        let mut cache = match CACHE.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        *cache = Some((path, mtime, lang.to_string(), choices.clone()));
        return Some(choices);
    }
    None
}

/// G-A3: mask ids selectable in the Server Settings "active mask override"
/// picker — reuses the same server-pushed catalog `mask_choices_from_catalog`
/// already parses for the connect-time "preferred mask" picker, minus the
/// `"auto"` sentinel entry (a client-side "let the client pick" value, not a
/// real mask id — `config/apply`'s `HeavySetting::ActiveMask` validates
/// against on-disk/preset masks only, see
/// `mgmt_service.rs::resolve_heavy_setting`, and would 404 on it). Empty
/// until a connection has received at least one catalog push.
fn admin_mask_choices(lang: &str) -> Vec<MaskChoice> {
    mask_choices_from_catalog(lang)
        .unwrap_or_default()
        .into_iter()
        .filter(|m| m.id != "auto")
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
enum DialogMode {
    None,
    Add,
    Edit(usize),
}

pub struct App {
    storage: KeyStorage,
    settings: AppSettings,
    status: VpnStatus,
    log_lines: Vec<String>,
    connection_key: Option<String>,
    /// A reconnect is waiting for the old client to be reaped before the
    /// new one may spawn (see Message::Connect / Message::OldClientReaped).
    pending_connect: bool,
    /// Kill-switch flag the CURRENT client was launched with. Teardown paths
    /// consult this, not live settings — toggling the checkbox while
    /// connected must not skip (or invent) a needed `kill-switch clear`.
    launched_kill_switch: bool,
    /// Orphaned aivpn-client adopted at startup from a crashed previous GUI
    /// run: (pid, /proc starttime). Not our child — torn down via
    /// `terminate_adopted_wait`, never wait()ed.
    adopted_client: Option<(u32, u64)>,
    /// `terminate_adopted_wait` for the adopted client is still running
    /// (kicked off by Message::Disconnect). A Connect arriving inside that
    /// ~3 s grace window must defer its spawn to OldClientReaped — exactly
    /// like the `pending_connect` reconnect path — otherwise the old
    /// client's late SIGTERM cleanup / SIGKILL kill-switch clear tears down
    /// the NEW session's routes and firewall rules.
    adopted_reap_in_flight: bool,
    child_handle: Arc<Mutex<Option<tokio::process::Child>>>,
    /// Extra settings section declared by an optional descriptor file. `None`
    /// in a public build, in which case none of this UI is rendered.
    ext_descriptor: Option<aivpn_common::ui_ext::Descriptor>,
    /// Live values of that section's fields, in declaration order.
    ext_values: Vec<(String, aivpn_common::ui_ext::FieldValue)>,
    /// Transport the section selected, passed to the client process on the
    /// next connect. `None` = the default transport.
    ext_transport: Option<aivpn_common::transport::TransportConfig>,
    ext_open: bool,
    dialog: DialogMode,
    dlg_name: String,
    dlg_key: String,
    dlg_mtls_cert: String,
    dlg_full_tunnel: bool,
    dlg_error: Option<String>,
    stats: TrafficStats,
    // Recording
    recording_service: String,
    recording_state: RecordingState,
    // Diagnostics / Bench
    bench_running: bool,
    bench_result: Option<String>,
    logs_open: bool,
    bootstrap_open: bool,
    /// 3c: true once this session's client child has emitted
    /// "AIVPN-STATUS bootstrap-fallback" (see `Message::BootstrapFallbackDetected`).
    /// Reset on every new `Connect` so a badge from a previous session never
    /// bleeds into the next one.
    bootstrap_fallback: bool,
    // ── Admin client-management panel ───────────────────────────────────
    /// Panel disclosure toggle; the panel itself only ever renders when the
    /// role is also confirmed Admin (see `Message::ToggleAdminPanel`/`view_main`).
    admin_open: bool,
    /// Server-assigned role cached by the daemon (0=User,1=Viewer,2=Admin),
    /// fetched fresh on every new Connected transition. `None` until loaded.
    admin_role: Option<u8>,
    admin_clients: Vec<ClientRecord>,
    admin_clients_loading: bool,
    admin_error: Option<String>,
    /// Set while any per-client mutating call (toggle/edit/reset/revoke) is
    /// in flight, so its row's buttons can be disabled instead of allowing a
    /// second concurrent request against the same client.
    admin_busy_id: Option<String>,
    admin_new_name: String,
    admin_new_one_time: bool,
    admin_new_expires: String,
    /// Wave B3: `host:port`, empty = use the pool's global default.
    admin_new_exit_node: String,
    admin_edit_id: Option<String>,
    admin_edit_name: String,
    admin_edit_expires: String,
    /// Wave B3: `host:port`, empty = use the pool's global default (clears
    /// any existing per-client override on save).
    admin_edit_exit_node: String,
    /// Two-step revoke: first press stores the target id here and the view
    /// renders a "Confirm revoke? [Yes][No]" row for just that client;
    /// nothing is revoked until `Message::AdminRevokeConfirm` on the same id.
    admin_pending_revoke: Option<String>,
    admin_key_view: Option<(String, String)>,
    admin_qr: Option<(String, image::Handle)>,
    admin_qr_loading: Option<String>,
    // ── Pool topology panel (B3) ────────────────────────────────────────
    /// Panel disclosure toggle; same admin-role gate as `admin_open` (see
    /// `view_main`).
    pool_open: bool,
    pool_nodes: Vec<PoolNode>,
    pool_health: Option<PoolHealth>,
    pool_loading: bool,
    pool_error: Option<String>,
    // ── G-A2: audit-log panel (Viewer + Admin) ──────────────────────────
    /// Panel disclosure toggle; same `admin_role >= 1` (Viewer or Admin)
    /// gate as `admin_open`/`pool_open` — see `view_main`.
    audit_open: bool,
    audit_entries: Vec<admin::AuditEntry>,
    /// Hash-chain verification result for `audit_entries` (from the
    /// server's `verify=1` response), `None` until the first load.
    audit_verified: Option<bool>,
    /// Tail-window index (0-based, oldest-first) of the first broken link,
    /// if `audit_verified == Some(false)`.
    audit_broken_at: Option<usize>,
    audit_loading: bool,
    audit_error: Option<String>,
    // ── G-A3: Server Settings (Admin-only apply-with-rollback) ──────────
    /// Panel disclosure toggle. Unlike `admin_open`/`pool_open`/`audit_open`
    /// (which any Viewer-or-Admin session can enter, `view_admin_section`
    /// itself splitting mutate-vs-view), this panel has no read-only
    /// rendering at all — `view_main` only calls
    /// `view_server_settings_section` when `admin_role == Some(2)`.
    server_settings_open: bool,
    /// Target client (id) for the active-mask-override picker below.
    /// `HeavySetting::ActiveMask` has no "apply to every client" form
    /// server-side (see `ConfigSetting`'s doc comment in `admin.rs`) — this
    /// is always one specific client, not a server-wide default.
    server_settings_mask_client: Option<String>,
    /// Mask id selected in the same picker (from `admin_mask_choices`).
    server_settings_mask_id: Option<String>,
    /// `host:port`, or empty for "(default)" i.e. clear — the pool's GLOBAL
    /// default exit node (`pool.exit_node` in `server.json`). Unlike the
    /// per-client override elsewhere in this panel, applying this only
    /// takes effect after the server process restarts.
    server_settings_exit_node: String,
    /// Set while an apply/confirm call is in flight — disables both Apply
    /// buttons and the Confirm button rather than allowing a second
    /// concurrent request.
    server_settings_busy: bool,
    /// `Some((token, kind))` once `config/apply` has returned a token
    /// awaiting `config/confirm` within the server's confirm window —
    /// `None` once confirmed, rolled back, or never applied. Only one
    /// pending change is tracked client-side at a time (both Apply buttons
    /// are disabled while this is `Some`), even though the server itself
    /// can track more than one concurrently by token.
    server_settings_pending: Option<(String, ServerSettingsPendingKind)>,
    /// Seconds remaining before the countdown assumes the server has
    /// auto-rolled `server_settings_pending` back — ticked down once a
    /// second by `Message::ServerSettingsCountdownTick` (see
    /// `subscription`), reset to `SERVER_SETTINGS_CONFIRM_WINDOW_SECS` on
    /// every successful apply.
    server_settings_countdown: u32,
    /// Set once the countdown above reaches 0 without a confirm — shown as
    /// a "rolled back" banner until the next successful Apply.
    server_settings_rolled_back: bool,
    server_settings_error: Option<String>,
    // ── C3: "Install server via SSH" wizard ─────────────────────────────
    install_wizard_open: bool,
    install_host: String,
    install_port: String,
    install_user: String,
    /// `false` = password auth, `true` = key-file auth.
    install_auth_is_key: bool,
    install_password: String,
    install_key_file: String,
    install_key_passphrase: String,
    /// Which of `Default`/`Url`/`LocalFile` the picker has selected; the
    /// URL/path text fields below are kept independently so toggling this
    /// never discards what the user already typed into the other one.
    install_binary_source_kind: InstallBinarySourceKind,
    install_binary_url: String,
    install_binary_file: String,
    install_server_ip: String,
    install_server_port: String,
    /// `false` = systemd (default), `true` = docker.
    install_mode_docker: bool,
    /// See `InstallTarget::bind_device` — defaults to `true` (bind this GUI's
    /// machine as the created client's device, matching `ssh-install run`'s
    /// own default of auto-detecting `~/.config/aivpn/device.key` when no
    /// device flag is given at all).
    install_bind_device: bool,
    /// TOFU host key fingerprint from `ssh-install probe`, reset whenever
    /// host/port/user changes so a stale confirmation can never apply to a
    /// different target.
    install_fingerprint: Option<String>,
    /// User pressed "I trust this key" for the fingerprint currently held in
    /// `install_fingerprint`.
    install_trusted: bool,
    install_probing: bool,
    install_error: Option<String>,
    /// `(sha256_hex, script_text)` — fetched lazily the first time "Show
    /// script" is pressed, then cached.
    install_script: Option<(String, String)>,
    install_script_open: bool,
    /// `true` while `ssh-install run`'s subprocess is alive — drives
    /// `subscription()`'s `install_sub` together with `install_target`.
    install_running: bool,
    /// `Some` fuels the streaming subscription (mirrors `connection_key`'s
    /// role for the VPN-connect worker subscription); cleared on
    /// finish/error so the subprocess isn't respawned.
    install_target: Option<InstallTarget>,
    install_log: Vec<String>,
    /// Set once the remote installer's final `##AIVPN` marker carries a
    /// non-null `connection_key` (only present when device-bound — see
    /// `ssh_install_cmd.rs`'s `Finished` event).
    install_connection_key: Option<String>,
    install_exit_code: Option<i32>,
    /// G-C1: profile name once `install_connection_key` has been added to
    /// `storage` automatically (see `import_installed_key`) — "install →
    /// immediately connected as admin" without a mandatory manual click.
    /// `None` until auto-import runs (or if it failed and the manual
    /// "Import profile" retry button is still waiting to be pressed).
    install_profile_imported: Option<String>,
}

impl App {
    pub fn new() -> (Self, Task<Message>) {
        let settings = AppSettings::load();
        let storage = KeyStorage::load();
        // Startup recovery: a previous GUI run that crashed (or was
        // SIGKILLed) leaves its aivpn-client running with the tunnel up.
        // Adopt it instead of showing Disconnected over a live tunnel and
        // spawning a second client on the next Connect.
        let adopted_client = recover_orphaned_client();
        let mut log_lines = Vec::new();
        let status = if let Some((pid, _)) = adopted_client {
            log_lines.push(format!(
                "Recovered running aivpn-client (pid {pid}) from a previous GUI session"
            ));
            VpnStatus::Connected {
                vpn_ip: "recovered".to_string(),
            }
        } else {
            VpnStatus::Disconnected
        };
        (
            Self {
                storage,
                settings,
                status,
                log_lines,
                connection_key: None,
                pending_connect: false,
                launched_kill_switch: false,
                adopted_client,
                adopted_reap_in_flight: false,
                child_handle: Arc::new(Mutex::new(None)),
                ext_descriptor: {
                    let d = aivpn_common::ui_ext::load_default();
                    if d.is_some() {
                        tracing::info!("extra settings section loaded from descriptor");
                    }
                    d
                },
                ext_values: Vec::new(),
                ext_transport: None,
                ext_open: false,
                dialog: DialogMode::None,
                dlg_name: String::new(),
                dlg_key: String::new(),
                dlg_mtls_cert: String::new(),
                dlg_full_tunnel: false,
                dlg_error: None,
                stats: TrafficStats::default(),
                recording_service: String::new(),
                recording_state: RecordingState::Idle,
                bench_running: false,
                bench_result: None,
                logs_open: false,
                bootstrap_open: false,
                bootstrap_fallback: false,
                admin_open: false,
                admin_role: None,
                admin_clients: Vec::new(),
                admin_clients_loading: false,
                admin_error: None,
                admin_busy_id: None,
                admin_new_name: String::new(),
                admin_new_one_time: false,
                admin_new_expires: String::new(),
                admin_new_exit_node: String::new(),
                admin_edit_id: None,
                admin_edit_name: String::new(),
                admin_edit_expires: String::new(),
                admin_edit_exit_node: String::new(),
                admin_pending_revoke: None,
                admin_key_view: None,
                admin_qr: None,
                admin_qr_loading: None,
                pool_open: false,
                pool_nodes: Vec::new(),
                pool_health: None,
                pool_loading: false,
                pool_error: None,
                audit_open: false,
                audit_entries: Vec::new(),
                audit_verified: None,
                audit_broken_at: None,
                audit_loading: false,
                audit_error: None,
                server_settings_open: false,
                server_settings_mask_client: None,
                server_settings_mask_id: None,
                server_settings_exit_node: String::new(),
                server_settings_busy: false,
                server_settings_pending: None,
                server_settings_countdown: 0,
                server_settings_rolled_back: false,
                server_settings_error: None,
                install_wizard_open: false,
                install_host: String::new(),
                install_port: String::new(),
                install_user: String::new(),
                install_auth_is_key: false,
                install_password: String::new(),
                install_key_file: String::new(),
                install_key_passphrase: String::new(),
                install_binary_source_kind: InstallBinarySourceKind::Default,
                install_binary_url: String::new(),
                install_binary_file: String::new(),
                install_server_ip: String::new(),
                install_server_port: String::new(),
                install_mode_docker: false,
                install_bind_device: true,
                install_fingerprint: None,
                install_trusted: false,
                install_probing: false,
                install_error: None,
                install_script: None,
                install_script_open: false,
                install_running: false,
                install_target: None,
                install_log: Vec::new(),
                install_connection_key: None,
                install_exit_code: None,
                install_profile_imported: None,
            },
            // An adopted session starts already Connected, so the
            // became_connected branch (the only other get_role caller) never
            // fires for it and the admin panel would stay hidden until a
            // reconnect. `role` only needs the running daemon's local admin
            // socket — no connection key — so fetch it right away.
            if adopted_client.is_some() {
                Task::perform(admin::get_role(), Message::AdminRoleLoaded)
            } else {
                Task::none()
            },
        )
    }

    /// Blocking graceful teardown for app exit (tray Quit). Async tasks are
    /// dropped when the runtime shuts down, so wait here on the UI thread
    /// (bounded) for the client's SIGTERM cleanup — kill-switch firewall
    /// rules, routes — to finish before kill_on_drop's SIGKILL fires.
    fn shutdown_child_blocking(&mut self) {
        // Adopted (recovered, non-child) client: same SIGTERM + grace +
        // SIGKILL sequence, but polled via /proc since it can't be wait()ed.
        if let Some((pid, starttime)) = self.adopted_client.take() {
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            while proc_starttime(pid) == Some(starttime) {
                if std::time::Instant::now() >= deadline {
                    unsafe {
                        libc::kill(pid as libc::pid_t, libc::SIGKILL);
                    }
                    spawn_kill_switch_clear();
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            remove_client_pidfile();
            return;
        }
        let mut guard = match self.child_handle.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let Some(mut child) = guard.take() else {
            return;
        };
        drop(guard);
        if let Some(pid) = child.id() {
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    remove_client_pidfile();
                    return;
                }
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                _ => break,
            }
        }
        // Grace period expired (or wait failed) — force-kill and clear any
        // firewall rules the client never got to remove. The clear process
        // is detached, so it survives this GUI exiting right after.
        let _ = child.start_kill();
        let _ = child.try_wait();
        if self.launched_kill_switch {
            spawn_kill_switch_clear();
        }
        remove_client_pidfile();
    }

    pub fn update(&mut self, msg: Message) -> Task<Message> {
        match msg {
            Message::Connect => {
                // 3c: a new connection attempt starts clean — any fallback
                // badge from a previous session must not persist into this
                // one until (if) the new child re-emits the status line.
                self.bootstrap_fallback = false;
                if let Some(k) = self.storage.selected_key() {
                    let key = k.key.clone();
                    // Kill any existing child before starting a new connection to
                    // avoid leaking a zombie VPN process when the user reconnects.
                    let mut guard = match self.child_handle.lock() {
                        Ok(g) => g,
                        Err(e) => e.into_inner(),
                    };
                    let old_child = guard.take();
                    drop(guard);
                    self.status = VpnStatus::Connecting;
                    if let Some((pid, starttime)) = self.adopted_client.take() {
                        // Recovered (non-child) client from a previous GUI
                        // run: same hold-the-spawn sequencing as the
                        // reconnect path below.
                        self.pending_connect = true;
                        self.connection_key = None;
                        return Task::perform(terminate_adopted_wait(pid, starttime), |_| {
                            Message::OldClientReaped
                        });
                    }
                    if let Some(child) = old_child {
                        // Reconnect: the old client's SIGTERM cleanup (route
                        // restore, kill-switch removal) takes up to ~3 s.
                        // Spawning the new client immediately would let that
                        // late cleanup tear down the NEW session's routes and
                        // firewall rules, so hold the spawn (connection_key
                        // stays None → no worker subscription) until the old
                        // child is fully reaped. The wait runs as an async
                        // Task — the UI thread is never blocked.
                        self.pending_connect = true;
                        self.connection_key = None;
                        return Task::perform(
                            terminate_child_wait(child, self.launched_kill_switch, true),
                            |_| Message::OldClientReaped,
                        );
                    }
                    if self.pending_connect || self.adopted_reap_in_flight {
                        // A reap from a previous reconnect — or an adopted
                        // client's teardown kicked off by Disconnect — is
                        // still in flight; OldClientReaped will spawn the
                        // client with the currently selected profile when it
                        // lands.
                        self.pending_connect = true;
                        return Task::none();
                    }
                    self.launched_kill_switch = self.settings.kill_switch;
                    self.connection_key = Some(key);
                } else {
                    self.push_log("No profile selected".to_string());
                }
            }
            Message::OldClientReaped => {
                // Old client fully exited and any inline kill-switch clear has
                // completed — safe to start the new client now.
                self.adopted_reap_in_flight = false;
                if self.pending_connect {
                    self.pending_connect = false;
                    if let Some(k) = self.storage.selected_key() {
                        self.launched_kill_switch = self.settings.kill_switch;
                        self.connection_key = Some(k.key.clone());
                    } else {
                        self.status = VpnStatus::Disconnected;
                    }
                }
            }
            Message::Disconnect => {
                self.pending_connect = false;
                self.connection_key = None;
                let reap_task = if let Some((pid, starttime)) = self.adopted_client.take() {
                    // Sequenced, not fire-and-forget: a Connect pressed
                    // during the ~3 s SIGTERM grace must defer its spawn to
                    // OldClientReaped (see `adopted_reap_in_flight`), or the
                    // old client's late route restore / kill-switch clear
                    // would tear down the new session.
                    self.adopted_reap_in_flight = true;
                    Task::perform(terminate_adopted_wait(pid, starttime), |_| {
                        Message::OldClientReaped
                    })
                } else {
                    Task::none()
                };
                // Recover from a poisoned mutex so the kill() always executes.
                let mut guard = match self.child_handle.lock() {
                    Ok(g) => g,
                    Err(e) => e.into_inner(),
                };
                if let Some(child) = guard.take() {
                    // SIGTERM (not SIGKILL) so the client clears its
                    // kill-switch firewall rules; reaped on a background task.
                    terminate_child_graceful(child, self.launched_kill_switch);
                }
                drop(guard);
                self.status = VpnStatus::Disconnected;
                self.bootstrap_fallback = false;
                self.push_log("Disconnected".to_string());
                return reap_task;
            }
            Message::StatusReceived(s) => {
                // While a reconnect waits for the old client's reap, the old
                // (cancelled) worker stream may still deliver stale statuses —
                // including a stale Connected. Drop them ALL so a dead session
                // can neither overwrite "Connecting" nor flash as live (and
                // fire a spurious "Connected" notification).
                if self.pending_connect {
                    return Task::none();
                }
                // Admin panel: the client only has a role to report once a
                // session is up (the daemon caches it from the handshake),
                // and any role from a previous session must not bleed into
                // this one — so fetch fresh on Connected, clear on drop.
                let became_connected = matches!(s, VpnStatus::Connected { .. })
                    && !matches!(self.status, VpnStatus::Connected { .. });
                let became_disconnected = !matches!(s, VpnStatus::Connected { .. })
                    && matches!(self.status, VpnStatus::Connected { .. });
                #[cfg(unix)]
                if matches!(s, VpnStatus::Connected { .. })
                    && !matches!(self.status, VpnStatus::Connected { .. })
                {
                    let _ = notify_rust::Notification::new()
                        .summary("AIVPN")
                        .body("Connected")
                        .show();
                }
                #[cfg(unix)]
                if matches!(s, VpnStatus::Disconnected)
                    && matches!(self.status, VpnStatus::Connected { .. })
                {
                    let _ = notify_rust::Notification::new()
                        .summary("AIVPN")
                        .body("Disconnected")
                        .show();
                }
                self.status = s;
                // A terminal status means the worker stream has ended. Clear the
                // connection key so its subscription id is dropped from the set;
                // otherwise iced keeps the finished id and never respawns the worker
                // on the next Connect, hanging forever on "Connecting...".
                if matches!(self.status, VpnStatus::Disconnected | VpnStatus::Error(_)) {
                    self.connection_key = None;
                    // A terminal status can now also arrive from an
                    // AIVPN-STATUS line while the child is still alive or
                    // unreaped (dropping connection_key cancels the worker
                    // before its own reap code runs) — terminate and reap it
                    // here so it can't linger as an orphan/zombie.
                    let mut guard = match self.child_handle.lock() {
                        Ok(g) => g,
                        Err(e) => e.into_inner(),
                    };
                    if let Some(child) = guard.take() {
                        terminate_child_graceful(child, self.launched_kill_switch);
                    }
                }
                if became_disconnected {
                    self.admin_role = None;
                    self.admin_open = false;
                    self.admin_clients.clear();
                    self.admin_error = None;
                    self.admin_key_view = None;
                    self.admin_qr = None;
                    self.admin_pending_revoke = None;
                    self.admin_edit_id = None;
                    // G-A3: a pending apply/confirm token is meaningless
                    // once the tunnel it rode in on is gone — confirming it
                    // now would just fail (no daemon session to reach the
                    // server through), and the server's own sweep will roll
                    // it back on its own timeline regardless.
                    self.server_settings_open = false;
                    self.server_settings_busy = false;
                    self.server_settings_pending = None;
                    self.server_settings_countdown = 0;
                    self.server_settings_rolled_back = false;
                    self.server_settings_error = None;
                } else if became_connected {
                    self.admin_role = None;
                    self.admin_clients.clear();
                    self.admin_clients_loading = false;
                    self.admin_error = None;
                    return Task::perform(admin::get_role(), Message::AdminRoleLoaded);
                }
            }
            Message::BootstrapFallbackDetected => {
                self.bootstrap_fallback = true;
            }
            Message::LogLine(line) => {
                self.push_log(line);
            }
            Message::ClearLog => {
                self.log_lines.clear();
            }
            Message::ToggleLogPanel => {
                self.logs_open = !self.logs_open;
            }
            Message::SaveLog => {
                return Task::perform(
                    async {
                        rfd::AsyncFileDialog::new()
                            .set_file_name("aivpn-debug.log")
                            .save_file()
                            .await
                            .map(|h| h.path().to_path_buf())
                    },
                    Message::SaveLogPathChosen,
                );
            }
            Message::SaveLogPathChosen(path) => {
                if let Some(path) = path {
                    let content = self.log_lines.join("\n");
                    let _ = std::fs::write(&path, content);
                }
            }
            Message::SelectProfile(idx) => {
                if idx < self.storage.keys.len() {
                    self.storage.selected = Some(idx);
                }
            }
            Message::ShowAddDialog => {
                self.dialog = DialogMode::Add;
                self.dlg_name.clear();
                self.dlg_key.clear();
                self.dlg_mtls_cert.clear();
                self.dlg_full_tunnel = false;
                self.dlg_error = None;
            }
            Message::ShowEditDialog(idx) => {
                if let Some(k) = self.storage.keys.get(idx) {
                    self.dlg_name = k.name.clone();
                    self.dlg_key = k.key.clone();
                    self.dlg_mtls_cert = k.mtls_cert.clone().unwrap_or_default();
                    self.dlg_full_tunnel = k.full_tunnel;
                    self.dialog = DialogMode::Edit(idx);
                    self.dlg_error = None;
                }
            }
            Message::DlgNameChanged(s) => {
                self.dlg_name = s;
            }
            Message::DlgKeyChanged(s) => {
                self.dlg_key = s;
            }
            Message::DlgMtlsCertChanged(s) => {
                self.dlg_mtls_cert = s;
            }
            Message::DlgFullTunnelToggled(v) => {
                self.dlg_full_tunnel = v;
            }
            Message::DlgSave => {
                let name = self.dlg_name.trim().to_string();
                let key_str = self.dlg_key.trim().to_string();
                match ConnectionKey::from_key_string(&name, &key_str) {
                    Ok(mut conn_key) => {
                        let mtls = self.dlg_mtls_cert.trim().to_string();
                        conn_key.mtls_cert = if mtls.is_empty() { None } else { Some(mtls) };
                        conn_key.full_tunnel = self.dlg_full_tunnel;
                        match &self.dialog {
                            DialogMode::Add => {
                                if let Err(e) = self.storage.add(conn_key) {
                                    self.dlg_error = Some(e);
                                    return Task::none();
                                }
                            }
                            DialogMode::Edit(idx) => {
                                let idx = *idx;
                                self.storage.update(idx, conn_key);
                            }
                            DialogMode::None => {}
                        }
                        self.dialog = DialogMode::None;
                    }
                    Err(e) => {
                        self.dlg_error = Some(e);
                    }
                }
            }
            Message::DlgCancel => {
                self.dialog = DialogMode::None;
                self.dlg_error = None;
            }
            Message::RemoveProfile(idx) => {
                self.storage.remove(idx);
            }
            Message::ToggleTheme => {
                self.settings.dark_mode = !self.settings.dark_mode;
                self.settings.save();
            }
            Message::ToggleLang => {
                self.settings.lang = if self.settings.lang == "ru" {
                    "en".to_string()
                } else {
                    "ru".to_string()
                };
                self.settings.save();
            }
            Message::ToggleKillSwitch(v) => {
                self.settings.kill_switch = v;
                self.settings.save();
            }
            Message::AdaptiveLevelChanged(opt) => {
                self.settings.adaptive_level = opt.to_level();
                self.settings.save();
            }
            Message::DnsProxyChanged(s) => {
                self.settings.dns_proxy = s;
                self.settings.save();
            }
            Message::ExcludeRoutesChanged(s) => {
                self.settings.exclude_routes = s;
                self.settings.save();
            }
            Message::IncludeRoutesChanged(s) => {
                self.settings.include_routes = s;
                self.settings.save();
            }
            Message::ToggleSocks5(v) => {
                self.settings.socks5_enabled = v;
                self.settings.save();
            }
            Message::Socks5AddrChanged(s) => {
                self.settings.socks5_addr = s;
                self.settings.save();
            }
            Message::ToggleAutostart(v) => {
                self.settings.autostart = v;
                self.settings.save();
                if v {
                    write_autostart_entry();
                } else {
                    remove_autostart_entry();
                }
            }
            Message::MaskOptionChanged(mask_id) => {
                self.settings.preferred_mask = mask_id;
                if self.settings.preferred_mask == "auto" {
                    // "Auto" has no concrete base mask to polymorph from — leaving
                    // the toggle checked would be inert (UI disables it, but the
                    // stored value stays true and could still be persisted/reused).
                    self.settings.polymorphic_mask = false;
                }
                self.settings.save();
            }
            Message::TogglePolymorphicMask(v) => {
                self.settings.polymorphic_mask = v;
                self.settings.save();
            }
            Message::ToggleShareMaskFeedback(v) => {
                self.settings.share_mask_feedback = v;
                self.settings.save();
            }
            Message::ToggleReceiveMaskHints(v) => {
                self.settings.receive_mask_hints = v;
                self.settings.save();
            }
            Message::CountryCodeChanged(s) => {
                let cleaned: String = s
                    .chars()
                    .filter(|c| c.is_ascii_alphabetic())
                    .take(2)
                    .collect::<String>()
                    .to_uppercase();
                self.settings.country_code = cleaned;
                self.settings.save();
            }
            // ── Extra settings section (aivpn_common::ui_ext) ──────────────
            // Generic handling: the GUI mutates whatever field the descriptor
            // declared and hands the whole set back on apply. It never
            // interprets a key, a label or a value.
            Message::ToggleExtPanel => {
                self.ext_open = !self.ext_open;
                if self.ext_open && self.ext_values.is_empty() {
                    if let Some(d) = &self.ext_descriptor {
                        self.ext_values = d
                            .fields
                            .iter()
                            .map(|f| {
                                let v = match &f.kind {
                                    aivpn_common::ui_ext::FieldKind::Toggle => {
                                        aivpn_common::ui_ext::FieldValue::Toggle(false)
                                    }
                                    aivpn_common::ui_ext::FieldKind::Text
                                    | aivpn_common::ui_ext::FieldKind::Secret => {
                                        aivpn_common::ui_ext::FieldValue::Text(String::new())
                                    }
                                    aivpn_common::ui_ext::FieldKind::Select { .. } => {
                                        aivpn_common::ui_ext::FieldValue::Select(0)
                                    }
                                };
                                (f.key.clone(), v)
                            })
                            .collect();
                    }
                }
            }
            Message::ExtToggleChanged(key, v) => {
                if let Some(slot) = self.ext_values.iter_mut().find(|(k, _)| *k == key) {
                    slot.1 = aivpn_common::ui_ext::FieldValue::Toggle(v);
                }
            }
            Message::ExtTextChanged(key, v) => {
                if let Some(slot) = self.ext_values.iter_mut().find(|(k, _)| *k == key) {
                    slot.1 = aivpn_common::ui_ext::FieldValue::Text(v);
                }
            }
            Message::ExtSelectChanged(key, idx) => {
                if let Some(slot) = self.ext_values.iter_mut().find(|(k, _)| *k == key) {
                    slot.1 = aivpn_common::ui_ext::FieldValue::Select(idx);
                }
            }
            Message::ExtApply => {
                // The descriptor decides whether these values select a
                // transport; `None` means the default one.
                self.ext_transport = self
                    .ext_descriptor
                    .as_ref()
                    .and_then(|d| aivpn_common::ui_ext::apply(d, &self.ext_values));
                self.log_lines.push(if self.ext_transport.is_some() {
                    "Settings applied — will take effect on next connect".into()
                } else {
                    "Settings applied — using default transport".into()
                });
            }
            Message::ToggleBootstrapPanel => {
                self.bootstrap_open = !self.bootstrap_open;
            }
            Message::BootstrapCdnUrlChanged(s) => {
                self.settings.bootstrap_cdn_url = s;
                self.settings.save();
            }
            Message::BootstrapTelegramTokenChanged(s) => {
                self.settings.bootstrap_telegram_token = s;
                self.settings.save();
            }
            Message::BootstrapTelegramChatChanged(s) => {
                self.settings.bootstrap_telegram_chat = s;
                self.settings.save();
            }
            Message::BootstrapGithubChanged(s) => {
                self.settings.bootstrap_github = s;
                self.settings.save();
            }
            Message::ServerSigningKeyChanged(s) => {
                self.settings.server_signing_key = s;
                self.settings.save();
            }
            Message::StatsRefresh(s) => {
                // `since` is the client's per-session epoch: a change while
                // Connected means the client silently reconnected in-process
                // (its counters and timer reset together) — surface it.
                if matches!(self.status, VpnStatus::Connected { .. }) {
                    if let (Some(old), Some(new)) = (self.stats.connected_since, s.connected_since)
                    {
                        if old != new {
                            self.push_log(
                                "client session restarted (in-process reconnect)".to_string(),
                            );
                        }
                    }
                }
                self.stats = s;
            }
            Message::TrayEvent(action) => match action {
                crate::tray::TrayAction::Quit => {
                    // Give the client a chance to run its SIGTERM cleanup
                    // (kill-switch rules) before the window closes and
                    // kill_on_drop SIGKILLs it.
                    self.shutdown_child_blocking();
                    return iced::window::get_oldest().then(|opt_id| {
                        if let Some(wid) = opt_id {
                            iced::window::close(wid)
                        } else {
                            Task::none()
                        }
                    });
                }
                crate::tray::TrayAction::Open => {
                    // Restore window from tray (it may have been minimized via close button)
                    return iced::window::get_oldest().then(|opt_id| {
                        if let Some(wid) = opt_id {
                            iced::window::minimize(wid, false)
                        } else {
                            Task::none()
                        }
                    });
                }
                crate::tray::TrayAction::Connect => {
                    // The ksni tray menu is stateless — gate Connect so a
                    // click during an in-flight attempt can't trigger a
                    // second spawn / reconnect storm.
                    if self.pending_connect || matches!(self.status, VpnStatus::Connecting) {
                        return Task::none();
                    }
                    return self.update(Message::Connect);
                }
                crate::tray::TrayAction::Disconnect => {
                    return self.update(Message::Disconnect);
                }
            },
            Message::WindowCloseRequested(id) => {
                return iced::window::minimize(id, true);
            }

            // ── Recording ────────────────────────────────────────────────
            Message::RecordServiceChanged(s) => {
                self.recording_service = s;
            }
            Message::StartRecording => {
                let svc = self.recording_service.trim().to_string();
                let svc = if svc.is_empty() {
                    "custom".to_string()
                } else {
                    svc
                };
                self.recording_state = RecordingState::Active(svc.clone());
                let binary = find_client_binary().ok();
                return Task::perform(
                    async move {
                        if let Some(bin) = binary {
                            let _ = tokio::process::Command::new(&bin)
                                .args(["record", "start", "--service", &svc])
                                .output()
                                .await;
                        }
                    },
                    |_| Message::Noop,
                );
            }
            Message::StopRecording => {
                self.recording_state = RecordingState::Stopping;
                let binary = find_client_binary().ok();
                return Task::perform(
                    async move {
                        if let Some(bin) = binary {
                            let _ = tokio::process::Command::new(&bin)
                                .args(["record", "stop"])
                                .output()
                                .await;
                        }
                    },
                    |_| Message::Noop,
                );
            }
            Message::RecordingPoll(snapshot) => {
                if let Some(snap) = snapshot {
                    match snap.state.as_str() {
                        "recording" => {
                            self.recording_state = RecordingState::Active(snap.service.clone());
                        }
                        "stopping" | "analyzing" => {
                            self.recording_state = RecordingState::Stopping;
                        }
                        "success" => {
                            let details = snap
                                .mask_id
                                .as_deref()
                                .map(|id| format!("Mask saved. ID: {id}"))
                                .unwrap_or_else(|| "Mask saved successfully.".to_string());
                            self.recording_state = RecordingState::Done {
                                succeeded: true,
                                details,
                            };
                        }
                        "failed" => {
                            let reason = snap
                                .message
                                .unwrap_or_else(|| "Recording failed".to_string());
                            self.recording_state = RecordingState::Done {
                                succeeded: false,
                                details: reason,
                            };
                        }
                        _ => {}
                    }
                }
            }
            Message::DismissRecordingResult => {
                self.recording_state = RecordingState::Idle;
            }

            // ── Diagnostics / Bench ──────────────────────────────────────
            Message::RunDiagnostics => {
                if self.bench_running {
                    return Task::none();
                }
                self.bench_running = true;
                self.bench_result = None;
                let key = self
                    .storage
                    .selected_key()
                    .map(|k| k.key.clone())
                    .unwrap_or_default();
                let binary = find_client_binary().ok();
                return Task::perform(
                    async move {
                        let bin = binary?;
                        if key.is_empty() {
                            return Some("No profile selected".to_string());
                        }
                        // Pass the key via env, not argv: argv is world-readable
                        // via /proc/<pid>/cmdline, so `--connection-key <key>`
                        // leaked the embedded PSK to any local user for the
                        // duration of the bench. The client reads
                        // AIVPN_CONNECTION_KEY when -k is absent (main.rs) and
                        // scrubs it from its own env right after parsing.
                        let out = tokio::process::Command::new(&bin)
                            .env("AIVPN_CONNECTION_KEY", &key)
                            .args(["bench", "--duration", "5", "--json"])
                            .output()
                            .await
                            .ok()?;
                        if out.status.success() {
                            let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
                            // extract_server_addr handles IPv6 addresses like [::1]:443 correctly
                            let srv =
                                extract_server_addr(&key).unwrap_or_else(|| "unknown".to_string());
                            Some(format!(
                                "{srv}  P50: {:.0}ms  P95: {:.0}ms  Loss: {:.1}%  Q: {}%",
                                v["latency_p50_ms"].as_f64().unwrap_or(0.0),
                                v["latency_p95_ms"].as_f64().unwrap_or(0.0),
                                v["packet_loss_pct"].as_f64().unwrap_or(0.0),
                                v["quality_score"].as_u64().unwrap_or(0),
                            ))
                        } else {
                            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                            Some(format!(
                                "bench failed: {}",
                                stderr.lines().next().unwrap_or("unknown error")
                            ))
                        }
                    },
                    Message::DiagnosticsResult,
                );
            }
            Message::DiagnosticsResult(result) => {
                self.bench_running = false;
                self.bench_result = result;
            }

            // ── Admin client-management panel ───────────────────────────
            Message::ToggleAdminPanel => {
                self.admin_open = !self.admin_open;
                // G-A1: the panel entry (and its client list) is open to
                // both Viewer (1) and Admin (2) — the server's `authorize()`
                // allows every curated GET route to a Viewer, so listing
                // clients is a read they're entitled to; only the mutating
                // controls inside `view_admin_section` stay Admin-only.
                let mut tasks: Vec<Task<Message>> = Vec::new();
                if self.admin_open
                    && self.admin_role.is_some_and(|r| r >= 1)
                    && self.admin_clients.is_empty()
                    && !self.admin_clients_loading
                {
                    self.admin_clients_loading = true;
                    self.admin_error = None;
                    tasks.push(Task::perform(
                        admin::list_clients(),
                        Message::AdminClientsLoaded,
                    ));
                }
                // G-B1: the exit-node `pick_list` (Admin-only mutating
                // control) is sourced from `GET /api/v1/pool/nodes` — load
                // it here too so the picker has data the first time the
                // add/edit form renders, without requiring the separate
                // Pool Topology panel to have been opened first. Shares
                // `pool_nodes`/`pool_loading` with that panel; whichever
                // opens first populates it for both.
                if self.admin_open
                    && self.admin_role == Some(2)
                    && self.pool_nodes.is_empty()
                    && !self.pool_loading
                {
                    self.pool_loading = true;
                    tasks.push(Task::perform(admin::pool_nodes(), Message::PoolNodesLoaded));
                }
                return Task::batch(tasks);
            }
            Message::AdminRoleLoaded(result) => match result {
                Ok(role) => {
                    self.admin_role = Some(role);
                    let mut tasks: Vec<Task<Message>> = Vec::new();
                    if role >= 1
                        && self.admin_open
                        && self.admin_clients.is_empty()
                        && !self.admin_clients_loading
                    {
                        self.admin_clients_loading = true;
                        tasks.push(Task::perform(
                            admin::list_clients(),
                            Message::AdminClientsLoaded,
                        ));
                    }
                    // G-B1: role wasn't known yet when `ToggleAdminPanel`
                    // ran (it's fetched fresh on every Connected — see the
                    // field doc on `admin_role`), so cover the case where
                    // the panel was already open before Admin confirmed.
                    if role == 2
                        && self.admin_open
                        && self.pool_nodes.is_empty()
                        && !self.pool_loading
                    {
                        self.pool_loading = true;
                        tasks.push(Task::perform(admin::pool_nodes(), Message::PoolNodesLoaded));
                    }
                    return Task::batch(tasks);
                }
                Err(_) => {
                    // Communication failure (older pre-defa271 client
                    // daemon that doesn't support the `role` subcommand at
                    // all, or no reply) — not an error worth surfacing; the
                    // panel entry point just stays hidden (admin_role
                    // remains None). A User/Viewer/Admin role on a current
                    // daemon always gets a numeric reply here (0/1/2), so
                    // this arm is NOT how User/Viewer gets hidden — that's
                    // the `role >= 1` check above and in `view_main`.
                    self.admin_role = None;
                }
            },
            Message::AdminRefreshClients => {
                self.admin_clients_loading = true;
                self.admin_error = None;
                return Task::perform(admin::list_clients(), Message::AdminClientsLoaded);
            }
            Message::AdminClientsLoaded(result) => {
                self.admin_clients_loading = false;
                match result {
                    Ok(clients) => {
                        self.admin_clients = clients;
                        self.admin_error = None;
                    }
                    Err(e) => self.admin_error = Some(e),
                }
            }
            Message::AdminNewNameChanged(s) => self.admin_new_name = s,
            Message::AdminNewOneTimeToggled(b) => self.admin_new_one_time = b,
            Message::AdminNewExpiresChanged(s) => self.admin_new_expires = s,
            Message::AdminNewExitNodeChanged(s) => self.admin_new_exit_node = s,
            Message::AdminNewExitNodePicked(choice) => match choice.selection {
                ExitNodeSelection::Default => self.admin_new_exit_node.clear(),
                ExitNodeSelection::Node(addr) => self.admin_new_exit_node = addr,
                ExitNodeSelection::Custom => {}
            },
            Message::AdminAddClient => {
                let name = self.admin_new_name.trim().to_string();
                if name.is_empty() || self.admin_busy_id.is_some() {
                    return Task::none();
                }
                self.admin_busy_id = Some(String::new()); // sentinel: "adding new"
                self.admin_error = None;
                let args = NewClientArgs {
                    name,
                    one_time: self.admin_new_one_time,
                    expires_at: self.admin_new_expires.trim().to_string(),
                    exit_node: self.admin_new_exit_node.trim().to_string(),
                };
                return Task::perform(admin::add_client(args), Message::AdminAddClientResult);
            }
            Message::AdminAddClientResult(result) => {
                self.admin_busy_id = None;
                match result {
                    Ok(client) => {
                        self.admin_clients.push(client);
                        self.admin_new_name.clear();
                        self.admin_new_one_time = false;
                        self.admin_new_expires.clear();
                        self.admin_new_exit_node.clear();
                        self.admin_error = None;
                    }
                    Err(e) => self.admin_error = Some(e),
                }
            }
            Message::AdminToggleEnabled(id, enabled) => {
                if self.admin_busy_id.is_some() {
                    return Task::none();
                }
                self.admin_busy_id = Some(id.clone());
                let args = EditClientArgs {
                    enabled: Some(enabled),
                    ..Default::default()
                };
                return Task::perform(
                    async move { admin::update_client(&id, args).await },
                    Message::AdminToggleEnabledResult,
                );
            }
            Message::AdminToggleEnabledResult(result) => {
                self.admin_busy_id = None;
                match result {
                    Ok(updated) => {
                        if let Some(c) = self.admin_clients.iter_mut().find(|c| c.id == updated.id)
                        {
                            *c = updated;
                        }
                        self.admin_error = None;
                    }
                    Err(e) => self.admin_error = Some(e),
                }
            }
            Message::AdminStartEdit(id) => {
                if let Some(c) = self.admin_clients.iter().find(|c| c.id == id) {
                    self.admin_edit_id = Some(id);
                    self.admin_edit_name = c.name.clone();
                    self.admin_edit_expires = c.expires_at.clone().unwrap_or_default();
                    self.admin_edit_exit_node = c.exit_node.clone().unwrap_or_default();
                }
            }
            Message::AdminEditNameChanged(s) => self.admin_edit_name = s,
            Message::AdminEditExpiresChanged(s) => self.admin_edit_expires = s,
            Message::AdminEditExitNodeChanged(s) => self.admin_edit_exit_node = s,
            Message::AdminEditExitNodePicked(choice) => match choice.selection {
                ExitNodeSelection::Default => self.admin_edit_exit_node.clear(),
                ExitNodeSelection::Node(addr) => self.admin_edit_exit_node = addr,
                ExitNodeSelection::Custom => {}
            },
            Message::AdminEditCancel => {
                self.admin_edit_id = None;
                self.admin_edit_name.clear();
                self.admin_edit_expires.clear();
                self.admin_edit_exit_node.clear();
            }
            Message::AdminEditSave => {
                if self.admin_busy_id.is_some() {
                    return Task::none();
                }
                if let Some(id) = self.admin_edit_id.clone() {
                    self.admin_busy_id = Some(id.clone());
                    let expires = self.admin_edit_expires.trim().to_string();
                    let exit_node = self.admin_edit_exit_node.trim().to_string();
                    let args = EditClientArgs {
                        name: Some(self.admin_edit_name.trim().to_string()),
                        enabled: None,
                        expires_at: Some(if expires.is_empty() {
                            None
                        } else {
                            Some(expires)
                        }),
                        exit_node: Some(if exit_node.is_empty() {
                            None
                        } else {
                            Some(exit_node)
                        }),
                    };
                    return Task::perform(
                        async move { admin::update_client(&id, args).await },
                        Message::AdminEditResult,
                    );
                }
            }
            Message::AdminEditResult(result) => {
                self.admin_busy_id = None;
                match result {
                    Ok(updated) => {
                        if let Some(c) = self.admin_clients.iter_mut().find(|c| c.id == updated.id)
                        {
                            *c = updated;
                        }
                        self.admin_edit_id = None;
                        self.admin_edit_name.clear();
                        self.admin_edit_expires.clear();
                        self.admin_edit_exit_node.clear();
                        self.admin_error = None;
                    }
                    Err(e) => self.admin_error = Some(e),
                }
            }
            Message::AdminResetDevice(id) => {
                if self.admin_busy_id.is_some() {
                    return Task::none();
                }
                self.admin_busy_id = Some(id.clone());
                return Task::perform(
                    async move {
                        let r = admin::reset_device(&id).await;
                        (id, r)
                    },
                    |(id, r)| Message::AdminResetDeviceResult(id, r),
                );
            }
            Message::AdminResetDeviceResult(id, result) => {
                self.admin_busy_id = None;
                match result {
                    Ok(()) => {
                        self.admin_error = None;
                        self.push_log(format!("[admin] Device binding reset for {id}"));
                        self.admin_clients_loading = true;
                        return Task::perform(admin::list_clients(), Message::AdminClientsLoaded);
                    }
                    Err(e) => self.admin_error = Some(e),
                }
            }
            Message::AdminRevokeRequest(id) => {
                self.admin_pending_revoke = Some(id);
            }
            Message::AdminRevokeCancel => {
                self.admin_pending_revoke = None;
            }
            Message::AdminRevokeConfirm(id) => {
                self.admin_pending_revoke = None;
                if self.admin_busy_id.is_some() {
                    return Task::none();
                }
                self.admin_busy_id = Some(id.clone());
                return Task::perform(
                    async move {
                        let r = admin::revoke_client(&id).await;
                        (id, r)
                    },
                    |(id, r)| Message::AdminRevokeResult(id, r),
                );
            }
            Message::AdminRevokeResult(id, result) => {
                self.admin_busy_id = None;
                match result {
                    Ok(()) => {
                        self.admin_clients.retain(|c| c.id != id);
                        self.push_log(format!("[admin] Revoked client {id}"));
                        self.admin_error = None;
                        if self.admin_key_view.as_ref().is_some_and(|(k, _)| k == &id) {
                            self.admin_key_view = None;
                            self.admin_qr = None;
                        }
                    }
                    Err(e) => self.admin_error = Some(e),
                }
            }
            Message::AdminShowKey(id) => {
                if self.admin_busy_id.is_some() {
                    return Task::none();
                }
                self.admin_busy_id = Some(id.clone());
                return Task::perform(
                    async move {
                        let r = admin::connection_key(&id).await;
                        (id, r)
                    },
                    |(id, r)| Message::AdminKeyLoaded(id, r),
                );
            }
            Message::AdminKeyLoaded(id, result) => {
                self.admin_busy_id = None;
                match result {
                    Ok(key) => {
                        self.admin_key_view = Some((id, key));
                        self.admin_qr = None;
                        self.admin_error = None;
                    }
                    Err(e) => self.admin_error = Some(e),
                }
            }
            Message::AdminCloseKeyView => {
                self.admin_key_view = None;
                self.admin_qr = None;
            }
            Message::AdminCopyKey(text) => {
                return iced::clipboard::write(text);
            }
            Message::AdminSaveKeyToFile => {
                return Task::perform(
                    async {
                        rfd::AsyncFileDialog::new()
                            .set_file_name("aivpn-connection-key.txt")
                            .save_file()
                            .await
                            .map(|h| h.path().to_path_buf())
                    },
                    Message::AdminSaveKeyPathChosen,
                );
            }
            Message::AdminSaveKeyPathChosen(path) => {
                if let (Some(path), Some((_, key))) = (path, &self.admin_key_view) {
                    let _ = std::fs::write(&path, key);
                }
            }
            Message::AdminRequestQr(id) => {
                let text = self
                    .admin_key_view
                    .as_ref()
                    .filter(|(kid, _)| kid == &id)
                    .map(|(_, k)| k.clone());
                let Some(text) = text else {
                    self.admin_error =
                        Some("Load the connection key before generating a QR code".to_string());
                    return Task::none();
                };
                self.admin_qr_loading = Some(id.clone());
                return Task::perform(
                    async move {
                        let r = admin::qr_png(text).await;
                        (id, r)
                    },
                    |(id, r)| Message::AdminQrLoaded(id, r),
                );
            }
            Message::AdminQrLoaded(id, result) => {
                self.admin_qr_loading = None;
                match result {
                    Ok(bytes) => {
                        self.admin_qr = Some((id, image::Handle::from_bytes(bytes)));
                        self.admin_error = None;
                    }
                    Err(e) => self.admin_error = Some(e),
                }
            }
            Message::AdminSaveQrToFile => {
                return Task::perform(
                    async {
                        rfd::AsyncFileDialog::new()
                            .set_file_name("aivpn-connection-qr.png")
                            .save_file()
                            .await
                            .map(|h| h.path().to_path_buf())
                    },
                    Message::AdminSaveQrPathChosen,
                );
            }
            Message::AdminSaveQrPathChosen(path) => {
                if let (Some(path), Some((_, handle))) = (path, &self.admin_qr) {
                    if let image::Handle::Bytes(_, bytes) = handle {
                        let _ = std::fs::write(&path, bytes.as_ref());
                    }
                }
            }

            // ── Pool topology panel (B3) ────────────────────────────────
            Message::TogglePoolPanel => {
                self.pool_open = !self.pool_open;
                if self.pool_open && self.pool_nodes.is_empty() && !self.pool_loading {
                    self.pool_loading = true;
                    self.pool_error = None;
                    return Task::batch([
                        Task::perform(admin::pool_nodes(), Message::PoolNodesLoaded),
                        Task::perform(admin::pool_health(), Message::PoolHealthLoaded),
                    ]);
                }
            }
            Message::PoolRefresh => {
                self.pool_loading = true;
                self.pool_error = None;
                return Task::batch([
                    Task::perform(admin::pool_nodes(), Message::PoolNodesLoaded),
                    Task::perform(admin::pool_health(), Message::PoolHealthLoaded),
                ]);
            }
            Message::PoolNodesLoaded(result) => {
                self.pool_loading = false;
                match result {
                    Ok(nodes) => {
                        self.pool_nodes = nodes;
                        self.pool_error = None;
                    }
                    Err(e) => self.pool_error = Some(e),
                }
            }
            Message::PoolHealthLoaded(result) => match result {
                Ok(health) => {
                    self.pool_health = Some(health);
                    self.pool_error = None;
                }
                Err(e) => self.pool_error = Some(e),
            },

            // ── G-A2: audit-log panel (Viewer + Admin, GET-only) ─────────
            Message::ToggleAuditPanel => {
                self.audit_open = !self.audit_open;
                if self.audit_open && self.audit_entries.is_empty() && !self.audit_loading {
                    self.audit_loading = true;
                    self.audit_error = None;
                    return Task::perform(admin::audit_log(), Message::AuditLogLoaded);
                }
            }
            Message::AuditRefresh => {
                self.audit_loading = true;
                self.audit_error = None;
                return Task::perform(admin::audit_log(), Message::AuditLogLoaded);
            }
            Message::AuditLogLoaded(result) => {
                self.audit_loading = false;
                match result {
                    Ok(view) => {
                        self.audit_entries = view.entries;
                        self.audit_verified = Some(view.verified);
                        self.audit_broken_at = view.broken_at;
                        self.audit_error = None;
                    }
                    Err(e) => self.audit_error = Some(e),
                }
            }

            // ── G-A3: Server Settings (Admin-only apply-with-rollback) ───
            Message::ToggleServerSettingsPanel => {
                self.server_settings_open = !self.server_settings_open;
                let mut tasks: Vec<Task<Message>> = Vec::new();
                // Self-sufficient regardless of whether the Client
                // management / Pool topology panels above have been opened
                // yet — both pickers below need this data, so fetch it on
                // first open here too (both share the same fields, so
                // whichever panel opens first just wins the race).
                if self.server_settings_open && self.admin_role == Some(2) {
                    if self.admin_clients.is_empty() && !self.admin_clients_loading {
                        self.admin_clients_loading = true;
                        self.admin_error = None;
                        tasks.push(Task::perform(
                            admin::list_clients(),
                            Message::AdminClientsLoaded,
                        ));
                    }
                    if self.pool_nodes.is_empty() && !self.pool_loading {
                        self.pool_loading = true;
                        tasks.push(Task::perform(admin::pool_nodes(), Message::PoolNodesLoaded));
                    }
                }
                return Task::batch(tasks);
            }
            Message::ServerSettingsMaskClientPicked(choice) => {
                self.server_settings_mask_client = Some(choice.id);
            }
            Message::ServerSettingsMaskPicked(choice) => {
                self.server_settings_mask_id = Some(choice.id);
            }
            Message::ServerSettingsApplyMask => {
                if !self.server_settings_busy && self.server_settings_pending.is_none() {
                    if let (Some(client), Some(mask)) = (
                        self.server_settings_mask_client.clone(),
                        self.server_settings_mask_id.clone(),
                    ) {
                        self.server_settings_busy = true;
                        self.server_settings_error = None;
                        self.server_settings_rolled_back = false;
                        return Task::perform(
                            admin::apply_config(ConfigSetting::ActiveMask { client, mask }),
                            |result| {
                                Message::ServerSettingsApplyResult(
                                    ServerSettingsPendingKind::ActiveMask,
                                    result,
                                )
                            },
                        );
                    }
                }
            }
            Message::ServerSettingsExitNodeChanged(s) => self.server_settings_exit_node = s,
            Message::ServerSettingsExitNodePicked(choice) => match choice.selection {
                ExitNodeSelection::Default => self.server_settings_exit_node.clear(),
                ExitNodeSelection::Node(addr) => self.server_settings_exit_node = addr,
                ExitNodeSelection::Custom => {}
            },
            Message::ServerSettingsApplyExitNode => {
                if !self.server_settings_busy && self.server_settings_pending.is_none() {
                    self.server_settings_busy = true;
                    self.server_settings_error = None;
                    self.server_settings_rolled_back = false;
                    let trimmed = self.server_settings_exit_node.trim();
                    let addr = if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    };
                    return Task::perform(
                        admin::apply_config(ConfigSetting::ExitNode(addr)),
                        |result| {
                            Message::ServerSettingsApplyResult(
                                ServerSettingsPendingKind::ExitNode,
                                result,
                            )
                        },
                    );
                }
            }
            Message::ServerSettingsApplyResult(kind, result) => {
                self.server_settings_busy = false;
                match result {
                    Ok(token) => {
                        // An apply whose result lands only after the tunnel
                        // dropped is a token from a dead session: the
                        // disconnect handler already cleared the pending
                        // state, and confirming it later (through a NEW
                        // session) races the server's own rollback sweep.
                        // Don't resurrect it — the server rolls the change
                        // back on its own timeline.
                        if matches!(self.status, VpnStatus::Connected { .. }) {
                            self.server_settings_pending = Some((token, kind));
                            self.server_settings_countdown = SERVER_SETTINGS_CONFIRM_WINDOW_SECS;
                            self.server_settings_rolled_back = false;
                            self.server_settings_error = None;
                        }
                    }
                    Err(e) => self.server_settings_error = Some(e),
                }
            }
            Message::ServerSettingsConfirm => {
                if !self.server_settings_busy {
                    if let Some((token, _)) = self.server_settings_pending.clone() {
                        self.server_settings_busy = true;
                        self.server_settings_error = None;
                        return Task::perform(
                            admin::confirm_config(token),
                            Message::ServerSettingsConfirmResult,
                        );
                    }
                }
            }
            Message::ServerSettingsConfirmResult(result) => {
                self.server_settings_busy = false;
                match result {
                    Ok(()) => {
                        self.server_settings_pending = None;
                        self.server_settings_countdown = 0;
                        self.server_settings_rolled_back = false;
                        self.server_settings_error = None;
                    }
                    Err(e) => {
                        // `confirm_config` (`mgmt_service.rs`) returns `404`
                        // for BOTH an unknown token and one the sweep task
                        // already rolled back past its deadline — the
                        // client-side countdown is only an estimate (see
                        // its field doc), so a 404 here is the authoritative
                        // "there is nothing left to confirm" signal: clear
                        // the pending state and show the rolled-back
                        // banner. Any OTHER error (e.g. a transient "no
                        // reply from daemon") leaves `server_settings_pending`
                        // untouched so Confirm can be retried against the
                        // same still-valid token instead of stranding the
                        // user with a banner they can never dismiss.
                        if e.starts_with("HTTP 404") {
                            self.server_settings_pending = None;
                            self.server_settings_countdown = 0;
                            self.server_settings_rolled_back = true;
                        }
                        self.server_settings_error = Some(e);
                    }
                }
            }
            Message::ServerSettingsCountdownTick => {
                if self.server_settings_pending.is_some() {
                    self.server_settings_countdown =
                        self.server_settings_countdown.saturating_sub(1);
                    if self.server_settings_countdown == 0 {
                        self.server_settings_pending = None;
                        self.server_settings_rolled_back = true;
                    }
                }
            }

            // ── C3: "Install server via SSH" wizard ─────────────────────
            Message::ToggleInstallWizard => {
                self.install_wizard_open = !self.install_wizard_open;
            }
            Message::InstallHostChanged(s) => {
                self.install_host = s;
                self.install_fingerprint = None;
                self.install_trusted = false;
            }
            Message::InstallPortChanged(s) => {
                self.install_port = s;
                self.install_fingerprint = None;
                self.install_trusted = false;
            }
            Message::InstallUserChanged(s) => {
                self.install_user = s;
                self.install_fingerprint = None;
                self.install_trusted = false;
            }
            Message::InstallAuthModeToggled(v) => self.install_auth_is_key = v,
            Message::InstallPasswordChanged(s) => self.install_password = s,
            Message::InstallKeyFileChanged(s) => self.install_key_file = s,
            Message::InstallKeyPassphraseChanged(s) => self.install_key_passphrase = s,
            Message::InstallBinarySourceChanged(kind) => self.install_binary_source_kind = kind,
            Message::InstallBinaryUrlChanged(s) => self.install_binary_url = s,
            Message::InstallBinaryFileChanged(s) => self.install_binary_file = s,
            Message::InstallBinaryFileBrowse => {
                return Task::perform(
                    async {
                        rfd::AsyncFileDialog::new()
                            .pick_file()
                            .await
                            .map(|h| h.path().to_path_buf())
                    },
                    Message::InstallBinaryFilePicked,
                );
            }
            Message::InstallBinaryFilePicked(path) => {
                if let Some(path) = path {
                    self.install_binary_file = path.display().to_string();
                }
            }
            Message::InstallServerIpChanged(s) => self.install_server_ip = s,
            Message::InstallServerPortChanged(s) => self.install_server_port = s,
            Message::InstallModeToggled(v) => self.install_mode_docker = v,
            Message::InstallBindDeviceToggled(v) => self.install_bind_device = v,
            Message::InstallShowScript => {
                self.install_script_open = true;
                if self.install_script.is_none() {
                    return Task::perform(
                        install_wizard::fetch_script(),
                        Message::InstallScriptLoaded,
                    );
                }
            }
            Message::InstallScriptLoaded(result) => match result {
                Ok(pair) => {
                    self.install_script = Some(pair);
                    self.install_error = None;
                }
                Err(e) => self.install_error = Some(e),
            },
            Message::InstallHideScript => {
                self.install_script_open = false;
            }
            Message::InstallProbe => {
                let host = self.install_host.trim().to_string();
                if host.is_empty() || self.install_probing {
                    return Task::none();
                }
                let port: u16 = self.install_port.trim().parse().unwrap_or(22);
                let user = if self.install_user.trim().is_empty() {
                    "root".to_string()
                } else {
                    self.install_user.trim().to_string()
                };
                self.install_probing = true;
                self.install_error = None;
                return Task::perform(
                    install_wizard::probe(host, port, user),
                    Message::InstallProbeResult,
                );
            }
            Message::InstallProbeResult(result) => {
                self.install_probing = false;
                match result {
                    Ok(fp) => {
                        self.install_fingerprint = Some(fp);
                        self.install_error = None;
                    }
                    Err(e) => self.install_error = Some(e),
                }
            }
            Message::InstallTrustFingerprint => {
                self.install_trusted = true;
            }
            Message::InstallDistrust => {
                self.install_fingerprint = None;
                self.install_trusted = false;
            }
            Message::InstallStart => {
                if self.install_running || !self.install_trusted {
                    return Task::none();
                }
                let Some(fingerprint) = self.install_fingerprint.clone() else {
                    return Task::none();
                };
                let port: u16 = self.install_port.trim().parse().unwrap_or(22);
                let user = if self.install_user.trim().is_empty() {
                    "root".to_string()
                } else {
                    self.install_user.trim().to_string()
                };
                let auth = if self.install_auth_is_key {
                    let path = self.install_key_file.trim().to_string();
                    if path.is_empty() {
                        self.install_error = Some("Key file path required".to_string());
                        return Task::none();
                    }
                    let pass = self.install_key_passphrase.trim();
                    InstallAuth::KeyFile {
                        path,
                        passphrase: if pass.is_empty() {
                            None
                        } else {
                            Some(pass.to_string())
                        },
                    }
                } else {
                    if self.install_password.is_empty() {
                        self.install_error = Some("Password required".to_string());
                        return Task::none();
                    }
                    InstallAuth::Password(self.install_password.clone())
                };
                let binary = match self.install_binary_source_kind {
                    InstallBinarySourceKind::Default => BinarySourceOpt::Default,
                    InstallBinarySourceKind::Url => {
                        let url = self.install_binary_url.trim().to_string();
                        if url.is_empty() {
                            self.install_error = Some("Binary URL required".to_string());
                            return Task::none();
                        }
                        BinarySourceOpt::Url(url)
                    }
                    InstallBinarySourceKind::LocalFile => {
                        let path = self.install_binary_file.trim().to_string();
                        if path.is_empty() {
                            self.install_error = Some("Binary file path required".to_string());
                            return Task::none();
                        }
                        BinarySourceOpt::LocalFile(path)
                    }
                };
                let server_ip = {
                    let s = self.install_server_ip.trim();
                    if s.is_empty() {
                        None
                    } else {
                        Some(s.to_string())
                    }
                };
                let server_port: Option<u16> = {
                    let s = self.install_server_port.trim();
                    if s.is_empty() {
                        None
                    } else {
                        s.parse().ok()
                    }
                };
                let mode = if self.install_mode_docker {
                    InstallModeOpt::Docker
                } else {
                    InstallModeOpt::Systemd
                };
                let target = InstallTarget {
                    host: self.install_host.trim().to_string(),
                    port,
                    user,
                    fingerprint,
                    auth,
                    binary,
                    mode,
                    server_ip,
                    server_port,
                    bind_device: self.install_bind_device,
                };
                self.install_running = true;
                self.install_error = None;
                self.install_log.clear();
                self.install_exit_code = None;
                self.install_connection_key = None;
                self.install_profile_imported = None;
                self.install_target = Some(target);
            }
            Message::InstallWizardLine(line) => match line {
                InstallLine::Raw(s) => {
                    if !s.trim().is_empty() {
                        self.install_log.push(s);
                    }
                }
                InstallLine::Marker {
                    step,
                    status,
                    code,
                    msg,
                    connection_key,
                } => {
                    let label = install_wizard::describe_step(&step, &self.settings.lang);
                    let mut line = format!("[{status}] {label}");
                    if let Some(c) = &code {
                        line.push_str(&format!(" ({c})"));
                    }
                    if let Some(m) = &msg {
                        line.push_str(&format!(": {m}"));
                    }
                    self.install_log.push(line);
                    if let Some(ck) = connection_key {
                        self.install_connection_key = Some(ck.clone());
                        // G-C1: auto-import — "install → immediately
                        // connected as admin", no mandatory manual click.
                        // Guarded so a re-delivered/duplicate marker line
                        // can never add the same profile twice.
                        if self.install_profile_imported.is_none() {
                            self.import_installed_key(ck);
                        }
                    }
                }
            },
            Message::InstallWizardFinished(code) => {
                self.install_running = false;
                self.install_exit_code = Some(code);
                self.install_target = None;
            }
            Message::InstallWizardSpawnError(e) => {
                self.install_running = false;
                self.install_error = Some(e);
                self.install_target = None;
            }
            Message::InstallReset => {
                self.install_host.clear();
                self.install_port.clear();
                self.install_user.clear();
                self.install_auth_is_key = false;
                self.install_password.clear();
                self.install_key_file.clear();
                self.install_key_passphrase.clear();
                self.install_binary_source_kind = InstallBinarySourceKind::Default;
                self.install_binary_url.clear();
                self.install_binary_file.clear();
                self.install_server_ip.clear();
                self.install_server_port.clear();
                self.install_mode_docker = false;
                self.install_bind_device = true;
                self.install_fingerprint = None;
                self.install_trusted = false;
                self.install_probing = false;
                self.install_error = None;
                self.install_script = None;
                self.install_script_open = false;
                self.install_running = false;
                self.install_target = None;
                self.install_log.clear();
                self.install_connection_key = None;
                self.install_exit_code = None;
                self.install_profile_imported = None;
            }
            // G-C1: retry path only — the happy path already ran this via
            // `import_installed_key` the moment the `##AIVPN` marker carrying
            // `connection_key` arrived (see `InstallWizardLine`). This button
            // only still shows when that auto-import failed (`install_error`
            // set, `install_profile_imported` still `None`).
            Message::InstallImportProfile => {
                if let Some(key) = self.install_connection_key.clone() {
                    self.import_installed_key(key);
                }
            }

            Message::Noop => {}
        }
        Task::none()
    }

    /// G-C1: shared by the auto-import on the installer's final marker and
    /// the manual "Import profile" retry button — decodes `key` and adds it
    /// to `storage` under a name derived from the install target host,
    /// recording success in `install_profile_imported` so the view can show
    /// a confirmation instead of a "click to import" prompt.
    fn import_installed_key(&mut self, key: String) {
        let name = if self.install_host.trim().is_empty() {
            "Installed server".to_string()
        } else {
            self.install_host.trim().to_string()
        };
        match ConnectionKey::from_key_string(name.clone(), key) {
            Ok(conn_key) => match self.storage.add(conn_key) {
                Ok(()) => {
                    self.install_error = None;
                    self.install_profile_imported = Some(name);
                }
                Err(e) => self.install_error = Some(e),
            },
            Err(e) => self.install_error = Some(e),
        }
    }

    pub fn subscription(&self) -> Subscription<Message> {
        let worker_sub = match &self.connection_key {
            Some(key) => {
                let key = key.clone();
                let child_handle = self.child_handle.clone();
                let ext_transport = self.ext_transport.clone();
                let kill_switch = self.launched_kill_switch;
                let adaptive_level = self.settings.adaptive_level;
                let dns_proxy = self.settings.dns_proxy.clone();
                let exclude_routes: Vec<String> = self
                    .settings
                    .exclude_routes
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                let include_routes: Vec<String> = self
                    .settings
                    .include_routes
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                let socks5_enabled = self.settings.socks5_enabled;
                let socks5_addr = self.settings.socks5_addr.clone();
                let full_tunnel = self
                    .storage
                    .selected_key()
                    .map(|k| k.full_tunnel)
                    .unwrap_or(false);
                let mtls_cert = self
                    .storage
                    .selected_key()
                    .and_then(|k| k.mtls_cert.clone());
                let preferred_mask = self.settings.preferred_mask.clone();
                let polymorphic_mask = self.settings.polymorphic_mask;
                let share_mask_feedback = self.settings.share_mask_feedback;
                let receive_mask_hints = self.settings.receive_mask_hints;
                let country_code = self.settings.country_code.clone();
                let bootstrap_cdn_url = self.settings.bootstrap_cdn_url.clone();
                let bootstrap_telegram_token = self.settings.bootstrap_telegram_token.clone();
                let bootstrap_telegram_chat = self.settings.bootstrap_telegram_chat.clone();
                let bootstrap_github = self.settings.bootstrap_github.clone();
                let server_signing_key = self.settings.server_signing_key.clone();
                let lang_clone = self.settings.lang.clone();
                let stream = iced::stream::channel(64, move |mut sender| async move {
                    let binary = match find_client_binary() {
                        Ok(b) => b,
                        Err(e) => {
                            let _ = sender.try_send(Message::StatusReceived(VpnStatus::Error(e)));
                            return;
                        }
                    };

                    let binary = if is_root() {
                        binary
                    } else {
                        match privilege::ensure_capable_binary(&binary, &lang_clone, &mut sender)
                            .await
                        {
                            Ok(p) => p,
                            Err(hint) => {
                                let _ = sender.try_send(Message::LogLine(hint));
                                binary
                            }
                        }
                    };
                    let launch_params = vpn_manager::ClientLaunchParams {
                        full_tunnel,
                        mtls_cert,
                        kill_switch,
                        adaptive_level,
                        dns_proxy,
                        exclude_routes,
                        include_routes,
                        socks5_enabled,
                        socks5_addr,
                        preferred_mask,
                        polymorphic_mask,
                        share_mask_feedback,
                        receive_mask_hints,
                        country_code,
                        bootstrap_cdn_url,
                        bootstrap_telegram_token,
                        bootstrap_telegram_chat,
                        bootstrap_github,
                        server_signing_key,
                    };
                    let mut cmd = vpn_manager::build_client_command(&binary, &key, &launch_params);
                    // The section may have selected an alternative transport.
                    // It travels neutrally: a name plus a base64 parameter blob
                    // this GUI never parses. Absent → the client uses direct UDP.
                    if let Some(cfg) = &ext_transport {
                        use base64::Engine as _;
                        cmd.env("AIVPN_TRANSPORT", cfg.name());
                        cmd.env(
                            "AIVPN_TRANSPORT_PARAMS",
                            base64::engine::general_purpose::STANDARD.encode(cfg.params()),
                        );
                    }

                    let mut child = match cmd.spawn() {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = sender.try_send(Message::StatusReceived(VpnStatus::Error(
                                format!("Launch failed: {e}"),
                            )));
                            return;
                        }
                    };

                    // Take the pipes and publish the child handle immediately —
                    // no awaits or early returns in between. Any path that
                    // drops the Child before it reaches child_handle fires
                    // kill_on_drop's SIGKILL, bypassing the client's
                    // kill-switch cleanup (traffic blackout).
                    let stdout = child.stdout.take();
                    let stderr = child.stderr.take();
                    let child_pid = child.id();
                    match child_handle.lock() {
                        Ok(mut guard) => *guard = Some(child),
                        Err(e) => *e.into_inner() = Some(child),
                    }
                    if let Some(pid) = child_pid {
                        write_client_pidfile(pid);
                    }
                    let (Some(stdout), Some(stderr)) = (stdout, stderr) else {
                        // Should be impossible with piped stdio — terminate
                        // the already-published child gracefully, never drop
                        // it.
                        let taken = match child_handle.lock() {
                            Ok(mut g) => g.take(),
                            Err(e) => e.into_inner().take(),
                        };
                        if let Some(c) = taken {
                            terminate_child_graceful(c, kill_switch);
                        }
                        let _ = sender.try_send(Message::StatusReceived(VpnStatus::Error(
                            "stdout/stderr pipe unavailable".to_string(),
                        )));
                        return;
                    };
                    let _ = sender
                        .send(Message::StatusReceived(VpnStatus::Connecting))
                        .await;

                    let mut out = BufReader::new(stdout).lines();
                    let mut err = BufReader::new(stderr).lines();

                    // Preferred, machine-readable status protocol: newer
                    // clients print "AIVPN-STATUS connected <vpn_ip>" /
                    // "AIVPN-STATUS reconnecting" / "AIVPN-STATUS disconnected"
                    // on stdout. A reconnecting client DEMOTES the UI to
                    // Connecting instead of showing Connected over a dead,
                    // silently-retrying tunnel.
                    let parse_status_line = vpn_manager::parse_status_line;

                    // Fallback heuristic for OLDER clients only: detects the
                    // "Connected to server at ..." / TUN-ready log line. The
                    // client's tracing subscriber writes to stderr (not stdout —
                    // see 9c84bf7, so bench --json's stdout output stays clean),
                    // so this line always arrives via `err`, never `out`; still
                    // checked on both streams in case a future client build ever
                    // emits it differently.
                    let check_connected = |l: &str| -> Option<Message> {
                        if l.contains("Connected") || l.contains("TUN interface") {
                            let ip = l
                                .split_whitespace()
                                .find(|t| t.contains('.') && t.contains('/'))
                                .map(|s| s.to_string())
                                .unwrap_or_default();
                            Some(Message::StatusReceived(VpnStatus::Connected { vpn_ip: ip }))
                        } else {
                            None
                        }
                    };

                    // Once one machine-readable line has been seen the
                    // heuristic is disabled for the rest of the session: it
                    // substring-matches log prose ("Reconnected", pre-handshake
                    // "TUN interface") and would fight the authoritative
                    // protocol.
                    let mut saw_status_line = false;
                    let mut line_messages = |l: &str| -> Vec<Message> {
                        let mut msgs = Vec::new();
                        // 3c: orthogonal to VpnStatus (can co-occur with
                        // Connecting/Connected), so it's dispatched
                        // separately rather than through parse_status_line.
                        if l.trim() == "AIVPN-STATUS bootstrap-fallback" {
                            msgs.push(Message::BootstrapFallbackDetected);
                        }
                        if let Some(status) = parse_status_line(l) {
                            saw_status_line = true;
                            msgs.push(Message::StatusReceived(status));
                        } else if !saw_status_line {
                            msgs.extend(check_connected(l));
                        }
                        msgs
                    };

                    // Drain BOTH streams to their own EOF (same fix as the
                    // install-wizard subscription): on child exit both pipes
                    // EOF and `select!` polls in random order — a bare
                    // `_ => break` on whichever EOF lands first silently
                    // dropped final status lines (e.g. "AIVPN-STATUS
                    // rejected <reason>") still buffered on the OTHER
                    // stream. Status/log messages are `send().await`ed (not
                    // `try_send`) so a burst of log lines can never overflow
                    // the channel and silently drop a status transition.
                    let mut out_done = false;
                    let mut err_done = false;
                    loop {
                        tokio::select! {
                            line = out.next_line(), if !out_done => match line {
                                Ok(Some(l)) => {
                                    for m in line_messages(&l) {
                                        let _ = sender.send(m).await;
                                    }
                                    let _ = sender.send(Message::LogLine(strip_ansi(&l))).await;
                                }
                                _ => out_done = true,
                            },
                            line = err.next_line(), if !err_done => match line {
                                Ok(Some(l)) => {
                                    for m in line_messages(&l) {
                                        let _ = sender.send(m).await;
                                    }
                                    let _ = sender
                                        .send(Message::LogLine(format!("[err] {}", strip_ansi(&l))))
                                        .await;
                                }
                                _ => err_done = true,
                            },
                            else => break,
                        }
                        if out_done && err_done {
                            break;
                        }
                    }

                    // The child has exited; reap it so it doesn't linger as a zombie
                    // until the next Connect/Disconnect. Take it out of the shared
                    // handle first (Disconnect may have already taken it) and wait
                    // without holding the std mutex across the await.
                    let reaped = match child_handle.lock() {
                        Ok(mut g) => g.take(),
                        Err(e) => e.into_inner().take(),
                    };
                    if let Some(mut c) = reaped {
                        let _ = c.wait().await;
                    }
                    remove_client_pidfile();
                    // send().await, not try_send: this terminal status is what
                    // lets the UI leave Connected/Connecting — if it were
                    // dropped on a full channel the status would stick forever.
                    let _ = sender
                        .send(Message::StatusReceived(VpnStatus::Disconnected))
                        .await;
                });
                Subscription::run_with_id("aivpn_worker", stream)
            }
            None => Subscription::none(),
        };

        // C3: SSH server install wizard — streams `ssh-install run`'s stdout
        // while a target is set (mirrors `worker_sub`'s use of
        // `connection_key` above), cleared on Finished/SpawnError so the
        // subprocess is never respawned.
        let install_sub = match &self.install_target {
            Some(target) => install_wizard::install_subscription(target.clone()),
            None => Subscription::none(),
        };

        let stats_stream = iced::stream::channel(4, |mut sender| async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let stats = read_traffic_stats();
                let _ = sender.try_send(Message::StatsRefresh(stats));
            }
        });
        let stats_sub = Subscription::run_with_id("stats_poll", stats_stream);

        let tray_sub = Self::tray_subscription();
        let close_sub = Self::close_subscription();

        // Recording status poll — only when connected and recording or stopping
        let recording_sub = if matches!(
            self.recording_state,
            RecordingState::Active(_) | RecordingState::Stopping
        ) {
            let stream = iced::stream::channel(4, |mut sender| async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    let snap = read_recording_status();
                    let _ = sender.try_send(Message::RecordingPoll(snap));
                }
            });
            Subscription::run_with_id("recording_poll", stream)
        } else {
            Subscription::none()
        };

        // G-A3: once-a-second countdown tick while a Server Settings apply
        // is pending confirmation — only included in the batch while
        // `server_settings_pending.is_some()`, so it starts/stops itself as
        // that flips (same conditional-inclusion pattern as `recording_sub`
        // above) rather than needing its own explicit start/stop messages.
        let server_settings_countdown_sub = if self.server_settings_pending.is_some() {
            let stream = iced::stream::channel(4, |mut sender| async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    let _ = sender.try_send(Message::ServerSettingsCountdownTick);
                }
            });
            Subscription::run_with_id("server_settings_countdown", stream)
        } else {
            Subscription::none()
        };

        Subscription::batch(vec![
            worker_sub,
            stats_sub,
            tray_sub,
            close_sub,
            recording_sub,
            install_sub,
            server_settings_countdown_sub,
        ])
    }

    fn tray_subscription() -> Subscription<Message> {
        let stream = iced::stream::channel(8, |mut sender| async move {
            let mut rx = match crate::tray::spawn().await {
                Ok(rx) => rx,
                Err(e) => {
                    tracing::warn!("Tray icon creation failed: {e}");
                    return;
                }
            };
            while let Some(action) = rx.recv().await {
                let _ = sender.try_send(Message::TrayEvent(action));
            }
        });
        Subscription::run_with_id("tray_ksni", stream)
    }

    fn close_subscription() -> Subscription<Message> {
        iced::event::listen_with(|event, _status, id| {
            if let iced::Event::Window(iced::window::Event::CloseRequested) = event {
                Some(Message::WindowCloseRequested(id))
            } else {
                None
            }
        })
    }

    pub fn theme(&self) -> Theme {
        if self.settings.dark_mode {
            Theme::Dark
        } else {
            Theme::Light
        }
    }

    fn push_log(&mut self, line: String) {
        self.log_lines.push(line);
        if self.log_lines.len() > MAX_LOG_LINES {
            let excess = self.log_lines.len() - MAX_LOG_LINES;
            self.log_lines.drain(0..excess);
        }
    }
}
