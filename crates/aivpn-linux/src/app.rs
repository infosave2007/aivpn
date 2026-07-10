use iced::widget::{
    button, checkbox, column, container, horizontal_rule, pick_list, row, scrollable, text,
    text_input, Space,
};
use iced::{Alignment, Background, Border, Color, Element, Length, Subscription, Task, Theme};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::key_storage::{ConnectionKey, KeyStorage};
use crate::settings::{remove_autostart_entry, write_autostart_entry, AppSettings};
use crate::vpn_manager::{
    extract_server_addr, find_client_binary, find_ip_helper_binary, format_bytes,
    read_recording_status, read_traffic_stats, RecordingSnapshot, TrafficStats, VpnStatus,
};
#[allow(unused_imports)]
use notify_rust;

const MAX_LOG_LINES: usize = 200;

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.as_str().starts_with('[') {
                chars.next();
                for ch in chars.by_ref() {
                    if ch.is_ascii_alphabetic() {
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

fn has_net_admin_cap(path: &std::path::Path) -> bool {
    std::process::Command::new("getcap")
        .arg(path)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("cap_net_admin"))
        .unwrap_or(false)
}

/// Refuse to grant CAP_NET_ADMIN to anything that isn't a root-owned,
/// non-group/other-writable file. Without this, a writable directory ahead
/// of /usr/bin in PATH (or an attacker-planted binary) could get a
/// standing, unprompted capability grant the next time the user clicks
/// through the one pkexec dialog they have a legitimate reason to trust.
#[cfg(unix)]
fn is_trusted_system_binary(path: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(meta) => meta.uid() == 0 && (meta.mode() & 0o022) == 0,
        Err(_) => false,
    }
}
#[cfg(not(unix))]
fn is_trusted_system_binary(_path: &std::path::Path) -> bool {
    false
}

/// Find every distinct `ip` binary reachable on this system: the one PATH
/// would actually resolve for an unqualified `Command::new("ip")` call (what
/// tunnel.rs uses), plus the common hardcoded locations. We grant
/// capabilities to ALL of them — cheap, and removes any ambiguity about
/// which one ends up exec'd. Paths are canonicalized and deduped by real
/// file identity, since /usr/sbin is a symlink to /usr/bin on many distros
/// (so granting both would otherwise setcap the same inode twice).
fn find_ip_binaries() -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();

    // Primary: PATH-based resolution, matching what Command::new("ip") does.
    if let Some(path_env) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_env) {
            let candidate = dir.join("ip");
            if candidate.is_file() {
                found.push(candidate);
                break; // first PATH hit is what actually gets exec'd
            }
        }
    }

    // Fallback / belt-and-suspenders: common hardcoded locations, in case
    // PATH lookup above failed (e.g. restricted PATH in the GUI's env) but
    // the spawned client's own PATH still finds one of these.
    for candidate in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"] {
        let p = std::path::Path::new(candidate);
        if p.exists() {
            found.push(p.to_path_buf());
        }
    }

    let mut seen = std::collections::HashSet::new();
    found
        .into_iter()
        .filter_map(|p| std::fs::canonicalize(&p).ok().or(Some(p)))
        .filter(|p| seen.insert(p.clone()))
        .filter(|p| is_trusted_system_binary(p))
        .collect()
}

/// Shell-quote a single argument for safe interpolation into the combined
/// `pkexec sh -c "..."` setup script below. Mirrors `Tunnel::shell_quote`
/// in crates/aivpn-client/src/tunnel.rs (duplicated rather than shared
/// across crates for a two-line pure function). This script is built
/// entirely from paths WE control (staged file paths under our own
/// persisted dir, hardcoded system destinations) — never from external
/// input — so shell-quoting it is defense in depth, not a load-bearing
/// trust boundary; the load-bearing boundary is the whitelist validator
/// inside the installed `aivpn-ip-helper` binary itself, which is what
/// actually runs with a cached, unattended authorization afterwards.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Fixed, root-owned system install directory for the privileged network
/// helper — NOT under the invoking user's home. A per-user path's parent
/// directory is necessarily writable by that user, so a root-owned FILE at
/// such a path can still be deleted/replaced by that user (directory write
/// permission governs unlink/replace, not file ownership) — and since
/// pkexec's polkit action binding is purely path-string-based, a swapped-in
/// file at that same path would still match the registered
/// `auth_admin_keep` action. A system directory whose entire chain is
/// root-owned and non-group/other-writable closes that hole, and as a
/// bonus makes the destination the SAME for every user on the machine, so
/// the polkit `.policy`'s `exec.path` annotation can be a fixed string
/// (see `AIVPN_POLICY_TEMPLATE` below) with no per-user templating.
const AIVPN_IP_HELPER_INSTALL_DIR: &str = "/usr/local/libexec/aivpn";

/// Stable system-wide path for the privileged network helper.
/// `aivpn-client` computes this exact same path independently (see
/// `Tunnel::ip_helper_path` in `crates/aivpn-client/src/tunnel.rs`) so no
/// IPC/CLI plumbing is needed to tell it where the helper lives.
fn aivpn_ip_helper_path() -> std::path::PathBuf {
    std::path::PathBuf::from(AIVPN_IP_HELPER_INSTALL_DIR).join("aivpn-ip-helper")
}

/// Polkit `.policy` file content for the helper above. The
/// `org.freedesktop.policykit.exec.path` annotation is a FIXED path baked
/// in at build time (see the file itself) — no per-user substitution is
/// needed now that the helper lives at a single system-wide location.
const AIVPN_POLICY_CONTENT: &str =
    include_str!("../../../platforms/linux/polkit/com.aivpn.client.policy");

const AIVPN_POLICY_DEST: &str = "/usr/share/polkit-1/actions/com.aivpn.client.policy";

/// Whether the polkit `.policy` file is installed system-wide with exactly
/// the content we ship. Now that the helper path is fixed system-wide
/// (rather than per-user), this is a simple "does this exact file exist
/// with this exact content" check — no per-user comparison needed. The
/// policy file lives under /usr/share/polkit-1/actions/ which is
/// world-readable by design (polkit needs every session to be able to read
/// action definitions), so this check needs no privilege.
fn policy_is_installed() -> bool {
    std::fs::read_to_string(AIVPN_POLICY_DEST)
        .map(|c| c == AIVPN_POLICY_CONTENT)
        .unwrap_or(false)
}

/// Whether the helper binary itself is installed at its fixed system path,
/// root-owned, non-writable by group/other, and byte-for-byte identical to
/// the `aivpn-ip-helper` binary built alongside this `aivpn-linux` release
/// (found via `find_ip_helper_binary`). Comparing against the freshly
/// built binary (rather than embedding source text) is required now that
/// the helper is a compiled Rust binary, not a shell script.
fn helper_is_installed(helper_path: &std::path::Path, built_helper: &std::path::Path) -> bool {
    if !is_trusted_system_binary(helper_path) {
        return false;
    }
    match (std::fs::read(helper_path), std::fs::read(built_helper)) {
        (Ok(installed), Ok(built)) => installed == built,
        _ => false,
    }
}

/// AppImage binaries run from a fresh /tmp/.mount-* path each launch, so a
/// `setcap` grant doesn't persist there. Copy the binary to a stable
/// per-user location once and grant CAP_NET_ADMIN via a single pkexec
/// prompt, so subsequent connects need no privilege escalation at all.
///
/// The client itself having CAP_NET_ADMIN isn't enough: it shells out to
/// `ip addr`/`ip route` to configure the tunnel, and a spawned child does
/// NOT inherit file capabilities (only "ambient" caps would propagate, and
/// we only grant effective+permitted). So `ip` itself needs the capability
/// too, granted in the same pkexec prompt.
///
/// This same one-shot pkexec prompt ALSO installs the `aivpn-ip-helper`
/// binary and its polkit `.policy` action (see the constants above) to
/// their fixed system-wide locations, so that once this setup has run,
/// `run_ip_batch_privileged` in aivpn-client's tunnel.rs can request root
/// via `pkexec /usr/local/libexec/aivpn/aivpn-ip-helper` instead of
/// `pkexec sh -c "..."` — pkexec then matches the
/// `com.aivpn.client.configure-network` action instead of the generic
/// `org.freedesktop.policykit.exec` one, and that action grants
/// `auth_admin_keep`, so disconnect→reconnect within the polkit session
/// cache window (~5 min by default) needs no further password prompt. The
/// helper itself validates every command against a strict whitelist before
/// executing anything (see `crates/aivpn-client/src/bin/aivpn-ip-helper.rs`),
/// so caching this authorization doesn't hand out more than that fixed
/// command grammar. Folding this into the SAME pkexec invocation as the
/// setcap call means installing the policy costs zero extra prompts over
/// what this function already asked for.
async fn ensure_capable_binary(
    source: &std::path::Path,
    lang: &str,
    sender: &mut iced::futures::channel::mpsc::Sender<Message>,
) -> Result<std::path::PathBuf, String> {
    let persisted = dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("aivpn")
        .join("aivpn-client");
    let helper_dest = aivpn_ip_helper_path();
    let built_helper = find_ip_helper_binary().ok();

    let needs_copy = match (std::fs::metadata(&persisted), std::fs::metadata(source)) {
        (Ok(p), Ok(s)) => p.len() != s.len(),
        _ => true,
    };

    let ip_bins = find_ip_binaries();
    let ip_needs_cap = ip_bins.iter().any(|p| !has_net_admin_cap(p));

    let policy_setup_needed = match &built_helper {
        Some(built) => !helper_is_installed(&helper_dest, built) || !policy_is_installed(),
        // No built aivpn-ip-helper binary found alongside aivpn-linux
        // (e.g. an older release tarball) — nothing to install; the
        // client will simply fall back to `pkexec sh -c "..."` at
        // connect time. Don't block on it, and don't error out.
        None => false,
    };

    let _ = sender.try_send(Message::LogLine(format!(
        "[diag] persisted={} needs_copy={} client_has_cap={} ip_bins={:?} ip_needs_cap={} \
         helper_dest={} built_helper={:?} policy_setup_needed={}",
        persisted.display(),
        needs_copy,
        has_net_admin_cap(&persisted),
        ip_bins,
        ip_needs_cap,
        helper_dest.display(),
        built_helper,
        policy_setup_needed
    )));

    if needs_copy || !has_net_admin_cap(&persisted) || ip_needs_cap || policy_setup_needed {
        if let Some(parent) = persisted.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::copy(source, &persisted).is_err() {
            return Err(if lang == "ru" {
                "[!] Не удалось скопировать клиент для выдачи прав".to_string()
            } else {
                "[!] Failed to copy client binary for capability grant".to_string()
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&persisted) {
                let mut perm = meta.permissions();
                perm.set_mode(0o755);
                let _ = std::fs::set_permissions(&persisted, perm);
            }
        }

        // Stage the helper binary + policy file as plain, unprivileged
        // files in our own (user-owned) persisted dir. The privileged step
        // below only ever moves/chowns *paths* we already fully control the
        // literal bytes of — the helper's own bytes come straight from the
        // build output (never generated/templated), and the policy's only
        // "variable" content (the fixed exec.path annotation) is baked in
        // at Rust-compile time via `include_str!`, not substituted here.
        let mut staged_helper = None;
        let mut staged_policy = None;
        if policy_setup_needed {
            if let Some(built) = &built_helper {
                let parent = persisted
                    .parent()
                    .map(std::path::Path::to_path_buf)
                    .unwrap_or_else(|| std::path::PathBuf::from("."));
                let h = parent.join("aivpn-ip-helper.staged");
                let p = parent.join("com.aivpn.client.policy.staged");
                let staged_ok = std::fs::copy(built, &h).is_ok()
                    && std::fs::write(&p, AIVPN_POLICY_CONTENT).is_ok();
                if !staged_ok {
                    let _ = sender.try_send(Message::LogLine(
                        "[diag] failed to stage aivpn-ip-helper/policy files; skipping polkit \
                         setup this run (will retry next connect)"
                            .to_string(),
                    ));
                } else {
                    staged_helper = Some(h);
                    staged_policy = Some(p);
                }
            }
        }

        let mut script_parts: Vec<String> = Vec::new();
        let mut setcap_cmd = vec!["setcap".to_string(), "cap_net_admin+ep".to_string()];
        setcap_cmd.push(shell_quote(&persisted.to_string_lossy()));
        for ip in &ip_bins {
            setcap_cmd.push("cap_net_admin+ep".to_string());
            setcap_cmd.push(shell_quote(&ip.to_string_lossy()));
        }
        script_parts.push(setcap_cmd.join(" "));

        if let (Some(h), Some(p)) = (&staged_helper, &staged_policy) {
            // Create the helper's root-owned parent directory as part of
            // this SAME privileged step (costs zero extra prompts): mode
            // 0755, root:root, so no unprivileged process can ever plant a
            // substitute file at the helper's exact install path — closing
            // the path-hijacking hole a per-user (user-writable parent
            // directory) install location would have.
            script_parts.push(format!(
                "install -d -m 0755 -o root -g root {}",
                shell_quote(AIVPN_IP_HELPER_INSTALL_DIR)
            ));
            script_parts.push(format!(
                "install -m 0755 -o root -g root {} {}",
                shell_quote(&h.to_string_lossy()),
                shell_quote(&helper_dest.to_string_lossy())
            ));
            script_parts.push(format!(
                "mkdir -p {}",
                shell_quote("/usr/share/polkit-1/actions")
            ));
            script_parts.push(format!(
                "install -m 0644 -o root -g root {} {}",
                shell_quote(&p.to_string_lossy()),
                shell_quote(AIVPN_POLICY_DEST)
            ));
            script_parts.push(format!(
                "rm -f {} {}",
                shell_quote(&h.to_string_lossy()),
                shell_quote(&p.to_string_lossy())
            ));
        }

        let script = script_parts.join(" && ");
        let setcap = tokio::process::Command::new("pkexec")
            .arg("sh")
            .arg("-c")
            .arg(&script)
            .status()
            .await;
        match setcap {
            Ok(s) if s.success() => {
                let client_ok = has_net_admin_cap(&persisted);
                let ip_status: Vec<String> = ip_bins
                    .iter()
                    .map(|p| format!("{}={}", p.display(), has_net_admin_cap(p)))
                    .collect();
                let helper_ok = built_helper
                    .as_ref()
                    .map(|b| helper_is_installed(&helper_dest, b))
                    .unwrap_or(false);
                let policy_ok = policy_is_installed();
                let _ = sender.try_send(Message::LogLine(format!(
                    "[diag] pkexec setup exit ok; verify client_cap={client_ok} ip_caps={ip_status:?} \
                     helper_installed={helper_ok} policy_installed={policy_ok}"
                )));
            }
            Ok(s) => {
                let _ = sender.try_send(Message::LogLine(format!(
                    "[diag] pkexec setup exited with status {s}"
                )));
                return Err(if lang == "ru" {
                    "[!] Не удалось выдать права (отменено или pkexec недоступен). Подключение от имени обычного пользователя может не работать.".to_string()
                } else {
                    "[!] Failed to grant capabilities (cancelled or pkexec unavailable). Connecting as a regular user may not work.".to_string()
                });
            }
            Err(e) => {
                let _ = sender.try_send(Message::LogLine(format!(
                    "[diag] pkexec failed to spawn: {e}"
                )));
                return Err(if lang == "ru" {
                    "[!] Не удалось выдать права (отменено или pkexec недоступен). Подключение от имени обычного пользователя может не работать.".to_string()
                } else {
                    "[!] Failed to grant capabilities (cancelled or pkexec unavailable). Connecting as a regular user may not work.".to_string()
                });
            }
        }
    }

    Ok(persisted)
}

#[derive(Debug, Clone, PartialEq)]
pub enum RecordingState {
    Idle,
    Active(String), // service name
    Stopping,
    Done { succeeded: bool, details: String },
}

#[derive(Debug, Clone)]
pub enum Message {
    Connect,
    /// The previous aivpn-client child has fully exited (reconnect path):
    /// its SIGTERM cleanup — route restore, kill-switch removal — is done,
    /// so it is now safe to spawn the new client.
    OldClientReaped,
    Disconnect,
    StatusReceived(VpnStatus),
    LogLine(String),
    ClearLog,
    SelectProfile(usize),
    ShowAddDialog,
    ShowEditDialog(usize),
    DlgNameChanged(String),
    DlgKeyChanged(String),
    DlgMtlsCertChanged(String),
    DlgFullTunnelToggled(bool),
    DlgSave,
    DlgCancel,
    RemoveProfile(usize),
    ToggleTheme,
    ToggleLang,
    ToggleKillSwitch(bool),
    AdaptiveLevelChanged(AdaptiveOption),
    DnsProxyChanged(String),
    ExcludeRoutesChanged(String),
    IncludeRoutesChanged(String),
    ToggleSocks5(bool),
    Socks5AddrChanged(String),
    StatsRefresh(TrafficStats),
    ToggleAutostart(bool),
    MaskOptionChanged(String),
    TogglePolymorphicMask(bool),
    ToggleShareMaskFeedback(bool),
    ToggleReceiveMaskHints(bool),
    CountryCodeChanged(String),
    TrayEvent(crate::tray::TrayAction),
    WindowCloseRequested(iced::window::Id),
    // Bootstrap descriptor discovery (advanced/operator settings)
    ToggleBootstrapPanel,
    BootstrapCdnUrlChanged(String),
    BootstrapTelegramTokenChanged(String),
    BootstrapTelegramChatChanged(String),
    BootstrapGithubChanged(String),
    ServerSigningKeyChanged(String),
    // Recording
    RecordServiceChanged(String),
    StartRecording,
    StopRecording,
    RecordingPoll(Option<RecordingSnapshot>),
    DismissRecordingResult,
    // Bench / Diagnostics
    RunDiagnostics,
    DiagnosticsResult(Option<String>),
    // Log panel
    ToggleLogPanel,
    SaveLog,
    SaveLogPathChosen(Option<std::path::PathBuf>),
    // Misc
    Noop,
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
fn mask_choices_from_catalog(lang: &str) -> Option<Vec<MaskChoice>> {
    for path in mask_catalog_file_paths() {
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
        return Some(choices);
    }
    None
}

#[derive(Debug, Clone, PartialEq)]
enum DialogMode {
    None,
    Add,
    Edit(usize),
}

fn t<'a>(lang: &str, key: &'a str) -> &'a str {
    if lang != "ru" {
        return key;
    }
    match key {
        "Disconnected" => "Отключено",
        "Connecting..." => "Подключение...",
        "Connect" => "Подключить",
        "Disconnect" => "Отключить",
        "No profiles - add one below" => "Нет профилей - добавьте ниже",
        "Select a profile below" => "Выберите профиль",
        "Profiles" => "Профили",
        "+ Add" => "+ Добавить",
        "Edit" => "Ред.",
        "Diagnostics" => "Диагностика",
        "Running diagnostics..." => "Диагностика...",
        "Adaptive mode" => "Адаптивный режим",
        "Mask profile" => "Маска трафика",
        "Polymorphic (per-session unique shape)" => "Полиморфизм (уникальная форма на сессию)",
        "Each session gets a unique variant of the selected mask. Not used with \"Auto\"." => {
            "Каждая сессия получает уникальный вариант выбранной маски. Недоступно для \"Авто\"."
        }
        "Share blocked-mask feedback" => "Делиться данными о заблокированных масках",
        "Receive mask hints for my region" => "Получать подсказки масок для моего региона",
        "Country code" => "Код страны",
        "Kill switch" => "Kill switch",
        "Start on login" => "Автозапуск",
        "DNS proxy" => "DNS прокси",
        "Exclude routes" => "Исключить маршруты",
        "Include routes only" => "Только эти маршруты",
        "SOCKS5 proxy" => "SOCKS5 прокси",
        "Device key path" => "Путь к ключу",
        "Log" => "Лог",
        "Clear" => "Очистить",
        "No output yet" => "Нет вывода",
        "Record New Mask" => "Запись маски",
        "Start Recording" => "Записать",
        "Stop" => "Стоп",
        "Dismiss" => "Закрыть",
        "Recording:" => "Запись:",
        "Stopping recording..." => "Остановка...",
        "Add Profile" => "Добавить профиль",
        "Edit Profile" => "Изменить профиль",
        "Name" => "Имя",
        "Connection key" => "Ключ подключения",
        "mTLS cert path (optional)" => "mTLS путь (необязательно)",
        "Save" => "Сохранить",
        "Cancel" => "Отмена",
        "Bootstrap (advanced)" => "Bootstrap (для опытных)",
        "Bootstrap CDN URL" => "CDN-адрес bootstrap",
        "Bootstrap Telegram token" => "Токен Telegram-бота bootstrap",
        "Bootstrap Telegram chat" => "Chat/канал Telegram bootstrap",
        "Bootstrap GitHub repo" => "GitHub-репозиторий bootstrap",
        "Server signing key" => "Ключ подписи сервера",
        _ => key,
    }
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
    child_handle: Arc<Mutex<Option<tokio::process::Child>>>,
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
}

impl App {
    pub fn new() -> (Self, Task<Message>) {
        let settings = AppSettings::load();
        let storage = KeyStorage::load();
        (
            Self {
                storage,
                settings,
                status: VpnStatus::Disconnected,
                log_lines: Vec::new(),
                connection_key: None,
                pending_connect: false,
                child_handle: Arc::new(Mutex::new(None)),
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
            },
            Task::none(),
        )
    }

    /// Blocking graceful teardown for app exit (tray Quit). Async tasks are
    /// dropped when the runtime shuts down, so wait here on the UI thread
    /// (bounded) for the client's SIGTERM cleanup — kill-switch firewall
    /// rules, routes — to finish before kill_on_drop's SIGKILL fires.
    fn shutdown_child_blocking(&mut self) {
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
                Ok(Some(_)) => return,
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
        if self.settings.kill_switch {
            spawn_kill_switch_clear();
        }
    }

    pub fn update(&mut self, msg: Message) -> Task<Message> {
        match msg {
            Message::Connect => {
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
                            terminate_child_wait(child, self.settings.kill_switch, true),
                            |_| Message::OldClientReaped,
                        );
                    }
                    if self.pending_connect {
                        // A reap from a previous reconnect is still in flight;
                        // OldClientReaped will spawn the client with the
                        // currently selected profile when it lands.
                        return Task::none();
                    }
                    self.connection_key = Some(key);
                } else {
                    self.push_log("No profile selected".to_string());
                }
            }
            Message::OldClientReaped => {
                // Old client fully exited and any inline kill-switch clear has
                // completed — safe to start the new client now.
                if self.pending_connect {
                    self.pending_connect = false;
                    if let Some(k) = self.storage.selected_key() {
                        self.connection_key = Some(k.key.clone());
                    } else {
                        self.status = VpnStatus::Disconnected;
                    }
                }
            }
            Message::Disconnect => {
                self.pending_connect = false;
                self.connection_key = None;
                // Recover from a poisoned mutex so the kill() always executes.
                let mut guard = match self.child_handle.lock() {
                    Ok(g) => g,
                    Err(e) => e.into_inner(),
                };
                if let Some(child) = guard.take() {
                    // SIGTERM (not SIGKILL) so the client clears its
                    // kill-switch firewall rules; reaped on a background task.
                    terminate_child_graceful(child, self.settings.kill_switch);
                }
                drop(guard);
                self.status = VpnStatus::Disconnected;
                self.push_log("Disconnected".to_string());
            }
            Message::StatusReceived(s) => {
                // While a reconnect waits for the old client's reap, the old
                // (cancelled) worker stream may still deliver a stale terminal
                // status; ignore it so it can't overwrite "Connecting".
                if self.pending_connect
                    && matches!(s, VpnStatus::Disconnected | VpnStatus::Error(_))
                {
                    return Task::none();
                }
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
                }
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

            Message::Noop => {}
        }
        Task::none()
    }

    pub fn view(&self) -> Element<'_, Message> {
        if self.dialog != DialogMode::None {
            return self.view_dialog();
        }
        self.view_main()
    }

    fn view_main(&self) -> Element<'_, Message> {
        let is_dark = self.settings.dark_mode;
        let lang = self.settings.lang.as_str();

        // Adaptive palette — grey tones that contrast in both light and dark themes
        let muted = if is_dark {
            Color::from_rgb(0.62, 0.64, 0.70)
        } else {
            Color::from_rgb(0.43, 0.45, 0.50)
        };
        // Card surface must visibly stand out from the window background.
        // iced Theme::Dark background ≈ rgb(0.20, 0.20, 0.20); card at 0.27 gives clear delta.
        let card_bg = if is_dark {
            Color::from_rgb(0.26, 0.27, 0.35)
        } else {
            Color::from_rgb(0.92, 0.93, 0.97)
        };
        let card_border_color = if is_dark {
            Color::from_rgba(1.0, 1.0, 1.0, 0.09)
        } else {
            Color::from_rgba(0.0, 0.0, 0.0, 0.07)
        };

        // ── Status colours ────────────────────────────────────────────────────
        let (dot_color, status_str, status_color) = match &self.status {
            VpnStatus::Disconnected => (
                muted,
                t(lang, "Disconnected").to_string(),
                if is_dark {
                    Color::from_rgb(0.82, 0.84, 0.90)
                } else {
                    Color::from_rgb(0.33, 0.35, 0.42)
                },
            ),
            VpnStatus::Connecting => (
                Color::from_rgb(1.0, 0.70, 0.15),
                t(lang, "Connecting...").to_string(),
                Color::from_rgb(1.0, 0.70, 0.15),
            ),
            VpnStatus::Connected { vpn_ip } => (
                Color::from_rgb(0.25, 0.84, 0.36),
                format!(
                    "{}  {vpn_ip}",
                    if lang == "ru" {
                        "Подключено"
                    } else {
                        "Connected"
                    }
                ),
                Color::from_rgb(0.25, 0.84, 0.36),
            ),
            VpnStatus::Error(e) => (
                Color::from_rgb(0.95, 0.28, 0.18),
                format!(
                    "{}: {e}",
                    if lang == "ru" {
                        "Ошибка"
                    } else {
                        "Error"
                    }
                ),
                Color::from_rgb(0.95, 0.28, 0.18),
            ),
        };

        // ── Header ────────────────────────────────────────────────────────────
        // Container-dot avoids Unicode glyph rendering issues on systems with
        // limited fonts — renders as a 10×10 colored circle regardless.
        let dot = container(Space::with_width(0))
            .width(10)
            .height(10)
            .style(move |_: &Theme| container::Style {
                background: Some(Background::Color(dot_color)),
                border: Border {
                    radius: 5.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            });
        let theme_btn = button(if self.settings.dark_mode {
            "Light"
        } else {
            "Dark"
        })
        .on_press(Message::ToggleTheme)
        .style(button::text);
        let lang_btn = button(if lang == "ru" { "EN" } else { "RU" })
            .on_press(Message::ToggleLang)
            .style(button::text);
        let version_label = text(concat!("v", env!("CARGO_PKG_VERSION")))
            .size(11)
            .color(muted);
        let header = row![
            dot,
            Space::with_width(6),
            text("AIVPN").size(17),
            Space::with_width(Length::Fill),
            version_label,
            Space::with_width(4),
            lang_btn,
            Space::with_width(2),
            theme_btn,
        ]
        .align_y(Alignment::Center);

        // ── Status card ───────────────────────────────────────────────────────
        let busy = matches!(
            self.status,
            VpnStatus::Connected { .. } | VpnStatus::Connecting
        );
        let is_connected = matches!(self.status, VpnStatus::Connected { .. });
        let has_profile = self.storage.selected_key().is_some();

        let profile_hint: Element<Message> = if let Some(k) = self.storage.selected_key() {
            text(format!("-> {}", k.name)).size(11).color(muted).into()
        } else if self.storage.keys.is_empty() {
            text(t(lang, "No profiles - add one below"))
                .size(11)
                .color(Color::from_rgb(1.0, 0.65, 0.15))
                .into()
        } else {
            text(t(lang, "Select a profile below"))
                .size(11)
                .color(Color::from_rgb(1.0, 0.65, 0.15))
                .into()
        };

        let conn_btn: Element<Message> = if busy {
            button(text(t(lang, "Disconnect")).size(13))
                .on_press(Message::Disconnect)
                .style(button::danger)
                .padding([6, 14])
                .into()
        } else {
            let b = button(text(t(lang, "Connect")).size(13))
                .style(button::primary)
                .padding([6, 14]);
            if has_profile {
                b.on_press(Message::Connect).into()
            } else {
                b.into()
            }
        };

        let traffic_row: Element<Message> = if is_connected {
            row![
                text(format!("RX {}", format_bytes(self.stats.bytes_received)))
                    .size(11)
                    .color(muted),
                Space::with_width(6),
                text(format!("TX {}", format_bytes(self.stats.bytes_sent)))
                    .size(11)
                    .color(muted),
            ]
            .align_y(Alignment::Center)
            .into()
        } else {
            profile_hint
        };

        let status_card = container(
            row![
                text(status_str).color(status_color).size(14),
                Space::with_width(8),
                traffic_row,
                Space::with_width(Length::Fill),
                conn_btn,
            ]
            .align_y(Alignment::Center),
        )
        .style(move |_theme: &Theme| container::Style {
            background: Some(Background::Color(card_bg)),
            border: Border {
                radius: 8.0.into(),
                width: 1.0,
                color: card_border_color,
            },
            ..Default::default()
        })
        .padding([10, 12])
        .width(Length::Fill);

        // ── Profiles ──────────────────────────────────────────────────────────
        let profiles_header = row![
            text(t(lang, "Profiles")).size(14),
            Space::with_width(Length::Fill),
            button(t(lang, "+ Add"))
                .on_press(Message::ShowAddDialog)
                .style(button::text),
        ]
        .align_y(Alignment::Center);

        let profile_rows: Vec<Element<Message>> = self
            .storage
            .keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let is_selected = self.storage.selected == Some(i);
                let name_text = text(&k.name).size(13);
                let addr_text = text(if k.server_addr.is_empty() {
                    "-"
                } else {
                    &k.server_addr
                })
                .size(11)
                .color(muted);
                let profile_col = column![name_text, addr_text].spacing(1);

                let edit_btn = button(t(lang, "Edit"))
                    .on_press(Message::ShowEditDialog(i))
                    .style(button::text);
                let del_btn = button("x")
                    .on_press(Message::RemoveProfile(i))
                    .style(button::text);

                let row_content: Element<Message> = row![
                    profile_col,
                    Space::with_width(Length::Fill),
                    edit_btn,
                    del_btn,
                ]
                .spacing(4)
                .align_y(Alignment::Center)
                .into();

                if is_selected {
                    container(row_content)
                        .padding([6, 8])
                        .width(Length::Fill)
                        .style(|theme: &Theme| {
                            let palette = theme.extended_palette();
                            container::Style {
                                background: Some(Background::Color(palette.primary.weak.color)),
                                border: Border {
                                    radius: 6.0.into(),
                                    ..Default::default()
                                },
                                ..Default::default()
                            }
                        })
                        .into()
                } else {
                    button(row_content)
                        .on_press(Message::SelectProfile(i))
                        .width(Length::Fill)
                        .style(button::text)
                        .padding([6, 8])
                        .into()
                }
            })
            .collect();

        let profile_list_h = ((self.storage.keys.len() * 46) + 8).max(46).min(180) as u16;
        let profiles_list = container(
            scrollable(
                container(column(profile_rows).spacing(2))
                    .width(Length::Fill)
                    .padding(4),
            )
            .height(profile_list_h),
        )
        .style(|theme: &Theme| {
            let palette = theme.extended_palette();
            container::Style {
                border: Border {
                    radius: 6.0.into(),
                    width: 1.0,
                    color: palette.background.weak.color,
                },
                ..Default::default()
            }
        })
        .width(Length::Fill);
        // ── Recording (visible when connected) ────────────────────────────────
        let recording_section: Element<Message> =
            if matches!(self.status, VpnStatus::Connected { .. }) {
                match &self.recording_state {
                    RecordingState::Done { succeeded, details } => {
                        let color = if *succeeded {
                            Color::from_rgb(0.2, 0.75, 0.3)
                        } else {
                            Color::from_rgb(0.9, 0.2, 0.1)
                        };
                        column![
                            text(t(lang, "Record New Mask")).size(13),
                            row![
                                text(details).color(color).size(12),
                                Space::with_width(Length::Fill),
                                button(t(lang, "Dismiss"))
                                    .on_press(Message::DismissRecordingResult)
                                    .style(button::text),
                            ]
                            .align_y(Alignment::Center),
                        ]
                        .spacing(4)
                        .into()
                    }
                    RecordingState::Active(svc) => row![
                        text(format!("{} {svc}", t(lang, "Recording:")))
                            .color(Color::from_rgb(0.9, 0.2, 0.1))
                            .size(13),
                        Space::with_width(Length::Fill),
                        button(t(lang, "Stop"))
                            .on_press(Message::StopRecording)
                            .style(button::danger),
                    ]
                    .align_y(Alignment::Center)
                    .into(),
                    RecordingState::Stopping => row![text(t(lang, "Stopping recording..."))
                        .color(Color::from_rgb(0.9, 0.6, 0.1))
                        .size(13),]
                    .into(),
                    RecordingState::Idle => column![
                        text(t(lang, "Record New Mask")).size(13),
                        row![
                            text_input("Service name", &self.recording_service)
                                .on_input(Message::RecordServiceChanged)
                                .width(180),
                            Space::with_width(8),
                            button(t(lang, "Start Recording")).on_press(Message::StartRecording),
                        ]
                        .align_y(Alignment::Center),
                    ]
                    .spacing(4)
                    .into(),
                }
            } else {
                Space::with_height(0).into()
            };

        // Only frame the recording area with its own trailing separator when
        // there is something to show (connected). Disconnected, the section is
        // empty, so a single separator sits between SOCKS5 and Bootstrap rather
        // than two with a blank gap between them.
        let recording_block: Element<Message> =
            if matches!(self.status, VpnStatus::Connected { .. }) {
                column![
                    Space::with_height(6),
                    recording_section,
                    Space::with_height(6),
                    horizontal_rule(1),
                ]
                .into()
            } else {
                Space::with_height(0).into()
            };

        // ── Diagnostics / Bench ───────────────────────────────────────────────
        let bench_label: Element<Message> = if self.bench_running {
            text(t(lang, "Running diagnostics..."))
                .color(muted)
                .size(12)
                .into()
        } else if let Some(r) = &self.bench_result {
            text(r).size(12).into()
        } else {
            Space::with_height(0).into()
        };
        let diag_btn = {
            let b = button(t(lang, "Diagnostics")).style(button::secondary);
            if !self.bench_running {
                b.on_press(Message::RunDiagnostics)
            } else {
                b
            }
        };

        let adaptive_opt = AdaptiveOption::from_level(self.settings.adaptive_level);
        let fec_text = if self.settings.adaptive_level >= 2 {
            " [FEC]"
        } else {
            ""
        };
        let fec_badge = text(fec_text)
            .color(Color::from_rgb(0.3, 0.8, 0.5))
            .size(11);
        let adaptive_row = row![
            text(t(lang, "Adaptive mode")).size(13).width(130),
            pick_list(
                AdaptiveOption::all(),
                Some(adaptive_opt.clone()),
                Message::AdaptiveLevelChanged,
            )
            .width(200),
            fec_badge,
        ]
        .spacing(8)
        .align_y(Alignment::Center);
        let adaptive_desc = text(adaptive_opt.desc(lang)).size(11).color(muted);

        let mask_opt = MaskOption::from_str(&self.settings.preferred_mask);
        // Dynamic picker: prefer the server-pushed catalog (which marks
        // auto-generated masks "(авто)"); fall back to the built-in presets
        // until a catalog has been received.
        let mask_choices: Vec<MaskChoice> = mask_choices_from_catalog(lang).unwrap_or_else(|| {
            MaskOption::all()
                .iter()
                .map(|m| MaskChoice {
                    id: m.as_str().to_string(),
                    display: m.label().to_string(),
                })
                .collect()
        });
        let selected_choice = mask_choices
            .iter()
            .find(|c| c.id == self.settings.preferred_mask)
            .cloned()
            .or_else(|| mask_choices.first().cloned());
        let mask_row = row![
            text(t(lang, "Mask profile")).size(13).width(130),
            pick_list(mask_choices, selected_choice, |c: MaskChoice| {
                Message::MaskOptionChanged(c.id)
            })
            .width(200),
        ]
        .spacing(8)
        .align_y(Alignment::Center);
        let mask_desc = text(mask_opt.desc(lang)).size(11).color(muted);

        // Polymorphic masks only make sense with a concrete (non-"auto") base mask —
        // mirrors the Windows/macOS/iOS GUIs, which all disable this control on "auto".
        let mask_is_preset =
            self.settings.preferred_mask != "auto" && !self.settings.preferred_mask.is_empty();
        let polymorphic_row = checkbox(
            t(lang, "Polymorphic (per-session unique shape)"),
            self.settings.polymorphic_mask,
        )
        .on_toggle_maybe(mask_is_preset.then_some(Message::TogglePolymorphicMask));
        let polymorphic_desc = text(t(
            lang,
            "Each session gets a unique variant of the selected mask. Not used with \"Auto\".",
        ))
        .size(11)
        .color(muted);

        // Stack the two toggles vertically: side by side they overflowed a
        // narrow window and wrapped to one letter per line ("плывёт").
        let feedback_row = column![
            checkbox(
                t(lang, "Share blocked-mask feedback"),
                self.settings.share_mask_feedback
            )
            .on_toggle(Message::ToggleShareMaskFeedback),
            checkbox(
                t(lang, "Receive mask hints for my region"),
                self.settings.receive_mask_hints
            )
            .on_toggle(Message::ToggleReceiveMaskHints),
        ]
        .spacing(6);

        let country_code_row = row![
            text(t(lang, "Country code")).size(13).width(130),
            text_input("DE", &self.settings.country_code)
                .on_input(Message::CountryCodeChanged)
                .width(80),
        ]
        .spacing(8)
        .align_y(Alignment::Center);

        let kill_switch_row = checkbox(t(lang, "Kill switch"), self.settings.kill_switch)
            .on_toggle(Message::ToggleKillSwitch);
        let autostart_row = checkbox(t(lang, "Start on login"), self.settings.autostart)
            .on_toggle(Message::ToggleAutostart);

        let dns_row = row![
            text(t(lang, "DNS proxy")).size(13).width(130),
            text_input("127.0.0.1:5300", &self.settings.dns_proxy)
                .on_input(Message::DnsProxyChanged)
                .width(Length::Fill),
        ]
        .spacing(8)
        .align_y(Alignment::Center);

        let routes_row = row![
            text(t(lang, "Exclude routes")).size(13).width(130),
            text_input("10.0.0.0/8, 192.168.0.0/16", &self.settings.exclude_routes)
                .on_input(Message::ExcludeRoutesChanged)
                .width(Length::Fill),
        ]
        .spacing(8)
        .align_y(Alignment::Center);

        let include_routes_row = row![
            text(t(lang, "Include routes only")).size(13).width(130),
            text_input("10.0.0.0/8", &self.settings.include_routes)
                .on_input(Message::IncludeRoutesChanged)
                .width(Length::Fill),
        ]
        .spacing(8)
        .align_y(Alignment::Center);

        let socks5_addr_input: Element<Message> = if self.settings.socks5_enabled {
            text_input("127.0.0.1:1080", &self.settings.socks5_addr)
                .on_input(Message::Socks5AddrChanged)
                .width(Length::Fill)
                .into()
        } else {
            Space::with_width(Length::Fill).into()
        };
        let socks5_row = row![
            checkbox(t(lang, "SOCKS5 proxy"), self.settings.socks5_enabled)
                .on_toggle(Message::ToggleSocks5),
            Space::with_width(8),
            socks5_addr_input,
        ]
        .align_y(Alignment::Center);

        let bootstrap_toggle_label = if self.bootstrap_open {
            format!("[-] {}", t(lang, "Bootstrap (advanced)"))
        } else {
            format!("[+] {}", t(lang, "Bootstrap (advanced)"))
        };
        let bootstrap_header = row![
            button(text(bootstrap_toggle_label))
                .on_press(Message::ToggleBootstrapPanel)
                .style(button::text),
            Space::with_width(Length::Fill),
        ]
        .align_y(Alignment::Center);
        let bootstrap_desc_text = text(bootstrap_desc(lang)).size(11).color(muted);

        let bootstrap_box: Element<Message> = if self.bootstrap_open {
            let cdn_row = row![
                text(t(lang, "Bootstrap CDN URL")).size(13).width(130),
                text_input(
                    "https://cdn.example.com/bootstrap.json",
                    &self.settings.bootstrap_cdn_url
                )
                .on_input(Message::BootstrapCdnUrlChanged)
                .width(Length::Fill),
            ]
            .spacing(8)
            .align_y(Alignment::Center);
            let telegram_token_row = row![
                text(t(lang, "Bootstrap Telegram token"))
                    .size(13)
                    .width(130),
                text_input("123456:ABC-DEF...", &self.settings.bootstrap_telegram_token)
                    .on_input(Message::BootstrapTelegramTokenChanged)
                    .width(Length::Fill),
            ]
            .spacing(8)
            .align_y(Alignment::Center);
            let telegram_chat_row = row![
                text(t(lang, "Bootstrap Telegram chat")).size(13).width(130),
                text_input("@aivpn_channel", &self.settings.bootstrap_telegram_chat)
                    .on_input(Message::BootstrapTelegramChatChanged)
                    .width(Length::Fill),
            ]
            .spacing(8)
            .align_y(Alignment::Center);
            let github_row = row![
                text(t(lang, "Bootstrap GitHub repo")).size(13).width(130),
                text_input("owner/repo", &self.settings.bootstrap_github)
                    .on_input(Message::BootstrapGithubChanged)
                    .width(Length::Fill),
            ]
            .spacing(8)
            .align_y(Alignment::Center);
            let signing_key_row = row![
                text(t(lang, "Server signing key")).size(13).width(130),
                text_input("base64 ed25519 pubkey", &self.settings.server_signing_key)
                    .on_input(Message::ServerSigningKeyChanged)
                    .width(Length::Fill),
            ]
            .spacing(8)
            .align_y(Alignment::Center);
            column![
                bootstrap_desc_text,
                Space::with_height(4),
                cdn_row,
                telegram_token_row,
                telegram_chat_row,
                github_row,
                signing_key_row,
            ]
            .spacing(4)
            .into()
        } else {
            Space::with_height(0).into()
        };

        let log_toggle_label = if self.logs_open {
            if lang == "ru" {
                "[-] Лог"
            } else {
                "[-] Log"
            }
        } else {
            if lang == "ru" {
                "[+] Лог"
            } else {
                "[+] Log"
            }
        };
        let log_header = row![
            button(log_toggle_label)
                .on_press(Message::ToggleLogPanel)
                .style(button::text),
            Space::with_width(Length::Fill),
            button(t(lang, "Clear"))
                .on_press(Message::ClearLog)
                .style(button::text),
            button(if lang == "ru" {
                "Сохранить"
            } else {
                "Save log"
            })
            .on_press(Message::SaveLog)
            .style(button::text),
        ]
        .align_y(Alignment::Center);

        let log_box: Element<Message> = if self.logs_open {
            let log_items: Vec<Element<Message>> = if self.log_lines.is_empty() {
                vec![text(t(lang, "No output yet")).color(muted).into()]
            } else {
                self.log_lines
                    .iter()
                    .map(|l| text(l).size(11).into())
                    .collect()
            };
            scrollable(
                container(column(log_items).spacing(1))
                    .padding(8)
                    .width(Length::Fill),
            )
            .height(160)
            .into()
        } else {
            Space::with_height(0).into()
        };

        // Wrap everything in a scrollable so settings + log are reachable
        // in windows smaller than the full content height.
        container(
            scrollable(
                column![
                    header,
                    Space::with_height(4),
                    horizontal_rule(1),
                    Space::with_height(6),
                    status_card,
                    Space::with_height(8),
                    horizontal_rule(1),
                    Space::with_height(6),
                    profiles_header,
                    Space::with_height(4),
                    profiles_list,
                    Space::with_height(6),
                    row![diag_btn, Space::with_width(8), bench_label].align_y(Alignment::Center),
                    Space::with_height(4),
                    horizontal_rule(1),
                    Space::with_height(6),
                    adaptive_row,
                    adaptive_desc,
                    Space::with_height(2),
                    mask_row,
                    mask_desc,
                    Space::with_height(2),
                    polymorphic_row,
                    polymorphic_desc,
                    Space::with_height(2),
                    feedback_row,
                    country_code_row,
                    Space::with_height(2),
                    row![kill_switch_row, Space::with_width(16), autostart_row]
                        .align_y(Alignment::Center),
                    dns_row,
                    routes_row,
                    include_routes_row,
                    socks5_row,
                    // Single separator after SOCKS5; the recording block adds its
                    // own trailing separator only when connected (see recording_block).
                    Space::with_height(6),
                    horizontal_rule(1),
                    recording_block,
                    Space::with_height(6),
                    bootstrap_header,
                    bootstrap_box,
                    Space::with_height(4),
                    horizontal_rule(1),
                    log_header,
                    log_box,
                    Space::with_height(4),
                ]
                .padding(16)
                .spacing(4),
            )
            .height(Length::Fill),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }

    fn view_dialog(&self) -> Element<'_, Message> {
        let lang = self.settings.lang.as_str();
        let title = match self.dialog {
            DialogMode::Add => t(lang, "Add Profile"),
            DialogMode::Edit(_) => t(lang, "Edit Profile"),
            DialogMode::None => "",
        };

        let name_input =
            text_input("Profile name", &self.dlg_name).on_input(Message::DlgNameChanged);
        let key_input =
            text_input("aivpn:// connection key", &self.dlg_key).on_input(Message::DlgKeyChanged);
        let mtls_input = text_input("mTLS cert path (optional)", &self.dlg_mtls_cert)
            .on_input(Message::DlgMtlsCertChanged);

        let error_row: Element<Message> = if let Some(e) = &self.dlg_error {
            text(e)
                .color(Color::from_rgb(0.9, 0.2, 0.1))
                .size(12)
                .into()
        } else {
            Space::with_height(0).into()
        };

        let buttons: Element<Message> = row![
            button(t(lang, "Save"))
                .on_press(Message::DlgSave)
                .style(button::primary),
            Space::with_width(8),
            button(t(lang, "Cancel")).on_press(Message::DlgCancel),
        ]
        .into();

        let dialog_content = container(
            column![
                text(title).size(16),
                Space::with_height(12),
                text(t(lang, "Name")).size(12),
                name_input,
                Space::with_height(8),
                text(t(lang, "Connection key")).size(12),
                key_input,
                Space::with_height(8),
                text(t(lang, "mTLS cert path (optional)")).size(12),
                mtls_input,
                Space::with_height(6),
                checkbox(
                    if lang == "ru" {
                        "Full tunnel (весь трафик через VPN)"
                    } else {
                        "Full tunnel (route all traffic through VPN)"
                    },
                    self.dlg_full_tunnel,
                )
                .on_toggle(Message::DlgFullTunnelToggled),
                Space::with_height(2),
                error_row,
                Space::with_height(12),
                buttons,
            ]
            .spacing(4)
            .padding(24),
        )
        .style(|theme: &Theme| {
            let palette = theme.extended_palette();
            container::Style {
                background: Some(Background::Color(palette.background.strong.color)),
                border: Border {
                    radius: 8.0.into(),
                    width: 1.0,
                    color: palette.background.weak.color,
                },
                ..Default::default()
            }
        })
        .width(420);

        container(dialog_content)
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(iced::alignment::Horizontal::Center)
            .align_y(iced::alignment::Vertical::Center)
            .into()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        let worker_sub = match &self.connection_key {
            Some(key) => {
                let key = key.clone();
                let child_handle = self.child_handle.clone();
                let kill_switch = self.settings.kill_switch;
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
                        match ensure_capable_binary(&binary, &lang_clone, &mut sender).await {
                            Ok(p) => p,
                            Err(hint) => {
                                let _ = sender.try_send(Message::LogLine(hint));
                                binary
                            }
                        }
                    };
                    let mut cmd = tokio::process::Command::new(&binary);
                    // Ensure the VPN client is killed if this GUI process exits
                    // (e.g. Quit from the tray). Without this, dropping the Child
                    // on shutdown leaves aivpn-client orphaned with the tunnel up.
                    cmd.kill_on_drop(true);
                    // Pass the connection key (which embeds the PSK) via the
                    // environment, NOT argv: /proc/<pid>/cmdline is world-readable
                    // on Linux, so a CLI arg would expose the PSK to every local
                    // user. /proc/<pid>/environ is owner/root-only, and the client
                    // reads AIVPN_CONNECTION_KEY then immediately removes it from
                    // its own environment. Matches the Windows GUI.
                    cmd.env("AIVPN_CONNECTION_KEY", &key);
                    if full_tunnel {
                        cmd.arg("--full-tunnel");
                    }
                    if let Some(ref cert) = mtls_cert {
                        if !cert.is_empty() {
                            cmd.args(["--mtls-cert", cert]);
                        }
                    }
                    if kill_switch {
                        cmd.arg("--kill-switch");
                    }
                    if adaptive_level > 0 {
                        cmd.args(["--adaptive-level", &adaptive_level.to_string()]);
                    }
                    if !dns_proxy.is_empty() {
                        cmd.args(["--dns-proxy", &dns_proxy]);
                    }
                    for route in &exclude_routes {
                        cmd.args(["--exclude-routes", route]);
                    }
                    for route in &include_routes {
                        cmd.args(["--include-routes", route]);
                    }
                    if socks5_enabled && !socks5_addr.is_empty() {
                        cmd.args(["--proxy-listen", &socks5_addr]);
                    }
                    let has_concrete_mask = !preferred_mask.is_empty() && preferred_mask != "auto";
                    if polymorphic_mask && has_concrete_mask {
                        // Polymorphic mode takes precedence: request a per-session
                        // unique variant of the chosen base mask instead of the
                        // fixed preset.
                        cmd.args(["--polymorphic-base", &preferred_mask]);
                    } else if has_concrete_mask {
                        cmd.args(["--preferred-mask", &preferred_mask]);
                    }
                    if share_mask_feedback {
                        cmd.arg("--share-mask-feedback");
                    }
                    if receive_mask_hints {
                        cmd.arg("--receive-mask-hints");
                    }
                    if !country_code.is_empty() {
                        cmd.args(["--country-code", &country_code]);
                    }
                    if !bootstrap_cdn_url.is_empty() {
                        cmd.args(["--bootstrap-cdn-url", &bootstrap_cdn_url]);
                    }
                    if !bootstrap_telegram_token.is_empty() {
                        // Via env, not argv — the token is a real credential and
                        // /proc/<pid>/cmdline is world-readable on Linux.
                        cmd.env("AIVPN_BOOTSTRAP_TELEGRAM_TOKEN", &bootstrap_telegram_token);
                    }
                    if !bootstrap_telegram_chat.is_empty() {
                        cmd.args(["--bootstrap-telegram-chat", &bootstrap_telegram_chat]);
                    }
                    if !bootstrap_github.is_empty() {
                        cmd.args(["--bootstrap-github", &bootstrap_github]);
                    }
                    if !server_signing_key.is_empty() {
                        cmd.args(["--server-signing-key", &server_signing_key]);
                    }
                    cmd.stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped());

                    let mut child = match cmd.spawn() {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = sender.try_send(Message::StatusReceived(VpnStatus::Error(
                                format!("Launch failed: {e}"),
                            )));
                            return;
                        }
                    };

                    let stdout = match child.stdout.take() {
                        Some(s) => s,
                        None => {
                            let _ = sender.try_send(Message::StatusReceived(VpnStatus::Error(
                                "stdout pipe unavailable".to_string(),
                            )));
                            return;
                        }
                    };
                    let stderr = match child.stderr.take() {
                        Some(s) => s,
                        None => {
                            let _ = sender.try_send(Message::StatusReceived(VpnStatus::Error(
                                "stderr pipe unavailable".to_string(),
                            )));
                            return;
                        }
                    };
                    match child_handle.lock() {
                        Ok(mut guard) => *guard = Some(child),
                        Err(e) => *e.into_inner() = Some(child),
                    }
                    let _ = sender.try_send(Message::StatusReceived(VpnStatus::Connecting));

                    let mut out = BufReader::new(stdout).lines();
                    let mut err = BufReader::new(stderr).lines();

                    // Detects the client's "Connected to server at ..." / TUN-ready log line
                    // to flip status to Connected. The client's tracing subscriber writes to
                    // stderr (not stdout — see 9c84bf7, so bench --json's stdout output stays
                    // clean), so this line always arrives via `err`, never `out`; still checked
                    // on both streams in case a future client build ever emits it differently.
                    let check_connected =
                        |sender: &mut iced::futures::channel::mpsc::Sender<Message>, l: &str| {
                            if l.contains("Connected") || l.contains("TUN interface") {
                                let ip = l
                                    .split_whitespace()
                                    .find(|t| t.contains('.') && t.contains('/'))
                                    .map(|s| s.to_string())
                                    .unwrap_or_default();
                                let _ = sender.try_send(Message::StatusReceived(
                                    VpnStatus::Connected { vpn_ip: ip },
                                ));
                            }
                        };

                    loop {
                        tokio::select! {
                            line = out.next_line() => match line {
                                Ok(Some(l)) => {
                                    check_connected(&mut sender, &l);
                                    let _ = sender.try_send(Message::LogLine(strip_ansi(&l)));
                                }
                                _ => break,
                            },
                            line = err.next_line() => match line {
                                Ok(Some(l)) => {
                                    check_connected(&mut sender, &l);
                                    let _ = sender
                                        .try_send(Message::LogLine(format!("[err] {}", strip_ansi(&l))));
                                }
                                _ => break,
                            },
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
                    let _ = sender.try_send(Message::StatusReceived(VpnStatus::Disconnected));
                });
                Subscription::run_with_id("aivpn_worker", stream)
            }
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

        Subscription::batch(vec![
            worker_sub,
            stats_sub,
            tray_sub,
            close_sub,
            recording_sub,
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
