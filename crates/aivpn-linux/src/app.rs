use iced::widget::{
    button, checkbox, column, container, horizontal_rule, image, pick_list, row, scrollable, text,
    text_input, Space,
};
use iced::{Alignment, Background, Border, Color, Element, Length, Subscription, Task, Theme};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::admin::{self, ClientRecord, EditClientArgs, NewClientArgs, PoolHealth, PoolNode};
use crate::install_wizard::{self, InstallAuth, InstallLine, InstallModeOpt, InstallTarget};
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

/// CAP_NET_ADMIN check via the `security.capability` xattr read directly:
/// getcap(8) lives in libcap2-bin under /usr/sbin and is absent from PATH on
/// stock Debian, which made a shell-out check always-false there (and thus
/// re-prompted through pkexec on every connect).
fn has_net_admin_cap(path: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(cpath) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let mut buf = [0u8; 64];
    let n = unsafe {
        libc::getxattr(
            cpath.as_ptr(),
            c"security.capability".as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    // struct vfs_cap_data: __le32 magic_etc, then data[0].permitted at offset
    // 4 (layout shared by v2 and v3). CAP_NET_ADMIN = bit 12, in data[0]; the
    // EFFECTIVE flag bit in magic_etc is what setcap's `+ep` adds over `+p`.
    if n < 12 {
        return false;
    }
    const VFS_CAP_FLAGS_EFFECTIVE: u32 = 0x1;
    const CAP_NET_ADMIN_MASK: u32 = 1 << 12;
    let magic_etc = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let permitted = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    permitted & CAP_NET_ADMIN_MASK != 0 && magic_etc & VFS_CAP_FLAGS_EFFECTIVE != 0
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

    // Byte-for-byte: a length-only check let a stale persisted copy that
    // happened to match the new build's size keep shadowing it forever.
    let needs_copy = match (std::fs::read(&persisted), std::fs::read(source)) {
        (Ok(p), Ok(s)) => p != s,
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
    /// 3c: the client printed "AIVPN-STATUS bootstrap-fallback" — it gave up
    /// on the descriptor-derived mask after repeated dead handshakes and is
    /// using the built-in default mask instead. Orthogonal to `VpnStatus`
    /// (can be true while Connecting or Connected), so it isn't folded into
    /// that enum.
    BootstrapFallbackDetected,
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
    // ── Admin client-management panel (in-tunnel management API bridge) ────
    ToggleAdminPanel,
    AdminRoleLoaded(Result<u8, String>),
    AdminRefreshClients,
    AdminClientsLoaded(Result<Vec<ClientRecord>, String>),
    AdminNewNameChanged(String),
    AdminNewOneTimeToggled(bool),
    AdminNewExpiresChanged(String),
    AdminNewExitNodeChanged(String),
    AdminAddClient,
    AdminAddClientResult(Result<ClientRecord, String>),
    AdminToggleEnabled(String, bool),
    AdminToggleEnabledResult(Result<ClientRecord, String>),
    AdminStartEdit(String),
    AdminEditNameChanged(String),
    AdminEditExpiresChanged(String),
    AdminEditExitNodeChanged(String),
    AdminEditSave,
    AdminEditCancel,
    AdminEditResult(Result<ClientRecord, String>),
    AdminResetDevice(String),
    AdminResetDeviceResult(String, Result<(), String>),
    AdminRevokeRequest(String),
    AdminRevokeCancel,
    AdminRevokeConfirm(String),
    AdminRevokeResult(String, Result<(), String>),
    AdminShowKey(String),
    AdminKeyLoaded(String, Result<String, String>),
    AdminCloseKeyView,
    AdminCopyKey(String),
    AdminSaveKeyToFile,
    AdminSaveKeyPathChosen(Option<std::path::PathBuf>),
    AdminRequestQr(String),
    AdminQrLoaded(String, Result<Vec<u8>, String>),
    AdminSaveQrToFile,
    AdminSaveQrPathChosen(Option<std::path::PathBuf>),
    // ── Pool topology panel (B3: pool nodes + health, admin-role gated) ────
    TogglePoolPanel,
    PoolRefresh,
    PoolNodesLoaded(Result<Vec<PoolNode>, String>),
    PoolHealthLoaded(Result<PoolHealth, String>),
    // ── C3: "Install server via SSH" wizard ─────────────────────────────
    ToggleInstallWizard,
    InstallHostChanged(String),
    InstallPortChanged(String),
    InstallUserChanged(String),
    InstallAuthModeToggled(bool),
    InstallPasswordChanged(String),
    InstallKeyFileChanged(String),
    InstallKeyPassphraseChanged(String),
    InstallServerIpChanged(String),
    InstallServerPortChanged(String),
    InstallModeToggled(bool),
    InstallBindDeviceToggled(bool),
    InstallShowScript,
    InstallScriptLoaded(Result<(String, String), String>),
    InstallHideScript,
    InstallProbe,
    InstallProbeResult(Result<String, String>),
    InstallTrustFingerprint,
    InstallDistrust,
    InstallStart,
    InstallWizardLine(InstallLine),
    InstallWizardFinished(i32),
    InstallWizardSpawnError(String),
    InstallReset,
    InstallImportProfile,
    // ── C3: server migration wizard (export/install/import) ────────────
    ToggleMigrationWizard,
    MigrationExport,
    MigrationExportResult(Result<Vec<u8>, String>),
    MigrationExportPathChosen(Option<std::path::PathBuf>),
    MigrationImportPick,
    MigrationImportFileChosen(Option<std::path::PathBuf>),
    MigrationImportResult(Result<(), String>),
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
        // 3c: bootstrap-fallback indicator (client fell back to the
        // built-in default mask after repeated dead handshakes).
        "Using built-in mask (fallback)" => "Встроенная маска (аварийный режим)",
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
        // Admin client-management panel
        "Admin — Client Management" => "Админ — управление клиентами",
        "Refresh" => "Обновить",
        "One-time" => "Одноразовый",
        "Adding..." => "Добавление...",
        "Loading..." => "Загрузка...",
        "No clients" => "Нет клиентов",
        "enabled" => "включён",
        "disabled" => "отключён",
        "one-time" => "одноразовый",
        "Confirm revoke?" => "Подтвердить отзыв?",
        "Yes" => "Да",
        "No" => "Нет",
        "Key" => "Ключ",
        "Disable" => "Отключить",
        "Enable" => "Включить",
        "Reset device" => "Сбросить устройство",
        "Revoke" => "Отозвать",
        "Copy" => "Копировать",
        "Show QR" => "Показать QR",
        "Close" => "Закрыть",
        "Generating QR..." => "Генерация QR...",
        "Save QR" => "Сохранить QR",
        "Exit node (optional)" => "Узел выхода (необязательно)",
        "Exit" => "Выход",
        // Pool topology panel (Wave B3)
        "Pool Topology" => "Топология пула",
        "Transport" => "Транспорт",
        "Connected" => "Подключено",
        "Converged" => "Синхронизировано",
        "Partition conflict detected" => "Обнаружен конфликт разделов",
        "Subnet mismatch detected" => "Обнаружено несоответствие подсети",
        "Some peers diverged" => "Некоторые узлы рассинхронизированы",
        "No pool nodes" => "Нет узлов пула",
        "verified" => "проверен",
        "unverified" => "не проверен",
        "connected" => "подключён",
        "offline" => "офлайн",
        "revoked" => "отозван",
        "Last seen" => "Последняя активность",
        "never" => "никогда",
        // C3: SSH server install wizard
        "Install Server via SSH" => "Установка сервера по SSH",
        "Use SSH key instead of password" => "Использовать SSH-ключ вместо пароля",
        "Private key path" => "Путь к приватному ключу",
        "Key passphrase (optional)" => "Пароль ключа (необязательно)",
        "SSH password" => "Пароль SSH",
        "Server IP (optional)" => "IP сервера (необязательно)",
        "Server port (optional)" => "Порт сервера (необязательно)",
        "Bind this device (admin access)" => "Привязать это устройство (доступ администратора)",
        "Show script" => "Показать скрипт",
        "Host key fingerprint" => "Отпечаток ключа хоста",
        "Confirm this is the correct server's key" => "Подтвердите, что это правильный ключ сервера",
        "I trust this key" => "Я доверяю этому ключу",
        "Don't trust" => "Не доверять",
        "Connect & verify host key" => "Подключиться и проверить ключ хоста",
        "Start over" => "Начать заново",
        "Import profile" => "Импортировать профиль",
        "Install finished successfully" => "Установка успешно завершена",
        "Install failed" => "Установка не удалась",
        "Installing..." => "Установка...",
        // C3: migration wizard
        "Server Migration" => "Миграция сервера",
        "Migration guide: 1) export from the old server while connected as admin, 2) install the new server via SSH above, 3) reconnect using the new server's admin profile and import." => {
            "Гид по миграции: 1) экспорт со старого сервера, подключившись как admin; 2) установка нового сервера по SSH выше; 3) переключитесь на admin-профиль нового сервера и импортируйте данные."
        }
        "Export backup from current server" => "Экспортировать резервную копию с текущего сервера",
        "Import backup into current server" => "Импортировать резервную копию на текущий сервер",
        "Install the new server using the wizard above, then reconnect using its admin profile." => {
            "Установите новый сервер через мастер выше, затем переподключитесь под его admin-профилем."
        }
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
    /// Kill-switch flag the CURRENT client was launched with. Teardown paths
    /// consult this, not live settings — toggling the checkbox while
    /// connected must not skip (or invent) a needed `kill-switch clear`.
    launched_kill_switch: bool,
    /// Orphaned aivpn-client adopted at startup from a crashed previous GUI
    /// run: (pid, /proc starttime). Not our child — torn down via
    /// `terminate_adopted_wait`, never wait()ed.
    adopted_client: Option<(u32, u64)>,
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
    // ── C3: server migration wizard (export → install → import) ────────
    migration_open: bool,
    migration_busy: bool,
    migration_error: Option<String>,
    migration_status: String,
    /// Export bytes fetched via `mgmt_call`, held only until the save-file
    /// dialog resolves (or is cancelled, in which case it's just dropped).
    migration_export_bytes: Option<Vec<u8>>,
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
                install_wizard_open: false,
                install_host: String::new(),
                install_port: String::new(),
                install_user: String::new(),
                install_auth_is_key: false,
                install_password: String::new(),
                install_key_file: String::new(),
                install_key_passphrase: String::new(),
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
                migration_open: false,
                migration_busy: false,
                migration_error: None,
                migration_status: String::new(),
                migration_export_bytes: None,
            },
            Task::none(),
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
                    if self.pending_connect {
                        // A reap from a previous reconnect is still in flight;
                        // OldClientReaped will spawn the client with the
                        // currently selected profile when it lands.
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
                if let Some((pid, starttime)) = self.adopted_client.take() {
                    tokio::spawn(terminate_adopted_wait(pid, starttime));
                }
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
                if self.admin_open
                    && self.admin_role == Some(2)
                    && self.admin_clients.is_empty()
                    && !self.admin_clients_loading
                {
                    self.admin_clients_loading = true;
                    self.admin_error = None;
                    return Task::perform(admin::list_clients(), Message::AdminClientsLoaded);
                }
            }
            Message::AdminRoleLoaded(result) => match result {
                Ok(role) => {
                    self.admin_role = Some(role);
                    if role == 2
                        && self.admin_open
                        && self.admin_clients.is_empty()
                        && !self.admin_clients_loading
                    {
                        self.admin_clients_loading = true;
                        return Task::perform(admin::list_clients(), Message::AdminClientsLoaded);
                    }
                }
                Err(_) => {
                    // Older client daemons (pre-defa271) or a User/Viewer
                    // role simply have nothing to report here — not an
                    // error worth surfacing; the panel entry point just
                    // stays hidden (admin_role remains None).
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
                        self.install_connection_key = Some(ck);
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
            }
            Message::InstallImportProfile => {
                if let Some(key) = self.install_connection_key.clone() {
                    let name = if self.install_host.trim().is_empty() {
                        "Installed server".to_string()
                    } else {
                        self.install_host.trim().to_string()
                    };
                    match ConnectionKey::from_key_string(name, key) {
                        Ok(conn_key) => {
                            if let Err(e) = self.storage.add(conn_key) {
                                self.install_error = Some(e);
                            } else {
                                self.install_error = None;
                            }
                        }
                        Err(e) => self.install_error = Some(e),
                    }
                }
            }

            // ── C3: server migration wizard (export → install → import) ──
            Message::ToggleMigrationWizard => {
                self.migration_open = !self.migration_open;
            }
            Message::MigrationExport => {
                if self.migration_busy {
                    return Task::none();
                }
                self.migration_busy = true;
                self.migration_error = None;
                return Task::perform(
                    async {
                        admin::mgmt_call(admin::MgmtMethod::Get, "/api/v1/backup/export", None)
                            .await
                    },
                    |r| Message::MigrationExportResult(r.map(|(_, body)| body)),
                );
            }
            Message::MigrationExportResult(result) => {
                self.migration_busy = false;
                match result {
                    Ok(bytes) => {
                        self.migration_export_bytes = Some(bytes);
                        self.migration_error = None;
                        return Task::perform(
                            async {
                                rfd::AsyncFileDialog::new()
                                    .set_file_name("aivpn-backup.json")
                                    .save_file()
                                    .await
                                    .map(|h| h.path().to_path_buf())
                            },
                            Message::MigrationExportPathChosen,
                        );
                    }
                    Err(e) => self.migration_error = Some(e),
                }
            }
            Message::MigrationExportPathChosen(path) => {
                let bytes = self.migration_export_bytes.take();
                if let (Some(path), Some(bytes)) = (path, bytes) {
                    match std::fs::write(&path, &bytes) {
                        Ok(()) => {
                            self.migration_status = format!("Exported to {}", path.display());
                            self.migration_error = None;
                        }
                        Err(e) => self.migration_error = Some(format!("Failed to write file: {e}")),
                    }
                }
            }
            Message::MigrationImportPick => {
                if self.migration_busy {
                    return Task::none();
                }
                return Task::perform(
                    async {
                        rfd::AsyncFileDialog::new()
                            .pick_file()
                            .await
                            .map(|h| h.path().to_path_buf())
                    },
                    Message::MigrationImportFileChosen,
                );
            }
            Message::MigrationImportFileChosen(path) => {
                let Some(path) = path else {
                    return Task::none();
                };
                let bytes = match std::fs::read(&path) {
                    Ok(b) => b,
                    Err(e) => {
                        self.migration_error = Some(format!("Failed to read file: {e}"));
                        return Task::none();
                    }
                };
                self.migration_busy = true;
                self.migration_error = None;
                return Task::perform(
                    async move {
                        admin::mgmt_call(
                            admin::MgmtMethod::Post,
                            "/api/v1/backup/import",
                            Some(bytes),
                        )
                        .await
                    },
                    |r| Message::MigrationImportResult(r.map(|_| ())),
                );
            }
            Message::MigrationImportResult(result) => {
                self.migration_busy = false;
                match result {
                    Ok(()) => {
                        self.migration_status = "Import successful".to_string();
                        self.migration_error = None;
                    }
                    Err(e) => self.migration_error = Some(e),
                }
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
            VpnStatus::Connected { vpn_ip } => {
                // MEDIUM-HIGH #3 (client parity): elapsed connection time,
                // derived the same way Windows (vpn_manager.rs
                // session_since_ms) and macOS (VPNManager) do — wall-clock
                // now minus the client's session epoch — instead of never
                // showing uptime at all. `connected_since` is already parsed
                // by `read_traffic_stats()`/`parse_traffic_stats()` from the
                // stats file's `since:` key; previously only consulted here
                // to detect a silent in-process reconnect, never displayed.
                let uptime_str = self.stats.connected_since.map(|since_ms| {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(since_ms);
                    let secs = now_ms.saturating_sub(since_ms) / 1000;
                    let h = secs / 3600;
                    let m = (secs % 3600) / 60;
                    let s = secs % 60;
                    if h > 0 {
                        format!("{h}:{m:02}:{s:02}")
                    } else {
                        format!("{m}:{s:02}")
                    }
                });
                let label = if lang == "ru" {
                    "Подключено"
                } else {
                    "Connected"
                };
                let status_str = match &uptime_str {
                    Some(u) => format!("{label}  {vpn_ip}  {u}"),
                    None => format!("{label}  {vpn_ip}"),
                };
                (
                    Color::from_rgb(0.25, 0.84, 0.36),
                    status_str,
                    Color::from_rgb(0.25, 0.84, 0.36),
                )
            }
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
            let mut r = row![
                text(format!("RX {}", format_bytes(self.stats.bytes_received)))
                    .size(11)
                    .color(muted),
                Space::with_width(6),
                text(format!("TX {}", format_bytes(self.stats.bytes_sent)))
                    .size(11)
                    .color(muted),
            ];
            // Live link quality from the client's quality.json (0 = not
            // reported yet / old client).
            if self.stats.quality_score > 0 {
                r = r.push(Space::with_width(6)).push(
                    text(format!("Q {}%", self.stats.quality_score))
                        .size(11)
                        .color(muted),
                );
            }
            r.align_y(Alignment::Center).into()
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

        // 3c: brief indicator shown while this session is running on the
        // built-in default mask (bootstrap-fallback) rather than a normal
        // bootstrap-derived one — only meaningful while a connection is
        // active/being attempted, and cleared on every new Connect/Disconnect
        // (see Message::Connect / Message::Disconnect / BootstrapFallbackDetected).
        let fallback_badge: Element<Message> = if self.bootstrap_fallback && busy {
            text(t(lang, "Using built-in mask (fallback)"))
                .size(11)
                .color(Color::from_rgb(1.0, 0.65, 0.15))
                .into()
        } else {
            Space::with_height(0).into()
        };

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
        // The FEC badge reflects the LIVE level the server actually runs the
        // session at (quality.json) when connected — not merely the requested
        // preference, which the adaptive controller may have overridden.
        let live_level = if is_connected && self.stats.server_adaptive_level > 0 {
            self.stats.server_adaptive_level
        } else {
            self.settings.adaptive_level
        };
        let fec_text = if live_level >= 2 { " [FEC]" } else { "" };
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

        // Admin client-management panel: gated on both a confirmed Admin
        // role (fetched fresh on every Connected transition — see
        // Message::StatusReceived) AND the panel being connected in the
        // first place, so a stale role from a just-ended session can never
        // show a panel that would immediately fail every call.
        let admin_is_connected = matches!(self.status, VpnStatus::Connected { .. });
        let admin_section: Element<Message> = if admin_is_connected && self.admin_role == Some(2) {
            self.view_admin_section()
        } else {
            Space::with_height(0).into()
        };
        // Pool topology panel (B3): same connected+Admin gate as the
        // client-management panel above — pool node/health data is just as
        // sensitive as the client list.
        let pool_section: Element<Message> = if admin_is_connected && self.admin_role == Some(2) {
            self.view_pool_section()
        } else {
            Space::with_height(0).into()
        };

        // C3: SSH server install + migration wizards. Deliberately NOT
        // gated behind `admin_is_connected` like the panels above — these
        // install/migrate a server the GUI isn't (yet) connected to at all,
        // so they must be reachable before any VPN session exists. Each
        // real call they make (mgmt_call for migration, ssh-install for
        // install) surfaces its own "not connected" error if attempted at
        // the wrong time.
        let install_wizard_section = self.view_install_wizard_section();
        let migration_section = self.view_migration_section();

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
                    fallback_badge,
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
                    admin_section,
                    Space::with_height(6),
                    pool_section,
                    Space::with_height(6),
                    install_wizard_section,
                    Space::with_height(6),
                    migration_section,
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

    /// Admin client-management panel body. Only ever called from
    /// `view_main` behind the `is_connected && admin_role == Some(2)` gate —
    /// this method itself does not re-check the role, since it has no
    /// meaningful "not authorized" rendering of its own (the caller simply
    /// never invokes it).
    fn view_admin_section(&self) -> Element<'_, Message> {
        let lang = self.settings.lang.as_str();
        let is_dark = self.settings.dark_mode;
        let muted = if is_dark {
            Color::from_rgb(0.62, 0.64, 0.70)
        } else {
            Color::from_rgb(0.43, 0.45, 0.50)
        };
        let danger = Color::from_rgb(0.95, 0.28, 0.18);

        let toggle_label = if self.admin_open {
            format!("[-] {}", t(lang, "Admin — Client Management"))
        } else {
            format!("[+] {}", t(lang, "Admin — Client Management"))
        };
        let header = row![
            button(text(toggle_label))
                .on_press(Message::ToggleAdminPanel)
                .style(button::text),
            Space::with_width(Length::Fill),
            if self.admin_open {
                button(t(lang, "Refresh"))
                    .on_press(Message::AdminRefreshClients)
                    .style(button::text)
                    .into()
            } else {
                Element::from(Space::with_width(0))
            },
        ]
        .align_y(Alignment::Center);

        if !self.admin_open {
            return column![header].into();
        }

        let mut body = column![].spacing(6);

        if let Some(err) = &self.admin_error {
            body = body.push(text(err).size(12).color(danger));
        }

        // ── Add-client form ─────────────────────────────────────────────
        let adding = self.admin_busy_id.as_deref() == Some("");
        let add_row = row![
            text_input(t(lang, "Name"), &self.admin_new_name)
                .on_input(Message::AdminNewNameChanged)
                .width(Length::FillPortion(2)),
            checkbox(t(lang, "One-time"), self.admin_new_one_time)
                .on_toggle(Message::AdminNewOneTimeToggled),
            text_input("expires (RFC3339, optional)", &self.admin_new_expires)
                .on_input(Message::AdminNewExpiresChanged)
                .width(Length::FillPortion(2)),
            text_input(t(lang, "Exit node (optional)"), &self.admin_new_exit_node)
                .on_input(Message::AdminNewExitNodeChanged)
                .width(Length::FillPortion(2)),
            button(text(if adding {
                t(lang, "Adding...")
            } else {
                t(lang, "+ Add")
            }))
            .on_press_maybe(
                (!adding && !self.admin_new_name.trim().is_empty())
                    .then_some(Message::AdminAddClient)
            ),
        ]
        .spacing(6)
        .align_y(Alignment::Center);
        body = body.push(add_row);

        // ── Client list ──────────────────────────────────────────────────
        if self.admin_clients_loading {
            body = body.push(text(t(lang, "Loading...")).size(12).color(muted));
        } else if self.admin_clients.is_empty() {
            body = body.push(text(t(lang, "No clients")).size(12).color(muted));
        }

        for c in &self.admin_clients {
            let busy = self.admin_busy_id.as_deref() == Some(c.id.as_str());
            let title_row = row![
                text(format!("{}", c.name)).size(13),
                text(format!("[{}]", c.role_label())).size(11).color(muted),
                text(if c.enabled {
                    t(lang, "enabled")
                } else {
                    t(lang, "disabled")
                })
                .size(11)
                .color(if c.enabled { muted } else { danger }),
                if c.one_time {
                    text(t(lang, "one-time")).size(11).color(muted)
                } else {
                    text("").size(11)
                },
                if let Some(exit) = &c.exit_node {
                    text(format!("{}: {}", t(lang, "Exit"), exit))
                        .size(11)
                        .color(muted)
                } else {
                    text("").size(11)
                },
            ]
            .spacing(8)
            .align_y(Alignment::Center);

            let mut card = column![title_row].spacing(4);

            if self.admin_pending_revoke.as_deref() == Some(c.id.as_str()) {
                card = card.push(
                    row![
                        text(t(lang, "Confirm revoke?")).size(12).color(danger),
                        button(t(lang, "Yes"))
                            .on_press(Message::AdminRevokeConfirm(c.id.clone()))
                            .style(button::danger),
                        button(t(lang, "No"))
                            .on_press(Message::AdminRevokeCancel)
                            .style(button::secondary),
                    ]
                    .spacing(6)
                    .align_y(Alignment::Center),
                );
            } else if self.admin_edit_id.as_deref() == Some(c.id.as_str()) {
                card = card.push(
                    row![
                        text_input(t(lang, "Name"), &self.admin_edit_name)
                            .on_input(Message::AdminEditNameChanged)
                            .width(Length::FillPortion(2)),
                        text_input("expires (RFC3339)", &self.admin_edit_expires)
                            .on_input(Message::AdminEditExpiresChanged)
                            .width(Length::FillPortion(2)),
                        text_input("host:port", &self.admin_edit_exit_node)
                            .on_input(Message::AdminEditExitNodeChanged)
                            .width(Length::FillPortion(2)),
                        button(t(lang, "Save"))
                            .on_press_maybe((!busy).then_some(Message::AdminEditSave)),
                        button(t(lang, "Cancel"))
                            .on_press(Message::AdminEditCancel)
                            .style(button::secondary),
                    ]
                    .spacing(6)
                    .align_y(Alignment::Center),
                );
            } else {
                card = card.push(
                    row![
                        button(t(lang, "Key"))
                            .on_press_maybe((!busy).then_some(Message::AdminShowKey(c.id.clone()))),
                        button(t(lang, "Edit")).on_press_maybe(
                            (!busy).then_some(Message::AdminStartEdit(c.id.clone()))
                        ),
                        button(text(if c.enabled {
                            t(lang, "Disable")
                        } else {
                            t(lang, "Enable")
                        }))
                        .on_press_maybe(
                            (!busy)
                                .then_some(Message::AdminToggleEnabled(c.id.clone(), !c.enabled))
                        ),
                        button(t(lang, "Reset device")).on_press_maybe(
                            (!busy).then_some(Message::AdminResetDevice(c.id.clone()))
                        ),
                        button(t(lang, "Revoke"))
                            .on_press_maybe(
                                (!busy).then_some(Message::AdminRevokeRequest(c.id.clone()))
                            )
                            .style(button::danger),
                    ]
                    .spacing(4)
                    .align_y(Alignment::Center),
                );
            }

            if let Some((kid, key)) = &self.admin_key_view {
                if kid == &c.id {
                    card = card.push(
                        scrollable(text(key).size(11))
                            .width(Length::Fill)
                            .height(50),
                    );
                    card = card.push(
                        row![
                            button(t(lang, "Copy")).on_press(Message::AdminCopyKey(key.clone())),
                            button(t(lang, "Save")).on_press(Message::AdminSaveKeyToFile),
                            button(t(lang, "Show QR")).on_press_maybe(
                                (self.admin_qr_loading.is_none())
                                    .then_some(Message::AdminRequestQr(c.id.clone()))
                            ),
                            button(t(lang, "Close"))
                                .on_press(Message::AdminCloseKeyView)
                                .style(button::secondary),
                        ]
                        .spacing(6)
                        .align_y(Alignment::Center),
                    );
                    if self.admin_qr_loading.as_deref() == Some(c.id.as_str()) {
                        card = card.push(text(t(lang, "Generating QR...")).size(11).color(muted));
                    }
                    if let Some((qid, handle)) = &self.admin_qr {
                        if qid == &c.id {
                            card = card.push(
                                column![
                                    image(handle.clone()).width(180).height(180),
                                    button(t(lang, "Save QR"))
                                        .on_press(Message::AdminSaveQrToFile)
                                        .style(button::text),
                                ]
                                .spacing(4),
                            );
                        }
                    }
                }
            }

            body = body.push(container(card).padding(8).width(Length::Fill).style(
                move |_: &Theme| container::Style {
                    background: Some(Background::Color(if is_dark {
                        Color::from_rgb(0.24, 0.25, 0.30)
                    } else {
                        Color::from_rgb(0.95, 0.95, 0.97)
                    })),
                    border: Border {
                        radius: 6.0.into(),
                        width: 1.0,
                        color: if is_dark {
                            Color::from_rgba(1.0, 1.0, 1.0, 0.08)
                        } else {
                            Color::from_rgba(0.0, 0.0, 0.0, 0.06)
                        },
                    },
                    ..Default::default()
                },
            ));
        }

        column![header, body].spacing(6).into()
    }

    /// Pool topology panel body (Wave B3): node list + health summary.
    /// Same gating discipline as `view_admin_section` — only ever called
    /// from `view_main` behind `is_connected && admin_role == Some(2)`.
    fn view_pool_section(&self) -> Element<'_, Message> {
        let lang = self.settings.lang.as_str();
        let is_dark = self.settings.dark_mode;
        let muted = if is_dark {
            Color::from_rgb(0.62, 0.64, 0.70)
        } else {
            Color::from_rgb(0.43, 0.45, 0.50)
        };
        let danger = Color::from_rgb(0.95, 0.28, 0.18);
        let good = Color::from_rgb(0.20, 0.70, 0.35);

        let toggle_label = if self.pool_open {
            format!("[-] {}", t(lang, "Pool Topology"))
        } else {
            format!("[+] {}", t(lang, "Pool Topology"))
        };
        let header = row![
            button(text(toggle_label))
                .on_press(Message::TogglePoolPanel)
                .style(button::text),
            Space::with_width(Length::Fill),
            if self.pool_open {
                button(t(lang, "Refresh"))
                    .on_press(Message::PoolRefresh)
                    .style(button::text)
                    .into()
            } else {
                Element::from(Space::with_width(0))
            },
        ]
        .align_y(Alignment::Center);

        if !self.pool_open {
            return column![header].into();
        }

        let mut body = column![].spacing(6);

        if let Some(err) = &self.pool_error {
            body = body.push(text(err).size(12).color(danger));
        }

        if let Some(h) = &self.pool_health {
            let health_row = row![
                text(format!("{}: {}", t(lang, "Transport"), h.transport)).size(12),
                text(format!(
                    "{}: {}/{}",
                    t(lang, "Connected"),
                    h.connected_peers,
                    h.total_nodes
                ))
                .size(12),
                text(format!("{}: {}", t(lang, "Converged"), h.converged_peers)).size(12),
            ]
            .spacing(12);
            body = body.push(health_row);

            if h.partition_conflict || h.subnet_mismatch {
                let mut warn = String::new();
                if h.partition_conflict {
                    warn.push_str(t(lang, "Partition conflict detected"));
                }
                if h.subnet_mismatch {
                    if !warn.is_empty() {
                        warn.push_str(" \u{b7} ");
                    }
                    warn.push_str(t(lang, "Subnet mismatch detected"));
                }
                body = body.push(text(warn).size(12).color(danger));
            } else if h.diverged {
                body = body.push(text(t(lang, "Some peers diverged")).size(12).color(muted));
            }
        }

        if self.pool_loading {
            body = body.push(text(t(lang, "Loading...")).size(12).color(muted));
        } else if self.pool_nodes.is_empty() {
            body = body.push(text(t(lang, "No pool nodes")).size(12).color(muted));
        }

        for n in &self.pool_nodes {
            let last_seen = n
                .last_seen_unix
                .map(|ts| ts.to_string())
                .unwrap_or_else(|| t(lang, "never").to_string());
            let node_row = row![
                text(n.node_id.clone())
                    .size(12)
                    .width(Length::FillPortion(2)),
                text(n.address.clone().unwrap_or_else(|| "-".to_string()))
                    .size(12)
                    .width(Length::FillPortion(2)),
                text(if n.verified {
                    t(lang, "verified")
                } else {
                    t(lang, "unverified")
                })
                .size(11)
                .color(if n.verified { good } else { muted }),
                text(if n.connected {
                    t(lang, "connected")
                } else {
                    t(lang, "offline")
                })
                .size(11)
                .color(if n.connected { good } else { muted }),
                if n.revoked {
                    text(t(lang, "revoked")).size(11).color(danger)
                } else {
                    text("").size(11)
                },
                text(format!("{}: {}", t(lang, "Last seen"), last_seen))
                    .size(11)
                    .color(muted),
            ]
            .spacing(8)
            .align_y(Alignment::Center);

            body = body.push(container(node_row).padding(6).width(Length::Fill).style(
                move |_: &Theme| container::Style {
                    background: Some(Background::Color(if is_dark {
                        Color::from_rgb(0.24, 0.25, 0.30)
                    } else {
                        Color::from_rgb(0.95, 0.95, 0.97)
                    })),
                    border: Border {
                        radius: 6.0.into(),
                        width: 1.0,
                        color: if is_dark {
                            Color::from_rgba(1.0, 1.0, 1.0, 0.08)
                        } else {
                            Color::from_rgba(0.0, 0.0, 0.0, 0.06)
                        },
                    },
                    ..Default::default()
                },
            ));
        }

        column![header, body].spacing(6).into()
    }

    /// C3: "Install server via SSH" wizard body — Target → TOFU → Installing
    /// steps, computed from state rather than an explicit step enum (each
    /// step's fields double as the "am I on this step" flags: no
    /// fingerprint yet => Target/probe step; fingerprint but not trusted =>
    /// TOFU confirm step; trusted => ready to start; running/exit_code set
    /// => streaming/result step).
    fn view_install_wizard_section(&self) -> Element<'_, Message> {
        let lang = self.settings.lang.as_str();
        let is_dark = self.settings.dark_mode;
        let muted = if is_dark {
            Color::from_rgb(0.62, 0.64, 0.70)
        } else {
            Color::from_rgb(0.43, 0.45, 0.50)
        };
        let danger = Color::from_rgb(0.95, 0.28, 0.18);
        let ok_color = if is_dark {
            Color::from_rgb(0.40, 0.85, 0.40)
        } else {
            Color::from_rgb(0.15, 0.55, 0.15)
        };

        let toggle_label = if self.install_wizard_open {
            format!("[-] {}", t(lang, "Install Server via SSH"))
        } else {
            format!("[+] {}", t(lang, "Install Server via SSH"))
        };
        let header = row![
            button(text(toggle_label))
                .on_press(Message::ToggleInstallWizard)
                .style(button::text),
            Space::with_width(Length::Fill),
        ]
        .align_y(Alignment::Center);

        if !self.install_wizard_open {
            return column![header].into();
        }

        let mut body = column![].spacing(8);

        if let Some(err) = &self.install_error {
            body = body.push(text(err).size(12).color(danger));
        }

        // ── Installing / result step ────────────────────────────────────
        if self.install_running || self.install_exit_code.is_some() {
            let log_items: Vec<Element<Message>> = self
                .install_log
                .iter()
                .map(|l| text(l).size(11).into())
                .collect();
            body = body.push(
                scrollable(
                    container(column(log_items).spacing(1))
                        .padding(8)
                        .width(Length::Fill),
                )
                .height(200),
            );
            if let Some(code) = self.install_exit_code {
                let status_text = if code == 0 {
                    text(t(lang, "Install finished successfully")).color(ok_color)
                } else {
                    text(format!("{} (exit {code})", t(lang, "Install failed"))).color(danger)
                };
                body = body.push(status_text);
                let mut actions = row![button(t(lang, "Start over"))
                    .on_press(Message::InstallReset)
                    .style(button::secondary)]
                .spacing(6);
                if self.install_connection_key.is_some() {
                    actions = actions.push(
                        button(t(lang, "Import profile")).on_press(Message::InstallImportProfile),
                    );
                }
                body = body.push(actions);
            } else {
                body = body.push(text(t(lang, "Installing...")).size(12).color(muted));
            }
            return column![header, body].spacing(6).into();
        }

        // ── Target step ─────────────────────────────────────────────────
        body = body.push(
            row![
                text_input("host or IP", &self.install_host)
                    .on_input(Message::InstallHostChanged)
                    .width(Length::FillPortion(3)),
                text_input("22", &self.install_port)
                    .on_input(Message::InstallPortChanged)
                    .width(Length::FillPortion(1)),
                text_input("root", &self.install_user)
                    .on_input(Message::InstallUserChanged)
                    .width(Length::FillPortion(1)),
            ]
            .spacing(6),
        );

        body = body.push(
            checkbox(
                t(lang, "Use SSH key instead of password"),
                self.install_auth_is_key,
            )
            .on_toggle(Message::InstallAuthModeToggled),
        );

        if self.install_auth_is_key {
            body = body.push(
                text_input(t(lang, "Private key path"), &self.install_key_file)
                    .on_input(Message::InstallKeyFileChanged),
            );
            body = body.push(
                text_input(
                    t(lang, "Key passphrase (optional)"),
                    &self.install_key_passphrase,
                )
                .secure(true)
                .on_input(Message::InstallKeyPassphraseChanged),
            );
        } else {
            body = body.push(
                text_input(t(lang, "SSH password"), &self.install_password)
                    .secure(true)
                    .on_input(Message::InstallPasswordChanged),
            );
        }

        body = body.push(
            row![
                text_input(t(lang, "Server IP (optional)"), &self.install_server_ip)
                    .on_input(Message::InstallServerIpChanged),
                text_input(t(lang, "Server port (optional)"), &self.install_server_port)
                    .on_input(Message::InstallServerPortChanged),
            ]
            .spacing(6),
        );

        body = body.push(
            row![
                checkbox("docker", self.install_mode_docker).on_toggle(Message::InstallModeToggled),
                checkbox(
                    t(lang, "Bind this device (admin access)"),
                    self.install_bind_device
                )
                .on_toggle(Message::InstallBindDeviceToggled),
            ]
            .spacing(12),
        );

        body = body.push(
            button(t(lang, "Show script"))
                .on_press(Message::InstallShowScript)
                .style(button::text),
        );

        if self.install_script_open {
            if let Some((sha, script)) = &self.install_script {
                body = body.push(text(format!("SHA256: {sha}")).size(11).color(muted));
                body = body.push(scrollable(text(script.clone()).size(10)).height(140));
            } else {
                body = body.push(text(t(lang, "Loading...")).size(11).color(muted));
            }
            body = body.push(
                button(t(lang, "Close"))
                    .on_press(Message::InstallHideScript)
                    .style(button::text),
            );
        }

        // ── TOFU step ────────────────────────────────────────────────────
        if let Some(fp) = &self.install_fingerprint {
            body = body.push(text(format!("{}: {fp}", t(lang, "Host key fingerprint"))).size(12));
            if self.install_trusted {
                let can_start = if self.install_auth_is_key {
                    !self.install_key_file.trim().is_empty()
                } else {
                    !self.install_password.is_empty()
                };
                body = body.push(
                    row![
                        button(t(lang, "Install"))
                            .on_press_maybe(can_start.then_some(Message::InstallStart)),
                        button(t(lang, "Don't trust"))
                            .on_press(Message::InstallDistrust)
                            .style(button::danger),
                    ]
                    .spacing(6),
                );
            } else {
                body = body.push(
                    row![
                        text(t(lang, "Confirm this is the correct server's key"))
                            .size(12)
                            .color(muted),
                        button(t(lang, "I trust this key"))
                            .on_press(Message::InstallTrustFingerprint),
                        button(t(lang, "Cancel"))
                            .on_press(Message::InstallDistrust)
                            .style(button::secondary),
                    ]
                    .spacing(6)
                    .align_y(Alignment::Center),
                );
            }
        } else {
            let can_probe = !self.install_probing && !self.install_host.trim().is_empty();
            body = body.push(
                button(text(if self.install_probing {
                    t(lang, "Connecting...")
                } else {
                    t(lang, "Connect & verify host key")
                }))
                .on_press_maybe(can_probe.then_some(Message::InstallProbe)),
            );
        }

        column![header, body].spacing(6).into()
    }

    /// C3: server migration wizard body — a 3-step real-call guide
    /// (export from the currently-connected old server's admin session →
    /// install the new server via the wizard above → import into the
    /// currently-connected new server's admin session after the user
    /// switches profiles). Reuses `admin::mgmt_call` (same backup
    /// export/import endpoints the web panel already exposes) rather than
    /// adding any new transport.
    fn view_migration_section(&self) -> Element<'_, Message> {
        let lang = self.settings.lang.as_str();
        let is_dark = self.settings.dark_mode;
        let muted = if is_dark {
            Color::from_rgb(0.62, 0.64, 0.70)
        } else {
            Color::from_rgb(0.43, 0.45, 0.50)
        };
        let danger = Color::from_rgb(0.95, 0.28, 0.18);

        let toggle_label = if self.migration_open {
            format!("[-] {}", t(lang, "Server Migration"))
        } else {
            format!("[+] {}", t(lang, "Server Migration"))
        };
        let header = row![
            button(text(toggle_label))
                .on_press(Message::ToggleMigrationWizard)
                .style(button::text),
            Space::with_width(Length::Fill),
        ]
        .align_y(Alignment::Center);

        if !self.migration_open {
            return column![header].into();
        }

        let mut body = column![].spacing(8);
        body = body.push(
            text(t(
                lang,
                "Migration guide: 1) export from the old server while connected as admin, 2) install the new server via SSH above, 3) reconnect using the new server's admin profile and import.",
            ))
            .size(12)
            .color(muted),
        );

        if let Some(err) = &self.migration_error {
            body = body.push(text(err).size(12).color(danger));
        }
        if !self.migration_status.is_empty() {
            body = body.push(text(self.migration_status.clone()).size(12));
        }

        body = body.push(
            row![
                text("1.").size(13),
                button(t(lang, "Export backup from current server"))
                    .on_press_maybe((!self.migration_busy).then_some(Message::MigrationExport)),
            ]
            .spacing(6)
            .align_y(Alignment::Center),
        );

        body = body.push(
            row![
                text("2.").size(13),
                text(t(
                    lang,
                    "Install the new server using the wizard above, then reconnect using its admin profile.",
                ))
                .size(12)
                .color(muted),
            ]
            .spacing(6)
            .align_y(Alignment::Center),
        );

        body = body.push(
            row![
                text("3.").size(13),
                button(t(lang, "Import backup into current server"))
                    .on_press_maybe((!self.migration_busy).then_some(Message::MigrationImportPick)),
            ]
            .spacing(6)
            .align_y(Alignment::Center),
        );

        column![header, body].spacing(6).into()
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
                    let _ = sender.try_send(Message::StatusReceived(VpnStatus::Connecting));

                    let mut out = BufReader::new(stdout).lines();
                    let mut err = BufReader::new(stderr).lines();

                    // Preferred, machine-readable status protocol: newer
                    // clients print "AIVPN-STATUS connected <vpn_ip>" /
                    // "AIVPN-STATUS reconnecting" / "AIVPN-STATUS disconnected"
                    // on stdout. A reconnecting client DEMOTES the UI to
                    // Connecting instead of showing Connected over a dead,
                    // silently-retrying tunnel.
                    let parse_status_line = |l: &str| -> Option<VpnStatus> {
                        let mut it = l.trim().strip_prefix("AIVPN-STATUS ")?.split_whitespace();
                        match it.next()? {
                            "connected" => Some(VpnStatus::Connected {
                                vpn_ip: it.next().unwrap_or_default().to_string(),
                            }),
                            "reconnecting" => Some(VpnStatus::Connecting),
                            "disconnected" => Some(VpnStatus::Disconnected),
                            // 3f: authenticated terminal handshake refusal —
                            // surfaced as an Error status (same red/urgent UI
                            // treatment as any other fatal client-side
                            // error). Mapped from the client's ASCII token
                            // (see handshake_reject_token in client.rs) so
                            // this doesn't depend on its English log wording.
                            "rejected" => {
                                let token = it.next().unwrap_or("unspecified");
                                let msg = match token {
                                    "one_time_used" => "server: one-time key already used",
                                    "expired" => "server: client expired",
                                    "disabled" => "server: client disabled",
                                    _ => "server: connection refused",
                                };
                                Some(VpnStatus::Error(msg.to_string()))
                            }
                            _ => None,
                        }
                    };

                    // Fallback heuristic for OLDER clients only: detects the
                    // "Connected to server at ..." / TUN-ready log line. The
                    // client's tracing subscriber writes to stderr (not stdout —
                    // see 9c84bf7, so bench --json's stdout output stays clean),
                    // so this line always arrives via `err`, never `out`; still
                    // checked on both streams in case a future client build ever
                    // emits it differently.
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

                    // Once one machine-readable line has been seen the
                    // heuristic is disabled for the rest of the session: it
                    // substring-matches log prose ("Reconnected", pre-handshake
                    // "TUN interface") and would fight the authoritative
                    // protocol.
                    let mut saw_status_line = false;
                    let mut handle_line =
                        |sender: &mut iced::futures::channel::mpsc::Sender<Message>, l: &str| {
                            // 3c: orthogonal to VpnStatus (can co-occur with
                            // Connecting/Connected), so it's dispatched
                            // separately rather than through parse_status_line.
                            if l.trim() == "AIVPN-STATUS bootstrap-fallback" {
                                let _ = sender.try_send(Message::BootstrapFallbackDetected);
                            }
                            if let Some(status) = parse_status_line(l) {
                                saw_status_line = true;
                                let _ = sender.try_send(Message::StatusReceived(status));
                            } else if !saw_status_line {
                                check_connected(sender, l);
                            }
                        };

                    loop {
                        tokio::select! {
                            line = out.next_line() => match line {
                                Ok(Some(l)) => {
                                    handle_line(&mut sender, &l);
                                    let _ = sender.try_send(Message::LogLine(strip_ansi(&l)));
                                }
                                _ => break,
                            },
                            line = err.next_line() => match line {
                                Ok(Some(l)) => {
                                    handle_line(&mut sender, &l);
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
                    remove_client_pidfile();
                    let _ = sender.try_send(Message::StatusReceived(VpnStatus::Disconnected));
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

        Subscription::batch(vec![
            worker_sub,
            stats_sub,
            tray_sub,
            close_sub,
            recording_sub,
            install_sub,
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
