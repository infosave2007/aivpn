//! Capability / polkit privilege detection and one-shot setup for the
//! `aivpn-client` binary and its `ip` helpers. Moved verbatim out of
//! `app/mod.rs` (pure move, no behavior change).

use crate::vpn_manager::find_ip_helper_binary;

use super::Message;

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
    include_str!("../../../../platforms/linux/polkit/com.aivpn.client.policy");

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
pub(super) async fn ensure_capable_binary(
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
