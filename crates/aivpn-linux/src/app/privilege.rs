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
    // Чужая user namespace не относится к правам, выданным этим установщиком.
    if magic_etc & 0xff00_0000 == 0x0300_0000
        && n >= 24
        && u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]) != 0
    {
        return false;
    }
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
    let Ok(canonical) = std::fs::canonicalize(path) else {
        return false;
    };
    let Ok(file) = std::fs::metadata(&canonical) else {
        return false;
    };
    file.is_file()
        && canonical.ancestors().all(|ancestor| {
            std::fs::symlink_metadata(ancestor).is_ok_and(|meta| {
                meta.uid() == 0 && meta.mode() & 0o022 == 0 && !meta.file_type().is_symlink()
            })
        })
}
#[cfg(not(unix))]
fn is_trusted_system_binary(_path: &std::path::Path) -> bool {
    false
}

/// Находим системные копии ip, чтобы снять выданные прежним установщиком права.
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
        .filter(|p| p.file_name().is_some_and(|name| name == "ip"))
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
    if !is_trusted_system_binary(std::path::Path::new(AIVPN_POLICY_DEST)) {
        return false;
    }
    std::fs::read_to_string(AIVPN_POLICY_DEST)
        .map(|c| c == AIVPN_POLICY_CONTENT)
        .unwrap_or(false)
}

/// Читает ровно один файл из pipe и отклоняет неполную передачу.
fn read_stage_file(name: &str, size: usize) -> String {
    format!(
        "head -c {size} > \"$stage/{name}\"\ntest \"$(wc -c < \"$stage/{name}\")\" -eq {size}\n"
    )
}

/// Удаляем только NET_ADMIN, сохраняя остальные права системной команды.
fn revoke_ip_capability(path: &std::path::Path) -> String {
    let path = shell_quote(&path.to_string_lossy());
    format!(
        "ip_path={path}\ncaps=$(getcap \"$ip_path\")\ncaps=${{caps#\"$ip_path \"}}\nsetcap \"$caps cap_net_admin-eip\" \"$ip_path\"\ncaps=$(getcap \"$ip_path\")\ncaps=${{caps#\"$ip_path \"}}\nif [ \"$caps\" = = ]; then setcap -r \"$ip_path\"; fi\n"
    )
}

/// Устанавливает клиент и помощник в каталог root и проверяет результат.
pub(super) async fn ensure_capable_binary(
    source: &std::path::Path,
    lang: &str,
    sender: &mut iced::futures::channel::mpsc::Sender<Message>,
) -> Result<std::path::PathBuf, String> {
    use tokio::io::AsyncWriteExt;
    let persisted = std::path::PathBuf::from(AIVPN_IP_HELPER_INSTALL_DIR).join("aivpn-client");
    let helper_dest = aivpn_ip_helper_path();
    // Снимки читаются до запроса прав. Привилегированный процесс получает байты
    // через pipe и не открывает подготовленные файлы в каталоге пользователя.
    let client = std::fs::read(source).map_err(|error| error.to_string())?;
    let built_helper = find_ip_helper_binary().ok();
    let helper = built_helper
        .as_ref()
        .map(std::fs::read)
        .transpose()
        .map_err(|error| error.to_string())?;
    let ip_bins = find_ip_binaries();
    let client_ok = || {
        is_trusted_system_binary(&persisted)
            && has_net_admin_cap(&persisted)
            && std::fs::read(&persisted).is_ok_and(|bytes| bytes == client)
    };
    let helper_ok = || {
        helper.as_ref().is_none_or(|expected| {
            is_trusted_system_binary(&helper_dest)
                && std::fs::read(&helper_dest).is_ok_and(|bytes| &bytes == expected)
                && policy_is_installed()
        })
    };
    if client_ok() && helper_ok() && ip_bins.iter().all(|path| !has_net_admin_cap(path)) {
        return Ok(persisted);
    }
    let mut files = vec![("client", client.as_slice(), persisted.as_path(), "0755")];
    if let Some(bytes) = &helper {
        files.push(("helper", bytes.as_slice(), helper_dest.as_path(), "0755"));
        files.push((
            "policy",
            AIVPN_POLICY_CONTENT.as_bytes(),
            std::path::Path::new(AIVPN_POLICY_DEST),
            "0644",
        ));
    }
    let mut script = String::from("set -eu\numask 077\n");
    script.push_str("for p in /usr /usr/local /usr/local/libexec /usr/local/libexec/aivpn /usr/share /usr/share/polkit-1 /usr/share/polkit-1/actions; do\nif [ ! -e \"$p\" ]; then install -d -m 0755 -o root -g root -- \"$p\"; fi\ntest ! -L \"$p\"\ntest \"$(stat -c %u -- \"$p\")\" = 0\ntest \"$((0$(stat -c %a -- \"$p\") & 0022))\" -eq 0\ndone\n");
    script.push_str("stage=$(mktemp -d /usr/local/libexec/aivpn/.setup.XXXXXXXX)\ntrap 'rm -rf -- \"$stage\"' EXIT\n");
    for (name, bytes, _, _) in &files {
        script.push_str(&read_stage_file(name, bytes.len()));
    }
    for (name, _, destination, mode) in &files {
        script.push_str(&format!(
            "install -m {mode} -o root -g root -- \"$stage/{name}\" {}\n",
            shell_quote(&destination.to_string_lossy())
        ));
    }
    script.push_str(&format!(
        "setcap cap_net_admin+ep {}",
        shell_quote(&persisted.to_string_lossy())
    ));
    script.push('\n');
    for ip in &ip_bins {
        if has_net_admin_cap(ip) {
            script.push_str(&revoke_ip_capability(ip));
        }
    }
    let mut child = tokio::process::Command::new("/usr/bin/pkexec")
        .args(["--disable-internal-agent", "sh", "-c", &script])
        .stdin(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| error.to_string())?;
    let mut input = child
        .stdin
        .take()
        .ok_or_else(|| "pkexec stdin недоступен".to_string())?;
    let write_result = async {
        for (_, bytes, _, _) in &files {
            input.write_all(bytes).await?;
        }
        input.shutdown().await
    }
    .await;
    drop(input);
    let status = child.wait().await.map_err(|error| error.to_string())?;
    if write_result.is_err()
        || !status.success()
        || !client_ok()
        || !helper_ok()
        || ip_bins.iter().any(|path| has_net_admin_cap(path))
    {
        let _ = sender.try_send(Message::LogLine(format!(
            "[diag] privileged setup failed: {status}"
        )));
        return Err(if lang == "ru" {
            "Не удалось установить клиент и проверить права. Подключение отменено.".into()
        } else {
            "Client installation or permission verification failed. Connection cancelled.".into()
        });
    }
    Ok(persisted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn capability_repair_preserves_other_flags_and_quotes_paths() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("aivpn-cap-repair-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let getcap = dir.join("getcap");
        let setcap = dir.join("setcap");
        std::fs::write(
            &getcap,
            "#!/bin/sh\nprintf '%s %s\\n' \"$1\" 'cap_net_admin,cap_net_raw=ep'\n",
        )
        .unwrap();
        std::fs::write(
            &setcap,
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CAP_CAPTURE\"\n",
        )
        .unwrap();
        for path in [&getcap, &setcap] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = dir.join("ip with 'quote");
        let output = dir.join("result");
        let result = std::process::Command::new("/bin/sh")
            .args(["-ec", &revoke_ip_capability(&path)])
            .env("PATH", &dir)
            .env("CAP_CAPTURE", &output)
            .status()
            .unwrap();
        assert!(result.success());
        assert_eq!(
            std::fs::read_to_string(&output).unwrap(),
            format!(
                "cap_net_admin,cap_net_raw=ep cap_net_admin-eip\n{}\n",
                path.display()
            )
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn staged_input_uses_snapshot_and_rejects_truncated_transfer() {
        let directory = std::env::temp_dir().join(format!(
            "aivpn-setup-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let source = directory.join("source");
        std::fs::write(&source, b"trusted\0binary").unwrap();
        let snapshot = std::fs::read(&source).unwrap();
        std::fs::write(&source, b"replacement").unwrap();
        for truncated in [false, true] {
            let script = format!("set -e\n{}", read_stage_file("client", snapshot.len()));
            let mut command = std::process::Command::new("sh")
                .args(["-c", &script])
                .env("stage", &directory)
                .stdin(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let mut input = command.stdin.take().unwrap();
            input
                .write_all(if truncated { &snapshot[..3] } else { &snapshot })
                .unwrap();
            drop(input);
            let success = command.wait().unwrap().success();
            assert_eq!(success, !truncated);
            if success {
                assert_eq!(std::fs::read(directory.join("client")).unwrap(), snapshot);
            }
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
}
