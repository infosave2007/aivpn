//! Append-only admin audit log.
//!
//! Each administrative action is recorded as a JSON line in the audit log path.
//! Rotation is handled externally via logrotate.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditActor {
    Cli,
    Api,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: String,
    pub actor: AuditActor,
    pub action: String,
    pub target: String,
    pub result: String,
}

/// Thread-safe append-only audit logger.
#[derive(Clone)]
pub struct AuditLogger {
    inner: Arc<Mutex<AuditLoggerInner>>,
}

struct AuditLoggerInner {
    path: PathBuf,
}

impl AuditLogger {
    pub fn new(path: &Path) -> Self {
        // `disabled()` points this at `/dev/null`, whose parent is the
        // system `/dev` directory — never touch permissions in that case
        // (chmod-ing a system directory would be catastrophic). Only harden
        // permissions for a real, operator-configured audit log path.
        let is_disabled_sentinel = path == Path::new("/dev/null");
        if let Some(dir) = path.parent() {
            let created = !dir.exists();
            let _ = std::fs::create_dir_all(dir);
            // MEDIUM (server-sec): harden the audit log directory — it
            // previously inherited the process umask (commonly world-
            // readable under root). Only chmod a directory THIS call
            // created (or the log file's own directory when it already
            // exists but isn't a system path), never an arbitrary
            // pre-existing directory that might be shared with unrelated
            // files. The file itself is hardened in `log()`.
            #[cfg(unix)]
            if !is_disabled_sentinel && created {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        Self {
            inner: Arc::new(Mutex::new(AuditLoggerInner {
                path: path.to_path_buf(),
            })),
        }
    }

    pub fn disabled() -> Self {
        Self::new(Path::new("/dev/null"))
    }

    pub fn log(&self, actor: AuditActor, action: &str, target: &str, result: &str) {
        let entry = AuditEntry {
            ts: Utc::now().to_rfc3339(),
            actor,
            action: action.to_string(),
            target: target.to_string(),
            result: result.to_string(),
        };
        let line = match serde_json::to_string(&entry) {
            Ok(s) => s,
            Err(e) => {
                warn!("audit_log serialize: {}", e);
                return;
            }
        };
        let inner = self.inner.lock().unwrap();
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&inner.path)
        {
            Ok(mut f) => {
                // MEDIUM (server-sec): audit entries can include admin
                // actions and target identifiers; harden the file's
                // permissions rather than inheriting the process umask
                // (commonly world-readable under root). Cheap relative to
                // admin-action call volume — set on every append rather
                // than tracking "did we just create it" so an operator who
                // manually loosens permissions gets them re-hardened on the
                // next audit event too. NEVER touch `/dev/null` itself
                // (the `disabled()` sentinel) — chmod-ing a shared system
                // device node would be catastrophic for every other
                // process/user on the host.
                #[cfg(unix)]
                if inner.path != Path::new("/dev/null") {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
                }
                let _ = writeln!(f, "{}", line);
            }
            Err(e) => {
                // MEDIUM (server-sec): audit logging fails open by design
                // (an admin action must not be blocked by a logging
                // outage), but that must never be SILENT. `warn!` alone can
                // be filtered out entirely by the tracing subscriber's
                // level/module config, making a persistent audit-write
                // failure invisible; eprintln! guarantees an operator
                // watching stderr sees it regardless of log configuration.
                warn!("audit_log write {:?}: {}", inner.path, e);
                eprintln!(
                    "AUDIT LOG WRITE FAILED ({:?}): {} — entry lost: {}",
                    inner.path, e, line
                );
            }
        }
    }
}
