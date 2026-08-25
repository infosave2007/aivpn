//! Apply-with-rollback for heavy config (P1.5) — "commit confirmed", like
//! network gear: a HEAVY setting change (active-mask override, global
//! exit-node) is applied immediately, a rollback timer starts, and if the
//! admin doesn't re-confirm within `PENDING_CONFIG_TIMEOUT` over a
//! still-working session, the gateway's periodic sweep restores the prior
//! value.
//!
//! Split out of `mgmt_service` (ЭТАП 1 decomposition, pure move — see that
//! module's doc comment for the full design rationale).

use std::time::Instant;

use rand::RngCore;
use serde::Serialize;

use super::*;

// ── Apply-with-rollback for heavy config (P1.5) ─────────────────────────
//
// "Commit confirmed", like network gear: a HEAVY setting change — one that
// could plausibly lock an admin out of the tunnel they're managing it
// through (wrong active mask today; port/DNS/exit-node in later phases) —
// is applied immediately, a rollback timer starts, and if the admin
// doesn't re-confirm within `PENDING_CONFIG_TIMEOUT` over a still-working
// session, the gateway's periodic sweep (see `gateway.rs`'s cleanup task)
// restores the prior value.
//
// **v1 scope boundary (deliberately narrow):** the one heavy op wired
// through this mechanism today is the active-mask override — the same
// `<mask_dir>/.overrides/<client-id>.mask` file `management_api.rs`'s
// pre-existing `set_active_mask` REST handler and `main.rs`'s
// `--set-mask` CLI path already write. That file is a **persisted
// setting**, not something this server continuously re-reads into a live
// in-memory structure on every packet (grep confirms no `gateway.rs` code
// path reads `.overrides/*.mask` today) — exactly the same "file-only"
// characteristic `server.json` has (this module's doc / the P1.5 plan
// explicitly permits scoping to settings that are "safe as
// file-only-until-restart" when they don't already hot-reload). Wrapping
// this SAME write in a rollback timer neither improves nor regresses that
// pre-existing behavior; it only adds the safety net. `PriorSnapshot`/
// `PendingConfig` (see `pending_config.rs`) are written generically
// (`target_path` + raw prior bytes), so a future heavy op — exit-node
// selection in Phase B, say — reuses `apply_heavy`/`confirm_config`
// unchanged by adding a new `HeavySetting` variant and a new
// `resolve_heavy_setting` arm below, without touching the rollback engine.

/// One heavy, rollback-guarded setting `apply_heavy` knows how to apply.
pub enum HeavySetting {
    /// Set client `client`'s active-mask override to `mask` — same file
    /// `management_api.rs::set_active_mask` writes.
    ActiveMask { client: String, mask: String },
    /// Wave B2a: set (or clear, when `addr` is `None`) the server's GLOBAL
    /// default exit node — `pool.exit_node` in `server.json`. This is the
    /// fallback used by any client that has no per-client
    /// `ClientConfig::exit_node` override set (see that field's doc
    /// comment).
    ///
    /// IMPORTANT SCOPE NOTE: this only PERSISTS the change to `server.json`
    /// with the same apply-with-rollback safety net every other
    /// `HeavySetting` gets — it does NOT live-apply. `pool.exit_node` is
    /// read once at startup (`main.rs`/pool wiring); the new value takes
    /// effect only after the server process is restarted. Live-applying a
    /// global exit-node change without a restart is Wave B2c, not this
    /// wave.
    ExitNode { addr: Option<String> },
}

/// Result of resolving a [`HeavySetting`] to a concrete file write, before
/// the write actually happens — lets `apply_heavy` validate everything
/// (client exists, mask exists) and compute `target_path`/`descriptor`
/// without yet touching disk, so a validation failure never registers a
/// half-applied `PendingConfig`.
struct ResolvedHeavyWrite {
    target_path: std::path::PathBuf,
    new_content: Vec<u8>,
    descriptor: String,
}

fn resolve_heavy_setting(
    ctx: &MgmtCtx,
    setting: &HeavySetting,
) -> Result<ResolvedHeavyWrite, MgmtError> {
    match setting {
        HeavySetting::ActiveMask { client, mask } => {
            if client.is_empty() || mask.is_empty() {
                return Err(MgmtError::BadRequest(
                    "fields 'client' and 'mask' are required".into(),
                ));
            }
            if !mask
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
            {
                return Err(MgmtError::BadRequest("invalid mask name".into()));
            }
            let resolved_client = ctx
                .db
                .find_by_name(client)
                .or_else(|| ctx.db.find_by_id(client))
                .ok_or(MgmtError::NotFound)?;

            let mask_path = ctx.mask_dir.join(format!("{}.json", mask));
            let on_disk = mask_path.exists();
            let is_preset = aivpn_common::mask::preset_masks::by_id(mask).is_some();
            if !on_disk && !is_preset {
                return Err(MgmtError::NotFound);
            }

            let target_path = ctx
                .mask_dir
                .join(".overrides")
                .join(format!("{}.mask", resolved_client.id));
            Ok(ResolvedHeavyWrite {
                target_path,
                new_content: mask.as_bytes().to_vec(),
                descriptor: format!("active mask: {} -> {}", resolved_client.id, mask),
            })
        }
        HeavySetting::ExitNode { addr } => {
            if let Some(a) = addr {
                crate::client_db::validate_exit_node_addr(a)
                    .map_err(|e| MgmtError::BadRequest(e.to_string()))?;
            }

            let config_path = ctx.config_path.ok_or_else(|| {
                MgmtError::Unavailable("server config path not configured on this node".into())
            })?;

            // Read-mutate-write round-trip: parse the EXISTING server.json
            // as generic JSON (not `ServerFileConfig` — round-tripping
            // through the typed struct would silently drop any field this
            // server build doesn't know about, corrupting a config written
            // by a newer/differently-featured node), touch only
            // `pool.exit_node`, and re-serialize. `apply_heavy` (the only
            // caller) separately reads the file's CURRENT bytes as `prior`
            // for rollback — this function only computes `new_content`.
            let content = std::fs::read_to_string(config_path)
                .map_err(|e| MgmtError::Internal(format!("read config: {}", e)))?;
            let mut value: serde_json::Value = serde_json::from_str(&content)
                .map_err(|e| MgmtError::Internal(format!("parse config: {}", e)))?;
            let obj = value
                .as_object_mut()
                .ok_or_else(|| MgmtError::Internal("config root is not a JSON object".into()))?;
            let pool_entry = obj
                .entry("pool".to_string())
                .or_insert_with(|| serde_json::json!({}));
            if !pool_entry.is_object() {
                *pool_entry = serde_json::json!({});
            }
            let pool_obj = pool_entry.as_object_mut().expect("just ensured object");
            match addr {
                Some(a) => {
                    pool_obj.insert(
                        "exit_node".to_string(),
                        serde_json::Value::String(a.clone()),
                    );
                }
                None => {
                    pool_obj.remove("exit_node");
                }
            }
            let new_content = serde_json::to_string_pretty(&value)
                .map_err(|e| MgmtError::Internal(format!("serialize config: {}", e)))?
                .into_bytes();

            Ok(ResolvedHeavyWrite {
                target_path: config_path.to_path_buf(),
                new_content,
                descriptor: format!(
                    "global exit node: {}",
                    addr.as_deref().unwrap_or("(disabled)")
                ),
            })
        }
    }
}

/// A successful [`apply_heavy`] call: the caller must present `token` back
/// to [`confirm_config`] within [`PENDING_CONFIG_TIMEOUT`] or the change is
/// automatically rolled back by the gateway's sweep task.
#[derive(Debug, Clone, Serialize)]
pub struct ApplyResponse {
    pub token: String,
    pub applied: bool,
}

/// Generate a fresh, unpredictable pending-config token — 16 random bytes,
/// hex-encoded (32 chars). Same `OsRng`-backed pattern
/// `management_api.rs::export_backup` uses for its unpredictable temp-file
/// suffix.
fn generate_token() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Apply a [`HeavySetting`] immediately (temp-file + rename, same pattern
/// `put_config` uses) and register a [`PendingConfig`] so the change
/// auto-rolls-back unless [`confirm_config`] is called within
/// [`PENDING_CONFIG_TIMEOUT`] of `now`. `now` is the caller's observation
/// of the current time — real `Instant::now()` in production
/// (`gateway.rs`'s `dispatch_mgmt_request`, the REST handler), an injected
/// fixed value in tests — this function itself never reads the wall clock.
///
/// Returns `MgmtError::Internal` if `ctx.pending_config` is `None` (a
/// caller that never wired a `PendingConfigManager` — should not happen
/// for any real REST/tunnel `MgmtCtx`, see that field's doc comment).
pub fn apply_heavy(
    ctx: &MgmtCtx,
    setting: HeavySetting,
    now: Instant,
) -> Result<ApplyResponse, MgmtError> {
    let manager = ctx.pending_config.ok_or_else(|| {
        MgmtError::Internal("pending-config manager not configured on this node".into())
    })?;

    // The target-file read/write and pending-entry registration are one
    // transaction. Without this guard, concurrent REST/tunnel applies can
    // associate a token with another request's file contents, and the timeout
    // sweeper can restore a superseded value between rename and begin().
    let mutation_guard = manager.lock_mutation();

    let resolved = match resolve_heavy_setting(ctx, &setting) {
        Ok(r) => r,
        Err(e) => {
            audit(
                ctx,
                "ConfigApply",
                "(validation)",
                &format!("failed: {}", e),
            );
            return Err(e);
        }
    };

    let prior = std::fs::read(&resolved.target_path).ok();

    if let Some(parent) = resolved.target_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            audit(
                ctx,
                "ConfigApply",
                &resolved.descriptor,
                &format!("failed: mkdir: {}", e),
            );
            return Err(MgmtError::Internal(format!("mkdir failed: {}", e)));
        }
    }
    // Unique (random-suffixed) temp name: two concurrent applies targeting
    // the same file (REST and tunnel are independent transports) must not
    // share one `<file>.tmp` — interleaved write/rename of a shared name
    // can rename the OTHER writer's half-written content into place.
    // Mirrors `backup.rs`'s randomized temp-file pattern.
    let tmp = resolved
        .target_path
        .with_extension(format!("tmp.{}", generate_token()));
    if let Err(e) = std::fs::write(&tmp, &resolved.new_content) {
        audit(
            ctx,
            "ConfigApply",
            &resolved.descriptor,
            &format!("failed: write: {}", e),
        );
        return Err(MgmtError::Internal(format!("write failed: {}", e)));
    }
    // The ExitNode heavy setting targets `server.json`, which can hold
    // plaintext secrets (bootstrap_publish tokens). std::fs::write() creates
    // the temp file with the process umask (commonly 0644 under root), so
    // the rename would silently DOWNGRADE an operator-set 0600 on the live
    // file. Harden the temp file BEFORE the rename — same pattern as
    // `ClientDatabase::save` / `backup::import_server`.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)) {
            tracing::warn!("Failed to set pending config permissions to 0600: {}", e);
        }
    }
    if let Err(e) = std::fs::rename(&tmp, &resolved.target_path) {
        // Best-effort: don't leave the orphaned temp file behind.
        let _ = std::fs::remove_file(&tmp);
        audit(
            ctx,
            "ConfigApply",
            &resolved.descriptor,
            &format!("failed: rename: {}", e),
        );
        return Err(MgmtError::Internal(format!("rename failed: {}", e)));
    }

    let token = generate_token();
    manager.begin_locked(
        PendingConfig::begin(
            token.clone(),
            resolved.target_path,
            prior,
            resolved.descriptor.clone(),
            now,
            PENDING_CONFIG_TIMEOUT,
        ),
        &mutation_guard,
    );

    audit(
        ctx,
        "ConfigApply",
        &format!("{} (token {})", resolved.descriptor, token),
        "ok, pending confirmation",
    );

    Ok(ApplyResponse {
        token,
        applied: true,
    })
}

/// Confirm a pending change by `token` — cancels its rollback, making the
/// change permanent. Returns the confirmed [`PendingConfig`] on success so
/// the caller can gate change-specific live side effects on WHAT was
/// confirmed (e.g. the REST/Unix-socket `confirm_config` handler only
/// hot-swaps the live global exit node when the confirmed entry's
/// `target_path` is `server.json` — confirming an unrelated ActiveMask
/// token must not take a still-pending, unconfirmed exit-node change live,
/// see `management_api::confirm_config`). `MgmtError::NotFound` for an
/// unknown token OR one that already expired and was rolled back by the
/// sweep task before this call arrived (both are indistinguishable to the
/// caller: "there is nothing left to confirm").
pub fn confirm_config(ctx: &MgmtCtx, token: &str) -> Result<PendingConfig, MgmtError> {
    let manager = ctx.pending_config.ok_or_else(|| {
        MgmtError::Internal("pending-config manager not configured on this node".into())
    })?;
    match manager.confirm_and_take(token) {
        Some(confirmed) => {
            audit(ctx, "ConfigConfirm", token, "ok");
            Ok(confirmed)
        }
        None => {
            audit(
                ctx,
                "ConfigConfirm",
                token,
                "failed: unknown or expired token",
            );
            Err(MgmtError::NotFound)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mgmt_service::test_support::*;

    #[test]
    fn apply_heavy_returns_token_and_confirm_succeeds() {
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        setup_mask_file(&mask_dir, "quic-video");
        let pending = PendingConfigManager::new();
        let c = ctx_with_pending(&db, &mask_dir, &pending);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "nadia".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let resp = apply_heavy(
            &c,
            HeavySetting::ActiveMask {
                client: created.id.clone(),
                mask: "quic-video".into(),
            },
            Instant::now(),
        )
        .expect("apply_heavy should succeed for a valid client+mask");
        assert!(resp.applied);
        assert!(!resp.token.is_empty());
        assert_eq!(
            pending.len(),
            1,
            "apply_heavy must register a pending entry"
        );

        let override_path = mask_dir
            .join(".overrides")
            .join(format!("{}.mask", created.id));
        assert_eq!(
            std::fs::read_to_string(&override_path).unwrap(),
            "quic-video",
            "apply_heavy must persist the new value immediately"
        );

        confirm_config(&c, &resp.token).expect("confirm_config should succeed for a fresh token");
        assert!(
            pending.is_empty(),
            "confirming must remove the entry from the pending manager"
        );

        // File must still hold the applied value after confirmation.
        assert_eq!(
            std::fs::read_to_string(&override_path).unwrap(),
            "quic-video"
        );
    }
    #[test]
    fn confirm_config_unknown_token_is_not_found() {
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        let pending = PendingConfigManager::new();
        let c = ctx_with_pending(&db, &mask_dir, &pending);

        let err = confirm_config(&c, "not-a-real-token")
            .expect_err("confirming an unknown token must fail");
        assert!(matches!(err, MgmtError::NotFound));
    }
    #[test]
    fn apply_heavy_without_pending_manager_is_internal_error() {
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        setup_mask_file(&mask_dir, "quic-video");
        let c = ctx(&db, &mask_dir); // no pending_config wired
        let created = add_client(
            &c,
            AddClientArgs {
                name: "omar".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let err = apply_heavy(
            &c,
            HeavySetting::ActiveMask {
                client: created.id,
                mask: "quic-video".into(),
            },
            Instant::now(),
        )
        .expect_err("apply_heavy must fail cleanly with no PendingConfigManager wired");
        assert!(matches!(err, MgmtError::Internal(_)));
    }
    #[test]
    fn apply_heavy_unknown_mask_is_not_found_and_does_not_register_pending() {
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        let pending = PendingConfigManager::new();
        let c = ctx_with_pending(&db, &mask_dir, &pending);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "priya".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let err = apply_heavy(
            &c,
            HeavySetting::ActiveMask {
                client: created.id,
                mask: "does-not-exist".into(),
            },
            Instant::now(),
        )
        .expect_err("an unknown mask must be rejected");
        assert!(matches!(err, MgmtError::NotFound));
        assert!(
            pending.is_empty(),
            "a failed apply must never register a pending rollback"
        );
    }
    #[test]
    fn apply_heavy_exit_node_writes_pool_exit_node_to_server_json_with_rollback_prior() {
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        let config_tmp = tempfile::tempdir().unwrap();
        let config_path = config_tmp.path().join("server.json");
        let original: &[u8] = br#"{"listen_addr":"0.0.0.0:443"}"#;
        std::fs::write(&config_path, original).unwrap();

        let pending = PendingConfigManager::new();
        let c = ctx_with_pending_and_config(&db, &mask_dir, &pending, &config_path);

        let resp = apply_heavy(
            &c,
            HeavySetting::ExitNode {
                addr: Some("198.51.100.7:51820".to_string()),
            },
            Instant::now(),
        )
        .expect("apply_heavy ExitNode should succeed");
        assert!(resp.applied);
        assert!(!resp.token.is_empty());
        assert_eq!(
            pending.len(),
            1,
            "apply_heavy must register a pending entry"
        );

        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(written["pool"]["exit_node"], "198.51.100.7:51820");
        assert_eq!(
            written["listen_addr"], "0.0.0.0:443",
            "the read-mutate-write round-trip must preserve unrelated existing keys"
        );

        // Rollback prior must be the file's ORIGINAL bytes, exactly.
        let expired_at =
            Instant::now() + PENDING_CONFIG_TIMEOUT + std::time::Duration::from_secs(1);
        let mut expired = pending.tick(expired_at);
        assert_eq!(expired.len(), 1, "the unconfirmed entry must be swept");
        let entry = expired.pop().unwrap();
        assert_eq!(entry.target_path(), config_path.as_path());
        assert_eq!(
            entry.rollback_value(),
            Some(original),
            "prior bytes for rollback must be the file's ORIGINAL content, byte-for-byte"
        );

        // Simulate the gateway sweep task performing the actual restore.
        std::fs::write(&config_path, entry.rollback_value().unwrap()).unwrap();
        assert_eq!(std::fs::read(&config_path).unwrap(), original);
    }
    #[test]
    fn apply_heavy_exit_node_none_clears_existing_value() {
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        let config_tmp = tempfile::tempdir().unwrap();
        let config_path = config_tmp.path().join("server.json");
        std::fs::write(
            &config_path,
            br#"{"listen_addr":"0.0.0.0:443","pool":{"exit_node":"old.example.com:1","peers":[]}}"#,
        )
        .unwrap();

        let pending = PendingConfigManager::new();
        let c = ctx_with_pending_and_config(&db, &mask_dir, &pending, &config_path);

        apply_heavy(&c, HeavySetting::ExitNode { addr: None }, Instant::now())
            .expect("clearing exit_node should succeed");

        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert!(
            written["pool"]["exit_node"].is_null(),
            "exit_node key must be removed, not just emptied"
        );
        assert_eq!(
            written["pool"]["peers"],
            serde_json::json!([]),
            "unrelated pool sub-keys must survive the clear"
        );
    }
    #[test]
    fn apply_heavy_exit_node_rejects_malformed_addr_and_registers_nothing() {
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        let config_tmp = tempfile::tempdir().unwrap();
        let config_path = config_tmp.path().join("server.json");
        std::fs::write(&config_path, br#"{}"#).unwrap();

        let pending = PendingConfigManager::new();
        let c = ctx_with_pending_and_config(&db, &mask_dir, &pending, &config_path);

        let err = apply_heavy(
            &c,
            HeavySetting::ExitNode {
                addr: Some("not-a-valid-addr".to_string()),
            },
            Instant::now(),
        )
        .expect_err("a malformed exit_node addr must be rejected");
        assert!(matches!(err, MgmtError::BadRequest(_)));
        assert!(
            pending.is_empty(),
            "a rejected apply must never register a pending rollback"
        );
    }
    #[test]
    fn apply_heavy_exit_node_without_config_path_is_unavailable() {
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        let pending = PendingConfigManager::new();
        let c = ctx_with_pending(&db, &mask_dir, &pending); // no config_path wired

        let err = apply_heavy(
            &c,
            HeavySetting::ExitNode {
                addr: Some("1.2.3.4:1".to_string()),
            },
            Instant::now(),
        )
        .expect_err("ExitNode must fail cleanly when this node has no config_path");
        assert!(matches!(err, MgmtError::Unavailable(_)));
    }
    #[test]
    fn confirm_config_returns_the_confirmed_entry_so_callers_gate_live_apply_on_it() {
        // Regression: the REST/tunnel confirm handlers live-apply the global
        // exit node ONLY when the token being confirmed actually targeted
        // server.json — confirming an unrelated ActiveMask token while an
        // exit-node change is still pending must NOT take that unconfirmed
        // change live (`apply_global_exit_and_teardown` re-reads the whole
        // file). This test pins the confirm→target_path signal both
        // handlers gate on.
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        setup_mask_file(&mask_dir, "quic-video");
        let config_tmp = tempfile::tempdir().unwrap();
        let config_path = config_tmp.path().join("server.json");
        std::fs::write(&config_path, br#"{"listen_addr":"0.0.0.0:443"}"#).unwrap();

        let pending = PendingConfigManager::new();
        let c = ctx_with_pending_and_config(&db, &mask_dir, &pending, &config_path);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "nadia".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let mask_resp = apply_heavy(
            &c,
            HeavySetting::ActiveMask {
                client: created.id.clone(),
                mask: "quic-video".into(),
            },
            Instant::now(),
        )
        .unwrap();
        let exit_resp = apply_heavy(
            &c,
            HeavySetting::ExitNode {
                addr: Some("198.51.100.7:51820".to_string()),
            },
            Instant::now(),
        )
        .unwrap();

        // Confirming the MASK token returns an entry that does NOT target
        // server.json — and leaves the exit-node change pending.
        let confirmed_mask = confirm_config(&c, &mask_resp.token).expect("mask confirm");
        assert_ne!(
            confirmed_mask.target_path(),
            config_path.as_path(),
            "a mask confirm must not be mistakable for an exit-node change"
        );
        assert!(
            pending.has_pending_for_path(&config_path),
            "the unrelated exit-node change must still be pending"
        );

        // Confirming the EXIT-NODE token returns an entry targeting
        // server.json — the gate's positive case.
        let confirmed_exit = confirm_config(&c, &exit_resp.token).expect("exit-node confirm");
        assert_eq!(confirmed_exit.target_path(), config_path.as_path());
        assert!(!pending.has_pending_for_path(&config_path));
    }
    #[cfg(unix)]
    #[test]
    fn apply_heavy_lands_server_json_with_owner_only_permissions() {
        // Regression: the tmp+rename write created the file with the process
        // umask (0644), silently DOWNGRADING an operator-set 0600 on
        // server.json (which can hold bootstrap_publish tokens). The temp
        // file must be hardened to 0600 BEFORE the rename, mirroring
        // `ClientDatabase::save`.
        use std::os::unix::fs::PermissionsExt;
        let (_dir, db) = test_db();
        let mask_tmp = tempfile::tempdir().unwrap();
        let mask_dir = mask_tmp.path().to_path_buf();
        let config_tmp = tempfile::tempdir().unwrap();
        let config_path = config_tmp.path().join("server.json");
        std::fs::write(&config_path, br#"{"listen_addr":"0.0.0.0:443"}"#).unwrap();

        let pending = PendingConfigManager::new();
        let c = ctx_with_pending_and_config(&db, &mask_dir, &pending, &config_path);

        apply_heavy(
            &c,
            HeavySetting::ExitNode {
                addr: Some("198.51.100.7:51820".to_string()),
            },
            Instant::now(),
        )
        .expect("apply_heavy ExitNode should succeed");

        let mode = std::fs::metadata(&config_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "server.json must be owner-only after a heavy-setting write"
        );
    }
}
