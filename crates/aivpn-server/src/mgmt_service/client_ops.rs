//! Client CRUD business logic — `list_clients`/`add_client`/
//! `update_client`/`remove_client`/`revoke`/`reset_device`/
//! `connection_key`/`status`, plus their argument types (`AddClientArgs`,
//! `UpdateClientArgs`).
//!
//! Split out of `mgmt_service` (ЭТАП 1 decomposition, pure move — see that
//! module's doc comment for the full design rationale).

use chrono::{DateTime, Utc};

use crate::client_db::{ClientRole, UpdateClientParams};
use crate::mgmt_wire_common::kernel_loaded;

use super::*;

// ── Arguments ────────────────────────────────────────────────────────────

pub struct AddClientArgs {
    pub name: String,
    pub one_time: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub role: ClientRole,
    /// Not exposed over the REST wire today (kept `None` by
    /// `management_api.rs`'s `add_client` handler to preserve the existing
    /// `AddClientRequest` JSON shape) — available for the P1.2 tunnel path.
    pub qos: Option<crate::qos::ClientQos>,
}

/// Fields set to `None` are left unchanged. For `qos`/`expires_at`, use
/// `Some(None)` to clear the setting — mirrors `UpdateClientParams`.
pub struct UpdateClientArgs {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub one_time: Option<bool>,
    pub qos: Option<Option<crate::qos::ClientQos>>,
    pub expires_at: Option<Option<DateTime<Utc>>>,
    pub role: Option<ClientRole>,
    /// Wave B2a: same double-Option semantics as `qos`/`expires_at`. Unlike
    /// `role`, this IS settable over the in-tunnel path (see
    /// `TunnelPatchClientRequest`) — it's a routing preference, not a
    /// privilege escalation.
    pub exit_node: Option<Option<String>>,
}

fn client_name_valid(name: &str) -> Result<(), MgmtError> {
    if name.is_empty() || name.len() > 64 {
        return Err(MgmtError::BadRequest("name must be 1–64 characters".into()));
    }
    Ok(())
}

// ── Operations ───────────────────────────────────────────────────────────

/// List all non-tombstoned clients (PSK-stripped).
pub fn list_clients(ctx: &MgmtCtx) -> Vec<ClientView> {
    ctx.db.list_clients().into_iter().map(Into::into).collect()
}

/// Create a client, optionally setting `expires_at`/`role`/`qos` in the
/// same atomic follow-up `update_client` call (mirrors the pre-refactor
/// `add_client` handler, which did the same two-step create-then-update).
pub fn add_client(ctx: &MgmtCtx, args: AddClientArgs) -> Result<ClientView, MgmtError> {
    client_name_valid(&args.name)?;

    let client = if args.one_time {
        ctx.db.add_client_one_time(&args.name)
    } else {
        ctx.db.add_client(&args.name)
    };
    let client = match client {
        Ok(c) => c,
        Err(e) => {
            audit(ctx, "ClientAdd", &args.name, &format!("failed: {}", e));
            return Err(MgmtError::Conflict(e.to_string()));
        }
    };

    let needs_followup =
        args.expires_at.is_some() || args.role != ClientRole::User || args.qos.is_some();
    let result = if needs_followup {
        ctx.db.update_client(
            &client.id,
            UpdateClientParams {
                expires_at: args.expires_at.map(Some),
                role: if args.role != ClientRole::User {
                    Some(args.role)
                } else {
                    None
                },
                qos: args.qos.map(Some),
                ..Default::default()
            },
        )
    } else {
        Ok(client)
    };

    match result {
        Ok(c) => {
            audit(ctx, "ClientAdd", &format!("{} ({})", c.name, c.id), "ok");
            Ok(c.into())
        }
        Err(e) => {
            audit(ctx, "ClientAdd", &args.name, &format!("failed: {}", e));
            Err(MgmtError::Conflict(e.to_string()))
        }
    }
}

/// Update mutable fields on an existing client. Setting `role` to
/// `Viewer`/`Admin` requires the client to already be device-bound; that
/// failure surfaces as `MgmtError::Forbidden` here (the REST handler maps
/// it back to `409 Conflict` to preserve pre-refactor wire compatibility —
/// see `management_api.rs::patch_client`).
pub fn update_client(
    ctx: &MgmtCtx,
    id: &str,
    args: UpdateClientArgs,
) -> Result<ClientView, MgmtError> {
    if let Some(ref name) = args.name {
        client_name_valid(name)?;
    }
    let params = UpdateClientParams {
        name: args.name,
        enabled: args.enabled,
        one_time: args.one_time,
        qos: args.qos,
        expires_at: args.expires_at,
        role: args.role,
        exit_node: args.exit_node,
    };
    match ctx.db.update_client(id, params) {
        Ok(c) => {
            audit(ctx, "ClientPatch", id, "ok");
            Ok(c.into())
        }
        Err(e) => {
            let msg = e.to_string();
            audit(ctx, "ClientPatch", id, &format!("failed: {}", msg));
            if msg.contains("not found") {
                Err(MgmtError::NotFound)
            } else if msg.contains("device binding") {
                Err(MgmtError::Forbidden)
            } else if msg.contains("exit_node") {
                Err(MgmtError::BadRequest(msg))
            } else {
                Err(MgmtError::Conflict(msg))
            }
        }
    }
}

/// Tombstone a client (revoke). Never hard-deletes — see
/// `ClientDatabase::remove_client`'s doc for why (pool-sync convergence).
pub fn remove_client(ctx: &MgmtCtx, id: &str) -> Result<(), MgmtError> {
    match ctx.db.remove_client(id) {
        Ok(()) => {
            audit(ctx, "ClientRemove", id, "ok");
            Ok(())
        }
        Err(e) => {
            audit(ctx, "ClientRemove", id, &format!("failed: {}", e));
            Err(MgmtError::NotFound)
        }
    }
}

/// Admin "revoke" (P1.3) — tombstones `id` exactly like [`remove_client`]
/// (same `ClientDatabase::remove_client` call, same LWW/tombstone-sticky
/// pool-sync convergence guarantee), but under its own `"ClientRevoke"`
/// audit action and its own dedicated route
/// (`POST /api/v1/clients/:id/revoke`, both REST and in-tunnel) so a revoke
/// is distinguishable from a plain `DELETE` in the audit trail and can carry
/// its own side effects.
///
/// **This function is the DB-tombstone + audit half only.** The two other
/// admin-revoke side effects the design calls for — (a) immediately
/// force-disconnecting any live session for `id` on this node, and (b)
/// triggering a high-priority pool beacon so peers converge fast — need a
/// `Gateway`/`SessionManager`/`PoolDialer` handle this axum-free,
/// gateway-unaware module deliberately never holds (see the module-level
/// doc comment). Callers that DO have one perform those side effects
/// themselves right after a successful `revoke()` call:
///   - the in-tunnel path: `gateway.rs`'s `MgmtRequest` handling, which
///     calls `Gateway::force_disconnect_client` + a `PoolDialer::broadcast`
///     priority beacon (both immediate — the gateway holds a live
///     `SessionManager`/`PoolDialer`);
///   - the REST path (`management_api.rs`): `ApiState` carries no
///     `Gateway`/`SessionManager`/`PoolDialer` handle (it's constructed
///     independently of the gateway in `main.rs`, wired only to
///     `ClientDatabase`/`AuditLogger`/etc.), so a REST-triggered revoke
///     relies on the gateway's existing periodic revocation sweep
///     (`gateway.rs`, ~5s cleanup-task cadence) to tear down any live
///     session — that sweep now also sends `Shutdown{reason:4}` before
///     `remove_session` (P1.3), and on the next scheduled pool anti-entropy
///     beacon/tick for peer convergence. Both still happen, just not
///     synchronously with the REST call returning.
pub fn revoke(ctx: &MgmtCtx, id: &str) -> Result<(), MgmtError> {
    match ctx.db.remove_client(id) {
        Ok(()) => {
            audit(ctx, "ClientRevoke", id, "ok");
            Ok(())
        }
        Err(e) => {
            audit(ctx, "ClientRevoke", id, &format!("failed: {}", e));
            Err(MgmtError::NotFound)
        }
    }
}

/// Clear a client's bound device key and re-enable one-time enrollment.
pub fn reset_device(ctx: &MgmtCtx, id: &str) -> Result<(), MgmtError> {
    match ctx.db.reset_device_binding(id) {
        Ok(()) => {
            audit(ctx, "DeviceReset", id, "ok");
            Ok(())
        }
        Err(e) => {
            audit(ctx, "DeviceReset", id, &format!("failed: {}", e));
            Err(MgmtError::NotFound)
        }
    }
}

/// Build the `aivpn://<base64url-json>` connection key for client `id` —
/// THE single implementation of this security-sensitive wire format.
/// Previously duplicated between `main.rs::build_connection_key` (CLI) and
/// `management_api.rs::get_connection_key` (REST) — both now delegate here.
/// JSON body: `{s,k,p,i,n}` always, plus `sk`/`mop` when those keys are
/// configured on this node.
pub fn connection_key(ctx: &MgmtCtx, id: &str) -> Result<String, MgmtError> {
    let (pub_key, server_addr) = match (&ctx.server_pub_key, &ctx.server_addr) {
        (Some(k), Some(a)) => (k, a.as_str()),
        _ => {
            return Err(MgmtError::Unavailable(
                "--server-ip or --key-file not configured; cannot build connection key".into(),
            ))
        }
    };
    let client = ctx.db.find_by_id(id).ok_or(MgmtError::NotFound)?;
    let client_net_cfg = ctx
        .db
        .network_config()
        .client_config(client.vpn_ip)
        .map_err(|e| MgmtError::Internal(e.to_string()))?;

    use base64::Engine;
    let psk_b64 = base64::engine::general_purpose::STANDARD.encode(client.psk);
    let pub_b64 = base64::engine::general_purpose::STANDARD.encode(pub_key);
    let mut json = serde_json::json!({
        "s": server_addr, "k": pub_b64, "p": psk_b64,
        "i": client_net_cfg.client_ip, "n": client_net_cfg,
    });
    // Parity fields: the server's ed25519 signing pubkey (`sk`) and the
    // operator mask-verifying pubkey (`mop`) so a client provisioned via
    // this key can verify signed server messages / pushed masks out of the
    // box, exactly like every other issuance path.
    if let Some(sk) = &ctx.server_signing_pubkey {
        json["sk"] =
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(sk));
    }
    if let Some(mop) = &ctx.mask_operator_pubkey {
        json["mop"] =
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(mop));
    }
    let json_str = serde_json::to_string(&json)
        .map_err(|e| MgmtError::Internal(format!("connection key serialization error: {}", e)))?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json_str.as_bytes());
    Ok(format!("aivpn://{}", encoded))
}

/// Server status summary (kernel-module presence + client counts). Uptime
/// isn't tracked here (this module has no notion of "process start time")
/// — `management_api.rs::get_status` merges this with its own
/// `ApiState::started_at` before responding, keeping the REST JSON shape
/// unchanged.
pub fn status(ctx: &MgmtCtx) -> StatusView {
    let clients = ctx.db.list_clients();
    StatusView {
        clients_total: clients.len(),
        clients_enabled: clients.iter().filter(|c| c.enabled).count(),
        kernel_module: kernel_loaded(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mgmt_service::test_support::*;

    #[test]
    fn add_client_happy_path_returns_view_without_psk() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let view = add_client(
            &c,
            AddClientArgs {
                name: "alice".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .expect("add_client should succeed");
        assert_eq!(view.name, "alice");
        assert!(!view.device_bound);
        assert_eq!(view.role, ClientRole::User);
        // ClientView has no `psk` field at all — this is a compile-time
        // guarantee, not just a runtime check, but assert the shape holds
        // by round-tripping through JSON and checking no psk/p key leaked.
        let json = serde_json::to_value(&view).unwrap();
        assert!(json.get("psk").is_none());
    }
    #[test]
    fn update_client_role_without_device_binding_is_rejected() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "bob".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let err = update_client(
            &c,
            &created.id,
            UpdateClientArgs {
                name: None,
                enabled: None,
                one_time: None,
                qos: None,
                expires_at: None,
                role: Some(ClientRole::Admin),
                exit_node: None,
            },
        )
        .expect_err("elevating role without a bound device must fail");
        assert!(matches!(
            err,
            MgmtError::Forbidden | MgmtError::BadRequest(_)
        ));
    }
    #[test]
    fn update_client_role_succeeds_once_device_bound() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "carol".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();
        db.enroll_device(&created.id, &[9u8; 32]).unwrap();

        let updated = update_client(
            &c,
            &created.id,
            UpdateClientArgs {
                name: None,
                enabled: None,
                one_time: None,
                qos: None,
                expires_at: None,
                role: Some(ClientRole::Admin),
                exit_node: None,
            },
        )
        .expect("elevating a device-bound client's role must succeed");
        assert_eq!(updated.role, ClientRole::Admin);
    }
    #[test]
    fn connection_key_starts_with_scheme_and_decodes_to_expected_fields() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "dave".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        let key = connection_key(&c, &created.id).expect("connection_key should succeed");
        assert!(key.starts_with("aivpn://"));

        use base64::Engine;
        let payload = key.strip_prefix("aivpn://").unwrap();
        let json_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        for field in ["s", "k", "p", "i", "n"] {
            assert!(
                json.get(field).is_some(),
                "connection key JSON missing field '{}'",
                field
            );
        }
    }
    #[test]
    fn list_clients_excludes_tombstoned_clients() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "erin".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();
        assert_eq!(list_clients(&c).len(), 1);

        remove_client(&c, &created.id).unwrap();
        assert!(
            list_clients(&c).is_empty(),
            "a tombstoned (revoked) client must not appear in list_clients"
        );
    }
    #[test]
    fn revoke_tombstones_client_and_it_no_longer_appears_in_list_clients() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "kate".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();
        assert_eq!(list_clients(&c).len(), 1);

        revoke(&c, &created.id).expect("revoke should succeed on a live client");
        assert!(
            list_clients(&c).is_empty(),
            "a revoked client must not appear in list_clients"
        );
    }
    #[test]
    fn revoke_missing_client_is_not_found() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);

        let err = revoke(&c, "does-not-exist").expect_err("revoking an absent id must fail");
        assert!(matches!(err, MgmtError::NotFound));
    }
    #[test]
    fn revoke_emits_client_revoke_audit_action() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let audit_dir = tempfile::tempdir().unwrap();
        let audit_log_path = audit_dir.path().join("audit.jsonl");
        let audit = crate::audit_log::AuditLogger::new(&audit_log_path);

        let mut c = ctx(&db, &mask_dir);
        c.audit = Some(&audit);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "leo".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();

        revoke(&c, &created.id).unwrap();

        let logged = std::fs::read_to_string(&audit_log_path).unwrap();
        assert!(
            logged.contains("\"action\":\"ClientRevoke\""),
            "audit log must contain a ClientRevoke entry, got: {}",
            logged
        );
        assert!(
            logged.contains(&created.id),
            "audit log's ClientRevoke entry must target the revoked client id"
        );
    }
    #[test]
    fn client_view_exposes_exit_node() {
        let (_dir, db) = test_db();
        let mask_dir = std::path::PathBuf::from("/tmp");
        let c = ctx(&db, &mask_dir);
        let created = add_client(
            &c,
            AddClientArgs {
                name: "rex".into(),
                one_time: false,
                expires_at: None,
                role: ClientRole::User,
                qos: None,
            },
        )
        .unwrap();
        assert_eq!(created.exit_node, None);

        let updated = update_client(
            &c,
            &created.id,
            UpdateClientArgs {
                name: None,
                enabled: None,
                one_time: None,
                qos: None,
                expires_at: None,
                role: None,
                exit_node: Some(Some("exit.example.com:51820".to_string())),
            },
        )
        .unwrap();
        assert_eq!(
            updated.exit_node,
            Some("exit.example.com:51820".to_string())
        );
    }
}
