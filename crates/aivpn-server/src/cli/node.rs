//! CLI handlers for pool-node identity management (`--list-nodes`,
//! `--revoke-node`) and the per-node Ed25519 identity seed loader shared
//! with `bootstrap::run_server`.
//!
//! Pure extract-module move from `main.rs` (ÉTAPE 1 decomposition, step 2).

use aivpn_server::node_registry::NodeRegistry;
use std::path::Path;
use tracing::{error, info};

/// PHASE 4 (per-node cryptographic identity, SEND side): resolve this node's
/// own durable Ed25519 identity seed at `path`. Loads it if present (must be
/// exactly 32 raw bytes — same convention as `--key-file`'s server private
/// key, see the `server_private_key` loading above); otherwise generates 32
/// random bytes and persists them atomically with 0600 permissions in a
/// single `create_new` + `mode` open (mirrors `handle_gen_mask_signing_key`'s
/// O_EXCL+mode create — no write-then-chmod window). Never logs the seed
/// itself, only the path it was loaded from or written to.
///
/// BUG D4 fix: a failure to PERSIST a freshly generated seed (either the
/// `create_new` open or the subsequent `write_all`) is FATAL — this used to
/// fall back to an ephemeral, unpersisted, in-memory-only seed "for this run
/// only". That fallback is unsafe once peers have TOFU-pinned this node
/// under its previous identity: every restart after a persist failure would
/// silently mint a brand-new, never-saved identity, and every peer that
/// pinned the old one then rejects this node's `NodeEnrollment` with a
/// `node_pub` mismatch — the node silently loses ALL of its pool
/// route-sync trust. So we hard-exit here, matching the existing hard-exit
/// for a malformed/unreadable EXISTING seed file (see the `Err` arms
/// below) — only the happy path (existing valid seed) and the successful
/// generate-and-persist path return normally.
pub(crate) fn load_or_generate_node_identity_seed(path: &Path) -> [u8; 32] {
    match std::fs::read(path) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                error!(
                    "Pool-node identity key '{}' must be exactly 32 bytes, got {}",
                    path.display(),
                    bytes.len()
                );
                std::process::exit(1);
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            info!("Loaded pool-node identity from {}", path.display());
            seed
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            use rand::RngCore;
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);

            #[cfg(unix)]
            let created = {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
            };
            #[cfg(not(unix))]
            let created = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path);

            match created {
                Ok(mut f) => {
                    use std::io::Write;
                    if let Err(e) = f.write_all(&seed) {
                        error!(
                            "node identity could not be persisted at '{}': {} — refusing to \
                             run with an ephemeral identity that would break pool trust on \
                             restart — fix permissions/disk and retry",
                            path.display(),
                            e
                        );
                        std::process::exit(1);
                    }
                    info!("Generated a new pool-node identity at {}", path.display());
                }
                Err(e) => {
                    error!(
                        "node identity could not be persisted at '{}': {} — refusing to run \
                         with an ephemeral identity that would break pool trust on restart — \
                         fix permissions/disk and retry",
                        path.display(),
                        e
                    );
                    std::process::exit(1);
                }
            }
            seed
        }
        Err(e) => {
            error!(
                "Failed to read pool-node identity key '{}': {}",
                path.display(),
                e
            );
            std::process::exit(1);
        }
    }
}

/// PHASE 4 (per-node crypto identity): print every pool node currently
/// bound in the node identity registry — the set of `node_id`s whose
/// `NodeEnrollment` Ed25519 proof this server will accept, and which
/// `site_sync::handle_route_sync` now trusts over any self-asserted
/// `node_id` in a RouteSync payload. `allow_auto_add: false` here since a
/// read-only listing must never itself bind a new (empty) registry entry.
pub(crate) fn handle_list_nodes(pool_nodes_path: &std::path::Path) {
    use base64::Engine;
    let registry = NodeRegistry::load(pool_nodes_path.to_path_buf(), false);
    let nodes = registry.list();
    if nodes.is_empty() {
        println!("No pool nodes bound.");
        return;
    }
    for (node_id, pubkey) in nodes {
        println!(
            "{}  {}",
            node_id,
            base64::engine::general_purpose::STANDARD.encode(pubkey)
        );
    }
}

/// PHASE 4 (per-node crypto identity): revoke a bound pool node's identity
/// by `node_id`. A revoked node must re-bind (TOFU, if `allow_auto_add` is
/// still enabled in the pool config) before its RouteSync adverts are
/// trusted again — see `site_sync::handle_route_sync`'s `verified_node_id`
/// handling. `allow_auto_add: false` here too: revocation must never
/// silently create the registry file with a fresh (empty) state.
pub(crate) fn handle_revoke_node(pool_nodes_path: &std::path::Path, node_id: &str) {
    let registry = NodeRegistry::load(pool_nodes_path.to_path_buf(), false);
    if registry.revoke(node_id) {
        println!("✅ Pool node '{}' revoked.", node_id);
    } else {
        eprintln!("❌ Pool node '{}' not found in the registry.", node_id);
        std::process::exit(1);
    }
}
