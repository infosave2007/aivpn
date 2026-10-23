//! CLI handlers for pool-node identity management (`--list-nodes`,
//! `--revoke-node`) and the per-node Ed25519 identity seed loader shared
//! with `bootstrap::run_server`.
//!
//! Pure extract-module move from `main.rs` (ÉTAPE 1 decomposition, step 2).

use aivpn_server::node_registry::NodeRegistry;
use std::path::Path;
use tracing::error;

/// Загружает постоянный ключ узла. Ошибка не допускает временную идентичность.
pub(crate) fn load_or_generate_node_identity_seed(path: &Path) -> [u8; 32] {
    aivpn_common::identity_file::load_or_create_secret(path).unwrap_or_else(|error| {
        error!(
            "Не удалось загрузить или сохранить ключ узла '{}': {error}",
            path.display()
        );
        std::process::exit(1);
    })
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
    if let Err(error) = registry.check_health() {
        eprintln!("Реестр узлов недоступен: {error}");
        std::process::exit(1);
    }
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
    match registry.try_revoke(node_id) {
        Ok(true) => println!("Узел '{}' отозван.", node_id),
        Ok(false) => println!("Узел '{}' уже отозван.", node_id),
        Err(error) => {
            eprintln!("Не удалось сохранить отзыв узла: {error}");
            std::process::exit(1);
        }
    }
}
