//! Client Database
//!
//! Manages registered VPN clients with pre-shared keys, static IPs,
//! and per-client statistics. Persisted to JSON file.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use aivpn_common::error::{Error, Result};
use aivpn_common::network_config::VpnNetworkConfig;

mod model;
pub use model::*;

mod merge;
pub use merge::*;

/// Parameters for `ClientDatabase::update_client`.
/// Fields set to `None` are left unchanged.
/// For `qos` / `expires_at`, use `Some(None)` to clear the setting.
#[derive(Debug, Default)]
pub struct UpdateClientParams {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub one_time: Option<bool>,
    pub qos: Option<Option<crate::qos::ClientQos>>,
    /// None = leave unchanged; Some(None) = clear; Some(Some(dt)) = set expiry
    pub expires_at: Option<Option<DateTime<Utc>>>,
    /// None = leave unchanged. Setting `Viewer`/`Admin` requires the client
    /// to already be (or be simultaneously, via `device_pubkey` — not
    /// exposed here, see `update_client`) device-bound; enforced atomically
    /// in `update_client`.
    pub role: Option<ClientRole>,
    /// None = leave unchanged; Some(None) = clear (fall back to the global
    /// default `pool.exit_node`); Some(Some(addr)) = set this client's
    /// exit-node override. `addr` must be `host:port` — validated in
    /// `update_client` via `validate_exit_node_addr`. Unlike `role`, this
    /// carries NO device-binding requirement: it's a routing preference an
    /// Admin sets on behalf of a client, not a privilege the client itself
    /// is granted.
    pub exit_node: Option<Option<String>>,
}

/// Persistent client database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ClientDbFile {
    clients: Vec<ClientConfig>,
    /// Next host offset within the configured VPN subnet to assign.
    #[serde(default = "default_next_host_offset", alias = "next_octet")]
    next_host_offset: u32,
}

fn default_next_host_offset() -> u32 {
    2
}

impl Default for ClientDbFile {
    fn default() -> Self {
        Self {
            clients: Vec::new(),
            next_host_offset: default_next_host_offset(),
        }
    }
}

mod ip_allocation;
pub use ip_allocation::*;

/// Thread-safe client database with file persistence
pub struct ClientDatabase {
    data: RwLock<ClientDbFile>,
    file_path: PathBuf,
    network_config: VpnNetworkConfig,
    /// This node's hard VPN-IP partition, if pool sync is configured — see
    /// `set_node_partition`. `None` (default / single-node / legacy) means
    /// `allocate_vpn_ip` uses the whole subnet, exactly as before Wave B-IP.
    partition: RwLock<Option<PartitionBounds>>,
    last_mtime: Mutex<Option<std::time::SystemTime>>,
    /// data-plane H4: `save()`'s temp file name is PID-only, so two
    /// concurrent `save()` calls in the SAME process (e.g. an admin update
    /// racing a pool-sync merge or a batched stats flush — all take only a
    /// shared read lock on `data`, so nothing stops them overlapping) write
    /// the identical temp path and race on rename order. Whichever rename
    /// lands last wins even if its snapshot was taken first — a silent lost
    /// update. Serializing the full read → serialize → write → rename
    /// sequence behind this mutex makes concurrent saves happen in a strict
    /// order matching call order, so the most recent save always wins.
    save_lock: Mutex<()>,
}

impl ClientDatabase {
    /// Load or create client database from file
    pub fn load(file_path: &Path, network_config: VpnNetworkConfig) -> Result<Self> {
        network_config.validate()?;
        let mut data: ClientDbFile = if file_path.exists() {
            let content = std::fs::read_to_string(file_path)
                .map_err(|e| Error::Session(format!("Failed to read client DB: {}", e)))?;
            if content.trim().is_empty() {
                // A zero-byte DB (e.g. pre-created by a package post-install)
                // is an empty database, not corruption.
                ClientDbFile::default()
            } else {
                serde_json::from_str(&content)
                    .map_err(|e| Error::Session(format!("Failed to parse client DB: {}", e)))?
            }
        } else {
            ClientDbFile::default()
        };

        let last_mtime = Mutex::new(std::fs::metadata(file_path).and_then(|m| m.modified()).ok());

        // Age out old tombstones so clients.json doesn't grow forever
        // (persisted on the next save()).
        reap_expired_tombstones(&mut data.clients);

        // Validate no duplicate VPN IPs in the loaded data
        Self::warn_duplicate_vpn_ips(&data.clients);

        Ok(Self {
            data: RwLock::new(data),
            file_path: file_path.to_path_buf(),
            network_config,
            partition: RwLock::new(None),
            last_mtime,
            save_lock: Mutex::new(()),
        })
    }

    /// Save database to file
    pub fn save(&self) -> Result<()> {
        // data-plane H4: serialize the whole read → write → rename sequence
        // so concurrent callers (admin API update, pool-sync merge, batched
        // stats flush) can never race the same temp file / rename target.
        let _save_guard = self.save_lock.lock();
        let data = self.data.read();
        let content = serde_json::to_string_pretty(&*data)
            .map_err(|e| Error::Session(format!("Failed to serialize client DB: {}", e)))?;

        // Write atomically via temp file (include PID to avoid races with concurrent processes)
        let tmp_path = self
            .file_path
            .with_extension(format!("{}.tmp", std::process::id()));
        std::fs::write(&tmp_path, &content)
            .map_err(|e| Error::Session(format!("Failed to write client DB: {}", e)))?;
        // server-sec HIGH4: clients.json holds every client's PSK in
        // plaintext (base64). std::fs::write() creates the file with the
        // process umask (commonly 0644 under root) — world/group readable.
        // Harden the temp file BEFORE the rename makes it visible at the
        // real path, so there is no window where the final file is
        // reachable with lax permissions.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) =
                std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))
            {
                warn!("Failed to set clients DB permissions to 0600: {}", e);
            }
        }
        std::fs::rename(&tmp_path, &self.file_path)
            .map_err(|e| Error::Session(format!("Failed to rename client DB: {}", e)))?;

        // Refresh cached mtime so reload_if_changed ignores our own write
        if let Ok(mtime) = std::fs::metadata(&self.file_path).and_then(|m| m.modified()) {
            *self.last_mtime.lock() = Some(mtime);
        }

        Ok(())
    }

    /// Validate that `content` deserializes as a well-formed clients-DB JSON
    /// document, without loading it into a live database. Used by backup
    /// import (`backup.rs`) to reject a corrupt or malicious `clients.json`
    /// BEFORE it is ever written into the live, hot-reloaded config
    /// directory (data-plane H5).
    pub(crate) fn validate_json(content: &[u8]) -> Result<()> {
        if content.iter().all(|b| b.is_ascii_whitespace()) {
            return Ok(()); // treated as an empty DB, same as `load()`
        }
        serde_json::from_slice::<ClientDbFile>(content)
            .map(|_| ())
            .map_err(|e| Error::Session(format!("Failed to parse client DB: {}", e)))
    }

    /// Add a new client, returns the generated config
    pub fn add_client(&self, name: &str) -> Result<ClientConfig> {
        self.add_client_inner(name, None)
    }

    /// Add a new client already bound to `device_pubkey` at creation time.
    ///
    /// Unlike `add_client`, the returned (and persisted) record has
    /// `device_pubkey: Some(..)` from the start, so it can be elevated to
    /// `Viewer`/`Admin` via `update_client` immediately — no separate
    /// `enroll_device` round trip needed. Used by the SSH installer
    /// (Phase C) to create a device-bound admin client for the installing
    /// app in one shot.
    pub fn add_client_bound(&self, name: &str, device_pubkey: [u8; 32]) -> Result<ClientConfig> {
        self.add_client_inner(name, Some(device_pubkey))
    }

    fn add_client_inner(
        &self,
        name: &str,
        device_pubkey: Option<[u8; 32]>,
    ) -> Result<ClientConfig> {
        let mut data = self.data.write();

        // Check name uniqueness (tombstones don't hold their name)
        if data.clients.iter().any(|c| c.name == name && !c.deleted) {
            return Err(Error::Session(format!("Client '{}' already exists", name)));
        }

        // Allocate VPN IP
        let vpn_ip = self.allocate_vpn_ip(&mut data)?;

        // Generate random ID and PSK
        let mut id_bytes = [0u8; 8];
        let mut psk = [0u8; 32];
        chacha20poly1305::aead::OsRng.fill_bytes(&mut id_bytes);
        chacha20poly1305::aead::OsRng.fill_bytes(&mut psk);

        let id = id_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        let client = ClientConfig {
            id,
            name: name.to_string(),
            psk,
            vpn_ip,
            enabled: true,
            created_at: Utc::now(),
            stats: ClientStats::default(),
            qos: None,
            device_pubkey,
            one_time: false,
            expires_at: None,
            updated_at: Some(Utc::now()),
            deleted: false,
            role: ClientRole::User,
            exit_node: None,
        };

        data.clients.push(client.clone());
        drop(data);

        self.save()?;
        Ok(client)
    }

    /// Add a new one-time enrollment client — the first device to connect will be auto-bound.
    pub fn add_client_one_time(&self, name: &str) -> Result<ClientConfig> {
        let mut client = self.add_client(name)?;
        {
            let mut data = self.data.write();
            if let Some(c) = data.clients.iter_mut().find(|c| c.id == client.id) {
                c.one_time = true;
                client.one_time = true;
            }
        }
        self.save()?;
        Ok(client)
    }

    /// Add a new one-time enrollment client already bound to `device_pubkey`
    /// at creation time. Combines `add_client_bound` with the `one_time`
    /// flag: since the device is already known, this mainly buys strict
    /// per-device mismatch enforcement on re-enroll (same as a client that
    /// was auto-bound via the classic one-time flow).
    pub fn add_client_one_time_bound(
        &self,
        name: &str,
        device_pubkey: [u8; 32],
    ) -> Result<ClientConfig> {
        let mut client = self.add_client_bound(name, device_pubkey)?;
        {
            let mut data = self.data.write();
            if let Some(c) = data.clients.iter_mut().find(|c| c.id == client.id) {
                c.one_time = true;
                client.one_time = true;
            }
        }
        self.save()?;
        Ok(client)
    }

    /// Find client by human-readable name.
    pub fn find_by_name(&self, name: &str) -> Option<ClientConfig> {
        let data = self.data.read();
        data.clients
            .iter()
            .find(|c| c.name == name && !c.deleted)
            .cloned()
    }

    /// Enroll or verify a device public key for `client_id`.
    ///
    /// Returns `Ok(true)` if the key was newly bound (one-time enrollment completed).
    /// Returns `Ok(false)` if the key was already bound and matches.
    /// Returns `Err` if there is an existing binding that does not match the presented key.
    pub fn enroll_device(&self, client_id: &str, static_pub: &[u8; 32]) -> Result<bool> {
        let mut data = self.data.write();
        let client = data
            .clients
            .iter_mut()
            .find(|c| c.id == client_id)
            .ok_or_else(|| Error::Session(format!("Client '{}' not found", client_id)))?;

        let enforce = client.one_time;
        match client.device_pubkey {
            None => {
                // First connect — always record. one_time is preserved so subsequent
                // connections from a different device are still rejected for one-time creds.
                client.device_pubkey = Some(*static_pub);
                drop(data);
                self.save()?;
                Ok(true)
            }
            Some(ref bound) => {
                use subtle::ConstantTimeEq;
                if bound.ct_eq(static_pub).into() {
                    Ok(false)
                } else if enforce {
                    // one_time = true: strict per-device enforcement
                    Err(Error::Session(format!(
                        "Device binding mismatch for client '{}'",
                        client_id
                    )))
                } else {
                    // one_time = false (regular credential): update binding on re-enroll
                    // (e.g. reinstall, device replacement) without rejecting
                    client.device_pubkey = Some(*static_pub);
                    drop(data);
                    self.save()?;
                    Ok(true)
                }
            }
        }
    }

    /// Reset device binding — clears the bound key and re-enables one-time enrollment.
    pub fn reset_device_binding(&self, client_id: &str) -> Result<()> {
        let mut data = self.data.write();
        let client = data
            .clients
            .iter_mut()
            .find(|c| c.id == client_id)
            .ok_or_else(|| Error::Session(format!("Client '{}' not found", client_id)))?;
        client.device_pubkey = None;
        client.one_time = true;
        drop(data);
        self.save()
    }

    pub fn network_config(&self) -> VpnNetworkConfig {
        self.network_config.clone()
    }

    /// Path to the on-disk JSON file backing this database. Used by
    /// callers (e.g. pool sync) that need a sibling location for their
    /// own small state files.
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    /// Remove a client by ID.
    ///
    /// The record is converted into a tombstone (not hard-deleted) so the
    /// revocation propagates convergently through pool sync: a peer's stale
    /// live copy of this client must not re-add / re-enable it here. The PSK
    /// is kept in the tombstone so peers can match the record (`merge_from_json`
    /// requires an id+PSK match) and apply the deletion themselves.
    pub fn remove_client(&self, client_id: &str) -> Result<()> {
        let mut data = self.data.write();
        let client = data
            .clients
            .iter_mut()
            .find(|c| c.id == client_id && !c.deleted)
            .ok_or_else(|| Error::Session(format!("Client '{}' not found", client_id)))?;
        client.deleted = true;
        client.enabled = false;
        client.device_pubkey = None;
        client.updated_at = Some(Utc::now());
        drop(data);
        self.save()?;
        Ok(())
    }

    /// Get all clients (tombstoned/deleted records excluded)
    pub fn list_clients(&self) -> Vec<ClientConfig> {
        self.data
            .read()
            .clients
            .iter()
            .filter(|c| !c.deleted)
            .cloned()
            .collect()
    }

    /// Full client list INCLUDING tombstones (records with `deleted == true`).
    ///
    /// Pool sync MUST use this — not `list_clients()` — so that revocations
    /// (tombstones) propagate to peer nodes. `list_clients()` hard-filters
    /// tombstones, so building a sync payload from it silently drops every
    /// deletion and leaves revoked clients live on every other pool node.
    pub fn list_clients_including_deleted(&self) -> Vec<ClientConfig> {
        self.data.read().clients.clone()
    }

    /// Find client by PSK (used during handshake to identify the connecting client).
    /// Returns `None` for disabled clients and for clients whose `expires_at` is in the past,
    /// consistent with the gateway's own handshake-iteration checks.
    pub fn find_by_psk(&self, psk: &[u8; 32]) -> Option<ClientConfig> {
        let data = self.data.read();
        data.clients
            .iter()
            .find(|c| {
                !c.deleted
                    && c.enabled
                    && !c.expires_at.is_some_and(|t| t <= chrono::Utc::now())
                    && subtle::ConstantTimeEq::ct_eq(&c.psk[..], &psk[..]).into()
            })
            .cloned()
    }

    /// Find client by VPN IP
    pub fn find_by_vpn_ip(&self, ip: &Ipv4Addr) -> Option<ClientConfig> {
        let data = self.data.read();
        data.clients
            .iter()
            .find(|c| c.vpn_ip == *ip && !c.deleted)
            .cloned()
    }

    /// Find client by ID
    pub fn find_by_id(&self, id: &str) -> Option<ClientConfig> {
        let data = self.data.read();
        data.clients
            .iter()
            .find(|c| c.id == id && !c.deleted)
            .cloned()
    }

    /// Update client stats (called from gateway on traffic)
    pub fn record_handshake(&self, client_id: &str) {
        let mut data = self.data.write();
        if let Some(client) = data.clients.iter_mut().find(|c| c.id == client_id) {
            client.stats.total_connections += 1;
            client.stats.last_handshake = Some(Utc::now());
            client.stats.last_connected = Some(Utc::now());
        }
    }

    /// Update traffic counters
    pub fn record_traffic(&self, client_id: &str, bytes_in: u64, bytes_out: u64) {
        let mut data = self.data.write();
        if let Some(client) = data.clients.iter_mut().find(|c| c.id == client_id) {
            client.stats.bytes_in += bytes_in;
            client.stats.bytes_out += bytes_out;
            client.stats.last_connected = Some(Utc::now());
        }
    }

    /// Persist stats periodically (called from a background task)
    pub fn flush_stats(&self) {
        if let Err(e) = self.save() {
            warn!("Failed to flush client stats: {}", e);
        }
    }

    /// Reload client database from disk if the file has changed.
    /// Preserves in-memory traffic stats for existing clients.
    /// Returns true if the client configuration changed.
    pub fn reload_if_changed(&self) -> bool {
        let metadata = match std::fs::metadata(&self.file_path) {
            Ok(m) => m,
            Err(_) => return false,
        };

        let current_mtime = metadata.modified().ok();
        {
            let last = self.last_mtime.lock();
            if *last == current_mtime {
                return false;
            }
        }

        match self.reload_from_disk() {
            Ok(changed) => {
                *self.last_mtime.lock() = current_mtime;
                if changed {
                    info!(
                        "Client database reloaded from disk ({} clients)",
                        self.list_clients().len()
                    );
                }
                changed
            }
            Err(e) => {
                warn!("Failed to reload client DB: {}", e);
                false
            }
        }
    }

    /// Internal: reload from disk, merging with in-memory stats.
    /// Returns Ok(true) if data changed, Ok(false) if unchanged.
    fn reload_from_disk(&self) -> Result<bool> {
        let content = std::fs::read_to_string(&self.file_path)
            .map_err(|e| Error::Session(format!("Failed to read client DB for reload: {}", e)))?;
        let new_data: ClientDbFile = serde_json::from_str(&content)
            .map_err(|e| Error::Session(format!("Failed to parse client DB for reload: {}", e)))?;

        let mut data = self.data.write();

        // Check if anything actually changed in the client configuration.
        // The signature must cover EVERY synced field (via the same
        // canonical-field digest pool sync uses — see
        // `merge::client_record_digest`), not just (id, name, psk, vpn_ip,
        // enabled): otherwise an external edit that touches only
        // device_pubkey / one_time / qos / role / expires_at / exit_node
        // (e.g. a sibling `aivpn-server --reset-device` / `--set-client-qos`
        // process) is never applied, AND `reload_if_changed` still consumes
        // the mtime, so the change would never be picked up at all.
        // vpn_ip rides alongside the digest because it is deliberately not
        // part of the pool-sync canonical field set (re-homed on conflict).
        let old_sig: std::collections::HashMap<String, ([u8; 32], Ipv4Addr)> = data
            .clients
            .iter()
            .map(|c| (c.id.clone(), (merge::client_record_digest(c), c.vpn_ip)))
            .collect();
        let new_sig: std::collections::HashMap<String, ([u8; 32], Ipv4Addr)> = new_data
            .clients
            .iter()
            .map(|c| (c.id.clone(), (merge::client_record_digest(c), c.vpn_ip)))
            .collect();
        let changed = old_sig != new_sig;

        if !changed {
            return Ok(false);
        }

        // Build a map of existing stats by client ID
        let mut stats_map: std::collections::HashMap<String, ClientStats> =
            std::collections::HashMap::new();
        for client in &data.clients {
            stats_map.insert(client.id.clone(), client.stats.clone());
        }

        // Replace clients list, preserving stats for existing clients
        let new_clients: Vec<ClientConfig> = new_data
            .clients
            .into_iter()
            .map(|mut c| {
                if let Some(saved_stats) = stats_map.get(&c.id) {
                    c.stats = saved_stats.clone();
                }
                c
            })
            .collect();

        Self::warn_duplicate_vpn_ips(&new_clients);

        data.clients = new_clients;
        data.next_host_offset = new_data.next_host_offset;

        Ok(true)
    }

    /// Export the full client list as JSON (for pool sync or backup).
    pub fn export_json(&self) -> Result<String> {
        let data = self.data.read();
        serde_json::to_string(&data.clients)
            .map_err(|e| Error::Session(format!("export_json: {}", e)))
    }

    /// Update mutable client fields in one atomic write.
    /// Only `Some` fields are applied; `None` means "leave unchanged".
    /// For QoS, use `Some(None)` to clear the setting.
    pub fn update_client(
        &self,
        client_id: &str,
        params: UpdateClientParams,
    ) -> Result<ClientConfig> {
        if let Some(ref name) = params.name {
            if name.trim().is_empty() {
                return Err(Error::Session("Client name must not be empty".into()));
            }
        }
        if let Some(Some(ref addr)) = params.exit_node {
            validate_exit_node_addr(addr)?;
        }
        let mut data = self.data.write();
        if let Some(ref new_name) = params.name {
            if data
                .clients
                .iter()
                .any(|c| c.name == *new_name && c.id != client_id && !c.deleted)
            {
                return Err(Error::Session(format!(
                    "Client name '{}' already taken",
                    new_name
                )));
            }
        }
        let client = data
            .clients
            .iter_mut()
            .find(|c| c.id == client_id && !c.deleted)
            .ok_or_else(|| Error::Session(format!("Client '{}' not found", client_id)))?;
        // Elevating to Viewer/Admin requires the client to already be
        // device-bound: role is only ever authenticated via the connecting
        // device's static key during the handshake, so granting it to a
        // PSK-only (not-yet-bound) client would be a privilege that can
        // never actually be proven to belong to whoever shows up with the
        // PSK. Checked against the CURRENT `device_pubkey` — this call never
        // sets one, so there is no ordering trick to bypass it.
        if let Some(role) = params.role {
            if role != ClientRole::User && client.device_pubkey.is_none() {
                return Err(Error::Session("role requires device binding".into()));
            }
        }
        if let Some(name) = params.name {
            client.name = name;
        }
        if let Some(enabled) = params.enabled {
            client.enabled = enabled;
        }
        if let Some(one_time) = params.one_time {
            client.one_time = one_time;
        }
        if let Some(qos) = params.qos {
            client.qos = qos;
        }
        if let Some(expires_at) = params.expires_at {
            client.expires_at = expires_at;
        }
        if let Some(role) = params.role {
            client.role = role;
        }
        if let Some(exit_node) = params.exit_node {
            client.exit_node = exit_node;
        }
        client.updated_at = Some(Utc::now());
        let updated = client.clone();
        drop(data);
        self.save()?;
        Ok(updated)
    }

    /// Update QoS settings for a specific client.
    pub fn set_client_qos(&self, client_id: &str, qos: crate::qos::ClientQos) -> Result<()> {
        let mut data = self.data.write();
        match data
            .clients
            .iter_mut()
            .find(|c| c.id == client_id && !c.deleted)
        {
            Some(client) => {
                client.qos = Some(qos);
                client.updated_at = Some(Utc::now());
                drop(data);
                self.save()
            }
            None => Err(Error::Session(format!("Client '{}' not found", client_id))),
        }
    }
}

/// Shared test fixtures used by `client_db` and all of its submodules
/// (`model`, `ip_allocation`, `merge`) — a single source of truth so every
/// submodule's tests build against the identical network config instead of
/// N duplicated copies drifting apart. See `mgmt_service::test_support` for
/// the same pattern used by that module's decomposition.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) fn test_network_config() -> VpnNetworkConfig {
        VpnNetworkConfig {
            server_vpn_ip: Ipv4Addr::new(10, 99, 0, 1),
            prefix_len: 24,
            mtu: 1400,
            keepalive_secs: None,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::test_network_config;
    use super::*;
    use std::time::Duration;

    #[test]
    fn load_treats_empty_file_as_empty_database() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("clients.json");
        // Package post-installs pre-create the DB as a zero-byte file.
        std::fs::write(&db_path, "").unwrap();

        let db = ClientDatabase::load(&db_path, test_network_config()).unwrap();
        assert!(db.list_clients().is_empty());

        // Whitespace-only must behave the same way.
        std::fs::write(&db_path, "  \n\t\n").unwrap();
        let db = ClientDatabase::load(&db_path, test_network_config()).unwrap();
        assert!(db.list_clients().is_empty());

        // A fresh DB must still be usable: adding a client persists it.
        db.add_client("alice").unwrap();
        let reloaded = ClientDatabase::load(&db_path, test_network_config()).unwrap();
        assert_eq!(reloaded.list_clients().len(), 1);
    }

    #[test]
    fn reload_if_changed_applies_psk_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("clients.json");
        let db = ClientDatabase::load(&db_path, test_network_config()).unwrap();

        let client = db.add_client("alice").unwrap();
        let old_psk = client.psk;

        db.record_traffic(&client.id, 111, 222);

        let mut on_disk: ClientDbFile =
            serde_json::from_str(&std::fs::read_to_string(&db_path).unwrap()).unwrap();
        let new_psk = [0xAB; 32];
        on_disk.clients[0].psk = new_psk;

        let original_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();
        let updated_json = serde_json::to_string_pretty(&on_disk).unwrap();
        let mut mtime_changed = false;
        for _ in 0..20 {
            std::fs::write(&db_path, &updated_json).unwrap();
            let new_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();
            if new_mtime != original_mtime {
                mtime_changed = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(60));
        }
        assert!(
            mtime_changed,
            "test setup failed to advance client DB mtime"
        );

        assert!(db.reload_if_changed(), "PSK rotation must trigger reload");
        assert!(
            db.find_by_psk(&old_psk).is_none(),
            "old PSK must stop authenticating after reload"
        );

        let reloaded = db
            .find_by_psk(&new_psk)
            .expect("new PSK must authenticate after reload");
        assert_eq!(reloaded.id, client.id);
        assert_eq!(reloaded.stats.bytes_in, 111);
        assert_eq!(reloaded.stats.bytes_out, 222);
    }

    /// Regression: the reload change-signature must cover ALL synced fields,
    /// not just (id, name, psk, vpn_ip, enabled). A sibling process running
    /// `--reset-device` (device_pubkey + one_time) or `--set-client-qos`
    /// (qos), or a manual edit of role/expires_at/exit_node, used to leave
    /// the signature unchanged — and since `reload_if_changed` consumes the
    /// mtime anyway, the edit would NEVER be applied without a restart.
    #[test]
    fn reload_if_changed_applies_external_qos_role_and_device_edits() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("clients.json");
        let db = ClientDatabase::load(&db_path, test_network_config()).unwrap();

        let client = db.add_client("alice").unwrap();

        let mut on_disk: ClientDbFile =
            serde_json::from_str(&std::fs::read_to_string(&db_path).unwrap()).unwrap();
        on_disk.clients[0].device_pubkey = Some([0x42; 32]);
        on_disk.clients[0].one_time = false;
        on_disk.clients[0].role = ClientRole::Admin;
        on_disk.clients[0].exit_node = Some("10.0.9.9:51820".to_string());
        on_disk.clients[0].qos = Some(crate::qos::ClientQos {
            bandwidth_limit_up: Some(1_000_000),
            ..Default::default()
        });

        let original_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();
        let updated_json = serde_json::to_string_pretty(&on_disk).unwrap();
        let mut mtime_changed = false;
        for _ in 0..20 {
            std::fs::write(&db_path, &updated_json).unwrap();
            let new_mtime = std::fs::metadata(&db_path).unwrap().modified().unwrap();
            if new_mtime != original_mtime {
                mtime_changed = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(60));
        }
        assert!(
            mtime_changed,
            "test setup failed to advance client DB mtime"
        );

        assert!(
            db.reload_if_changed(),
            "device_pubkey/one_time/role/exit_node/qos edits must trigger reload"
        );
        let reloaded = db.find_by_id(&client.id).unwrap();
        assert_eq!(reloaded.device_pubkey, Some([0x42; 32]));
        assert!(!reloaded.one_time);
        assert_eq!(reloaded.role, ClientRole::Admin);
        assert_eq!(reloaded.exit_node.as_deref(), Some("10.0.9.9:51820"));
        assert_eq!(
            reloaded.qos.as_ref().and_then(|q| q.bandwidth_limit_up),
            Some(1_000_000)
        );

        // And a second reload with no further edits must report "unchanged"
        // (the digest covers the same field set on both sides).
        assert!(
            !db.reload_if_changed(),
            "no on-disk change must not be reported as changed"
        );
    }

    #[test]
    fn update_client_rejects_elevated_role_without_device_binding() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();
        let client = db.add_client("no-device").unwrap();
        assert!(client.device_pubkey.is_none());

        for role in [ClientRole::Viewer, ClientRole::Admin] {
            let err = db
                .update_client(
                    &client.id,
                    UpdateClientParams {
                        role: Some(role),
                        ..Default::default()
                    },
                )
                .unwrap_err();
            assert!(
                err.to_string().contains("device binding"),
                "unexpected error for {:?}: {}",
                role,
                err
            );
        }
        // Role must remain unchanged (User) after the rejected attempts.
        assert_eq!(db.find_by_id(&client.id).unwrap().role, ClientRole::User);

        // Once device-bound, elevation succeeds.
        db.enroll_device(&client.id, &[0x33; 32]).unwrap();
        db.update_client(
            &client.id,
            UpdateClientParams {
                role: Some(ClientRole::Admin),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(db.find_by_id(&client.id).unwrap().role, ClientRole::Admin);
    }

    // --- Wave C1a: device-bound client creation -------------------------

    #[test]
    fn add_client_bound_sets_device_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();
        let pubkey = [0x44u8; 32];
        let client = db.add_client_bound("installer-admin", pubkey).unwrap();
        assert_eq!(client.device_pubkey, Some(pubkey));
        assert_eq!(client.role, ClientRole::User);

        // Persisted record must also carry the binding (not just the
        // in-memory return value).
        let reloaded = db.find_by_id(&client.id).unwrap();
        assert_eq!(reloaded.device_pubkey, Some(pubkey));
    }

    #[test]
    fn add_client_bound_can_be_elevated_to_admin_immediately() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();
        let client = db
            .add_client_bound("installer-admin", [0x55u8; 32])
            .unwrap();

        // Unlike an unbound client, elevation must succeed right away —
        // no separate enroll_device() round trip needed.
        db.update_client(
            &client.id,
            UpdateClientParams {
                role: Some(ClientRole::Admin),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(db.find_by_id(&client.id).unwrap().role, ClientRole::Admin);
    }

    #[test]
    fn add_client_still_creates_unbound_client_and_rejects_elevation() {
        // Regression: plain add_client() must remain device-UNBOUND, and
        // elevating it without a prior enroll_device() must still fail.
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();
        let client = db.add_client("plain").unwrap();
        assert!(client.device_pubkey.is_none());

        let err = db
            .update_client(
                &client.id,
                UpdateClientParams {
                    role: Some(ClientRole::Admin),
                    ..Default::default()
                },
            )
            .unwrap_err();
        assert!(err.to_string().contains("device binding"));
    }

    #[test]
    fn add_client_bound_rejects_duplicate_name() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();
        db.add_client("dup").unwrap();
        let err = db.add_client_bound("dup", [0x66u8; 32]).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn add_client_one_time_bound_sets_pubkey_and_one_time_flag() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();
        let client = db
            .add_client_one_time_bound("installer-admin", [0x77u8; 32])
            .unwrap();
        assert_eq!(client.device_pubkey, Some([0x77u8; 32]));
        assert!(client.one_time);

        // A different device presenting the PSK is still rejected.
        let err = db.enroll_device(&client.id, &[0x88u8; 32]).unwrap_err();
        assert!(err.to_string().contains("mismatch"));

        // The actual bound device re-enrolling is fine (already matches).
        assert_eq!(db.enroll_device(&client.id, &[0x77u8; 32]).unwrap(), false);
    }

    // --- Wave B2a: per-client exit_node config layer -------------------

    #[test]
    fn update_client_sets_and_clears_exit_node_double_option() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();
        let client = db.add_client("exit-node-client").unwrap();
        assert_eq!(client.exit_node, None);

        // None (leave unchanged) — a no-op update must not touch exit_node.
        db.update_client(
            &client.id,
            UpdateClientParams {
                name: Some("exit-node-client".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(db.find_by_id(&client.id).unwrap().exit_node, None);

        // Some(Some(addr)) — set.
        let updated = db
            .update_client(
                &client.id,
                UpdateClientParams {
                    exit_node: Some(Some("10.0.9.9:51820".to_string())),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(updated.exit_node, Some("10.0.9.9:51820".to_string()));
        assert_eq!(
            db.find_by_id(&client.id).unwrap().exit_node,
            Some("10.0.9.9:51820".to_string())
        );

        // Some(None) — clear.
        let cleared = db
            .update_client(
                &client.id,
                UpdateClientParams {
                    exit_node: Some(None),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(cleared.exit_node, None);
        assert_eq!(db.find_by_id(&client.id).unwrap().exit_node, None);
    }

    #[test]
    fn update_client_rejects_malformed_exit_node() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();
        let client = db.add_client("bad-exit-node").unwrap();

        for bad in ["no-port-here", "", ":51820", "host:not-a-port", "host:"] {
            let err = db
                .update_client(
                    &client.id,
                    UpdateClientParams {
                        exit_node: Some(Some(bad.to_string())),
                        ..Default::default()
                    },
                )
                .unwrap_err();
            assert!(
                err.to_string().contains("exit_node"),
                "unexpected error for {:?}: {}",
                bad,
                err
            );
        }
        // Must remain unset after all rejected attempts.
        assert_eq!(db.find_by_id(&client.id).unwrap().exit_node, None);

        // A well-formed value succeeds.
        db.update_client(
            &client.id,
            UpdateClientParams {
                exit_node: Some(Some("exit.example.com:443".to_string())),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            db.find_by_id(&client.id).unwrap().exit_node,
            Some("exit.example.com:443".to_string())
        );
    }
}
