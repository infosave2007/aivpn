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
use tracing::{error, info, warn};

use aivpn_common::error::{Error, Result};
use aivpn_common::network_config::VpnNetworkConfig;

/// Client configuration and credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Unique client ID (UUID-like hex string)
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Pre-shared key (32 bytes, base64-encoded in JSON).
    /// SECURITY: never return `ClientConfig` directly from API handlers — use `ClientResponse`
    /// instead, which explicitly excludes this field.
    #[serde(with = "base64_bytes")]
    pub psk: [u8; 32],
    /// Assigned static VPN IP
    pub vpn_ip: Ipv4Addr,
    /// Whether client is enabled
    pub enabled: bool,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Traffic and connection statistics
    pub stats: ClientStats,
    /// Per-client QoS / bandwidth settings (0.8.0+, optional for backward compat)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qos: Option<crate::qos::ClientQos>,
    /// Static X25519 device public key bound to this client (0.9.0+).
    /// None = any device may connect; Some = only the enrolled device may connect.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_base64_bytes"
    )]
    pub device_pubkey: Option<[u8; 32]>,
    /// When true, the first connecting device's static key is auto-bound (one-time enrollment).
    #[serde(default)]
    pub one_time: bool,
    /// Optional expiry timestamp. When set and in the past, the client cannot connect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Last-modified timestamp, used for last-writer-wins conflict resolution
    /// in pool sync (`merge_from_json`). `None` on records written by older
    /// versions — treated as "older than any timestamped record".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    /// Tombstone: the client was deleted locally. The record is kept (and
    /// synced) so the deletion propagates convergently through the pool — a
    /// peer's stale live copy must not resurrect a revoked client. Tombstoned
    /// clients are invisible to all lookup/list paths.
    #[serde(default, skip_serializing_if = "is_false")]
    pub deleted: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// How long a tombstone (deleted client record) is kept before being hard-
/// deleted. Must be well beyond any plausible pool-node downtime so every
/// peer receives the revocation first — a peer that was offline less than
/// this still converges on the tombstone via pool sync. Without a TTL,
/// tombstones accumulate forever: `clients.json` and every 5-second sync
/// payload grow unbounded, and revoked records would otherwise pin state
/// permanently.
const TOMBSTONE_TTL: chrono::Duration = chrono::Duration::days(30);

/// Drop tombstones older than [`TOMBSTONE_TTL`] (by `updated_at`, i.e. the
/// deletion time). Untimestamped tombstones (written by pre-`updated_at`
/// versions) are kept — they cannot be aged, and are rare enough not to
/// matter for growth. Returns `true` if anything was removed.
fn reap_expired_tombstones(clients: &mut Vec<ClientConfig>) -> bool {
    let cutoff = Utc::now() - TOMBSTONE_TTL;
    let before = clients.len();
    clients.retain(|c| !(c.deleted && c.updated_at.is_some_and(|t| t < cutoff)));
    before != clients.len()
}

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
}

/// Per-client traffic statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientStats {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub last_connected: Option<DateTime<Utc>>,
    pub total_connections: u64,
    pub last_handshake: Option<DateTime<Utc>>,
}

/// Persistent client database
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientDbFile {
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

/// Thread-safe client database with file persistence
pub struct ClientDatabase {
    data: RwLock<ClientDbFile>,
    file_path: PathBuf,
    network_config: VpnNetworkConfig,
    last_mtime: Mutex<Option<std::time::SystemTime>>,
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
            last_mtime,
        })
    }

    /// Save database to file
    pub fn save(&self) -> Result<()> {
        let data = self.data.read();
        let content = serde_json::to_string_pretty(&*data)
            .map_err(|e| Error::Session(format!("Failed to serialize client DB: {}", e)))?;

        // Write atomically via temp file (include PID to avoid races with concurrent processes)
        let tmp_path = self
            .file_path
            .with_extension(format!("{}.tmp", std::process::id()));
        std::fs::write(&tmp_path, &content)
            .map_err(|e| Error::Session(format!("Failed to write client DB: {}", e)))?;
        std::fs::rename(&tmp_path, &self.file_path)
            .map_err(|e| Error::Session(format!("Failed to rename client DB: {}", e)))?;

        // Refresh cached mtime so reload_if_changed ignores our own write
        if let Ok(mtime) = std::fs::metadata(&self.file_path).and_then(|m| m.modified()) {
            *self.last_mtime.lock() = Some(mtime);
        }

        Ok(())
    }

    /// Add a new client, returns the generated config
    pub fn add_client(&self, name: &str) -> Result<ClientConfig> {
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
            device_pubkey: None,
            one_time: false,
            expires_at: None,
            updated_at: Some(Utc::now()),
            deleted: false,
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
        // PSK must be part of the signature so secret rotation takes effect
        // without requiring a full server restart.
        let old_sig: std::collections::HashSet<(String, String, [u8; 32], Ipv4Addr, bool)> = data
            .clients
            .iter()
            .map(|c| (c.id.clone(), c.name.clone(), c.psk, c.vpn_ip, c.enabled))
            .collect();
        let new_sig: std::collections::HashSet<(String, String, [u8; 32], Ipv4Addr, bool)> =
            new_data
                .clients
                .iter()
                .map(|c| (c.id.clone(), c.name.clone(), c.psk, c.vpn_ip, c.enabled))
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

    /// Log an error for any duplicate VPN IPs found in the client list.
    /// Does not modify the list — the caller decides how to handle duplicates.
    fn warn_duplicate_vpn_ips(clients: &[ClientConfig]) {
        let mut seen: std::collections::HashMap<Ipv4Addr, &str> = std::collections::HashMap::new();
        for client in clients {
            // Tombstones don't hold their IP (it may have been legitimately
            // reassigned by allocate_vpn_ip) and never get a session.
            if client.deleted {
                continue;
            }
            if let Some(first_name) = seen.get(&client.vpn_ip) {
                error!(
                    "Duplicate VPN IP {} assigned to clients '{}' and '{}'. \
                     The second connecting client will evict the first session. \
                     Fix clients.json to resolve this conflict.",
                    client.vpn_ip, first_name, client.name
                );
            } else {
                seen.insert(client.vpn_ip, &client.name);
            }
        }
    }

    /// Merge clients received from a pool peer into the local database.
    /// Upserts by client ID — adds new clients, updates existing ones if PSK matches.
    ///
    /// Convergent revocation: local deletions are tombstones (see
    /// `remove_client`) and revocation is STICKY — an incoming tombstone
    /// always beats a live local record, and a local tombstone is never
    /// overwritten by a live incoming record, regardless of timestamps (a
    /// clock-skewed or later admin edit on a peer must not un-revoke).
    /// Between records of the same liveness, conflicts are resolved
    /// last-writer-wins on `updated_at`. Records without `updated_at` (older
    /// peer versions) are treated as older than any timestamped record;
    /// between two untimestamped live records the legacy overwrite behavior
    /// is kept.
    ///
    /// Tombstones past `TOMBSTONE_TTL` are reaped at the end of every merge
    /// (and at load), so `clients.json` and the sync payload stay bounded.
    ///
    /// Returns the number of clients merged.
    pub fn merge_from_json(&self, json: &str) -> Result<usize> {
        let incoming: Vec<ClientConfig> = serde_json::from_str(json)
            .map_err(|e| Error::Session(format!("merge_from_json parse: {}", e)))?;
        let mut data = self.data.write();
        let mut merged = 0usize;
        for mut inc in incoming {
            if let Some(existing) = data.clients.iter_mut().find(|c| c.id == inc.id) {
                // Only update if PSK matches (same logical client)
                if existing.psk == inc.psk {
                    // Revocation is STICKY: timestamps decide only between two
                    // records of the same liveness. A tombstone always beats a
                    // live record — otherwise a peer's later admin edit (or a
                    // fast-skewed clock) could out-timestamp the tombstone and
                    // silently un-revoke the client pool-wide. Concretely:
                    //  - local tombstone: only a strictly-newer incoming
                    //    tombstone (a re-issued deletion) may replace it;
                    //  - incoming tombstone vs live local: always wins;
                    //  - live vs live: normal last-writer-wins on `updated_at`.
                    let strictly_newer = match (inc.updated_at, existing.updated_at) {
                        (Some(i), Some(e)) => i > e,
                        (Some(_), None) => true,
                        (None, _) => false,
                    };
                    let incoming_wins = match (existing.deleted, inc.deleted) {
                        (true, false) => false,
                        (false, true) => true,
                        (true, true) => strictly_newer,
                        // Between two untimestamped live records the legacy
                        // overwrite behavior is kept.
                        (false, false) => {
                            strictly_newer
                                || (inc.updated_at.is_none() && existing.updated_at.is_none())
                        }
                    };
                    if !incoming_wins {
                        continue;
                    }
                    existing.name = inc.name;
                    // A deleted record is never "enabled", whatever the peer sent.
                    existing.enabled = inc.enabled && !inc.deleted;
                    existing.qos = inc.qos;
                    existing.deleted = inc.deleted;
                    existing.updated_at = inc.updated_at;
                    merged += 1;
                }
            } else if inc.deleted {
                // Unknown id arriving already tombstoned: keep the tombstone so
                // the deletion keeps propagating through the pool. No IP
                // conflict check — tombstones are invisible to lookups.
                data.clients.push(inc);
                merged += 1;
            } else {
                // H-S-2: Reject incoming records whose vpn_ip is already
                // assigned to a *different* client — prevents pool sync from
                // overwriting IP assignments and causing routing collisions.
                // Tombstones don't hold their IP (allocate_vpn_ip may have
                // reassigned it), so they don't conflict.
                let ip_conflict = data
                    .clients
                    .iter()
                    .any(|c| c.vpn_ip == inc.vpn_ip && c.id != inc.id && !c.deleted);
                if ip_conflict {
                    // Each node allocates VPN IPs locally from the same base
                    // (10.x.0.2…), so clients added INDEPENDENTLY on two pool
                    // nodes get identical IPs. Silently dropping the incoming
                    // one (the old behavior) left credentials un-synced forever.
                    // Instead re-home it onto a free local IP: the credential
                    // (id + PSK) still propagates, only the local routing IP
                    // differs per node — which is fine, each node routes it
                    // locally. The reassignment stays local (the existing-client
                    // merge branch never overwrites vpn_ip), so it doesn't churn.
                    match self.allocate_vpn_ip(&mut data).ok() {
                        Some(free_ip) => {
                            warn!(
                                "merge_from_json: client '{}' vpn_ip {} conflicts locally — re-homed to {}",
                                inc.id, inc.vpn_ip, free_ip
                            );
                            inc.vpn_ip = free_ip;
                        }
                        None => {
                            warn!(
                                "merge_from_json: skipping client '{}' — vpn_ip {} conflicts and no free IP to re-home",
                                inc.id, inc.vpn_ip
                            );
                            continue;
                        }
                    }
                }
                data.clients.push(inc);
                merged += 1;
            }
        }
        // Reap AFTER the merge loop: an expired tombstone a peer still
        // advertises is re-added above and immediately dropped here, so it
        // can't ping-pong back into the database forever.
        let reaped = reap_expired_tombstones(&mut data.clients);
        drop(data);
        if merged > 0 || reaped {
            self.save()?;
        }
        Ok(merged)
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

    fn allocate_vpn_ip(&self, data: &mut ClientDbFile) -> Result<Ipv4Addr> {
        let max_host_offset = self.network_config.max_host_offset();
        if max_host_offset < 1 {
            return Err(Error::Session(
                "Configured VPN subnet has no usable host addresses".into(),
            ));
        }

        let mut candidate_offset = if data.next_host_offset == 0 {
            default_next_host_offset()
        } else {
            data.next_host_offset
        };

        for _ in 0..max_host_offset {
            if let Some(candidate_ip) = self.network_config.ip_for_host_offset(candidate_offset) {
                // Tombstoned (revoked) clients don't hold their VPN IP:
                // counting them would permanently leak one address per
                // lifetime revocation and eventually exhaust the subnet with
                // zero active clients. All data-plane lookups
                // (find_by_vpn_ip / find_by_psk) already ignore tombstones,
                // and merge_from_json's IP-conflict check does too, so
                // reusing the address is safe.
                let already_used = data
                    .clients
                    .iter()
                    .any(|client| client.vpn_ip == candidate_ip && !client.deleted);
                if candidate_ip != self.network_config.server_vpn_ip && !already_used {
                    data.next_host_offset = if candidate_offset >= max_host_offset {
                        1
                    } else {
                        candidate_offset + 1
                    };
                    return Ok(candidate_ip);
                }
            }

            candidate_offset = if candidate_offset >= max_host_offset {
                1
            } else {
                candidate_offset + 1
            };
        }

        Err(Error::Session(
            "No more VPN IPs available in configured subnet".into(),
        ))
    }
}

/// Custom serde for Option<[u8; 32]> as base64 string or null
mod opt_base64_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        bytes: &Option<[u8; 32]>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use base64::Engine;
        match bytes {
            Some(b) => {
                let b64 = base64::engine::general_purpose::STANDARD.encode(b);
                b64.serialize(serializer)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Option<[u8; 32]>, D::Error> {
        use base64::Engine;
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            None => Ok(None),
            Some(s) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&s)
                    .map_err(serde::de::Error::custom)?;
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom(format!(
                        "device_pubkey must be 32 bytes, got {}",
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            }
        }
    }
}

/// Custom serde module for [u8; 32] as base64
mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        bytes: &[u8; 32],
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        b64.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<[u8; 32], D::Error> {
        use base64::Engine;
        let s = String::deserialize(deserializer)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "PSK must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_network_config() -> VpnNetworkConfig {
        VpnNetworkConfig {
            server_vpn_ip: Ipv4Addr::new(10, 99, 0, 1),
            prefix_len: 24,
            mtu: 1400,
            keepalive_secs: None,
            ..Default::default()
        }
    }

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

    /// MED-2 regression: a peer's later (or clock-skewed) live edit must not
    /// out-timestamp and silently reverse a revocation.
    #[test]
    fn merge_never_unrevokes_a_local_tombstone() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();

        let client = db.add_client("alice").unwrap();
        db.remove_client(&client.id).unwrap();

        // Peer record: same client, live, timestamped WELL AFTER the tombstone
        // (e.g. a QoS edit on a peer with a fast clock).
        let mut incoming = db.list_clients_including_deleted()[0].clone();
        incoming.deleted = false;
        incoming.enabled = true;
        incoming.updated_at = Some(Utc::now() + chrono::Duration::minutes(10));
        let json = serde_json::to_string(&vec![incoming]).unwrap();
        db.merge_from_json(&json).unwrap();

        assert!(
            db.find_by_id(&client.id).is_none(),
            "revocation must be sticky: a newer live record must not un-delete"
        );
        assert!(db.list_clients_including_deleted()[0].deleted);
    }

    /// MED-2 regression (other direction): an incoming tombstone revokes even
    /// when its timestamp is OLDER than the local live record's.
    #[test]
    fn merge_incoming_tombstone_beats_newer_live_record() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();

        let client = db.add_client("bob").unwrap();

        let mut incoming = db.list_clients_including_deleted()[0].clone();
        incoming.deleted = true;
        incoming.enabled = false;
        incoming.updated_at = Some(Utc::now() - chrono::Duration::hours(1));
        let json = serde_json::to_string(&vec![incoming]).unwrap();
        db.merge_from_json(&json).unwrap();

        assert!(
            db.find_by_id(&client.id).is_none(),
            "an incoming revocation must apply regardless of timestamp order"
        );
    }

    /// MED-1 regression: expired tombstones are reaped (bounded clients.json /
    /// sync payload) while fresh ones are kept for propagation.
    #[test]
    fn expired_tombstones_are_reaped_on_merge() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();

        let old = db.add_client("old").unwrap();
        let fresh = db.add_client("fresh").unwrap();
        db.remove_client(&old.id).unwrap();
        db.remove_client(&fresh.id).unwrap();

        // Age the first tombstone beyond the TTL.
        db.data
            .write()
            .clients
            .iter_mut()
            .find(|c| c.id == old.id)
            .unwrap()
            .updated_at = Some(Utc::now() - TOMBSTONE_TTL - chrono::Duration::days(1));

        // Any merge (even empty) runs the reaper.
        db.merge_from_json("[]").unwrap();

        let all = db.list_clients_including_deleted();
        assert!(
            !all.iter().any(|c| c.id == old.id),
            "expired tombstone must be hard-deleted"
        );
        assert!(
            all.iter().any(|c| c.id == fresh.id && c.deleted),
            "fresh tombstone must be kept so the revocation still propagates"
        );

        // A peer still advertising the expired tombstone must not resurrect
        // it past the same merge call.
        let mut stale = old.clone();
        stale.deleted = true;
        stale.updated_at = Some(Utc::now() - TOMBSTONE_TTL - chrono::Duration::days(1));
        db.merge_from_json(&serde_json::to_string(&vec![stale]).unwrap())
            .unwrap();
        assert!(
            !db.list_clients_including_deleted()
                .iter()
                .any(|c| c.id == old.id),
            "re-advertised expired tombstone must be reaped in the same merge"
        );
    }

    /// MED-1 regression: a tombstone no longer pins its VPN IP — the address
    /// is reusable by allocation, and pool sync accepts a live record on it.
    #[test]
    fn tombstoned_vpn_ip_is_reusable() {
        let dir = tempfile::tempdir().unwrap();
        let db =
            ClientDatabase::load(&dir.path().join("clients.json"), test_network_config()).unwrap();

        let a = db.add_client("a").unwrap(); // gets 10.99.0.2
        db.remove_client(&a.id).unwrap();

        // Rewind the allocation cursor so the tombstone's address is the
        // first candidate again.
        db.data.write().next_host_offset = 2;
        let b = db.add_client("b").unwrap();
        assert_eq!(
            b.vpn_ip, a.vpn_ip,
            "a revoked client's IP must be allocatable again"
        );

        // And merge must not treat the tombstone as an IP conflict for an
        // incoming live client either.
        let mut peer_client = b.clone();
        peer_client.id = "peer-new-id".to_string();
        peer_client.name = "peer-new".to_string();
        peer_client.psk = [0x42; 32];
        // Remove b locally first so the IP is only held by the tombstone.
        db.remove_client(&b.id).unwrap();
        db.merge_from_json(&serde_json::to_string(&vec![peer_client]).unwrap())
            .unwrap();
        assert!(
            db.find_by_id("peer-new-id").is_some(),
            "tombstone must not block an incoming live client on the same IP"
        );
    }
}
