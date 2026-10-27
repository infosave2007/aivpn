//! Постоянные привязки идентичностей узлов и запреты повторного enrollment.
//! Поврежденный реестр запрещает аутентификацию до устранения ошибки и перезапуска.

use aivpn_common::crypto;
use base64::Engine as _;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use tracing::{error, warn};

const NODE_ENROLL_WINDOW_MS: u64 = 60_000;
const MAX_REGISTRY_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedStore {
    nodes: HashMap<String, String>,
    #[serde(default)]
    revoked: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeAuthOutcome {
    Verified,
    BoundNew,
    Rejected(&'static str),
}

#[derive(Default)]
struct RegistryState {
    nodes: HashMap<String, [u8; 32]>,
    revoked: HashSet<String>,
    // Неудачно сохраненный запрет действует в текущем процессе до явной отмены.
    unsaved_revocations: HashSet<String>,
    existed: bool,
    poisoned: bool,
}

pub struct NodeRegistry {
    path: PathBuf,
    allow_auto_add: bool,
    state: Mutex<RegistryState>,
    #[cfg(test)]
    fail_write: std::sync::atomic::AtomicBool,
}

fn secure_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl NodeRegistry {
    pub fn load(path: PathBuf, allow_auto_add: bool) -> Self {
        let registry = Self {
            path,
            allow_auto_add,
            state: Mutex::new(RegistryState::default()),
            #[cfg(test)]
            fail_write: std::sync::atomic::AtomicBool::new(false),
        };
        if let Err(error) = registry.check_health() {
            error!("Реестр узлов недоступен: {error}");
        }
        registry
    }

    fn lock_file(&self) -> io::Result<File> {
        let file = secure_options()
            .read(true)
            .write(true)
            .create(true)
            .open(self.path.with_extension("json.lock"))?;
        if !file.metadata()?.is_file() {
            return Err(invalid_data(
                "Блокировка реестра не является обычным файлом",
            ));
        }
        file.lock()?;
        Ok(file)
    }

    fn refresh(&self, state: &mut RegistryState) -> io::Result<()> {
        if state.poisoned {
            return Err(invalid_data(
                "Реестр узлов заблокирован после ошибки чтения",
            ));
        }
        let result = (|| {
            let mut file = match secure_options().read(true).open(&self.path) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound && !state.existed => {
                    return Ok(())
                }
                Err(error) => return Err(error),
            };
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.len() > MAX_REGISTRY_BYTES {
                return Err(invalid_data("Некорректный файл реестра узлов"));
            }
            let mut content = String::new();
            (&mut file)
                .take(MAX_REGISTRY_BYTES + 1)
                .read_to_string(&mut content)?;
            if content.len() as u64 > MAX_REGISTRY_BYTES {
                return Err(invalid_data("Реестр узлов превышает лимит"));
            }
            let store = match serde_json::from_str::<PersistedStore>(&content) {
                Ok(store) => store,
                Err(_) => PersistedStore {
                    nodes: serde_json::from_str(&content)
                        .map_err(|_| invalid_data("Поврежденный JSON реестра узлов"))?,
                    revoked: Vec::new(),
                },
            };
            let mut nodes = HashMap::new();
            for (node_id, encoded) in store.nodes {
                let key: [u8; 32] = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or_else(|| invalid_data("Поврежденный ключ узла"))?;
                let verifying = ed25519_dalek::VerifyingKey::from_bytes(&key)
                    .map_err(|_| invalid_data("Некорректный ключ узла"))?;
                if node_id.trim().is_empty() || verifying.is_weak() {
                    return Err(invalid_data("Недопустимая идентичность узла"));
                }
                nodes.insert(node_id, key);
            }
            state.nodes = nodes;
            state.revoked = store.revoked.into_iter().collect();
            state
                .revoked
                .extend(state.unsaved_revocations.iter().cloned());
            state.existed = true;
            Ok(())
        })();
        if result.is_err() {
            state.poisoned = true;
        }
        result
    }

    pub fn check_health(&self) -> io::Result<()> {
        let mut state = self.state.lock();
        let _file = self.lock_file()?;
        self.refresh(&mut state)
    }

    /// Проверяет актуальный запрет, в том числе записанный отдельным CLI-процессом.
    pub fn is_authorized(&self, node_id: &str, node_pub: &[u8; 32]) -> bool {
        let mut state = self.state.lock();
        let Ok(_file) = self.lock_file() else {
            return false;
        };
        self.refresh(&mut state).is_ok()
            && state.nodes.get(node_id) == Some(node_pub)
            && !state.revoked.contains(node_id)
    }

    pub fn authenticate(
        &self,
        node_id: &str,
        node_pub: &[u8; 32],
        time_window: u64,
        signature: &[u8; 64],
        server_eph_pub: &[u8; 32],
        client_eph_pub: &[u8; 32],
    ) -> NodeAuthOutcome {
        let cur =
            crypto::compute_time_window(crypto::current_timestamp_ms(), NODE_ENROLL_WINDOW_MS);
        if time_window.abs_diff(cur) > 2 {
            return NodeAuthOutcome::Rejected("stale enrollment");
        }
        if node_id.trim().is_empty()
            || !crypto::verify_node_enrollment(
                node_pub,
                node_id,
                time_window,
                signature,
                server_eph_pub,
                client_eph_pub,
            )
        {
            return NodeAuthOutcome::Rejected("bad signature");
        }
        let mut state = self.state.lock();
        let Ok(_file) = self.lock_file() else {
            return NodeAuthOutcome::Rejected("registry unavailable");
        };
        if self.refresh(&mut state).is_err() {
            return NodeAuthOutcome::Rejected("registry unavailable");
        }
        if state.revoked.contains(node_id) {
            return NodeAuthOutcome::Rejected("revoked node — re-approval required");
        }
        if let Some(stored) = state.nodes.get(node_id) {
            return if stored == node_pub {
                NodeAuthOutcome::Verified
            } else {
                NodeAuthOutcome::Rejected("node_pub mismatch - impostor or key rotation")
            };
        }
        if !self.allow_auto_add {
            return NodeAuthOutcome::Rejected("unknown node, auto-add disabled");
        }
        state.nodes.insert(node_id.to_string(), *node_pub);
        if let Err(error) = self.persist(&state) {
            state.nodes.remove(node_id);
            warn!("Не удалось сохранить привязку узла: {error}");
            return NodeAuthOutcome::Rejected("registry persistence failed");
        }
        state.existed = true;
        NodeAuthOutcome::BoundNew
    }

    pub fn try_revoke(&self, node_id: &str) -> io::Result<bool> {
        let mut state = self.state.lock();
        let operation = (|| {
            let _file = self.lock_file()?;
            self.refresh(&mut state)?;
            let changed =
                state.nodes.remove(node_id).is_some() | state.revoked.insert(node_id.to_string());
            self.persist(&state)?;
            state.existed = true;
            state.unsaved_revocations.remove(node_id);
            Ok(changed)
        })();
        if operation.is_err() {
            state.nodes.remove(node_id);
            state.revoked.insert(node_id.to_string());
            state.unsaved_revocations.insert(node_id.to_string());
        }
        operation
    }

    pub fn revoke(&self, node_id: &str) -> bool {
        self.try_revoke(node_id).unwrap_or_else(|error| {
            warn!("Не удалось сохранить отзыв узла: {error}");
            false
        })
    }

    pub fn try_unrevoke(&self, node_id: &str) -> io::Result<bool> {
        let mut state = self.state.lock();
        let _file = self.lock_file()?;
        self.refresh(&mut state)?;
        let removed = state.revoked.remove(node_id);
        if !removed {
            return Ok(false);
        }
        if let Err(error) = self.persist(&state) {
            state.revoked.insert(node_id.to_string());
            return Err(error);
        }
        state.existed = true;
        state.unsaved_revocations.remove(node_id);
        Ok(true)
    }

    pub fn unrevoke(&self, node_id: &str) -> bool {
        self.try_unrevoke(node_id).unwrap_or_else(|error| {
            warn!("Не удалось отменить отзыв узла: {error}");
            false
        })
    }

    pub fn list(&self) -> Vec<(String, [u8; 32])> {
        if self.check_health().is_err() {
            return Vec::new();
        }
        let state = self.state.lock();
        let mut nodes: Vec<_> = state
            .nodes
            .iter()
            .filter(|(id, _)| !state.revoked.contains(*id))
            .map(|(id, key)| (id.clone(), *key))
            .collect();
        nodes.sort_by(|a, b| a.0.cmp(&b.0));
        nodes
    }

    pub fn list_revoked(&self) -> Vec<String> {
        let _ = self.check_health();
        let mut revoked: Vec<_> = self.state.lock().revoked.iter().cloned().collect();
        revoked.sort();
        revoked
    }

    fn persist(&self, state: &RegistryState) -> io::Result<()> {
        #[cfg(test)]
        if self.fail_write.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(io::Error::other("injected write failure"));
        }
        let store = PersistedStore {
            nodes: state
                .nodes
                .iter()
                .map(|(id, key)| {
                    (
                        id.clone(),
                        base64::engine::general_purpose::STANDARD.encode(key),
                    )
                })
                .collect(),
            revoked: state.revoked.iter().cloned().collect(),
        };
        let content = serde_json::to_vec_pretty(&store).map_err(io::Error::other)?;
        let temporary = self
            .path
            .with_extension(format!("{:032x}.tmp", rand::random::<u128>()));
        let mut file = secure_options()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let result = (|| {
            file.write_all(&content)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.path)?;
            // После rename новое состояние уже видно другим процессам. При ошибке
            // fsync каталога не откатываем только память к предыдущему состоянию.
            if let Err(error) = File::open(
                self.path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new(".")),
            )
            .and_then(|dir| dir.sync_all())
            {
                warn!("Реестр записан, но fsync каталога не выполнен: {error}");
            }
            Ok(())
        })();
        drop(file);
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed test session transcript — every test below authenticates
    /// against this same (server_eph_pub, client_eph_pub) pair unless it is
    /// specifically exercising cross-session-replay rejection, so the
    /// existing TOFU/impostor/revoke/stale coverage holds unchanged under a
    /// consistent transcript.
    const TEST_SERVER_EPH: [u8; 32] = [0xD1u8; 32];
    const TEST_CLIENT_EPH: [u8; 32] = [0xD2u8; 32];

    /// Build a valid enrollment tuple `(node_pub, time_window, signature)`
    /// for `node_id`, signed with the identity derived from `seed`, bound to
    /// the fixed `TEST_SERVER_EPH`/`TEST_CLIENT_EPH` test transcript.
    fn build_enrollment(seed: &[u8; 32], node_id: &str) -> ([u8; 32], u64, [u8; 64]) {
        let signing_key = crypto::node_identity_from_seed(seed);
        let node_pub = signing_key.verifying_key().to_bytes();
        let time_window =
            crypto::compute_time_window(crypto::current_timestamp_ms(), NODE_ENROLL_WINDOW_MS);
        let msg = crypto::node_enrollment_signing_bytes(
            node_id,
            &node_pub,
            time_window,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        let signature = {
            use ed25519_dalek::Signer;
            signing_key.sign(&msg).to_bytes()
        };
        (node_pub, time_window, signature)
    }

    fn registry_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("pool_nodes.json")
    }

    #[test]
    fn tofu_binds_new_node_then_verifies_on_reauth() {
        let dir = tempfile::tempdir().unwrap();
        let reg = NodeRegistry::load(registry_path(&dir), true);
        let seed = [0x11u8; 32];
        let (node_pub, time_window, signature) = build_enrollment(&seed, "node-a:443");

        let first = reg.authenticate(
            "node-a:443",
            &node_pub,
            time_window,
            &signature,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        assert_eq!(first, NodeAuthOutcome::BoundNew);

        let second = reg.authenticate(
            "node-a:443",
            &node_pub,
            time_window,
            &signature,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        assert_eq!(second, NodeAuthOutcome::Verified);
    }

    #[test]
    fn rejects_unknown_node_when_auto_add_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let reg = NodeRegistry::load(registry_path(&dir), false);
        let seed = [0x22u8; 32];
        let (node_pub, time_window, signature) = build_enrollment(&seed, "node-b:443");

        let outcome = reg.authenticate(
            "node-b:443",
            &node_pub,
            time_window,
            &signature,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        assert_eq!(
            outcome,
            NodeAuthOutcome::Rejected("unknown node, auto-add disabled")
        );
        assert!(reg.list().is_empty());
    }

    #[test]
    fn rejects_impostor_with_different_key_for_bound_node() {
        let dir = tempfile::tempdir().unwrap();
        let reg = NodeRegistry::load(registry_path(&dir), true);

        let seed_legit = [0x33u8; 32];
        let (pub_legit, tw_legit, sig_legit) = build_enrollment(&seed_legit, "node-c:443");
        assert_eq!(
            reg.authenticate(
                "node-c:443",
                &pub_legit,
                tw_legit,
                &sig_legit,
                &TEST_SERVER_EPH,
                &TEST_CLIENT_EPH
            ),
            NodeAuthOutcome::BoundNew
        );

        let seed_impostor = [0x44u8; 32];
        let (pub_impostor, tw_impostor, sig_impostor) =
            build_enrollment(&seed_impostor, "node-c:443");
        let outcome = reg.authenticate(
            "node-c:443",
            &pub_impostor,
            tw_impostor,
            &sig_impostor,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        assert_eq!(
            outcome,
            NodeAuthOutcome::Rejected("node_pub mismatch - impostor or key rotation")
        );

        // The original binding must be untouched.
        let legit_recheck = reg.authenticate(
            "node-c:443",
            &pub_legit,
            tw_legit,
            &sig_legit,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        assert_eq!(legit_recheck, NodeAuthOutcome::Verified);
    }

    #[test]
    fn rejects_bad_signature() {
        let dir = tempfile::tempdir().unwrap();
        let reg = NodeRegistry::load(registry_path(&dir), true);
        let seed = [0x55u8; 32];
        let (node_pub, time_window, mut signature) = build_enrollment(&seed, "node-d:443");
        signature[0] ^= 0xFF; // tamper

        let outcome = reg.authenticate(
            "node-d:443",
            &node_pub,
            time_window,
            &signature,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        assert_eq!(outcome, NodeAuthOutcome::Rejected("bad signature"));
    }

    #[test]
    fn rejects_stale_time_window() {
        let dir = tempfile::tempdir().unwrap();
        let reg = NodeRegistry::load(registry_path(&dir), true);
        let seed = [0x66u8; 32];
        let signing_key = crypto::node_identity_from_seed(&seed);
        let node_pub = signing_key.verifying_key().to_bytes();
        let cur =
            crypto::compute_time_window(crypto::current_timestamp_ms(), NODE_ENROLL_WINDOW_MS);
        let stale_window = cur.saturating_sub(10);
        let msg = crypto::node_enrollment_signing_bytes(
            "node-e:443",
            &node_pub,
            stale_window,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        let signature = {
            use ed25519_dalek::Signer;
            signing_key.sign(&msg).to_bytes()
        };

        let outcome = reg.authenticate(
            "node-e:443",
            &node_pub,
            stale_window,
            &signature,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        assert_eq!(outcome, NodeAuthOutcome::Rejected("stale enrollment"));
    }

    #[test]
    fn revoke_removes_binding() {
        let dir = tempfile::tempdir().unwrap();
        let reg = NodeRegistry::load(registry_path(&dir), true);
        let seed = [0x77u8; 32];
        let (node_pub, time_window, signature) = build_enrollment(&seed, "node-f:443");
        assert_eq!(
            reg.authenticate(
                "node-f:443",
                &node_pub,
                time_window,
                &signature,
                &TEST_SERVER_EPH,
                &TEST_CLIENT_EPH
            ),
            NodeAuthOutcome::BoundNew
        );
        assert_eq!(reg.list().len(), 1);

        assert!(reg.revoke("node-f:443"));
        assert!(reg.list().is_empty());
        assert!(!reg.revoke("node-f:443")); // already gone
    }

    #[test]
    fn list_is_sorted_by_node_id() {
        let dir = tempfile::tempdir().unwrap();
        let reg = NodeRegistry::load(registry_path(&dir), true);
        for id in ["zeta:443", "alpha:443", "mid:443"] {
            let seed = blake3::hash(id.as_bytes());
            let seed_bytes: [u8; 32] = *seed.as_bytes();
            let (node_pub, time_window, signature) = build_enrollment(&seed_bytes, id);
            reg.authenticate(
                id,
                &node_pub,
                time_window,
                &signature,
                &TEST_SERVER_EPH,
                &TEST_CLIENT_EPH,
            );
        }
        let ids: Vec<String> = reg.list().into_iter().map(|(id, _)| id).collect();
        assert_eq!(ids, vec!["alpha:443", "mid:443", "zeta:443"]);
    }

    #[test]
    fn persists_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = registry_path(&dir);
        let seed = [0x88u8; 32];
        let (node_pub, time_window, signature) = build_enrollment(&seed, "node-g:443");
        {
            let reg = NodeRegistry::load(path.clone(), true);
            assert_eq!(
                reg.authenticate(
                    "node-g:443",
                    &node_pub,
                    time_window,
                    &signature,
                    &TEST_SERVER_EPH,
                    &TEST_CLIENT_EPH
                ),
                NodeAuthOutcome::BoundNew
            );
        }

        let reloaded = NodeRegistry::load(path, true);
        assert_eq!(reloaded.list(), vec![("node-g:443".to_string(), node_pub)]);
    }

    /// D3 regression test: revoking a node must make the revocation stick
    /// even against a re-enrollment with the SAME valid key and signature —
    /// before the fix, `revoke` only removed the binding, so this next
    /// `authenticate` call would return `BoundNew` again via TOFU.
    #[test]
    fn revoke_blocks_reenrollment_even_with_valid_signature() {
        let dir = tempfile::tempdir().unwrap();
        let reg = NodeRegistry::load(registry_path(&dir), true);
        let seed = [0x99u8; 32];
        let (node_pub, time_window, signature) = build_enrollment(&seed, "node-h:443");
        assert_eq!(
            reg.authenticate(
                "node-h:443",
                &node_pub,
                time_window,
                &signature,
                &TEST_SERVER_EPH,
                &TEST_CLIENT_EPH
            ),
            NodeAuthOutcome::BoundNew
        );

        assert!(reg.revoke("node-h:443"));
        assert!(reg.list().is_empty());

        let (node_pub2, time_window2, signature2) = build_enrollment(&seed, "node-h:443");
        let outcome = reg.authenticate(
            "node-h:443",
            &node_pub2,
            time_window2,
            &signature2,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        assert_eq!(
            outcome,
            NodeAuthOutcome::Rejected("revoked node — re-approval required")
        );
        assert!(reg.list().is_empty());
        assert_eq!(reg.list_revoked(), vec!["node-h:443".to_string()]);
    }

    #[test]
    fn unrevoke_allows_rebinding() {
        let dir = tempfile::tempdir().unwrap();
        let reg = NodeRegistry::load(registry_path(&dir), true);
        let seed = [0xaau8; 32];
        let (node_pub, time_window, signature) = build_enrollment(&seed, "node-i:443");
        assert_eq!(
            reg.authenticate(
                "node-i:443",
                &node_pub,
                time_window,
                &signature,
                &TEST_SERVER_EPH,
                &TEST_CLIENT_EPH
            ),
            NodeAuthOutcome::BoundNew
        );
        assert!(reg.revoke("node-i:443"));

        let (node_pub2, time_window2, signature2) = build_enrollment(&seed, "node-i:443");
        assert_eq!(
            reg.authenticate(
                "node-i:443",
                &node_pub2,
                time_window2,
                &signature2,
                &TEST_SERVER_EPH,
                &TEST_CLIENT_EPH
            ),
            NodeAuthOutcome::Rejected("revoked node — re-approval required")
        );

        assert!(reg.unrevoke("node-i:443"));
        assert!(!reg.unrevoke("node-i:443")); // already gone
        assert!(reg.list_revoked().is_empty());

        let (node_pub3, time_window3, signature3) = build_enrollment(&seed, "node-i:443");
        assert_eq!(
            reg.authenticate(
                "node-i:443",
                &node_pub3,
                time_window3,
                &signature3,
                &TEST_SERVER_EPH,
                &TEST_CLIENT_EPH
            ),
            NodeAuthOutcome::BoundNew
        );
        assert_eq!(reg.list().len(), 1);
    }

    /// Load-compat regression test: a `pool_nodes.json` written before this
    /// module gained durable revocation (flat `{node_id: pubkey}` shape)
    /// must still load correctly, and persisting from a legacy-loaded
    /// registry must upgrade the on-disk shape without losing data.
    #[test]
    fn legacy_flat_format_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = registry_path(&dir);
        let seed = [0xbbu8; 32];
        let signing_key = crypto::node_identity_from_seed(&seed);
        let node_pub = signing_key.verifying_key().to_bytes();
        let b64 = base64::engine::general_purpose::STANDARD.encode(node_pub);
        let legacy_json = format!("{{\"node-j:443\": \"{}\"}}", b64);
        std::fs::write(&path, legacy_json).unwrap();

        let reg = NodeRegistry::load(path.clone(), true);
        assert_eq!(reg.list(), vec![("node-j:443".to_string(), node_pub)]);
        assert!(reg.list_revoked().is_empty());

        // Re-authenticating against the legacy-loaded binding must Verify,
        // not re-bind.
        let time_window =
            crypto::compute_time_window(crypto::current_timestamp_ms(), NODE_ENROLL_WINDOW_MS);
        let msg = crypto::node_enrollment_signing_bytes(
            "node-j:443",
            &node_pub,
            time_window,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        );
        let signature = {
            use ed25519_dalek::Signer;
            signing_key.sign(&msg).to_bytes()
        };
        assert_eq!(
            reg.authenticate(
                "node-j:443",
                &node_pub,
                time_window,
                &signature,
                &TEST_SERVER_EPH,
                &TEST_CLIENT_EPH
            ),
            NodeAuthOutcome::Verified
        );

        // Persisting from a legacy-loaded registry (structured-form
        // upgrade) must still reload correctly, including the revoked set.
        assert!(reg.revoke("node-j:443"));
        let reloaded = NodeRegistry::load(path, true);
        assert!(reloaded.list().is_empty());
        assert_eq!(reloaded.list_revoked(), vec!["node-j:443".to_string()]);
    }

    #[test]
    fn revoked_set_persists_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = registry_path(&dir);
        let seed = [0xccu8; 32];
        let (node_pub, time_window, signature) = build_enrollment(&seed, "node-k:443");
        {
            let reg = NodeRegistry::load(path.clone(), true);
            assert_eq!(
                reg.authenticate(
                    "node-k:443",
                    &node_pub,
                    time_window,
                    &signature,
                    &TEST_SERVER_EPH,
                    &TEST_CLIENT_EPH
                ),
                NodeAuthOutcome::BoundNew
            );
            assert!(reg.revoke("node-k:443"));
        }

        let reloaded = NodeRegistry::load(path, true);
        assert!(reloaded.list().is_empty());
        assert_eq!(reloaded.list_revoked(), vec!["node-k:443".to_string()]);

        // The revocation must still block re-enrollment after reload.
        let (node_pub2, time_window2, signature2) = build_enrollment(&seed, "node-k:443");
        assert_eq!(
            reloaded.authenticate(
                "node-k:443",
                &node_pub2,
                time_window2,
                &signature2,
                &TEST_SERVER_EPH,
                &TEST_CLIENT_EPH
            ),
            NodeAuthOutcome::Rejected("revoked node — re-approval required")
        );
    }

    /// B2/D2 regression test: `authenticate` must reject a captured, otherwise
    /// valid enrollment tuple when it is replayed with a DIFFERENT session
    /// transcript — the cross-peer replay this fix closes. Before the fix,
    /// `authenticate` had no transcript parameters at all, so this exact
    /// tuple would have verified (and TOFU-bound) identically on any session.
    #[test]
    fn authenticate_rejects_cross_session_replay() {
        let dir = tempfile::tempdir().unwrap();
        let reg = NodeRegistry::load(registry_path(&dir), true);
        let seed = [0xddu8; 32];
        let (node_pub, time_window, signature) = build_enrollment(&seed, "node-l:443");

        // Binds fine under the transcript it was actually signed for.
        assert_eq!(
            reg.authenticate(
                "node-l:443",
                &node_pub,
                time_window,
                &signature,
                &TEST_SERVER_EPH,
                &TEST_CLIENT_EPH
            ),
            NodeAuthOutcome::BoundNew
        );

        // A fresh registry (simulating a different, un-bound session's
        // peer) must reject the exact same tuple when the caller supplies a
        // different session transcript.
        let other_server_eph = [0xE5u8; 32];
        let other_client_eph = [0xE6u8; 32];
        let dir2 = tempfile::tempdir().unwrap();
        let reg2 = NodeRegistry::load(registry_path(&dir2), true);
        assert_eq!(
            reg2.authenticate(
                "node-l:443",
                &node_pub,
                time_window,
                &signature,
                &other_server_eph,
                &other_client_eph
            ),
            NodeAuthOutcome::Rejected("bad signature")
        );
        assert!(
            reg2.list().is_empty(),
            "a cross-session-replayed proof must never TOFU-bind"
        );
    }

    /// D5 regression test: concurrent TOFU binds in the same process must
    /// not collide on the persist-temp-file name. Before the fix, the temp
    /// path was named only `{path}.{pid}.tmp`, so two concurrent `persist()`
    /// calls from different threads could race on the same temp file and
    /// corrupt state or fail the rename.
    #[test]
    fn concurrent_binds_do_not_collide_on_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = registry_path(&dir);
        let reg = std::sync::Arc::new(NodeRegistry::load(path.clone(), true));

        let handles: Vec<_> = (0..8u8)
            .map(|i| {
                let reg = reg.clone();
                std::thread::spawn(move || {
                    let seed = [i; 32];
                    let node_id = format!("node-concurrent-{}:443", i);
                    let (node_pub, time_window, signature) = build_enrollment(&seed, &node_id);
                    reg.authenticate(
                        &node_id,
                        &node_pub,
                        time_window,
                        &signature,
                        &TEST_SERVER_EPH,
                        &TEST_CLIENT_EPH,
                    )
                })
            })
            .collect();

        for h in handles {
            assert_eq!(h.join().unwrap(), NodeAuthOutcome::BoundNew);
        }

        assert_eq!(reg.list().len(), 8);
        let reloaded = NodeRegistry::load(path, true);
        assert_eq!(reloaded.list().len(), 8);
    }
    fn enroll(registry: &NodeRegistry, id: &str, seed: u8) -> NodeAuthOutcome {
        let (key, window, signature) = build_enrollment(&[seed; 32], id);
        registry.authenticate(
            id,
            &key,
            window,
            &signature,
            &TEST_SERVER_EPH,
            &TEST_CLIENT_EPH,
        )
    }

    #[test]
    fn corrupt_registry_never_resets_trust() {
        for content in ["", "{", r#"{"nodes":{"peer":"broken"},"revoked":[]}"#] {
            let dir = tempfile::tempdir().unwrap();
            let path = registry_path(&dir);
            fs::write(&path, content).unwrap();
            let registry = NodeRegistry::load(path.clone(), true);
            assert!(registry.check_health().is_err());
            assert!(matches!(
                enroll(&registry, "peer", 4),
                NodeAuthOutcome::Rejected(_)
            ));
            assert_eq!(fs::read_to_string(&path).unwrap(), content);
            fs::write(&path, "{}").unwrap();
            assert!(registry.check_health().is_err());
        }
    }

    #[test]
    fn independent_instances_share_pins_and_revocations() {
        let dir = tempfile::tempdir().unwrap();
        let path = registry_path(&dir);
        let first = NodeRegistry::load(path.clone(), true);
        let second = NodeRegistry::load(path.clone(), true);
        assert_eq!(enroll(&first, "one", 1), NodeAuthOutcome::BoundNew);
        assert_eq!(enroll(&second, "two", 2), NodeAuthOutcome::BoundNew);
        assert_eq!(first.list().len(), 2);
        let key = crypto::node_identity_from_seed(&[1; 32])
            .verifying_key()
            .to_bytes();
        assert!(first.is_authorized("one", &key));
        assert!(second.try_revoke("one").unwrap());
        assert!(!first.is_authorized("one", &key));
        assert!(matches!(
            enroll(&first, "one", 3),
            NodeAuthOutcome::Rejected(_)
        ));
        assert!(second.try_unrevoke("one").unwrap());
        assert_eq!(enroll(&second, "one", 3), NodeAuthOutcome::BoundNew);
        assert!(!first.is_authorized("one", &key));
        assert_eq!(first.list().len(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn failed_writes_never_grant_trust_and_revocation_remains_local() {
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let path = registry_path(&dir);
        let registry = NodeRegistry::load(path.clone(), true);
        registry.fail_write.store(true, Ordering::Relaxed);
        assert_eq!(
            enroll(&registry, "peer", 1),
            NodeAuthOutcome::Rejected("registry persistence failed")
        );
        assert!(registry.list().is_empty());
        assert!(!path.exists());
        registry.fail_write.store(false, Ordering::Relaxed);
        assert_eq!(enroll(&registry, "peer", 1), NodeAuthOutcome::BoundNew);
        registry.fail_write.store(true, Ordering::Relaxed);
        assert!(registry.try_revoke("peer").is_err());
        assert!(matches!(
            enroll(&registry, "peer", 1),
            NodeAuthOutcome::Rejected(_)
        ));
        assert!(registry.try_unrevoke("peer").is_err());
        assert!(matches!(
            enroll(&registry, "peer", 1),
            NodeAuthOutcome::Rejected(_)
        ));
        registry.fail_write.store(false, Ordering::Relaxed);
        registry.try_revoke("peer").unwrap();
        assert_eq!(NodeRegistry::load(path, true).list_revoked(), vec!["peer"]);
    }

    #[test]
    fn removed_registry_does_not_allow_new_tofu() {
        let dir = tempfile::tempdir().unwrap();
        let path = registry_path(&dir);
        let registry = NodeRegistry::load(path.clone(), true);
        assert_eq!(enroll(&registry, "peer", 1), NodeAuthOutcome::BoundNew);
        fs::remove_file(path).unwrap();
        assert!(matches!(
            enroll(&registry, "peer", 2),
            NodeAuthOutcome::Rejected(_)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn registry_and_lock_symlinks_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = registry_path(&dir);
        let victim = dir.path().join("victim.json");
        fs::write(&victim, "{}").unwrap();
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        assert!(NodeRegistry::load(path.clone(), true)
            .check_health()
            .is_err());
        fs::remove_file(&path).unwrap();
        fs::remove_file(path.with_extension("json.lock")).unwrap();
        std::os::unix::fs::symlink(&victim, path.with_extension("json.lock")).unwrap();
        assert!(NodeRegistry::load(path, true).check_health().is_err());
        assert_eq!(fs::read_to_string(victim).unwrap(), "{}");
    }
}
