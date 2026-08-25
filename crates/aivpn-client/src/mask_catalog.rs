//! Client-side cache of the server's mask catalog.
//!
//! The server pushes a `ControlPayload::MaskCatalog` (list of selectable masks,
//! each flagged `generated` when it was auto-built by mask_gen). The GUIs run
//! `aivpn-client` as a subprocess and cannot see control packets, so the client
//! persists the catalog to a small JSON file that the pickers read to render a
//! live list — and mark auto-generated masks "(авто)". Mirrors the status-file
//! IPC already used for traffic stats and recording status.

use serde::{Deserialize, Serialize};

/// One selectable mask as advertised by the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskCatalogEntry {
    pub mask_id: String,
    /// Human-facing label (falls back to `mask_id`).
    pub label: String,
    /// True when the server auto-generated this mask from a recording.
    pub generated: bool,
}

/// Candidate paths for the catalog file, most-preferred first. The client
/// writes the first writable one; readers (GUIs) try them in order.
pub fn mask_catalog_paths() -> Vec<std::path::PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let mut paths = Vec::new();
        if let Some(local_app) = std::env::var_os("LOCALAPPDATA") {
            let dir = std::path::PathBuf::from(local_app).join("AIVPN");
            let _ = std::fs::create_dir_all(&dir);
            paths.push(dir.join("mask_catalog.json"));
        }
        paths.push(std::env::temp_dir().join("aivpn-mask-catalog.json"));
        paths
    }
    #[cfg(not(target_os = "windows"))]
    {
        let mut paths = Vec::new();
        if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
            let dir = std::path::PathBuf::from(runtime_dir).join("aivpn");
            let _ = std::fs::create_dir_all(&dir);
            paths.push(dir.join("mask_catalog.json"));
        }
        paths.push(std::path::PathBuf::from("/var/run/aivpn/mask_catalog.json"));
        paths.push(std::path::PathBuf::from("/tmp/aivpn-mask-catalog.json"));
        paths
    }
}

/// Persist the catalog received from the server (best-effort; writes to every
/// candidate path that succeeds so readers using a different base still see it).
pub fn write_mask_catalog(masks: &[(String, String, bool)]) {
    let entries: Vec<MaskCatalogEntry> = masks
        .iter()
        .map(|(mask_id, label, generated)| MaskCatalogEntry {
            mask_id: mask_id.clone(),
            label: label.clone(),
            generated: *generated,
        })
        .collect();
    let json = match serde_json::to_vec(&entries) {
        Ok(j) => j,
        Err(_) => return,
    };
    for path in mask_catalog_paths() {
        // O_NOFOLLOW/create_new-hardened atomic write: this can fall back to
        // a predictable world-writable /tmp path, which a local attacker
        // could pre-plant as a symlink to a file this process can write.
        crate::secure_write::write_status_best_effort(&path, &json);
    }
}

/// Read the cached catalog (for GUIs). Returns the first path that parses.
pub fn read_mask_catalog() -> Option<Vec<MaskCatalogEntry>> {
    for path in mask_catalog_paths() {
        if let Ok(bytes) = std::fs::read(&path) {
            if let Ok(entries) = serde_json::from_slice::<Vec<MaskCatalogEntry>>(&bytes) {
                return Some(entries);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_json_roundtrips() {
        let masks = vec![
            ("webrtc_zoom_v3".to_string(), "Zoom".to_string(), false),
            ("auto_quic_v1".to_string(), "QUIC".to_string(), true),
        ];
        let entries: Vec<MaskCatalogEntry> = masks
            .iter()
            .map(|(id, l, g)| MaskCatalogEntry {
                mask_id: id.clone(),
                label: l.clone(),
                generated: *g,
            })
            .collect();
        let json = serde_json::to_vec(&entries).unwrap();
        let back: Vec<MaskCatalogEntry> = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.len(), 2);
        assert!(!back[0].generated);
        assert!(back[1].generated);
        assert_eq!(back[1].mask_id, "auto_quic_v1");
    }
}
