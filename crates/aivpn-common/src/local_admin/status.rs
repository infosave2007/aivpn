//! Снимок живой desktop-сессии не содержит ключей и паролей.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingStatus {
    pub can_record: Option<bool>,
    pub state: String,
    pub service: Option<String>,
    pub message: Option<String>,
    pub mask_id: Option<String>,
    pub confidence: Option<f32>,
    pub updated_at_ms: u64,
}

impl Default for RecordingStatus {
    fn default() -> Self {
        Self {
            can_record: None,
            state: "idle".into(),
            service: None,
            message: Some("Recording access not checked yet".into()),
            mask_id: None,
            confidence: None,
            updated_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionStatistics {
    pub sent: u64,
    pub received: u64,
    pub since: u64,
    pub ip: String,
    pub fallback: bool,
    pub quality: u8,
    pub adaptive: u8,
    pub fec_group: u8,
    pub role: u8,
    pub recording: Option<RecordingStatus>,
}
