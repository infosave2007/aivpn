//! Команды управления передаются только по каналу конкретного работника.
use serde::{Deserialize, Serialize};
use std::{fmt, io, num::NonZeroU64, time::Duration};

#[cfg(any(
    test,
    all(target_os = "linux", feature = "linux-kernel"),
    target_os = "windows"
))]
pub(crate) mod link;
#[cfg(all(target_os = "linux", feature = "linux-kernel"))]
pub(crate) mod unix;

pub const MAX_ADMIN_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Clone, Serialize)]
#[serde(transparent)]
pub struct PrivateText(String);
pub type CommandText = PrivateText;
pub type ReplyText = PrivateText;

impl PrivateText {
    pub fn new(value: String) -> io::Result<Self> {
        if value.is_empty() || value.len() > MAX_ADMIN_FRAME_BYTES || value.contains('\0') {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn into_string(self) -> String {
        self.0
    }
}
impl<'de> Deserialize<'de> for PrivateText {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}
impl fmt::Debug for PrivateText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateText([скрыто])")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionQuery {
    Statistics {},
    Execute { command: CommandText },
}
impl SessionQuery {
    pub fn timeout(&self) -> Duration {
        match self {
            Self::Statistics {} => Duration::from_secs(5),
            Self::Execute { command } => command
                .as_str()
                .strip_prefix("bench:")
                .and_then(|duration| duration.parse::<u64>().ok())
                .map(|seconds| Duration::from_secs(seconds.min(30) + 15))
                .unwrap_or(Duration::from_secs(15)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdministrationRequest {
    pub generation: NonZeroU64,
    pub id: NonZeroU64,
    pub query: SessionQuery,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdministrationReply {
    pub generation: NonZeroU64,
    pub id: NonZeroU64,
    pub success: bool,
    pub output: ReplyText,
}

pub fn encode_payload(value: &impl Serialize) -> io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    check_length(bytes.len())?;
    Ok(bytes)
}

pub fn decode_payload<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    check_length(bytes.len())?;
    serde_json::from_slice(bytes).map_err(io::Error::from)
}

fn check_length(length: usize) -> io::Result<()> {
    if length == 0 || length > MAX_ADMIN_FRAME_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}
