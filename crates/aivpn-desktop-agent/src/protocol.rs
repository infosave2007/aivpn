use crate::MAX_FRAME_BYTES;
use aivpn_desktop_policy::{Owner, Platform, PolicyDocument, ProfileStatus};
use serde::de::DeserializeOwned;
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};
use std::num::NonZeroU64;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("Превышен размер сообщения")]
    TooLarge,
    #[error("Версия локального протокола не поддерживается")]
    Version,
    #[error("Некорректное сообщение: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Status {},
    ListProfiles {},
    RegisterProfile {
        owner: Owner,
        registration_key: String,
        consumers: Vec<Owner>,
    },
    DeleteProfile {
        profile: String,
    },
    StartProfile {
        profile: String,
        connection: crate::connection::ConnectionDocument,
    },
    StopProfile {
        profile: String,
    },
    SessionAdmin {
        profile: String,
        assignment_generation: NonZeroU64,
        session_id: [u8; 16],
        query: crate::administration::SessionQuery,
    },
    GetPolicy {
        owner: Owner,
    },
    ValidatePolicy {
        document: PolicyDocument,
        expected_generation: Option<u64>,
    },
    ApplyPolicy {
        document: PolicyDocument,
        expected_generation: Option<u64>,
    },
    RemovePolicy {
        owner: Owner,
        expected_generation: u64,
    },
    SetGlobalDns {
        profile: String,
        acknowledge_outage: bool,
    },
    ClearGlobalDns {},
    Decommission {},
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendState {
    Unavailable,
    Recovering,
    ProtectionUnverified,
    Guarded,
    Active,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    Status {
        platform: Platform,
        backend: BackendState,
        revision: u64,
        global_dns_profile: Option<String>,
    },
    Profiles {
        profiles: Vec<ProfileStatus>,
    },
    Registered {
        profile: String,
    },
    Policy {
        document: Option<PolicyDocument>,
    },
    Validated {
        revision: u64,
    },
    Applied {
        revision: u64,
    },
    Done {},
    SessionReply {
        output: crate::administration::ReplyText,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    AccessDenied,
    NotFound,
    Conflict,
    Capacity,
    BackendUnavailable,
    RecoveryRequired,
    Storage,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum Outcome {
    Ok { reply: Reply },
    Error { code: ErrorCode },
}

#[derive(Debug)]
pub struct Request {
    id: NonZeroU64,
    command: Command,
}

#[derive(Debug)]
pub struct Response {
    id: NonZeroU64,
    result: Outcome,
}

/// Отложенный I/O выполняется после проверки полномочий, вне писателя состояния.
pub enum PreparedResponse {
    Ready(Response),
    Deferred(Box<dyn FnOnce() -> Response + Send>),
}

impl PreparedResponse {
    pub(crate) fn finish(self) -> Response {
        match self {
            Self::Ready(response) => response,
            Self::Deferred(work) => work(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    version: u32,
    id: NonZeroU64,
    #[serde(rename = "command")]
    body: T,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseEnvelope<T> {
    version: u32,
    id: NonZeroU64,
    result: T,
}

trait Versioned {
    fn version(&self) -> u32;
}

impl<T> Versioned for Envelope<T> {
    fn version(&self) -> u32 {
        self.version
    }
}

impl<T> Versioned for ResponseEnvelope<T> {
    fn version(&self) -> u32 {
        self.version
    }
}

impl Request {
    pub fn response_timeout(&self) -> std::time::Duration {
        match &self.command {
            Command::SessionAdmin { query, .. } => query.timeout(),
            Command::StartProfile { .. }
            | Command::StopProfile { .. }
            | Command::RegisterProfile { .. }
            | Command::DeleteProfile { .. }
            | Command::ApplyPolicy { .. }
            | Command::RemovePolicy { .. }
            | Command::SetGlobalDns { .. }
            | Command::ClearGlobalDns {}
            | Command::Decommission {} => std::time::Duration::from_secs(30),
            _ => std::time::Duration::from_secs(5),
        }
    }
    pub fn new(id: NonZeroU64, command: Command) -> Self {
        Self { id, command }
    }

    pub fn id(&self) -> NonZeroU64 {
        self.id
    }

    pub fn command(&self) -> &Command {
        &self.command
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, ProtocolError> {
        decode::<Envelope<Command>>(bytes).map(|m| Self::new(m.id, m.body))
    }

    pub fn to_json(&self) -> Result<Vec<u8>, ProtocolError> {
        encode_message(&self.command, self.id, "command")
    }
}

impl Response {
    pub fn success(id: NonZeroU64, reply: Reply) -> Self {
        Self::new(id, Outcome::Ok { reply })
    }

    pub fn failure(id: NonZeroU64, code: ErrorCode) -> Self {
        Self::new(id, Outcome::Error { code })
    }

    fn new(id: NonZeroU64, result: Outcome) -> Self {
        Self { id, result }
    }

    pub fn id(&self) -> NonZeroU64 {
        self.id
    }

    pub fn result(&self) -> &Outcome {
        &self.result
    }

    pub fn into_result(self) -> Outcome {
        self.result
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, ProtocolError> {
        decode::<ResponseEnvelope<Outcome>>(bytes).map(|m| Self::new(m.id, m.result))
    }

    pub fn to_json(&self) -> Result<Vec<u8>, ProtocolError> {
        encode_message(&self.result, self.id, "result")
    }
}

fn encode_message(
    value: &impl Serialize,
    id: NonZeroU64,
    key: &str,
) -> Result<Vec<u8>, ProtocolError> {
    let mut bytes = Vec::new();
    let mut encoder = serde_json::Serializer::new(&mut bytes);
    let mut message = encoder.serialize_map(Some(3))?;
    message.serialize_entry("version", &1u32)?;
    message.serialize_entry("id", &id)?;
    message.serialize_entry(key, value)?;
    message.end()?;
    check_length(bytes.len())?;
    Ok(bytes)
}

fn decode<T: DeserializeOwned + Versioned>(bytes: &[u8]) -> Result<T, ProtocolError> {
    check_length(bytes.len())?;
    let envelope: T = serde_json::from_slice(bytes)?;
    check_version(envelope.version())?;
    Ok(envelope)
}

fn check_length(length: usize) -> Result<(), ProtocolError> {
    if length > MAX_FRAME_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    Ok(())
}

fn check_version(version: u32) -> Result<(), ProtocolError> {
    if version != 1 {
        return Err(ProtocolError::Version);
    }
    Ok(())
}
