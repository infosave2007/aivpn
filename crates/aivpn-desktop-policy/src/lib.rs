//! Локальная политика маршрутизации. Данные процессов поставляет системный backend.
//! Пакет не открывает сокеты, не меняет маршруты и не добавляет метаданные в VPN.

mod compiler;
mod matcher;
mod network;
mod profiles;
mod registry;
mod validate;

pub use compiler::{CompileError, KernelBindings, KernelPolicy};
pub use profiles::{
    PreparedAssignment, ProfileAssignment, ProfileCatalog, ProfileError, ProfileLease,
    ProfileStatus, RuntimeProfile,
};
pub use registry::{PolicyRegistry, PreparedPolicy, PreparedRemoval, RegistryError};

use network::Network;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use thiserror::Error;

const MAX_DOCUMENT_BYTES: usize = 128 * 1024;
const MAX_RULES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Linux,
    Windows,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Owner {
    LinuxUser { uid: u32 },
    WindowsUser { sid: String },
    Machine {},
}

impl Owner {
    pub(crate) fn sort_key(&self) -> String {
        match self {
            Self::Machine {} => "0".into(),
            Self::LinuxUser { uid } => format!("1{uid:010}"),
            Self::WindowsUser { sid } => format!("2{sid}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "route", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    System {},
    Block {},
    Vpn { profile: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Selector {
    Any {},
    Executable { path: String },
    WindowsPackage { sid: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DnsPolicy {
    SharedVpn {
        profile: String,
        acknowledge_outage: bool,
    },
}

impl DnsPolicy {
    pub fn profile(&self) -> &str {
        match self {
            Self::SharedVpn { profile, .. } => profile,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDocument {
    pub id: String,
    pub application: Selector,
    pub destination: Option<String>,
    #[serde(default = "inherit_by_default")]
    pub inherit_children: bool,
    pub action: Action,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    #[serde(
        default = "legacy_split_enabled",
        skip_serializing_if = "split_is_enabled"
    )]
    pub split_enabled: bool,
    pub version: u32,
    pub id: String,
    pub generation: u64,
    pub platform: Platform,
    pub owner: Owner,
    pub default_action: Action,
    pub dns: DnsPolicy,
    pub rules: Vec<RuleDocument>,
}

fn split_is_enabled(value: &bool) -> bool {
    *value
}

fn legacy_split_enabled() -> bool {
    true
}

/// Полномочия берутся из учетных данных IPC, а не из JSON клиента.
#[derive(Debug, Clone)]
pub struct Authority {
    pub user: Owner,
    pub machine_admin: bool,
}

/// Идентичность поставляет backend после проверки исполняемого файла средствами ОС.
/// Пути документа и процесса должны быть приведены им к одному системному виду.
#[derive(Debug, Clone)]
pub struct ProcessIdentity {
    pub owner: Owner,
    pub canonical_executable: String,
    pub package_sid: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionReason {
    MatchedRule,
    Default,
    OutsideOwner,
    VpnUnavailable,
    UnresolvedIdentity,
    UnresolvedAncestry,
    LocalDestination,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub policy_id: String,
    pub generation: u64,
    pub rule_id: Option<String>,
    pub requested: Action,
    pub effective: Action,
    pub reason: DecisionReason,
    pub inherited_depth: Option<u8>,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Некорректная политика: {0}")]
    Invalid(&'static str),
    #[error("Некорректный JSON политики: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct Policy {
    document: PolicyDocument,
    effective_document: PolicyDocument,
    networks: Vec<Option<Network>>,
}

impl Policy {
    pub fn from_json(text: &str, authority: &Authority) -> Result<Self, PolicyError> {
        if text.len() > MAX_DOCUMENT_BYTES {
            return Err(PolicyError::Invalid("превышен размер документа"));
        }
        Self::validate(serde_json::from_str(text)?, authority)
    }

    pub fn validate(document: PolicyDocument, authority: &Authority) -> Result<Self, PolicyError> {
        validate::document(&document, authority)?;
        let mut effective_document = document.clone();
        if !document.split_enabled {
            effective_document.default_action = Action::Vpn {
                profile: document.dns.profile().into(),
            };
            effective_document.rules.clear();
        }
        let networks = effective_document
            .rules
            .iter()
            .map(|rule| rule.destination.as_deref().map(Network::parse).transpose())
            .collect::<Result<Vec<_>, _>>()?;
        if serde_json::to_vec(&document)?.len() > MAX_DOCUMENT_BYTES {
            return Err(PolicyError::Invalid("превышен размер документа"));
        }
        Ok(Self {
            document,
            effective_document,
            networks,
        })
    }

    pub fn document(&self) -> &PolicyDocument {
        &self.document
    }

    /// Исполняемый снимок отделен от сохраненных правил выключенного split.
    pub fn effective_document(&self) -> &PolicyDocument {
        &self.effective_document
    }

    /// Рассчитывает путь нового соединения. Решения уже открытых потоков хранит backend.
    /// Готовность VPN проверяется для конкретного адреса, включая его семейство.
    pub fn decide(
        &self,
        process: &ProcessIdentity,
        destination: IpAddr,
        vpn_available: impl Fn(&str, IpAddr) -> bool,
    ) -> Decision {
        self.decide_with_ancestors(process, &[], destination, vpn_available)
    }

    /// Предки перечисляются от ближайшего родителя. Смена владельца прерывает наследование.
    pub fn decide_with_ancestors(
        &self,
        process: &ProcessIdentity,
        ancestors: &[ProcessIdentity],
        destination: IpAddr,
        vpn_available: impl Fn(&str, IpAddr) -> bool,
    ) -> Decision {
        let destination = network::canonical_ip(destination);
        let vpn_available = |profile: &str| vpn_available(profile, destination);
        let decide = |rule_id, requested, reason| {
            self.decision(
                rule_id,
                requested,
                reason,
                destination.is_loopback(),
                &vpn_available,
            )
        };
        if self.document.owner != (Owner::Machine {}) && self.document.owner != process.owner {
            return decide(None, &Action::System {}, DecisionReason::OutsideOwner);
        }
        if !self.document.split_enabled {
            return decide(
                None,
                &self.effective_document.default_action,
                DecisionReason::Default,
            );
        }
        if ancestors.len() > 32 {
            return decide(None, &Action::Block {}, DecisionReason::UnresolvedAncestry);
        }
        if matcher::unresolved_identity(self, process, destination) {
            return decide(None, &Action::Block {}, DecisionReason::UnresolvedIdentity);
        }
        let selection = match matcher::select(self, process, ancestors, destination) {
            Ok(selection) => selection,
            Err(()) => return decide(None, &Action::Block {}, DecisionReason::UnresolvedAncestry),
        };
        if let Some((index, depth)) = selection {
            let rule = &self.effective_document.rules[index];
            let mut decision = decide(Some(&rule.id), &rule.action, DecisionReason::MatchedRule);
            decision.inherited_depth = (depth > 0).then_some(depth as u8);
            return decision;
        }
        decide(
            None,
            &self.effective_document.default_action,
            DecisionReason::Default,
        )
    }

    fn decision(
        &self,
        rule_id: Option<&String>,
        requested: &Action,
        mut reason: DecisionReason,
        local: bool,
        available: &impl Fn(&str) -> bool,
    ) -> Decision {
        let effective = match requested {
            Action::Vpn { .. } if local => {
                reason = DecisionReason::LocalDestination;
                Action::System {}
            }
            Action::Vpn { profile } if !available(profile) => {
                reason = DecisionReason::VpnUnavailable;
                Action::Block {}
            }
            action => action.clone(),
        };
        Decision {
            policy_id: self.document.id.clone(),
            generation: self.document.generation,
            rule_id: rule_id.cloned(),
            requested: requested.clone(),
            effective,
            reason,
            inherited_depth: None,
        }
    }
}

fn inherit_by_default() -> bool {
    true
}
