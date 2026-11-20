use crate::network::Network;
use crate::{
    Action, Authority, Owner, Policy, ProfileCatalog, ProfileError, RuleDocument, Selector,
    MAX_RULES,
};
use std::collections::HashMap;
use std::num::NonZeroU32;
use thiserror::Error;

const HEADER_BYTES: usize = 40;
const RULE_BYTES: usize = 56;

/// Привязки создает backend после проверки файлов, пользователей и экземпляров VPN.
/// Номера не принимаются из документа политики или запроса GUI.
#[derive(Debug, Default)]
pub struct KernelBindings {
    pub profiles: HashMap<String, NonZeroU32>,
    pub executables: HashMap<String, NonZeroU32>,
    pub packages: HashMap<String, NonZeroU32>,
    pub windows_owners: HashMap<String, NonZeroU32>,
}

#[derive(Debug, Error)]
pub enum CompileError {
    #[error(transparent)]
    Profile(#[from] ProfileError),
    #[error("Не найдена привязка {0}")]
    MissingBinding(&'static str),
}

/// Локальная схема карт ядра без имен приложений и секретов.
/// Числа используют порядок байтов хоста, IP-адреса и маски - сетевой порядок.
#[derive(Debug)]
pub struct KernelPolicy {
    header: [u8; HEADER_BYTES],
    rules: Vec<[u8; RULE_BYTES]>,
}

impl KernelPolicy {
    /// Ревизия установки не повторяется после удаления и повторного создания политики.
    pub fn compile_prepared(
        prepared: &crate::PreparedPolicy,
        catalog: &ProfileCatalog,
        authority: &Authority,
        bindings: &KernelBindings,
    ) -> Result<Self, CompileError> {
        Self::compile(prepared.policy(), catalog, authority, bindings)
            .map(|compiled| compiled.with_revision(prepared.revision()))
    }

    /// Восстановленный реестр уже содержит ревизию активации. Поколение документа
    /// может повториться после удаления, поэтому его нельзя использовать вместо нее.
    pub fn compile_registered(
        registry: &crate::PolicyRegistry,
        owner: &Owner,
        catalog: &ProfileCatalog,
        authority: &Authority,
        bindings: &KernelBindings,
    ) -> Result<Self, CompileError> {
        let policy = registry
            .get(owner)
            .ok_or(CompileError::MissingBinding("политики"))?;
        Self::compile(&policy, catalog, authority, bindings)
            .map(|compiled| compiled.with_revision(registry.revision()))
    }

    fn with_revision(mut self, revision: u64) -> Self {
        self.header[16..24].copy_from_slice(&revision.to_ne_bytes());
        self
    }

    pub fn compile(
        policy: &Policy,
        catalog: &ProfileCatalog,
        authority: &Authority,
        bindings: &KernelBindings,
    ) -> Result<Self, CompileError> {
        catalog.authorize_policy(policy, authority)?;
        let doc = policy.effective_document();
        let (owner_kind, owner_id) = bindings.owner(&doc.owner)?;
        let (default_action, default_profile) = bindings.action(&doc.default_action)?;
        let dns_profile = bindings.profile(doc.dns.profile())?;
        let mut header = [0; HEADER_BYTES];
        for (offset, value) in [
            (0, 1),
            (4, owner_kind),
            (8, owner_id),
            (12, doc.rules.len() as u32),
            (24, default_action),
            (28, default_profile),
            (32, dns_profile),
        ] {
            write_word(&mut header, offset, value);
        }
        header[16..24].copy_from_slice(&doc.generation.to_ne_bytes());
        let rules = doc
            .rules
            .iter()
            .zip(&policy.networks)
            .map(|(rule, network)| bindings.rule(rule, network.as_ref()))
            .collect::<Result<Vec<_>, CompileError>>()?;
        Ok(Self { header, rules })
    }

    pub fn to_native_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0; HEADER_BYTES + RULE_BYTES * MAX_RULES];
        bytes[..HEADER_BYTES].copy_from_slice(&self.header);
        for (index, rule) in self.rules.iter().enumerate() {
            let start = HEADER_BYTES + RULE_BYTES * index;
            bytes[start..start + RULE_BYTES].copy_from_slice(rule);
        }
        bytes
    }
}

impl KernelBindings {
    fn rule(
        &self,
        rule: &RuleDocument,
        network: Option<&Network>,
    ) -> Result<[u8; RULE_BYTES], CompileError> {
        let (kind, app) = self.application(&rule.application)?;
        let (action, profile) = self.action(&rule.action)?;
        let mut bytes = [0; RULE_BYTES];
        for (offset, value) in [
            (0, kind),
            (4, app),
            (12, u32::from(rule.inherit_children)),
            (16, action),
            (20, profile),
        ] {
            write_word(&mut bytes, offset, value);
        }
        write_network(&mut bytes, network);
        Ok(bytes)
    }

    fn profile(&self, profile: &str) -> Result<u32, CompileError> {
        self.profiles
            .get(profile)
            .map(|id| id.get())
            .ok_or(CompileError::MissingBinding("профиля VPN"))
    }

    fn action(&self, action: &Action) -> Result<(u32, u32), CompileError> {
        match action {
            Action::System {} => Ok((0, 0)),
            Action::Block {} => Ok((1, 0)),
            Action::Vpn { profile } => Ok((2, self.profile(profile)?)),
        }
    }

    fn owner(&self, owner: &Owner) -> Result<(u32, u32), CompileError> {
        match owner {
            Owner::Machine {} => Ok((3, 0)),
            Owner::LinuxUser { uid } => Ok((1, *uid)),
            Owner::WindowsUser { sid } => self
                .windows_owners
                .get(sid)
                .map(|id| (2, id.get()))
                .ok_or(CompileError::MissingBinding("пользователя Windows")),
        }
    }

    fn application(&self, selector: &Selector) -> Result<(u32, u32), CompileError> {
        let (kind, entry) = match selector {
            Selector::Any {} => return Ok((0, 0)),
            Selector::Executable { path } => (1, self.executables.get(path)),
            Selector::WindowsPackage { sid } => (2, self.packages.get(sid)),
        };
        entry
            .map(|id| (kind, id.get()))
            .ok_or(CompileError::MissingBinding("приложения"))
    }
}

fn write_word(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

fn write_network(bytes: &mut [u8; RULE_BYTES], network: Option<&Network>) {
    match network {
        None => {}
        Some(Network::V4 { address, mask }) => {
            write_word(bytes, 8, 4);
            bytes[24..28].copy_from_slice(&address.to_be_bytes());
            bytes[40..44].copy_from_slice(&mask.to_be_bytes());
        }
        Some(Network::V6 { address, mask }) => {
            write_word(bytes, 8, 6);
            bytes[24..40].copy_from_slice(&address.to_be_bytes());
            bytes[40..56].copy_from_slice(&mask.to_be_bytes());
        }
    }
}
