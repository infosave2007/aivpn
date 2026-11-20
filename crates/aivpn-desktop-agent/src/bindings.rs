//! Подготовка номеров перед установкой политик. Файлы и объекты ОС проверяет backend.

use crate::control::ControlStore;
use crate::slots::{KernelSlotStore, SlotKey, SlotKind};
use aivpn_desktop_policy::{
    Authority, KernelBindings, KernelPolicy, Owner, Policy, PolicyRegistry, ProfileCatalog,
    Selector,
};
use std::collections::BTreeSet;
use std::io;

pub struct BindingPlan {
    namespace: [u8; 16],
    bindings: KernelBindings,
    policies: Vec<KernelPolicy>,
}

impl BindingPlan {
    pub fn prepare<S: ControlStore>(
        registry: &PolicyRegistry,
        catalog: &ProfileCatalog,
        authority: &Authority,
        slots: &mut KernelSlotStore<S>,
    ) -> io::Result<Self> {
        Self::prepare_with(registry, catalog, authority, slots, false)
    }

    pub(crate) fn prepare_with<S: ControlStore>(
        registry: &PolicyRegistry,
        catalog: &ProfileCatalog,
        authority: &Authority,
        slots: &mut KernelSlotStore<S>,
        grouped: bool,
    ) -> io::Result<Self> {
        if slots.namespace() != catalog.namespace() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Нумерация относится к другому каталогу профилей",
            ));
        }
        let required = required_keys(registry, catalog, authority)?;
        // Номера сохраняются до передачи backend; ошибка не публикует частичный план.
        #[cfg(any(
            target_os = "windows",
            all(target_os = "linux", feature = "linux-kernel")
        ))]
        let values = if grouped {
            slots.synchronize_grouped(&required)?
        } else {
            slots.synchronize(&required)?
        };
        #[cfg(not(any(
            target_os = "windows",
            all(target_os = "linux", feature = "linux-kernel")
        )))]
        let values = {
            let _ = grouped;
            slots.synchronize(&required)?
        };
        let bindings = kernel_bindings(values);
        let mut policies = registry
            .policies()
            .map(|policy| {
                KernelPolicy::compile_registered(
                    registry,
                    &policy.document().owner,
                    catalog,
                    authority,
                    &bindings,
                )
                .map_err(io::Error::other)
            })
            .collect::<io::Result<Vec<_>>>()?;
        policies.sort_by_cached_key(KernelPolicy::to_native_bytes);
        Ok(Self {
            namespace: catalog.namespace(),
            bindings,
            policies,
        })
    }

    pub fn bindings(&self) -> &KernelBindings {
        &self.bindings
    }

    pub fn policies(&self) -> &[KernelPolicy] {
        &self.policies
    }

    pub fn namespace(&self) -> [u8; 16] {
        self.namespace
    }

    #[cfg(all(target_os = "linux", feature = "linux-kernel"))]
    pub(crate) fn executable_slot<S: ControlStore>(
        &self,
        slots: &KernelSlotStore<S>,
        path: &str,
    ) -> io::Result<std::num::NonZeroU32> {
        if self.namespace != slots.namespace() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let number = *self
            .bindings
            .executables
            .get(path)
            .ok_or(io::ErrorKind::InvalidInput)?;
        slots.require_binding(&SlotKey::new(SlotKind::Executable, path.into())?, number)?;
        Ok(number)
    }
}

fn required_keys(
    registry: &PolicyRegistry,
    catalog: &ProfileCatalog,
    authority: &Authority,
) -> io::Result<BTreeSet<SlotKey>> {
    let mut keys = catalog
        .runtime_profiles(authority)
        .map_err(io::Error::other)?
        .into_iter()
        .map(|profile| SlotKey::new(SlotKind::Profile, profile.id))
        .collect::<io::Result<BTreeSet<_>>>()?;
    for policy in registry.policies() {
        catalog
            .authorize_policy(policy, authority)
            .map_err(io::Error::other)?;
        keys.extend(policy_keys(policy)?);
    }
    Ok(keys)
}

fn policy_keys(policy: &Policy) -> io::Result<BTreeSet<SlotKey>> {
    let mut keys = BTreeSet::new();
    if let Owner::WindowsUser { sid } = &policy.document().owner {
        keys.insert(SlotKey::new(SlotKind::Owner, sid.clone())?);
    }
    for rule in &policy.effective_document().rules {
        if let Some(key) = selector_key(&rule.application)? {
            keys.insert(key);
        }
    }
    Ok(keys)
}

fn selector_key(selector: &Selector) -> io::Result<Option<SlotKey>> {
    match selector {
        Selector::Any {} => Ok(None),
        Selector::Executable { path } => SlotKey::new(SlotKind::Executable, path.clone()).map(Some),
        Selector::WindowsPackage { sid } => SlotKey::new(SlotKind::Package, sid.clone()).map(Some),
    }
}

fn kernel_bindings(
    slots: std::collections::BTreeMap<SlotKey, std::num::NonZeroU32>,
) -> KernelBindings {
    let mut bindings = KernelBindings::default();
    for (key, number) in slots {
        let target = match key.kind {
            SlotKind::Profile => &mut bindings.profiles,
            SlotKind::Executable => &mut bindings.executables,
            SlotKind::Package => &mut bindings.packages,
            SlotKind::Owner => &mut bindings.windows_owners,
            SlotKind::FileIdentity => continue,
        };
        target.insert(key.name, number);
    }
    bindings
}
