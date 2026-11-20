//! Каждый профиль сохраняет свои TUN, mark, conntrack zone и журнал.
use super::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    profile: String,
    slot: u32,
    number: u16,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u32,
    namespace: [u8; 16],
    entries: Vec<Entry>,
}

pub(in crate::linux::backend) struct DataPaths {
    primary: DataPath,
    additional: BTreeMap<String, DataPath>,
    store: StateDirectory,
    index: Index,
    poisoned: bool,
}
impl DataPaths {
    pub(in crate::linux::backend) fn open(
        namespace: [u8; 16],
        resources: StateDirectory,
    ) -> io::Result<Self> {
        // Первый журнал сохраняет прежнее расположение и номера сетевых ресурсов.
        let store = resources.child(c"profiles")?;
        let primary = DataPath::open(namespace, resources)?;
        let index: Index = match store.load(StateFile::Committed)? {
            Some(bytes) => serde_json::from_slice(&bytes)?,
            None => Index {
                version: 1,
                namespace,
                entries: Vec::new(),
            },
        };
        if index.version != 1 || index.namespace != namespace || index.entries.len() > 255 {
            return Err(invalid());
        }
        let mut names = BTreeSet::new();
        let mut slots = BTreeSet::new();
        if let Some(profile) = &primary.record.profile {
            names.insert(profile.clone());
            slots.insert(primary.record.slot);
        } else if !index.entries.is_empty() {
            return Err(invalid());
        }
        let mut additional = BTreeMap::new();
        for (position, entry) in index.entries.iter().enumerate() {
            if entry.profile.is_empty()
                || entry.profile.len() > 256
                || entry.slot == 0
                || entry.number as usize != position + 2
                || !names.insert(entry.profile.clone())
                || !slots.insert(entry.slot)
            {
                return Err(invalid());
            }
            let name = CString::new(format!("profile{}", entry.number)).map_err(|_| invalid())?;
            let path = DataPath::open_number(namespace, store.child(&name)?, entry.number)?;
            if path
                .record
                .profile
                .as_ref()
                .is_some_and(|id| id != &entry.profile)
                || path.record.slot != 0 && path.record.slot != entry.slot
            {
                return Err(invalid());
            }
            additional.insert(entry.profile.clone(), path);
        }
        Ok(Self {
            primary,
            additional,
            store,
            index,
            poisoned: false,
        })
    }
    pub(super) fn all(&self) -> impl Iterator<Item = &DataPath> {
        std::iter::once(&self.primary).chain(self.additional.values())
    }
    fn all_mut(&mut self) -> impl Iterator<Item = &mut DataPath> {
        std::iter::once(&mut self.primary).chain(self.additional.values_mut())
    }
    fn owned_rules(&self) -> Vec<OwnedRule> {
        self.all()
            .filter(|path| path.record.phase != "new")
            .map(|path| OwnedRule {
                priority: path.record.priority,
                table: path.record.table,
                mark: path.record.mark,
            })
            .collect()
    }
    pub(in crate::linux::backend) fn get(&self, profile: &str) -> io::Result<&DataPath> {
        if self.primary.record.profile.as_deref() == Some(profile) {
            Ok(&self.primary)
        } else {
            self.additional
                .get(profile)
                .ok_or_else(|| io::ErrorKind::NotFound.into())
        }
    }
    pub(in crate::linux::backend) fn get_mut(
        &mut self,
        profile: &str,
    ) -> io::Result<&mut DataPath> {
        if self.primary.record.profile.as_deref() == Some(profile) {
            Ok(&mut self.primary)
        } else {
            self.additional
                .get_mut(profile)
                .ok_or_else(|| io::ErrorKind::NotFound.into())
        }
    }
    pub(in crate::linux::backend) fn begin(
        &mut self,
        writer: &KernelWriter,
        profile: &str,
        slot: u32,
        matcher: OwnedFd,
    ) -> io::Result<&OwnedTunnel> {
        if self.poisoned || profile.is_empty() || profile.len() > 256 || slot == 0 {
            return Err(invalid());
        }
        self.verify_kernel(writer)?;
        let peers = self.owned_rules();
        if self.primary.record.profile.is_none() {
            return self.primary.begin(writer, profile, slot, matcher, &peers);
        }
        if self.primary.record.profile.as_deref() == Some(profile) {
            return self.primary.begin(writer, profile, slot, matcher, &peers);
        }
        if !self.additional.contains_key(profile) {
            if self.index.entries.len() >= 255 || self.all().any(|path| path.record.slot == slot) {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            let number = self.index.entries.len() as u16 + 2;
            let name = CString::new(format!("profile{number}")).map_err(|_| invalid())?;
            let path =
                DataPath::open_number(self.index.namespace, self.store.child(&name)?, number)?;
            self.index.entries.push(Entry {
                profile: profile.into(),
                slot,
                number,
            });
            // Номер остается зарезервированным даже при прерванной установке пути.
            if let Err(error) = self
                .store
                .replace(StateFile::Committed, &serde_json::to_vec(&self.index)?)
            {
                self.poisoned = true;
                return Err(error);
            }
            self.additional.insert(profile.into(), path);
        }
        self.get_mut(profile)?
            .begin(writer, profile, slot, matcher, &peers)
    }
    pub(in crate::linux::backend) fn verify_kernel(&self, writer: &KernelWriter) -> io::Result<()> {
        if self.poisoned {
            return Err(invalid());
        }
        for path in self.all() {
            if path.record.phase != "new" {
                path.verify_persistent().map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("Журнал профиля {:?}: {error}", path.record.profile),
                    )
                })?;
            }
            path.verify_kernel(writer).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("Ядро профиля {:?}: {error}", path.record.profile),
                )
            })?;
        }
        // Приоритет общий, но исключения относятся только к проверенным собственным путям.
        let owned = self.owned_rules();
        for family in ["-4", "-6"] {
            let rules = json("ip", &[family, "-j", "rule", "show"])?;
            validate_route_rules(&rules, &owned)?;
        }
        Ok(())
    }
    pub(in crate::linux::backend) fn prepare(
        &mut self,
        desired: &ControlState,
        live: &ProfileCatalog,
        authority: &Authority,
    ) -> io::Result<()> {
        for path in self.all_mut() {
            path.prepare(desired, live, authority).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("Профиль {:?}: {error}", path.record.profile),
                )
            })?;
        }
        Ok(())
    }
    pub(in crate::linux::backend) fn publish(
        &self,
        writer: &mut KernelWriter,
        desired: &ControlState,
        live: &ProfileCatalog,
        authority: &Authority,
    ) -> io::Result<()> {
        for path in self.all() {
            if let Some((runtime, network)) =
                path.ready_profile(desired, live, authority)
                    .map_err(|error| {
                        io::Error::new(
                            error.kind(),
                            format!("Готовность профиля {:?}: {error}", path.record.profile),
                        )
                    })?
            {
                writer.publish_profile(&runtime, &network, path.tunnel()?)?;
            }
        }
        Ok(())
    }
    pub(in crate::linux::backend) fn end(&mut self, profile: &str) -> io::Result<()> {
        self.get_mut(profile)?.end()
    }
    pub(in crate::linux::backend) fn contains_device(&self, device: u64) -> io::Result<bool> {
        for path in self.all() {
            if let Some(tunnel) = &path.tunnel {
                if tunnel.verify()?.device_identity.get() == device {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

fn validate_route_rules(rules: &Value, owned: &[OwnedRule]) -> io::Result<()> {
    let rules = rules.as_array().ok_or_else(invalid)?;
    for path in owned {
        if rules.iter().filter(|rule| path.matches(rule)).count() != 1 {
            return Err(io::Error::other(
                "Правило профиля отсутствует или повторяется",
            ));
        }
    }
    for rule in rules {
        if owned.iter().any(|path| path.matches(rule)) {
            continue;
        }
        if number(&rule["priority"]).is_some_and(|priority| priority > 0 && priority <= 100) {
            return Err(io::Error::other(
                "Постороннее правило опережает пути профилей",
            ));
        }
        for path in owned {
            if number(&rule["table"]) == Some(u64::from(path.table))
                || mark_overlap(rule, path.mark)?
            {
                return Err(io::Error::other(
                    "Постороннее правило пересекает путь профиля",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn owned() -> Vec<OwnedRule> {
        vec![
            OwnedRule {
                priority: 100,
                table: 42001,
                mark: 0xa1010000,
            },
            OwnedRule {
                priority: 100,
                table: 42002,
                mark: 0xa1020000,
            },
        ]
    }
    fn rules() -> Value {
        json!([
            {"priority":0,"table":"local"},
            {"priority":100,"table":42001,"fwmark":"0xa1010000","fwmask":"0xffff0000"},
            {"priority":100,"table":42002,"fwmark":"0xa1020000","fwmask":"0xffff0000"},
            {"priority":32766,"table":"main"},
            {"priority":32767,"table":"default"}
        ])
    }
    #[test]
    fn route_rules_accept_two_owned_profiles_with_an_unrelated_vpn() {
        let mut rules = rules();
        rules
            .as_array_mut()
            .unwrap()
            .push(json!({"priority":200,"fwmark":"0x1234","fwmask":"0xffff","table":51820}));
        validate_route_rules(&rules, &owned()).unwrap();
    }
    #[test]
    fn route_rules_reject_foreign_precedence_overlap_and_duplicate_owned_rules() {
        for extra in [
            json!({"priority":50,"table":51820}),
            json!({"priority":100,"table":42003,"fwmark":"0xa1030000","fwmask":"0xffff0000"}),
            json!({"priority":200,"table":51820,"fwmark":"0xa1010000","fwmask":"0xffff0000"}),
            json!({"priority":200,"table":42002}),
            json!({"priority":100,"table":42001,"fwmark":"0xa1010000","fwmask":"0xffff0000"}),
        ] {
            let mut actual = rules();
            actual.as_array_mut().unwrap().push(extra);
            assert!(validate_route_rules(&actual, &owned()).is_err(), "{actual}");
        }
    }
}
