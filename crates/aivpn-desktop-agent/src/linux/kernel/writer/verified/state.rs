use super::*;
use crate::linux::kernel::objects::{read_array, ObjectInfo};

pub(super) const GROUP_LIMIT: usize = 4096;
pub(super) const EDGE_LIMIT: usize = 65536;
pub(super) const TRANSACTION_LIMIT: usize = 64;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Instance {
    pub(super) namespace: [u8; 16],
    boot: [u8; 32],
    image: [u8; 32],
    inventory: [u8; 32],
    path_map: u32,
    inode_map: u32,
    seed: [u8; 16],
}
impl Instance {
    pub(super) fn read(writer: &KernelWriter) -> io::Result<Self> {
        Ok(Self {
            namespace: writer.slots.namespace(),
            boot: boot_digest()?,
            image: Sha256::digest(writer.kernel.mode().image()).into(),
            inventory: writer.kernel.identity_digest()?,
            path_map: ObjectInfo::read(writer.kernel.map(c"path_key")?)?.words[1],
            inode_map: ObjectInfo::read(writer.kernel.map(c"inode_tokens")?)?.words[1],
            seed: read_array(writer.kernel.map(c"path_key")?)?,
        })
    }
    pub(super) fn digest(&self) -> [u8; 32] {
        Sha256::digest(serde_json::to_vec(self).unwrap()).into()
    }
    pub(super) fn key(&self, cookie: u64) -> io::Result<SlotKey> {
        let prefix: String = self.digest().iter().map(|b| format!("{b:02x}")).collect();
        SlotKey::file_identity(format!("{prefix}/{cookie:016x}"))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Selected {
    pub owner: u64,
    pub path: String,
    pub selector: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Alias {
    pub owner: u64,
    pub path: String,
    pub selector: u32,
    pub group: u32,
    pub keys: [[u64; 3]; 2],
    pub source_keys: [[u64; 3]; 2],
    pub source_scope: [u64; 4],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Group {
    pub slot: u32,
    pub cookie: u64,
    pub device: u64,
    pub inode: u64,
    pub evidence: Option<GroupEvidence>,
    pub releasing: bool,
    pub published: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Transaction {
    pub id: u64,
    pub serial: u64,
    pub digest: [u8; 32],
    pub aliases: Vec<Alias>,
    pub policies: Vec<Vec<u8>>,
    pub staged: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct History {
    pub owner: u64,
    pub selector: u32,
    pub group: u32,
    pub accepted_serial: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    kind: String,
    version: u32,
    pub instance: Instance,
    pub next: u64,
    pub serial: u64,
    pub digest: [u8; 32],
    pub groups: Vec<Group>,
    pub transactions: Vec<Transaction>,
    pub history: Vec<History>,
    pub publication: super::publication::Publication,
}
pub(in crate::linux::kernel::writer) struct Registry {
    store: StateDirectory,
    pub(super) state: Manifest,
    pub(super) poisoned: bool,
    recovered: bool,
    pub(super) publication_checked: bool,
}
impl Registry {
    pub(super) fn memberships(&self, tx: &Transaction) -> Vec<VerifiedMembership> {
        let mut edges = BTreeMap::new();
        for alias in &tx.aliases {
            edges.insert((alias.owner, alias.selector, alias.group), None);
        }
        for history in &self.state.history {
            if tx
                .aliases
                .iter()
                .any(|a| (a.owner, a.selector) == (history.owner, history.selector))
            {
                edges.insert(
                    (history.owner, history.selector, history.group),
                    Some(history.accepted_serial),
                );
            }
        }
        edges
            .into_iter()
            .map(
                |((owner, selector, group), accepted_serial)| VerifiedMembership {
                    owner,
                    selector: SelectorId(NonZeroU32::new(selector).unwrap()),
                    group: FileGroupId(NonZeroU32::new(group).unwrap()),
                    accepted_serial,
                },
            )
            .collect()
    }
    pub(super) fn open(store: StateDirectory, instance: Instance) -> io::Result<Self> {
        if store.load(StateFile::Pending)?.is_some() {
            return Err(invalid());
        }
        let bytes = store.load(StateFile::Committed)?;
        let mut registry = Self {
            store,
            state: Manifest {
                kind: "linux-verified-bindings".into(),
                version: 3,
                instance: instance.clone(),
                next: 1,
                serial: 0,
                digest: [0; 32],
                groups: Vec::new(),
                transactions: Vec::new(),
                history: Vec::new(),
                publication: super::publication::Publication::default(),
            },
            poisoned: false,
            recovered: false,
            publication_checked: false,
        };
        match bytes {
            Some(bytes) => {
                registry.restore(&bytes, &instance)?;
            }
            None => registry.persist()?,
        }
        Ok(registry)
    }
    fn restore(&mut self, bytes: &[u8], instance: &Instance) -> io::Result<()> {
        if bytes.len() > MAX_STATE_BYTES {
            return Err(invalid());
        }
        let candidate = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        let previous = std::mem::replace(&mut self.state, candidate);
        let result = self.validate().and_then(|()| {
            if &self.state.instance == instance {
                Ok(())
            } else {
                Err(invalid())
            }
        });
        if result.is_err() {
            self.state = previous;
        }
        result
    }
    pub(in crate::linux::kernel::writer) fn available(&self) -> io::Result<()> {
        crate::slots::require_unpoisoned(self.poisoned)
    }
    pub(super) fn ensure_recovered(&self) -> io::Result<()> {
        self.available()?;
        if !self.recovered {
            return Err(io::Error::other("Сначала восстановите журнал привязок"));
        }
        Ok(())
    }
    pub(super) fn persist(&mut self) -> io::Result<()> {
        self.available()?;
        self.validate()?;
        let bytes = serde_json::to_vec(&self.state).map_err(io::Error::other)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(invalid());
        }
        if let Err(error) = self.store.replace(StateFile::Committed, &bytes) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }
    pub(super) fn select(&mut self, serial: u64, digest: [u8; 32]) -> io::Result<()> {
        if serial == 0
            || serial < self.state.serial
            || serial == self.state.serial && digest != self.state.digest
        {
            return Err(invalid());
        }
        self.state.serial = serial;
        self.state.digest = digest;
        self.persist()
    }
    pub(super) fn token(&self, number: u64) -> BindingTxnId {
        BindingTxnId {
            instance: self.state.instance.digest(),
            number,
        }
    }
    pub(super) fn transaction(&self, token: BindingTxnId) -> io::Result<&Transaction> {
        if token.instance != self.state.instance.digest() {
            return Err(invalid());
        }
        self.state
            .transactions
            .iter()
            .find(|tx| tx.id == token.number)
            .ok_or_else(invalid)
    }
    pub(super) fn check_request(&self, request: &LinuxBindingRequest) -> io::Result<()> {
        self.ensure_recovered()?;
        if request.instance != self.state.instance
            || request.serial != self.state.serial
            || request.digest != self.state.digest
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn transaction_groups(&self, tx: &Transaction) -> io::Result<Vec<GroupEvidence>> {
        let mut slots: BTreeSet<_> = tx.aliases.iter().map(|a| a.group).collect();
        for history in &self.state.history {
            if tx
                .aliases
                .iter()
                .any(|a| (a.owner, a.selector) == (history.owner, history.selector))
            {
                slots.insert(history.group);
            }
        }
        slots
            .into_iter()
            .map(|slot| {
                self.state
                    .groups
                    .iter()
                    .find(|g| g.slot == slot)
                    .and_then(|g| g.evidence.clone())
                    .ok_or_else(invalid)
            })
            .collect()
    }
    pub(super) fn validate(&self) -> io::Result<()> {
        let state = &self.state;
        validate_header(state)?;
        validate_groups(&state.groups)?;
        validate_transactions(state)?;
        validate_history(state)?;
        state.publication.validate(state)
    }
    pub(super) fn recover(&mut self, writer: &mut KernelWriter) -> io::Result<BindingRecovery> {
        self.recovered = false;
        self.restore_current(writer)?;
        if self.state.publication.unused() {
            self.publication_checked = true;
        }
        if !self.publication_checked {
            return Err(io::Error::other("Сначала восстановите durable публикацию"));
        }
        self.check_inventory(writer)?;
        self.check_slots(writer)?;
        self.recover_transactions(writer)?;
        self.prune_reserved_keys(writer)?;
        self.recovered = true;
        Ok(BindingRecovery {
            staged: self
                .state
                .transactions
                .iter()
                .map(|t| self.token(t.id))
                .collect(),
        })
    }
    fn restore_current(&mut self, writer: &KernelWriter) -> io::Result<()> {
        self.available()?;
        let instance = Instance::read(writer)?;
        if instance != self.state.instance {
            return Err(invalid());
        }
        let bytes = self.store.load(StateFile::Committed)?.ok_or_else(invalid)?;
        self.restore(&bytes, &instance)
    }
    fn recover_transactions(&mut self, writer: &mut KernelWriter) -> io::Result<()> {
        let incomplete: Vec<_> = self
            .state
            .transactions
            .iter()
            .filter(|t| !t.staged)
            .map(|t| self.token(t.id))
            .collect();
        for token in incomplete {
            self.abort(writer, token)?;
        }
        self.mark_orphans_releasing()?;
        self.finish_releases(writer)?;
        for group in &self.state.groups {
            if let Some(evidence) = &group.evidence {
                GroupRetention::verify(writer, evidence)?;
            }
        }
        Ok(())
    }
    fn mark_orphans_releasing(&mut self) -> io::Result<()> {
        let claimed: BTreeSet<_> = self
            .state
            .transactions
            .iter()
            .flat_map(|tx| tx.aliases.iter().map(|alias| alias.group))
            .chain(self.state.history.iter().map(|edge| edge.group))
            .collect();
        let mut changed = false;
        for group in &mut self.state.groups {
            if group.evidence.is_none()
                && !group.published
                && !group.releasing
                && !claimed.contains(&group.slot)
            {
                group.releasing = true;
                changed = true;
            }
        }
        if changed {
            self.persist()?;
        }
        Ok(())
    }
    pub(super) fn prune_reserved_keys(&self, writer: &mut KernelWriter) -> io::Result<()> {
        let retained = self
            .state
            .groups
            .iter()
            .map(|g| self.state.instance.key(g.cookie))
            .collect::<io::Result<BTreeSet<_>>>()?;
        for key in writer.slots.group_keys() {
            if !retained.contains(&key) {
                writer.slots.forget_group(&key)?;
            }
        }
        Ok(())
    }
    fn check_inventory(&self, writer: &KernelWriter) -> io::Result<()> {
        let inventory = GroupRetention::inventory(writer)?;
        for name in inventory {
            let value = name.to_str().map_err(|_| invalid())?;
            if !self
                .state
                .groups
                .iter()
                .filter_map(|g| g.evidence.as_ref())
                .any(|e| {
                    ["link", "pending", "releasing"]
                        .iter()
                        .any(|p| value == format!("{p}_{:08x}", e.link))
                })
            {
                return Err(invalid());
            }
        }
        if self.state.groups.len() + writer.recover_retentions()?.len() > GROUP_LIMIT {
            return Err(invalid());
        }
        Ok(())
    }
    fn check_slots(&self, writer: &KernelWriter) -> io::Result<()> {
        for group in &self.state.groups {
            writer.slots.require_binding(
                &self.state.instance.key(group.cookie)?,
                NonZeroU32::new(group.slot).ok_or_else(invalid)?,
            )?;
        }
        self.check_selector_slots(writer)?;
        Ok(())
    }
    fn check_selector_slots(&self, writer: &KernelWriter) -> io::Result<()> {
        for tx in &self.state.transactions {
            for alias in &tx.aliases {
                self.check_selector(writer, alias)?;
            }
        }
        for edge in &self.state.history {
            writer.slots.require_selector(edge.selector)?;
        }
        Ok(())
    }
    fn check_selector(&self, writer: &KernelWriter, alias: &Alias) -> io::Result<()> {
        let key = SlotKey::new(crate::slots::SlotKind::Executable, alias.path.clone())?;
        writer
            .slots
            .require_binding(&key, NonZeroU32::new(alias.selector).ok_or_else(invalid)?)
    }
    pub(super) fn abort(
        &mut self,
        writer: &mut KernelWriter,
        token: BindingTxnId,
    ) -> io::Result<()> {
        self.available()?;
        self.require_issued(token)?;
        if self.state.publication.references(token.number) {
            return Err(io::Error::other(
                "Подготовка удерживается опубликованным снимком",
            ));
        }
        if !self
            .state
            .transactions
            .iter()
            .any(|tx| tx.id == token.number)
        {
            return self.finish_releases(writer);
        }
        self.state.transactions.retain(|t| t.id != token.number);
        for group in &mut self.state.groups {
            if !group.published
                && !self
                    .state
                    .transactions
                    .iter()
                    .any(|t| t.aliases.iter().any(|a| a.group == group.slot))
            {
                group.releasing = true;
            }
        }
        // Release Intent предшествует первому unlink и сохраняется при любом сбое.
        self.persist()?;
        self.finish_releases(writer)
    }
    fn require_issued(&self, token: BindingTxnId) -> io::Result<()> {
        if token.instance != self.state.instance.digest()
            || token.number == 0
            || token.number >= self.state.next
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn finish_releases(&mut self, writer: &mut KernelWriter) -> io::Result<()> {
        let pending: Vec<_> = self
            .state
            .groups
            .iter()
            .filter(|g| g.releasing)
            .cloned()
            .collect();
        for group in pending {
            if group.published {
                return Err(invalid());
            }
            if let Some(evidence) = &group.evidence {
                GroupRetention::release(writer, evidence)?;
            }
            self.state.groups.retain(|g| g.slot != group.slot);
            self.persist()?;
            writer
                .slots
                .forget_group(&self.state.instance.key(group.cookie)?)?;
        }
        Ok(())
    }
}
fn valid_owner(owner: u64) -> io::Result<()> {
    if owner >> 32 != 1 && owner != 3u64 << 32 {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn validate_header(state: &Manifest) -> io::Result<()> {
    if state.kind != "linux-verified-bindings" || state.version != 3 || state.next == 0 {
        return Err(invalid());
    }
    if state.groups.len() > GROUP_LIMIT
        || state.transactions.len() > TRANSACTION_LIMIT
        || state.history.len() > EDGE_LIMIT
    {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn validate_transactions(state: &Manifest) -> io::Result<()> {
    let mut ids = BTreeSet::new();
    let mut edges = state.history.len();
    for tx in &state.transactions {
        valid_transaction_id(tx, state)?;
        if !ids.insert(tx.id) {
            return Err(invalid());
        }
        edges = edges.checked_add(tx.aliases.len()).ok_or_else(invalid)?;
        validate_aliases(tx, &state.groups)?;
    }
    if edges > EDGE_LIMIT {
        return Err(invalid());
    }
    Ok(())
}
fn valid_transaction_id(tx: &Transaction, state: &Manifest) -> io::Result<()> {
    if tx.id == 0 || tx.id >= state.next || tx.serial == 0 || tx.serial > state.serial {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn validate_history(state: &Manifest) -> io::Result<()> {
    let mut history = BTreeSet::new();
    for edge in &state.history {
        if edge.accepted_serial == 0 || edge.accepted_serial > state.serial || edge.selector == 0 {
            return Err(invalid());
        }
        if !history.insert((edge.owner, edge.selector, edge.group))
            || !state
                .groups
                .iter()
                .any(|g| g.slot == edge.group && g.published)
        {
            return Err(invalid());
        }
        valid_owner(edge.owner)?;
    }
    Ok(())
}
pub(super) fn validate_groups(groups: &[Group]) -> io::Result<()> {
    let mut slots = BTreeSet::new();
    let mut cookies = BTreeSet::new();
    let mut links = BTreeSet::new();
    for group in groups {
        validate_group(group)?;
        if !slots.insert(group.slot) || !cookies.insert(group.cookie) {
            return Err(invalid());
        }
        if let Some(e) = &group.evidence {
            if !links.insert(e.link) {
                return Err(invalid());
            }
        }
    }
    Ok(())
}
fn validate_group(group: &Group) -> io::Result<()> {
    if group.slot == 0 || group.cookie == 0 || group.inode == 0 {
        return Err(invalid());
    }
    if let Some(e) = &group.evidence {
        validate_evidence(group, e)?;
    }
    if group.published && (group.releasing || group.evidence.is_none()) {
        return Err(invalid());
    }
    Ok(())
}
fn validate_evidence(group: &Group, evidence: &GroupEvidence) -> io::Result<()> {
    if (
        evidence.slot,
        evidence.cookie,
        evidence.device,
        evidence.inode,
    ) != (group.slot, group.cookie, group.device, group.inode)
    {
        return Err(invalid());
    }
    if evidence.link == 0 || evidence.record == 0 || evidence.program == 0 || evidence.pid == 0 {
        return Err(invalid());
    }
    Ok(())
}
fn validate_aliases(tx: &Transaction, groups: &[Group]) -> io::Result<()> {
    if tx.policies.len() > 256 || tx.policies.iter().any(|p| p.len() != 14376) {
        return Err(invalid());
    }
    let mut aliases = BTreeSet::new();
    for alias in &tx.aliases {
        validate_alias(alias)?;
        if !aliases.insert((alias.owner, alias.selector)) {
            return Err(invalid());
        }
        let group = groups
            .iter()
            .find(|g| g.slot == alias.group)
            .ok_or_else(invalid)?;
        validate_alias_group(tx, group)?;
    }
    Ok(())
}
fn validate_alias_group(tx: &Transaction, group: &Group) -> io::Result<()> {
    if group.releasing || tx.staged && group.evidence.is_none() {
        return Err(invalid());
    }
    Ok(())
}
fn validate_alias(alias: &Alias) -> io::Result<()> {
    valid_owner(alias.owner)?;
    if alias.selector == 0 || alias.path.is_empty() || alias.path.len() >= 4096 {
        return Err(invalid());
    }
    if !Path::new(&alias.path).is_absolute() || alias.path.contains('\0') {
        return Err(invalid());
    }
    if alias.source_scope[0] == 0
        || alias.source_scope[2] == 0
        || alias.source_scope[3] == 0
        || alias.source_keys[1][2] != u64::MAX
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;
    struct Fixture {
        registry: Registry,
        path: std::path::PathBuf,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.path).unwrap();
        }
    }
    fn fixture() -> Fixture {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aivpn-verified-model-{}-{sequence}",
            std::process::id()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        let instance = Instance {
            namespace: [1; 16],
            boot: [2; 32],
            image: [3; 32],
            inventory: [4; 32],
            path_map: 5,
            inode_map: 6,
            seed: [7; 16],
        };
        let registry = Registry::open(StateDirectory::open(&path).unwrap(), instance).unwrap();
        Fixture { registry, path }
    }
    fn group(slot: u32, published: bool) -> Group {
        Group {
            slot,
            cookie: u64::from(slot),
            device: 1,
            inode: u64::from(slot),
            published,
            releasing: false,
            evidence: Some(GroupEvidence {
                slot,
                cookie: u64::from(slot),
                device: 1,
                inode: u64::from(slot),
                link: slot,
                record: slot,
                program: 1,
                pid: 1,
                digest: [0; 32],
            }),
        }
    }
    fn alias(owner: u64, group: u32) -> Alias {
        Alias {
            owner,
            path: "/selected".into(),
            selector: 10,
            group,
            keys: [[0; 3]; 2],
            source_keys: [[0; 3], [0, 0, u64::MAX]],
            source_scope: [1, 0, 1, 1],
        }
    }
    #[test]
    fn modeled_accepted_history_is_owner_scoped_and_reactivation_requires_a_current_alias() {
        let mut fixture = fixture();
        let registry = &mut fixture.registry;
        let u1 = (1u64 << 32) | 1000;
        let u2 = (1u64 << 32) | 1001;
        registry.state.groups = vec![group(1, true), group(2, false), group(3, true)];
        registry.state.history = vec![
            History {
                owner: u1,
                selector: 10,
                group: 1,
                accepted_serial: 1,
            },
            History {
                owner: u2,
                selector: 10,
                group: 3,
                accepted_serial: 1,
            },
        ];
        let mut tx = Transaction {
            id: 1,
            serial: 2,
            digest: [0; 32],
            aliases: vec![alias(u1, 2)],
            policies: vec![],
            staged: true,
        };
        let memberships = registry.memberships(&tx);
        assert_eq!(
            memberships
                .iter()
                .map(|e| e.group.get())
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(memberships[0].accepted_serial, Some(1));
        assert_eq!(memberships[1].accepted_serial, None);
        tx.aliases.clear();
        assert!(registry.memberships(&tx).is_empty());
        tx.aliases.push(alias(u2, 2));
        assert_eq!(
            registry
                .memberships(&tx)
                .iter()
                .map(|e| e.group.get())
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(registry.state.history.len(), 2);
    }
    #[test]
    fn modeled_manifest_bounds_reject_duplicate_groups_edges_transactions_and_foreign_state() {
        let mut fixture = fixture();
        let registry = &mut fixture.registry;
        registry.state.groups = (1..=4096).map(|n| group(n, false)).collect();
        assert!(registry.validate().is_ok());
        registry.state.groups.push(group(4097, false));
        assert!(registry.validate().is_err());
        registry.state.groups.pop();
        registry.state.groups[1].cookie = 1;
        assert!(registry.validate().is_err());
        registry.state.groups.clear();
        registry.state.next = 0;
        assert!(registry.validate().is_err());
        registry.state.next = 1;
        registry.state.history = (0..=EDGE_LIMIT)
            .map(|_| History {
                owner: 3u64 << 32,
                selector: 1,
                group: 1,
                accepted_serial: 1,
            })
            .collect();
        assert!(registry.validate().is_err());
        registry.state.history.clear();
        let tx = Transaction {
            id: 1,
            serial: 1,
            digest: [0; 32],
            aliases: vec![],
            policies: vec![],
            staged: false,
        };
        registry.state.transactions = vec![tx; TRANSACTION_LIMIT + 1];
        assert!(registry.validate().is_err());
    }
    #[test]
    fn orphan_release_preserves_claimed_retained_and_published_groups() {
        let mut fixture = fixture();
        let registry = &mut fixture.registry;
        registry.state.serial = 1;
        registry.state.next = 2;
        registry.state.groups = vec![
            group(1, false),
            group(2, false),
            group(3, false),
            group(4, true),
        ];
        registry.state.groups[0].evidence = None;
        registry.state.groups[1].evidence = None;
        registry.state.transactions.push(Transaction {
            id: 1,
            serial: 1,
            digest: [0; 32],
            aliases: vec![alias(3u64 << 32, 2)],
            policies: vec![],
            staged: false,
        });
        registry.state.history.push(History {
            owner: 3u64 << 32,
            selector: 10,
            group: 4,
            accepted_serial: 1,
        });
        registry.persist().unwrap();
        registry.mark_orphans_releasing().unwrap();
        assert_eq!(
            registry
                .state
                .groups
                .iter()
                .filter(|g| g.releasing)
                .map(|g| g.slot)
                .collect::<Vec<_>>(),
            vec![1]
        );
        let saved = registry.store.load(StateFile::Committed).unwrap().unwrap();
        registry.mark_orphans_releasing().unwrap();
        assert_eq!(
            registry.store.load(StateFile::Committed).unwrap().unwrap(),
            saved
        );
        assert_eq!(registry.state.transactions.len(), 1);
        assert_eq!(registry.state.history.len(), 1);
    }
    #[test]
    fn stale_serial_and_same_serial_changed_digest_are_refused() {
        let mut fixture = fixture();
        let registry = &mut fixture.registry;
        registry.select(7, [4; 32]).unwrap();
        assert!(registry.select(6, [4; 32]).is_err());
        assert!(registry.select(7, [5; 32]).is_err());
        registry.select(7, [4; 32]).unwrap();
    }
}
