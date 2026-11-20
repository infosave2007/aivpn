use super::*;

impl KernelWriter {
    /// Принимает по одному файлу на уникальный выбранный source path.
    /// Владельцы одного пути получают отдельные scoped memberships.
    /// # Safety
    /// Во всем процессе сериализованы mmap/exec. Удерживаемые inode никогда
    /// не отображаются в его mm, включая dlopen; службе нужен отдельный helper.
    pub unsafe fn stage_verified_bindings(
        &mut self,
        request: &LinuxBindingRequest,
        files: Vec<LocatedExecutable>,
    ) -> io::Result<VerifiedBindingSet> {
        self.with_registry(|writer, registry| {
            registry.check_request(request)?;
            let files = verify_files(writer, request, files)?;
            let transaction = registry.reserve(writer, request, &files)?;
            registry.attach_groups(writer, &files)?;
            let set = VerifiedBindingSet { transaction, files };
            registry.verify_files_and_groups(writer, &set)?;
            registry
                .state
                .transactions
                .iter_mut()
                .find(|t| t.id == transaction.number)
                .ok_or_else(invalid)?
                .staged = true;
            registry.persist()?;
            registry.verify_set(writer, &set)?;
            Ok(set)
        })
    }
}
fn verify_files(
    writer: &KernelWriter,
    request: &LinuxBindingRequest,
    files: Vec<LocatedExecutable>,
) -> io::Result<BTreeMap<String, VerifiedFile>> {
    let required: BTreeSet<_> = request.selected.iter().map(|s| s.path.as_str()).collect();
    if files.len() != required.len() {
        return Err(invalid());
    }
    let mut held = BTreeMap::new();
    for file in files {
        let path = file.source_path().to_str().ok_or_else(invalid)?.to_string();
        if !required.contains(path.as_str()) || held.contains_key(&path) {
            return Err(invalid());
        }
        held.insert(path, VerifiedFile::new(writer, file)?);
    }
    Ok(held)
}
impl Registry {
    fn reserve(
        &mut self,
        writer: &mut KernelWriter,
        request: &LinuxBindingRequest,
        files: &BTreeMap<String, VerifiedFile>,
    ) -> io::Result<BindingTxnId> {
        let next = self.preflight(request, files.len())?;
        let legacy = writer.recover_retentions()?.len();
        let mut groups = self.state.groups.clone();
        let identities = files
            .iter()
            .map(|(path, file)| {
                self.identity(writer, file, &mut groups, legacy)
                    .map(|slot| (path.clone(), slot))
            })
            .collect::<io::Result<BTreeMap<_, _>>>();
        let identities = match identities {
            Ok(identities) => identities,
            Err(error) => {
                // Кандидат не попадает в manifest; выданные номера остаются сожженными.
                self.prune_reserved_keys(writer)?;
                return Err(error);
            }
        };
        let mut aliases = Vec::new();
        for selected in &request.selected {
            let group = identities[&selected.path];
            aliases.push(Alias {
                owner: selected.owner,
                selector: selected.selector,
                path: selected.path.clone(),
                group,
                keys: files[&selected.path].keys(),
                source_keys: files[&selected.path].source_keys(),
                source_scope: files[&selected.path].executable.source_scope(),
            });
        }
        self.state.groups = groups;
        let id = self.state.next;
        self.state.next = next;
        self.state.transactions.push(Transaction {
            id,
            serial: request.serial,
            digest: request.digest,
            aliases,
            policies: request.policies.clone(),
            staged: false,
        });
        self.persist()?;
        Ok(self.token(id))
    }
    fn preflight(&self, request: &LinuxBindingRequest, files: usize) -> io::Result<u64> {
        if self.state.transactions.iter().any(|t| !t.staged)
            || self.state.transactions.len() == TRANSACTION_LIMIT
        {
            return Err(invalid());
        }
        let count = self
            .state
            .transactions
            .iter()
            .map(|t| t.aliases.len())
            .sum::<usize>()
            + self.state.history.len()
            + request.selected.len();
        if count > EDGE_LIMIT {
            return Err(invalid());
        }
        self.check_byte_budget(request, files)?;
        self.state.next.checked_add(1).ok_or_else(invalid)
    }
    fn check_byte_budget(&self, request: &LinuxBindingRequest, files: usize) -> io::Result<()> {
        let saved = serde_json::to_vec(&self.state)
            .map_err(io::Error::other)?
            .len();
        let policies: usize = request
            .policies
            .iter()
            .map(|bytes| bytes.len() * 4 + 8)
            .sum();
        let aliases: usize = request
            .selected
            .iter()
            .map(|alias| alias.path.len() * 6 + 256)
            .sum();
        let maximum = saved + policies + aliases + files * 2048 + 4096;
        if maximum > MAX_STATE_BYTES {
            return Err(invalid());
        }
        Ok(())
    }
    fn identity(
        &self,
        writer: &mut KernelWriter,
        file: &VerifiedFile,
        groups: &mut Vec<Group>,
        legacy: usize,
    ) -> io::Result<u32> {
        let cookie = cookie::acquire(writer, &file.executable)?;
        let device = file.executable.filesystem_device();
        let inode = std::fs::File::from(file.executable.as_fd().try_clone_to_owned()?)
            .metadata()?
            .ino();
        if let Some(group) = groups.iter().find(|g| g.cookie == cookie) {
            return reuse(writer, group, device, inode);
        }
        self.reserve_group(writer, groups, cookie, device, inode, legacy)
    }
    fn reserve_group(
        &self,
        writer: &mut KernelWriter,
        groups: &mut Vec<Group>,
        cookie: u64,
        device: u64,
        inode: u64,
        legacy: usize,
    ) -> io::Result<u32> {
        require_capacity(groups.len(), legacy)?;
        let key = self.state.instance.key(cookie)?;
        let slots = writer
            .slots
            .synchronize_grouped(&BTreeSet::from([key.clone()]))?;
        let slot = slots[&key].get();
        groups.push(Group {
            slot,
            cookie,
            device,
            inode,
            evidence: None,
            releasing: false,
            published: false,
        });
        Ok(slot)
    }
    fn attach_groups(
        &mut self,
        writer: &KernelWriter,
        files: &BTreeMap<String, VerifiedFile>,
    ) -> io::Result<()> {
        for file in files.values() {
            let cookie = cookie::acquire(writer, &file.executable)?;
            let index = self
                .state
                .groups
                .iter()
                .position(|g| g.cookie == cookie)
                .ok_or_else(invalid)?;
            if self.state.groups[index].evidence.is_some() {
                continue;
            }
            let proof = PreparedGroupExecutable::new(
                writer,
                &self.state.instance,
                &self.state.groups[index],
                file,
            )?;
            let retention = GroupRetention::attach(writer, &proof)?;
            self.state.groups[index].evidence = Some(retention.evidence());
            // Точные map/link IDs попадают в durable Intent до первого pin.
            self.persist()?;
            retention.pin(writer, &proof)?;
        }
        Ok(())
    }
    pub(super) fn verify_set(
        &self,
        writer: &KernelWriter,
        set: &VerifiedBindingSet,
    ) -> io::Result<()> {
        self.ensure_recovered()?;
        let tx = self.transaction(set.transaction)?;
        if !tx.staged || tx.serial != self.state.serial || tx.digest != self.state.digest {
            return Err(invalid());
        }
        self.verify_files_and_groups(writer, set)
    }
    fn verify_files_and_groups(
        &self,
        writer: &KernelWriter,
        set: &VerifiedBindingSet,
    ) -> io::Result<()> {
        if Instance::read(writer)? != self.state.instance {
            return Err(invalid());
        }
        let tx = self.transaction(set.transaction)?;
        verify_set_paths(set, tx)?;
        for alias in &tx.aliases {
            self.verify_alias(writer, set, alias)?;
        }
        self.verify_retained(writer, tx)
    }
    pub(super) fn verify_retained(
        &self,
        writer: &KernelWriter,
        tx: &Transaction,
    ) -> io::Result<()> {
        for group in self.transaction_groups(tx)? {
            GroupRetention::verify(writer, &group)?;
        }
        Ok(())
    }
    fn verify_alias(
        &self,
        writer: &KernelWriter,
        set: &VerifiedBindingSet,
        alias: &Alias,
    ) -> io::Result<()> {
        let file = set.files.get(&alias.path).ok_or_else(invalid)?;
        file.verify(writer)?;
        let group = self
            .state
            .groups
            .iter()
            .find(|g| g.slot == alias.group)
            .ok_or_else(invalid)?;
        if file.keys() != alias.keys
            || file.source_keys() != alias.source_keys
            || file.executable.source_scope() != alias.source_scope
            || cookie::acquire(writer, &file.executable)? != group.cookie
        {
            return Err(invalid());
        }
        self.verify_alias_slots(writer, alias, group)
    }
    fn verify_alias_slots(
        &self,
        writer: &KernelWriter,
        alias: &Alias,
        group: &Group,
    ) -> io::Result<()> {
        writer.slots.require_binding(
            &self.state.instance.key(group.cookie)?,
            NonZeroU32::new(group.slot).ok_or_else(invalid)?,
        )?;
        let key = SlotKey::new(crate::slots::SlotKind::Executable, alias.path.clone())?;
        writer
            .slots
            .require_binding(&key, NonZeroU32::new(alias.selector).ok_or_else(invalid)?)
    }
}

fn require_capacity(groups: usize, legacy: usize) -> io::Result<()> {
    if groups
        .checked_add(legacy)
        .is_none_or(|count| count >= GROUP_LIMIT)
    {
        return Err(io::Error::other("Лимит удерживаемых групп inode исчерпан"));
    }
    Ok(())
}
fn reuse(writer: &KernelWriter, group: &Group, device: u64, inode: u64) -> io::Result<u32> {
    if group.device != device || group.inode != inode || group.releasing {
        return Err(invalid());
    }
    if let Some(evidence) = &group.evidence {
        GroupRetention::verify(writer, evidence)?;
    }
    Ok(group.slot)
}

fn verify_set_paths(set: &VerifiedBindingSet, tx: &Transaction) -> io::Result<()> {
    let paths: BTreeSet<_> = tx.aliases.iter().map(|a| &a.path).collect();
    if paths.len() != set.files.len() {
        return Err(invalid());
    }
    Ok(())
}
