//! Журнал удаления лежит рядом с состоянием и переживает удаление control/state.json.
use super::logs::worker_log;
use super::*;
use crate::maintenance::DecommissionProof;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Seek, SeekFrom},
};

const LIMIT: usize = 65536;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Node {
    path: String,
    directory: bool,
    volume: u32,
    id: u64,
    hash: Option<[u8; 32]>,
}

pub(crate) struct RemovalEvidence {
    namespace: [u8; 16],
    serial: u64,
    state: [u8; 32],
    root: (u32, u64),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StateRetirement {
    version: u32,
    root: PathBuf,
    namespace: [u8; 16],
    serial: u64,
    state: [u8; 32],
    complete: bool,
    nodes: Vec<Node>,
}

impl StateDirectory {
    pub(crate) fn removal_evidence(
        &self,
        proof: &DecommissionProof<'_>,
    ) -> io::Result<RemovalEvidence> {
        self.validate_directory()?;
        proof.confirm()?;
        if self.load(StateFile::Committed)?.as_deref() != Some(proof.namespace().as_slice()) {
            return Err(unsafe_object());
        }
        Ok(RemovalEvidence {
            namespace: proof.namespace(),
            serial: proof.serial(),
            state: proof.digest(),
            root: identity(&information(
                self.ancestors.last().ok_or_else(unsafe_object)?,
                true,
            )?),
        })
    }
}

fn canonical(path: &Path) -> io::Result<PathBuf> {
    let (mut root, names) = api::volume_path(path)?;
    if names.is_empty() {
        return Err(unsafe_object());
    }
    root.extend(names);
    Ok(root)
}

fn identity(info: &BY_HANDLE_FILE_INFORMATION) -> (u32, u64) {
    (
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    )
}

fn known(path: &str, directory: bool) -> bool {
    if directory {
        return ["", "control", "slots", "retirement"].contains(&path);
    }
    let parts: Vec<_> = path.split('/').collect();
    let record = |name: &str| {
        name == ".lock"
            || [
                StateFile::Committed,
                StateFile::Pending,
                StateFile::DnsJournal,
            ]
            .into_iter()
            .any(|file| {
                let (committed, temporary) = names_for(file);
                name == committed || name == temporary
            })
    };
    match parts.as_slice() {
        [name] if record(name) => true,
        ["control" | "slots" | "retirement", name] => record(name),
        [name] => worker_log(name),
        _ => false,
    }
}

fn file_hash(file: &File) -> io::Result<[u8; 32]> {
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut total = 0;
    loop {
        let width = reader.read(&mut buffer)?;
        if width == 0 {
            break;
        }
        total += width;
        if total > MAX_STATE_BYTES {
            return Err(oversized());
        }
        hash.update(&buffer[..width]);
    }
    Ok(hash.finalize().into())
}

fn scan(root: &Path) -> io::Result<Vec<(Node, File)>> {
    fn visit(
        root: &Path,
        relative: &str,
        directory: bool,
        descriptor: &Descriptor,
        objects: &mut Vec<(Node, File)>,
    ) -> io::Result<()> {
        if objects.len() >= LIMIT || !known(relative, directory) {
            return Err(unsafe_object());
        }
        let path = if relative.is_empty() {
            root.to_owned()
        } else {
            root.join(relative.replace('/', "\\"))
        };
        let file = open(
            &path,
            FILE_READ_ATTRIBUTES
                | READ_CONTROL
                | DELETE
                | if directory { 0 } else { FILE_READ_DATA },
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            None,
            FILE_FLAG_BACKUP_SEMANTICS,
        )?;
        let info = information(&file, directory)?;
        if !directory && worker_log(relative) {
            // SCM может назначить владельцем журнала Administrators. Запись остается привилегированной.
            image::protected_writer(&file)?;
        } else {
            descriptor.validate(&file, directory)?;
        }
        let (volume, id) = identity(&info);
        let hash = if directory {
            None
        } else {
            Some(file_hash(&file)?)
        };
        objects.push((
            Node {
                path: relative.into(),
                directory,
                volume,
                id,
                hash,
            },
            file,
        ));
        if directory {
            for entry in std::fs::read_dir(&path)? {
                let entry = entry?;
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| unsafe_object())?;
                let child = if relative.is_empty() {
                    name
                } else {
                    format!("{relative}/{name}")
                };
                visit(
                    root,
                    &child,
                    entry.file_type()?.is_dir(),
                    descriptor,
                    objects,
                )?;
            }
        }
        Ok(())
    }
    let mut objects = Vec::new();
    visit(root, "", true, &Descriptor::current()?, &mut objects)?;
    Ok(objects)
}

impl StateRetirement {
    pub(crate) fn load(store: &StateDirectory, requested: &Path) -> io::Result<Option<Self>> {
        store.validate_directory()?;
        image::protected_writer(
            store
                .ancestors
                .get(
                    store
                        .ancestors
                        .len()
                        .checked_sub(2)
                        .ok_or_else(unsafe_object)?,
                )
                .ok_or_else(unsafe_object)?,
        )?;
        let Some(bytes) = store.load(StateFile::Committed)? else {
            return Ok(None);
        };
        let plan: Self = serde_json::from_slice(&bytes)?;
        plan.validate(requested)?;
        if store.load(StateFile::Pending)?.is_some() {
            return Err(unsafe_object());
        }
        if plan.complete && std::fs::symlink_metadata(&plan.root).is_ok() {
            // Новый экземпляр требует новой decommission-проверки, прежний план его не удаляет.
            return Ok(None);
        }
        Ok(Some(plan))
    }

    pub(crate) fn capture(
        requested: &Path,
        evidence: RemovalEvidence,
        store: &mut StateDirectory,
    ) -> io::Result<Self> {
        image::protected_writer(
            store
                .ancestors
                .get(
                    store
                        .ancestors
                        .len()
                        .checked_sub(2)
                        .ok_or_else(unsafe_object)?,
                )
                .ok_or_else(unsafe_object)?,
        )?;
        let root = canonical(requested)?;
        let nodes = scan(&root)?
            .into_iter()
            .map(|(node, _)| node)
            .collect::<Vec<_>>();
        let source = nodes
            .iter()
            .find(|node| node.path.is_empty())
            .ok_or_else(unsafe_object)?;
        if (source.volume, source.id) != evidence.root
            || nodes
                .iter()
                .find(|node| node.path == "control/state.json")
                .and_then(|node| node.hash)
                != Some(evidence.state)
            || nodes
                .iter()
                .find(|node| node.path == "state.json")
                .and_then(|node| node.hash)
                != Some(Sha256::digest(evidence.namespace).into())
        {
            return Err(unsafe_object());
        }
        let plan = Self {
            version: 1,
            root,
            namespace: evidence.namespace,
            serial: evidence.serial,
            state: evidence.state,
            complete: false,
            nodes,
        };
        plan.validate(requested)?;
        let bytes = serde_json::to_vec(&plan)?;
        store.replace(StateFile::Committed, &bytes)?;
        if store.load(StateFile::Committed)?.as_deref() != Some(bytes.as_slice()) {
            return Err(unsafe_object());
        }
        Ok(plan)
    }

    fn validate(&self, requested: &Path) -> io::Result<()> {
        if self.version != 1
            || self.root != canonical(requested)?
            || self.nodes.is_empty()
            || self.nodes.len() > LIMIT
        {
            return Err(unsafe_object());
        }
        let mut paths = std::collections::BTreeSet::new();
        for node in &self.nodes {
            if !known(&node.path, node.directory)
                || node.id == 0
                || node.hash.is_none() != node.directory
                || !paths.insert(&node.path)
            {
                return Err(unsafe_object());
            }
        }
        if !self
            .nodes
            .iter()
            .any(|node| node.path.is_empty() && node.directory)
        {
            return Err(unsafe_object());
        }
        if self.serial == 0
            || self
                .nodes
                .iter()
                .find(|node| node.path == "control/state.json")
                .and_then(|node| node.hash)
                != Some(self.state)
            || self
                .nodes
                .iter()
                .find(|node| node.path == "state.json")
                .and_then(|node| node.hash)
                != Some(Sha256::digest(self.namespace).into())
        {
            return Err(unsafe_object());
        }
        Ok(())
    }

    pub(crate) fn apply(&mut self, requested: &Path, store: &mut StateDirectory) -> io::Result<()> {
        self.validate(requested)?;
        let live = match std::fs::symlink_metadata(&self.root) {
            Ok(_) if self.complete => return Err(unsafe_object()),
            Ok(_) => scan(&self.root)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error),
        };
        let expected: BTreeMap<_, _> = self
            .nodes
            .iter()
            .map(|node| (node.path.as_str(), node))
            .collect();
        for (node, _) in &live {
            if expected.get(node.path.as_str()).copied() != Some(node) {
                return Err(unsafe_object());
            }
        }
        let mut live = live;
        live.sort_by_key(|(node, _)| {
            (
                std::cmp::Reverse(if node.path.is_empty() {
                    0
                } else {
                    node.path.matches('/').count() + 1
                }),
                node.directory,
            )
        });
        for (node, file) in live {
            let info = information(&file, node.directory)?;
            if identity(&info) != (node.volume, node.id)
                || !node.directory && Some(file_hash(&file)?) != node.hash
            {
                return Err(unsafe_object());
            }
            let disposition = FILE_DISPOSITION_INFO_EX {
                Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
            };
            fault(Point::Delete)?;
            checked(unsafe {
                SetFileInformationByHandle(
                    handle(&file),
                    FileDispositionInfoEx,
                    ptr::addr_of!(disposition).cast(),
                    std::mem::size_of_val(&disposition) as u32,
                )
            })?;
        }
        store.flush_volume()?;
        self.complete = true;
        store.replace(StateFile::Committed, &serde_json::to_vec(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn state_retirement_accepts_only_internal_records_and_exact_worker_log_names() {
        for (path, directory) in [
            ("", true),
            ("control", true),
            ("slots/state.json", false),
            ("worker-12345678-1234-abcd-1234567890abcdef.log", false),
        ] {
            assert!(known(path, directory), "{path}");
        }
        for (path, directory) in [
            ("../control", true),
            ("control/state.json/extra", false),
            ("manual-note.txt", false),
            ("worker-x.log", false),
            ("worker.log", false),
            ("retirement/foreign", true),
            ("control", false),
        ] {
            assert!(!known(path, directory), "{path}");
        }
    }

    #[test]
    #[ignore = "Нужен отдельный LocalSystem стенд с правом сброса NTFS"]
    fn native_state_removal_preserves_unknown_and_replaced_files_then_resumes_without_control() {
        assert_eq!(
            crate::windows::current_owner().unwrap(),
            crate::policy::Owner::WindowsUser {
                sid: "S-1-5-18".into()
            }
        );
        let base = std::env::temp_dir().join(format!(
            "aivpn-retirement-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let parent = StateDirectory::open(&base).unwrap();
        let requested = base.join("state");
        let namespace = [0x44; 16];
        let control_bytes = b"terminal control filesystem fixture";
        let mut root = StateDirectory::open(&requested).unwrap();
        root.replace(StateFile::Committed, &namespace).unwrap();
        let mut control = root.child(c"control").unwrap();
        control
            .replace(StateFile::Committed, control_bytes)
            .unwrap();
        drop(control);
        let root_id = identity(&information(root.ancestors.last().unwrap(), true).unwrap());
        drop(root);
        let mut sd = ptr::null_mut();
        checked(unsafe {windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW(api::wide("O:BAD:P(A;;FA;;;SY)").as_ptr(),1,&mut sd,ptr::null_mut())}).unwrap();
        let attributes = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let log = open(
            &requested.join("worker-12345678-1234-abcd-1234567890abcdef.log"),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            CREATE_NEW,
            Some(&attributes),
            0,
        );
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(sd);
        }
        drop(log.unwrap());
        let evidence = || RemovalEvidence {
            namespace,
            serial: 1,
            state: Sha256::digest(control_bytes).into(),
            root: root_id,
        };
        let mut journal = StateDirectory::open(&base.join("stateRemoval")).unwrap();
        let unknown = requested.join("manual-note.txt");
        std::fs::write(&unknown, b"preserve").unwrap();
        assert!(StateRetirement::capture(&requested, evidence(), &mut journal).is_err());
        assert_eq!(std::fs::read(&unknown).unwrap(), b"preserve");
        assert_eq!(
            std::fs::read(requested.join("state.json")).unwrap(),
            namespace
        );
        std::fs::remove_file(unknown).unwrap();
        let mut plan = StateRetirement::capture(&requested, evidence(), &mut journal).unwrap();
        let record = requested.join("control/state.json");
        let backup = base.join("saved-control");
        std::fs::rename(&record, &backup).unwrap();
        std::fs::write(&record, control_bytes).unwrap();
        assert!(plan.apply(&requested, &mut journal).is_err());
        assert_eq!(std::fs::read(&record).unwrap(), control_bytes);
        assert_eq!(
            std::fs::read(requested.join("state.json")).unwrap(),
            namespace
        );
        std::fs::remove_file(&record).unwrap();
        std::fs::rename(backup, &record).unwrap();
        // Реальный завершенный префикс удаления: control snapshot больше недоступен.
        std::fs::remove_file(record).unwrap();
        let mut resumed = StateRetirement::load(&journal, &requested)
            .unwrap()
            .unwrap();
        FAULT.with(|fault| fault.set(Some(Point::VolumeFlush)));
        assert!(resumed.apply(&requested, &mut journal).is_err());
        assert!(!requested.exists());
        let mut resumed = StateRetirement::load(&journal, &requested)
            .unwrap()
            .unwrap();
        resumed.apply(&requested, &mut journal).unwrap();
        resumed.apply(&requested, &mut journal).unwrap();
        let fresh = StateDirectory::open(&requested).unwrap();
        assert!(StateRetirement::load(&journal, &requested)
            .unwrap()
            .is_none());
        assert!(resumed.apply(&requested, &mut journal).is_err());
        drop(fresh);
        drop(journal);
        drop(parent);
        std::fs::remove_dir_all(base).unwrap();
    }
}
