//! План удаления сохраняется до unlink и не принимает новые или замененные pins.
use super::{
    objects::{open_pin, ObjectInfo},
    pins::{bpffs_root, open_directory_at},
};
use crate::{
    maintenance::DecommissionProof,
    state::{StateDirectory, StateFile},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CStr, CString},
    fs::File,
    io,
    os::{fd::AsRawFd, unix::ffi::OsStrExt},
};

const MAX_PINS: usize = 65536;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::linux) enum Base {
    Routes,
    Snapshots,
    Groups,
    Profiles,
}
impl Base {
    fn name(self) -> &'static CStr {
        match self {
            Self::Routes => c"aivpn_app_routes",
            Self::Snapshots => c"aivpn_app_binding_snapshots",
            Self::Groups => c"aivpn_app_group_retainers",
            Self::Profiles => c"aivpn_app_profile_programs",
        }
    }
    fn directory(self, namespace: [u8; 16]) -> io::Result<Option<File>> {
        let result = (|| {
            let base = open_directory_at(&bpffs_root()?, self.name())?;
            if self == Self::Profiles {
                return Ok(base);
            }
            open_directory_at(&base, &namespace_name(namespace))
        })();
        match result {
            Ok(directory) => Ok(Some(directory)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::linux) enum Kind {
    Map,
    Program,
    RootLink,
    RetainerLink,
}
impl Kind {
    fn fingerprint(self, info: &ObjectInfo) -> io::Result<Vec<u32>> {
        match self {
            Self::Map => info.fingerprint(c"maps/pin"),
            Self::Program => info.fingerprint(c"programs/pin"),
            Self::RootLink => info.fingerprint(c"links/pin"),
            // Идентичность fd-session link проверяет GroupRetention до записи плана.
            Self::RetainerLink => Ok(info.words[..3].to_vec()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::linux) struct Pin {
    base: Base,
    path: String,
    kind: Kind,
    fingerprint: Vec<u32>,
}
impl Pin {
    pub(in crate::linux) fn capture(
        base: Base,
        namespace: [u8; 16],
        path: String,
        kind: Kind,
        id: u32,
    ) -> io::Result<Self> {
        let mut pin = Self {
            base,
            path,
            kind,
            fingerprint: vec![],
        };
        pin.validate_path()?;
        let directory = base.directory(namespace)?.ok_or(io::ErrorKind::NotFound)?;
        let (parent, leaf) = parent(&directory, &pin.path)?;
        let actual = ObjectInfo::read(&open_pin(&parent, &leaf)?)?;
        if actual.words[1] != id {
            return Err(invalid());
        }
        pin.fingerprint = kind.fingerprint(&actual)?;
        Ok(pin)
    }
    fn validate_path(&self) -> io::Result<()> {
        if self.path.is_empty()
            || self.path.len() > 256
            || self.path.split('/').any(|part| {
                part.is_empty()
                    || !part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            })
        {
            return Err(invalid());
        }
        let parts: Vec<_> = self.path.split('/').collect();
        let valid = match (self.base, self.kind, parts.as_slice()) {
            (Base::Routes, Kind::Map, ["metadata" | "inventory" | "core_inventory"]) => true,
            (Base::Routes, Kind::Map, ["maps", _]) => true,
            (Base::Routes, Kind::Program, ["programs", _]) => true,
            (Base::Routes, Kind::RootLink, ["links", _]) => true,
            (Base::Profiles, Kind::Program, [name]) => {
                name.len() == 41
                    && name.as_bytes()[32] == b'_'
                    && name[..32].bytes().all(|b| b.is_ascii_hexdigit())
                    && name[33..].bytes().all(|b| b.is_ascii_hexdigit())
            }
            (Base::Snapshots, Kind::Map, [name]) => hex_name(name, "snapshot_", 16),
            (Base::Groups, Kind::RetainerLink, [name, "link"])
            | (Base::Groups, Kind::Map, [name, "record" | "instance"]) => {
                ["link_", "pending_", "releasing_"]
                    .iter()
                    .any(|prefix| hex_name(name, prefix, 8))
            }
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(invalid())
        }
    }
    fn check(&self, directory: &File) -> io::Result<bool> {
        let result = (|| {
            let (parent, leaf) = parent(directory, &self.path)?;
            let actual = ObjectInfo::read(&open_pin(&parent, &leaf)?)?;
            if self.kind.fingerprint(&actual)? != self.fingerprint {
                return Err(invalid());
            }
            Ok(true)
        })();
        match result {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            other => other,
        }
    }
    fn priority(&self) -> u8 {
        match self.kind {
            Kind::RootLink => 0,
            Kind::RetainerLink => 1,
            Kind::Program => 3,
            Kind::Map => 2,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: u32,
    namespace: [u8; 16],
    boot: String,
    serial: u64,
    state: [u8; 32],
    complete: bool,
    pins: Vec<Pin>,
    paths: crate::linux::backend::path::retirement::PathRetirement,
}
impl Plan {
    fn new(
        proof: &DecommissionProof<'_>,
        mut pins: Vec<Pin>,
        paths: crate::linux::backend::path::retirement::PathRetirement,
    ) -> io::Result<Self> {
        proof.confirm()?;
        pins.sort_by(|a, b| (a.priority(), a.base, &a.path).cmp(&(b.priority(), b.base, &b.path)));
        let plan = Self {
            version: 2,
            namespace: proof.namespace(),
            boot: boot()?,
            serial: proof.serial(),
            state: proof.digest(),
            complete: false,
            pins,
            paths,
        };
        plan.validate(proof)?;
        Ok(plan)
    }
    fn validate(&self, proof: &DecommissionProof<'_>) -> io::Result<()> {
        proof.confirm()?;
        if self.version != 2
            || self.namespace != proof.namespace()
            || self.serial != proof.serial()
            || self.state != proof.digest()
            || self.pins.len() > MAX_PINS
            || self.boot.is_empty()
        {
            return Err(invalid());
        }
        self.paths.validate(self.namespace)?;
        let mut keys = BTreeSet::new();
        for pin in &self.pins {
            pin.validate_path()?;
            if pin.base == Base::Profiles
                && !pin.path.starts_with(&format!(
                    "{}_",
                    namespace_name(self.namespace).to_str().unwrap()
                ))
            {
                return Err(invalid());
            }
            if !(3..=16).contains(&pin.fingerprint.len())
                || pin.fingerprint[1] == 0
                || !keys.insert((pin.base, pin.path.as_str()))
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
    fn preflight(&self) -> io::Result<()> {
        let same_boot = self.boot == boot()?;
        for base in [Base::Routes, Base::Snapshots, Base::Groups, Base::Profiles] {
            let Some(directory) = base.directory(self.namespace)? else {
                continue;
            };
            if base == Base::Profiles {
                let prefix = format!("{}_", namespace_name(self.namespace).to_str().unwrap());
                for entry in std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))?
                {
                    let entry = entry?;
                    let name = entry.file_name().into_string().map_err(|_| invalid())?;
                    if !name.starts_with(&prefix) {
                        continue;
                    }
                    if !same_boot || self.complete {
                        return Err(invalid());
                    }
                    let pin = self
                        .pins
                        .iter()
                        .find(|pin| pin.base == base && pin.path == name)
                        .ok_or_else(invalid)?;
                    if entry.file_type()?.is_dir() || !pin.check(&directory)? {
                        return Err(invalid());
                    }
                }
                continue;
            }
            if !same_boot || self.complete {
                return Err(invalid());
            }
            let pins: BTreeMap<_, _> = self
                .pins
                .iter()
                .filter(|pin| pin.base == base)
                .map(|pin| (pin.path.as_str(), pin))
                .collect();
            let mut allowed_dirs: BTreeSet<String> = if base == Base::Routes {
                ["maps", "programs", "links"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
            } else {
                BTreeSet::new()
            };
            for path in pins.keys() {
                if let Some((parent, _)) = path.rsplit_once('/') {
                    allowed_dirs.insert(parent.to_owned());
                }
            }
            scan(&directory, "", &pins, &allowed_dirs, self.complete, &mut 0)?;
        }
        Ok(())
    }
    fn apply(&mut self, proof: &DecommissionProof<'_>) -> io::Result<()> {
        self.validate(proof)?;
        self.preflight()?;
        self.paths.preflight()?;
        if self.complete {
            return Ok(());
        }
        self.paths.apply(proof)?;
        for pin in &self.pins {
            proof.confirm()?;
            let Some(directory) = pin.base.directory(self.namespace)? else {
                continue;
            };
            if !pin.check(&directory)? {
                continue;
            }
            let (parent, leaf) = parent(&directory, &pin.path)?;
            if unsafe { libc::unlinkat(parent.as_raw_fd(), leaf.as_ptr(), 0) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        self.remove_directories()?;
        self.complete = true;
        Ok(())
    }
    fn remove_directories(&self) -> io::Result<()> {
        for base in [Base::Routes, Base::Snapshots, Base::Groups] {
            let Some(directory) = base.directory(self.namespace)? else {
                continue;
            };
            for entry in std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    return Err(invalid());
                }
                let entry_name = entry.file_name();
                let text = entry_name.to_str().ok_or_else(invalid)?;
                let known = base == Base::Routes && ["maps", "programs", "links"].contains(&text)
                    || self.pins.iter().any(|pin| {
                        pin.base == base
                            && pin.path.split('/').next() == Some(text)
                            && pin.path.contains('/')
                    });
                if !known {
                    return Err(invalid());
                }
                let name = CString::new(entry.file_name().as_bytes()).map_err(|_| invalid())?;
                open_directory_at(&directory, &name)?;
                if unsafe {
                    libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR)
                } < 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            let parent = open_directory_at(&bpffs_root()?, base.name())?;
            if unsafe {
                libc::unlinkat(
                    parent.as_raw_fd(),
                    namespace_name(self.namespace).as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

pub(super) fn execute(
    proof: &DecommissionProof<'_>,
    store: &mut StateDirectory,
    prepare: impl FnOnce() -> io::Result<(
        Vec<Pin>,
        crate::linux::backend::path::retirement::PathRetirement,
    )>,
) -> io::Result<()> {
    let mut plan = match store.load(StateFile::Committed)? {
        Some(bytes) => serde_json::from_slice::<Plan>(&bytes).map_err(|_| invalid())?,
        None => {
            let (pins, paths) = prepare()?;
            let plan = Plan::new(proof, pins, paths)?;
            plan.preflight().map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("Сверка списка pins перед удалением: {error}"),
                )
            })?;
            plan.paths.preflight()?;
            let bytes = serde_json::to_vec(&plan)?;
            store.replace(StateFile::Committed, &bytes)?;
            store.confirm_loaded(StateFile::Committed, &bytes)?;
            plan
        }
    };
    plan.apply(proof)?;
    store.replace(StateFile::Committed, &serde_json::to_vec(&plan)?)
}

pub(super) fn remove(proof: &DecommissionProof<'_>, runtime: StateDirectory) -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    super::hooks::require_system_namespaces()?;
    let mut store = runtime.child(c"retirement")?;
    execute(proof, &mut store, || {
        let namespace = proof.namespace();
        if ![Base::Routes, Base::Snapshots, Base::Groups]
            .into_iter()
            .map(|base| base.directory(namespace))
            .collect::<io::Result<Vec<_>>>()?
            .iter()
            .any(Option::is_some)
        {
            return Ok((Vec::new(), Default::default()));
        }
        let mut writer =
            super::KernelWriter::open_existing_snapshot(namespace, runtime.child(c"slots")?)?;
        writer.open_verified_bindings(runtime.child(c"bindings")?)?;
        let mut pins = writer.retirement_pins()?;
        let (paths, profile_pins) =
            crate::linux::backend::path::retirement::PathRetirement::capture(
                namespace,
                runtime.child(c"network")?,
            )?;
        pins.extend(profile_pins);
        Ok((pins, paths))
    })
}

fn scan(
    directory: &File,
    prefix: &str,
    pins: &BTreeMap<&str, &Pin>,
    dirs: &BTreeSet<String>,
    complete: bool,
    count: &mut usize,
) -> io::Result<()> {
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
        *count += 1;
        if *count > MAX_PINS * 2 {
            return Err(invalid());
        }
        let entry = entry?;
        let name = entry.file_name().into_string().map_err(|_| invalid())?;
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if entry.file_type()?.is_dir() {
            if !dirs.contains(&path) {
                return Err(invalid());
            }
            let child = open_directory_at(directory, &CString::new(name).map_err(|_| invalid())?)?;
            scan(&child, &path, pins, dirs, complete, count)?;
        } else {
            let pin = pins.get(path.as_str()).ok_or_else(invalid)?;
            if complete {
                return Err(invalid());
            }
            let actual = ObjectInfo::read(&open_pin(
                directory,
                &CString::new(name).map_err(|_| invalid())?,
            )?)?;
            if pin.kind.fingerprint(&actual)? != pin.fingerprint {
                return Err(invalid());
            }
        }
    }
    Ok(())
}
fn parent(directory: &File, path: &str) -> io::Result<(File, CString)> {
    let mut parts: Vec<_> = path.split('/').collect();
    let leaf = CString::new(parts.pop().ok_or_else(invalid)?).map_err(|_| invalid())?;
    let mut parent = directory.try_clone()?;
    for part in parts {
        parent = open_directory_at(&parent, &CString::new(part).map_err(|_| invalid())?)?;
    }
    Ok((parent, leaf))
}
fn namespace_name(namespace: [u8; 16]) -> CString {
    CString::new(
        namespace
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
    .unwrap()
}
fn hex_name(name: &str, prefix: &str, length: usize) -> bool {
    name.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == length && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}
fn boot() -> io::Result<String> {
    Ok(std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .into())
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Принадлежность удаляемых объектов ядра не подтверждена",
    )
}

pub(super) fn names(directory: &File) -> io::Result<BTreeSet<CString>> {
    let mut names = BTreeSet::new();
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
        if names.len() >= MAX_PINS {
            return Err(invalid());
        }
        names.insert(CString::new(entry?.file_name().as_bytes()).map_err(|_| invalid())?);
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_saved_plan_cannot_escape_its_namespace_or_change_object_kinds() {
        for (base, path, kind) in [
            (Base::Routes, "../foreign/maps/data", Kind::Map),
            (Base::Routes, "/maps/data", Kind::Map),
            (Base::Routes, "maps//data", Kind::Map),
            (Base::Routes, "links/trace", Kind::Map),
            (Base::Routes, "metadata", Kind::Program),
            (
                Base::Snapshots,
                "snapshot_0000000000000001/other",
                Kind::Map,
            ),
            (Base::Groups, "link_00000001/instance", Kind::RetainerLink),
            (Base::Groups, "link_00000001/../../foreign", Kind::Map),
        ] {
            let pin = Pin {
                base,
                path: path.into(),
                kind,
                fingerprint: vec![1, 2, 3],
            };
            assert!(pin.validate_path().is_err(), "{pin:?}");
        }
        for (base, path, kind) in [
            (Base::Routes, "maps/process_routes", Kind::Map),
            (Base::Routes, "links/capture_exec", Kind::RootLink),
            (Base::Routes, "programs/classify_exec", Kind::Program),
            (Base::Routes, "inventory", Kind::Map),
            (Base::Routes, "core_inventory", Kind::Map),
            (Base::Snapshots, "snapshot_0000000000000001", Kind::Map),
            (Base::Groups, "link_00000001/instance", Kind::Map),
            (Base::Groups, "releasing_00000001/link", Kind::RetainerLink),
        ] {
            let pin = Pin {
                base,
                path: path.into(),
                kind,
                fingerprint: vec![1, 2, 3],
            };
            assert!(pin.validate_path().is_ok(), "{pin:?}");
        }
    }
}
