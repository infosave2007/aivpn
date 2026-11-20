//! Принятие прежних объектов без загрузки новых программ и сброса потоков.

use super::image::{ExpectedInventory, KernelImage};
use super::invalid_object;
use super::objects::{inventory_digest, open_pin, read_array, ObjectInfo};
use super::pins::{bpffs_root, open_directory_at};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

/// Принадлежность начальных guards проверена. Готовность профилей, TUN и DNS
/// подтверждается отдельно; открытие объектов не меняет их данные.
pub struct RecoveredKernel {
    pub(super) mode: super::BindingMode,
    _directory: File,
    _resources: BTreeMap<CString, OwnedFd>,
    _metadata: OwnedFd,
    _inventory: OwnedFd,
}

struct ResourceSet {
    handles: BTreeMap<CString, OwnedFd>,
    info: BTreeMap<CString, ObjectInfo>,
}

struct Completion {
    metadata: OwnedFd,
    inventory: OwnedFd,
    digest: [u8; 32],
}

impl Completion {
    fn read(directory: &File, namespace: [u8; 16], mode: super::BindingMode) -> io::Result<Self> {
        let metadata = completed_pin(directory, c"metadata")?;
        verify_metadata(&metadata, namespace, mode)?;
        let inventory = completed_pin(directory, c"inventory")?;
        let digest = read_array::<32>(&inventory)?;
        Ok(Self {
            metadata,
            inventory,
            digest,
        })
    }
}

impl RecoveredKernel {
    pub(super) fn identity_digest(&self) -> io::Result<[u8; 32]> {
        read_array::<32>(&self._inventory)
    }
    pub(super) fn program(&self, name: &CStr) -> io::Result<&OwnedFd> {
        self._resources
            .get(&qualified(c"programs", name))
            .ok_or_else(invalid_object)
    }

    pub(super) fn map(&self, name: &CStr) -> io::Result<&OwnedFd> {
        self._resources
            .get(&qualified(c"maps", name))
            .ok_or_else(invalid_object)
    }

    pub fn open_existing(namespace: [u8; 16]) -> io::Result<Self> {
        Self::open_mode(namespace, super::BindingMode::Legacy)
    }

    pub(super) fn open_mode(namespace: [u8; 16], mode: super::BindingMode) -> io::Result<Self> {
        let directory = open_namespace(namespace)?;
        require_names(
            &directory,
            &names(["maps", "programs", "links", "metadata", "inventory"]),
        )?;
        let completion = Completion::read(&directory, namespace, mode)?;
        let expected = KernelImage::open_mode(mode)?.expected_inventory()?;
        let resources = read_resources(&directory, expected)?;
        if inventory_digest(&resources.info)? != completion.digest {
            return Err(invalid_object());
        }
        Ok(Self {
            mode,
            _directory: directory,
            _resources: resources.handles,
            _metadata: completion.metadata,
            _inventory: completion.inventory,
        })
    }
}

fn open_namespace(namespace: [u8; 16]) -> io::Result<File> {
    super::hooks::require_system_namespaces()?;
    let root = bpffs_root()?;
    let base = open_directory_at(&root, c"aivpn_app_routes")?;
    let name = CString::new(
        namespace
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
    .unwrap();
    open_directory_at(&base, &name)
}

fn completed_pin(directory: &File, name: &CStr) -> io::Result<OwnedFd> {
    open_pin(directory, name).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            invalid_object()
        } else {
            error
        }
    })
}

fn verify_metadata(fd: &OwnedFd, namespace: [u8; 16], mode: super::BindingMode) -> io::Result<()> {
    let metadata = read_array::<64>(fd)?;
    let mut expected = [0u8; 64];
    expected[..4].copy_from_slice(&4u32.to_ne_bytes());
    expected[4..8].copy_from_slice(&mode.code().to_ne_bytes());
    expected[8..24].copy_from_slice(&namespace);
    expected[24..56].copy_from_slice(&Sha256::digest(mode.image()));
    if metadata != expected {
        return Err(invalid_object());
    }
    Ok(())
}

fn read_resources(directory: &File, expected: ExpectedInventory) -> io::Result<ResourceSet> {
    verify_resource_names(directory, &expected)?;
    let mut resources = ResourceSet {
        handles: BTreeMap::new(),
        info: BTreeMap::new(),
    };
    read_maps(directory, &expected, &mut resources)?;
    let program_ids = read_programs(directory, &expected, &mut resources)?;
    let links: usize = expected
        .programs
        .iter()
        .map(|program| program.root_links)
        .sum();
    read_links(directory, links, &program_ids, &mut resources)?;
    Ok(resources)
}

fn read_maps(
    directory: &File,
    expected: &ExpectedInventory,
    resources: &mut ResourceSet,
) -> io::Result<()> {
    for map in &expected.maps {
        let name = qualified(c"maps", &map.name);
        let info = resources.open(directory, name)?;
        if info.map_shape() != map.shape {
            return Err(invalid_object());
        }
    }
    Ok(())
}

fn read_links(
    directory: &File,
    links: usize,
    program_ids: &BTreeSet<u32>,
    resources: &mut ResourceSet,
) -> io::Result<()> {
    for index in 0..links {
        let name = CString::new(format!("links/root_{index:02}")).unwrap();
        let info = resources.open(directory, name)?;
        if ![2, 3, 10].contains(&info.words[0]) || !program_ids.contains(&info.words[2]) {
            return Err(invalid_object());
        }
    }
    Ok(())
}

fn read_programs(
    directory: &File,
    expected: &ExpectedInventory,
    resources: &mut ResourceSet,
) -> io::Result<BTreeSet<u32>> {
    let mut ids = BTreeSet::new();
    for program in &expected.programs {
        let info = resources.open(directory, qualified(c"programs", &program.name))?;
        if info.words[0] != program.kind {
            return Err(invalid_object());
        }
        ids.insert(info.words[1]);
    }
    Ok(ids)
}

impl ResourceSet {
    fn open(&mut self, directory: &File, name: CString) -> io::Result<&ObjectInfo> {
        let descriptor = completed_pin(directory, &name)?;
        let info = ObjectInfo::read(&descriptor)?;
        self.handles.insert(name.clone(), descriptor);
        self.info.insert(name.clone(), info);
        self.info.get(&name).ok_or_else(invalid_object)
    }
}

fn verify_resource_names(directory: &File, expected: &ExpectedInventory) -> io::Result<()> {
    let maps = open_directory_at(directory, c"maps")?;
    require_names(
        &maps,
        &expected
            .maps
            .iter()
            .map(|map| map.name.to_bytes().to_vec())
            .collect(),
    )?;
    let programs = open_directory_at(directory, c"programs")?;
    require_names(
        &programs,
        &expected
            .programs
            .iter()
            .map(|program| program.name.to_bytes().to_vec())
            .collect(),
    )?;
    let links = open_directory_at(directory, c"links")?;
    let count: usize = expected
        .programs
        .iter()
        .map(|program| program.root_links)
        .sum();
    require_names(
        &links,
        &(0..count)
            .map(|index| format!("root_{index:02}").into_bytes())
            .collect(),
    )
}

fn qualified(group: &CStr, name: &CStr) -> CString {
    CString::new([group.to_bytes(), b"/", name.to_bytes()].concat()).unwrap()
}

fn names<const N: usize>(values: [&str; N]) -> BTreeSet<Vec<u8>> {
    values
        .into_iter()
        .map(|value| value.as_bytes().to_vec())
        .collect()
}

fn require_names(directory: &File, expected: &BTreeSet<Vec<u8>>) -> io::Result<()> {
    let entries = std::fs::read_dir(format!("/proc/thread-self/fd/{}", directory.as_raw_fd()))?;
    let actual = entries
        .map(|entry| entry.map(|entry| entry.file_name().as_bytes().to_vec()))
        .collect::<io::Result<BTreeSet<_>>>()?;
    if &actual != expected {
        return Err(invalid_object());
    }
    Ok(())
}

pub(super) fn require_claim_names<'a>(
    directory: &File,
    claims: impl Iterator<Item = &'a String>,
) -> io::Result<()> {
    let mut groups: BTreeMap<&str, BTreeSet<Vec<u8>>> = ["maps", "programs", "links"]
        .into_iter()
        .map(|group| (group, BTreeSet::new()))
        .collect();
    let mut root = names(["maps", "programs", "links"]);
    for name in claims {
        if let Some((group, entry)) = name.split_once('/') {
            if entry.contains('/') {
                return Err(invalid_object());
            }
            groups
                .get_mut(group)
                .ok_or_else(invalid_object)?
                .insert(entry.as_bytes().to_vec());
        } else {
            root.insert(name.as_bytes().to_vec());
        }
    }
    require_names(directory, &root)?;
    for (group, expected) in groups {
        require_names(
            &open_directory_at(directory, &CString::new(group).unwrap())?,
            &expected,
        )?;
    }
    Ok(())
}
