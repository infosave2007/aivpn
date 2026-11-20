#![cfg(all(target_os = "linux", feature = "linux-kernel"))]

use aivpn_desktop_agent::bindings::BindingPlan;
use aivpn_desktop_agent::linux::kernel::KernelWriter;
use aivpn_desktop_agent::linux::{ExecutableFile, LocatedExecutable, MountSnapshot};
use aivpn_desktop_agent::slots::{KernelSlotStore, KernelState};
use aivpn_desktop_agent::state::StateDirectory;
use aivpn_desktop_policy::*;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

#[path = "support/kernel_slot_store.rs"]
mod storage;

const NAMESPACE: [u8; 16] = [0x3e; 16];

#[test]
#[ignore = "Нужен изолированный root-стенд с bpffs и BPF LSM"]
fn prepared_executable_requires_current_file_slot_and_kernel_instance() {
    assert!(std::fs::read_to_string("/proc/cmdline")
        .unwrap()
        .split_ascii_whitespace()
        .any(|word| word == "aivpn.app-routing-lab=1"));
    assert_eq!(
        std::fs::read_to_string("/lab/.app-routing-guest").unwrap(),
        "aivpn-offline-routing-lab\n"
    );
    let directory = Path::new("/lab/prepared-executable");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(directory)
        .unwrap();
    let _files = OwnFiles(directory.into());
    let state = directory.join("state");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)
        .unwrap();
    let path = directory.join("application");
    let other = directory.join("other");
    std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
    std::fs::copy(&path, &other).unwrap();
    let (catalog, mut registry, authority) = inputs(&path, NAMESPACE);
    let mut writer =
        KernelWriter::install_new(NAMESPACE, StateDirectory::open(&state).unwrap()).unwrap();
    let pins = Path::new("/sys/fs/bpf/aivpn_app_routes").join("3e".repeat(16));
    let cleanup = OwnPins(pins.clone());
    let plan = writer.prepare(&registry, &catalog, &authority).unwrap();
    let name = path.to_str().unwrap();
    let prepared = writer
        .prepare_executable(&plan, name, locate(&path))
        .unwrap();
    prepared.verify(&writer, &plan).unwrap();
    assert!(writer
        .prepare_executable(&plan, name, locate(&other))
        .is_err());
    assert!(writer
        .prepare_executable(&plan, other.to_str().unwrap(), locate(&other))
        .is_err());

    let (foreign_catalog, foreign_registry, _) = inputs(&path, [0x3f; 16]);
    let mut slots =
        KernelSlotStore::open(storage::Store::default(), [0x3f; 16], KernelState::Fresh).unwrap();
    let foreign =
        BindingPlan::prepare(&foreign_registry, &foreign_catalog, &authority, &mut slots).unwrap();
    assert!(writer
        .prepare_executable(&foreign, name, locate(&path))
        .is_err());
    assert!(prepared.verify(&writer, &foreign).is_err());
    assert_eq!(
        foreign.bindings().executables[name],
        plan.bindings().executables[name]
    );
    change_key_seed(&pins, || assert!(prepared.verify(&writer, &plan).is_err()));
    prepared.verify(&writer, &plan).unwrap();

    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        let denied = prepared
            .verify(&writer, &plan)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied);
        unsafe { libc::_exit(if denied { 0 } else { 1 }) };
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert_eq!(status, 0);

    drop(writer);
    writer = KernelWriter::open_existing(NAMESPACE, StateDirectory::open(&state).unwrap()).unwrap();
    prepared.verify(&writer, &plan).unwrap();
    let owner = Owner::LinuxUser { uid: 1000 };
    let mut document = registry.get(&owner).unwrap().document().clone();
    document.generation = 2;
    document.rules.clear();
    let change = registry.prepare(document, &authority, Some(1)).unwrap();
    registry.commit(change).unwrap();
    let removed = writer.prepare(&registry, &catalog, &authority).unwrap();
    assert!(writer
        .prepare_executable(&plan, name, locate(&path))
        .is_err());
    assert!(prepared.verify(&writer, &plan).is_err());
    assert!(prepared.verify(&writer, &removed).is_err());
    let (_, replacement_registry, _) = inputs(&path, NAMESPACE);
    let replacement_plan = writer
        .prepare(&replacement_registry, &catalog, &authority)
        .unwrap();
    assert_ne!(
        replacement_plan.bindings().executables[name],
        plan.bindings().executables[name]
    );
    assert!(prepared.verify(&writer, &replacement_plan).is_err());
    let current = writer
        .prepare_executable(&replacement_plan, name, locate(&path))
        .unwrap();
    current.verify(&writer, &replacement_plan).unwrap();
    let replacement = directory.join("replacement");
    std::fs::copy(&other, &replacement).unwrap();
    std::fs::rename(replacement, &path).unwrap();
    assert!(current.verify(&writer, &replacement_plan).is_err());
    let latest = writer
        .prepare_executable(&replacement_plan, name, locate(&path))
        .unwrap();
    drop(writer);
    drop(cleanup);
    std::fs::remove_dir_all(&state).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)
        .unwrap();
    let mut writer =
        KernelWriter::install_new(NAMESPACE, StateDirectory::open(&state).unwrap()).unwrap();
    let _cleanup = OwnPins(pins);
    let fresh_plan = writer
        .prepare(&replacement_registry, &catalog, &authority)
        .unwrap();
    assert_eq!(
        fresh_plan.bindings().executables,
        plan.bindings().executables
    );
    assert!(latest.verify(&writer, &fresh_plan).is_err());
    let fresh = writer
        .prepare_executable(&fresh_plan, name, locate(&path))
        .unwrap();
    fresh.verify(&writer, &fresh_plan).unwrap();
}

fn locate(path: &Path) -> LocatedExecutable {
    MountSnapshot::read_current()
        .unwrap()
        .locate(ExecutableFile::open(path).unwrap())
        .unwrap()
}

fn inputs(path: &Path, namespace: [u8; 16]) -> (ProfileCatalog, PolicyRegistry, Authority) {
    let authority = Authority {
        user: Owner::LinuxUser { uid: 0 },
        machine_admin: true,
    };
    let mut catalog = ProfileCatalog::new(Platform::Linux, namespace);
    let profile = catalog
        .register(&authority, Owner::LinuxUser { uid: 1000 }, vec![])
        .unwrap();
    catalog.set_global_dns(&profile, &authority).unwrap();
    let mut registry = PolicyRegistry::new(Platform::Linux);
    let document = PolicyDocument {
        split_enabled: true,
        version: 1,
        id: "prepared-executable".into(),
        generation: 1,
        platform: Platform::Linux,
        owner: Owner::LinuxUser { uid: 1000 },
        default_action: Action::System {},
        dns: DnsPolicy::SharedVpn {
            profile,
            acknowledge_outage: true,
        },
        rules: vec![RuleDocument {
            id: "selected".into(),
            application: Selector::Executable {
                path: path.to_str().unwrap().into(),
            },
            destination: None,
            inherit_children: true,
            action: Action::Block {},
        }],
    };
    let change = registry.prepare(document, &authority, None).unwrap();
    registry.commit(change).unwrap();
    (catalog, registry, authority)
}

struct OwnFiles(PathBuf);
impl Drop for OwnFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct OwnPins(PathBuf);
impl Drop for OwnPins {
    fn drop(&mut self) {
        for group in ["links", "programs", "maps"] {
            let path = self.0.join(group);
            if let Ok(entries) = std::fs::read_dir(&path) {
                for entry in entries {
                    let _ = std::fs::remove_file(entry.unwrap().path());
                }
            }
            let _ = std::fs::remove_dir(path);
        }
        let _ = std::fs::remove_file(self.0.join("metadata"));
        let _ = std::fs::remove_file(self.0.join("inventory"));
        let _ = std::fs::remove_dir(&self.0);
    }
}

fn change_key_seed(pins: &Path, check: impl FnOnce()) {
    use std::ffi::{c_char, c_int, c_void, CString};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    unsafe extern "C" {
        fn bpf_obj_get(path: *const c_char) -> c_int;
        fn bpf_map_lookup_elem(fd: c_int, key: *const c_void, value: *mut c_void) -> c_int;
        fn bpf_map_update_elem(
            fd: c_int,
            key: *const c_void,
            value: *const c_void,
            flags: u64,
        ) -> c_int;
    }
    struct Restore(OwnedFd, [u8; 16]);
    impl Drop for Restore {
        fn drop(&mut self) {
            let zero = 0u32;
            assert_eq!(
                unsafe {
                    bpf_map_update_elem(
                        self.0.as_raw_fd(),
                        (&zero as *const u32).cast(),
                        self.1.as_ptr().cast(),
                        0,
                    )
                },
                0
            );
        }
    }
    let name = CString::new(pins.join("maps/path_key").as_os_str().as_bytes()).unwrap();
    let raw = unsafe { bpf_obj_get(name.as_ptr()) };
    assert!(raw >= 0);
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let zero = 0u32;
    let mut seed = [0; 16];
    assert_eq!(
        unsafe {
            bpf_map_lookup_elem(
                fd.as_raw_fd(),
                (&zero as *const u32).cast(),
                seed.as_mut_ptr().cast(),
            )
        },
        0
    );
    let restore = Restore(fd, seed);
    seed[0] ^= 1;
    assert_eq!(
        unsafe {
            bpf_map_update_elem(
                restore.0.as_raw_fd(),
                (&zero as *const u32).cast(),
                seed.as_ptr().cast(),
                0,
            )
        },
        0
    );
    check();
}
