use aivpn_desktop_agent::linux::kernel::KernelWriter;
use aivpn_desktop_agent::linux::{ExecutableFile, LocatedExecutable, MountSnapshot};
use aivpn_desktop_agent::state::StateDirectory;
use aivpn_desktop_policy::*;
use std::ffi::{c_char, c_void, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

pub const NS: [u8; 16] = [0x71; 16];
pub const ROOT: &str = "/lab/retention-test";
pub const TARGET: &str = "/usr/bin/retention-target";
pub const ALIAS: &str = "/usr/bin/retention-alias";
pub const CONTROL: &str = "/usr/bin/retention-control";

pub fn require_lab() {
    assert!(std::fs::read_to_string("/proc/cmdline")
        .unwrap()
        .split_ascii_whitespace()
        .any(|w| w == "aivpn.app-routing-lab=1"));
    assert_eq!(
        std::fs::read_to_string("/lab/.app-routing-guest").unwrap(),
        "aivpn-offline-routing-lab\n"
    );
}
pub fn setup() {
    require_lab();
    std::fs::DirBuilder::new().mode(0o700).create(ROOT).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(format!("{ROOT}/state"))
        .unwrap();
    for path in [TARGET, CONTROL] {
        std::fs::copy("/usr/bin/true", path).unwrap();
    }
    std::fs::hard_link(TARGET, ALIAS).unwrap();
}
pub fn writer(new: bool) -> KernelWriter {
    let state = StateDirectory::open(Path::new(&format!("{ROOT}/state"))).unwrap();
    if new {
        KernelWriter::install_new(NS, state).unwrap()
    } else {
        KernelWriter::open_existing(NS, state).unwrap()
    }
}
pub fn locate(path: &Path) -> LocatedExecutable {
    MountSnapshot::read_current()
        .unwrap()
        .locate(ExecutableFile::open(path).unwrap())
        .unwrap()
}
pub fn static_pins() -> PathBuf {
    Path::new("/sys/fs/bpf/aivpn_app_routes").join("71".repeat(16))
}
pub fn dynamic_pins() -> PathBuf {
    Path::new("/sys/fs/bpf/aivpn_app_retainers").join("71".repeat(16))
}
pub fn fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}
pub fn evict() {
    unsafe {
        libc::sync();
    }
    std::fs::write("/proc/sys/vm/drop_caches", "3").unwrap();
}
pub struct Cleanup;
impl Drop for Cleanup {
    fn drop(&mut self) {
        for p in [dynamic_pins(), static_pins()] {
            if p.exists() {
                std::fs::remove_dir_all(p).unwrap();
            }
        }
        for p in [TARGET, ALIAS, CONTROL] {
            let _ = std::fs::remove_file(p);
        }
        let _ = std::fs::remove_dir_all(ROOT);
    }
}
unsafe extern "C" {
    pub fn bpf_obj_get(path: *const c_char) -> i32;
    pub fn bpf_obj_pin(fd: i32, path: *const c_char) -> i32;
    pub fn bpf_map_create(
        kind: u32,
        name: *const c_char,
        key: u32,
        value: u32,
        capacity: u32,
        options: *const c_void,
    ) -> i32;
    pub fn bpf_map_lookup_elem(fd: i32, key: *const c_void, value: *mut c_void) -> i32;
    pub fn bpf_map_update_elem(
        fd: i32,
        key: *const c_void,
        value: *const c_void,
        flags: u64,
    ) -> i32;
    pub fn bpf_map_freeze(fd: i32) -> i32;
}
pub fn open(path: &Path) -> OwnedFd {
    let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let raw = unsafe { bpf_obj_get(path.as_ptr()) };
    assert!(raw >= 0, "open BPF {path:?}: {raw}");
    unsafe { OwnedFd::from_raw_fd(raw) }
}
pub fn cookie(path: &str) -> Option<u64> {
    let file = std::fs::File::open(path).unwrap();
    let fd = file.as_raw_fd();
    let map = open(&static_pins().join("maps/inode_tokens"));
    let mut cookie = 0u64;
    let result = unsafe {
        bpf_map_lookup_elem(
            map.as_raw_fd(),
            (&fd as *const i32).cast(),
            (&mut cookie as *mut u64).cast(),
        )
    };
    if result == 0 {
        assert_ne!(cookie, 0);
        Some(cookie)
    } else {
        assert_eq!(result, -libc::ENOENT);
        None
    }
}
pub fn execute(path: &str) {
    assert!(std::process::Command::new(path).status().unwrap().success());
}
pub fn pin(fd: &OwnedFd, path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let c = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { bpf_obj_pin(fd.as_raw_fd(), c.as_ptr()) }, 0);
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
pub fn bytes(fd: &OwnedFd) -> [u8; 128] {
    let mut bytes = [0u8; 128];
    let zero = 0u32;
    assert_eq!(
        unsafe {
            bpf_map_lookup_elem(
                fd.as_raw_fd(),
                (&zero as *const u32).cast(),
                bytes.as_mut_ptr().cast(),
            )
        },
        0
    );
    bytes
}
pub fn replace_record(path: &Path, bytes: &[u8; 128], freeze: bool) {
    let raw = unsafe { bpf_map_create(2, c"fault_record".as_ptr(), 4, 128, 1, std::ptr::null()) };
    assert!(raw >= 0);
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let zero = 0u32;
    assert_eq!(
        unsafe {
            bpf_map_update_elem(
                fd.as_raw_fd(),
                (&zero as *const u32).cast(),
                bytes.as_ptr().cast(),
                0,
            )
        },
        0
    );
    if freeze {
        assert_eq!(unsafe { bpf_map_freeze(fd.as_raw_fd()) }, 0);
    }
    std::fs::remove_file(path).unwrap();
    pin(&fd, path);
}
pub fn inputs(path: &Path, namespace: [u8; 16]) -> (ProfileCatalog, PolicyRegistry, Authority) {
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

pub fn file_counter() -> u64 {
    let map = open(&static_pins().join("maps/file_counter"));
    let zero = 0u32;
    let mut value = 0u64;
    assert_eq!(
        unsafe {
            bpf_map_lookup_elem(
                map.as_raw_fd(),
                (&zero as *const u32).cast(),
                (&mut value as *mut u64).cast(),
            )
        },
        0
    );
    value
}
