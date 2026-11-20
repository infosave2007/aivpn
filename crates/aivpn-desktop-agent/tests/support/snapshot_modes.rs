use super::lab;
use aivpn_desktop_agent::{linux::kernel::KernelWriter, state::StateDirectory};
use std::{
    collections::BTreeMap,
    ffi::c_void,
    fs, io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::DirBuilderExt,
    },
    path::{Path, PathBuf},
};
unsafe extern "C" {
    fn bpf_obj_get_info_by_fd(fd: i32, info: *mut c_void, length: *mut u32) -> i32;
    fn btf__new_empty() -> *mut c_void;
    fn btf__add_int(btf: *mut c_void, name: *const i8, bytes: usize, encoding: i32) -> i32;
    fn btf__add_struct(btf: *mut c_void, name: *const i8, bytes: u32) -> i32;
    fn btf__load_into_kernel(btf: *mut c_void) -> i32;
    fn btf__fd(btf: *const c_void) -> i32;
    fn btf__resolve_size(btf: *const c_void, type_id: u32) -> i64;
    fn btf__free(btf: *mut c_void);
}
const OLD_CAPTURE_MAPS: [(&str, u32, u32, u32); 2] =
    [("processes", 29, 4, 0), ("routing_subjects", 1, 8, 65536)];
struct FixtureBtf {
    pointer: *mut c_void,
    key: i32,
    wide_key: i32,
    value: i32,
}
impl FixtureBtf {
    fn new() -> Self {
        let pointer = unsafe { btf__new_empty() };
        assert!(!pointer.is_null());
        let mut btf = Self {
            pointer,
            key: 0,
            wide_key: 0,
            value: 0,
        };
        btf.key = unsafe { btf__add_int(pointer, c"int".as_ptr(), 4, 1) };
        btf.wide_key = unsafe { btf__add_int(pointer, c"unsigned long long".as_ptr(), 8, 0) };
        btf.value = unsafe { btf__add_struct(pointer, c"old_capture".as_ptr(), 2120) };
        assert!(btf.key > 0 && btf.wide_key > 0 && btf.value > 0);
        btf
    }
    fn key_type(&self, bytes: u32) -> u32 {
        match bytes {
            4 => self.key as u32,
            8 => self.wide_key as u32,
            _ => panic!("Неизвестный размер ключа старого capture"),
        }
    }
}
impl Drop for FixtureBtf {
    fn drop(&mut self) {
        unsafe { btf__free(self.pointer) };
    }
}
#[test]
fn old_capture_btf_matches_map_key_and_value_sizes_without_kernel_load() {
    let btf = FixtureBtf::new();
    for (_, _, key, _) in OLD_CAPTURE_MAPS {
        let key_type = btf.key_type(key);
        assert!(key_type > 0 && btf.value > 0);
        assert_eq!(
            unsafe { btf__resolve_size(btf.pointer, key_type) },
            i64::from(key)
        );
        assert_eq!(
            unsafe { btf__resolve_size(btf.pointer, btf.value as u32) },
            2120
        );
    }
}
fn files(root: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            result.extend(files(&path));
        } else {
            result.push(path);
        }
    }
    result.sort();
    result
}
fn identities(root: &Path) -> BTreeMap<PathBuf, u32> {
    files(root)
        .into_iter()
        .map(|path| {
            let fd = lab::open(&path);
            let mut info = [0u32; 64];
            let mut length = std::mem::size_of_val(&info) as u32;
            assert_eq!(
                unsafe {
                    bpf_obj_get_info_by_fd(fd.as_raw_fd(), info.as_mut_ptr().cast(), &mut length)
                },
                0
            );
            (path, info[1])
        })
        .collect()
}
fn state(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    files(root)
        .into_iter()
        .map(|path| {
            let bytes = fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect()
}
fn open(namespace: [u8; 16], root: &Path, snapshot: bool) -> io::Result<KernelWriter> {
    let store = StateDirectory::open(root)?;
    if snapshot {
        KernelWriter::open_existing_snapshot(namespace, store)
    } else {
        KernelWriter::open_existing(namespace, store)
    }
}
fn refusal(namespace: [u8; 16], root: &Path, snapshot: bool, label: &str) {
    let error = match open(namespace, root, snapshot) {
        Ok(_) => panic!("Принят чужой режим: {label}"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{label}: {error}");
    assert_eq!(
        error.to_string(),
        "Объекты ядра не соответствуют службе маршрутизации"
    );
    println!(
        "MODE_REFUSAL {label} kind={:?} reason={error}",
        error.kind()
    );
}
fn fake_metadata(bytes: &[u8; 64]) -> OwnedFd {
    let raw =
        unsafe { lab::bpf_map_create(2, c"mode_fixture".as_ptr(), 4, 64, 1, std::ptr::null()) };
    assert!(raw >= 0);
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let zero = 0u32;
    assert_eq!(
        unsafe {
            lab::bpf_map_update_elem(raw, (&zero as *const u32).cast(), bytes.as_ptr().cast(), 0)
        },
        0
    );
    assert_eq!(unsafe { lab::bpf_map_freeze(raw) }, 0);
    fd
}
fn check_metadata(namespace: [u8; 16], root: &Path, pins: &Path, snapshot: bool) {
    let path = pins.join("metadata");
    let original = lab::open(&path);
    let mut bytes = [0u8; 64];
    let zero = 0u32;
    assert_eq!(
        unsafe {
            lab::bpf_map_lookup_elem(
                original.as_raw_fd(),
                (&zero as *const u32).cast(),
                bytes.as_mut_ptr().cast(),
            )
        },
        0
    );
    let before = identities(pins);
    let saved = state(root);
    for (offset, value, label) in [
        (0, 2u32, "v2-refused-by-v3"),
        (4, u32::from(!snapshot), "wrong-v3-mode"),
        (
            24,
            u32::from_ne_bytes(bytes[24..28].try_into().unwrap()).wrapping_add(1),
            "old-image-digest",
        ),
    ] {
        let mut changed = bytes;
        changed[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        fs::remove_file(&path).unwrap();
        let replacement = fake_metadata(&changed);
        lab::pin(&replacement, &path);
        let expected = identities(pins);
        refusal(namespace, root, snapshot, label);
        assert_eq!(identities(pins), expected);
        assert_eq!(state(root), saved);
        fs::remove_file(&path).unwrap();
        lab::pin(&original, &path);
        drop(open(namespace, root, snapshot).unwrap());
        assert_eq!(identities(pins), before);
        assert_eq!(state(root), saved);
    }
}

fn check_old_capture_layout(namespace: [u8; 16], root: &Path, pins: &Path, snapshot: bool) {
    #[repr(C)]
    struct Options {
        size: usize,
        btf_and_inner: [u32; 5],
        flags: u32,
    }
    let btf = FixtureBtf::new();
    assert_eq!(unsafe { btf__load_into_kernel(btf.pointer) }, 0);
    let mut options = Options {
        size: std::mem::size_of::<Options>(),
        btf_and_inner: [
            unsafe { btf__fd(btf.pointer) } as u32,
            btf.key_type(4),
            btf.value as u32,
            0,
            0,
        ],
        flags: 1,
    };
    let saved = state(root);
    for (name, kind, key, capacity) in OLD_CAPTURE_MAPS {
        let path = pins.join("maps").join(name);
        let original = lab::open(&path);
        options.btf_and_inner[1] = btf.key_type(key);
        let raw = unsafe {
            lab::bpf_map_create(
                kind,
                c"old_capture".as_ptr(),
                key,
                2120,
                capacity,
                (&options as *const Options).cast(),
            )
        };
        assert!(raw >= 0);
        let replacement = unsafe { OwnedFd::from_raw_fd(raw) };
        fs::remove_file(&path).unwrap();
        lab::pin(&replacement, &path);
        let expected = identities(pins);
        refusal(namespace, root, snapshot, name);
        assert_eq!(identities(pins), expected);
        assert_eq!(state(root), saved);
        fs::remove_file(&path).unwrap();
        lab::pin(&original, &path);
        drop(open(namespace, root, snapshot).unwrap());
    }
}
pub fn run() {
    super::snapshot_fixture::require_guest();
    for snapshot in [false, true] {
        let byte = if snapshot { 0x7c } else { 0x7b };
        let namespace = [byte; 16];
        let root = PathBuf::from(format!("/lab/mode-{byte}"));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let pins = PathBuf::from(format!(
            "/sys/fs/bpf/aivpn_app_routes/{}",
            format!("{byte:02x}").repeat(16)
        ));
        let store = StateDirectory::open(&root).unwrap();
        let mut writer = if snapshot {
            KernelWriter::install_new_snapshot(namespace, store)
        } else {
            KernelWriter::install_new(namespace, store)
        }
        .unwrap();
        let (catalog, registry, authority) = lab::inputs(Path::new("/usr/bin/true"), namespace);
        let plan = writer.prepare(&registry, &catalog, &authority).unwrap();
        let slots = plan.bindings().executables.clone();
        drop(writer); // Важно: отрицательный результат не может быть отказом state-directory lock.
        let saved = state(&root);
        let ids = identities(&pins);
        refusal(namespace, &root, !snapshot, "opposite-open-api");
        assert_eq!(state(&root), saved);
        assert_eq!(identities(&pins), ids);
        check_metadata(namespace, &root, &pins, snapshot);
        check_old_capture_layout(namespace, &root, &pins, snapshot);
        let mut restored = open(namespace, &root, snapshot).unwrap();
        assert_eq!(
            restored
                .prepare(&registry, &catalog, &authority)
                .unwrap()
                .bindings()
                .executables,
            slots
        );
        drop(restored);
        assert_eq!(state(&root), saved);
        assert_eq!(identities(&pins), ids);
        println!(
            "MODE_PRESERVED {}",
            serde_json::json!({"snapshot":snapshot,"pin_ids":ids.iter().map(|(p,id)|(p.to_string_lossy(),id)).collect::<Vec<_>>(),"slot_files":saved.len(),"slots":slots.len()})
        );
        fs::remove_dir_all(&pins).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }
    println!("MODE_CLEANED");
}
