//! Владение libbpf-объектом. Здесь нет установки правил или изменения сети.

use super::invalid_object as invalid_schema;
use std::ffi::{c_char, c_int, c_long, c_uint, c_void, CStr, CString};
use std::io;
use std::ptr::NonNull;

#[repr(C)]
struct BpfObject {
    _private: [u8; 0],
}
#[repr(C)]
struct BpfMap {
    _private: [u8; 0],
}
#[repr(C)]
pub(super) struct BpfProgram {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn bpf_object__open_mem(
        image: *const c_void,
        length: usize,
        options: *const c_void,
    ) -> *mut BpfObject;
    fn libbpf_get_error(pointer: *const c_void) -> c_long;
    fn bpf_object__close(object: *mut BpfObject);
    fn bpf_object__load(object: *mut BpfObject) -> c_int;
    fn bpf_object__find_map_by_name(object: *const BpfObject, name: *const c_char) -> *mut BpfMap;
    fn bpf_map__inner_map(map: *mut BpfMap) -> *mut BpfMap;
    fn bpf_map__type(map: *const BpfMap) -> c_uint;
    fn bpf_map__key_size(map: *const BpfMap) -> c_uint;
    fn bpf_map__value_size(map: *const BpfMap) -> c_uint;
    fn bpf_map__max_entries(map: *const BpfMap) -> c_uint;
    fn bpf_map__map_flags(map: *const BpfMap) -> c_uint;
    fn bpf_map__fd(map: *const BpfMap) -> c_int;
    fn bpf_object__next_map(object: *const BpfObject, previous: *const BpfMap) -> *mut BpfMap;
    fn bpf_map__name(map: *const BpfMap) -> *const c_char;
    fn bpf_map__is_internal(map: *const BpfMap) -> bool;
    fn bpf_map_update_elem(
        descriptor: c_int,
        key: *const c_void,
        value: *const c_void,
        flags: u64,
    ) -> c_int;
    fn bpf_object__find_program_by_name(
        object: *const BpfObject,
        name: *const c_char,
    ) -> *mut BpfProgram;
    fn bpf_program__set_autoload(program: *mut BpfProgram, enabled: bool) -> c_int;
    fn bpf_object__next_program(
        object: *const BpfObject,
        previous: *mut BpfProgram,
    ) -> *mut BpfProgram;
    fn bpf_program__section_name(program: *const BpfProgram) -> *const c_char;
    fn bpf_program__name(program: *const BpfProgram) -> *const c_char;
    fn bpf_program__fd(program: *const BpfProgram) -> c_int;
    fn bpf_program__type(program: *const BpfProgram) -> c_uint;
    fn bpf_map__reuse_fd(map: *mut BpfMap, fd: c_int) -> c_int;
    fn bpf_map__set_initial_value(map: *mut BpfMap, data: *const c_void, size: usize) -> c_int;
}

/// Незагруженный встроенный образ. Объектом владеет один писатель.
pub struct KernelImage {
    object: NonNull<BpfObject>,
    snapshot: bool,
}

/// Загрузка программ еще не означает, что защита установлена или профиль готов.
pub struct LoadedKernel {
    image: KernelImage,
}

pub(super) struct ExpectedMap {
    pub name: CString,
    pub shape: [u32; 5],
}

pub(super) struct ExpectedProgram {
    pub name: CString,
    pub kind: u32,
    pub root_links: usize,
}

pub(super) struct ExpectedInventory {
    pub maps: Vec<ExpectedMap>,
    pub programs: Vec<ExpectedProgram>,
}

struct MapSchema {
    name: &'static CStr,
    kind: u32,
    key: u32,
    value: u32,
    capacity: u32,
}

const SCHEMA: &[MapSchema] = &[
    MapSchema {
        name: c"path_key",
        kind: 2,
        key: 4,
        value: 16,
        capacity: 1,
    },
    MapSchema {
        name: c"applications",
        kind: 1,
        key: 24,
        value: 4,
        capacity: 16384,
    },
    MapSchema {
        name: c"file_bindings",
        kind: 1,
        key: 8,
        value: 4,
        capacity: 4096,
    },
    MapSchema {
        name: c"policies",
        kind: 1,
        key: 8,
        value: 14376,
        capacity: 256,
    },
    MapSchema {
        name: c"profiles",
        kind: 1,
        key: 4,
        value: 64,
        capacity: 256,
    },
    MapSchema {
        name: c"interface_profiles",
        kind: 1,
        key: 16,
        value: 4,
        capacity: 256,
    },
    MapSchema {
        name: c"mark_profiles",
        kind: 1,
        key: 16,
        value: 4,
        capacity: 512,
    },
    MapSchema {
        name: c"profile_zones",
        kind: 1,
        key: 4,
        value: 4,
        capacity: 256,
    },
];

// Полный creator состоит из двух согласованных частей, каждая помещается в local storage.
const CAPTURE_SCHEMA: &[(&CStr, [u32; 5])] = &[
    (c"dns_epochs", [1, 4, 16, 1, 0]),
    (c"dns_sockets", [1, 8, 72, 512, 0]),
    (c"dns_guard", [1, 4, 16, 1, 0]),
    (c"dns_listeners", [1, 40, 16, 8, 0]),
    (c"dns_listener_fds", [1, 8, 40, 8, 0]),
    (c"transport_sockets", [1, 8, 72, 256, 0]),
    (c"transport_leases", [1, 4, 16, 256, 0]),
    (c"processes", [29, 4, 5952, 0, 1]),
    (c"process_companions", [29, 4, 5136, 0, 1]),
    (c"socket_states", [24, 4, 5968, 0, 513]),
    (c"socket_companions", [24, 4, 5136, 0, 513]),
    (c"mptcp_listeners", [29, 4, 5832, 0, 1]),
    (c"mptcp_companions", [29, 4, 5136, 0, 1]),
    (c"routing_subjects", [1, 8, 5808, 65536, 1]),
    (c"routing_companions", [1, 8, 5136, 65536, 1]),
    (c"route_work", [6, 4, 6176, 4, 0]),
];

// Layout следует routing.h и включенным BPF типам; старые pins не переинициализируются.
const ADMISSION_SCHEMA: &[(&CStr, [u32; 5])] = &[
    (c"routing_overrides", [1, 40, 200, 65536, 1]),
    (c"routing_system", [9, 40, 200, 65536, 0]),
    (c"tcp_routes", [1, 64, 112, 65536, 1]),
    (c"connection_routes", [1, 8, 160, 65536, 1]),
];

impl KernelImage {
    pub(super) fn load_profile_match(
        self,
        slot: u32,
        mut map_fd: impl FnMut(&CStr) -> io::Result<c_int>,
    ) -> io::Result<LoadedKernel> {
        if slot == 0 {
            return Err(invalid_schema());
        }
        let mut program = std::ptr::null_mut();
        loop {
            program = unsafe { bpf_object__next_program(self.object.as_ptr(), program) };
            if program.is_null() {
                break;
            }
            let name = unsafe { CStr::from_ptr(bpf_program__name(program)) };
            result(unsafe { bpf_program__set_autoload(program, name == c"match_profile") })?;
        }
        let mut map = std::ptr::null_mut();
        loop {
            map = unsafe { bpf_object__next_map(self.object.as_ptr(), map) };
            if map.is_null() {
                break;
            }
            let name = unsafe { CStr::from_ptr(bpf_map__name(map)) };
            if unsafe { bpf_map__is_internal(map) } {
                if name.to_bytes().ends_with(b".rodata.profile") {
                    if unsafe { bpf_map__value_size(map) } != 4 {
                        return Err(invalid_schema());
                    }
                    result(unsafe {
                        bpf_map__set_initial_value(map, (&slot as *const u32).cast(), 4)
                    })?;
                }
            } else {
                result(unsafe { bpf_map__reuse_fd(map, map_fd(name)?) })?;
            }
        }
        result(unsafe { bpf_object__load(self.object.as_ptr()) })?;
        // Core maps уже инициализированы. Повторная запись path_key недопустима.
        Ok(LoadedKernel { image: self })
    }
    pub(super) fn expected_inventory(&self) -> io::Result<ExpectedInventory> {
        Ok(ExpectedInventory {
            maps: self.expected_maps()?,
            programs: self.expected_programs()?,
        })
    }

    fn expected_maps(&self) -> io::Result<Vec<ExpectedMap>> {
        let mut maps = Vec::new();
        let mut map = std::ptr::null_mut();
        loop {
            map = unsafe { bpf_object__next_map(self.object.as_ptr(), map) };
            if map.is_null() {
                return Ok(maps);
            }
            if unsafe { bpf_map__is_internal(map) } {
                continue;
            }
            let name = unsafe { bpf_map__name(map) };
            if name.is_null() {
                return Err(invalid_schema());
            }
            let shape = unsafe {
                [
                    bpf_map__type(map),
                    bpf_map__key_size(map),
                    bpf_map__value_size(map),
                    bpf_map__max_entries(map),
                    bpf_map__map_flags(map),
                ]
            };
            maps.push(ExpectedMap {
                name: unsafe { CStr::from_ptr(name) }.to_owned(),
                shape,
            });
        }
    }

    fn expected_programs(&self) -> io::Result<Vec<ExpectedProgram>> {
        let mut programs = Vec::new();
        let mut program = std::ptr::null_mut();
        loop {
            program = unsafe { bpf_object__next_program(self.object.as_ptr(), program) };
            if program.is_null() {
                return Ok(programs);
            }
            let name = unsafe { bpf_program__name(program) };
            let section = unsafe { bpf_program__section_name(program) };
            if name.is_null() || section.is_null() {
                return Err(invalid_schema());
            }
            let name = unsafe { CStr::from_ptr(name) };
            if name == c"match_profile" {
                continue;
            }
            let section = unsafe { CStr::from_ptr(section) };
            let root_links = if section == c"netfilter" {
                2
            } else if [c"socket", c"uprobe.multi", c"tcx/ingress"].contains(&section) {
                0
            } else {
                1
            };
            programs.push(ExpectedProgram {
                name: name.to_owned(),
                kind: unsafe { bpf_program__type(program) },
                root_links,
            });
        }
    }

    /// Проверяет образ без привилегий и без создания программ в ядре.
    pub fn open() -> io::Result<Self> {
        Self::open_mode(super::BindingMode::Legacy)
    }

    pub(super) fn open_mode(mode: super::BindingMode) -> io::Result<Self> {
        Self::open_bytes(mode.image(), mode == super::BindingMode::Snapshot)
    }

    /// Открывает только образ Snapshot. До загрузки корня consumer безопасно отказывает.
    pub fn open_snapshot() -> io::Result<Self> {
        Self::open_mode(super::BindingMode::Snapshot)
    }

    fn open_bytes(bytes: &'static [u8], snapshot: bool) -> io::Result<Self> {
        // libbpf может читать образ до закрытия объекта; байты живут весь процесс.
        let raw =
            unsafe { bpf_object__open_mem(bytes.as_ptr().cast(), bytes.len(), std::ptr::null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let error = unsafe { libbpf_get_error(raw.cast()) };
        if error != 0 {
            return Err(io::Error::from_raw_os_error((-error) as i32));
        }
        let image = Self {
            object: NonNull::new(raw).expect("Проверен ненулевой объект"),
            snapshot,
        };
        image.validate_schema()?;
        // Для профилей служба создает отдельные программы с собственным селектором.
        let selector = unsafe { bpf_object__find_program_by_name(raw, c"match_profile".as_ptr()) };
        if selector.is_null() {
            return Err(invalid_schema());
        }
        result(unsafe { bpf_program__set_autoload(selector, false) })?;
        Ok(image)
    }

    fn validate_schema(&self) -> io::Result<()> {
        self.validate_capture_schema()?;
        for expected in SCHEMA {
            let map = unsafe {
                bpf_object__find_map_by_name(self.object.as_ptr(), expected.name.as_ptr())
            };
            validate_map_schema(map, expected)?;
        }
        if self.snapshot {
            self.validate_snapshot_schema()?;
        }
        Ok(())
    }

    fn validate_capture_schema(&self) -> io::Result<()> {
        for (name, shape) in CAPTURE_SCHEMA.iter().chain(ADMISSION_SCHEMA) {
            let map = unsafe { bpf_object__find_map_by_name(self.object.as_ptr(), name.as_ptr()) };
            let mut expected = *shape;
            if self.snapshot {
                expected[2] = match name.to_bytes() {
                    b"processes" => 6224,
                    b"process_companions"
                    | b"socket_companions"
                    | b"mptcp_companions"
                    | b"routing_companions" => 5392,
                    b"socket_states" => 6232,
                    b"mptcp_listeners" => 6096,
                    b"routing_subjects" => 6072,
                    b"route_work" => 1104,
                    b"routing_overrides" | b"routing_system" => 184,
                    _ => expected[2],
                };
            }
            require_map_shape(map, expected)?;
        }
        let scratch =
            unsafe { bpf_object__find_map_by_name(self.object.as_ptr(), c"scratch".as_ptr()) };
        require_map_shape(
            scratch,
            [6, 4, if self.snapshot { 13248 } else { 8884 }, 4, 0],
        )
    }

    fn validate_snapshot_schema(&self) -> io::Result<()> {
        let lookups = unsafe {
            bpf_object__find_map_by_name(self.object.as_ptr(), c"lookup_captures".as_ptr())
        };
        require_map_shape(lookups, [29, 4, 4880, 0, 1])?;
        let proofs = unsafe {
            bpf_object__find_map_by_name(self.object.as_ptr(), c"source_proofs".as_ptr())
        };
        require_map_shape(proofs, [1, 8, 14440, 65536, 1])?;
        let prefixes = unsafe {
            bpf_object__find_map_by_name(self.object.as_ptr(), c"lookup_prefixes".as_ptr())
        };
        require_map_shape(prefixes, [1, 16, 80, 262144, 1])?;
        let files =
            unsafe { bpf_object__find_map_by_name(self.object.as_ptr(), c"lookup_files".as_ptr()) };
        require_map_shape(files, [1, 8, 8, 65536, 1])?;
        let filesystems = unsafe {
            bpf_object__find_map_by_name(self.object.as_ptr(), c"lookup_filesystems".as_ptr())
        };
        require_map_shape(filesystems, [1, 8, 56, 65536, 1])?;
        let lifetimes = unsafe {
            bpf_object__find_map_by_name(self.object.as_ptr(), c"lookup_lifetimes".as_ptr())
        };
        require_map_shape(lifetimes, [2, 4, 32, 1, 0])?;
        for name in [
            c"lookup_stage0a",
            c"lookup_stage0b",
            c"lookup_stage1a",
            c"lookup_stage1b",
            c"lookup_stage2a",
            c"lookup_stage2b",
            c"lookup_stage3a",
            c"lookup_stage3b",
        ] {
            let stage =
                unsafe { bpf_object__find_map_by_name(self.object.as_ptr(), name.as_ptr()) };
            require_map_shape(stage, [29, 4, 7168, 0, 1])?;
        }
        let root =
            unsafe { bpf_object__find_map_by_name(self.object.as_ptr(), c"binding_root".as_ptr()) };
        require_map_shape(root, [12, 4, 4, 1, 0])?;
        let inner = unsafe { bpf_map__inner_map(root) };
        require_map_shape(inner, [1, 40, 64, 401408, 129])?;
        for (name, shape) in [
            (c"request_routes", [1, 8, 128, 65536, 1]),
            (c"request_peers", [1, 40, 8, 65536, 1]),
            (c"admission_scratch", [6, 4, 248, 4, 0]),
            (c"early_scratch", [6, 4, 256, 1, 0]),
        ] {
            let map = unsafe { bpf_object__find_map_by_name(self.object.as_ptr(), name.as_ptr()) };
            require_map_shape(map, shape)?;
        }
        Ok(())
    }

    pub fn load(self) -> io::Result<LoadedKernel> {
        super::capabilities::require_path_sequence()?;
        if self.snapshot {
            super::capabilities::require_snapshot_admission()?;
        }
        result(unsafe { bpf_object__load(self.object.as_ptr()) })?;
        let programs = LoadedKernel { image: self };
        programs.initialize_path_key()?;
        Ok(programs)
    }
}

impl Drop for KernelImage {
    fn drop(&mut self) {
        unsafe { bpf_object__close(self.object.as_ptr()) };
    }
}

impl LoadedKernel {
    pub(super) fn duplicate_program(&self, name: &CStr) -> io::Result<std::os::fd::OwnedFd> {
        use std::os::fd::BorrowedFd;
        let program = self.program(name)?;
        let fd = unsafe { bpf_program__fd(program.as_ptr()) };
        if fd < 0 {
            return Err(invalid_schema());
        }
        unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned()
    }
    pub(super) fn uses_snapshot(&self) -> bool {
        self.image.snapshot
    }

    pub(super) fn pin_resources(&self, pins: &mut super::pins::PinTransaction) -> io::Result<()> {
        self.pin_maps(pins)?;
        self.pin_programs(pins)
    }

    fn pin_maps(&self, pins: &mut super::pins::PinTransaction) -> io::Result<()> {
        let mut map = std::ptr::null_mut();
        loop {
            map = unsafe { bpf_object__next_map(self.image.object.as_ptr(), map) };
            if map.is_null() {
                return Ok(());
            }
            if unsafe { bpf_map__is_internal(map) } {
                continue;
            }
            let name = unsafe { bpf_map__name(map) };
            if name.is_null() {
                return Err(invalid_schema());
            }
            let name = unsafe { CStr::from_ptr(name) };
            let descriptor = unsafe { bpf_map__fd(map) };
            if descriptor < 0 {
                return Err(invalid_schema());
            }
            pins.pin(c"maps", name, descriptor)?;
        }
    }

    fn pin_programs(&self, pins: &mut super::pins::PinTransaction) -> io::Result<()> {
        let mut program = std::ptr::null_mut();
        loop {
            program = unsafe { bpf_object__next_program(self.image.object.as_ptr(), program) };
            if program.is_null() {
                return Ok(());
            }
            let name = unsafe { bpf_program__name(program) };
            if name.is_null() {
                return Err(invalid_schema());
            }
            let name = unsafe { CStr::from_ptr(name) };
            if name == c"match_profile" {
                continue;
            }
            let descriptor = unsafe { bpf_program__fd(program) };
            if descriptor < 0 {
                return Err(invalid_schema());
            }
            pins.pin(c"programs", name, descriptor)?;
        }
    }

    pub(super) fn root_program_names(&self) -> io::Result<Vec<CString>> {
        let mut names = Vec::new();
        let mut program = std::ptr::null_mut();
        loop {
            program = unsafe { bpf_object__next_program(self.image.object.as_ptr(), program) };
            if program.is_null() {
                return Ok(names);
            }
            let section = unsafe { bpf_program__section_name(program) };
            let name = unsafe { bpf_program__name(program) };
            if section.is_null() || name.is_null() {
                return Err(invalid_schema());
            }
            let section = unsafe { CStr::from_ptr(section) };
            // У этих программ отдельные владельцы: selector, файл приложения и TUN.
            if ![c"socket", c"uprobe.multi", c"tcx/ingress"].contains(&section) {
                names.push(unsafe { CStr::from_ptr(name) }.to_owned());
            }
        }
    }

    fn initialize_path_key(&self) -> io::Result<()> {
        let mut key = [0u8; 16];
        let length = unsafe { libc::getrandom(key.as_mut_ptr().cast(), key.len(), 0) };
        if length < 0 {
            return Err(io::Error::last_os_error());
        }
        if length as usize != key.len() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        let map = unsafe {
            bpf_object__find_map_by_name(self.image.object.as_ptr(), c"path_key".as_ptr())
        };
        if map.is_null() {
            return Err(invalid_schema());
        }
        let descriptor = unsafe { bpf_map__fd(map) };
        if descriptor < 0 {
            return Err(invalid_schema());
        }
        let zero = 0u32;
        result(unsafe {
            bpf_map_update_elem(
                descriptor,
                (&zero as *const u32).cast(),
                key.as_ptr().cast(),
                0,
            )
        })
    }

    /// Проверка схемы не меняет карты и не подтверждает установку защиты.
    pub fn validate_schema(&self) -> io::Result<()> {
        self.image.validate_schema()
    }

    pub(super) fn program(&self, name: &CStr) -> io::Result<NonNull<BpfProgram>> {
        NonNull::new(unsafe {
            bpf_object__find_program_by_name(self.image.object.as_ptr(), name.as_ptr())
        })
        .ok_or_else(invalid_schema)
    }
}

fn require_map_shape(map: *mut BpfMap, expected: [u32; 5]) -> io::Result<()> {
    if map.is_null() {
        return Err(invalid_schema());
    }
    let actual = unsafe {
        [
            bpf_map__type(map),
            bpf_map__key_size(map),
            bpf_map__value_size(map),
            bpf_map__max_entries(map),
            bpf_map__map_flags(map),
        ]
    };
    if actual != expected {
        return Err(invalid_schema());
    }
    Ok(())
}

fn validate_map_schema(map: *mut BpfMap, expected: &MapSchema) -> io::Result<()> {
    if map.is_null() {
        return Err(invalid_schema());
    }
    let matches = unsafe {
        bpf_map__type(map) == expected.kind
            && bpf_map__key_size(map) == expected.key
            && bpf_map__value_size(map) == expected.value
            && bpf_map__max_entries(map) == expected.capacity
    };
    if matches {
        Ok(())
    } else {
        Err(invalid_schema())
    }
}

pub(super) fn result(status: c_int) -> io::Result<()> {
    if status < 0 {
        Err(io::Error::from_raw_os_error(-status))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" {
        fn bpf_map__set_max_entries(map: *mut BpfMap, capacity: c_uint) -> c_int;
        fn bpf_map__set_value_size(map: *mut BpfMap, size: c_uint) -> c_int;
    }

    #[test]
    fn rejects_non_object_input() {
        assert!(KernelImage::open_bytes(b"invalid object", false).is_err());
    }

    #[test]
    fn rejects_incompatible_map_schema_before_loading() {
        let image = KernelImage::open().unwrap();
        let map =
            unsafe { bpf_object__find_map_by_name(image.object.as_ptr(), c"profiles".as_ptr()) };
        assert!(!map.is_null());
        result(unsafe { bpf_map__set_max_entries(map, 255) }).unwrap();
        assert_eq!(
            image.validate_schema().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn rejects_previous_capture_layout_before_loading() {
        for (name, _) in CAPTURE_SCHEMA.iter().chain(ADMISSION_SCHEMA) {
            let image = KernelImage::open().unwrap();
            let map = unsafe { bpf_object__find_map_by_name(image.object.as_ptr(), name.as_ptr()) };
            let old_size = unsafe { bpf_map__value_size(map) } - 8;
            result(unsafe { bpf_map__set_value_size(map, old_size) }).unwrap();
            assert_eq!(
                image.validate_schema().unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}
