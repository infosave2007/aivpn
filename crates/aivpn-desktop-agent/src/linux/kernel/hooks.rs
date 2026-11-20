//! Установка общих hooks до публикации политик. Ошибка откатывает только новые links.

use super::image::{BpfProgram, LoadedKernel};
use std::collections::BTreeSet;
use std::ffi::{c_int, c_long, c_void, CStr};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::ptr::NonNull;

#[repr(C)]
struct BpfLink {
    _private: [u8; 0],
}

// ABI проверен по bpf/libbpf.h. Поддерживаемые desktop-архитектуры имеют size_t 64 bit.
#[repr(C)]
struct NetfilterOptions {
    size: usize,
    family: u32,
    hook: u32,
    priority: i32,
    flags: u32,
}

unsafe extern "C" {
    fn libbpf_get_error(pointer: *const c_void) -> c_long;
    fn bpf_program__attach_lsm(program: *const BpfProgram) -> *mut BpfLink;
    fn bpf_program__attach_trace(program: *const BpfProgram) -> *mut BpfLink;
    fn bpf_program__attach_cgroup(program: *const BpfProgram, descriptor: c_int) -> *mut BpfLink;
    fn bpf_program__attach_netfilter(
        program: *const BpfProgram,
        options: *const NetfilterOptions,
    ) -> *mut BpfLink;
    fn bpf_link__destroy(link: *mut BpfLink) -> c_int;
    fn bpf_link__fd(link: *const BpfLink) -> c_int;
}

struct Link(NonNull<BpfLink>);

#[derive(Default)]
struct Links(Vec<Link>);

impl Links {
    fn push(&mut self, link: Link) {
        self.0.push(link);
    }
}

impl Drop for Links {
    fn drop(&mut self) {
        // Сначала снимаются потребители состояния, затем создающие его hooks.
        while let Some(link) = self.0.pop() {
            drop(link);
        }
    }
}

/// Общие hooks установлены, но политики, интерфейсы и маршруты еще не опубликованы.
/// До закрепления всей защиты drop снимает только эти новые hooks.
pub struct UnpublishedKernel {
    links: Links,
    _programs: LoadedKernel,
}

const LSM: &[&CStr] = &[
    c"prepare_socket",
    c"inherit_process",
    c"capture_exec_begin",
    c"classify_exec",
    c"prepare_connect",
    c"record_udp_reuse",
    c"route_clone",
    c"route_request",
    c"route_mptcp_prepare_listener",
    c"route_mptcp_epoch",
    c"route_before_send",
];
const TRACING: &[&CStr] = &[
    c"observe_owner",
    c"route_free",
    c"route_request_free",
    c"forget_connection",
    c"route_mptcp_listen",
    c"route_mptcp_listen_done",
];
const CGROUP: &[&CStr] = &[
    c"route_socket",
    c"route_connect4",
    c"route_connect6",
    c"route_send4",
    c"route_send6",
    c"guard_output",
    c"record_incoming_datagram",
];

enum HookKind {
    Lsm,
    Tracing,
    Cgroup,
}

impl LoadedKernel {
    pub fn attach_root_hooks(self) -> io::Result<UnpublishedKernel> {
        self.attach_with_pins(None)
    }

    pub(super) fn attach_pinned_root_hooks(
        self,
        pins: &mut super::pins::PinTransaction,
    ) -> io::Result<UnpublishedKernel> {
        self.pin_resources(pins)?;
        self.attach_with_pins(Some(pins))
    }

    fn attach_with_pins(
        self,
        mut pins: Option<&mut super::pins::PinTransaction>,
    ) -> io::Result<UnpublishedKernel> {
        verify_hook_coverage(&self)?;
        let cgroup = system_cgroup()?;
        let mut links = Links::default();
        for (names, kind) in [
            (LSM, HookKind::Lsm),
            (TRACING, HookKind::Tracing),
            (CGROUP, HookKind::Cgroup),
        ] {
            attach_programs(&self, names, kind, &cgroup, &mut links, &mut pins)?;
        }
        if self.uses_snapshot() {
            attach_programs(
                &self,
                &[c"prepare_packet_dispatch"],
                HookKind::Tracing,
                &cgroup,
                &mut links,
                &mut pins,
            )?;
        }
        attach_network_guards(&self, &mut links, &mut pins)?;
        Ok(UnpublishedKernel {
            links,
            _programs: self,
        })
    }
}

fn verify_hook_coverage(programs: &LoadedKernel) -> io::Result<()> {
    let names = programs.root_program_names()?;
    let actual: BTreeSet<&CStr> = names.iter().map(|name| name.as_c_str()).collect();
    let mut expected: BTreeSet<&CStr> = LSM
        .iter()
        .chain(TRACING)
        .chain(CGROUP)
        .copied()
        .chain([
            c"guard_profile_input",
            c"guard_profile_forward",
            c"guard_marked_output",
            c"guard_final_output",
        ])
        .collect();
    if programs.uses_snapshot() {
        expected.extend([c"prepare_packet_dispatch", c"ensure_local_dispatch"]);
    }
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Набор системных hooks не соответствует образу",
        ));
    }
    Ok(())
}

fn attach_programs(
    programs: &LoadedKernel,
    names: &[&CStr],
    kind: HookKind,
    cgroup: &File,
    links: &mut Links,
    pins: &mut Option<&mut super::pins::PinTransaction>,
) -> io::Result<()> {
    for name in names {
        let program = programs.program(name)?;
        let link = unsafe {
            match kind {
                HookKind::Lsm => bpf_program__attach_lsm(program.as_ptr()),
                HookKind::Tracing => bpf_program__attach_trace(program.as_ptr()),
                HookKind::Cgroup => {
                    bpf_program__attach_cgroup(program.as_ptr(), cgroup.as_raw_fd())
                }
            }
        };
        retain_link(links, Link::new(link)?, pins)?;
    }
    Ok(())
}

fn attach_network_guards(
    programs: &LoadedKernel,
    links: &mut Links,
    pins: &mut Option<&mut super::pins::PinTransaction>,
) -> io::Result<()> {
    let mut guards = vec![
        (c"guard_profile_input", 0, -150),
        (c"guard_profile_forward", 2, -150),
        (c"guard_marked_output", 4, i32::MAX - 2),
        (c"guard_final_output", 4, i32::MAX - 1),
    ];
    if programs.uses_snapshot() {
        // NF_IP_PRI_FILTER=0; anchor только гарантирует вызов dispatcher.
        guards.push((c"ensure_local_dispatch", 3, 0));
    }
    for (name, hook, priority) in guards {
        let program = programs.program(name)?;
        for family in [libc::AF_INET, libc::AF_INET6] {
            let options = NetfilterOptions {
                size: std::mem::size_of::<NetfilterOptions>(),
                family: family as u32,
                hook,
                priority,
                flags: 0,
            };
            retain_link(
                links,
                Link::new(unsafe { bpf_program__attach_netfilter(program.as_ptr(), &options) })?,
                pins,
            )?;
        }
    }
    Ok(())
}

impl UnpublishedKernel {
    pub fn link_count(&self) -> usize {
        self.links.0.len()
    }
}

fn retain_link(
    links: &mut Links,
    link: Link,
    pins: &mut Option<&mut super::pins::PinTransaction>,
) -> io::Result<()> {
    if let Some(pins) = pins.as_mut() {
        // Производитель закрепляется до установки следующего потребителя.
        // SIGKILL между attach и pin не оставит потребителя без его состояния.
        let name = std::ffi::CString::new(format!("root_{:02}", links.0.len())).unwrap();
        let descriptor = unsafe { bpf_link__fd(link.0.as_ptr()) };
        if descriptor < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "У hook нет дескриптора",
            ));
        }
        pins.pin(c"links", &name, descriptor)?;
    }
    links.push(link);
    Ok(())
}

impl Link {
    fn new(raw: *mut BpfLink) -> io::Result<Self> {
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let error = unsafe { libbpf_get_error(raw.cast()) };
        if error != 0 {
            return Err(io::Error::from_raw_os_error((-error) as i32));
        }
        Ok(Self(NonNull::new(raw).expect("Проверен ненулевой link")))
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        unsafe { bpf_link__destroy(self.0.as_ptr()) };
    }
}

pub(super) fn system_cgroup() -> io::Result<File> {
    require_system_namespaces()?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/sys/fs/cgroup")?;
    verify_root_mount(&directory)?;
    Ok(directory)
}

pub(super) fn require_system_namespaces() -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    // Linux proc_ns.h (6.12) и nsfs.h: PID_NS_INIT_INO. Локальный PID1
    // контейнера не является подтверждением namespace всей машины.
    if fs::metadata("/proc/thread-self/ns/pid")?.ino() != 0xefff_fffc {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Нужен исходный PID namespace",
        ));
    }
    for namespace in ["net", "cgroup", "user"] {
        let current = fs::metadata(format!("/proc/thread-self/ns/{namespace}"))?;
        let system = fs::metadata(format!("/proc/1/ns/{namespace}"))?;
        if (current.dev(), current.ino()) != (system.dev(), system.ino()) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Нужен системный namespace",
            ));
        }
    }
    Ok(())
}

fn verify_root_mount(directory: &File) -> io::Result<()> {
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(directory.as_raw_fd(), &mut filesystem) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if filesystem.f_type != libc::CGROUP2_SUPER_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Нужен корень cgroup v2",
        ));
    }
    let mut status: libc::statx = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::statx(
            directory.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_MNT_ID,
            &mut status,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mounts = fs::read_to_string("/proc/thread-self/mountinfo")?;
    if status.stx_mask & libc::STATX_MNT_ID == 0 || !is_root_mount(&mounts, status.stx_mnt_id) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Вместо корня cgroup открыт подкаталог",
        ));
    }
    Ok(())
}

fn is_root_mount(mounts: &str, id: u64) -> bool {
    mounts.lines().any(|line| {
        let Some((mount, filesystem)) = line.split_once(" - ") else {
            return false;
        };
        let mut fields = mount.split_ascii_whitespace();
        fields.next().and_then(|value| value.parse::<u64>().ok()) == Some(id)
            && fields.nth(2) == Some("/")
            && fields.next() == Some("/sys/fs/cgroup")
            && filesystem.split_ascii_whitespace().next() == Some("cgroup2")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cgroup_subtree_or_different_mount_cannot_stand_for_the_system_root() {
        let mounts = "10 1 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n11 1 0:1 /user.slice /other rw - cgroup2 cgroup rw\n12 1 0:2 / /fake rw - tmpfs tmpfs rw\n13 1 0:1 / /sys/fs rw - cgroup2 cgroup rw\n";
        assert!(is_root_mount(mounts, 10));
        for id in [11, 12, 13, 14] {
            assert!(!is_root_mount(mounts, id));
        }
        assert!(!is_root_mount("10 broken", 10));
    }
}
