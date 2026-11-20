#![cfg(all(target_os = "linux", feature = "linux-kernel"))]

use aivpn_desktop_agent::linux::kernel::{embedded_programs, PinnedKernel, RecoveredKernel};
use sha2::{Digest, Sha256};
use std::ffi::{c_char, c_int, c_void, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

#[test]
#[ignore = "Меняет kptr_restrict только в изолированной VM"]
fn hidden_kernel_symbol_cannot_confirm_a_new_guard_instance() {
    require_native_guest();
    struct Restore(String);
    impl Drop for Restore {
        fn drop(&mut self) {
            std::fs::write("/proc/sys/kernel/kptr_restrict", &self.0).unwrap();
        }
    }
    let restore = Restore(std::fs::read_to_string("/proc/sys/kernel/kptr_restrict").unwrap());
    std::fs::write("/proc/sys/kernel/kptr_restrict", b"2").unwrap();
    let path = PathBuf::from("/sys/fs/bpf/aivpn_app_routes").join("3d".repeat(16));
    let _cleanup = OwnPins(path.clone());
    let error = PinnedKernel::install_new([0x3d; 16])
        .err()
        .expect("Нулевой адрес символа не подтверждает проверку путей");
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    assert!(
        !path.exists(),
        "Отказ capability probe не оставляет начальную установку"
    );
    drop(restore);
    drop(PinnedKernel::install_new([0x3d; 16]).unwrap());
}

#[test]
#[ignore = "Нужен изолированный стенд с bpffs и BPF LSM"]
fn new_writer_cannot_initialize_counter_for_existing_kernel() {
    require_native_guest();
    use aivpn_desktop_agent::linux::kernel::KernelWriter;
    use aivpn_desktop_agent::state::{StateDirectory, StateFile};
    use std::os::unix::fs::DirBuilderExt;
    let state = Path::new("/lab/kernel-writer-existing-state");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(state)
        .unwrap();
    let _pinned = PinnedKernel::install_new([0x3c; 16]).unwrap();
    let path = PathBuf::from("/sys/fs/bpf/aivpn_app_routes").join("3c".repeat(16));
    let _cleanup = OwnPins(path.clone());
    let link = identity(&path.join("links/root_00"));
    assert!(KernelWriter::install_new([0x3c; 16], StateDirectory::open(state).unwrap()).is_err());
    let store = StateDirectory::open(state).unwrap();
    assert!(
        store.load(StateFile::Committed).unwrap().is_none(),
        "Отказ новой установки не должен создавать счетчик для прежнего ядра"
    );
    assert!(KernelWriter::open_existing([0x3c; 16], store).is_err());
    assert_eq!(identity(&path.join("links/root_00")), link);
    std::fs::remove_dir_all(state).unwrap();
}

#[test]
#[ignore = "Нужен изолированный стенд с bpffs и BPF LSM"]
fn durable_writer_installs_compiled_policy_and_recovers_without_reset() {
    require_native_guest();
    use aivpn_desktop_agent::linux::kernel::KernelWriter;
    use aivpn_desktop_agent::state::StateDirectory;
    use aivpn_desktop_policy::*;
    use std::os::unix::fs::DirBuilderExt;
    let state = Path::new("/lab/kernel-writer-state");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(state)
        .unwrap();
    let (mut catalog, mut registry, authority) = writer_inputs(Action::Block {});
    let mut writer =
        KernelWriter::install_new([0x3b; 16], StateDirectory::open(state).unwrap()).unwrap();
    let path = PathBuf::from("/sys/fs/bpf/aivpn_app_routes").join("3b".repeat(16));
    let _cleanup = OwnPins(path.clone());
    assert!(StateDirectory::open(state).is_err());
    let plan = writer.prepare(&registry, &catalog, &authority).unwrap();
    let bindings = plan.bindings().profiles.clone();
    user_probe(false);
    writer.write_policy(&plan.policies()[0]).unwrap();
    user_probe(true);
    for (generation, action, blocked) in
        [(2, Action::System {}, false), (3, Action::Block {}, true)]
    {
        let mut doc = registry
            .get(&Owner::LinuxUser { uid: 1000 })
            .unwrap()
            .document()
            .clone();
        doc.generation = generation;
        doc.default_action = action;
        let prepared = registry
            .prepare(doc, &authority, Some(generation - 1))
            .unwrap();
        registry.commit(prepared).unwrap();
        let update = writer.prepare(&registry, &catalog, &authority).unwrap();
        writer.write_policy(&update.policies()[0]).unwrap();
        user_probe(blocked);
    }
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        let refused = writer
            .withdraw_policy(&Owner::LinuxUser { uid: 1000 })
            .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied);
        unsafe { libc::_exit(if refused { 0 } else { 1 }) };
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert_eq!(status, 0, "Копия писателя после fork не должна менять ядро");
    user_probe(true);
    let link = identity(&path.join("links/root_00"));
    drop(writer);
    user_probe(true);
    for fault in ["write-error", "sync-directory"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "writer_state_fault_child",
                "--test-threads=1",
                "--nocapture",
            ])
            .env("LD_PRELOAD", "/lab/kernel-state-faults.so")
            .env("AIVPN_STATE_FAULT", fault)
            .output()
            .unwrap();
        assert!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "{fault}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        user_probe(true);
    }
    let mut writer =
        KernelWriter::open_existing([0x3b; 16], StateDirectory::open(state).unwrap()).unwrap();
    assert_eq!(
        writer
            .prepare(&registry, &catalog, &authority)
            .unwrap()
            .bindings()
            .profiles,
        bindings
    );
    assert_eq!(identity(&path.join("links/root_00")), link);
    user_probe(true);
    assert!(writer
        .withdraw_policy(&Owner::WindowsUser {
            sid: "S-1-5-21-1000".into()
        })
        .is_err());
    user_probe(true);
    writer
        .withdraw_policy(&Owner::LinuxUser { uid: 1000 })
        .unwrap();
    writer
        .withdraw_policy(&Owner::LinuxUser { uid: 1000 })
        .unwrap();
    user_probe(false);
    probe_machine_policy(&mut writer, &mut catalog, &authority);
    drop(writer);
    std::fs::remove_dir_all(state).unwrap();
}

#[test]
#[ignore = "Дочерний процесс проверки отказа хранилища писателя"]
fn writer_state_fault_child() {
    require_native_guest();
    assert!(std::env::var_os("AIVPN_STATE_FAULT").is_some());
    use aivpn_desktop_agent::linux::kernel::KernelWriter;
    use aivpn_desktop_agent::state::StateDirectory;
    use aivpn_desktop_policy::*;
    let (catalog, mut registry, authority) = writer_inputs(Action::System {});
    let mut writer = KernelWriter::open_existing(
        [0x3b; 16],
        StateDirectory::open(Path::new("/lab/kernel-writer-state")).unwrap(),
    )
    .unwrap();
    let old = writer.prepare(&registry, &catalog, &authority).unwrap();
    let mut doc = registry
        .get(&Owner::LinuxUser { uid: 1000 })
        .unwrap()
        .document()
        .clone();
    doc.generation = 2;
    doc.rules.push(RuleDocument {
        id: "new-app".into(),
        application: Selector::Executable {
            path: "/usr/bin/new-app".into(),
        },
        destination: None,
        inherit_children: true,
        action: Action::Block {},
    });
    let prepared = registry.prepare(doc, &authority, Some(1)).unwrap();
    registry.commit(prepared).unwrap();
    std::env::set_var("AIVPN_STATE_ARMED", "1");
    assert!(writer.prepare(&registry, &catalog, &authority).is_err());
    std::env::remove_var("AIVPN_STATE_ARMED");
    assert!(writer.write_policy(&old.policies()[0]).is_err());
    assert!(writer
        .withdraw_policy(&Owner::LinuxUser { uid: 1000 })
        .is_err());
    assert!(writer.prepare(&registry, &catalog, &authority).is_err());
}

fn writer_inputs(
    action: aivpn_desktop_policy::Action,
) -> (
    aivpn_desktop_policy::ProfileCatalog,
    aivpn_desktop_policy::PolicyRegistry,
    aivpn_desktop_policy::Authority,
) {
    use aivpn_desktop_policy::*;
    let authority = Authority {
        user: Owner::LinuxUser { uid: 0 },
        machine_admin: true,
    };
    let mut catalog = ProfileCatalog::new(Platform::Linux, [0x3b; 16]);
    let profile = catalog
        .register(&authority, Owner::LinuxUser { uid: 1000 }, vec![])
        .unwrap();
    catalog.set_global_dns(&profile, &authority).unwrap();
    let mut registry = PolicyRegistry::new(Platform::Linux);
    let doc = PolicyDocument {
        split_enabled: true,
        version: 1,
        id: "writer".into(),
        generation: 1,
        platform: Platform::Linux,
        owner: Owner::LinuxUser { uid: 1000 },
        default_action: action,
        dns: DnsPolicy::SharedVpn {
            profile,
            acknowledge_outage: true,
        },
        rules: vec![],
    };
    let prepared = registry.prepare(doc, &authority, None).unwrap();
    registry.commit(prepared).unwrap();
    (catalog, registry, authority)
}

fn probe_machine_policy(
    writer: &mut aivpn_desktop_agent::linux::kernel::KernelWriter,
    catalog: &mut aivpn_desktop_policy::ProfileCatalog,
    authority: &aivpn_desktop_policy::Authority,
) {
    use aivpn_desktop_policy::*;
    let profile = catalog
        .register(authority, Owner::Machine {}, vec![])
        .unwrap();
    catalog.set_global_dns(&profile, authority).unwrap();
    let machine = PolicyDocument {
        split_enabled: true,
        version: 1,
        id: "machine".into(),
        generation: 1,
        platform: Platform::Linux,
        owner: Owner::Machine {},
        default_action: Action::Block {},
        dns: DnsPolicy::SharedVpn {
            profile,
            acknowledge_outage: true,
        },
        rules: vec![],
    };
    let mut registry = PolicyRegistry::new(Platform::Linux);
    let prepared = registry.prepare(machine, authority, None).unwrap();
    registry.commit(prepared).unwrap();
    let plan = writer.prepare(&registry, catalog, authority).unwrap();
    writer.write_policy(&plan.policies()[0]).unwrap();
    user_probe(true);
    for address in ["127.0.0.1:9", "[::1]:9"] {
        let socket = std::net::UdpSocket::bind(if address.starts_with('[') {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        })
        .unwrap();
        assert_eq!(
            socket.send_to(b"machine", address).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
    writer.withdraw_policy(&Owner::Machine {}).unwrap();
    user_probe(false);
}

unsafe extern "C" {
    fn bpf_obj_get(path: *const c_char) -> c_int;
    fn bpf_obj_get_info_by_fd(fd: c_int, info: *mut c_void, size: *mut u32) -> c_int;
    fn bpf_map_lookup_elem(fd: c_int, key: *const c_void, value: *mut c_void) -> c_int;
    fn bpf_map_update_elem(
        fd: c_int,
        key: *const c_void,
        value: *const c_void,
        flags: u64,
    ) -> c_int;
    fn bpf_map_delete_elem(fd: c_int, key: *const c_void) -> c_int;
    fn bpf_map_create(
        kind: u32,
        name: *const c_char,
        key: u32,
        value: u32,
        capacity: u32,
        options: *const c_void,
    ) -> c_int;
    fn bpf_obj_pin(fd: c_int, path: *const c_char) -> c_int;
    fn bpf_map_freeze(fd: c_int) -> c_int;
    fn bpf_prog_load(
        kind: u32,
        name: *const c_char,
        license: *const c_char,
        instructions: *const ProbeInstruction,
        count: usize,
        options: *const c_void,
    ) -> c_int;
    fn bpf_link_update(link: c_int, program: c_int, options: *const c_void) -> c_int;
}

#[repr(C)]
struct ProbeInstruction {
    code: u8,
    registers: u8,
    offset: i16,
    value: i32,
}

fn probe_program(kind: u32) -> OwnedFd {
    let instructions = [
        ProbeInstruction {
            code: 0xb7,
            registers: 0,
            offset: 0,
            value: 1,
        },
        ProbeInstruction {
            code: 0x95,
            registers: 0,
            offset: 0,
            value: 0,
        },
    ];
    let descriptor = unsafe {
        bpf_prog_load(
            kind,
            c"recovery_probe".as_ptr(),
            c"GPL".as_ptr(),
            instructions.as_ptr(),
            instructions.len(),
            std::ptr::null(),
        )
    };
    assert!(descriptor >= 0, "{}", std::io::Error::last_os_error());
    unsafe { OwnedFd::from_raw_fd(descriptor) }
}

#[test]
#[ignore = "Нужен изолированный стенд с bpffs и BPF LSM"]
fn recovery_refuses_replaced_programs_and_updated_links() {
    require_native_guest();
    let _pinned = PinnedKernel::install_new([0x3a; 16]).unwrap();
    let path = PathBuf::from("/sys/fs/bpf/aivpn_app_routes").join("3a".repeat(16));
    let _cleanup = OwnPins(path.clone());
    let program = path.join("programs/match_vpn");
    let original = open_pin(&program);
    let replacement = probe_program(1);
    std::fs::remove_file(&program).unwrap();
    pin_test_object(&replacement, &program);
    assert_eq!(
        recovery_refusal([0x3a; 16]).kind(),
        std::io::ErrorKind::InvalidData
    );
    std::fs::remove_file(&program).unwrap();
    pin_test_object(&original, &program);
    drop(RecoveredKernel::open_existing([0x3a; 16]).unwrap());

    let ingress = path.join("programs/record_incoming_datagram");
    let id = identity(&ingress);
    let link = std::fs::read_dir(path.join("links"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|name| kernel_info(name)[1] as u32 == id)
        .unwrap();
    let original = open_pin(&ingress);
    let link_fd = open_pin(&link);
    let link_id = identity(&link);
    let replacement = probe_program(8);
    assert_eq!(
        unsafe {
            bpf_link_update(
                link_fd.as_raw_fd(),
                replacement.as_raw_fd(),
                std::ptr::null(),
            )
        },
        0
    );
    assert_eq!(identity(&link), link_id);
    assert_eq!(
        recovery_refusal([0x3a; 16]).kind(),
        std::io::ErrorKind::InvalidData
    );
    assert_eq!(
        unsafe { bpf_link_update(link_fd.as_raw_fd(), original.as_raw_fd(), std::ptr::null()) },
        0
    );
    drop(RecoveredKernel::open_existing([0x3a; 16]).unwrap());
}

#[test]
#[ignore = "Нужен изолированный стенд с bpffs и BPF LSM"]
fn a_private_submount_cannot_redirect_the_host_pins() {
    require_native_guest();
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::fs::PermissionsExt;
    let base = Path::new("/sys/fs/bpf/aivpn_app_routes");
    match std::fs::DirBuilder::new().mode(0o700).create(base) {
        Ok(()) => {}
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists),
    }
    let path = base.join("39".repeat(16));
    assert!(!path.exists());
    let _cleanup = OwnPins(path.clone());
    std::thread::spawn(|| {
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
        assert_eq!(
            unsafe {
                libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                libc::mount(
                    c"bpf".as_ptr(),
                    c"/sys/fs/bpf/aivpn_app_routes".as_ptr(),
                    c"bpf".as_ptr(),
                    0,
                    c"mode=0700".as_ptr().cast(),
                )
            },
            0
        );
        std::fs::set_permissions(
            "/sys/fs/bpf/aivpn_app_routes",
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let _pinned = PinnedKernel::install_new([0x39; 16]).unwrap();
        let host = Path::new("/proc/1/root/sys/fs/bpf/aivpn_app_routes").join("39".repeat(16));
        assert!(
            host.join("metadata").exists(),
            "Новый экземпляр должен закрепляться в основной системе"
        );
        drop(RecoveredKernel::open_existing([0x39; 16]).unwrap());
    })
    .join()
    .unwrap();
    assert!(path.join("metadata").exists());
}

#[test]
#[ignore = "Нужен изолированный стенд с bpffs и BPF LSM"]
fn recovery_rejects_a_different_map_with_the_same_shape() {
    require_native_guest();
    let _pinned = PinnedKernel::install_new([0x37; 16]).unwrap();
    let path = PathBuf::from("/sys/fs/bpf/aivpn_app_routes").join("37".repeat(16));
    let _cleanup = OwnPins(path.clone());
    let profile = path.join("maps/profiles");
    let old = open_pin(&profile);
    let original = identity(&profile);
    let link = identity(&path.join("links/root_00"));
    std::fs::remove_file(&profile).unwrap();
    let fake = new_map(1, 64, 256);
    pin_test_object(&fake, &profile);
    let replaced = identity(&profile);
    assert_ne!(replaced, original);
    let info = kernel_info(&profile);
    assert_eq!(
        [
            info[0] as u32,
            info[1] as u32,
            (info[1] >> 32) as u32,
            info[2] as u32
        ],
        [1, 4, 64, 256]
    );
    let error = recovery_refusal([0x37; 16]);
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(identity(&profile), replaced);
    assert_eq!(identity(&path.join("links/root_00")), link);
    std::fs::remove_file(&profile).unwrap();
    pin_test_object(&old, &profile);
    drop(RecoveredKernel::open_existing([0x37; 16]).unwrap());
}

#[test]
#[ignore = "Нужен изолированный стенд с bpffs и BPF LSM"]
fn recovery_checks_metadata_size_and_image_before_lookup_or_adoption() {
    require_native_guest();
    let _pinned = PinnedKernel::install_new([0x38; 16]).unwrap();
    let path = PathBuf::from("/sys/fs/bpf/aivpn_app_routes").join("38".repeat(16));
    let _cleanup = OwnPins(path.clone());
    let metadata = path.join("metadata");
    let old = open_pin(&metadata);
    let link = identity(&path.join("links/root_00"));
    for size in [4096, 64] {
        std::fs::remove_file(&metadata).unwrap();
        let fake = new_map(2, size, 1);
        let zero = 0u32;
        let mut value = vec![0u8; size as usize];
        if size == 64 {
            assert_eq!(
                unsafe {
                    bpf_map_lookup_elem(
                        old.as_raw_fd(),
                        (&zero as *const u32).cast(),
                        value.as_mut_ptr().cast(),
                    )
                },
                0
            );
            value[24] ^= 1;
        }
        assert_eq!(
            unsafe {
                bpf_map_update_elem(
                    fake.as_raw_fd(),
                    (&zero as *const u32).cast(),
                    value.as_ptr().cast(),
                    0,
                )
            },
            0
        );
        assert_eq!(unsafe { bpf_map_freeze(fake.as_raw_fd()) }, 0);
        pin_test_object(&fake, &metadata);
        let error = recovery_refusal([0x38; 16]);
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(identity(&path.join("links/root_00")), link);
    }
    std::fs::remove_file(&metadata).unwrap();
    pin_test_object(&old, &metadata);
    drop(RecoveredKernel::open_existing([0x38; 16]).unwrap());
}

fn new_map(kind: u32, value: u32, capacity: u32) -> OwnedFd {
    let descriptor = unsafe {
        bpf_map_create(
            kind,
            c"test_resource".as_ptr(),
            4,
            value,
            capacity,
            std::ptr::null(),
        )
    };
    assert!(descriptor >= 0);
    unsafe { OwnedFd::from_raw_fd(descriptor) }
}

fn pin_test_object(descriptor: &OwnedFd, path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(
        unsafe { bpf_obj_pin(descriptor.as_raw_fd(), name.as_ptr()) },
        0
    );
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
#[ignore = "Нужен изолированный стенд с bpffs и BPF LSM"]
fn a_killed_owner_keeps_enforcing_the_pinned_policy() {
    require_native_guest();
    user_probe(false);
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "pin_crash_child",
            "--test-threads=1",
            "--nocapture",
        ])
        .env("AIVPN_PIN_CRASH_CHILD", "1")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = ChildOwner(child);
    use std::io::BufRead;
    let mut reader = std::io::BufReader::new(child.0.stdout.take().unwrap());
    loop {
        let mut line = String::new();
        assert_ne!(
            reader.read_line(&mut line).unwrap(),
            0,
            "Владелец должен завершить установку"
        );
        if line.contains("PIN_CRASH_READY") {
            break;
        }
    }
    let path = PathBuf::from("/sys/fs/bpf/aivpn_app_routes").join("34".repeat(16));
    let _cleanup = OwnPins(path.clone());
    let before = identity(&path.join("links/root_00"));
    user_probe(true);
    child.0.kill().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(child.0.wait().unwrap().signal(), Some(libc::SIGKILL));
    let recovered = RecoveredKernel::open_existing([0x34; 16]).unwrap();
    assert_eq!(identity(&path.join("links/root_00")), before);
    user_probe(true);
    drop(recovered);
    user_probe(true);
    let policies = open_pin(&path.join("maps/policies"));
    let key = (1u64 << 32) | 1000;
    assert_eq!(
        unsafe { bpf_map_delete_elem(policies.as_raw_fd(), (&key as *const u64).cast()) },
        0
    );
    user_probe(false);
}

#[test]
#[ignore = "Нужен изолированный стенд с bpffs и BPF LSM"]
fn recovery_refuses_incomplete_inventory_without_changing_existing_guards() {
    require_native_guest();
    let _pinned = PinnedKernel::install_new([0x36; 16]).unwrap();
    let path = PathBuf::from("/sys/fs/bpf/aivpn_app_routes").join("36".repeat(16));
    let _cleanup = OwnPins(path.clone());
    let link = identity(&path.join("links/root_00"));
    std::fs::rename(path.join("maps/profiles"), path.join("maps/profiles_saved")).unwrap();
    let error = recovery_refusal([0x36; 16]);
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(path.join("maps/profiles_saved").exists());
    assert_eq!(identity(&path.join("links/root_00")), link);
    std::fs::rename(path.join("maps/profiles_saved"), path.join("maps/profiles")).unwrap();
    drop(RecoveredKernel::open_existing([0x36; 16]).unwrap());
    assert_eq!(identity(&path.join("links/root_00")), link);
}

#[test]
#[ignore = "Нужен изолированный стенд с bpffs и BPF LSM"]
fn killing_during_pin_prefix_does_not_break_system_sockets() {
    require_native_guest();
    use std::os::unix::process::ExitStatusExt;
    for cut in ["maps/path_key", "links/root_16", "links/root_27"] {
        let path = PathBuf::from("/sys/fs/bpf/aivpn_app_routes").join("35".repeat(16));
        let cleanup = OwnPins(path.clone());
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "pin_cut_child",
                "--test-threads=1",
                "--nocapture",
            ])
            .env("LD_PRELOAD", "/lab/kernel-pin-faults.so")
            .env("AIVPN_KERNEL_PIN_KILL", cut)
            .output()
            .unwrap();
        assert_eq!(
            output.status.signal(),
            Some(libc::SIGKILL),
            "{cut}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(path.exists());
        assert!(!path.join("metadata").exists());
        let error = recovery_refusal([0x35; 16]);
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(path.exists());
        user_probe(false);
        drop(cleanup);
        user_probe(false);
    }
}

#[test]
#[ignore = "Дочерний процесс проверки гибели посреди pinning"]
fn pin_cut_child() {
    require_native_guest();
    assert!(std::env::var_os("AIVPN_KERNEL_PIN_KILL").is_some());
    let _pinned = PinnedKernel::install_new([0x35; 16]).unwrap();
    panic!("Стенд должен завершить процесс до публикации metadata");
}

#[test]
#[ignore = "Дочерний процесс проверки SIGKILL"]
fn pin_crash_child() {
    require_native_guest();
    assert_eq!(std::env::var("AIVPN_PIN_CRASH_CHILD").as_deref(), Ok("1"));
    let _pinned = PinnedKernel::install_new([0x34; 16]).unwrap();
    let policy = blocking_policy();
    let policies = open_pin(
        &Path::new("/sys/fs/bpf/aivpn_app_routes")
            .join("34".repeat(16))
            .join("maps/policies"),
    );
    let key = (1u64 << 32) | 1000;
    assert_eq!(
        unsafe {
            bpf_map_update_elem(
                policies.as_raw_fd(),
                (&key as *const u64).cast(),
                policy.as_ptr().cast(),
                0,
            )
        },
        0
    );
    println!("PIN_CRASH_READY");
    use std::io::Write;
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::park();
    }
}

#[test]
#[ignore = "Дочерний процесс проверки пользовательского трафика"]
fn pin_user_probe_child() {
    require_native_guest();
    assert_eq!(unsafe { libc::geteuid() }, 1000);
    let blocked = std::env::var("AIVPN_PIN_USER_BLOCKED").unwrap() == "1";
    for address in ["127.0.0.1:9", "[::1]:9"] {
        let local = if address.starts_with('[') {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        };
        let socket = std::net::UdpSocket::bind(local).unwrap();
        let result = socket.send_to(b"pinned-policy", address);
        if blocked {
            assert_eq!(
                result.unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
        } else {
            assert_eq!(result.unwrap(), 13);
        }
    }
}

fn blocking_policy() -> Vec<u8> {
    use aivpn_desktop_policy::*;
    let authority = Authority {
        user: Owner::LinuxUser { uid: 1000 },
        machine_admin: false,
    };
    let mut catalog = ProfileCatalog::new(Platform::Linux, [0x34; 16]);
    let id = catalog
        .register(&authority, authority.user.clone(), vec![])
        .unwrap();
    catalog
        .set_global_dns(
            &id,
            &Authority {
                machine_admin: true,
                ..authority.clone()
            },
        )
        .unwrap();
    let policy = Policy::validate(
        PolicyDocument {
            split_enabled: true,
            version: 1,
            id: "crash-gate".into(),
            generation: 1,
            platform: Platform::Linux,
            owner: authority.user.clone(),
            default_action: Action::Block {},
            dns: DnsPolicy::SharedVpn {
                profile: id.clone(),
                acknowledge_outage: true,
            },
            rules: vec![],
        },
        &authority,
    )
    .unwrap();
    let mut bindings = KernelBindings::default();
    bindings
        .profiles
        .insert(id, std::num::NonZeroU32::new(1).unwrap());
    KernelPolicy::compile(&policy, &catalog, &authority, &bindings)
        .unwrap()
        .to_native_bytes()
}

fn user_probe(blocked: bool) {
    use std::os::unix::process::CommandExt;
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "pin_user_probe_child",
            "--test-threads=1",
            "--nocapture",
        ])
        .env("AIVPN_PIN_USER_BLOCKED", if blocked { "1" } else { "0" })
        .uid(1000)
        .gid(1000)
        .output()
        .unwrap();
    assert!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct ChildOwner(std::process::Child);
impl Drop for ChildOwner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "Нужен изолированный стенд с bpffs и BPF LSM"]
fn a_private_bpffs_cannot_claim_persistent_system_protection() {
    require_native_guest();
    std::thread::spawn(|| {
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
        assert_eq!(
            unsafe {
                libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                libc::mount(
                    c"bpf".as_ptr(),
                    c"/sys/fs/bpf".as_ptr(),
                    c"bpf".as_ptr(),
                    0,
                    c"mode=0700".as_ptr().cast(),
                )
            },
            0
        );
        let error = PinnedKernel::install_new([0x32; 16])
            .err()
            .expect("Временный bpffs не подтверждает сохранение защиты");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    })
    .join()
    .unwrap();
}

#[test]
#[ignore = "Нужен изолированный стенд с bpffs и BPF LSM"]
fn pin_failures_remove_only_the_new_instance_and_preserve_system_sockets() {
    require_native_guest();
    for needle in [
        "maps/path_key",
        "programs/prepare_socket",
        "links/root_00",
        "links/root_16",
        "metadata",
    ] {
        let _cleanup = OwnPins(PathBuf::from("/sys/fs/bpf/aivpn_app_routes").join("33".repeat(16)));
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "pin_failure_child",
                "--test-threads=1",
                "--nocapture",
            ])
            .env("LD_PRELOAD", "/lab/kernel-pin-faults.so")
            .env("AIVPN_KERNEL_PIN_FAIL", needle)
            .output()
            .unwrap();
        assert!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "{needle}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
#[ignore = "Дочерний процесс проверки отказа pinning"]
fn pin_failure_child() {
    require_native_guest();
    assert!(std::env::var_os("AIVPN_KERNEL_PIN_FAIL").is_some());
    let before = std::fs::read_dir("/proc/self/fd").unwrap().count();
    let error = PinnedKernel::install_new([0x33; 16])
        .err()
        .expect("Стенд отклоняет выбранный pin");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(
        std::fs::read_dir("/proc/self/fd").unwrap().count(),
        before,
        "Отказ установки должен закрывать дескрипторы links, программ, карт и каталогов"
    );
    assert!(!Path::new("/sys/fs/bpf/aivpn_app_routes")
        .join("33".repeat(16))
        .exists());
    for family in [libc::AF_INET, libc::AF_INET6] {
        let descriptor = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        assert!(descriptor >= 0, "Откат не должен запрещать SYSTEM-сокеты");
        drop(unsafe { OwnedFd::from_raw_fd(descriptor) });
    }
}

#[test]
#[ignore = "Нужен изолированный стенд с bpffs и BPF LSM"]
fn persisted_guards_survive_owner_drop_and_duplicate_installation() {
    require_native_guest();
    let namespace = [0x31; 16];
    let path = PathBuf::from("/sys/fs/bpf/aivpn_app_routes").join("31".repeat(16));
    let pinned = PinnedKernel::install_new(namespace).unwrap();
    let _cleanup = OwnPins(path.clone());
    assert_network_guard_placement(&path);
    let before = identity(&path.join("links/root_00"));
    let profile = identity(&path.join("maps/profiles"));
    let duplicate = PinnedKernel::install_new(namespace)
        .err()
        .expect("Существующие pins нельзя заменять");
    assert_eq!(duplicate.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(identity(&path.join("links/root_00")), before);
    assert_eq!(identity(&path.join("maps/profiles")), profile);
    drop(pinned);
    assert_eq!(identity(&path.join("links/root_00")), before);
    assert_eq!(identity(&path.join("maps/profiles")), profile);

    let descriptor = open_pin(&path.join("metadata"));
    let zero = 0u32;
    let mut metadata = [0u8; 64];
    assert_eq!(
        unsafe {
            bpf_map_lookup_elem(
                descriptor.as_raw_fd(),
                (&zero as *const u32).cast(),
                metadata.as_mut_ptr().cast(),
            )
        },
        0
    );
    assert_eq!(&metadata[..4], &4u32.to_ne_bytes());
    assert_eq!(&metadata[8..24], &namespace);
    assert_eq!(&metadata[24..56], &Sha256::digest(embedded_programs())[..]);
    assert!(
        unsafe {
            bpf_map_update_elem(
                descriptor.as_raw_fd(),
                (&zero as *const u32).cast(),
                metadata.as_ptr().cast(),
                0,
            )
        } < 0,
        "Метаданные должны быть закрыты от записи даже для открытого root FD"
    );
}

fn open_pin(path: &Path) -> OwnedFd {
    use std::os::unix::ffi::OsStrExt;
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let fd = unsafe { bpf_obj_get(path.as_ptr()) };
    assert!(
        fd >= 0,
        "Не удалось открыть собственный pin: {}",
        std::io::Error::last_os_error()
    );
    unsafe { OwnedFd::from_raw_fd(fd) }
}

fn identity(path: &Path) -> u32 {
    (kernel_info(path)[0] >> 32) as u32
}

fn kernel_info(path: &Path) -> [u64; 32] {
    let descriptor = open_pin(path);
    let mut info = [0u64; 32];
    let mut size = std::mem::size_of_val(&info) as u32;
    assert_eq!(
        unsafe {
            bpf_obj_get_info_by_fd(descriptor.as_raw_fd(), info.as_mut_ptr().cast(), &mut size)
        },
        0
    );
    let id = (info[0] >> 32) as u32;
    assert_ne!(id, 0);
    info
}

fn assert_network_guard_placement(path: &Path) {
    use std::collections::BTreeSet;
    let mut expected = BTreeSet::new();
    for (name, hook, priority) in [
        ("guard_profile_input", 0, -150),
        ("guard_profile_forward", 2, -150),
        ("guard_marked_output", 4, i32::MAX - 2),
        ("guard_final_output", 4, i32::MAX - 1),
    ] {
        let program = identity(&path.join("programs").join(name));
        for family in [libc::AF_INET as u32, libc::AF_INET6 as u32] {
            expected.insert((program, family, hook, priority, 0u32));
        }
    }
    let mut actual = BTreeSet::new();
    for entry in std::fs::read_dir(path.join("links")).unwrap() {
        let info = kernel_info(&entry.unwrap().path());
        if info[0] as u32 == 10 {
            // Linux UAPI bpf_link_info.netfilter: pf, hooknum, priority, flags.
            actual.insert((
                info[1] as u32,
                info[2] as u32,
                (info[2] >> 32) as u32,
                info[3] as u32 as i32,
                (info[3] >> 32) as u32,
            ));
        }
    }
    assert_eq!(
        actual, expected,
        "Проверяем фактические точки и порядок фильтрации в ядре"
    );
}

fn recovery_refusal(namespace: [u8; 16]) -> std::io::Error {
    let before = std::fs::read_dir("/proc/self/fd").unwrap().count();
    let error = RecoveredKernel::open_existing(namespace)
        .err()
        .expect("Поврежденный экземпляр нельзя принимать");
    assert_eq!(
        std::fs::read_dir("/proc/self/fd").unwrap().count(),
        before,
        "Отказ восстановления должен закрывать все временные дескрипторы"
    );
    error
}

struct OwnPins(PathBuf);
impl Drop for OwnPins {
    fn drop(&mut self) {
        for group in ["links", "programs", "maps"] {
            let path = self.0.join(group);
            if let Ok(entries) = std::fs::read_dir(&path) {
                let mut entries: Vec<_> = entries.map(|entry| entry.unwrap().path()).collect();
                entries.sort();
                for entry in entries.into_iter().rev() {
                    let _ = std::fs::remove_file(entry);
                }
            }
            let _ = std::fs::remove_dir(path);
        }
        let _ = std::fs::remove_file(self.0.join("metadata"));
        let _ = std::fs::remove_file(self.0.join("inventory"));
        let _ = std::fs::remove_dir(&self.0);
    }
}

fn require_native_guest() {
    assert!(std::fs::read_to_string("/proc/cmdline")
        .unwrap()
        .split_ascii_whitespace()
        .any(|word| word == "aivpn.app-routing-lab=1"));
    assert_eq!(
        std::fs::read_to_string("/lab/.app-routing-guest").unwrap(),
        "aivpn-offline-routing-lab\n"
    );
}
