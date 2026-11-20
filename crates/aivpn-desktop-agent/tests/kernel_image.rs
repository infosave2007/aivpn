#![cfg(all(target_os = "linux", feature = "linux-kernel"))]

use aivpn_desktop_agent::linux::kernel::KernelImage;

#[test]
fn embedded_image_opens_without_kernel_privileges() {
    KernelImage::open().expect("Встроенный объект соответствует схеме службы");
}

#[test]
#[ignore = "Нужен изолированный стенд с BPF LSM и правами root"]
fn embedded_image_loads_on_native_kernel() {
    require_native_guest();
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "Проверка выполняется только в стенде"
    );
    let programs = KernelImage::open().unwrap().load().unwrap();
    programs.validate_schema().unwrap();
    let guards = programs.attach_root_hooks().unwrap();
    assert_eq!(guards.link_count(), 30);
}

#[test]
#[ignore = "Нужен изолированный стенд с BPF LSM и правами root"]
fn a_thread_in_a_different_network_namespace_cannot_attach_system_guards() {
    require_native_guest();
    std::thread::spawn(|| {
        let programs = KernelImage::open().unwrap().load().unwrap();
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
        let error = programs
            .attach_root_hooks()
            .err()
            .expect("Namespace потока должен быть отклонен");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    })
    .join()
    .unwrap();
}

#[test]
#[ignore = "Нужен изолированный стенд с BPF LSM и правами root"]
fn a_bind_mounted_cgroup_subtree_cannot_replace_the_system_root() {
    require_native_guest();
    let cleanup = CgroupFixture::create();
    std::thread::spawn(|| {
        let programs = KernelImage::open().unwrap().load().unwrap();
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
                    c"/sys/fs/cgroup/image-test-subtree".as_ptr(),
                    c"/sys/fs/cgroup".as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            },
            0
        );
        let error = programs
            .attach_root_hooks()
            .err()
            .expect("Подкаталог должен быть отклонен");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    })
    .join()
    .unwrap();
    drop(cleanup);
    assert!(!std::path::Path::new("/sys/fs/cgroup/image-test-subtree").exists());
}

#[test]
#[ignore = "Нужен изолированный стенд с BPF LSM и правами root"]
fn a_container_local_pid_one_cannot_authorize_global_guards() {
    require_native_guest();
    let output = std::process::Command::new("unshare")
        .args(["--pid", "--fork", "--mount-proc", "--net", "--cgroup"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "initial_pid_namespace_child",
            "--test-threads=1",
            "--nocapture",
        ])
        .env("AIVPN_KERNEL_NAMESPACE_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "Дочерний процесс native namespace-теста"]
fn initial_pid_namespace_child() {
    require_native_guest();
    assert_eq!(
        std::env::var("AIVPN_KERNEL_NAMESPACE_CHILD").as_deref(),
        Ok("1")
    );
    use std::os::unix::fs::MetadataExt;
    for namespace in ["net", "cgroup", "user"] {
        assert_eq!(
            std::fs::metadata(format!("/proc/thread-self/ns/{namespace}"))
                .unwrap()
                .ino(),
            std::fs::metadata(format!("/proc/1/ns/{namespace}"))
                .unwrap()
                .ino()
        );
    }
    let programs = KernelImage::open().unwrap().load().unwrap();
    let error = programs
        .attach_root_hooks()
        .err()
        .expect("Локальный PID1 не подтверждает всю машину");
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
}

#[test]
#[ignore = "Нужен изолированный стенд с BPF LSM и правами root"]
fn hook_cleanup_preserves_ordinary_socket_creation() {
    require_native_guest();
    for mode in ["drop", "rollback"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "kernel_link_probe_child",
                "--test-threads=1",
                "--nocapture",
            ])
            .env("LD_PRELOAD", "/lab/kernel-link-faults.so")
            .env("AIVPN_KERNEL_LINK_PROBE", mode)
            .env("AIVPN_KERNEL_FORCE_ATTACH_FAIL", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "{mode}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
#[ignore = "Дочерний процесс проверки снятия hooks"]
fn kernel_link_probe_child() {
    require_native_guest();
    let arm = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"aivpn_kernel_arm_link_probe".as_ptr()) };
    let result = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"aivpn_kernel_link_probe_result".as_ptr(),
        )
    };
    assert!(!arm.is_null() && !result.is_null());
    let arm: unsafe extern "C" fn() = unsafe { std::mem::transmute(arm) };
    let result: unsafe extern "C" fn() -> u64 = unsafe { std::mem::transmute(result) };
    let programs = KernelImage::open().unwrap().load().unwrap();
    let rollback = std::env::var("AIVPN_KERNEL_LINK_PROBE").unwrap() == "rollback";
    let expected_links = if rollback {
        unsafe { arm() };
        let error = programs
            .attach_root_hooks()
            .err()
            .expect("Отказ третьего cgroup hook");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        17
    } else {
        let guards = programs.attach_root_hooks().unwrap();
        unsafe { arm() };
        drop(guards);
        30
    };
    let observed = unsafe { result() };
    assert_eq!(
        observed >> 32,
        expected_links * 2,
        "Проверка обоих семейств после каждого снятого link"
    );
    assert_eq!(
        observed as u32, 0,
        "SYSTEM-сокеты должны работать на каждом шаге снятия hooks"
    );
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

struct CgroupFixture;

impl CgroupFixture {
    fn create() -> Self {
        std::fs::create_dir("/sys/fs/cgroup/image-test-subtree").unwrap();
        Self
    }
}

impl Drop for CgroupFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir("/sys/fs/cgroup/image-test-subtree");
    }
}
