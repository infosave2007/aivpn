use aivpn_desktop_agent::{
    bindings::BindingPlan,
    linux::{
        kernel::{embedded_programs, KernelWriter},
        ExecutableFile, MountSnapshot,
    },
    state::StateDirectory,
};
use aivpn_desktop_policy::*;
use sha2::{Digest, Sha256};
use std::{
    ffi::{c_void, CString},
    fs,
    io::{self, BufRead, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{DirBuilderExt, MetadataExt},
    },
    path::Path,
};

const NS: [u8; 16] = [0x73; 16];
const PINS: &str = "/sys/fs/bpf/aivpn_app_routes/73737373737373737373737373737373";
const ROOT: &str = "/lab/binding-state";
const A: &str = "/usr/bin/binding-a";
const B: &str = "/usr/bin/binding-b";

unsafe extern "C" {
    fn bpf_obj_get(path: *const i8) -> i32;
    fn bpf_map_lookup_elem(fd: i32, key: *const c_void, value: *mut c_void) -> i32;
    fn aivpn_path_hash(path: *const u8, length: u32, key0: u64, key1: u64, out: *mut u64);
}

pub fn require_guest() {
    assert!(fs::read_to_string("/proc/cmdline")
        .unwrap()
        .split_ascii_whitespace()
        .any(|word| word == "aivpn.app-routing-lab=1"));
    assert_eq!(
        fs::read_to_string("/lab/.app-routing-guest").unwrap(),
        "aivpn-offline-routing-lab\n"
    );
    assert_eq!(unsafe { libc::geteuid() }, 0);
}

fn map(name: &str) -> OwnedFd {
    let path = CString::new(format!("{PINS}/maps/{name}")).unwrap();
    let raw = unsafe { bpf_obj_get(path.as_ptr()) };
    assert!(raw >= 0, "Не удалось открыть карту {name}");
    unsafe { OwnedFd::from_raw_fd(raw) }
}

fn hash(seed: [u64; 2], path: &[u8], scope: u64) -> [u64; 3] {
    let mut result = [0, 0, scope];
    unsafe {
        aivpn_path_hash(
            path.as_ptr(),
            path.len() as u32,
            seed[0],
            seed[1],
            result.as_mut_ptr(),
        )
    };
    result
}

fn registry(authority: &Authority, profile: &str, inherit: bool) -> PolicyRegistry {
    let mut registry = PolicyRegistry::new(Platform::Linux);
    for (uid, path) in [(1000, A), (1001, B)] {
        let mut rules: Vec<RuleDocument> = ["198.18.0.53/32", "2001:db8:53::53/128"]
            .into_iter()
            .enumerate()
            .map(|(index, network)| RuleDocument {
                id: format!("selected-{index}"),
                application: Selector::Executable { path: path.into() },
                destination: Some(network.into()),
                inherit_children: inherit,
                action: Action::Vpn {
                    profile: profile.to_owned(),
                },
            })
            .collect();
        if uid == 1000 && std::env::var("SNAPSHOT_VARIANT").as_deref() == Ok("exec-sockets") {
            rules = vec![
                RuleDocument {
                    id: "selected-a".into(),
                    application: Selector::Executable { path: A.into() },
                    destination: None,
                    inherit_children: inherit,
                    action: Action::Vpn {
                        profile: profile.to_owned(),
                    },
                },
                RuleDocument {
                    id: "selected-b".into(),
                    application: Selector::Executable { path: B.into() },
                    destination: None,
                    inherit_children: inherit,
                    action: Action::System {},
                },
            ];
        }
        let mut document = PolicyDocument {
            split_enabled: true,
            version: 1,
            id: format!("binding-{uid}"),
            generation: 1,
            platform: Platform::Linux,
            owner: Owner::LinuxUser { uid },
            default_action: Action::System {},
            dns: DnsPolicy::SharedVpn {
                profile: profile.to_owned(),
                acknowledge_outage: true,
            },
            rules,
        };
        let change = registry.prepare(document.clone(), authority, None).unwrap();
        registry.commit(change).unwrap();
        if inherit {
            document.generation = 2;
            let change = registry.prepare(document, authority, Some(1)).unwrap();
            registry.commit(change).unwrap();
        }
    }
    registry
}

pub fn run() {
    fs::DirBuilder::new().mode(0o700).create(ROOT).unwrap();
    let mut writer =
        KernelWriter::install_new(NS, StateDirectory::open(Path::new(ROOT)).unwrap()).unwrap();
    let authority = Authority {
        user: Owner::LinuxUser { uid: 0 },
        machine_admin: true,
    };
    let mut catalog = ProfileCatalog::new(Platform::Linux, NS);
    let profile = catalog
        .register(
            &authority,
            Owner::LinuxUser { uid: 1000 },
            vec![Owner::LinuxUser { uid: 1001 }],
        )
        .unwrap();
    catalog.set_global_dns(&profile, &authority).unwrap();
    let plan = writer
        .prepare(&registry(&authority, &profile, false), &catalog, &authority)
        .unwrap();
    let key = map("path_key");
    let mut seed = [0u64; 2];
    let zero = 0u32;
    assert_eq!(
        unsafe {
            bpf_map_lookup_elem(
                key.as_raw_fd(),
                (&zero as *const u32).cast(),
                seed.as_mut_ptr().cast(),
            )
        },
        0
    );
    let mut retained = vec![];
    let mut rows = vec![];
    for path in [A, B] {
        assert!(std::process::Command::new(path)
            .args(["-c", "pass"])
            .status()
            .unwrap()
            .success());
        let located = MountSnapshot::read_current()
            .unwrap()
            .locate(ExecutableFile::open(Path::new(path)).unwrap())
            .unwrap();
        let physical = hash(seed, located.filesystem_path(), located.filesystem_device());
        let logical = hash(
            seed,
            located.canonical_path().as_os_str().as_encoded_bytes(),
            u64::MAX,
        );
        let prepared = writer.prepare_executable(&plan, path, located).unwrap();
        // Целевой executable исполняется отдельным процессом и не отображен в writer.
        let hold = unsafe { writer.retain_executable(&plan, &prepared) }.unwrap();
        let slot = hold.application_slot();
        retained.push(hold);
        let file = fs::File::open(path).unwrap();
        let fd = file.as_raw_fd();
        let tokens = map("inode_tokens");
        let mut cookie = 0u64;
        assert_eq!(
            unsafe {
                bpf_map_lookup_elem(
                    tokens.as_raw_fd(),
                    (&fd as *const i32).cast(),
                    (&mut cookie as *mut u64).cast(),
                )
            },
            0
        );
        assert!(cookie > 0);
        rows.push(serde_json::json!({"path":path,"slot":slot,"cookie":cookie,
            "inode":file.metadata().unwrap().ino(),"device":file.metadata().unwrap().dev(),
            "physical":physical,"logical":logical}));
    }
    assert_ne!(rows[0]["cookie"], rows[1]["cookie"]);
    assert_ne!(rows[0]["slot"], rows[1]["slot"]);
    println!(
        "BINDING_READY {}",
        serde_json::json!({"bindings":rows,
        "profile":plan.bindings().profiles[&profile].get(),"pins":PINS,
        "embedded_sha256":format!("{:x}", Sha256::digest(embedded_programs())),
        "embedded_bytes":embedded_programs().len()})
    );
    io::stdout().flush().unwrap();
    for line in io::stdin().lock().lines() {
        match line.unwrap().as_str() {
            "publish" => {
                publish(&mut writer, &plan);
            }
            "inherit" => {
                let inherited = writer
                    .prepare(&registry(&authority, &profile, true), &catalog, &authority)
                    .unwrap();
                assert_eq!(
                    inherited.bindings().executables,
                    plan.bindings().executables
                );
                assert_eq!(inherited.bindings().profiles, plan.bindings().profiles);
                publish(&mut writer, &inherited);
            }
            "cleanup" => break,
            command => panic!("Неизвестная команда {command}"),
        }
        io::stdout().flush().unwrap();
    }
    for uid in [1000, 1001] {
        writer.withdraw_policy(&Owner::LinuxUser { uid }).unwrap();
    }
    for hold in retained {
        writer.release_retention(hold).unwrap();
    }
    drop(writer);
    fs::remove_dir_all(PINS).unwrap();
    fs::remove_dir_all("/sys/fs/bpf/aivpn_app_retainers/73737373737373737373737373737373").unwrap();
    fs::remove_dir_all(ROOT).unwrap();
    println!("BINDING_CLEANED");
}

fn publish(writer: &mut KernelWriter, plan: &BindingPlan) {
    for policy in plan.policies() {
        writer.write_policy(policy).unwrap();
    }
    println!("PUBLISHED");
}
