use aivpn_desktop_agent::{
    linux::{
        kernel::{embedded_snapshot_programs, KernelWriter},
        ExecutableFile, MountSnapshot,
    },
    state::StateDirectory,
};
use aivpn_desktop_policy::*;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::{c_void, CString},
    fs,
    io::{self, BufRead, Write},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
        unix::fs::DirBuilderExt,
    },
    path::Path,
};

const NS: [u8; 16] = [0x75; 16];
const ROOT: &str = "/lab/snapshot-state";
const PINS: &str = "/sys/fs/bpf/aivpn_app_routes/75757575757575757575757575757575";
const RETENTIONS: &str = "/sys/fs/bpf/aivpn_app_group_retainers/75757575757575757575757575757575";
const A: &str = "/usr/bin/binding-a";
const H: &str = "/usr/bin/binding-a-alias";
const B: &str = "/usr/bin/binding-b";

unsafe extern "C" {
    fn bpf_obj_get(path: *const i8) -> i32;
    fn bpf_map_update_elem(fd: i32, key: *const c_void, value: *const c_void, flags: u64) -> i32;
    fn bpf_map_lookup_elem(fd: i32, key: *const c_void, value: *mut c_void) -> i32;
    fn bpf_map_get_next_key(fd: i32, key: *const c_void, next: *mut c_void) -> i32;
    fn aivpn_snapshot_create() -> i32;
    fn bpf_map_freeze(fd: i32) -> i32;
    fn bpf_map_delete_elem(fd: i32, key: *const c_void) -> i32;
}
pub fn require_guest() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let cmd = fs::read_to_string("/proc/cmdline").unwrap();
    for marker in ["aivpn.app-routing-lab=1", "aivpn.binding-snapshot=1"] {
        assert!(cmd.split_ascii_whitespace().any(|word| word == marker));
    }
    assert_eq!(
        fs::read_to_string("/lab/.app-routing-guest").unwrap(),
        "aivpn-offline-routing-lab\n"
    );
}
fn map(name: &str) -> OwnedFd {
    let path = CString::new(format!("{PINS}/maps/{name}")).unwrap();
    let raw = unsafe { bpf_obj_get(path.as_ptr()) };
    assert!(raw >= 0, "{path:?}: {raw}");
    unsafe { OwnedFd::from_raw_fd(raw) }
}
fn document(owner: Owner, profile: &str, rules: Vec<RuleDocument>) -> PolicyDocument {
    PolicyDocument {
        split_enabled: true,
        version: 1,
        id: "snapshot-policy".into(),
        generation: 1,
        platform: Platform::Linux,
        owner,
        default_action: Action::System {},
        dns: DnsPolicy::SharedVpn {
            profile: profile.into(),
            acknowledge_outage: true,
        },
        rules,
    }
}
fn rules(path: &str, action: Action, inherit: bool, outside: bool) -> Vec<RuleDocument> {
    let cidrs = if outside {
        ["198.18.0.54/32", "2001:db8:53::54/128"]
    } else {
        ["198.18.0.53/32", "2001:db8:53::53/128"]
    };
    cidrs
        .into_iter()
        .enumerate()
        .map(|(i, cidr)| RuleDocument {
            id: format!("{}-{i}", path.rsplit('/').next().unwrap()),
            application: Selector::Executable { path: path.into() },
            destination: Some(cidr.into()),
            inherit_children: inherit,
            action: action.clone(),
        })
        .collect()
}
fn selected_rules(profile: &str, variant: &str) -> Vec<RuleDocument> {
    if variant.starts_with("admission-") {
        let action = if variant == "admission-matrix" {
            admission_action(&std::env::var("ADMISSION_BEFORE").unwrap(), profile)
        } else if variant == "admission-system-block" {
            Action::Block {}
        } else {
            Action::Vpn {
                profile: profile.into(),
            }
        };
        return rules(A, action, true, false);
    }
    if variant.starts_with("exec-") {
        let source = fs::read_to_string("/lab/exec-policy.json").unwrap();
        let value: serde_json::Value =
            serde_json::from_str(&source.replace("@PROFILE@", profile)).unwrap();
        return serde_json::from_value(value["rules"].clone()).unwrap();
    }
    let mut selected = rules(
        A,
        Action::Vpn {
            profile: profile.into(),
        },
        true,
        false,
    );
    selected.extend(rules(
        B,
        Action::Vpn {
            profile: profile.into(),
        },
        false,
        true,
    ));
    if variant == "full" {
        selected = (0..256)
            .map(|index| RuleDocument {
                id: format!("full-{index}"),
                application: Selector::Executable { path: A.into() },
                destination: Some(
                    if index == 255 {
                        "198.18.0.53/32"
                    } else {
                        "198.18.0.54/32"
                    }
                    .into(),
                ),
                inherit_children: true,
                action: Action::Vpn {
                    profile: profile.into(),
                },
            })
            .collect();
    }
    if variant == "capture-owner" {
        selected.truncate(2);
    }
    if variant == "precedence" {
        selected.extend(rules(
            "/usr/bin/binding-unknown",
            Action::System {},
            false,
            false,
        ));
    }
    if variant == "loopback" {
        selected = vec![RuleDocument {
            id: "loopback".into(),
            application: Selector::Executable { path: A.into() },
            destination: None,
            inherit_children: true,
            action: Action::Vpn {
                profile: profile.into(),
            },
        }];
    }
    if matches!(variant, "aliases" | "modeled-history") {
        selected.extend(rules(
            "/usr/bin/binding-link",
            Action::Block {},
            true,
            false,
        ));
    }
    if variant == "leads" {
        for path in [
            "/usr/bin/selected-script",
            "/usr/bin/selected-launcher",
            "/usr/bin/selected.AppImage",
        ] {
            selected.extend(rules(
                path,
                Action::Vpn {
                    profile: profile.into(),
                },
                true,
                false,
            ));
        }
    }
    selected
}

fn admission_action(name: &str, profile: &str) -> Action {
    match name {
        "SYSTEM" => Action::System {},
        "VPN" => Action::Vpn {
            profile: profile.into(),
        },
        "BLOCK" => Action::Block {},
        _ => panic!("Неизвестный маршрут fixture"),
    }
}
fn registry(authority: &Authority, profile: &str, variant: &str) -> PolicyRegistry {
    let mut registry = PolicyRegistry::new(Platform::Linux);
    let mut documents = vec![
        document(
            Owner::LinuxUser { uid: 1000 },
            profile,
            selected_rules(profile, variant),
        ),
        document(
            Owner::LinuxUser { uid: 1001 },
            profile,
            rules(H, Action::Block {}, false, false),
        ),
    ];
    if variant.starts_with("exec-") {
        let fixture: serde_json::Value =
            serde_json::from_str(&fs::read_to_string("/lab/exec-policy.json").unwrap()).unwrap();
        if fixture["machine"].as_bool() == Some(true) {
            documents = vec![document(
                Owner::Machine {},
                profile,
                selected_rules(profile, variant),
            )];
        }
    }
    if variant == "capture-owner" {
        documents[1]
            .rules
            .extend(rules(B, Action::Block {}, false, false));
    }
    if matches!(variant, "machine" | "boundary") {
        documents = vec![document(
            Owner::Machine {},
            profile,
            machine_rules(profile, variant),
        )];
    }
    if variant == "reverse" {
        documents.reverse();
    }
    for doc in documents {
        let change = registry.prepare(doc, authority, None).unwrap();
        registry.commit(change).unwrap();
    }
    registry
}
fn machine_rules(profile: &str, variant: &str) -> Vec<RuleDocument> {
    let (first, second, action) = if variant == "machine" {
        (H, A, Action::Block {})
    } else {
        (
            A,
            H,
            Action::Vpn {
                profile: profile.into(),
            },
        )
    };
    let mut selected = rules(first, action.clone(), true, false);
    selected.extend(rules(second, action, true, false));
    selected
}
pub fn run() {
    require_guest();
    let variant = std::env::var("SNAPSHOT_VARIANT").unwrap_or_else(|_| "basic".into());
    for directory in [ROOT, &format!("{ROOT}/slots"), &format!("{ROOT}/bindings")] {
        fs::DirBuilder::new().mode(0o700).create(directory).unwrap();
    }
    let mut writer = KernelWriter::install_new_snapshot(
        NS,
        StateDirectory::open(Path::new(&format!("{ROOT}/slots"))).unwrap(),
    )
    .unwrap();
    let initial_core = writer.core_phase_proof().unwrap().digest();
    if std::env::var_os("VERTICAL_CAPTURE_CHECK").is_some() {
        println!(
            "SNAPSHOT_CAPTURE_READY {}",
            serde_json::json!({"links":6,"network_links":0,"core":initial_core})
        );
        io::stdout().flush().unwrap();
        let mut command = String::new();
        io::stdin().read_line(&mut command).unwrap();
        assert_eq!(command.trim(), "capture-go");
        drop(writer);
        writer = KernelWriter::open_existing_snapshot(
            NS,
            StateDirectory::open(Path::new(&format!("{ROOT}/slots"))).unwrap(),
        )
        .unwrap();
        assert_eq!(writer.core_phase_proof().unwrap().digest(), initial_core);
    }
    writer
        .open_verified_bindings(
            StateDirectory::open(Path::new(&format!("{ROOT}/bindings"))).unwrap(),
        )
        .unwrap();
    writer.recover_verified_bindings().unwrap();
    let authority = Authority {
        user: Owner::LinuxUser { uid: 0 },
        machine_admin: true,
    };
    let mut catalog = ProfileCatalog::new(Platform::Linux, NS);
    let profile = catalog
        .register(
            &authority,
            Owner::Machine {},
            vec![
                Owner::LinuxUser { uid: 1000 },
                Owner::LinuxUser { uid: 1001 },
            ],
        )
        .unwrap();
    catalog.set_global_dns(&profile, &authority).unwrap();
    let mut registry = registry(&authority, &profile, &variant);
    let mut request = writer
        .selected_executables(&registry, &catalog, &authority, 1)
        .unwrap();
    let paths: BTreeSet<_> = registry
        .policies()
        .flat_map(|p| p.document().rules.iter())
        .filter_map(|r| match &r.application {
            Selector::Executable { path } => Some(path.clone()),
            _ => None,
        })
        .collect();
    let mounts = MountSnapshot::read_current().unwrap();
    let files = paths
        .iter()
        .map(|path| {
            mounts
                .locate(ExecutableFile::open(Path::new(path)).unwrap())
                .unwrap()
        })
        .collect();
    let staged = unsafe { writer.stage_verified_bindings(&request, files) }.unwrap();
    let manifest = writer
        .seal_for_publication(&staged, request.desired_digest())
        .unwrap();
    let frozen = writer.prepare_binding_snapshot(&request, &staged).unwrap();
    let alias = manifest.aliases().iter().find(|a| a.path() == A);
    if !variant.starts_with("exec-") {
        let alias = alias.unwrap();
        let hardlink = manifest.aliases().iter().find(|a| a.path() == H).unwrap();
        assert_ne!(alias.selector(), hardlink.selector());
        assert_eq!(alias.group(), hardlink.group());
    }
    let mut value = [0u8; 64];
    let key = [7u64, 0, 0, 0, 0];
    let fd = frozen.as_fd().as_raw_fd();
    assert_eq!(
        unsafe { bpf_map_lookup_elem(fd, key.as_ptr().cast(), value.as_mut_ptr().cast()) },
        0
    );
    assert_eq!(
        unsafe { bpf_map_update_elem(fd, key.as_ptr().cast(), value.as_ptr().cast(), 0) },
        -libc::EPERM
    );
    assert_eq!(
        unsafe { bpf_map_delete_elem(fd, key.as_ptr().cast()) },
        -libc::EPERM
    );
    writer
        .validate_sealed_bindings(&manifest, &request)
        .unwrap();
    // Только fixture делает root видимым. Все claims живут до снятия hooks.
    let corrupt = fixture_image(fd, &variant, &manifest);
    let installed = corrupt.as_ref().map_or(fd, AsRawFd::as_raw_fd);
    let root = map("binding_root");
    let zero = 0u32;
    assert_eq!(
        unsafe {
            bpf_map_update_elem(
                root.as_raw_fd(),
                (&zero as *const u32).cast(),
                (&fd as *const i32).cast(),
                0,
            )
        },
        0
    );
    let attachment = writer.complete_snapshot_installation().unwrap();
    assert_eq!(attachment.core_digest(), initial_core);
    if variant == "missing-root" {
        assert_eq!(
            unsafe { bpf_map_delete_elem(root.as_raw_fd(), (&zero as *const u32).cast()) },
            0
        );
    } else if corrupt.is_some() {
        assert_eq!(
            unsafe {
                bpf_map_update_elem(
                    root.as_raw_fd(),
                    (&zero as *const u32).cast(),
                    (&installed as *const i32).cast(),
                    0,
                )
            },
            0
        );
    }
    if variant == "full" {
        let keys = alias.unwrap().negative_keys();
        for kind in [5u64, 6] {
            let k = keys[(kind - 5) as usize];
            let key = [kind, (1 << 32) | 1000, k[0], k[1], k[2]];
            let mut bitmap = [0u64; 8];
            assert_eq!(
                unsafe { bpf_map_lookup_elem(fd, key.as_ptr().cast(), bitmap.as_mut_ptr().cast()) },
                0
            );
            assert_eq!(&bitmap[..4], &[u64::MAX; 4]);
            assert_eq!(&bitmap[4..], &[0; 4]);
        }
    }
    let profile_slot = u32::from_ne_bytes(manifest.policies()[0][32..36].try_into().unwrap());
    println!(
        "SNAPSHOT_READY {}",
        serde_json::json!({"profile":profile_slot,"pins":PINS,"bindings":[],"records":frozen.record_count(),
        "manifest_digest":frozen.manifest_digest(),"bundle_digest":frozen.bundle_digest(),
        "core_before":initial_core,"core_after":attachment.core_digest(),"final_inventory":attachment.inventory_digest(),
        "binding_tag":u64::from_ne_bytes(value[8..16].try_into().unwrap()),
        "fixture_model":match variant.as_str() {"modeled-history"=>"MODELED_HISTORY","modeled-owner-precedence"=>"MODELED_OWNER_PRECEDENCE",_=>"REAL_REGISTRY"},
        "aliases":manifest.aliases().iter().map(|a|serde_json::json!({"path":a.path(),"selector":a.selector().get(),"group":a.group().get(),"keys":a.negative_keys(),"owner":a.owner()})).collect::<Vec<_>>(),
        "embedded_sha256":format!("{:x}",Sha256::digest(embedded_snapshot_programs()))})
    );
    io::stdout().flush().unwrap();
    let mut refreshed = Vec::new();
    for command in io::stdin().lock().lines() {
        match command.unwrap().as_str() {
            "cleanup" => break,
            command
                if variant.starts_with("admission-")
                    && refreshed.is_empty()
                    && (command == "refresh" || command.starts_with("policy:")) =>
            {
                if let Some(action) = command.strip_prefix("policy:") {
                    let mut document = registry
                        .policies()
                        .find(|p| p.document().owner == Owner::LinuxUser { uid: 1000 })
                        .unwrap()
                        .document()
                        .clone();
                    let previous = document.generation;
                    document.generation += 1;
                    for rule in &mut document.rules {
                        rule.action = admission_action(action, &profile);
                    }
                    let change = registry
                        .prepare(document, &authority, Some(previous))
                        .unwrap();
                    registry.commit(change).unwrap();
                    request = writer
                        .selected_executables(&registry, &catalog, &authority, 2)
                        .unwrap();
                }
                let files = paths
                    .iter()
                    .map(|path| {
                        mounts
                            .locate(ExecutableFile::open(Path::new(path)).unwrap())
                            .unwrap()
                    })
                    .collect();
                let held = unsafe { writer.stage_verified_bindings(&request, files) }.unwrap();
                let next = writer.prepare_binding_snapshot(&request, &held).unwrap();
                let next_fd = next.as_fd().as_raw_fd();
                assert_eq!(
                    unsafe {
                        bpf_map_update_elem(
                            root.as_raw_fd(),
                            (&zero as *const u32).cast(),
                            (&next_fd as *const i32).cast(),
                            0,
                        )
                    },
                    0
                );
                let mut meta = [0u64; 8];
                assert_eq!(
                    unsafe {
                        bpf_map_lookup_elem(next_fd, key.as_ptr().cast(), meta.as_mut_ptr().cast())
                    },
                    0
                );
                let generation = registry
                    .policies()
                    .find(|p| p.document().owner == Owner::LinuxUser { uid: 1000 })
                    .unwrap()
                    .document()
                    .generation;
                println!(
                    "SNAPSHOT_SWAPPED {}",
                    serde_json::json!({"binding_tag":meta[1], "document_generation":generation,"bundle_digest":next.bundle_digest()})
                );
                io::stdout().flush().unwrap();
                refreshed.push((held, next));
            }
            other => panic!("Неизвестная команда fixture: {other}"),
        }
    }
    drop(root);
    drop(writer);
    fs::remove_dir_all(PINS).unwrap();
    drop(frozen);
    drop(corrupt);
    fs::remove_dir_all(RETENTIONS).unwrap();
    drop(refreshed);
    drop(staged);
    fs::remove_dir_all(ROOT).unwrap();
    println!("SNAPSHOT_CLEANED");
}

// Заведомо поврежденная raw карта существует только в guarded fixture.
fn read_records(source: i32) -> Vec<([u64; 5], [u8; 64])> {
    let mut records = Vec::new();
    let mut previous: Option<[u64; 5]> = None;
    loop {
        let mut key = [0u64; 5];
        let pointer = previous
            .as_ref()
            .map_or(std::ptr::null(), |k| k.as_ptr().cast());
        let status = unsafe { bpf_map_get_next_key(source, pointer, key.as_mut_ptr().cast()) };
        if status == -libc::ENOENT {
            break;
        }
        assert_eq!(status, 0);
        let mut value = [0u8; 64];
        assert_eq!(
            unsafe { bpf_map_lookup_elem(source, key.as_ptr().cast(), value.as_mut_ptr().cast()) },
            0
        );
        records.push((key, value));
        previous = Some(key);
    }
    records
}

fn malformed(source: i32, variant: &str) -> OwnedFd {
    let raw = unsafe { aivpn_snapshot_create() };
    assert!(raw >= 0);
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    for (key, mut value) in read_records(source) {
        corrupt_value(&key, &mut value, variant);
        if !skip_record(&key, variant) {
            assert_eq!(
                unsafe {
                    bpf_map_update_elem(
                        fd.as_raw_fd(),
                        key.as_ptr().cast(),
                        value.as_ptr().cast(),
                        1,
                    )
                },
                0
            );
        }
    }
    fd
}

fn fixture_image(
    source: i32,
    variant: &str,
    manifest: &aivpn_desktop_agent::linux::kernel::SealedBindingManifest,
) -> Option<OwnedFd> {
    let variant = match variant {
        "exec-fault-invalid" => "malformed-missing-meta",
        "exec-fault-missing-rule" => "malformed-missing-first-rule",
        value => value,
    };
    if !variant.starts_with("malformed-")
        && !matches!(variant, "modeled-history" | "modeled-owner-precedence")
    {
        return None;
    }
    let fd = malformed(source, variant);
    if variant == "modeled-history" {
        // MODELED_HISTORY: raw membership не является sealed artifact или принятой историей.
        let selector = manifest
            .aliases()
            .iter()
            .find(|a| a.path() == A)
            .unwrap()
            .selector()
            .get();
        let group = manifest
            .aliases()
            .iter()
            .find(|a| a.path() == B)
            .unwrap()
            .group()
            .get();
        let key = [4u64, (1 << 32) | 1000, selector.into(), group.into(), 0];
        let mut value = [0u64; 8];
        value[0] = 1;
        assert_eq!(
            unsafe {
                bpf_map_update_elem(
                    fd.as_raw_fd(),
                    key.as_ptr().cast(),
                    value.as_ptr().cast(),
                    1,
                )
            },
            0
        );
        println!(
            "MODELED_HISTORY {}",
            serde_json::json!({"added_membership_key":key,"value":value})
        );
    }
    if variant == "modeled-owner-precedence" {
        add_machine_model(source, &fd);
    }
    assert_eq!(unsafe { bpf_map_freeze(fd.as_raw_fd()) }, 0);
    Some(fd)
}

fn skip_record(key: &[u64; 5], variant: &str) -> bool {
    match variant {
        "malformed-missing-meta" => key[0] == 7,
        "malformed-missing-first-rule" => {
            key[0] == 2 && key[1] == ((1 << 32) | 1000) && key[2] == 0
        }
        "malformed-missing-rule" => key[0] == 2 && key[1] == ((1 << 32) | 1000) && key[2] == 3,
        _ => false,
    }
}
fn corrupt_value(key: &[u64; 5], value: &mut [u8; 64], variant: &str) {
    let corrupt = match variant {
        "malformed-schema" => key[0] == 7,
        "malformed-header" => key[0] == 1 && key[1] == ((1 << 32) | 1000),
        _ => false,
    };
    if corrupt {
        value[..4].copy_from_slice(&2u32.to_ne_bytes());
    }
}

fn add_machine_model(source: i32, fd: &OwnedFd) {
    // MODELED_OWNER_PRECEDENCE не обходит запрет PolicyRegistry для product inputs.
    for (mut key, mut value) in read_records(source) {
        if key[1] != ((1 << 32) | 1001) {
            continue;
        }
        key[1] = 3 << 32;
        if key[0] == 1 {
            value[4..8].copy_from_slice(&3u32.to_ne_bytes());
            value[8..12].copy_from_slice(&0u32.to_ne_bytes());
        }
        assert_eq!(
            unsafe {
                bpf_map_update_elem(
                    fd.as_raw_fd(),
                    key.as_ptr().cast(),
                    value.as_ptr().cast(),
                    1,
                )
            },
            0
        );
        println!(
            "MODELED_OWNER_PRECEDENCE {}",
            serde_json::json!({"added_key":key})
        );
    }
}
