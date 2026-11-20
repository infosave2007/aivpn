#![cfg(all(target_os = "linux", feature = "linux-kernel"))]
// Общая fixture обслуживает также legacy retention tests с дополнительными helpers.
#[allow(dead_code)]
#[path = "support/retention_lab.rs"]
mod lab;
use aivpn_desktop_agent::state::StateDirectory;
use aivpn_desktop_policy::*;
use lab::*;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

#[test]
#[ignore = "Нужен собственный изолированный root-стенд"]
fn fresh_aliases_stage_without_executing_selected_file() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    require_lab();
    assert!(std::fs::read_to_string("/proc/cmdline")
        .unwrap()
        .split_ascii_whitespace()
        .any(|s| s == "aivpn.verified-bindings=1"));
    setup();
    std::fs::copy("/usr/bin/verified-canary", TARGET).unwrap();
    let _cleanup = Cleanup;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(format!("{ROOT}/bindings"))
        .unwrap();
    let mut writer = lab::writer(true);
    writer
        .open_verified_bindings(
            StateDirectory::open(Path::new(&format!("{ROOT}/bindings"))).unwrap(),
        )
        .unwrap();
    writer.recover_verified_bindings().unwrap();
    let (catalog, mut registry, authority) = inputs(Path::new(TARGET), NS);
    let mut document = registry.policies().next().unwrap().document().clone();
    document.generation += 1;
    document.rules.push(RuleDocument {
        id: "alias".into(),
        application: Selector::Executable { path: ALIAS.into() },
        ..document.rules[0].clone()
    });
    let change = registry.prepare(document, &authority, Some(1)).unwrap();
    registry.commit(change).unwrap();
    assert_eq!(cookie(TARGET), None);
    let request = writer
        .selected_executables(&registry, &catalog, &authority, 1)
        .unwrap();
    let staged = unsafe {
        writer.stage_verified_bindings(
            &request,
            vec![locate(Path::new(TARGET)), locate(Path::new(ALIAS))],
        )
    };
    assert!(
        staged.is_ok(),
        "Новый stage API отказал: {:?}",
        staged.as_ref().err()
    );
    let staged = staged.unwrap();
    let sealed = writer
        .seal_for_publication(&staged, request.desired_digest())
        .unwrap();
    writer.validate_sealed_bindings(&sealed, &request).unwrap();
    assert_eq!(sealed.aliases().len(), 2);
    assert_ne!(
        sealed.aliases()[0].selector(),
        sealed.aliases()[1].selector()
    );
    assert_eq!(sealed.aliases()[0].group(), sealed.aliases()[1].group());
    assert_eq!(sealed.groups().len(), 1);
    assert_eq!(cookie(TARGET), Some(sealed.groups()[0].cookie()));
    assert_eq!(cookie(ALIAS), cookie(TARGET));
    assert!(!Path::new("/lab/verified-entrypoint-canary").exists());
    assert_eq!(std::fs::read_dir(group_pins()).unwrap().count(), 1);
    assert!(writer.prepare(&registry, &catalog, &authority).is_err());
    let transaction = staged.transaction();
    drop(staged);
    drop(writer);
    let mut writer = lab::writer(false);
    assert!(writer.prepare(&registry, &catalog, &authority).is_err());
    writer
        .open_verified_bindings(
            StateDirectory::open(Path::new(&format!("{ROOT}/bindings"))).unwrap(),
        )
        .unwrap();
    assert_eq!(
        writer.recover_verified_bindings().unwrap().staged(),
        &[transaction]
    );
    let resumed = writer.resume_verified_bindings(transaction).unwrap();
    let again = writer
        .seal_for_publication(&resumed, request.desired_digest())
        .unwrap();
    assert_eq!(again.groups()[0].link_id(), sealed.groups()[0].link_id());
    writer.abort_unpublished(transaction).unwrap();
    writer.abort_unpublished(transaction).unwrap();
    assert_eq!(std::fs::read_dir(group_pins()).unwrap().count(), 0);
    assert_eq!(cookie(TARGET), Some(sealed.groups()[0].cookie()));
}

fn group_pins() -> std::path::PathBuf {
    Path::new("/sys/fs/bpf/aivpn_app_group_retainers").join("71".repeat(16))
}

fn policy_inputs(
    paths: &[(&str, u32)],
    machine: bool,
) -> (ProfileCatalog, PolicyRegistry, Authority) {
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
    let mut owners = vec![1000, 1001];
    if machine {
        owners.push(u32::MAX);
    }
    let mut registry = PolicyRegistry::new(Platform::Linux);
    for uid in owners {
        let rules: Vec<_> = paths
            .iter()
            .filter(|(_, owner)| *owner == uid)
            .enumerate()
            .map(|(index, (path, _))| RuleDocument {
                id: format!("rule-{index}"),
                application: Selector::Executable {
                    path: (*path).into(),
                },
                destination: None,
                inherit_children: true,
                action: Action::Block {},
            })
            .collect();
        if rules.is_empty() {
            continue;
        }
        let owner = if uid == u32::MAX {
            Owner::Machine {}
        } else {
            Owner::LinuxUser { uid }
        };
        let doc = PolicyDocument {
            split_enabled: true,
            version: 1,
            id: format!("owner-{uid}"),
            generation: 1,
            platform: Platform::Linux,
            owner,
            default_action: Action::System {},
            dns: DnsPolicy::SharedVpn {
                profile: profile.clone(),
                acknowledge_outage: true,
            },
            rules,
        };
        let update = registry.prepare(doc, &authority, None).unwrap();
        registry.commit(update).unwrap();
    }
    (catalog, registry, authority)
}
fn start() -> (
    aivpn_desktop_agent::linux::kernel::KernelWriter,
    GroupsCleanup,
) {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    require_lab();
    assert!(std::fs::read_to_string("/proc/cmdline")
        .unwrap()
        .split_ascii_whitespace()
        .any(|s| s == "aivpn.verified-bindings=1"));
    setup();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(format!("{ROOT}/bindings"))
        .unwrap();
    let mut writer = reopen(true);
    writer.recover_verified_bindings().unwrap();
    (writer, GroupsCleanup(Cleanup))
}
struct GroupsCleanup(Cleanup);
impl Drop for GroupsCleanup {
    fn drop(&mut self) {
        if group_pins().exists() {
            std::fs::remove_dir_all(group_pins()).unwrap();
        }
    }
}
fn reopen(new: bool) -> aivpn_desktop_agent::linux::kernel::KernelWriter {
    let mut writer = lab::writer(new);
    writer
        .open_verified_bindings(
            StateDirectory::open(Path::new(&format!("{ROOT}/bindings"))).unwrap(),
        )
        .unwrap();
    writer
}
fn stage(
    writer: &mut aivpn_desktop_agent::linux::kernel::KernelWriter,
    paths: &[(&str, u32)],
    serial: u64,
) -> aivpn_desktop_agent::linux::kernel::SealedBindingManifest {
    let routing_before = routing_snapshot();
    let (catalog, registry, authority) = policy_inputs(paths, true);
    let request = writer
        .selected_executables(&registry, &catalog, &authority, serial)
        .unwrap();
    let unique: std::collections::BTreeSet<_> = paths.iter().map(|(path, _)| *path).collect();
    let files = unique
        .into_iter()
        .rev()
        .map(|path| locate(Path::new(path)))
        .collect();
    let set = unsafe { writer.stage_verified_bindings(&request, files) }.unwrap();
    let sealed = writer
        .seal_for_publication(&set, request.desired_digest())
        .unwrap();
    writer.validate_sealed_bindings(&sealed, &request).unwrap();
    assert_eq!(routing_snapshot(), routing_before);
    sealed
}
fn routing_snapshot() -> Vec<Vec<u8>> {
    use std::os::fd::AsRawFd;
    unsafe extern "C" {
        fn bpf_map_get_next_key(
            fd: i32,
            previous: *const std::ffi::c_void,
            next: *mut std::ffi::c_void,
        ) -> i32;
    }
    let mut result = Vec::new();
    for (name, key_size, value_size) in [
        ("applications", 24, 4),
        ("file_bindings", 8, 4),
        ("policies", 8, 14376),
    ] {
        let map = open(&static_pins().join("maps").join(name));
        let mut previous: Option<Vec<u8>> = None;
        loop {
            let mut key = vec![0; key_size];
            let status = unsafe {
                bpf_map_get_next_key(
                    map.as_raw_fd(),
                    previous
                        .as_ref()
                        .map_or(std::ptr::null(), |key| key.as_ptr().cast()),
                    key.as_mut_ptr().cast(),
                )
            };
            if status == -libc::ENOENT {
                break;
            }
            assert_eq!(status, 0);
            let mut value = vec![0; value_size];
            assert_eq!(
                unsafe {
                    bpf_map_lookup_elem(
                        map.as_raw_fd(),
                        key.as_ptr().cast(),
                        value.as_mut_ptr().cast(),
                    )
                },
                0
            );
            result.push([name.as_bytes(), &key, &value].concat());
            previous = Some(key);
            assert!(result.len() < 8192);
        }
    }
    result.sort();
    result
}
fn system_control() {
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .unwrap();
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(b"ordinary-system", receiver.local_addr().unwrap())
        .unwrap();
    let mut bytes = [0; 32];
    assert_eq!(receiver.recv(&mut bytes).unwrap(), 15);
}

#[test]
#[ignore = "Нужен собственный изолированный root-стенд"]
fn aliases_replacement_known_inode_and_owner_scopes_keep_stable_groups() {
    let (mut writer, _cleanup) = start();
    let before = routing_snapshot();
    system_control();
    let both = stage(
        &mut writer,
        &[(TARGET, 1000), (ALIAS, 1000), (TARGET, 1001)],
        1,
    );
    assert_eq!(both.groups().len(), 1);
    assert_eq!(both.memberships().len(), 3);
    let original = both.groups()[0].id();
    let machine = stage(&mut writer, &[(ALIAS, u32::MAX)], 2);
    assert_eq!(machine.groups()[0].id(), original);
    assert_eq!(machine.memberships()[0].owner(), Owner::Machine {});
    let only = stage(&mut writer, &[(ALIAS, 1000)], 3);
    assert_eq!(only.groups()[0].id(), original);
    assert_eq!(only.aliases().len(), 1);
    writer.abort_unpublished(both.transaction()).unwrap();
    assert_eq!(std::fs::read_dir(group_pins()).unwrap().count(), 1);
    let returned = stage(&mut writer, &[(TARGET, 1000), (ALIAS, 1001)], 4);
    assert_eq!(returned.groups()[0].id(), original);
    std::fs::copy(CONTROL, format!("{TARGET}.new")).unwrap();
    std::fs::rename(format!("{TARGET}.new"), TARGET).unwrap();
    assert_eq!(std::fs::read_dir(group_pins()).unwrap().count(), 1);
    let replacement = stage(&mut writer, &[(TARGET, 1000)], 5);
    assert_ne!(replacement.groups()[0].id(), original);
    assert_eq!(std::fs::read_dir(group_pins()).unwrap().count(), 2);
    let known = stage(&mut writer, &[(CONTROL, 1001)], 6);
    std::fs::hard_link(CONTROL, format!("{TARGET}.known")).unwrap();
    std::fs::rename(format!("{TARGET}.known"), TARGET).unwrap();
    let moved = stage(&mut writer, &[(TARGET, 1000), (CONTROL, 1001)], 7);
    assert_eq!(moved.groups().len(), 1);
    assert_eq!(moved.groups()[0].id(), known.groups()[0].id());
    assert_ne!(moved.groups()[0].id(), original);
    assert_eq!(std::fs::read_dir(group_pins()).unwrap().count(), 3);
    assert_eq!(routing_snapshot(), before);
    system_control();
    for token in [
        machine.transaction(),
        only.transaction(),
        returned.transaction(),
        replacement.transaction(),
        known.transaction(),
        moved.transaction(),
    ] {
        writer.abort_unpublished(token).unwrap();
        assert_eq!(routing_snapshot(), before);
    }
    assert_eq!(std::fs::read_dir(group_pins()).unwrap().count(), 0);
}

#[test]
#[ignore = "Нужен собственный изолированный root-стенд"]
fn exact_desired_files_authority_and_reverification_are_required() {
    let (mut writer, _cleanup) = start();
    let (catalog, registry, authority) = policy_inputs(&[(TARGET, 1000), (ALIAS, 1000)], false);
    let request = writer
        .selected_executables(&registry, &catalog, &authority, 1)
        .unwrap();
    let before = routing_snapshot();
    for paths in [
        vec![TARGET],
        vec![TARGET, TARGET],
        vec![TARGET, CONTROL],
        vec![TARGET, ALIAS, CONTROL],
    ] {
        let files = paths.iter().map(|p| locate(Path::new(p))).collect();
        assert!(unsafe { writer.stage_verified_bindings(&request, files) }.is_err());
    }
    let wrong = Authority {
        user: Owner::LinuxUser { uid: 1001 },
        machine_admin: false,
    };
    assert!(writer
        .selected_executables(&registry, &catalog, &wrong, 2)
        .is_err());
    let set = unsafe {
        writer.stage_verified_bindings(
            &request,
            vec![locate(Path::new(TARGET)), locate(Path::new(ALIAS))],
        )
    }
    .unwrap();
    let sealed = writer
        .seal_for_publication(&set, request.desired_digest())
        .unwrap();
    assert!(writer.seal_for_publication(&set, [0; 32]).is_err());
    std::fs::copy(CONTROL, format!("{TARGET}.new")).unwrap();
    std::fs::rename(format!("{TARGET}.new"), TARGET).unwrap();
    assert!(writer
        .seal_for_publication(&set, request.desired_digest())
        .is_err());
    let newer = writer
        .selected_executables(&registry, &catalog, &authority, 2)
        .unwrap();
    assert!(writer.validate_sealed_bindings(&sealed, &newer).is_err());
    assert!(unsafe {
        writer.stage_verified_bindings(
            &request,
            vec![locate(Path::new(TARGET)), locate(Path::new(ALIAS))],
        )
    }
    .is_err());
    assert!(writer
        .selected_executables(&registry, &catalog, &authority, 1)
        .is_err());
    writer.abort_unpublished(set.transaction()).unwrap();
    assert_eq!(routing_snapshot(), before);
}

fn helper(mode: &str) -> std::process::Command {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--ignored", "--exact", "verified_child", "--nocapture"])
        .env("VERIFIED_CHILD", mode)
        .env("LD_PRELOAD", "/lab/verified-faults.so");
    command
}
#[test]
#[ignore = "Вспомогательный процесс собственного стенда"]
fn verified_child() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    require_lab();
    assert!(std::fs::read_to_string("/proc/cmdline")
        .unwrap()
        .split_ascii_whitespace()
        .any(|s| s == "aivpn.verified-bindings=1"));
    let mut writer = reopen(false);
    let recovered = writer.recover_verified_bindings().unwrap();
    match std::env::var("VERIFIED_CHILD").unwrap().as_str() {
        "release" => writer.abort_unpublished(recovered.staged()[0]).unwrap(),
        "stage" => {
            stage(&mut writer, &[(TARGET, 1000), (ALIAS, 1000)], 1);
        }
        "ambiguous" => {
            let (catalog, registry, authority) = policy_inputs(&[(TARGET, 1000)], false);
            assert!(writer
                .selected_executables(&registry, &catalog, &authority, 1)
                .is_err());
            assert!(writer
                .selected_executables(&registry, &catalog, &authority, 1)
                .is_err());
            assert!(writer.recover_verified_bindings().is_err());
        }
        _ => panic!("Неизвестный режим"),
    }
}

#[test]
#[ignore = "Нужен собственный изолированный root-стенд"]
fn actual_exec_lsm_wins_noexist_without_cookie_overwrite() {
    let (writer, _cleanup) = start();
    drop(writer);
    let status = helper("stage")
        .env("VERIFIED_MODE", "exec-race")
        .status()
        .unwrap();
    assert!(status.success());
    let result = std::fs::read_to_string("/lab/verified-race-result").unwrap();
    let fields: Vec<_> = result
        .split_ascii_whitespace()
        .map(|v| v.parse::<i128>().unwrap())
        .collect();
    assert_eq!(fields[0], -(libc::EEXIST as i128));
    assert_ne!(fields[1], fields[2]);
    assert_eq!(cookie(TARGET), Some(fields[2] as u64));
    let mut writer = reopen(false);
    let recovered = writer.recover_verified_bindings().unwrap();
    assert_eq!(recovered.staged().len(), 1);
    writer.abort_unpublished(recovered.staged()[0]).unwrap();
    std::fs::remove_file("/lab/verified-race-result").unwrap();
}

#[test]
#[ignore = "Нужен собственный изолированный root-стенд"]
fn sigkill_cuts_recover_exact_pending_completed_and_release_steps() {
    use std::os::unix::process::ExitStatusExt;
    let cuts: Vec<Vec<(&str, &str)>> = vec![
        vec![
            ("VERIFIED_RENAME_DIR", "state"),
            ("VERIFIED_RENAME_NTH", "3"),
        ],
        vec![
            ("VERIFIED_RENAME_DIR", "bindings"),
            ("VERIFIED_RENAME_NTH", "2"),
        ],
        vec![
            ("VERIFIED_RENAME_DIR", "bindings"),
            ("VERIFIED_RENAME_NTH", "3"),
        ],
        vec![("VERIFIED_MODE", "pending")],
        vec![("VERIFIED_PIN_CUT", "/instance")],
        vec![("VERIFIED_PIN_CUT", "/record")],
        vec![("VERIFIED_PIN_CUT", "/link")],
        vec![("VERIFIED_MODE", "completed")],
        vec![
            ("VERIFIED_RENAME_DIR", "bindings"),
            ("VERIFIED_RENAME_NTH", "4"),
        ],
    ];
    for (index, cut) in cuts.iter().enumerate() {
        let (writer, _cleanup) = start();
        let before = routing_snapshot();
        drop(writer);
        let status = helper("stage").envs(cut.iter().copied()).status().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL), "cut {index}");
        let mut writer = reopen(false);
        let recovered = writer.recover_verified_bindings().unwrap();
        assert_eq!(
            recovered.staged().len(),
            usize::from(index == 8),
            "cut {index}"
        );
        for token in recovered.staged() {
            writer.abort_unpublished(*token).unwrap();
        }
        assert_eq!(
            std::fs::read_dir(group_pins())
                .map(|d| d.count())
                .unwrap_or(0),
            0
        );
        assert_eq!(routing_snapshot(), before);
        // Новый verified stage после recovery не использует сожженный номер заново.
        let sealed = stage(&mut writer, &[(TARGET, 1000)], 2);
        assert!(sealed.groups()[0].id().get() > 2);
        writer.abort_unpublished(sealed.transaction()).unwrap();
    }
    let releases = [
        vec![
            ("VERIFIED_RENAME_DIR", "bindings"),
            ("VERIFIED_RENAME_NTH", "1"),
        ],
        vec![("VERIFIED_MODE", "releasing")],
        vec![("VERIFIED_UNLINK_CUT", "link")],
        vec![("VERIFIED_UNLINK_CUT", "record")],
        vec![("VERIFIED_UNLINK_CUT", "instance")],
        vec![("VERIFIED_MODE", "rmdir")],
    ];
    for cut in releases {
        let (mut writer, _cleanup) = start();
        let before = routing_snapshot();
        stage(&mut writer, &[(TARGET, 1000)], 1);
        drop(writer);
        let status = helper("release").envs(cut).status().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        let mut writer = reopen(false);
        assert!(writer
            .recover_verified_bindings()
            .unwrap()
            .staged()
            .is_empty());
        assert_eq!(std::fs::read_dir(group_pins()).unwrap().count(), 0);
        assert_eq!(routing_snapshot(), before);
    }
}

#[test]
#[ignore = "Нужен собственный изолированный root-стенд"]
fn ambiguous_durable_write_poisons_until_reopen() {
    let (writer, _cleanup) = start();
    drop(writer);
    let status = helper("ambiguous")
        .env("VERIFIED_MODE", "ambiguous")
        .env("VERIFIED_RENAME_DIR", "bindings")
        .env("VERIFIED_RENAME_NTH", "1")
        .status()
        .unwrap();
    assert!(status.success());
    let mut writer = reopen(false);
    writer.recover_verified_bindings().unwrap();
    let sealed = stage(&mut writer, &[(TARGET, 1000)], 2);
    writer.abort_unpublished(sealed.transaction()).unwrap();
}

#[test]
#[ignore = "Нужен собственный изолированный root-стенд"]
fn legacy_apr1_is_preserved_and_never_assumed_to_prove_a_group() {
    let (mut writer, _cleanup) = start();
    let (catalog, registry, authority) = inputs(Path::new(TARGET), NS);
    let plan = writer.prepare(&registry, &catalog, &authority).unwrap();
    let prepared = writer
        .prepare_executable(&plan, TARGET, locate(Path::new(TARGET)))
        .unwrap();
    let legacy = unsafe { writer.retain_executable(&plan, &prepared) }.unwrap();
    let sealed = stage(&mut writer, &[(TARGET, 1000)], 1);
    assert_ne!(sealed.groups()[0].link_id(), legacy.link_id());
    assert!(unsafe { writer.retain_executable(&plan, &prepared) }.is_err());
    assert_eq!(writer.recover_retentions().unwrap().len(), 1);
    writer.abort_unpublished(sealed.transaction()).unwrap();
    assert_eq!(
        writer.recover_retentions().unwrap()[0].link_id(),
        legacy.link_id()
    );
    writer.release_retention(legacy).unwrap();
}

#[test]
#[ignore = "Нужен собственный изолированный root-стенд"]
fn foreign_pending_and_completed_pins_are_preserved_on_refusal() {
    use std::os::unix::process::ExitStatusExt;
    let (writer, _cleanup) = start();
    drop(writer);
    assert_eq!(
        helper("stage")
            .env("VERIFIED_PIN_CUT", "/instance")
            .status()
            .unwrap()
            .signal(),
        Some(libc::SIGKILL)
    );
    let directory = std::fs::read_dir(group_pins())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let foreign = open(&static_pins().join("maps/file_counter"));
    pin(&foreign, &directory.join("unexpected"));
    let mut writer = reopen(false);
    assert!(writer.recover_verified_bindings().is_err());
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 2);
    assert!(directory.join("unexpected").exists());
    std::fs::remove_file(directory.join("unexpected")).unwrap();
    writer.recover_verified_bindings().unwrap();
    let sealed = stage(&mut writer, &[(TARGET, 1000)], 2);
    let directory = group_pins().join(format!("link_{:08x}", sealed.groups()[0].link_id()));
    let original = open(&directory.join("instance"));
    std::fs::remove_file(directory.join("instance")).unwrap();
    let wrong_class = open(&static_pins().join("programs/retain_application_inode"));
    pin(&wrong_class, &directory.join("instance"));
    assert!(writer.recover_verified_bindings().is_err());
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 3);
    std::fs::remove_file(directory.join("instance")).unwrap();
    pin(&original, &directory.join("instance"));
    writer.recover_verified_bindings().unwrap();
    writer.abort_unpublished(sealed.transaction()).unwrap();
}

#[test]
#[ignore = "Нужен собственный изолированный root-стенд"]
fn apr2_malformed_and_unfrozen_records_refuse_without_deletion() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let (mut writer, _cleanup) = start();
    let sealed = stage(&mut writer, &[(TARGET, 1000)], 1);
    let path = group_pins().join(format!("link_{:08x}/record", sealed.groups()[0].link_id()));
    let original = open(&path);
    let mut bytes = [0u8; 256];
    let zero = 0u32;
    let manifest_path = format!("{ROOT}/bindings/state.json");
    let manifest = std::fs::read(&manifest_path).unwrap();
    assert_eq!(
        unsafe {
            bpf_map_lookup_elem(
                original.as_raw_fd(),
                (&zero as *const u32).cast(),
                bytes.as_mut_ptr().cast(),
            )
        },
        0
    );
    for field in ["namespace", "boot", "image", "inventory", "seed"] {
        let mut damaged: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
        damaged["instance"][field][0] =
            (damaged["instance"][field][0].as_u64().unwrap() ^ 1).into();
        std::fs::write(&manifest_path, serde_json::to_vec(&damaged).unwrap()).unwrap();
        assert!(
            writer.recover_verified_bindings().is_err(),
            "injected instance {field}"
        );
        assert!(path.exists());
        std::fs::write(&manifest_path, &manifest).unwrap();
        writer.recover_verified_bindings().unwrap();
    }
    assert_eq!(&bytes[..4], b"APR2");
    assert_eq!(u32::from_le_bytes(bytes[132..136].try_into().unwrap()), 256);
    for (offset, freeze) in [
        (0, true),
        (136, true),
        (144, true),
        (180, true),
        (224, true),
        (255, false),
    ] {
        let mut damaged = bytes;
        if freeze {
            damaged[offset] ^= 1;
        }
        let raw = unsafe { bpf_map_create(2, c"apr2_fault".as_ptr(), 4, 256, 1, std::ptr::null()) };
        assert!(raw >= 0);
        let fake = unsafe { OwnedFd::from_raw_fd(raw) };
        assert_eq!(
            unsafe {
                bpf_map_update_elem(
                    fake.as_raw_fd(),
                    (&zero as *const u32).cast(),
                    damaged.as_ptr().cast(),
                    0,
                )
            },
            0
        );
        if freeze {
            assert_eq!(unsafe { bpf_map_freeze(fake.as_raw_fd()) }, 0);
        }
        std::fs::remove_file(&path).unwrap();
        pin(&fake, &path);
        unsafe extern "C" {
            fn bpf_obj_get_info_by_fd(fd: i32, info: *mut std::ffi::c_void, size: *mut u32) -> i32;
        }
        let mut info = [0u64; 64];
        let mut length = 512u32;
        assert_eq!(
            unsafe {
                bpf_obj_get_info_by_fd(fake.as_raw_fd(), info.as_mut_ptr().cast(), &mut length)
            },
            0
        );
        let record_id = (info[0] >> 32) as u32;
        let mut state: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
        state["groups"][0]["evidence"]["record"] = record_id.into();
        std::fs::write(&manifest_path, serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(
            writer.recover_verified_bindings().is_err(),
            "APR2 offset={offset} frozen={freeze}"
        );
        assert!(path.exists());
        std::fs::remove_file(&path).unwrap();
        pin(&original, &path);
        std::fs::write(&manifest_path, &manifest).unwrap();
        writer.recover_verified_bindings().unwrap();
    }
    writer.abort_unpublished(sealed.transaction()).unwrap();
}

#[test]
#[ignore = "Нужен собственный изолированный root-стенд"]
fn actual_zero_storage_and_exhausted_allocator_refuse_without_retention() {
    use std::os::fd::AsRawFd;
    let (mut writer, _cleanup) = start();
    let file = std::fs::File::open(TARGET).unwrap();
    let fd = file.as_raw_fd();
    let inode_map = open(&static_pins().join("maps/inode_tokens"));
    let zero_cookie = 0u64;
    assert_eq!(
        unsafe {
            bpf_map_update_elem(
                inode_map.as_raw_fd(),
                (&fd as *const i32).cast(),
                (&zero_cookie as *const u64).cast(),
                1,
            )
        },
        0
    );
    let (catalog, registry, authority) = policy_inputs(&[(TARGET, 1000)], false);
    let request = writer
        .selected_executables(&registry, &catalog, &authority, 1)
        .unwrap();
    assert!(
        unsafe { writer.stage_verified_bindings(&request, vec![locate(Path::new(TARGET))]) }
            .is_err()
    );
    let counter = open(&static_pins().join("maps/file_counter"));
    let zero = 0u32;
    let maximum = u64::MAX;
    assert_eq!(
        unsafe {
            bpf_map_update_elem(
                counter.as_raw_fd(),
                (&zero as *const u32).cast(),
                (&maximum as *const u64).cast(),
                0,
            )
        },
        0
    );
    let (catalog, registry, authority) = policy_inputs(&[(CONTROL, 1000)], false);
    let request = writer
        .selected_executables(&registry, &catalog, &authority, 2)
        .unwrap();
    assert!(
        unsafe { writer.stage_verified_bindings(&request, vec![locate(Path::new(CONTROL))]) }
            .is_err()
    );
    assert_eq!(file_counter(), u64::MAX);
    assert_eq!(
        std::fs::read_dir(group_pins())
            .map(|d| d.count())
            .unwrap_or(0),
        0
    );
}

#[test]
#[ignore = "Нужен собственный изолированный root-стенд"]
fn numeric_id_collision_cannot_substitute_a_program_for_the_instance_map() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    assert_eq!(unsafe { libc::geteuid() }, 0);
    require_lab();
    assert!(std::fs::read_to_string("/proc/cmdline")
        .unwrap()
        .split_ascii_whitespace()
        .any(|s| s == "aivpn.verified-bindings=1"));
    let library =
        unsafe { libc::dlopen(c"/lab/kernel-retention-faults.so".as_ptr(), libc::RTLD_NOW) };
    assert!(!library.is_null());
    let reserve: unsafe extern "C" fn() -> i32 = unsafe {
        std::mem::transmute(libc::dlsym(
            library,
            c"ar_retention_test_reserve_map_ids".as_ptr(),
        ))
    };
    let foreign: unsafe extern "C" fn(i32, *mut u32) -> i32 = unsafe {
        std::mem::transmute(libc::dlsym(
            library,
            c"ar_retention_test_same_id_program".as_ptr(),
        ))
    };
    assert_eq!(unsafe { reserve() }, 0);
    let (mut writer, _cleanup) = start();
    let sealed = stage(&mut writer, &[(TARGET, 1000)], 1);
    let directory = group_pins().join(format!("link_{:08x}", sealed.groups()[0].link_id()));
    let path = directory.join("instance");
    let original = open(&path);
    let mut identity = [0; 2];
    let raw = unsafe { foreign(original.as_raw_fd(), identity.as_mut_ptr()) };
    assert!(raw >= 0);
    let forged = unsafe { OwnedFd::from_raw_fd(raw) };
    assert_eq!(identity[0], 2);
    std::fs::remove_file(&path).unwrap();
    pin(&forged, &path);
    assert!(writer.recover_verified_bindings().is_err());
    assert!(writer.abort_unpublished(sealed.transaction()).is_err());
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 3);
    println!(
        "APR2_MAP_PROGRAM_COLLISION type={} actual_equal_id={}",
        identity[0], identity[1]
    );
    std::fs::remove_file(&path).unwrap();
    pin(&original, &path);
    assert!(writer
        .recover_verified_bindings()
        .unwrap()
        .staged()
        .is_empty());
    assert_eq!(std::fs::read_dir(group_pins()).unwrap().count(), 0);
    unsafe { libc::dlclose(library) };
}

#[test]
#[ignore = "Нужен собственный изолированный root-стенд"]
fn exhausted_transaction_and_missing_grouped_manifest_never_reset_identity() {
    let (writer, _cleanup) = start();
    drop(writer);
    let path = format!("{ROOT}/bindings/state.json");
    let original = std::fs::read(&path).unwrap();
    let mut state: serde_json::Value = serde_json::from_slice(&original).unwrap();
    state["next"] = u64::MAX.into();
    std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
    let mut writer = reopen(false);
    writer.recover_verified_bindings().unwrap();
    let (catalog, registry, authority) = policy_inputs(&[(TARGET, 1000)], false);
    let request = writer
        .selected_executables(&registry, &catalog, &authority, 1)
        .unwrap();
    assert!(
        unsafe { writer.stage_verified_bindings(&request, vec![locate(Path::new(TARGET))]) }
            .is_err()
    );
    assert_eq!(
        std::fs::read_dir(group_pins())
            .map(|d| d.count())
            .unwrap_or(0),
        0
    );
    drop(writer);
    std::fs::remove_file(&path).unwrap();
    let mut writer = lab::writer(false);
    assert!(writer
        .open_verified_bindings(
            StateDirectory::open(Path::new(&format!("{ROOT}/bindings"))).unwrap()
        )
        .is_err());
    assert!(writer.prepare(&registry, &catalog, &authority).is_err());
}

#[test]
#[ignore = "Нужен собственный изолированный root-стенд"]
fn grouped_stage_keeps_fork_and_mmap_preconditions() {
    let (mut writer, _cleanup) = start();
    let own = std::env::current_exe().unwrap();
    let (catalog, registry, authority) = policy_inputs(&[(own.to_str().unwrap(), 1000)], false);
    let request = writer
        .selected_executables(&registry, &catalog, &authority, 1)
        .unwrap();
    assert!(unsafe { writer.stage_verified_bindings(&request, vec![locate(&own)]) }.is_err());
    writer.recover_verified_bindings().unwrap();
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let denied = writer
            .recover_verified_bindings()
            .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied);
        unsafe { libc::_exit(if denied { 0 } else { 1 }) };
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert_eq!(status, 0);
    assert_eq!(
        std::fs::read_dir(group_pins())
            .map(|d| d.count())
            .unwrap_or(0),
        0
    );
}

#[test]
#[ignore = "Нужен собственный изолированный root-стенд"]
fn grouped_manifest_refuses_a_new_kernel_instance_in_the_same_namespace() {
    let (mut writer, _cleanup) = start();
    let sealed = stage(&mut writer, &[(TARGET, 1000)], 1);
    drop(writer);
    std::fs::remove_dir_all(static_pins()).unwrap();
    let mut fresh = lab::writer(true);
    assert!(fresh
        .open_verified_bindings(
            StateDirectory::open(Path::new(&format!("{ROOT}/bindings"))).unwrap()
        )
        .is_err());
    let directory = group_pins().join(format!("link_{:08x}", sealed.groups()[0].link_id()));
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 3);
}

fn saved_state(directory: &str) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(format!("{ROOT}/{directory}/state.json")).unwrap())
        .unwrap()
}

#[test]
#[ignore = "Нужен собственный изолированный root-стенд"]
fn returned_error_before_intent_does_not_leak_a_group_or_reuse_its_number() {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    let (mut writer, _cleanup) = start();
    assert_ne!(
        std::fs::metadata(CONTROL).unwrap().ino(),
        std::fs::metadata(TARGET).unwrap().ino()
    );
    assert!(CONTROL < TARGET);
    let file = std::fs::File::open(TARGET).unwrap();
    let fd = file.as_raw_fd();
    let inode_map = open(&static_pins().join("maps/inode_tokens"));
    let zero_cookie = 0u64;
    // Инъекция нулевого значения заставляет второй inode вернуть живой Err до Intent.
    assert_eq!(
        unsafe {
            bpf_map_update_elem(
                inode_map.as_raw_fd(),
                (&fd as *const i32).cast(),
                (&zero_cookie as *const u64).cast(),
                1,
            )
        },
        0
    );
    let (catalog, registry, authority) = policy_inputs(&[(CONTROL, 1000), (TARGET, 1000)], false);
    let request = writer
        .selected_executables(&registry, &catalog, &authority, 1)
        .unwrap();
    let burned = saved_state("state")["next"].as_u64().unwrap();
    assert!(unsafe {
        writer.stage_verified_bindings(
            &request,
            vec![locate(Path::new(TARGET)), locate(Path::new(CONTROL))],
        )
    }
    .is_err());
    let first_cookie = cookie(CONTROL).expect("Первый inode прошел acquisition");
    assert!(saved_state("state")["next"].as_u64().unwrap() > burned);
    assert!(saved_state("bindings")["transactions"]
        .as_array()
        .unwrap()
        .is_empty());
    let (catalog, registry, authority) = policy_inputs(&[(CONTROL, 1000)], false);
    // Следующая операция намеренно выполняется без ручного recovery.
    writer
        .selected_executables(&registry, &catalog, &authority, 2)
        .unwrap();
    assert!(
        saved_state("bindings")["groups"]
            .as_array()
            .unwrap()
            .is_empty(),
        "Ошибка до Intent оставила группу без claims и retention"
    );
    assert!(writer
        .recover_verified_bindings()
        .unwrap()
        .staged()
        .is_empty());
    assert!(!saved_state("state")["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|binding| binding["key"]["kind"] == "file_identity"));
    drop(writer);
    let mut writer = reopen(false);
    assert!(writer
        .recover_verified_bindings()
        .unwrap()
        .staged()
        .is_empty());
    let sealed = stage(&mut writer, &[(CONTROL, 1000)], 3);
    assert!(u64::from(sealed.aliases()[0].group().get()) > burned);
    assert_eq!(sealed.groups()[0].cookie(), first_cookie);
    println!(
        "PRE_INTENT_RETURNED_ERR burned_slot={burned} next_group={} cookie={first_cookie}",
        sealed.aliases()[0].group().get()
    );
    writer.abort_unpublished(sealed.transaction()).unwrap();
}

fn write_saved_state(directory: &str, value: &serde_json::Value) {
    std::fs::write(
        format!("{ROOT}/{directory}/state.json"),
        serde_json::to_vec(value).unwrap(),
    )
    .unwrap();
}

#[test]
#[ignore = "Нужен собственный изолированный root-стенд"]
fn persisted_orphan_recovery_preserves_live_groups_and_foreign_pins() {
    let (mut writer, _cleanup) = start();
    let abandoned = stage(&mut writer, &[(CONTROL, 1000)], 1);
    let burned = abandoned.aliases()[0].group().get();
    let mut orphan = saved_state("bindings")["groups"][0].clone();
    let reserved = saved_state("state")["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|binding| binding["number"] == burned)
        .unwrap()
        .clone();
    writer.abort_unpublished(abandoned.transaction()).unwrap();
    let live = stage(&mut writer, &[(TARGET, 1000)], 2);
    let mut manifest = saved_state("bindings");
    let live_group = manifest["groups"][0].clone();
    let mut slots = saved_state("state");
    let next = slots["next"].clone();
    drop(writer);
    // Восстанавливаем точную форму старой ошибки: свой slot и inode, без claims и evidence.
    orphan["evidence"] = serde_json::Value::Null;
    manifest["groups"].as_array_mut().unwrap().push(orphan);
    slots["bindings"].as_array_mut().unwrap().push(reserved);
    write_saved_state("bindings", &manifest);
    write_saved_state("state", &slots);
    let foreign_directory = group_pins().join("pending_ffffffff");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&foreign_directory)
        .unwrap();
    let foreign = open(&static_pins().join("maps/file_counter"));
    pin(&foreign, &foreign_directory.join("instance"));
    let mut writer = reopen(false);
    assert!(writer.recover_verified_bindings().is_err());
    assert_eq!(saved_state("bindings"), manifest);
    assert_eq!(saved_state("state"), slots);
    assert!(foreign_directory.join("instance").exists());
    std::fs::remove_file(foreign_directory.join("instance")).unwrap();
    std::fs::remove_dir(foreign_directory).unwrap();
    assert_eq!(
        writer.recover_verified_bindings().unwrap().staged(),
        &[live.transaction()]
    );
    assert_eq!(
        saved_state("bindings")["groups"],
        serde_json::json!([live_group])
    );
    assert_eq!(saved_state("state")["next"], next);
    assert!(!saved_state("state")["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|binding| binding["number"] == burned));
    assert_eq!(std::fs::read_dir(group_pins()).unwrap().count(), 1);
    drop(writer);
    let mut writer = reopen(false);
    assert_eq!(
        writer.recover_verified_bindings().unwrap().staged(),
        &[live.transaction()]
    );
    let resumed = writer.resume_verified_bindings(live.transaction()).unwrap();
    let sealed = writer
        .seal_for_publication(&resumed, live.desired_digest())
        .unwrap();
    assert_eq!(sealed.groups()[0].link_id(), live.groups()[0].link_id());
    let again = stage(&mut writer, &[(CONTROL, 1000), (TARGET, 1000)], 3);
    let control = again
        .aliases()
        .iter()
        .find(|alias| alias.path() == CONTROL)
        .unwrap();
    assert!(control.group().get() > burned);
    assert_eq!(cookie(CONTROL), Some(abandoned.groups()[0].cookie()));
    println!(
        "PERSISTED_ORPHAN burned_slot={burned} next_group={} live_link={}",
        control.group().get(),
        live.groups()[0].link_id()
    );
    writer.abort_unpublished(live.transaction()).unwrap();
    writer.abort_unpublished(again.transaction()).unwrap();
}

fn locate_selected(path: &str) -> aivpn_desktop_agent::linux::LocatedExecutable {
    use aivpn_desktop_agent::linux::{ExecutableFile, MountSnapshot};
    MountSnapshot::read_current()
        .unwrap()
        .locate(ExecutableFile::resolve_selected(Path::new(path)).unwrap())
        .unwrap()
}

fn replace_selected(target: &str) {
    let replacement = format!("{ALIAS}.new");
    std::os::unix::fs::symlink(target, &replacement).unwrap();
    std::fs::rename(replacement, ALIAS).unwrap();
}

#[test]
#[ignore = "Нужен собственный изолированный root-стенд"]
fn selected_symlink_stage_seal_and_resume_keep_selector_and_target_separate() {
    let (mut writer, _cleanup) = start();
    std::fs::copy("/usr/bin/verified-canary", TARGET).unwrap();
    replace_selected(TARGET);
    assert!(Path::new(ALIAS).is_symlink());
    let before = routing_snapshot();
    let (catalog, registry, authority) = policy_inputs(&[(TARGET, 1000), (ALIAS, 1000)], false);
    let request = writer
        .selected_executables(&registry, &catalog, &authority, 1)
        .unwrap();
    assert!(unsafe {
        writer.stage_verified_bindings(
            &request,
            vec![locate_selected(TARGET), locate_selected(TARGET)],
        )
    }
    .is_err());
    let set = unsafe {
        writer.stage_verified_bindings(
            &request,
            vec![locate_selected(TARGET), locate_selected(ALIAS)],
        )
    }
    .unwrap();
    let sealed = writer
        .seal_for_publication(&set, request.desired_digest())
        .unwrap();
    writer.validate_sealed_bindings(&sealed, &request).unwrap();
    assert_eq!(sealed.aliases().len(), 2);
    let direct = sealed
        .aliases()
        .iter()
        .find(|alias| alias.path() == TARGET)
        .unwrap();
    let selected = sealed
        .aliases()
        .iter()
        .find(|alias| alias.path() == ALIAS)
        .unwrap();
    assert_eq!(selected.owner(), Owner::LinuxUser { uid: 1000 });
    assert_ne!(selected.selector(), direct.selector());
    assert_eq!(selected.group(), direct.group());
    assert_eq!(selected.negative_keys(), direct.negative_keys());
    assert_eq!(sealed.groups().len(), 1);
    assert_eq!(cookie(TARGET), Some(sealed.groups()[0].cookie()));
    assert_eq!(cookie(ALIAS), cookie(TARGET));
    assert!(!Path::new("/lab/verified-entrypoint-canary").exists());
    assert_eq!(routing_snapshot(), before);
    assert!(writer.prepare(&registry, &catalog, &authority).is_err());
    let transaction = set.transaction();
    drop(set);
    drop(writer);
    let mut writer = reopen(false);
    assert_eq!(
        writer.recover_verified_bindings().unwrap().staged(),
        &[transaction]
    );
    let resumed = writer.resume_verified_bindings(transaction).unwrap();
    let again = writer
        .seal_for_publication(&resumed, request.desired_digest())
        .unwrap();
    assert_eq!(again.groups()[0].cookie(), sealed.groups()[0].cookie());
    assert_eq!(again.groups()[0].link_id(), sealed.groups()[0].link_id());
    assert_eq!(routing_snapshot(), before);
    assert!(!Path::new("/lab/verified-entrypoint-canary").exists());
    writer.abort_unpublished(transaction).unwrap();
}

#[test]
#[ignore = "Нужен собственный изолированный root-стенд"]
fn selected_symlink_live_seal_refuses_retarget_and_same_target_replacement() {
    let (mut writer, _cleanup) = start();
    replace_selected(TARGET);
    let before = routing_snapshot();
    let (catalog, registry, authority) = policy_inputs(&[(ALIAS, 1000)], false);
    for (serial, target) in [(1, TARGET), (2, CONTROL)] {
        replace_selected(TARGET);
        let request = writer
            .selected_executables(&registry, &catalog, &authority, serial)
            .unwrap();
        let set = unsafe { writer.stage_verified_bindings(&request, vec![locate_selected(ALIAS)]) }
            .unwrap();
        writer
            .seal_for_publication(&set, request.desired_digest())
            .unwrap();
        replace_selected(target);
        assert!(writer
            .seal_for_publication(&set, request.desired_digest())
            .is_err());
        writer.abort_unpublished(set.transaction()).unwrap();
    }
    assert_eq!(routing_snapshot(), before);
}

#[test]
#[ignore = "Нужен собственный изолированный root-стенд"]
fn selected_symlink_resume_proves_current_chain_and_retained_target() {
    let (mut writer, _cleanup) = start();
    replace_selected(TARGET);
    let (catalog, registry, authority) = policy_inputs(&[(ALIAS, 1000)], false);
    let request = writer
        .selected_executables(&registry, &catalog, &authority, 1)
        .unwrap();
    let set =
        unsafe { writer.stage_verified_bindings(&request, vec![locate_selected(ALIAS)]) }.unwrap();
    let transaction = set.transaction();
    drop(set);
    drop(writer);
    // Журнал хранит target group, но не историческую цепочку ссылок.
    replace_selected(TARGET);
    let mut writer = reopen(false);
    writer.recover_verified_bindings().unwrap();
    let resumed = writer.resume_verified_bindings(transaction).unwrap();
    writer
        .seal_for_publication(&resumed, request.desired_digest())
        .unwrap();
    drop(resumed);
    drop(writer);
    replace_selected(CONTROL);
    let mut writer = reopen(false);
    writer.recover_verified_bindings().unwrap();
    assert!(writer.resume_verified_bindings(transaction).is_err());
    writer.abort_unpublished(transaction).unwrap();
}
