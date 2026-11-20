//! Изолированная сборка настоящего Control, backend и координатора.
use aivpn_desktop_agent::{
    control::Control,
    linux::{LinuxCoordinator, LinuxRoutingBackend, WorkerConfiguration, WorkerProgress},
    protocol::{Command, Outcome, Reply, Request},
    state::StateDirectory,
};
use aivpn_desktop_policy::*;
use std::{
    fs,
    io::{self, Write},
    num::NonZeroU64,
    os::unix::fs::DirBuilderExt,
    path::Path,
    time::{Duration, Instant},
};
const ROOT: &str = "/lab/product-state";
const NS: [u8; 16] = [0x76; 16];
const RUNTIME_SECS: u64 = 300;
pub fn run(
    mut progress: impl FnMut(&mut LinuxCoordinator, &WorkerProgress) -> io::Result<()>,
) -> io::Result<()> {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert!(fs::read_to_string("/proc/cmdline")?
        .split_whitespace()
        .any(|word| word == "aivpn.vertical-path=1"));
    assert_eq!(
        fs::read_to_string("/lab/.app-routing-guest")?,
        "aivpn-offline-routing-lab\n"
    );
    for path in [
        ROOT,
        &format!("{ROOT}/control"),
        &format!("{ROOT}/slots"),
        &format!("{ROOT}/bindings"),
        &format!("{ROOT}/network"),
    ] {
        if !Path::new(path).exists() {
            fs::DirBuilder::new().mode(0o700).create(path)?;
        }
    }
    let store = |part: &str| StateDirectory::open(Path::new(&format!("{ROOT}/{part}")));
    let mut backend =
        LinuxRoutingBackend::open(NS, store("slots")?, store("bindings")?, store("network")?)?;
    if std::env::var_os("VERTICAL_SYSTEM_DNS").is_some() {
        match std::env::var("VERTICAL_SYSTEM_DNS_PROVIDER").as_deref() {
            Ok("networkmanager") => backend.configure_network_manager_system_dns()?,
            Ok("resolved") => backend.configure_resolved_system_dns()?,
            Ok("resolvconf") => backend.configure_resolvconf_system_dns()?,
            Ok("auto") => backend.configure_automatic_system_dns()?,
            Err(std::env::VarError::NotPresent) | Ok("file") => {
                backend.configure_unmanaged_system_dns()?
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Неизвестный DNS provider стенда",
                ))
            }
        }
    }
    let control = Control::open(Platform::Linux, NS, store("control")?, backend)?;
    let authority = Authority {
        user: Owner::LinuxUser { uid: 0 },
        machine_admin: true,
    };
    let mut coordinator = LinuxCoordinator::new(control);
    let mut apply = |command| control_command(&mut coordinator, &authority, command);
    let response = apply(Command::RegisterProfile {
        owner: Owner::Machine {},
        registration_key: "vertical".into(),
        consumers: vec![
            Owner::LinuxUser { uid: 1000 },
            Owner::LinuxUser { uid: 65532 },
        ],
    })?;
    let profile = response["profile"].as_str().unwrap().to_owned();
    apply(Command::SetGlobalDns {
        profile: profile.clone(),
        acknowledge_outage: true,
    })?;
    for uid in [1000, 65532] {
        let previous = apply(Command::GetPolicy {
            owner: Owner::LinuxUser { uid },
        })?;
        if !previous["document"].is_null() {
            continue;
        }
        let rules = if uid == 1000 {
            vec![
                RuleDocument {
                    id: "selected-vpn".into(),
                    application: Selector::Executable {
                        path: "/usr/bin/binding-a".into(),
                    },
                    destination: Some("198.18.0.53/32".into()),
                    inherit_children: true,
                    action: Action::Vpn {
                        profile: profile.clone(),
                    },
                },
                RuleDocument {
                    id: "same-peer".into(),
                    application: Selector::Executable {
                        path: "/usr/bin/binding-a".into(),
                    },
                    destination: Some("192.0.2.1/32".into()),
                    inherit_children: true,
                    action: Action::Block {},
                },
            ]
        } else {
            vec![]
        };
        apply(Command::ApplyPolicy {
            document: PolicyDocument {
                split_enabled: true,
                version: 1,
                id: format!("vertical-{uid}"),
                generation: 1,
                platform: Platform::Linux,
                owner: Owner::LinuxUser { uid },
                default_action: if uid == 65532 {
                    Action::Block {}
                } else {
                    Action::System {}
                },
                dns: DnsPolicy::SharedVpn {
                    profile: profile.clone(),
                    acknowledge_outage: true,
                },
                rules,
            },
            expected_generation: None,
        })?;
    }
    println!(
        "PRODUCT_CONTROL {}",
        serde_json::json!({"status":coordinator.backend_state(),"publication":coordinator.publication(),"public_active":false})
    );
    io::stdout().flush()?;
    if std::env::var_os("VERTICAL_FAIL_SPAWN").is_some() {
        let path = Path::new("/usr/libexec/aivpn/aivpn");
        let saved = path.with_extension("held");
        fs::rename(path, &saved)?;
        fs::write(path, b"invalid executable image")?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
        let rejected = coordinator.start_profile(
            &profile,
            &authority,
            WorkerConfiguration::open(Path::new("/run/vertical-connection.json"))?
                .with_local_identity()?,
        );
        fs::remove_file(path)?;
        fs::rename(&saved, path)?;
        assert!(rejected.is_err());
        let response = coordinator.handle(
            &authority,
            Request::new(NonZeroU64::MIN, Command::ListProfiles {}),
        );
        let Outcome::Ok {
            reply: Reply::Profiles { profiles },
        } = response.result()
        else {
            panic!("Нет статуса профиля после отказа spawn")
        };
        assert!(profiles
            .iter()
            .all(|p| !p.session_active && !p.ready_ipv4 && !p.ready_ipv6));
        let prefix = format!("aivpn-worker-{}-", std::process::id());
        assert!(!fs::read_dir("/run")?.any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(&prefix)));
        println!("PRODUCT_SPAWN_REJECTED {{\"session_active\":false,\"ready_ipv4\":false,\"worker_homes\":0}}");
        io::stdout().flush()?;
    }
    let pid = coordinator.start_profile(
        &profile,
        &authority,
        WorkerConfiguration::open(Path::new("/run/vertical-connection.json"))?
            .with_local_identity()?,
    )?;
    println!(
        "PRODUCT_RESTRICTED {}",
        serde_json::json!({"pid":pid,"parent":std::process::id(),"creds_are_child_proof":false})
    );
    io::stdout().flush()?;
    let deadline = Instant::now() + Duration::from_secs(RUNTIME_SECS);
    println!(
        "PRODUCT_RUNTIME_LIMIT {}",
        serde_json::json!({"seconds": RUNTIME_SECS})
    );
    let dns_peer = std::env::var("VERTICAL_DNS_PROBE")
        .ok()
        .map(|value| value.parse::<std::net::SocketAddr>())
        .transpose()
        .map_err(io::Error::other)?;
    let mut dns_probe = None;
    let mut dns_done = false;
    let mut dns_guard = false;
    while Instant::now() < deadline {
        let event = coordinator.step(Duration::from_millis(100))?;
        progress(&mut coordinator, &event)?;
        match event {
            WorkerProgress::TransportRegistered { cookie } => println!(
                "PRODUCT_TRANSPORT {}",
                serde_json::json!({"cookie":cookie,"kernel_registered":true,"before_send":true})
            ),
            WorkerProgress::Assigned { generation } => {
                println!(
                    "PRODUCT_READY {}",
                    serde_json::json!({"generation":generation,"status":coordinator.backend_state(),"publication":coordinator.publication(),"public_active":false})
                );
                if let Some(peer) = dns_peer.filter(|_| !dns_done && dns_probe.is_none()) {
                    if !dns_guard && std::env::var_os("VERTICAL_DNS_GUARD").is_some() {
                        let _listeners = coordinator.protect_system_dns(Vec::new())?;
                        dns_guard = true;
                    }
                    let port = coordinator.dns_route(peer)?;
                    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
                    std::thread::spawn(move || {
                        let _ = sender.send(probe_dns(port));
                    });
                    dns_probe = Some(receiver);
                }
            }
            WorkerProgress::Disconnected | WorkerProgress::Exited => {
                println!("PRODUCT_STOPPED");
                break;
            }
            WorkerProgress::Idle => {}
            WorkerProgress::Reconnecting => println!("PRODUCT_RECONNECTING"),
        }
        if let Some(receiver) = &dns_probe {
            match receiver.try_recv() {
                Ok(result) => {
                    let result = result?;
                    println!("PRODUCT_DNS {}", result);
                    dns_done = true;
                    dns_probe = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => (),
                Err(error) => return Err(io::Error::other(error)),
            }
        }
        io::stdout().flush()?;
    }
    coordinator.stop_profile()?;
    if std::env::var_os("VERTICAL_RESTORE_SYSTEM_DNS").is_some() {
        for uid in [1000, 65532] {
            let policy = control_command(
                &mut coordinator,
                &authority,
                Command::GetPolicy {
                    owner: Owner::LinuxUser { uid },
                },
            )?;
            if let Some(generation) = policy["document"]["generation"].as_u64() {
                control_command(
                    &mut coordinator,
                    &authority,
                    Command::RemovePolicy {
                        owner: Owner::LinuxUser { uid },
                        expected_generation: generation,
                    },
                )?;
            }
        }
        control_command(&mut coordinator, &authority, Command::ClearGlobalDns {})?;
        println!("PRODUCT_DNS_RESTORED {{\"clear_committed\":true}}");
        io::stdout().flush()?;
    }
    Ok(())
}

fn control_command(
    coordinator: &mut LinuxCoordinator,
    authority: &Authority,
    command: Command,
) -> io::Result<serde_json::Value> {
    let result = coordinator.handle(authority, Request::new(NonZeroU64::MIN, command));
    match result.result() {
        Outcome::Ok { reply } => serde_json::to_value(reply).map_err(io::Error::other),
        other => Err(io::Error::other(format!(
            "Control отказал: {other:?}; {}",
            coordinator
                .failure_reason()
                .unwrap_or("причина не получена")
        ))),
    }
}

fn probe_dns(port: aivpn_desktop_agent::dns::DnsRoutePort) -> io::Result<serde_json::Value> {
    use std::os::fd::AsFd;
    let peer = port.peer();
    let socket = std::net::UdpSocket::bind(if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    port.register(socket.as_fd().try_clone_to_owned()?, move |result| {
        let _ = sender.send(result);
    })?;
    let _lease = receiver
        .recv_timeout(Duration::from_secs(5))
        .map_err(io::Error::other)??;
    socket.connect(peer)?;
    let mut wire = vec![0x56, 0x78, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    let name = format!("p{}.lab.test", std::process::id());
    for label in name.split('.') {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.extend_from_slice(&[0, 0, 1, 0, 1]);
    socket.send(&wire)?;
    let mut answer = [0u8; 4096];
    let size = socket.recv(&mut answer)?;
    if size < wire.len()
        || answer[..2] != wire[..2]
        || answer[2] & 0x80 == 0
        || answer[3] & 15 != 0
        || answer[size - 4..size] != [198, 51, 100, 77]
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS endpoint не подтвердил ответ",
        ));
    }
    Ok(
        serde_json::json!({"ok":true,"local":socket.local_addr()?.to_string(),"reply_bytes":size,"raw_probe_only":true,"os_dns_changed":false}),
    )
}
