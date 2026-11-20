mod held;
mod memberships;
mod performance;
mod process;
mod terminal;
use aivpn_client::service_dns::WindowsDnsRelay;
use aivpn_desktop_agent::{
    control::Control,
    protocol::{Command, Outcome, Reply, Request},
    state::{StateDirectory, StateFile},
    windows::{
        ControlClient, WindowsCoordinator, WindowsRoutingBackend, WindowsService,
        WorkerConfiguration, WorkerProgress,
    },
};
use aivpn_desktop_policy::*;
use std::{
    io,
    num::NonZeroU64,
    os::windows::io::AsRawHandle,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*, System::Threading::*};

fn stage(name: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{name}: {error}"))
}

fn native_path(path: &Path) -> io::Result<String> {
    let file = std::fs::File::open(path)?;
    let mut text = vec![0; 4096];
    let count = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            text.as_mut_ptr(),
            text.len() as u32,
            VOLUME_NAME_NT,
        )
    };
    if count == 0 || count as usize >= text.len() {
        return Err(io::Error::last_os_error());
    }
    Ok(String::from_utf16(&text[..count as usize])
        .map_err(io::Error::other)?
        .to_lowercase())
}
fn apply(
    coordinator: &mut WindowsCoordinator,
    authority: &Authority,
    command: Command,
) -> io::Result<serde_json::Value> {
    let reply = coordinator.handle(authority, Request::new(NonZeroU64::MIN, command));
    match reply.result() {
        Outcome::Ok { reply } => serde_json::to_value(reply).map_err(io::Error::other),
        result => Err(io::Error::other(format!(
            "Control: {result:?}; {}",
            coordinator.failure_detail().unwrap_or("Нет ошибки backend")
        ))),
    }
}
struct Probe {
    tag: String,
    child: process::Process,
    result: Option<u32>,
    expected: bool,
}
fn probe_batch(root: &Path, phase: &str) -> io::Result<Vec<Probe>> {
    let mut probes = Vec::new();
    for (selected, protocol) in [(true, "tcp"), (false, "tcp"), (true, "udp"), (false, "udp")] {
        let base = format!(
            "{}-{protocol}",
            if selected { "selected" } else { "system" }
        );
        let tag = if phase == "initial" {
            base
        } else {
            format!("{phase}-{base}")
        };
        let app = root.join(if selected {
            "netprobe-selected.exe"
        } else {
            "netprobe-system.exe"
        });
        let child = process::spawn(
            &app,
            &format!("{protocol} 10.0.2.2 58080"),
            &root.join(format!("{tag}.log")),
        )?;
        probes.push(Probe {
            tag,
            child,
            result: None,
            expected: phase != "down" || !selected,
        });
    }
    Ok(probes)
}
fn dns_probe_batch(root: &Path, run: &str) -> io::Result<Vec<Probe>> {
    let mut probes = Vec::new();
    for (selected, protocol) in [(true, "tcp"), (false, "tcp"), (true, "udp"), (false, "udp")] {
        let tag = format!(
            "{}-{protocol}",
            if selected { "selected" } else { "system" }
        );
        let app = root.join(if selected {
            "netprobe-selected.exe"
        } else {
            "netprobe-system.exe"
        });
        let child = process::spawn(
            &app,
            &format!("dns-{protocol} {tag}-{run}.lab.test 58080"),
            &root.join(format!("{tag}.log")),
        )?;
        probes.push(Probe {
            tag,
            child,
            result: None,
            expected: true,
        });
    }
    Ok(probes)
}
pub fn run() -> io::Result<()> {
    let root = Path::new(r"C:\AivpnLab\VerticalPath");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("run.json"))?)?;
    let run = manifest["uuid"]
        .as_str()
        .filter(|s| s.len() == 32 && s.bytes().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let interface = manifest["interface"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let case = manifest["case"].as_str().unwrap_or("roundtrip");
    if !matches!(
        case,
        "roundtrip"
            | "worker-kill"
            | "service-exit"
            | "recover"
            | "memberships"
            | "restore-memberships"
            | "worker-held"
            | "service-held"
            | "recover-held"
            | "restore-held"
            | "performance"
            | "terminal"
            | "dns"
    ) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let worker_fault = case == "worker-kill";
    let directory = root.join("product-state-runtime-v1");
    let _parent = StateDirectory::open(&directory).map_err(|e| stage("Каталог состояния", e))?;
    let store = |part: &str| StateDirectory::open(&directory.join(part));
    let namespace = [17; 16];
    let name = format!("vertical-{run}");
    let upstream = manifest["dns_upstream"]
        .as_str()
        .unwrap_or("198.18.0.53:53")
        .parse()
        .map_err(|_| io::ErrorKind::InvalidInput)?;
    let mut dns =
        WindowsDnsRelay::bind(upstream).map_err(|e| stage("Локальные слушатели DNS", e))?;
    let mut service = WindowsService::bind(&name, || {
        let slots = store("slots").map_err(|e| stage("Хранилище слотов", e))?;
        let mut backend = WindowsRoutingBackend::open(namespace, slots, interface)
            .map_err(|e| stage("Открытие backend", e))?;
        backend
            .configure_system_dns()
            .map_err(|e| stage("Предварительная проверка DNS ОС", e))?;
        let store = store("control").map_err(|e| stage("Хранилище Control", e))?;
        let control = Control::open(Platform::Windows, namespace, store, backend)
            .map_err(|e| stage("Восстановление Control", e))?;
        Ok(WindowsCoordinator::new(control))
    })?;
    let authority = Authority {
        user: Owner::WindowsUser {
            sid: "S-1-5-18".into(),
        },
        machine_admin: true,
    };
    let registered = apply(
        service.coordinator(),
        &authority,
        Command::RegisterProfile {
            owner: authority.user.clone(),
            registration_key: "vertical".into(),
            consumers: vec![],
        },
    )?;
    let profile = registered["profile"]
        .as_str()
        .ok_or_else(|| io::Error::other("Нет профиля"))?
        .to_owned();
    apply(
        service.coordinator(),
        &authority,
        Command::SetGlobalDns {
            profile: profile.clone(),
            acknowledge_outage: true,
        },
    )?;
    let mut document = PolicyDocument {
        split_enabled: true,
        version: 1,
        id: "windows-vertical-path".into(),
        generation: 1,
        platform: Platform::Windows,
        owner: authority.user.clone(),
        default_action: Action::System {},
        dns: DnsPolicy::SharedVpn {
            profile: profile.clone(),
            acknowledge_outage: true,
        },
        rules: vec![RuleDocument {
            id: "selected".into(),
            application: Selector::Executable {
                path: native_path(&root.join("netprobe-selected.exe"))?,
            },
            destination: None,
            inherit_children: false,
            action: Action::Vpn {
                profile: profile.clone(),
            },
        }],
    };
    let stored = apply(
        service.coordinator(),
        &authority,
        Command::GetPolicy {
            owner: authority.user.clone(),
        },
    )?;
    if !stored["document"].is_null() {
        document.generation = stored["document"]["generation"]
            .as_u64()
            .ok_or_else(|| io::Error::other("Нет поколения policy"))?;
        let mut expected = document.clone();
        if matches!(case, "recover-held" | "restore-held") {
            expected.rules.push(held::rule(root, &profile)?);
        }
        if stored["document"] != serde_json::to_value(&expected)? {
            if case != "restore-memberships" {
                return Err(io::Error::other("Recovery policy не совпадает"));
            }
            let old: PolicyDocument = serde_json::from_value(stored["document"].clone())?;
            let a = native_path(&root.join("nm-a.exe"))?;
            let b = native_path(&root.join("nm-b.exe"))?;
            if old.id != document.id || old.owner != document.owner || old.default_action != document.default_action ||
                old.dns != document.dns || old.rules.len() != 2 || old.rules.iter().any(|rule|
                    !matches!(&rule.application, Selector::Executable { path } if path == &a || path == &b)) {
                return Err(io::Error::other("Неизвестная policy, восстановление отказано"));
            }
            let sid = manifest["other_sid"]
                .as_str()
                .ok_or_else(|| io::Error::other("Нет SID recovery"))?;
            let owner = Owner::WindowsUser { sid: sid.into() };
            let other = apply(
                service.coordinator(),
                &authority,
                Command::GetPolicy {
                    owner: owner.clone(),
                },
            )?;
            if !other["document"].is_null() {
                if other["document"]["id"] != "windows-memberships-other" {
                    return Err(io::Error::other("Чужая policy recovery"));
                }
                let generation = other["document"]["generation"]
                    .as_u64()
                    .ok_or_else(|| io::Error::other("Нет поколения recovery"))?;
                apply(
                    service.coordinator(),
                    &authority,
                    Command::RemovePolicy {
                        owner,
                        expected_generation: generation,
                    },
                )?;
            }
            document.generation += 1;
            apply(
                service.coordinator(),
                &authority,
                Command::ApplyPolicy {
                    expected_generation: Some(old.generation),
                    document: document.clone(),
                },
            )?;
            println!(
                "RESTORED_MEMBERSHIPS {}",
                serde_json::json!({"uuid":run,"generation":document.generation,"publication":service.coordinator().publication()})
            );
        }
        println!(
            "RECOVERED_POLICY {}",
            serde_json::json!({"generation":document.generation,"publication":service.coordinator().publication()})
        );
    } else {
        if case == "recover" {
            return Err(io::Error::other("Нет сохраненной recovery policy"));
        }
        apply(
            service.coordinator(),
            &authority,
            Command::ApplyPolicy {
                expected_generation: None,
                document: document.clone(),
            },
        )?;
    }
    if case == "restore-held" {
        let previous = document.generation;
        document.generation += 1;
        apply(
            service.coordinator(),
            &authority,
            Command::ApplyPolicy {
                expected_generation: Some(previous),
                document,
            },
        )?;
        println!(
            "RESTORED_HELD {}",
            serde_json::json!({"uuid":run,"publication":service.coordinator().publication(),"statistics":service.coordinator().packet_statistics()?})
        );
        return Ok(());
    }
    if case == "restore-memberships" {
        return Ok(());
    }
    let mut connection = store("connection")?;
    connection.replace(
        StateFile::Committed,
        &std::fs::read(root.join("connection.json"))?,
    )?;
    if matches!(
        case,
        "worker-held" | "service-held" | "recover-held" | "restore-held"
    ) {
        return held::run(
            &mut service,
            &authority,
            &profile,
            root,
            run,
            &connection,
            document,
            case,
        );
    }
    if case == "terminal" {
        return terminal::run(
            &mut service,
            &authority,
            &profile,
            root,
            run,
            &connection,
            document,
        );
    }
    if case == "performance" {
        return performance::run(
            &mut service,
            &authority,
            &profile,
            root,
            run,
            &connection,
            document,
        );
    }
    if case == "memberships" {
        let sid = manifest["other_sid"]
            .as_str()
            .ok_or_else(|| io::Error::other("Нет SID второго native caller"))?;
        return memberships::run(
            &mut service,
            &authority,
            &profile,
            root,
            run,
            &connection,
            document,
            sid,
        );
    }
    let config = WorkerConfiguration::open(&connection)?.with_local_identity()?;
    let worker_log = if case == "recover" {
        format!("worker-recovery-{run}.log")
    } else {
        format!("worker-{run}.log")
    };
    let worker = service.coordinator().start_profile(
        &profile,
        &authority,
        config,
        &root.join("aivpn.exe"),
        &root.join(worker_log),
    )?;
    println!(
        "PRODUCT_WORKER {}",
        serde_json::json!({"pid":worker,"separate_process":true,"suspended_identity_verified":true,"restricted_token":true,"job":true,"inherited_handles":4,"inherited_station_access":service.coordinator().inherited_station_access(),"state":service.coordinator().backend_state()})
    );
    let control_name = name.clone();
    let control = std::thread::spawn(move || {
        ControlClient::call(
            &control_name,
            &Request::new(NonZeroU64::new(77).unwrap(), Command::Status {}),
        )
    });
    let stop = Arc::new(AtomicBool::new(false));
    let mut diagnosed = std::collections::HashSet::new();
    let mut diagnostic_poll = Instant::now();
    let mut probes = Vec::<Probe>::new();
    let mut stage = 0;
    let mut completed_at = None;
    let mut failed = false;
    let deadline = Instant::now() + Duration::from_secs(30);
    service.run(&stop, |progress, coordinator| {
        dns.progress(coordinator, &progress)?;
        match progress {
            WorkerProgress::Idle | WorkerProgress::Packets => (),
            WorkerProgress::TransportRegistered { endpoint } => println!("PRODUCT_TRANSPORT {}", serde_json::json!({"endpoint":endpoint,"before_send":true})),
            WorkerProgress::Assigned { generation } => {
                println!("ASSIGNMENT {}", serde_json::json!({"generation":generation,"publication":coordinator.publication(),"transport_receipt":coordinator.transport_receipt()?,"state":"Guarded","prepared_scope":false}));
                if stage == 0 { probes = if case == "dns" { dns_probe_batch(root, run)? } else { probe_batch(root, if case == "recover" { "recover" } else { "initial" })? }; stage = 1; }
                else if stage == 4 { probes = probe_batch(root, "recover")?; stage = 5; }
                else { return Err(io::Error::other("Неожиданное назначение во время probes")); }
            }
            WorkerProgress::Exited if worker_fault && stage == 2 => {
                println!("WORKER_EXIT_OBSERVED {}", serde_json::json!({"publication":coordinator.publication(),"state":coordinator.backend_state()}));
                probes = probe_batch(root, "down")?; stage = 3;
            }
            other => return Err(io::Error::other(format!("Worker: {other:?}; receipt={:?}", coordinator.transport_receipt()))),
        }
        let inspect_failure = diagnostic_poll.elapsed() >= Duration::from_millis(100);
        if inspect_failure { diagnostic_poll = Instant::now(); }
        for Probe { tag, child, result, expected } in &mut probes {
            // Probe сообщает отказ до короткой задержки выхода. Это только
            // активная диагностика после socket error: DIAGNOSE может claim origin.
            // Его результат не подтверждает состояние identity до отказа.
            if case == "roundtrip" && inspect_failure && result.is_none() && !diagnosed.contains(tag) {
                if let Ok(bytes) = std::fs::read(root.join(format!("{tag}.log"))) {
                    if serde_json::from_slice::<serde_json::Value>(&bytes).ok().is_some_and(|v| v["ok"] == false) {
                        println!("FAILED_IDENTITY {tag} {:?}", coordinator.diagnose_process(&child.process, "10.0.2.2".parse().unwrap()));
                        diagnosed.insert(tag.clone());
                    }
                }
            }
            if result.is_none() && unsafe { WaitForSingleObject(child.process.as_raw_handle(), 0) } == WAIT_OBJECT_0 {
                let code = child.wait(Duration::from_millis(1))?;
                println!("PROBE {tag} exit={code} expected_reply={expected}"); failed |= (code == 0) != *expected; *result = Some(code);
            }
        }
        if !probes.is_empty() && probes.iter().all(|probe| probe.result.is_some()) {
            let finished = completed_at.get_or_insert_with(Instant::now);
            #[cfg(feature = "desktop-worker-lab")]
            if finished.elapsed() < Duration::from_millis(5) {
                println!("DNS_NATIVE_COUNTERS {}", serde_json::json!({"words":coordinator.lab_counters()?,"statistics":coordinator.packet_statistics()?,"diagnostic_only":true}));
            }
            if finished.elapsed() >= Duration::from_millis(500) {
                if case == "service-exit" && stage == 1 {
                    if failed { return Err(io::Error::other("Нет рабочего состояния до service fault")); }
                    println!("SERVICE_EXIT {}", serde_json::json!({"pid":std::process::id(),"after_working_replies":true,"drop_cleanup":false}));
                    std::io::Write::flush(&mut std::io::stdout())?;
                    // Завершение собственного harness без Drop coordinator.
                    // CDO, job и transport освобождает Windows при смерти процесса.
                    unsafe { TerminateProcess(GetCurrentProcess(), 77); }
                    return Err(io::Error::last_os_error());
                }
                if worker_fault && stage == 1 {
                    if failed { return Err(io::Error::other("Нет рабочего состояния до worker fault")); }
                    // PID получен из удержанного coordinator process. Handle не дает
                    // сетевой authority и используется только для собственного fault.
                    let pid = coordinator.worker_pid().ok_or_else(|| io::Error::other("Нет worker для fault"))?;
                    let process = process::owned(unsafe { OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, 0, pid) })?;
                    process::checked(unsafe { TerminateProcess(process.as_raw_handle(), 77) })?;
                    if unsafe { WaitForSingleObject(process.as_raw_handle(), 1000) } != WAIT_OBJECT_0 { return Err(io::ErrorKind::TimedOut.into()); }
                    println!("WORKER_KILLED {}", serde_json::json!({"pid":pid,"after_working_replies":true}));
                    stage = 2; probes.clear(); completed_at = None;
                } else if worker_fault && stage == 3 {
                    let worker = coordinator.start_profile(&profile, &authority, WorkerConfiguration::open(&connection)?.with_local_identity()?, &root.join("aivpn.exe"), &root.join(format!("worker-recovery-{run}.log")))?;
                    println!("WORKER_RECOVERY {}", serde_json::json!({"pid":worker,"state":coordinator.backend_state()}));
                    stage = 4; probes.clear(); completed_at = None;
                } else if stage == 1 || stage == 5 { stop.store(true, Ordering::Release); }
            }
        }
        if Instant::now() >= deadline { return Err(io::Error::new(io::ErrorKind::TimedOut, "Нет завершения product probes")); }
        Ok(())
    })?;
    dns.close();
    if case == "dns" {
        apply(
            service.coordinator(),
            &authority,
            Command::RemovePolicy {
                owner: authority.user.clone(),
                expected_generation: document.generation,
            },
        )?;
        apply(
            service.coordinator(),
            &authority,
            Command::ClearGlobalDns {},
        )?;
        println!(
            "DNS_RESTORED {}",
            serde_json::json!({"uuid":run,"owned_restore":true})
        );
    }
    let response = control
        .join()
        .map_err(|_| io::Error::other("Поток Control завершился аварийно"))??;
    match response.result() {
        Outcome::Ok {
            reply: Reply::Status { backend, .. },
        } => println!(
            "PRODUCT_CONTROL {}",
            serde_json::json!({"backend":backend,"authenticated_pipe":true})
        ),
        _ => return Err(io::Error::other("Нет ответа Control")),
    }
    println!(
        "COMPLETED {}",
        serde_json::json!({"uuid":run,"case":case,"prepared_scope":false,"separate_worker":true,"public_active":false})
    );
    if failed {
        return Err(io::Error::other("Один из probes не получил ответ"));
    }
    Ok(())
}
