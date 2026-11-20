use super::*;

fn signal(root: &Path, phase: u64) -> io::Result<()> {
    std::fs::write(root.join("held-command.txt"), phase.to_string())
}
fn result(root: &Path, tag: &str, phase: u64) -> Option<serde_json::Value> {
    std::fs::read_to_string(root.join(format!("held-{tag}.log")))
        .ok()?
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|value| value["phase"].as_u64() == Some(phase))
}

pub fn rule(root: &Path, profile: &str) -> io::Result<RuleDocument> {
    Ok(RuleDocument {
        id: "held".into(),
        application: Selector::Executable {
            path: native_path(&root.join("held-selected.exe"))?,
        },
        destination: None,
        inherit_children: false,
        action: Action::Vpn {
            profile: profile.into(),
        },
    })
}

pub fn run(
    service: &mut WindowsService,
    authority: &Authority,
    profile: &str,
    root: &Path,
    run: &str,
    connection: &StateDirectory,
    mut restore: PolicyDocument,
    case: &str,
) -> io::Result<()> {
    let recovery = case == "recover-held";
    let mut policy = restore.clone();
    if !recovery {
        policy.generation += 1;
    }
    policy.rules.push(rule(root, profile)?);
    if !recovery {
        apply(
            service.coordinator(),
            authority,
            Command::ApplyPolicy {
                expected_generation: Some(restore.generation),
                document: policy.clone(),
            },
        )?;
    }
    println!(
        "HELD_STATISTICS_BEFORE {}",
        serde_json::to_string(&service.coordinator().packet_statistics()?)?
    );
    if !recovery {
        signal(root, 0)?;
    }
    service.coordinator().start_profile(
        profile,
        authority,
        WorkerConfiguration::open(connection)?.with_local_identity()?,
        &root.join("aivpn.exe"),
        &root.join(if recovery {
            format!("worker-recovery-{run}.log")
        } else {
            format!("worker-{run}.log")
        }),
    )?;
    let stop = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now() + Duration::from_secs(35);
    let mut phase = 0u64;
    let mut stage = if recovery { 4 } else { 0 };
    let mut seen = std::collections::HashSet::new();
    let mut children = Vec::new();
    let mut fresh = Vec::<Probe>::new();
    let mut close_started = None;
    let outcome = service.run(&stop, |progress, coordinator| {
        match progress {
            WorkerProgress::Idle | WorkerProgress::Packets => (),
            WorkerProgress::TransportRegistered { endpoint } => println!("HELD_TRANSPORT {{\"endpoint\":{endpoint}}}"),
            WorkerProgress::Assigned { generation } => {
                println!("HELD_ASSIGNMENT {}", serde_json::json!({"generation":generation,"receipt":coordinator.transport_receipt()?,"publication":coordinator.publication()}));
                if stage == 0 {
                    for selected in [true, false] { for protocol in ["tcp", "udp"] {
                        let kind = if selected { "selected" } else { "system" };
                        children.push(process::spawn(&root.join(format!("held-{kind}.exe")),
                            &format!("{protocol} 10.0.2.2 58084 {}",root.join("held-command.txt").display()),
                            &root.join(format!("held-{kind}-{protocol}.log")))?);
                    } }
                    stage = 1; phase = 1; signal(root, phase)?;
                } else if stage == 4 {
                    stage = 5; phase = 3; signal(root, phase)?;
                    fresh = probe_batch(root, "recover")?;
                } else { return Err(io::Error::other("Неожиданное held assignment")); }
            }
            WorkerProgress::Exited if stage == 2 => {
                println!("HELD_WORKER_EXIT {}",serde_json::json!({"publication":coordinator.publication(),"state":coordinator.backend_state()}));
                stage = 3; phase = 2; signal(root, phase)?;
            }
            other => return Err(io::Error::other(format!("Held worker: {other:?}"))),
        }
        if matches!(stage, 1 | 3 | 5) { for selected in [true, false] { for protocol in ["tcp", "udp"] {
            let tag = format!("{}-{protocol}",if selected { "selected" } else { "system" });
            if seen.contains(&tag) { continue; }
            if let Some(value) = result(root,&tag,phase) {
                let expected = !selected || phase == 1;
                let reply = format!("observed={};phase={phase}",if selected { "10.67.0.2" } else { "172.31.10.2" });
                println!("HELD_SOCKET {}",serde_json::json!({"phase":phase,"tag":tag,"expected_reply":expected,"result":value}));
                if (value["ok"] == true) != expected || (expected && value["reply"] != reply) {
                    return Err(io::Error::other(format!("Held phase {phase}: {tag}")));
                }
                seen.insert(tag);
            }
        } } }
        for probe in &mut fresh {
            if probe.result.is_none() && unsafe { WaitForSingleObject(probe.child.process.as_raw_handle(),0) } == WAIT_OBJECT_0 {
                let code = probe.child.wait(Duration::from_millis(1))?;
                println!("FRESH_AFTER_HELD {}",serde_json::json!({"tag":probe.tag,"exit":code}));
                if code != 0 { return Err(io::Error::other("Новый socket после held fault не получил ответ")); }
                probe.result = Some(code);
            }
        }
        if seen.len() == 4 {
            if stage == 1 {
                if case == "service-held" {
                    println!("HELD_SERVICE_EXIT {}",serde_json::json!({"pid":std::process::id(),"after_working_replies":true,"drop_cleanup":false}));
                    std::io::Write::flush(&mut std::io::stdout())?;
                    unsafe { TerminateProcess(GetCurrentProcess(),77); }
                    return Err(io::Error::last_os_error());
                }
                let pid = coordinator.worker_pid().ok_or_else(|| io::Error::other("Нет held worker"))?;
                let process = process::owned(unsafe { OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE,0,pid) })?;
                process::checked(unsafe { TerminateProcess(process.as_raw_handle(),77) })?;
                if unsafe { WaitForSingleObject(process.as_raw_handle(),1000) } != WAIT_OBJECT_0 { return Err(io::ErrorKind::TimedOut.into()); }
                println!("HELD_WORKER_KILLED {}",serde_json::json!({"pid":pid,"after_working_replies":true}));
                stage = 2; seen.clear();
            } else if stage == 3 {
                coordinator.start_profile(profile,authority,WorkerConfiguration::open(connection)?.with_local_identity()?,
                    &root.join("aivpn.exe"),&root.join(format!("worker-recovery-{run}.log")))?;
                stage = 4; seen.clear();
            } else if stage == 5 && fresh.iter().all(|probe| probe.result == Some(0)) {
                signal(root,99)?;
                close_started = Some(Instant::now()); stage = 6;
                println!("HELD_CLOSE {}",serde_json::json!({"publication":coordinator.publication(),"worker_alive":coordinator.worker_pid()}));
            }
        }
        if stage == 6 && close_started.is_some_and(|time| time.elapsed() >= Duration::from_secs(1)) {
            stop.store(true,Ordering::Release);
        }
        if Instant::now() >= deadline { return Err(io::Error::other("Held timeout")); }
        Ok(())
    });
    signal(root, 99)?;
    for child in children {
        let _ = child.wait(Duration::from_secs(1));
    }
    restore.generation = policy.generation + 1;
    let restored = apply(
        service.coordinator(),
        authority,
        Command::ApplyPolicy {
            expected_generation: Some(policy.generation),
            document: restore,
        },
    );
    outcome?;
    restored?;
    println!(
        "HELD_STATISTICS_AFTER {}",
        serde_json::to_string(&service.coordinator().packet_statistics()?)?
    );
    println!(
        "HELD_COMPLETED {}",
        serde_json::json!({"uuid":run,"same_sockets":true,"case":case,"public_active":false})
    );
    Ok(())
}
