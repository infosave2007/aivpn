use super::*;

pub fn run(
    service: &mut WindowsService,
    authority: &Authority,
    profile: &str,
    root: &Path,
    run: &str,
    connection: &StateDirectory,
    mut restore: PolicyDocument,
) -> io::Result<()> {
    let mut policy = restore.clone();
    policy.generation += 1;
    policy.rules.push(RuleDocument {
        id: "terminal".into(),
        application: Selector::Executable {
            path: native_path(&root.join("terminal-selected.exe"))?,
        },
        destination: None,
        inherit_children: false,
        action: Action::Vpn {
            profile: profile.into(),
        },
    });
    apply(
        service.coordinator(),
        authority,
        Command::ApplyPolicy {
            expected_generation: Some(restore.generation),
            document: policy.clone(),
        },
    )?;
    service.coordinator().start_profile(
        profile,
        authority,
        WorkerConfiguration::open(connection)?.with_local_identity()?,
        &root.join("aivpn.exe"),
        &root.join(format!("worker-{run}.log")),
    )?;
    let stop = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now() + Duration::from_secs(25);
    let mut controls = Vec::<Probe>::new();
    let mut assigned = false;
    let mut child = None::<process::Process>;
    let mut completed = None;
    let outcome = service.run(&stop, |progress, coordinator| {
        match progress {
            WorkerProgress::Idle | WorkerProgress::Packets | WorkerProgress::TransportRegistered { .. } => (),
            WorkerProgress::Assigned { generation } if !assigned => {
                assigned = true;
                println!("TERMINAL_ASSIGNMENT {}", serde_json::json!({"generation":generation,"statistics":coordinator.packet_statistics()?}));
                controls = probe_batch(root, "initial")?;
            }
            other => return Err(io::Error::other(format!("Terminal worker: {other:?}"))),
        }
        for probe in &mut controls {
            if probe.result.is_none() && unsafe { WaitForSingleObject(probe.child.process.as_raw_handle(), 0) } == WAIT_OBJECT_0 {
                let code = probe.child.wait(Duration::from_millis(1))?;
                println!("TERMINAL_CONTROL {}", serde_json::json!({"tag":probe.tag,"exit":code}));
                if code != 0 { return Err(io::Error::other("Нет рабочего control перед terminal case")); }
                probe.result = Some(code);
            }
        }
        if let Some(process) = &child {
            if completed.is_none() && unsafe { WaitForSingleObject(process.process.as_raw_handle(), 0) } == WAIT_OBJECT_0 {
                let code = process.wait(Duration::from_millis(1))?;
                let value: serde_json::Value = serde_json::from_slice(&std::fs::read(root.join("terminal.log"))?)?;
                println!("TERMINAL_RESULT {}", serde_json::json!({"exit":code,"result":value,"statistics":coordinator.packet_statistics()?}));
                let records = value.as_array().ok_or_else(|| io::Error::other("Нет terminal outcomes"))?;
                if code != 0 || records.len() != 8 || records.iter().enumerate().any(|(i, r)| r["error"] != if i < 4 {10061} else {10035}) {
                    return Err(io::Error::other("Terminal outcome не совпал"));
                }
                completed = Some(Instant::now());
            }
        } else if assigned && controls.iter().all(|probe| probe.result == Some(0)) {
            println!("TERMINAL_BEFORE {}", serde_json::to_string(&coordinator.packet_statistics()?)?);
            child = Some(process::spawn(&root.join("terminal-selected.exe"), "", &root.join("terminal.log"))?);
        }
        if completed.is_some_and(|at| at.elapsed() >= Duration::from_secs(2)) {
            println!("TERMINAL_AFTER {}", serde_json::to_string(&coordinator.packet_statistics()?)?);
            stop.store(true, Ordering::Release);
        }
        if Instant::now() >= deadline { return Err(io::Error::other("Terminal timeout")); }
        Ok(())
    });
    drop(child);
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
        "TERMINAL_COMPLETED {}",
        serde_json::json!({"uuid":run,"public_active":false})
    );
    Ok(())
}
