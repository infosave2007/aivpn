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
        id: "performance".into(),
        application: Selector::Executable {
            path: native_path(&root.join("perf-selected.exe"))?,
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
    let deadline = Instant::now() + Duration::from_secs(40);
    let mut controls = Vec::<Probe>::new();
    let mut current = None::<process::Process>;
    let mut next = 0;
    let mut assigned = false;
    let cases = [
        ("upload", "tcp-upload", 58083),
        ("download", "tcp-download", 58083),
        ("latency", "udp-latency", 58080),
    ];
    let outcome = service.run(&stop, |progress, coordinator| {
        match progress {
            WorkerProgress::Idle | WorkerProgress::Packets => (),
            WorkerProgress::TransportRegistered { endpoint } => println!("PERF_TRANSPORT {{\"endpoint\":{endpoint}}}"),
            WorkerProgress::Assigned { generation } if !assigned => {
                assigned = true;
                println!("PERF_ASSIGNMENT {}", serde_json::json!({"generation":generation,
                    "receipt":coordinator.transport_receipt()?,"statistics":coordinator.packet_statistics()?}));
                controls = probe_batch(root, "initial")?;
            }
            other => return Err(io::Error::other(format!("Performance worker: {other:?}"))),
        }
        for probe in &mut controls {
            if probe.result.is_none() && unsafe { WaitForSingleObject(probe.child.process.as_raw_handle(), 0) } == WAIT_OBJECT_0 {
                let code = probe.child.wait(Duration::from_millis(1))?;
                println!("PERF_CONTROL {}", serde_json::json!({"tag":probe.tag,"exit":code}));
                if code != 0 { return Err(io::Error::other("Нет рабочего control перед замером")); }
                probe.result = Some(code);
            }
        }
        if let Some(child) = &current {
            if unsafe { WaitForSingleObject(child.process.as_raw_handle(), 0) } == WAIT_OBJECT_0 {
                let code = child.wait(Duration::from_millis(1))?;
                let tag = cases[next - 1].0;
                let value: serde_json::Value = serde_json::from_slice(&std::fs::read(root.join(format!("perf-{tag}.log")))?)?;
                println!("PERF_RESULT {}", serde_json::json!({"tag":tag,"exit":code,"result":value,
                    "statistics":coordinator.packet_statistics()?}));
                if code != 0 || value["ok"] != true || value["reply"] != "observed=10.67.0.2" ||
                    (tag != "latency" && value["bytes"] != 8 * 1024 * 1024) {
                    return Err(io::Error::other("Performance probe не подтвердил данные через VPN"));
                }
                current = None;
            }
        }
        if assigned && controls.iter().all(|probe| probe.result == Some(0)) && current.is_none() {
            if next == cases.len() { stop.store(true, Ordering::Release); }
            else {
                let (tag, protocol, port) = cases[next];
                current = Some(process::spawn(&root.join("perf-selected.exe"),
                    &format!("{protocol} 10.67.0.1 {port}"), &root.join(format!("perf-{tag}.log")))?);
                next += 1;
            }
        }
        if Instant::now() >= deadline { return Err(io::Error::other("Performance timeout")); }
        Ok(())
    });
    drop(current);
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
        "PERF_COMPLETED {}",
        serde_json::json!({"uuid":run,"public_active":false})
    );
    Ok(())
}
