use super::*;

fn phase_result(root: &Path, tag: &str, phase: u64) -> io::Result<Option<serde_json::Value>> {
    let text = std::fs::read_to_string(root.join(format!("nm-{tag}.log"))).unwrap_or_default();
    let mut current = false;
    let mut result = None;
    for line in text.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if value["phase_start"].as_u64() == Some(phase) {
            current = true;
            result = None;
        }
        if current && value.get("ok").is_some() {
            result = Some(value.clone());
        }
        if value["phase_complete"].as_u64() == Some(phase) {
            let result =
                result.ok_or_else(|| io::Error::other("Нет socket result перед completion"))?;
            if (value["exit"] == 0) != (result["ok"] == true) {
                return Err(io::Error::other("Socket result/exit расходятся"));
            }
            return Ok(Some(result));
        }
    }
    Ok(None)
}

fn signal(root: &Path, phase: u64) -> io::Result<()> {
    std::fs::write(root.join("nm-command.txt"), phase.to_string())
}

pub fn run(
    service: &mut WindowsService,
    authority: &Authority,
    profile: &str,
    root: &Path,
    run: &str,
    connection: &StateDirectory,
    mut restore: PolicyDocument,
    other_sid: &str,
) -> io::Result<()> {
    if other_sid == "S-1-5-18" || !other_sid.starts_with("S-1-5-21-") {
        return Err(io::Error::other("Нет отдельного SID native caller"));
    }
    let other = Owner::WindowsUser {
        sid: other_sid.into(),
    };
    let path_a = native_path(&root.join("nm-a.exe"))?;
    let path_b = native_path(&root.join("nm-b.exe"))?;
    let mut policy = restore.clone();
    policy.generation += 1;
    policy.rules = vec![
        RuleDocument {
            id: "a".into(),
            application: Selector::Executable {
                path: path_a.clone(),
            },
            destination: None,
            inherit_children: false,
            action: Action::Vpn {
                profile: profile.into(),
            },
        },
        RuleDocument {
            id: "b".into(),
            application: Selector::Executable {
                path: path_b.clone(),
            },
            destination: None,
            inherit_children: false,
            action: Action::Block {},
        },
    ];
    apply(
        service.coordinator(),
        authority,
        Command::ApplyPolicy {
            expected_generation: Some(restore.generation),
            document: policy.clone(),
        },
    )?;
    // U2 A не получает G2 от U1. После замены A его непроверенный alias
    // дает negative fact для G2; отдельный G3 проверяет живой SYSTEM путь.
    let other_policy = PolicyDocument {
        split_enabled: true,
        version: 1,
        id: "windows-memberships-other".into(),
        generation: 1,
        platform: Platform::Windows,
        owner: other.clone(),
        default_action: Action::System {},
        dns: restore.dns.clone(),
        rules: vec![
            RuleDocument {
                id: "a".into(),
                application: Selector::Executable { path: path_a },
                destination: None,
                inherit_children: false,
                action: Action::Block {},
            },
            RuleDocument {
                id: "b".into(),
                application: Selector::Executable { path: path_b },
                destination: None,
                inherit_children: false,
                action: Action::System {},
            },
        ],
    };
    apply(
        service.coordinator(),
        authority,
        Command::ApplyPolicy {
            expected_generation: None,
            document: other_policy,
        },
    )?;
    let mut children = Vec::new();
    for alias in ["a", "b", "system"] {
        for protocol in ["tcp", "udp"] {
            children.push(process::spawn(
                &root.join(format!("nm-{alias}.exe")),
                &format!(
                    "loop {protocol} 10.0.2.2 58080 {}",
                    root.join("nm-command.txt").display()
                ),
                &root.join(format!("nm-u1-{alias}-{protocol}.log")),
            )?);
        }
    }
    service.coordinator().start_profile(
        profile,
        authority,
        WorkerConfiguration::open(connection)?.with_local_identity()?,
        &root.join("aivpn.exe"),
        &root.join(format!("worker-{run}.log")),
    )?;
    let stop = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now() + Duration::from_secs(35);
    let mut phase = 0u64;
    let mut seen = std::collections::HashSet::new();
    let mut completed = None;
    service.run(&stop, |progress, coordinator| {
        match progress {
            WorkerProgress::Idle | WorkerProgress::Packets => (),
            WorkerProgress::TransportRegistered { endpoint } => println!("NM_TRANSPORT {{\"endpoint\":{endpoint}}}"),
            WorkerProgress::Assigned { generation } if phase == 0 => {
                println!("NM_ASSIGNMENT {}", serde_json::json!({"generation":generation,"receipt":coordinator.transport_receipt()?,"publication":coordinator.publication()}));
                phase = 1;
                println!("NM_PUBLICATION {}", serde_json::json!({"phase":phase,"bindings":coordinator.binding_receipts(),"publication":coordinator.publication()}));
                signal(root, phase)?;
            }
            other => return Err(io::Error::other(format!("NM worker: {other:?}"))),
        }
        if phase != 0 { for owner in ["u1", "u2"] { for alias in ["a", "b", "system"] { for protocol in ["tcp", "udp"] {
            let tag = format!("{owner}-{alias}-{protocol}");
            if seen.contains(&tag) { continue; }
            if let Some(result) = phase_result(root, &tag, phase)? {
                let route = match (owner, alias, phase) {
                    ("u1", "a", _) | ("u1", "b", 2) => "observed=10.67.0.2",
                    (_, "system", _) | ("u2", "b", 1) => "observed=172.31.10.2",
                    _ => "blocked",
                };
                println!("NM_SOCKET {}", serde_json::json!({"phase":phase,"tag":tag,"expected":route,"result":result}));
                let valid = if route == "blocked" {
                    result["ok"] == false && matches!(result["error"].as_u64(), Some(10013 | 10060))
                } else { result["ok"] == true && result["reply"] == route };
                if !valid { return Err(io::Error::other(format!("NM phase {phase}: {tag} != {route}"))); }
                seen.insert(tag);
            }
        } } } }
        if seen.len() == 12 {
            let ready = completed.get_or_insert_with(Instant::now);
            if ready.elapsed() >= Duration::from_millis(500) {
                if phase == 3 { signal(root, 99)?; stop.store(true, Ordering::Release); }
                else {
                    if phase == 1 {
                        std::fs::rename(root.join("nm-a.exe"), root.join("nm-a-old.exe"))?;
                        std::fs::hard_link(root.join("nm-b.exe"), root.join("nm-a.exe"))?;
                    } else { policy.rules.reverse(); }
                    let previous = policy.generation;
                    policy.generation += 1;
                    apply(coordinator, authority, Command::ApplyPolicy { expected_generation: Some(previous), document: policy.clone() })?;
                    phase += 1; seen.clear(); completed = None;
                    println!("NM_PUBLICATION {}", serde_json::json!({"phase":phase,"bindings":coordinator.binding_receipts(),"publication":coordinator.publication()}));
                    signal(root, phase)?;
                }
            }
        }
        if Instant::now() >= deadline { return Err(io::Error::other("NM timeout")); }
        Ok(())
    })?;
    for child in children {
        if child.wait(Duration::from_secs(1))? != 0 {
            return Err(io::Error::other("NM child exit"));
        }
    }
    apply(
        service.coordinator(),
        authority,
        Command::RemovePolicy {
            owner: other,
            expected_generation: 1,
        },
    )?;
    restore.generation = policy.generation + 1;
    apply(
        service.coordinator(),
        authority,
        Command::ApplyPolicy {
            expected_generation: Some(policy.generation),
            document: restore,
        },
    )?;
    println!(
        "NM_COMPLETED {}",
        serde_json::json!({"uuid":run,"phases":3,"ordinary_live_processes":true,"other_sid":other_sid,"public_active":false})
    );
    Ok(())
}
