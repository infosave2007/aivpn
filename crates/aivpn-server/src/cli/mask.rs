//! CLI handlers for mask management: validate, sign, generate a signing key,
//! list, set a per-client override, and export signed bootstrap descriptors.
//!
//! Pure extract-module move from `main.rs` (ÉTAPE 1 decomposition, step 2).

use aivpn_common::mask::{IATDistType, MaskProfile, SizeDistType};
use aivpn_server::server_config::ServerFileConfig;
use aivpn_server::{ClientDatabase, ServerArgs};

/// `--gen-mask-signing-key PATH`: generate a fresh operator Ed25519 seed,
/// write it base64-encoded to PATH (0600), print the base64 public key.
pub(crate) fn handle_gen_mask_signing_key(path: &str) {
    use base64::Engine;
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let b64 = base64::engine::general_purpose::STANDARD.encode(seed);
    // MEDIUM (server-sec): create the key file atomically with 0600 already
    // set (O_EXCL + mode in a single open()) instead of write-then-chmod —
    // the latter leaves a window where the key briefly exists with the
    // process umask's (often world/group-readable) permissions before the
    // follow-up chmod lands. `create_new` doubles as the existing
    // don't-overwrite check, so the separate `exists()` probe is removed
    // (it was itself a TOCTOU race against this same open()).
    #[cfg(unix)]
    let opened = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    };
    #[cfg(not(unix))]
    let opened = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path);
    match opened {
        Ok(mut f) => {
            use std::io::Write;
            if let Err(e) = f.write_all(b64.as_bytes()) {
                eprintln!("Failed to write '{}': {}", path, e);
                std::process::exit(1);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            eprintln!("Refusing to overwrite existing key file '{}'", path);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to create '{}': {}", path, e);
            std::process::exit(1);
        }
    }
    let pubkey = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    println!("✅ Operator mask-signing key written to {}", path);
    println!(
        "   Public key (base64) — distribute to servers (--mask-operator-pubkey)\n   and clients (--mask-operator-pubkey / config mask_operator_pubkey):\n   {}",
        base64::engine::general_purpose::STANDARD.encode(pubkey)
    );
}

/// `--sign-mask-dir DIR`: sign every `*.json` mask in DIR in place (and its
/// nested reverse profile) with the operator key from `--mask-signing-key`, so
/// the corpus survives `mask_verify_mode=enforce`. The reverse profile is signed
/// first because the outer signature covers it.
pub(crate) fn handle_sign_mask_dir(dir: &str, args: &ServerArgs) {
    // Load server.json first so a config-only `mask_signing_key` works here
    // too (previously only the CLI/env flag was consulted).
    let config_path = crate::config_resolve::resolve_config_path(args);
    let file_config = crate::config_resolve::load_server_file_config(config_path.as_deref());
    let seed = match crate::config_resolve::resolve_mask_signing_key(args, file_config.as_ref()) {
        Some(s) => s,
        None => {
            eprintln!("--sign-mask-dir requires --mask-signing-key (or config mask_signing_key)");
            std::process::exit(1);
        }
    };
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Cannot read directory '{dir}': {e}");
            std::process::exit(1);
        }
    };
    let mut signed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let data = match std::fs::read_to_string(&path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("  skip {}: read failed: {e}", path.display());
                continue;
            }
        };
        let mut profile: aivpn_common::mask::MaskProfile = match serde_json::from_str(&data) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("  skip {}: not a MaskProfile: {e}", path.display());
                continue;
            }
        };
        if let Some(rev) = profile.reverse_profile.as_deref_mut() {
            rev.sign(&key);
        }
        profile.sign(&key);
        match serde_json::to_string_pretty(&profile) {
            Ok(out) => match std::fs::write(&path, out) {
                Ok(()) => {
                    signed += 1;
                    println!("  signed {}", path.display());
                }
                Err(e) => eprintln!("  FAILED {}: write: {e}", path.display()),
            },
            Err(e) => eprintln!("  FAILED {}: serialize: {e}", path.display()),
        }
    }
    println!("✅ Signed {signed} mask(s) in '{dir}' with the operator key.");
}

pub(crate) fn load_bootstrap_masks(
    file_config: Option<&ServerFileConfig>,
) -> Result<Vec<MaskProfile>, String> {
    let Some(files) = file_config.and_then(|config| config.bootstrap_mask_files.clone()) else {
        return Ok(Vec::new());
    };

    let mut masks = Vec::new();
    for file in files {
        let content = std::fs::read_to_string(&file).map_err(|e| format!("{}: {}", file, e))?;

        // Trim whitespace to check if file is empty
        let trimmed = content.trim();
        if trimmed.is_empty() {
            // Skip empty files silently
            continue;
        }

        // Try to parse as a single MaskProfile first
        if let Ok(mask) = serde_json::from_str::<MaskProfile>(trimmed) {
            masks.push(mask);
            continue;
        }

        // Try to parse as an array of MaskProfile
        if let Ok(arr) = serde_json::from_str::<Vec<MaskProfile>>(trimmed) {
            masks.extend(arr);
            continue;
        }

        // If both fail, return an error
        return Err(format!(
            "{}: invalid JSON format, expected MaskProfile object or array of MaskProfile objects",
            file
        ));
    }
    Ok(masks)
}

/// --list-masks: print mask JSON filenames from mask-dir
pub(crate) fn handle_list_masks(args: &ServerArgs, file_config: Option<&ServerFileConfig>) {
    let mask_dir = crate::config_resolve::resolve_mask_dir(args, file_config);
    let mut names: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&mask_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    names.push(stem.to_string());
                }
            }
        }
    }
    names.sort();
    if names.is_empty() {
        println!("No masks found in {}", mask_dir.display());
    } else {
        println!(
            "Available masks in {} ({}):",
            mask_dir.display(),
            names.len()
        );
        for name in &names {
            println!("  {}", name);
        }
    }
}

/// --export-bootstrap-descriptor: print the current signed descriptors as a
/// JSON array (identical shape to what already-connected clients receive),
/// for an operator to manually publish to a CDN/GitHub/Telegram/other
/// channel. Requires --key-file: an ephemeral key would produce a descriptor
/// signed by a key nobody's client trusts, so unlike normal server startup
/// (which tolerates an ephemeral key with just a warning), this exits.
pub(crate) fn handle_export_bootstrap_descriptor(
    args: &ServerArgs,
    bootstrap_masks: &[MaskProfile],
) {
    let Some(ref key_file) = args.key_file else {
        eprintln!("--export-bootstrap-descriptor requires --key-file (an ephemeral server key cannot be exported — no client trusts it)");
        std::process::exit(1);
    };
    let key_data = std::fs::read(key_file).unwrap_or_else(|e| {
        eprintln!("Failed to read key file '{}': {}", key_file, e);
        std::process::exit(1);
    });
    if key_data.len() != 32 {
        eprintln!("Key file must be exactly 32 bytes, got {}", key_data.len());
        std::process::exit(1);
    }
    let mut server_private_key = [0u8; 32];
    server_private_key.copy_from_slice(&key_data);

    let signing_key = aivpn_server::gateway::derive_server_signing_key(&server_private_key);
    let descriptors = aivpn_server::gateway::build_bootstrap_descriptors(
        &server_private_key,
        &signing_key,
        bootstrap_masks,
    );
    let json = serde_json::to_string_pretty(&descriptors).unwrap_or_else(|e| {
        eprintln!("Failed to serialize bootstrap descriptors: {}", e);
        std::process::exit(1);
    });

    match &args.bootstrap_output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &json) {
                eprintln!("Failed to write {}: {}", path, e);
                std::process::exit(1);
            }
            eprintln!(
                "Wrote {} signed bootstrap descriptor(s) to {}",
                descriptors.len(),
                path
            );
        }
        None => println!("{}", json),
    }
}

/// --set-mask NAME_OR_ID --mask-name MASK_NAME: write a mask override file
pub(crate) fn handle_set_mask(
    client_db: &ClientDatabase,
    name_or_id: &str,
    args: &ServerArgs,
    file_config: Option<&ServerFileConfig>,
) {
    let mask_name = match args.mask_name.as_deref() {
        Some(n) if !n.is_empty() => n,
        _ => {
            eprintln!("--mask-name is required with --set-mask");
            std::process::exit(1);
        }
    };
    // Validate client exists
    let client = client_db
        .find_by_name(name_or_id)
        .or_else(|| client_db.find_by_id(name_or_id));
    let client = match client {
        Some(c) => c,
        None => {
            eprintln!("Client '{}' not found", name_or_id);
            std::process::exit(1);
        }
    };
    // Validate mask exists (on disk or as a built-in preset)
    let mask_dir = crate::config_resolve::resolve_mask_dir(args, file_config);
    let on_disk = mask_dir.join(format!("{}.json", mask_name)).exists();
    let is_preset = aivpn_common::mask::preset_masks::by_id(mask_name).is_some();
    if !on_disk && !is_preset {
        eprintln!(
            "Mask '{}' not found in {} or built-in presets",
            mask_name,
            mask_dir.display()
        );
        std::process::exit(1);
    }
    // Write override: <mask_dir>/.overrides/<client-id>.mask
    let overrides_dir = mask_dir.join(".overrides");
    if let Err(e) = std::fs::create_dir_all(&overrides_dir) {
        eprintln!("Failed to create overrides dir: {}", e);
        std::process::exit(1);
    }
    let override_path = overrides_dir.join(format!("{}.mask", client.id));
    if let Err(e) = std::fs::write(&override_path, mask_name) {
        eprintln!("Failed to write mask override: {}", e);
        std::process::exit(1);
    }
    println!(
        "Mask override set: client '{}' ({}) → '{}'",
        client.name, client.id, mask_name
    );
}

pub(crate) fn handle_validate_mask(path: &str) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: cannot read {path}: {e}");
            std::process::exit(1);
        }
    };
    let profile: MaskProfile = match serde_json::from_str(&content) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: JSON parse failed in {path}: {e}");
            std::process::exit(1);
        }
    };

    let mut issues: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // signature_vector
    let sig_len = profile.signature_vector.len();
    if sig_len != 64 {
        issues.push(format!("signature_vector: {sig_len} floats (expected 64)"));
    } else if !profile.signature_vector.iter().all(|v| v.is_finite()) {
        issues.push("signature_vector: contains NaN or Inf".to_string());
    } else {
        let l2: f32 = profile
            .signature_vector
            .iter()
            .map(|v| v * v)
            .sum::<f32>()
            .sqrt();
        if l2 == 0.0 {
            warnings.push(
                "signature_vector is all-zeros — neural resonance inactive for this mask"
                    .to_string(),
            );
        }
    }

    // header_template vs eph_pub_offset
    let hdr_len = profile.header_template.len();
    if hdr_len != profile.eph_pub_offset as usize {
        issues.push(format!(
            "header_template length ({hdr_len}) != eph_pub_offset ({})",
            profile.eph_pub_offset
        ));
    }
    if profile.eph_pub_length != 32 {
        warnings.push(format!(
            "eph_pub_length = {} (expected 32 for X25519)",
            profile.eph_pub_length
        ));
    }
    let eph_end = profile.eph_pub_offset as u32 + profile.eph_pub_length as u32;
    if eph_end > 1350 {
        issues.push(format!(
            "eph region ends at byte {eph_end}, which exceeds 1350"
        ));
    }

    // size distribution bins sum
    if matches!(profile.size_distribution.dist_type, SizeDistType::Histogram) {
        let sum: f32 = profile.size_distribution.bins.iter().map(|b| b.2).sum();
        if (sum - 1.0).abs() > 0.02 {
            issues.push(format!(
                "size_distribution bins sum = {sum:.4} (expected 1.0 ± 0.02)"
            ));
        }
    }

    // FSM integrity
    let state_ids: std::collections::HashSet<u16> =
        profile.fsm_states.iter().map(|s| s.state_id).collect();
    if !state_ids.contains(&profile.fsm_initial_state) {
        issues.push(format!(
            "fsm_initial_state {} not found in fsm_states",
            profile.fsm_initial_state
        ));
    }
    for state in &profile.fsm_states {
        for t in &state.transitions {
            if !state_ids.contains(&t.next_state) {
                issues.push(format!(
                    "FSM state {}: transition to unknown state {}",
                    state.state_id, t.next_state
                ));
            }
        }
    }

    // expiry
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expires_str = if profile.expires_at == u64::MAX {
        "never".to_string()
    } else if profile.expires_at < now_secs {
        let days = (now_secs - profile.expires_at) / 86400;
        issues.push(format!("mask expired {days} day(s) ago"));
        format!("EXPIRED ({days} days ago)")
    } else {
        let days = (profile.expires_at - now_secs) / 86400;
        format!("{days} days remaining")
    };

    // ── Report ────────────────────────────────────────────────────────────
    println!("═══════════════════════════════════════════════════════");
    println!("Mask:     {} (v{})", profile.mask_id, profile.version);
    println!("Protocol: {:?}", profile.spoof_protocol);
    println!(
        "Header:   {} bytes, eph_pub @ {}..{}",
        hdr_len, profile.eph_pub_offset, eph_end
    );
    println!("Expires:  {expires_str}");

    let l2: f32 = if sig_len == 64 {
        profile
            .signature_vector
            .iter()
            .map(|v| v * v)
            .sum::<f32>()
            .sqrt()
    } else {
        0.0
    };
    println!("Sig vec:  {sig_len} floats, L2={l2:.3}");

    println!("───────────────────────────────────────────────────────");

    match profile.size_distribution.dist_type {
        SizeDistType::Histogram => {
            let bins = &profile.size_distribution.bins;
            let sum: f32 = bins.iter().map(|b| b.2).sum();
            println!("Size:     Histogram ({} bins), sum={sum:.3}", bins.len());
            for (lo, hi, p) in bins {
                println!("          [{lo}–{hi}]: {:.1}%", p * 100.0);
            }
        }
        SizeDistType::Parametric => {
            println!(
                "Size:     Parametric ({:?})",
                profile.size_distribution.parametric_type
            );
        }
    }

    let (jlo, jhi) = profile.iat_distribution.jitter_range_ms;
    let iat_type = match profile.iat_distribution.dist_type {
        IATDistType::Exponential => "Exponential",
        IATDistType::LogNormal => "LogNormal",
        IATDistType::Empirical => "Empirical",
        IATDistType::Gamma => "Gamma",
        IATDistType::Gmm => "GMM",
    };
    println!(
        "IAT:      {} params={:?} jitter=[{jlo:.1}, {jhi:.1}] ms",
        iat_type, profile.iat_distribution.params
    );

    println!(
        "FSM:      {} states, initial={}",
        profile.fsm_states.len(),
        profile.fsm_initial_state
    );
    println!("───────────────────────────────────────────────────────");

    for w in &warnings {
        println!("WARN:  {w}");
    }
    if issues.is_empty() {
        if warnings.is_empty() {
            println!("Result: PASS");
        } else {
            println!("Result: PASS (with warnings)");
        }
    } else {
        for issue in &issues {
            println!("FAIL:  {issue}");
        }
        println!("Result: FAIL ({} issue(s))", issues.len());
        std::process::exit(1);
    }
}
