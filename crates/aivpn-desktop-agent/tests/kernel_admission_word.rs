#![cfg(all(target_os = "linux", feature = "linux-kernel"))]

#[test]
fn canonical_word_serializes_admission_refresh_and_retirement() {
    run_model("admission_word", "CAS_MODEL_PASS");
}

#[test]
fn canonical_payload_survives_adoption_and_terminal_gc() {
    run_model("admission_payload", "PAYLOAD_MODEL_PASS");
}

#[test]
fn directory_prefix_hash_matches_full_path_across_byte_boundaries() {
    run_model("path_hash_prefix", "PREFIX_HASH_PASS");
}

fn run_model(name: &str, expected: &str) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = std::env::temp_dir().join(format!("aivpn-{name}-{}", std::process::id()));
    let compiled = std::process::Command::new("cc")
        .args([
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pthread",
            "-Wno-attributes",
            "-Wno-unused-function",
        ])
        .arg(root.join(format!("tests/support/{name}.c")))
        .arg("-o")
        .arg(&output)
        .status()
        .unwrap();
    assert!(compiled.success());
    let result = std::process::Command::new("timeout")
        .arg("15")
        .arg(&output)
        .output()
        .unwrap();
    std::fs::remove_file(output).unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains(expected));
}
