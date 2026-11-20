#![cfg(all(target_os = "linux", feature = "linux-kernel"))]
use std::{fs, path::Path};

struct Temporary(std::path::PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .unwrap()
        .1
        .split_once(end)
        .unwrap()
        .0
}
fn generated_header(root: &Path) -> String {
    let routing = fs::read_to_string(root.join("native/linux/routing.bpf.c")).unwrap();
    let choice = fs::read_to_string(root.join("native/linux/policy-choice.h")).unwrap();
    let legacy = section(
        &routing,
        "#ifndef AP_BINDING_SNAPSHOT\n",
        "\n#else\n#include \"binding-evaluate.h\"",
    );
    let same = &choice[choice
        .find("static __always_inline int same_origin")
        .unwrap()
        ..choice
            .find("static __always_inline const struct process_state")
            .unwrap()];
    let available = section(
        &choice,
        "static __always_inline const struct origin_hash *\n",
        "\n/* Выбор правила",
    );
    format!("#ifdef TEST_SNAPSHOT\n#include \"binding-evaluate.h\"\n#else\n{legacy}\n#endif\n{same}\nstatic __always_inline const struct origin_hash *\n{available}\n")
}
#[test]
fn incomplete_known_file_cannot_confirm_missing_path_facts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let temporary =
        std::env::temp_dir().join(format!("aivpn-incomplete-origin-{}", std::process::id()));
    fs::create_dir(&temporary).unwrap();
    let _cleanup = Temporary(temporary.clone());
    fs::write(
        temporary.join("production-origin.h"),
        generated_header(root),
    )
    .unwrap();
    let mut failures = Vec::new();
    for mode in ["legacy", "snapshot"] {
        let binary = temporary.join(mode);
        let mut command = std::process::Command::new("cc");
        command.args([
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-unused-function",
        ]);
        if mode == "snapshot" {
            command.arg("-DTEST_SNAPSHOT=1");
        }
        let compile = command
            .arg("-I")
            .arg(root.join("native/linux"))
            .arg("-I")
            .arg(&temporary)
            .arg(root.join("tests/support/incomplete_origin.c"))
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let result = std::process::Command::new(&binary).output().unwrap();
        println!("{mode}: {}", String::from_utf8_lossy(&result.stdout));
        if !result.status.success() {
            failures.push(mode);
        }
    }
    fs::remove_dir_all(temporary).unwrap();
    assert!(failures.is_empty(), "Неполные facts приняты: {failures:?}");
}
