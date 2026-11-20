use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn main() {
    println!("cargo:rerun-if-changed=native/linux");
    println!("cargo:rerun-if-changed=native/dns_ports.h");
    println!("cargo:rerun-if-env-changed=AIVPN_BPF_CLANG");
    if env::var_os("CARGO_FEATURE_LINUX_KERNEL").is_some()
        && env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
    {
        build_programs();
        build_path_hash();
    }
}

fn build_path_hash() {
    #[cfg(feature = "linux-kernel")]
    cc::Build::new()
        .file("native/linux/path_hash.c")
        .file("native/linux/snapshot.c")
        .file("native/linux/retention.c")
        .file("native/linux/installation.c")
        .warnings_into_errors(true)
        .compile("aivpn_path_hash");
}

fn build_programs() {
    build_variant("routing.bpf.o", false);
    build_variant("routing-snapshot.bpf.o", true);
}

fn build_variant(name: &str, snapshot: bool) {
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR не задан"));
    let clang = env::var_os("AIVPN_BPF_CLANG").unwrap_or_else(|| "clang".into());
    let mut command = Command::new(clang);
    command.args([
        "-target",
        "bpf",
        target_architecture(),
        "-O2",
        "-g",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-fdebug-compilation-dir=.",
        "-c",
        "native/linux/routing.bpf.c",
        "-o",
    ]);
    command.arg(output.join(name));
    if snapshot {
        command.arg("-DAP_BINDING_SNAPSHOT=1");
    }
    let result = command
        .output()
        .expect("Не удалось запустить clang с поддержкой BPF");
    require_success(result);
    require_object(&output.join(name));
}

fn target_architecture() -> &'static str {
    match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "-D__TARGET_ARCH_x86",
        Ok("aarch64") => "-D__TARGET_ARCH_arm64",
        _ => panic!("Ядро desktop-маршрутизации поддерживает Linux x86_64 и aarch64"),
    }
}

fn require_success(result: Output) {
    if !result.status.success() {
        panic!(
            "Не удалось собрать программы маршрутизации BPF:\n{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

fn require_object(path: &Path) {
    let metadata = path.metadata().expect("clang не создал объект BPF");
    assert!(metadata.len() > 0, "clang создал пустой объект BPF");
}
