use std::{env, fs, path::PathBuf};

fn main() {
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let windows = env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    if windows {
        match env::var("CARGO_CFG_TARGET_ENV").as_deref() {
            Ok("gnu") => {
                println!("cargo:rerun-if-changed=src/windows_load_config.c");
                cc::Build::new()
                    .file("src/windows_load_config.c")
                    .compile("aivpn_windows_load_config");
            }
            Ok("msvc") => println!("cargo:rustc-link-arg=/DEPENDENTLOADFLAG:0x800"),
            _ => panic!("Unsupported Windows linker environment"),
        }
    }
    let routing = windows && env::var_os("CARGO_FEATURE_DESKTOP_SERVICE").is_some();
    let driver = routing && env::var_os("AIVPN_ROUTING_DRIVER").is_some_and(|v| !v.is_empty());
    let altitude = if routing {
        env::var("AIVPN_ROUTING_ALTITUDE").unwrap_or_default()
    } else {
        String::new()
    };
    assert_eq!(
        driver,
        !altitude.is_empty(),
        "Driver and altitude must be configured together"
    );
    for (variable, name) in [
        ("AIVPN_WINTUN_DLL", "wintun.bin"),
        ("AIVPN_ROUTING_DRIVER", "routing-driver.bin"),
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
        let data = if windows && (variable != "AIVPN_ROUTING_DRIVER" || routing) {
            env::var_os(variable)
                .filter(|path| !path.is_empty())
                .map(|path| {
                    println!("cargo:rerun-if-changed={}", PathBuf::from(&path).display());
                    fs::read(path).expect("Cannot read configured Windows resource")
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        if !data.is_empty() {
            assert!(
                data.starts_with(b"MZ"),
                "Windows resource must be a PE image"
            );
        }
        fs::write(output.join(name), data).expect("Cannot prepare Windows resource");
    }
    println!("cargo:rerun-if-env-changed=AIVPN_ROUTING_ALTITUDE");
    if !altitude.is_empty() {
        let parts: Vec<_> = altitude.split('.').collect();
        assert!(
            (1..=2).contains(&parts.len())
                && (1..=6).contains(&parts[0].len())
                && parts
                    .iter()
                    .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
                && parts.get(1).is_none_or(|part| part.len() <= 16),
            "Invalid minifilter altitude"
        );
    }
    println!("cargo:rustc-env=AIVPN_EMBEDDED_ALTITUDE={altitude}");
}
