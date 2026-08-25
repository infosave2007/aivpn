use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn manifest(arch: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="aivpn" version="1.1.0.0" processorArchitecture="{arch}"/>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
          type="win32"
          name="Microsoft.Windows.Common-Controls"
          version="6.0.0.0"
          processorArchitecture="{arch}"
          publicKeyToken="6595b64144ccf1df"
          language="*"/>
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"#
    )
}

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    // Map Rust target arch to manifest processorArchitecture values
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "amd64",
        Ok("x86") => "x86",
        Ok("aarch64") => "arm64",
        _ => "amd64",
    };
    let manifest_path = out_dir.join("aivpn.manifest");
    fs::write(&manifest_path, manifest(arch)).expect("failed to write manifest");

    // Build .rc that embeds the manifest (resource id 1 = CREATEPROCESS_MANIFEST_RESOURCE_ID)
    // and the icon if present.
    // Icon lives in the shared brand folder (single source of truth across all
    // clients): repo-root assets/brand/win/aivpn.ico, i.e. ../../ from this crate.
    let icon_path = PathBuf::from("../../assets/brand/win/aivpn.ico")
        .canonicalize()
        .ok();
    // Escape backslashes in paths for the RC file format (Windows paths contain '\')
    let esc = |p: std::path::Display| p.to_string().replace('\\', "\\\\");
    let rc_content = if let Some(ref ico) = icon_path {
        format!(
            "1 RT_MANIFEST \"{manifest}\"\n1 ICON \"{icon}\"\n",
            manifest = esc(manifest_path.display()),
            icon = esc(ico.display())
        )
    } else {
        format!(
            "1 RT_MANIFEST \"{manifest}\"\n",
            manifest = esc(manifest_path.display())
        )
    };

    let rc_path = out_dir.join("resources.rc");
    let obj_path = out_dir.join("resources.o");
    fs::write(&rc_path, &rc_content).expect("failed to write .rc file");

    // Pick windres binary: cross-compilation uses the MinGW-prefixed binary.
    let windres = match env::var("TARGET").as_deref() {
        Ok("x86_64-pc-windows-gnu") => "x86_64-w64-mingw32-windres",
        Ok("i686-pc-windows-gnu") => "i686-w64-mingw32-windres",
        Ok("aarch64-pc-windows-gnu") => "aarch64-w64-mingw32-windres",
        _ => "windres",
    };

    let status = Command::new(windres)
        .args([
            "-O",
            "coff",
            rc_path.to_str().unwrap(),
            "-o",
            obj_path.to_str().unwrap(),
        ])
        .status();

    match status {
        Ok(s) if s.success() => {
            // Link the compiled resource object directly — the only reliable way with MinGW.
            println!("cargo:rustc-link-arg={}", obj_path.display());
        }
        Ok(s) => {
            panic!("windres exited with {s} — UAC manifest embedding failed; install mingw-w64-windres");
        }
        Err(e) => {
            panic!("windres not found ({e}) — UAC manifest embedding failed; install mingw-w64-windres");
        }
    }
}
