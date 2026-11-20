use super::*;
use crate::classic_windows::is_elevated;
use base64::Engine;
use std::path::Path;
use std::{
    fs::File,
    io::{Read, Write},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    process::{Command, Stdio},
};
use windows_sys::Win32::{
    Foundation::*,
    System::{
        SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW},
        Threading::*,
    },
    UI::{Shell::*, WindowsAndMessaging::SW_HIDE},
};

const COMMON: &str = include_str!("../../../../deploy/windows-setup-common.ps1");
const BASIC: &str = include_str!("../../../../deploy/install-client-image.ps1");
const ROUTING: &str = include_str!("../../../../deploy/install-app-routing.ps1");
const WINTUN: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/wintun.bin"));
const DRIVER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/routing-driver.bin"));
const ALTITUDE: &str = env!("AIVPN_EMBEDDED_ALTITUDE");

pub(super) fn resources() -> (bool, bool) {
    (
        !WINTUN.is_empty(),
        !DRIVER.is_empty() && !ALTITUDE.is_empty(),
    )
}

fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain([0]).collect()
}
fn image_snapshot() -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(std::env::current_exe()?)?
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 512 * 1024 * 1024 || !bytes.starts_with(b"MZ") {
        return Err(io::Error::other("Недопустимый образ клиента"));
    }
    Ok(bytes)
}
fn powershell() -> io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let mut path = vec![0u16; 32768];
    let len = unsafe { GetSystemDirectoryW(path.as_mut_ptr(), path.len() as u32) };
    if len == 0 || len as usize >= path.len() {
        return Err(io::Error::last_os_error());
    }
    Ok(PathBuf::from(OsString::from_wide(&path[..len as usize]))
        .join(r"WindowsPowerShell\v1.0\powershell.exe"))
}

pub(super) fn environment() -> io::Result<Vec<(OsString, OsString)>> {
    use std::os::windows::ffi::OsStringExt;
    let shell = powershell()?;
    let system_dir = shell
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| io::Error::other("Нет системного каталога"))?;
    let mut buffer = vec![0u16; 32768];
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 || length as usize >= buffer.len() {
        return Err(io::Error::last_os_error());
    }
    let windows = PathBuf::from(OsString::from_wide(&buffer[..length as usize]));
    let drive = windows
        .to_string_lossy()
        .get(..2)
        .ok_or_else(|| io::Error::other("Нет системного тома"))?
        .to_owned();
    let shell_dir = shell.parent().unwrap();
    Ok(vec![
        ("SystemRoot".into(), windows.clone().into_os_string()),
        ("windir".into(), windows.clone().into_os_string()),
        ("SystemDrive".into(), drive.into()),
        (
            "PATH".into(),
            std::env::join_paths([system_dir, windows.as_path(), shell_dir])
                .map_err(io::Error::other)?,
        ),
        (
            "PSModulePath".into(),
            shell_dir.join("Modules").into_os_string(),
        ),
        ("TEMP".into(), windows.join("Temp").into_os_string()),
        ("TMP".into(), windows.join("Temp").into_os_string()),
    ])
}

fn program_files() -> io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath},
    };
    let mut raw = std::ptr::null_mut();
    if unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, std::ptr::null_mut(), &mut raw) }
        < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut length = 0;
    while unsafe { *raw.add(length) } != 0 {
        length += 1;
    }
    let path = PathBuf::from(OsString::from_wide(unsafe {
        std::slice::from_raw_parts(raw, length)
    }));
    unsafe {
        CoTaskMemFree(raw.cast());
    }
    Ok(path)
}

pub(super) fn ensure() -> io::Result<PathBuf> {
    let root = program_files()?.join("AIVPN");
    let image = root.join("aivpn.exe");
    let trusted = |path: &Path| {
        aivpn_desktop_agent::windows::classic::TrustedClassicImage::open(path).is_ok()
    };
    let snapshot = image_snapshot()?;
    if trusted(&image)
        && trusted(&root.join("wintun.dll"))
        && std::fs::read(&image).is_ok_and(|bytes| bytes == snapshot)
    {
        return Ok(image);
    }
    install("install", false, None)?;
    if !trusted(&image) || !trusted(&root.join("wintun.dll")) {
        return Err(io::Error::other("Не подтверждена системная установка"));
    }
    Ok(image)
}

fn routing_resource(routing: bool, action: &str) -> io::Result<(Vec<u8>, String)> {
    if !routing || action != "install" || !DRIVER.is_empty() {
        return Ok((DRIVER.to_vec(), ALTITUDE.to_owned()));
    }
    use aivpn_desktop_agent::windows::classic::TrustedClassicImage;
    let root = program_files()?.join("AIVPNRouting");
    let _receipt = TrustedClassicImage::open(&root.join("installation.json")).map_err(|_| {
        io::Error::other(
            "Нужен включенный в сборку или уже установленный проверенный драйвер app-routing",
        )
    })?;
    let mut bytes = Vec::new();
    File::open(root.join("installation.json"))?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::other("Превышен размер журнала установки"));
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if !matches!(value["version"].as_u64(), Some(1 | 2)) {
        return Err(io::Error::other("Неизвестный формат журнала драйвера"));
    }
    let altitude = value["altitude"]
        .as_str()
        .ok_or_else(|| io::Error::other("Нет высоты установленного драйвера"))?;
    let parts: Vec<_> = altitude.split('.').collect();
    if !(1..=2).contains(&parts.len())
        || !(1..=6).contains(&parts[0].len())
        || parts.iter().any(|part| {
            part.is_empty() || part.len() > 16 || !part.bytes().all(|b| b.is_ascii_digit())
        })
    {
        return Err(io::Error::other("Неверная высота драйвера"));
    }
    let _driver = TrustedClassicImage::open(&root.join("aivpn-app-routing.sys"))?;
    let mut driver = Vec::new();
    File::open(root.join("aivpn-app-routing.sys"))?
        .take(32 * 1024 * 1024 + 1)
        .read_to_end(&mut driver)?;
    if driver.len() > 32 * 1024 * 1024 || !driver.starts_with(b"MZ") {
        return Err(io::Error::other("Неверный образ установленного драйвера"));
    }
    Ok((driver, altitude.to_owned()))
}

pub(super) fn install(action: &str, routing: bool, expected: Option<&str>) -> io::Result<ExitCode> {
    let routing = routing
        || (action == "install"
            && program_files()?
                .join("AIVPNRouting/installation.json")
                .exists());
    if routing && !cfg!(feature = "desktop-service") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "В этой сборке нет app-routing",
        ));
    }
    let image = image_snapshot()?;
    let digest = blake3::hash(&image).to_hex().to_string();
    if expected.is_some_and(|value| value != digest) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Образ изменился до повышения прав",
        ));
    }
    // Проверка ресурса предшествует UAC; права не запрашиваются заведомо зря.
    let (driver, altitude) = routing_resource(routing, action)?;
    if !is_elevated() {
        return elevate(action, routing, &digest);
    }
    if action == "install"
        && (WINTUN.is_empty() || (routing && (driver.is_empty() || altitude.is_empty())))
    {
        return Err(io::Error::other(
            "В сборку не включены необходимые установочные ресурсы",
        ));
    }
    let action = match action {
        "install" => "Install",
        "uninstall" => "Uninstall",
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Неверное действие установки",
            ))
        }
    };
    let resources = [
        ("aivpn.exe", image.as_slice()),
        ("wintun.dll", WINTUN),
        ("aivpn-app-routing.sys", driver.as_slice()),
    ];
    let mut script =
        String::from("$ErrorActionPreference='Stop'\n$ProgressPreference='SilentlyContinue'\n[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)\nSet-StrictMode -Version Latest\n");
    script.push_str(COMMON.trim_start_matches('\u{feff}'));
    script.push_str("\n$stageParent=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'AIVPNSetup'\nNew-ProtectedDirectory $stageParent $false\n$bundle=Join-Path $stageParent ([Guid]::NewGuid().ToString('N'))\nNew-ProtectedDirectory $bundle $false\ntry {\n$inputStream=[Console]::OpenStandardInput()\n");
    for (name, bytes) in resources {
        script.push_str(&format!("$remaining={}\n$file=New-Object IO.FileStream((Join-Path $bundle '{name}'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)\ntry {{ $buffer=New-Object byte[] 65536; while($remaining -gt 0) {{ $read=$inputStream.Read($buffer,0,[Math]::Min($buffer.Length,$remaining));if($read -le 0){{throw 'Неполный внутренний комплект'}};$file.Write($buffer,0,$read);$remaining-=$read }};$file.Flush($true) }} finally {{$file.Dispose()}}\n",bytes.len()));
    }
    let basic =
        base64::engine::general_purpose::STANDARD.encode(BASIC.trim_start_matches('\u{feff}'));
    let route =
        base64::engine::general_purpose::STANDARD.encode(ROUTING.trim_start_matches('\u{feff}'));
    script.push_str(&format!("$basic=[ScriptBlock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{basic}')))\n$routing=[ScriptBlock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{route}')))\n"));
    let compiled = if cfg!(feature = "desktop-service") {
        "$true"
    } else {
        "$false"
    };
    if routing {
        // При обновлении общий EXE заменяет сама транзакция службы, после ее остановки.
        script.push_str("$appMetadata=Join-Path (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AIVPNRouting') 'installation.json'\n");
        if action == "Install" {
            script.push_str(&format!("if(-not(Test-Path -LiteralPath $appMetadata)){{ & $basic -Action Install -SourceDirectory $bundle -RoutingCompiled {compiled} }}else{{ & $basic -Action Prepare -SourceDirectory $bundle -RoutingCompiled {compiled} }}\n"));
            script.push_str(&format!("$files=@{{}};foreach($name in @('aivpn.exe','wintun.dll','aivpn-app-routing.sys')){{$files[$name]=Hash (Join-Path $bundle $name)}}\n$manifest=([pscustomobject]@{{version=1;altitude='{altitude}';files=$files}})|ConvertTo-Json -Depth 6 -Compress\n& $routing -Action Install -SourceDirectory $bundle -BundleManifest $manifest\n& $basic -Action Install -SourceDirectory $bundle -RoutingCompiled {compiled}\n"));
        } else {
            script.push_str("& $routing -Action Uninstall -SourceDirectory $bundle\n");
        }
    } else {
        script.push_str(&format!(
            "& $basic -Action {action} -SourceDirectory $bundle -RoutingCompiled {compiled}\n"
        ));
    }
    script.push_str("} finally { if(Test-Path -LiteralPath $bundle){Remove-Item -LiteralPath $bundle -Recurse -Force} }\n");
    // В argv идет только короткий загрузчик. Сам скрипт и бинарные ресурсы
    // передаются раздельными кадрами через stdin, без лимита command line Windows.
    let bootstrap=format!("$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';$inputStream=[Console]::OpenStandardInput();$scriptBytes=New-Object byte[] {}; $offset=0;while($offset -lt $scriptBytes.Length){{$read=$inputStream.Read($scriptBytes,$offset,$scriptBytes.Length-$offset);if($read -le 0){{throw 'Неполный установщик'}};$offset+=$read}};& ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($scriptBytes)))",script.len());
    let encoded = base64::engine::general_purpose::STANDARD.encode(
        bootstrap
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    use std::os::windows::process::CommandExt;
    let shell = powershell()?;
    let mut child = Command::new(&shell)
        .envs(environment()?)
        .current_dir(
            shell
                .parent()
                .ok_or_else(|| io::Error::other("Нет системного каталога"))?,
        )
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-OutputFormat",
            "Text",
            "-EncodedCommand",
            &encoded,
        ])
        .stdin(Stdio::piped())
        .creation_flags(0x08000000)
        .spawn()?;
    let mut input = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("Нет канала комплекта"))?;
    let write = (|| {
        input.write_all(script.as_bytes())?;
        for (_, bytes) in resources {
            input.write_all(bytes)?;
        }
        io::Result::Ok(())
    })();
    drop(input);
    let status = child.wait()?;
    write?;
    match status.code() {
        Some(0) => Ok(ExitCode::SUCCESS),
        Some(3010) => Ok(ExitCode::from(10)),
        _ => Err(io::Error::other(format!(
            "Установка не завершена: {status}"
        ))),
    }
}
fn elevate(action: &str, routing: bool, digest: &str) -> io::Result<ExitCode> {
    let image = std::env::current_exe()?;
    let file = wide(image.as_os_str());
    let verb = wide(std::ffi::OsStr::new("runas"));
    let text = format!(
        "__setup {action} {} {digest}",
        if routing { "routing" } else { "basic" }
    );
    let params = wide(std::ffi::OsStr::new(&text));
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of_val(&info) as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = SW_HIDE;
    if unsafe { ShellExecuteExW(&mut info) } == 0 || info.hProcess.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Установка отменена",
        ));
    }
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
    if unsafe { WaitForSingleObject(process.as_raw_handle(), INFINITE) } != WAIT_OBJECT_0 {
        return Err(io::Error::last_os_error());
    }
    let mut code = 0;
    if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if code == 0 {
        Ok(ExitCode::SUCCESS)
    } else if code == 10 {
        Ok(ExitCode::from(10))
    } else {
        Err(io::Error::other(
            "Установка отменена или завершилась с ошибкой",
        ))
    }
}

pub(super) fn run_internal(arguments: Vec<OsString>) -> io::Result<ExitCode> {
    if arguments.len() != 3 || !is_elevated() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Неверный внутренний запуск установки",
        ));
    }
    let action = arguments[0]
        .to_str()
        .filter(|v| matches!(*v, "install" | "uninstall"))
        .ok_or_else(|| io::Error::other("Неверное действие"))?;
    let routing = match arguments[1].to_str() {
        Some("routing") => true,
        Some("basic") => false,
        _ => return Err(io::Error::other("Неверный режим")),
    };
    let digest = arguments[2]
        .to_str()
        .filter(|v| v.len() == 64 && v.bytes().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| io::Error::other("Неверный хеш образа"))?;
    install(action, routing, Some(digest))
}
