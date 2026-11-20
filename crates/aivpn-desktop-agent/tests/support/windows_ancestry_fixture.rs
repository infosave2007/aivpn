use super::{accounts, fixture, os};
use aivpn_desktop_policy::{Action, Selector};
use serde_json::{json, Value};
use std::{
    os::windows::io::{AsRawHandle, OwnedHandle},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use windows_sys::Win32::{Security::TokenSessionId, System::Threading::*};

pub fn helper_guard() {
    assert_eq!(
        std::env::var("AIVPN_ANCESTRY_LAB").as_deref(),
        Ok("isolated-qemu-local-system")
    );
    assert_eq!(
        std::fs::read_to_string(r"C:\AivpnLab\windows-ancestry-lab.guard").unwrap(),
        "aivpn-isolated-qemu-ancestry\n"
    );
}
pub fn guard() {
    helper_guard();
    assert_eq!(accounts::sid(), "S-1-5-18");
    assert_eq!(
        accounts::token_u32(accounts::process_token().as_raw_handle(), TokenSessionId),
        0
    );
}
fn wait_marker(marker: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !marker.exists() {
        assert!(
            Instant::now() < deadline,
            "Не появился собственный leaf marker"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[expect(
    clippy::zombie_processes,
    reason = "Создатель намеренно завершается раньше потомка для проверки сохраненной родословной Windows"
)]
pub fn child() {
    let remaining: u32 = std::env::var("AIVPN_ANCESTRY_REMAINING")
        .unwrap()
        .parse()
        .unwrap();
    assert!(remaining <= 34);
    let marker = PathBuf::from(std::env::var("AIVPN_ANCESTRY_MARKER").unwrap());
    if remaining == 0 {
        std::fs::write(&marker, std::process::id().to_string()).unwrap();
        wait_marker(&marker.with_extension("release"));
        return;
    }
    if remaining == 1 && std::env::var_os("AIVPN_ANCESTRY_OWNER_BOUNDARY").is_some() {
        guard();
        let token = accounts::logon("AivpnAncestryOwn", false);
        let leaf = os::suspended(
            &PathBuf::from(std::env::var("AIVPN_ANCESTRY_COPY").unwrap()),
            Some(&token),
            None,
        );
        let pid = unsafe { GetProcessId(leaf.0.as_raw_handle()) };
        assert_ne!(pid, 0);
        std::fs::write(&marker, pid.to_string()).unwrap();
        wait_marker(&marker.with_extension("release"));
        drop(leaf);
        return;
    }
    let selected = std::env::var("AIVPN_ANCESTRY_SELECTED_DEPTH")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());
    let image = if selected == Some(remaining - 1) {
        "AIVPN_ANCESTRY_SELECTED"
    } else {
        "AIVPN_ANCESTRY_COPY"
    };
    if std::env::var_os("AIVPN_ANCESTRY_RETIRE").is_some() {
        std::fs::write(
            marker.with_extension(format!("creator-{remaining}")),
            std::process::id().to_string(),
        )
        .unwrap();
    }
    let mut child = command(&PathBuf::from(std::env::var(image).unwrap()))
        .env("AIVPN_ANCESTRY_REMAINING", (remaining - 1).to_string())
        .spawn()
        .unwrap();
    if std::env::var_os("AIVPN_ANCESTRY_RETIRE").is_some() {
        wait_marker(&marker);
        wait_marker(&marker.with_extension("retire"));
    } else {
        assert!(child.wait().unwrap().success());
    }
}
fn command(path: &std::path::Path) -> Command {
    let mut command = Command::new(path);
    command
        .args([
            "--ignored",
            "--exact",
            "ancestry_chain_child",
            "--test-threads=1",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}
pub struct Chain {
    scratch: os::Scratch,
    marker: PathBuf,
    child: Root,
    pub process: OwnedHandle,
    selected: PathBuf,
    depth: u32,
}
impl Chain {
    pub fn start(depth: u32, selected_depth: Option<u32>, retire: bool, boundary: bool) -> Self {
        Self::start_inner(depth, selected_depth, retire, boundary, false)
    }
    pub fn complete() -> Self {
        Self::start_inner(2, None, false, false, true)
    }
    fn start_inner(
        depth: u32,
        selected_depth: Option<u32>,
        retire: bool,
        boundary: bool,
        user_root: bool,
    ) -> Self {
        let scratch = os::Scratch::new();
        let copy = scratch.copy("chain.exe");
        let selected = scratch.copy("selected.exe");
        if user_root {
            assert!(Command::new(r"C:\Windows\System32\icacls.exe")
                .arg(&scratch.0)
                .args(["/grant", "AivpnAncestryOwn:(OI)(CI)M", "/T"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success());
        }
        let marker = scratch.0.join("leaf");
        let mut command = command(&copy);
        command
            .env("AIVPN_ANCESTRY_REMAINING", (depth - 1).to_string())
            .env("AIVPN_ANCESTRY_MARKER", &marker)
            .env("AIVPN_ANCESTRY_COPY", &copy)
            .env("AIVPN_ANCESTRY_SELECTED", &selected);
        if let Some(value) = selected_depth {
            command.env("AIVPN_ANCESTRY_SELECTED_DEPTH", value.to_string());
        }
        if retire {
            command.env("AIVPN_ANCESTRY_RETIRE", "1");
        }
        if boundary {
            command.env("AIVPN_ANCESTRY_OWNER_BOUNDARY", "1");
        } else {
            command.env_remove("AIVPN_CONTROL_PASSWORD");
        }
        let mut child = if user_root {
            Root::User(spawn_user(&command, &scratch.0.join("user-root.log")))
        } else {
            Root::Standard(command.spawn().unwrap())
        };
        if let Err(payload) = std::panic::catch_unwind(|| wait_marker(&marker)) {
            eprintln!(
                "Собственный user helper: {}",
                std::fs::read_to_string(scratch.0.join("user-root.log")).unwrap_or_default()
            );
            child.wait();
            std::panic::resume_unwind(payload);
        }
        let pid = std::fs::read_to_string(&marker).unwrap().parse().unwrap();
        let process =
            os::own(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | 0x100000, 0, pid) });
        if retire {
            retire_creators(&mut child, &marker, depth);
        }
        Self {
            scratch,
            marker,
            child,
            process,
            selected: if selected_depth.is_some() {
                selected
            } else {
                std::env::current_exe().unwrap()
            },
            depth,
        }
    }
    pub fn finish(self) {
        drop(self);
    }
    fn release(&mut self) {
        std::fs::write(self.marker.with_extension("release"), "release").unwrap();
        self.child.wait();
        assert_eq!(
            unsafe { WaitForSingleObject(self.process.as_raw_handle(), 10000) },
            0
        );
    }
}
impl Drop for Chain {
    fn drop(&mut self) {
        self.release();
    }
}

fn retire_creators(child: &mut Root, marker: &std::path::Path, depth: u32) {
    let creators = (1..depth)
        .map(|remaining| {
            let pid =
                std::fs::read_to_string(marker.with_extension(format!("creator-{remaining}")))
                    .unwrap()
                    .parse()
                    .unwrap();
            os::own(unsafe { OpenProcess(0x100000, 0, pid) })
        })
        .collect::<Vec<_>>();
    std::fs::write(marker.with_extension("retire"), "retire").unwrap();
    child.wait();
    for process in &creators {
        assert_eq!(
            unsafe { WaitForSingleObject(process.as_raw_handle(), 10000) },
            0
        );
    }
    println!("ANCESTRY_RETIRE creators_exited={}", creators.len());
}

enum Root {
    Standard(Child),
    User(OwnedHandle),
}
impl Root {
    fn wait(&mut self) {
        match self {
            Self::Standard(child) => assert!(child.wait().unwrap().success()),
            Self::User(process) => {
                assert_eq!(
                    unsafe { WaitForSingleObject(process.as_raw_handle(), 10000) },
                    0
                );
                let mut code = 0;
                accounts::checked(unsafe {
                    GetExitCodeProcess(process.as_raw_handle(), &mut code)
                });
                assert_eq!(code, 0);
            }
        }
    }
}
fn spawn_user(command: &Command, log: &std::path::Path) -> OwnedHandle {
    let token = accounts::logon("AivpnAncestryOwn", false);
    let text = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|s| format!("\"{}\"", s.to_str().unwrap()))
        .collect::<Vec<_>>()
        .join(" ");
    let mut text = accounts::wide(&text);
    let mut vars = std::env::vars_os().collect::<std::collections::BTreeMap<_, _>>();
    for (key, value) in command.get_envs() {
        match value {
            Some(value) => {
                vars.insert(key.into(), value.into());
            }
            None => {
                vars.remove(key);
            }
        }
    }
    let mut vars = vars.into_iter().collect::<Vec<_>>();
    vars.sort_by_key(|(key, _)| key.to_string_lossy().to_uppercase());
    let mut environment = vars
        .into_iter()
        .flat_map(|(key, value)| {
            format!("{}={}\0", key.to_str().unwrap(), value.to_str().unwrap())
                .encode_utf16()
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    environment.push(0);
    let mut startup = STARTUPINFOW::default();
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let log = std::fs::File::create(log).unwrap();
    accounts::checked(unsafe {
        windows_sys::Win32::Foundation::SetHandleInformation(log.as_raw_handle(), 1, 1)
    });
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = log.as_raw_handle();
    startup.hStdError = log.as_raw_handle();
    let mut process = PROCESS_INFORMATION::default();
    accounts::checked(unsafe {
        CreateProcessAsUserW(
            token.as_raw_handle(),
            std::ptr::null(),
            text.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            environment.as_ptr().cast(),
            std::ptr::null(),
            &startup,
            &mut process,
        )
    });
    drop(os::own(process.hThread));
    os::own(process.hProcess)
}

pub struct Case<'a> {
    label: &'a str,
    action: u32,
    inherit: bool,
    pub outside: bool,
    pub unselected: bool,
}
impl<'a> Case<'a> {
    pub fn new(label: &'a str, action: u32, inherit: bool) -> Self {
        Self {
            label,
            action,
            inherit,
            outside: false,
            unselected: false,
        }
    }
}
pub fn diagnose(chain: &Chain, case: Case<'_>) -> Value {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::*;
    let selected = if case.unselected {
        chain.scratch.copy("unused.exe")
    } else {
        chain.selected.clone()
    };
    let native = os::native_path(&selected);
    let device = fixture::open().unwrap();
    let status = fixture::query(&device, 0);
    assert_eq!(
        fixture::word(&status, 40),
        0,
        "Диагностика не включает enforcement"
    );
    let session = fixture::wide_word(&status, 8);
    let token = os::token(&os::current());
    let mut owner = fixture::request(session, 8320);
    owner[24] = 2;
    owner[28] = 1;
    owner[32..40].copy_from_slice(&(token.as_raw_handle() as u64).to_le_bytes());
    owner[40] = 12;
    owner[48..60].copy_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
    fixture::ioctl(&device, fixture::QUERY + 8, &owner, 48).unwrap();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .access_mode(FILE_READ_DATA | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .open(&selected)
        .unwrap();
    let mut binding = fixture::request(session, 8320);
    binding[24] = 1;
    binding[28] = 3;
    binding[32..40].copy_from_slice(&(file.as_raw_handle() as u64).to_le_bytes());
    os::request_path(&mut binding, &native);
    fixture::ioctl(&device, fixture::QUERY + 8, &binding, 48).unwrap();
    let (policy, _) = os::policy_default(
        Selector::Executable { path: native },
        case.action,
        1,
        case.inherit,
        Action::System {},
    );
    let mut stage = fixture::request(session, 14400);
    stage[24..].copy_from_slice(&policy.to_native_bytes());
    if case.outside {
        // IPv4 198.51.100.0/24 не включает диагностический 192.0.2.1.
        stage[24 + 40 + 8] = 4;
        stage[24 + 40 + 24..24 + 40 + 28].copy_from_slice(&[198, 51, 100, 0]);
        stage[24 + 40 + 40..24 + 40 + 44].copy_from_slice(&[255, 255, 255, 0]);
    }
    fixture::ioctl(&device, fixture::STAGE, &stage, 48).unwrap();
    let mut input = fixture::request(session, 56);
    input[24..32].copy_from_slice(&(chain.process.as_raw_handle() as u64).to_le_bytes());
    input[32] = 4;
    input[40..44].copy_from_slice(&[192, 0, 2, 1]);
    let bytes = fixture::ioctl(&device, fixture::QUERY + 12, &input, 264).unwrap();
    assert_eq!(bytes.len(), 264);
    let mut result = serde_json::Map::new();
    for (name, at) in [
        ("action", 24),
        ("profile", 28),
        ("rule", 32),
        ("depth", 36),
        ("unresolved", 40),
        ("owner_slot", 60),
        ("application_slot", 64),
        ("resolved", 72),
        ("parent_count", 76),
        ("image_available", 80),
        ("path_available", 84),
    ] {
        result.insert(name.into(), fixture::word(&bytes, at).into());
    }
    result.insert(
        "raw_hex".into(),
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            .into(),
    );
    let result = Value::Object(result);
    println!(
        "ANCESTRY {}",
        json!({"case":case.label,"requested_depth":chain.depth,"diagnostic":result})
    );
    assert_eq!(result["resolved"], 1);
    assert_eq!(result["image_available"], 1);
    assert_eq!(result["path_available"], 1);
    result
}
pub fn assert_decision(result: &Value, expected: (u32, u32, u32, u32)) {
    assert_eq!(
        (
            result["action"].as_u64().unwrap() as u32,
            result["profile"].as_u64().unwrap() as u32,
            result["depth"].as_u64().unwrap() as u32,
            result["unresolved"].as_u64().unwrap() as u32
        ),
        expected,
        "{result}"
    );
}
