//! Повышается только headless VPN-процесс. Профиль поступает после проверки канала.
use aivpn_desktop_agent::windows::classic::{
    ClassicChannel, ClassicListener, ClassicPeer, TrustedClassicImage,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::File,
    io::{self, Read},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
        process::ExitStatusExt,
    },
    path::Path,
    process::{Child, Command, ExitCode, ExitStatus},
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::*,
    System::{Console::*, Pipes::CreatePipe, Threading::*},
    UI::{Shell::*, WindowsAndMessaging::SW_HIDE},
};

const LIMIT: usize = 64 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    certificate: Option<Vec<u8>>,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Input {
    Connect { profile: Profile },
    Clear {},
    Stop {},
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "Неверный профиль повышенного клиента",
    )
}
fn permitted_environment(key: &str) -> bool {
    matches!(
        key,
        "AIVPN_CONNECTION_KEY"
            | "AIVPN_TRANSPORT"
            | "AIVPN_TRANSPORT_PARAMS"
            | "AIVPN_BOOTSTRAP_TELEGRAM_TOKEN"
    )
}
impl Profile {
    fn validate(&self) -> io::Result<()> {
        if self.arguments.len() > 256
            || self.environment.len() > 4
            || self.certificate.as_ref().is_some_and(|v| v.len() > 4096)
            || self
                .environment
                .keys()
                .any(|key| !permitted_environment(key))
        {
            return Err(invalid());
        }
        let mut args = self.arguments.iter();
        while let Some(arg) = args.next() {
            if arg.starts_with("--split-enabled=") {
                if !matches!(
                    arg.as_str(),
                    "--split-enabled=true" | "--split-enabled=false"
                ) {
                    return Err(invalid());
                }
                continue;
            }
            if matches!(
                arg.as_str(),
                "--full-tunnel"
                    | "--kill-switch"
                    | "--share-mask-feedback"
                    | "--receive-mask-hints"
            ) {
                continue;
            }
            if !matches!(
                arg.as_str(),
                "--proxy-listen"
                    | "--exclude-routes"
                    | "--include-routes"
                    | "--adaptive-level"
                    | "--dns-proxy"
                    | "--polymorphic-base"
                    | "--preferred-mask"
                    | "--country-code"
                    | "--bootstrap-cdn-url"
                    | "--bootstrap-telegram-chat"
                    | "--bootstrap-github"
                    | "--server-signing-key"
            ) {
                return Err(invalid());
            }
            let value = args.next().ok_or_else(invalid)?;
            if value.is_empty() || value.len() > 8192 || value.contains('\0') {
                return Err(invalid());
            }
        }
        if self
            .environment
            .values()
            .any(|v| v.len() > 32768 || v.contains('\0'))
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn capture(command: &Command) -> io::Result<Self> {
        let mut arguments = Vec::new();
        let mut certificate = None;
        let mut args = command.get_args();
        if args.next().and_then(|v| v.to_str()) != Some("cli") {
            return Err(invalid());
        }
        while let Some(arg) = args.next() {
            if arg == "--mtls-cert" {
                let path = args.next().ok_or_else(invalid)?;
                let mut bytes = Vec::new();
                File::open(path)?.take(4097).read_to_end(&mut bytes)?;
                if bytes.len() > 4096 {
                    return Err(invalid());
                }
                certificate = Some(bytes);
            } else {
                arguments.push(arg.to_str().ok_or_else(invalid)?.to_owned());
            }
        }
        let environment = command
            .get_envs()
            .filter_map(|(key, value)| {
                value
                    .filter(|_| permitted_environment(&key.to_string_lossy()))
                    .map(|value| {
                        (
                            key.to_string_lossy().into_owned(),
                            value.to_string_lossy().into_owned(),
                        )
                    })
            })
            .collect();
        let profile = Self {
            arguments,
            environment,
            certificate,
        };
        profile.validate()?;
        Ok(profile)
    }
}

pub fn is_elevated() -> bool {
    let mut raw = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return false;
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut value: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
    let mut size = 0;
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&mut value as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of_val(&value) as u32,
            &mut size,
        ) != 0
            && value.TokenIsElevated != 0
    }
}
fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain([0]).collect()
}

struct Elevated {
    handle: OwnedHandle,
    control: ClassicChannel,
    _image: TrustedClassicImage,
    _wintun: Option<TrustedClassicImage>,
}
pub struct ClientProcess {
    inner: Process,
    pub stdout: Option<Box<dyn Read + Send>>,
}
enum Process {
    Plain(Child),
    Elevated(Elevated),
}
impl AsRawHandle for ClientProcess {
    fn as_raw_handle(&self) -> RawHandle {
        match &self.inner {
            Process::Plain(child) => child.as_raw_handle(),
            Process::Elevated(child) => child.handle.as_raw_handle(),
        }
    }
}
impl ClientProcess {
    pub fn is_elevated_child(&self) -> bool {
        matches!(self.inner, Process::Elevated(_))
    }
    pub fn spawn(command: &mut Command, elevate: bool) -> io::Result<Self> {
        if !elevate || is_elevated() {
            let mut child = command.spawn()?;
            let stdout = child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn Read + Send>);
            return Ok(Self {
                inner: Process::Plain(child),
                stdout,
            });
        }
        let image = crate::installer::ensure_basic_windows()?;
        Self::elevate(
            &image,
            Input::Connect {
                profile: Profile::capture(command)?,
            },
        )
    }
    fn elevate(image: &Path, input: Input) -> io::Result<Self> {
        let image_guard = TrustedClassicImage::open(image).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("Клиент следует установить в защищенный системный каталог: {error}"),
            )
        })?;
        let image_path = image_guard.shell_path()?;
        let wintun = if matches!(input, Input::Connect { .. }) {
            Some(TrustedClassicImage::open(
                &image.parent().ok_or_else(invalid)?.join("wintun.dll"),
            )?)
        } else {
            None
        };
        let image = image_path.as_path();
        let payload = serde_json::to_vec(&input)?;
        if payload.len() > LIMIT {
            return Err(invalid());
        }
        let context = format!("{:032x}", rand::random::<u128>());
        let listener = ClassicListener::bind(&context)?;
        let verb = wide(std::ffi::OsStr::new("runas"));
        let file = wide(image.as_os_str());
        let args = wide(std::ffi::OsStr::new(&format!(
            "__classic-client {} {context}",
            std::process::id()
        )));
        let directory = image.parent().map(|p| wide(p.as_os_str()));
        let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
        info.cbSize = std::mem::size_of_val(&info) as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = args.as_ptr();
        info.lpDirectory = directory.as_ref().map_or(ptr::null(), |s| s.as_ptr());
        info.nShow = SW_HIDE;
        if unsafe { ShellExecuteExW(&mut info) } == 0 || info.hProcess.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Повышение прав отменено или недоступно",
            ));
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
        let pid = unsafe { GetProcessId(handle.as_raw_handle()) };
        let (control, peer) = match listener.accept(pid, Duration::from_secs(30)) {
            Ok(result) => result,
            Err(error) => {
                unsafe {
                    TerminateProcess(handle.as_raw_handle(), 1);
                }
                return Err(error);
            }
        };
        control.send(&payload)?;
        let reader = ClassicOutput {
            channel: control.try_clone()?,
            peer,
            pending: Vec::new(),
            offset: 0,
        };
        Ok(Self {
            inner: Process::Elevated(Elevated {
                handle,
                control,
                _image: image_guard,
                _wintun: wintun,
            }),
            stdout: Some(Box::new(reader)),
        })
    }
    pub fn id(&self) -> u32 {
        match &self.inner {
            Process::Plain(c) => c.id(),
            Process::Elevated(c) => unsafe { GetProcessId(c.handle.as_raw_handle()) },
        }
    }
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        match &mut self.inner {
            Process::Plain(c) => c.try_wait(),
            Process::Elevated(c) => {
                match unsafe { WaitForSingleObject(c.handle.as_raw_handle(), 0) } {
                    WAIT_TIMEOUT => Ok(None),
                    WAIT_OBJECT_0 => {
                        let mut code = 0;
                        if unsafe { GetExitCodeProcess(c.handle.as_raw_handle(), &mut code) } == 0 {
                            return Err(io::Error::last_os_error());
                        }
                        Ok(Some(ExitStatus::from_raw(code)))
                    }
                    _ => Err(io::Error::last_os_error()),
                }
            }
        }
    }
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        if let Process::Plain(c) = &mut self.inner {
            return c.wait();
        }
        match unsafe { WaitForSingleObject(self.as_raw_handle(), 10_000) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Остановка повышенного клиента не подтверждена",
                ))
            }
            _ => return Err(io::Error::last_os_error()),
        }
        self.try_wait()?.ok_or_else(invalid)
    }
    pub fn kill(&mut self) -> io::Result<()> {
        match &mut self.inner {
            Process::Plain(c) => c.kill(),
            Process::Elevated(c) => {
                if unsafe { WaitForSingleObject(c.handle.as_raw_handle(), 0) } == WAIT_OBJECT_0 {
                    return Ok(());
                }
                let sent = c.control.send(&serde_json::to_vec(&Input::Stop {})?);
                if sent.is_ok()
                    && unsafe { WaitForSingleObject(c.handle.as_raw_handle(), 10_000) }
                        == WAIT_OBJECT_0
                {
                    return Ok(());
                }
                if unsafe { TerminateProcess(c.handle.as_raw_handle(), 1) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            }
        }
    }
}
struct ClassicOutput {
    channel: ClassicChannel,
    peer: ClassicPeer,
    pending: Vec<u8>,
    offset: usize,
}
impl Read for ClassicOutput {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.offset == self.pending.len() {
            match self.channel.receive_owned(&self.peer) {
                Ok(payload) => {
                    self.pending = payload;
                    self.offset = 0;
                }
                Err(error)
                    if matches!(
                        error.raw_os_error().map(|value| value as u32),
                        Some(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED)
                    ) || matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::UnexpectedEof
                    ) =>
                {
                    return Ok(0)
                }
                Err(error) => return Err(error),
            }
        }
        let size = bytes.len().min(self.pending.len() - self.offset);
        bytes[..size].copy_from_slice(&self.pending[self.offset..self.offset + size]);
        self.offset += size;
        Ok(size)
    }
}

fn redirect_output(channel: ClassicChannel) -> io::Result<(File, std::thread::JoinHandle<()>)> {
    let mut read = ptr::null_mut();
    let mut write = ptr::null_mut();
    if unsafe { CreatePipe(&mut read, &mut write, ptr::null(), 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut input = unsafe { File::from_raw_handle(read) };
    let output = unsafe { File::from_raw_handle(write) };
    if unsafe { SetStdHandle(STD_OUTPUT_HANDLE, output.as_raw_handle()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let pump = std::thread::Builder::new()
        .name("aivpn-status".into())
        .spawn(move || {
            let mut bytes = [0; 4096];
            while let Ok(size) = input.read(&mut bytes) {
                if size == 0 || channel.send(&bytes[..size]).is_err() {
                    break;
                }
            }
        })?;
    Ok((output, pump))
}

pub fn run(arguments: Vec<OsString>) -> io::Result<ExitCode> {
    if arguments.len() != 2 || !is_elevated() {
        return Err(invalid());
    }
    // До runtime и потоков исключаем пользовательские пути системных команд.
    for (key, value) in crate::installer::windows_environment()? {
        std::env::set_var(key, value);
    }
    let parent = arguments[0]
        .to_str()
        .and_then(|v| v.parse().ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(invalid)?;
    let context = arguments[1].to_str().ok_or_else(invalid)?;
    let _image = TrustedClassicImage::open(&std::env::current_exe()?)?;
    let (channel, peer) = ClassicChannel::connect(context, parent)?;
    let input: Input = serde_json::from_slice(&channel.receive(Duration::from_secs(30))?)?;
    let (output, pump) = redirect_output(channel.try_clone()?)?;
    let result = match input {
        Input::Clear {} => {
            crate::kill_switch::KillSwitch::clear_for_operator().map_err(io::Error::other)
        }
        Input::Stop {} => Err(invalid()),
        Input::Connect { profile } => {
            profile.validate()?;
            for (key, _) in
                std::env::vars_os().filter(|(k, _)| k.to_string_lossy().starts_with("AIVPN_"))
            {
                std::env::remove_var(key);
            }
            for (key, value) in profile.environment {
                std::env::set_var(key, value);
            }
            std::env::set_var("RUST_LOG", "info");
            let shutdown = Arc::new(AtomicBool::new(false));
            let retain_firewall = Arc::new(AtomicBool::new(false));
            let retained = retain_firewall.clone();
            let requested = shutdown.clone();
            std::thread::Builder::new()
                .name("aivpn-owner".into())
                .spawn(move || {
                    match channel.receive_owned(&peer).and_then(|bytes| {
                        serde_json::from_slice::<Input>(&bytes).map_err(io::Error::other)
                    }) {
                        Ok(Input::Stop {}) => {}
                        _ => retained.store(true, Ordering::SeqCst),
                    }
                    requested.store(true, Ordering::SeqCst);
                    // Если ядро зависло, процесс закрывается с сохраненной защитой.
                    std::thread::sleep(Duration::from_secs(8));
                    std::process::exit(1);
                })?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let args = std::iter::once(OsString::from("aivpn"))
                .chain(profile.arguments.into_iter().map(OsString::from))
                .collect();
            runtime.block_on(crate::run::run_with_context(
                Vec::new(),
                aivpn_common::transport::no_socket_guard(),
                args,
                crate::run::RunContext {
                    shutdown: Some(shutdown.clone()),
                    retain_firewall: Some(retain_firewall.clone()),
                    mtls_certificate: profile.certificate,
                },
            ));
            if shutdown.load(Ordering::SeqCst) && !retain_firewall.load(Ordering::SeqCst) {
                crate::kill_switch::KillSwitch::clear_for_operator().map_err(io::Error::other)
            } else {
                Ok(())
            }
        }
    };
    if let Err(error) = &result {
        eprintln!("Повышенный клиент: {error}");
    }
    drop(output);
    let _ = pump.join();
    result.map(|_| ExitCode::SUCCESS)
}

pub fn clear(_image: &Path) -> io::Result<()> {
    if is_elevated() {
        return crate::kill_switch::KillSwitch::clear_for_operator().map_err(io::Error::other);
    }
    let image = crate::installer::ensure_basic_windows()?;
    let mut child = ClientProcess::elevate(&image, Input::Clear {})?;
    drop(child.stdout.take());
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(io::Error::other("Не удалось снять защиту AIVPN"))
            };
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    child.kill()?;
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "Истек срок очистки защиты",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn elevated_profile_cannot_run_subcommands_or_read_admin_files() {
        let profile = |arguments: &[&str]| Profile {
            arguments: arguments.iter().map(|v| v.to_string()).collect(),
            environment: BTreeMap::new(),
            certificate: None,
        };
        for args in [
            &["ssh-install"][..],
            &["--config", "C:\\Windows\\secret"],
            &["--mtls-cert", "C:\\Windows\\secret"],
            &["__packet-worker"],
            &["--full-tunnel", "--help"],
        ] {
            assert!(profile(args).validate().is_err());
        }
        assert!(profile(&[
            "--full-tunnel",
            "--split-enabled=false",
            "--preferred-mask",
            "quic"
        ])
        .validate()
        .is_ok());
        assert!(serde_json::from_slice::<Input>(br#"{"action":"stop","command":"sh"}"#).is_err());
    }
}
