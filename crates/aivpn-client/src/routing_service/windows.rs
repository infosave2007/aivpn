use aivpn_client::service_dns::DesktopDnsRelay;
use aivpn_desktop_agent::{
    client::WINDOWS_CONTROL_NAME,
    control::Control,
    policy::Platform,
    state::{StateDirectory, StateFile},
    windows::{ProvenanceVolume, WindowsCoordinator, WindowsRoutingBackend, WindowsService},
};
use clap::Parser;
use rand::RngCore;
use std::{
    io,
    net::SocketAddr,
    path::PathBuf,
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock,
    },
};
use windows_sys::Win32::{
    Foundation::*,
    System::{EventLog::*, Rpc::UuidFromStringW, Services::*},
};

const NAME: &str = "AivpnAppRouting";
static OPTIONS: OnceLock<Args> = OnceLock::new();
static STOP: AtomicBool = AtomicBool::new(false);
static FAILED: AtomicBool = AtomicBool::new(false);

#[derive(Parser)]
#[command(version, about = "Привилегированная служба split по приложениям")]
struct Args {
    /// Удалить только проверенные объекты WFP после decommission.
    #[arg(long)]
    cleanup: bool,
    /// Удалить внутренние записи по сохраненному плану после decommission.
    #[arg(long, requires = "cleanup")]
    purge_state: bool,
    #[arg(long, default_value = r"C:\ProgramData\AIVPN\AppRouting")]
    state_directory: PathBuf,
    /// Устойчивый GUID сетевого адаптера пакетного пути.
    #[arg(long, required_unless_present = "cleanup")]
    interface_guid: Option<String>,
    #[arg(long, default_value = "1.1.1.1:53")]
    dns_upstream: SocketAddr,
    #[arg(long, default_value = "AivpnAppRoutingDriver")]
    driver_filter: String,
    /// Явно подключаемый локальный NTFS-том.
    #[arg(long, required_unless_present = "cleanup")]
    provenance_volume: Option<PathBuf>,
}

pub fn run() -> io::Result<()> {
    run_from(std::env::args_os().collect())
}

pub fn run_from(arguments: Vec<std::ffi::OsString>) -> io::Result<()> {
    OPTIONS
        .set(Args::parse_from(arguments))
        .map_err(|_| io::ErrorKind::AlreadyExists)?;
    let mut name = wide(NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    check(unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) })?;
    if FAILED.load(Ordering::Acquire) {
        return Err(io::Error::other("Служба SCM завершилась с ошибкой"));
    }
    Ok(())
}

unsafe extern "system" fn service_main(_: u32, _: *mut *mut u16) {
    let name = wide(NAME);
    let handle =
        unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), ptr::null()) };
    if handle.is_null() {
        FAILED.store(true, Ordering::Release);
        return;
    }
    let result = report(handle, SERVICE_START_PENDING, 0).and_then(|()| serve(handle));
    if let Err(error) = &result {
        FAILED.store(true, Ordering::Release);
        eprintln!("Служба маршрутизации: {error}");
        log_error(error);
    }
    if report(handle, SERVICE_STOPPED, u32::from(result.is_err())).is_err() {
        FAILED.store(true, Ordering::Release);
    }
}

fn log_error(error: &io::Error) {
    let source = wide(NAME);
    let handle = unsafe { RegisterEventSourceW(ptr::null(), source.as_ptr()) };
    if handle.is_null() {
        return;
    }
    let message = wide(&format!("Ошибка службы маршрутизации: {error}"));
    unsafe {
        ReportEventW(
            handle,
            EVENTLOG_ERROR_TYPE,
            0,
            1,
            ptr::null_mut(),
            1,
            0,
            &message.as_ptr(),
            ptr::null(),
        );
        DeregisterEventSource(handle);
    }
}

unsafe extern "system" fn control(
    code: u32,
    _: u32,
    _: *mut core::ffi::c_void,
    _: *mut core::ffi::c_void,
) -> u32 {
    match code {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            STOP.store(true, Ordering::Release);
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

fn serve(handle: SERVICE_STATUS_HANDLE) -> io::Result<()> {
    let args = OPTIONS.get().ok_or(io::ErrorKind::InvalidInput)?;
    if args.cleanup {
        if args.purge_state {
            report(handle, SERVICE_RUNNING, 0)?;
            return aivpn_desktop_agent::windows::purge_owned_routing(&args.state_directory);
        }
        let root = StateDirectory::open(&args.state_directory)?;
        let namespace: [u8; 16] = root
            .load(StateFile::Committed)?
            .ok_or(io::ErrorKind::NotFound)?
            .try_into()
            .map_err(|_| io::ErrorKind::InvalidData)?;
        let control = root.child(c"control")?;
        let proof = aivpn_desktop_agent::maintenance::DecommissionProof::open(
            Platform::Windows,
            namespace,
            &control,
        )?;
        report(handle, SERVICE_RUNNING, 0)?;
        return aivpn_desktop_agent::windows::remove_owned_routing(
            &proof,
            root.child(c"retirement")?,
        );
    }
    let mut text = wide(
        args.interface_guid
            .as_ref()
            .ok_or(io::ErrorKind::InvalidInput)?
            .trim_start_matches('{')
            .trim_end_matches('}'),
    );
    let mut guid = windows_sys::core::GUID::default();
    let status = unsafe { UuidFromStringW(text.as_mut_ptr(), &mut guid) };
    if status != 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let provenance = ProvenanceVolume::attach(
        &args.driver_filter,
        args.provenance_volume
            .as_deref()
            .ok_or(io::ErrorKind::InvalidInput)?,
    )?;
    let mut root = StateDirectory::open(&args.state_directory)?;
    let namespace = match root.load(StateFile::Committed)? {
        Some(bytes) => bytes.try_into().map_err(|_| io::ErrorKind::InvalidData)?,
        None => {
            let mut namespace = [0; 16];
            rand::thread_rng().fill_bytes(&mut namespace);
            root.replace(StateFile::Committed, &namespace)?;
            namespace
        }
    };
    let image = std::env::current_exe()?;
    let mut relay = DesktopDnsRelay::bind(args.dns_upstream)?;
    let mut service = WindowsService::bind(WINDOWS_CONTROL_NAME, || {
        let mut backend =
            WindowsRoutingBackend::open_for_guid(namespace, root.child(c"slots")?, &guid)?;
        backend.configure_provenance(provenance)?;
        backend.configure_system_dns()?;
        let control = Control::open(
            Platform::Windows,
            namespace,
            root.child(c"control")?,
            backend,
        )?;
        let mut coordinator = WindowsCoordinator::new(control);
        coordinator.configure_worker_paths(image, root)?;
        Ok(coordinator)
    })?;
    report(handle, SERVICE_RUNNING, 0)?;
    let result = service.run(&STOP, |event, coordinator| {
        if let Some(error) = coordinator.take_runtime_failure() {
            log_error(&io::Error::other(error));
        }
        relay.progress(coordinator, &event)
    });
    relay.close();
    result
}

fn report(handle: SERVICE_STATUS_HANDLE, state: u32, code: u32) -> io::Result<()> {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: if code == 0 {
            0
        } else {
            ERROR_SERVICE_SPECIFIC_ERROR
        },
        dwServiceSpecificExitCode: code,
        dwCheckPoint: if state == SERVICE_START_PENDING { 1 } else { 0 },
        dwWaitHint: if state == SERVICE_START_PENDING {
            30000
        } else {
            0
        },
    };
    check(unsafe { SetServiceStatus(handle, &status) })
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn check(value: i32) -> io::Result<()> {
    if value == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
