use aivpn_client::service_dns::DesktopDnsRelay;
use aivpn_desktop_agent::{
    client::LINUX_CONTROL_PATH,
    control::Control,
    linux::{LinuxCoordinator, LinuxRoutingBackend},
    protocol::{Request, Response},
    state::{StateDirectory, StateFile},
    unix::service::{ControlHandler, ControlServer, ControlStop},
};
use clap::{Parser, ValueEnum};
use rand::RngCore;
use std::{
    io,
    net::SocketAddr,
    os::fd::{AsRawFd, FromRawFd},
    os::unix::net::UnixListener,
    path::PathBuf,
    sync::mpsc,
    thread::JoinHandle,
    time::Duration,
};

#[path = "linux/readiness.rs"]
mod readiness;

#[derive(Parser)]
#[command(version, about = "Привилегированная служба split по приложениям")]
struct Args {
    /// Очистить собственные объекты ядра после подготовки удаления и остановки службы.
    #[arg(long)]
    cleanup: bool,
    #[arg(long, default_value = "/var/lib/aivpn-app-routing")]
    state_directory: PathBuf,
    #[arg(long, default_value = "/run/aivpn-app-routing/state")]
    runtime_directory: PathBuf,
    #[arg(long, default_value = "1.1.1.1:53")]
    dns_upstream: SocketAddr,
    #[arg(long, value_enum, default_value = "auto")]
    dns_provider: DnsProvider,
}

#[derive(Clone, Copy, ValueEnum)]
enum DnsProvider {
    Auto,
    Networkmanager,
    File,
    Resolved,
    Resolvconf,
}

struct Service {
    coordinator: LinuxCoordinator,
    relay: DesktopDnsRelay,
}
impl ControlHandler for Service {
    fn prepare(
        &mut self,
        authority: &aivpn_desktop_agent::policy::Authority,
        request: Request,
    ) -> aivpn_desktop_agent::protocol::PreparedResponse {
        self.coordinator.prepare(authority, request)
    }
    fn stopping(&mut self) -> io::Result<()> {
        self.coordinator.stop_profile()
    }
    fn handle(
        &mut self,
        authority: &aivpn_desktop_agent::policy::Authority,
        request: Request,
    ) -> Response {
        self.coordinator.handle(authority, request)
    }
    fn progress(&mut self) -> io::Result<()> {
        let event = self.coordinator.step(Duration::ZERO)?;
        if let Some(error) = self.coordinator.take_runtime_failure() {
            eprintln!("{error}");
        }
        self.relay.progress(&mut self.coordinator, &event)
    }
    fn poll_interval(&self) -> Duration {
        Duration::from_millis(250)
    }
    fn wait_for_activity(
        &mut self,
        pending: std::os::fd::BorrowedFd<'_>,
        timeout: Duration,
    ) -> io::Result<()> {
        self.coordinator.wait_for_activity(pending, timeout)
    }
}

pub fn run() -> io::Result<()> {
    run_from(std::env::args_os().collect())
}

pub fn run_from(arguments: Vec<std::ffi::OsString>) -> io::Result<()> {
    let args = Args::parse_from(arguments);
    if args.cleanup {
        if unsafe { libc::geteuid() } != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let root = StateDirectory::open(&args.state_directory)?;
        let namespace: [u8; 16] = root
            .load(StateFile::Committed)?
            .ok_or(io::ErrorKind::NotFound)?
            .try_into()
            .map_err(|_| io::ErrorKind::InvalidData)?;
        let control = root.child(c"control")?;
        let proof = aivpn_desktop_agent::maintenance::DecommissionProof::open(
            aivpn_desktop_agent::policy::Platform::Linux,
            namespace,
            &control,
        )?;
        return aivpn_desktop_agent::linux::kernel::remove_owned_routing(
            &proof,
            StateDirectory::open(&args.runtime_directory)?,
        );
    }
    if unsafe { libc::geteuid() } != 0
        || std::env::var("LISTEN_PID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            != Some(std::process::id())
        || std::env::var("LISTEN_FDS").as_deref() != Ok("1")
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Требуется root-служба с единственным сокетом systemd",
        ));
    }
    let notify_socket = std::env::var_os("NOTIFY_SOCKET");
    std::env::remove_var("NOTIFY_SOCKET");
    let listener = unsafe { UnixListener::from_raw_fd(3) };
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");
    if listener.local_addr()?.as_pathname() != Some(std::path::Path::new(LINUX_CONTROL_PATH)) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let mut accepting = 0;
    let mut length = std::mem::size_of_val(&accepting) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            listener.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            (&mut accepting as *mut libc::c_int).cast(),
            &mut length,
        )
    } < 0
        || accepting != 1
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    if unsafe { libc::fcntl(listener.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
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
    // Ссылки на объекты ядра действуют только до перезагрузки ОС.
    let runtime = StateDirectory::open(&args.runtime_directory)?;
    let mut backend = LinuxRoutingBackend::open(
        namespace,
        runtime.child(c"slots")?,
        runtime.child(c"bindings")?,
        runtime.child(c"network")?,
    )?;
    match args.dns_provider {
        DnsProvider::Networkmanager => backend.configure_network_manager_system_dns()?,
        DnsProvider::File => backend.configure_unmanaged_system_dns()?,
        DnsProvider::Resolved => backend.configure_resolved_system_dns()?,
        DnsProvider::Resolvconf => backend.configure_resolvconf_system_dns()?,
        DnsProvider::Auto => backend.configure_automatic_system_dns()?,
    }
    let control = Control::open(
        aivpn_desktop_agent::policy::Platform::Linux,
        namespace,
        root.child(c"control")?,
        backend,
    )?;
    let mut coordinator = LinuxCoordinator::new(control);
    let relay = DesktopDnsRelay::bind_for_system(args.dns_upstream, &mut coordinator)?;
    let mut service = Service { coordinator, relay };
    let (server, stop) = ControlServer::new(listener)?;
    let signals = Signals::start(stop)?;
    readiness::notify(notify_socket.as_deref())?;
    let result = server.run_handler(&mut service);
    service.relay.close();
    let stopped = service.coordinator.stop_profile();
    drop(signals);
    result.and(stopped)
}

struct Signals {
    cancel: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}
impl Signals {
    fn start(stop: ControlStop) -> io::Result<Self> {
        let (cancel, cancelled) = tokio::sync::oneshot::channel();
        let (ready, received) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new().name("aivpn-service-signals".into()).spawn(move || {
            let outcome = (|| -> io::Result<()> {
                let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
                runtime.block_on(async {
                    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
                    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
                    ready.send(Ok(())).map_err(|_| io::ErrorKind::BrokenPipe)?;
                    tokio::select! { _ = term.recv() => stop.stop(), _ = interrupt.recv() => stop.stop(), _ = cancelled => () }
                    Ok(())
                })
            })();
            if let Err(error) = outcome { let _ = ready.send(Err(error)); stop.stop(); }
        })?;
        let result = Self {
            cancel: Some(cancel),
            thread: Some(thread),
        };
        received.recv().map_err(|_| io::ErrorKind::BrokenPipe)??;
        Ok(result)
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
