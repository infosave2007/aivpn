use crate::{
    kill_switch::KillSwitch,
    network_session::{Reply, Request, MAX_REQUEST},
};
use aivpn_desktop_agent::unix::LocalStream;
use std::{
    io::{self, Write},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
        unix::{fs::MetadataExt, net::UnixListener},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tun::AbstractDevice;

struct SocketPath(PathBuf);
impl Drop for SocketPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct Device {
    device: tun::Device,
    name: String,
    network: aivpn_common::network_config::ClientNetworkConfig,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn validate(
    name: &str,
    network: &aivpn_common::network_config::ClientNetworkConfig,
) -> io::Result<()> {
    if name.is_empty()
        || name.len() >= libc::IFNAMSIZ
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(invalid("Недопустимое имя TUN"));
    }
    network.validate().map_err(io::Error::other)
}

struct Resources {
    device: Option<Device>,
    firewall: Option<KillSwitch>,
    routes: Option<crate::transport_routes::TransportRoutes>,
    ip: super::owned::OwnedIp,
    owner_uid: u32,
    firewall_lease: Option<std::fs::File>,
}

fn run_request(
    request: Request,
    state: &mut Resources,
    descriptors: &[OwnedFd],
) -> io::Result<(Vec<(String, i32)>, Option<OwnedFd>)> {
    let Resources {
        device,
        firewall,
        routes,
        ip,
        owner_uid,
        firewall_lease,
    } = state;
    let assigned_mark = crate::network_session::assigned_transport_mark(*owner_uid)?;
    let expected = usize::from(matches!(request, Request::MarkSocket { .. }));
    if descriptors.len() != expected {
        return Err(invalid("Неподтвержденное число дескрипторов запроса"));
    }
    match request {
        Request::MarkSocket { mark } => {
            if mark != assigned_mark {
                return Err(invalid("Метка не принадлежит владельцу"));
            }
            let socket = descriptors[0].as_raw_fd();
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(socket, &mut stat) } < 0 || stat.st_uid != *owner_uid {
                return Err(invalid("Сокет принадлежит другому пользователю"));
            }
            let mut domain: libc::c_int = 0;
            let mut length = std::mem::size_of_val(&domain) as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    socket,
                    libc::SOL_SOCKET,
                    libc::SO_DOMAIN,
                    (&mut domain as *mut libc::c_int).cast(),
                    &mut length,
                )
            } < 0
                || !matches!(domain, libc::AF_INET | libc::AF_INET6)
            {
                return Err(invalid("Ожидался сетевой сокет транспорта"));
            }
            if unsafe {
                libc::setsockopt(
                    socket,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    (&mark as *const u32).cast(),
                    std::mem::size_of_val(&mark) as libc::socklen_t,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok((Vec::new(), None))
        }
        Request::Transport { mark } => {
            if mark.is_some_and(|m| m != assigned_mark) {
                return Err(invalid("Метка не принадлежит владельцу"));
            }
            *routes = None;
            if let Some(mark) = mark {
                *routes = Some(crate::transport_routes::TransportRoutes::install(mark)?);
            }
            Ok((Vec::new(), None))
        }
        Request::Create { name, network } => {
            validate(&name, &network)?;
            if device.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "TUN сеанса уже открыт",
                ));
            }
            let c_name = std::ffi::CString::new(name.as_str()).map_err(io::Error::other)?;
            if unsafe { libc::if_nametoindex(c_name.as_ptr()) } != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "Чужой или еще работающий интерфейс не подключается",
                ));
            }
            let mut config = tun::Configuration::default();
            config.tun_name(&name);
            config.platform_config(|value| {
                value.ensure_root_privileges(false);
            });
            let native = tun::create(&config).map_err(io::Error::other)?;
            let raw = unsafe { libc::fcntl(native.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
            *device = Some(Device {
                device: native,
                name,
                network,
            });
            Ok((Vec::new(), Some(descriptor)))
        }
        Request::Peer { peer } => {
            ip.set_peer(peer)?;
            Ok((Vec::new(), None))
        }
        Request::Configure {} => {
            let current = device
                .as_mut()
                .ok_or_else(|| invalid("TUN еще не создан"))?;
            let mut config = tun::Configuration::default();
            config
                .address(current.network.client_ip)
                .netmask(current.network.netmask())
                .mtu(current.network.mtu)
                .up();
            current
                .device
                .configure(&config)
                .map_err(io::Error::other)?;
            Ok((Vec::new(), None))
        }
        Request::Release {} => {
            ip.clear()?;
            *routes = None;
            *device = None;
            Ok((Vec::new(), None))
        }
        Request::Ip { batch } => {
            if batch.len() > MAX_REQUEST {
                return Err(invalid("Превышен размер команд сети"));
            }
            let tun = &device
                .as_ref()
                .ok_or_else(|| invalid("TUN еще не создан"))?
                .name;
            let commands = super::batch::parse_batch(&batch).map_err(io::Error::other)?;
            Ok((ip.apply(commands, tun)?, None))
        }

        Request::Firewall { name, peer, mark } => {
            if !device.as_ref().is_some_and(|value| value.name == name)
                || mark.is_some_and(|m| m != assigned_mark)
            {
                return Err(invalid("Firewall не принадлежит открытому TUN"));
            }
            if firewall_lease.is_none() {
                *firewall_lease = Some(acquire_firewall(Some(*owner_uid))?);
            }
            let mut protection = KillSwitch::new(name, peer.to_string());
            if let Some(mark) = mark {
                protection = protection.with_mark(mark);
            }
            let result = protection.activate().map_err(io::Error::other);
            *firewall = Some(protection);
            result?;
            Ok((Vec::new(), None))
        }
        Request::ClearFirewall {} => {
            if let Some(mut protection) = firewall.take() {
                protection.deactivate();
            }
            if let Some(lease) = firewall_lease.as_ref() {
                lease.set_len(0)?;
                lease.sync_all()?;
            }
            *firewall_lease = None;
            Ok((Vec::new(), None))
        }
        Request::Stop {} => Ok((Vec::new(), None)),
    }
}

pub(crate) fn acquire_firewall(uid: Option<u32>) -> io::Result<std::fs::File> {
    use std::io::{Read, Seek, Write};
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let directory = Path::new("/run/aivpn-network");
    match std::fs::DirBuilder::new().mode(0o711).create(directory) {
        Ok(()) => (),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e),
    }
    let meta = std::fs::symlink_metadata(directory)?;
    if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err(invalid("Небезопасный журнал firewall"));
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("firewall.lock"))?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != 0 || meta.nlink() != 1 || meta.mode() & 0o077 != 0 {
        return Err(invalid("Небезопасный владелец firewall"));
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        return Err(io::Error::other("Firewall принадлежит работающему сеансу"));
    }
    let mut previous = String::new();
    Read::by_ref(&mut file)
        .take(32)
        .read_to_string(&mut previous)?;
    if let Some(uid) = uid {
        if !previous.is_empty() && previous.trim().parse::<u32>() != Ok(uid) {
            return Err(invalid("Прежняя защита принадлежит другому пользователю"));
        }
        file.set_len(0)?;
        file.rewind()?;
        write!(&mut file, "{uid}\n")?;
        file.sync_all()?;
    }
    Ok(file)
}

pub(super) fn serve() -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Для сетевого помощника нужны права root",
        ));
    }
    let parent = unsafe { libc::getppid() };
    if parent <= 1 {
        return Err(invalid("Нет процесса владельца"));
    }
    let status = std::fs::read_to_string(format!("/proc/{parent}/status"))?;
    let owner_uid: u32 = status
        .lines()
        .find_map(|line| {
            line.strip_prefix("Uid:")
                .and_then(|value| value.split_whitespace().nth(1))
        })
        .ok_or_else(|| invalid("Нет UID владельца"))?
        .parse()
        .map_err(io::Error::other)?;
    if let Some(uid) = std::env::var_os("PKEXEC_UID") {
        if uid.to_str().and_then(|s| s.parse::<u32>().ok()) != Some(owner_uid) {
            return Err(invalid("Не совпал владелец разрешения Polkit"));
        }
    }
    let directory = Path::new("/run/aivpn-network");
    if !directory.exists() {
        use std::os::unix::fs::DirBuilderExt;
        match std::fs::DirBuilder::new().mode(0o711).create(directory) {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
            Err(error) => return Err(error),
        }
    }
    for part in directory.ancestors() {
        let meta = std::fs::symlink_metadata(part)?;
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(invalid("Небезопасный каталог сетевого канала"));
        }
    }
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o711))?;
    let path = SocketPath(directory.join(format!("{:032x}.sock", rand::random::<u128>())));
    let listener = UnixListener::bind(&path.0)?;
    std::fs::set_permissions(&path.0, std::fs::Permissions::from_mode(0o600))?;
    let c_path =
        std::ffi::CString::new(path.0.as_os_str().as_encoded_bytes()).map_err(io::Error::other)?;
    if unsafe { libc::chown(c_path.as_ptr(), owner_uid, u32::MAX) } < 0 {
        return Err(io::Error::last_os_error());
    }
    println!("{}", path.0.display());
    std::io::stdout().flush()?;
    let sink = std::fs::OpenOptions::new().write(true).open("/dev/null")?;
    if unsafe { libc::dup2(sink.as_raw_fd(), libc::STDOUT_FILENO) } < 0 {
        return Err(io::Error::last_os_error());
    }
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let socket = loop {
        if unsafe { libc::getppid() } != parent || Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Владелец не подключился к помощнику",
            ));
        }
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(error) => return Err(error),
        }
    };
    let watch = socket.try_clone()?;
    let mut stream = LocalStream::new(socket);
    let credentials = stream.peer_credentials()?;
    if credentials.uid != owner_uid || credentials.pid.get() != parent as u32 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Чужой владелец сетевого канала",
        ));
    }
    let owner_process = stream.peer_process().ok();
    drop(path);
    let mut state = Resources {
        device: None,
        firewall: None,
        routes: None,
        ip: super::owned::OwnedIp::new(),
        owner_uid,
        firewall_lease: None,
    };
    loop {
        if unsafe { libc::getppid() } != parent {
            break;
        }
        let mut events = vec![libc::pollfd {
            fd: watch.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        if let Some(owner) = &owner_process {
            events.push(libc::pollfd {
                fd: owner.as_fd().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        let timeout = if owner_process.is_some() { -1 } else { 1000 };
        let ready =
            unsafe { libc::poll(events.as_mut_ptr(), events.len() as libc::nfds_t, timeout) };
        if events.get(1).is_some_and(|event| event.revents != 0) {
            break;
        }
        if ready < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io::Error::last_os_error());
        }
        if ready == 0 {
            continue;
        }
        let frame = match stream.receive(Some(Duration::from_secs(5))) {
            Ok(frame) => frame,
            Err(_) => break,
        };
        if frame.payload.len() > MAX_REQUEST || frame.descriptors.len() > 1 {
            return Err(invalid("Недопустимый сетевой запрос"));
        }
        let request: Request = serde_json::from_slice(&frame.payload)?;
        let stop = matches!(request, Request::Stop {});
        let (reply, descriptor) = match run_request(request, &mut state, &frame.descriptors) {
            Ok((statuses, descriptor)) => (
                Reply {
                    error: None,
                    statuses,
                },
                descriptor,
            ),
            Err(error) => (
                Reply {
                    error: Some(error.to_string()),
                    statuses: Vec::new(),
                },
                None,
            ),
        };
        let handles: Vec<_> = descriptor
            .as_ref()
            .map(|fd| fd.as_fd())
            .into_iter()
            .collect();
        let sent = stream.send(&serde_json::to_vec(&reply)?, &handles);
        if stop {
            break;
        }
        sent?;
    }
    Ok(())
}
