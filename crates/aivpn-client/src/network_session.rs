//! Закрытый канал обычного клиента с ограниченным сетевым помощником.

use aivpn_desktop_agent::unix::{Frame, LocalStream};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, BufRead, Read},
    os::{
        fd::{AsRawFd, BorrowedFd, OwnedFd},
        unix::net::UnixStream,
    },
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, Weak,
    },
    time::Duration,
};

pub const IMAGE: &str = "/usr/libexec/aivpn/aivpn";
pub const HELPER_ROLE: &str = "__network-helper";
pub const MAX_REQUEST: usize = 64 * 1024;
struct Sessions {
    current: Weak<NetworkSession>,
    held: Option<Arc<NetworkSession>>,
    owners: usize,
}
static CURRENT: Mutex<Sessions> = Mutex::new(Sessions {
    current: Weak::new(),
    held: None,
    owners: 0,
});

pub struct NetworkOwner;
pub fn keep_alive() -> io::Result<NetworkOwner> {
    let mut state = CURRENT
        .lock()
        .map_err(|_| io::Error::other("Закрыт владелец сети"))?;
    state.owners = state
        .owners
        .checked_add(1)
        .ok_or_else(|| io::Error::other("Превышено число владельцев"))?;
    state.held = state.current.upgrade();
    Ok(NetworkOwner)
}
impl Drop for NetworkOwner {
    fn drop(&mut self) {
        let held = if let Ok(mut state) = CURRENT.lock() {
            state.owners = state.owners.saturating_sub(1);
            if state.owners == 0 {
                state.held.take()
            } else {
                None
            }
        } else {
            None
        };
        drop(held);
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Create {
        name: String,
        network: aivpn_common::network_config::ClientNetworkConfig,
    },
    Peer {
        peer: std::net::IpAddr,
    },
    Configure {},
    Release {},
    Ip {
        batch: String,
    },
    Firewall {
        name: String,
        peer: std::net::IpAddr,
        mark: Option<u32>,
    },
    ClearFirewall {},
    Transport {
        mark: Option<u32>,
    },
    MarkSocket {
        mark: u32,
    },
    Stop {},
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub error: Option<String>,
    pub statuses: Vec<(String, i32)>,
}

pub struct NetworkSession {
    alive: AtomicBool,
    stream: Mutex<LocalStream>,
    child: Mutex<Option<Child>>,
}

pub struct TunLease {
    session: Arc<NetworkSession>,
}

impl TunLease {
    pub fn configure(&self) -> io::Result<()> {
        self.session.request(Request::Configure {}).map(|_| ())
    }
}

impl Drop for TunLease {
    fn drop(&mut self) {
        let _ = self.session.request(Request::Release {});
    }
}

pub fn create_tun(
    name: &str,
    network: aivpn_common::network_config::ClientNetworkConfig,
) -> io::Result<(OwnedFd, TunLease)> {
    let session = prepare()?;
    let (_, mut descriptors) = session.request(Request::Create {
        name: name.to_owned(),
        network,
    })?;
    let descriptor = descriptors
        .pop()
        .ok_or_else(|| io::Error::other("Нет дескриптора TUN"))?;
    Ok((descriptor, TunLease { session }))
}

pub fn needed() -> bool {
    if unsafe { libc::geteuid() } == 0 {
        return false;
    }
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    let mut header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [[0u32; 3]; 2];
    (unsafe { libc::syscall(libc::SYS_capget, &mut header, &mut data) }) < 0
        || data[0][0] & (1 << 12) == 0
}

pub fn current() -> Option<Arc<NetworkSession>> {
    CURRENT.lock().ok()?.current.upgrade()
}

/// Сильный владелец живет вместе с обычным VPN-сеансом, включая переподключения.
pub fn prepare() -> io::Result<Arc<NetworkSession>> {
    let mut slot = CURRENT
        .lock()
        .map_err(|_| io::Error::other("Закрыт владелец сетевого помощника"))?;
    if let Some(session) = slot.current.upgrade() {
        if session.running() {
            return Ok(session);
        }
    }
    validate_image(Path::new(IMAGE), false)?;
    validate_image(Path::new("/usr/bin/pkexec"), true)?;
    let child = Command::new("/usr/bin/pkexec")
        .args([
            "--disable-internal-agent",
            IMAGE,
            HELPER_ROLE,
            "--tun-session",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut startup = StartupChild(Some(child));
    let child = startup.0.as_mut().unwrap();
    let output = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("Нет ответа установщика сети"))?;
    let mut readiness = libc::pollfd {
        fd: output.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ready = unsafe { libc::poll(&mut readiness, 1, 120_000) };
    if ready <= 0 {
        let _ = child.kill();
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Истекло ожидание разрешения на настройку сети",
        ));
    }
    let mut line = String::new();
    let read = io::BufReader::new(output).take(4097).read_line(&mut line);
    if read.is_err() || line.len() > 4096 || !line.ends_with('\n') {
        return Err(io::Error::other(
            "Сетевой помощник не подтвердил запуск или разрешение отменено",
        ));
    }
    let path = line.trim_end();
    let socket = Path::new(path);
    if !valid_socket_path(socket) {
        return Err(io::Error::other("Недопустимый адрес сетевого помощника"));
    }
    let stream = LocalStream::new(UnixStream::connect(socket)?);
    let peer = stream.peer_credentials()?;
    if peer.uid != 0 || peer.pid.get() != child.id() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Не подтвержден root-процесс сетевого помощника",
        ));
    }
    let session = Arc::new(NetworkSession {
        alive: AtomicBool::new(true),
        stream: Mutex::new(stream),
        child: Mutex::new(startup.0.take()),
    });
    slot.current = Arc::downgrade(&session);
    if slot.owners > 0 {
        slot.held = Some(session.clone());
    }
    Ok(session)
}

pub fn validate_image(path: &Path, allow_setuid: bool) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    for component in path.ancestors() {
        let meta = std::fs::symlink_metadata(component)?;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 || meta.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Нужен установленный образ в защищенном системном каталоге",
            ));
        }
    }
    let meta = std::fs::metadata(path)?;
    if !meta.is_file()
        || meta.mode() & 0o3000 != 0
        || (!allow_setuid && meta.mode() & 0o4000 != 0)
        || meta.mode() & 0o111 == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Недопустимые права образа сетевого помощника",
        ));
    }
    if !allow_setuid {
        let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(io::Error::other)?;
        let caps = unsafe {
            libc::getxattr(
                path.as_ptr(),
                c"security.capability".as_ptr(),
                std::ptr::null_mut(),
                0,
            )
        };
        if caps >= 0
            || !matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ENODATA | libc::ENOTSUP)
            )
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Общий образ не должен иметь file capabilities",
            ));
        }
    }
    Ok(())
}

fn valid_socket_path(path: &Path) -> bool {
    path.parent() == Some(Path::new("/run/aivpn-network"))
        && path
            .file_name()
            .and_then(|value| value.to_str())
            .and_then(|value| value.strip_suffix(".sock"))
            .is_some_and(|value| {
                value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
}

struct StartupChild(Option<Child>);
impl Drop for StartupChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = std::thread::Builder::new()
                .name("aivpn-startup-reaper".into())
                .spawn(move || {
                    let _ = child.wait();
                });
        }
    }
}

impl NetworkSession {
    fn running(&self) -> bool {
        if !self.alive.load(Ordering::Acquire) {
            return false;
        }
        if self
            .child
            .lock()
            .ok()
            .and_then(|mut child| {
                child
                    .as_mut()
                    .and_then(|child| child.try_wait().ok().flatten())
            })
            .is_some()
        {
            self.alive.store(false, Ordering::Release);
            return false;
        }
        true
    }
    pub fn request(&self, request: Request) -> io::Result<(Reply, Vec<OwnedFd>)> {
        self.request_with_fds(request, &[])
    }

    fn request_with_fds(
        &self,
        request: Request,
        descriptors: &[BorrowedFd<'_>],
    ) -> io::Result<(Reply, Vec<OwnedFd>)> {
        let payload = serde_json::to_vec(&request)?;
        if payload.len() > MAX_REQUEST {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Превышен размер сетевого запроса",
            ));
        }
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| io::Error::other("Закрыт сетевой канал"))?;
        if let Err(error) = stream.send(&payload, descriptors) {
            self.alive.store(false, Ordering::Release);
            return Err(error);
        }
        let Frame {
            payload,
            descriptors,
        } = match stream.receive(Some(Duration::from_secs(10))) {
            Ok(frame) => frame,
            Err(error) => {
                self.alive.store(false, Ordering::Release);
                return Err(error);
            }
        };
        let reply: Reply = serde_json::from_slice(&payload)?;
        if let Some(error) = &reply.error {
            return Err(io::Error::other(error.clone()));
        }
        let expected = usize::from(matches!(request, Request::Create { .. }));
        if descriptors.len() != expected {
            return Err(io::Error::other(
                "Неподтвержденное число сетевых дескрипторов",
            ));
        }
        if matches!(request, Request::Stop {}) {
            self.alive.store(false, Ordering::Release);
        }
        Ok((reply, descriptors))
    }
}

impl Drop for NetworkSession {
    fn drop(&mut self) {
        if let Ok(stream) = self.stream.get_mut() {
            if let Ok(payload) = serde_json::to_vec(&Request::Stop {}) {
                let _ = stream.send(&payload, &[]);
            }
        }
        if let Ok(child) = self.child.get_mut() {
            if let Some(mut child) = child.take() {
                let _ = std::thread::Builder::new()
                    .name("aivpn-helper-reaper".into())
                    .spawn(move || {
                        let _ = child.wait();
                    });
            }
        }
    }
}

pub fn assigned_transport_mark(uid: u32) -> io::Result<u32> {
    if uid >= 0x80000000 {
        return Err(io::ErrorKind::Unsupported.into());
    }
    Ok(0x80000000 | uid)
}

/// Подменяется только явно поддерживающая делегирование защита сокетов.
pub fn delegated_guard(
    guard: aivpn_common::transport::SharedGuard,
) -> io::Result<aivpn_common::transport::SharedGuard> {
    if !needed() || guard.routing_mark().is_none() {
        return Ok(guard);
    }
    guard
        .with_assigned_socket_protector(
            assigned_transport_mark(unsafe { libc::getuid() })?,
            Arc::new(|fd, mark| {
                let session = prepare()?;
                let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
                session.request_with_fds(Request::MarkSocket { mark }, &[borrowed])?;
                Ok(())
            }),
        )
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "Защита транспорта не поддерживает делегирование сетевых прав",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bootstrap_path_is_exact_and_not_a_user_directory() {
        assert!(valid_socket_path(Path::new(
            "/run/aivpn-network/0123456789abcdef0123456789abcdef.sock"
        )));
        for path in [
            "/tmp/0123456789abcdef0123456789abcdef.sock",
            "/run/aivpn-network/c.sock",
            "/run/aivpn-network/../0123456789abcdef0123456789abcdef.sock",
        ] {
            assert!(!valid_socket_path(Path::new(path)), "{path}");
        }
    }
    #[test]
    fn network_requests_reject_extra_fields_and_roles() {
        assert!(serde_json::from_str::<Request>(r#"{"action":"stop","role":"cli"}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"action":"exec","program":"sh"}"#).is_err());
    }
}
