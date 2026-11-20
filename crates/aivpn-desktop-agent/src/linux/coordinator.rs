//! Только служба создает сеанс и связывает приватный канал с собственным Child.
use super::{worker_protocol::WorkerEvent, LinuxRoutingBackend};
pub use crate::connection::WorkerConfiguration;
use crate::{
    control::Control,
    protocol::{BackendState, Command as ControlCommand, ErrorCode, Reply, Request, Response},
    state::StateDirectory,
    unix::LocalStream,
};
use aivpn_desktop_policy::{Authority, ProfileAssignment, ProfileLease};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io,
    net::SocketAddr,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

#[derive(Debug)]
pub enum WorkerProgress {
    Idle,
    Reconnecting,
    TransportRegistered { cookie: u64 },
    Assigned { generation: u64 },
    Disconnected,
    Exited,
}

struct WorkerHome(PathBuf);
impl Drop for WorkerHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Session {
    administration: crate::administration::link::AdministrationLink,
    generation: u64,
    lease: ProfileLease,
    profile: String,
    authority: Authority,
    child: Child,
    pidfd: OwnedFd,
    monitor: OwnedFd,
    channel: LocalStream,
    peer: SocketAddr,
    source: WorkerConfiguration,
    _home: WorkerHome,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.administration.close();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
pub struct LinuxCoordinator {
    control: Control<StateDirectory, LinuxRoutingBackend>,
    sessions: BTreeMap<String, Session>,
    poll_cursor: usize,
    runtime_failure: Option<String>,
    next: u64,
    dns: crate::dns::DnsRequests,
    dns_next: u64,
    dns_active: Option<(u64, SocketAddr)>,
    dns_wake: Option<std::sync::Arc<OwnedFd>>,
}
impl LinuxCoordinator {
    pub fn dns_relay_uses_ipv6(&mut self) -> io::Result<bool> {
        self.control.backend_and_state().1.dns_relay_uses_ipv6()
    }
    pub fn system_dns_epoch(&mut self) -> io::Result<Option<u64>> {
        self.control.backend_and_state().1.system_dns_epoch()
    }
    pub fn prepare(
        &mut self,
        authority: &Authority,
        request: Request,
    ) -> crate::protocol::PreparedResponse {
        let ControlCommand::SessionAdmin {
            profile,
            query,
            assignment_generation,
            session_id,
        } = request.command()
        else {
            return crate::protocol::PreparedResponse::Ready(self.handle(authority, request));
        };
        let id = request.id();
        let capability = (|| {
            self.control
                .state()
                .authorize_profile_control(authority, profile)?;
            let session = self.sessions.get(profile).ok_or(ErrorCode::NotFound)?;
            self.control.authorize_session_administration(
                authority,
                profile,
                &session.lease,
                *assignment_generation,
                *session_id,
            )?;
            session
                .administration
                .capability(session.generation)
                .map_err(|_| ErrorCode::NotFound)
        })();
        match capability {
            Err(code) => crate::protocol::PreparedResponse::Ready(Response::failure(id, code)),
            Ok(capability) => {
                let query = query.clone();
                crate::protocol::PreparedResponse::Deferred(Box::new(move || {
                    match capability.request(query) {
                        Ok(output) => Response::success(id, Reply::SessionReply { output }),
                        Err(error) => Response::failure(id, runtime_error(error)),
                    }
                }))
            }
        }
    }
    pub fn new(control: Control<StateDirectory, LinuxRoutingBackend>) -> Self {
        Self {
            control,
            sessions: BTreeMap::new(),
            poll_cursor: 0,
            runtime_failure: None,
            next: 0,
            dns: crate::dns::DnsRequests::new(),
            dns_next: 0,
            dns_active: None,
            dns_wake: None,
        }
    }
    pub fn handle(&mut self, authority: &Authority, request: Request) -> Response {
        if matches!(request.command(), ControlCommand::Decommission {}) {
            let result = self
                .control
                .state()
                .authorize_decommission(authority)
                .and_then(|()| self.stop_profile().map_err(runtime_error));
            if let Err(code) = result {
                return Response::failure(request.id(), code);
            }
            return self.control.handle(authority, request);
        }
        let outcome = match request.command() {
            ControlCommand::StartProfile {
                profile,
                connection,
            } => self
                .control
                .state()
                .authorize_profile_control(authority, profile)
                .and_then(|()| {
                    let config = WorkerConfiguration::from_document(connection)
                        .map_err(|_| ErrorCode::InvalidRequest)?;
                    config
                        .validate_identity()
                        .map_err(|_| ErrorCode::InvalidRequest)?;
                    self.start_profile(profile, authority, config)
                        .map(|_| Reply::Done {})
                        .map_err(|error| {
                            eprintln!("Не удалось запустить VPN-профиль: {error}");
                            runtime_error(error)
                        })
                }),
            ControlCommand::StopProfile { profile } => self
                .control
                .state()
                .authorize_profile_control(authority, profile)
                .and_then(|()| {
                    self.stop_profile_id(profile)
                        .map(|()| Reply::Done {})
                        .map_err(runtime_error)
                }),
            _ => return self.control.handle(authority, request),
        };
        match outcome {
            Ok(reply) => Response::success(request.id(), reply),
            Err(code) => Response::failure(request.id(), code),
        }
    }
    pub fn backend_state(&self) -> BackendState {
        self.control.backend_state()
    }
    pub fn transport_dns_servers(&mut self) -> io::Result<Vec<SocketAddr>> {
        self.control.transport_dns_servers()
    }
    pub fn failure_reason(&mut self) -> Option<&str> {
        self.control.backend_and_state().1.last_failure()
    }
    pub fn publication(&mut self) -> Option<(u64, u64, u32, [u8; 32])> {
        self.control.backend_and_state().1.publication()
    }
    pub fn worker_pid(&self) -> Option<u32> {
        if self.sessions.len() == 1 {
            self.sessions
                .values()
                .next()
                .map(|session| session.child.id())
        } else {
            None
        }
    }
    pub fn worker_pid_for(&self, profile: &str) -> Option<u32> {
        self.sessions.get(profile).map(|session| session.child.id())
    }
    pub fn take_runtime_failure(&mut self) -> Option<String> {
        self.runtime_failure.take()
    }
    pub fn dns_session_identity(
        &mut self,
        peer: SocketAddr,
    ) -> io::Result<Option<([u8; 16], u64)>> {
        let catalog = self.control.state().profiles();
        let Some(id) = catalog.global_dns_profile() else {
            return Ok(None);
        };
        let Some(session) = self.sessions.get_mut(id) else {
            return Ok(None);
        };
        if session.child.try_wait()?.is_some() {
            return Ok(None);
        }
        let Ok(profile) = catalog.session_profile(&session.lease) else {
            return Ok(None);
        };
        if !(if peer.is_ipv4() {
            profile.ready_ipv4
        } else {
            profile.ready_ipv6
        }) {
            return Ok(None);
        }
        Ok(Some((
            session.lease.session_id(),
            profile.assignment_generation,
        )))
    }
    pub fn dns_route(&mut self, peer: SocketAddr) -> io::Result<crate::dns::DnsRoutePort> {
        let id = self
            .control
            .state()
            .profiles()
            .global_dns_profile()
            .ok_or_else(denied)?
            .to_owned();
        let session = self.sessions.get_mut(&id).ok_or_else(denied)?;
        if session.child.try_wait()?.is_some() {
            return Err(denied());
        }
        let catalog = self.control.state().profiles();
        let profile = catalog
            .session_profile(&session.lease)
            .map_err(|_| denied())?;
        if catalog.global_dns_profile() != Some(session.profile.as_str())
            || !(if peer.is_ipv4() {
                profile.ready_ipv4
            } else {
                profile.ready_ipv6
            })
        {
            return Err(denied());
        }
        let lease = session.lease.clone();
        if self.dns_wake.is_none() {
            let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = std::sync::Arc::new(unsafe { OwnedFd::from_raw_fd(fd) });
            let signal = fd.clone();
            self.dns
                .set_wake(std::sync::Arc::new(move || signal_dns(&signal)));
            self.dns_wake = Some(fd);
        }
        self.dns_next = self.dns_next.checked_add(1).ok_or_else(denied)?;
        let route = self
            .dns
            .route(lease, profile.assignment_generation, self.dns_next, peer)?;
        self.control
            .backend_and_state()
            .1
            .prepare_dns_route(&id, self.dns_next)?;
        self.dns_active = Some((self.dns_next, peer));
        Ok(route)
    }
    pub fn protect_system_dns(
        &mut self,
        listeners: Vec<OwnedFd>,
    ) -> io::Result<Vec<crate::dns::DnsSocketLease>> {
        if self
            .control
            .state()
            .profiles()
            .global_dns_profile()
            .is_none()
        {
            return Err(denied());
        }
        self.control
            .backend_and_state()
            .1
            .protect_system_dns(listeners)
    }
    fn dns_requests(&mut self) -> io::Result<()> {
        if let Some(fd) = &self.dns_wake {
            let mut value = 0u64;
            let read = unsafe { libc::read(fd.as_raw_fd(), (&mut value as *mut u64).cast(), 8) };
            if read < 0
                && !matches!(
                    io::Error::last_os_error().raw_os_error(),
                    Some(libc::EAGAIN | libc::EINTR)
                )
            {
                return Err(io::Error::last_os_error());
            }
        }
        for index in 0..16 {
            let request = match self.dns.receive() {
                Ok(request) => request,
                Err(std::sync::mpsc::TryRecvError::Empty) => return Ok(()),
                Err(_) => return Err(io::ErrorKind::BrokenPipe.into()),
            };
            let crate::dns::Registration {
                socket,
                lease,
                assignment_generation,
                resolver_epoch,
                peer,
                reply,
            } = request;
            let result = (|| {
                if self.dns_active != Some((resolver_epoch, peer)) {
                    return Err(denied());
                }
                let id = self
                    .control
                    .state()
                    .profiles()
                    .global_dns_profile()
                    .ok_or_else(denied)?;
                let session = self.sessions.get_mut(id).ok_or_else(denied)?;
                if session.child.try_wait()?.is_some() {
                    return Err(denied());
                }
                let catalog = self.control.state().profiles();
                let profile = catalog.session_profile(&lease).map_err(|_| denied())?;
                if profile.id != session.profile
                    || catalog.global_dns_profile() != Some(session.profile.as_str())
                    || profile.assignment_generation != assignment_generation
                    || !(if peer.is_ipv4() {
                        profile.ready_ipv4
                    } else {
                        profile.ready_ipv6
                    })
                {
                    return Err(denied());
                }
                self.control.backend_and_state().1.register_dns_socket(
                    socket,
                    peer,
                    assignment_generation,
                    resolver_epoch,
                )
            })();
            reply(result);
            if index == 15 {
                if let Some(fd) = &self.dns_wake {
                    signal_dns(fd)?;
                }
            }
        }
        Ok(())
    }
    pub fn start_profile(
        &mut self,
        profile: &str,
        authority: &Authority,
        mut configuration: WorkerConfiguration,
    ) -> io::Result<u32> {
        self.control
            .state()
            .authorize_profile_control(authority, profile)
            .map_err(|_| denied())?;
        configuration.validate_identity()?;
        if self.sessions.contains_key(profile) || self.sessions.len() >= 256 {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        if !matches!(
            self.control.backend_state(),
            BackendState::Guarded | BackendState::Active
        ) {
            return Err(denied());
        }
        let resolved = self
            .control
            .resolve_worker_configuration(&mut configuration)?;
        let peer = resolved.numeric_peer()?;
        let lease = self
            .control
            .begin_profile_session(profile, authority)
            .map_err(|_| denied())?;
        let result = (|| {
            let (state, backend) = self.control.backend_and_state();
            let tunnel = backend.begin_path(state, profile)?;
            let descriptor = tunnel.duplicate_descriptor()?;
            let name = tunnel.name().to_owned();
            self.next = self.next.checked_add(1).ok_or_else(denied)?;
            let (mut session, administration) =
                spawn(lease.clone(), peer, self.next, configuration)?;
            let restricted = session.channel.receive(Some(Duration::from_secs(10)))?;
            if restricted.payload != b"RESTRICTED" || !restricted.descriptors.is_empty() {
                return Err(denied());
            }
            verify_restricted(&mut session)?;
            session.channel.send(&serde_json::to_vec(&serde_json::json!({"name":name,"generation":session.generation,"connection":resolved.connection}))?,&[descriptor.as_fd(), administration.as_fd()])?;
            session.profile = profile.into();
            session.authority = authority.clone();
            Ok::<_, io::Error>(session)
        })();
        match result {
            Ok(session) => {
                let pid = session.child.id();
                self.sessions.insert(profile.into(), session);
                Ok(pid)
            }
            Err(error) => {
                let _ = self.control.backend_and_state().1.revoke_transport(profile);
                let _ = self.control.disconnect_profile_session(&lease);
                let _ = self.control.backend_and_state().1.end_path(profile);
                Err(error)
            }
        }
    }
    /// Завершение службы закрывает все ее профили; пользовательский Stop закрывает только свой.
    pub fn stop_profile(&mut self) -> io::Result<()> {
        let profiles: Vec<_> = self.sessions.keys().cloned().collect();
        let mut failed = None;
        for profile in profiles {
            if let Err(error) = self.stop_profile_id(&profile) {
                failed.get_or_insert(error);
            }
        }
        match failed {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    fn stop_profile_id(&mut self, profile: &str) -> io::Result<()> {
        if let Some(session) = self.sessions.remove(profile) {
            session.administration.close();
            if self.control.state().profiles().global_dns_profile() == Some(profile) {
                self.dns_active = None;
            }
            let revoked = self.control.backend_and_state().1.revoke_transport(profile);
            let disconnected = self
                .control
                .disconnect_profile_session(&session.lease)
                .map_err(|_| denied());
            drop(session);
            let ended = self.control.backend_and_state().1.end_path(profile);
            revoked.and(disconnected).and(ended)?;
        }
        Ok(())
    }
    fn activity_fds(&self, profiles: &[String], control: i32) -> Vec<libc::pollfd> {
        let mut fds = Vec::with_capacity(2 + profiles.len() * 2);
        fds.push(libc::pollfd {
            fd: self.dns_wake.as_ref().map_or(-1, |fd| fd.as_raw_fd()),
            events: libc::POLLIN,
            revents: 0,
        });
        for profile in profiles {
            let session = &self.sessions[profile];
            fds.push(libc::pollfd {
                fd: session.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
            fds.push(libc::pollfd {
                fd: session.monitor.as_raw_fd(),
                events: libc::POLLIN | libc::POLLRDHUP,
                revents: 0,
            });
        }
        fds.push(libc::pollfd {
            fd: control,
            events: libc::POLLIN,
            revents: 0,
        });
        fds
    }
    /// Запрос Control, DNS или событие работника будит того же единственного writer.
    pub fn wait_for_activity(&self, control: BorrowedFd<'_>, timeout: Duration) -> io::Result<()> {
        let profiles = self.sessions.keys().cloned().collect::<Vec<_>>();
        let mut fds = self.activity_fds(&profiles, control.as_raw_fd());
        let result = unsafe {
            libc::poll(
                fds.as_mut_ptr(),
                fds.len() as libc::nfds_t,
                timeout.as_millis().min(5000) as i32,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        if [fds[0].revents, fds.last().unwrap().revents]
            .iter()
            .any(|events| events & (libc::POLLERR | libc::POLLNVAL) != 0)
        {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }
    pub fn step(&mut self, timeout: Duration) -> io::Result<WorkerProgress> {
        self.dns_requests()?;
        let maintenance = (|| {
            self.control.backend_and_state().1.maintain()?;
            self.control.backend_and_state().1.refresh_transport()
        })();
        if let Err(error) = maintenance {
            let _ = self.stop_profile();
            return Err(error);
        }
        let mut profiles: Vec<_> = self.sessions.keys().cloned().collect();
        if profiles.is_empty() {
            return Ok(WorkerProgress::Idle);
        }
        let cursor = self.poll_cursor % profiles.len();
        profiles.rotate_left(cursor);
        let mut fds = self.activity_fds(&profiles, -1);
        let ready = unsafe {
            libc::poll(
                fds.as_mut_ptr(),
                fds.len() as libc::nfds_t,
                timeout.as_millis().min(5000) as i32,
            )
        };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(WorkerProgress::Idle);
            }
            return Err(error);
        }
        if fds[0].revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(io::Error::other("Не работает пробуждение DNS"));
        }
        if fds[0].revents & libc::POLLIN != 0 {
            self.dns_requests()?;
        }
        let selected = profiles.iter().enumerate().find(|(index, profile)| {
            fds[1 + index * 2].revents != 0
                || fds[2 + index * 2].revents != 0
                || self.sessions[*profile].administration.is_closed()
        });
        let Some((index, profile)) = selected else {
            return Ok(WorkerProgress::Idle);
        };
        self.poll_cursor = (cursor + index + 1) % profiles.len();
        let mut session = self.sessions.remove(profile).ok_or_else(denied)?;
        let result = self.step_session(&mut session, Duration::ZERO);
        match result {
            Ok(WorkerProgress::Disconnected | WorkerProgress::Exited) | Err(_) => {
                if let Err(error) = &result {
                    self.runtime_failure = Some(format!("Профиль {profile}: {error}"));
                }
                let cause = self.runtime_failure.clone();
                session.administration.close();
                if self.control.state().profiles().global_dns_profile() == Some(profile) {
                    self.dns_active = None;
                }
                let revoked = self.control.backend_and_state().1.revoke_transport(profile);
                let disconnected = self
                    .control
                    .disconnect_profile_session(&session.lease)
                    .map_err(|_| denied());
                drop(session);
                let ended = self.control.backend_and_state().1.end_path(profile);
                revoked.and(disconnected).and(ended).map_err(|error| {
                    io::Error::other(format!(
                        "Закрытие профиля {profile}: {error}; причина: {}; backend: {}",
                        cause.as_deref().unwrap_or("сеанс завершен"),
                        self.control
                            .backend_and_state()
                            .1
                            .last_failure()
                            .unwrap_or("нет")
                    ))
                })?;
                Ok(WorkerProgress::Exited)
            }
            Ok(progress) => {
                self.sessions.insert(profile.clone(), session);
                Ok(progress)
            }
        }
    }
    fn step_session(
        &mut self,
        session: &mut Session,
        timeout: Duration,
    ) -> io::Result<WorkerProgress> {
        if session.administration.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Закрыт канал управления работником",
            ));
        }
        let mut fds = [
            libc::pollfd {
                fd: session.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: session.monitor.as_raw_fd(),
                events: libc::POLLIN | libc::POLLRDHUP,
                revents: 0,
            },
            libc::pollfd {
                fd: self.dns_wake.as_ref().map_or(-1, |fd| fd.as_raw_fd()),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let result = unsafe {
            libc::poll(
                fds.as_mut_ptr(),
                fds.len() as libc::nfds_t,
                timeout.as_millis().min(5000) as i32,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if result == 0 {
            return Ok(WorkerProgress::Idle);
        }
        if fds[0].revents != 0
            || fds[1].revents & (libc::POLLHUP | libc::POLLRDHUP | libc::POLLERR) != 0
        {
            return Ok(WorkerProgress::Exited);
        }
        if fds[2].revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(io::Error::other("Не работает пробуждение DNS"));
        }
        if fds[1].revents & libc::POLLIN == 0 {
            return Ok(WorkerProgress::Idle);
        }
        verify_restricted(session)?;
        self.control
            .state()
            .profiles()
            .session_profile(&session.lease)
            .map_err(|_| denied())?;
        let frame = session.channel.receive(None)?;
        let event: WorkerEvent = serde_json::from_slice(&frame.payload)?;
        if event.generation() != session.generation {
            return Err(denied());
        }
        let mut response = b"ACK".to_vec();
        let progress = match event {
            WorkerEvent::Transport { peer, .. } => {
                if peer != session.peer || frame.descriptors.len() != 1 {
                    return Err(denied());
                }
                let descriptor = frame.descriptors.into_iter().next().unwrap();
                let inspection = super::transport::ValidatedTransport::inspect(
                    descriptor,
                    peer,
                    session.child.id(),
                    self.control
                        .backend_and_state()
                        .1
                        .tunnel(&session.profile)?
                        .verify()?,
                )?;
                match inspection {
                    super::transport::TransportInspection::Ready(validated) => {
                        let cookie = validated.cookie();
                        self.control
                            .backend_and_state()
                            .1
                            .register_transport(&session.profile, validated)?;
                        WorkerProgress::TransportRegistered { cookie }
                    }
                    super::transport::TransportInspection::RouteUnavailable(error) => {
                        self.runtime_failure = Some(format!(
                            "Профиль {} ожидает системный маршрут: {error}",
                            session.profile
                        ));
                        response = b"RETRY".to_vec();
                        WorkerProgress::Idle
                    }
                }
            }
            WorkerEvent::Assignment { network, .. } => {
                if !frame.descriptors.is_empty() {
                    return Err(denied());
                }
                let identity = self
                    .control
                    .backend_and_state()
                    .1
                    .tunnel(&session.profile)?
                    .verify()?;
                self.control
                    .backend_and_state()
                    .1
                    .confirm_assignment(&session.profile, network)?;
                let generation = self
                    .control
                    .assign_profile(
                        &session.lease,
                        ProfileAssignment {
                            interface_id: identity.device_identity.get(),
                            ipv4: network.client_ip,
                            ipv6: network.ipv6.map(|network| network.address),
                        },
                    )
                    .map_err(|error| {
                        io::Error::other(format!(
                            "Назначение Control {error:?}: {}",
                            self.control
                                .backend_and_state()
                                .1
                                .last_failure()
                                .unwrap_or("backend не сообщил ошибку")
                        ))
                    })?;
                session.source.connected();
                WorkerProgress::Assigned { generation }
            }
            WorkerEvent::Reconnecting { .. } => {
                if !frame.descriptors.is_empty() {
                    return Err(denied());
                }
                let next_generation = session.generation.checked_add(1).ok_or_else(denied)?;
                session.administration.advance(next_generation)?;
                let revoked = self
                    .control
                    .backend_and_state()
                    .1
                    .revoke_transport(&session.profile);
                let disconnected = self
                    .control
                    .disconnect_profile_session(&session.lease)
                    .map_err(|_| denied());
                revoked.and(disconnected)?;
                session.source.finish_attempt();
                let resolved = self
                    .control
                    .resolve_worker_configuration(&mut session.source)?;
                session.peer = resolved.numeric_peer()?;
                session.lease = self
                    .control
                    .begin_profile_session(&session.profile, &session.authority)
                    .map_err(|_| denied())?;
                session.generation = next_generation;
                response = serde_json::to_vec(
                    &serde_json::json!({"next_generation":session.generation,"peer":session.peer}),
                )?;
                WorkerProgress::Reconnecting
            }
            WorkerEvent::Disconnected { .. } => {
                if !frame.descriptors.is_empty() {
                    return Err(denied());
                }
                WorkerProgress::Disconnected
            }
        };
        session.channel.send(&response, &[])?;
        Ok(progress)
    }
}

impl Drop for LinuxCoordinator {
    fn drop(&mut self) {
        let _ = self.stop_profile();
    }
}

fn runtime_error(error: io::Error) -> ErrorCode {
    match error.kind() {
        io::ErrorKind::AlreadyExists => ErrorCode::Conflict,
        io::ErrorKind::PermissionDenied => ErrorCode::AccessDenied,
        _ => ErrorCode::BackendUnavailable,
    }
}

fn spawn(
    lease: ProfileLease,
    peer: SocketAddr,
    number: u64,
    source: WorkerConfiguration,
) -> io::Result<(Session, OwnedFd)> {
    let (administration, child_administration) = crate::administration::unix::pair(1)?;
    for parent in ["/", "/usr", "/usr/libexec", "/usr/libexec/aivpn"] {
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(denied());
        }
    }
    let original = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/usr/libexec/aivpn/aivpn")?;
    let image = reserve_worker_image(&original)?;
    let metadata = original.metadata()?;
    drop(original);
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o7022 != 0
        || metadata.mode() & 0o111 == 0
        || metadata.nlink() != 1
    {
        return Err(denied());
    }
    let home = PathBuf::from(format!("/run/aivpn-worker-{}-{number}", std::process::id()));
    fs::create_dir(&home)?;
    let home = WorkerHome(home);
    fs::set_permissions(&home.0, fs::Permissions::from_mode(0o700))?;
    let home_c =
        std::ffi::CString::new(home.0.to_str().ok_or_else(denied)?).map_err(|_| denied())?;
    if unsafe { libc::chown(home_c.as_ptr(), 65532, 65532) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let (parent, child_channel) = UnixStream::pair()?;
    let control = child_channel.as_raw_fd();
    let monitor = parent.as_fd().try_clone_to_owned()?;
    let mut command = Command::new(format!("/proc/self/fd/{}", image.as_raw_fd()));
    command
        .arg("__packet-worker")
        .env_clear()
        .env("HOME", &home.0)
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(control, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::syscall(libc::SYS_close_range, 4u32, u32::MAX, 4u32) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setgroups(0, std::ptr::null()) < 0 {
                return Err(io::Error::last_os_error());
            }
            for capability in 0..64 {
                if libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) < 0
                    && io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL)
                {
                    return Err(io::Error::last_os_error());
                }
            }
            if libc::setresgid(65532, 65532, 65532) < 0
                || libc::setresuid(65532, 65532, 65532) < 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    drop(child_channel);
    drop(image);
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) } as i32;
    if raw < 0 {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::last_os_error());
    }
    Ok((
        Session {
            administration,
            source,
            generation: 1,
            lease,
            profile: String::new(),
            authority: Authority {
                user: aivpn_desktop_policy::Owner::LinuxUser { uid: 0 },
                machine_admin: false,
            },
            child,
            pidfd: unsafe { OwnedFd::from_raw_fd(raw) },
            monitor,
            channel: LocalStream::new(parent),
            peer,
            _home: home,
        },
        child_administration,
    ))
}
fn verify_restricted(session: &mut Session) -> io::Result<()> {
    if session.child.try_wait()?.is_some() {
        return Err(denied());
    }
    let status = fs::read_to_string(format!("/proc/{}/status", session.child.id()))?;
    for (key, expected) in [
        ("Uid:", "65532 65532 65532 65532"),
        ("Gid:", "65532 65532 65532 65532"),
        ("Groups:", ""),
        ("NoNewPrivs:", "1"),
        ("Seccomp:", "2"),
        ("CapInh:", "0000000000000000"),
        ("CapPrm:", "0000000000000000"),
        ("CapEff:", "0000000000000000"),
        ("CapBnd:", "0000000000000000"),
        ("CapAmb:", "0000000000000000"),
    ] {
        let actual = status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .ok_or_else(denied)?
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if actual != expected {
            return Err(denied());
        }
    }
    Ok(())
}
fn signal_dns(fd: &OwnedFd) -> io::Result<()> {
    let value = 1u64;
    let written = unsafe { libc::write(fd.as_raw_fd(), (&value as *const u64).cast(), 8) };
    if written == 8 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EAGAIN) {
        Ok(())
    } else {
        Err(error)
    }
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Не подтвержден собственный ограниченный работник или его сеанс",
    )
}

fn reserve_worker_image(file: &File) -> io::Result<OwnedFd> {
    let raw = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::IntoRawFd;
    #[test]
    fn worker_image_survives_descriptor_three_collision() {
        if std::env::var_os("AIVPN_FD_COLLISION_CHILD").is_none() {
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "linux::coordinator::tests::worker_image_survives_descriptor_three_collision",
                    "--nocapture",
                ])
                .env("AIVPN_FD_COLLISION_CHILD", "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let path = std::env::temp_dir().join(format!("aivpn-image-fd-{}", std::process::id()));
        let original = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut &original, b"held-image").unwrap();
        let raw = original.into_raw_fd();
        if raw != 3 {
            assert_eq!(unsafe { libc::dup2(raw, 3) }, 3);
            unsafe {
                libc::close(raw);
            }
        }
        let original = unsafe { File::from_raw_fd(3) };
        let image = reserve_worker_image(&original).unwrap();
        assert!(image.as_raw_fd() >= 64);
        let (channel, _peer) = UnixStream::pair().unwrap();
        assert_eq!(unsafe { libc::dup2(channel.as_raw_fd(), 3) }, 3);
        let mut bytes = [0u8; 10];
        assert_eq!(
            unsafe { libc::pread(image.as_raw_fd(), bytes.as_mut_ptr().cast(), 10, 0) },
            10
        );
        assert_eq!(&bytes, b"held-image");
        fs::remove_file(path).unwrap();
    }
}
