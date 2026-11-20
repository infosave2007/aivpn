//! Сеанс Control связан с удержанным worker process и приватными handles службы.
use super::{
    api::{check, denied},
    worker::{SharedTransport, WorkerProcess},
    WindowsRoutingBackend,
};
use crate::{
    control::Control,
    protocol::{BackendState, Command, ErrorCode, Reply, Request, Response},
    state::StateDirectory,
    worker_protocol::WorkerEvent,
};
use aivpn_desktop_policy::{Authority, ProfileAssignment, ProfileLease};
use std::{
    collections::BTreeMap,
    io,
    net::SocketAddr,
    os::windows::io::{AsRawHandle, OwnedHandle},
    path::{Path, PathBuf},
    ptr,
    sync::Arc,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    System::{SystemServices::MAXIMUM_WAIT_OBJECTS, Threading::*},
};

pub use crate::connection::WorkerConfiguration;
#[derive(Debug)]
pub enum WorkerProgress {
    Idle,
    Packets,
    TransportRegistered { endpoint: u64 },
    Assigned { generation: u64 },
    Reconnecting,
    Disconnected,
    Exited,
}
struct Session {
    source: WorkerConfiguration,
    worker: WorkerProcess,
    lease: ProfileLease,
    generation: u64,
    profile: String,
    authority: Authority,
    peer: SocketAddr,
}

pub struct WindowsCoordinator {
    control: Control<StateDirectory, WindowsRoutingBackend>,
    sessions: BTreeMap<String, Session>,
    poll_cursor: usize,
    next: u64,
    packet: Vec<u8>,
    dns: crate::dns::DnsRequests,
    dns_next: u64,
    dns_active: Option<(u64, SocketAddr)>,
    worker_paths: Option<(PathBuf, StateDirectory)>,
    runtime_failure: Option<String>,
    wake: Option<Arc<OwnedHandle>>,
}
impl WindowsCoordinator {
    pub fn prepare(
        &mut self,
        authority: &Authority,
        request: Request,
    ) -> crate::protocol::PreparedResponse {
        let Command::SessionAdmin {
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
                .worker
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
    pub fn transport_dns_servers(&mut self) -> io::Result<Vec<SocketAddr>> {
        self.control.transport_dns_servers()
    }
    pub fn new(control: Control<StateDirectory, WindowsRoutingBackend>) -> Self {
        Self {
            control,
            sessions: BTreeMap::new(),
            poll_cursor: 0,
            next: 0,
            packet: vec![0; 65551],
            dns: crate::dns::DnsRequests::new(),
            dns_next: 0,
            dns_active: None,
            worker_paths: None,
            runtime_failure: None,
            wake: None,
        }
    }
    fn wake_event(&mut self) -> io::Result<Arc<OwnedHandle>> {
        if self.wake.is_none() {
            let event = Arc::new(
                super::api::Handle::new(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) })?
                    .into_owned(),
            );
            let notify = event.clone();
            self.dns.set_wake(Arc::new(move || {
                check(unsafe { SetEvent(notify.as_raw_handle()) })
            }));
            self.wake = Some(event);
        }
        Ok(self.wake.as_ref().unwrap().clone())
    }
    pub(super) fn begin_progress(&self) -> io::Result<()> {
        if let Some(event) = &self.wake {
            check(unsafe { ResetEvent(event.as_raw_handle()) })?;
        }
        Ok(())
    }
    pub(super) fn wait_for_activity(&mut self, endpoints: &[HANDLE]) -> io::Result<()> {
        let mut handles = endpoints.to_vec();
        handles.push(self.control.backend_and_state().1.packet_event());
        if let Some(event) = &self.wake {
            handles.push(event.as_raw_handle());
        }
        handles.extend(
            self.sessions
                .values()
                .map(|session| session.worker.process().as_raw_handle()),
        );
        if handles.len() > MAXIMUM_WAIT_OBJECTS as usize {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        match unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, 50) } {
            WAIT_TIMEOUT => Ok(()),
            result if result < WAIT_OBJECT_0 + handles.len() as u32 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }
    /// Образ и закрытый каталог журналов задает служба, запрос пользователя их не содержит.
    pub fn configure_worker_paths(
        &mut self,
        image: PathBuf,
        log_directory: StateDirectory,
    ) -> io::Result<()> {
        if self.worker_paths.is_some() || !image.is_absolute() {
            return Err(denied());
        }
        self.worker_paths = Some((image, log_directory));
        Ok(())
    }
    pub fn handle(&mut self, authority: &Authority, request: Request) -> Response {
        if matches!(request.command(), Command::Decommission {}) {
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
        let result = match request.command() {
            Command::StartProfile {
                profile,
                connection,
            } => self
                .control
                .state()
                .authorize_profile_control(authority, profile)
                .and_then(|()| {
                    if self.sessions.contains_key(profile) {
                        return Err(ErrorCode::Conflict);
                    }
                    let config = WorkerConfiguration::from_document(connection)
                        .map_err(|_| ErrorCode::InvalidRequest)?;
                    config
                        .validate_identity()
                        .map_err(|_| ErrorCode::InvalidRequest)?;
                    let (image, log) = {
                        let (image, directory) = self
                            .worker_paths
                            .as_ref()
                            .ok_or(ErrorCode::BackendUnavailable)?;
                        let log = directory
                            .prepare_worker_log(&worker_log_name().map_err(runtime_error)?)
                            .map_err(runtime_error)?;
                        (image.clone(), log)
                    };
                    self.start_profile(profile, authority, config, &image, &log)
                        .map(|_| Reply::Done {})
                        .map_err(|error| {
                            self.runtime_failure = Some(format!("Запуск работника: {error}"));
                            runtime_error(error)
                        })
                }),
            Command::StopProfile { profile } => self
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
        match result {
            Ok(reply) => Response::success(request.id(), reply),
            Err(code) => Response::failure(request.id(), code),
        }
    }
    pub fn backend_state(&self) -> BackendState {
        self.control.backend_state()
    }
    pub fn take_runtime_failure(&mut self) -> Option<String> {
        self.runtime_failure.take()
    }
    /// Активная диагностика через прежний ABI. Может claim provenance и изменить
    /// cache origin; результат не описывает состояние до этого вызова.
    pub fn diagnose_process(
        &mut self,
        process: &std::os::windows::io::OwnedHandle,
        destination: std::net::IpAddr,
    ) -> io::Result<super::driver::IdentityDiagnostic> {
        self.control
            .backend_and_state()
            .1
            .diagnose_process(process, destination)
    }
    #[cfg(feature = "windows-lab")]
    pub fn lab_injection_barrier(
        &mut self,
        started: &std::os::windows::io::OwnedHandle,
        release: &std::os::windows::io::OwnedHandle,
    ) -> io::Result<()> {
        self.control
            .backend_and_state()
            .1
            .lab_injection_barrier(started, release)
    }
    pub fn packet_statistics(&mut self) -> io::Result<super::driver::PacketStatistics> {
        self.control.backend_and_state().1.packet_statistics()
    }
    #[cfg(feature = "windows-lab")]
    pub fn lab_counters(&mut self) -> io::Result<Vec<u32>> {
        self.control.backend_and_state().1.lab_counters()
    }
    pub fn publication(&mut self) -> Option<(u64, u64)> {
        self.control.backend_and_state().1.publication()
    }
    pub fn failure_detail(&mut self) -> Option<&str> {
        self.control.backend_and_state().1.last_failure()
    }
    pub fn transport_receipt(&mut self) -> io::Result<Option<super::driver::TransportReceipt>> {
        self.control.backend_and_state().1.transport_receipt()
    }
    /// Только подтвержденные receipts текущего процесса службы, без pointer/FileID authority.
    pub fn binding_receipts(&mut self) -> serde_json::Value {
        self.control.backend_and_state().1.binding_receipts()
    }
    pub fn inherited_station_access(&self) -> Option<bool> {
        if self.sessions.len() == 1 {
            self.sessions
                .values()
                .next()
                .map(|session| session.worker.inherited_station_access())
        } else {
            None
        }
    }
    pub fn worker_pid(&self) -> Option<u32> {
        if self.sessions.len() == 1 {
            self.sessions
                .values()
                .next()
                .map(|session| session.worker.id())
        } else {
            None
        }
    }
    pub fn worker_pid_for(&self, profile: &str) -> Option<u32> {
        self.sessions
            .get(profile)
            .map(|session| session.worker.id())
    }
    pub fn dns_session_identity(
        &mut self,
        peer: SocketAddr,
    ) -> io::Result<Option<([u8; 16], u64)>> {
        let Some(session) = self
            .control
            .state()
            .profiles()
            .global_dns_profile()
            .and_then(|profile| self.sessions.get(profile))
        else {
            return Ok(None);
        };
        if session.worker.exited()? {
            return Ok(None);
        }
        let catalog = self.control.state().profiles();
        if catalog.global_dns_profile() != Some(session.profile.as_str()) {
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
        let profile_id = self
            .control
            .state()
            .profiles()
            .global_dns_profile()
            .ok_or_else(denied)?
            .to_owned();
        let session = self.sessions.get(&profile_id).ok_or_else(denied)?;
        if session.worker.exited()? {
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
        self.dns_next = self.dns_next.checked_add(1).ok_or_else(denied)?;
        let route = self.dns.route(
            session.lease.clone(),
            profile.assignment_generation,
            self.dns_next,
            peer,
        )?;
        self.control
            .backend_and_state()
            .1
            .prepare_dns_route(&profile_id, self.dns_next)?;
        self.dns_active = Some((self.dns_next, peer));
        Ok(route)
    }
    pub fn protect_system_dns(
        &mut self,
        listeners: Vec<std::os::windows::io::OwnedSocket>,
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
        for _ in 0..16 {
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
                let profile_id = self
                    .control
                    .state()
                    .profiles()
                    .global_dns_profile()
                    .ok_or_else(denied)?;
                let session = self.sessions.get(profile_id).ok_or_else(denied)?;
                if session.worker.exited()? {
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
                self.control
                    .backend_and_state()
                    .1
                    .register_dns_socket(socket, peer, resolver_epoch)
            })();
            reply(result);
        }
        if let Some(event) = &self.wake {
            check(unsafe { SetEvent(event.as_raw_handle()) })?;
        }
        Ok(())
    }
    pub fn start_profile(
        &mut self,
        profile: &str,
        authority: &Authority,
        mut config: WorkerConfiguration,
        image: &Path,
        log: &Path,
    ) -> io::Result<u32> {
        self.control
            .state()
            .authorize_profile_control(authority, profile)
            .map_err(|_| denied())?;
        config.validate_identity()?;
        if !matches!(
            self.control.backend_state(),
            BackendState::Guarded | BackendState::Active
        ) {
            return Err(denied());
        }
        if self.sessions.contains_key(profile)
            || self.sessions.len() + 4 >= MAXIMUM_WAIT_OBJECTS as usize
        {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let resolved = self
            .control
            .resolve_worker_configuration(&mut config)
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("Разрешение адреса транспорта: {error}"),
                )
            })?;
        let peer = resolved.numeric_peer()?;
        let lease = self
            .control
            .begin_profile_session(profile, authority)
            .map_err(|_| self.failure())?;
        let result = (|| {
            let (state, backend) = self.control.backend_and_state();
            backend.begin_path(state, profile).map_err(|error| {
                io::Error::new(error.kind(), format!("Подготовка пути: {error}"))
            })?;
            self.next = self.next.checked_add(1).ok_or_else(denied)?;
            let wake = self.wake_event()?;
            let mut worker =
                WorkerProcess::spawn_suspended(image, log, self.next, &wake).map_err(|error| {
                    io::Error::new(error.kind(), format!("Создание работника: {error}"))
                })?;
            self.control
                .backend_and_state()
                .1
                .register_worker(profile, &worker, self.next)
                .map_err(|e| io::Error::new(e.kind(), format!("Регистрация работника: {e}")))?;
            worker.resume()?;
            let hello = worker
                .control
                .receive(Duration::from_secs(10))
                .map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!(
                            "Worker hello: {error}; pid={}; exit={:?}; inherited_station_access={}",
                            worker.id(),
                            worker.wait_exit_code(),
                            worker.inherited_station_access()
                        ),
                    )
                })?;
            if hello != b"RESTRICTED" {
                return Err(denied());
            }
            worker.verify()?;
            worker.control.send(&serde_json::to_vec(&serde_json::json!({"name":"aivpn-app-packets","generation":self.next,"connection":resolved.connection}))?, Duration::from_secs(5)).map_err(|error| {
                io::Error::new(error.kind(), format!("Передача настроек работнику: {error}"))
            })?;
            Ok(Session {
                worker,
                lease: lease.clone(),
                generation: self.next,
                profile: profile.into(),
                authority: authority.clone(),
                peer,
                source: config,
            })
        })();
        match result {
            Ok(session) => {
                let pid = session.worker.id();
                self.sessions.insert(profile.into(), session);
                Ok(pid)
            }
            Err(error) => {
                let _ = self.control.backend_and_state().1.revoke_transport(profile);
                let _ = self.control.disconnect_profile_session(&lease);
                Err(error)
            }
        }
    }
    fn failure(&mut self) -> io::Error {
        io::Error::other(
            self.control
                .backend_and_state()
                .1
                .last_failure()
                .unwrap_or("Control отказал в runtime операции")
                .to_owned(),
        )
    }
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
            self.finish_session(session, None)?;
        }
        Ok(())
    }
    fn finish_session(&mut self, session: Session, cause: Option<io::Error>) -> io::Result<()> {
        if let Some(error) = &cause {
            self.runtime_failure = Some(format!("Профиль {}: {error}", session.profile));
        }
        session.worker.administration.close();
        if self.control.state().profiles().global_dns_profile() == Some(session.profile.as_str()) {
            self.dns_active = None;
        }
        let revoked = self
            .control
            .backend_and_state()
            .1
            .revoke_transport(&session.profile);
        let disconnected = self
            .control
            .disconnect_profile_session(&session.lease)
            .map_err(|_| self.failure());
        drop(session);
        revoked.and(disconnected).map_err(|error| {
            io::Error::other(format!(
                "Закрытие сеанса: {error}; причина: {}",
                cause
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "сеанс завершен".into())
            ))
        })
    }
    pub fn step(&mut self, timeout: Duration) -> io::Result<WorkerProgress> {
        self.dns_requests()?;
        let deadline = Instant::now() + timeout.min(Duration::from_millis(50));
        loop {
            if self.sessions.is_empty() {
                return Ok(WorkerProgress::Idle);
            }
            let mut profiles: Vec<_> = self.sessions.keys().cloned().collect();
            let cursor = self.poll_cursor % profiles.len();
            profiles.rotate_left(cursor);
            let mut selected = None;
            for (index, profile) in profiles.iter().enumerate() {
                let session = &self.sessions[profile];
                let state = (|| -> io::Result<Option<u8>> {
                    if session.worker.administration.is_closed() {
                        return Err(io::ErrorKind::BrokenPipe.into());
                    }
                    if session.worker.exited()? {
                        return Ok(Some(2));
                    }
                    if session.worker.control.readable()? {
                        return Ok(Some(0));
                    }
                    if session.worker.packets.readable()? {
                        return Ok(Some(1));
                    }
                    Ok(None)
                })();
                match state {
                    Ok(None) => (),
                    ready => {
                        selected = Some((index, profile.clone(), ready));
                        break;
                    }
                }
            }
            let mut progress = None;
            let mut transferred = false;
            if let Some((index, profile, ready)) = selected {
                self.poll_cursor = (cursor + index + 1) % profiles.len();
                let mut session = self.sessions.remove(&profile).ok_or_else(denied)?;
                let result = match ready {
                    Err(error) => Err(error),
                    Ok(Some(0)) => self.worker_event(&mut session),
                    Ok(Some(1)) => (|| {
                        for _ in 0..32 {
                            if !session.worker.packets.readable()? {
                                break;
                            }
                            let Some(count) = session
                                .worker
                                .packets
                                .packet_receive(session.generation, &mut self.packet[..65535])?
                            else {
                                continue;
                            };
                            self.control
                                .backend_and_state()
                                .1
                                .send_packet(&profile, &mut self.packet[..count])?;
                            transferred = true;
                        }
                        Ok(WorkerProgress::Packets)
                    })(),
                    Ok(Some(2)) => Ok(WorkerProgress::Exited),
                    _ => Err(denied()),
                };
                match result {
                    Ok(WorkerProgress::Disconnected | WorkerProgress::Exited) => {
                        self.finish_session(session, None)?;
                        return Ok(WorkerProgress::Exited);
                    }
                    Err(error) => {
                        self.finish_session(session, Some(error))?;
                        return Ok(WorkerProgress::Exited);
                    }
                    Ok(event) => {
                        progress = Some(event);
                        self.sessions.insert(profile, session);
                    }
                }
            }
            for _ in 0..32 {
                let Some(packet) = self
                    .control
                    .backend_and_state()
                    .1
                    .receive_packet(&mut self.packet)?
                else {
                    break;
                };
                let profile = self
                    .control
                    .backend_and_state()
                    .1
                    .packet_profile(packet.route)
                    .map(str::to_owned);
                let Some(profile) = profile else {
                    continue;
                };
                let Some(session) = self.sessions.get_mut(&profile) else {
                    continue;
                };
                if session.generation != packet.route.generation.get() {
                    continue;
                }
                if let Err(error) = session
                    .worker
                    .packets
                    .packet_send(session.generation, &self.packet[16..16 + packet.size])
                {
                    let session = self.sessions.remove(&profile).ok_or_else(denied)?;
                    self.finish_session(session, Some(error))?;
                    return Ok(WorkerProgress::Exited);
                }
                transferred = true;
            }
            if let Some(progress) = progress {
                return Ok(progress);
            }
            if transferred {
                return Ok(WorkerProgress::Packets);
            }
            if Instant::now() >= deadline {
                return Ok(WorkerProgress::Idle);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn worker_event(&mut self, session: &mut Session) -> io::Result<WorkerProgress> {
        session
            .worker
            .verify()
            .map_err(|e| io::Error::new(e.kind(), format!("Worker token/job: {e}")))?;
        self.control
            .state()
            .profiles()
            .session_profile(&session.lease)
            .map_err(|_| io::Error::other("Worker lease отсутствует"))?;
        let event: WorkerEvent =
            serde_json::from_slice(&session.worker.control.receive(Duration::from_secs(2))?)?;
        if event.generation() != session.generation {
            return Err(denied());
        }
        let mut response = b"ACK".to_vec();
        let progress = match event {
            WorkerEvent::Transport { peer, .. } => {
                if peer != session.peer {
                    return Err(io::Error::other(
                        "Transport peer не совпадает с конфигурацией",
                    ));
                }
                let transport = SharedTransport::create(peer.is_ipv4())
                    .map_err(|e| io::Error::new(e.kind(), format!("Shared transport: {e}")))?;
                let endpoint = transport.endpoint();
                response = transport.duplicate_for(session.worker.id())?;
                self.control
                    .backend_and_state()
                    .1
                    .register_transport(&session.profile, transport, peer)
                    .map_err(|e| {
                        io::Error::new(e.kind(), format!("Transport registration: {e}"))
                    })?;
                WorkerProgress::TransportRegistered { endpoint }
            }
            WorkerEvent::Assignment { network, .. } => {
                let interface_id = self
                    .control
                    .backend_and_state()
                    .1
                    .confirm_assignment(&session.profile, network)?;
                let generation = self
                    .control
                    .assign_profile(
                        &session.lease,
                        ProfileAssignment {
                            interface_id,
                            ipv4: network.client_ip,
                            ipv6: network.ipv6.map(|network| network.address),
                        },
                    )
                    .map_err(|_| self.failure())?;
                session.source.connected();
                WorkerProgress::Assigned { generation }
            }
            WorkerEvent::Reconnecting { .. } => {
                session
                    .worker
                    .administration
                    .advance(session.generation.checked_add(1).ok_or_else(denied)?)?;
                if self.control.state().profiles().global_dns_profile()
                    == Some(session.profile.as_str())
                {
                    self.dns_active = None;
                }
                self.control
                    .backend_and_state()
                    .1
                    .revoke_transport(&session.profile)?;
                self.control
                    .disconnect_profile_session(&session.lease)
                    .map_err(|_| self.failure())?;
                session.source.finish_attempt();
                let resolved = self
                    .control
                    .resolve_worker_configuration(&mut session.source)?;
                session.peer = resolved.numeric_peer()?;
                session.lease = self
                    .control
                    .begin_profile_session(&session.profile, &session.authority)
                    .map_err(|_| self.failure())?;
                session.generation = session.generation.checked_add(1).ok_or_else(denied)?;
                self.next = self.next.max(session.generation);
                self.control.backend_and_state().1.register_worker(
                    &session.profile,
                    &session.worker,
                    session.generation,
                )?;
                response = serde_json::to_vec(
                    &serde_json::json!({"next_generation":session.generation,"peer":session.peer}),
                )?;
                WorkerProgress::Reconnecting
            }
            WorkerEvent::Disconnected { .. } => WorkerProgress::Disconnected,
        };
        session
            .worker
            .control
            .send(&response, Duration::from_secs(2))?;
        Ok(progress)
    }
}

fn runtime_error(_: io::Error) -> ErrorCode {
    // Полномочия пользователя проверены до runtime; отказ native API относится к backend.
    ErrorCode::BackendUnavailable
}
fn worker_log_name() -> io::Result<String> {
    let mut uuid = windows_sys::core::GUID::default();
    let status = unsafe { windows_sys::Win32::System::Rpc::UuidCreate(&mut uuid) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    Ok(format!(
        "worker-{:08x}-{:04x}-{:04x}-{:016x}.log",
        uuid.data1,
        uuid.data2,
        uuid.data3,
        u64::from_le_bytes(uuid.data4)
    ))
}
impl Drop for WindowsCoordinator {
    fn drop(&mut self) {
        let _ = self.stop_profile();
    }
}
