//! Локальное управление Windows с проверкой учетных данных ОС.
//!
//! Два постоянных экземпляра pipe ограничивают admission без очереди потоков.
//! Готовые user/admin соединения чередуются; первый выбор отдан admin.
mod api;
#[cfg(feature = "windows-kernel")]
mod backend;
pub mod classic;
#[cfg(feature = "windows-kernel")]
mod coordinator;
#[cfg(feature = "windows-kernel")]
mod deferred;
#[cfg(feature = "windows-kernel")]
pub mod driver;
#[cfg(feature = "windows-kernel")]
mod filters;
#[cfg(feature = "windows-kernel")]
mod retirement;
#[cfg(feature = "windows-kernel")]
pub use retirement::{purge_owned_routing, remove_owned_routing};
#[cfg(feature = "windows-kernel")]
mod provenance_volume;
mod security;
#[cfg(feature = "windows-kernel")]
pub mod worker;
#[cfg(feature = "windows-kernel")]
pub use provenance_volume::ProvenanceVolume;
#[cfg(feature = "windows-kernel")]
pub(crate) mod dns;
#[cfg(feature = "windows-kernel")]
pub use backend::WindowsRoutingBackend;
#[cfg(feature = "windows-kernel")]
pub use coordinator::{WindowsCoordinator, WorkerConfiguration, WorkerProgress};

pub(crate) fn current_owner() -> std::io::Result<aivpn_desktop_policy::Owner> {
    security::process_owner()
}

#[cfg(feature = "windows-kernel")]
use crate::protocol::{ErrorCode, PreparedResponse};
use crate::{
    control::{Control, ControlStore, RoutingBackend},
    protocol::{Request, Response},
    state::StateDirectory,
};
use aivpn_desktop_policy::Platform;
use api::{check, invalid, Handle, Operation, TIMEOUT};
use std::{
    io,
    path::Path,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::*,
    System::{Pipes::*, Threading::SetEvent},
};

/// Control и хранилище создаются на потоке службы после проверки LocalSystem.
/// Библиотека не создает фоновых потоков и не устанавливает Windows-службу.
pub struct ControlServer<S, B> {
    ordinary: Handle,
    admin: Handle,
    control: Control<S, B>,
}
impl<B: RoutingBackend<StateDirectory>> ControlServer<StateDirectory, B> {
    pub fn open(name: &str, directory: &Path, namespace: [u8; 16], backend: B) -> io::Result<Self> {
        Self::bind(name, || {
            Control::open(
                Platform::Windows,
                namespace,
                StateDirectory::open(directory)?,
                backend,
            )
        })
    }
}
impl<S: ControlStore, B: RoutingBackend<S>> ControlServer<S, B> {
    /// Фабрика исполняется только в проверенном контексте службы, после захвата обоих имен.
    pub fn bind(
        name: &str,
        create: impl FnOnce() -> io::Result<Control<S, B>>,
    ) -> io::Result<Self> {
        security::service_authority()?;
        let ordinary = create_pipe(name, false)?;
        let admin = create_pipe(name, true)?;
        let control = create()?;
        security::service_authority()?;
        Ok(Self {
            ordinary,
            admin,
            control,
        })
    }

    /// Один запрос и один ответ на соединение, каждый кадр ожидается не дольше двух секунд.
    /// stop прерывает ожидания I/O; начатая транзакция Control заканчивается синхронно.
    pub fn run(&mut self, stop: &AtomicBool) -> io::Result<()> {
        security::service_authority()?;
        let result = serve(&self.ordinary, &self.admin, &mut self.control, stop);
        unsafe {
            DisconnectNamedPipe(self.ordinary.raw());
            DisconnectNamedPipe(self.admin.raw());
        }
        result
    }
}

fn serve<S: ControlStore, B: RoutingBackend<S>>(
    ordinary: &Handle,
    admin: &Handle,
    control: &mut Control<S, B>,
    stop: &AtomicBool,
) -> io::Result<()> {
    let mut public_accept = accept(ordinary)?;
    let mut admin_accept = accept(admin)?;
    let mut previous_admin = false;
    while !stop.load(Ordering::Acquire) {
        let next = ready_endpoint(&public_accept, &admin_accept, previous_admin)?;
        if next == Some(true) {
            previous_admin = true;
            admin_accept = exchange(admin, admin_accept, control, stop)?;
        } else if next == Some(false) {
            previous_admin = false;
            public_accept = exchange(ordinary, public_accept, control, stop)?;
        } else {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    Ok(())
}

fn ready_endpoint(
    public: &Operation<'_>,
    admin: &Operation<'_>,
    previous_admin: bool,
) -> io::Result<Option<bool>> {
    Ok(select_endpoint(
        public.ready()?,
        admin.ready()?,
        previous_admin,
    ))
}

fn select_endpoint(public: bool, admin: bool, previous_admin: bool) -> Option<bool> {
    if admin && (!public || !previous_admin) {
        Some(true)
    } else if public {
        Some(false)
    } else {
        None
    }
}

fn exchange<'a, S: ControlStore, B: RoutingBackend<S>>(
    pipe: &'a Handle,
    accepted: Operation<'a>,
    control: &mut Control<S, B>,
    stop: &AtomicBool,
) -> io::Result<Operation<'a>> {
    // Ошибка клиента завершает только его соединение. Следующий запрос идет в новый кадр.
    let _ = request_response(pipe, control, stop);
    drop(accepted);
    check(unsafe { DisconnectNamedPipe(pipe.raw()) })?;
    accept(pipe)
}

fn request_response<S: ControlStore, B: RoutingBackend<S>>(
    pipe: &Handle,
    control: &mut Control<S, B>,
    stop: &AtomicBool,
) -> io::Result<()> {
    request_response_with(pipe, stop, |authority, request| {
        control.handle(authority, request)
    })
}

fn request_response_with(
    pipe: &Handle,
    stop: &AtomicBool,
    handle: impl FnOnce(&aivpn_desktop_policy::Authority, Request) -> Response,
) -> io::Result<()> {
    let deadline = Instant::now() + TIMEOUT;
    let payload = api::receive(pipe, deadline, stop)?;
    let authority = security::client_authority(pipe.raw())?;
    let request = Request::from_json(&payload).map_err(|_| invalid())?;
    api::remaining(deadline, stop)?;
    security::service_authority()?;
    let response = handle(&authority, request);
    send_response(pipe, &response, Instant::now() + TIMEOUT, stop)
}

/// Control endpoint и worker runtime обслуживают один экземпляр Control.
#[cfg(feature = "windows-kernel")]
pub struct WindowsService {
    name: String,
    ordinary: Handle,
    admin: Handle,
    coordinator: WindowsCoordinator,
}
#[cfg(feature = "windows-kernel")]
impl WindowsService {
    pub fn bind(
        name: &str,
        create: impl FnOnce() -> io::Result<WindowsCoordinator>,
    ) -> io::Result<Self> {
        security::service_authority()?;
        let ordinary = create_pipe_instance(name, false, true, deferred::MAX_INSTANCES)?;
        let admin = create_pipe_instance(name, true, true, deferred::MAX_INSTANCES)?;
        let coordinator = create()?;
        security::service_authority()?;
        Ok(Self {
            name: name.into(),
            ordinary,
            admin,
            coordinator,
        })
    }
    pub fn coordinator(&mut self) -> &mut WindowsCoordinator {
        &mut self.coordinator
    }
    pub fn run(
        &mut self,
        stop: &AtomicBool,
        mut observe: impl FnMut(WorkerProgress, &mut WindowsCoordinator) -> io::Result<()>,
    ) -> io::Result<()> {
        security::service_authority()?;
        let mut replies = deferred::DeferredReplies::default();
        let result = self.run_prepared(stop, &mut observe, &mut replies);
        let stopped = self.coordinator.stop_profile();
        let completed = replies.finish();
        result.and(stopped).and(completed)
    }
    fn run_prepared(
        &mut self,
        stop: &AtomicBool,
        observe: &mut impl FnMut(WorkerProgress, &mut WindowsCoordinator) -> io::Result<()>,
        replies: &mut deferred::DeferredReplies,
    ) -> io::Result<()> {
        let mut ordinary_pipe = self.ordinary.try_clone()?;
        let mut admin_pipe = self.admin.try_clone()?;
        let mut ordinary = accept(&ordinary_pipe)?;
        let mut admin = accept(&admin_pipe)?;
        let mut previous_admin = false;
        while !stop.load(Ordering::Acquire) {
            self.coordinator.begin_progress()?;
            replies
                .reap()
                .map_err(|error| service_error("Завершение ответа", error))?;
            if let Some(is_admin) = ready_endpoint(&ordinary, &admin, previous_admin)
                .map_err(|error| service_error("Выбор IPC", error))?
            {
                previous_admin = is_admin;
                if is_admin {
                    let replacement = self.prepare_reply(&admin_pipe, true, stop, replies);
                    drop(admin);
                    match replacement {
                        Ok(Some(pipe)) => admin_pipe = pipe,
                        _ => check(unsafe { DisconnectNamedPipe(admin_pipe.raw()) })
                            .map_err(|error| service_error("Закрытие admin IPC", error))?,
                    }
                    admin = accept(&admin_pipe)
                        .map_err(|error| service_error("Ожидание admin IPC", error))?;
                } else {
                    let replacement = self.prepare_reply(&ordinary_pipe, false, stop, replies);
                    drop(ordinary);
                    match replacement {
                        Ok(Some(pipe)) => ordinary_pipe = pipe,
                        _ => check(unsafe { DisconnectNamedPipe(ordinary_pipe.raw()) })
                            .map_err(|error| service_error("Закрытие user IPC", error))?,
                    }
                    ordinary = accept(&ordinary_pipe)
                        .map_err(|error| service_error("Ожидание user IPC", error))?;
                }
            }
            let progress = self
                .coordinator
                .step(std::time::Duration::ZERO)
                .map_err(|error| service_error("Обработка работника и пакетов", error))?;
            let idle = matches!(progress, WorkerProgress::Idle);
            observe(progress, &mut self.coordinator)
                .map_err(|error| service_error("Обновление DNS", error))?;
            if idle {
                self.coordinator
                    .wait_for_activity(&[ordinary.event(), admin.event()])?;
            }
        }
        Ok(())
    }
    fn prepare_reply(
        &mut self,
        pipe: &Handle,
        admin: bool,
        stop: &AtomicBool,
        replies: &mut deferred::DeferredReplies,
    ) -> io::Result<Option<Handle>> {
        let deadline = Instant::now() + TIMEOUT;
        let payload = api::receive(pipe, deadline, stop)?;
        let authority = security::client_authority(pipe.raw())?;
        let request = Request::from_json(&payload).map_err(|_| invalid())?;
        let id = request.id();
        api::remaining(deadline, stop)?;
        security::service_authority()?;
        match self.coordinator.prepare(&authority, request) {
            PreparedResponse::Ready(response) => {
                send_response(pipe, &response, Instant::now() + TIMEOUT, stop)?;
                Ok(None)
            }
            PreparedResponse::Deferred(work) => {
                if !replies.admits(&authority) {
                    send_response(
                        pipe,
                        &Response::failure(id, ErrorCode::Capacity),
                        deadline,
                        stop,
                    )?;
                    return Ok(None);
                }
                // Старый SYSTEM handle сохраняет имя до создания нового защищенного экземпляра.
                let replacement =
                    create_pipe_instance(&self.name, admin, false, deferred::MAX_INSTANCES)?;
                replies.spawn(pipe.try_clone()?, &authority, work)?;
                Ok(Some(replacement))
            }
        }
    }
}

#[cfg(feature = "windows-kernel")]
fn service_error(stage: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{stage}: {error}"))
}

fn send_response(
    pipe: &Handle,
    response: &Response,
    deadline: Instant,
    stop: &AtomicBool,
) -> io::Result<()> {
    let payload = response.to_json().map_err(|_| invalid())?;
    api::send(pipe, &payload, deadline, stop)?;
    let mut ack = [0];
    api::read(pipe, &mut ack, deadline, stop)?;
    if ack != [0xa1] {
        return Err(invalid());
    }
    Ok(())
}

fn pipe_name(name: &str, admin: bool) -> io::Result<Vec<u16>> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(format!(
        "\\\\.\\pipe\\aivpn-{name}-{}\0",
        if admin { "admin" } else { "user" }
    )
    .encode_utf16()
    .collect())
}

fn create_pipe(name: &str, admin: bool) -> io::Result<Handle> {
    create_pipe_instance(name, admin, true, 1)
}

fn create_pipe_instance(
    name: &str,
    admin: bool,
    first: bool,
    max_instances: u32,
) -> io::Result<Handle> {
    let name = pipe_name(name, admin)?;
    let descriptor = security::Descriptor::new(admin)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    Handle::new(unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX
                | FILE_FLAG_OVERLAPPED
                | if first {
                    FILE_FLAG_FIRST_PIPE_INSTANCE
                } else {
                    0
                },
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            max_instances,
            4096,
            4096,
            0,
            &attributes,
        )
    })
}

fn accept(pipe: &Handle) -> io::Result<Operation<'_>> {
    let mut op = Operation::new(pipe)?;
    let result = unsafe { ConnectNamedPipe(pipe.raw(), op.pointer()) };
    if result == 0
        && matches!(
            unsafe { GetLastError() },
            ERROR_PIPE_CONNECTED | ERROR_NO_DATA
        )
    {
        // Ранний disconnect обрабатывается как готовое соединение с ошибкой чтения.
        // Общий exchange выполнит DisconnectNamedPipe и rearm, сохраняя stop и fairness.
        check(unsafe { SetEvent((*op.pointer()).hEvent) })?;
    } else {
        op.started(result)?;
    }
    Ok(op)
}

pub struct ControlClient;
impl ControlClient {
    /// Проверка защищенного SYSTEM endpoint завершается до передачи JSON.
    pub fn call(name: &str, request: &Request) -> io::Result<Response> {
        let deadline = Instant::now() + request.response_timeout();
        let stop = AtomicBool::new(false);
        let admin = security::is_admin()?;
        let pipe = connect(name, admin, deadline, &stop)?;
        security::authenticate_server(pipe.raw(), admin)?;
        let payload = request.to_json().map_err(|_| invalid())?;
        api::send(&pipe, &payload, deadline, &stop)?;
        receive_response(&pipe, request, deadline, &stop)
    }
}

fn receive_response(
    pipe: &Handle,
    request: &Request,
    deadline: Instant,
    stop: &AtomicBool,
) -> io::Result<Response> {
    let payload = api::receive(pipe, deadline, stop)?;
    let response = Response::from_json(&payload).map_err(|_| invalid())?;
    if response.id() != request.id() {
        return Err(invalid());
    }
    api::write(pipe, &[0xa1], deadline, stop)?;
    Ok(response)
}

fn connect(name: &str, admin: bool, deadline: Instant, stop: &AtomicBool) -> io::Result<Handle> {
    let name = pipe_name(name, admin)?;
    loop {
        api::remaining(deadline, stop)?;
        let raw = unsafe {
            CreateFileW(
                name.as_ptr(),
                security::CLIENT_ACCESS,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if raw != INVALID_HANDLE_VALUE {
            return Handle::new(raw);
        }
        let code = unsafe { GetLastError() };
        if code != ERROR_PIPE_BUSY {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[cfg(all(test, feature = "windows-kernel"))]
mod tests;
