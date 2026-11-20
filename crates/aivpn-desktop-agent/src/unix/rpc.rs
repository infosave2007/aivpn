use super::LocalStream;
use crate::control::{Control, ControlStore, RoutingBackend};
use crate::protocol::{PreparedResponse, Request, Response};
use aivpn_desktop_policy::{Authority, Owner};
use std::io;
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// Чтение выполняется до получения доступа к единственному писателю состояния.
/// Соединение обрабатывает один запрос, полномочия которого получены от ядра.
pub struct IncomingControl {
    stream: LocalStream,
    request: Request,
    authority: Authority,
}

pub struct OutgoingControl {
    stream: LocalStream,
    response: PreparedResponse,
}

impl IncomingControl {
    pub fn receive(stream: UnixStream) -> io::Result<Self> {
        let mut stream = LocalStream::new(stream);
        let peer = stream.peer_credentials()?;
        let frame = stream.receive(Some(Duration::from_secs(5)))?;
        if !frame.descriptors.is_empty() {
            return Err(invalid_message());
        }
        let request = Request::from_json(&frame.payload).map_err(|_| invalid_message())?;
        Ok(Self {
            stream,
            request,
            authority: Authority {
                user: Owner::LinuxUser { uid: peer.uid },
                machine_admin: peer.uid == 0,
            },
        })
    }

    pub fn execute<S: ControlStore, B: RoutingBackend<S>>(
        self,
        control: &mut Control<S, B>,
    ) -> OutgoingControl {
        self.execute_with(|authority, request| control.handle(authority, request))
    }

    pub(crate) fn execute_with(
        self,
        handle: impl FnOnce(&Authority, Request) -> Response,
    ) -> OutgoingControl {
        self.prepare_with(|authority, request| PreparedResponse::Ready(handle(authority, request)))
    }

    pub(crate) fn prepare_with(
        self,
        prepare: impl FnOnce(&Authority, Request) -> PreparedResponse,
    ) -> OutgoingControl {
        OutgoingControl {
            stream: self.stream,
            response: prepare(&self.authority, self.request),
        }
    }
}

impl OutgoingControl {
    /// Медленный получатель ответа не удерживает право записи в состоянии службы.
    pub fn send(mut self) -> io::Result<()> {
        let payload = self
            .response
            .finish()
            .to_json()
            .map_err(|_| invalid_message())?;
        self.stream.send(&payload, &[])
    }
}

pub(super) fn invalid_message() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Неверное сообщение локального управления",
    )
}
