//! События системной шины обрабатывает прежний поток службы, без отдельного опроса процессов.
use super::{
    nm::bus_error,
    resolved::{self, StubService},
};
use futures_core::Stream;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};
use zbus::{
    blocking::{Connection, MessageIterator},
    MatchRule, MessageStream,
};

pub(super) struct Changes {
    stream: MessageStream,
    bus: Connection,
    service: StubService,
    epoch: u64,
    pending: Option<Instant>,
    retry: Instant,
}
impl Changes {
    pub(super) fn open(bus: &Connection, service: StubService) -> io::Result<Self> {
        let rule = MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender("org.freedesktop.DBus")
            .map_err(bus_error)?
            .path("/org/freedesktop/DBus")
            .map_err(bus_error)?
            .interface("org.freedesktop.DBus")
            .map_err(bus_error)?
            .member("NameOwnerChanged")
            .map_err(bus_error)?
            .add_arg(service.name())
            .map_err(bus_error)?
            .build();
        let stream = MessageIterator::for_match_rule(rule, bus, Some(16))
            .map_err(bus_error)?
            .into_inner();
        Ok(Self {
            stream,
            bus: bus.clone(),
            service,
            epoch: 1,
            pending: Some(Instant::now()),
            retry: Instant::now(),
        })
    }
    pub(super) fn epoch(&mut self) -> io::Result<Option<u64>> {
        let mut context = Context::from_waker(Waker::noop());
        let mut changed = false;
        for _ in 0..16 {
            let message = match Pin::new(&mut self.stream).poll_next(&mut context) {
                Poll::Pending => break,
                Poll::Ready(Some(message)) => message.map_err(bus_error)?,
                Poll::Ready(None) => return Err(io::ErrorKind::BrokenPipe.into()),
            };
            let (name, _old, _new): (String, String, String) =
                message.body().deserialize().map_err(bus_error)?;
            if name != self.service.name() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            changed = true;
        }
        let now = Instant::now();
        if changed {
            self.epoch = self.epoch.checked_add(1).ok_or(io::ErrorKind::Other)?;
            self.pending = Some(now);
            self.retry = now;
        }
        let Some(started) = self.pending else {
            return Ok(Some(self.epoch));
        };
        if now < self.retry {
            return Ok(None);
        }
        match resolved::capture_service(&self.bus, self.service) {
            Ok(sockets) => {
                // Дубликаты не удерживают порт после остановки исходного процесса.
                drop(sockets);
                self.pending = None;
                Ok(Some(self.epoch))
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied
                        | io::ErrorKind::InvalidData
                        | io::ErrorKind::FileTooLarge
                ) =>
            {
                Err(error)
            }
            Err(_) if now.duration_since(started) < Duration::from_secs(5) => {
                self.retry = now + Duration::from_millis(50);
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}
