use super::rpc::{IncomingControl, OutgoingControl};
use super::LocalStream;
use crate::control::{Control, ControlStore, RoutingBackend};
use crate::protocol::{Request, Response};
use aivpn_desktop_policy::Authority;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MAX_INFLIGHT: usize = 32;
const PER_OWNER: usize = 4;
const ADMIN_RESERVE: usize = 2;
const REPLY_BUFFER_BYTES: libc::c_int = 32 * 1024;

/// Чтение и отправка ограничены отдельным пулом; состояние меняет вызывающий поток.
pub struct ControlServer {
    listener: Arc<UnixListener>,
    stop: ControlStop,
    wake: UnixStream,
}

#[derive(Clone)]
pub struct ControlStop {
    wake: Arc<UnixStream>,
    progress: Arc<OwnedFd>,
    stopped: Arc<AtomicBool>,
}

#[derive(Default)]
struct Counts {
    total: usize,
    owners: BTreeMap<u32, usize>,
}

struct Quota {
    counts: Mutex<Counts>,
    stop: ControlStop,
}

struct Permit {
    quota: Arc<Quota>,
    uid: u32,
}

struct Job {
    stream: UnixStream,
    _permit: Permit,
}

struct Pending {
    incoming: IncomingControl,
    reply: SyncSender<OutgoingControl>,
}

type Inbox = Arc<Mutex<Receiver<Job>>>;

/// IPC и наблюдение за работником меняют состояние на одном потоке службы.
pub trait ControlHandler {
    fn handle(&mut self, authority: &Authority, request: Request) -> Response;
    fn prepare(
        &mut self,
        authority: &Authority,
        request: Request,
    ) -> crate::protocol::PreparedResponse {
        crate::protocol::PreparedResponse::Ready(self.handle(authority, request))
    }
    fn stopping(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn progress(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn poll_interval(&self) -> Duration {
        Duration::from_millis(250)
    }
    fn wait_for_activity(&mut self, pending: BorrowedFd<'_>, timeout: Duration) -> io::Result<()> {
        let mut event = libc::pollfd {
            fd: pending.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut event, 1, timeout.as_millis() as i32) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        if event.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }
}

impl<S: ControlStore, B: RoutingBackend<S>> ControlHandler for Control<S, B> {
    fn handle(&mut self, authority: &Authority, request: Request) -> Response {
        Control::handle(self, authority, request)
    }
}

struct StartFailure {
    error: io::Error,
    workers: Vec<JoinHandle<()>>,
}

struct StopOnExit(ControlStop);
impl Drop for StopOnExit {
    fn drop(&mut self) {
        self.0.stop();
    }
}

impl ControlServer {
    pub fn new(listener: UnixListener) -> io::Result<(Self, ControlStop)> {
        listener.set_nonblocking(true)?;
        let listener = Arc::new(listener);
        let (wake, reader) = UnixStream::pair()?;
        wake.set_nonblocking(true)?;
        reader.set_nonblocking(true)?;
        let progress = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if progress < 0 {
            return Err(io::Error::last_os_error());
        }
        let stop = ControlStop {
            wake: Arc::new(wake),
            progress: Arc::new(unsafe { OwnedFd::from_raw_fd(progress) }),
            stopped: Arc::new(AtomicBool::new(false)),
        };
        Ok((
            Self {
                listener,
                stop: stop.clone(),
                wake: reader,
            },
            stop,
        ))
    }

    pub fn run<S: ControlStore, B: RoutingBackend<S>>(
        self,
        control: &mut Control<S, B>,
    ) -> io::Result<()> {
        self.run_handler(control)
    }

    pub fn run_handler(self, handler: &mut impl ControlHandler) -> io::Result<()> {
        let _stop_on_exit = StopOnExit(self.stop.clone());
        let (jobs, inbox) = mpsc::sync_channel(MAX_INFLIGHT);
        let (events, receiver) = mpsc::sync_channel(MAX_INFLIGHT);
        let quota = Arc::new(Quota {
            counts: Mutex::new(Counts::default()),
            stop: self.stop.clone(),
        });
        let workers = match start_workers(Arc::new(Mutex::new(inbox)), events, &self.stop) {
            Ok(workers) => workers,
            Err(failure) => {
                self.stop.stop();
                drop(jobs);
                let _ = join_workers(failure.workers);
                return Err(failure.error);
            }
        };
        let listener = self.listener.clone();
        let stop = self.stop.clone();
        let wake = self.wake;
        let acceptor = thread::Builder::new()
            .name("aivpn-control-accept".into())
            .spawn(move || accept_connections(listener, wake, stop, quota, jobs));
        let acceptor = match acceptor {
            Ok(acceptor) => acceptor,
            Err(error) => {
                self.stop.stop();
                let _ = join_workers(workers);
                return Err(error);
            }
        };
        let written = write_state(handler, &receiver, &self.stop, &acceptor, &workers);
        self.stop.stop();
        let stopped = handler.stopping();
        drop(receiver);
        let accepted = acceptor
            .join()
            .map_err(|_| worker_failure())
            .and_then(|result| result);
        let handled = join_workers(workers);
        accepted.and(handled).and(written).and(stopped)
    }
}

impl ControlStop {
    pub fn stop(&self) {
        if self.stopped.swap(true, Ordering::AcqRel) {
            return;
        }
        // Listener принадлежит также systemd. Будим только собственный поток приемки.
        let mut wake = self.wake.as_ref();
        loop {
            match wake.write(&[1]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                _ => break,
            }
        }
        let _ = self.notify_progress();
    }

    fn notify_progress(&self) -> io::Result<()> {
        let value = 1u64;
        loop {
            let result =
                unsafe { libc::write(self.progress.as_raw_fd(), (&value as *const u64).cast(), 8) };
            if result == 8 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::WouldBlock => return Ok(()),
                io::ErrorKind::Interrupted => continue,
                _ => return Err(error),
            }
        }
    }

    fn drain_progress(&self) -> io::Result<()> {
        let mut value = 0u64;
        loop {
            let result = unsafe {
                libc::read(
                    self.progress.as_raw_fd(),
                    (&mut value as *mut u64).cast(),
                    8,
                )
            };
            if result == 8 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::WouldBlock => return Ok(()),
                io::ErrorKind::Interrupted => continue,
                _ => return Err(error),
            }
        }
    }

    fn requested(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }
}

impl Quota {
    fn claim(self: &Arc<Self>, uid: u32) -> Option<Permit> {
        let mut counts = match self.counts.lock() {
            Ok(counts) => counts,
            Err(_) => {
                self.stop.stop();
                return None;
            }
        };
        let owner = counts.owners.get(&uid).copied().unwrap_or(0);
        let ordinary = counts.total - counts.owners.get(&0).copied().unwrap_or(0);
        if counts.total >= MAX_INFLIGHT
            || owner >= PER_OWNER
            || (uid != 0 && ordinary >= MAX_INFLIGHT - ADMIN_RESERVE)
        {
            return None;
        }
        counts.total += 1;
        *counts.owners.entry(uid).or_default() += 1;
        Some(Permit {
            quota: self.clone(),
            uid,
        })
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let Ok(mut counts) = self.quota.counts.lock() else {
            self.quota.stop.stop();
            return;
        };
        counts.total -= 1;
        if let Some(owner) = counts.owners.get_mut(&self.uid) {
            *owner -= 1;
            if *owner == 0 {
                counts.owners.remove(&self.uid);
            }
        }
    }
}

fn accept_connections(
    listener: Arc<UnixListener>,
    wake: UnixStream,
    stop: ControlStop,
    quota: Arc<Quota>,
    jobs: SyncSender<Job>,
) -> io::Result<()> {
    while !stop.requested() {
        let mut descriptors = [
            libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, -1) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if stop.requested() {
            break;
        }
        if descriptors
            .iter()
            .any(|fd| fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0)
        {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if descriptors[0].revents & libc::POLLIN == 0 {
            continue;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                if let Some(job) = admit(stream, &quota) {
                    if jobs.send(job).is_err() {
                        break;
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) =>
            {
                continue
            }
            Err(_) if stop.requested() => break,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn admit(stream: UnixStream, quota: &Arc<Quota>) -> Option<Job> {
    let stream = LocalStream::new(stream);
    let uid = stream.peer_credentials().ok()?.uid;
    Some(Job {
        stream: stream.stream,
        _permit: quota.claim(uid)?,
    })
}

fn start_workers(
    inbox: Inbox,
    events: SyncSender<Pending>,
    stop: &ControlStop,
) -> Result<Vec<JoinHandle<()>>, StartFailure> {
    let mut workers = Vec::with_capacity(MAX_INFLIGHT);
    for index in 0..MAX_INFLIGHT {
        let inbox = inbox.clone();
        let events = events.clone();
        let stop = stop.clone();
        match thread::Builder::new()
            .name(format!("aivpn-control-io-{index}"))
            .spawn(move || read_requests(inbox, events, stop))
        {
            Ok(worker) => workers.push(worker),
            Err(error) => return Err(StartFailure { error, workers }),
        }
    }
    Ok(workers)
}

fn read_requests(inbox: Inbox, events: SyncSender<Pending>, stop: ControlStop) {
    loop {
        let job = {
            let Ok(inbox) = inbox.lock() else {
                return;
            };
            inbox.recv()
        };
        let Ok(job) = job else {
            return;
        };
        if stop.requested() {
            return;
        }
        handle_connection(job, &events, &stop);
    }
}

fn handle_connection(job: Job, events: &SyncSender<Pending>, stop: &ControlStop) {
    if reply_buffer(&job.stream).is_err() {
        return;
    }
    let Ok(incoming) = IncomingControl::receive(job.stream) else {
        return;
    };
    let (reply, response) = mpsc::sync_channel(1);
    if events.send(Pending { incoming, reply }).is_err() {
        return;
    }
    if stop.notify_progress().is_err() {
        stop.stop();
        return;
    }
    if let Ok(outgoing) = response.recv() {
        let _ = outgoing.send();
    }
}

fn reply_buffer(stream: &UnixStream) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            (&REPLY_BUFFER_BYTES as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn write_state(
    handler: &mut impl ControlHandler,
    receiver: &Receiver<Pending>,
    stop: &ControlStop,
    acceptor: &JoinHandle<io::Result<()>>,
    workers: &[JoinHandle<()>],
) -> io::Result<()> {
    while !stop.requested()
        && !acceptor.is_finished()
        && !workers.iter().any(JoinHandle::is_finished)
    {
        // Сбрасываем уведомление до чтения очередей, чтобы не потерять новое событие.
        stop.drain_progress()?;
        handler.progress()?;
        let interval = handler.poll_interval();
        if interval.is_zero() || interval > Duration::from_millis(250) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        match receiver.try_recv() {
            Ok(pending) => {
                let response = pending
                    .incoming
                    .prepare_with(|authority, request| handler.prepare(authority, request));
                let _ = pending.reply.send(response);
            }
            Err(mpsc::TryRecvError::Empty) => {
                handler.wait_for_activity(stop.progress.as_fd(), interval)?;
            }
            Err(mpsc::TryRecvError::Disconnected) => break,
        }
    }
    if stop.requested() {
        Ok(())
    } else {
        Err(worker_failure())
    }
}

fn join_workers(workers: Vec<JoinHandle<()>>) -> io::Result<()> {
    let mut failed = false;
    for worker in workers {
        failed |= worker.join().is_err();
    }
    if failed {
        Err(worker_failure())
    } else {
        Ok(())
    }
}

fn worker_failure() -> io::Error {
    io::Error::other("Сбой обработчика локального управления")
}

#[cfg(test)]
#[path = "../../tests/support/control_service_supervision.rs"]
mod tests;
