use super::*;
use crate::state::StateFile;
use aivpn_desktop_policy::{Platform, ProfileCatalog};

struct Store;
impl ControlStore for Store {
    fn load(&self, _: StateFile) -> io::Result<Option<Vec<u8>>> {
        Ok(None)
    }
    fn replace(&mut self, _: StateFile, _: &[u8]) -> io::Result<()> {
        unreachable!("Проверка надзора не меняет состояние")
    }
    fn clear_pending(&mut self) -> io::Result<()> {
        unreachable!("Проверка надзора не меняет состояние")
    }
}
struct Backend;
impl<S: crate::control::ControlStore> RoutingBackend<S> for Backend {
    fn installed_state(&self) -> crate::control::InstalledState {
        crate::control::InstalledState::Active
    }
    fn supported(&self) -> bool {
        true
    }
    fn install(
        &mut self,
        _store: &mut S,
        _: &crate::control::ControlState,
        _: &ProfileCatalog,
    ) -> io::Result<()> {
        Ok(())
    }
    fn block(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn unexpected_acceptor_or_io_exit_is_reported_without_an_external_stop() {
    for accept_failed in [false, true] {
        let (listener, _) = ControlServer::new(UnixListener::bind("").unwrap()).unwrap();
        let stop = listener.stop.clone();
        let cleanup = stop.clone();
        let (accept_release, accept_wait) = mpsc::channel::<()>();
        let (io_release, io_wait) = mpsc::channel::<()>();
        let acceptor = thread::spawn(move || {
            if !accept_failed {
                let _ = accept_wait.recv();
            }
            Ok(())
        });
        let worker = thread::spawn(move || {
            if accept_failed {
                let _ = io_wait.recv();
            }
        });
        let (events, receiver) = mpsc::sync_channel(1);
        let (result, completed) = mpsc::channel();
        let driver = thread::spawn(move || {
            let workers = vec![worker];
            let mut control = Control::open(Platform::Linux, [91; 16], Store, Backend).unwrap();
            let response = write_state(&mut control, &receiver, &stop, &acceptor, &workers);
            result.send(response).unwrap();
            let _ = acceptor.join();
            join_workers(workers).unwrap();
        });
        let response = completed.recv_timeout(Duration::from_secs(1));
        cleanup.stop();
        drop(accept_release);
        drop(io_release);
        drop(events);
        driver.join().unwrap();
        assert!(response.unwrap().is_err(), "accept_failed={accept_failed}");
    }
}

#[test]
fn worker_progress_and_failure_do_not_wait_for_a_control_client() {
    struct FailingWorker {
        ticks: usize,
    }
    impl ControlHandler for FailingWorker {
        fn handle(
            &mut self,
            _: &aivpn_desktop_policy::Authority,
            _: crate::protocol::Request,
        ) -> crate::protocol::Response {
            panic!("Клиент управления не подключен")
        }
        fn progress(&mut self) -> io::Result<()> {
            self.ticks += 1;
            if self.ticks == 3 {
                Err(io::ErrorKind::BrokenPipe.into())
            } else {
                Ok(())
            }
        }
        fn poll_interval(&self) -> Duration {
            Duration::from_millis(1)
        }
    }
    let (server, _) = ControlServer::new(UnixListener::bind("").unwrap()).unwrap();
    let mut handler = FailingWorker { ticks: 0 };
    assert_eq!(
        server.run_handler(&mut handler).unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(handler.ticks, 3);
}

struct ObservedWait {
    entered: Option<SyncSender<()>>,
    wakes: Arc<std::sync::atomic::AtomicUsize>,
}
impl ControlHandler for ObservedWait {
    fn handle(&mut self, _: &Authority, request: Request) -> Response {
        Response::success(request.id(), crate::protocol::Reply::Done {})
    }

    fn wait_for_activity(&mut self, pending: BorrowedFd<'_>, _: Duration) -> io::Result<()> {
        if let Some(entered) = self.entered.take() {
            entered.send(()).unwrap();
        }
        let mut event = libc::pollfd {
            fd: pending.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let result = unsafe { libc::poll(&mut event, 1, 5000) };
            if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            assert!(result >= 0, "{}", io::Error::last_os_error());
            if event.revents & libc::POLLIN != 0 {
                self.wakes.fetch_add(1, Ordering::SeqCst);
            }
            return Ok(());
        }
    }
}

#[test]
fn stopping_service_wakes_the_waiting_state_writer() {
    let (server, stop) = ControlServer::new(UnixListener::bind("").unwrap()).unwrap();
    let (entered, ready) = mpsc::sync_channel(1);
    let wakes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = wakes.clone();
    let worker = thread::spawn(move || {
        server.run_handler(&mut ObservedWait {
            entered: Some(entered),
            wakes: observed,
        })
    });
    let started = ready.recv_timeout(Duration::from_secs(2));
    stop.stop();
    worker.join().unwrap().unwrap();
    started.unwrap();
    assert!(
        wakes.load(Ordering::SeqCst) > 0,
        "Остановка должна разбудить poll"
    );
}

#[test]
fn complete_request_wakes_the_waiting_state_writer() {
    let listener = UnixListener::bind("").unwrap();
    let address = listener.local_addr().unwrap();
    let (server, stop) = ControlServer::new(listener).unwrap();
    let (entered, ready) = mpsc::sync_channel(1);
    let wakes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = wakes.clone();
    let worker = thread::spawn(move || {
        server.run_handler(&mut ObservedWait {
            entered: Some(entered),
            wakes: observed,
        })
    });
    let response = (|| -> io::Result<_> {
        ready
            .recv_timeout(Duration::from_secs(2))
            .map_err(io::Error::other)?;
        let mut client = LocalStream::new(UnixStream::connect_addr(&address)?);
        let request = Request::new(
            std::num::NonZeroU64::new(7).unwrap(),
            crate::protocol::Command::Status {},
        );
        client.send(&request.to_json().unwrap(), &[])?;
        let response = client.receive(Some(Duration::from_secs(2)))?;
        assert!(response.descriptors.is_empty());
        Ok(Response::from_json(&response.payload).unwrap())
    })();
    let request_woke = wakes.load(Ordering::SeqCst) > 0;
    stop.stop();
    worker.join().unwrap().unwrap();
    assert!(matches!(
        response.unwrap().result(),
        crate::protocol::Outcome::Ok {
            reply: crate::protocol::Reply::Done {}
        }
    ));
    assert!(
        request_woke,
        "Очередь запросов должна разбудить poll до остановки"
    );
}
