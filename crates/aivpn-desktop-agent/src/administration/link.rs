//! Корреляция ограниченного числа запросов не задерживает писатель состояния службы.
use super::{encode_payload, AdministrationReply, AdministrationRequest, ReplyText, SessionQuery};
use std::{
    collections::HashMap,
    io,
    num::NonZeroU64,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc, Mutex, Weak,
    },
    thread::{self, JoinHandle},
    time::Instant,
};

const MAX_PENDING: usize = 32;
type SendFrame = Box<dyn FnMut(&[u8]) -> io::Result<()> + Send>;
struct Pending {
    generation: NonZeroU64,
    result: mpsc::SyncSender<io::Result<ReplyText>>,
}
struct Shared {
    generation: AtomicU64,
    next: AtomicU64,
    closed: AtomicBool,
    pending: Mutex<HashMap<NonZeroU64, Pending>>,
    send: Mutex<SendFrame>,
    shutdown: Box<dyn Fn() + Send + Sync>,
}

pub(crate) struct AdministrationLink {
    shared: Arc<Shared>,
    reader: Option<JoinHandle<()>>,
}

#[derive(Clone)]
pub(crate) struct AdministrationCapability {
    generation: NonZeroU64,
    shared: Arc<Shared>,
}

impl AdministrationLink {
    pub fn new(
        generation: u64,
        send: impl FnMut(&[u8]) -> io::Result<()> + Send + 'static,
        mut receive: impl FnMut() -> io::Result<AdministrationReply> + Send + 'static,
        shutdown: impl Fn() + Send + Sync + 'static,
    ) -> io::Result<Self> {
        NonZeroU64::new(generation).ok_or(io::ErrorKind::InvalidInput)?;
        let shared = Arc::new(Shared {
            generation: AtomicU64::new(generation),
            next: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            pending: Mutex::new(HashMap::new()),
            send: Mutex::new(Box::new(send)),
            shutdown: Box::new(shutdown),
        });
        let weak = Arc::downgrade(&shared);
        let reader = thread::Builder::new()
            .name("aivpn-worker-admin".into())
            .spawn(move || {
                let _close = CloseOnExit(weak.clone());
                while let Ok(reply) = receive() {
                    let Some(shared) = weak.upgrade() else {
                        break;
                    };
                    if shared.closed.load(Ordering::Acquire) {
                        break;
                    }
                    let Ok(mut pending) = shared.pending.lock() else {
                        break;
                    };
                    let entry = pending.remove(&reply.id);
                    drop(pending);
                    let Some(entry) = entry else {
                        if reply.id.get() > shared.next.load(Ordering::Acquire) {
                            break;
                        }
                        continue;
                    };
                    if reply.generation != entry.generation {
                        let _ = entry
                            .result
                            .try_send(Err(io::ErrorKind::InvalidData.into()));
                        break;
                    }
                    let result = if !shared.valid(entry.generation) {
                        Err(stale())
                    } else if reply.success {
                        Ok(reply.output)
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Работник отклонил запрос",
                        ))
                    };
                    let _ = entry.result.try_send(result);
                }
            })?;
        Ok(Self {
            shared,
            reader: Some(reader),
        })
    }

    pub fn capability(&self, generation: u64) -> io::Result<AdministrationCapability> {
        let generation = NonZeroU64::new(generation).ok_or(io::ErrorKind::InvalidInput)?;
        if !self.shared.valid(generation) {
            return Err(stale());
        }
        Ok(AdministrationCapability {
            generation,
            shared: self.shared.clone(),
        })
    }

    pub fn advance(&self, generation: u64) -> io::Result<()> {
        let mut pending = self.shared.pending.lock().map_err(|_| broken())?;
        let before = self.shared.generation.load(Ordering::Acquire);
        if self.shared.closed.load(Ordering::Acquire) || before.checked_add(1) != Some(generation) {
            return Err(stale());
        }
        self.shared.generation.store(generation, Ordering::Release);
        for (_, request) in pending.drain() {
            let _ = request.result.try_send(Err(stale()));
        }
        Ok(())
    }

    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::Acquire)
    }
    pub fn close(&self) {
        self.shared.close();
    }
}

impl Drop for AdministrationLink {
    fn drop(&mut self) {
        self.shared.close();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl AdministrationCapability {
    pub fn request(&self, query: SessionQuery) -> io::Result<ReplyText> {
        if !self.shared.valid(self.generation) {
            return Err(stale());
        }
        let deadline = Instant::now() + query.timeout();
        let previous = self
            .shared
            .next
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |id| id.checked_add(1))
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        let id = NonZeroU64::new(previous + 1).ok_or(io::ErrorKind::InvalidData)?;
        let bytes = encode_payload(&AdministrationRequest {
            generation: self.generation,
            id,
            query,
        })?;
        let (result, response) = mpsc::sync_channel(1);
        {
            let mut pending = self.shared.pending.lock().map_err(|_| broken())?;
            if !self.shared.valid(self.generation) {
                return Err(stale());
            }
            if pending.len() >= MAX_PENDING {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            pending.insert(
                id,
                Pending {
                    generation: self.generation,
                    result,
                },
            );
        }
        let _pending = PendingGuard {
            id,
            shared: &self.shared,
        };
        {
            let mut send = self.shared.send.lock().map_err(|_| broken())?;
            if !self.shared.valid(self.generation) {
                return Err(stale());
            }
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            if let Err(error) = send(&bytes) {
                self.shared.close();
                return Err(error);
            }
        }
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .ok_or(io::ErrorKind::TimedOut)?;
        let result = response
            .recv_timeout(timeout)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => io::Error::from(io::ErrorKind::TimedOut),
                mpsc::RecvTimeoutError::Disconnected => broken(),
            })?;
        if !self.shared.valid(self.generation) {
            return Err(stale());
        }
        result
    }
}

struct PendingGuard<'a> {
    id: NonZeroU64,
    shared: &'a Shared,
}
impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.shared.pending.lock() {
            pending.remove(&self.id);
        }
    }
}
struct CloseOnExit(Weak<Shared>);
impl Drop for CloseOnExit {
    fn drop(&mut self) {
        if let Some(shared) = self.0.upgrade() {
            shared.close();
        }
    }
}
impl Shared {
    fn valid(&self, generation: NonZeroU64) -> bool {
        !self.closed.load(Ordering::Acquire)
            && self.generation.load(Ordering::Acquire) == generation.get()
    }
    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        (self.shutdown)();
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for (_, request) in pending.drain() {
            let _ = request.result.try_send(Err(broken()));
        }
    }
}
fn stale() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "Поколение работника завершено")
}
fn broken() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "Канал работника закрыт")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::administration::{decode_payload, CommandText};

    struct Stand {
        link: AdministrationLink,
        requests: mpsc::Receiver<Vec<u8>>,
        replies: mpsc::SyncSender<io::Result<Vec<u8>>>,
    }
    fn stand() -> Stand {
        let (outgoing, requests) = mpsc::sync_channel(32);
        let (replies, incoming) = mpsc::sync_channel::<io::Result<Vec<u8>>>(32);
        let shutdown = replies.clone();
        let link = AdministrationLink::new(
            1,
            move |frame| outgoing.try_send(frame.to_vec()).map_err(|_| broken()),
            move || decode_payload(&incoming.recv().map_err(|_| broken())??),
            move || {
                let _ = shutdown.try_send(Err(broken()));
            },
        )
        .unwrap();
        Stand {
            link,
            requests,
            replies,
        }
    }
    fn reply(request: &AdministrationRequest, output: &str) -> AdministrationReply {
        AdministrationReply {
            generation: request.generation,
            id: request.id,
            success: true,
            output: ReplyText::new(output.into()).unwrap(),
        }
    }
    fn request(stand: &Stand) -> AdministrationRequest {
        decode_payload(
            &stand
                .requests
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn independent_commands_receive_their_own_out_of_order_replies() {
        let stand = stand();
        let role = stand.link.capability(1).unwrap();
        let recording = role.clone();
        let first = thread::spawn(move || {
            role.request(SessionQuery::Execute {
                command: CommandText::new("role".into()).unwrap(),
            })
        });
        let second = thread::spawn(move || {
            recording.request(SessionQuery::Execute {
                command: CommandText::new("record_status".into()).unwrap(),
            })
        });
        let a = request(&stand);
        let b = request(&stand);
        for request in [&b, &a] {
            let SessionQuery::Execute { command } = &request.query else {
                panic!("Неверная команда")
            };
            let output = if command.as_str() == "role" {
                "2"
            } else {
                "recording"
            };
            stand
                .replies
                .send(Ok(encode_payload(&reply(request, output)).unwrap()))
                .unwrap();
        }
        assert_eq!(first.join().unwrap().unwrap().as_str(), "2");
        assert_eq!(second.join().unwrap().unwrap().as_str(), "recording");
        assert!(!stand.link.is_closed());
    }

    #[test]
    fn reconnect_revokes_waiters_and_a_late_old_reply_cannot_complete_a_new_request() {
        let stand = stand();
        let old = stand.link.capability(1).unwrap();
        let worker = old.clone();
        let pending = thread::spawn(move || worker.request(SessionQuery::Statistics {}));
        let old_request = request(&stand);
        stand.link.advance(2).unwrap();
        assert_eq!(
            pending.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        assert_eq!(
            old.request(SessionQuery::Statistics {}).unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        let current = stand.link.capability(2).unwrap();
        let pending = thread::spawn(move || current.request(SessionQuery::Statistics {}));
        let current_request = request(&stand);
        stand
            .replies
            .send(Ok(encode_payload(&reply(&old_request, "old")).unwrap()))
            .unwrap();
        stand
            .replies
            .send(Ok(
                encode_payload(&reply(&current_request, "current")).unwrap()
            ))
            .unwrap();
        assert_eq!(pending.join().unwrap().unwrap().as_str(), "current");
        let current = stand.link.capability(2).unwrap();
        stand.link.close();
        assert_eq!(
            current
                .request(SessionQuery::Statistics {})
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );
    }
}
