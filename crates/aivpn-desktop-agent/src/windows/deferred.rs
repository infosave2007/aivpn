//! Долгий ответ не удерживает поток Control. Число I/O задач ограничено владельцем.
use super::{
    api::{Handle, TIMEOUT},
    send_response,
};
use crate::{
    policy::{Authority, Owner},
    protocol::{PreparedResponse, Response},
};
use std::{
    io,
    sync::atomic::AtomicBool,
    thread::{self, JoinHandle},
    time::Instant,
};

const MAX_PENDING: usize = 32;
const PER_OWNER: usize = 4;
const ADMIN_RESERVE: usize = 8;
// Постоянный anchor и текущий listener сохраняют имя, пока старые ответы завершаются.
pub(super) const MAX_INSTANCES: u32 = MAX_PENDING as u32 + 2;

struct Pending {
    owner: Owner,
    admin: bool,
    worker: JoinHandle<()>,
}

#[derive(Default)]
pub(super) struct DeferredReplies {
    pending: Vec<Pending>,
}

impl DeferredReplies {
    pub fn admits(&self, authority: &Authority) -> bool {
        self.pending.len() < MAX_PENDING
            && self
                .pending
                .iter()
                .filter(|job| job.owner == authority.user && job.admin == authority.machine_admin)
                .count()
                < PER_OWNER
            && (authority.machine_admin
                || self.pending.iter().filter(|job| !job.admin).count()
                    < MAX_PENDING - ADMIN_RESERVE)
    }

    pub fn spawn(
        &mut self,
        pipe: Handle,
        authority: &Authority,
        work: Box<dyn FnOnce() -> Response + Send>,
    ) -> io::Result<()> {
        if !self.admits(authority) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let worker = thread::Builder::new()
            .name("aivpn-control-reply".into())
            .spawn(move || {
                let response = PreparedResponse::Deferred(work).finish();
                let _ = send_response(
                    &pipe,
                    &response,
                    Instant::now() + TIMEOUT,
                    &AtomicBool::new(false),
                );
                unsafe {
                    windows_sys::Win32::System::Pipes::DisconnectNamedPipe(pipe.raw());
                }
            })?;
        self.pending.push(Pending {
            owner: authority.user.clone(),
            admin: authority.machine_admin,
            worker,
        });
        Ok(())
    }

    pub fn reap(&mut self) -> io::Result<()> {
        let mut index = 0;
        while index < self.pending.len() {
            if self.pending[index].worker.is_finished() {
                self.pending
                    .swap_remove(index)
                    .worker
                    .join()
                    .map_err(|_| worker_failed())?;
            } else {
                index += 1;
            }
        }
        Ok(())
    }

    pub fn finish(self) -> io::Result<()> {
        let mut result = Ok(());
        for pending in self.pending {
            if pending.worker.join().is_err() {
                result = Err(worker_failed());
            }
        }
        result
    }
}

fn worker_failed() -> io::Error {
    io::Error::other("Прерван обработчик отложенного ответа")
}
