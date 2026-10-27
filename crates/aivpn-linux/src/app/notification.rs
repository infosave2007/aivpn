//! Уведомления не задерживают обработку состояния VPN и ввод пользователя.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, OnceLock,
};

struct Notifier {
    latest: Arc<AtomicBool>,
    wake: mpsc::SyncSender<()>,
}

impl Notifier {
    fn send(&self, connected: bool) {
        self.latest.store(connected, Ordering::Release);
        let _ = self.wake.try_send(());
    }
}

fn spawn_worker(mut show: impl FnMut(bool) + Send + 'static) -> std::io::Result<Notifier> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let latest = Arc::new(AtomicBool::new(false));
    let state = latest.clone();
    std::thread::Builder::new()
        .name("aivpn-notifications".into())
        .spawn(move || {
            for () in receiver {
                show(state.load(Ordering::Acquire));
            }
        })?;
    Ok(Notifier {
        latest,
        wake: sender,
    })
}

pub(super) fn connection_changed(connected: bool) {
    static SENDER: OnceLock<Option<Notifier>> = OnceLock::new();
    if let Some(sender) = SENDER.get_or_init(|| {
        spawn_worker(|connected| {
            let _ = notify_rust::Notification::new()
                .summary("AIVPN")
                .body(if connected {
                    "Connected"
                } else {
                    "Disconnected"
                })
                .show();
        })
        .ok()
    }) {
        sender.send(connected);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn stalled_notification_does_not_block_or_grow_the_queue() {
        let (started, events) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let sender = spawn_worker(move |state| {
            started.send(state).unwrap();
            let _ = wait.recv();
        })
        .unwrap();
        sender.send(true);
        assert!(events.recv_timeout(Duration::from_secs(1)).unwrap());
        for _ in 0..10_000 {
            sender.send(false);
        }
        sender.send(true);
        release.send(()).unwrap();
        assert!(events.recv_timeout(Duration::from_secs(1)).unwrap());
        assert!(matches!(events.try_recv(), Err(mpsc::TryRecvError::Empty)));
        release.send(()).unwrap();
    }
}
