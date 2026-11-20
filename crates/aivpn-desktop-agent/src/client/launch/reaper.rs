//! Один поток забирает завершения приложений, без потока на каждый запуск.
use std::{
    io,
    process::{Child, Command},
    sync::{Arc, Condvar, Mutex, OnceLock},
    time::Duration,
};

const MAX_CHILDREN: usize = 256;
type Shared = Arc<(Mutex<Vec<Child>>, Condvar)>;
static REAPER: OnceLock<io::Result<Shared>> = OnceLock::new();

fn collect(children: &mut Vec<Child>) {
    children.retain_mut(|child| !matches!(child.try_wait(), Ok(Some(_))));
}

pub(super) fn spawn(command: &mut Command) -> io::Result<u32> {
    let shared = REAPER
        .get_or_init(|| {
            let shared = Arc::new((Mutex::new(Vec::<Child>::new()), Condvar::new()));
            let worker = shared.clone();
            std::thread::Builder::new()
                .name("aivpn-app-reaper".into())
                .spawn(move || {
                    let (children, wake) = &*worker;
                    let mut children = children.lock().unwrap_or_else(|e| e.into_inner());
                    loop {
                        collect(&mut children);
                        children = if children.is_empty() {
                            wake.wait(children).unwrap_or_else(|e| e.into_inner())
                        } else {
                            wake.wait_timeout(children, Duration::from_secs(1))
                                .unwrap_or_else(|e| e.into_inner())
                                .0
                        };
                    }
                })?;
            Ok(shared)
        })
        .as_ref()
        .map_err(|e| io::Error::new(e.kind(), e.to_string()))?;
    let (children, wake) = &**shared;
    let mut children = children.lock().unwrap_or_else(|e| e.into_inner());
    collect(&mut children);
    if children.len() >= MAX_CHILDREN {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "Достигнут предел запущенных приложений",
        ));
    }
    let child = command.spawn()?;
    let id = child.id();
    children.push(child);
    wake.notify_one();
    Ok(id)
}
