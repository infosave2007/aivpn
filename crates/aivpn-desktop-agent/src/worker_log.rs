//! Журнал не растет бесконечно при длительном соединении.
use std::{
    fs::File,
    io::{self, Seek, SeekFrom, Write},
    sync::{Arc, Mutex},
};

pub const WORKER_LOG_LIMIT: usize = 1024 * 1024;

#[derive(Clone)]
pub struct WorkerLog(Arc<Mutex<File>>);
impl WorkerLog {
    pub fn new(mut file: File) -> io::Result<Self> {
        if !file.metadata()?.is_file() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        Ok(Self(Arc::new(Mutex::new(file))))
    }
}
impl Write for WorkerLog {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut journal = self
            .0
            .lock()
            .map_err(|_| io::Error::other("Повреждена блокировка журнала"))?;
        if bytes.is_empty() {
            return Ok(0);
        }
        let retained = &bytes[bytes.len().saturating_sub(WORKER_LOG_LIMIT)..];
        if journal
            .stream_position()?
            .saturating_add(retained.len() as u64)
            > WORKER_LOG_LIMIT as u64
        {
            journal.set_len(0)?;
            journal.seek(SeekFrom::Start(0))?;
        }
        // Пишется последний фрагмент, даже если одно событие больше всего журнала.
        // Успех сообщает о принятом событии, а не о числе сохраненных старых байтов.
        journal.write_all(retained)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("Повреждена блокировка журнала"))?
            .flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};
    #[test]
    fn long_running_worker_keeps_a_bounded_recent_log() {
        let path = std::env::temp_dir().join(format!("aivpn-worker-log-{}", std::process::id()));
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        #[cfg(unix)]
        std::fs::remove_file(&path).unwrap();
        let mut observed = file.try_clone().unwrap();
        let mut log = WorkerLog::new(file).unwrap();
        for _ in 0..300 {
            log.write_all(&[b'x'; 8192]).unwrap();
        }
        log.write_all(b"latest failure detail\n").unwrap();
        log.flush().unwrap();
        let size = observed.metadata().unwrap().len();
        assert!(size <= WORKER_LOG_LIMIT as u64, "worker log grew to {size}");
        observed.seek(SeekFrom::Start(0)).unwrap();
        let mut data = Vec::new();
        observed.read_to_end(&mut data).unwrap();
        assert!(data.ends_with(b"latest failure detail\n"));
        drop(log);
        drop(observed);
        #[cfg(windows)]
        std::fs::remove_file(path).unwrap();
    }
}

#[cfg(test)]
mod oversized_tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};
    #[test]
    fn oversized_event_and_cloned_writers_share_the_same_limit() {
        let path =
            std::env::temp_dir().join(format!("aivpn-worker-log-oversized-{}", std::process::id()));
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        #[cfg(unix)]
        std::fs::remove_file(&path).unwrap();
        let mut observed = file.try_clone().unwrap();
        let mut log = WorkerLog::new(file).unwrap();
        let large = vec![b'x'; WORKER_LOG_LIMIT * 3];
        assert_eq!(log.write(&large).unwrap(), large.len());
        assert_eq!(observed.metadata().unwrap().len(), WORKER_LOG_LIMIT as u64);
        let writers = (0..4)
            .map(|_| {
                let mut clone = log.clone();
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        clone.write_all(&[b'y'; 8192]).unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();
        for writer in writers {
            writer.join().unwrap();
        }
        assert_eq!(log.write(&[]).unwrap(), 0);
        log.write_all(b"final shared marker\n").unwrap();
        log.flush().unwrap();
        assert!(observed.metadata().unwrap().len() <= WORKER_LOG_LIMIT as u64);
        observed.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        observed.read_to_end(&mut bytes).unwrap();
        assert!(bytes.ends_with(b"final shared marker\n"));
        drop(log);
        drop(observed);
        #[cfg(windows)]
        std::fs::remove_file(path).unwrap();
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};
    #[test]
    fn exact_capacity_keeps_both_parts_and_rollover_drops_the_old_tail() {
        let path =
            std::env::temp_dir().join(format!("aivpn-worker-log-boundary-{}", std::process::id()));
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        #[cfg(unix)]
        std::fs::remove_file(&path).unwrap();
        file.write_all(b"stale output").unwrap();
        let mut observed = file.try_clone().unwrap();
        let mut log = WorkerLog::new(file).unwrap();
        assert_eq!(observed.metadata().unwrap().len(), 0);
        let half = vec![b'a'; WORKER_LOG_LIMIT / 2];
        log.write_all(&half).unwrap();
        log.clone()
            .write_all(&vec![b'b'; WORKER_LOG_LIMIT / 2])
            .unwrap();
        assert_eq!(observed.metadata().unwrap().len(), WORKER_LOG_LIMIT as u64);
        observed.seek(SeekFrom::Start(0)).unwrap();
        let mut data = Vec::new();
        observed.read_to_end(&mut data).unwrap();
        assert!(data[..half.len()].iter().all(|v| *v == b'a'));
        assert!(data[half.len()..].iter().all(|v| *v == b'b'));
        log.write_all(b"current").unwrap();
        assert_eq!(observed.metadata().unwrap().len(), 7);
        observed.seek(SeekFrom::Start(0)).unwrap();
        data.clear();
        observed.read_to_end(&mut data).unwrap();
        assert_eq!(data, b"current");
        drop(log);
        drop(observed);
        #[cfg(windows)]
        std::fs::remove_file(path).unwrap();
    }
}
