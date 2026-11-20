use aivpn_desktop_agent::control::ControlStore;
use aivpn_desktop_agent::state::StateFile;
use std::cell::RefCell;
use std::io;
use std::rc::Rc;

#[derive(Default)]
pub struct Records {
    pub committed: Option<Vec<u8>>,
    pub pending: Option<Vec<u8>>,
    pub writes: usize,
    pub fault: Option<bool>,
}
#[derive(Clone, Default)]
pub struct Store(pub Rc<RefCell<Records>>);
impl ControlStore for Store {
    fn load(&self, file: StateFile) -> io::Result<Option<Vec<u8>>> {
        Ok(match file {
            StateFile::Committed => self.0.borrow().committed.clone(),
            StateFile::Pending => self.0.borrow().pending.clone(),
            StateFile::DnsJournal => return Err(io::ErrorKind::InvalidInput.into()),
        })
    }
    fn replace(&mut self, file: StateFile, bytes: &[u8]) -> io::Result<()> {
        assert!(matches!(file, StateFile::Committed));
        let mut data = self.0.borrow_mut();
        data.writes += 1;
        let fault = data.fault.take();
        if fault != Some(false) {
            data.committed = Some(bytes.into());
        }
        if fault.is_some() {
            Err(io::Error::other("storage fault"))
        } else {
            Ok(())
        }
    }
    fn clear_pending(&mut self) -> io::Result<()> {
        panic!("Нумерация не управляет журналом Control")
    }
}
