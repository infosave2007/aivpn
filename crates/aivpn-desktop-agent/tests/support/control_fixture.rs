use aivpn_desktop_agent::control::*;
use aivpn_desktop_agent::state::StateFile;
use aivpn_desktop_policy::ProfileCatalog;
use std::io;

#[derive(Default)]
pub(crate) struct Memory {
    committed: Option<Vec<u8>>,
    pending: Option<Vec<u8>>,
    dns: Option<Vec<u8>>,
}

impl ControlStore for Memory {
    fn load(&self, file: StateFile) -> io::Result<Option<Vec<u8>>> {
        Ok(match file {
            StateFile::Committed => &self.committed,
            StateFile::Pending => &self.pending,
            StateFile::DnsJournal => &self.dns,
        }
        .clone())
    }
    fn replace(&mut self, file: StateFile, data: &[u8]) -> io::Result<()> {
        *match file {
            StateFile::Committed => &mut self.committed,
            StateFile::Pending => &mut self.pending,
            StateFile::DnsJournal => &mut self.dns,
        } = Some(data.into());
        Ok(())
    }
    fn clear_pending(&mut self) -> io::Result<()> {
        self.pending = None;
        Ok(())
    }
}

pub(crate) struct Backend;

impl<S: aivpn_desktop_agent::control::ControlStore> RoutingBackend<S> for Backend {
    fn installed_state(&self) -> aivpn_desktop_agent::control::InstalledState {
        aivpn_desktop_agent::control::InstalledState::Active
    }
    fn supported(&self) -> bool {
        true
    }
    fn install(
        &mut self,
        _store: &mut S,
        _desired: &ControlState,
        _live: &ProfileCatalog,
    ) -> io::Result<()> {
        Ok(())
    }
    fn block(&mut self) -> io::Result<()> {
        Ok(())
    }
}
