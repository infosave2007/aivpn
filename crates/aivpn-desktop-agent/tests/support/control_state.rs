use super::*;
use crate::protocol::Outcome;
use crate::state::StateDirectory;
use aivpn_desktop_policy::ProfileAssignment;
use std::cell::{Cell, RefCell};
use std::fs;
use std::num::NonZeroU64;
use std::os::unix::fs::DirBuilderExt;
use std::rc::Rc;

struct Directory(std::path::PathBuf);

impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct ObservedBackend {
    live: Rc<RefCell<Vec<bool>>>,
    fail: Rc<Cell<bool>>,
    authority: Authority,
}

impl<S: crate::control::ControlStore> RoutingBackend<S> for ObservedBackend {
    fn installed_state(&self) -> crate::control::InstalledState {
        crate::control::InstalledState::Active
    }
    fn supported(&self) -> bool {
        true
    }
    fn install(
        &mut self,
        _store: &mut S,
        _desired: &ControlState,
        profiles: &ProfileCatalog,
    ) -> io::Result<()> {
        self.live.borrow_mut().push(
            profiles
                .list(&self.authority)
                .unwrap()
                .iter()
                .any(|profile| profile.ready_ipv4),
        );
        if self.fail.get() {
            return Err(io::Error::other("test fault"));
        }
        Ok(())
    }
    fn block(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn real_files_preserve_live_leases_and_failed_transactions_revoke_them() {
    let directory = Directory(
        std::env::temp_dir().join(format!("aivpn-control-state-test-{}", std::process::id())),
    );
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory.0)
        .unwrap();
    fs::write(
        directory.0.join(".aivpn-state-test"),
        b"aivpn-state-fixture-v1\n",
    )
    .unwrap();
    let store = StateDirectory::open(&directory.0).unwrap();
    let authority = Authority {
        user: Owner::LinuxUser {
            uid: unsafe { libc::geteuid() },
        },
        machine_admin: false,
    };
    let live = Rc::new(RefCell::new(vec![]));
    let fail = Rc::new(Cell::new(false));
    let backend = ObservedBackend {
        live: live.clone(),
        fail: fail.clone(),
        authority: authority.clone(),
    };
    let mut control = Control::open(Platform::Linux, [31; 16], store, backend).unwrap();
    let next = std::sync::atomic::AtomicU64::new(0);
    let register = || {
        Request::new(
            NonZeroU64::MIN,
            Command::RegisterProfile {
                registration_key: format!(
                    "internal-{}",
                    next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                ),
                owner: authority.user.clone(),
                consumers: vec![],
            },
        )
    };
    let response = control.handle(&authority, register());
    let id = match response.result() {
        Outcome::Ok {
            reply: Reply::Registered { profile },
        } => profile.clone(),
        other => panic!("{other:?}"),
    };
    let lease = control
        .state
        .profiles
        .begin_session(&id, &authority)
        .unwrap();
    let assignment = ProfileAssignment {
        interface_id: 41,
        ipv4: "10.67.0.2".parse().unwrap(),
        ipv6: None,
    };
    let prepared = control
        .state
        .profiles
        .prepare_assignment(&lease, assignment)
        .unwrap();
    control.state.profiles.commit_ready(prepared).unwrap();
    let delete = Request::new(
        NonZeroU64::MIN,
        Command::DeleteProfile {
            profile: id.clone(),
        },
    );
    assert!(matches!(
        control.handle(&authority, delete).result(),
        Outcome::Error {
            code: ErrorCode::Conflict
        }
    ));
    assert!(matches!(
        control.handle(&authority, register()).result(),
        Outcome::Ok { .. }
    ));
    assert!(control
        .state
        .profiles
        .available(&id, "192.0.2.1".parse().unwrap()));
    assert!(live.borrow().last().unwrap());
    fail.set(true);
    let response = control.handle(&authority, register());
    assert!(matches!(
        response.result(),
        Outcome::Error {
            code: ErrorCode::BackendUnavailable
        }
    ));
    assert!(control
        .state
        .profiles
        .prepare_assignment(&lease, assignment)
        .is_err());
    drop(control);
    let store = StateDirectory::open(&directory.0).unwrap();
    fail.set(false);
    let backend = ObservedBackend {
        live,
        fail,
        authority: authority.clone(),
    };
    let control = Control::open(Platform::Linux, [32; 16], store, backend).unwrap();
    assert_eq!(control.state.profiles.namespace(), [31; 16]);
    let profiles = control.state.profiles.list(&authority).unwrap();
    assert_eq!(profiles.len(), 3);
    assert!(profiles
        .iter()
        .all(|profile| !profile.ready_ipv4 && !profile.session_active));
    assert!(control.store.load(StateFile::Pending).unwrap().is_none());
}
