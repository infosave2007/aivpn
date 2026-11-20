//! Фиксированная команда провайдера с ограничением вывода, времени и потомков.
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const MAX_OUTPUT: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    device: u64,
    inode: u64,
    ctime: i64,
    ctime_nsec: i64,
}
pub(super) struct Program {
    path: PathBuf,
    file: File,
    identity: Identity,
}
impl Program {
    pub(super) fn open() -> io::Result<Self> {
        let path = Path::new("/usr/bin/resolvconf").canonicalize()?;
        for parent in path.ancestors() {
            let m = fs::symlink_metadata(parent)?;
            if m.uid() != 0 || m.mode() & 0o022 != 0 {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)?;
        let m = file.metadata()?;
        if !m.is_file() || m.mode() & 0o111 == 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let identity = identity(&m);
        Ok(Self {
            path,
            file,
            identity,
        })
    }
    pub(super) fn identity(&self) -> &Identity {
        &self.identity
    }
    fn verify(&self) -> io::Result<()> {
        if identity(&self.file.metadata()?) != self.identity
            || identity(&fs::metadata(&self.path)?) != self.identity
        {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        Ok(())
    }
    pub(super) fn run(&self, args: &[&str], input: Option<&[u8]>) -> io::Result<Vec<u8>> {
        self.verify()?;
        if input.is_some_and(|input| input.len() > 4096) {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        let child = Command::new(&self.path)
            .args(args)
            .current_dir("/")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .process_group(0)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut child = Running(child);
        if let Some(input) = input {
            child.0.stdin.take().unwrap().write_all(input)?;
        }
        let mut stdout = child.0.stdout.take().unwrap();
        let flags = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                < 0
        {
            return Err(io::Error::last_os_error());
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut bytes = Vec::new();
        let mut eof = false;
        loop {
            let mut block = [0; 8192];
            match stdout.read(&mut block) {
                Ok(0) => eof = true,
                Ok(count) => {
                    if bytes.len() + count > MAX_OUTPUT {
                        return Err(io::ErrorKind::FileTooLarge.into());
                    }
                    bytes.extend_from_slice(&block[..count]);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
            if let Some(success) = child.exited()? {
                if eof {
                    self.verify()?;
                    return if success {
                        Ok(bytes)
                    } else {
                        Err(io::Error::other("resolvconf не подтвердил операцию DNS"))
                    };
                }
            }
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
fn identity(m: &fs::Metadata) -> Identity {
    Identity {
        device: m.dev(),
        inode: m.ino(),
        ctime: m.ctime(),
        ctime_nsec: m.ctime_nsec(),
    }
}
struct Running(Child);
impl Running {
    fn exited(&self) -> io::Result<Option<bool>> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::waitid(
                libc::P_PID,
                self.0.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        // WNOWAIT сохраняет PID до завершения всей принадлежащей нам группы.
        Ok((unsafe { info.si_pid() } != 0)
            .then(|| info.si_code == libc::CLD_EXITED && unsafe { info.si_status() } == 0))
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        // Потомок, удержавший stdout после выхода родителя, не блокирует writer.
        if self.exited().is_ok() {
            unsafe {
                libc::kill(-(self.0.id() as i32), libc::SIGKILL);
            }
        }
        let _ = self.0.wait();
    }
}
