use super::super::{KernelWriter, VerifiedFile};
use super::{
    invalid, mappings, native,
    record::{id, Record},
    storage,
};
use crate::linux::kernel::objects::{open_pin, read_array, ObjectInfo};
use crate::linux::kernel::writer::verified::PreparedGroupExecutable;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::linux::kernel::writer) struct GroupEvidence {
    pub slot: u32,
    pub cookie: u64,
    pub device: u64,
    pub inode: u64,
    pub link: u32,
    pub program: u32,
    pub pid: u32,
    pub record: u32,
    pub digest: [u8; 32],
}

pub(in crate::linux::kernel::writer) struct GroupRetention {
    evidence: GroupEvidence,
    instance: OwnedFd,
    link: OwnedFd,
    record: OwnedFd,
}

fn record_bytes(writer: &KernelWriter, evidence: &GroupEvidence) -> io::Result<[u8; 256]> {
    let legacy = Record::new(
        writer,
        [evidence.link, evidence.program, evidence.pid],
        evidence.slot,
        evidence.device,
        evidence.inode,
    )?;
    let mut bytes = [0; 256];
    bytes[..128].copy_from_slice(&legacy.0);
    bytes[..4].copy_from_slice(b"APR2");
    bytes[128..132].copy_from_slice(&2u32.to_le_bytes());
    bytes[132..136].copy_from_slice(&256u32.to_le_bytes());
    bytes[136..144].copy_from_slice(&evidence.cookie.to_le_bytes());
    bytes[144..148].copy_from_slice(&id(writer.kernel.map(c"inode_tokens")?)?.to_le_bytes());
    bytes[148..180].copy_from_slice(&boot_digest()?);
    bytes[180..212].copy_from_slice(&writer.kernel.identity_digest()?);
    let digest = Sha256::digest(&bytes[..224]);
    bytes[224..].copy_from_slice(&digest);
    Ok(bytes)
}

pub(in crate::linux::kernel::writer) fn boot_digest() -> io::Result<[u8; 32]> {
    let mut bytes = Vec::new();
    File::open("/proc/sys/kernel/random/boot_id")?
        .take(38)
        .read_to_end(&mut bytes)?;
    if bytes.len() != 37 {
        return Err(invalid());
    }
    Ok(Sha256::digest(bytes).into())
}

impl GroupRetention {
    pub fn attach(writer: &KernelWriter, proof: &PreparedGroupExecutable<'_>) -> io::Result<Self> {
        proof.verify(writer)?;
        let file = proof.file();
        let (link, ids) = attach_checked(writer, file)?;
        let evidence = evidence_for_file(file, proof.slot().get(), proof.cookie(), ids)?;
        Self::new(writer, file, link, evidence)
    }
    fn new(
        writer: &KernelWriter,
        file: &VerifiedFile,
        link: OwnedFd,
        mut evidence: GroupEvidence,
    ) -> io::Result<Self> {
        let bytes = record_bytes(writer, &evidence)?;
        evidence.digest.copy_from_slice(&bytes[224..]);
        let record = native::record(&bytes)?;
        evidence.record = id(&record)?;
        Ok(Self {
            evidence,
            instance: file.instance.as_fd().try_clone_to_owned()?,
            link,
            record,
        })
    }
    pub fn evidence(&self) -> GroupEvidence {
        self.evidence.clone()
    }
    pub fn pin(
        &self,
        writer: &KernelWriter,
        proof: &PreparedGroupExecutable<'_>,
    ) -> io::Result<()> {
        self.verify_claim(writer, proof)?;
        let file = proof.file();
        let base = base(writer, true)?;
        let name = name("pending", self.evidence.link);
        if unsafe { libc::mkdirat(base.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let directory = storage::directory(&base, &name, false)?;
        self.pin_objects(&directory)?;
        file.verify(writer)?;
        mappings::exclude(&file.executable)?;
        verify_directory(writer, &directory, &self.evidence, true)?;
        storage::rename(&base, &name, &storage::completed_name(self.evidence.link))
    }
    fn verify_claim(
        &self,
        writer: &KernelWriter,
        proof: &PreparedGroupExecutable<'_>,
    ) -> io::Result<()> {
        proof.verify(writer)?;
        if self.evidence.slot != proof.slot().get() || self.evidence.cookie != proof.cookie() {
            return Err(invalid());
        }
        Ok(())
    }
    fn pin_objects(&self, directory: &File) -> io::Result<()> {
        pin(directory, c"instance", &self.instance)?;
        pin(directory, c"record", &self.record)?;
        pin(directory, c"link", &self.link)
    }
    pub fn verify(writer: &KernelWriter, evidence: &GroupEvidence) -> io::Result<()> {
        let directory = storage::open_record(
            &base(writer, false)?,
            &storage::completed_name(evidence.link),
        )?;
        verify_directory(writer, &directory, evidence, true)
    }
    pub fn inventory(writer: &KernelWriter) -> io::Result<Vec<CString>> {
        match base(writer, false) {
            Ok(base) => storage::names(&base, storage::LIMIT),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(error),
        }
    }
    pub fn release(writer: &KernelWriter, evidence: &GroupEvidence) -> io::Result<()> {
        let base = match base(writer, false) {
            Ok(base) => base,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        Self::release_in(writer, &base, evidence)
    }
    fn release_in(writer: &KernelWriter, base: &File, evidence: &GroupEvidence) -> io::Result<()> {
        let Some(current) = release_name(base, evidence.link)? else {
            return Ok(());
        };
        let directory = storage::directory(base, &current, false)?;
        verify_directory(writer, &directory, evidence, false)?;
        let releasing = name("releasing", evidence.link);
        if current != releasing {
            storage::rename(base, &current, &releasing)?;
        }
        for entry in [c"link", c"record", c"instance"] {
            remove_exact(writer, &directory, entry, evidence)?;
        }
        storage::remove_directory(base, &releasing, &directory)
    }
}

fn verify_directory(
    writer: &KernelWriter,
    directory: &File,
    evidence: &GroupEvidence,
    complete: bool,
) -> io::Result<()> {
    let names = storage::names(directory, 3)?;
    if complete && names.len() != 3 {
        return Err(invalid());
    }
    for name in names {
        verify_pin(writer, directory, &name, evidence)?;
    }
    Ok(())
}
fn verify_pin(
    writer: &KernelWriter,
    directory: &File,
    name: &CStr,
    evidence: &GroupEvidence,
) -> io::Result<OwnedFd> {
    let fd = open_pin(directory, name)?;
    match name.to_bytes() {
        b"instance" => {
            verify_instance(writer, &fd)?;
        }
        b"record" => verify_record(writer, &fd, evidence)?,
        b"link" => {
            native::inspect(&fd, evidence.program, evidence.link, evidence.pid, false)?;
        }
        _ => return Err(invalid()),
    }
    Ok(fd)
}
fn verify_record(writer: &KernelWriter, fd: &OwnedFd, evidence: &GroupEvidence) -> io::Result<()> {
    let expected = record_bytes(writer, evidence)?;
    if id(fd)? != evidence.record || read_array::<256>(fd)? != expected {
        return Err(invalid());
    }
    if evidence.digest != expected[224..] || evidence.cookie == 0 {
        return Err(invalid());
    }
    verify_frozen(fd)?;
    verify_legacy_fields(writer, &expected)
}
fn verify_frozen(fd: &OwnedFd) -> io::Result<()> {
    let mut info = String::new();
    File::open(format!("/proc/thread-self/fdinfo/{}", fd.as_raw_fd()))?
        .take(4097)
        .read_to_string(&mut info)?;
    if info.len() > 4096 || !info.lines().any(|line| line == "frozen:\t1") {
        return Err(invalid());
    }
    Ok(())
}
fn verify_legacy_fields(writer: &KernelWriter, expected: &[u8; 256]) -> io::Result<()> {
    let mut legacy = [0; 128];
    legacy.copy_from_slice(&expected[..128]);
    legacy[..4].copy_from_slice(b"APR1");
    Record(legacy).verify(writer, writer.kernel.map(c"path_key")?)
}
fn remove_exact(
    writer: &KernelWriter,
    directory: &File,
    name: &CStr,
    evidence: &GroupEvidence,
) -> io::Result<()> {
    match verify_pin(writer, directory, name, evidence) {
        Ok(fd) => storage::remove(directory, name, id(&fd)?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}
fn base(writer: &KernelWriter, create: bool) -> io::Result<File> {
    storage::named_base(
        writer.slots.namespace(),
        c"aivpn_app_group_retainers",
        create,
    )
}
fn name(prefix: &str, link: u32) -> CString {
    CString::new(format!("{prefix}_{link:08x}")).unwrap()
}
fn pin(directory: &File, name: &CStr, fd: &OwnedFd) -> io::Result<()> {
    unsafe extern "C" {
        fn bpf_obj_pin(fd: i32, path: *const libc::c_char) -> i32;
    }
    let path = CString::new(format!(
        "/proc/thread-self/fd/{}/{}",
        directory.as_raw_fd(),
        name.to_str().unwrap()
    ))
    .unwrap();
    crate::linux::kernel::image::result(unsafe { bpf_obj_pin(fd.as_raw_fd(), path.as_ptr()) })?;
    if unsafe { libc::fchmodat(directory.as_raw_fd(), name.as_ptr(), 0o600, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let _ = ObjectInfo::read(&open_pin(directory, name)?)?;
    Ok(())
}

fn attach_checked(writer: &KernelWriter, file: &VerifiedFile) -> io::Result<(OwnedFd, [u32; 3])> {
    file.verify(writer)?;
    mappings::exclude(&file.executable)?;
    let program = writer.kernel.program(c"retain_application_inode")?;
    let link = native::attach(program, file.executable.as_fd())?;
    let ids = native::inspect(&link, id(program)?, 0, std::process::id(), true)?;
    file.verify(writer)?;
    mappings::exclude(&file.executable)?;
    Ok((link, ids))
}
fn evidence_for_file(
    file: &VerifiedFile,
    slot: u32,
    cookie: u64,
    ids: [u32; 3],
) -> io::Result<GroupEvidence> {
    let inode = File::from(file.executable.as_fd().try_clone_to_owned()?)
        .metadata()?
        .ino();
    Ok(GroupEvidence {
        slot,
        cookie,
        device: file.executable.filesystem_device(),
        inode,
        link: ids[0],
        program: ids[1],
        pid: ids[2],
        record: 0,
        digest: [0; 32],
    })
}
fn release_name(base: &File, link: u32) -> io::Result<Option<CString>> {
    let candidates = [
        name("link", link),
        name("pending", link),
        name("releasing", link),
    ];
    let existing = storage::names(base, storage::LIMIT)?;
    let mut found = candidates
        .into_iter()
        .filter(|name| existing.contains(name));
    let first = found.next();
    if found.next().is_some() {
        return Err(invalid());
    }
    Ok(first)
}
fn verify_instance(writer: &KernelWriter, fd: &OwnedFd) -> io::Result<()> {
    let expected = writer.kernel.map(c"path_key")?;
    if id(fd)? != id(expected)? || read_array::<16>(fd)? != read_array::<16>(expected)? {
        return Err(invalid());
    }
    Ok(())
}
