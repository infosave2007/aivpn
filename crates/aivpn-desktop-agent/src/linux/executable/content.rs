use super::FileStamp;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

const MAX_CONTENT_BYTES: u64 = 1024 * 1024 * 1024;
const READ_BYTES: usize = 64 * 1024;

pub(super) fn fingerprint(descriptor: &File, stamp: &FileStamp) -> io::Result<[u8; 32]> {
    if stamp.length > MAX_CONTENT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Исполняемый файл превышает предел 1 GiB",
        ));
    }
    stamp.verify(descriptor.metadata())?;
    let digest = read_content(descriptor, stamp.length)?;
    stamp.verify(descriptor.metadata())?;
    Ok(digest)
}

fn read_content(descriptor: &File, length: u64) -> io::Result<[u8; 32]> {
    let mut hash = Sha256::new();
    let mut buffer = [0; READ_BYTES];
    let mut offset = 0;
    while offset < length {
        let remaining = (length - offset).min(READ_BYTES as u64) as usize;
        let count = descriptor.read_at(&mut buffer[..remaining], offset)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Файл изменился при чтении",
            ));
        }
        hash.update(&buffer[..count]);
        offset += count as u64;
    }
    Ok(hash.finalize().into())
}
