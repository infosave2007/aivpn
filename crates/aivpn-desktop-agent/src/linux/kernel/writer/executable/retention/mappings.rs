use crate::linux::LocatedExecutable;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;

const MAX_MAP_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn exclude(executable: &LocatedExecutable) -> io::Result<()> {
    let file = File::from(executable.as_fd().try_clone_to_owned()?);
    let metadata = file.metadata()?;
    let device = (libc::major(metadata.dev()) << 20) | libc::minor(metadata.dev());
    let mut maps = Vec::new();
    File::open("/proc/self/maps")?
        .take(MAX_MAP_BYTES as u64 + 1)
        .read_to_end(&mut maps)?;
    if maps.is_empty() || maps.len() > MAX_MAP_BYTES {
        return Err(invalid());
    }
    exclude_table(
        &maps,
        metadata.ino(),
        &[device as u64, executable.filesystem_device()],
    )
}

fn exclude_table(bytes: &[u8], inode: u64, devices: &[u64]) -> io::Result<()> {
    for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        let (mapped_device, mapped_inode) = identity(line)?;
        if mapped_inode == inode && devices.contains(&mapped_device) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Файл отображен в mm службы",
            ));
        }
    }
    Ok(())
}

fn identity(line: &[u8]) -> io::Result<(u64, u64)> {
    let line = std::str::from_utf8(line).map_err(|_| invalid())?;
    let fields: Vec<_> = line.split_ascii_whitespace().take(5).collect();
    if fields.len() != 5 {
        return Err(invalid());
    }
    let inode = fields[4].parse().map_err(|_| invalid())?;
    Ok((device(fields[3])?, inode))
}

fn device(value: &str) -> io::Result<u64> {
    let (major, minor) = value.split_once(':').ok_or_else(invalid)?;
    let major = u64::from_str_radix(major, 16).map_err(|_| invalid())?;
    let minor = u64::from_str_radix(minor, 16).map_err(|_| invalid())?;
    if major >= 1 << 12 || minor >= 1 << 20 {
        return Err(invalid());
    }
    Ok((major << 20) | minor)
}

fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identities_cover_kernel_and_getattr_devices_without_names() {
        let table = b"1000-2000 r--p 0000 00:1b 42 /different name (deleted)\n";
        assert!(exclude_table(table, 42, &[100, 27]).is_err());
        assert!(exclude_table(table, 43, &[100, 27]).is_ok());
        assert!(exclude_table(b"malformed", 42, &[27]).is_err());
        assert!(exclude_table(b"1-2 r--p 0 1000:00 42\n", 42, &[27]).is_err());
        assert!(exclude_table(b"1-2 r--p 0 00:100000 42\n", 42, &[27]).is_err());
    }
}
