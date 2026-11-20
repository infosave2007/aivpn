use super::*;

pub(super) struct Mount {
    pub device: u64,
    root: Option<PathBuf>,
    point: PathBuf,
}

impl Mount {
    pub fn filesystem_path(&self, canonical: &Path) -> io::Result<Vec<u8>> {
        let root = self.root.as_ref().ok_or_else(invalid_location)?;
        let suffix = canonical
            .strip_prefix(&self.point)
            .map_err(|_| invalid_location())?;
        let path = if suffix.as_os_str().is_empty() {
            root.clone()
        } else {
            root.join(suffix)
        }
        .into_os_string()
        .into_vec();
        if path.len() >= 4096 {
            return Err(invalid_location());
        }
        Ok(path)
    }
}

pub(super) fn parse(bytes: &[u8]) -> io::Result<BTreeMap<u64, Mount>> {
    let mut mounts = BTreeMap::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let fields: Vec<_> = line.split(|byte| *byte == b' ').collect();
        if fields.len() < 10 || !fields[6..].contains(&&b"-"[..]) {
            return Err(invalid_location());
        }
        let id = number(fields[0])?;
        if id == 0 || mounts.insert(id, parse_mount(&fields)?).is_some() {
            return Err(invalid_location());
        }
    }
    if mounts.is_empty() {
        return Err(invalid_location());
    }
    Ok(mounts)
}

fn parse_mount(fields: &[&[u8]]) -> io::Result<Mount> {
    Ok(Mount {
        device: device(fields[2])?,
        // nsfs и другие псевдофайлы могут иметь корень вида net:[inode].
        // Такая запись не мешает снимку, но не дает физического пути файла.
        root: fields[3]
            .starts_with(b"/")
            .then(|| decode_path(fields[3]))
            .transpose()?,
        point: decode_path(fields[4])?,
    })
}

fn device(field: &[u8]) -> io::Result<u64> {
    let mut device = field.split(|byte| *byte == b':');
    let major = number(device.next().ok_or_else(invalid_location)?)?;
    let minor = number(device.next().ok_or_else(invalid_location)?)?;
    if device.next().is_some() {
        return Err(invalid_location());
    }
    if major >= 1 << 12 || minor >= 1 << 20 {
        return Err(invalid_location());
    }
    // Btrfs может выдавать st_dev подтома. Для BPF нужен s_dev из mountinfo.
    Ok((major << 20) | minor)
}

fn number(bytes: &[u8]) -> io::Result<u64> {
    if !bytes.iter().all(u8::is_ascii_digit) {
        return Err(invalid_location());
    }
    std::str::from_utf8(bytes)
        .map_err(|_| invalid_location())?
        .parse()
        .map_err(|_| invalid_location())
}

fn decode_path(source: &[u8]) -> io::Result<PathBuf> {
    let mut bytes = Vec::with_capacity(source.len());
    let mut cursor = 0;
    while cursor < source.len() {
        let byte = source[cursor];
        if byte == b'\\' {
            let escaped = source
                .get(cursor + 1..cursor + 4)
                .ok_or_else(invalid_location)?;
            if !escaped.iter().all(|byte| matches!(byte, b'0'..=b'7')) || escaped[0] > b'3' {
                return Err(invalid_location());
            }
            bytes.push(
                ((escaped[0] - b'0') << 6) | ((escaped[1] - b'0') << 3) | (escaped[2] - b'0'),
            );
            cursor += 4;
        } else {
            bytes.push(byte);
            cursor += 1;
        }
    }
    if !bytes.starts_with(b"/") || bytes.contains(&0) {
        return Err(invalid_location());
    }
    if bytes
        .split(|byte| *byte == b'/')
        .any(|part| matches!(part, b"." | b".."))
    {
        return Err(invalid_location());
    }
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

pub(super) fn invalid_location() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Не удалось подтвердить физический путь приложения",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn roots_subvolumes_and_file_binds_keep_the_kernel_device_and_path() {
        for (root, point, file, physical) in [
            ("/", "/", "/usr/bin/app", "/usr/bin/app"),
            ("/arch", "/", "/usr/bin/app", "/arch/usr/bin/app"),
            ("/usr/bin", "/alias", "/alias/app", "/usr/bin/app"),
            ("/usr/bin/app", "/bound", "/bound", "/usr/bin/app"),
        ] {
            let bytes =
                format!("42 1 0:27 {root} {point} rw shared:3 - btrfs /dev/mapper/root rw\n");
            let mounts = parse(bytes.as_bytes()).unwrap();
            let mount = &mounts[&42];
            assert_eq!(mount.device, 27);
            assert_eq!(
                mount.filesystem_path(Path::new(file)).unwrap(),
                physical.as_bytes()
            );
            assert!(mount.filesystem_path(Path::new("/unrelated")).is_err() || point == "/");
        }
    }

    #[test]
    fn escaped_and_non_utf8_names_remain_raw_path_bytes() {
        assert_eq!(
            decode_path(b"/raw\\040name\\011\\012\\134\xff")
                .unwrap()
                .as_os_str()
                .as_bytes(),
            b"/raw name\t\n\\\xff"
        );
        assert_eq!(
            decode_path(b"/raw\\377").unwrap().as_os_str().as_bytes(),
            b"/raw\xff"
        );
        for path in [
            b"relative".as_slice(),
            b"/bad\\00",
            b"/bad\\400",
            b"/bad\\0x0",
            b"/bad\\000",
            b"/a/../b",
            b"/./b",
        ] {
            assert!(decode_path(path).is_err());
        }
    }

    #[test]
    fn malformed_or_ambiguous_tables_cannot_be_used_for_binding() {
        for table in [
            "",
            "0 1 0:2 / / rw - tmpfs none rw\n",
            "1 1 4096:2 / / rw - tmpfs none rw\n",
            "1 1 0:1048576 / / rw - tmpfs none rw\n",
            "1 1 0:2 / / rw tmpfs none rw\n",
            "1 1 0:2 / / rw - tmpfs none\n",
            "1 1 0:2 / / rw - tmpfs none rw\n1 1 0:2 / / rw - tmpfs none rw\n",
        ] {
            assert!(parse(table.as_bytes()).is_err());
        }
        let mounts = parse(b"1 1 12:3 / / rw - ext4 /dev/root rw\n").unwrap();
        assert_eq!(mounts[&1].device, (12 << 20) | 3);
        let path = format!("/{}", "a".repeat(4095));
        assert!(mounts[&1].filesystem_path(Path::new(&path)).is_err());
        let mounts = parse(b"1 1 0:4 net:[123] /run/netns/test rw - nsfs nsfs rw\n").unwrap();
        assert!(mounts[&1]
            .filesystem_path(Path::new("/run/netns/test"))
            .is_err());
    }
}
