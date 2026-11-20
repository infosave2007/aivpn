use super::*;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;

#[test]
fn unix_socket_paths_preserve_bytes_and_reject_truncation_or_nuls() {
    for bytes in [
        b"/run/aivpn/control.sock".to_vec(),
        b"/socket-\xff".to_vec(),
    ] {
        let path = std::path::PathBuf::from(OsString::from_vec(bytes.clone()));
        let (address, length) = socket_address(&path).unwrap();
        assert_eq!(address.sun_family, libc::AF_UNIX as libc::sa_family_t);
        assert_eq!(
            address.sun_path[..bytes.len()]
                .iter()
                .map(|byte| *byte as u8)
                .collect::<Vec<_>>(),
            bytes
        );
        assert_eq!(address.sun_path[bytes.len()], 0);
        assert_eq!(
            length as usize,
            std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1
        );
    }
    let capacity = unsafe { std::mem::zeroed::<libc::sockaddr_un>() }
        .sun_path
        .len();
    for bytes in [
        b"relative.sock".to_vec(),
        b"/bad\0.sock".to_vec(),
        vec![b'/'; capacity],
        vec![],
    ] {
        let path = std::path::PathBuf::from(OsString::from_vec(bytes));
        assert_eq!(
            socket_address(&path).err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
    }
    socket_address(Path::new(&"/".repeat(capacity - 1))).unwrap();
}

#[test]
fn mapped_root_must_not_be_confused_with_the_initial_user_namespace() {
    for bytes in [
        b"0 1000 1\n".as_slice(),
        b"",
        b"0 0 1\n",
        b"0 0 4294967295\n1 1 1\n",
        b"0 0 4294967296\n",
    ] {
        assert!(!initial_mapping(bytes), "{bytes:?}");
    }
    assert!(initial_mapping(b"         0          0 4294967295\n"));
}

#[test]
fn a_mapping_read_error_or_oversized_file_cannot_authorize_the_endpoint() {
    struct Failed;
    impl Read for Failed {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
    }
    assert_eq!(
        check_mapping(Failed).err().unwrap().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        check_mapping(&[b' '; 129][..]).err().unwrap().kind(),
        io::ErrorKind::Unsupported
    );
    assert_eq!(
        check_mapping(&b"0 0 1\n"[..]).err().unwrap().kind(),
        io::ErrorKind::Unsupported
    );
    check_mapping(&b"0 0 4294967295\n"[..]).unwrap();
    let mut boundary = b"0 0 4294967295\n".to_vec();
    boundary.resize(128, b' ');
    check_mapping(boundary.as_slice()).unwrap();
    boundary.push(b' ');
    assert_eq!(
        check_mapping(boundary.as_slice()).err().unwrap().kind(),
        io::ErrorKind::Unsupported
    );
}
