//! Проверка доступа к данным ядра до установки защиты путей приложений.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};

const MAX_SYMBOL_BYTES: u64 = 64 * 1024 * 1024;

pub(super) fn require_path_sequence() -> io::Result<()> {
    verify_path_sequence(File::open("/proc/kallsyms")?)
}

const ADMISSION_FUNCTIONS: [&std::ffi::CStr; 4] = [
    c"nf_hook_slow",
    c"bpf_rbtree_root",
    c"bpf_rbtree_left",
    c"bpf_rbtree_right",
];

unsafe extern "C" {
    fn btf__load_vmlinux_btf() -> *mut std::ffi::c_void;
    fn btf__find_by_name_kind(
        btf: *const std::ffi::c_void,
        name: *const std::ffi::c_char,
        kind: u32,
    ) -> i32;
    fn btf__free(btf: *mut std::ffi::c_void);
    fn libbpf_get_error(pointer: *const std::ffi::c_void) -> std::ffi::c_long;
}

pub(super) fn require_snapshot_admission() -> io::Result<()> {
    let btf = unsafe { btf__load_vmlinux_btf() };
    if btf.is_null() || unsafe { libbpf_get_error(btf) } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Недоступен BTF ядра для проверки snapshot admission",
        ));
    }
    let result = verify_admission_functions(|name| unsafe {
        btf__find_by_name_kind(btf, name.as_ptr(), 12) > 0
    });
    unsafe { btf__free(btf) };
    result
}

fn verify_admission_functions(
    mut available: impl FnMut(&std::ffi::CStr) -> bool,
) -> io::Result<()> {
    for name in ADMISSION_FUNCTIONS {
        if !available(name) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "Ядро не предоставляет {} для snapshot admission",
                    name.to_string_lossy()
                ),
            ));
        }
    }
    Ok(())
}

fn verify_path_sequence(source: impl Read) -> io::Result<()> {
    let mut found = false;
    let mut bytes = 0u64;
    for line in BufReader::new(source.take(MAX_SYMBOL_BYTES + 1)).split(b'\n') {
        let line = line?;
        bytes += line.len() as u64 + 1;
        if bytes > MAX_SYMBOL_BYTES || line.len() > 65536 {
            return Err(unavailable());
        }
        if path_symbol(&line)? {
            if found {
                return Err(unavailable());
            }
            found = true;
        }
    }
    if !found {
        return Err(unavailable());
    }
    Ok(())
}

fn path_symbol(line: &[u8]) -> io::Result<bool> {
    let mut fields = line
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty());
    let address = fields.next().unwrap_or_default();
    let kind = fields.next().unwrap_or_default();
    if fields.next() != Some(b"rename_lock") {
        return Ok(false);
    }
    // Некоторые сборки ядра помечают данные как T и в kallsyms, и в System.map.
    // Раскладка полей задается CO-RE, а не буквенным обозначением.
    if kind.len() != 1 || !kind[0].is_ascii_alphabetic() || fields.next().is_some() {
        return Err(unavailable());
    }
    let address = std::str::from_utf8(address).map_err(|_| unavailable())?;
    if u64::from_str_radix(address, 16)
        .ok()
        .filter(|address| *address != 0)
        .is_none()
    {
        return Err(unavailable());
    }
    Ok(true)
}

fn unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "Ядро не предоставляет доступ к проверке путей приложений",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_admission_requires_every_traversal_function() {
        verify_admission_functions(|_| true).unwrap();
        for missing in ADMISSION_FUNCTIONS {
            let error = verify_admission_functions(|name| name != missing).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert!(error.to_string().contains(missing.to_str().unwrap()));
        }
    }

    #[test]
    fn only_an_unambiguous_nonzero_kernel_symbol_allows_path_support() {
        for source in [
            "1 D rename_lock\n",
            "1 T rename_lock\n",
            "0 T unrelated\n0000000000000001 B rename_lock\n0 d different\n",
        ] {
            verify_path_sequence(source.as_bytes()).unwrap();
        }
        for source in [
            "",
            "0 D rename_lock\n",
            "1 ?? rename_lock\n",
            "invalid D rename_lock\n",
            "1 D rename_lock [module]\n",
            "1 D rename_lock\n2 D rename_lock\n",
        ] {
            assert!(verify_path_sequence(source.as_bytes()).is_err());
        }
    }

    #[test]
    fn symbol_read_errors_are_not_reported_as_supported() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }
        assert_eq!(
            verify_path_sequence(Broken).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
