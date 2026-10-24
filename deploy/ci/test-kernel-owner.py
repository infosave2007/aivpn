#!/usr/bin/env python3
"""Проверяет настоящий участок конструктора до регистрации miscdevice без загрузки модуля."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class KernelOwnerTest(unittest.TestCase):
    def test_constructor_rejects_unpinned_callbacks_before_registration(self):
        source = (ROOT / "platforms/linux-kernel/src/dev.rs").read_text()
        start = source.index("pub(crate) fn new()")
        body_start = source.index("{", start) + 1
        # Здесь начинается публикация устройства через pin initializer. До нее
        # исполняется настоящий production-код; остальной kernel API не нужен.
        prefix = source[body_start:source.index("KBox::pin_init(", body_start)]
        harness = r'''
#![allow(dead_code, unused_variables)]
use std::cell::Cell;
type Result<T> = std::result::Result<T, i32>;
const ENODEV: i32 = -19;
macro_rules! pr_err { ($($arg:tt)*) => { eprint!($($arg)*) }; }
#[macro_export]
macro_rules! c_str { ($name:literal) => { $name }; }
mod kernel { pub use crate::c_str; }

// Только граница kernel API: into_raw возвращает immutable static fops.
struct FileOperations { owner: *mut () }
unsafe impl Sync for FileOperations {}
static UNOWNED: FileOperations = FileOperations { owner: std::ptr::null_mut() };
static MODULE_ID: u8 = 0;
static OWNED: FileOperations = FileOperations { owner: &MODULE_ID as *const u8 as *mut () };
thread_local! {
    static API: Cell<u8> = const { Cell::new(0) };
    static REGISTRATIONS: Cell<usize> = const { Cell::new(0) };
}
struct RawMiscDevice { fops: *const FileOperations }
struct MiscDeviceOptions { name: &'static str }
impl MiscDeviceOptions {
    fn into_raw<T>(&self) -> RawMiscDevice {
        let fops = API.with(|api| match api.get() {
            0 => std::ptr::null(),
            1 => &UNOWNED,
            _ => &OWNED,
        });
        RawMiscDevice { fops }
    }
}
struct AivpnDev;
impl AivpnDev {
    fn new() -> Result<()> {
CONSTRUCTOR_PREFIX
        REGISTRATIONS.with(|n| n.set(n.get() + 1));
        Ok(())
    }
}

#[test]
fn null_fops_never_reaches_registration() {
    API.with(|api| api.set(0));
    assert_eq!(AivpnDev::new(), Err(ENODEV));
    REGISTRATIONS.with(|n| assert_eq!(n.get(), 0));
}
#[test]
fn old_api_without_module_owner_never_reaches_registration() {
    API.with(|api| api.set(1));
    assert_eq!(AivpnDev::new(), Err(ENODEV));
    REGISTRATIONS.with(|n| assert_eq!(n.get(), 0));
}
#[test]
fn owner_correct_api_reaches_registration_once() {
    API.with(|api| api.set(2));
    assert_eq!(AivpnDev::new(), Ok(()));
    REGISTRATIONS.with(|n| assert_eq!(n.get(), 1));
}
'''.replace("CONSTRUCTOR_PREFIX", prefix)
        with tempfile.TemporaryDirectory(prefix="aivpn-owner-test-") as tmp:
            src = Path(tmp) / "owner.rs"
            binary = Path(tmp) / "owner-test"
            src.write_text(harness)
            subprocess.run(["rustc", "--edition=2021", "--test", str(src), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)

    def test_make_rejects_headers_without_rust(self):
        with tempfile.TemporaryDirectory(prefix="aivpn-kernel-config-") as tmp:
            tree = Path(tmp)
            (tree / "Makefile").touch()
            (tree / "include/config").mkdir(parents=True)
            (tree / "include/config/auto.conf").write_text("# CONFIG_RUST is not set\n")
            result = subprocess.run(["make", "-s", "-C", str(ROOT / "platforms/linux-kernel"),
                                     f"KDIR={tree}", "KVER=7.2.11", "_check_kver"],
                                    capture_output=True, text=True, env=os.environ | {"LC_ALL": "C"})
            self.assertNotEqual(result.returncode, 0, "Номер ядра не заменяет доступность Rust API")

    def test_make_checks_headers_instead_of_assuming_a_version_range(self):
        with tempfile.TemporaryDirectory(prefix="aivpn-kernel-config-") as tmp:
            tree = Path(tmp)
            (tree / "Makefile").touch()
            (tree / "include/config").mkdir(parents=True)
            (tree / "include/config/auto.conf").write_text("CONFIG_RUST=y\n")
            # Номер не доказывает owner fix: его проверит именно constructor.
            result = subprocess.run(["make", "-s", "-C", str(ROOT / "platforms/linux-kernel"),
                                     f"KDIR={tree}", "KVER=6.0-backport", "_check_kver"],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_make_rejects_missing_header_tree(self):
        with tempfile.TemporaryDirectory(prefix="aivpn-kernel-config-") as tmp:
            result = subprocess.run(["make", "-s", "-C", str(ROOT / "platforms/linux-kernel"),
                                     f"KDIR={tmp}/missing", "KVER=99.0", "_check_kver"],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
