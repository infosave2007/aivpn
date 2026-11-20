#!/usr/bin/env python3
"""Проверяет build-inputs единого EXE без служебных программ и сценариев поставки."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC=importlib.util.spec_from_file_location('routing_package',Path(__file__).with_name('prepare-windows-routing.py'))
PACKAGE=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(PACKAGE)

class WindowsRoutingPackage(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='aivpn-windows-package-')
        self.addCleanup(self.temporary.cleanup);self.root=Path(self.temporary.name)
        self.driver=self.root/'input.sys';self.driver.write_bytes(b'MZ'+b'fixture driver')
    def test_reduced_package_does_not_require_a_driver_or_script(self):
        PACKAGE.prepare(self.root)
        self.assertEqual((self.root/'routing-bootstrap.nsh').read_text(),'!define ROUTING_ENABLED 0\n')
        self.assertFalse(list(self.root.glob('*.ps1')))
        self.assertFalse(list(self.root.glob('*.exe')))
        self.assertIsNone(json.loads((self.root/'.build-inputs/manifest.json').read_text())['driver_sha256'])
    def test_full_input_preserves_the_exact_driver_bytes_and_altitude(self):
        PACKAGE.prepare(self.root,self.driver,'385249.158')
        copied=self.root/'.build-inputs/routing-driver.sys'
        self.assertEqual(copied.read_bytes(),self.driver.read_bytes())
        manifest=json.loads((self.root/'.build-inputs/manifest.json').read_text())
        self.assertEqual(manifest['driver_sha256'],hashlib.sha256(self.driver.read_bytes()).hexdigest())
        self.assertEqual(manifest['altitude'],'385249.158')
        self.assertEqual((self.root/'routing-bootstrap.nsh').read_text(),'!define ROUTING_ENABLED 1\n')
        self.assertFalse(list(self.root.glob('*.ps1')))
    def test_partial_driver_configuration_is_refused(self):
        for driver,altitude in [(self.driver,None),(None,'385249.158')]:
            with self.subTest(driver=driver,altitude=altitude),self.assertRaises(ValueError):PACKAGE.prepare(self.root,driver,altitude)
    def test_unknown_altitude_and_link_are_refused(self):
        with self.assertRaises(ValueError):PACKAGE.prepare(self.root,self.driver,'385249;bad')
        alias=self.root/'alias.sys';alias.symlink_to(self.driver)
        with self.assertRaises(ValueError):PACKAGE.prepare(self.root,alias,'385249.158')
    def test_invalid_image_cannot_enable_installation(self):
        self.driver.write_bytes(b'not a PE image')
        with self.assertRaises(ValueError):PACKAGE.prepare(self.root,self.driver,'385249.158')
        self.assertFalse((self.root/'routing-bootstrap.nsh').exists())

if __name__=='__main__':unittest.main()
