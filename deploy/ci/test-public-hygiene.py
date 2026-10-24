#!/usr/bin/env python3
"""Проверяет узкое исключение домена и сохранение границы публичного дерева."""

import importlib.util
import contextlib
import io
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("hygiene", Path(__file__).with_name("ci-public-hygiene.py"))
HYGIENE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HYGIENE)


class PublicHygieneTests(unittest.TestCase):
    @staticmethod
    def forbidden_token():
        source = (ROOT / "crates/aivpn-common/src/mask_io.rs").read_text()
        domain = next(item for item in re.findall(r'"([a-z0-9.-]+\.[a-z]+)"', source)
                      if HYGIENE.digest(item) in HYGIENE.PUBLIC_WIRE_HOSTS)
        return next(match.group(0) for match in HYGIENE.TOKEN.finditer(domain)
                    if HYGIENE.digest(match.group(0)) in HYGIENE.FORBIDDEN)

    def check_tree(self, files):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "--quiet", directory], check=True)
            for name, content in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content if isinstance(content, bytes) else content.encode())
            output = io.StringIO()
            with mock.patch.object(HYGIENE, "REPO_ROOT", root), contextlib.redirect_stdout(output):
                status = HYGIENE.main()
            return status, output.getvalue()

    def test_untracked_source_content_is_checked(self):
        status, output = self.check_tree({"src/new.rs": self.forbidden_token()})
        self.assertEqual(status, 1)
        self.assertIn("src/new.rs:1:", output)

    def test_forbidden_filename_is_checked_even_for_binary(self):
        status, output = self.check_tree({f"assets/{self.forbidden_token()}.bin": b"\0\xff"})
        self.assertEqual(status, 1)
        self.assertIn("служебный путь", output)

    def test_report_paths_are_rejected_at_any_depth(self):
        for name in ["CODE_REVIEW.md", "docs/code_review_sprint.md"]:
            with self.subTest(name=name):
                self.assertEqual(self.check_tree({name: "Проверка"})[0], 1)

    def test_ignored_local_reports_stay_outside_the_public_tree(self):
        self.assertEqual(self.check_tree({".gitignore": "local/\n", "local/CODE_REVIEW.md": self.forbidden_token()})[0], 0)

    def test_lockfiles_and_binary_payloads_are_skipped(self):
        self.assertEqual(self.check_tree({"Cargo.lock": self.forbidden_token(), "image.bin": b"\0\xff", "src/main.rs": "fn main() {}"})[0], 0)

    def test_only_the_exact_wire_domain_in_protocol_code_is_allowed(self):
        path = "crates/aivpn-common/src/mask_io.rs"
        source = (ROOT / path).read_text()
        domains = [item for item in re.findall(r'"([a-z0-9.-]+\.[a-z]+)"', source)
                   if HYGIENE.digest(item) in HYGIENE.PUBLIC_WIRE_HOSTS]
        self.assertTrue(domains)
        for domain in domains:
            original = HYGIENE.line_violations("README.md", f'"{domain}"')
            self.assertTrue(original)
            self.assertEqual(HYGIENE.line_violations(path, f'"{domain}"'), [])
            self.assertEqual(HYGIENE.line_violations(path, domain), original)
            self.assertEqual(HYGIENE.line_violations(path, f'"{domain}.example"'), original)
            self.assertEqual(HYGIENE.line_violations(path, f'"prefix.{domain}"'), original)
            self.assertEqual(HYGIENE.line_violations(path, f'"{domain.split(".")[0]}"'), original)


if __name__ == "__main__":
    unittest.main()
