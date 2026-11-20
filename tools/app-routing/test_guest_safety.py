"""Проверки отказа от изменения чужого каталога при сборке стенда."""

from pathlib import Path
import tempfile
import unittest

from make_guest import build


class GuestSafetyTests(unittest.TestCase):
    def test_foreign_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            existing = output / "keep.txt"
            existing.write_text("existing data")
            with self.assertRaises(ValueError):
                build(output, "7.2.15-arch1-1")
            self.assertEqual(existing.read_text(), "existing data")
            self.assertEqual(list(output.iterdir()), [existing])

    def test_invalid_kernel_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "new"
            with self.assertRaises(ValueError):
                build(output, "../../not-a-kernel")
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
