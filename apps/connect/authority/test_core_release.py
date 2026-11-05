"""Packaging must never accept an unbounded or ambiguous authority dependency."""
import tempfile
import unittest
from pathlib import Path

from core_release import required_core_version, require_installed_core_version


class CoreReleaseTests(unittest.TestCase):
    def test_qualification_cannot_use_an_installed_core_different_from_the_pin(self):
        self.assertEqual(require_installed_core_version(required_core_version()), required_core_version())
        with self.assertRaisesRegex(ValueError, "Choose an isolated matching environment"):
            require_installed_core_version("0.0.0")

    def test_exact_pin_with_comments(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requirements.txt"
            path.write_text("# Release pin\n\ngenesis-mesh==2.3.4\n", encoding="utf-8")
            self.assertEqual(required_core_version(path), "2.3.4")

    def test_ranges_extra_dependencies_and_install_options_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requirements.txt"
            for invalid in ("genesis-mesh>=1.0.0", "genesis-mesh==1.0.0\nrequests",
                            "--index-url https://example.com", "genesis-mesh==1.0.0rc1", ""):
                with self.subTest(invalid=invalid):
                    path.write_text(invalid, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        required_core_version(path)


if __name__ == "__main__":
    unittest.main()
