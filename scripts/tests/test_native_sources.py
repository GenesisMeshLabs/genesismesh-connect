import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from packaging.requirements import Requirement

spec = importlib.util.spec_from_file_location("sources", Path(__file__).parents[1] / "android_authority_sources.py")
sources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sources)


class SourceTests(unittest.TestCase):
    def test_source_build_is_isolated_from_connect_cargo_workspace(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "Cargo.toml").write_text("[workspace]\nmembers=[]\n")
            with patch.object(sources, "verified_source") as fetch:
                with self.assertRaisesRegex(ValueError, "outside.*Cargo workspace"):
                    sources.prepare("pydantic-core", root / "native")
                fetch.assert_not_called()
    def test_ranges_urls_and_conditional_dependencies_cannot_replace_exact_pin(self):
        for text in ("example>=1", "example==1.*", "example @ https://example.com/pkg.whl", 'example==1; sys_platform=="linux"'):
            with self.assertRaises(ValueError):
                sources.exact(Requirement(text))
        self.assertEqual(sources.exact(Requirement("example==1.2.3")), "1.2.3")

    def test_archive_cannot_escape_its_new_output_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            archive = root / "source.tar.gz"
            with tarfile.open(archive, "w:gz") as stream:
                entry = tarfile.TarInfo("../outside")
                entry.size = 1
                stream.addfile(entry, io.BytesIO(b"x"))
            with self.assertRaises(tarfile.TarError):
                sources.unpack(archive, root / "extracted")
            self.assertFalse((root / "outside").exists())

    def test_changed_source_hash_and_changed_authority_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            lock = Path(folder) / "lock.json"
            document = {"schema": 1, "authority_pin_sha256": hashlib.sha256(b"genesis-mesh==1.0.0").hexdigest(),
                        "packages": {"pydantic-core": {"version": "1.0.0", "url": "https://files.pythonhosted.org/pkg.tar.gz", "sha256": "0"*64}}}
            lock.write_text(json.dumps(document))
            with patch.object(sources, "LOCK", lock), patch.object(sources, "versions", return_value={"pydantic-core": "1.0.0"}), patch.object(sources, "pin", return_value=Requirement("genesis-mesh==1.0.0")), patch.object(sources, "fetch", return_value=b"changed"):
                with self.assertRaisesRegex(ValueError, "hash mismatch"):
                    sources.verified_source("pydantic-core")
                document["authority_pin_sha256"] = "0"*64
                lock.write_text(json.dumps(document))
                with self.assertRaisesRegex(ValueError, "Authority release changed"):
                    sources.verified_source("pydantic-core")

    def test_host_wheel_and_forged_contents_cannot_pass_android_check(self):
        version = json.loads(sources.LOCK.read_text())["packages"]["pydantic-core"]["version"]
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with self.assertRaisesRegex(ValueError, "Android target"):
                sources.check_wheel(root / f"pydantic_core-{version}-cp313-cp313-manylinux_2_28_aarch64.whl")
            wheel = root / f"pydantic_core-{version}-cp313-cp313-android_24_arm64_v8a.whl"
            with zipfile.ZipFile(wheel, "w") as stream:
                stream.writestr("pydantic_core.dist-info/METADATA", "Name: another-package\nVersion: 1.0.0\n")
            with self.assertRaisesRegex(ValueError, "contents disagree"):
                sources.check_wheel(wheel)


if __name__ == "__main__":
    unittest.main()
