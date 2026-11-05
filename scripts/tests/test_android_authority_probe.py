import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("probe", Path(__file__).parents[1] / "probe-android-authority.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ProbeTests(unittest.TestCase):
    def test_only_single_exact_core_pin_is_accepted(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "pin.txt"
            for value in ("genesis-mesh>=1.0", "genesis-mesh==1.0.0\ncryptography==1", "--extra-index-url https://example.com"):
                path.write_text(value, encoding="utf-8")
                with self.assertRaises(ValueError):
                    probe.core_pin(path)
            path.write_text("# single source\ngenesis-mesh==1.0.0\n", encoding="utf-8")
            self.assertEqual(probe.core_pin(path), "genesis-mesh==1.0.0")

    def test_resolver_never_builds_sources_installs_or_changes_pins(self):
        args = probe.command("genesis-mesh==1.0.0", Path("wheels"))
        self.assertIn("download", args)
        self.assertIn("--only-binary=:all:", args)
        self.assertNotIn("--no-deps", args)
        self.assertNotIn("install", args)
        self.assertEqual(args[-1], "genesis-mesh==1.0.0")
        self.assertIn("android_24_arm64_v8a", args)
        self.assertNotIn("manylinux", " ".join(args))

    def test_partial_failure_is_not_available_and_stale_outputs_are_refused(self):
        def failed(args, **kwargs):
            (Path(args[args.index("--dest")+1]) / "partial.whl").write_bytes(b"partial")
            return subprocess.CompletedProcess(args, 1)
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "probe"
            report = probe.probe(output, runner=failed)
            self.assertEqual(report["status"], "unavailable")
            self.assertFalse(report["hosting_accepted"])
            self.assertEqual(len(report["wheels"][0]["sha256"]), 64)
            with self.assertRaises(FileExistsError):
                probe.probe(output, runner=failed)

    def test_timeout_and_empty_success_are_unconfirmed(self):
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired("pip", 900)
        with tempfile.TemporaryDirectory() as folder:
            for name, runner in (("timeout", timeout), ("empty", lambda args, **kwargs: subprocess.CompletedProcess(args, 0))):
                report = probe.probe(Path(folder) / name, runner=runner)
                self.assertEqual(report["status"], "unconfirmed")
                self.assertFalse(report["hosting_accepted"])


if __name__ == "__main__":
    unittest.main()
