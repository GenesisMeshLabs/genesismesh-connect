from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class EngineLifecycleTests(unittest.TestCase):
    def test_delayed_old_run_cannot_publish_after_relaunch(self):
        self.assertIsNotNone(shutil.which("javac"), "JDK required for the lifecycle regression")
        root = Path(__file__).parents[2] / "spikes/android-authority"
        with tempfile.TemporaryDirectory() as folder:
            subprocess.run(["javac", "--release", "8", "-d", folder,
                            str(root / "src/main/java/org/genesismesh/connect/authoritycheck/EngineCheckRunner.java"),
                            str(root / "tests/EngineCheckRunnerTest.java")], check=True, timeout=30)
            subprocess.run(["java", "-cp", folder,
                            "org.genesismesh.connect.authoritycheck.EngineCheckRunnerTest"], check=True, timeout=20)


if __name__ == "__main__":
    unittest.main()
