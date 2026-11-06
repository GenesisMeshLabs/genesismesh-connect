"""Host-only session guard regression; no devices, native keys or startup fault injection."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class OwnerBridgeTests(unittest.TestCase):
    def test_serial_native_session_refuses_replay_scope_changes_and_reactivation(self):
        root = Path(__file__).parents[2]
        with tempfile.TemporaryDirectory() as folder:
            subprocess.run(["javac", "--release", "8", "-d", folder,
                str(root / "apps/connect/native/android/src/main/java/org/genesismesh/connect/authority/OwnerSessionGuard.java"),
                str(root / "spikes/android-authority/tests/OwnerSessionGuardTest.java")], check=True, timeout=30)
            subprocess.run(["java", "-cp", folder, "org.genesismesh.connect.authority.OwnerSessionGuardTest"], check=True, timeout=20)


if __name__ == "__main__": unittest.main()
