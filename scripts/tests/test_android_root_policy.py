"""Regression for Android KeyInfo's documented per-use sentinel, no device keys."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class RootPolicyTests(unittest.TestCase):
    def test_native_policy_accepts_documented_and_keystore2_per_use_values(self):
        root = Path(__file__).parents[2]
        with tempfile.TemporaryDirectory() as folder:
            subprocess.run(["javac", "--release", "8", "-d", folder,
                str(root / "apps/connect/native/android/src/main/java/org/genesismesh/connect/authority/RootKeyPolicy.java"),
                str(root / "spikes/android-authority/tests/RootKeyPolicyTest.java")], check=True, timeout=30)
            subprocess.run(["java", "-cp", folder, "org.genesismesh.connect.authority.RootKeyPolicyTest"], check=True, timeout=20)


if __name__ == "__main__": unittest.main()
