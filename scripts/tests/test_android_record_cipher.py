"""Host regression for per-use cipher ordering; does not qualify Android Keystore."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class RecordCipherTests(unittest.TestCase):
    def test_authentication_precedes_aad_and_payload_for_the_exact_cipher(self):
        root = Path(__file__).parents[2]
        with tempfile.TemporaryDirectory() as folder:
            subprocess.run(["javac", "--release", "8", "-d", folder,
                str(root / "apps/connect/native/android/src/main/java/org/genesismesh/connect/authority/ProtectedRecordCipher.java"),
                str(root / "spikes/android-authority/tests/ProtectedRecordCipherTest.java")], check=True, timeout=30)
            subprocess.run(["java", "-cp", folder, "org.genesismesh.connect.authority.ProtectedRecordCipherTest"], check=True, timeout=20)


if __name__ == "__main__": unittest.main()
