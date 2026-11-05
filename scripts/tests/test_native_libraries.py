import importlib.util
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("native", Path(__file__).parents[1] / "android_authority_native.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class NativeTests(unittest.TestCase):
    def test_host_environment_cannot_start_target_library_build(self):
        runner = Mock()
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "cross environment"):
                native.prepare_sodium(Path("unused"), runner)
        runner.assert_not_called()

    def test_host_python_sdk_is_refused_before_configure(self):
        runner = Mock()
        with tempfile.TemporaryDirectory() as folder:
            lib = Path(folder) / "lib"
            lib.mkdir()
            header = bytearray(20)
            header[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", header, 18, 62)  # x86_64, not Android arm64
            (lib / "libpython3.13.so").write_bytes(header)
            with patch.dict(os.environ, {"CIBW_HOST_TRIPLET": "aarch64-linux-android", "ANDROID_API_LEVEL": "24", "PYO3_CROSS_LIB_DIR": str(lib)}, clear=True):
                with self.assertRaisesRegex(ValueError, "host or incompatible"):
                    native.prepare_sodium(Path(folder), runner)
        runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
