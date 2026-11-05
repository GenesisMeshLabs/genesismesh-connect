import importlib.util
import io
import struct
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("apk_alignment", Path(__file__).parents[1] / "check-android-apk.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(alignment=16384, relro_end=16384, load_end=32768):
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<HH", header, 54, 56, 2)
    load = struct.pack("<IIQQQQQQ", 1, 6, 0, 0, 0, 176, load_end, alignment)
    relro = struct.pack("<IIQQQQQQ", module.PT_GNU_RELRO, 4, 0, 0, 0, 176, relro_end, 1)
    return bytes(header) + load + relro


class AndroidAlignmentTests(unittest.TestCase):
    def test_the_real_device_4k_failure_is_refused(self):
        with self.assertRaisesRegex(ValueError, "LOAD segment"):
            module.check_elf(io.BytesIO(fixture(4096)), 176)

    def test_relro_must_not_seal_following_writable_data(self):
        with self.assertRaisesRegex(ValueError, "RELRO"):
            module.check_elf(io.BytesIO(fixture(relro_end=8192)), 176)
        self.assertEqual(module.check_elf(io.BytesIO(fixture(relro_end=8192, load_end=8192)), 176), 1)

    def test_16k_passes_and_truncated_headers_do_not(self):
        self.assertEqual(module.check_elf(io.BytesIO(fixture()), 176), 1)
        with self.assertRaises(ValueError):
            module.check_elf(io.BytesIO(fixture()[:80]), 176)


if __name__ == "__main__":
    unittest.main()
