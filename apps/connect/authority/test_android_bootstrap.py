"""Real-core bootstrap host checks; test-only vault/publisher, not Android acceptance."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_embedded_owner import TestVault
sys.path.insert(0, str(Path(__file__).parents[1] / "native/android/python"))
from android_connect_owner import AndroidVault, begin, handshake, exchange


class NativeVault(TestVault):
    def hasCustody(self): self.ready(); return bool(self.keys)
    def open_owner(self, instance, data): return bytearray(super().open_owner(instance, data))
    def open_member(self, instance, data): return bytearray(super().open_member(instance, data))


class AndroidBootstrapTests(unittest.TestCase):
    def test_registration_handshake_does_not_activate_or_create_authority_keys(self):
        with tempfile.TemporaryDirectory() as directory, patch("android_connect_owner.AndroidPublisher", return_value=os.link):
            native = NativeVault(); owner = begin(Path(directory) / "native-selected", native)
            try:
                result = json.loads(handshake(owner))["ok"]
                self.assertTrue(result["native_only"])
                self.assertFalse(result["production_create_enabled"])
                self.assertIsNone(owner.embedded.service)
                self.assertEqual(native.creations, 0)
                self.assertFalse(owner.embedded.storage.directory.exists())
            finally: owner.close()

    def test_native_bootstrap_uses_existing_core_and_preserves_owned_identity(self):
        with tempfile.TemporaryDirectory() as directory, patch("android_connect_owner.AndroidPublisher", return_value=os.link):
            path = Path(directory) / "native-selected"; native = NativeVault()
            owner = begin(path, native)
            try:
                info = json.loads(exchange(owner, '{"op":"create","name":"Native bootstrap"}'))["ok"]
                identity = owner.embedded.identity.copy()
                self.assertTrue(owner.embedded.check_member())
                owner.close()
                owner = begin(path, native)
                self.assertEqual(json.loads(exchange(owner, '{"op":"open"}'))["ok"]["pin"], info["pin"])
                self.assertEqual(owner.embedded.identity, identity)
                self.assertEqual(native.creations, 1)
            finally: owner.close()

    def test_native_unwrap_clears_returned_buffer_after_copy(self):
        with patch("android_connect_owner.AndroidPublisher", return_value=os.link):
            vault = AndroidVault(object(), "/native-selected")
            buffer = bytearray(b"test fixture only")
            self.assertEqual(vault._open(lambda *_: buffer, "instance", b"fixture"), b"test fixture only")
            self.assertEqual(buffer, bytearray(len(buffer)))


if __name__ == "__main__": unittest.main()
