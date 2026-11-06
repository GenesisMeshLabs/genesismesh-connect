"""Focused publication/selection checks; no authority startup-failure tests."""
import errno
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

EMBEDDED = Path(__file__).with_name("embedded")
sys.path.insert(0, str(EMBEDDED))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "spikes/android-authority/src/main/python"))
from android_storage import AndroidPublisher, check_publication
from state_storage import StateStorage, Refused
from owner_check import initial_operation


class StorageTests(unittest.TestCase):
    def test_existing_desktop_publication_and_collision_preserve_original(self):
        with tempfile.TemporaryDirectory() as root:
            storage = StateStorage(root); storage.acquire()
            try:
                storage.write_new("initializing.json", b"original")
                with self.assertRaises(FileExistsError): storage.write_new("initializing.json", b"replacement")
                self.assertEqual(storage.read("initializing.json"), b"original")
                self.assertEqual({p.name for p in Path(root).iterdir()}, {".authority-lock", "initializing.json"})
            finally: storage.release()

    def test_publisher_error_never_falls_back_to_link_or_overwrite(self):
        with tempfile.TemporaryDirectory() as root:
            def refused(*_): raise PermissionError(errno.EPERM, "publication refused")
            storage = StateStorage(root, publish_new=refused); storage.acquire()
            try:
                with patch("os.link", side_effect=AssertionError("Unsafe fallback")):
                    with self.assertRaises(PermissionError): storage.write_new("initializing.json", b"public probe")
                self.assertFalse((Path(root) / "initializing.json").exists())
            finally: storage.release()

    def test_explicit_initial_creation_only_for_empty_preinitialization_and_absent_aliases(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "profile"
            self.assertEqual(initial_operation(path, False), "create")
            self.assertEqual(initial_operation(path, True), "reopen")
            path.mkdir(); (path / ".authority-lock").write_bytes(b"")
            self.assertEqual(initial_operation(path, False), "create")
            self.assertEqual(initial_operation(path, True), "reopen")
            for name in ["initializing.json", "state.json", "owner.sealed", "member.sealed", ".state-abcdefgh", "unknown"]:
                file = path / name; file.write_bytes(b"preserve")
                for custody in [False, True]: self.assertEqual(initial_operation(path, custody), "reopen")
                self.assertEqual(file.read_bytes(), b"preserve"); file.unlink()

    @unittest.skipUnless(sys.platform.startswith("linux"), "Actual Linux renameat2 ABI check")
    def test_real_no_replace_rename_preserves_collision_and_rejects_foreign_paths(self):
        # Same ABI/flags on host glibc; Android's Bionic path is verified on-device.
        import cffi
        original = cffi.FFI.dlopen
        def libc(ffi, name, *args, **kwargs):
            return original(ffi, "libc.so.6" if name == "libc.so" else name, *args, **kwargs)
        with patch.object(cffi.FFI, "dlopen", libc), tempfile.TemporaryDirectory() as root:
            check_publication(root)
            publisher = AndroidPublisher(root)
            source = Path(root) / ".state-abcdefgh"; source.write_bytes(b"new")
            with self.assertRaises(Refused): publisher(source, Path(root).parent / "state.json")
            with self.assertRaises(Refused): publisher(source, Path(root) / "not-an-authority-file")
            self.assertEqual(source.read_bytes(), b"new")
            (Path(root) / "state.json").symlink_to(Path(root) / "initializing.json")
            with self.assertRaises(FileExistsError): publisher(source, Path(root) / "state.json")
            self.assertEqual((Path(root) / "initializing.json").read_bytes(), b'{"probe":"original"}')

    def test_missing_native_symbol_is_refused(self):
        import cffi
        with tempfile.TemporaryDirectory() as root, patch.object(cffi.FFI, "dlopen", return_value=object()):
            with self.assertRaises(Refused): AndroidPublisher(root)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Actual Linux renameat2 ABI check")
    def test_real_core_owner_uses_injected_no_replace_publication_across_reopen(self):
        import cffi
        from test_embedded_owner import TestVault
        from owner_adapter import EmbeddedOwner
        from core_release import required_core_version
        original = cffi.FFI.dlopen
        def libc(ffi, name, *args, **kwargs):
            return original(ffi, "libc.so.6" if name == "libc.so" else name, *args, **kwargs)
        with patch.object(cffi.FFI, "dlopen", libc), tempfile.TemporaryDirectory() as root:
            path = Path(root) / "authority"
            vault = TestVault(); vault.publish_new = AndroidPublisher(path)
            owner = EmbeddedOwner(path, vault, required_core_version())
            try:
                identity = owner.create("Atomic publisher qualification")
                self.assertTrue(owner.check_member())
                owner.close()
                self.assertEqual(owner.open(), identity)
                self.assertTrue(owner.check_member())
                self.assertEqual(vault.creations, 1)
            finally: owner.close()


if __name__ == "__main__": unittest.main()
