"""Root isolation over real core; host custody is explicitly test-only."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_embedded_owner import EmbeddedOwner, TestVault, required_core_version, Refused
from owner_adapter import public, seed


class RootVault(TestVault):
    def __init__(self):
        super().__init__()
        self.root_authorized = True
        self.root_seals = self.root_opens = 0

    def seal_root(self, instance, data):
        if not self.root_authorized: raise Refused("Test root authentication required")
        self.root_seals += 1
        return super().seal_root(instance, data)

    def open_root(self, instance, data):
        if not self.root_authorized: raise Refused("Test root authentication required")
        self.root_opens += 1
        return super().open_root(instance, data)


class OwnerRootTests(unittest.TestCase):
    def test_root_is_separate_and_ordinary_open_never_decrypts_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "owner"
            vault = RootVault()
            owner = EmbeddedOwner(path, vault, required_core_version())
            try:
                identity = owner.create("Separate root")
                self.assertEqual(set(owner.keys), {"na", "operator"})
                daily = json.loads(vault.open_owner(identity["instance"], (path / "owner.sealed").read_bytes()))
                self.assertEqual(set(daily["keys"]), {"na", "operator"})
                root = json.loads(vault.open_root(identity["instance"], (path / "root.sealed").read_bytes()))
                self.assertEqual(public(seed(root["seed"])), identity["root_public_key"])
                self.assertNotIn(root["seed"], json.dumps(daily))
                self.assertNotEqual(vault.keys["root"], vault.keys["owner"])
                self.assertEqual(vault.root_seals, 1)
                owner.close()
                before = vault.root_opens
                vault.root_authorized = False
                self.assertEqual(owner.open(), identity)
                self.assertTrue(owner.check_member())
                self.assertEqual(vault.root_opens, before)
                self.assertEqual(vault.root_seals, 1)
                self.assertEqual(vault.creations, 1)
            finally: owner.close()

    def test_root_ciphertext_cannot_be_opened_in_daily_custody_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            vault = RootVault(); owner = EmbeddedOwner(Path(directory) / "owner", vault, required_core_version())
            try:
                identity = owner.create("Purpose separation")
                sealed = owner.storage.read("root.sealed")
                for method in (vault.open_owner, vault.open_member):
                    with self.assertRaises(Exception): method(identity["instance"], sealed)
                vault.root_authorized = False
                with self.assertRaisesRegex(Refused, "authentication required"):
                    vault.open_root(identity["instance"], sealed)
            finally: owner.close()

    def test_missing_or_changed_root_record_never_gets_recreated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "owner"; vault = RootVault()
            owner = EmbeddedOwner(path, vault, required_core_version())
            try:
                identity = owner.create("Preserve root"); owner.close()
                root = path / "root.sealed"; original = root.read_bytes()
                for content in (None, b"changed root ciphertext"):
                    if content is None: root.unlink()
                    else: root.write_bytes(content)
                    with self.assertRaises(Exception): owner.open()
                    self.assertEqual(root.read_bytes() if root.exists() else None, content)
                    self.assertEqual((vault.creations, vault.root_seals, vault.root_opens), (1, 1, 0))
                    root.write_bytes(original)
                self.assertEqual(owner.open(), identity)
            finally: owner.close()

    def test_legacy_combined_profile_is_refused_before_decrypting_or_migrating(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "owner"; vault = RootVault()
            owner = EmbeddedOwner(path, vault, required_core_version())
            try:
                owner.create("Legacy refusal"); owner.close()
                state = json.loads((path / "state.json").read_bytes()); state["schema"] = 2
                (path / "state.json").write_text(json.dumps(state))
                before = {p.name: p.read_bytes() for p in path.iterdir()}
                with patch.object(vault, "open_owner", side_effect=AssertionError("Must not decrypt legacy root")):
                    with self.assertRaisesRegex(Refused, "explicit root-custody migration"):
                        owner.open()
                self.assertEqual({p.name: p.read_bytes() for p in path.iterdir()}, before)
            finally: owner.close()


if __name__ == "__main__": unittest.main()
