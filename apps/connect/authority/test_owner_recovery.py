"""Recovery of a phone-run network onto another device, over real core.

Host custody here is explicitly test-only; the phone seals with Android Keystore.
"""
from pathlib import Path
import tempfile
import unittest

from test_embedded_owner import EmbeddedOwner, Refused, required_core_version
from test_owner_root import RootVault


class OwnerRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name)
        self.owners = []

    def tearDown(self):
        for owner in self.owners: owner.close()
        self.temporary.cleanup()

    def owner(self, name, vault):
        owner = EmbeddedOwner(self.path / name, vault, required_core_version())
        self.owners.append(owner)
        return owner

    def test_export_and_import_bring_the_same_network_to_another_device(self):
        old_vault, new_vault = RootVault(), RootVault()
        old, new = self.owner("old", old_vault), self.owner("new", new_vault)
        identity = old.create("Recovered network")
        opened = old_vault.root_opens
        keys = old.export_recovery(self.path / "staging")
        self.assertEqual(old_vault.root_opens, opened + 1)  # Export asks for the root key's authentication.
        self.assertEqual(sorted(p.name for p in (self.path / "staging").iterdir()),
                         ["authority.db", "genesis.json", "policy.json", "state.json"])
        old.close()
        self.assertEqual(new.import_recovery(self.path / "staging", keys), identity)
        # The same identity, sealed under the new device's own custody.
        self.assertNotEqual(new_vault.keys["root"], old_vault.keys["root"])
        self.assertNotEqual((self.path / "new" / "owner.sealed").read_bytes(),
                            (self.path / "old" / "owner.sealed").read_bytes())
        self.assertTrue(new.check_member())
        new.close()
        new_vault.root_authorized = False  # Reopening never needs the root key.
        self.assertEqual(new.open(), identity)

    def test_export_needs_the_root_keys_authentication(self):
        vault = RootVault()
        owner = self.owner("old", vault)
        owner.create("Protected export")
        vault.root_authorized = False
        with self.assertRaises(Refused):
            owner.export_recovery(self.path / "staging")
        self.assertFalse((self.path / "staging").exists())

    def test_import_refuses_another_networks_keys_and_an_existing_network(self):
        first, second = self.owner("first", RootVault()), self.owner("second", RootVault())
        first.create("First network"); second.create("Second network")
        first_keys = first.export_recovery(self.path / "first-staging")
        second_keys = second.export_recovery(self.path / "second-staging")
        vault = RootVault()
        target = self.owner("target", vault)
        with self.assertRaises(Refused):
            target.import_recovery(self.path / "first-staging", second_keys)
        self.assertEqual({p.name for p in (self.path / "target").iterdir()}, {".authority-lock"})
        self.assertFalse(vault.has_custody())
        # A device that already runs a network keeps it.
        second.close()
        existing = self.owner("second", RootVault())
        with self.assertRaises(Refused):
            existing.import_recovery(self.path / "first-staging", first_keys)


if __name__ == "__main__":
    unittest.main()
