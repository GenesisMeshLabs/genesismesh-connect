"""Real-core lifecycle/refusal tests with a test-only encrypted vault.

This vault deliberately has no Android qualification claim and is not packaged.
"""
import hashlib
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).with_name("embedded")))
from owner_adapter import EmbeddedOwner, Refused
from core_release import required_core_version


class TestVault:
    def __init__(self): self.keys = {}; self.locked = False; self.creations = 0
    def ready(self):
        if self.locked: raise Refused("Test vault locked")
    def create(self):
        self.ready()
        if self.keys: raise Refused("Existing vault keys")
        self.creations += 1
        self.keys = {name: AESGCM.generate_key(bit_length=256) for name in ("owner", "member")}
    def seal(self, role, instance, data):
        self.ready(); nonce = os.urandom(12)
        return nonce + AESGCM(self.keys[role]).encrypt(nonce, data, (role + instance).encode())
    def open(self, role, instance, data):
        self.ready()
        return AESGCM(self.keys[role]).decrypt(data[:12], data[12:], (role + instance).encode())
    def seal_owner(self, instance, data): return self.seal("owner", instance, data)
    def seal_member(self, instance, data): return self.seal("member", instance, data)
    def open_owner(self, instance, data): return self.open("owner", instance, data)
    def open_member(self, instance, data): return self.open("member", instance, data)


class EmbeddedOwnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "owner"
        self.vault = TestVault()
        self.owners = []

    def tearDown(self):
        for owner in self.owners: owner.close()
        self.temporary.cleanup()

    def owner(self, vault=None):
        owner = EmbeddedOwner(self.root, vault or self.vault, required_core_version())
        self.owners.append(owner)
        return owner

    def created(self):
        owner = self.owner(); identity = owner.create("Phone-local test")
        owner.close()
        return identity

    def snapshot(self):
        return {p.name: p.read_bytes() for p in self.root.iterdir() if p.is_file() and not p.is_symlink()}

    def test_real_create_close_reopen_preserves_all_identities_and_member(self):
        owner = self.owner(); identity = owner.create("My phone network")
        private = [bytes(k) for k in [*owner.keys.values(), owner.member]]
        self.assertTrue(owner.check_member())
        self.assertEqual(owner.service.boundary_policy_enforcement, "required")
        owner.close()
        self.assertEqual(self.owner().open(), identity)
        self.assertTrue(self.owners[-1].check_member())
        self.owners[-1].close()
        for value in self.snapshot().values():
            for secret in private:
                self.assertNotIn(secret, value)
                import base64
                self.assertNotIn(base64.b64encode(secret), value)
        self.assertEqual(self.vault.creations, 1)

    def test_existing_creator_and_concurrent_owner_are_refused_without_replacing(self):
        first = self.owner(); identity = first.create("Original")
        with self.assertRaises(Refused): first.create("Replace")
        with self.assertRaises(Refused): self.owner().open()
        self.assertTrue(first.check_member())
        first.close()
        with self.assertRaises(Refused): self.owner().create("Replace")
        self.assertEqual(self.owner().open(), identity)
        self.assertEqual(self.vault.creations, 1)

    def test_missing_and_corrupt_state_or_database_never_regenerates(self):
        identity = self.created(); original = self.snapshot()
        for name in ("state.json", "owner.sealed", "member.sealed", "authority.db"):
            for content in (None, b"corrupt"):
                with self.subTest(name=name, corrupt=content is not None):
                    path = self.root / name
                    if content is None: path.unlink()
                    else: path.write_bytes(content)
                    before = self.snapshot()
                    with self.assertRaises(Exception): self.owner().open()
                    self.assertEqual(self.snapshot(), before)
                    self.assertEqual(self.vault.creations, 1)
                    path.write_bytes(original[name])
        self.assertEqual(self.owner().open(), identity)

    def test_locked_missing_or_wrong_vault_key_preserves_ciphertext(self):
        identity = self.created(); original = self.snapshot(); keys = dict(self.vault.keys)
        self.vault.locked = True
        with self.assertRaises(Refused): self.owner().open()
        self.vault.locked = False
        for role in ("owner", "member"):
            for value in (None, AESGCM.generate_key(bit_length=256)):
                self.vault.keys = dict(keys)
                if value is None: del self.vault.keys[role]
                else: self.vault.keys[role] = value
                with self.assertRaises(Exception): self.owner().open()
                self.assertEqual(self.snapshot(), original)
                self.assertEqual(self.vault.creations, 1)
        self.vault.keys = keys
        self.assertEqual(self.owner().open(), identity)

    def test_public_identity_and_domain_swaps_are_refused_even_with_updated_hashes(self):
        self.created(); original = self.snapshot()
        state_path = self.root / "state.json"
        for mode in ("identity", "domains", "instance"):
            with self.subTest(mode=mode):
                state = json.loads(original["state.json"])
                if mode == "identity": state["identity"]["network_name"] = "Other network"
                elif mode == "instance":
                    import uuid
                    state["identity"]["instance"] = str(uuid.uuid4())
                else:
                    for role, other in (("owner", "member"), ("member", "owner")):
                        (self.root / (role + ".sealed")).write_bytes(original[other + ".sealed"])
                        state[role + "_sha256"] = hashlib.sha256(original[other + ".sealed"]).hexdigest()
                state_path.write_text(json.dumps(state))
                before = self.snapshot()
                with self.assertRaises(Exception): self.owner().open()
                self.assertEqual(self.snapshot(), before)
                for name, content in original.items(): (self.root / name).write_bytes(content)

    def test_interrupted_creation_is_preserved_and_never_retried_as_new(self):
        for name in ("initializing.json", "owner.sealed", "member.sealed", "state.json"):
            with self.subTest(point=name), tempfile.TemporaryDirectory() as parent:
                root = Path(parent) / "owner"; vault = TestVault()
                owner = EmbeddedOwner(root, vault, required_core_version())
                write = owner.storage.write_new
                def interrupted(filename, value):
                    write(filename, value)
                    if filename == name: raise OSError("Injected interrupted create")
                with patch.object(owner.storage, "write_new", side_effect=interrupted):
                    with self.assertRaises(OSError): owner.create("Interrupted")
                before = {p.name: p.read_bytes() for p in root.iterdir()}
                next_owner = EmbeddedOwner(root, vault, required_core_version())
                with self.assertRaises(Exception): next_owner.open()
                with self.assertRaises(Refused): next_owner.create("Replacement")
                next_owner.close()
                self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()}, before)
                self.assertLessEqual(vault.creations, 1)

    def test_missing_or_revoked_database_member_refused_before_core_start(self):
        self.created(); original = (self.root / "authority.db").read_bytes()
        for sql in ("DELETE FROM issued_certs", "UPDATE issued_certs SET status='revoked'"):
            with closing(sqlite3.connect(self.root / "authority.db")) as db:
                db.execute(sql)
                db.commit()
            before = (self.root / "authority.db").read_bytes()
            with patch("owner_adapter.NetworkAuthorityService", side_effect=AssertionError("Must not start")):
                with self.assertRaises(Refused): self.owner().open()
            self.assertEqual((self.root / "authority.db").read_bytes(), before)
            (self.root / "authority.db").write_bytes(original)

    def test_symlink_cannot_redirect_state(self):
        self.created()
        path = self.root / "owner.sealed"; original = path.read_bytes()
        target = Path(self.temporary.name) / "outside"
        target.write_bytes(original); path.unlink()
        try: path.symlink_to(target)
        except OSError as error: self.skipTest("Symlink creation unavailable: " + type(error).__name__)
        with self.assertRaises(Refused): self.owner().open()
        self.assertEqual(target.read_bytes(), original)

    def test_release_mismatch_fails_before_creating_state(self):
        with self.assertRaises(Refused): EmbeddedOwner(self.root, self.vault, "not-the-core-pin")
        self.assertFalse(self.root.exists())

    def test_invalid_name_is_refused_before_native_key_creation(self):
        for name in ("", " ", "x" * 81, "hidden\u0085control", None):
            with self.assertRaises(Refused): self.owner().create(name)
        self.assertFalse(self.root.exists())
        self.assertEqual(self.vault.creations, 0)

    def test_partial_native_key_creation_preserves_the_entry_and_reservation(self):
        owner = self.owner()
        def partial():
            self.vault.creations += 1
            self.vault.keys["owner"] = AESGCM.generate_key(bit_length=256)
            raise OSError("Injected second key failure")
        with patch.object(self.vault, "create", side_effect=partial):
            with self.assertRaises(OSError): owner.create("Interrupted native custody")
        before = self.snapshot(); keys = dict(self.vault.keys)
        with self.assertRaises(Refused): self.owner().create("Replacement")
        with self.assertRaises(Refused): self.owner().open()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.vault.keys, keys)

    def test_erased_profile_cannot_replace_existing_keystore_identity(self):
        self.created(); keys = dict(self.vault.keys)
        for path in self.root.iterdir(): path.unlink()
        self.root.rmdir()
        with self.assertRaises(Refused): self.owner().open()
        self.assertFalse(self.root.exists())
        with self.assertRaises(Refused): self.owner().create("Replacement")
        self.assertEqual(self.vault.keys, keys)
        self.assertEqual(self.vault.creations, 1)


if __name__ == "__main__": unittest.main()
