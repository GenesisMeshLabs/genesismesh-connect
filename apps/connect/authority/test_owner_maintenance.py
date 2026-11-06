"""Automatic routine activation and explicit uncertainty recovery, real core."""
from contextlib import closing
from datetime import timedelta
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import requests
from test_embedded_owner import EmbeddedOwner, TestVault, core_time, required_core_version, Refused


class OwnerMaintenanceTests(unittest.TestCase):
    def test_expired_and_day_91_activation_renew_with_same_keys_and_no_root_decrypt(self):
        for offset in (timedelta(minutes=6), timedelta(days=90)):
            with self.subTest(offset=offset), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "owner"; vault = TestVault()
                owner = EmbeddedOwner(path, vault, required_core_version())
                try:
                    identity = owner.create("Routine membership")
                    protected = {name: (path / name).read_bytes() for name in ("root.sealed", "owner.sealed", "member.sealed")}
                    expires = owner.certificate.expires_at; owner.close()
                    with core_time(expires + offset), patch.object(vault, "open_root", side_effect=AssertionError("Routine activation must not decrypt root")):
                        renewed = owner.open_for_use()
                        self.assertNotEqual(renewed["certificate_id"], identity["certificate_id"])
                        self.assertEqual({k: v for k, v in renewed.items() if k != "certificate_id"}, {k: v for k, v in identity.items() if k != "certificate_id"})
                        self.assertTrue(owner.check_member())
                        owner.close()
                        self.assertEqual(owner.open_for_use(), renewed, "Healthy reopen reissued a credential")
                        self.assertEqual(vault.creations, 1)
                        self.assertFalse((path / "member-renewal.json").exists())
                        self.assertEqual({name: (path / name).read_bytes() for name in protected}, protected)
                finally: owner.close()

    def test_exact_one_hour_threshold_and_healthy_reopen(self):
        for remaining, changed in ((timedelta(hours=1, seconds=1), False), (timedelta(hours=1), True)):
            with self.subTest(remaining=remaining), tempfile.TemporaryDirectory() as directory:
                owner = EmbeddedOwner(Path(directory) / "owner", TestVault(), required_core_version())
                try:
                    identity = owner.create("Renewal threshold")
                    at = owner.certificate.expires_at - remaining; owner.close()
                    with core_time(at):
                        result = owner.open_for_use()
                        self.assertEqual(result["certificate_id"] != identity["certificate_id"], changed)
                        self.assertTrue(owner.check_member())
                finally: owner.close()

    def test_lost_reply_leaves_intent_and_reopen_never_replays_the_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "owner"; owner = EmbeddedOwner(path, TestVault(), required_core_version())
            try:
                identity = owner.create("Uncertain routine update")
                at = owner.certificate.expires_at + timedelta(minutes=6); owner.close()
                post = owner._post
                def lost(path, body, headers=None):
                    result = post(path, body, headers)
                    if path == "/join": raise requests.Timeout("Test-only lost reply")
                    return result
                with core_time(at):
                    with patch.object(owner, "_post", side_effect=lost):
                        with self.assertRaisesRegex(Refused, "could not be confirmed"):
                            owner.open_for_use()
                    self.assertTrue((path / "member-renewal.json").exists())
                    def count():
                        with closing(sqlite3.connect((path / "authority.db").as_uri() + "?mode=ro", uri=True)) as db:
                            return db.execute("SELECT COUNT(*) FROM issued_certs").fetchone()[0]
                    recorded = count()
                    self.assertEqual(recorded, 2)
                    with patch.object(owner, "_enroll_member", side_effect=AssertionError("Must not replay")):
                        with self.assertRaisesRegex(Refused, "previous membership update needs review"):
                            owner.open_for_use()
                        self.assertEqual(count(), recorded)
                        recovered = owner.reconcile_member()
                        self.assertNotEqual(recovered["certificate_id"], identity["certificate_id"])
                        self.assertEqual(count(), recorded)
                        self.assertTrue(owner.check_member())
            finally: owner.close()

    def test_revoked_member_is_not_automatically_reenrolled(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "owner"; owner = EmbeddedOwner(path, TestVault(), required_core_version())
            try:
                owner.create("Revocation stays final"); at = owner.certificate.expires_at + timedelta(minutes=6)
                owner._admin("/admin/revoke", {"cert_id": owner.certificate.cert_id, "reason": "key_compromise"})
                owner.close()
                with core_time(at), patch.object(owner, "_enroll_member", side_effect=AssertionError("Must not reenroll revoked membership")):
                    with self.assertRaises(Refused): owner.open_for_use()
                self.assertFalse((path / "member-renewal.json").exists())
            finally: owner.close()


if __name__ == "__main__": unittest.main()
