"""Disposable real-core fixtures; inspection itself is forbidden every write/network/root action."""
from contextlib import ExitStack, closing
from datetime import timedelta
import hashlib
import json
import sqlite3
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from genesis_mesh.crypto import sign_data
from test_embedded_owner import EmbeddedOwner, TestVault, required_core_version, core_time, Refused
from member_renewal import DOMAIN
from membership_inspection import inspect, certificate_digest
from state_storage import encode


class MembershipInspectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "authority"
        self.vault = TestVault()
        self.owner = EmbeddedOwner(self.path, self.vault, required_core_version())
        self.identity = self.owner.create("Read-only recovery fixture")
        self.operator = self.owner.keys["operator"]
        self.at = self.owner.certificate.expires_at + timedelta(minutes=6)
        self.owner.close()

    def tearDown(self):
        self.owner.close()
        self.temporary.cleanup()

    def pending(self, count=1, linked=False, keep_live=False, revoke=False):
        # SETUP ONLY: exercise the genuine core and existing renewal writer to
        # obtain a pending intent/issued certificate. Inspection never invokes it.
        with core_time(self.at):
            self.owner.open()
            enroll = self.owner._enroll_member
            certificates = []
            def interrupted():
                for _ in range(count): certificates.append(enroll())
                raise TimeoutError("Fixture-only lost outcome")
            with patch.object(self.owner, "_enroll_member", side_effect=interrupted):
                with self.assertRaises(TimeoutError): self.owner.renew_member()
            if revoke:
                self.owner._admin("/admin/revoke", {"cert_id": certificates[0].cert_id, "reason": "key_compromise"})
            if not keep_live: self.owner.close()
        if linked: self.link(certificates[0])
        return certificates

    def link(self, certificate, **change):
        # A fixture for a FUTURE signed exact-outcome reference. No production
        # schema-2 writer or recovery action is implemented by this slice.
        intent = json.loads((self.path / "member-renewal.json").read_bytes())
        intent.pop("signature")
        intent.update(schema=2, outcome={"certificate_id": certificate.cert_id,
                                       "certificate_sha256": certificate_digest(certificate)})
        intent.update(change)
        intent["signature"] = sign_data(DOMAIN + encode(intent), self.operator)
        (self.path / "member-renewal.json").write_bytes(encode(intent))

    def snapshot(self):
        if not self.path.exists(): return None
        return {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ino) for p in self.path.iterdir()}

    def inspect_readonly(self, at=None):
        before = self.snapshot()
        forbidden = ["create", "open", "open_for_use", "_open", "_start", "_admin", "_post", "_enroll_member",
                     "_commit_certificate", "renew_member", "reconcile_member", "cancel_member_recovery"]
        with ExitStack() as stack:
            stack.enter_context(core_time(at or self.at))
            for method in forbidden:
                mocked = stack.enter_context(patch.object(EmbeddedOwner, method, side_effect=AssertionError("Inspection action attempted")))
                stack.callback(mocked.assert_not_called)
            for method in ("create", "seal_root", "seal_owner", "seal_member", "open_root"):
                mocked = stack.enter_context(patch.object(self.vault, method, side_effect=AssertionError("Inspection custody write/root use")))
                stack.callback(mocked.assert_not_called)
            mocked = stack.enter_context(patch("requests.Session.request", side_effect=AssertionError("Inspection network request")))
            stack.callback(mocked.assert_not_called)
            result = inspect(self.path, self.vault, required_core_version())
        self.assertEqual(self.snapshot(), before, "Inspection changed files, inventory or modification times")
        self.assertLess(len(encode(result)), 4096)
        self.assertNotIn("private", json.dumps(result))
        return result

    def test_exact_signed_reference_matches_existing_real_core_outcome_without_adopting_it(self):
        certificate = self.pending(linked=True)[0]
        before_state = (self.path / "state.json").read_bytes()
        result = self.inspect_readonly()
        self.assertEqual(result["status"], "matching_recorded_outcome")
        self.assertEqual(result["outcome"]["certificate_id"], certificate.cert_id)
        self.assertEqual(result["binding"]["member_public_key"], self.identity["member_public_key"])
        self.assertEqual(result["binding"]["previous_certificate_id"], self.identity["certificate_id"])
        self.assertEqual(result["binding"]["operation"], json.loads((self.path / "member-renewal.json").read_bytes())["operation"])
        self.assertEqual((self.path / "state.json").read_bytes(), before_state)
        self.assertTrue((self.path / "member-renewal.json").exists())
        with self.assertRaises(Refused): self.owner.open_for_use()

    def test_no_recorded_issuance_is_only_an_observation_and_preserves_the_intent(self):
        self.pending(count=0)
        result = self.inspect_readonly()
        self.assertEqual(result["status"], "no_recorded_issuance_observed")
        self.assertIsNotNone(result["binding"])
        self.assertIsNone(result["outcome"])
        self.assertTrue((self.path / "member-renewal.json").exists())

    def test_unique_legacy_candidate_does_not_prove_operation_causality(self):
        self.pending()
        result = self.inspect_readonly()
        self.assertEqual(result["status"], "ambiguous_or_invalid_evidence")
        self.assertEqual(result["reason"], "legacy_intent_has_no_exact_outcome_link")
        self.assertIsNone(result["outcome"])

    def test_multiple_real_core_outcomes_are_ambiguous_even_with_a_reference(self):
        self.pending(count=2, linked=True)
        self.assertEqual(self.inspect_readonly()["reason"], "multiple_recorded_issuances")

    def test_changed_reference_or_unsigned_intent_cannot_confirm_an_outcome(self):
        certificate = self.pending(linked=True)[0]
        self.link(certificate, outcome={"certificate_id": certificate.cert_id, "certificate_sha256": "0" * 64})
        self.assertEqual(self.inspect_readonly()["reason"], "referenced_outcome_mismatch")
        value = json.loads((self.path / "member-renewal.json").read_bytes())
        value["operation"] = "00000000-0000-4000-8000-000000000000"
        (self.path / "member-renewal.json").write_bytes(encode(value))
        result = self.inspect_readonly()
        self.assertEqual(result["status"], "ambiguous_or_invalid_evidence")
        self.assertIsNone(result["binding"])

    def test_expired_recorded_outcome_is_observed_but_not_made_active(self):
        certificate = self.pending(linked=True)[0]
        result = self.inspect_readonly(certificate.expires_at + timedelta(days=1))
        self.assertEqual(result["status"], "matching_recorded_outcome")
        self.assertTrue(result["outcome"]["expired"])

    def test_future_recorded_outcome_is_ambiguous_even_inside_clock_tolerance(self):
        certificate = self.pending(linked=True)[0]
        result = self.inspect_readonly(certificate.issued_at - timedelta(seconds=1))
        self.assertEqual(result["reason"], "invalid_evidence")
        self.assertIsNone(result["outcome"])

    def test_foreign_signed_intent_and_missing_baseline_cannot_confirm(self):
        certificate = self.pending(linked=True)[0]
        self.link(certificate, instance="00000000-0000-4000-8000-000000000000")
        result = self.inspect_readonly()
        self.assertEqual(result["reason"], "invalid_evidence")
        self.assertIsNone(result["binding"])
        self.link(certificate, instance=self.identity["instance"],
                  baseline=sorted([self.identity["certificate_id"], "00000000-0000-4000-8000-000000000000"]))
        result = self.inspect_readonly()
        self.assertEqual(result["reason"], "invalid_evidence")
        self.assertIsNotNone(result["binding"])

    def test_database_metadata_and_certificate_signature_are_checked(self):
        certificate = self.pending(linked=True)[0]
        # SETUP ONLY: change the disposable offline database, never in inspection.
        with closing(sqlite3.connect(self.path / "authority.db")) as db, db:
            db.execute("UPDATE issued_certs SET status='unknown' WHERE cert_id=?", (certificate.cert_id,))
        self.assertEqual(self.inspect_readonly()["reason"], "invalid_evidence")
        value = certificate.model_dump(mode="json")
        value["network_name"] = "Untrusted fixture network"
        with closing(sqlite3.connect(self.path / "authority.db")) as db, db:
            db.execute("UPDATE issued_certs SET status='issued',cert_json=? WHERE cert_id=?",
                       (json.dumps(value), certificate.cert_id))
        self.assertEqual(self.inspect_readonly()["reason"], "invalid_evidence")

    def test_revoked_outcome_is_never_confirmed_as_recoverable(self):
        self.pending(linked=True, revoke=True)
        result = self.inspect_readonly()
        self.assertEqual(result["status"], "ambiguous_or_invalid_evidence")
        self.assertEqual(result["reason"], "recorded_membership_revoked")

    def test_wal_or_hot_journal_is_preserved_not_ignored_checkpointed_or_copied(self):
        self.pending(count=0)
        for name in ("authority.db-wal", "authority.db-journal"):
            path = self.path / name; path.write_bytes(b"unsettled fixture journal")
            self.assertEqual(self.inspect_readonly()["reason"], "database_requires_settlement")
            path.unlink()  # Disposable fixture teardown between cases, not an inspection action.

    def test_unknown_staging_is_preserved_and_not_adopted(self):
        self.pending(linked=True)
        path = self.path / ".state-abcdefgh"; path.write_bytes(b"untrusted retained evidence")
        result = self.inspect_readonly()
        self.assertEqual(result["status"], "ambiguous_or_invalid_evidence")
        self.assertIsNone(result["outcome"])

    def test_busy_owner_is_not_closed_or_reused_by_fresh_inspection(self):
        self.pending(count=0, keep_live=True)
        result = self.inspect_readonly()
        self.assertEqual(result["reason"], "profile_busy_or_unavailable")
        self.assertIsNotNone(self.owner.service)
        self.assertIsNotNone(self.owner.storage.lock)

    def test_missing_lock_or_absent_profile_does_not_create_any_state(self):
        self.pending(count=0)
        (self.path / ".authority-lock").unlink()
        self.assertEqual(self.inspect_readonly()["status"], "ambiguous_or_invalid_evidence")
        self.assertFalse((self.path / ".authority-lock").exists())
        absent = Path(self.temporary.name) / "does-not-exist"
        result = inspect(absent, self.vault, required_core_version())
        self.assertEqual(result["status"], "ambiguous_or_invalid_evidence")
        self.assertFalse(absent.exists())

    def test_no_pending_intent_is_a_readonly_status_not_an_activation(self):
        self.assertEqual(self.inspect_readonly()["status"], "no_pending_update")

    def test_native_inspection_path_leaves_the_poisoned_write_owner_and_activation_fences_unchanged(self):
        import sys
        sys.path.insert(0, str(Path(__file__).parents[1] / "native/android/python"))
        from android_connect_owner import inspect_membership, AndroidReadVault
        from connect_owner import ConnectOwner
        self.pending(count=0)
        actor = ConnectOwner(Path(self.temporary.name), self.vault)
        actor.uncertain = True
        vault = self.vault
        class NativeReads:
            def ready(self): vault.ready()
            def require_root_custody(self): vault.require_root_custody()
            def open_owner(self, instance, value): return bytearray(vault.open_owner(instance, value))
            def open_member(self, instance, value): return bytearray(vault.open_member(instance, value))
        before = self.snapshot()
        try:
            with core_time(self.at), patch("android_connect_owner.AndroidPublisher", side_effect=AssertionError("Must not prepare a writer")):
                result = json.loads(inspect_membership(Path(self.temporary.name), NativeReads()))["ok"]
            self.assertEqual(result["status"], "no_recorded_issuance_observed")
            self.assertTrue(actor.uncertain)
            with self.assertRaises(Refused): actor.request('{"op":"open"}')
            with self.assertRaises(Refused): self.owner.open_for_use()
            for name in ("create", "seal_owner", "seal_root", "open_root"):
                self.assertFalse(hasattr(AndroidReadVault(NativeReads()), name))
            self.assertEqual(self.snapshot(), before)
        finally: actor.close()

    def test_oversized_or_duplicate_intent_is_invalid_and_preserved(self):
        self.pending(count=0)
        path = self.path / "member-renewal.json"
        for value in (b" " * 65537, b'{"schema":1,"schema":1}'):
            path.write_bytes(value)
            result = self.inspect_readonly()
            self.assertEqual(result["status"], "ambiguous_or_invalid_evidence")
            self.assertIsNone(result["binding"])


if __name__ == "__main__": unittest.main()
