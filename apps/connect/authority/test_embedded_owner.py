"""Real-core lifecycle/refusal tests with a test-only encrypted vault.

This vault deliberately has no Android qualification claim and is not packaged.
"""
import hashlib
from contextlib import closing, contextmanager, ExitStack
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import socket
import time
import threading
import requests
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).with_name("embedded")))
from owner_adapter import EmbeddedOwner, Refused
from core_release import required_core_version


@contextmanager
def core_time(at):
    """Advance loaded adapter/core clocks in host tests only, never production code."""
    import member_renewal
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None): return at.astimezone(tz) if tz else at.replace(tzinfo=None)
    with ExitStack() as stack:
        for name, module in list(sys.modules.items()):
            if (name in ("owner_adapter", "member_renewal") or name.startswith("genesis_mesh.")) and getattr(module, "datetime", None) is datetime:
                stack.enter_context(patch.object(module, "datetime", Clock))
        yield


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

    def test_incomplete_loopback_request_cannot_stall_shutdown(self):
        owner = self.owner(); identity = owner.create("Bounded shutdown")
        server = owner.server
        with socket.create_connection(("127.0.0.1", server.server_port), timeout=2) as client:
            client.sendall(b"POST /heartbeat HTTP/1.1\r\nHost: localhost\r\nContent-Length: 512\r\n\r\n{")
            with server.condition:
                self.assertTrue(server.condition.wait_for(lambda: bool(server.active), timeout=2))
            started = time.monotonic()
            owner.close()
            self.assertLess(time.monotonic() - started, 2)
            self.assertFalse(server.active)
            self.assertIsNone(owner.keys)
            self.assertIsNone(owner.storage.lock)
        self.assertEqual(self.owner().open(), identity)

    def test_unsettled_handler_retains_keys_and_exclusive_state_until_it_finishes(self):
        owner = self.owner(); identity = owner.create("Settling handler")
        entered, release = threading.Event(), threading.Event()
        server = owner.server
        view = owner.service.app.view_functions["na_public.get_policy"]
        def delayed():
            entered.set()
            if not release.wait(5): raise RuntimeError("Test handler timed out")
            owner.service.db.add_audit_event("test_handler_settled", {"ok": True})
            return view()
        owner.service.app.view_functions["na_public.get_policy"] = delayed
        def request():
            try: requests.get(owner.origin + "/policy", timeout=5)
            except requests.RequestException: pass  # Socket is deliberately closed during shutdown.
        client = threading.Thread(target=request); client.start()
        try:
            self.assertTrue(entered.wait(2))
            with patch("local_server.SHUTDOWN_SECONDS", 0.15):
                started = time.monotonic()
                with self.assertRaisesRegex(Refused, "still settling"): owner.close()
                self.assertLess(time.monotonic() - started, 1)
            self.assertIsNotNone(owner.keys)
            self.assertIsNotNone(owner.storage.lock)
            with self.assertRaises(Refused): self.owner().open()
        finally:
            release.set(); client.join(3)
        with server.condition:
            self.assertTrue(server.condition.wait_for(lambda: not server.active, timeout=3))
        owner.close()
        self.assertIsNone(owner.keys)
        self.assertIsNone(owner.storage.lock)
        self.assertEqual(self.owner().open(), identity)

    def test_every_private_identity_is_durable_before_core_can_publish_it(self):
        import owner_adapter
        real_service = owner_adapter.NetworkAuthorityService
        observed = []
        owner = self.owner()
        def construct(*args, **kwargs):
            instance = json.loads((self.root / "initializing.json").read_bytes())["instance"]
            saved = json.loads(self.vault.open_owner(instance, (self.root / "owner.sealed").read_bytes()))
            member = json.loads(self.vault.open_member(instance, (self.root / "member.sealed").read_bytes()))
            for name, private in owner.keys.items():
                self.assertEqual(owner_adapter.public(owner_adapter.seed(saved["keys"][name])), owner_adapter.public(private))
            self.assertEqual(owner_adapter.public(owner_adapter.seed(member["seed"])), owner_adapter.public(owner.member))
            self.assertFalse((self.root / "authority.db").exists())
            observed.append(True)
            return real_service(*args, **kwargs)
        with patch("owner_adapter.NetworkAuthorityService", side_effect=construct):
            owner.create("Durable before use")
        self.assertEqual(observed, [True])

    def test_owner_reopens_across_member_expiry_without_authorizing_expired_membership(self):
        owner = self.owner(); identity = owner.create("Expiry boundaries")
        expires = owner.certificate.expires_at; owner.close()
        for offset, status in ((timedelta(seconds=-1), "active"), (timedelta(), "renewal_required"),
                               (timedelta(minutes=5, seconds=1), "renewal_required"), (timedelta(days=5), "renewal_required")):
            with self.subTest(offset=offset), core_time(expires + offset):
                self.assertEqual(owner.open(), identity)
                self.assertEqual(owner.member_status(), status)
                if status == "active": self.assertTrue(owner.check_member())
                else:
                    with self.assertRaisesRegex(Refused, "Renew the member"): owner.check_member()
                owner.close()

    def test_explicit_owner_recovery_uses_core_and_preserves_every_identity_key(self):
        owner = self.owner(); identity = owner.create("Explicit member recovery")
        expires = owner.certificate.expires_at; owner.close()
        with core_time(expires + timedelta(minutes=6)):
            self.assertEqual(owner.open(), identity)
            before = {name: (self.root / name).read_bytes() for name in ("owner.sealed", "member.sealed")}
            renewed = owner.renew_member()
            self.assertNotEqual(renewed["certificate_id"], identity["certificate_id"])
            self.assertEqual({k:v for k,v in renewed.items() if k != "certificate_id"}, {k:v for k,v in identity.items() if k != "certificate_id"})
            self.assertEqual({name: (self.root / name).read_bytes() for name in before}, before)
            self.assertTrue(owner.check_member())
            from genesis_mesh.crypto.node_auth import sign_node_request
            import uuid
            old = sign_node_request({"cert_id":identity["certificate_id"], "node_public_key":identity["member_public_key"],
                "timestamp":(expires + timedelta(minutes=6)).isoformat(),
                "nonce":str(uuid.uuid4())}, owner.member)
            response = owner.session.post(owner.origin + "/heartbeat", json=old, timeout=3)
            self.assertEqual(response.status_code, 403)
            self.assertEqual(response.json()["error"]["code"], "certificate_expired")
            owner.close()
            self.assertEqual(owner.open(), renewed)
            self.assertTrue(owner.check_member())

    def _uncertain_member_recovery(self, failure):
        owner = self.owner(); identity = owner.create("Uncertain member recovery")
        expires = owner.certificate.expires_at; owner.close()
        with core_time(expires + timedelta(minutes=6)):
            owner.open(); before = (self.root / "state.json").read_bytes()
            if failure == "commit": target, method = owner.storage, "replace_state"
            else: target, method = owner, "_enroll_member"
            original = getattr(target, method)
            def uncertain(*args, **kwargs):
                if failure == "reply": original(*args, **kwargs)
                raise OSError("Injected uncertain local outcome")
            with patch.object(target, method, side_effect=uncertain):
                with self.assertRaises(OSError): owner.renew_member()
            self.assertEqual((self.root / "state.json").read_bytes(), before)
            count = len(owner.service.db.get_certs_by_node_key(identity["member_public_key"]))
            self.assertEqual(count, 2)
            with self.assertRaisesRegex(Refused, "must not be replayed"): owner.renew_member()
            self.assertEqual(len(owner.service.db.get_certs_by_node_key(identity["member_public_key"])), count)
            owner.close()
            with self.assertRaises(Refused): self.owner().open()
            recovered = self.owner()
            with patch.object(recovered, "_enroll_member", side_effect=AssertionError("No write replay")):
                renewed = recovered.reconcile_member()
            self.assertEqual({k:v for k,v in renewed.items() if k != "certificate_id"}, {k:v for k,v in identity.items() if k != "certificate_id"})
            self.assertNotEqual(renewed["certificate_id"], identity["certificate_id"])
            self.assertEqual(len(recovered.service.db.get_certs_by_node_key(identity["member_public_key"])), count)
            self.assertTrue(recovered.check_member())
            self.assertFalse((self.root / "member-renewal.json").exists())

    def test_lost_join_reply_reconciles_the_core_outcome_without_issuing_again(self):
        self._uncertain_member_recovery("reply")

    def test_failed_state_commit_reconciles_the_core_outcome_without_issuing_again(self):
        self._uncertain_member_recovery("commit")

    def test_current_member_is_not_reissued_and_revoked_member_cannot_be_recovered(self):
        owner = self.owner(); identity = owner.create("No unnecessary reissue")
        with self.assertRaisesRegex(Refused, "does not need renewal"): owner.renew_member()
        self.assertFalse((self.root / "member-renewal.json").exists())
        expires = owner.certificate.expires_at
        with core_time(expires + timedelta(minutes=6)):
            with owner.service.db.conn:
                owner.service.db.conn.execute("UPDATE issued_certs SET status='revoked' WHERE cert_id=?", (identity["certificate_id"],))
            with self.assertRaisesRegex(Refused, "revoked member"): owner.renew_member()
            self.assertFalse((self.root / "member-renewal.json").exists())

    def test_expired_uncertain_outcome_is_recovered_without_granting_expired_access(self):
        owner = self.owner(); identity = owner.create("Delayed reconciliation")
        expires = owner.certificate.expires_at; owner.close()
        with core_time(expires + timedelta(minutes=6)):
            owner.open()
            enroll = owner._enroll_member
            def lost(): enroll(); raise OSError("Lost reply")
            with patch.object(owner, "_enroll_member", side_effect=lost):
                with self.assertRaises(OSError): owner.renew_member()
            owner.close()
        with core_time(expires + timedelta(days=3)):
            recovered = self.owner()
            with patch.object(recovered, "_enroll_member", side_effect=AssertionError("No automatic reissue")):
                recovered.reconcile_member()
            self.assertEqual(recovered.member_status(), "renewal_required")
            with self.assertRaises(Refused): recovered.check_member()
            fresh = recovered.renew_member()
            self.assertTrue(recovered.check_member())
            self.assertEqual(fresh["member_public_key"], identity["member_public_key"])
            self.assertEqual(fresh["root_public_key"], identity["root_public_key"])

    def test_unperformed_recovery_requires_explicit_cancellation_before_retry(self):
        owner = self.owner(); identity = owner.create("No replay after no outcome")
        expires = owner.certificate.expires_at; owner.close()
        with core_time(expires + timedelta(minutes=6)):
            owner.open()
            with patch.object(owner, "_enroll_member", side_effect=OSError("Before core write")):
                with self.assertRaises(OSError): owner.renew_member()
            owner.close()
            recovered = self.owner()
            with patch.object(recovered, "_enroll_member", side_effect=AssertionError("No replay")):
                with self.assertRaisesRegex(Refused, "not repeated"): recovered.reconcile_member()
            self.assertTrue((self.root / "member-renewal.json").exists())
            self.assertEqual(recovered.cancel_member_recovery(), {"status":"cancelled", "identity":identity})
            self.assertEqual(recovered.member_status(), "renewal_required")
            fresh = recovered.renew_member()
            self.assertEqual(fresh["member_public_key"], identity["member_public_key"])
            self.assertTrue(recovered.check_member())

    def test_completed_outcome_cannot_be_discarded_or_unsigned_intent_replayed(self):
        owner = self.owner(); owner.create("Authenticated recovery intent")
        expires = owner.certificate.expires_at; owner.close()
        with core_time(expires + timedelta(minutes=6)):
            owner.open()
            with patch.object(owner.storage, "replace_state", side_effect=OSError("Commit lost")):
                with self.assertRaises(OSError): owner.renew_member()
            owner.close()
            with self.assertRaisesRegex(Refused, "Core recorded"): self.owner().cancel_member_recovery()
            intent_path = self.root / "member-renewal.json"
            original = intent_path.read_bytes(); intent = json.loads(original)
            intent["operation"] = "tampered"; intent_path.write_text(json.dumps(intent))
            with self.assertRaisesRegex(Refused, "intent is invalid"): self.owner().reconcile_member()
            self.assertTrue(intent_path.exists())
            intent_path.write_bytes(original)
            self.assertTrue(self.owner().reconcile_member())


if __name__ == "__main__": unittest.main()
