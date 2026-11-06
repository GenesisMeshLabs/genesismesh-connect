"""Focused real-core application adapter checks; no startup-failure suite."""
import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest
import uuid

from nacl.signing import SigningKey
from genesis_mesh.crypto.node_auth import sign_node_request, sign_executor_proof

sys.path.insert(0, str(Path(__file__).with_name("embedded")))
from connect_owner import ConnectOwner, decode_request, dispatch, exchange
from state_storage import Refused
from test_embedded_owner import TestVault


class Vault(TestVault):
    def has_custody(self):
        self.ready()
        return bool(self.keys)


class ConnectEmbeddedTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "connect"
        self.vault = Vault()
        self.owner = ConnectOwner(self.path, self.vault)

    def tearDown(self):
        self.owner.close()
        self.temporary.cleanup()

    def request(self, op, **fields):
        return self.owner.request(json.dumps({"op": op, **fields}))

    def reopen(self):
        self.owner.close()
        self.owner = ConnectOwner(self.path, self.vault)
        return self.request("open")

    def test_native_create_operations_and_reopen_preserve_identity_and_shares(self):
        self.assertFalse(self.request("status")["configured"])
        info = self.request("create", name="Phone-first network")
        identity = self.owner.embedded.identity.copy()
        capability = self.request("capabilities")
        self.assertEqual(capability["pin"], info["pin"])
        self.assertEqual(capability["transport"], "local_android_embedded")
        self.assertEqual(self.request("pairing_ready")["transport"], "local_android_embedded")
        host, peer = [base64.b64encode(bytes(SigningKey.generate().verify_key)).decode() for _ in range(2)]
        collection = str(uuid.uuid4())
        self.request("space_share", host=host, collection=collection, name="Home service", recipients=[peer], kind="web")
        settings = self.request("access_get", host=host, collection=collection)
        settings.update(max_bytes=8192, max_seconds=60)
        updated = self.request("access_update", host=host, collection=collection, settings=settings)
        self.assertEqual(updated["settings"]["version"], 2)
        self.assertEqual(self.reopen()["pin"], info["pin"])
        self.assertEqual(self.owner.embedded.identity, identity)
        self.assertEqual(self.request("space_list")[0]["collection"], collection)
        self.assertEqual(self.request("access_get", host=host, collection=collection)["max_bytes"], 8192)
        self.assertEqual(self.vault.creations, 1)

    def test_recovery_moves_the_network_and_its_spaces_to_another_device(self):
        info = self.request("create", name="Recovered phone network")
        identity = self.owner.embedded.identity.copy()
        host, peer = [base64.b64encode(bytes(SigningKey.generate().verify_key)).decode() for _ in range(2)]
        collection = str(uuid.uuid4())
        self.request("space_share", host=host, collection=collection, name="Photos", recipients=[peer])
        exported = self.request("recovery_export")
        self.assertEqual((exported["root"], exported["config"]), ("embedded", "state.json"))
        self.assertEqual(set(exported["keys"]), {"root", "na", "operator", "member"})
        staging = Path(exported["staging"])
        self.assertTrue((staging / "application" / "spaces.json").is_file())
        # Exporting changes nothing: the network keeps working here.
        self.assertEqual(self.request("space_list")[0]["collection"], collection)
        vault = Vault()
        replacement = ConnectOwner(Path(self.temporary.name) / "replacement", vault)
        try:
            restored = replacement.request(json.dumps({"op": "recovery_import", "staging": str(staging), "keys": exported["keys"]}))
            self.assertEqual(restored["pin"], info["pin"])
            self.assertEqual(replacement.embedded.identity, identity)
            self.assertEqual(json.loads(json.dumps(replacement.request(json.dumps({"op": "space_list"}))))[0]["collection"], collection)
            # A device that runs a network never takes another one.
            with self.assertRaises(Refused):
                replacement.request(json.dumps({"op": "recovery_import", "staging": str(staging), "keys": exported["keys"]}))
        finally:
            replacement.close()

    def test_real_core_host_invitation_enrollment_and_independent_revocation(self):
        self.request("create", name="Independent phone")
        node, executor = SigningKey.generate(), SigningKey.generate()
        public = base64.b64encode(bytes(node.verify_key)).decode()
        invite = self.request("invite", node=public, host=True)["invite"]
        body = {"node_public_key": public, "invite_token": invite, "validity_hours": 24,
                "executor_public_key": base64.b64encode(bytes(executor.verify_key)).decode(),
                "timestamp": datetime.now(timezone.utc).isoformat(), "nonce": str(uuid.uuid4())}
        embedded = self.owner.embedded
        joined = embedded.session.post(embedded.origin + "/join", json=sign_node_request(sign_executor_proof(body, executor), node), timeout=5)
        self.assertEqual(joined.status_code, 201, joined.text)
        certificate = joined.json()
        def heartbeat():
            return embedded.session.post(embedded.origin + "/heartbeat", json=sign_node_request({
                "cert_id": certificate["cert_id"], "node_public_key": public, "status": "connect-test",
                "timestamp": datetime.now(timezone.utc).isoformat(), "nonce": str(uuid.uuid4())}, node), timeout=5)
        self.assertEqual(heartbeat().status_code, 200)
        self.assertEqual(self.request("remove_device", node=public)["revoked"], 1)
        self.assertGreaterEqual(heartbeat().status_code, 400)
        self.assertTrue(embedded.check_member(), "Revoking the other device revoked local health membership")

    def test_strict_bounded_protocol_rejects_paths_keys_duplicates_and_nonobjects(self):
        for text in ['[]', '{"op":"open","op":"create"}', '{"op":NaN}', 'x' * 16385]:
            with self.assertRaises(Refused): decode_request(text)
        self.request("create", name="Private boundary")
        for op, fields in [("backup", {}), ("restore", {"keys": "do-not-reflect"}), ("attach", {"config": "/private/path"}), ("open", {"directory": "/elsewhere"})]:
            with self.assertRaises(Refused): dispatch(self.owner.operations, {"op": op, **fields})
        result = json.loads(exchange(self.owner, '{"op":"restore","keys":"do-not-reflect"}'))
        self.assertIn("error", result)
        self.assertNotIn("do-not-reflect", json.dumps(result))
        self.assertNotIn("/private", json.dumps(result))
        self.assertEqual(self.vault.creations, 1)

    def test_existing_custody_cannot_create_another_network(self):
        self.request("create", name="Preserved")
        identity = self.owner.embedded.identity.copy()
        self.reopen()
        with self.assertRaises(Refused): self.request("create", name="Replacement")
        self.assertEqual(self.owner.embedded.identity, identity)
        self.assertEqual(self.vault.creations, 1)

    def test_locked_custody_refuses_application_operations(self):
        self.request("create", name="Locked vault")
        self.vault.locked = True
        with self.assertRaises(Refused): self.request("invite", node="ignored", host=True)
        self.vault.locked = False
        self.assertEqual(self.request("space_list"), [])

    def test_changed_or_missing_registry_is_preserved_and_refused(self):
        self.request("create", name="Registry integrity")
        registry = self.path / "application" / "spaces.json"
        original = registry.read_bytes()
        data = json.loads(original); data["root"] = "foreign"
        registry.write_text(json.dumps(data))
        with self.assertRaises(Refused): self.request("space_list")
        self.assertEqual(json.loads(registry.read_bytes())["root"], "foreign")
        registry.write_bytes(original)
        self.reopen()
        registry.unlink()
        with self.assertRaises(FileNotFoundError): self.request("space_list")
        self.assertFalse(registry.exists())


if __name__ == "__main__": unittest.main()
