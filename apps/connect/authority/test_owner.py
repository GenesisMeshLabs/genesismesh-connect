"""Real core operations with disposable owner state; no existing network used."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from owner import Owner, Refused
from protection import MAGIC
from genesis_mesh.crypto import generate_keypair


class OwnerTests(unittest.TestCase):
    def test_create_reopen_and_bound_invite_use_real_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/"owner"
            owner=Owner(root)
            try:
                info=owner.create("My home")
                self.assertEqual(info["pin"]["network_name"],"My home")
                original=info["pin"]
                for private in (root/"network"/"keys").glob("*.key"):
                    self.assertTrue(private.read_bytes().startswith(MAGIC))
                node=generate_keypair().public_key_b64
                invitation=owner.invite(node)
                self.assertTrue(invitation["invite"])
                host_invite=owner.invite(generate_keypair().public_key_b64,True)
                second_host_invite=owner.invite(generate_keypair().public_key_b64,True)
                self.assertTrue(host_invite["invite"])
                self.assertTrue(second_host_invite["invite"])
                self.assertNotIn("private",json.dumps(info).lower())
                with self.assertRaises(Refused): owner.create("Replace the root")
                with self.assertRaises(Refused): owner.invite("invalid")
            finally: owner.close()
            reopened=Owner(root)
            try:
                self.assertEqual(reopened.open()["pin"],original)
                self.assertTrue(reopened.invite(node)["invite"])
            finally: reopened.close()

    def test_sharing_policy_and_attestation_are_scoped_to_peer_and_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            owner=Owner(Path(directory)/"owner")
            try:
                owner.create("Scoped sharing")
                host,peer=(generate_keypair().public_key_b64 for _ in range(2))
                import uuid
                collection=str(uuid.uuid4())
                result=owner.share(host,peer,collection)
                self.assertEqual(result["collection_id"],collection)
                self.assertEqual(result["policy_id"],"connect-"+collection)
                self.assertTrue(result["attestation_id"])
                row=owner.service.db.get_boundary_policy_row(result["policy_id"],1)
                policy=owner.service.db.parse_boundary_policy_row(row)
                self.assertEqual(policy.selector.parameter_equals,{"request_parameters.collection_id":[collection]})
                second=str(uuid.uuid4())
                second_result=owner.share(host,peer,second)
                second_policy=owner.service.db.parse_boundary_policy_row(owner.service.db.get_boundary_policy_row(second_result["policy_id"],1))
                self.assertNotEqual(policy.selector.parameter_equals,second_policy.selector.parameter_equals)
                with self.assertRaises(ValueError): owner.share(host,peer,"../../escape")
            finally: owner.close()

    def test_nonempty_or_incomplete_network_is_never_reinitialized(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/"owner"; root.mkdir()
            marker=root/"keep.txt"; marker.write_text("original")
            owner=Owner(root)
            try:
                with self.assertRaises(Refused): owner.create("New root")
                self.assertEqual(marker.read_text(),"original")
            finally: owner.close()

    def test_tampered_owner_key_cannot_reopen_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/"owner"; owner=Owner(root)
            try: owner.create("Tamper refusal")
            finally: owner.close()
            private=root/"network"/"keys"/"na.key"
            content=bytearray(private.read_bytes()); content[-8]^=0x80; private.write_bytes(content)
            owner=Owner(root)
            try:
                with self.assertRaises(RuntimeError): owner.open()
            finally: owner.close()

    def test_backup_and_restore_move_the_same_network_to_another_computer(self):
        with tempfile.TemporaryDirectory() as directory:
            first=Path(directory)/"first"/"owner"
            owner=Owner(first)
            try:
                info=owner.create("Moving home")
                node=generate_keypair().public_key_b64
                owner.invite(node)
                staged=owner.backup()
                staging=Path(staged["staging"])
                self.assertEqual(staging.parent,first)
                # Owner keys travel only in the reply, never as files.
                self.assertFalse(list(staging.rglob("*.key")))
                self.assertTrue((staging/"network"/"na.db").is_file())
                self.assertTrue((staging/staged["config"]).is_file())
                self.assertEqual(sorted(Path(k).name for k in staged["keys"]),["na.key","operator.key","root.key"])
                # A second, empty computer: stage beside its owner directory.
                second=Path(directory)/"second"/"owner"; second.parent.mkdir()
                moved=second.parent/".restore-test"
                shutil.copytree(staging,moved)
                shutil.rmtree(staging)
            finally: owner.close()
            restored=Owner(second)
            try:
                result=restored.restore(str(moved),staged["root"],staged["config"],staged["keys"])
                self.assertEqual(result["pin"],info["pin"])
                for private in (second/"network"/"keys").glob("*.key"):
                    self.assertTrue(private.read_bytes().startswith(MAGIC))
                settings=(second/staged["config"]).read_text()
                self.assertNotIn(staged["root"],settings)
                self.assertIn(second.as_posix(),settings)
                # The restored authority keeps its history and its operator.
                self.assertTrue(restored.invite(node)["invite"])
                self.assertTrue(restored.service.db.conn.execute("select count(*) from invite_tokens").fetchone()[0]>=2)
            finally: restored.close()
            reopened=Owner(second)
            try: self.assertEqual(reopened.open()["pin"],info["pin"])
            finally: reopened.close()

    def test_restore_refuses_an_existing_network_and_escaping_names(self):
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/"source"/"owner"
            owner=Owner(source)
            try:
                owner.create("Refusals")
                staged=owner.backup()
            finally: owner.close()
            target=Path(directory)/"target"/"owner"; target.parent.mkdir()
            moved=target.parent/".restore-test"
            shutil.copytree(staged["staging"],moved)
            escaping={"../outside.key":next(iter(staged["keys"].values()))}
            with self.assertRaises(Refused): Owner(target).restore(str(moved),staged["root"],staged["config"],escaping)
            with self.assertRaises(Refused): Owner(target).restore(str(moved),staged["root"],"../settings.toml",staged["keys"])
            with self.assertRaises(Refused): Owner(target).restore(str(moved),"/elsewhere",staged["config"],staged["keys"])
            self.assertFalse((target/"owner.json").exists())
            elsewhere=Path(directory)/"elsewhere"; shutil.copytree(moved,elsewhere)
            with self.assertRaises(Refused): Owner(target).restore(str(elsewhere),staged["root"],staged["config"],staged["keys"])
            with self.assertRaises(Refused): Owner(source).restore(str(moved),staged["root"],staged["config"],staged["keys"])

if __name__=="__main__": unittest.main()
