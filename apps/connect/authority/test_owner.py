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

    def test_spaces_name_exact_devices_change_only_by_their_host_and_stop_cleanly(self):
        import uuid
        from datetime import datetime, timedelta, timezone
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/"owner"
            owner=Owner(root)
            try:
                owner.create("Spaces")
                host,phone,tablet,other=(generate_keypair().public_key_b64 for _ in range(4))
                collection=str(uuid.uuid4())
                entry=owner.space_share(host,collection,"  Photos ",[phone])
                self.assertEqual((entry["name"],entry["host"],entry["recipients"]),("Photos",host,[phone]))
                self.assertEqual(entry["subject"],owner.subject(host))
                self.assertEqual((entry["policy_id"],entry["policy_version"]),("connect-"+collection,1))
                def active(policy_id):
                    return [p for p in owner.service.db.load_active_boundary_policies().policies if p.policy_id==policy_id]
                def peers(policy):
                    return next(g.config["values"] for g in policy.gates if g.gate_id=="peer")
                self.assertEqual([peers(p) for p in active(entry["policy_id"])],[[phone]])
                # Its host changes the devices: a new version replaces the old.
                changed=owner.space_share(host,collection,"Photos",[tablet,phone,phone])
                self.assertEqual(changed["policy_version"],2)
                self.assertEqual(changed["created_at"],entry["created_at"])
                self.assertEqual([(p.version,peers(p)) for p in active(entry["policy_id"])],[(2,sorted([phone,tablet]))])
                self.assertEqual(len(owner.space_list()),1)
                # Nobody else changes or removes it, and nobody shares with itself.
                with self.assertRaises(Refused): owner.space_share(other,collection,"Mine now",[phone])
                with self.assertRaises(Refused): owner.space_remove(other,collection)
                with self.assertRaises(Refused): owner.space_share(host,str(uuid.uuid4()),"Self",[host])
                with self.assertRaises(Refused): owner.space_share(host,str(uuid.uuid4()),"Nobody",[])
                with self.assertRaises(Refused): owner.space_share(host,str(uuid.uuid4()),"x"*65,[phone])
                with self.assertRaises(Refused): owner.space_share(host,str(uuid.uuid4()),"Bad",["not a key"])
                with self.assertRaises(Refused): owner.space_share(host,str(uuid.uuid4()),"Wrong subject",[phone],"someone-else")
                with self.assertRaises(ValueError): owner.space_share(host,"../escape","Escape",[phone])
                # Devices refuse every control character in a name; so does this.
                for bad in ("Tab\tname","Delete\x7f","C1\x85"):
                    with self.assertRaises(Refused,msg=repr(bad)): owner.space_share(host,str(uuid.uuid4()),bad,[phone])
                # A folder shared before Spaces has a policy but no entry: no
                # device can claim it, only this computer can adopt it.
                legacy=str(uuid.uuid4())
                owner.share(host,phone,legacy,owner.subject(host))
                with self.assertRaises(Refused): owner.space_share(other,legacy,"Taken",[phone])
                with self.assertRaises(Refused): owner.space_share(host,legacy,"Taken",[phone])
                adopted=owner.space_share(host,legacy,"Old folder",[phone,tablet],owner.subject(host),adopt=True)
                self.assertEqual((adopted["policy_version"],adopted["recipients"]),(2,sorted([phone,tablet])))
                self.assertTrue(owner.space_remove(host,legacy))
                self.assertEqual(active("connect-"+legacy),[])
                # Renewal re-grants Spaces close to their end, with a new attestation.
                spaces=owner.space_list()
                spaces[0]["valid_until"]=(datetime.now(timezone.utc)+timedelta(days=2)).isoformat()
                owner._save_spaces(spaces)
                # A renewal that fails for one Space keeps the others it made.
                broken=owner.space_share(host,str(uuid.uuid4()),"Broken",[phone])
                spaces=owner.space_list()
                for space in spaces:
                    space["valid_until"]=(datetime.now(timezone.utc)+timedelta(days=2)).isoformat()
                owner._save_spaces(spaces)
                grant=owner._grant
                def failing(host_node,subject,collection_id,*rest):
                    if collection_id==broken["collection"]: raise Refused("Simulated authority failure")
                    return grant(host_node,subject,collection_id,*rest)
                owner._grant=failing
                try: self.assertEqual(owner.space_renew(),[collection])
                finally: owner._grant=grant
                self.assertEqual(owner.space_renew(days=3),[broken["collection"]],"It is renewed on the next pass")
                self.assertTrue(owner.space_remove(host,broken["collection"]))
                renewed=next(s for s in owner.space_list() if s["collection"]==collection)
                self.assertEqual(renewed["policy_version"],3)
                self.assertNotEqual(renewed["attestation_id"],changed["attestation_id"])
                self.assertEqual(owner.space_renew(),[])
                # The registry is in the recovery file.
                staged=owner.backup()
                self.assertTrue((Path(staged["staging"])/"spaces.json").is_file())
                shutil.rmtree(staged["staging"])
                # Stopping deactivates the policy: no decision can allow it.
                self.assertTrue(owner.space_remove(host,collection))
                self.assertEqual(active(entry["policy_id"]),[])
                self.assertEqual(owner.space_list(),[])
                self.assertFalse(owner.space_remove(host,collection))
                # A device shares up to 16 folders.
                for index in range(16): owner.space_share(host,str(uuid.uuid4()),f"Folder {index}",[phone])
                with self.assertRaises(Refused): owner.space_share(host,str(uuid.uuid4()),"One more",[phone])
            finally: owner.close()

    def test_an_inbox_lets_its_devices_write_and_nothing_else(self):
        import uuid
        with tempfile.TemporaryDirectory() as directory:
            owner=Owner(Path(directory)/"owner")
            try:
                owner.create("Inboxes")
                host,phone=(generate_keypair().public_key_b64 for _ in range(2))
                collection=str(uuid.uuid4())
                inbox=owner.space_share(host,collection,"Inbox",[phone],kind="inbox")
                self.assertEqual(inbox["kind"],"inbox")
                policy=[p for p in owner.service.db.load_active_boundary_policies().policies if p.policy_id==inbox["policy_id"]][0]
                self.assertEqual(list(policy.selector.capabilities),["connect.inbox.write"])
                attestation=owner.service.db.get_membership_attestation(inbox["attestation_id"])["attestation"]
                self.assertEqual(attestation.claims["capabilities"],["connect.inbox.write"])
                # A Space keeps its kind, and an unknown kind is refused.
                with self.assertRaises(Refused): owner.space_share(host,collection,"Inbox",[phone])
                with self.assertRaises(Refused): owner.space_share(host,str(uuid.uuid4()),"Odd",[phone],kind="anything")
                folder=owner.space_share(host,str(uuid.uuid4()),"Photos",[phone])
                self.assertEqual(folder["kind"],"folder")
                # Renewal keeps an inbox an inbox.
                spaces=owner.space_list()
                for space in spaces: space["valid_until"]="2026-01-01T00:00:00+00:00"
                owner._save_spaces(spaces)
                owner.space_renew()
                renewed=next(s for s in owner.space_list() if s["collection"]==collection)
                active=[p for p in owner.service.db.load_active_boundary_policies().policies if p.policy_id==renewed["policy_id"]][0]
                self.assertEqual((renewed["kind"],list(active.selector.capabilities)),("inbox",["connect.inbox.write"]))
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
            secret=next(iter(staged["keys"].values()))
            # Rooted, drive-relative and backslash names would escape on Windows.
            for name in ("../outside.key","/Windows/Temp/x.key","D:x.key","network\\keys\\na.key","network/./na.key"):
                with self.assertRaises(Refused,msg=name): Owner(target).restore(str(moved),staged["root"],staged["config"],{name:secret})
            with self.assertRaises(Refused): Owner(target).restore(str(moved),staged["root"],"\\Users\\v\\settings.toml",staged["keys"])
            climbing=moved/staged["config"]
            original=climbing.read_text()
            climbing.write_text(original.replace(staged["root"]+"/network/na.db",staged["root"]+"/../../escaped.db"))
            with self.assertRaises(Refused): Owner(target).restore(str(moved),staged["root"],staged["config"],staged["keys"])
            self.assertFalse((target.parent.parent/"escaped.db").exists())
            climbing.write_text(original)
            with self.assertRaises(Refused): Owner(target).restore(str(moved),staged["root"],"../settings.toml",staged["keys"])
            with self.assertRaises(Refused): Owner(target).restore(str(moved),"/elsewhere",staged["config"],staged["keys"])
            self.assertFalse((target/"owner.json").exists())
            elsewhere=Path(directory)/"elsewhere"; shutil.copytree(moved,elsewhere)
            with self.assertRaises(Refused): Owner(target).restore(str(elsewhere),staged["root"],staged["config"],staged["keys"])
            with self.assertRaises(Refused): Owner(source).restore(str(moved),staged["root"],staged["config"],staged["keys"])

if __name__=="__main__": unittest.main()
