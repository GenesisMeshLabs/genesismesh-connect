"""Authority founding-key lifetime semantics against the pinned real core."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from genesis_mesh.crypto import sign_model
from test_embedded_owner import EmbeddedOwner, TestVault, core_time, required_core_version, Refused


class OwnerLifetimeTests(unittest.TestCase):
    def test_day_91_reopens_same_network_without_authorizing_expired_membership(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = EmbeddedOwner(Path(directory) / "owner", TestVault(), required_core_version())
            try:
                identity = owner.create("Long-lived phone network")
                at = owner.genesis.network_authority.valid_from + timedelta(days=91)
                owner.close()
                with core_time(at):
                    self.assertEqual(owner.open(), identity)
                    self.assertEqual(owner.member_status(), "renewal_required")
                    with self.assertRaisesRegex(Refused, "Renew the member"):
                        owner.check_member()
            finally: owner.close()

    def test_founding_authority_start_allows_only_five_minutes_clock_tolerance(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = EmbeddedOwner(Path(directory) / "owner", TestVault(), required_core_version())
            try:
                owner.create("Clock tolerance")
                genesis = owner.genesis.model_copy(deep=True)
                genesis.network_authority.valid_from += timedelta(minutes=5)
                from owner_adapter import seed
                protected = json.loads(owner.vault.open_root(owner.identity["instance"], owner.storage.read("root.sealed")))
                genesis.signatures = [sign_model(genesis, seed(protected["seed"]), "connect-root")]
                at = genesis.network_authority.valid_from - timedelta(minutes=5)
                with core_time(at):
                    owner._verify(genesis, owner.policy, owner.certificate, require_current=False)
                with core_time(at - timedelta(microseconds=1)):
                    with self.assertRaisesRegex(Refused, "authority.*not valid yet"):
                        owner._verify(genesis, owner.policy, owner.certificate, require_current=False)
            finally: owner.close()

    def test_verification_reports_the_failed_boundary_without_secret_values(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = EmbeddedOwner(Path(directory) / "owner", TestVault(), required_core_version())
            try:
                owner.create("Specific failures")
                cases = [
                    ("genesis", lambda g: setattr(g, "signatures", []), "founding record signature"),
                    ("policy", lambda p: setattr(p, "signatures", []), "policy signature"),
                    ("certificate", lambda c: setattr(c, "network_name", "Other"), "membership.*network"),
                    ("certificate", lambda c: setattr(c, "roles", []), "membership roles"),
                    ("certificate", lambda c: setattr(c, "issued_by", "other"), "membership issuer"),
                    ("certificate", lambda c: setattr(c, "signatures", []), "membership signature"),
                ]
                for target, mutate, reason in cases:
                    with self.subTest(boundary=reason):
                        values = {name: getattr(owner, name).model_copy(deep=True) for name in ("genesis", "policy", "certificate")}
                        mutate(values[target])
                        with self.assertRaisesRegex(Refused, reason):
                            owner._verify(**values)
            finally: owner.close()


if __name__ == "__main__": unittest.main()
