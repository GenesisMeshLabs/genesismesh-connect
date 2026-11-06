"""Explicit owner member recovery with a signed intent and no automatic replay.

This is an owner operation: the existing protected operator issues a key-bound
invite, and the existing member proves possession at the genuine core join route.
It does not extend an expired certificate or weaken the node renewal grace.
"""
from datetime import datetime, timedelta, timezone
import json
import uuid
import hashlib

from genesis_mesh.crypto import sign_data, verify_signature
from genesis_mesh.models import JoinCertificate

from state_storage import Refused, encode
from owner_adapter import STATE_DOMAIN

DOMAIN = b"GenesisMesh.Connect.EmbeddedOwner.MemberRecovery.v1\0"


def _public(key):
    import base64
    return base64.b64encode(bytes(key.verify_key)).decode()


def _intent(owner):
    value = json.loads(owner.storage.read("member-renewal.json"))
    body = {k: v for k, v in value.items() if k != "signature"}
    if (body.get("schema") != 1 or body.get("instance") != owner.identity["instance"]
            or not isinstance(body.get("baseline"), list) or not 1 <= len(body["baseline"]) <= 256
            or body.get("previous") not in body["baseline"]
            or not verify_signature(DOMAIN + encode(body), value.get("signature", ""), _public(owner.keys["operator"]))):
        raise Refused("The member recovery intent is invalid. Existing state was preserved.")
    return body


def _clear(owner):
    owner.storage.path("member-renewal.json").unlink()
    owner.storage.sync()
    owner.renewal_pending = False


def _staged_evidence(owner, certificate):
    staged = owner.storage.check_files(allow_renewal=True)
    recorded = dict(owner.state.get("recovery_evidence", {}))
    unrecorded = owner.storage.check_evidence(recorded, staged, allow_unrecorded=True)
    identity = owner._identity(owner.identity["instance"], owner.genesis, certificate)
    allowed = {"schema", "revision", "identity", "certificate", "root_sha256", "owner_sha256", "member_sha256", "state_signature", "recovery_evidence", "connect_registry_initialized"}
    for name in unrecorded:
        content = owner.storage.read_staged(name)
        value = json.loads(content)
        body = {k:v for k,v in value.items() if k != "state_signature"}
        if (not set(value) <= allowed or type(value.get("schema")) is not int or value["schema"] != 3 or value.get("identity") != identity
                or type(value.get("revision")) is not int
                or value["revision"] not in (owner.state["revision"], owner.state["revision"] + 1)
                or value.get("root_sha256") != owner.state["root_sha256"]
                or value.get("owner_sha256") != owner.state["owner_sha256"]
                or value.get("member_sha256") != owner.state["member_sha256"]
                or value.get("connect_registry_initialized") != owner.state.get("connect_registry_initialized")
                or JoinCertificate.model_validate(value["certificate"]) != certificate
                or not verify_signature(STATE_DOMAIN + encode(body), value.get("state_signature", ""), _public(owner.keys["operator"]))):
            raise Refused("Staged state does not authenticate the recorded core outcome. Existing evidence was preserved.")
        owner.storage.check_evidence(value.get("recovery_evidence", {}), staged, allow_unrecorded=True)
        recorded[name] = hashlib.sha256(content).hexdigest()
    return recorded


def renew(owner):
    with owner.mutex:
        owner.vault.ready()
        if owner.identity is None: raise Refused("Open the owner profile first.")
        if owner.renewal_pending or owner.storage.path("member-renewal.json").exists():
            raise Refused("Reconcile the pending member recovery; it must not be replayed.")
        owner._verify(owner.genesis, owner.policy, owner.certificate, require_current=False)
        if owner.certificate.expires_at - datetime.now(timezone.utc) > timedelta(hours=1):
            raise Refused("The current member credential does not need renewal yet.")
        row = owner.service.db.get_cert(owner.certificate.cert_id)
        if not row or row["status"] != "issued": raise Refused("A missing or revoked member cannot be recovered this way.")
        baseline = sorted(row["cert_id"] for row in owner.service.db.get_certs_by_node_key(_public(owner.member)))
        if not 1 <= len(baseline) <= 256: raise Refused("Member history requires operator review.")
        intent = {"schema": 1, "instance": owner.identity["instance"], "previous": owner.certificate.cert_id,
                  "baseline": baseline, "operation": str(uuid.uuid4())}
        intent["signature"] = sign_data(DOMAIN + encode(intent), owner.keys["operator"])
        owner.storage.write_new("member-renewal.json", encode(intent))
        owner.renewal_pending = True
        # Any exception leaves the signed intent and old committed state. No auto retry.
        certificate = owner._enroll_member()
        if certificate.cert_id in baseline: raise Refused("Core did not issue a new member credential.")
        owner._commit_certificate(certificate)
        _clear(owner)
        return dict(owner.identity)


def reconcile(owner):
    with owner.mutex:
        owner.vault.ready()
        if owner.storage.lock is not None: owner.close()  # Settle all prior handlers before examining outcomes.
        try:
            owner._open(allow_renewal=True)
            if not owner.renewal_pending: raise Refused("There is no pending member recovery.")
            intent = _intent(owner)
            candidates = []
            for row in owner.service.db.get_certs_by_node_key(_public(owner.member)):
                if row["cert_id"] in intent["baseline"] or row["status"] != "issued": continue
                certificate = JoinCertificate.model_validate_json(row["cert_json"])
                # Recover the authentic outcome even if its credential expired
                # while the app was away. It still grants no expired membership.
                owner._verify(owner.genesis, owner.policy, certificate, require_current=False)
                candidates.append(certificate)
            if len(candidates) != 1:
                raise Refused("No single completed enrollment was found. Review the pending operation; it was not repeated.")
            certificate = candidates[0]
            evidence = _staged_evidence(owner, certificate)
            if owner.certificate.cert_id != certificate.cert_id or evidence != owner.state.get("recovery_evidence", {}):
                if owner.certificate.cert_id not in (intent["previous"], certificate.cert_id):
                    raise Refused("The pending member recovery does not match current state.")
                owner._commit_certificate(certificate, require_current=False, recovery_evidence=evidence)
            _clear(owner)
            return dict(owner.identity)
        except Exception:
            owner.close()
            raise


def cancel(owner):
    with owner.mutex:
        owner.vault.ready()
        if owner.storage.lock is not None: owner.close()
        try:
            owner._open(allow_renewal=True)
            if not owner.renewal_pending: raise Refused("There is no pending member recovery.")
            intent = _intent(owner)
            staged = owner.storage.check_files(allow_renewal=True)
            owner.storage.check_evidence(owner.state.get("recovery_evidence", {}), staged)
            rows = owner.service.db.get_certs_by_node_key(_public(owner.member))
            if any(row["cert_id"] not in intent["baseline"] for row in rows):
                raise Refused("Core recorded an enrollment outcome. Reconcile or review it instead of discarding it.")
            if owner.certificate.cert_id != intent["previous"]:
                raise Refused("The pending recovery no longer matches current state.")
            _clear(owner)
            return {"status": "cancelled", "identity": dict(owner.identity)}
        except Exception:
            owner.close()
            raise
