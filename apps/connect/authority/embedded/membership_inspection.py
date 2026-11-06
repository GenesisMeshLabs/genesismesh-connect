"""Fresh read-only pending-renewal inspection. No authority, network or recovery action."""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import sqlite3
import stat
import uuid

from genesis_mesh.crypto import verify_signature
from genesis_mesh.models import JoinCertificate, PolicyManifest
from member_renewal import DOMAIN, _public, _staged_evidence
from owner_adapter import EmbeddedOwner
from state_storage import Refused, encode

MAX_DATABASE = 64 * 1024 * 1024
MAX_CERTIFICATES = 258
MAX_REPLY = 4096


class InspectionRefused(RuntimeError):
    def __init__(self, reason): self.reason = reason


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise InspectionRefused("invalid_evidence")
        result[key] = value
    return result


def decode(content):
    return json.loads(content, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(InspectionRefused("invalid_evidence")))


def canonical_uuid(value):
    return isinstance(value, str) and str(uuid.UUID(value)) == value


def certificate_digest(certificate):
    """Local reference digest includes signatures; it is not a core audit receipt."""
    return hashlib.sha256(encode(certificate.model_dump(mode="json"))).hexdigest()


def _read_intent(owner):
    raw = owner.storage.read("member-renewal.json")
    value = decode(raw)
    fields = {"schema", "instance", "previous", "baseline", "operation", "signature"}
    if type(value.get("schema")) is not int or value["schema"] not in (1, 2):
        raise InspectionRefused("invalid_evidence")
    if set(value) != (fields | {"outcome"} if value["schema"] == 2 else fields):
        raise InspectionRefused("invalid_evidence")
    body = {k: v for k, v in value.items() if k != "signature"}
    baseline = body["baseline"]
    if (body["instance"] != owner.identity["instance"] or not canonical_uuid(body["operation"])
            or not canonical_uuid(body["previous"]) or not isinstance(baseline, list)
            or not 1 <= len(baseline) <= 256 or any(not canonical_uuid(item) for item in baseline)
            or baseline != sorted(set(baseline)) or body["previous"] not in baseline
            or not verify_signature(DOMAIN + encode(body), value["signature"], _public(owner.keys["operator"]))):
        raise InspectionRefused("invalid_evidence")
    if value["schema"] == 2:
        outcome = body["outcome"]
        if (not isinstance(outcome, dict) or set(outcome) != {"certificate_id", "certificate_sha256"}
                or not canonical_uuid(outcome["certificate_id"]) or outcome["certificate_id"] in baseline
                or not isinstance(outcome["certificate_sha256"], str)
                or not re.fullmatch(r"[a-f0-9]{64}", outcome["certificate_sha256"])):
            raise InspectionRefused("invalid_evidence")
    binding = {**owner.identity, "previous_certificate_id": body["previous"], "operation": body["operation"],
               "intent_sha256": hashlib.sha256(encode(value)).hexdigest()}
    return body, binding


def _inventory(owner):
    # Includes inodes/mtime and bytes. Atime is an OS read side effect, not a persistence guarantee.
    records = {}
    for path in owner.storage.directory.iterdir():
        if len(records) >= 24: raise InspectionRefused("inspection_limit")
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise InspectionRefused("invalid_evidence")
        limit = MAX_DATABASE if path.name == "authority.db" else 65536
        if metadata.st_size > limit: raise InspectionRefused("inspection_limit")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise InspectionRefused("snapshot_changed")
            digest = hashlib.sha256()
            remaining = limit + 1
            while remaining:
                chunk = stream.read(min(65536, remaining))
                if not chunk: break
                remaining -= len(chunk)
                digest.update(chunk)
            if not remaining: raise InspectionRefused("inspection_limit")
            settled = os.fstat(stream.fileno())
            if (settled.st_size, settled.st_mtime_ns) != (metadata.st_size, metadata.st_mtime_ns):
                raise InspectionRefused("snapshot_changed")
        records[path.name] = (metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, digest.hexdigest())
    return records


def _database(owner, intent):
    for name in ("authority.db-wal", "authority.db-journal"):
        path = owner.storage.directory / name
        if path.exists() and path.stat().st_size:
            # immutable=1 must not hide uncheckpointed issuance. No checkpoint or copy fallback.
            raise InspectionRefused("database_requires_settlement")
    path = owner.storage.path("authority.db")
    if not path.is_file() or path.is_symlink() or not 0 < path.stat().st_size <= MAX_DATABASE:
        raise InspectionRefused("invalid_evidence")
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True, timeout=0)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 65536)
        steps = 0
        def budget():
            nonlocal steps
            steps += 1
            return int(steps > 1000)
        db.set_progress_handler(budget, 1000)
        if db.execute("PRAGMA quick_check").fetchone() != ("ok",): raise InspectionRefused("invalid_evidence")
        for table in ("issued_certs", "policy_versions"):
            row = db.execute("SELECT type,sql FROM sqlite_schema WHERE name=?", (table,)).fetchone()
            if not row or row[0] != "table" or not row[1].lstrip().upper().startswith("CREATE TABLE"):
                raise InspectionRefused("invalid_evidence")
        policy = db.execute("SELECT policy_json FROM policy_versions WHERE active=1 LIMIT 2").fetchall()
        if len(policy) != 1 or PolicyManifest.model_validate(decode(policy[0][0])) != owner.policy:
            raise InspectionRefused("invalid_evidence")
        rows = db.execute("SELECT cert_id,node_public_key,cert_json,status FROM issued_certs WHERE node_public_key=? LIMIT ?",
                          (owner.identity["member_public_key"], MAX_CERTIFICATES)).fetchall()
        if len(rows) >= MAX_CERTIFICATES: raise InspectionRefused("inspection_limit")
        certificates = {}
        for cert_id, node, text, status in rows:
            certificate = JoinCertificate.model_validate(decode(text))
            owner._verify(owner.genesis, owner.policy, certificate, require_current=False)
            if (cert_id in certificates or cert_id != certificate.cert_id or node != certificate.node_public_key
                    or status not in ("issued", "revoked")):
                raise InspectionRefused("invalid_evidence")
            certificates[cert_id] = (certificate, status)
        if not set(intent["baseline"]) <= set(certificates): raise InspectionRefused("invalid_evidence")
        current = certificates.get(owner.certificate.cert_id)
        if not current or current[0] != owner.certificate: raise InspectionRefused("invalid_evidence")
        if current[1] != "issued": raise InspectionRefused("recorded_membership_revoked")
        return {key: value for key, value in certificates.items() if key not in intent["baseline"]}


def inspect(directory, vault, expected_core_version):
    """Fresh inspection only; never reuse or repair a live/uncertain owner session."""
    observed = datetime.now(timezone.utc)
    result = {"schema": 1, "observed_at": observed.isoformat(),
              "status": "ambiguous_or_invalid_evidence", "reason": "snapshot_unavailable", "binding": None, "outcome": None}
    owner = None
    try:
        owner = EmbeddedOwner(directory, vault, expected_core_version)
        vault.ready()
        try: owner.storage.acquire_readonly()
        except Refused: raise InspectionRefused("profile_busy_or_unavailable") from None
        owner._read_saved(allow_renewal=True)
        before = _inventory(owner)
        if (owner.storage.read("state.json") != owner.state_bytes
                or any(before[name + ".sealed"][3] != owner.state[name + "_sha256"] for name in ("root", "owner", "member"))):
            raise InspectionRefused("snapshot_changed")
        intent_path = owner.storage.path("member-renewal.json")
        if not intent_path.exists():
            _database(owner, {"baseline": [owner.certificate.cert_id]})
            result.update(status="no_pending_update", reason="no_pending_intent")
        else:
            intent, binding = _read_intent(owner)
            result["binding"] = binding
            certificates = _database(owner, intent)
            staged = owner.storage.check_files(allow_renewal=True)
            unknown = owner.storage.check_evidence(owner.state.get("recovery_evidence", {}), staged, allow_unrecorded=True)
            if not certificates:
                if owner.certificate.cert_id != intent["previous"] or unknown:
                    raise InspectionRefused("invalid_evidence")
                if intent["schema"] == 2: raise InspectionRefused("referenced_outcome_missing")
                result.update(status="no_recorded_issuance_observed", reason="no_new_certificate_in_snapshot")
            elif len(certificates) != 1:
                raise InspectionRefused("multiple_recorded_issuances")
            elif intent["schema"] == 1:
                raise InspectionRefused("legacy_intent_has_no_exact_outcome_link")
            else:
                certificate, status = next(iter(certificates.values()))
                reference = intent["outcome"]
                if certificate.cert_id != reference["certificate_id"] or certificate_digest(certificate) != reference["certificate_sha256"]:
                    raise InspectionRefused("referenced_outcome_mismatch")
                if owner.certificate.cert_id not in (intent["previous"], certificate.cert_id):
                    raise InspectionRefused("invalid_evidence")
                if status != "issued": raise InspectionRefused("recorded_membership_revoked")
                if certificate.issued_at > observed or certificate.issued_at >= certificate.expires_at:
                    raise InspectionRefused("invalid_evidence")
                _staged_evidence(owner, certificate)  # Authenticates staging, writes/adopts nothing.
                result.update(status="matching_recorded_outcome", reason="signed_exact_outcome_reference",
                    outcome={"certificate_id": certificate.cert_id, "certificate_sha256": certificate_digest(certificate),
                             "issued_at": certificate.issued_at.isoformat(), "expires_at": certificate.expires_at.isoformat(),
                             "expired": certificate.expires_at <= observed})
        if _inventory(owner) != before: raise InspectionRefused("snapshot_changed")
    except InspectionRefused as error:
        result.update(status="ambiguous_or_invalid_evidence", reason=error.reason, outcome=None)
    except Exception:
        result.update(status="ambiguous_or_invalid_evidence", reason="invalid_evidence", outcome=None)
    finally:
        if owner is not None: owner.close()  # This fresh object has no service/listener; only releases its own handles.
    if len(encode(result)) > MAX_REPLY: raise Refused("Inspection result is too large.")
    return result
