"""Fixed embedded owner lifecycle over the pinned, unchanged Genesis Mesh core.

Native callers provide an app-private directory and the purpose-separated vault.
Only create/open/close/public identity cross that boundary. No key export or
generic route, filesystem or Python execution operation belongs in the UI.
"""
import base64
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
from importlib.metadata import version
import json
import os
import sqlite3
import threading
import uuid
import unicodedata

from nacl.signing import SigningKey
import requests
from werkzeug.serving import make_server, WSGIRequestHandler
from genesis_mesh.crypto import generate_keypair, sign_model, verify_model_signature
from genesis_mesh.crypto.admin_auth import sign_admin_request
from genesis_mesh.crypto.node_auth import sign_node_request
from genesis_mesh.models import GenesisBlock, NetworkAuthority, PolicyManifestRef, PolicyManifest, JoinCertificate
from genesis_mesh.na_service.server import NetworkAuthorityService

from state_storage import StateStorage, Refused, encode

NA_ID, OPERATOR_ID, ROOT_ID = "connect-na", "connect-owner", "connect-root"


class QuietHandler(WSGIRequestHandler):
    def log_request(self, code="-", size="-"): pass


def public(key):
    return base64.b64encode(bytes(key.verify_key)).decode()


def seed(value):
    raw = base64.b64decode(value, validate=True)
    if len(raw) != 32: raise Refused("Authority key storage needs attention.")
    return SigningKey(raw)


class EmbeddedOwner:
    def __init__(self, directory, vault, expected_core_version):
        if version("genesis-mesh") != expected_core_version:
            raise Refused("Update the embedded authority to the pinned release.")
        self.storage = StateStorage(directory)
        self.vault = vault
        self.service = self.server = self.thread = None
        self.keys = self.member = self.identity = None
        self.mutex = threading.RLock()
        self.session = requests.Session()
        self.session.trust_env = False

    def create(self, network_name):
        with self.mutex:
            if not isinstance(network_name, str) or not 1 <= len(network_name.strip()) <= 80 or any(unicodedata.category(c) == "Cc" for c in network_name):
                raise Refused("Choose a network name with 1 to 80 characters.")
            self.vault.ready()
            self.storage.acquire(create=True)
            try:
                if {p.name for p in self.storage.directory.iterdir()} != {".authority-lock"}:
                    raise Refused("Existing authority state must be reopened or recovered, never replaced.")
                instance = str(uuid.uuid4())
                self.storage.write_new("initializing.json", encode({"schema": 1, "instance": instance}))
                self.vault.create()  # Refuses missing-state/existing-key and partial-key situations.
                root, na, operator, member = [generate_keypair().private_key for _ in range(4)]
                now = datetime.now(timezone.utc)
                policy = PolicyManifest(policy_id="connect-initial", issued_at=now, issued_by=NA_ID,
                                        min_client_version="0.1.0", allowed_ports=[], allowed_services=[],
                                        routing={"preferred_transports": ["quic"], "max_hops": 6})
                policy.signatures.append(sign_model(policy, na, NA_ID))
                genesis = GenesisBlock(network_name=network_name.strip(), network_version="v0.1",
                    root_public_key=public(root), network_authority=NetworkAuthority(public_key=public(na),
                    valid_from=now, valid_to=now + timedelta(days=90)), allowed_transports=["quic"],
                    policy_manifest=PolicyManifestRef(hash="sha256:" + hashlib.sha256(policy.to_canonical_json().encode()).hexdigest()))
                genesis.signatures.append(sign_model(genesis, root, ROOT_ID))
                self.keys = {"root": root, "na": na, "operator": operator}
                self.member = member
                self._start(genesis)
                self.service.db.save_policy(policy, active=True)
                invite = self._admin("/admin/invite", {"roles": ["role:client"], "recipient_public_key": public(member),
                                                      "max_validity_hours": 24, "token_expiry_hours": 1})
                body = sign_node_request({"node_public_key": public(member), "invite_token": invite["token_id"],
                    "validity_hours": 24, "timestamp": now.isoformat(), "nonce": str(uuid.uuid4())}, member)
                certificate = JoinCertificate.model_validate(self._post("/join", body))
                self._verify(genesis, policy, certificate)
                payload = {"schema": 1, "instance": instance, "genesis": genesis.model_dump(mode="json"),
                    "policy": policy.model_dump(mode="json"), "certificate": certificate.model_dump(mode="json"),
                    "keys": {name: base64.b64encode(bytes(key)).decode() for name, key in self.keys.items()}}
                owner_sealed = bytes(self.vault.seal_owner(instance, encode(payload)))
                member_sealed = bytes(self.vault.seal_member(instance, encode({"schema": 1, "instance": instance,
                                              "seed": base64.b64encode(bytes(member)).decode()})))
                self.storage.write_new("owner.sealed", owner_sealed)
                self.storage.write_new("member.sealed", member_sealed)
                self.identity = self._identity(instance, genesis, certificate)
                self.service.db.conn.execute("PRAGMA wal_checkpoint(FULL)")
                descriptor = os.open(self.storage.path("authority.db"), os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
                try: os.fsync(descriptor)
                finally: os.close(descriptor)
                self.storage.write_new("state.json", encode({"schema": 1, "identity": self.identity,
                    "owner_sha256": hashlib.sha256(owner_sealed).hexdigest(),
                    "member_sha256": hashlib.sha256(member_sealed).hexdigest()}))
                self.storage.path("initializing.json").unlink()
                self.storage.sync()
                return dict(self.identity)
            except Exception:
                self.close()
                raise

    def open(self):
        with self.mutex:
            self.vault.ready()
            self.storage.acquire()
            try:
                self.storage.check_files()
                state = json.loads(self.storage.read("state.json"))
                if state["schema"] != 1: raise Refused("Unsupported authority state.")
                instance = state["identity"]["instance"]
                if str(uuid.UUID(instance)) != instance: raise Refused("Invalid authority identity.")
                owner_sealed, member_sealed = [self.storage.read(n) for n in ("owner.sealed", "member.sealed")]
                if (hashlib.sha256(owner_sealed).hexdigest() != state["owner_sha256"]
                        or hashlib.sha256(member_sealed).hexdigest() != state["member_sha256"]):
                    raise Refused("Authority storage was changed. Existing state was preserved.")
                payload = json.loads(bytes(self.vault.open_owner(instance, owner_sealed)))
                member = json.loads(bytes(self.vault.open_member(instance, member_sealed)))
                if any(p["schema"] != 1 or p["instance"] != instance for p in (payload, member)):
                    raise Refused("Authority custody does not match this network.")
                self.keys = {name: seed(payload["keys"][name]) for name in ("root", "na", "operator")}
                self.member = seed(member["seed"])
                genesis = GenesisBlock.model_validate(payload["genesis"])
                policy = PolicyManifest.model_validate(payload["policy"])
                certificate = JoinCertificate.model_validate(payload["certificate"])
                self._verify(genesis, policy, certificate)
                identity = self._identity(instance, genesis, certificate)
                if identity != state["identity"]: raise Refused("Saved authority identity does not match its protected keys.")
                database = self.storage.path("authority.db")
                if database.is_symlink() or not database.is_file() or database.stat().st_size == 0:
                    raise Refused("The existing authority database is missing.")
                # Read-only preflight: do not let core create/repair a missing or foreign database.
                with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as db:
                    if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
                        raise Refused("Authority database needs recovery.")
                    row = db.execute("SELECT cert_json,status FROM issued_certs WHERE cert_id=?", (certificate.cert_id,)).fetchone()
                    if not row or row[1] != "issued" or JoinCertificate.model_validate_json(row[0]) != certificate:
                        raise Refused("The persisted member identity is missing or revoked.")
                    saved = db.execute("SELECT policy_json FROM policy_versions WHERE active=1").fetchall()
                    if len(saved) != 1 or PolicyManifest.model_validate_json(saved[0][0]) != policy:
                        raise Refused("The persisted policy does not match this authority profile.")
                self.identity = identity
                self._start(genesis)
                return dict(identity)
            except Exception:
                self.close()
                raise

    def _verify(self, genesis, policy, certificate):
        na = genesis.network_authority
        now = datetime.now(timezone.utc)
        if (public(self.keys["root"]) != genesis.root_public_key or public(self.keys["na"]) != na.public_key
                or not na.valid_from <= now <= na.valid_to
                or not genesis.signatures or not all(verify_model_signature(genesis, s, genesis.root_public_key) for s in genesis.signatures)
                or not policy.signatures or not all(verify_model_signature(policy, s, na.public_key) for s in policy.signatures)
                or genesis.policy_manifest.hash != "sha256:" + hashlib.sha256(policy.to_canonical_json().encode()).hexdigest()
                or certificate.node_public_key != public(self.member) or certificate.network_name != genesis.network_name
                or certificate.roles != ["role:client"] or not certificate.is_valid()
                or certificate.issued_by != NA_ID or not certificate.signatures
                or not all(verify_model_signature(certificate, s, na.public_key) for s in certificate.signatures)):
            raise Refused("The protected network identity or membership is invalid.")

    def _identity(self, instance, genesis, certificate):
        return {"instance": instance, "network_name": genesis.network_name, "root_public_key": genesis.root_public_key,
                "authority_public_key": genesis.network_authority.public_key, "operator_public_key": public(self.keys["operator"]),
                "member_public_key": certificate.node_public_key, "certificate_id": certificate.cert_id}

    def _start(self, genesis):
        self.service = NetworkAuthorityService(genesis_block=genesis, na_private_key=self.keys["na"],
            key_id=NA_ID, db_path=str(self.storage.path("authority.db")),
            operator_public_keys={OPERATOR_ID: public(self.keys["operator"])}, operator_key_tiers={OPERATOR_ID: "privileged"},
            boundary_policy_enforcement="required", evidence_store="on", evidence_out_of_band="on")
        self.server = make_server("127.0.0.1", 0, self.service.app, request_handler=QuietHandler)
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.1), daemon=True)
        self.thread.start()

    def _post(self, path, body, headers=None):
        response = self.session.post(self.origin + path, json=body, headers=headers, timeout=5, allow_redirects=False)
        if response.status_code not in (200, 201) or len(response.content) > 65536:
            raise Refused("The local authority refused the fixed operation.")
        return response.json()

    def _admin(self, path, body):
        return self._post(path, body, sign_admin_request(self.keys["operator"], OPERATOR_ID,
            method="POST", path=path, audience=public(self.keys["na"]), body=body))

    def check_member(self):
        """Fixed native qualification/liveness operation; no caller-supplied body or route."""
        with self.mutex:
            self.vault.ready()
            if self.identity is None: raise Refused("Open the authority first.")
            body = {"cert_id": self.identity["certificate_id"], "node_public_key": public(self.member),
                    "status": "connect-owner", "timestamp": datetime.now(timezone.utc).isoformat(), "nonce": str(uuid.uuid4())}
            self._post("/heartbeat", sign_node_request(body, self.member))
            denied = self.session.post(self.origin + "/heartbeat", json={**body, "nonce": str(uuid.uuid4())}, timeout=5)
            if denied.status_code != 401: raise Refused("Unsigned membership request was not refused.")
            return True

    def close(self):
        with self.mutex:
            if self.server is not None:
                self.server.shutdown()
                self.server.server_close()
                self.thread.join(5)
                if self.thread.is_alive(): raise Refused("Authority shutdown needs attention.")
                self.server = self.thread = None
            if self.service is not None:
                self.service.db.close()
                self.service = None
            self.keys = self.member = self.identity = None
            self.session.close()
            self.storage.release()
