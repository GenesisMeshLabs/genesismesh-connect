"""Owner-only adapter over the real Genesis Mesh CLI and signed admin routes.

Only fixed operations cross a local inherited pipe. This service is not shipped
to a phone and exposes no operator credential or arbitrary HTTP proxy to it.
"""
import base64
import hashlib
import contextlib
import io
import json
import os
import shutil
import sqlite3
import tempfile
import threading
import tomllib
import unicodedata
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import nacl.signing
import requests
from werkzeug.serving import make_server, WSGIRequestHandler
from genesis_mesh.cli.config import save_config
from genesis_mesh.cli.init_ops import init as initialize_network
from genesis_mesh.crypto import load_private_key
from genesis_mesh.crypto.admin_auth import sign_admin_request
from genesis_mesh.models.genesis import GenesisBlock
from genesis_mesh.na_service.rate_limit import RateLimits
from genesis_mesh.na_service.server import NetworkAuthorityService

from protection import discard, protect, unprotect, ready


class Refused(Exception):
    pass


# What each kind of Space lets its devices do: read a shared folder, or
# write into the host's inbox.
KINDS = {"folder": ["connect.collection.read", "connect.collection.list"],
         "inbox": ["connect.inbox.write"]}
# Every device reaches this authority through Connect's bridge on loopback,
# so per-address limits would cap the whole network as one client. They sit
# above what the bridge forwards (its own budgets: 1,024 connections and 480
# decisions and attestation reads a minute); per-device limits stay as core
# sets them.
BRIDGED_LIMITS = RateLimits(read=2400, node_address=1200)
SPACE_DAYS = 90
RENEW_DAYS = 30
MAX_SPACES = 64
MAX_HOST_SPACES = 16
MAX_RECIPIENTS = 31


def space_name(value):
    # The same control characters devices refuse (Unicode category Cc), so a
    # name stored here never makes a device drop the list.
    if (not isinstance(value, str) or not value.strip() or len(value.strip()) > 64
            or any(unicodedata.category(c) == "Cc" for c in value)):
        raise Refused("Name the shared folder with 1 to 64 characters.")
    return value.strip()


def name(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 80 or any(ord(c) < 32 for c in value):
        raise Refused("Choose a name between 1 and 80 characters.")
    return value.strip()


def node(value):
    try:
        if not isinstance(value, str) or len(base64.b64decode(value, validate=True)) != 32:
            raise ValueError()
    except (ValueError, TypeError):
        raise Refused("The requesting device identity is invalid.") from None
    return value


def atomic(path, data, *, create=False):
    path = Path(path)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        pending = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            pending.unlink(missing_ok=True)
            raise
    try:
        if create:
            # Same-directory hard-link commit refuses replacement on Unix too.
            try:
                os.link(pending, path)
            except FileExistsError:
                raise Refused("Network state already exists.")
        else:
            os.replace(pending, path)
    finally:
        pending.unlink(missing_ok=True)


def relative(value):
    """A forward-slash relative name from a recovery file. Drive letters,
    roots and backslashes are refused on every platform."""
    if (not isinstance(value, str) or not value or len(value) > 512 or value.startswith("/")
            or "\\" in value or ":" in value
            or any(part in ("", ".", "..") for part in value.split("/"))):
        raise Refused("The recovery file names an invalid location.")
    return Path(*value.split("/"))


def within(root, path):
    """Refuse any target that resolves outside the network directory."""
    resolved = Path(path).resolve()
    if resolved != root and root not in resolved.parents:
        raise Refused("The recovery file names a location outside its network.")
    return resolved


def key(path, *, managed):
    with Path(path).open("rb") as stream:
        raw = stream.read(16 * 1024 + 1)
    if len(raw) > 16 * 1024:
        raise Refused("Network key storage needs attention.")
    if managed:
        text = unprotect(raw).decode("utf-8")
        seed = "".join(line.strip() for line in text.splitlines() if not line.startswith("#"))
        return nacl.signing.SigningKey(base64.b64decode(seed, validate=True))
    return load_private_key(str(path))


class QuietHandler(WSGIRequestHandler):
    def log_request(self, code="-", size="-"):
        pass


class Owner:
    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        self.server = None
        self.service = None
        self.thread = None
        self.config = None
        self.session = requests.Session()
        self.session.trust_env = False
        self.marker = self.directory / "owner.json"

    def create(self, network_name):
        ready()
        network_name = name(network_name)
        if self.directory.exists() and any(self.directory.iterdir()):
            raise Refused("A network already exists here. Reopen it instead of replacing its identity.")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        profile = self.directory / "network"
        config = self.directory / "genesis-mesh.toml"
        # Reuse the supported core initializer, never a synthetic Genesis block.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            initialize_network.main(args=["--home", str(profile), "--config", str(config),
                "--network-name", network_name, "--na-port", "9443"], standalone_mode=False)
        for path in (profile / "keys").glob("*.key"):
            atomic(path, protect(path.read_bytes()))
        atomic(self.marker, json.dumps({"version": 1, "managed": True, "config": str(config)}).encode(), create=True)
        return self.open()

    def attach(self, config_path):
        if self.marker.exists() or self.config:
            raise Refused("A network is already configured on this computer.")
        if self.directory.exists() and any(self.directory.iterdir()):
            raise Refused("Existing network state needs attention before importing another network.")
        path = Path(config_path).resolve(strict=True)
        if not path.is_file() or path.stat().st_size > 64 * 1024:
            raise Refused("Choose the existing network settings file.")
        self.directory.mkdir(parents=True, exist_ok=True)
        self._load(path, managed=False)
        # Public network identity is read from the selected local configuration,
        # never adopted from a remote discovery response.
        atomic(self.marker, json.dumps({"version": 1, "managed": False, "config": str(path)}).encode(), create=True)
        return self.info()

    def open(self):
        if self.config:
            return self.info()
        if not self.marker.is_file() or self.marker.stat().st_size > 8192:
            raise Refused("Set up your network first.")
        marker = json.loads(self.marker.read_text())
        if marker.get("version") != 1 or type(marker.get("managed")) is not bool:
            raise Refused("Network owner settings need attention.")
        self._load(Path(marker["config"]), managed=marker["managed"])
        return self.info()

    def _load(self, path, *, managed):
        if path.stat().st_size > 64 * 1024:
            raise Refused("Network settings are too large.")
        config = tomllib.loads(path.read_text(encoding="utf-8"))
        def location(field):
            value = Path(config["paths"][field])
            return value if value.is_absolute() else path.parent / value
        genesis = GenesisBlock.model_validate_json(location("genesis").read_bytes())
        operator = key(location("operator_private_key"), managed=managed)
        na_key = key(location("na_private_key"), managed=managed)
        if managed:
            service = NetworkAuthorityService(genesis_block=genesis, na_private_key=na_key,
                key_id=config["na"]["key_id"], db_path=str(location("db")),
                operator_public_keys={config["operator"]["key_id"]:base64.b64encode(bytes(operator.verify_key)).decode()},
                operator_key_tiers={config["operator"]["key_id"]:"privileged"},
                boundary_policy_enforcement="required", evidence_store="on", evidence_out_of_band="on",
                rate_limits=BRIDGED_LIMITS)
            self.service = service
            self.server = make_server("127.0.0.1", 0, service.app, request_handler=QuietHandler)
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
            origin = f"http://127.0.0.1:{self.server.server_port}"
        else:
            origin = config["network"]["na_endpoint"]
            parsed = urlsplit(origin)
            if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "::1") or not parsed.port or parsed.username or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
                raise Refused("Use settings for the authority on this computer.")
        self.genesis, self.operator, self.na_key, self.origin = genesis, operator, na_key, origin.rstrip("/")
        self.config, self.config_path = config, path
        self.database = location("db")

    def info(self):
        return {"url":self.origin,"pin":{"root_public_key":self.genesis.root_public_key,"network_name":self.genesis.network_name},"managed":self.server is not None}

    def admin(self, path, body):
        if not self.config:
            raise Refused("Open the network first.")
        audience = base64.b64encode(bytes(self.na_key.verify_key)).decode()
        headers = sign_admin_request(self.operator, self.config["operator"]["key_id"], method="POST", path=path, audience=audience, body=body)
        response = self.session.post(self.origin+path,json=body,headers=headers,timeout=5,allow_redirects=False)
        if response.status_code not in (200,201) or len(response.content)>512*1024:
            raise Refused(f"The network authority refused this operation ({response.status_code}).")
        return response.json()

    def read(self, path, params=None):
        """A signed admin read; the signature covers the query too."""
        if not self.config:
            raise Refused("Open the network first.")
        audience = base64.b64encode(bytes(self.na_key.verify_key)).decode()
        headers = sign_admin_request(self.operator, self.config["operator"]["key_id"], method="GET", path=path, audience=audience, query=params)
        return self.session.get(self.origin+path,params=params,headers=headers,timeout=5,allow_redirects=False)

    def policy_versions(self, policy_id):
        """Every stored version of one policy, through the signed admin route,
        so attached networks answer too. Empty when the policy does not exist."""
        response = self.read(f"/admin/boundary-policies/{policy_id}/history")
        if response.status_code == 400 and response.json().get("error", {}).get("code") == "boundary_policy_not_found":
            return []
        # Every change and renewal adds a version with its full policy, so the
        # history grows over the years; allow it room.
        if response.status_code != 200 or len(response.content) > 16*1024*1024:
            raise Refused(f"The network authority refused this operation ({response.status_code}).")
        return response.json()["versions"]

    def invite(self, public_key, host=False):
        public_key=node(public_key)
        body={"roles":["role:client"],"recipient_public_key":public_key,"max_validity_hours":24,"token_expiry_hours":1}
        if host:
            identity=hashlib.sha256(base64.b64decode(public_key,validate=True)).hexdigest()
            # Core sovereign IDs are at most 64 characters. A 192-bit digest
            # keeps device subjects distinct within that existing constraint.
            body.update(node_sovereign_id="connect-device-"+identity[:48],executor_resource_prefix="connect:device:"+identity+"/")
        return {"invite":self.admin("/admin/invite",body)["token_id"]}

    def subject(self, host_node):
        """The sharing subject this network's host invitations give a device."""
        return "connect-device-"+hashlib.sha256(base64.b64decode(node(host_node),validate=True)).hexdigest()[:48]

    def share(self, host_node, peer_node, collection_id, subject="connect-host"):
        host_node,peer_node=node(host_node),node(peer_node)
        expected="connect-device-"+hashlib.sha256(base64.b64decode(host_node,validate=True)).hexdigest()[:48]
        if subject not in ("connect-host",expected):
            raise Refused("The sharing subject does not belong to this device.")
        uuid.UUID(collection_id)
        policy_id="connect-"+collection_id
        now=datetime.now(timezone.utc)
        result=self.admin("/admin/boundary-policies",{"policy_id":policy_id,
            "valid_from":now.isoformat(),"valid_until":(now+timedelta(days=30)).isoformat(),
            "selector":{"capabilities":["connect.collection.read","connect.collection.list"],
                "parameter_equals":{"request_parameters.collection_id":[collection_id]}},
            "gates":[{"gate_id":"collection","gate_type":"allowlist.v1","order":0,"config":{"path":"request_parameters.collection_id","values":[collection_id]}},
                {"gate_id":"peer","gate_type":"allowlist.v1","order":1,"config":{"path":"request_parameters.peer_node","values":[peer_node]}},
                {"gate_id":"size","gate_type":"max_value.v1","order":2,"config":{"path":"request_parameters.size","max":1073741824}}]})
        self.admin(f"/admin/boundary-policies/{policy_id}/activate",{"version":result["version"]})
        attestation=self.admin("/admin/attestations",{"subject_id":subject,"subject_public_key":host_node,"roles":["role:client"],"validity_hours":720,"claims":{"capabilities":["connect.collection.read","connect.collection.list"]}})
        return {"collection_id":collection_id,"policy_id":policy_id,"attestation_id":attestation["attestation_id"]}

    # -- Spaces ---------------------------------------------------------------
    #
    # A Space is one device's folder shared with chosen devices. The registry
    # lives in this directory, so recovery files carry it; the authority holds
    # the policy (one per Space, versioned) and the host's attestation.

    def _spaces(self):
        path = self.directory / "spaces.json"
        if not path.exists():
            return []
        if path.stat().st_size > 256 * 1024:
            raise Refused("The list of shared folders needs attention.")
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("version") != 1 or not isinstance(data.get("spaces"), list):
            raise Refused("The list of shared folders needs attention.")
        return data["spaces"]

    def _save_spaces(self, spaces):
        atomic(self.directory / "spaces.json", json.dumps({"version": 1, "spaces": spaces}).encode())

    def _grant(self, host_node, subject, collection_id, recipients, kind="folder"):
        """Publish and activate the Space's policy for exactly these devices,
        and attest the host for it. Returns the registry fields."""
        capabilities = KINDS[kind]
        policy_id = "connect-" + collection_id
        now = datetime.now(timezone.utc)
        valid_until = now + timedelta(days=SPACE_DAYS)
        result = self.admin("/admin/boundary-policies", {"policy_id": policy_id,
            "valid_from": now.isoformat(), "valid_until": valid_until.isoformat(),
            "selector": {"capabilities": capabilities,
                "parameter_equals": {"request_parameters.collection_id": [collection_id]}},
            "gates": [{"gate_id": "collection", "gate_type": "allowlist.v1", "order": 0, "config": {"path": "request_parameters.collection_id", "values": [collection_id]}},
                {"gate_id": "peer", "gate_type": "allowlist.v1", "order": 1, "config": {"path": "request_parameters.peer_node", "values": sorted(recipients)}},
                {"gate_id": "size", "gate_type": "max_value.v1", "order": 2, "config": {"path": "request_parameters.size", "max": 1073741824}}]})
        self.admin(f"/admin/boundary-policies/{policy_id}/activate", {"version": result["version"]})
        attestation = self.admin("/admin/attestations", {"subject_id": subject, "subject_public_key": host_node,
            "roles": ["role:client"], "validity_hours": SPACE_DAYS * 24,
            "claims": {"capabilities": capabilities}})
        return {"policy_id": policy_id, "policy_version": result["version"],
            "attestation_id": attestation["attestation_id"], "valid_until": valid_until.isoformat()}

    def space_share(self, host_node, collection_id, space, recipients, subject=None, adopt=False, kind="folder"):
        """Create a Space, or change its name and devices. Only its host may
        change it; the policy names exactly the chosen devices. A new Space
        never takes over an existing policy: only this computer, moving a
        folder it shared before Spaces (`adopt`), may give one a registry entry.
        An inbox Space lets its devices send files into the host's folder."""
        if kind not in KINDS:
            raise Refused("Choose a shared folder or an inbox.")
        host_node = node(host_node)
        expected = self.subject(host_node)
        subject = expected if subject is None else subject
        if subject not in ("connect-host", expected):
            raise Refused("The sharing subject does not belong to this device.")
        uuid.UUID(collection_id)
        space = space_name(space)
        if not isinstance(recipients, list) or not 1 <= len(recipients) <= MAX_RECIPIENTS:
            raise Refused("Choose between 1 and 31 devices to share with.")
        recipients = sorted({node(r) for r in recipients})
        if host_node in recipients:
            raise Refused("A device cannot share with itself.")
        spaces = self._spaces()
        existing = next((s for s in spaces if s["collection"] == collection_id), None)
        if existing is not None and existing["host"] != host_node:
            raise Refused("This shared folder belongs to another device.")
        if existing is not None and existing.get("kind", "folder") != kind:
            raise Refused("A shared folder and an inbox stay what they are.")
        if existing is None:
            if self.policy_versions("connect-" + collection_id) and not adopt:
                raise Refused("This folder already has a permission on this network.")
            if sum(1 for s in spaces if s["host"] == host_node) >= MAX_HOST_SPACES:
                raise Refused("A device can share up to 16 folders.")
            if len(spaces) >= MAX_SPACES:
                raise Refused("This network shares up to 64 folders.")
        entry = {"collection": collection_id, "name": space, "host": host_node, "kind": kind,
            "subject": subject, "recipients": recipients,
            "created_at": existing["created_at"] if existing else datetime.now(timezone.utc).isoformat()}
        entry.update(self._grant(host_node, subject, collection_id, recipients, kind))
        spaces = [s for s in spaces if s["collection"] != collection_id] + [entry]
        self._save_spaces(spaces)
        return entry

    def space_remove(self, host_node, collection_id):
        """Stop a Space: its policy is deactivated, so no decision allows it."""
        host_node = node(host_node)
        uuid.UUID(collection_id)
        spaces = self._spaces()
        existing = next((s for s in spaces if s["collection"] == collection_id), None)
        if existing is None:
            return False
        if existing["host"] != host_node:
            raise Refused("This shared folder belongs to another device.")
        policy_id = "connect-" + collection_id
        # The registry entry goes only once no version is active, so a failure
        # here leaves the Space listed and the removal can be asked again.
        for version in self.policy_versions(policy_id):
            if version["active"]:
                self.admin(f"/admin/boundary-policies/{policy_id}/deactivate", {"version": version["version"]})
        if any(v["active"] for v in self.policy_versions(policy_id)):
            raise Refused("The shared folder's permission is still active. Try again.")
        self._save_spaces([s for s in spaces if s["collection"] != collection_id])
        return True

    def space_list(self):
        return self._spaces()

    def remove_device(self, host_node):
        """Take a device off the network. Every certificate of its key is
        revoked at the authority, so no device and no decision accepts it
        again; the Spaces it shares stop, and those shared with it no longer
        name it (one left with nobody stops). Asking again finishes what a
        failure left undone."""
        host_node = node(host_node)
        response = self.read("/admin/edge-nodes", {"node_sovereign_id": self.subject(host_node)})
        if response.status_code != 200 or len(response.content) > 512*1024:
            raise Refused(f"The network authority refused this operation ({response.status_code}).")
        revoked = 0
        for edge in response.json()["edge_nodes"]:
            if edge["node_public_key"] == host_node and edge["cert_id"]:
                result = self.admin("/admin/revoke", {"cert_id": edge["cert_id"], "reason": "cessation_of_operation"})
                revoked += len(result.get("edge_node", {}).get("revoked_cert_ids", []))
        stopped, changed = [], []
        for entry in self._spaces():
            if entry["host"] == host_node:
                self.space_remove(host_node, entry["collection"])
                stopped.append(entry["collection"])
            elif host_node in entry["recipients"]:
                others = [r for r in entry["recipients"] if r != host_node]
                if others:
                    self.space_share(entry["host"], entry["collection"], entry["name"], others,
                        entry["subject"], kind=entry.get("kind", "folder"))
                    changed.append(entry["collection"])
                else:
                    self.space_remove(entry["host"], entry["collection"])
                    stopped.append(entry["collection"])
        return {"revoked": revoked, "stopped": stopped, "changed": changed}

    def space_renew(self, days=RENEW_DAYS):
        """Renew every Space whose policy ends within `days`. Returns the
        renewed Spaces; their hosts pick up the new attestation."""
        spaces = self._spaces()
        limit = datetime.now(timezone.utc) + timedelta(days=days)
        renewed = []
        for entry in spaces:
            if datetime.fromisoformat(entry["valid_until"]) <= limit:
                # One failure leaves that Space for the next pass; every
                # renewal is saved as it is made.
                try:
                    entry.update(self._grant(entry["host"], entry["subject"], entry["collection"], entry["recipients"], entry.get("kind", "folder")))
                except Exception:
                    continue
                self._save_spaces(spaces)
                renewed.append(entry["collection"])
        return renewed

    def backup(self):
        """Stage the network for a recovery file: a consistent database
        snapshot and the public files on disk, inside this private directory;
        the owner keys only in the reply, never as plaintext files."""
        if not self.config or not self.server:
            raise Refused("Recovery files cover networks Connect created on this computer.")
        root = self.directory
        for value in self.config["paths"].values():
            path = Path(value) if Path(value).is_absolute() else self.config_path.parent / value
            if root not in path.resolve().parents:
                raise Refused("This network keeps files outside Connect's folder.")
        database = self.database.resolve()
        live = {database, database.with_name(database.name + "-wal"), database.with_name(database.name + "-shm"), self.marker}
        # An earlier backup that did not finish leaves no staging behind.
        for stale in root.glob(".recovery-*"):
            shutil.rmtree(stale, ignore_errors=True)
        staging = Path(tempfile.mkdtemp(prefix=".recovery-", dir=root))
        try:
            keys = {}
            for path in sorted(root.rglob("*")):
                if not path.is_file() or path.resolve() in live or path.name.startswith(".recovery-") or any(p.name.startswith(".recovery-") for p in path.relative_to(root).parents if p.name):
                    continue
                name = path.relative_to(root).as_posix()
                if path.suffix == ".key":
                    with path.open("rb") as stream:
                        keys[name] = base64.b64encode(unprotect(stream.read(16 * 1024 + 1))).decode("ascii")
                    continue
                target = staging / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
            target = staging / database.relative_to(root).as_posix()
            target.parent.mkdir(parents=True, exist_ok=True)
            # SQLite's online backup is consistent while the authority keeps serving.
            source, copy = sqlite3.connect(str(database)), sqlite3.connect(str(target))
            try:
                source.backup(copy)
            finally:
                copy.close(); source.close()
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        return {"staging": str(staging), "root": root.as_posix(), "config": self.config_path.resolve().relative_to(root).as_posix(), "keys": keys}

    def restore(self, staging, old_root, config_name, keys):
        """Install a network from a decrypted recovery file staged next to this
        directory. Owner keys are protected again for this computer, and
        settings are moved to this location. Never replaces an existing network."""
        if self.marker.exists() or self.config:
            raise Refused("A network is already configured on this computer.")
        if self.directory.exists() and any(self.directory.iterdir()):
            raise Refused("Existing network state needs attention before restoring another network.")
        ready()
        staging = Path(staging).resolve(strict=True)
        if not staging.is_dir() or staging.parent != self.directory.parent:
            raise Refused("The recovery file was not staged for this computer.")
        if not isinstance(old_root, str) or not old_root or len(old_root) > 1024 or not isinstance(keys, dict) or not keys or len(keys) > 16:
            raise Refused("The recovery file is incomplete.")
        root = self.directory.resolve()
        config_path = within(root, root / relative(config_name))
        targets = {}
        for name, data in keys.items():
            if relative(name).suffix != ".key" or not isinstance(data, str) or len(data) > 32 * 1024:
                raise Refused("The recovery file is incomplete.")
            targets[within(root, root / relative(name))] = data
        config = tomllib.loads((staging / relative(config_name)).read_text(encoding="utf-8"))
        for field, value in config.get("paths", {}).items():
            if not isinstance(value, str) or not (value == old_root or value.startswith(old_root + "/")):
                raise Refused("The recovery file's settings name files outside its network.")
            suffix = value[len(old_root) + 1:]
            config["paths"][field] = (within(root, root / relative(suffix)) if suffix else root).as_posix()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        sealed = []
        try:
            shutil.copytree(staging, self.directory, dirs_exist_ok=True)
            for target, data in targets.items():
                target.parent.mkdir(parents=True, exist_ok=True)
                protected = protect(base64.b64decode(data, validate=True))
                sealed.append(protected)
                atomic(target, protected)
            save_config(config, str(config_path))
            atomic(self.marker, json.dumps({"version": 1, "managed": True, "config": str(config_path)}).encode(), create=True)
            return self.open()
        except BaseException:
            # This directory was empty, so remove everything written here and
            # every key sealed into the credential store: nothing half-restored
            # may later open as a network.
            self._stop()
            self.config = None
            for protected in sealed:
                with contextlib.suppress(Exception):
                    discard(protected)
            shutil.rmtree(self.directory, ignore_errors=True)
            raise

    def _stop(self):
        if self.server:
            self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=5)
            self.server=None
        if self.service:
            self.service.db.close()
            self.service=None

    def close(self):
        self._stop()
        self.session.close()
