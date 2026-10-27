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
from genesis_mesh.na_service.server import NetworkAuthorityService

from protection import discard, protect, unprotect, ready


class Refused(Exception):
    pass


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
                boundary_policy_enforcement="required", evidence_store="on", evidence_out_of_band="on")
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

    def invite(self, public_key, host=False):
        public_key=node(public_key)
        body={"roles":["role:client"],"recipient_public_key":public_key,"max_validity_hours":24,"token_expiry_hours":1}
        if host:
            identity=hashlib.sha256(base64.b64decode(public_key,validate=True)).hexdigest()
            # Core sovereign IDs are at most 64 characters. A 192-bit digest
            # keeps device subjects distinct within that existing constraint.
            body.update(node_sovereign_id="connect-device-"+identity[:48],executor_resource_prefix="connect:device:"+identity+"/")
        return {"invite":self.admin("/admin/invite",body)["token_id"]}

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
